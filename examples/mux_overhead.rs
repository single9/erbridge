//! Decomposes erbridge's reverse-tunnel per-message cost into its layers.
//!
//! `compare_tunnels` measures the whole tunnel against other tools, which
//! answers "how do we compare" but not "what are we paying for". This walks
//! the same ping-pong up the stack one layer at a time:
//!
//!   tcp          client <-> echo server, no erbridge      (the floor)
//!   tcp+tls      the control channel's encryption only
//!   tcp+yamux    the multiplexer only, unencrypted
//!   tcp+tls+yamux    both, i.e. what a reverse tunnel actually rides on
//!
//! Subtracting adjacent rows gives the marginal cost of each layer, and
//! comparing (tls - tcp) + (yamux - tcp) against (tls+yamux - tcp) says
//! whether the two costs are additive or whether they interact.
//!
//! Every derived number -- the marginal column and the summary lines -- is
//! computed from the minimum rather than the median. Both endpoints run in
//! this one process on a multi-thread runtime, where which worker a task lands
//! on costs more than the layer being measured: the same plain TCP ping-pong
//! comes out at ~11 us here against ~7 us on a current-thread runtime. That
//! placement noise lands in the median and not in the minimum, which is the
//! iteration where nothing got in the way. The percentile columns are still
//! printed, but read them as a tail-behaviour check rather than as the signal
//! -- a difference visible in p50 but not in min is scheduling, not a layer.
//!
//! Those four rows all use a single TCP connection, whereas a real tunnel
//! chains three (client->A, A->B, B->target) with erbridge's copy loop at each
//! hop, so they cannot simply be subtracted from `compare_tunnels`' erbridge
//! number. The last row closes that gap:
//!
//!   tcp+2 relays  client -> relay -> relay -> echo, all plain TCP, each
//!                 relay running erbridge's own `pipe_bidirectional_tracked`
//!
//! It has a real tunnel's shape with the TLS+yamux link replaced by a plain
//! one, so it isolates what the proxy topology costs on its own. Adding the
//! TLS+yamux marginal cost on top should then predict the full tunnel.
//!
//! Run with: `cargo run --release --example mux_overhead`

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

use rustls_pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use erbridge::mux;
use erbridge::proxy::pipe_bidirectional_tracked;
use erbridge::tls;

const PAYLOAD: &[u8; 64] = &[0x42; 64];
const WARMUP: usize = 200;
const ITERS: usize = 5000;

/// Pause between passes, so one run does not inflate the next.
const SETTLE: Duration = Duration::from_millis(500);

/// Passes per layer. Samples from all of them are pooled, so the reported min
/// is the best of `PASSES * ITERS` iterations rather than of one pass.
const PASSES: usize = 3;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Layer {
    Tcp,
    Tls,
    Yamux,
    TlsYamux,
    Relays,
}

impl Layer {
    fn label(self) -> &'static str {
        match self {
            Layer::Tcp => "tcp",
            Layer::Tls => "tcp+tls",
            Layer::Yamux => "tcp+yamux",
            Layer::TlsYamux => "tcp+tls+yamux",
            Layer::Relays => "tcp+2 relays",
        }
    }
    fn uses_tls(self) -> bool {
        matches!(self, Layer::Tls | Layer::TlsYamux)
    }
    fn uses_yamux(self) -> bool {
        matches!(self, Layer::Yamux | Layer::TlsYamux)
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Echoes everything back on whichever stream the layer hands us. The two
/// halves are split so the copy is a straight pipe, matching how the real
/// proxy path moves bytes.
async fn echo<S>(stream: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + 'static,
{
    let (mut r, mut w) = tokio::io::split(stream);
    let _ = tokio::io::copy(&mut r, &mut w).await;
}

async fn serve_one(listener: TcpListener, layer: Layer, acceptor: Option<TlsAcceptor>) {
    let (sock, _) = match listener.accept().await {
        Ok(v) => v,
        Err(_) => return,
    };
    let _ = sock.set_nodelay(true);

    // Each arm ends up calling `echo` on a different concrete stream type, so
    // the layers stay monomorphic rather than boxing every read and write.
    match (layer.uses_tls(), layer.uses_yamux()) {
        (false, false) => echo(sock).await,
        (false, true) => {
            let (_ctl, mut inbound) = mux::spawn(sock.compat(), mux::Mode::Server);
            if let Some(s) = inbound.recv().await {
                echo(s.compat()).await;
            }
        }
        (true, false) => {
            let tls = match acceptor.unwrap().accept(sock).await {
                Ok(v) => v,
                Err(_) => return,
            };
            echo(tls).await;
        }
        (true, true) => {
            let tls = match acceptor.unwrap().accept(sock).await {
                Ok(v) => v,
                Err(_) => return,
            };
            let (_ctl, mut inbound) = mux::spawn(tls.compat(), mux::Mode::Server);
            if let Some(s) = inbound.recv().await {
                echo(s.compat()).await;
            }
        }
    }
}

/// Drives WARMUP + ITERS roundtrips and returns the per-iteration timings.
async fn ping_pong<S>(mut stream: S) -> Vec<Duration>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut buf = [0u8; PAYLOAD.len()];
    for _ in 0..WARMUP {
        stream.write_all(PAYLOAD).await.unwrap();
        stream.read_exact(&mut buf).await.unwrap();
    }
    let mut out = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        let t0 = Instant::now();
        stream.write_all(PAYLOAD).await.unwrap();
        stream.read_exact(&mut buf).await.unwrap();
        out.push(t0.elapsed());
    }
    out
}

/// One hop of a proxy chain: accept a connection, dial the next hop, and pump
/// bytes between them with the same copy loop the real data path uses.
async fn relay(listen: SocketAddr, next: SocketAddr) {
    let listener = TcpListener::bind(listen).await.expect("bind relay");
    let (client, _) = listener.accept().await.expect("relay accept");
    let _ = client.set_nodelay(true);
    let upstream = TcpStream::connect(next).await.expect("relay dial");
    let _ = upstream.set_nodelay(true);
    let _ = pipe_bidirectional_tracked(
        client,
        upstream,
        Arc::new(AtomicU64::new(0)),
        Arc::new(AtomicU64::new(0)),
    )
    .await;
}

/// client -> relay -> relay -> echo, every link a plain TCP connection: a real
/// tunnel's topology with the TLS+yamux link swapped for an unencrypted one.
async fn measure_relays() -> Vec<Duration> {
    let echo_addr: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let second: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let first: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();

    let echo_listener = TcpListener::bind(echo_addr).await.expect("bind echo");
    tokio::spawn(async move {
        let (sock, _) = echo_listener.accept().await.expect("echo accept");
        let _ = sock.set_nodelay(true);
        echo(sock).await;
    });
    tokio::spawn(relay(second, echo_addr));
    tokio::spawn(relay(first, second));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let sock = TcpStream::connect(first).await.expect("connect");
    sock.set_nodelay(true).unwrap();
    ping_pong(sock).await
}

async fn measure(layer: Layer) -> Vec<Duration> {
    if layer == Layer::Relays {
        return measure_relays().await;
    }
    let addr: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let listener = TcpListener::bind(addr).await.expect("bind");

    let acceptor = if layer.uses_tls() {
        let cert = tls::generate_self_signed().expect("cert");
        Some(TlsAcceptor::from(
            tls::server_tls_config(&cert).expect("server tls config"),
        ))
    } else {
        None
    };
    tokio::spawn(serve_one(listener, layer, acceptor));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let sock = TcpStream::connect(addr).await.expect("connect");
    sock.set_nodelay(true).unwrap();

    match (layer.uses_tls(), layer.uses_yamux()) {
        (false, false) => ping_pong(sock).await,
        (false, true) => {
            // `_inbound` is held for the whole measurement: dropping the
            // receiver would let the mux driver task shut down mid-run.
            let (ctl, _inbound) = mux::spawn(sock.compat(), mux::Mode::Client);
            let s = ctl.open_stream().await.expect("open stream");
            ping_pong(s.compat()).await
        }
        (true, false) => {
            let tls = connect_tls(sock).await;
            ping_pong(tls).await
        }
        (true, true) => {
            let tls = connect_tls(sock).await;
            let (ctl, _inbound) = mux::spawn(tls.compat(), mux::Mode::Client);
            let s = ctl.open_stream().await.expect("open stream");
            ping_pong(s.compat()).await
        }
    }
}

async fn connect_tls(sock: TcpStream) -> tokio_rustls::client::TlsStream<TcpStream> {
    let config: Arc<_> = tls::client_tls_config().expect("client tls config");
    let connector = TlsConnector::from(config);
    let name = ServerName::try_from("erbridge").expect("static name");
    connector.connect(name, sock).await.expect("tls handshake")
}

struct Stats {
    min: f64,
    p50: f64,
    p95: f64,
    p99: f64,
}

fn percentiles(mut samples: Vec<Duration>) -> Stats {
    samples.sort();
    let us = |d: Duration| d.as_secs_f64() * 1e6;
    let n = samples.len();
    let at = |q: f64| us(samples[(((n - 1) as f64) * q).round() as usize]);
    Stats {
        min: us(samples[0]),
        p50: at(0.50),
        p95: at(0.95),
        p99: at(0.99),
    }
}

#[tokio::main]
async fn main() {
    tls::install_crypto_provider();

    // Layers are measured in one process, one after another, so a machine that
    // ramps its clocks up (or heats up and throttles) systematically favours
    // whichever position a layer sits in -- a bias no amount of repetition
    // removes. `MUX_ROTATE` rotates the running order so a caller can give
    // every layer every position across a set of runs and cancel it out.
    let mut layers = vec![
        Layer::Tcp,
        Layer::Tls,
        Layer::Yamux,
        Layer::TlsYamux,
        Layer::Relays,
    ];
    let rotate = std::env::var("MUX_ROTATE")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0)
        % layers.len();
    layers.rotate_left(rotate);

    // Some layers come out bimodal across passes -- the plain tcp and tcp+tls
    // rows land near either ~12 us or ~20 us depending on the pass, while the
    // yamux and relay rows repeat to within a few tenths. A single pass that
    // catches a layer in its slow mode moves every marginal derived from it,
    // and the tcp row moves all of them at once. Pooling several passes per
    // layer and taking the min over the lot settles on the floor instead.
    let mut stats = Vec::new();
    for layer in layers {
        let mut samples = Vec::new();
        for _ in 0..PASSES {
            samples.extend(measure(layer).await);
            // Let the machine settle between passes, for the same reason
            // `make compare-tunnels` does: back-to-back rounds inflate
            // everything.
            tokio::time::sleep(SETTLE).await;
        }
        stats.push((layer, percentiles(samples)));
    }

    println!(
        "\n{:<16}{:>9}{:>9}{:>9}{:>9}{:>14}",
        "layer", "min", "p50", "p95", "p99", "marginal min"
    );
    println!("{}", "-".repeat(66));
    stats.sort_by_key(|(layer, _)| *layer as u8);
    let base = stats[0].1.min;
    for (layer, s) in &stats {
        let marginal = match layer {
            Layer::Tcp => "—".to_string(),
            _ => format!("{:+.1} µs", s.min - base),
        };
        println!(
            "{:<16}{:>8.1}{:>9.1}{:>9.1}{:>9.1}{:>14}",
            layer.label(),
            s.min,
            s.p50,
            s.p95,
            s.p99,
            marginal
        );
    }

    let m = |l: Layer| stats.iter().find(|(x, _)| *x == l).unwrap().1.min;
    let tls_only = m(Layer::Tls) - m(Layer::Tcp);
    let yamux_only = m(Layer::Yamux) - m(Layer::Tcp);
    let both = m(Layer::TlsYamux) - m(Layer::Tcp);
    println!("\ntls alone      : {tls_only:+.1} µs");
    println!("yamux alone    : {yamux_only:+.1} µs");
    println!("both together  : {both:+.1} µs");
    println!(
        "interaction    : {:+.1} µs (both - tls - yamux; ~0 means the costs simply add)",
        both - tls_only - yamux_only
    );

    // A real tunnel is the relay topology with its middle link carrying TLS and
    // yamux, so this is what `compare_tunnels`' erbridge row should land near.
    let relays_only = m(Layer::Relays) - m(Layer::Tcp);
    println!("\n2 relays alone : {relays_only:+.1} µs");
    println!(
        "predicted full tunnel : {:.1} µs  (tcp {:.1} + relays {:+.1} + tls/yamux {:+.1})",
        m(Layer::Tcp) + relays_only + both,
        m(Layer::Tcp),
        relays_only,
        both
    );
}
