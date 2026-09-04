//! Steady-state request/response latency across erbridge's three data paths:
//!
//!   - baseline: client <-> echo server directly (no erbridge in the loop)
//!   - forward:  client <-> erbridge forward <-> echo server
//!   - reverse:  client <-> A (serve) <=yamux/TLS=> B (connect) <-> echo server
//!
//! Each connection is established once during setup and then reused across
//! iterations (write payload, read the echo back) so the numbers reflect
//! per-message pipe/mux overhead rather than TCP handshake cost. Compare the
//! `forward_tcp_roundtrip` and `reverse_tunnel_tcp_roundtrip` distributions
//! against `baseline_direct_tcp_roundtrip` to get erbridge's added latency.

use std::hint::black_box;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio::sync::Mutex;

use erbridge::config::{
    ConnectConfig, ConnectTunnel, ForwardRule, ProtocolKind, ServeConfig, ServeTunnel,
};
use erbridge::forward::run_forward;
use erbridge::reverse::connect::run_connect;
use erbridge::reverse::serve::run_serve;
use erbridge::stats::Registry;

/// Fixed-size ping payload; big enough to be a realistic small message,
/// small enough that framing/mux overhead (not memcpy) dominates the timing.
const PAYLOAD: &[u8; 64] = &[0x42; 64];

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn run_echo_server(addr: SocketAddr) {
    let listener = TcpListener::bind(addr).await.expect("bind echo server");
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let _ = stream.set_nodelay(true);
        tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(stream);
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
    }
}

async fn connect_client(addr: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect(addr)
        .await
        .expect("connect to bench target");
    stream.set_nodelay(true).expect("set nodelay");
    stream
}

async fn roundtrip(stream: &Mutex<TcpStream>) {
    let mut guard = stream.lock().await;
    guard.write_all(PAYLOAD).await.expect("write ping");
    let mut buf = [0u8; PAYLOAD.len()];
    guard.read_exact(&mut buf).await.expect("read pong");
    black_box(&buf);
}

fn bench_baseline(c: &mut Criterion, rt: &Runtime) {
    let target_addr: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let stream = rt.block_on(async move {
        tokio::spawn(run_echo_server(target_addr));
        tokio::time::sleep(Duration::from_millis(50)).await;
        Arc::new(Mutex::new(connect_client(target_addr).await))
    });

    c.bench_function("baseline_direct_tcp_roundtrip", |b| {
        let stream = stream.clone();
        b.to_async(rt).iter(move || {
            let stream = stream.clone();
            async move { roundtrip(&stream).await }
        });
    });
}

fn bench_forward(c: &mut Criterion, rt: &Runtime) {
    let target_port = free_port();
    let listen_port = free_port();
    let target_addr: SocketAddr = format!("127.0.0.1:{target_port}").parse().unwrap();
    let listen_addr: SocketAddr = format!("127.0.0.1:{listen_port}").parse().unwrap();

    let rule = ForwardRule {
        name: Some("bench".into()),
        listen: format!("127.0.0.1:{listen_port}"),
        target: format!("127.0.0.1:{target_port}"),
        protocol: ProtocolKind::Tcp,
        udp_idle_secs: 60,
    };
    let stream = rt.block_on(async move {
        tokio::spawn(run_echo_server(target_addr));
        tokio::time::sleep(Duration::from_millis(50)).await;
        tokio::spawn(run_forward(vec![rule], Registry::new()));
        tokio::time::sleep(Duration::from_millis(100)).await;
        Arc::new(Mutex::new(connect_client(listen_addr).await))
    });

    c.bench_function("forward_tcp_roundtrip", |b| {
        let stream = stream.clone();
        b.to_async(rt).iter(move || {
            let stream = stream.clone();
            async move { roundtrip(&stream).await }
        });
    });
}

fn bench_reverse(c: &mut Criterion, rt: &Runtime) {
    let target_port = free_port();
    let control_port = free_port();
    let external_port = free_port();
    let target_addr: SocketAddr = format!("127.0.0.1:{target_port}").parse().unwrap();
    let external_addr: SocketAddr = format!("127.0.0.1:{external_port}").parse().unwrap();

    let serve_cfg = ServeConfig {
        listen: format!("127.0.0.1:{control_port}"),
        token: "bench-token".into(),
        tunnel: vec![ServeTunnel {
            name: "web".into(),
            external: format!("127.0.0.1:{external_port}"),
        }],
    };
    let connect_cfg = ConnectConfig {
        server: format!("127.0.0.1:{control_port}"),
        token: "bench-token".into(),
        tunnel: vec![ConnectTunnel {
            name: "web".into(),
            target: format!("127.0.0.1:{target_port}"),
        }],
        reconnect_min_secs: 1,
        reconnect_max_secs: 2,
    };

    let stream = rt.block_on(async move {
        tokio::spawn(run_echo_server(target_addr));
        tokio::time::sleep(Duration::from_millis(50)).await;
        tokio::spawn(run_serve(serve_cfg, Registry::new()));
        tokio::time::sleep(Duration::from_millis(50)).await;
        tokio::spawn(run_connect(connect_cfg, Registry::new()));
        // Control-channel TLS handshake + yamux setup needs longer than the
        // plain forward path's listener bind before the tunnel is ready.
        tokio::time::sleep(Duration::from_millis(300)).await;
        Arc::new(Mutex::new(connect_client(external_addr).await))
    });

    c.bench_function("reverse_tunnel_tcp_roundtrip", |b| {
        let stream = stream.clone();
        b.to_async(rt).iter(move || {
            let stream = stream.clone();
            async move { roundtrip(&stream).await }
        });
    });
}

fn benches(c: &mut Criterion) {
    let rt = Runtime::new().expect("build tokio runtime");
    bench_baseline(c, &rt);
    bench_forward(c, &rt);
    bench_reverse(c, &rt);
}

criterion_group!(latency, benches);
criterion_main!(latency);
