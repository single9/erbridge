//! Direct forward mode: `external listen port -> internal target host:port`,
//! for TCP, UDP, or both, all reachable directly (no reverse hop needed).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;

use crate::config::{ForwardRule, ProtocolKind, Transport};
use crate::noise;
use crate::proxy::pipe_bidirectional_tracked;
use crate::reverse::{MAX_TOKEN_LEN, constant_time_eq, read_frame};
use crate::stats::{ConnectionInfo, Protocol, Registry};
use crate::tls;

/// Object-safe alias so a plain `TcpStream` and a `TlsStream<TcpStream>` can
/// share one code path through [`pipe_bidirectional_tracked`].
trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

pub async fn run_forward(rules: Vec<ForwardRule>, registry: Registry) -> Result<()> {
    if rules.is_empty() {
        anyhow::bail!("forward mode needs at least one mapping (config `[[forward]]` or --map)");
    }
    for rule in &rules {
        rule.validate()?;
    }

    let mut handles = Vec::new();
    for rule in rules {
        if matches!(rule.protocol, ProtocolKind::Tcp | ProtocolKind::Both) {
            let rule = rule.clone();
            let registry = registry.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = run_tcp_forward(rule.clone(), registry.clone()).await {
                    registry.error(format!(
                        "forward[{}] tcp listener stopped: {e:#}",
                        rule.label()
                    ));
                }
            }));
        }
        if matches!(rule.protocol, ProtocolKind::Udp | ProtocolKind::Both) {
            let rule = rule.clone();
            let registry = registry.clone();
            handles.push(tokio::spawn(async move {
                if let Err(e) = run_udp_forward(rule.clone(), registry.clone()).await {
                    registry.error(format!(
                        "forward[{}] udp listener stopped: {e:#}",
                        rule.label()
                    ));
                }
            }));
        }
    }

    for handle in handles {
        let _ = handle.await;
    }
    Ok(())
}

/// Per-rule state needed to secure an accepted client connection, built once
/// at listener startup rather than per-connection.
#[derive(Clone)]
enum ConnSecurity {
    Plain,
    Tls(TlsAcceptor),
    Noise([u8; 32]),
}

async fn run_tcp_forward(rule: ForwardRule, registry: Registry) -> Result<()> {
    let listener = TcpListener::bind(&rule.listen)
        .await
        .with_context(|| format!("binding TCP listener on {}", rule.listen))?;

    let security = match rule.transport {
        None => ConnSecurity::Plain,
        Some(Transport::Tls) => {
            tls::install_crypto_provider();
            let cert = tls::generate_self_signed()?;
            ConnSecurity::Tls(TlsAcceptor::from(tls::server_tls_config(&cert)?))
        }
        Some(Transport::Noise) => {
            // Validated at startup: `transport = "noise"` requires a token.
            let token = rule
                .token
                .as_ref()
                .expect("noise transport requires a token");
            ConnSecurity::Noise(noise::derive_psk(token))
        }
    };

    registry.info(format!(
        "forward[{}] tcp{} listening on {} -> {}",
        rule.label(),
        match rule.transport {
            None => "",
            Some(Transport::Tls) => " (tls)",
            Some(Transport::Noise) => " (noise)",
        },
        rule.listen,
        rule.target
    ));

    loop {
        let (client, peer) = listener.accept().await?;
        let rule = rule.clone();
        let registry = registry.clone();
        let security = security.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_conn(client, peer, &rule, &registry, security).await {
                registry.error(format!("forward[{}] tcp {peer}: {e:#}", rule.label()));
            }
        });
    }
}

async fn handle_tcp_conn(
    client: TcpStream,
    peer: SocketAddr,
    rule: &ForwardRule,
    registry: &Registry,
    security: ConnSecurity,
) -> Result<()> {
    let _ = client.set_nodelay(true);

    let client: Box<dyn AsyncStream> = match security {
        ConnSecurity::Plain => Box::new(client),
        ConnSecurity::Tls(acceptor) => {
            let mut tls_stream = acceptor
                .accept(client)
                .await
                .context("TLS handshake with client failed")?;
            if let Some(token) = &rule.token {
                let presented = read_frame(&mut tls_stream, MAX_TOKEN_LEN)
                    .await
                    .context("reading token from client")?;
                if !constant_time_eq(&presented, token.as_bytes()) {
                    let _ = tls_stream.write_all(&[0u8]).await;
                    anyhow::bail!("token mismatch from {peer}");
                }
                tls_stream.write_all(&[1u8]).await?;
            }
            Box::new(tls_stream)
        }
        ConnSecurity::Noise(psk) => {
            let noise_stream = noise::accept(client, &psk)
                .await
                .context("Noise handshake with client failed")?;
            Box::new(noise_stream)
        }
    };

    let target = TcpStream::connect(&rule.target)
        .await
        .with_context(|| format!("connecting to target {}", rule.target))?;
    let _ = target.set_nodelay(true);

    let info = registry.open(
        format!("forward:{}", rule.label()),
        Protocol::Tcp,
        peer.to_string(),
        rule.target.clone(),
    );
    let result = pipe_bidirectional_tracked(
        client,
        target,
        info.bytes_in.clone(),
        info.bytes_out.clone(),
    )
    .await;
    registry.close(&info);
    result.map_err(Into::into)
}

struct UdpSession {
    to_target: mpsc::UnboundedSender<Vec<u8>>,
    last_active: Arc<StdMutex<Instant>>,
}

async fn run_udp_forward(rule: ForwardRule, registry: Registry) -> Result<()> {
    let listen_addr: SocketAddr = rule
        .listen
        .parse()
        .with_context(|| format!("parsing UDP listen address {}", rule.listen))?;
    let socket = Arc::new(
        UdpSocket::bind(listen_addr)
            .await
            .with_context(|| format!("binding UDP listener on {}", rule.listen))?,
    );
    registry.info(format!(
        "forward[{}] udp listening on {} -> {}",
        rule.label(),
        rule.listen,
        rule.target
    ));

    let sessions: Arc<StdMutex<HashMap<SocketAddr, UdpSession>>> =
        Arc::new(StdMutex::new(HashMap::new()));
    let idle = Duration::from_secs(rule.udp_idle_secs.max(1));

    {
        let sessions = sessions.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(5));
            loop {
                tick.tick().await;
                sessions
                    .lock()
                    .unwrap()
                    .retain(|_, s| s.last_active.lock().unwrap().elapsed() < idle);
            }
        });
    }

    let mut buf = vec![0u8; 65536];
    loop {
        let (n, src) = socket.recv_from(&mut buf).await.context("udp recv_from")?;
        let data = buf[..n].to_vec();

        let sender = {
            let mut map = sessions.lock().unwrap();
            if let Some(session) = map.get(&src) {
                *session.last_active.lock().unwrap() = Instant::now();
                session.to_target.clone()
            } else {
                let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
                let last_active = Arc::new(StdMutex::new(Instant::now()));
                let info = registry.open(
                    format!("forward:{}", rule.label()),
                    Protocol::Udp,
                    src.to_string(),
                    rule.target.clone(),
                );
                map.insert(
                    src,
                    UdpSession {
                        to_target: tx.clone(),
                        last_active,
                    },
                );
                spawn_udp_session(
                    socket.clone(),
                    src,
                    rule.target.clone(),
                    rx,
                    info,
                    sessions.clone(),
                    registry.clone(),
                );
                tx
            }
        };
        let _ = sender.send(data);
    }
}

fn spawn_udp_session(
    external: Arc<UdpSocket>,
    client_addr: SocketAddr,
    target_addr: String,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
    info: ConnectionInfo,
    sessions: Arc<StdMutex<HashMap<SocketAddr, UdpSession>>>,
    registry: Registry,
) {
    tokio::spawn(async move {
        let result: Result<()> = async {
            let target_sock = UdpSocket::bind(("0.0.0.0", 0)).await?;
            target_sock
                .connect(&target_addr)
                .await
                .with_context(|| format!("connecting UDP target {target_addr}"))?;
            let target_sock = Arc::new(target_sock);

            let reply_task = {
                let target_sock = target_sock.clone();
                let external = external.clone();
                let info = info.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65536];
                    while let Ok(n) = target_sock.recv(&mut buf).await {
                        info.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
                        if external.send_to(&buf[..n], client_addr).await.is_err() {
                            break;
                        }
                    }
                })
            };

            while let Some(data) = rx.recv().await {
                info.bytes_in
                    .fetch_add(data.len() as u64, Ordering::Relaxed);
                if target_sock.send(&data).await.is_err() {
                    break;
                }
            }
            reply_task.abort();
            Ok(())
        }
        .await;

        if let Err(e) = result {
            registry.error(format!("forward udp session {client_addr}: {e:#}"));
        }
        sessions.lock().unwrap().remove(&client_addr);
        registry.close(&info);
    });
}
