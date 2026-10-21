#![allow(dead_code)] // each test binary only exercises a subset of these helpers

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio_rustls::TlsConnector;

/// Binds an ephemeral port, reads its number, then releases it. There's an
/// inherent (tiny) race between releasing and the caller rebinding, but it's
/// the standard way to get a free port for a test without threading the
/// bound listener itself through async task boundaries.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Accepts TCP connections forever, echoing every byte back until the peer
/// half-closes, then closing its own side too.
pub async fn run_tcp_echo_server(addr: SocketAddr) {
    let listener = TcpListener::bind(addr).await.expect("bind echo server");
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => continue,
        };
        tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(stream);
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
    }
}

/// Receives UDP datagrams forever and echoes each one back upper-cased, so
/// tests can distinguish "the target answered" from "the client's own bytes
/// looped back somewhere".
pub async fn run_udp_echo_server(addr: SocketAddr) {
    let socket = UdpSocket::bind(addr).await.expect("bind udp echo server");
    let mut buf = vec![0u8; 4096];
    loop {
        let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
            continue;
        };
        let reply: Vec<u8> = buf[..n].to_ascii_uppercase();
        let _ = socket.send_to(&reply, peer).await;
    }
}

pub async fn tcp_roundtrip(addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to forwarded port");
    stream.write_all(payload).await.expect("write payload");
    stream.shutdown().await.expect("shutdown write half");
    let mut out = Vec::new();
    stream
        .read_to_end(&mut out)
        .await
        .expect("read echoed payload");
    out
}

/// Same as [`tcp_roundtrip`] but over TLS, accepting the forward listener's
/// self-signed cert the same way `connect` accepts `serve`'s (see `tls`
/// module docs: confidentiality, not peer identity).
pub async fn tls_roundtrip(addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
    erbridge_core::tls::install_crypto_provider();
    let connector = TlsConnector::from(erbridge_core::tls::client_tls_config().unwrap());
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to forwarded port");
    let server_name = rustls_pki_types::ServerName::try_from("erbridge").unwrap();
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .expect("tls handshake");
    stream.write_all(payload).await.expect("write payload");
    stream.shutdown().await.expect("shutdown write half");
    let mut out = Vec::new();
    stream
        .read_to_end(&mut out)
        .await
        .expect("read echoed payload");
    out
}

/// Accepts TCP connections forever, counting them, and holds each one open
/// without ever writing a byte back. Models a server that waits for the client
/// to speak first and has not answered yet -- the case where nothing on the
/// target side would prompt the tunnel to acknowledge its streams.
pub async fn run_silent_tcp_server(addr: SocketAddr, accepted: Arc<AtomicUsize>) {
    let listener = TcpListener::bind(addr).await.expect("bind silent server");
    let mut held = Vec::new();
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        accepted.fetch_add(1, Ordering::SeqCst);
        held.push(stream);
    }
}

/// The TLS ClientHello a real rustls client would send for `name`. Enough to
/// exercise SNI routing without completing a handshake.
pub fn client_hello(name: &str) -> Vec<u8> {
    use rustls_pki_types::ServerName;
    erbridge_core::tls::install_crypto_provider();
    let config = erbridge_core::tls::client_tls_config().unwrap();
    let server_name = ServerName::try_from(name.to_string()).unwrap();
    let mut conn = rustls::ClientConnection::new(config, server_name).unwrap();
    let mut out = Vec::new();
    conn.write_tls(&mut out).unwrap();
    out
}

/// Accepts TCP connections forever; for each, answers every read with `tag`
/// followed by the bytes read, so a test can tell which target it reached.
/// Counts accepted connections in `hits`.
pub async fn run_tagged_echo_server(addr: SocketAddr, tag: &'static str, hits: Arc<AtomicUsize>) {
    let listener = TcpListener::bind(addr).await.expect("bind tagged echo");
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        hits.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let mut reply = tag.as_bytes().to_vec();
                        reply.extend_from_slice(&buf[..n]);
                        if stream.write_all(&reply).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
    }
}

/// A TLS server (self-signed) that answers each read with `tag` followed by the
/// bytes read, so a test can tell which target a real TLS client reached.
pub async fn run_tls_tagged_echo_server(addr: SocketAddr, tag: &'static str) {
    erbridge_core::tls::install_crypto_provider();
    let cert = erbridge_core::tls::generate_self_signed().unwrap();
    let acceptor =
        tokio_rustls::TlsAcceptor::from(erbridge_core::tls::server_tls_config(&cert).unwrap());
    let listener = TcpListener::bind(addr).await.expect("bind tls echo");
    loop {
        let Ok((tcp, _)) = listener.accept().await else {
            continue;
        };
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let Ok(mut stream) = acceptor.accept(tcp).await else {
                return;
            };
            let mut buf = vec![0u8; 8192];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let mut reply = tag.as_bytes().to_vec();
                        reply.extend_from_slice(&buf[..n]);
                        if stream.write_all(&reply).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
    }
}

/// A TLS client for `sni` (connecting to `addr`) that completes the handshake
/// and returns the first reply to `payload`. Any failure is an `Err`, so a test
/// can assert that a connection is refused.
pub async fn tls_exchange(addr: SocketAddr, sni: &str, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    use std::io::{Error, ErrorKind};
    erbridge_core::tls::install_crypto_provider();
    let attempt = async {
        let connector = TlsConnector::from(erbridge_core::tls::client_tls_config().unwrap());
        let tcp = tokio::net::TcpStream::connect(addr).await?;
        let name = rustls_pki_types::ServerName::try_from(sni.to_string())
            .map_err(|e| Error::new(ErrorKind::InvalidInput, e))?;
        let mut stream = connector.connect(name, tcp).await?;
        stream.write_all(payload).await?;
        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await?;
        buf.truncate(n);
        Ok(buf)
    };
    tokio::time::timeout(std::time::Duration::from_secs(3), attempt)
        .await
        .map_err(|_| Error::new(ErrorKind::TimedOut, "tls exchange timed out"))?
}
