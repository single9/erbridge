#![allow(dead_code)] // each test binary only exercises a subset of these helpers

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

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
