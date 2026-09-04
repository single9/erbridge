//! Measures reverse-tunnel *connection setup* latency: connect to A's external
//! port, send a request, and wait for the first response byte. The ping-pong
//! benchmarks all reuse one long-lived connection, so they never see this.
use std::time::{Duration, Instant};

use erbridge::config::{ConnectConfig, ConnectTunnel, ServeConfig, ServeTunnel};
use erbridge::reverse::{connect::run_connect, serve::run_serve};
use erbridge::stats::Registry;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const ITERS: usize = 400;
const WARMUP: usize = 50;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[tokio::main]
async fn main() {
    let (tp, cp, ep) = (free_port(), free_port(), free_port());

    tokio::spawn(async move {
        let l = TcpListener::bind(format!("127.0.0.1:{tp}")).await.unwrap();
        loop {
            let (s, _) = l.accept().await.unwrap();
            let _ = s.set_nodelay(true);
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(s);
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });

    let serve_cfg = ServeConfig {
        listen: format!("127.0.0.1:{cp}"), token: "t".into(),
        tunnel: vec![ServeTunnel { name: "w".into(), external: format!("127.0.0.1:{ep}") }],
    };
    let connect_cfg = ConnectConfig {
        server: format!("127.0.0.1:{cp}"), token: "t".into(),
        tunnel: vec![ConnectTunnel { name: "w".into(), target: format!("127.0.0.1:{tp}") }],
        reconnect_min_secs: 1, reconnect_max_secs: 2,
    };
    tokio::spawn(run_serve(serve_cfg, Registry::new()));
    tokio::time::sleep(Duration::from_millis(200)).await;
    tokio::spawn(run_connect(connect_cfg, Registry::new()));
    tokio::time::sleep(Duration::from_millis(400)).await;

    let addr = format!("127.0.0.1:{ep}");
    let mut out = Vec::with_capacity(ITERS);
    for i in 0..(WARMUP + ITERS) {
        let t0 = Instant::now();
        let mut s = TcpStream::connect(&addr).await.unwrap();
        s.set_nodelay(true).unwrap();
        s.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await.unwrap();
        let dt = t0.elapsed();
        if i >= WARMUP { out.push(dt); }
    }
    out.sort();
    let us = |d: Duration| d.as_secs_f64() * 1e6;
    let at = |q: f64| us(out[(((out.len() - 1) as f64) * q).round() as usize]);
    println!("{:.1} {:.1} {:.1}", us(out[0]), at(0.50), at(0.95));
}
