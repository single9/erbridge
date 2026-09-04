mod common;

use std::time::Duration;

use erbridge::config::{ForwardRule, ProtocolKind};
use erbridge::forward::run_forward;
use erbridge::stats::Registry;

#[tokio::test]
async fn forwards_tcp_traffic_to_target() {
    let target_port = common::free_port();
    let listen_port = common::free_port();
    let target_addr = format!("127.0.0.1:{target_port}").parse().unwrap();

    tokio::spawn(common::run_tcp_echo_server(target_addr));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let rule = ForwardRule {
        name: Some("test".into()),
        listen: format!("127.0.0.1:{listen_port}"),
        target: format!("127.0.0.1:{target_port}"),
        protocol: ProtocolKind::Tcp,
        udp_idle_secs: 60,
    };
    let registry = Registry::new();
    tokio::spawn(run_forward(vec![rule], registry.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let listen_addr = format!("127.0.0.1:{listen_port}").parse().unwrap();
    let echoed = common::tcp_roundtrip(listen_addr, b"hello over tcp forward").await;
    assert_eq!(echoed, b"hello over tcp forward");

    let totals = registry.totals();
    assert_eq!(totals.total_connections, 1);
    assert!(totals.bytes_in >= "hello over tcp forward".len() as u64);
}

#[tokio::test]
async fn forwards_multiple_concurrent_tcp_connections() {
    let target_port = common::free_port();
    let listen_port = common::free_port();
    let target_addr = format!("127.0.0.1:{target_port}").parse().unwrap();

    tokio::spawn(common::run_tcp_echo_server(target_addr));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let rule = ForwardRule {
        name: None,
        listen: format!("127.0.0.1:{listen_port}"),
        target: format!("127.0.0.1:{target_port}"),
        protocol: ProtocolKind::Tcp,
        udp_idle_secs: 60,
    };
    let registry = Registry::new();
    tokio::spawn(run_forward(vec![rule], registry.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let listen_addr: std::net::SocketAddr = format!("127.0.0.1:{listen_port}").parse().unwrap();
    let mut handles = Vec::new();
    for i in 0..10 {
        let payload = format!("client-{i}").into_bytes();
        handles.push(tokio::spawn(async move {
            let echoed = common::tcp_roundtrip(listen_addr, &payload).await;
            assert_eq!(echoed, payload);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    assert_eq!(registry.totals().total_connections, 10);
}
