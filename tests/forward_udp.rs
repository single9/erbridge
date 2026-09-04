mod common;

use std::time::Duration;

use tokio::net::UdpSocket;
use erbridge::config::{ForwardRule, ProtocolKind};
use erbridge::forward::run_forward;
use erbridge::stats::Registry;

#[tokio::test]
async fn forwards_udp_traffic_to_target() {
    let target_port = common::free_port();
    let listen_port = common::free_port();
    let target_addr = format!("127.0.0.1:{target_port}").parse().unwrap();

    tokio::spawn(common::run_udp_echo_server(target_addr));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let rule = ForwardRule {
        name: Some("udp-test".into()),
        listen: format!("127.0.0.1:{listen_port}"),
        target: format!("127.0.0.1:{target_port}"),
        protocol: ProtocolKind::Udp,
        udp_idle_secs: 5,
    };
    let registry = Registry::new();
    tokio::spawn(run_forward(vec![rule], registry.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(b"hello", ("127.0.0.1", listen_port))
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("udp reply timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"HELLO");
}

#[tokio::test]
async fn evicts_idle_udp_sessions() {
    let target_port = common::free_port();
    let listen_port = common::free_port();
    let target_addr = format!("127.0.0.1:{target_port}").parse().unwrap();

    tokio::spawn(common::run_udp_echo_server(target_addr));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let rule = ForwardRule {
        name: Some("udp-idle-test".into()),
        listen: format!("127.0.0.1:{listen_port}"),
        target: format!("127.0.0.1:{target_port}"),
        protocol: ProtocolKind::Udp,
        udp_idle_secs: 1,
    };
    let registry = Registry::new();
    tokio::spawn(run_forward(vec![rule], registry.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(b"ping", ("127.0.0.1", listen_port))
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("first reply timed out")
        .unwrap();
    assert_eq!(registry.totals().live_connections, 1);

    // The reaper runs every 5s and the session idle timeout is 1s, so after
    // ~7s the session must have been evicted.
    tokio::time::sleep(Duration::from_secs(7)).await;
    assert_eq!(registry.totals().live_connections, 0);
}
