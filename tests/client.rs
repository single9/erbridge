mod common;

use std::time::Duration;

use erbridge::client::run_client;
use erbridge::config::{ClientRule, ForwardRule, ProtocolKind, Transport};
use erbridge::forward::run_forward;
use erbridge::stats::Registry;

#[tokio::test]
async fn client_reaches_token_secured_forward_mapping() {
    let target_port = common::free_port();
    let forward_port = common::free_port();
    let local_port = common::free_port();
    let target_addr = format!("127.0.0.1:{target_port}").parse().unwrap();

    tokio::spawn(common::run_tcp_echo_server(target_addr));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let forward_rule = ForwardRule {
        name: Some("secured".into()),
        listen: format!("127.0.0.1:{forward_port}"),
        target: format!("127.0.0.1:{target_port}"),
        protocol: ProtocolKind::Tcp,
        udp_idle_secs: 60,
        transport: Some(Transport::Tls),
        token: Some("change-me".into()),
    };
    let forward_registry = Registry::new();
    tokio::spawn(run_forward(vec![forward_rule], forward_registry.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client_rule = ClientRule {
        name: Some("secured".into()),
        listen: format!("127.0.0.1:{local_port}"),
        server: format!("127.0.0.1:{forward_port}"),
        transport: Transport::Tls,
        token: Some("change-me".into()),
    };
    let client_registry = Registry::new();
    tokio::spawn(run_client(vec![client_rule], client_registry.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let local_addr = format!("127.0.0.1:{local_port}").parse().unwrap();
    let echoed = common::tcp_roundtrip(local_addr, b"hello through client mode").await;
    assert_eq!(echoed, b"hello through client mode");

    assert_eq!(forward_registry.totals().total_connections, 1);
    assert_eq!(client_registry.totals().total_connections, 1);
}

#[tokio::test]
async fn client_with_wrong_token_is_rejected() {
    let target_port = common::free_port();
    let forward_port = common::free_port();
    let local_port = common::free_port();
    let target_addr = format!("127.0.0.1:{target_port}").parse().unwrap();

    tokio::spawn(common::run_tcp_echo_server(target_addr));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let forward_rule = ForwardRule {
        name: Some("secured".into()),
        listen: format!("127.0.0.1:{forward_port}"),
        target: format!("127.0.0.1:{target_port}"),
        protocol: ProtocolKind::Tcp,
        udp_idle_secs: 60,
        transport: Some(Transport::Tls),
        token: Some("correct-token".into()),
    };
    let forward_registry = Registry::new();
    tokio::spawn(run_forward(vec![forward_rule], forward_registry.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client_rule = ClientRule {
        name: Some("secured".into()),
        listen: format!("127.0.0.1:{local_port}"),
        server: format!("127.0.0.1:{forward_port}"),
        transport: Transport::Tls,
        token: Some("wrong-token".into()),
    };
    let client_registry = Registry::new();
    tokio::spawn(run_client(vec![client_rule], client_registry.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The client's local listener accepted the connection, but the token
    // handshake with the secured mapping fails behind the scenes, so the
    // local socket is dropped without ever being relayed anywhere -- either
    // as a clean close (empty read) or a reset, depending on timing.
    let local_addr: std::net::SocketAddr = format!("127.0.0.1:{local_port}").parse().unwrap();
    let mut stream = tokio::net::TcpStream::connect(local_addr)
        .await
        .expect("connect to client's local listener");
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let _ = stream.write_all(b"hello").await;
    let _ = stream.shutdown().await;
    let mut out = Vec::new();
    let read_result = stream.read_to_end(&mut out).await;
    assert!(
        read_result.is_err() || out.is_empty(),
        "expected the rejected token to close the connection, got: {out:?}"
    );
}

#[tokio::test]
async fn client_reaches_noise_secured_forward_mapping() {
    let target_port = common::free_port();
    let forward_port = common::free_port();
    let local_port = common::free_port();
    let target_addr = format!("127.0.0.1:{target_port}").parse().unwrap();

    tokio::spawn(common::run_tcp_echo_server(target_addr));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let forward_rule = ForwardRule {
        name: Some("secured".into()),
        listen: format!("127.0.0.1:{forward_port}"),
        target: format!("127.0.0.1:{target_port}"),
        protocol: ProtocolKind::Tcp,
        udp_idle_secs: 60,
        transport: Some(Transport::Noise),
        token: Some("change-me".into()),
    };
    let forward_registry = Registry::new();
    tokio::spawn(run_forward(vec![forward_rule], forward_registry.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client_rule = ClientRule {
        name: Some("secured".into()),
        listen: format!("127.0.0.1:{local_port}"),
        server: format!("127.0.0.1:{forward_port}"),
        transport: Transport::Noise,
        token: Some("change-me".into()),
    };
    let client_registry = Registry::new();
    tokio::spawn(run_client(vec![client_rule], client_registry.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let local_addr = format!("127.0.0.1:{local_port}").parse().unwrap();
    let echoed = common::tcp_roundtrip(local_addr, b"hello through noise client mode").await;
    assert_eq!(echoed, b"hello through noise client mode");

    assert_eq!(forward_registry.totals().total_connections, 1);
    assert_eq!(client_registry.totals().total_connections, 1);
}

#[tokio::test]
async fn client_with_wrong_token_over_noise_is_rejected() {
    let target_port = common::free_port();
    let forward_port = common::free_port();
    let local_port = common::free_port();
    let target_addr = format!("127.0.0.1:{target_port}").parse().unwrap();

    tokio::spawn(common::run_tcp_echo_server(target_addr));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let forward_rule = ForwardRule {
        name: Some("secured".into()),
        listen: format!("127.0.0.1:{forward_port}"),
        target: format!("127.0.0.1:{target_port}"),
        protocol: ProtocolKind::Tcp,
        udp_idle_secs: 60,
        transport: Some(Transport::Noise),
        token: Some("correct-token".into()),
    };
    let forward_registry = Registry::new();
    tokio::spawn(run_forward(vec![forward_rule], forward_registry.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client_rule = ClientRule {
        name: Some("secured".into()),
        listen: format!("127.0.0.1:{local_port}"),
        server: format!("127.0.0.1:{forward_port}"),
        transport: Transport::Noise,
        token: Some("wrong-token".into()),
    };
    let client_registry = Registry::new();
    tokio::spawn(run_client(vec![client_rule], client_registry.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let local_addr: std::net::SocketAddr = format!("127.0.0.1:{local_port}").parse().unwrap();
    let mut stream = tokio::net::TcpStream::connect(local_addr)
        .await
        .expect("connect to client's local listener");
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let _ = stream.write_all(b"hello").await;
    let _ = stream.shutdown().await;
    let mut out = Vec::new();
    let read_result = stream.read_to_end(&mut out).await;
    assert!(
        read_result.is_err() || out.is_empty(),
        "expected the mismatched PSK to close the connection, got: {out:?}"
    );
}
