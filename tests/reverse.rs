mod common;

use std::time::Duration;

use erbridge::config::{ConnectConfig, ConnectTunnel, ServeConfig, ServeTunnel};
use erbridge::reverse::connect::run_connect;
use erbridge::reverse::serve::run_serve;
use erbridge::stats::Registry;

#[tokio::test]
async fn reverse_tunnel_roundtrip() {
    let target_port = common::free_port();
    let control_port = common::free_port();
    let external_port = common::free_port();

    let target_addr = format!("127.0.0.1:{target_port}").parse().unwrap();
    tokio::spawn(common::run_tcp_echo_server(target_addr));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let serve_cfg = ServeConfig {
        listen: format!("127.0.0.1:{control_port}"),
        token: "test-token".into(),
        tunnel: vec![ServeTunnel {
            name: "web".into(),
            external: format!("127.0.0.1:{external_port}"),
        }],
    };
    let connect_cfg = ConnectConfig {
        server: format!("127.0.0.1:{control_port}"),
        token: "test-token".into(),
        tunnel: vec![ConnectTunnel {
            name: "web".into(),
            target: format!("127.0.0.1:{target_port}"),
        }],
        reconnect_min_secs: 1,
        reconnect_max_secs: 2,
    };

    let serve_registry = Registry::new();
    let connect_registry = Registry::new();
    tokio::spawn(run_serve(serve_cfg, serve_registry.clone()));
    tokio::time::sleep(Duration::from_millis(50)).await;
    tokio::spawn(run_connect(connect_cfg, connect_registry.clone()));

    // The external listener blocks new connections until B's control
    // session is up, so we don't need to sleep-and-hope here: it's safe to
    // dial immediately and let the server-side wait for us.
    let external_addr: std::net::SocketAddr = format!("127.0.0.1:{external_port}").parse().unwrap();
    let echoed = tokio::time::timeout(
        Duration::from_secs(5),
        common::tcp_roundtrip(external_addr, b"through the reverse tunnel"),
    )
    .await
    .expect("reverse roundtrip timed out");
    assert_eq!(echoed, b"through the reverse tunnel");

    assert_eq!(serve_registry.totals().total_connections, 1);
    assert_eq!(connect_registry.totals().total_connections, 1);
}

#[tokio::test]
async fn multiple_streams_share_one_control_connection() {
    let target_port = common::free_port();
    let control_port = common::free_port();
    let external_port = common::free_port();

    let target_addr = format!("127.0.0.1:{target_port}").parse().unwrap();
    tokio::spawn(common::run_tcp_echo_server(target_addr));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let serve_cfg = ServeConfig {
        listen: format!("127.0.0.1:{control_port}"),
        token: "shared-token".into(),
        tunnel: vec![ServeTunnel {
            name: "web".into(),
            external: format!("127.0.0.1:{external_port}"),
        }],
    };
    let connect_cfg = ConnectConfig {
        server: format!("127.0.0.1:{control_port}"),
        token: "shared-token".into(),
        tunnel: vec![ConnectTunnel {
            name: "web".into(),
            target: format!("127.0.0.1:{target_port}"),
        }],
        reconnect_min_secs: 1,
        reconnect_max_secs: 2,
    };

    tokio::spawn(run_serve(serve_cfg, Registry::new()));
    tokio::time::sleep(Duration::from_millis(50)).await;
    tokio::spawn(run_connect(connect_cfg, Registry::new()));

    let external_addr: std::net::SocketAddr = format!("127.0.0.1:{external_port}").parse().unwrap();
    let mut handles = Vec::new();
    for i in 0..8 {
        let payload = format!("stream-{i}").into_bytes();
        handles.push(tokio::spawn(async move {
            let echoed = tokio::time::timeout(
                Duration::from_secs(5),
                common::tcp_roundtrip(external_addr, &payload),
            )
            .await
            .expect("roundtrip timed out");
            assert_eq!(echoed, payload);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn rejects_mismatched_token() {
    let control_port = common::free_port();
    let external_port = common::free_port();

    let serve_cfg = ServeConfig {
        listen: format!("127.0.0.1:{control_port}"),
        token: "correct-token".into(),
        tunnel: vec![ServeTunnel {
            name: "web".into(),
            external: format!("127.0.0.1:{external_port}"),
        }],
    };
    let connect_cfg = ConnectConfig {
        server: format!("127.0.0.1:{control_port}"),
        token: "wrong-token".into(),
        tunnel: vec![ConnectTunnel {
            name: "web".into(),
            target: "127.0.0.1:1".into(),
        }],
        reconnect_min_secs: 1,
        reconnect_max_secs: 1,
    };

    let serve_registry = Registry::new();
    tokio::spawn(run_serve(serve_cfg, serve_registry.clone()));
    tokio::time::sleep(Duration::from_millis(50)).await;
    tokio::spawn(run_connect(connect_cfg, Registry::new()));

    tokio::time::sleep(Duration::from_millis(500)).await;
    let log = serve_registry.recent_log();
    assert!(
        log.iter().any(|line| line.contains("token mismatch")),
        "expected a token mismatch log line, got: {log:?}"
    );
    assert_eq!(serve_registry.totals().total_connections, 0);
}
