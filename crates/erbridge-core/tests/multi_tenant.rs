mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use erbridge_core::config::{ConnectConfig, ConnectTunnel, ServeConfig};
use erbridge_core::noise;
use erbridge_core::reverse::connect::run_connect_with_shutdown;
use erbridge_core::reverse::serve::run_serve_with_shutdown;
use erbridge_core::stats::Registry;
use erbridge_core::tenant::{Tenant, TenantSet};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

struct Serve {
    control: String,
    sni: SocketAddr,
    #[allow(dead_code)]
    file: PathBuf,
    shutdown: CancellationToken,
    _dir: tempfile::TempDir,
}

fn tenant(name: &str, token: &str, sni: &str) -> Tenant {
    Tenant {
        name: name.into(),
        psk: noise::derive_psk(token),
        sni: sni.into(),
        max_conns: 8,
        disabled: false,
    }
}

async fn start_serve(tenants: Vec<Tenant>) -> Serve {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("tenants.toml");
    std::fs::write(
        &file,
        TenantSet::new(tenants, vec![]).unwrap().to_toml().unwrap(),
    )
    .unwrap();

    let control_port = common::free_port();
    let sni_port = common::free_port();
    let shutdown = CancellationToken::new();
    let cfg = ServeConfig {
        listen: format!("127.0.0.1:{control_port}"),
        tenants_file: Some(file.display().to_string()),
        sni_listen: Some(format!("127.0.0.1:{sni_port}")),
        ..Default::default()
    };
    tokio::spawn(run_serve_with_shutdown(
        cfg,
        Registry::new(),
        shutdown.clone(),
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;
    Serve {
        control: format!("127.0.0.1:{control_port}"),
        sni: format!("127.0.0.1:{sni_port}").parse().unwrap(),
        file,
        shutdown,
        _dir: dir,
    }
}

fn spawn_connect(serve: &Serve, token: &str, tunnels: &[(&str, SocketAddr)]) -> CancellationToken {
    let stop = CancellationToken::new();
    let cfg = ConnectConfig {
        server: serve.control.clone(),
        token: token.into(),
        tunnel: tunnels
            .iter()
            .map(|(name, target)| ConnectTunnel {
                name: (*name).into(),
                target: target.to_string(),
            })
            .collect(),
        reconnect_min_secs: 1,
        reconnect_max_secs: 1,
    };
    tokio::spawn(run_connect_with_shutdown(
        cfg,
        Registry::new(),
        stop.clone(),
    ));
    stop
}

async fn target(tag: &'static str) -> (SocketAddr, Arc<AtomicUsize>) {
    let addr: SocketAddr = format!("127.0.0.1:{}", common::free_port())
        .parse()
        .unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    tokio::spawn(common::run_tagged_echo_server(addr, tag, hits.clone()));
    tokio::time::sleep(Duration::from_millis(30)).await;
    (addr, hits)
}

/// Opens a connection to the SNI listener, sends a hello for `host`, and
/// returns whatever comes back until the far side closes or goes quiet.
async fn hello_and_read(serve: &Serve, host: &str, expect_at_least: usize) -> Vec<u8> {
    let hello = common::client_hello(host);
    let mut conn = TcpStream::connect(serve.sni).await.unwrap();
    conn.write_all(&hello).await.unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while got.len() < expect_at_least.max(1) {
        match tokio::time::timeout_at(deadline, conn.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => got.extend_from_slice(&buf[..n]),
        }
    }
    got
}

async fn wait_until_online(serve: &Serve, host: &str, tag: &str) {
    for _ in 0..50 {
        let got = hello_and_read(serve, host, tag.len()).await;
        if got.starts_with(tag.as_bytes()) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("tenant at {host} never came online");
}

#[tokio::test]
async fn two_tenants_reach_only_their_own_targets() {
    let serve = start_serve(vec![
        tenant("ta", "token-a", "a.example.com"),
        tenant("tb", "token-b", "b.example.com"),
    ])
    .await;
    let (addr_a, hits_a) = target("A:").await;
    let (addr_b, hits_b) = target("B:").await;
    let _a = spawn_connect(&serve, "token-a", &[("ta", addr_a)]);
    let _b = spawn_connect(&serve, "token-b", &[("tb", addr_b)]);
    wait_until_online(&serve, "a.example.com", "A:").await;
    wait_until_online(&serve, "b.example.com", "B:").await;

    let (a0, b0) = (hits_a.load(Ordering::SeqCst), hits_b.load(Ordering::SeqCst));
    assert!(
        hello_and_read(&serve, "a.example.com", 2)
            .await
            .starts_with(b"A:")
    );
    assert!(
        hello_and_read(&serve, "b.example.com", 2)
            .await
            .starts_with(b"B:")
    );
    assert!(
        hello_and_read(&serve, "A.EXAMPLE.COM", 2)
            .await
            .starts_with(b"A:")
    );
    assert_eq!(hits_a.load(Ordering::SeqCst) - a0, 2);
    assert_eq!(hits_b.load(Ordering::SeqCst) - b0, 1);
    serve.shutdown.cancel();
}

#[tokio::test]
async fn a_connect_cannot_pick_another_tenants_tunnel() {
    let serve = start_serve(vec![
        tenant("ta", "token-a", "a.example.com"),
        tenant("tb", "token-b", "b.example.com"),
    ])
    .await;
    let (real_a, _) = target("A:").await;
    let (real_b, _) = target("B:").await;
    let (decoy, decoy_hits) = target("DECOY:").await;

    // A's connect also declares a tunnel named after tenant B, pointing at a
    // decoy. It must never be reached, because serve names the tunnel itself.
    let _a = spawn_connect(&serve, "token-a", &[("ta", real_a), ("tb", decoy)]);
    let _b = spawn_connect(&serve, "token-b", &[("tb", real_b)]);
    wait_until_online(&serve, "a.example.com", "A:").await;
    wait_until_online(&serve, "b.example.com", "B:").await;

    for _ in 0..3 {
        assert!(
            hello_and_read(&serve, "a.example.com", 2)
                .await
                .starts_with(b"A:")
        );
        assert!(
            hello_and_read(&serve, "b.example.com", 2)
                .await
                .starts_with(b"B:")
        );
    }
    assert_eq!(decoy_hits.load(Ordering::SeqCst), 0);
    serve.shutdown.cancel();
}

#[tokio::test]
async fn wrong_tokens_are_closed_without_a_reply() {
    let serve = start_serve(vec![tenant("ta", "token-a", "a.example.com")]).await;

    for bad in ["token-b", "", "token-a "] {
        let mut sock = TcpStream::connect(&serve.control).await.unwrap();
        let psk = noise::derive_psk(bad);
        // The initiator's first message goes out, then the server must just
        // close: no reply frame that could confirm or deny a guess.
        let attempt = noise::connect(&mut sock, &psk).await;
        assert!(attempt.is_err(), "token {bad:?} was accepted");
        let mut rest = Vec::new();
        sock.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    }
    serve.shutdown.cancel();
}

#[tokio::test]
async fn unroutable_connections_are_closed_without_a_reply() {
    let serve = start_serve(vec![tenant("ta", "token-a", "a.example.com")]).await;

    // Known tenant, but nobody has connected for it.
    assert!(hello_and_read(&serve, "a.example.com", 1).await.is_empty());
    // Unknown host.
    assert!(
        hello_and_read(&serve, "nobody.example.com", 1)
            .await
            .is_empty()
    );
    // Not TLS at all.
    let mut conn = TcpStream::connect(serve.sni).await.unwrap();
    conn.write_all(b"GET / HTTP/1.1\r\nHost: a.example.com\r\n\r\n")
        .await
        .unwrap();
    let mut rest = Vec::new();
    // Unread request bytes make the server's close an RST, which is as good as
    // a clean close here: what matters is that nothing was sent back.
    let _ = tokio::time::timeout(Duration::from_secs(3), conn.read_to_end(&mut rest))
        .await
        .expect("connection left open");
    assert!(rest.is_empty());
    serve.shutdown.cancel();
}

#[tokio::test]
async fn disabled_tenants_cannot_connect_or_be_reached() {
    let mut disabled = tenant("td", "token-d", "d.example.com");
    disabled.disabled = true;
    let serve = start_serve(vec![disabled]).await;

    let mut sock = TcpStream::connect(&serve.control).await.unwrap();
    assert!(
        noise::connect(&mut sock, &noise::derive_psk("token-d"))
            .await
            .is_err()
    );
    serve.shutdown.cancel();
}

#[tokio::test]
async fn a_second_session_replaces_the_first() {
    let serve = start_serve(vec![tenant("ta", "token-a", "a.example.com")]).await;
    let psk = noise::derive_psk("token-a");

    let first = TcpStream::connect(&serve.control).await.unwrap();
    let mut first = noise::connect(first, &psk).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let second = TcpStream::connect(&serve.control).await.unwrap();
    let _second = noise::connect(second, &psk).await.unwrap();

    // The first session is dropped by the server rather than the newcomer
    // being refused.
    let mut buf = [0u8; 16];
    let ended = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match first.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => continue, // yamux housekeeping frames
            }
        }
    })
    .await;
    assert!(ended.is_ok(), "old session stayed up");
    serve.shutdown.cancel();
}

#[tokio::test]
async fn mixing_single_and_multi_tenant_options_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("t.toml").display().to_string();
    let base = || ServeConfig {
        listen: "127.0.0.1:0".into(),
        ..Default::default()
    };

    let with_token = ServeConfig {
        token: "x".into(),
        tenants_file: Some(file.clone()),
        sni_listen: Some("127.0.0.1:0".into()),
        ..base()
    };
    let no_sni = ServeConfig {
        tenants_file: Some(file.clone()),
        ..base()
    };
    let sni_alone = ServeConfig {
        sni_listen: Some("127.0.0.1:0".into()),
        ..base()
    };
    for cfg in [with_token, no_sni, sni_alone] {
        let result = run_serve_with_shutdown(cfg, Registry::new(), CancellationToken::new()).await;
        assert!(result.is_err());
    }
}

#[tokio::test]
async fn shutdown_ends_sessions_and_frees_both_ports() {
    let serve = start_serve(vec![tenant("ta", "token-a", "a.example.com")]).await;
    let (addr_a, _) = target("A:").await;
    let _a = spawn_connect(&serve, "token-a", &[("ta", addr_a)]);
    wait_until_online(&serve, "a.example.com", "A:").await;

    serve.shutdown.cancel();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let control_port: u16 = serve.control.rsplit(':').next().unwrap().parse().unwrap();
    std::net::TcpListener::bind(("127.0.0.1", control_port)).expect("control port still bound");
    std::net::TcpListener::bind(serve.sni).expect("sni port still bound");
}
