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
use erbridge_core::reverse::tenant_serve::{TenantServeConfig, run_tenant_serve_with_store};
use erbridge_core::stats::Registry;
use erbridge_core::tenant::{Tenant, TenantSet};
use erbridge_core::tenant_store::{FileStore, TenantStore};
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

/// Like `start_serve`, but through the store-backed entry point with a fast
/// reload interval, so tests of live changes do not wait a second for each.
async fn start_serve_fast_reload(tenants: Vec<Tenant>) -> (Serve, FileStore) {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("tenants.toml");
    let store = FileStore::new(&file);
    for t in tenants {
        store.add_tenant(t).unwrap();
    }

    let control_port = common::free_port();
    let sni_port = common::free_port();
    let shutdown = CancellationToken::new();
    let cfg = TenantServeConfig {
        listen: format!("127.0.0.1:{control_port}"),
        sni_listen: format!("127.0.0.1:{sni_port}"),
        reload_interval: Duration::from_millis(50),
    };
    tokio::spawn(run_tenant_serve_with_store(
        cfg,
        Arc::new(FileStore::new(&file)),
        Registry::new(),
        shutdown.clone(),
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let serve = Serve {
        control: format!("127.0.0.1:{control_port}"),
        sni: format!("127.0.0.1:{sni_port}").parse().unwrap(),
        file,
        shutdown,
        _dir: dir,
    };
    (serve, store)
}

async fn wait_until_offline(serve: &Serve, host: &str) {
    for _ in 0..50 {
        if hello_and_read(serve, host, 1).await.is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("tenant at {host} never went offline");
}

#[tokio::test]
async fn adding_a_tenant_while_serving_needs_no_restart() {
    let (serve, store) = start_serve_fast_reload(vec![]).await;
    let (addr, _) = target("N:").await;
    let _c = spawn_connect(&serve, "token-n", &[("tn", addr)]);

    // Nobody by that name yet: the connect keeps retrying and is refused.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(hello_and_read(&serve, "n.example.com", 1).await.is_empty());

    store
        .add_tenant(tenant("tn", "token-n", "n.example.com"))
        .unwrap();
    wait_until_online(&serve, "n.example.com", "N:").await;
    serve.shutdown.cancel();
}

#[tokio::test]
async fn revoking_one_tenant_leaves_the_others_connections_alone() {
    let (serve, store) = start_serve_fast_reload(vec![
        tenant("ta", "token-a", "a.example.com"),
        tenant("tb", "token-b", "b.example.com"),
    ])
    .await;
    let (addr_a, _) = target("A:").await;
    let (addr_b, _) = target("B:").await;
    let _a = spawn_connect(&serve, "token-a", &[("ta", addr_a)]);
    let _b = spawn_connect(&serve, "token-b", &[("tb", addr_b)]);
    wait_until_online(&serve, "a.example.com", "A:").await;
    wait_until_online(&serve, "b.example.com", "B:").await;

    // A connection to B that stays open across the revocation.
    let mut held = TcpStream::connect(serve.sni).await.unwrap();
    held.write_all(&common::client_hello("b.example.com"))
        .await
        .unwrap();
    let mut buf = vec![0u8; 4096];
    assert!(held.read(&mut buf).await.unwrap() > 0);

    store.revoke("ta").unwrap();
    wait_until_offline(&serve, "a.example.com").await;

    held.write_all(b"still there").await.unwrap();
    let n = tokio::time::timeout(Duration::from_secs(3), held.read(&mut buf))
        .await
        .expect("B's connection stalled")
        .unwrap();
    assert!(buf[..n].starts_with(b"B:still there"));
    assert!(
        hello_and_read(&serve, "b.example.com", 2)
            .await
            .starts_with(b"B:")
    );
    serve.shutdown.cancel();
}

#[tokio::test]
async fn disabling_ends_the_session_and_enabling_brings_it_back() {
    let (serve, store) =
        start_serve_fast_reload(vec![tenant("ta", "token-a", "a.example.com")]).await;
    let (addr, _) = target("A:").await;
    let _a = spawn_connect(&serve, "token-a", &[("ta", addr)]);
    wait_until_online(&serve, "a.example.com", "A:").await;

    store.set_disabled("ta", true).unwrap();
    wait_until_offline(&serve, "a.example.com").await;

    store.set_disabled("ta", false).unwrap();
    wait_until_online(&serve, "a.example.com", "A:").await;
    serve.shutdown.cancel();
}

#[tokio::test]
async fn rotating_a_tenants_token_ends_the_old_session() {
    let (serve, store) =
        start_serve_fast_reload(vec![tenant("ta", "old-token", "a.example.com")]).await;
    let (addr, _) = target("A:").await;
    let _old = spawn_connect(&serve, "old-token", &[("ta", addr)]);
    wait_until_online(&serve, "a.example.com", "A:").await;

    store
        .replace_with(&mut |set| {
            set.without_tenant("ta")?
                .with_tenant(tenant("ta", "new-token", "a.example.com"))
        })
        .unwrap();
    wait_until_offline(&serve, "a.example.com").await;

    let _new = spawn_connect(&serve, "new-token", &[("ta", addr)]);
    wait_until_online(&serve, "a.example.com", "A:").await;
    serve.shutdown.cancel();
}

#[tokio::test]
async fn a_corrupt_file_keeps_the_previous_tenants_until_it_is_fixed() {
    let (serve, store) =
        start_serve_fast_reload(vec![tenant("tb", "token-b", "b.example.com")]).await;
    let (addr_b, _) = target("B:").await;
    let _b = spawn_connect(&serve, "token-b", &[("tb", addr_b)]);
    wait_until_online(&serve, "b.example.com", "B:").await;

    std::fs::write(&serve.file, "[[tenant]\nbroken").unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        hello_and_read(&serve, "b.example.com", 2)
            .await
            .starts_with(b"B:")
    );

    // Repairing the file with a new tenant added is picked up.
    std::fs::write(
        &serve.file,
        TenantSet::new(
            vec![
                tenant("tb", "token-b", "b.example.com"),
                tenant("tc", "token-c", "c.example.com"),
            ],
            vec![],
        )
        .unwrap()
        .to_toml()
        .unwrap(),
    )
    .unwrap();
    let (addr_c, _) = target("C:").await;
    let _c = spawn_connect(&serve, "token-c", &[("tc", addr_c)]);
    wait_until_online(&serve, "c.example.com", "C:").await;
    let _ = store;
    serve.shutdown.cancel();
}

fn limited(name: &str, token: &str, sni: &str, max_conns: usize) -> Tenant {
    Tenant {
        max_conns,
        ..tenant(name, token, sni)
    }
}

/// Opens a connection to `host` and waits for the first reply, so the relay is
/// known to be established. `None` if the server closed it instead.
async fn open_held(serve: &Serve, host: &str) -> Option<TcpStream> {
    let mut conn = TcpStream::connect(serve.sni).await.unwrap();
    conn.write_all(&common::client_hello(host)).await.unwrap();
    let mut buf = [0u8; 4096];
    match tokio::time::timeout(Duration::from_secs(2), conn.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => Some(conn),
        _ => None,
    }
}

/// `open_held`, retried while earlier probe connections finish closing and
/// give their slots back.
async fn open_held_when_free(serve: &Serve, host: &str) -> TcpStream {
    for _ in 0..30 {
        if let Some(conn) = open_held(serve, host).await {
            return conn;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no connection slot became free for {host}");
}

#[tokio::test]
async fn connections_beyond_max_conns_are_closed_and_a_freed_slot_is_reusable() {
    let (serve, _store) = start_serve_fast_reload(vec![
        limited("ta", "token-a", "a.example.com", 2),
        limited("tb", "token-b", "b.example.com", 2),
    ])
    .await;
    let (addr_a, _) = target("A:").await;
    let (addr_b, _) = target("B:").await;
    let _a = spawn_connect(&serve, "token-a", &[("ta", addr_a)]);
    let _b = spawn_connect(&serve, "token-b", &[("tb", addr_b)]);
    wait_until_online(&serve, "a.example.com", "A:").await;
    wait_until_online(&serve, "b.example.com", "B:").await;

    let first = open_held_when_free(&serve, "a.example.com").await;
    let _second = open_held_when_free(&serve, "a.example.com").await;
    assert!(
        open_held(&serve, "a.example.com").await.is_none(),
        "third connection should be refused"
    );

    // Another tenant has its own budget.
    assert!(open_held(&serve, "b.example.com").await.is_some());

    // Freeing a slot makes room again.
    drop(first);
    let mut reused = None;
    for _ in 0..30 {
        reused = open_held(&serve, "a.example.com").await;
        if reused.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(reused.is_some(), "slot was never freed");
    serve.shutdown.cancel();
}

#[tokio::test]
async fn a_changed_limit_applies_to_new_connections_after_reload() {
    let (serve, store) =
        start_serve_fast_reload(vec![limited("ta", "token-a", "a.example.com", 1)]).await;
    let (addr, _) = target("A:").await;
    let _a = spawn_connect(&serve, "token-a", &[("ta", addr)]);
    wait_until_online(&serve, "a.example.com", "A:").await;

    let _held = open_held_when_free(&serve, "a.example.com").await;
    assert!(open_held(&serve, "a.example.com").await.is_none());

    store
        .replace_with(&mut |set| {
            set.without_tenant("ta")?
                .with_tenant(limited("ta", "token-a", "a.example.com", 3))
        })
        .unwrap();
    // Same name and PSK, so the session survives; give the reload a moment.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _one = open_held_when_free(&serve, "a.example.com").await;
    let _two = open_held_when_free(&serve, "a.example.com").await;
    let _three = open_held_when_free(&serve, "a.example.com").await;
    assert!(open_held(&serve, "a.example.com").await.is_none());
    serve.shutdown.cancel();
}
