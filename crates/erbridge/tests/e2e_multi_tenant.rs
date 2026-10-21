//! Drives the real `erbridge` binary through a multi-tenant lifecycle: issue a
//! code, serve, enroll, connect, reach the tenant with a TLS client by SNI,
//! then revoke it.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use erbridge_core::reverse::enroll::Credentials;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const BIN: &str = env!("CARGO_BIN_EXE_erbridge");

/// A long-running child that is killed and reaped when dropped, so a failing
/// test never leaves a stray server behind.
struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Runs a one-shot command to completion and returns (success, stdout, stderr).
fn run(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(BIN).args(args).output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
        String::from_utf8_lossy(&out.stderr).trim().to_string(),
    )
}

fn spawn(log: &Path, args: &[&str]) -> Proc {
    let child = Command::new(BIN)
        .args(["--headless", "--log-file"])
        .arg(log)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    Proc(child)
}

async fn wait_for_port(addr: &str) {
    for _ in 0..100 {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{addr} never started listening");
}

/// A TLS server that answers each read with `T:` followed by what it read.
async fn tls_target() -> SocketAddr {
    erbridge_core::tls::install_crypto_provider();
    let cert = erbridge_core::tls::generate_self_signed().unwrap();
    let acceptor =
        tokio_rustls::TlsAcceptor::from(erbridge_core::tls::server_tls_config(&cert).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                continue;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = vec![0u8; 4096];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let mut reply = b"T:".to_vec();
                    reply.extend_from_slice(&buf[..n]);
                    if stream.write_all(&reply).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

async fn tls_exchange(sni_addr: &str, sni: &str, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    erbridge_core::tls::install_crypto_provider();
    let attempt = async {
        let connector =
            tokio_rustls::TlsConnector::from(erbridge_core::tls::client_tls_config().unwrap());
        let tcp = TcpStream::connect(sni_addr).await?;
        let name = rustls_pki_types::ServerName::try_from(sni.to_string()).unwrap();
        let mut stream = connector.connect(name, tcp).await?;
        stream.write_all(payload).await?;
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await?;
        buf.truncate(n);
        Ok(buf)
    };
    tokio::time::timeout(Duration::from_secs(3), attempt)
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "timed out"))?
}

async fn eventually_ok(sni_addr: &str, sni: &str, payload: &[u8]) -> Vec<u8> {
    for _ in 0..60 {
        if let Ok(reply) = tls_exchange(sni_addr, sni, payload).await {
            return reply;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no TLS reply from {sni}");
}

#[tokio::test]
async fn issue_serve_enroll_connect_reach_and_revoke() {
    let dir = tempfile::tempdir().unwrap();
    let tenants: PathBuf = dir.path().join("tenants.toml");
    let creds = dir.path().join("credentials.toml");
    let (control, sni) = (
        format!("127.0.0.1:{}", free_port()),
        format!("127.0.0.1:{}", free_port()),
    );
    let tenants_s = tenants.to_str().unwrap();

    // 1. An operator issues a code before the server even starts.
    let (ok, code, err) = run(&[
        "serve-admin",
        "--tenants",
        tenants_s,
        "issue",
        "--sni",
        "bin.example.com",
        "--expires-in",
        "600",
    ]);
    assert!(ok, "{err}");
    assert_eq!(code.len(), 32);

    // 2. The server starts against that file.
    let _serve = spawn(
        &dir.path().join("serve.log"),
        &[
            "serve",
            "--listen",
            &control,
            "--tenants",
            tenants_s,
            "--sni-listen",
            &sni,
        ],
    );
    wait_for_port(&control).await;
    wait_for_port(&sni).await;

    // 3. A user enrolls with the code.
    let (ok, _, err) = run(&[
        "enroll",
        "--server",
        &control,
        "--code",
        &code,
        "--out",
        creds.to_str().unwrap(),
    ]);
    assert!(ok, "{err}");
    let parsed = Credentials::from_toml(&std::fs::read_to_string(&creds).unwrap()).unwrap();
    let name = parsed.name.clone();
    assert_eq!(parsed.sni, "bin.example.com");
    assert!(!parsed.token.is_empty());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&creds).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    // Credentials are never overwritten, and a spent code does not work twice.
    let creds_s = creds.to_str().unwrap();
    assert!(
        !run(&[
            "enroll", "--server", &control, "--code", &code, "--out", creds_s
        ])
        .0
    );

    // 4. The user connects, and a TLS client reaches their target by SNI.
    let target = tls_target().await;
    let _connect = spawn(
        &dir.path().join("connect.log"),
        &[
            "connect",
            "--server",
            &control,
            "--credentials",
            creds_s,
            "--target",
            &target.to_string(),
        ],
    );
    assert_eq!(
        eventually_ok(&sni, "bin.example.com", b"hello").await,
        b"T:hello"
    );

    // 5. It shows up in the listing, and revoking it cuts it off.
    let (ok, listing, _) = run(&["serve-admin", "--tenants", tenants_s, "list"]);
    assert!(
        ok && listing.contains(&name) && listing.contains("1 tenant(s)"),
        "{listing}"
    );

    let (ok, _, err) = run(&["serve-admin", "--tenants", tenants_s, "revoke", &name]);
    assert!(ok, "{err}");
    let mut cut_off = false;
    for _ in 0..60 {
        if tls_exchange(&sni, "bin.example.com", b"again")
            .await
            .is_err()
        {
            cut_off = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(cut_off, "tenant still reachable after revoke");
}

#[tokio::test]
async fn bad_codes_and_mixed_options_fail_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let tenants = dir.path().join("tenants.toml");
    let tenants_s = tenants.to_str().unwrap();
    let (control, sni) = (
        format!("127.0.0.1:{}", free_port()),
        format!("127.0.0.1:{}", free_port()),
    );

    // Mixing single- and multi-tenant options is refused up front.
    let (ok, _, err) = run(&[
        "--headless",
        "--log-file",
        dir.path().join("l.log").to_str().unwrap(),
        "serve",
        "--listen",
        &control,
        "--token",
        "x",
        "--tenants",
        tenants_s,
        "--sni-listen",
        &sni,
    ]);
    assert!(!ok);
    assert!(err.contains("tenants_file"), "{err}");

    // A made-up code is refused by a running server.
    let _serve = spawn(
        &dir.path().join("serve.log"),
        &[
            "serve",
            "--listen",
            &control,
            "--tenants",
            tenants_s,
            "--sni-listen",
            &sni,
        ],
    );
    wait_for_port(&control).await;
    let out = dir.path().join("c.toml");
    let (ok, _, err) = run(&[
        "enroll",
        "--server",
        &control,
        "--code",
        "not-a-real-code",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(!ok);
    assert!(!err.is_empty());
    assert!(!out.exists(), "no credentials file on failure");

    // serve-admin needs to know where the file is.
    let (ok, _, err) = run(&["serve-admin", "list"]);
    assert!(!ok);
    assert!(err.contains("tenant file"), "{err}");
}
