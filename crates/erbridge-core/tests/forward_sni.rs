mod common;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use erbridge_core::config::{ForwardRule, ProtocolKind, Transport};
use erbridge_core::forward::run_forward;
use erbridge_core::stats::{Event, Registry};
use rustls::ClientConnection;
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The ClientHello record a real rustls client sends for `name`.
fn client_hello(name: &str) -> Vec<u8> {
    erbridge_core::tls::install_crypto_provider();
    let config = erbridge_core::tls::client_tls_config().unwrap();
    let server_name = ServerName::try_from(name.to_string()).unwrap();
    let mut conn = ClientConnection::new(config, server_name).unwrap();
    let mut out = Vec::new();
    conn.write_tls(&mut out).unwrap();
    out
}

/// A target that answers every connection with `tag` followed by an echo of
/// everything it receives, so a test sees both where it landed and what
/// arrived there.
async fn spawn_tagged_echo(tag: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(stream);
                if w.write_all(tag.as_bytes()).await.is_ok() {
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                }
            });
        }
    });
    addr
}

struct Setup {
    listen: SocketAddr,
    registry: Registry,
    a: String,
}

/// Starts a forward rule routing `a.example.com` to target A and
/// `*.example.net` to target B, with an optional fallback target C.
async fn start(transport: Option<Transport>, with_fallback: bool) -> Setup {
    let a = spawn_tagged_echo("A|").await;
    let b = spawn_tagged_echo("B|").await;
    let c = spawn_tagged_echo("C|").await;
    let listen_port = common::free_port();
    let rule = ForwardRule {
        name: Some("sni".into()),
        listen: format!("127.0.0.1:{listen_port}"),
        target: with_fallback.then_some(c),
        protocol: ProtocolKind::Tcp,
        udp_idle_secs: 60,
        transport,
        token: transport.map(|_| "test-token".into()),
        sni: BTreeMap::from([
            ("a.example.com".into(), a.clone()),
            ("*.example.net".into(), b),
        ]),
    };
    let registry = Registry::new();
    tokio::spawn(run_forward(vec![rule], registry.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;
    Setup {
        listen: format!("127.0.0.1:{listen_port}").parse().unwrap(),
        registry,
        a,
    }
}

/// Sends `payload`, half-closes, and returns everything read back.
async fn roundtrip<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, payload: &[u8]) -> Vec<u8> {
    // A refused or unrouted connection may be reset mid-write; the empty
    // read below is what tests check for.
    let _ = stream.write_all(payload).await;
    let _ = stream.shutdown().await;
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out).await;
    out
}

async fn plain_roundtrip(addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
    roundtrip(TcpStream::connect(addr).await.unwrap(), payload).await
}

fn tagged(tag: &str, body: &[u8]) -> Vec<u8> {
    [tag.as_bytes(), body].concat()
}

#[tokio::test]
async fn routes_by_exact_and_wildcard_sni_and_replays_the_hello() {
    let s = start(None, false).await;

    let hello = client_hello("a.example.com");
    let payload = [hello.as_slice(), b" then app data"].concat();
    assert_eq!(
        plain_roundtrip(s.listen, &payload).await,
        tagged("A|", &payload)
    );

    let hello = client_hello("x.example.net");
    assert_eq!(
        plain_roundtrip(s.listen, &hello).await,
        tagged("B|", &hello)
    );
}

#[tokio::test]
async fn unmatched_sni_goes_to_the_fallback() {
    let s = start(None, true).await;
    let hello = client_hello("other.example.org");
    assert_eq!(
        plain_roundtrip(s.listen, &hello).await,
        tagged("C|", &hello)
    );

    // Wildcards cover one label only, so the apex falls through too.
    let hello = client_hello("example.net");
    assert_eq!(
        plain_roundtrip(s.listen, &hello).await,
        tagged("C|", &hello)
    );
}

#[tokio::test]
async fn unmatched_sni_without_fallback_is_closed() {
    let s = start(None, false).await;
    let hello = client_hello("other.example.org");
    assert!(plain_roundtrip(s.listen, &hello).await.is_empty());
    assert_eq!(s.registry.totals().total_connections, 0);
}

#[tokio::test]
async fn non_tls_input_is_closed() {
    let s = start(None, true).await;
    let out = plain_roundtrip(s.listen, b"GET / HTTP/1.1\r\nHost: a.example.com\r\n\r\n").await;
    assert!(out.is_empty());
}

#[tokio::test]
async fn the_hello_counts_as_inbound_bytes_and_events_record_target_and_sni() {
    let s = start(None, false).await;
    let mut events = s.registry.subscribe();

    let hello = client_hello("A.Example.com");
    plain_roundtrip(s.listen, &hello).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(s.registry.totals().bytes_in, hello.len() as u64);
    let (destination, sni) = opened(&mut events).await;
    assert_eq!(destination, s.a);
    // As the client sent it, not normalized.
    assert_eq!(sni.as_deref(), Some("A.Example.com"));
}

#[tokio::test]
async fn a_fallback_connection_still_records_its_sni() {
    let s = start(None, true).await;
    let mut events = s.registry.subscribe();

    plain_roundtrip(s.listen, &client_hello("other.example.org")).await;
    let (destination, sni) = opened(&mut events).await;
    assert_ne!(destination, s.a);
    assert_eq!(sni.as_deref(), Some("other.example.org"));
}

/// The destination and SNI of the next `ConnectionOpened` event.
async fn opened(events: &mut tokio::sync::broadcast::Receiver<Event>) -> (String, Option<String>) {
    loop {
        if let Event::ConnectionOpened {
            destination, sni, ..
        } = events.recv().await.unwrap()
        {
            return (destination, sni);
        }
    }
}

#[tokio::test]
async fn routes_inside_a_noise_transport() {
    let s = start(Some(Transport::Noise), false).await;
    let psk = erbridge_core::noise::derive_psk("test-token");

    let tcp = TcpStream::connect(s.listen).await.unwrap();
    let stream = erbridge_core::noise::connect(tcp, &psk).await.unwrap();
    let hello = client_hello("y.example.net");
    assert_eq!(roundtrip(stream, &hello).await, tagged("B|", &hello));
}

#[tokio::test]
async fn silent_clients_are_capped_per_address() {
    let s = start(None, true).await;

    // Fill this address's pending slots with clients that never send a
    // ClientHello.
    let mut silent = Vec::new();
    for _ in 0..16 {
        silent.push(TcpStream::connect(s.listen).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The next one is refused at once rather than waiting for the SNI timeout.
    let hello = client_hello("a.example.com");
    let out = tokio::time::timeout(Duration::from_secs(2), plain_roundtrip(s.listen, &hello))
        .await
        .expect("refused connection should close promptly");
    assert!(out.is_empty());

    // Releasing the slots lets new clients through again.
    drop(silent);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        plain_roundtrip(s.listen, &hello).await,
        tagged("A|", &hello)
    );
}
