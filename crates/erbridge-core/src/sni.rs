//! Reads the SNI out of a TLS ClientHello without terminating TLS, so a router
//! can pick a destination and then replay the exact bytes it consumed.
//!
//! Only the first TLS record is examined, and the whole ClientHello must fit in
//! it. That holds for every mainstream client (the record limit is 16 KiB and
//! even post-quantum hellos are around 1.5 KiB); a hello fragmented across
//! records is rejected rather than reassembled.

use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt};

const RECORD_HEADER_LEN: usize = 5;
/// TLS plaintext records are at most 2^14 bytes.
const MAX_RECORD_BODY: usize = 16 * 1024;
const HANDSHAKE_RECORD: u8 = 0x16;
const CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0;
const NAME_TYPE_HOST: u8 = 0;

/// What was read from the stream, and the SNI found in it.
#[derive(Debug, PartialEq, Eq)]
pub struct Peeked {
    /// `None` when the hello carries no (usable) server name.
    pub sni: Option<String>,
    /// Every byte consumed from the stream, to be replayed to the destination.
    pub buffered: Vec<u8>,
}

/// Reads one TLS record from `r` and extracts the SNI. Gives up after
/// `timeout`, so a peer that stalls cannot hold the connection open.
pub async fn peek_sni<R: AsyncRead + Unpin>(r: &mut R, timeout: Duration) -> Result<Peeked> {
    tokio::time::timeout(timeout, read_record(r))
        .await
        .context("timed out waiting for a TLS ClientHello")?
        .and_then(|buffered| {
            let sni = parse_record(&buffered)?;
            Ok(Peeked { sni, buffered })
        })
}

async fn read_record<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; RECORD_HEADER_LEN];
    r.read_exact(&mut buf)
        .await
        .context("reading TLS record header")?;
    let body_len = check_header(&buf)?;
    buf.resize(RECORD_HEADER_LEN + body_len, 0);
    r.read_exact(&mut buf[RECORD_HEADER_LEN..])
        .await
        .context("reading TLS record body")?;
    Ok(buf)
}

/// Validates a record header and returns the body length it announces.
fn check_header(header: &[u8]) -> Result<usize> {
    if header[0] != HANDSHAKE_RECORD || header[1] != 3 {
        bail!("not a TLS handshake record");
    }
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if len == 0 || len > MAX_RECORD_BODY {
        bail!("implausible TLS record length {len}");
    }
    Ok(len)
}

/// Extracts the SNI from one complete TLS record (header included). Returns
/// `Ok(None)` for a well-formed hello without a usable host name.
pub fn parse_record(record: &[u8]) -> Result<Option<String>> {
    if record.len() < RECORD_HEADER_LEN {
        bail!("truncated TLS record header");
    }
    let body_len = check_header(&record[..RECORD_HEADER_LEN])?;
    let body = record
        .get(RECORD_HEADER_LEN..RECORD_HEADER_LEN + body_len)
        .context("truncated TLS record")?;
    parse_handshake(body)
}

fn parse_handshake(body: &[u8]) -> Result<Option<String>> {
    let mut r = Reader(body);
    if r.u8()? != CLIENT_HELLO {
        bail!("first handshake message is not a ClientHello");
    }
    let hello_len = r.u24()?;
    let mut hello = Reader(
        r.take(hello_len)
            .context("ClientHello spans several records")?,
    );

    hello.take(2)?; // legacy_version
    hello.take(32)?; // random
    let session_id = hello.u8()? as usize;
    hello.take(session_id)?;
    let suites = hello.u16()? as usize;
    hello.take(suites)?;
    let compression = hello.u8()? as usize;
    hello.take(compression)?;

    if hello.is_empty() {
        return Ok(None); // a hello with no extensions at all
    }
    let ext_len = hello.u16()? as usize;
    let mut exts = Reader(hello.take(ext_len)?);
    while !exts.is_empty() {
        let kind = exts.u16()?;
        let len = exts.u16()? as usize;
        let data = exts.take(len)?;
        if kind == EXT_SERVER_NAME {
            return parse_server_name(data);
        }
    }
    Ok(None)
}

fn parse_server_name(data: &[u8]) -> Result<Option<String>> {
    let mut r = Reader(data);
    let list_len = r.u16()? as usize;
    let mut list = Reader(r.take(list_len)?);
    while !list.is_empty() {
        let name_type = list.u8()?;
        let len = list.u16()? as usize;
        let name = list.take(len)?;
        if name_type == NAME_TYPE_HOST {
            return Ok(host_name(name));
        }
    }
    Ok(None)
}

/// A usable name is a DNS-style ASCII host; IP literals are not valid SNI.
fn host_name(raw: &[u8]) -> Option<String> {
    let name = std::str::from_utf8(raw).ok()?;
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'));
    (valid && name.parse::<IpAddr>().is_err()).then(|| name.to_string())
}

/// Bounds-checked cursor; every read errors instead of panicking.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            bail!("truncated or malformed ClientHello");
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> Result<usize> {
        let b = self.take(3)?;
        Ok(((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::ClientConnection;
    use rustls_pki_types::ServerName;
    use tokio::io::AsyncWriteExt;

    /// The ClientHello record a real rustls client would send for `name`.
    fn client_hello(name: &str) -> Vec<u8> {
        crate::tls::install_crypto_provider();
        let config = crate::tls::client_tls_config().unwrap();
        let server_name = ServerName::try_from(name.to_string()).unwrap();
        let mut conn = ClientConnection::new(config, server_name).unwrap();
        let mut out = Vec::new();
        conn.write_tls(&mut out).unwrap();
        out
    }

    #[test]
    fn extracts_the_sni_from_a_real_client_hello() {
        let hello = client_hello("abc123.example.com");
        assert_eq!(
            parse_record(&hello).unwrap().as_deref(),
            Some("abc123.example.com")
        );
    }

    #[test]
    fn an_ip_literal_yields_no_sni() {
        let hello = client_hello("192.0.2.7");
        assert_eq!(parse_record(&hello).unwrap(), None);
    }

    #[test]
    fn non_tls_and_non_hello_input_is_rejected() {
        assert!(parse_record(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").is_err());
        let mut not_hello = client_hello("a.example.com");
        not_hello[RECORD_HEADER_LEN] = 0x02; // ServerHello
        assert!(parse_record(&not_hello).is_err());
        let mut wrong_type = client_hello("a.example.com");
        wrong_type[0] = 0x17; // application data
        assert!(parse_record(&wrong_type).is_err());
    }

    #[test]
    fn every_truncation_is_an_error_not_a_panic() {
        let hello = client_hello("abc123.example.com");
        for n in 0..hello.len() {
            assert!(parse_record(&hello[..n]).is_err(), "prefix of {n} bytes");
        }
    }

    #[test]
    fn corrupting_any_single_byte_never_panics() {
        let hello = client_hello("abc123.example.com");
        for i in 0..hello.len() {
            for flip in [0x00, 0xff, 0x80, 0x01] {
                let mut bad = hello.clone();
                bad[i] ^= flip;
                let _ = parse_record(&bad);
            }
        }
    }

    #[tokio::test]
    async fn peek_returns_the_consumed_bytes_and_leaves_the_rest() {
        let hello = client_hello("abc123.example.com");
        let (mut tx, mut rx) = tokio::io::duplex(65536);
        tx.write_all(&hello).await.unwrap();
        tx.write_all(b"after the hello").await.unwrap();
        drop(tx);

        let peeked = peek_sni(&mut rx, Duration::from_secs(1)).await.unwrap();
        assert_eq!(peeked.sni.as_deref(), Some("abc123.example.com"));
        assert_eq!(peeked.buffered, hello);

        let mut rest = Vec::new();
        rx.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"after the hello");
    }

    #[tokio::test]
    async fn an_oversized_record_is_rejected_before_its_body_is_read() {
        let (mut tx, mut rx) = tokio::io::duplex(64);
        // Header announcing 65535 bytes; nothing follows.
        tx.write_all(&[0x16, 0x03, 0x01, 0xff, 0xff]).await.unwrap();
        let err = peek_sni(&mut rx, Duration::from_secs(1)).await.unwrap_err();
        assert!(err.to_string().contains("implausible"), "{err:#}");
    }

    #[tokio::test]
    async fn a_silent_peer_times_out() {
        let (_tx, mut rx) = tokio::io::duplex(64);
        let err = peek_sni(&mut rx, Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("timed out"), "{err:#}");
    }
}
