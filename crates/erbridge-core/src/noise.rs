//! Noise-protocol transport for connections that are always erbridge-to-
//! erbridge: the `serve`/`connect` control channel, and `forward`/`client`
//! mappings configured with `transport = "noise"`.
//!
//! Handshake pattern is `Noise_NNpsk0`: no static keys (there is no identity
//! to speak of beyond "knows the token"), with the token mixed in as a
//! pre-shared symmetric key rather than checked afterward in a plaintext
//! frame the way the TLS transport does. The PSK is mixed in before the
//! first message, so a mismatched PSK fails AEAD tag verification on the
//! very first handshake message the responder reads -- there is no separate
//! "token rejected" reply frame; the connection just closes, the same as it
//! would on any other handshake or network failure. This avoids giving a
//! remote peer a wire-level oracle purpose-built to confirm or deny a
//! guessed token.
//!
//! Wire format for both the handshake and the transport phase is the same
//! length-prefixed frame `reverse::{read_frame, write_frame}` already use
//! elsewhere in this codebase.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::{Context as _, Result};
use sha2::{Digest, Sha256};
use snow::{Builder, HandshakeState, TransportState};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::reverse::{read_frame, write_frame};

const NOISE_PATTERN: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";

/// Noise caps a single transport message at 65535 bytes, 16 of which are the
/// authentication tag, leaving this much room for plaintext.
const MAX_PLAINTEXT: usize = 65535 - 16;
const MAX_MESSAGE: usize = 65535;

/// A 32-byte Noise pre-shared key.
///
/// A distinct type so a PSK cannot be mistaken for any other 32 bytes, cannot
/// be printed by accident ([`Debug`] redacts it), and is always compared in
/// constant time.
#[derive(Clone, Copy)]
pub struct Psk([u8; 32]);

impl Psk {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq for Psk {
    fn eq(&self, other: &Self) -> bool {
        crate::reverse::constant_time_eq(&self.0, &other.0)
    }
}

impl Eq for Psk {}

impl std::hash::Hash for Psk {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl std::fmt::Debug for Psk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Psk(<redacted>)")
    }
}

/// Stored as 64 lowercase hex characters, the form of the tenant file.
impl serde::Serialize for Psk {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut out = String::with_capacity(64);
        for b in &self.0 {
            out.push_str(&format!("{b:02x}"));
        }
        s.serialize_str(&out)
    }
}

impl<'de> serde::Deserialize<'de> for Psk {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let text = String::deserialize(d)?;
        if text.len() != 64 || !text.is_ascii() {
            return Err(D::Error::custom("psk must be 64 hex characters"));
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
                .map_err(|_| D::Error::custom("psk must be 64 hex characters"))?;
        }
        Ok(Self(out))
    }
}

/// Derives a Noise PSK from an operator-facing token of any length.
pub fn derive_psk(token: &str) -> Psk {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    Psk(hasher.finalize().into())
}

fn to_io_err(e: snow::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

/// Runs the initiator side of the handshake over `io` and returns a
/// transport-mode stream. Used by `connect` (dialling `serve`) and `client`
/// (dialling a `transport = "noise"` forward mapping).
pub async fn connect<T>(mut io: T, psk: &Psk) -> Result<NoiseStream<T>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let params = NOISE_PATTERN.parse().expect("valid static Noise params");
    let mut hs = Builder::new(params)
        .psk(0, psk.as_bytes())
        .context("configuring Noise PSK")?
        .build_initiator()
        .context("building Noise initiator")?;

    let mut buf = vec![0u8; MAX_MESSAGE];
    let len = hs
        .write_message(&[], &mut buf)
        .context("writing Noise handshake message 1")?;
    write_frame(&mut io, &buf[..len])
        .await
        .context("sending Noise handshake message 1")?;

    let msg = read_frame(&mut io, MAX_MESSAGE)
        .await
        .context("reading Noise handshake message 2")?;
    hs.read_message(&msg, &mut buf)
        .context("processing Noise handshake message 2")?;

    let transport = hs
        .into_transport_mode()
        .context("entering Noise transport mode")?;
    Ok(NoiseStream::new(io, transport))
}

/// Runs the responder side of the handshake over `io` and returns a
/// transport-mode stream. Used by `serve` (accepting `connect`) and `forward`
/// (accepting a client on a `transport = "noise"` mapping).
pub async fn accept<T>(io: T, psk: &Psk) -> Result<NoiseStream<T>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let (stream, _) = accept_any(io, std::slice::from_ref(psk)).await?;
    Ok(stream)
}

/// Like [`accept`], but for a responder that does not know in advance which of
/// several PSKs the initiator holds. Reads handshake message 1 once, then tries
/// each candidate on a fresh responder; the one whose AEAD tag verifies wins and
/// its index is returned alongside the stream.
///
/// Every candidate is tried even after a match, so the time taken does not
/// reveal the matching position. On no match the connection is dropped without
/// a reply, exactly as for a single wrong PSK.
pub async fn accept_any<T>(mut io: T, psks: &[Psk]) -> Result<(NoiseStream<T>, usize)>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let msg = read_frame(&mut io, MAX_MESSAGE)
        .await
        .context("reading Noise handshake message 1")?;

    let mut buf = vec![0u8; MAX_MESSAGE];
    let mut matched: Option<(usize, HandshakeState)> = None;
    for (index, psk) in psks.iter().enumerate() {
        let params = NOISE_PATTERN.parse().expect("valid static Noise params");
        let mut hs = Builder::new(params)
            .psk(0, psk.as_bytes())
            .context("configuring Noise PSK")?
            .build_responder()
            .context("building Noise responder")?;
        if hs.read_message(&msg, &mut buf).is_ok() && matched.is_none() {
            matched = Some((index, hs));
        }
    }
    let (index, mut hs) = matched.context("processing Noise handshake message 1")?;

    let len = hs
        .write_message(&[], &mut buf)
        .context("writing Noise handshake message 2")?;
    write_frame(&mut io, &buf[..len])
        .await
        .context("sending Noise handshake message 2")?;

    let transport = hs
        .into_transport_mode()
        .context("entering Noise transport mode")?;
    Ok((NoiseStream::new(io, transport), index))
}

/// Accumulates an incoming length-prefixed ciphertext frame across however
/// many `poll_read` calls on the underlying transport it takes. `body_buf`
/// is allocated once at `MAX_MESSAGE` and reused for every frame -- only its
/// `[..body_len]` prefix is meaningful once a frame completes.
struct FrameReader {
    len_buf: [u8; 2],
    len_filled: usize,
    have_len: bool,
    body_buf: Vec<u8>,
    body_len: usize,
    body_filled: usize,
}

impl Default for FrameReader {
    fn default() -> Self {
        Self {
            len_buf: [0; 2],
            len_filled: 0,
            have_len: false,
            body_buf: vec![0u8; MAX_MESSAGE],
            body_len: 0,
            body_filled: 0,
        }
    }
}

impl FrameReader {
    /// Drives `inner` until a full ciphertext frame has been read into
    /// `body_buf`, returning its length. `Ok(None)` signals a clean EOF at a
    /// frame boundary (nothing partially read yet) so callers can propagate
    /// it as a normal EOF rather than an error; an EOF mid-frame is a real
    /// error, since the stream closed without finishing a frame it had
    /// already started sending.
    fn poll_frame<T: AsyncRead + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        mut inner: Pin<&mut T>,
    ) -> Poll<io::Result<Option<usize>>> {
        if !self.have_len {
            while self.len_filled < 2 {
                let mut buf = ReadBuf::new(&mut self.len_buf[self.len_filled..]);
                match inner.as_mut().poll_read(cx, &mut buf) {
                    Poll::Ready(Ok(())) => {
                        let n = buf.filled().len();
                        if n == 0 {
                            if self.len_filled == 0 {
                                return Poll::Ready(Ok(None));
                            }
                            return Poll::Ready(Err(truncated()));
                        }
                        self.len_filled += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            self.body_len = u16::from_be_bytes(self.len_buf) as usize;
            self.body_filled = 0;
            self.have_len = true;
        }

        while self.body_filled < self.body_len {
            let mut buf = ReadBuf::new(&mut self.body_buf[self.body_filled..self.body_len]);
            match inner.as_mut().poll_read(cx, &mut buf) {
                Poll::Ready(Ok(())) => {
                    let n = buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(truncated()));
                    }
                    self.body_filled += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        self.have_len = false;
        self.len_filled = 0;
        Poll::Ready(Ok(Some(self.body_len)))
    }
}

fn truncated() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "noise stream closed mid-frame",
    )
}

/// Buffers an encrypted, framed message until it has been fully written to
/// the underlying transport. `buf` is allocated once at `2 + MAX_MESSAGE`
/// (header + largest possible ciphertext) and reused for every frame; `len`
/// tracks how much of it is meaningful for the frame currently in flight.
struct FrameWriter {
    buf: Vec<u8>,
    len: usize,
    sent: usize,
}

impl Default for FrameWriter {
    fn default() -> Self {
        Self {
            buf: vec![0u8; 2 + MAX_MESSAGE],
            len: 0,
            sent: 0,
        }
    }
}

impl FrameWriter {
    fn is_pending(&self) -> bool {
        self.sent < self.len
    }

    /// Tries to push as much of the buffered frame as possible into `inner`
    /// without blocking. Returns `Ready(Ok(()))` once fully flushed.
    fn poll_drain<T: AsyncWrite + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        mut inner: Pin<&mut T>,
    ) -> Poll<io::Result<()>> {
        while self.is_pending() {
            match inner
                .as_mut()
                .poll_write(cx, &self.buf[self.sent..self.len])
            {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write noise frame",
                    )));
                }
                Poll::Ready(Ok(n)) => self.sent += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

/// An `AsyncRead + AsyncWrite` adapter that speaks Noise transport messages
/// over an inner stream, so it drops into the same code paths (`mux::spawn`,
/// `proxy::pipe_bidirectional_tracked`) that the TLS transport uses today.
/// All buffers are allocated once at construction and reused for the life of
/// the stream -- steady-state reads/writes do no heap allocation.
pub struct NoiseStream<T> {
    inner: T,
    transport: TransportState,
    reader: FrameReader,
    plaintext_buf: Vec<u8>,
    plaintext_len: usize,
    plaintext_pos: usize,
    writer: FrameWriter,
}

impl<T> NoiseStream<T> {
    fn new(inner: T, transport: TransportState) -> Self {
        Self {
            inner,
            transport,
            reader: FrameReader::default(),
            plaintext_buf: vec![0u8; MAX_MESSAGE],
            plaintext_len: 0,
            plaintext_pos: 0,
            writer: FrameWriter::default(),
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for NoiseStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.plaintext_pos < this.plaintext_len {
                let available = &this.plaintext_buf[this.plaintext_pos..this.plaintext_len];
                let n = available.len().min(buf.remaining());
                buf.put_slice(&available[..n]);
                this.plaintext_pos += n;
                return Poll::Ready(Ok(()));
            }

            let ciphertext_len = match this.reader.poll_frame(cx, Pin::new(&mut this.inner)) {
                Poll::Ready(Ok(Some(len))) => len,
                Poll::Ready(Ok(None)) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };

            let plain_len = this
                .transport
                .read_message(
                    &this.reader.body_buf[..ciphertext_len],
                    &mut this.plaintext_buf,
                )
                .map_err(to_io_err)?;
            this.plaintext_len = plain_len;
            this.plaintext_pos = 0;
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for NoiseStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if this.writer.is_pending() {
            match this.writer.poll_drain(cx, Pin::new(&mut this.inner)) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let chunk_len = buf.len().min(MAX_PLAINTEXT);

        let cipher_len = this
            .transport
            .write_message(&buf[..chunk_len], &mut this.writer.buf[2..])
            .map_err(to_io_err)?;
        this.writer.buf[..2].copy_from_slice(&(cipher_len as u16).to_be_bytes());
        this.writer.len = 2 + cipher_len;
        this.writer.sent = 0;

        // Best-effort immediate drain, matching tokio-rustls: callers here
        // (`proxy::pump`) only flush at EOF via shutdown, so data must go out
        // during poll_write on an unbacked-up socket rather than waiting for
        // an explicit flush that may never come until then.
        match this.writer.poll_drain(cx, Pin::new(&mut this.inner)) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) | Poll::Pending => {}
        }

        Poll::Ready(Ok(chunk_len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.writer.is_pending() {
            match this.writer.poll_drain(cx, Pin::new(&mut this.inner)) {
                Poll::Ready(Ok(())) => {}
                other => return other,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.writer.is_pending() {
            match this.writer.poll_drain(cx, Pin::new(&mut this.inner)) {
                Poll::Ready(Ok(())) => {}
                other => return other,
            }
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn handshake_and_round_trip_with_matching_psk() {
        let (a, b) = tokio::io::duplex(4096);
        let psk = derive_psk("shared-secret");

        let (mut initiator, mut responder) =
            tokio::try_join!(connect(a, &psk), accept(b, &psk)).unwrap();

        initiator.write_all(b"hello from initiator").await.unwrap();
        let mut buf = [0u8; 20];
        responder.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello from initiator");

        responder.write_all(b"hello back").await.unwrap();
        let mut buf = [0u8; 10];
        initiator.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello back");
    }

    #[tokio::test]
    async fn accept_any_identifies_which_psk_matched() {
        let psks = [derive_psk("one"), derive_psk("two"), derive_psk("three")];
        for (expected, token) in ["one", "two", "three"].iter().enumerate() {
            let (a, b) = tokio::io::duplex(4096);
            let client_psk = derive_psk(token);
            let ((mut initiator, _), (mut responder, index)) = tokio::try_join!(
                async { Ok::<_, anyhow::Error>((connect(a, &client_psk).await?, ())) },
                async { accept_any(b, &psks).await.map(|r| (r.0, r.1)) },
            )
            .unwrap();
            assert_eq!(index, expected);

            initiator.write_all(b"ping").await.unwrap();
            let mut buf = [0u8; 4];
            responder.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
        }
    }

    #[tokio::test]
    async fn accept_any_with_no_match_fails_and_writes_nothing() {
        let (mut a, b) = tokio::io::duplex(4096);
        let psks = [derive_psk("one"), derive_psk("two")];
        let wrong = derive_psk("nope");

        // Drive the initiator's first message by hand so the socket can be
        // inspected afterwards.
        let params = NOISE_PATTERN.parse().unwrap();
        let mut hs = Builder::new(params)
            .psk(0, wrong.as_bytes())
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut buf = vec![0u8; MAX_MESSAGE];
        let len = hs.write_message(&[], &mut buf).unwrap();
        write_frame(&mut a, &buf[..len]).await.unwrap();

        assert!(accept_any(b, &psks).await.is_err());

        // `b` was consumed and dropped by the failed accept; the peer must see
        // a plain close, not a reply frame.
        let mut rest = Vec::new();
        a.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty(), "server replied to an unknown PSK");
    }

    #[tokio::test]
    async fn accept_any_with_empty_candidates_fails() {
        let (a, b) = tokio::io::duplex(4096);
        let psk = derive_psk("x");
        let (client, server) = tokio::join!(connect(a, &psk), accept_any(b, &[]));
        assert!(server.is_err());
        assert!(client.is_err());
    }

    #[tokio::test]
    async fn large_write_is_chunked_and_reassembled() {
        let (a, b) = tokio::io::duplex(1 << 20);
        let psk = derive_psk("shared-secret");
        let (mut initiator, mut responder) =
            tokio::try_join!(connect(a, &psk), accept(b, &psk)).unwrap();

        let payload = vec![0xABu8; MAX_PLAINTEXT * 3 + 17];
        let write_payload = payload.clone();
        let writer = tokio::spawn(async move {
            initiator.write_all(&write_payload).await.unwrap();
            initiator.flush().await.unwrap();
        });

        let mut received = vec![0u8; payload.len()];
        responder.read_exact(&mut received).await.unwrap();
        writer.await.unwrap();
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn clean_shutdown_propagates_as_eof_not_error() {
        let (a, b) = tokio::io::duplex(4096);
        let psk = derive_psk("shared-secret");
        let (mut initiator, mut responder) =
            tokio::try_join!(connect(a, &psk), accept(b, &psk)).unwrap();

        initiator.write_all(b"done").await.unwrap();
        AsyncWriteExt::shutdown(&mut initiator).await.unwrap();

        let mut out = Vec::new();
        responder.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"done");
    }

    #[tokio::test]
    async fn mismatched_psk_fails_handshake() {
        let (a, b) = tokio::io::duplex(4096);
        let psk_a = derive_psk("token-a");
        let psk_b = derive_psk("token-b");

        // The PSK is mixed in before message 1, so the responder's AEAD tag
        // check on that very first message fails -- no application data ever
        // has to flow for a mismatched token to be caught.
        let (initiator_result, responder_result) =
            tokio::join!(connect(a, &psk_a), accept(b, &psk_b));
        assert!(responder_result.is_err());
        assert!(initiator_result.is_err());
    }
}
