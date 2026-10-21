//! Reverse tunnel: A (`serve`) listens for an external client's traffic and
//! for B (`connect`) to dial in; once B is connected, A multiplexes every
//! external connection as a yamux stream over the single A<->B link, and B
//! dials the locally-configured target for each stream it receives.
//!
//! Wire protocol over the TLS-wrapped control connection:
//!   1. B writes a length-prefixed token frame; A replies with one byte,
//!      `1` (accepted) or `0` (rejected, connection then closes).
//!   2. Both sides start yamux on the same connection: A as `Mode::Client`
//!      (it is the side that opens new streams), B as `Mode::Server`.
//!   3. For every new external client, A opens a yamux stream and writes a
//!      length-prefixed tunnel-name frame identifying which `[[connect.tunnel]]`
//!      entry on B should receive it; B reads that frame, resolves the target,
//!      and dials it.
//!   4. B replies with one byte, `1` (target connected) or `0` (dial failed),
//!      and the rest of the stream is then piped unmodified. B must send this
//!      before any payload: it is what carries yamux's stream ACK, and without
//!      it a target that waits for the client to speak first would leave
//!      streams unacknowledged and cap the tunnel at yamux's 256-stream ack
//!      backlog.
//!
//! Only A's *response* direction waits for that byte, because it has to be
//! consumed rather than delivered to the external client. A forwards the
//! client's request as soon as it arrives; gating that direction too would put
//! a full A<->B round trip in front of every new connection.

pub mod connect;
pub mod serve;

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) const MAX_TOKEN_LEN: usize = 4096;
const MAX_NAME_LEN: usize = 256;

pub(crate) async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> io::Result<()> {
    let len: u16 = data
        .len()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(data).await?;
    w.flush().await
}

pub(crate) async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    max_len: usize,
) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    r.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len > max_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Compares two byte strings in time proportional only to their length, not
/// to the position of the first mismatch, so a failed token check does not
/// leak timing information about how much of the token was guessed correctly.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
