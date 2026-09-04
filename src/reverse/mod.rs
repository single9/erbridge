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
//!      dials it, and pipes the rest of the stream unmodified.

pub mod connect;
pub mod serve;

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_TOKEN_LEN: usize = 4096;
const MAX_NAME_LEN: usize = 256;

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> io::Result<()> {
    let len: u16 = data
        .len()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(data).await?;
    w.flush().await
}

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R, max_len: usize) -> io::Result<Vec<u8>> {
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
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
