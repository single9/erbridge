//! Low-latency bidirectional byte pumping shared by direct-forward and
//! reverse-tunnel data paths, with live-updating byte counters for the TUI.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// 16 KiB keeps a single read/write syscall pair cheap while still
/// amortizing overhead; matches yamux's own default frame split size so
/// tunnelled streams don't get fragmented further downstream.
const BUF_SIZE: usize = 16 * 1024;

async fn pump<R, W>(mut r: R, mut w: W, counter: Arc<AtomicU64>) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; BUF_SIZE];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            let _ = w.shutdown().await;
            return Ok(());
        }
        w.write_all(&buf[..n]).await?;
        counter.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// Splices `a` and `b` together in both directions concurrently, updating
/// `a_to_b`/`b_to_a` as bytes move so a live dashboard can show progress
/// mid-transfer rather than only a final total. Returns once both
/// directions have finished (or one has errored).
pub async fn pipe_bidirectional_tracked<A, B>(
    a: A,
    b: B,
    a_to_b: Arc<AtomicU64>,
    b_to_a: Arc<AtomicU64>,
) -> io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (ar, aw) = tokio::io::split(a);
    let (br, bw) = tokio::io::split(b);
    let t1 = tokio::spawn(pump(ar, bw, a_to_b));
    let t2 = tokio::spawn(pump(br, aw, b_to_a));
    let (r1, r2) = tokio::join!(t1, t2);
    r1.unwrap_or_else(|e| Err(io::Error::other(e)))?;
    r2.unwrap_or_else(|e| Err(io::Error::other(e)))?;
    Ok(())
}
