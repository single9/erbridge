//! Thin actor around `yamux::Connection`, which only exposes a raw poll-based
//! API (`poll_new_outbound` / `poll_next_inbound`) with no built-in task-safe
//! handle. This module drives one `Connection` on a dedicated task and hands
//! out a cloneable `MuxControl` for opening outbound streams plus a receiver
//! for inbound ones, so the rest of the code can treat it like a normal
//! multiplexer.

use std::future::poll_fn;
use std::task::Poll;

use futures::StreamExt;
use futures::channel::{mpsc, oneshot};
use futures::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc as tmpsc;
use yamux::{Connection, ConnectionError, Stream};

pub use yamux::{Config as MuxConfig, Mode};

#[derive(Clone)]
pub struct MuxControl {
    open_tx: mpsc::Sender<oneshot::Sender<Result<Stream, ConnectionError>>>,
}

impl MuxControl {
    pub async fn open_stream(&self) -> anyhow::Result<Stream> {
        let (tx, rx) = oneshot::channel();
        self.open_tx
            .clone()
            .try_send(tx)
            .map_err(|_| anyhow::anyhow!("mux connection is closed"))?;
        let stream = rx
            .await
            .map_err(|_| anyhow::anyhow!("mux connection closed before stream opened"))??;
        Ok(stream)
    }
}

/// Spawns the driver task for `socket` and returns a control handle for
/// opening outbound streams plus a channel of inbound streams accepted from
/// the peer. The driver task exits once the underlying connection closes.
pub fn spawn<T>(socket: T, mode: Mode) -> (MuxControl, tmpsc::UnboundedReceiver<Stream>)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (open_tx, mut open_rx) =
        mpsc::channel::<oneshot::Sender<Result<Stream, ConnectionError>>>(64);
    let (inbound_tx, inbound_rx) = tmpsc::unbounded_channel();

    tokio::spawn(async move {
        let mut conn = Connection::new(socket, MuxConfig::default(), mode);
        let mut pending: std::collections::VecDeque<
            oneshot::Sender<Result<Stream, ConnectionError>>,
        > = std::collections::VecDeque::new();

        loop {
            enum Action {
                Continue,
                Stop,
            }

            let action = poll_fn(|cx| {
                // Service one pending "open outbound stream" request, if any.
                if pending.front().is_some()
                    && let Poll::Ready(result) = conn.poll_new_outbound(cx)
                {
                    let waiter = pending.pop_front().unwrap();
                    let _ = waiter.send(result);
                    return Poll::Ready(Action::Continue);
                }

                // Pull newly-requested opens into the pending queue.
                match open_rx.poll_next_unpin(cx) {
                    Poll::Ready(Some(waiter)) => {
                        pending.push_back(waiter);
                        return Poll::Ready(Action::Continue);
                    }
                    Poll::Ready(None) => {
                        // No more callers will ever request an outbound stream;
                        // that's fine, we keep driving inbound traffic.
                    }
                    Poll::Pending => {}
                }

                // Make progress on inbound streams / connection bookkeeping.
                match conn.poll_next_inbound(cx) {
                    Poll::Ready(Some(Ok(stream))) => {
                        let _ = inbound_tx.send(stream);
                        return Poll::Ready(Action::Continue);
                    }
                    Poll::Ready(Some(Err(_))) | Poll::Ready(None) => {
                        return Poll::Ready(Action::Stop);
                    }
                    Poll::Pending => {}
                }

                Poll::Pending
            })
            .await;

            match action {
                Action::Continue => continue,
                Action::Stop => break,
            }
        }

        // Wake up anyone still waiting on an outbound stream with an error.
        while let Some(waiter) = pending.pop_front() {
            let _ = waiter.send(Err(ConnectionError::Closed));
        }
        while let Ok(waiter) = open_rx.try_recv() {
            let _ = waiter.send(Err(ConnectionError::Closed));
        }
    });

    (MuxControl { open_tx }, inbound_rx)
}
