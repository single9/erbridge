use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tokio_util::sync::CancellationToken;
use yamux::Stream as MuxStream;

use crate::config::ConnectConfig;
use crate::mux;
use crate::noise;
use crate::proxy::pipe_bidirectional_tracked;
use crate::reverse::{MAX_NAME_LEN, read_frame};
use crate::stats::{Protocol, Registry};

/// Runs the B role: repeatedly dials `cfg.server`, and for every stream A
/// opens through the tunnel, dials the locally-configured target named in
/// the stream's header frame. Reconnects with exponential backoff whenever
/// the session ends, whether cleanly or on error.
pub async fn run_connect(cfg: ConnectConfig, registry: Registry) -> Result<()> {
    run_connect_with_shutdown(cfg, registry, CancellationToken::new()).await
}

/// Like [`run_connect`], but returns `Ok(())` once `shutdown` is cancelled,
/// after the session and every in-flight tunnelled connection has been
/// stopped and its socket dropped.
pub async fn run_connect_with_shutdown(
    cfg: ConnectConfig,
    registry: Registry,
    shutdown: CancellationToken,
) -> Result<()> {
    if cfg.tunnel.is_empty() {
        bail!("connect needs at least one [[connect.tunnel]] entry");
    }

    let psk = noise::derive_psk(&cfg.token);

    let targets: HashMap<String, String> = cfg
        .tunnel
        .iter()
        .map(|t| (t.name.clone(), t.target.clone()))
        .collect();

    let min_backoff = cfg.reconnect_min_secs.max(1);
    let max_backoff = cfg.reconnect_max_secs.max(min_backoff);
    let mut backoff = min_backoff;

    loop {
        let session = run_one_session(&cfg, &psk, &targets, &registry, &shutdown);
        let Some(outcome) = shutdown.run_until_cancelled(session).await else {
            return Ok(());
        };
        match outcome {
            Ok(()) => {
                registry.info("connect: session ended, reconnecting".to_string());
                backoff = min_backoff;
            }
            Err(e) => {
                registry.error(format!("connect: session error: {e:#}"));
                backoff = (backoff * 2).min(max_backoff);
            }
        }
        registry.info(format!("connect: retrying in {backoff}s"));
        let retry_wait = tokio::time::sleep(Duration::from_secs(backoff));
        if shutdown.run_until_cancelled(retry_wait).await.is_none() {
            return Ok(());
        }
    }
}

async fn run_one_session(
    cfg: &ConnectConfig,
    psk: &noise::Psk,
    targets: &HashMap<String, String>,
    registry: &Registry,
    shutdown: &CancellationToken,
) -> Result<()> {
    let tcp = TcpStream::connect(&cfg.server)
        .await
        .with_context(|| format!("connecting to server (A) at {}", cfg.server))?;
    let _ = tcp.set_nodelay(true);

    let noise_stream = noise::connect(tcp, psk)
        .await
        .context("Noise handshake with A failed")?;
    registry.info(format!("connect: connected to {}", cfg.server));

    let (_control, mut inbound_rx) =
        mux::spawn_with_shutdown(noise_stream.compat(), mux::Mode::Server, shutdown.clone());
    while let Some(stream) = inbound_rx.recv().await {
        let targets = targets.clone();
        let registry = registry.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            let inbound = handle_inbound_stream(stream, targets, registry.clone());
            if let Some(Err(e)) = shutdown.run_until_cancelled(inbound).await {
                registry.error(format!("connect: inbound stream error: {e:#}"));
            }
        });
    }
    Ok(())
}

async fn handle_inbound_stream(
    stream: MuxStream,
    targets: HashMap<String, String>,
    registry: Registry,
) -> Result<()> {
    let mut compat = stream.compat();
    let name_bytes = read_frame(&mut compat, MAX_NAME_LEN)
        .await
        .context("reading tunnel header from A")?;
    let name = String::from_utf8(name_bytes).context("tunnel header is not valid utf-8")?;
    let target_addr = targets
        .get(&name)
        .with_context(|| format!("A requested unknown tunnel '{name}'"))?
        .clone();

    // Answer A as soon as the target is dialled, rather than waiting for the
    // target to speak. Two reasons, and the second is the load-bearing one:
    //
    //   1. It tells A whether the dial actually succeeded, so a failure
    //      surfaces as an error instead of an external client piping into a
    //      stream that will never carry anything.
    //   2. This first byte is what makes yamux attach the stream ACK. Until A
    //      sees that ACK the stream counts against yamux's ack backlog
    //      (`MAX_ACK_BACKLOG`, 256), and A's 257th `open_stream` blocks. With
    //      a target that only speaks after the client does, that silently caps
    //      the whole tunnel at 256 concurrent connections.
    let target = match TcpStream::connect(&target_addr).await {
        Ok(t) => t,
        Err(e) => {
            let _ = compat.write_all(&[0u8]).await;
            let _ = compat.flush().await;
            return Err(e).with_context(|| format!("connecting to local target {target_addr}"));
        }
    };
    let _ = target.set_nodelay(true);
    compat
        .write_all(&[1u8])
        .await
        .context("acknowledging stream to A")?;
    compat
        .flush()
        .await
        .context("flushing stream acknowledgement to A")?;

    let info = registry.open(
        format!("reverse:{name}"),
        Protocol::Tcp,
        "A".to_string(),
        target_addr,
    );
    let result = pipe_bidirectional_tracked(
        compat,
        target,
        info.bytes_in.clone(),
        info.bytes_out.clone(),
    )
    .await;
    registry.close(&info);
    result.map_err(Into::into)
}
