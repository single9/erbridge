use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use yamux::Stream as MuxStream;

use crate::config::ConnectConfig;
use crate::mux;
use crate::proxy::pipe_bidirectional_tracked;
use crate::reverse::{MAX_NAME_LEN, read_frame, write_frame};
use crate::stats::{Protocol, Registry};
use crate::tls;

/// Runs the B role: repeatedly dials `cfg.server`, and for every stream A
/// opens through the tunnel, dials the locally-configured target named in
/// the stream's header frame. Reconnects with exponential backoff whenever
/// the session ends, whether cleanly or on error.
pub async fn run_connect(cfg: ConnectConfig, registry: Registry) -> Result<()> {
    if cfg.tunnel.is_empty() {
        bail!("connect needs at least one [[connect.tunnel]] entry");
    }

    tls::install_crypto_provider();
    let tls_config = tls::client_tls_config()?;
    let connector = TlsConnector::from(tls_config);

    let targets: HashMap<String, String> = cfg
        .tunnel
        .iter()
        .map(|t| (t.name.clone(), t.target.clone()))
        .collect();

    let min_backoff = cfg.reconnect_min_secs.max(1);
    let max_backoff = cfg.reconnect_max_secs.max(min_backoff);
    let mut backoff = min_backoff;

    loop {
        match run_one_session(&cfg, &connector, &targets, &registry).await {
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
        tokio::time::sleep(Duration::from_secs(backoff)).await;
    }
}

async fn run_one_session(
    cfg: &ConnectConfig,
    connector: &TlsConnector,
    targets: &HashMap<String, String>,
    registry: &Registry,
) -> Result<()> {
    let tcp = TcpStream::connect(&cfg.server)
        .await
        .with_context(|| format!("connecting to server (A) at {}", cfg.server))?;
    let _ = tcp.set_nodelay(true);

    let server_name = ServerName::try_from("erbridge").expect("static server name is valid");
    let mut tls_stream = connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake with A failed")?;

    write_frame(&mut tls_stream, cfg.token.as_bytes())
        .await
        .context("sending token to A")?;
    let mut ack = [0u8; 1];
    tokio::io::AsyncReadExt::read_exact(&mut tls_stream, &mut ack)
        .await
        .context("reading token acknowledgement from A")?;
    if ack[0] != 1 {
        bail!("token rejected by A");
    }
    registry.info(format!("connect: connected to {}", cfg.server));

    let (_control, mut inbound_rx) = mux::spawn(tls_stream.compat(), mux::Mode::Server);
    while let Some(stream) = inbound_rx.recv().await {
        let targets = targets.clone();
        let registry = registry.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_inbound_stream(stream, targets, registry.clone()).await {
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

    let target = TcpStream::connect(&target_addr)
        .await
        .with_context(|| format!("connecting to local target {target_addr}"))?;
    let _ = target.set_nodelay(true);

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
