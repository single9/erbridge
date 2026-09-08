//! Companion to a `forward` mapping secured with `secure = true`: listens
//! locally in plaintext, and for every accepted connection dials the secured
//! mapping over TLS, presents the token if one is configured, then relays
//! bytes -- letting a plain local client (that doesn't speak TLS) reach it.
//!
//! Uses the same TLS trust model as `serve`/`connect` (see `tls` module
//! docs): the server's self-signed cert is accepted without verifying its
//! identity, so this only protects against passive eavesdropping. When the
//! far side's mapping also requires a `token`, this presents it right after
//! the TLS handshake using the same length-prefixed frame the `serve`/`connect`
//! control channel uses, and aborts if the far side rejects it.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use rustls_pki_types::ServerName;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use crate::config::ClientRule;
use crate::proxy::pipe_bidirectional_tracked;
use crate::reverse::write_frame;
use crate::stats::{Protocol, Registry};
use crate::tls;

pub async fn run_client(rules: Vec<ClientRule>, registry: Registry) -> Result<()> {
    if rules.is_empty() {
        anyhow::bail!("client mode needs at least one mapping (config `[[client]]` or --map)");
    }

    tls::install_crypto_provider();
    let connector = TlsConnector::from(tls::client_tls_config()?);

    let mut handles = Vec::new();
    for rule in rules {
        let registry = registry.clone();
        let connector = connector.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = run_client_map(rule.clone(), connector, registry.clone()).await {
                registry.error(format!("client[{}] stopped: {e:#}", rule.label()));
            }
        }));
    }

    for handle in handles {
        let _ = handle.await;
    }
    Ok(())
}

async fn run_client_map(
    rule: ClientRule,
    connector: TlsConnector,
    registry: Registry,
) -> Result<()> {
    let listener = TcpListener::bind(&rule.listen)
        .await
        .with_context(|| format!("binding local listener on {}", rule.listen))?;
    registry.info(format!(
        "client[{}] listening on {} -> tls -> {}",
        rule.label(),
        rule.listen,
        rule.server
    ));

    loop {
        let (local, peer) = listener.accept().await?;
        let rule = rule.clone();
        let connector = connector.clone();
        let registry = registry.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_local_conn(local, peer, &rule, connector, &registry).await {
                registry.error(format!("client[{}] {peer}: {e:#}", rule.label()));
            }
        });
    }
}

async fn handle_local_conn(
    local: TcpStream,
    peer: SocketAddr,
    rule: &ClientRule,
    connector: TlsConnector,
    registry: &Registry,
) -> Result<()> {
    let _ = local.set_nodelay(true);

    let remote = TcpStream::connect(&rule.server)
        .await
        .with_context(|| format!("connecting to {}", rule.server))?;
    let _ = remote.set_nodelay(true);

    let server_name = ServerName::try_from("erbridge").expect("static DNS name is valid");
    let mut tls_stream = connector
        .connect(server_name, remote)
        .await
        .with_context(|| format!("TLS handshake with {}", rule.server))?;

    if let Some(token) = &rule.token {
        write_frame(&mut tls_stream, token.as_bytes())
            .await
            .context("sending token")?;
        let mut ack = [0u8; 1];
        tls_stream
            .read_exact(&mut ack)
            .await
            .context("reading token ack")?;
        if ack != [1u8] {
            anyhow::bail!("server rejected token");
        }
    }

    let info = registry.open(
        format!("client:{}", rule.label()),
        Protocol::Tcp,
        peer.to_string(),
        rule.server.clone(),
    );
    let result = pipe_bidirectional_tracked(
        local,
        tls_stream,
        info.bytes_in.clone(),
        info.bytes_out.clone(),
    )
    .await;
    registry.close(&info);
    result.map_err(Into::into)
}
