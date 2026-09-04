use std::net::SocketAddr;

use anyhow::{Context, Result, bail};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use crate::config::{ServeConfig, ServeTunnel};
use crate::mux::{self, MuxControl};
use crate::proxy::pipe_bidirectional_tracked;
use crate::reverse::{MAX_TOKEN_LEN, constant_time_eq, read_frame, write_frame};
use crate::stats::{Protocol, Registry};
use crate::tls;

/// Runs the A role: waits for B to dial in on `cfg.listen`, then opens one
/// external listener per configured tunnel. External listeners start
/// immediately and stay up across B reconnects; new external connections
/// simply wait until a B session is active.
pub async fn run_serve(cfg: ServeConfig, registry: Registry) -> Result<()> {
    if cfg.tunnel.is_empty() {
        bail!("serve needs at least one [[serve.tunnel]] entry");
    }

    tls::install_crypto_provider();
    let cert = tls::generate_self_signed()?;
    let tls_config = tls::server_tls_config(&cert)?;
    let acceptor = TlsAcceptor::from(tls_config);

    let (current_tx, current_rx) = watch::channel::<Option<MuxControl>>(None);

    let mut handles = Vec::new();
    for tunnel in cfg.tunnel.clone() {
        let current_rx = current_rx.clone();
        let registry = registry.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) =
                run_external_listener(tunnel.clone(), current_rx, registry.clone()).await
            {
                registry.error(format!(
                    "serve: external listener '{}' stopped: {e:#}",
                    tunnel.name
                ));
            }
        }));
    }

    let listener = TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("binding control listener on {}", cfg.listen))?;
    registry.info(format!(
        "serve: waiting for tunnel client (B) on {}",
        cfg.listen
    ));

    handles.push(tokio::spawn(async move {
        loop {
            let (sock, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    registry.error(format!("serve: accept failed: {e:#}"));
                    continue;
                }
            };
            let acceptor = acceptor.clone();
            let cfg = cfg.clone();
            let registry = registry.clone();
            let current_tx = current_tx.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    handle_control_conn(sock, peer, acceptor, cfg, registry.clone(), current_tx)
                        .await
                {
                    registry.error(format!("serve: control connection {peer}: {e:#}"));
                }
            });
        }
    }));

    for handle in handles {
        let _ = handle.await;
    }
    Ok(())
}

async fn handle_control_conn(
    sock: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    cfg: ServeConfig,
    registry: Registry,
    current_tx: watch::Sender<Option<MuxControl>>,
) -> Result<()> {
    if current_tx.borrow().is_some() {
        bail!("rejecting {peer}: a tunnel client is already connected");
    }

    let _ = sock.set_nodelay(true);
    let mut tls_stream = acceptor
        .accept(sock)
        .await
        .context("TLS handshake with tunnel client failed")?;

    let token = read_frame(&mut tls_stream, MAX_TOKEN_LEN)
        .await
        .context("reading token from tunnel client")?;
    if !constant_time_eq(&token, cfg.token.as_bytes()) {
        let _ = tls_stream.write_all(&[0u8]).await;
        bail!("token mismatch from {peer}");
    }
    tls_stream.write_all(&[1u8]).await?;

    registry.info(format!("serve: tunnel client connected from {peer}"));
    let (control, mut inbound_rx) = mux::spawn(tls_stream.compat(), mux::Mode::Client);
    let _ = current_tx.send(Some(control));

    // A never expects B to open streams back to it in this design; drain and
    // discard so the mux driver keeps making progress, exiting once the
    // underlying connection (and thus the driver task) goes away.
    while inbound_rx.recv().await.is_some() {}

    let _ = current_tx.send(None);
    registry.info(format!("serve: tunnel client {peer} disconnected"));
    Ok(())
}

async fn run_external_listener(
    tunnel: ServeTunnel,
    current_rx: watch::Receiver<Option<MuxControl>>,
    registry: Registry,
) -> Result<()> {
    let listener = TcpListener::bind(&tunnel.external)
        .await
        .with_context(|| format!("binding external listener on {}", tunnel.external))?;
    registry.info(format!(
        "serve: tunnel '{}' external listener on {}",
        tunnel.name, tunnel.external
    ));

    loop {
        let (client, peer) = listener.accept().await?;
        let tunnel = tunnel.clone();
        let mut current_rx = current_rx.clone();
        let registry = registry.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_external_client(client, peer, tunnel.clone(), &mut current_rx, &registry)
                    .await
            {
                registry.error(format!("serve: tunnel '{}' {peer}: {e:#}", tunnel.name));
            }
        });
    }
}

async fn handle_external_client(
    client: TcpStream,
    peer: SocketAddr,
    tunnel: ServeTunnel,
    current_rx: &mut watch::Receiver<Option<MuxControl>>,
    registry: &Registry,
) -> Result<()> {
    let _ = client.set_nodelay(true);

    let control = loop {
        if let Some(c) = current_rx.borrow().clone() {
            break c;
        }
        current_rx
            .changed()
            .await
            .context("tunnel client control channel closed")?;
    };

    let stream = control
        .open_stream()
        .await
        .context("opening mux stream to tunnel client")?;
    let mut compat = stream.compat();
    write_frame(&mut compat, tunnel.name.as_bytes())
        .await
        .context("sending tunnel header")?;

    let label = format!("reverse:{}", tunnel.name);
    let info = registry.open(
        label,
        Protocol::Tcp,
        peer.to_string(),
        format!("B:{}", tunnel.name),
    );
    let result = pipe_bidirectional_tracked(
        client,
        compat,
        info.bytes_in.clone(),
        info.bytes_out.clone(),
    )
    .await;
    registry.close(&info);
    result.map_err(Into::into)
}
