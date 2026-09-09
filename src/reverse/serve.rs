use std::net::SocketAddr;

use anyhow::{Context, Result, bail};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use crate::config::{ServeConfig, ServeTunnel};
use crate::mux::{self, MuxControl};
use crate::noise;
use crate::proxy::pump;
use crate::reverse::write_frame;
use crate::stats::{Protocol, Registry};

/// Runs the A role: waits for B to dial in on `cfg.listen`, then opens one
/// external listener per configured tunnel. External listeners start
/// immediately and stay up across B reconnects; new external connections
/// simply wait until a B session is active.
pub async fn run_serve(cfg: ServeConfig, registry: Registry) -> Result<()> {
    if cfg.tunnel.is_empty() {
        bail!("serve needs at least one [[serve.tunnel]] entry");
    }

    let psk = noise::derive_psk(&cfg.token);

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
            let registry = registry.clone();
            let current_tx = current_tx.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    handle_control_conn(sock, peer, psk, registry.clone(), current_tx).await
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
    psk: [u8; 32],
    registry: Registry,
    current_tx: watch::Sender<Option<MuxControl>>,
) -> Result<()> {
    if current_tx.borrow().is_some() {
        bail!("rejecting {peer}: a tunnel client is already connected");
    }

    let _ = sock.set_nodelay(true);
    let noise_stream = noise::accept(sock, &psk)
        .await
        .context("Noise handshake with tunnel client failed")?;

    registry.info(format!("serve: tunnel client connected from {peer}"));
    let (control, mut inbound_rx) = mux::spawn(noise_stream.compat(), mux::Mode::Client);
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

    let (client_r, client_w) = tokio::io::split(client);
    let (mut mux_r, mux_w) = tokio::io::split(compat);

    // Start forwarding the client's request straight away instead of waiting
    // for B's reply first. The two directions are otherwise symmetric, but
    // gating this one would put a full A<->B round trip in front of every new
    // connection -- barely visible on loopback, and an entire link RTT on the
    // wide-area links this tunnel exists for.
    let to_b = tokio::spawn(pump(client_r, mux_w, info.bytes_in.clone()));

    // B answers with one byte once it has dialled the target (see the note in
    // `connect::handle_inbound_stream`). It is consumed here, before anything
    // is forwarded back, or it would reach the external client as the first
    // byte of the response. Only this direction waits for it.
    let mut ready = [0u8; 1];
    let opened = async {
        mux_r
            .read_exact(&mut ready)
            .await
            .context("waiting for B to open the target connection")?;
        if ready[0] != 1 {
            bail!("B could not reach the target for tunnel '{}'", tunnel.name);
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;

    if let Err(e) = opened {
        // Nothing will ever come back on this stream, so stop feeding it and
        // drop both halves of the client socket. Waiting on `to_b` instead
        // would hang until the client happened to disconnect on its own.
        to_b.abort();
        registry.close(&info);
        return Err(e);
    }

    let from_b = tokio::spawn(pump(mux_r, client_w, info.bytes_out.clone()));
    let (to_b, from_b) = tokio::join!(to_b, from_b);
    registry.close(&info);
    to_b.context("client -> B copy task")??;
    from_b.context("B -> client copy task")??;
    Ok(())
}
