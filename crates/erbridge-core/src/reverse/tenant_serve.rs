//! Multi-tenant `serve`: many `connect` clients, each authenticated by its own
//! token and reached through its own SNI host.
//!
//! Two listeners run side by side:
//!
//! * the control listener accepts tunnel clients. The Noise handshake tries
//!   every known PSK ([`noise::accept_any`]); whichever verifies names the
//!   tenant, so a client never states who it is.
//! * the SNI listener accepts TLS connections, reads the ClientHello's SNI
//!   without decrypting anything, and relays the connection through the
//!   matching tenant's session.
//!
//! The tunnel name `connect` receives is always the tenant's own, decided
//! here, so a client cannot steer traffic at another tenant's target.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tokio_util::sync::CancellationToken;

use crate::config::ServeConfig;
use crate::mux::{self, MuxControl};
use crate::noise;
use crate::reverse::serve::relay;
use crate::sni;
use crate::stats::Registry;
use crate::tenant::{Identity, Tenant, TenantSet};
use crate::tenant_store::{FileStore, TenantStore};

/// How long a TLS client gets to send its ClientHello.
const SNI_TIMEOUT: Duration = Duration::from_secs(5);

/// How often the store is re-read for changes.
const DEFAULT_RELOAD_INTERVAL: Duration = Duration::from_secs(1);

/// Where a store-backed multi-tenant `serve` listens, and how often it checks
/// the store for changes.
#[derive(Debug, Clone)]
pub struct TenantServeConfig {
    /// Control address tunnel clients dial.
    pub listen: String,
    /// Address that accepts TLS connections and routes them by SNI.
    pub sni_listen: String,
    pub reload_interval: Duration,
}

struct Session {
    id: u64,
    /// The PSK this session authenticated with, to notice a rotation.
    psk: [u8; 32],
    control: MuxControl,
    cancel: CancellationToken,
}

struct Hub {
    store: Arc<dyn TenantStore>,
    set: watch::Sender<Arc<TenantSet>>,
    sessions: Mutex<HashMap<String, Session>>,
    next_session: AtomicU64,
    /// Per-tenant connection budgets, as (capacity, semaphore).
    budgets: Mutex<HashMap<String, (usize, Arc<Semaphore>)>>,
}

impl Hub {
    /// Takes one connection slot for `tenant`, or `None` if it is at its limit.
    ///
    /// A changed `max_conns` gets a fresh budget. Connections already open keep
    /// holding slots of the old one, so during the switch a tenant can briefly
    /// have a few more than either limit; that is the cost of not tracking
    /// individual connections.
    fn try_acquire(&self, tenant: &Tenant) -> Option<OwnedSemaphorePermit> {
        let semaphore = {
            let mut budgets = self.budgets.lock().unwrap();
            let entry = budgets
                .entry(tenant.name.clone())
                .or_insert_with(|| (tenant.max_conns, Arc::new(Semaphore::new(tenant.max_conns))));
            if entry.0 != tenant.max_conns {
                *entry = (tenant.max_conns, Arc::new(Semaphore::new(tenant.max_conns)));
            }
            entry.1.clone()
        };
        semaphore.try_acquire_owned().ok()
    }

    fn snapshot(&self) -> Arc<TenantSet> {
        self.set.borrow().clone()
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) async fn run_tenant_serve(
    cfg: ServeConfig,
    registry: Registry,
    shutdown: CancellationToken,
) -> Result<()> {
    let path = cfg
        .tenants_file
        .as_deref()
        .context("tenants_file is not set")?;
    let sni_listen = cfg.sni_listen.clone().context("sni_listen is not set")?;
    let tcfg = TenantServeConfig {
        listen: cfg.listen.clone(),
        sni_listen,
        reload_interval: DEFAULT_RELOAD_INTERVAL,
    };
    run_tenant_serve_with_store(tcfg, Arc::new(FileStore::new(path)), registry, shutdown).await
}

/// Runs multi-tenant `serve` against any [`TenantStore`]. Returns `Ok(())` once
/// `shutdown` is cancelled and every listener and session has been stopped.
pub async fn run_tenant_serve_with_store(
    cfg: TenantServeConfig,
    store: Arc<dyn TenantStore>,
    registry: Registry,
    shutdown: CancellationToken,
) -> Result<()> {
    let initial = store.snapshot()?;

    let control_listener = TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("binding control listener on {}", cfg.listen))?;
    let sni_listener = TcpListener::bind(&cfg.sni_listen)
        .await
        .with_context(|| format!("binding SNI listener on {}", cfg.sni_listen))?;
    registry.info(format!(
        "serve: multi-tenant, {} tenant(s); tunnel clients on {}, TLS by SNI on {}",
        initial.tenants().len(),
        cfg.listen,
        cfg.sni_listen
    ));

    let hub = Arc::new(Hub {
        store,
        set: watch::channel(Arc::new(initial)).0,
        sessions: Mutex::new(HashMap::new()),
        next_session: AtomicU64::new(1),
        budgets: Mutex::new(HashMap::new()),
    });

    let control_loop = accept_loop(control_listener, &shutdown, &registry, "control", {
        let hub = hub.clone();
        let registry = registry.clone();
        let shutdown = shutdown.clone();
        move |sock, peer| {
            let (hub, registry, shutdown) = (hub.clone(), registry.clone(), shutdown.clone());
            async move { handle_control(hub, sock, peer, &registry, shutdown).await }
        }
    });
    let sni_loop = accept_loop(sni_listener, &shutdown, &registry, "sni", {
        let hub = hub.clone();
        let registry = registry.clone();
        move |sock, peer| {
            let (hub, registry) = (hub.clone(), registry.clone());
            async move { handle_sni(hub, sock, peer, &registry).await }
        }
    });
    let reload = reload_loop(
        hub.clone(),
        cfg.reload_interval,
        registry.clone(),
        shutdown.clone(),
    );
    tokio::join!(control_loop, sni_loop, reload);
    Ok(())
}

/// Accepts connections until `shutdown`, running `handler` for each in its own
/// task that also stops on shutdown.
async fn accept_loop<F, Fut>(
    listener: TcpListener,
    shutdown: &CancellationToken,
    registry: &Registry,
    what: &'static str,
    handler: F,
) where
    F: Fn(TcpStream, SocketAddr) -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    let accepting = async {
        loop {
            let (sock, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    registry.error(format!("serve: {what} accept failed: {e:#}"));
                    continue;
                }
            };
            let registry = registry.clone();
            let shutdown = shutdown.clone();
            let conn = handler(sock, peer);
            tokio::spawn(async move {
                if let Some(Err(e)) = shutdown.run_until_cancelled(conn).await {
                    registry.error(format!("serve: {what} connection {peer}: {e:#}"));
                }
            });
        }
    };
    shutdown.run_until_cancelled(accepting).await;
}

async fn handle_control(
    hub: Arc<Hub>,
    sock: TcpStream,
    peer: SocketAddr,
    registry: &Registry,
    shutdown: CancellationToken,
) -> Result<()> {
    let _ = sock.set_nodelay(true);
    let candidates = hub.snapshot().candidates(now_unix());
    let (stream, index) = noise::accept_any(sock, &candidates.psks)
        .await
        .context("Noise handshake with tunnel client failed")?;

    match candidates.identity(index).clone() {
        Identity::Tenant(tenant) => {
            run_session(&hub, tenant, stream, peer, registry, shutdown).await
        }
        Identity::Code(_) => bail!("enrollment is not available yet"),
    }
}

async fn run_session(
    hub: &Hub,
    tenant: Tenant,
    stream: noise::NoiseStream<TcpStream>,
    peer: SocketAddr,
    registry: &Registry,
    shutdown: CancellationToken,
) -> Result<()> {
    let cancel = shutdown.child_token();
    let (control, mut inbound_rx) =
        mux::spawn_with_shutdown(stream.compat(), mux::Mode::Client, cancel.clone());
    let id = hub.next_session.fetch_add(1, Ordering::Relaxed);

    // A new session takes over from any older one for the same tenant, so a
    // client reconnecting after a network drop is not locked out until the
    // dead connection times out.
    let replaced = hub.sessions.lock().unwrap().insert(
        tenant.name.clone(),
        Session {
            id,
            psk: tenant.psk,
            control,
            cancel,
        },
    );
    if let Some(old) = replaced {
        old.cancel.cancel();
        registry.info(format!(
            "serve: tenant '{}' reconnected from {peer}, replacing its previous session",
            tenant.name
        ));
    } else {
        registry.info(format!(
            "serve: tenant '{}' connected from {peer}",
            tenant.name
        ));
    }

    // B never opens streams back to A; drain so the mux driver keeps making
    // progress, ending once the connection (or this session) goes away.
    while inbound_rx.recv().await.is_some() {}

    let mut sessions = hub.sessions.lock().unwrap();
    if sessions.get(&tenant.name).is_some_and(|s| s.id == id) {
        sessions.remove(&tenant.name);
    }
    drop(sessions);
    registry.info(format!(
        "serve: tenant '{}' disconnected ({peer})",
        tenant.name
    ));
    Ok(())
}

async fn handle_sni(
    hub: Arc<Hub>,
    mut client: TcpStream,
    peer: SocketAddr,
    registry: &Registry,
) -> Result<()> {
    let peeked = sni::peek_sni(&mut client, SNI_TIMEOUT).await?;
    let host = peeked.sni.ok_or_else(|| anyhow!("no SNI in ClientHello"))?;

    let tenant = hub
        .snapshot()
        .tenant_by_sni(&host)
        .cloned()
        .ok_or_else(|| anyhow!("no tenant for host '{host}'"))?;
    let control = hub
        .sessions
        .lock()
        .unwrap()
        .get(&tenant.name)
        .map(|s| s.control.clone())
        .ok_or_else(|| anyhow!("tenant '{}' is offline", tenant.name))?;

    // Held until the relay ends, which frees the slot.
    let _slot = hub.try_acquire(&tenant).ok_or_else(|| {
        anyhow!(
            "tenant '{}' is at its limit of {} connections",
            tenant.name,
            tenant.max_conns
        )
    })?;

    relay(
        client,
        peer,
        &control,
        &tenant.name,
        &peeked.buffered,
        registry,
    )
    .await
}

/// Re-reads the store every `interval` and applies what changed. A store that
/// cannot be read or parsed leaves the previous tenants in force; the error is
/// logged once per distinct message rather than on every tick.
async fn reload_loop(
    hub: Arc<Hub>,
    interval: Duration,
    registry: Registry,
    shutdown: CancellationToken,
) {
    let watching = async {
        let mut last_error: Option<String> = None;
        loop {
            tokio::time::sleep(interval).await;
            let store = hub.store.clone();
            let read = tokio::task::spawn_blocking(move || store.snapshot()).await;
            match read {
                Ok(Ok(next)) => {
                    last_error = None;
                    if *hub.snapshot() != next {
                        apply(&hub, next, &registry);
                    }
                }
                Ok(Err(e)) => {
                    let message = format!("{e:#}");
                    if last_error.as_deref() != Some(message.as_str()) {
                        registry.error(format!(
                            "serve: keeping the previous tenants, could not reload: {message}"
                        ));
                        last_error = Some(message);
                    }
                }
                Err(e) => registry.error(format!("serve: tenant reload task failed: {e}")),
            }
        }
    };
    shutdown.run_until_cancelled(watching).await;
}

/// Publishes a new snapshot and ends the session of every tenant that is gone,
/// disabled or holds a different PSK now. Other sessions are not touched.
fn apply(hub: &Hub, next: TenantSet, registry: &Registry) {
    let next = Arc::new(next);
    hub.set.send_replace(next.clone());

    let mut sessions = hub.sessions.lock().unwrap();
    sessions.retain(|name, session| {
        let still_valid = next
            .tenant(name)
            .is_some_and(|t| !t.disabled && t.psk == session.psk);
        if !still_valid {
            session.cancel.cancel();
            registry.info(format!(
                "serve: tenant '{name}' no longer allowed, session ended"
            ));
        }
        still_valid
    });
    drop(sessions);
    hub.budgets
        .lock()
        .unwrap()
        .retain(|name, _| next.tenant(name).is_some());
    registry.info(format!(
        "serve: reloaded tenants, {} now configured",
        next.tenants().len()
    ));
}
