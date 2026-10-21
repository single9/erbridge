//! TCP/UDP port forwarding and reverse tunnels, usable as a library.
//!
//! Embedding the `connect` role of a reverse tunnel, with a way to stop it
//! and to observe what it is doing:
//!
//! ```no_run
//! use erbridge_core::config::{ConnectConfig, ConnectTunnel};
//! use erbridge_core::reverse::connect::run_connect_with_shutdown;
//! use erbridge_core::stats::{Event, Registry};
//! use tokio_util::sync::CancellationToken;
//!
//! # async fn demo() -> anyhow::Result<()> {
//! let cfg = ConnectConfig {
//!     server: "relay.example.com:9000".into(),
//!     token: "secret".into(),
//!     tunnel: vec![ConnectTunnel {
//!         name: "web".into(),
//!         target: "127.0.0.1:8080".into(),
//!     }],
//!     reconnect_min_secs: 1,
//!     reconnect_max_secs: 30,
//! };
//!
//! let registry = Registry::new();
//! let mut events = registry.subscribe();
//! let shutdown = CancellationToken::new();
//! let task = tokio::spawn(run_connect_with_shutdown(cfg, registry, shutdown.clone()));
//!
//! while let Ok(event) = events.recv().await {
//!     if let Event::Error { message } = event {
//!         eprintln!("tunnel: {message}");
//!     }
//! }
//!
//! shutdown.cancel();
//! task.await??;
//! # Ok(())
//! # }
//! ```
//!
//! The command-line interface and terminal UI are in the separate `erbridge`
//! crate, so depending on this one pulls in neither.

pub mod client;
pub mod config;
pub mod forward;
#[doc(hidden)]
pub mod mux;
#[doc(hidden)]
pub mod noise;
#[doc(hidden)]
pub mod proxy;
pub mod reverse;
pub mod stats;
#[doc(hidden)]
pub mod tls;
