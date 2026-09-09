use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "erbridge",
    version,
    about = "Low-latency TCP/UDP port forwarder with a reverse (NAT-traversal) mode"
)]
pub struct Cli {
    /// TOML config file (see config.toml.example).
    #[arg(long, short = 'c', global = true)]
    pub config: Option<PathBuf>,

    /// Disable the interactive TUI and write structured JSON logs instead
    /// (use when running unattended, e.g. as a background/Windows service).
    #[arg(long, global = true)]
    pub headless: bool,

    /// JSON log file path when --headless is set. Defaults to `erbridge.log`.
    #[arg(long, global = true)]
    pub log_file: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Direct forwarding: external listen port(s) -> internal target(s).
    Forward {
        /// Ad-hoc mapping, repeatable: LISTEN->TARGET[/tcp|udp|both], where
        /// proto can add a `+tls` or `+noise` modifier (or bare `tls`/`noise`
        /// for `tcp+tls`/`tcp+noise`) to wrap that mapping's listen side in
        /// that transport. LISTEN may be a bare port (binds 0.0.0.0) or
        /// host:port.
        #[arg(long = "map", value_name = "LISTEN->TARGET[/proto]")]
        maps: Vec<String>,
        /// Token for every `+tls`/`+noise` mapping above that doesn't set its
        /// own (applies to all of them). Mandatory for `+noise`; for `+tls`,
        /// omitting it lets any TLS client connect, same as today.
        #[arg(long)]
        token: Option<String>,
    },

    /// Companion to a `forward` mapping secured with `+tls`/`+noise`
    /// (optionally `--token`): listens locally in plaintext, and for every
    /// connection dials the secured mapping using that same transport,
    /// presents the token if configured, then relays bytes -- so a plain
    /// local client doesn't need its own TLS/Noise support to reach it.
    Client {
        /// Ad-hoc mapping, repeatable: LOCAL_LISTEN->SERVER_ADDR[/tls|/noise].
        /// LOCAL_LISTEN may be a bare port (binds 127.0.0.1) or host:port;
        /// the modifier names the far side mapping's transport and defaults
        /// to `tls` when omitted.
        #[arg(long = "map", value_name = "LOCAL_LISTEN->SERVER_ADDR[/proto]")]
        maps: Vec<String>,
        /// Token to present to the secured mapping (applies to all of them
        /// above); must match its `--token`/`token`.
        #[arg(long)]
        token: Option<String>,
    },

    /// Reverse tunnel role A: wait for `connect` (B) to dial in, then expose
    /// external ports that get relayed through B to B's local targets.
    Serve {
        /// Control address B dials, e.g. 0.0.0.0:9000.
        #[arg(long)]
        listen: Option<String>,
        /// Shared secret B must present to be accepted.
        #[arg(long)]
        token: Option<String>,
        /// Ad-hoc tunnel, repeatable: NAME=EXTERNAL_ADDR.
        #[arg(long = "tunnel", value_name = "NAME=EXTERNAL_ADDR")]
        tunnels: Vec<String>,
    },

    /// Reverse tunnel role B: dial `serve` (A) and relay each stream it
    /// opens to a locally-configured target.
    Connect {
        /// A's control address to dial, e.g. 1.2.3.4:9000.
        #[arg(long)]
        server: Option<String>,
        /// Shared secret to present to A.
        #[arg(long)]
        token: Option<String>,
        /// Ad-hoc tunnel, repeatable: NAME=TARGET_ADDR.
        #[arg(long = "tunnel", value_name = "NAME=TARGET_ADDR")]
        tunnels: Vec<String>,
    },
}
