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
        /// Ad-hoc mapping, repeatable: LISTEN->TARGET[/tcp|udp|both].
        /// LISTEN may be a bare port (binds 0.0.0.0) or host:port.
        #[arg(long = "map", value_name = "LISTEN->TARGET[/proto]")]
        maps: Vec<String>,
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
