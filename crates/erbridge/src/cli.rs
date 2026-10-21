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
        /// Multi-tenant mode: the tenant file (see `serve-admin`). Each tenant
        /// has its own token and is reached by its own TLS SNI host. Replaces
        /// --token and --tunnel; needs --sni-listen.
        #[arg(long, value_name = "FILE")]
        tenants: Option<PathBuf>,
        /// Multi-tenant mode: address that accepts TLS connections and routes
        /// them to tenants by SNI, e.g. 0.0.0.0:443.
        #[arg(long, value_name = "ADDR")]
        sni_listen: Option<String>,
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
        /// Credentials file written by `enroll`: supplies the token and the
        /// tunnel name, so only --target is needed besides --server.
        #[arg(long, value_name = "FILE")]
        credentials: Option<PathBuf>,
        /// Local target for the tunnel named in --credentials.
        #[arg(long, value_name = "ADDR", requires = "credentials")]
        target: Option<String>,
    },

    /// Trade a single-use enrollment code for the credentials of a new tenant
    /// on a multi-tenant `serve`.
    Enroll {
        /// The server's control address, e.g. relay.example.com:9000.
        #[arg(long)]
        server: String,
        /// The code from `serve-admin issue`.
        #[arg(long)]
        code: String,
        /// Write the credentials here (mode 0600, never overwrites) instead of
        /// printing them.
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },

    /// Manage the tenant file of a multi-tenant `serve`. Safe to run while
    /// `serve` is up; changes apply within a second.
    ServeAdmin {
        /// The tenant file (or set `serve.tenants_file` in the config).
        #[arg(long, value_name = "FILE", global = true)]
        tenants: Option<PathBuf>,
        #[command(subcommand)]
        action: AdminAction,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum AdminAction {
    /// Print a new single-use enrollment code for a host.
    Issue {
        /// The TLS SNI host the new tenant will be reached at.
        #[arg(long)]
        sni: String,
        /// Concurrent connections the tenant may have (default 64).
        #[arg(long)]
        max_conns: Option<usize>,
        /// Seconds until the code stops working (default: never).
        #[arg(long, value_name = "SECS")]
        expires_in: Option<u64>,
    },
    /// Remove a tenant; its token stops working and its session ends.
    Revoke { name: String },
    /// Suspend a tenant without forgetting it.
    Disable { name: String },
    /// Resume a suspended tenant.
    Enable { name: String },
    /// List tenants and the number of unused codes.
    List,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("erbridge").chain(args.iter().copied()))
    }

    #[test]
    fn serve_accepts_the_multi_tenant_flags() {
        let cli = parse(&[
            "serve",
            "--listen",
            "0.0.0.0:9000",
            "--tenants",
            "t.toml",
            "--sni-listen",
            "0.0.0.0:443",
        ])
        .unwrap();
        let Command::Serve {
            tenants,
            sni_listen,
            token,
            ..
        } = cli.command
        else {
            panic!("not serve");
        };
        assert_eq!(tenants.unwrap().to_str(), Some("t.toml"));
        assert_eq!(sni_listen.as_deref(), Some("0.0.0.0:443"));
        assert!(token.is_none());
    }

    #[test]
    fn connect_takes_credentials_and_a_target() {
        let cli = parse(&[
            "connect",
            "--server",
            "h:9000",
            "--credentials",
            "c.toml",
            "--target",
            "127.0.0.1:80",
        ])
        .unwrap();
        let Command::Connect {
            credentials,
            target,
            ..
        } = cli.command
        else {
            panic!("not connect");
        };
        assert_eq!(credentials.unwrap().to_str(), Some("c.toml"));
        assert_eq!(target.as_deref(), Some("127.0.0.1:80"));
        // --target alone makes no sense.
        assert!(parse(&["connect", "--server", "h:1", "--target", "x:1"]).is_err());
    }

    #[test]
    fn enroll_needs_a_server_and_a_code() {
        assert!(parse(&["enroll", "--server", "h:9000", "--code", "abc"]).is_ok());
        assert!(parse(&["enroll", "--server", "h:9000"]).is_err());
        assert!(parse(&["enroll", "--code", "abc"]).is_err());
    }

    #[test]
    fn serve_admin_subcommands_parse() {
        let cli = parse(&[
            "serve-admin",
            "--tenants",
            "t.toml",
            "issue",
            "--sni",
            "a.example.com",
            "--max-conns",
            "5",
            "--expires-in",
            "3600",
        ])
        .unwrap();
        let Command::ServeAdmin { tenants, action } = cli.command else {
            panic!("not serve-admin");
        };
        assert_eq!(tenants.unwrap().to_str(), Some("t.toml"));
        assert!(matches!(
            action,
            AdminAction::Issue {
                max_conns: Some(5),
                expires_in: Some(3600),
                ..
            }
        ));
        for ok in [
            &["serve-admin", "revoke", "t-1"][..],
            &["serve-admin", "disable", "t-1"],
            &["serve-admin", "enable", "t-1"],
            &["serve-admin", "list"],
        ] {
            assert!(parse(ok).is_ok(), "{ok:?}");
        }
        assert!(
            parse(&["serve-admin", "issue"]).is_err(),
            "issue needs --sni"
        );
    }
}
