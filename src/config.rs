use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolKind {
    Tcp,
    Udp,
    #[default]
    Both,
}

fn default_udp_idle_secs() -> u64 {
    60
}

fn default_reconnect_min_secs() -> u64 {
    1
}

fn default_reconnect_max_secs() -> u64 {
    30
}

#[derive(Debug, Clone, Deserialize)]
pub struct ForwardRule {
    pub name: Option<String>,
    pub listen: String,
    pub target: String,
    #[serde(default)]
    pub protocol: ProtocolKind,
    #[serde(default = "default_udp_idle_secs")]
    pub udp_idle_secs: u64,
}

impl ForwardRule {
    pub fn label(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("{}->{}", self.listen, self.target))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServeTunnel {
    pub name: String,
    pub external: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServeConfig {
    /// Control address A listens on, waiting for B (`connect`) to dial in.
    pub listen: String,
    pub token: String,
    #[serde(default)]
    pub tunnel: Vec<ServeTunnel>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConnectTunnel {
    pub name: String,
    pub target: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConnectConfig {
    /// A's control address to dial.
    pub server: String,
    pub token: String,
    #[serde(default)]
    pub tunnel: Vec<ConnectTunnel>,
    #[serde(default = "default_reconnect_min_secs")]
    pub reconnect_min_secs: u64,
    #[serde(default = "default_reconnect_max_secs")]
    pub reconnect_max_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct FileConfig {
    #[serde(default)]
    pub forward: Vec<ForwardRule>,
    pub serve: Option<ServeConfig>,
    pub connect: Option<ConnectConfig>,
}

impl FileConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        let cfg: FileConfig = toml::from_str(&text)
            .with_context(|| format!("parsing config file {}", path.display()))?;
        Ok(cfg)
    }
}

/// Parses a `--map LISTEN:TARGET_HOST:TARGET_PORT[/proto]` CLI shorthand into a
/// `ForwardRule`. `LISTEN` may be `PORT` or `HOST:PORT`.
pub fn parse_map_flag(raw: &str) -> Result<ForwardRule> {
    let (rest, protocol) = match raw.rsplit_once('/') {
        Some((rest, proto)) => (rest, parse_protocol(proto)?),
        None => (raw, ProtocolKind::Both),
    };
    let parts: Vec<&str> = rest.splitn(2, "->").map(str::trim).collect();
    let (listen_raw, target_raw) = match parts.as_slice() {
        [listen, target] => (*listen, *target),
        _ => bail!("--map must look like LISTEN->TARGET[/proto], got: {raw}"),
    };
    let listen = normalize_listen(listen_raw)?;
    Ok(ForwardRule {
        name: None,
        listen,
        target: target_raw.to_string(),
        protocol,
        udp_idle_secs: default_udp_idle_secs(),
    })
}

fn parse_protocol(s: &str) -> Result<ProtocolKind> {
    match s.to_ascii_lowercase().as_str() {
        "tcp" => Ok(ProtocolKind::Tcp),
        "udp" => Ok(ProtocolKind::Udp),
        "both" | "tcp+udp" | "udp+tcp" => Ok(ProtocolKind::Both),
        other => bail!("unknown protocol '{other}', expected tcp, udp, or both"),
    }
}

/// Accepts a bare port ("8080") as shorthand for "0.0.0.0:8080".
fn normalize_listen(raw: &str) -> Result<String> {
    if raw.parse::<u16>().is_ok() {
        Ok(format!("0.0.0.0:{raw}"))
    } else {
        Ok(raw.to_string())
    }
}
