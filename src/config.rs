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
    /// Wraps the external (listen-side) TCP connection in TLS using a fresh
    /// self-signed cert generated at startup, same trust model as the
    /// serve/connect control channel (see `tls` module docs): confidentiality
    /// against passive eavesdropping, no peer-identity verification. Only
    /// applies to the TCP leg; UDP forwarding is unaffected. The leg from
    /// erbridge to `target` remains plaintext.
    #[serde(default)]
    pub secure: bool,
    /// Only meaningful when `secure` is set. If present, the client must
    /// present this token (in the same length-prefixed frame + constant-time
    /// compare scheme as `serve`/`connect`) right after the TLS handshake, or
    /// the connection is closed before anything is forwarded. Leaving it
    /// unset keeps `secure`'s original behavior: any TLS client (`curl -k`,
    /// `openssl s_client`, ...) can connect. Setting it means only erbridge's
    /// own `client` mode (or something implementing the same handshake) can.
    #[serde(default)]
    pub token: Option<String>,
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

#[derive(Debug, Clone, Deserialize)]
pub struct ClientRule {
    pub name: Option<String>,
    /// Local plaintext address this side listens on.
    pub listen: String,
    /// Address of a `forward` mapping with `secure = true` on the far side.
    pub server: String,
    /// Must match that mapping's `token`, if it set one.
    #[serde(default)]
    pub token: Option<String>,
}

impl ClientRule {
    pub fn label(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("{}->{}", self.listen, self.server))
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct FileConfig {
    #[serde(default)]
    pub forward: Vec<ForwardRule>,
    pub serve: Option<ServeConfig>,
    pub connect: Option<ConnectConfig>,
    #[serde(default)]
    pub client: Vec<ClientRule>,
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
/// `ForwardRule`. `LISTEN` may be `PORT` or `HOST:PORT`. `proto` may add a
/// `+tls` modifier (e.g. `tcp+tls`, or bare `tls` as shorthand for `tcp+tls`)
/// to wrap the listen-side TCP connection in TLS; see `ForwardRule::secure`.
pub fn parse_map_flag(raw: &str) -> Result<ForwardRule> {
    let (rest, (protocol, secure)) = match raw.rsplit_once('/') {
        Some((rest, proto)) => (rest, parse_protocol(proto)?),
        None => (raw, (ProtocolKind::Both, false)),
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
        secure,
        token: None,
    })
}

/// Parses a `--map LOCAL_LISTEN->SERVER_ADDR` CLI shorthand for `client` mode
/// into a `ClientRule`. `LOCAL_LISTEN` may be a bare port (binds 127.0.0.1) or
/// host:port; `SERVER_ADDR` must be `host:port`.
pub fn parse_client_map_flag(raw: &str) -> Result<ClientRule> {
    let parts: Vec<&str> = raw.splitn(2, "->").map(str::trim).collect();
    let (listen_raw, server_raw) = match parts.as_slice() {
        [listen, server] => (*listen, *server),
        _ => bail!("--map must look like LOCAL_LISTEN->SERVER_ADDR, got: {raw}"),
    };
    let listen = normalize_client_listen(listen_raw)?;
    Ok(ClientRule {
        name: None,
        listen,
        server: server_raw.to_string(),
        token: None,
    })
}

/// Accepts a bare port ("1080") as shorthand for "127.0.0.1:1080" -- unlike
/// `forward`'s external listeners, this is a local-only endpoint by default.
fn normalize_client_listen(raw: &str) -> Result<String> {
    if raw.parse::<u16>().is_ok() {
        Ok(format!("127.0.0.1:{raw}"))
    } else {
        Ok(raw.to_string())
    }
}

fn parse_protocol(s: &str) -> Result<(ProtocolKind, bool)> {
    let secure = s
        .split('+')
        .any(|part| part.eq_ignore_ascii_case("tls"));
    let without_tls: Vec<&str> = s
        .split('+')
        .filter(|part| !part.eq_ignore_ascii_case("tls"))
        .collect();
    let protocol = match without_tls.join("+").to_ascii_lowercase().as_str() {
        "" if secure => ProtocolKind::Tcp,
        "tcp" => ProtocolKind::Tcp,
        "udp" => ProtocolKind::Udp,
        "both" | "tcp+udp" | "udp+tcp" => ProtocolKind::Both,
        other => bail!("unknown protocol '{other}', expected tcp, udp, both, optionally with a +tls modifier"),
    };
    if secure && protocol != ProtocolKind::Tcp {
        bail!("+tls only supports the tcp protocol, got '{s}' (UDP forwarding cannot be wrapped in TLS)");
    }
    Ok((protocol, secure))
}

/// Accepts a bare port ("8080") as shorthand for "0.0.0.0:8080".
fn normalize_listen(raw: &str) -> Result<String> {
    if raw.parse::<u16>().is_ok() {
        Ok(format!("0.0.0.0:{raw}"))
    } else {
        Ok(raw.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_flag_without_proto_is_plaintext_both() {
        let rule = parse_map_flag("8080->10.0.0.5:80").unwrap();
        assert_eq!(rule.protocol, ProtocolKind::Both);
        assert!(!rule.secure);
    }

    #[test]
    fn map_flag_bare_tls_means_secure_tcp() {
        let rule = parse_map_flag("8080->10.0.0.5:80/tls").unwrap();
        assert_eq!(rule.protocol, ProtocolKind::Tcp);
        assert!(rule.secure);
    }

    #[test]
    fn map_flag_tcp_plus_tls_means_secure_tcp() {
        let rule = parse_map_flag("8080->10.0.0.5:80/tcp+tls").unwrap();
        assert_eq!(rule.protocol, ProtocolKind::Tcp);
        assert!(rule.secure);
    }

    #[test]
    fn map_flag_udp_plus_tls_is_rejected() {
        assert!(parse_map_flag("5353->10.0.0.5:53/udp+tls").is_err());
    }

    #[test]
    fn map_flag_both_plus_tls_is_rejected() {
        assert!(parse_map_flag("8080->10.0.0.5:80/both+tls").is_err());
    }
}
