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

/// How a mapping's listen-side TCP leg is secured. Replaces the old
/// `secure: bool` field: a config using `secure`/`token` in this shape fails
/// to load with a message pointing here, rather than silently keeping the
/// previous behavior (see README's Security notes).
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// A fresh self-signed cert generated at startup: confidentiality
    /// against passive eavesdropping, no peer-identity verification (see
    /// `tls` module docs). Interoperable with any TLS client (`curl -k`,
    /// `openssl s_client`, ...); `token` is optional here and, if set, is
    /// exchanged as a plaintext frame right after the handshake.
    #[default]
    Tls,
    /// The Noise protocol (see `noise` module docs), with `token` mandatory
    /// and hashed into a pre-shared key mixed into the handshake itself.
    /// Only interoperable with another erbridge instance.
    Noise,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardRule {
    pub name: Option<String>,
    pub listen: String,
    pub target: String,
    #[serde(default)]
    pub protocol: ProtocolKind,
    #[serde(default = "default_udp_idle_secs")]
    pub udp_idle_secs: u64,
    /// Wraps the external (listen-side) TCP connection per [`Transport`].
    /// `None` leaves it plaintext. Only applies to the TCP leg; UDP
    /// forwarding is unaffected. The leg from erbridge to `target` remains
    /// plaintext either way.
    #[serde(default)]
    pub transport: Option<Transport>,
    /// Meaning depends on `transport`: see [`Transport::Tls`] and
    /// [`Transport::Noise`]. Required when `transport = "noise"`.
    #[serde(default)]
    pub token: Option<String>,
}

impl ForwardRule {
    pub fn label(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("{}->{}", self.listen, self.target))
    }

    /// `transport = "noise"` has no anonymous form (see [`Transport::Noise`]),
    /// so a token is mandatory there; `tls` and plaintext leave it optional.
    pub fn validate(&self) -> Result<()> {
        if self.transport == Some(Transport::Noise) && self.token.is_none() {
            bail!(
                "forward[{}]: transport = \"noise\" requires a token",
                self.label()
            );
        }
        Ok(())
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
#[serde(deny_unknown_fields)]
pub struct ClientRule {
    pub name: Option<String>,
    /// Local plaintext address this side listens on.
    pub listen: String,
    /// Address of a `forward` mapping with a `transport` set on the far side.
    pub server: String,
    /// Which transport the far side's mapping uses. Defaults to `tls` to
    /// match the transport a bare `secure = true` mapping used before
    /// `transport` existed.
    #[serde(default)]
    pub transport: Transport,
    /// Must match that mapping's `token`. Required when `transport = "noise"`.
    #[serde(default)]
    pub token: Option<String>,
}

impl ClientRule {
    pub fn label(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("{}->{}", self.listen, self.server))
    }

    pub fn validate(&self) -> Result<()> {
        if self.transport == Transport::Noise && self.token.is_none() {
            bail!(
                "client[{}]: transport = \"noise\" requires a token",
                self.label()
            );
        }
        Ok(())
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
/// `+tls` or `+noise` modifier (e.g. `tcp+tls`, or bare `tls`/`noise` as
/// shorthand for `tcp+tls`/`tcp+noise`) to wrap the listen-side TCP
/// connection per [`Transport`].
pub fn parse_map_flag(raw: &str) -> Result<ForwardRule> {
    let (rest, (protocol, transport)) = match raw.rsplit_once('/') {
        Some((rest, proto)) => (rest, parse_protocol(proto)?),
        None => (raw, (ProtocolKind::Both, None)),
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
        transport,
        token: None,
    })
}

/// Parses a `--map LOCAL_LISTEN->SERVER_ADDR[/tls|/noise]` CLI shorthand for
/// `client` mode into a `ClientRule`. `LOCAL_LISTEN` may be a bare port
/// (binds 127.0.0.1) or host:port; `SERVER_ADDR` must be `host:port`. The
/// modifier names the far side mapping's transport; omitting it defaults to
/// `tls`, matching the transport `client` always spoke before `transport`
/// existed.
pub fn parse_client_map_flag(raw: &str) -> Result<ClientRule> {
    let (rest, transport) = match raw.rsplit_once('/') {
        Some((rest, modifier)) => (rest, parse_client_transport(modifier)?),
        None => (raw, Transport::Tls),
    };
    let parts: Vec<&str> = rest.splitn(2, "->").map(str::trim).collect();
    let (listen_raw, server_raw) = match parts.as_slice() {
        [listen, server] => (*listen, *server),
        _ => bail!("--map must look like LOCAL_LISTEN->SERVER_ADDR[/proto], got: {raw}"),
    };
    let listen = normalize_client_listen(listen_raw)?;
    Ok(ClientRule {
        name: None,
        listen,
        server: server_raw.to_string(),
        transport,
        token: None,
    })
}

fn parse_client_transport(modifier: &str) -> Result<Transport> {
    match modifier.to_ascii_lowercase().as_str() {
        "tls" => Ok(Transport::Tls),
        "noise" => Ok(Transport::Noise),
        other => bail!("unknown transport '{other}', expected tls or noise"),
    }
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

fn parse_protocol(s: &str) -> Result<(ProtocolKind, Option<Transport>)> {
    let is_transport =
        |part: &&str| part.eq_ignore_ascii_case("tls") || part.eq_ignore_ascii_case("noise");
    let transport_parts: Vec<&str> = s.split('+').filter(is_transport).collect();
    let transport = match transport_parts.as_slice() {
        [] => None,
        [t] if t.eq_ignore_ascii_case("tls") => Some(Transport::Tls),
        [t] if t.eq_ignore_ascii_case("noise") => Some(Transport::Noise),
        _ => bail!("'{s}' names more than one transport, expected at most one of +tls/+noise"),
    };
    let without_transport: Vec<&str> = s.split('+').filter(|p| !is_transport(p)).collect();
    let protocol = match without_transport.join("+").to_ascii_lowercase().as_str() {
        "" if transport.is_some() => ProtocolKind::Tcp,
        "tcp" => ProtocolKind::Tcp,
        "udp" => ProtocolKind::Udp,
        "both" | "tcp+udp" | "udp+tcp" => ProtocolKind::Both,
        other => bail!(
            "unknown protocol '{other}', expected tcp, udp, both, optionally with a +tls/+noise modifier"
        ),
    };
    if transport.is_some() && protocol != ProtocolKind::Tcp {
        bail!(
            "+tls/+noise only support the tcp protocol, got '{s}' (UDP forwarding cannot be wrapped in a transport)"
        );
    }
    Ok((protocol, transport))
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
        assert_eq!(rule.transport, None);
    }

    #[test]
    fn map_flag_bare_tls_means_tls_tcp() {
        let rule = parse_map_flag("8080->10.0.0.5:80/tls").unwrap();
        assert_eq!(rule.protocol, ProtocolKind::Tcp);
        assert_eq!(rule.transport, Some(Transport::Tls));
    }

    #[test]
    fn map_flag_tcp_plus_tls_means_tls_tcp() {
        let rule = parse_map_flag("8080->10.0.0.5:80/tcp+tls").unwrap();
        assert_eq!(rule.protocol, ProtocolKind::Tcp);
        assert_eq!(rule.transport, Some(Transport::Tls));
    }

    #[test]
    fn map_flag_bare_noise_means_noise_tcp() {
        let rule = parse_map_flag("8080->10.0.0.5:80/noise").unwrap();
        assert_eq!(rule.protocol, ProtocolKind::Tcp);
        assert_eq!(rule.transport, Some(Transport::Noise));
    }

    #[test]
    fn map_flag_both_transports_is_rejected() {
        assert!(parse_map_flag("8080->10.0.0.5:80/tcp+tls+noise").is_err());
    }

    #[test]
    fn map_flag_udp_plus_tls_is_rejected() {
        assert!(parse_map_flag("5353->10.0.0.5:53/udp+tls").is_err());
    }

    #[test]
    fn map_flag_both_plus_tls_is_rejected() {
        assert!(parse_map_flag("8080->10.0.0.5:80/both+tls").is_err());
    }

    #[test]
    fn client_map_flag_without_modifier_defaults_to_tls() {
        let rule = parse_client_map_flag("1080->10.0.0.5:8443").unwrap();
        assert_eq!(rule.transport, Transport::Tls);
    }

    #[test]
    fn client_map_flag_noise_modifier_selects_noise() {
        let rule = parse_client_map_flag("1080->10.0.0.5:8443/noise").unwrap();
        assert_eq!(rule.transport, Transport::Noise);
    }

    #[test]
    fn client_map_flag_unknown_modifier_is_rejected() {
        assert!(parse_client_map_flag("1080->10.0.0.5:8443/quic").is_err());
    }
}
