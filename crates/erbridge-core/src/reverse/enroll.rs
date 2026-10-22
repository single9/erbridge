//! Client side of enrollment: trade a single-use code for the credentials of a
//! new tenant.
//!
//! The code is used as the Noise PSK, so the exchange is as private as any
//! other tunnel connection. `serve` burns the code, creates the tenant, and
//! sends the credentials as one frame inside the encrypted channel. If that
//! frame is lost in transit the code is already spent; ask for a new one.

use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;

use crate::noise;
use crate::reverse::read_frame;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CREDENTIALS_LEN: usize = 4096;

/// What an enrolled client needs to run `connect`: the token to authenticate
/// with and the tunnel name `serve` will address it by.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    /// Tenant name; use it as the `[[connect.tunnel]]` name.
    pub name: String,
    /// Long-term secret; use it as the `connect` token. Shown once.
    pub token: String,
    /// The host this tenant is reached at.
    pub sni: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("name", &self.name)
            .field("token", &"<redacted>")
            .field("sni", &self.sni)
            .finish()
    }
}

impl Credentials {
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).context("serialising credentials")
    }

    pub fn from_toml(text: &str) -> Result<Self> {
        toml::from_str(text).context("parsing credentials")
    }
}

/// Redeems `code` at the control address `server`.
pub async fn enroll(server: &str, code: &str) -> Result<Credentials> {
    enroll_with_timeout(server, code, DEFAULT_TIMEOUT).await
}

/// [`enroll`] with an explicit overall time limit.
pub async fn enroll_with_timeout(
    server: &str,
    code: &str,
    timeout: Duration,
) -> Result<Credentials> {
    let attempt = async {
        let tcp = TcpStream::connect(server)
            .await
            .with_context(|| format!("connecting to {server}"))?;
        let _ = tcp.set_nodelay(true);
        let mut stream = noise::connect(tcp, &noise::derive_psk(code))
            .await
            .context("enrollment handshake failed (is the code right?)")?;
        let frame = read_frame(&mut stream, MAX_CREDENTIALS_LEN)
            .await
            .context("server did not return credentials")?;
        serde_json::from_slice(&frame).context("server sent malformed credentials")
    };
    tokio::time::timeout(timeout, attempt)
        .await
        .context("timed out waiting for enrollment")?
}
