//! Tenants and enrollment codes for a multi-tenant `serve`, and the snapshot
//! type the handshake and router consult. Nothing here touches a socket.
//!
//! A tenant is identified during the Noise handshake by which of the known
//! PSKs verifies (see [`crate::noise::accept_any`]); its `sni` is the routing
//! key for inbound TLS connections. Only the PSK (a hash of the token) is
//! stored, never the token itself.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub const DEFAULT_MAX_CONNS: usize = 64;

fn default_max_conns() -> usize {
    DEFAULT_MAX_CONNS
}

/// Trims a host, lowercases it and drops one trailing dot: the form used for
/// matching.
pub fn normalize_host(host: &str) -> String {
    let host = host.trim();
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tenant {
    pub name: String,
    #[serde(with = "hex32")]
    pub psk: [u8; 32],
    pub sni: String,
    #[serde(default = "default_max_conns")]
    pub max_conns: usize,
    #[serde(default)]
    pub disabled: bool,
}

/// A single-use PSK that can be redeemed for a new tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollCode {
    #[serde(with = "hex32")]
    pub psk: [u8; 32],
    pub sni: String,
    #[serde(default = "default_max_conns")]
    pub max_conns: usize,
    /// Unix seconds after which the code no longer works.
    #[serde(default)]
    pub expires_at: Option<u64>,
}

/// What a successful PSK match turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    Tenant(Tenant),
    Code(EnrollCode),
}

/// The PSKs to try for one handshake, and what each one stands for.
#[derive(Debug, Clone, Default)]
pub struct Candidates {
    pub psks: Vec<[u8; 32]>,
    ids: Vec<Identity>,
}

impl Candidates {
    pub fn identity(&self, index: usize) -> &Identity {
        &self.ids[index]
    }
}

/// An immutable, validated snapshot of every tenant and outstanding code.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TenantSet {
    tenants: Vec<Tenant>,
    codes: Vec<EnrollCode>,
}

impl TenantSet {
    /// Builds a snapshot, rejecting anything that would make identification or
    /// routing ambiguous: duplicate names, duplicate hosts, a PSK shared by two
    /// entries, an empty host, or a zero connection limit.
    pub fn new(tenants: Vec<Tenant>, codes: Vec<EnrollCode>) -> Result<Self> {
        let mut names = HashSet::new();
        let mut hosts = HashSet::new();
        let mut psks = HashSet::new();
        for t in &tenants {
            if t.name.is_empty() {
                bail!("tenant has an empty name");
            }
            if !names.insert(t.name.clone()) {
                bail!("duplicate tenant name '{}'", t.name);
            }
            check_entry(&t.sni, t.max_conns, &t.name)?;
            if !hosts.insert(normalize_host(&t.sni)) {
                bail!("duplicate sni '{}' (tenant '{}')", t.sni, t.name);
            }
            if !psks.insert(t.psk) {
                bail!("tenant '{}' shares a PSK with another entry", t.name);
            }
        }
        for c in &codes {
            check_entry(&c.sni, c.max_conns, "enrollment code")?;
            if !psks.insert(c.psk) {
                bail!("an enrollment code shares a PSK with another entry");
            }
        }
        Ok(Self { tenants, codes })
    }

    pub fn tenants(&self) -> &[Tenant] {
        &self.tenants
    }

    pub fn codes(&self) -> &[EnrollCode] {
        &self.codes
    }

    pub fn tenant(&self, name: &str) -> Option<&Tenant> {
        self.tenants.iter().find(|t| t.name == name)
    }

    /// The enabled tenant routed by `sni`, if any.
    pub fn tenant_by_sni(&self, sni: &str) -> Option<&Tenant> {
        let wanted = normalize_host(sni);
        self.tenants
            .iter()
            .find(|t| !t.disabled && normalize_host(&t.sni) == wanted)
    }

    /// PSKs worth trying at `now_unix` seconds: enabled tenants and codes that
    /// have not expired.
    pub fn candidates(&self, now_unix: u64) -> Candidates {
        let mut out = Candidates::default();
        for t in self.tenants.iter().filter(|t| !t.disabled) {
            out.psks.push(t.psk);
            out.ids.push(Identity::Tenant(t.clone()));
        }
        for c in self
            .codes
            .iter()
            .filter(|c| c.expires_at.is_none_or(|at| now_unix < at))
        {
            out.psks.push(c.psk);
            out.ids.push(Identity::Code(c.clone()));
        }
        out
    }
}

fn check_entry(sni: &str, max_conns: usize, what: &str) -> Result<()> {
    if normalize_host(sni).is_empty() {
        bail!("{what} has an empty sni");
    }
    if max_conns == 0 {
        bail!("{what} has max_conns = 0");
    }
    Ok(())
}

/// On-disk shape of the tenant file.
#[derive(Debug, Default, Serialize, Deserialize)]
struct TenantFile {
    #[serde(default)]
    tenant: Vec<Tenant>,
    #[serde(default)]
    code: Vec<EnrollCode>,
}

impl TenantSet {
    pub fn from_toml(text: &str) -> Result<Self> {
        let file: TenantFile = toml::from_str(text).context("parsing tenant file")?;
        Self::new(file.tenant, file.code)
    }

    pub fn to_toml(&self) -> Result<String> {
        let file = TenantFile {
            tenant: self.tenants.clone(),
            code: self.codes.clone(),
        };
        toml::to_string_pretty(&file).context("serialising tenant file")
    }

    /// Reads a tenant file. A missing file is an empty set, so a fresh
    /// deployment can start `serve` before issuing anything.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::from_toml(&text)
                .with_context(|| format!("loading tenant file {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }
}

/// Serde adapter storing a 32-byte PSK as 64 hex characters.
mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        let mut out = String::with_capacity(64);
        for b in bytes {
            out.push_str(&format!("{b:02x}"));
        }
        s.serialize_str(&out)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        if text.len() != 64 || !text.is_ascii() {
            return Err(D::Error::custom("psk must be 64 hex characters"));
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
                .map_err(|_| D::Error::custom("psk must be 64 hex characters"))?;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::derive_psk;

    fn tenant(name: &str, token: &str, sni: &str) -> Tenant {
        Tenant {
            name: name.into(),
            psk: derive_psk(token),
            sni: sni.into(),
            max_conns: 8,
            disabled: false,
        }
    }

    fn code(token: &str, sni: &str, expires_at: Option<u64>) -> EnrollCode {
        EnrollCode {
            psk: derive_psk(token),
            sni: sni.into(),
            max_conns: 8,
            expires_at,
        }
    }

    #[test]
    fn sni_lookup_ignores_case_and_trailing_dot() {
        let set = TenantSet::new(vec![tenant("a", "ta", "Abc.Example.com")], vec![]).unwrap();
        assert_eq!(set.tenant_by_sni("abc.example.COM.").unwrap().name, "a");
        assert!(set.tenant_by_sni("other.example.com").is_none());
    }

    #[test]
    fn disabled_tenants_are_neither_routed_nor_candidates() {
        let mut t = tenant("a", "ta", "a.example.com");
        t.disabled = true;
        let set = TenantSet::new(vec![t], vec![]).unwrap();
        assert!(set.tenant_by_sni("a.example.com").is_none());
        assert!(set.candidates(0).psks.is_empty());
    }

    #[test]
    fn expired_codes_are_not_candidates() {
        let set = TenantSet::new(
            vec![],
            vec![
                code("fresh", "a.x", Some(200)),
                code("stale", "b.x", Some(100)),
            ],
        )
        .unwrap();
        let c = set.candidates(150);
        assert_eq!(c.psks, vec![derive_psk("fresh")]);
        assert!(matches!(c.identity(0), Identity::Code(_)));
        assert!(set.candidates(100).psks.len() == 1, "expiry is exclusive");
    }

    #[test]
    fn candidates_map_back_to_their_identity() {
        let set = TenantSet::new(
            vec![tenant("a", "ta", "a.x"), tenant("b", "tb", "b.x")],
            vec![code("c1", "c.x", None)],
        )
        .unwrap();
        let c = set.candidates(0);
        let at = |token: &str| c.psks.iter().position(|p| *p == derive_psk(token)).unwrap();
        assert!(matches!(c.identity(at("tb")), Identity::Tenant(t) if t.name == "b"));
        assert!(matches!(c.identity(at("c1")), Identity::Code(_)));
    }

    #[test]
    fn ambiguous_sets_are_rejected() {
        let dup_name = TenantSet::new(
            vec![tenant("a", "t1", "a.x"), tenant("a", "t2", "b.x")],
            vec![],
        );
        let dup_host = TenantSet::new(
            vec![tenant("a", "t1", "A.x"), tenant("b", "t2", "a.X")],
            vec![],
        );
        let dup_psk = TenantSet::new(
            vec![tenant("a", "same", "a.x"), tenant("b", "same", "b.x")],
            vec![],
        );
        let code_psk = TenantSet::new(
            vec![tenant("a", "same", "a.x")],
            vec![code("same", "z.x", None)],
        );
        let empty_sni = TenantSet::new(vec![tenant("a", "t", " ")], vec![]);
        let zero = {
            let mut t = tenant("a", "t", "a.x");
            t.max_conns = 0;
            TenantSet::new(vec![t], vec![])
        };
        for (what, r) in [
            ("duplicate name", dup_name),
            ("duplicate host", dup_host),
            ("duplicate psk", dup_psk),
            ("code psk clash", code_psk),
            ("empty sni", empty_sni),
            ("zero max_conns", zero),
        ] {
            assert!(r.is_err(), "{what} should be rejected");
        }
    }

    #[test]
    fn toml_round_trip_stores_the_psk_as_hex() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct File {
            tenant: Vec<Tenant>,
        }
        let original = File {
            tenant: vec![tenant("a", "ta", "a.x")],
        };
        let text = toml::to_string(&original).unwrap();
        assert!(text.contains(&format!("psk = \"{}\"", hex_of(&derive_psk("ta")))));
        assert!(!text.contains("\"ta\""), "the token must never be stored");
        assert_eq!(toml::from_str::<File>(&text).unwrap(), original);
    }

    #[test]
    fn malformed_psk_is_rejected_on_load() {
        let bad = "name = \"a\"\npsk = \"zz\"\nsni = \"a.x\"\n";
        assert!(toml::from_str::<Tenant>(bad).is_err());
    }

    fn hex_of(b: &[u8; 32]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
