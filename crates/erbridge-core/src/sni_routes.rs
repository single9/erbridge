//! The `[forward.sni]` route table: picks a forward rule's target from the
//! SNI of the TLS ClientHello its client sends.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use anyhow::{Result, bail};

use crate::tenant::normalize_host;

/// A validated SNI route table plus the rule's optional fallback target.
///
/// Matching order: exact host, then a single-label wildcard (`*.example.com`
/// matches `a.example.com`, but neither `example.com` nor `a.b.example.com`),
/// then the fallback. Hosts are compared after [`normalize_host`].
#[derive(Debug, Clone)]
pub(crate) struct SniRoutes {
    exact: HashMap<String, String>,
    /// Keyed by the part after `*.`.
    wildcard: HashMap<String, String>,
    fallback: Option<String>,
}

impl SniRoutes {
    pub(crate) fn new(table: &BTreeMap<String, String>, fallback: Option<&str>) -> Result<Self> {
        let mut exact = HashMap::new();
        let mut wildcard = HashMap::new();
        for (raw_key, target) in table {
            if target.trim().is_empty() {
                bail!("SNI route '{raw_key}' has an empty target");
            }
            let key = normalize_host(raw_key);
            let (map, host) = match key.strip_prefix("*.") {
                Some(suffix) => (&mut wildcard, suffix),
                None => (&mut exact, key.as_str()),
            };
            check_host(raw_key, host)?;
            if map.insert(host.to_string(), target.clone()).is_some() {
                bail!("SNI route '{raw_key}' duplicates another key once normalized");
            }
        }
        Ok(Self {
            exact,
            wildcard,
            fallback: fallback.map(str::to_string),
        })
    }

    /// The target for a ClientHello carrying `sni`, or `None` if nothing
    /// matches and there is no fallback.
    pub(crate) fn resolve(&self, sni: Option<&str>) -> Option<&str> {
        let routed = sni.and_then(|raw| {
            let host = normalize_host(raw);
            self.exact.get(&host).or_else(|| {
                let (_, parent) = host.split_once('.')?;
                self.wildcard.get(parent)
            })
        });
        routed.or(self.fallback.as_ref()).map(String::as_str)
    }
}

/// A key must be a DNS-style host with at least two labels; `*` is only valid
/// as the whole leftmost label, and an IP literal can never appear in SNI.
fn check_host(raw_key: &str, host: &str) -> Result<()> {
    let valid = !host.is_empty()
        && host.contains('.')
        && host
            .split('.')
            .all(|label| !label.is_empty() && label.bytes().all(is_host_byte));
    if !valid {
        bail!(
            "SNI route '{raw_key}' is not a valid host name (use `a.example.com` or `*.example.com`)"
        );
    }
    if host.parse::<IpAddr>().is_ok() {
        bail!("SNI route '{raw_key}' is an IP address, which never appears in SNI");
    }
    Ok(())
}

fn is_host_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routes(pairs: &[(&str, &str)], fallback: Option<&str>) -> Result<SniRoutes> {
        let table = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        SniRoutes::new(&table, fallback)
    }

    #[test]
    fn exact_match_wins_over_wildcard() {
        let r = routes(
            &[("a.example.com", "exact:1"), ("*.example.com", "wild:2")],
            None,
        )
        .unwrap();
        assert_eq!(r.resolve(Some("a.example.com")), Some("exact:1"));
        assert_eq!(r.resolve(Some("b.example.com")), Some("wild:2"));
    }

    #[test]
    fn wildcard_matches_exactly_one_label() {
        let r = routes(&[("*.example.com", "wild:2")], None).unwrap();
        assert_eq!(r.resolve(Some("example.com")), None);
        assert_eq!(r.resolve(Some("a.b.example.com")), None);
    }

    #[test]
    fn matching_ignores_case_and_a_trailing_dot() {
        let r = routes(&[("App.Example.COM.", "t:1")], None).unwrap();
        assert_eq!(r.resolve(Some("app.example.com")), Some("t:1"));
        assert_eq!(r.resolve(Some("APP.example.com.")), Some("t:1"));
    }

    #[test]
    fn unmatched_or_missing_sni_uses_the_fallback() {
        let r = routes(&[("a.example.com", "t:1")], Some("fb:9")).unwrap();
        assert_eq!(r.resolve(Some("other.example.net")), Some("fb:9"));
        assert_eq!(r.resolve(None), Some("fb:9"));
    }

    #[test]
    fn unmatched_without_fallback_is_none() {
        let r = routes(&[("a.example.com", "t:1")], None).unwrap();
        assert_eq!(r.resolve(None), None);
        assert_eq!(r.resolve(Some("b.example.com")), None);
    }

    #[test]
    fn keys_equal_after_normalizing_are_rejected() {
        let err = routes(&[("A.example.com", "t:1"), ("a.example.com", "t:2")], None).unwrap_err();
        assert!(err.to_string().contains("duplicates"), "{err:#}");
    }

    #[test]
    fn malformed_keys_are_rejected() {
        for key in [
            "",
            "*",
            "*.",
            "*.com.*",
            "a.*.example.com",
            "**.example.com",
            "localhost",
            "a..example.com",
            "a b.example.com",
            "192.0.2.1",
        ] {
            assert!(routes(&[(key, "t:1")], None).is_err(), "accepted {key:?}");
        }
    }

    #[test]
    fn an_empty_target_is_rejected() {
        assert!(routes(&[("a.example.com", " ")], None).is_err());
    }
}
