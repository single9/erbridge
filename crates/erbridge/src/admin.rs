//! `serve-admin`: edits the tenant file a multi-tenant `serve` is watching.
//! Safe to run while `serve` is up; changes apply within its reload interval.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use erbridge_core::tenant::{self, DEFAULT_MAX_CONNS};
use erbridge_core::tenant_store::{FileStore, TenantStore};

use crate::cli::AdminAction;

/// Runs one admin action against the tenant file at `path` and returns what to
/// print on stdout.
pub fn run(path: &Path, action: &AdminAction) -> Result<String> {
    let store = FileStore::new(path);
    match action {
        AdminAction::Issue {
            sni,
            max_conns,
            expires_in,
        } => {
            let max_conns = max_conns.unwrap_or(DEFAULT_MAX_CONNS);
            if max_conns == 0 {
                bail!("--max-conns must be at least 1");
            }
            let expires_at = expires_in.map(|secs| now_unix() + secs);
            let (code, entry) = tenant::new_enroll_code(sni, max_conns, expires_at);
            store.issue_code(entry)?;
            Ok(format!("{code}\n"))
        }
        AdminAction::Revoke { name } => {
            store.revoke(name)?;
            Ok(format!("revoked {name}\n"))
        }
        AdminAction::Disable { name } => {
            store.set_disabled(name, true)?;
            Ok(format!("disabled {name}\n"))
        }
        AdminAction::Enable { name } => {
            store.set_disabled(name, false)?;
            Ok(format!("enabled {name}\n"))
        }
        AdminAction::List => {
            let set = store.snapshot()?;
            let mut out = String::new();
            for t in set.tenants() {
                out.push_str(&format!(
                    "{}\t{}\tmax_conns={}\t{}\n",
                    t.name,
                    t.sni,
                    t.max_conns,
                    if t.disabled { "disabled" } else { "enabled" }
                ));
            }
            out.push_str(&format!(
                "{} tenant(s), {} unused enrollment code(s)\n",
                set.tenants().len(),
                set.codes().len()
            ));
            Ok(out)
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use erbridge_core::noise::derive_psk;
    use erbridge_core::tenant::Tenant;

    fn file() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tenants.toml");
        (dir, path)
    }

    fn issue(path: &Path, sni: &str) -> String {
        run(
            path,
            &AdminAction::Issue {
                sni: sni.into(),
                max_conns: Some(3),
                expires_in: Some(60),
            },
        )
        .unwrap()
        .trim()
        .to_string()
    }

    #[test]
    fn issue_prints_a_code_and_stores_only_its_hash() {
        let (_dir, path) = file();
        let code = issue(&path, "a.example.com");
        assert_eq!(code.len(), 32);

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains(&code), "the code itself must not be stored");
        let set = FileStore::new(&path).snapshot().unwrap();
        assert_eq!(set.codes().len(), 1);
        assert_eq!(set.codes()[0].psk, derive_psk(&code));
        assert_eq!(set.codes()[0].max_conns, 3);
        assert!(set.codes()[0].expires_at.unwrap() > now_unix());
    }

    #[test]
    fn revoke_disable_enable_and_list_work_on_existing_tenants() {
        let (_dir, path) = file();
        let store = FileStore::new(&path);
        store
            .add_tenant(Tenant {
                name: "t-1".into(),
                psk: derive_psk("x"),
                sni: "a.example.com".into(),
                max_conns: 8,
                disabled: false,
            })
            .unwrap();

        run(&path, &AdminAction::Disable { name: "t-1".into() }).unwrap();
        assert!(run(&path, &AdminAction::List).unwrap().contains("disabled"));
        run(&path, &AdminAction::Enable { name: "t-1".into() }).unwrap();
        let listing = run(&path, &AdminAction::List).unwrap();
        assert!(listing.contains("t-1\ta.example.com\tmax_conns=8\tenabled"));
        assert!(listing.contains("1 tenant(s), 0 unused"));

        run(&path, &AdminAction::Revoke { name: "t-1".into() }).unwrap();
        assert!(
            run(&path, &AdminAction::List)
                .unwrap()
                .contains("0 tenant(s)")
        );
    }

    #[test]
    fn unknown_names_and_bad_limits_are_errors() {
        let (_dir, path) = file();
        assert!(
            run(
                &path,
                &AdminAction::Revoke {
                    name: "nope".into()
                }
            )
            .is_err()
        );
        assert!(
            run(
                &path,
                &AdminAction::Disable {
                    name: "nope".into()
                }
            )
            .is_err()
        );
        let zero = AdminAction::Issue {
            sni: "a.x".into(),
            max_conns: Some(0),
            expires_in: None,
        };
        assert!(run(&path, &zero).is_err());
    }

    #[test]
    fn issuing_the_same_host_twice_is_allowed_until_redeemed() {
        // Two outstanding codes for one host are fine; the clash, if any,
        // surfaces when the second is redeemed.
        let (_dir, path) = file();
        issue(&path, "a.example.com");
        issue(&path, "a.example.com");
        assert_eq!(FileStore::new(&path).snapshot().unwrap().codes().len(), 2);
    }
}
