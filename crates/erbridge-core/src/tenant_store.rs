//! Where tenants live. [`TenantStore`] is the seam a host can implement to keep
//! them somewhere other than a file (a database, say); `MemoryStore` and
//! `FileStore` are the two provided implementations.
//!
//! Every change is a read-modify-write of the whole [`TenantSet`], applied
//! atomically, so concurrent writers (`serve` redeeming a code while an
//! operator issues another) cannot lose each other's entries.

use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::noise::Psk;
use anyhow::{Context, Result};

use crate::tenant::{EnrollCode, Tenant, TenantSet};

/// The type of the closure [`TenantStore::replace_with`] applies.
pub type Edit<'a> = dyn FnMut(&TenantSet) -> Result<TenantSet> + 'a;

pub trait TenantStore: Send + Sync {
    /// The current contents.
    fn snapshot(&self) -> Result<TenantSet>;

    /// Atomically replaces the contents with `edit(current)` and returns the
    /// new contents. If `edit` fails nothing is written.
    fn replace_with(&self, edit: &mut Edit<'_>) -> Result<TenantSet>;

    fn add_tenant(&self, tenant: Tenant) -> Result<()> {
        self.replace_with(&mut |s| s.with_tenant(tenant.clone()))
            .map(drop)
    }

    fn issue_code(&self, code: EnrollCode) -> Result<()> {
        self.replace_with(&mut |s| s.with_code(code.clone()))
            .map(drop)
    }

    /// Removes a tenant outright; its PSK stops working and its session ends.
    fn revoke(&self, name: &str) -> Result<()> {
        self.replace_with(&mut |s| s.without_tenant(name)).map(drop)
    }

    /// Suspends or resumes a tenant without forgetting it.
    fn set_disabled(&self, name: &str, disabled: bool) -> Result<()> {
        self.replace_with(&mut |s| s.with_disabled(name, disabled))
            .map(drop)
    }

    /// Burns an enrollment code and creates the tenant it entitles. Exactly one
    /// of several concurrent redemptions of the same code succeeds.
    fn redeem(&self, code_psk: &Psk, now_unix: u64, name: String, psk: Psk) -> Result<Tenant> {
        let mut created = None;
        self.replace_with(&mut |s| {
            let (next, tenant) = s.redeem(code_psk, now_unix, name.clone(), psk)?;
            created = Some(tenant);
            Ok(next)
        })?;
        Ok(created.expect("redeem succeeded without producing a tenant"))
    }
}

/// Keeps everything in memory; for tests and hosts that manage persistence
/// themselves.
#[derive(Default)]
pub struct MemoryStore(Mutex<TenantSet>);

impl MemoryStore {
    pub fn new(initial: TenantSet) -> Self {
        Self(Mutex::new(initial))
    }
}

impl TenantStore for MemoryStore {
    fn snapshot(&self) -> Result<TenantSet> {
        Ok(self.0.lock().unwrap().clone())
    }

    fn replace_with(&self, edit: &mut Edit<'_>) -> Result<TenantSet> {
        let mut guard = self.0.lock().unwrap();
        let next = edit(&guard)?;
        *guard = next.clone();
        Ok(next)
    }
}

/// A TOML file, safe to edit from several processes: writers take an exclusive
/// lock on a sidecar `<file>.lock`, and replace the file by atomic rename so a
/// reader never sees a half-written one.
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn sidecar(&self, suffix: &str) -> PathBuf {
        let mut name = self.path.as_os_str().to_owned();
        name.push(suffix);
        PathBuf::from(name)
    }
}

impl TenantStore for FileStore {
    fn snapshot(&self) -> Result<TenantSet> {
        TenantSet::load(&self.path)
    }

    fn replace_with(&self, edit: &mut Edit<'_>) -> Result<TenantSet> {
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.sidecar(".lock"))
            .with_context(|| format!("opening lock file for {}", self.path.display()))?;
        lock.lock().context("locking the tenant file")?;

        let current = TenantSet::load(&self.path)?;
        let next = edit(&current)?;
        let text = next.to_toml()?;

        // Unique per writer, so a crashed writer's leftover cannot be mistaken
        // for a live one's.
        let tmp = self.sidecar(&format!(".tmp-{}", std::process::id()));
        let written = write_private(&tmp, text.as_bytes())
            .with_context(|| format!("writing {}", tmp.display()))
            .and_then(|()| {
                std::fs::rename(&tmp, &self.path)
                    .with_context(|| format!("replacing {}", self.path.display()))
            });
        if written.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        written?;
        // The lock is released when `lock` drops.
        Ok(next)
    }
}

/// Writes `bytes` to `path` readable by its owner only: the file holds PSKs.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    // A leftover from a crashed writer may have looser permissions, and the
    // mode below only applies to a file this call creates.
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file: File = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::derive_psk;
    use std::sync::Arc;

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
            max_conns: 5,
            expires_at,
        }
    }

    /// The behaviour every implementation must share.
    fn conformance(store: &dyn TenantStore) {
        assert_eq!(store.snapshot().unwrap(), TenantSet::default());

        store.add_tenant(tenant("a", "ta", "a.x")).unwrap();
        store.add_tenant(tenant("b", "tb", "b.x")).unwrap();
        assert!(
            store.add_tenant(tenant("a", "other", "z.x")).is_err(),
            "duplicate name"
        );
        assert_eq!(store.snapshot().unwrap().tenants().len(), 2);

        store.set_disabled("a", true).unwrap();
        assert!(store.snapshot().unwrap().tenant("a").unwrap().disabled);
        assert!(store.set_disabled("nope", true).is_err());

        store.revoke("a").unwrap();
        assert!(store.snapshot().unwrap().tenant("a").is_none());
        assert!(store.snapshot().unwrap().tenant("b").is_some());
        assert!(store.revoke("a").is_err());

        // Redeeming creates a tenant from the code's host and limit, and burns it.
        store.issue_code(code("c1", "c.x", None)).unwrap();
        let made = store
            .redeem(&derive_psk("c1"), 0, "t-new".into(), derive_psk("fresh"))
            .unwrap();
        assert_eq!((made.sni.as_str(), made.max_conns), ("c.x", 5));
        let snap = store.snapshot().unwrap();
        assert!(snap.codes().is_empty());
        assert_eq!(snap.tenant("t-new").unwrap().psk, derive_psk("fresh"));
        assert!(
            store
                .redeem(&derive_psk("c1"), 0, "t-again".into(), derive_psk("x"))
                .is_err(),
            "a code works once"
        );

        // Expired codes cannot be redeemed, and the failure changes nothing.
        store.issue_code(code("old", "o.x", Some(100))).unwrap();
        let before = store.snapshot().unwrap();
        assert!(
            store
                .redeem(&derive_psk("old"), 100, "t-old".into(), derive_psk("y"))
                .is_err()
        );
        assert_eq!(store.snapshot().unwrap(), before);
    }

    fn concurrent_writers_lose_nothing(store: Arc<dyn TenantStore>) {
        let threads: Vec<_> = (0..8)
            .map(|t| {
                let store = store.clone();
                std::thread::spawn(move || {
                    for i in 0..10 {
                        let n = t * 10 + i;
                        store
                            .issue_code(code(&format!("tok-{n}"), &format!("h{n}.x"), None))
                            .unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(store.snapshot().unwrap().codes().len(), 80);
    }

    #[test]
    fn memory_store_conforms() {
        conformance(&MemoryStore::default());
        concurrent_writers_lose_nothing(Arc::new(MemoryStore::default()));
    }

    #[test]
    fn file_store_conforms() {
        let dir = tempfile::tempdir().unwrap();
        conformance(&FileStore::new(dir.path().join("tenants.toml")));
        let dir = tempfile::tempdir().unwrap();
        concurrent_writers_lose_nothing(Arc::new(FileStore::new(dir.path().join("t.toml"))));
    }

    #[test]
    fn two_file_stores_on_one_file_do_not_lose_each_others_writes() {
        // Stands in for `serve` and `serve-admin` writing from two processes.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.toml");
        let (a, b) = (FileStore::new(&path), FileStore::new(&path));
        let ta = std::thread::spawn(move || {
            for i in 0..20 {
                a.issue_code(code(&format!("a{i}"), &format!("a{i}.x"), None))
                    .unwrap();
            }
        });
        let tb = std::thread::spawn(move || {
            for i in 0..20 {
                b.issue_code(code(&format!("b{i}"), &format!("b{i}.x"), None))
                    .unwrap();
            }
        });
        ta.join().unwrap();
        tb.join().unwrap();
        assert_eq!(FileStore::new(&path).snapshot().unwrap().codes().len(), 40);
    }

    #[test]
    fn a_missing_file_is_an_empty_set_and_a_corrupt_one_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.toml");
        let store = FileStore::new(&path);
        assert_eq!(store.snapshot().unwrap(), TenantSet::default());

        std::fs::write(&path, "this is [not valid").unwrap();
        assert!(store.snapshot().is_err());
        assert!(store.add_tenant(tenant("a", "t", "a.x")).is_err());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "this is [not valid",
            "a failed edit must not overwrite the file"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_readable_by_its_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.toml");
        FileStore::new(&path)
            .add_tenant(tenant("a", "t", "a.x"))
            .unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
