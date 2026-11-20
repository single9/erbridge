//! Bounds how many connections may sit in an unauthenticated or not yet
//! routed state (mid-handshake, waiting for a ClientHello), in total and per
//! source address, so slow or silent peers cannot pin unbounded tasks and
//! file descriptors.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// How many connections may be pending at once, by default.
pub(crate) const DEFAULT_MAX_PENDING: usize = 256;

/// How many of those one address may hold, by default, so a single host cannot
/// use up every slot.
pub(crate) const DEFAULT_MAX_PENDING_PER_IP: usize = 16;

#[derive(Debug)]
pub(crate) struct PendingLimiter {
    global: Arc<Semaphore>,
    per_ip: usize,
    by_ip: Mutex<HashMap<IpAddr, usize>>,
    refused: AtomicU64,
}

/// Holds one pending slot, global and per address, until dropped.
#[derive(Debug)]
pub(crate) struct PendingSlot {
    limiter: Arc<PendingLimiter>,
    ip: IpAddr,
    _global: OwnedSemaphorePermit,
}

impl Drop for PendingSlot {
    fn drop(&mut self) {
        let mut by_ip = lock(&self.limiter.by_ip);
        if let Some(n) = by_ip.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                by_ip.remove(&self.ip);
            }
        }
    }
}

impl PendingLimiter {
    pub(crate) fn new(max: usize, per_ip: usize) -> Arc<Self> {
        Arc::new(Self {
            global: Arc::new(Semaphore::new(max)),
            per_ip,
            by_ip: Mutex::new(HashMap::new()),
            refused: AtomicU64::new(0),
        })
    }

    pub(crate) fn with_defaults() -> Arc<Self> {
        Self::new(DEFAULT_MAX_PENDING, DEFAULT_MAX_PENDING_PER_IP)
    }

    /// Takes a slot for `ip`, or returns `Err(refused_so_far)` if the limiter
    /// or that address is at its limit. The count lets the caller log the
    /// first refusal and then only every thousandth, since under a flood this
    /// would otherwise be one log line per connection.
    pub(crate) fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Result<PendingSlot, Refused> {
        let refuse = || Refused(self.refused.fetch_add(1, Ordering::Relaxed) + 1);
        let Ok(global) = self.global.clone().try_acquire_owned() else {
            return Err(refuse());
        };
        let mut by_ip = lock(&self.by_ip);
        let n = by_ip.entry(ip).or_insert(0);
        if *n >= self.per_ip {
            drop(by_ip);
            return Err(refuse());
        }
        *n += 1;
        drop(by_ip);
        Ok(PendingSlot {
            limiter: self.clone(),
            ip,
            _global: global,
        })
    }
}

/// A refused acquisition, carrying how many have been refused so far
/// (this one included).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Refused(pub(crate) u64);

impl Refused {
    /// Whether this refusal is worth a log line: the first, then every
    /// thousandth.
    pub(crate) fn should_log(self) -> bool {
        self.0 == 1 || self.0.is_multiple_of(1000)
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
    const B: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2));

    #[test]
    fn per_address_limit_does_not_block_other_addresses() {
        let limiter = PendingLimiter::new(10, 2);
        let _a1 = limiter.try_acquire(A).unwrap();
        let _a2 = limiter.try_acquire(A).unwrap();
        assert_eq!(limiter.try_acquire(A).unwrap_err(), Refused(1));
        assert!(limiter.try_acquire(B).is_ok());
    }

    #[test]
    fn global_limit_applies_across_addresses() {
        let limiter = PendingLimiter::new(1, 5);
        let _a = limiter.try_acquire(A).unwrap();
        assert!(limiter.try_acquire(B).is_err());
    }

    #[test]
    fn dropping_a_slot_frees_it() {
        let limiter = PendingLimiter::new(1, 1);
        drop(limiter.try_acquire(A).unwrap());
        let slot = limiter.try_acquire(A).unwrap();
        drop(slot);
        assert!(
            lock(&limiter.by_ip).is_empty(),
            "drained entries are removed"
        );
    }

    #[test]
    fn refusals_are_logged_first_then_every_thousandth() {
        assert!(Refused(1).should_log());
        assert!(!Refused(2).should_log());
        assert!(!Refused(999).should_log());
        assert!(Refused(1000).should_log());
        assert!(Refused(2000).should_log());
    }
}
