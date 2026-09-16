//! Trusted hash cache — local file-level trust from prior verified scans.
//!
//! When a file is scanned clean AND has a valid signature or reputation match,
//! its SHA-256 hash is cached. Future scans skip full analysis if the hash
//! matches and the file hasn't changed.
//!
//! NOT a whitelist — cached trust expires after signature updates.
//! NOT cloud-dependent — fully local, deterministic.

use std::collections::HashMap;
use std::sync::Mutex;

/// Maximum entries in the trusted cache.
const MAX_ENTRIES: usize = 10_000;

/// A verified-clean file entry.
#[allow(dead_code)] // signer/reputation stored for future diagnostics export
struct TrustedEntry {
    signer: Option<String>,
    reputation: Option<String>,
    score: u32,
    sig_generation: u64,
    last_verified: u64, // access counter for LRU
}

/// Thread-safe trusted hash cache.
pub struct TrustedCache {
    inner: Mutex<CacheInner>,
}

struct CacheInner {
    entries: HashMap<String, TrustedEntry>, // key = SHA-256
    sig_generation: u64,
    access_counter: u64,
}

impl Default for TrustedCache {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustedCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(CacheInner {
                entries: HashMap::new(),
                sig_generation: 1,
                access_counter: 0,
            }),
        }
    }

    /// Check if a hash is in the trusted cache.
    /// Returns Some(previous_score) if trusted and still valid, None if not cached.
    pub fn check(&self, sha256: &str) -> Option<u32> {
        let mut inner = self.inner.lock().ok()?;
        inner.access_counter += 1;
        let current_gen = inner.sig_generation;
        let current_acc = inner.access_counter;

        inner.entries.get_mut(sha256).and_then(|entry| {
            if entry.sig_generation == current_gen {
                entry.last_verified = current_acc;
                Some(entry.score)
            } else {
                None // Expired — signatures updated since verification.
            }
        })
    }

    /// Record a file as verified-clean with trust signals.
    /// Only caches files that have signer OR reputation (not random unsigned files).
    pub fn record(&self, sha256: &str, score: u32, signer: Option<&str>, reputation: Option<&str>) {
        // Only cache if there's trust evidence.
        if signer.is_none() && reputation.is_none() {
            return;
        }
        // Only cache clean/low-suspicion files.
        if score > 25 {
            return;
        }

        let mut inner = match self.inner.lock() {
            Ok(i) => i,
            Err(_) => return,
        };

        inner.access_counter += 1;

        // LRU eviction.
        if inner.entries.len() >= MAX_ENTRIES {
            let threshold = inner.access_counter.saturating_sub(MAX_ENTRIES as u64 / 2);
            inner.entries.retain(|_, e| e.last_verified > threshold);
        }

        let current_gen = inner.sig_generation;
        let current_acc = inner.access_counter;
        inner.entries.insert(
            sha256.to_string(),
            TrustedEntry {
                signer: signer.map(|s| s.to_string()),
                reputation: reputation.map(|s| s.to_string()),
                score,
                sig_generation: current_gen,
                last_verified: current_acc,
            },
        );
    }

    /// Invalidate all entries (e.g., after signature update).
    pub fn invalidate(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.sig_generation += 1;
            // Drop the now-stale entries immediately — otherwise up to
            // MAX_ENTRIES dead entries linger until LRU pressure evicts them.
            inner.entries.clear();
        }
    }

    /// Cache stats.
    pub fn stats(&self) -> (usize, u64) {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        (inner.entries.len(), inner.sig_generation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hit_then_expire_on_invalidate() {
        let cache = TrustedCache::new();
        // Only signed/reputable, low-score files are cached.
        cache.record("abc", 0, Some("Acme Corp"), None);
        assert_eq!(cache.check("abc"), Some(0), "freshly recorded hash must hit");

        // A signature/rule update bumps the generation → the entry must expire,
        // forcing re-analysis. This is the wiring that production was missing.
        cache.invalidate();
        assert_eq!(
            cache.check("abc"),
            None,
            "entry must expire after invalidate() so new rules re-scan it"
        );
    }

    #[test]
    fn unsigned_or_high_score_not_cached() {
        let cache = TrustedCache::new();
        cache.record("nosig", 0, None, None); // no trust evidence
        assert_eq!(cache.check("nosig"), None);
        cache.record("hot", 40, Some("Acme"), None); // score > 25
        assert_eq!(cache.check("hot"), None);
    }
}
