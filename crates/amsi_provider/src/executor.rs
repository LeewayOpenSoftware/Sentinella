//! Bounded, panic-safe execution of the daemon round-trip (Finding 3).
//!
//! The provider runs inside Word/PowerShell, and PowerShell scans nearly
//! every command and script block, so spawning a thread per `Scan` was
//! high-frequency thread creation inside the host — and, worse, a scan that
//! overran its budget left its worker thread *detached and blocked on pipe
//! I/O*, so a wedged daemon accumulated one stuck thread per subsequent
//! scan.
//!
//! This replaces spawn-per-call with:
//! - a small **fixed pool** of persistent workers (bounded thread count no
//!   matter the scan rate), and
//! - a **circuit breaker**: after a few consecutive budget overruns it
//!   short-circuits to fail-open (NOT_DETECTED) for a cool-down window
//!   without touching a worker at all, so a stuck or dead daemon cannot
//!   pile up blocked threads in the host.

use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::decision::DaemonVerdict;

/// Hard per-scan wall-clock budget. Missing it fails open.
pub const SCAN_BUDGET: Duration = Duration::from_millis(250);
/// Consecutive budget overruns before the breaker opens.
const BREAKER_THRESHOLD: u32 = 3;
/// How long the breaker stays open (fail open fast, no worker touched).
const BREAKER_COOLDOWN: Duration = Duration::from_secs(5);
/// Persistent workers. Enough for host concurrency; bounded so a wedged
/// daemon can leak at most this many threads, ever — not one per scan.
const POOL_SIZE: usize = 4;
/// Per-worker queue depth. try_send failure across all workers => shed.
const PER_WORKER_CAP: usize = 4;

type Verdict = Option<DaemonVerdict>;
type Job = Box<dyn FnOnce() -> Verdict + Send + 'static>;

struct Queued {
    job: Job,
    reply: SyncSender<Verdict>,
}

/// Pure circuit-breaker state, parameterised for deterministic testing.
struct Breaker {
    consecutive: AtomicU32,
    /// Millis (from a monotonic base) the breaker stays open until; 0 = closed.
    open_until_ms: AtomicU64,
}

impl Breaker {
    const fn new() -> Self {
        Self {
            consecutive: AtomicU32::new(0),
            open_until_ms: AtomicU64::new(0),
        }
    }
    fn is_open(&self, now_ms: u64) -> bool {
        let until = self.open_until_ms.load(Ordering::Relaxed);
        until != 0 && now_ms < until
    }
    fn record_success(&self) {
        self.consecutive.store(0, Ordering::Relaxed);
        self.open_until_ms.store(0, Ordering::Relaxed);
    }
    fn record_timeout(&self, now_ms: u64, threshold: u32, cooldown_ms: u64) {
        let n = self.consecutive.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= threshold {
            self.open_until_ms.store(now_ms + cooldown_ms, Ordering::Relaxed);
        }
    }
}

struct Executor {
    txs: Vec<SyncSender<Queued>>,
    next: AtomicUsize,
    breaker: Breaker,
    base: Instant,
}

impl Executor {
    fn now_ms(&self) -> u64 {
        self.base.elapsed().as_millis() as u64
    }
}

fn executor() -> &'static Executor {
    static EXEC: OnceLock<Executor> = OnceLock::new();
    EXEC.get_or_init(|| {
        let mut txs = Vec::with_capacity(POOL_SIZE);
        for _ in 0..POOL_SIZE {
            let (tx, rx) = sync_channel::<Queued>(PER_WORKER_CAP);
            txs.push(tx);
            // A worker that cannot even be spawned just means fewer workers;
            // the breaker + shed path still keep the host safe.
            let _ = std::thread::Builder::new()
                .name("amsi-scan".into())
                .spawn(move || {
                    while let Ok(q) = rx.recv() {
                        // The reply may have already timed out; that is fine,
                        // try_send just fails and we drop the result.
                        let v = (q.job)();
                        let _ = q.reply.try_send(v);
                    }
                });
        }
        Executor {
            txs,
            next: AtomicUsize::new(0),
            breaker: Breaker::new(),
            base: Instant::now(),
        }
    })
}

/// Run one daemon round-trip under the budget and breaker. `None` means
/// fail open (breaker tripped, all workers saturated, or the job overran
/// the budget). Never spawns a thread per call.
pub fn run_scan<F>(f: F) -> Verdict
where
    F: FnOnce() -> Verdict + Send + 'static,
{
    let ex = executor();
    let now = ex.now_ms();
    if ex.breaker.is_open(now) {
        return None; // fail open fast, no worker touched
    }
    if ex.txs.is_empty() {
        return None; // no workers could be spawned
    }

    let (rtx, rrx) = sync_channel::<Verdict>(1);
    let mut queued = Queued {
        job: Box::new(f),
        reply: rtx,
    };
    // Round-robin across workers; shed if every worker's queue is full.
    let start = ex.next.fetch_add(1, Ordering::Relaxed);
    let mut dispatched = false;
    for k in 0..ex.txs.len() {
        let idx = (start + k) % ex.txs.len();
        match ex.txs[idx].try_send(queued) {
            Ok(()) => {
                dispatched = true;
                break;
            }
            Err(std::sync::mpsc::TrySendError::Full(q)) => queued = q,
            Err(std::sync::mpsc::TrySendError::Disconnected(q)) => queued = q,
        }
    }
    if !dispatched {
        ex.breaker.record_timeout(
            ex.now_ms(),
            BREAKER_THRESHOLD,
            BREAKER_COOLDOWN.as_millis() as u64,
        );
        return None;
    }

    match rrx.recv_timeout(SCAN_BUDGET) {
        Ok(v) => {
            ex.breaker.record_success();
            v
        }
        Err(_) => {
            ex.breaker.record_timeout(
                ex.now_ms(),
                BREAKER_THRESHOLD,
                BREAKER_COOLDOWN.as_millis() as u64,
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn breaker_opens_after_threshold_and_resets_on_success() {
        let b = Breaker::new();
        assert!(!b.is_open(0));
        b.record_timeout(0, 3, 5_000);
        assert!(!b.is_open(0));
        b.record_timeout(0, 3, 5_000);
        assert!(!b.is_open(0));
        b.record_timeout(0, 3, 5_000); // third -> open
        assert!(b.is_open(0));
        assert!(b.is_open(4_999));
        assert!(!b.is_open(5_000)); // cooldown elapsed
        // A success fully closes and resets the counter.
        b.record_success();
        assert!(!b.is_open(0));
        b.record_timeout(0, 3, 5_000);
        assert!(!b.is_open(0)); // counter was reset, so one timeout != open
    }

    #[test]
    fn fast_job_returns_value() {
        let r = run_scan(|| Some(DaemonVerdict { score: 42, should_block: true }));
        assert_eq!(r, Some(DaemonVerdict { score: 42, should_block: true }));
    }

    #[test]
    fn slow_job_times_out_to_none_within_budget() {
        let start = Instant::now();
        let r = run_scan(|| {
            std::thread::sleep(Duration::from_millis(1500));
            Some(DaemonVerdict { score: 99, should_block: true })
        });
        assert_eq!(r, None); // budget exceeded -> fail open
        // Must have given up around the budget, not waited the full 1.5s.
        assert!(start.elapsed() < Duration::from_millis(900));
    }

    #[test]
    fn recovers_after_a_single_timeout() {
        // One slow scan must not wedge the pool for the next one.
        let _ = run_scan(|| {
            std::thread::sleep(Duration::from_millis(1500));
            None
        });
        let r = run_scan(|| Some(DaemonVerdict { score: 1, should_block: false }));
        assert_eq!(r, Some(DaemonVerdict { score: 1, should_block: false }));
    }
}
