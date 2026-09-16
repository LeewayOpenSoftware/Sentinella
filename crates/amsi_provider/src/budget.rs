//! A hard wall-clock budget for the daemon round-trip.
//!
//! The provider runs inside Word, PowerShell, etc. The named-pipe I/O it
//! does has no portable read timeout, so instead of trying to time-bound
//! the syscall we run the whole round-trip on a scratch thread and wait at
//! most `budget` for a result. If the budget elapses we return `None` and
//! the caller fails open; the worker thread is detached and its late
//! result is simply dropped. This guarantees `Scan` returns within roughly
//! `budget` no matter how wedged the daemon is.

use std::sync::mpsc;
use std::time::Duration;

/// Run `f` and wait at most `budget`. `None` on timeout (or if a worker
/// thread cannot even be spawned — also a reason to fail open rather than
/// block the host).
pub fn run_with_budget<T, F>(budget: Duration, f: F) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("amsi-scan".into())
        .spawn(move || {
            // Ignore send errors: the receiver may have already timed out.
            let _ = tx.send(f());
        });
    if spawned.is_err() {
        return None;
    }
    rx.recv_timeout(budget).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_work_returns_value() {
        let r = run_with_budget(Duration::from_secs(5), || 21 * 2);
        assert_eq!(r, Some(42));
    }

    #[test]
    fn slow_work_times_out_to_none() {
        // Worker sleeps well past the budget -> None (fail-open trigger).
        let r = run_with_budget(Duration::from_millis(50), || {
            std::thread::sleep(Duration::from_millis(600));
            42
        });
        assert_eq!(r, None);
    }

    #[test]
    fn timeout_is_roughly_bounded() {
        let start = std::time::Instant::now();
        let _ = run_with_budget(Duration::from_millis(100), || {
            std::thread::sleep(Duration::from_secs(10));
        });
        // We must have given up long before the worker's 10s.
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
