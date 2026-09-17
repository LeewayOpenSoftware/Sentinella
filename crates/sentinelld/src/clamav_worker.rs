//! Optional external ClamAV worker invocation.
//!
//! Spawns `clamavd.exe` as a subprocess for isolated ClamAV scanning.
//! If clamavd crashes (e.g., CVE in libclamav), only the worker dies.
//! The daemon survives and can respawn a new worker.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use crate::win_process::QuietCommand;

use serde::Deserialize;

const MAX_OUTPUT_BYTES: usize = 1024 * 1024; // 1 MB max stdout
/// Max concurrent clamavd subprocesses (each loads ~400MB of sigs).
const MAX_CONCURRENT_WORKERS: usize = 2;

static ACTIVE_WORKERS: AtomicUsize = AtomicUsize::new(0);

/// Simple RAII guard — runs closure on drop.
struct Guard<F: FnOnce()>(Option<F>);
impl<F: FnOnce()> Drop for Guard<F> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}
fn scopeguard<F: FnOnce()>(f: F) -> Guard<F> {
    Guard(Some(f))
}

#[derive(Clone, Debug)]
pub struct ClamWorkerSettings {
    pub enabled: bool,
    pub dll_dir: PathBuf,
    pub db_dir: PathBuf,
    pub timeout: Duration,
}

#[derive(Debug, Deserialize)]
pub struct ClamWorkerOutput {
    pub path: String,
    pub infected: bool,
    pub virus_name: Option<String>,
    pub scanned_bytes: u64,
    pub error: Option<String>,
    pub signature_count: u64,
    pub scan_time_ms: u64,
}

/// Why an isolated worker scan produced no verdict. Typed (SR-01) so the
/// caller can apply the isolation policy WITHOUT fragile substring matching:
/// only [`WorkerError::Failed`] is a genuine subprocess failure; `Cancelled`
/// and `Busy` must never be treated as one.
#[derive(Debug)]
pub enum WorkerError {
    /// The user cancelled (the cancel flag was observed). NOT a failure and
    /// must NEVER trigger an in-process fallback — that would both defeat the
    /// cancellation and re-scan the file the user asked to stop.
    Cancelled,
    /// Concurrency limit reached (`MAX_CONCURRENT_WORKERS`) — a deliberate
    /// load-shed, not a crash. There is simply no isolated capacity right now,
    /// so the caller falls back to in-process. (This leaves a residual
    /// isolation gap under sustained load; see the SR-01 report.)
    Busy,
    /// Genuine subprocess failure: spawn/timeout/protocol/crash. With
    /// `clamav_isolation=subprocess` this must FAIL CLOSED — the caller must
    /// NOT scan the (possibly-malicious) file in-process in the privileged
    /// daemon (SR-01).
    Failed(String),
}

impl std::fmt::Display for WorkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkerError::Cancelled => write!(f, "cancelled"),
            WorkerError::Busy => write!(f, "clamavd concurrency limit reached"),
            WorkerError::Failed(e) => write!(f, "{e}"),
        }
    }
}

impl From<String> for WorkerError {
    fn from(s: String) -> Self {
        WorkerError::Failed(s)
    }
}

impl From<&str> for WorkerError {
    fn from(s: &str) -> Self {
        WorkerError::Failed(s.to_string())
    }
}

/// Scan a file using the isolated clamavd subprocess.
/// Limits concurrent workers to MAX_CONCURRENT_WORKERS to prevent RAM explosion.
pub fn scan_file(
    settings: &ClamWorkerSettings,
    path: &Path,
    cancel: &AtomicBool,
) -> Result<ClamWorkerOutput, WorkerError> {
    // Concurrency gate — each clamavd loads ~400MB of signatures.
    let active = ACTIVE_WORKERS.fetch_add(1, Ordering::Relaxed);
    if active >= MAX_CONCURRENT_WORKERS {
        ACTIVE_WORKERS.fetch_sub(1, Ordering::Relaxed);
        // Load-shed, not a failure: the caller may fall back to in-process.
        return Err(WorkerError::Busy);
    }
    let _guard = scopeguard(|| {
        ACTIVE_WORKERS.fetch_sub(1, Ordering::Relaxed);
    });

    let worker = find_clamavd();
    let worker_path = worker.ok_or_else(|| "clamavd.exe not found".to_string())?;

    let mut child = std::process::Command::new(&worker_path)
        .arg(path)
        .arg("--dll-dir")
        .arg(&settings.dll_dir)
        .arg("--db-dir")
        .arg(&settings.db_dir)
        .arg("--json")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .quiet_windows()
        .spawn()
        .map_err(|e| format!("clamavd spawn failed: {e}"))?;

    // Real leak fix: Rust's `Child` Drop is a no-op — it does NOT kill or
    // wait the spawned process. The previous `child.stdout.take().ok_or("no stdout")?`
    // early-returned, dropping `child` and orphaning the clamavd process. On
    // a busy realtime watcher that compounds quickly. Kill+wait before
    // bubbling up if take() fails.
    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err("no stdout".into());
        }
    };
    let reader = std::thread::spawn(move || read_limited(stdout, MAX_OUTPUT_BYTES));
    let stderr_reader = child
        .stderr
        .take()
        .map(|stderr| std::thread::spawn(move || read_limited(stderr, MAX_OUTPUT_BYTES)));

    // Wait with timeout + cancellation.
    let start = Instant::now();
    loop {
        if cancel.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(WorkerError::Cancelled);
        }
        if start.elapsed() > settings.timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(WorkerError::Failed(format!(
                "clamavd timeout after {}s",
                settings.timeout.as_secs()
            )));
        }
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(WorkerError::Failed(format!("clamavd wait error: {e}")));
            }
        }
    }

    let stdout_data = reader
        .join()
        .map_err(|_| "stdout reader panicked".to_string())?
        .map_err(|e| format!("stdout read: {e}"))?;
    if let Some(reader) = stderr_reader {
        let _ = reader
            .join()
            .map_err(|_| "stderr reader panicked".to_string())?;
    }

    if stdout_data.is_empty() {
        return Err("clamavd produced empty output".into());
    }

    let output: ClamWorkerOutput =
        serde_json::from_slice(&stdout_data).map_err(|e| format!("clamavd JSON parse: {e}"))?;

    // Worker/daemon desync guard (same as argus_worker): the reported path
    // must be the file we asked to scan. clamavd echoes the CLI arg verbatim.
    let want = path.to_string_lossy();
    if !output.path.trim().eq_ignore_ascii_case(&want) {
        return Err(WorkerError::Failed(format!(
            "clamavd JSON path mismatch: reported {}, requested {want}",
            output.path.trim()
        )));
    }

    Ok(output)
}

fn read_limited<R: Read>(mut reader: R, limit: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            break;
        }
        if out.len() + n > limit {
            return Err("output too large".into());
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

fn find_clamavd() -> Option<PathBuf> {
    // ☠️ R9-LETHAL: same policy as argus_worker::resolve_worker_path —
    // the daemon's exe dir plus the strictly-shaped dev sibling
    // target/{release,debug}. NEVER an ancestor walk: from an installed
    // location (C:\Program Files\Sentinella) that probed e.g.
    // C:\target\release\clamavd.exe and ran whatever it found as SYSTEM.
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let candidate = dir.join("clamavd.exe");
    if candidate.exists() {
        return Some(candidate);
    }
    if let Some(root) = crate::argus_worker::project_root_from_target_dir(dir) {
        for profile in ["release", "debug"] {
            let dev = root.join("target").join(profile).join("clamavd.exe");
            if dev.exists() {
                return Some(dev);
            }
        }
    }
    None
}
