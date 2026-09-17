//! Daemon runtime state — the single source of truth.
//!
//! Supports background Quick Scan with progress tracking and cancellation.
//!
//! ## Lock Safety
//!
//! All `Mutex` and `RwLock` access uses poison-recovering helpers
//! (`lock_inner`, etc.) so a panic in one request never brings down
//! the entire daemon. The engine slot is lock-free
//! (`arc_swap::ArcSwap<EngineSnapshot>`) — see Phase 3 docs on
//! `engine_state`.

use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex, MutexGuard,
    atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use uuid::Uuid;

use sentinella_ipc_proto::engine::{EngineState, EngineStatus, ReloadPhase};

/// Pack a `ReloadPhase` into an `AtomicU8` slot. Inverse of
/// `reload_phase_from_u8`. Kept local since the proto crate is a pure
/// data definition and shouldn't depend on `Atomic*` plumbing.
fn reload_phase_u8(p: ReloadPhase) -> u8 {
    match p {
        ReloadPhase::Idle => 0,
        ReloadPhase::Compiling => 1,
        ReloadPhase::Activating => 2,
        ReloadPhase::Failed => 3,
    }
}

fn reload_phase_from_u8(v: u8) -> ReloadPhase {
    match v {
        1 => ReloadPhase::Compiling,
        2 => ReloadPhase::Activating,
        3 => ReloadPhase::Failed,
        _ => ReloadPhase::Idle,
    }
}
#[allow(unused_imports)]
use sentinella_ipc_proto::quarantine::QuarantineEntry;
use sentinella_ipc_proto::update::{UpdateState, UpdateStatus};
use sentinella_ipc_proto::watcher::{WatcherMode, WatcherStatus};

use crate::db::{ActivityRow, Database, DetectionRow, ScanRow};
use crate::engine::ClamEngine;

/// Default max file size to scan (512 MB). Overridden by config.max_file_size_mb.
const DEFAULT_MAX_FILE_SIZE: u64 = 512 * 1024 * 1024;

/// Engine reload concurrency guard — module-level so policy layer can check it.
static ENGINE_RELOAD_IN_PROGRESS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

// ── AMSI provider observability (Track F) ───────────────────────────
// Counters for scan requests that arrive via the AMSI provider path
// (origin=="amsi" on runtime.scan_buffer). Module statics rather than
// AppState fields: a single global count is all this needs and it keeps
// the change contained. The point is ATTRIBUTION — proving a block came
// from OUR provider and not from another registered AMSI provider such as
// Defender, which the DLL-loads-fine check alone cannot show.
static AMSI_REQUESTS_TOTAL: AtomicU64 = AtomicU64::new(0);
static AMSI_BLOCKS_TOTAL: AtomicU64 = AtomicU64::new(0);
static AMSI_LAST_SEEN_UNIX: AtomicI64 = AtomicI64::new(0);

/// Record one AMSI-path scan. Called from the `runtime.scan_buffer` handler
/// only when the request declares `origin == "amsi"`; `blocked` mirrors the
/// verdict returned to the host.
pub(crate) fn record_amsi_scan(blocked: bool) {
    AMSI_REQUESTS_TOTAL.fetch_add(1, Ordering::Relaxed);
    if blocked {
        AMSI_BLOCKS_TOTAL.fetch_add(1, Ordering::Relaxed);
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    AMSI_LAST_SEEN_UNIX.store(now, Ordering::Relaxed);
}

/// Read-only probe: is our AMSI provider CLSID enrolled under
/// `HKLM\SOFTWARE\Microsoft\AMSI\Providers`? Opening the key read-only is a
/// pure query and never writes. Keep the CLSID in sync with
/// `crates/amsi_provider/src/registration.rs`.
#[cfg(windows)]
fn amsi_provider_registered() -> bool {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
    };
    use windows::core::PCWSTR;
    const SUBKEY: &str =
        r"SOFTWARE\Microsoft\AMSI\Providers\{53E6920C-21B6-4826-9752-81485B3CBA2A}";
    let wide: Vec<u16> = SUBKEY.encode_utf16().chain(std::iter::once(0)).collect();
    let mut hkey = HKEY(std::ptr::null_mut());
    // SAFETY: read-only open of a fixed subkey; the handle is closed on success.
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(wide.as_ptr()),
            0,
            KEY_READ,
            &mut hkey,
        )
    };
    if rc.0 == 0 {
        unsafe {
            let _ = RegCloseKey(hkey);
        }
        true
    } else {
        false
    }
}

#[cfg(not(windows))]
fn amsi_provider_registered() -> bool {
    false
}

/// Get max file size from config (or default).
fn max_file_size() -> u64 {
    crate::config::Config::load(None)
        .map(|c| c.max_file_size_mb * 1024 * 1024)
        .unwrap_or(DEFAULT_MAX_FILE_SIZE)
}

/// Parallel scan threads for background folder/full scans, derived from the
/// machine's logical cores. Was a fixed 4 regardless of hardware — a 2c/4t
/// i7-7200U got the same pool as a 10-thread i5-1265U (oversubscribed on the
/// small box, under-utilized on the big one). Use ~half the logical CPUs to
/// leave headroom for UI / OS / the real-time watcher, clamped so a Core 2 Quad
/// still parallelizes and a big Ryzen doesn't thread-bomb a disk-bound scan.
fn scan_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| (n.get() / 2).clamp(2, 8))
        .unwrap_or(4)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn generate_ipc_secret() -> String {
    let mut bytes = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn load_or_create_ipc_secret() -> Option<String> {
    let path = ipc_secret_path();
    let env_secret = std::env::var("SENTINELLA_IPC_SECRET")
        .ok()
        .filter(|s| s.len() >= 32);

    if let Some(env_s) = env_secret {
        // Hardening: if disk secret exists, env var MUST match it. An attacker
        // (or stale GPO/scheduled task) setting the env var would otherwise
        // poison the persisted secret and lock the GUI out.
        if let Ok(disk) = std::fs::read_to_string(&path) {
            let disk_trim = disk.trim();
            if disk_trim.len() >= 32 {
                if disk_trim != env_s {
                    tracing::error!(
                        "IPC secret env var differs from disk secret — ignoring env var (possible tamper attempt)"
                    );
                    restrict_ipc_secret_permissions(&path);
                    return Some(disk_trim.to_string());
                }
                // Matches — accept either, prefer the disk one.
                restrict_ipc_secret_permissions(&path);
                return Some(disk_trim.to_string());
            }
        }
        // No disk secret yet — accept env, persist it.
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::write(&path, &env_s).is_ok() {
            restrict_ipc_secret_permissions(&path);
        }
        return Some(env_s);
    }

    if let Ok(secret) = std::fs::read_to_string(&path) {
        let trimmed = secret.trim().to_string();
        if trimmed.len() >= 32 {
            // Always re-apply ACL on startup to repair any prior install that
            // wrote restrictive permissions before the Users-readable fix.
            restrict_ipc_secret_permissions(&path);
            return Some(trimmed);
        }
    }

    let secret = generate_ipc_secret();
    if let Some(parent) = path.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            tracing::warn!("cannot create IPC secret directory");
            return None;
        }
    }
    // R3-25: TOCTOU-safe create. If two daemons race here, only one wins
    // the create_new; the loser reads the winner's secret from disk so
    // both end up using the same value.
    use std::io::Write;
    let create_result = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path);
    match create_result {
        Ok(mut f) => {
            if f.write_all(secret.as_bytes()).is_err() {
                tracing::warn!("failed to write IPC secret");
                return None;
            }
            drop(f);
            restrict_ipc_secret_permissions(&path);
            return Some(secret);
        }
        Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Lost the race — read what the winner wrote. The winner's
            // create_new makes the (empty) file visible BEFORE its
            // write_all lands, so the loser can read an empty/short file
            // here; retry briefly instead of falling through to the
            // truncate-write path with our OWN secret, which would leave
            // the two daemons with divergent in-memory secrets (the GUI
            // reads the disk copy and gets locked out of the winner).
            let mut recovered: Option<String> = None;
            for _ in 0..20 {
                if let Ok(s) = std::fs::read_to_string(&path) {
                    let t = s.trim().to_string();
                    if t.len() >= 32 {
                        recovered = Some(t);
                        break;
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            if let Some(t) = recovered {
                restrict_ipc_secret_permissions(&path);
                return Some(t);
            }
            // Disk file still unreadable/invalid after 500ms — fall through
            // to the legacy write path below as a last resort.
        }
        Err(_) => {}
    }

    // Write + fsync the secret before applying ACLs. If the buffered write is
    // lost on crash, next start reads truncated/empty → spurious auth failures
    // and a regenerated secret that already-connected GUIs can't use.
    let write_res = (|| -> std::io::Result<()> {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        f.write_all(secret.as_bytes())?;
        f.sync_all()?;
        Ok(())
    })();
    match write_res {
        Ok(()) => {
            // C2 fix: restrict IPC secret file permissions — only SYSTEM
            // and Administrators should be able to read the shared secret.
            restrict_ipc_secret_permissions(&path);
            Some(secret)
        }
        Err(e) => {
            tracing::warn!(%e, "cannot persist IPC secret");
            None
        }
    }
}

/// Restrict IPC secret file so only SYSTEM, Administrators, and the
/// interactive Users group can read it. The GUI (Sentinella.exe) runs as
/// the unelevated user token via autostart, so it MUST be able to read this
/// file — otherwise authenticated scans (full/startup) fail with -32602.
///
/// Security trade-off: any locally-logged-in user can read the secret and
/// invoke authenticated IPC actions on this machine. The named pipe ACL
/// already allows authenticated users to connect; the secret is one more
/// gate. This matches the consumer-AV pattern where the per-machine daemon
/// trusts logged-in users on the same machine.
#[cfg(target_os = "windows")]
fn restrict_ipc_secret_permissions(path: &Path) {
    use crate::win_process::QuietCommand;
    use std::process::Command;
    let path_str = path.to_string_lossy();
    let _ = Command::new("icacls")
        .args([
            path_str.as_ref(),
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(R)",      // NT AUTHORITY\SYSTEM
            "/grant:r",
            "*S-1-5-32-544:(R)",  // BUILTIN\Administrators
            "/grant:r",
            "*S-1-5-32-545:(R)",  // BUILTIN\Users — needed for unelevated GUI
        ])
        .quiet_windows()
        .output();
}

#[cfg(not(target_os = "windows"))]
fn restrict_ipc_secret_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

fn ipc_secret_path() -> PathBuf {
    // Dev mode: if running from project tree (CWD has crates/sentinelld),
    // use project-local runtime/state/ipc_secret so GUI can find the same file.
    if let Ok(cwd) = std::env::current_dir() {
        if cwd.join("crates").join("sentinelld").exists() {
            return cwd.join("runtime").join("state").join("ipc_secret");
        }
    }
    // Installed mode: ProgramData.
    sentinella_common::paths::data_dir()
        .join("state")
        .join("ipc_secret")
}

#[derive(Clone, Default)]
enum UpdatePhase {
    #[default]
    Idle,
    Checking,
    Downloading(String), // current database file name
    Applying,
    ReloadingEngine,
    ReloadingArgus,
    Completed,
}

/// Atomic snapshot of the engine slot — what `ArcSwap` actually holds.
///
/// Phase 3 audit fix: keeping `engine` and `engine_error` in separate
/// synchronization primitives left a memory-ordering hole. The
/// `ArcSwap::swap` `Release` synchronizes-with `load_full` on the same
/// slot only; a `RwLock` write to a sibling `engine_error` field was a
/// distinct happens-before edge, so a reader on a weakly-ordered
/// platform could observe (engine = new) paired with (engine_error =
/// stale-old). On x86_64 TSO this never reproduced, but the Rust model
/// declares it possible.
///
/// Folding both into a single `Arc<EngineSnapshot>` published through
/// one `ArcSwap` makes the swap atomically deliver both fields. Any
/// reader sees a self-consistent (engine, last_error) pair, full stop.
#[derive(Clone)]
struct EngineSnapshot {
    engine: Option<Arc<ClamEngine>>,
    /// Most recent error from a load / reload attempt. `Some` even when
    /// `engine` is `Some` means "an engine is serving scans, but the
    /// last reload failed and the prior engine is still in place."
    last_error: Option<String>,
}

/// Shared daemon state. Wrapped in `Arc` by the IPC server.
pub struct AppState {
    started_at: Instant,
    /// **v0.1.7 Phase 3 — lock-free A/B engine swap.** Scans clone the
    /// inner `Arc<ClamEngine>` from a `Guard<Arc<EngineSnapshot>>` via
    /// a relaxed atomic load (no read lock); a reload swaps a freshly-
    /// built `EngineSnapshot` into the slot atomically (no write lock).
    /// Net effect:
    ///   * Scans NEVER block on a reload, not even microseconds during
    ///     the swap moment.
    ///   * Two engines coexist briefly: the new one freshly compiled,
    ///     the old one held by Arcs in any in-flight scans. The old
    ///     drops naturally when the last in-flight scan releases its
    ///     Arc, freeing its mpool/cache cleanly.
    ///   * Reload is fail-closed: compile the new engine into a local
    ///     first, then swap. A compile error leaves the slot untouched
    ///     (an RCU update bumps `last_error` only).
    ///   * The audit-flagged "engine = new + engine_error = stale"
    ///     window is closed because both fields are swapped together.
    engine_state: arc_swap::ArcSwap<EngineSnapshot>,
    /// **v0.1.7 Phase 2 — committed-state mirror.** Updated atomically as
    /// the LAST step of every successful engine load / reload. Read by
    /// `engine_status` instead of probing the live `engine` RwLock, so
    /// the GUI's `engine.status` poll never observes the transient
    /// freshclam-CVD-replaced-on-disk-but-engine-not-yet-reloaded window
    /// that previously made `signature_count` and `db_timestamp`
    /// disagree → false "outdated definitions" banner.
    signature_count: std::sync::atomic::AtomicU64,
    /// `db_version` snapshot at the most recent successful commit. Read
    /// by `engine_status`. Mirror; `read_cvd_version()` still reads the
    /// authoritative CVD header on disk for back-compat callers.
    committed_db_version: std::sync::atomic::AtomicU32,
    /// `db_timestamp` snapshot at the most recent successful commit.
    /// i64::MIN sentinel = "no successful commit yet".
    committed_db_timestamp: std::sync::atomic::AtomicI64,
    /// Where the current reload (if any) is in its lifecycle. Stored as
    /// `u8` so it's lock-free for `engine_status` readers.
    reload_phase: std::sync::atomic::AtomicU8,
    dll_dir: Option<PathBuf>,
    db_dir: Option<PathBuf>,
    db: Mutex<Option<Database>>,
    watcher: Mutex<Option<crate::watcher::RealtimeWatcher>>,
    idle_scanner: Mutex<Option<crate::idle_scanner::IdleScanner>>,
    scan_cache: Arc<crate::scan::cache::ScanCache>,
    orchestrator: Arc<crate::orchestrator::ScanOrchestrator>,
    argus: Arc<argus::ArgusEngine>,
    argus_worker: crate::argus_worker::ArgusWorkerSettings,
    argus_worker_fallback_count: AtomicU64,
    argus_worker_timeout_count: AtomicU64,
    argus_worker_last_error: Mutex<Option<String>>,
    argus_worker_last_timeout: Mutex<Option<String>>,
    /// Per-scan-type orchestrator routing, consulted by `start_scan`.
    ///
    /// ATOMIC, not plain bools, for the same reason as the staleness
    /// thresholds below: `restart_requirement()` classifies all four as
    /// hot-applied, so the GUI shows no restart pill when they change.
    /// Cached at construction they kept their boot values, so a user who
    /// turned `orchestrator_full_scan_enabled` off to escape a stuck
    /// orchestrator queue was routed through it anyway — and
    /// `orchestrator_diagnostics()` reported the stale value back, agreeing
    /// with the wrong behaviour instead of exposing it.
    /// `refresh_scan_routing` is what makes "hot-applied" true.
    orchestrator_file_scan_enabled: AtomicBool,
    orchestrator_folder_scan_enabled: AtomicBool,
    orchestrator_quick_scan_enabled: AtomicBool,
    orchestrator_full_scan_enabled: AtomicBool,
    last_orchestrated_job: Mutex<Option<OrchestratedJobResult>>,
    orchestrated_completed_file: AtomicU64,
    orchestrated_completed_folder: AtomicU64,
    orchestrated_completed_quick: AtomicU64,
    orchestrated_completed_full: AtomicU64,
    orchestrated_cancelled_jobs: AtomicU64,
    orchestrated_failed_jobs: AtomicU64,
    ipc_secret: Option<String>,
    inner: Mutex<Inner>,
    // ── IPC health (atomic — no lock) ─────────────────
    ipc_reconnect_count: AtomicU64,
    ipc_last_error_ts: AtomicU64,
    ipc_total_requests: AtomicU64,
    // ── Lock-free scan state for IPC ──────────────────
    scan_live: Mutex<Option<Arc<ScanLiveState>>>,
    // ── Intentional protection disable ───────────────
    /// True when user explicitly paused protection (not crash).
    user_disabled_protection: std::sync::atomic::AtomicBool,
    /// Unix timestamp when protection was disabled (0 = never).
    protection_disabled_at: AtomicU64,
    /// Race fix: serialize disable/enable so a concurrent pair can't
    /// interleave — without it, `enable` could start_watcher() *before*
    /// the racing `disable` stop_watcher() ran, leaving protection silently
    /// off after the enable call returned success.
    protection_toggle_lock: std::sync::Mutex<()>,
    // ── FISH (File Integrity Shield) ─────────────────
    fish_window: std::sync::Mutex<crate::fish::MutationWindow>,
    /// Live FISH config — the one `fish_diagnostics()` reports and therefore
    /// the one `fish_handle_burst` uses to choose observe vs suspend/terminate.
    ///
    /// RwLock, not a plain field. As a plain field it was written once at
    /// construction and never again, so `observe_only`/`active_response`
    /// stayed at their defaults (`true` / `"observe"`) for the life of the
    /// process: the UAC-gated "terminate" setting saved, reported success,
    /// and did nothing while ransomware encrypted. Reads happen per burst
    /// and per status poll; the write happens per config load.
    fish_config: std::sync::RwLock<crate::fish::FishConfig>,
    // ── Footprint baselines ──────────────────────────
    footprint_baselines: crate::footprint::FootprintBaselines,
    // ── Memory pressure ──────────────────────────────
    pressure_tracker: crate::footprint::pressure::PressureTracker,
    performance_config: crate::config::PerformanceConfig,
    /// Developer-mode state (gates local perf telemetry). Mutable at runtime via
    /// `load_developer_config` when the mode is toggled.
    developer_config: std::sync::Mutex<crate::config::DeveloperConfig>,
    /// Web-protection read handle, published by `run_daemon` once the
    /// subsystem has started (or refused). `None` until then, and `None`
    /// forever when the feature is off. RwLock because reads (status
    /// polls) massively outnumber the single write.
    web_protection: std::sync::RwLock<
        Option<std::sync::Arc<crate::web_protection::WebProtectionHandle>>,
    >,
    /// v0.1.9 Phase 2 (audit MED-6): serialises every config load→mutate→save
    /// sequence so two concurrent IPC handlers (e.g. settings.set_full racing
    /// dev.set_developer_mode) can't clobber each other's changes via
    /// last-writer-wins-on-rename. Acquired with `with_config_write` /
    /// `lock_config_write`; held across the whole read-modify-write window,
    /// NOT just the disk write. Tokio runtime is multi-threaded so two
    /// handlers genuinely can run in parallel.
    config_write_lock: std::sync::Mutex<()>,
    /// v0.1.9 Phase 4 (audit MED-8): GUI-reported foreground-window
    /// fullscreen verdict. The daemon runs in Windows session 0 (it's a
    /// service), so its `GetForegroundWindow` returns NULL and the v0.1.8
    /// foreground-window check was dead code in production. Now the GUI
    /// (which runs in the user session) polls the foreground every ~5s
    /// and pushes the verdict here via `system.fullscreen_report`. The
    /// idle scanner consults this cache first; if no recent push (>15s
    /// old), falls back to the session-0 SHQuery-only detector.
    ///
    /// `gui_fullscreen_ts` is the unix-seconds timestamp of the last
    /// report; 0 = never reported. Stored as i64 (not u64) so a future
    /// before-epoch test doesn't underflow into "fresh".
    gui_fullscreen_active: AtomicBool,
    gui_fullscreen_ts: AtomicI64,
    /// Signature-staleness warning threshold (hours), from config.signature_stale_days.
    ///
    /// ATOMIC, not a plain field. `restart_requirement()` classifies both
    /// staleness thresholds as hot-applied, so the GUI shows no restart pill
    /// — but `settings.set_full` only writes the TOML, it pushes nothing back
    /// into AppState. Cached at construction these kept their boot values
    /// until the daemon restarted, making that "no restart needed" a promise
    /// the daemon did not keep. `refresh_staleness_thresholds` makes it true.
    signature_stale_hours: AtomicU64,
    /// Threshold (hours) at which staleness becomes worth INTERRUPTING the
    /// user, from config.signature_stale_notify_days. Much larger than
    /// `signature_stale_hours` — see that config field for why a failed fetch
    /// is not itself notification-worthy.
    signature_stale_notify_hours: AtomicU64,
    // ── ClamAV isolation config (cached) ───────────────
    clamav_subprocess_enabled: AtomicBool,
    clamav_worker_timeout_sec: AtomicU64,
    // ── Detection exclusions ──────────────────────────
    excluded_detections: std::sync::Mutex<Vec<String>>,
    // ── Trusted hashes (manual whitelist) ────────────
    trusted_hashes: std::sync::Mutex<Vec<String>>,
    // ── Daemon operating mode ─────────────────────────
    audit_mode: AtomicBool,
    // ── Resilience telemetry ─────────────────────────
    worker_panics_total: AtomicU64,
    worker_timeouts_total: AtomicU64,
    last_recovery_reason: Mutex<Option<String>>,
    /// Watcher heartbeat: unix timestamp of last watcher event.
    watcher_last_heartbeat: AtomicU64,
    /// Orchestrator heartbeat: unix timestamp of last completed job.
    orchestrator_last_heartbeat: AtomicU64,
    // ── FP Calibration ──────────────────────────────
    calibration: Mutex<Option<crate::calibration::CalibrationLog>>,
    // ── Bounded Execution counters ──────────────────
    budget_files_with_timeouts: AtomicU64,
    budget_clamav_timeouts: AtomicU64,
    budget_yara_timeouts: AtomicU64,
    budget_total_timeouts: AtomicU64,
    budget_partial_results: AtomicU64,
    budget_exhausted: AtomicU64,
    budget_realtime_timeouts: AtomicU64,
    budget_idle_timeouts: AtomicU64,
    budget_transient_skips: AtomicU64,
    // ── PLM (Process Lineage Monitor) ────────────────
    plm: Option<crate::plm::PlmMonitor>,
    // ── PowerShell bridge ──────────────────────────
    ps_bridge: Mutex<Option<crate::amsi::ps_bridge::PsBridge>>,
    // ── Trust Graph ────────────────────────────────
    trust_graph: Option<crate::trust_graph::TrustGraph>,
    // ── Ecosystem Tracker ─────────────────────────
    pub(crate) ecosystem: crate::ecosystem::EcosystemTracker,
    // ── Working Set Residency ────────────────────
    pub(crate) activity_tracker: crate::footprint::residency::ActivityTracker,
    residency_manager: crate::footprint::residency::ResidencyManager,
    // ── IPC Rate Limiter ──────────────────────────
    pub(crate) rate_limiter: super::policy::RateLimiter,
    // ── Quarantine F4: post-restore watcher suppression ──
    /// Paths recently restored from quarantine. The realtime watcher consults
    /// this set (with a 30s TTL) and skips scans on these paths to break the
    /// restore → CREATE event → re-detect → re-quarantine loop that could
    /// otherwise fire before the caller commits the DB status flip.
    restore_suppress: std::sync::Mutex<std::collections::HashMap<PathBuf, Instant>>,
    // ── Tamper-detection signals (set once at startup) ──────────
    /// A startup binary-integrity check found a hash mismatch against the
    /// stored TOFU baseline (`binary_integrity.json`). Surfaced via the
    /// `health` IPC so a paused/stopped GUI can flag tampering without
    /// trusting the daemon log.
    binary_integrity_drift: AtomicBool,
    /// The config file's HMAC sidecar (`sentinelld.toml.hmac`) did not match
    /// the on-disk config at load time → someone edited the config outside
    /// the daemon. Fail-loud, not fail-closed (daemon continues with the
    /// loaded values so the operator can see the bad config).
    config_drift: AtomicBool,
    /// Number of times the supervisor restarted the watcher after a stalled
    /// heartbeat. Diagnostics-only; surfaced via `resilience`.
    watcher_restarts_total: AtomicU64,
}

struct Inner {
    // ── Active scan job ────────────────────────────────
    active_scan: Option<ScanJob>,

    // ── History ────────────────────────────────────────
    scan_history: Vec<ScanRecord>,
    activity: Vec<ActivityEntry>,

    // ── Challenge token for dangerous commands ─────────
    // Adversary A2: token is now bound to the IPC method it was issued for.
    // Without binding, a token approved for (say) quarantine.delete could be
    // replayed against engine.reload or settings.set in the same UAC window —
    // defeating the per-dangerous-op consent model. The middle field is the
    // method name the token is scoped to; validate_challenge_token requires
    // it to match exactly.
    challenge_token: Option<(String, String, Instant)>, // (token, method, created_at)

    // ── Update tracking ────────────────────────────────
    update_running: bool,
    update_phase: UpdatePhase,
    update_current_file: String,
    last_update_timestamp: Option<i64>,
    last_update_error: Option<String>,
    /// Should `last_update_error` be surfaced as `UpdateState::Error`?
    ///
    /// Only for updates the USER started. They pressed a button and are
    /// watching; silence would read as a hung UI. A SCHEDULED update that
    /// fails is recorded (activity log + `last_update_error` for diagnostics)
    /// but stays `Idle`, because the user is not watching and the next cycle
    /// is at most `update_interval_hours` away. What eventually interrupts
    /// them is `db_stale_notify` — signature age, not a failed fetch.
    last_update_error_notifiable: bool,
}

/// Aggregate scan performance summary.
#[derive(Clone, Default, Serialize)]
pub struct ScanPerformanceSummary {
    pub strategy_full: u64,
    pub strategy_light: u64,
    pub strategy_signature: u64,
    pub strategy_skip: u64,
    pub strategy_too_large: u64,
    pub total_argus_us: u64,
    pub total_yara_us: u64,
    pub total_hash_us: u64,
    /// Aggregated ClamAV phase time across the job (µs). v0.1.6+.
    pub total_clamav_us: u64,
    /// Aggregated bytes ClamAV actually scanned across the job. v0.1.6+.
    pub total_bytes_scanned: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    /// Slowest files (path, time_us). Capped at 10.
    pub slowest_files: Vec<(String, u64)>,
}

impl ScanPerformanceSummary {
    fn record_file(
        &mut self,
        path: &str,
        file_size: u64,
        timing: &argus::verdict::ScanTiming,
    ) {
        // Strategy counts.
        if let Some(strategy) = timing.strategy {
            match strategy {
                argus::verdict::ScanStrategy::FullAnalysis => self.strategy_full += 1,
                argus::verdict::ScanStrategy::LightAnalysis => self.strategy_light += 1,
                argus::verdict::ScanStrategy::SignatureOnly => self.strategy_signature += 1,
                argus::verdict::ScanStrategy::SkipSafe => self.strategy_skip += 1,
                argus::verdict::ScanStrategy::TooLarge => self.strategy_too_large += 1,
            }
        }
        self.total_argus_us = self.total_argus_us.saturating_add(timing.argus_total_us);
        self.total_yara_us = self.total_yara_us.saturating_add(timing.yara_us);
        self.total_hash_us = self.total_hash_us.saturating_add(timing.hash_us);
        // ClamAV phase + bytes per file. Sat-add since a busy daemon can run for
        // weeks and TB-scale scans push these into the high range.
        self.total_clamav_us = self.total_clamav_us.saturating_add(timing.clamav_us);
        self.total_bytes_scanned = self.total_bytes_scanned.saturating_add(file_size);

        // Track slowest files (top 10).
        if timing.argus_total_us > 100_000 {
            // >100ms = notable
            self.slowest_files
                .push((path.to_string(), timing.argus_total_us));
            self.slowest_files.sort_by(|a, b| b.1.cmp(&a.1));
            if self.slowest_files.len() > 10 {
                self.slowest_files.truncate(10);
            }
        }
    }
}

/// Lightweight scan snapshot — readable without locking Inner.
/// Used by scan.status IPC to avoid blocking on worker contention.
pub struct ScanLiveState {
    pub id: String,
    pub kind: String,
    pub started_at: i64,
    pub files_total: AtomicU64,
    pub files_scanned: AtomicU64,
    pub threats_found: AtomicU64,
    pub cancel_flag: Arc<AtomicBool>,
    pub status: std::sync::atomic::AtomicU8, // 0=pending,1=running,2=completed,3=cancelled,4=failed,5=draining
    pub current_path: Mutex<String>,
}

impl ScanLiveState {
    fn status_enum(&self) -> ScanJobStatus {
        match self.status.load(Ordering::Relaxed) {
            1 => ScanJobStatus::Running,
            2 => ScanJobStatus::Completed,
            3 => ScanJobStatus::Cancelled,
            4 => ScanJobStatus::Failed,
            5 => ScanJobStatus::Draining,
            _ => ScanJobStatus::Pending,
        }
    }
    fn set_status(&self, s: ScanJobStatus) {
        self.status.store(
            match s {
                ScanJobStatus::Pending => 0,
                ScanJobStatus::Running => 1,
                ScanJobStatus::Completed => 2,
                ScanJobStatus::Cancelled => 3,
                ScanJobStatus::Failed => 4,
                ScanJobStatus::Draining => 5,
            },
            Ordering::Relaxed,
        );
    }
}

/// A running or completed scan job.
#[derive(Clone)]
struct ScanJob {
    id: Uuid,
    kind: String,
    status: ScanJobStatus,
    started_at: i64,
    finished_at: Option<i64>,
    files_scanned: u64,
    files_total: u64,
    threats_found: u64,
    current_path: String,
    detections: Vec<Detection>,
    errors: Vec<String>,
    cancel_flag: Arc<AtomicBool>,
    perf_summary: ScanPerformanceSummary,
    /// Shared live state for lock-free status reads.
    live: Option<Arc<ScanLiveState>>,
}

#[derive(Clone, Copy, PartialEq)]
#[allow(dead_code)]
enum ScanJobStatus {
    Pending,
    Running,
    Completed,
    Cancelled,
    Failed,
    Draining,
}

#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    path: String,
    virus_name: String,
}

/// Core of [`AppState::try_reserve_scan`], split out so the atomic
/// check-and-reserve invariant can be unit-tested without constructing a full
/// `AppState`. The caller MUST hold the `inner` lock for the entire call so the
/// overlap check and the reservation are one indivisible critical section
/// (TOCTOU fix — see `try_reserve_scan`).
/// Pure staleness decision: given the most-recent signature timestamp (unix
/// secs, the max of in-memory + file-mtime sources) and the current time,
/// decide whether the DB is stale and report its age in hours. `None` ts means
/// no signatures present at all → genuinely stale.
fn compute_db_stale(effective_ts: Option<i64>, now_ts: i64, threshold_hours: u64) -> (bool, u64) {
    match effective_ts {
        Some(ts) => {
            let hours = ((now_ts - ts).max(0) as u64) / 3600;
            (hours > threshold_hours, hours)
        }
        None => (true, 0),
    }
}

/// Should the user be INTERRUPTED about signature age?
///
/// Split out of `runtime_stats` so the no-timestamp guard is reachable from a
/// test. `compute_db_stale` answers `(true, 0)` when it has no timestamp,
/// which means "unknown age", NOT "old" — firing a notification on that would
/// shout at every user whose signature mtimes were briefly unreadable at boot.
/// Uses the same `effective_ts` as the 3-day UI threshold, so the two can
/// never disagree about how old the database is.
fn compute_db_stale_notify(effective_ts: Option<i64>, now_ts: i64, threshold_hours: u64) -> bool {
    match effective_ts {
        Some(_) => compute_db_stale(effective_ts, now_ts, threshold_hours).0,
        None => false,
    }
}

/// Extract the actionable reason from freshclam output for the activity log.
/// freshclam's real error (DNS failure, dead mirror, permission/tempdir issue)
/// is on the LAST non-empty line(s); the head is banner + progress noise. The
/// old code logged the first 200 chars, which usually truncated before the
/// reason — making a tray (scheduled) update failure undiagnosable. Surface the
/// tail instead so the activity log says *why*.
fn freshclam_error_detail(message: &str) -> String {
    let tail: Vec<&str> = message
        .lines()
        .rev()
        .filter(|l| !l.trim().is_empty())
        .take(3)
        .collect();
    if tail.is_empty() {
        return "freshclam failed (no output)".to_string();
    }
    let joined = tail.into_iter().rev().collect::<Vec<_>>().join(" | ");
    joined.chars().take(300).collect()
}

/// Did a freshclam run that exited 0 actually try to fetch anything?
///
/// `fc_update_databases` takes a cool-down branch when a previous run got a
/// 403 (region/IP block) or 429 (rate limit) from the ClamAV CDN: it prints the
/// retry-after date, downloads NOTHING, sets `FC_SUCCESS` and exits 0. The
/// in-run 429 path does the same (`goto success`). Counting those as a
/// successful update stamps `last_update_timestamp = now`, and because
/// `runtime_stats` takes the max of that stamp and the signature file mtimes,
/// the stamp always wins — so the signature-age card, the product's one
/// user-facing staleness signal, could never fire again for the life of the
/// process. A machine blocked by the CDN for weeks showed a green "Up to date".
fn freshclam_output_is_cooldown(message: &str) -> bool {
    // Matches both "You are on cool-down until after: <date>" (this run hit
    // the limit) and "You are still on cool-down until after: <date>" (an
    // earlier run did and freshclam.dat's retry_after has not expired).
    // Deliberately NOT the bare word "cool-down": freshclam also logs
    // "Cool-down expired, ok to try again." immediately before a real fetch.
    message
        .to_ascii_lowercase()
        .contains("cool-down until after")
}

fn reserve_active_scan(inner: &mut Inner, job: ScanJob) -> Result<(), ScanStartResponse> {
    if let Some(ref existing) = inner.active_scan {
        if matches!(
            existing.status,
            ScanJobStatus::Running | ScanJobStatus::Pending | ScanJobStatus::Draining
        ) {
            return Err(ScanStartResponse {
                job_id: existing.id.to_string(),
                status: "error".into(),
                result: None,
                error: Some(format!(
                    "Another scan is already {} — cancel it or wait",
                    match existing.status {
                        ScanJobStatus::Pending => "queued",
                        ScanJobStatus::Running => "running",
                        ScanJobStatus::Draining => "draining",
                        ScanJobStatus::Completed => "completed",
                        ScanJobStatus::Cancelled => "cancelled",
                        ScanJobStatus::Failed => "failed",
                    }
                )),
            });
        }
    }
    inner.active_scan = Some(job);
    Ok(())
}

/// Pure cancel decision for [`AppState::cancel_scan`], split out for unit
/// testing. Only `Pending`/`Running` are cancellable. A terminal job
/// (Completed/Failed/Cancelled) must NOT be flipped to non-terminal
/// `Draining`: the workers/completers that write terminal states are gone
/// by then, so nothing would ever move the job out of `Draining` and
/// `reserve_active_scan` would reject every future scan until daemon
/// restart. (The IPC handler's `scan_status()` pre-check is check-then-act
/// and cannot close that race — the decision has to happen here, under
/// the same critical section as the transition.)
fn cancel_transition(previous: ScanJobStatus) -> Option<ScanJobStatus> {
    match previous {
        ScanJobStatus::Pending => Some(ScanJobStatus::Cancelled),
        ScanJobStatus::Running => Some(ScanJobStatus::Draining),
        _ => None,
    }
}

/// SR-01 isolation policy: whether an isolated (`clamav_isolation=subprocess`)
/// scan may fall back to the in-process engine after the worker did not
/// return a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClamFallback {
    /// Do NOT scan in-process — return a cancelled/errored result instead.
    Refuse,
    /// Fall back to the in-process engine (only the concurrency load-shed).
    InProcess,
}

/// Pure SR-01 fallback decision, split out for unit testing (the real path
/// needs a live clamavd, so the *policy* is tested here without one).
///
/// - A user cancellation (`cancelled` flag set, or a typed `Cancelled`) never
///   falls back: that would defeat the cancellation and re-scan the file the
///   user asked to stop.
/// - `Busy` (concurrency limit) is a deliberate load-shed, not a failure —
///   there is simply no isolated capacity, so in-process is permitted.
/// - `Failed` is a genuine subprocess failure: falling back would scan a
///   possibly-malicious file in the privileged daemon, defeating the very
///   isolation the operator configured. Fail CLOSED.
fn clamav_fallback_decision(
    err: &crate::clamav_worker::WorkerError,
    cancelled: bool,
) -> ClamFallback {
    use crate::clamav_worker::WorkerError;
    if cancelled {
        return ClamFallback::Refuse;
    }
    match err {
        WorkerError::Cancelled => ClamFallback::Refuse,
        WorkerError::Busy => ClamFallback::InProcess,
        WorkerError::Failed(_) => ClamFallback::Refuse,
    }
}

impl AppState {
    /// v0.1.9 Phase 2 — guard for the config read-modify-write window.
    /// IPC handlers that mutate `sentinelld.toml` must wrap their entire
    /// `Config::load → mutate → config.save` sequence in:
    ///
    /// ```ignore
    /// let _guard = state.lock_config_write();
    /// let mut config = Config::load(None).unwrap_or_default();
    /// // ...mutate...
    /// config.save(&path)?;
    /// drop(_guard); // explicit if you need to log after the write
    /// ```
    ///
    /// Returns a `MutexGuard` so the borrow checker enforces the lifetime
    /// match: you can't accidentally drop the guard mid-sequence.
    /// `Result::unwrap_or_else(|e| e.into_inner())` recovers from a
    /// poisoned lock — the previous panicking handler already lost its
    /// own write; we don't want a single panicked thread to permanently
    /// brick every future settings save.
    pub fn lock_config_write(&self) -> std::sync::MutexGuard<'_, ()> {
        self.config_write_lock
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    // ── v0.1.9 Phase 4: GUI-reported fullscreen cache ─────────────
    //
    // The GUI runs in the user session and can call GetForegroundWindow
    // correctly; the daemon runs in session 0 and cannot. The GUI polls
    // every ~5s and pushes its verdict here so the idle scanner can
    // honour true-fullscreen pauses for real games.

    /// Update the GUI-reported foreground fullscreen verdict.
    /// Called by the `system.fullscreen_report` IPC handler.
    pub fn record_gui_fullscreen(&self, active: bool) {
        self.gui_fullscreen_active.store(active, Ordering::Relaxed);
        self.gui_fullscreen_ts
            .store(chrono::Utc::now().timestamp(), Ordering::Relaxed);
    }

    /// Returns `Some(active)` if a GUI report arrived within `max_age_secs`,
    /// `None` if no report has ever arrived or the last one is too old to
    /// trust (caller should fall back to the session-0 SHQuery-only path).
    pub fn fresh_gui_fullscreen(&self, max_age_secs: i64) -> Option<bool> {
        let ts = self.gui_fullscreen_ts.load(Ordering::Relaxed);
        if ts == 0 {
            return None;
        }
        let age = chrono::Utc::now().timestamp().saturating_sub(ts);
        if age > max_age_secs {
            return None;
        }
        Some(self.gui_fullscreen_active.load(Ordering::Relaxed))
    }

    pub fn new(
        dll_dir: Option<PathBuf>,
        db_dir: Option<PathBuf>,
        database: Option<Database>,
    ) -> Self {
        let now_ts = chrono::Utc::now().timestamp();
        let mut activity = vec![ActivityEntry {
            event_type: "daemon_start".into(),
            message: "Daemon started".into(),
            detail: Some("sentinelld initializing".into()),
            timestamp: now_ts,
        }];

        let (engine, engine_error, sig_count) = match (&dll_dir, &db_dir) {
            (Some(dll), Some(db)) => match ClamEngine::load(dll, db) {
                Ok(eng) => {
                    let sigs = eng.signature_count() as u64;
                    activity.push(ActivityEntry {
                        event_type: "engine_loaded".into(),
                        message: format!("ClamAV engine loaded — {} signatures", sigs),
                        detail: Some("Engine compiled and ready to scan".into()),
                        timestamp: chrono::Utc::now().timestamp(),
                    });
                    (Some(Arc::new(eng)), None, sigs)
                }
                Err(e) => {
                    tracing::error!(error = %e, "ClamAV engine failed to load");
                    activity.push(ActivityEntry {
                        event_type: "engine_error".into(),
                        message: format!("Engine failed: {e}"),
                        detail: None,
                        timestamp: chrono::Utc::now().timestamp(),
                    });
                    (None, Some(e), 0)
                }
            },
            _ => {
                activity.push(ActivityEntry {
                    event_type: "engine_skipped".into(),
                    message: "Engine not configured".into(),
                    detail: None,
                    timestamp: chrono::Utc::now().timestamp(),
                });
                (None, Some("Not configured".into()), 0)
            }
        };

        // Persist the startup activity event.
        if let Some(ref db) = database {
            for evt in &activity {
                db.insert_activity(&ActivityRow {
                    event_id: Uuid::new_v4().to_string(),
                    timestamp: evt.timestamp,
                    severity: "info".into(),
                    category: "system".into(),
                    title: evt.message.clone(),
                    message: evt.detail.clone().unwrap_or_default(),
                    related_scan_id: None,
                });
            }
        }

        let daemon_config = crate::config::Config::load(None).unwrap_or_default();
        let argus_worker = crate::argus_worker::ArgusWorkerSettings::from_config(&daemon_config);
        let argus_engine = Arc::new(argus::ArgusEngine::with_defaults());
        activity.push(ActivityEntry {
            event_type: "argus_loaded".into(),
            message: format!(
                "ARGUS heuristics engine v{} initialized — {} layers active",
                argus::ENGINE_VERSION,
                argus_engine.stats().active_layers
            ),
            detail: Some("Layered suspicion engine ready".into()),
            timestamp: chrono::Utc::now().timestamp(),
        });

        // ── Load ARGUS intelligence packs ──────────────────
        // IOC hash database.
        let ioc_paths = crate::paths::paths().ioc_hash_paths();
        for ioc_path in &ioc_paths {
            if ioc_path.exists() {
                match argus_engine.ioc.load_from_file(ioc_path) {
                    Ok(count) => {
                        tracing::info!(count, path = %ioc_path.display(), "IOC hash database loaded");
                        activity.push(ActivityEntry {
                            event_type: "ioc_loaded".into(),
                            message: format!("IOC database loaded — {count} hash(es)"),
                            detail: Some(format!("Source: {}", ioc_path.display())),
                            timestamp: chrono::Utc::now().timestamp(),
                        });
                    }
                    Err(e) => tracing::warn!(%e, "Failed to load IOC database"),
                }
                break;
            }
        }

        // YARA rule engine — compiled on a dedicated thread with 8 MB stack
        // because wasmtime/cranelift JIT uses deep call stacks during compilation.
        let yara_dirs = crate::paths::paths().yara_rule_dirs();
        let yara_result = argus_engine.yara.load_rules_on_large_stack(&yara_dirs);

        match yara_result {
            Ok(count) if count > 0 => {
                activity.push(ActivityEntry {
                    event_type: "yara_loaded".into(),
                    message: format!(
                        "ARGUS YARA engine loaded — {count} behavioral rules compiled"
                    ),
                    detail: Some(format!(
                        "Rule sources: {}",
                        yara_dirs
                            .iter()
                            .filter(|d| d.exists())
                            .map(|d| d.display().to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )),
                    timestamp: chrono::Utc::now().timestamp(),
                });
            }
            Ok(_) => {
                tracing::info!("No YARA rules found — YARA layer inactive");
            }
            Err(e) => {
                tracing::warn!(%e, "YARA rule compilation failed");
                activity.push(ActivityEntry {
                    event_type: "yara_error".into(),
                    message: format!("YARA rule loading failed: {e}"),
                    detail: None,
                    timestamp: chrono::Utc::now().timestamp(),
                });
            }
        }

        // D-3 fix: seed cache integrity from vault key before loading DB.
        // Entries without a matching integrity hash are rejected as tampered.
        let scan_cache = {
            let p = crate::paths::paths();
            if let Ok(key_data) = std::fs::read(p.vault_integrity_key()) {
                crate::scan::cache::set_cache_integrity_secret(&key_data);
            }
            Arc::new(crate::scan::cache::ScanCache::with_persistence(
                &p.scan_cache_db(),
            ))
        };

        // R7 (audit cross-cutting): entries recorded under a DIFFERENT
        // signature set must not survive an update + restart — sync the
        // persisted signature fingerprint now (provider fingerprint +
        // loaded signature count). A changed fingerprint bumps
        // sig_generation, invalidating every stale entry (in-memory and
        // persisted); identical restarts keep the cache warm. This also
        // covers the sources.update activation path, which requires a
        // daemon restart — the post-update fingerprint differs, so the
        // old "clean" entries are invalidated on first boot after update.
        if let Some(db) = &db_dir {
            let mut source_mgr = crate::engine::sources::SignatureSourceManager::new(db);
            let provider = if daemon_config.enhanced_signature_provider == "none" {
                None
            } else {
                Some(daemon_config.enhanced_signature_provider.clone())
            };
            source_mgr.load_config(provider);
            let fingerprint = format!("{}:{}", source_mgr.provider_fingerprint(), sig_count);
            scan_cache.sync_signature_fingerprint(&fingerprint);
        }

        Self {
            started_at: Instant::now(),
            // Phase 3 audit fix: engine and last_error are now atomic
            // siblings inside one ArcSwap-published snapshot.
            engine_state: arc_swap::ArcSwap::new(Arc::new(EngineSnapshot {
                engine,
                last_error: engine_error,
            })),
            signature_count: std::sync::atomic::AtomicU64::new(sig_count),
            // Committed mirror seeded at construction. If the initial
            // engine load succeeded, the CVD header is already on disk
            // and `read_cvd_version()` will populate these on first
            // status read; the atomics are written by every later commit.
            committed_db_version: std::sync::atomic::AtomicU32::new(0),
            committed_db_timestamp: std::sync::atomic::AtomicI64::new(i64::MIN),
            reload_phase: std::sync::atomic::AtomicU8::new(reload_phase_u8(ReloadPhase::Idle)),
            dll_dir: dll_dir.clone(),
            db_dir: db_dir.clone(),
            db: Mutex::new(database),
            watcher: Mutex::new(None),
            idle_scanner: Mutex::new(None),
            scan_cache,
            orchestrator: crate::orchestrator::ScanOrchestrator::start(),
            argus: argus_engine,
            argus_worker,
            argus_worker_fallback_count: AtomicU64::new(0),
            argus_worker_timeout_count: AtomicU64::new(0),
            argus_worker_last_error: Mutex::new(None),
            argus_worker_last_timeout: Mutex::new(None),
            orchestrator_file_scan_enabled: AtomicBool::new(
                daemon_config.scan.orchestrator_file_scan_enabled,
            ),
            orchestrator_folder_scan_enabled: AtomicBool::new(
                daemon_config.scan.orchestrator_folder_scan_enabled,
            ),
            orchestrator_quick_scan_enabled: AtomicBool::new(
                daemon_config.scan.orchestrator_quick_scan_enabled,
            ),
            orchestrator_full_scan_enabled: AtomicBool::new(
                daemon_config.scan.orchestrator_full_scan_enabled,
            ),
            last_orchestrated_job: Mutex::new(None),
            orchestrated_completed_file: AtomicU64::new(0),
            orchestrated_completed_folder: AtomicU64::new(0),
            orchestrated_completed_quick: AtomicU64::new(0),
            orchestrated_completed_full: AtomicU64::new(0),
            orchestrated_cancelled_jobs: AtomicU64::new(0),
            orchestrated_failed_jobs: AtomicU64::new(0),
            ipc_secret: load_or_create_ipc_secret(),
            ipc_reconnect_count: AtomicU64::new(0),
            ipc_last_error_ts: AtomicU64::new(0),
            ipc_total_requests: AtomicU64::new(0),
            scan_live: Mutex::new(None),
            user_disabled_protection: std::sync::atomic::AtomicBool::new(false),
            protection_disabled_at: AtomicU64::new(0),
            protection_toggle_lock: std::sync::Mutex::new(()),
            // Seed from the on-disk config, not `FishConfig::default()`:
            // `Config::load` already validated it, and starting from the
            // defaults meant the window and the diagnostics disagreed with
            // the user's settings for the whole window between construction
            // and `load_fish_config`.
            fish_config: std::sync::RwLock::new(daemon_config.fish.clone()),
            fish_window: std::sync::Mutex::new(crate::fish::MutationWindow::new(
                &daemon_config.fish,
            )),
            footprint_baselines: crate::footprint::FootprintBaselines::new(),
            pressure_tracker: crate::footprint::pressure::PressureTracker::new(),
            performance_config: {
                // Honor the user's [performance] config (incl. memory_profile),
                // which AppState::new previously ignored entirely. When the
                // thresholds are left at the defaults (treated as "auto"), derive
                // them from THIS machine's RAM so back-off behavior is consistent
                // across hardware (4 GB Core 2 Quad ↔ 32 GB i5-1265U) instead of a
                // static 1500/2500 MB. Explicit user overrides are respected as-is.
                let mut pc = crate::config::Config::load(None)
                    .map(|c| c.performance)
                    .unwrap_or_default();
                let defaults = crate::config::PerformanceConfig::default();
                let at_defaults = pc.memory_warning_mb == defaults.memory_warning_mb
                    && pc.memory_critical_mb == defaults.memory_critical_mb;
                if at_defaults {
                    if let Some(ram_mb) = crate::footprint::pressure::detect_total_ram_mb() {
                        let (w, c) = crate::footprint::pressure::ram_relative_thresholds(
                            ram_mb,
                            &pc.memory_profile,
                        );
                        pc.memory_warning_mb = w;
                        pc.memory_critical_mb = c;
                        tracing::info!(
                            total_ram_mb = ram_mb,
                            warning_mb = w,
                            critical_mb = c,
                            profile = pc.memory_profile.as_str(),
                            "memory pressure thresholds auto-derived from total RAM"
                        );
                    }
                } else {
                    tracing::info!(
                        warning_mb = pc.memory_warning_mb,
                        critical_mb = pc.memory_critical_mb,
                        "using user-configured memory pressure thresholds"
                    );
                }
                pc
            },
            config_write_lock: std::sync::Mutex::new(()),
            gui_fullscreen_active: AtomicBool::new(false),
            gui_fullscreen_ts: AtomicI64::new(0),
            web_protection: std::sync::RwLock::new(None),
            developer_config: std::sync::Mutex::new(
                crate::config::Config::load(None)
                    .map(|c| c.developer)
                    .unwrap_or_default(),
            ),
            signature_stale_hours: AtomicU64::new(
                crate::config::Config::load(None)
                    .map(|c| c.signature_stale_days)
                    .unwrap_or(3)
                    .clamp(1, 30) as u64
                    * 24,
            ),
            signature_stale_notify_hours: AtomicU64::new(
                crate::config::Config::load(None)
                    .map(|c| c.signature_stale_notify_days)
                    .unwrap_or(14)
                    .clamp(3, 365) as u64
                    * 24,
            ),
            clamav_subprocess_enabled: AtomicBool::new(false),
            clamav_worker_timeout_sec: AtomicU64::new(30),
            excluded_detections: std::sync::Mutex::new(Vec::new()),
            trusted_hashes: std::sync::Mutex::new(Vec::new()),
            audit_mode: AtomicBool::new(false),
            worker_panics_total: AtomicU64::new(0),
            worker_timeouts_total: AtomicU64::new(0),
            last_recovery_reason: Mutex::new(None),
            watcher_last_heartbeat: AtomicU64::new(0),
            orchestrator_last_heartbeat: AtomicU64::new(0),
            calibration: Mutex::new(
                crate::calibration::CalibrationLog::open(&crate::paths::paths().calibration_db())
                    .ok(),
            ),
            budget_files_with_timeouts: AtomicU64::new(0),
            budget_clamav_timeouts: AtomicU64::new(0),
            budget_yara_timeouts: AtomicU64::new(0),
            budget_total_timeouts: AtomicU64::new(0),
            budget_partial_results: AtomicU64::new(0),
            budget_exhausted: AtomicU64::new(0),
            budget_realtime_timeouts: AtomicU64::new(0),
            budget_idle_timeouts: AtomicU64::new(0),
            budget_transient_skips: AtomicU64::new(0),
            plm: Some(crate::plm::PlmMonitor::start(5)),
            ps_bridge: Mutex::new(None),
            trust_graph: {
                let p = crate::paths::paths();
                if let Ok(key_data) = std::fs::read(p.vault_integrity_key()) {
                    crate::trust_graph::set_trust_integrity_secret(&key_data);
                }
                crate::trust_graph::TrustGraph::open(&p.trust_graph_db()).ok()
            },
            ecosystem: crate::ecosystem::EcosystemTracker::new(),
            activity_tracker: crate::footprint::residency::ActivityTracker::new(),
            residency_manager: crate::footprint::residency::ResidencyManager::new(
                crate::footprint::residency::ResidencyConfig::default(),
            ),
            rate_limiter: super::policy::RateLimiter::new(),
            restore_suppress: std::sync::Mutex::new(std::collections::HashMap::new()),
            binary_integrity_drift: AtomicBool::new(false),
            config_drift: AtomicBool::new(false),
            watcher_restarts_total: AtomicU64::new(0),
            inner: Mutex::new(Inner {
                active_scan: None,
                scan_history: Vec::new(),
                activity,
                challenge_token: None,
                update_running: false,
                update_phase: UpdatePhase::Idle,
                update_current_file: String::new(),
                last_update_timestamp: None,
                last_update_error: None,
                last_update_error_notifiable: false,
            }),
        }
    }

    /// Generate a single-use challenge token for a specific dangerous IPC method.
    /// Token expires after 60 seconds and is REJECTED when presented to a
    /// different method than the one it was issued for (Adversary A2: prevents
    /// cross-method token replay across a single UAC consent window).
    pub fn generate_challenge_token(&self, method: &str) -> String {
        let token = Uuid::new_v4().to_string();
        let mut inner = self.lock_inner();
        inner.challenge_token = Some((token.clone(), method.to_string(), Instant::now()));
        token
    }

    /// Validate GUI-owned IPC secret before issuing dangerous challenge tokens.
    pub fn validate_ipc_auth(&self, auth: &str) -> bool {
        let Some(secret) = self.ipc_secret.as_deref() else {
            tracing::warn!("dangerous IPC rejected: auth secret not configured");
            return false;
        };
        let ok = constant_time_eq(secret.as_bytes(), auth.as_bytes());
        if !ok {
            tracing::warn!("dangerous IPC rejected: invalid auth secret");
        }
        ok
    }

    /// Validate and consume a challenge token. Returns true if valid AND
    /// scoped to `expected_method`. Adversary A2: a token issued for one
    /// dangerous method must not be reusable against another, otherwise the
    /// UAC-per-dangerous-op model collapses (e.g. user approves
    /// quarantine.delete, the GUI/attacker replays the token into
    /// engine.reload during the same window).
    pub fn validate_challenge_token(&self, token: &str, expected_method: &str) -> bool {
        let mut inner = self.lock_inner();
        if let Some((ref stored, ref stored_method, created)) = inner.challenge_token {
            // Constant-time comparison on the token bytes to prevent timing
            // side channels. Method scope is compared with normal equality
            // since the value comes from a server-side string registry, not
            // attacker-controlled bytes whose timing leaks would matter.
            let ct_eq = stored.len() == token.len()
                && stored
                    .bytes()
                    .zip(token.bytes())
                    .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                    == 0;
            let method_match = stored_method == expected_method;
            let fresh = created.elapsed().as_secs() < 60;
            if ct_eq && method_match && fresh {
                inner.challenge_token = None; // Consumed — single use.
                return true;
            }
            // Failure closed: burn the token on any mismatch (wrong value,
            // wrong scope, or expired) so a replay attempt does not survive
            // and a parallel legitimate flow has to request a fresh token.
            inner.challenge_token = None;
        }
        // Log failed attempt. `expected_method` is the server-known method
        // string (e.g. "engine.reload"), safe to log.
        drop(inner);
        self.log_activity(
            "warning",
            "security",
            "Invalid challenge token — dangerous command rejected",
            expected_method,
            None,
        );
        false
    }

    pub fn db_ref(&self) -> &Mutex<Option<Database>> {
        &self.db
    }
    /// Check and apply quiet working set trim if conditions are met.
    pub fn check_residency_trim(&self) {
        self.residency_manager
            .check_and_trim(&self.activity_tracker);
    }

    /// Get residency diagnostics.
    pub fn residency_diagnostics(&self) -> serde_json::Value {
        self.residency_manager.diagnostics(&self.activity_tracker)
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
    pub fn argus(&self) -> &argus::ArgusEngine {
        &self.argus
    }
    /// Shared handle to the ARGUS engine for IPC handlers that move analysis
    /// onto the blocking thread pool (spawn_blocking requires 'static
    /// ownership — a borrowed &ArgusEngine can't cross into the task).
    pub(crate) fn argus_shared(&self) -> Arc<argus::ArgusEngine> {
        Arc::clone(&self.argus)
    }
    pub fn plm(&self) -> Option<&crate::plm::PlmMonitor> {
        self.plm.as_ref()
    }

    /// Start the PowerShell Script Block Logging bridge.
    /// Config-gated: only starts if powershell_bridge_enabled = true.
    pub fn start_ps_bridge(self: &Arc<Self>, poll_secs: u64) {
        let engine = Arc::clone(&self.argus);
        let plm_graph = self.plm.as_ref().map(|p| Arc::clone(&p.graph));
        let bridge = crate::amsi::ps_bridge::PsBridge::start(poll_secs, engine, plm_graph);
        *self.ps_bridge.lock().unwrap_or_else(|e| e.into_inner()) = Some(bridge);
        tracing::info!(poll_secs, "PowerShell Script Block Logging bridge started");
    }

    /// Access the trust graph.
    #[allow(dead_code)]
    pub fn trust_graph(&self) -> Option<&crate::trust_graph::TrustGraph> {
        self.trust_graph.as_ref()
    }

    /// Get PowerShell bridge diagnostics.
    pub fn ps_bridge_diagnostics(&self) -> serde_json::Value {
        let guard = self.ps_bridge.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref bridge) = *guard {
            bridge.diagnostics.to_json()
        } else {
            serde_json::json!({"enabled": false})
        }
    }

    /// Scan a file with ClamAV — routes through subprocess if configured.
    pub fn scan_file_clamav(
        &self,
        engine: &crate::engine::ClamEngine,
        path: &std::path::Path,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> crate::engine::clamav::ScanResult {
        // Use cached performance config — clamav_isolation is read from there.
        // Avoids re-reading TOML from disk on every scan call.
        let use_subprocess = self.clamav_subprocess_enabled.load(Ordering::Relaxed);
        let timeout_sec = self.clamav_worker_timeout_sec.load(Ordering::Relaxed);
        if use_subprocess {
            if self.dll_dir.is_none() || self.db_dir.is_none() {
                tracing::warn!(
                    "clamav_isolation=subprocess but dll_dir/db_dir missing — using in-process"
                );
            }
            // Try subprocess worker.
            if let Some(dll_dir) = &self.dll_dir {
                if let Some(db_dir) = &self.db_dir {
                    let settings = crate::clamav_worker::ClamWorkerSettings {
                        enabled: true,
                        dll_dir: dll_dir.clone(),
                        db_dir: db_dir.clone(),
                        timeout: std::time::Duration::from_secs(timeout_sec.max(10)),
                    };
                    match crate::clamav_worker::scan_file(&settings, path, cancel) {
                        Ok(output) => {
                            return crate::engine::clamav::ScanResult {
                                path: output.path,
                                infected: output.infected,
                                virus_name: output.virus_name,
                                scanned_bytes: output.scanned_bytes,
                                error: output.error,
                            };
                        }
                        // SR-01: the crash-vs-cancel conflation is gone. The
                        // worker now returns a TYPED error, and the pure
                        // `clamav_fallback_decision` policy (unit-tested) says
                        // whether an in-process fallback is permitted. Only the
                        // concurrency load-shed (`Busy`) may fall back; a user
                        // cancellation and a genuine subprocess failure must
                        // NOT scan the file in-process (that would defeat the
                        // isolation boundary the operator configured, or re-run
                        // the scan the user asked to stop).
                        Err(e) => {
                            let cancelled = cancel.load(Ordering::Relaxed);
                            match clamav_fallback_decision(&e, cancelled) {
                                ClamFallback::InProcess => {
                                    tracing::debug!(
                                        path = %path.display(),
                                        "clamavd at concurrency limit — in-process fallback (load-shed, not a failure)"
                                    );
                                    // Fall through to in-process.
                                }
                                ClamFallback::Refuse => {
                                    let error = if cancelled
                                        || matches!(&e, crate::clamav_worker::WorkerError::Cancelled)
                                    {
                                        "cancelled".to_string()
                                    } else {
                                        tracing::warn!(
                                            path = %path.display(),
                                            error = %e,
                                            "clamavd subprocess failed — isolation enforced, NOT falling back to in-process (SR-01)"
                                        );
                                        format!(
                                            "clamavd subprocess failed and clamav_isolation=subprocess forbids in-process fallback: {e}"
                                        )
                                    };
                                    return crate::engine::clamav::ScanResult {
                                        path: path.to_string_lossy().to_string(),
                                        infected: false,
                                        virus_name: None,
                                        scanned_bytes: 0,
                                        error: Some(error),
                                    };
                                }
                            }
                        }
                    }
                }
            }
        }
        // Default: in-process scan.
        engine.scan_file(path)
    }

    /// Run the ARGUS hardware-parity benchmark via the worker binary and return
    /// the parsed report. When developer telemetry is on, the result is also
    /// appended to the local perf-telemetry dump (closing the benchmark→file
    /// routing gap). The benchmark always needs the worker binary even if the
    /// external-worker scan path is disabled, so it falls back to "argusd".
    pub fn run_benchmark(&self, passes: u32) -> Result<serde_json::Value, String> {
        let worker_path = if self.argus_worker.path.trim().is_empty() {
            // Match the config default so resolution lands the sibling binary.
            "argusd.exe".to_string()
        } else {
            self.argus_worker.path.clone()
        };
        let cancel = AtomicBool::new(false);
        let report = crate::argus_worker::run_benchmark(
            &worker_path,
            passes,
            std::time::Duration::from_secs(120),
            &cancel,
        )?;

        // Route into the dev-mode telemetry file (no-op unless telemetry is on).
        let dev = self
            .developer_config
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if crate::devmode::telemetry::enabled(&dev) {
            let num = |path: &[&str]| -> f64 {
                let mut cur = &report;
                for k in path {
                    match cur.get(k) {
                        Some(v) => cur = v,
                        None => return 0.0,
                    }
                }
                cur.as_f64().unwrap_or(0.0)
            };
            let files = num(&["corpus", "files"]) as u64;
            let bytes = num(&["corpus", "total_bytes"]) as u64;
            let rec = crate::devmode::telemetry::PerfRecord {
                files,
                bytes,
                ..crate::devmode::telemetry::PerfRecord::new("benchmark", "generated")
            }
            .note(format!("files_per_sec={:.1}", num(&["files_per_sec"])))
            .note(format!("mb_per_sec={:.1}", num(&["mb_per_sec"])))
            .note(format!("performance_index={}", num(&["performance_index"]) as u64))
            .note(format!(
                "per_file_us p50={} p95={}",
                num(&["per_file_us", "p50"]) as u64,
                num(&["per_file_us", "p95"]) as u64,
            ));
            crate::devmode::telemetry::record(&dev, &rec);
        }

        Ok(report)
    }

    pub fn argus_worker_diagnostics(&self) -> serde_json::Value {
        let last_error = self
            .argus_worker_last_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let last_timeout = self
            .argus_worker_last_timeout
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        serde_json::json!({
            "enabled": self.argus_worker.enabled,
            "path": self.argus_worker.path.clone(),
            "timeout_sec": self.argus_worker.timeout.as_secs(),
            "fallback_count": self.argus_worker_fallback_count.load(Ordering::Relaxed),
            "timeout_count": self.argus_worker_timeout_count.load(Ordering::Relaxed),
            "last_error": last_error,
            "last_timeout": last_timeout,
        })
    }

    pub fn orchestrator_diagnostics(&self) -> serde_json::Value {
        let state = serde_json::to_value(self.orchestrator.diagnostics())
            .unwrap_or_else(|_| serde_json::json!({}));
        let manual_queue = state
            .get("queues")
            .and_then(|queues| queues.as_array())
            .and_then(|queues| {
                queues.iter().find(|queue| {
                    queue.get("kind").and_then(|kind| kind.as_str()) == Some("manual")
                })
            });
        let manual_queue_depth = manual_queue
            .and_then(|queue| queue.get("depth"))
            .and_then(|depth| depth.as_u64())
            .unwrap_or(0);
        let average_manual_scan_duration_ms = manual_queue
            .and_then(|queue| queue.get("average_scan_duration_ms"))
            .and_then(|duration| duration.as_u64())
            .unwrap_or(0);
        let worker_active_path = self
            .scan_live
            .lock()
            .ok()
            .and_then(|live| {
                live.as_ref().and_then(|state| {
                    if !matches!(
                        state.status_enum(),
                        ScanJobStatus::Running | ScanJobStatus::Draining
                    ) {
                        return None;
                    }
                    state.current_path.lock().ok().map(|path| path.clone())
                })
            })
            .filter(|path| !path.is_empty())
            .or_else(|| {
                let inner = self.lock_inner();
                inner
                    .active_scan
                    .as_ref()
                    .filter(|job| job.status == ScanJobStatus::Running)
                    .map(|job| job.current_path.clone())
            });
        let last_orchestrated_job = self
            .last_orchestrated_job
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        // Health gate — computed outside json! macro.
        let health_gate = {
            let orch_d = self.orchestrator.diagnostics();
            let crashes: u64 = orch_d.workers.iter().map(|w| w.crash_count).sum();
            let timeouts = self.argus_worker_timeout_count.load(Ordering::Relaxed);
            let fallbacks = self.argus_worker_fallback_count.load(Ordering::Relaxed);
            let failed = self.orchestrated_failed_jobs.load(Ordering::Relaxed);
            let completed = self.orchestrated_completed_file.load(Ordering::Relaxed);
            let healthy = crashes == 0 && timeouts == 0 && failed == 0 && fallbacks <= 2;
            let ready_for_next = healthy && completed >= 3;
            serde_json::json!({
                "healthy": healthy,
                "ready_for_next_pilot": ready_for_next,
                "crashes": crashes,
                "timeouts": timeouts,
                "fallbacks": fallbacks,
                "failed": failed,
                "completed_file_scans": completed,
            })
        };

        serde_json::json!({
            "enabled_file_scan": self.orchestrator_file_scan_enabled.load(Ordering::Relaxed),
            "enabled_folder_scan": self.orchestrator_folder_scan_enabled.load(Ordering::Relaxed),
            "enabled_quick_scan": self.orchestrator_quick_scan_enabled.load(Ordering::Relaxed),
            "enabled_full_scan": self.orchestrator_full_scan_enabled.load(Ordering::Relaxed),
            "state": state,
            "last_orchestrated_job": last_orchestrated_job,
            "manual_queue_depth": manual_queue_depth,
            "worker_active_path": worker_active_path,
            "completed_file": self.orchestrated_completed_file.load(Ordering::Relaxed),
            "completed_folder": self.orchestrated_completed_folder.load(Ordering::Relaxed),
            "completed_quick": self.orchestrated_completed_quick.load(Ordering::Relaxed),
            "completed_full": self.orchestrated_completed_full.load(Ordering::Relaxed),
            "cancelled_jobs": self.orchestrated_cancelled_jobs.load(Ordering::Relaxed),
            "failed_jobs": self.orchestrated_failed_jobs.load(Ordering::Relaxed),
            "worker_fallbacks": self.argus_worker_fallback_count.load(Ordering::Relaxed),
            "worker_timeouts": self.argus_worker_timeout_count.load(Ordering::Relaxed),
            "average_manual_scan_duration_ms": average_manual_scan_duration_ms,
            "health": health_gate,
        })
    }

    fn record_argus_worker_failure(&self, error: &str) {
        self.argus_worker_fallback_count
            .fetch_add(1, Ordering::Relaxed);
        *self
            .argus_worker_last_error
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(error.to_string());
        if error.contains("timeout") {
            self.argus_worker_timeout_count
                .fetch_add(1, Ordering::Relaxed);
            *self
                .argus_worker_last_timeout
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Some(error.to_string());
            self.record_worker_timeout(error);
        } else if error.contains("panic") || error.contains("crash") {
            self.record_worker_panic(error);
        }
    }

    fn analyze_argus_file(
        &self,
        path: &Path,
        cancel: &AtomicBool,
        budget: &argus::budget::ScanExecutionBudget,
    ) -> Result<(argus::ArgusVerdict, Option<String>), String> {
        // Use external worker if explicitly enabled, audit mode, or memory pressure.
        let use_external = self.argus_worker.enabled
            || self.is_audit_mode()
            || (self.performance_config.external_argus_under_pressure
                && self.pressure_tracker.prefer_external_argus());

        if use_external {
            let reason = if self.argus_worker.enabled {
                "config"
            } else if self.is_audit_mode() {
                "audit_mode"
            } else {
                "memory_pressure"
            };
            tracing::debug!(
                path = %path.display(),
                reason,
                "routing ARGUS to external worker"
            );
            match crate::argus_worker::scan_file(&self.argus_worker, path, cancel) {
                Ok(verdict) => return Ok((verdict, None)),
                Err(e) if e.contains("cancelled") => return Err(e),
                Err(e) => {
                    self.record_argus_worker_failure(&e);
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        reason,
                        "ARGUS worker failed, falling back in-process"
                    );
                    let verdict = self.argus.analyze_file_with_budget(path, budget.clone());
                    return Ok((verdict, Some(e)));
                }
            }
        }
        Ok((
            self.argus.analyze_file_with_budget(path, budget.clone()),
            None,
        ))
    }

    /// Record an IPC request (called from dispatch).
    pub fn record_request(&self) {
        self.ipc_total_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an IPC pipe error/reconnect.
    pub fn record_ipc_error(&self) {
        self.ipc_reconnect_count.fetch_add(1, Ordering::Relaxed);
        self.ipc_last_error_ts
            .store(chrono::Utc::now().timestamp() as u64, Ordering::Relaxed);
    }

    /// Check if a manual scan is currently active (for idle scanner backpressure).
    pub fn is_scan_active(&self) -> bool {
        let inner = self.lock_inner();
        inner
            .active_scan
            .as_ref()
            .map(|j| j.status == ScanJobStatus::Running)
            .unwrap_or(false)
    }

    // ── Lock helpers — recover from poisoned mutexes ───────────
    // A panic inside a locked section poisons the mutex. These helpers
    // recover the inner value so the daemon stays alive.

    fn lock_inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| {
            tracing::warn!("inner mutex was poisoned — recovering");
            e.into_inner()
        })
    }

    fn lock_db(&self) -> MutexGuard<'_, Option<Database>> {
        self.db.lock().unwrap_or_else(|e| {
            tracing::warn!("db mutex was poisoned — recovering");
            e.into_inner()
        })
    }

    fn lock_watcher(&self) -> MutexGuard<'_, Option<crate::watcher::RealtimeWatcher>> {
        self.watcher.lock().unwrap_or_else(|e| {
            tracing::warn!("watcher mutex was poisoned — recovering");
            e.into_inner()
        })
    }

    /// Lock-free read of the current engine. Returns an owned
    /// `Option<Arc<ClamEngine>>` whose `Arc` is a refcount bump on the
    /// engine currently in the swap slot. Cheap: one atomic snapshot
    /// load + at most one Arc clone. The returned `Arc` keeps the
    /// engine alive for as long as the caller holds it, even if a
    /// concurrent reload swaps in a different snapshot.
    fn read_engine(&self) -> Option<Arc<ClamEngine>> {
        self.engine_state.load().engine.clone()
    }

    /// Lock-free read of the full engine snapshot — for callers that
    /// need both the engine handle and the most recent error in a
    /// guaranteed-consistent pair (e.g. the scan dispatcher's "engine
    /// missing → format the last error for the user" path).
    fn read_engine_snapshot(&self) -> arc_swap::Guard<Arc<EngineSnapshot>> {
        self.engine_state.load()
    }

    /// Lock-free read of the most recent engine load/reload error. Always
    /// observes a snapshot that is internally consistent with whatever
    /// `read_engine` would return at the same moment. Reserved for future
    /// callers (e.g. an `engine.health` IPC method that returns the live
    /// error alongside the engine state); current consumers go through
    /// `read_engine_snapshot()` to read both at once.
    #[allow(dead_code)]
    fn last_engine_error(&self) -> Option<String> {
        self.engine_state.load().last_error.clone()
    }

    // (read_engine_error / write_engine_error removed in the Phase 3
    // audit fix — the error now travels in the same atomic snapshot as
    // the engine handle. Callers use `last_engine_error()` or
    // `read_engine_snapshot()` to read, and `publish_engine_snapshot()`
    // / `record_engine_error()` to write.)

    /// Publish a new engine snapshot atomically (success path of a
    /// reload). Returns the previous snapshot so the caller can move its
    /// drop to a dedicated thread — see audit MED #3.
    fn publish_engine_snapshot(&self, snap: EngineSnapshot) -> Arc<EngineSnapshot> {
        self.engine_state.swap(Arc::new(snap))
    }

    /// Update only the `last_error` field of the currently-published
    /// snapshot (failure path of a reload — the previous engine stays
    /// in place; only the error annotation changes). Uses ArcSwap's RCU
    /// loop so concurrent updates compose correctly.
    fn record_engine_error(&self, err: Option<String>) {
        self.engine_state.rcu(|current| {
            Arc::new(EngineSnapshot {
                engine: current.engine.clone(),
                last_error: err.clone(),
            })
        });
    }

    /// Persist an activity event to both in-memory log and SQLite.
    pub fn log_activity(
        &self,
        severity: &str,
        category: &str,
        title: &str,
        message: &str,
        scan_id: Option<&str>,
    ) {
        let now = chrono::Utc::now().timestamp();
        let evt_id = Uuid::new_v4().to_string();

        // In-memory (capped to prevent unbounded growth).
        {
            let mut inner = self.lock_inner();
            inner.activity.push(ActivityEntry {
                event_type: category.to_string(),
                message: title.to_string(),
                detail: if message.is_empty() {
                    None
                } else {
                    Some(message.to_string())
                },
                timestamp: now,
            });
            // Keep last 500 entries in memory. SQLite has the full history.
            let alen = inner.activity.len();
            if alen > 500 {
                inner.activity.drain(..alen - 500);
            }
        }

        // SQLite.
        {
            let db_guard = self.lock_db();
            if let Some(ref db) = *db_guard {
                db.insert_activity(&ActivityRow {
                    event_id: evt_id,
                    timestamp: now,
                    severity: severity.into(),
                    category: category.into(),
                    title: title.into(),
                    message: message.into(),
                    related_scan_id: scan_id.map(|s| s.to_string()),
                });
            }
        }
    }

    /// Persist a scan record to SQLite.
    fn persist_scan(&self, scan: &ScanRow) {
        {
            let db_guard = self.lock_db();
            if let Some(ref db) = *db_guard {
                db.insert_scan(scan);
            }
        }
        // Local dev-mode perf telemetry (no-op unless developer mode is on).
        // persist_scan is the single chokepoint every recorded scan flows
        // through, so this is the natural completion checkpoint.
        self.emit_scan_telemetry(scan);
    }

    /// Append a dev-mode perf record for a completed scan. Cheap no-op unless
    /// developer mode + telemetry are enabled (gate checked before any work).
    fn emit_scan_telemetry(&self, scan: &ScanRow) {
        let dev = self
            .developer_config
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if !crate::devmode::telemetry::enabled(&dev) {
            return;
        }
        let snap = self.capture_footprint();
        let pressure = self.pressure_state();
        let (cache_hits, cache_misses, cache_entries) = self.scan_cache.stats();
        let rec = crate::devmode::telemetry::PerfRecord {
            files: scan.files_scanned,
            // bytes_scanned is now real (B1 follow-up): ClamAV scanned-byte
            // totals for single-file scans and accumulated per-job for
            // orchestrated multi-file scans. Drives MB/sec in the dump.
            bytes: scan.bytes_scanned,
            duration_ms: scan.duration_ms,
            threats: scan.threats_found,
            working_set_mb: snap.working_set_mb,
            private_bytes_mb: snap.private_bytes_mb,
            peak_working_set_mb: snap.peak_working_set_mb,
            pressure: format!("{pressure:?}"),
            ..crate::devmode::telemetry::PerfRecord::new("scan", scan.scan_type.clone())
        }
        .note(format!("status={}", scan.status))
        .note(format!("scan_id={}", scan.scan_id))
        .note(format!("errors={}", scan.errors_count))
        .note(format!(
            "scan_cache: hits={cache_hits} misses={cache_misses} entries={cache_entries}"
        ))
        // ClamAV-vs-ARGUS phase split — answers "where did the time go?"
        // across hardware. Zero on legacy/failure rows.
        .note(format!(
            "phase: clamav={}us argus={}us",
            scan.clamav_phase_us, scan.argus_phase_us
        ));
        crate::devmode::telemetry::record(&dev, &rec);
    }

    /// Publish the web-protection read handle for the IPC layer.
    ///
    /// A slot rather than a constructor argument because the subsystem
    /// starts AFTER `AppState` exists, and an `RwLock` rather than a plain
    /// field because a plain field could only ever hold its construction-time
    /// value — which for a handle published later means `webprotection.status`
    /// answering `disabled()` forever. Called from `run_daemon`; if that call
    /// is ever dropped, the status surface goes permanently dark, so this
    /// deliberately carries no `#[allow(dead_code)]` — let the compiler say so.
    pub fn set_web_protection(&self, handle: std::sync::Arc<crate::web_protection::WebProtectionHandle>) {
        *self
            .web_protection
            .write()
            .unwrap_or_else(|e| e.into_inner()) = Some(handle);
    }

    /// Current web-protection status, or the disabled shape when the
    /// subsystem never started.
    pub fn web_protection_status(&self) -> crate::web_protection::WebProtectionStatus {
        self.web_protection
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|h| h.status())
            .unwrap_or_else(crate::web_protection::WebProtectionStatus::disabled)
    }

    /// Replace the cached developer-mode config (called when the mode is toggled
    /// at runtime so telemetry gating reflects the new state immediately).
    pub fn load_developer_config(&self, dev: crate::config::DeveloperConfig) {
        *self
            .developer_config
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = dev;
    }

    /// Snapshot of the current developer-mode config.
    /// Wired by the forthcoming `dev.status` IPC (B2).
    #[allow(dead_code)]
    pub fn developer_config(&self) -> crate::config::DeveloperConfig {
        self.developer_config
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Persist a detection to SQLite.
    fn persist_detection(&self, det: &DetectionRow) {
        {
            let db_guard = self.lock_db();
            if let Some(ref db) = *db_guard {
                db.insert_detection(det);
            }
        }
    }

    /// Persist an ARGUS verdict to SQLite as a forensic intelligence record.
    fn persist_argus_verdict(&self, scan_id: &str, verdict: &argus::ArgusVerdict) {
        let findings_json = serde_json::to_string(&verdict.findings).unwrap_or("[]".into());
        let row = crate::db::ArgusVerdictRow {
            scan_id: scan_id.to_string(),
            path: verdict.path.clone(),
            score: verdict.score,
            verdict: verdict.verdict.label().to_string(),
            findings_json,
            sha256: verdict.sha256.clone(),
            mime_type: verdict.mime_type.clone(),
            file_size: verdict.file_size,
            analysis_time_us: verdict.analysis_time_us,
            engine_version: verdict.engine_version.to_string(),
            timestamp: verdict.timestamp,
        };
        let db_guard = self.lock_db();
        if let Some(ref db) = *db_guard {
            db.insert_argus_verdict(&row);
        }
    }

    // ═══════════════════════════════════════════════════════
    //  engine.status
    // ═══════════════════════════════════════════════════════

    pub fn engine_status(&self) -> EngineStatus {
        let inner = self.lock_inner();
        // Phase 2: prefer the committed mirror. Falls back to the live CVD
        // read only when no commit has happened yet (initial boot before
        // the first successful engine load completes).
        let committed_ver = self.committed_db_version.load(Ordering::Acquire);
        let committed_ts = self.committed_db_timestamp.load(Ordering::Acquire);
        let (db_version, db_timestamp) = if committed_ts != i64::MIN {
            (
                if committed_ver == 0 { None } else { Some(committed_ver) },
                Some(committed_ts),
            )
        } else {
            self.read_cvd_version()
        };
        let phase = reload_phase_from_u8(self.reload_phase.load(Ordering::Acquire));

        // `state` reflects the COMMITTED engine, not the in-flight one.
        // A reload that is currently `Compiling` or `Activating` keeps the
        // previous engine serving scans, so the shield must stay Ready.
        // The UI distinguishes "engine is busy reloading" via `reload_phase`.
        let state = if self.read_engine().is_some() {
            EngineState::Ready
        } else {
            EngineState::Error
        };

        EngineStatus {
            state,
            protocol_version: 1,
            db_version,
            db_timestamp,
            signature_count: self.signature_count.load(Ordering::Relaxed),
            last_update: inner.last_update_timestamp,
            engine_version: sentinella_common::PRODUCT_VERSION.into(),
            reload_phase: phase,
        }
    }

    /// Write the committed-state mirror atomically. Called as the LAST step
    /// of every successful engine load / reload, after the engine slot has
    /// been swapped to the new `Arc<ClamEngine>`.
    ///
    /// Phase 2 invariant: a status snapshot taken after this call observes
    /// the new (signature_count, db_version, db_timestamp) triple
    /// consistently. Anything observed between the freshclam CVD write and
    /// this commit reads the PRIOR mirror — so the GUI never sees the
    /// "old sigs / new db_ts" inconsistency that triggered the false
    /// "outdated definitions" banner.
    fn commit_engine_state(&self, sigs: u64) {
        let (db_ver, db_ts) = self.read_cvd_version();
        // Ordering: write `signature_count` LAST so a reader that observes
        // the new count is guaranteed (via the Release/Acquire pair) to
        // also see the new db_version + db_timestamp.
        self.committed_db_version
            .store(db_ver.unwrap_or(0), Ordering::Release);
        self.committed_db_timestamp
            .store(db_ts.unwrap_or(i64::MIN), Ordering::Release);
        self.signature_count.store(sigs, Ordering::Release);
    }

    /// Read ClamAV database version from CVD file header.
    /// CVD format: first line = `ClamAV-VDB:time:version:sigs:func_level:md5:builder:stime`
    /// `stime` (field 7) is unix timestamp.
    fn read_cvd_version(&self) -> (Option<u32>, Option<i64>) {
        let db_dir = match &self.db_dir {
            Some(d) => d,
            None => return (None, None),
        };

        // Try daily.cvd first (most frequently updated), then main.cvd.
        for name in &["daily.cvd", "daily.cld", "main.cvd", "main.cld"] {
            let path = db_dir.join(name);
            if let Ok(file) = std::fs::File::open(&path) {
                use std::io::Read;
                let mut header = [0u8; 512];
                let mut reader = std::io::BufReader::new(file);
                if reader.read(&mut header).unwrap_or(0) > 20 {
                    let line = String::from_utf8_lossy(&header);
                    if let Some(first_line) = line.lines().next() {
                        let parts: Vec<&str> = first_line.split(':').collect();
                        if parts.len() >= 3 && parts[0].starts_with("ClamAV-VDB") {
                            let version = parts[2].parse::<u32>().ok();
                            // Field 7 (index 7) is unix timestamp if available.
                            let stime = if parts.len() > 7 {
                                parts[7].trim().parse::<i64>().ok()
                            } else {
                                None
                            };
                            return (version, stime);
                        }
                    }
                }
            }
        }

        (None, None)
    }

    /// Most-recent modification time (unix secs) across the signature DB files.
    /// Reflects when freshclam last WROTE a definition — and unlike the
    /// in-memory `last_update_timestamp`, it persists across daemon restarts.
    /// Used for staleness so a freshly-updated DB isn't reported "out of date"
    /// merely because the daemon (or the whole box) restarted.
    fn newest_signature_db_mtime_secs(&self) -> Option<i64> {
        let db_dir = self.db_dir.as_ref()?;
        let names = [
            "daily.cvd", "daily.cld", "main.cvd", "main.cld", "bytecode.cvd", "bytecode.cld",
        ];
        let mut newest: Option<i64> = None;
        for name in &names {
            if let Ok(meta) = std::fs::metadata(db_dir.join(name)) {
                if let Ok(modified) = meta.modified() {
                    if let Ok(dur) = modified.duration_since(std::time::UNIX_EPOCH) {
                        let secs = dur.as_secs() as i64;
                        newest = Some(newest.map_or(secs, |n| n.max(secs)));
                    }
                }
            }
        }
        newest
    }

    // ═══════════════════════════════════════════════════════
    //  scan.start — single file or quick scan
    // ═══════════════════════════════════════════════════════

    pub fn start_scan(
        self: &Arc<Self>,
        scan_type: &str,
        target: Option<&str>,
    ) -> ScanStartResponse {
        // Phase 3 + audit fix: take ONE atomic snapshot so the engine
        // handle and the error message we'd report come from the same
        // consistent (engine, last_error) pair. Avoids the previous
        // race where engine could read "new" while the error read
        // still saw the prior reload's stale string.
        let snap = self.read_engine_snapshot();
        let engine = match snap.engine.clone() {
            Some(e) => e,
            None => {
                let err = snap
                    .last_error
                    .clone()
                    .unwrap_or_else(|| "No engine".to_string());
                drop(snap);
                return ScanStartResponse {
                    job_id: Uuid::new_v4().to_string(),
                    status: "error".into(),
                    result: None,
                    error: Some(format!("Engine not available: {err}")),
                };
            }
        };
        drop(snap);

        // Record manual scan activity — blocks quiet re-trim.
        self.activity_tracker.record_manual_scan();

        match scan_type {
            "file" if self.orchestrator_file_scan_enabled.load(Ordering::Relaxed) => {
                self.start_orchestrated_file_scan(engine, target)
            }
            "file" => self.scan_single_file(&engine, target),
            "quick" if self.orchestrator_quick_scan_enabled.load(Ordering::Relaxed) => {
                self.start_orchestrated_quick_scan(engine)
            }
            "quick" => self.start_quick_scan(engine),
            "folder" if self.orchestrator_folder_scan_enabled.load(Ordering::Relaxed) => {
                self.start_orchestrated_folder_scan(engine, target)
            }
            "folder" => self.start_folder_scan(engine, target),
            "full" if self.orchestrator_full_scan_enabled.load(Ordering::Relaxed) => {
                self.start_orchestrated_full_scan(engine)
            }
            "full" => self.start_full_scan(engine),
            "startup" => self.start_startup_scan(engine),
            _ => ScanStartResponse {
                job_id: Uuid::new_v4().to_string(),
                status: "error".into(),
                result: None,
                error: Some(format!("Unknown scan type: {scan_type}")),
            },
        }
    }

    fn scan_single_file(&self, engine: &ClamEngine, target: Option<&str>) -> ScanStartResponse {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();

        let path_str = match target {
            Some(p) => p,
            None => {
                return ScanStartResponse {
                    job_id: id.to_string(),
                    status: "error".into(),
                    result: None,
                    error: Some("No target path specified".into()),
                };
            }
        };

        let path = Path::new(path_str);
        let mut argus_result: Option<argus::ArgusVerdict> = None;

        let result = if !path.exists() {
            ScanResultResponse {
                path: path_str.to_string(),
                infected: false,
                virus_name: None,
                scanned_bytes: 0,
                error: Some("File not found".into()),
            }
        } else if {
            let config = crate::config::Config::load(None).unwrap_or_default();
            crate::scan::is_excluded(path, &config.excluded_paths, &config.excluded_extensions)
        } {
            ScanResultResponse {
                path: path_str.to_string(),
                infected: false,
                virus_name: None,
                scanned_bytes: 0,
                error: Some("Path excluded by configuration".into()),
            }
        } else {
            // ── Layer 0: ClamAV signature scan ─────────────────
            let no_cancel = AtomicBool::new(false);
            let r = self.scan_file_clamav(&engine, path, &no_cancel);

            // ── Layers 1–7: ARGUS heuristic analysis ───────────
            // Single-file user-initiated scan → manual profile budget.
            let budget = argus::budget::ScanExecutionBudget::manual();
            let (argus_verdict, worker_error) = self
                .analyze_argus_file(path, &no_cancel, &budget)
                .unwrap_or_else(|e| {
                    (
                        self.argus
                            .analyze_file_with_budget(path, budget.clone()),
                        Some(e),
                    )
                });

            // ── Unified verdict: one file, one detection ──────
            let (infected, virus_name) = unify_detection_filtered(
                r.infected,
                r.virus_name.as_deref(),
                &argus_verdict,
                &self.detection_exclusions(),
            );

            if !argus_verdict.findings.is_empty() {
                tracing::debug!(
                    path = path_str,
                    score = argus_verdict.score,
                    findings = argus_verdict.findings.len(),
                    time_us = argus_verdict.analysis_time_us,
                    "ARGUS analysis: {}",
                    argus_verdict.verdict.label(),
                );
            }
            if let Some(error) = worker_error {
                tracing::warn!(path = path_str, error = %error, "ARGUS worker fallback used");
            }

            argus_result = Some(argus_verdict);

            ScanResultResponse {
                path: r.path,
                infected,
                virus_name,
                scanned_bytes: r.scanned_bytes,
                error: r.error,
            }
        };

        // An ARGUS analysis-error verdict (read failure / sharing violation)
        // is NOT a clean result — surface the file as errored so the caller
        // doesn't record it as "scanned clean".
        let argus_incomplete = argus_result
            .as_ref()
            .and_then(|v| argus_analysis_error(v))
            .is_some();
        let status = if result.error.is_some() || argus_incomplete {
            "error"
        } else if result.infected {
            "infected"
        } else {
            "clean"
        };

        let finished = chrono::Utc::now().timestamp();
        let threats = if result.infected { 1u64 } else { 0 };
        let scan_id_str = id.to_string();

        // Persist scan record. Per-job perf fields populated from this single
        // file's clamav phase (`scanned_bytes`) and the ARGUS phase timing.
        let (clamav_us, argus_us) = argus_result
            .as_ref()
            .and_then(|v| v.timing.as_ref())
            .map(|t| (t.clamav_us, t.argus_total_us))
            .unwrap_or((0, 0));
        let scan_row = ScanRow {
            scan_id: scan_id_str.clone(),
            scan_type: "file".into(),
            status: status.to_string(),
            started_at: now,
            finished_at: Some(finished),
            files_scanned: 1,
            threats_found: threats,
            errors_count: if result.error.is_some() { 1 } else { 0 },
            // .max(0) guard: NTP backward correction between `now` and `finished`
            // would otherwise underflow the i64 subtraction → cast-to-u64 wraps
            // to a garbage value and the row, telemetry and UI all show insane
            // duration_ms. Every other completion site already guards this — this
            // single-file path was the outlier.
            duration_ms: ((finished - now).max(0) as u64) * 1000,
            bytes_scanned: result.scanned_bytes,
            clamav_phase_us: clamav_us,
            argus_phase_us: argus_us,
        };
        self.persist_scan(&scan_row);

        // Persist ARGUS verdict as forensic record.
        if let Some(ref av) = argus_result {
            self.persist_argus_verdict(&scan_id_str, av);
        }

        // Persist in-memory history (capped).
        let mut inner = self.lock_inner();
        inner.scan_history.push(ScanRecord {
            job_id: scan_id_str.clone(),
            scan_type: "file".into(),
            started_at: now,
            finished_at: finished,
            files_scanned: 1,
            threats_found: threats,
            status: status.to_string(),
        });
        let hlen = inner.scan_history.len();
        if hlen > 200 {
            inner.scan_history.drain(..hlen - 200);
        }
        drop(inner);

        // Persist detection if infected.
        if result.infected {
            self.persist_detection(&DetectionRow {
                detection_id: Uuid::new_v4().to_string(),
                scan_id: scan_id_str.clone(),
                path: path_str.to_string(),
                virus_name: result.virus_name.clone().unwrap_or("Unknown".into()),
                detected_at: finished,
                action_taken: "none".into(),
            });
        }

        // Activity event.
        let severity = if result.infected { "critical" } else { "info" };
        let title = if result.infected {
            format!(
                "Threat: {}",
                result.virus_name.as_deref().unwrap_or("Unknown")
            )
        } else {
            "File scan: clean".into()
        };
        self.log_activity(severity, "scan", &title, path_str, Some(&scan_id_str));

        ScanStartResponse {
            job_id: id.to_string(),
            status: status.to_string(),
            result: Some(result),
            error: None,
        }
    }

    /// Atomically reserve `active_scan` for a new scan, or reject if one is
    /// already in flight. The overlap **check** and the **reservation** happen
    /// in a SINGLE `inner` critical section.
    ///
    /// This closes a TOCTOU race: the IPC server `tokio::spawn`s one task per
    /// pipe connection, so two `scan.start` requests genuinely run in parallel.
    /// The previous `check_no_overlapping_scan()` released the lock before the
    /// caller separately re-acquired it to set `active_scan`, so two callers
    /// could both pass the check and both install their job — orphaning the
    /// first (uncancellable; its completion handler no-ops because
    /// `active.id != job.id`).
    ///
    /// On success the caller installs `scan_live` and submits the orchestrated
    /// job. `active_scan.status` remains the single source of truth for
    /// "is a scan running?" — the Completed/Cancelled/Failed transitions reset
    /// it, so do NOT add a parallel flag that could desync.
    fn try_reserve_scan(&self, job: ScanJob) -> Result<(), ScanStartResponse> {
        // Hold the SINGLE `inner` lock across the whole check-and-reserve.
        reserve_active_scan(&mut self.lock_inner(), job)
    }

    fn start_orchestrated_file_scan(
        self: &Arc<Self>,
        engine: Arc<ClamEngine>,
        target: Option<&str>,
    ) -> ScanStartResponse {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();
        // Fail-fast validation BEFORE reserving — don't claim the scan slot
        // for a request that's about to error out.
        let path_str = match target {
            Some(p) if !p.trim().is_empty() => p.to_string(),
            _ => {
                return ScanStartResponse {
                    job_id: id.to_string(),
                    status: "error".into(),
                    result: None,
                    error: Some("No target path specified".into()),
                };
            }
        };

        let cancel_flag = Arc::new(AtomicBool::new(false));
        let token = crate::orchestrator::CancellationToken::from_flag(Arc::clone(&cancel_flag));
        let live = Arc::new(ScanLiveState {
            id: id.to_string(),
            kind: "file".into(),
            started_at: now,
            files_total: AtomicU64::new(1),
            files_scanned: AtomicU64::new(0),
            threats_found: AtomicU64::new(0),
            cancel_flag: Arc::clone(&cancel_flag),
            status: std::sync::atomic::AtomicU8::new(0), // pending/queued
            current_path: Mutex::new(path_str.clone()),
        });

        // Atomic check-and-reserve (TOCTOU fix). The fully-built job — with the
        // real cancel_flag + live — is installed in the same critical section
        // as the overlap check, so a concurrent scan.cancel in the window
        // cannot be lost to a throwaway placeholder.
        if let Err(reject) = self.try_reserve_scan(ScanJob {
            id,
            kind: "file".into(),
            status: ScanJobStatus::Pending,
            started_at: now,
            finished_at: None,
            files_scanned: 0,
            files_total: 1,
            threats_found: 0,
            current_path: path_str.clone(),
            detections: Vec::new(),
            errors: Vec::new(),
            cancel_flag: Arc::clone(&cancel_flag),
            perf_summary: ScanPerformanceSummary::default(),
            live: Some(Arc::clone(&live)),
        }) {
            return reject;
        }
        *self.scan_live.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::clone(&live));

        let job = OrchestratedScanJob {
            id: id.to_string(),
            queue_kind: crate::orchestrator::QueueKind::Manual,
            path: path_str.clone(),
            requested_at: now,
        };
        let state = Arc::clone(self);
        let submit_result = self.orchestrator.submit(
            crate::orchestrator::QueueKind::Manual,
            token,
            move |token| {
                state.run_orchestrated_file_scan(job, engine, token, live);
            },
        );

        if let Err(e) = submit_result {
            self.complete_orchestrated_file_failure(
                id.to_string(),
                path_str.clone(),
                now,
                e.clone(),
            );
            return ScanStartResponse {
                job_id: id.to_string(),
                status: "error".into(),
                result: None,
                error: Some(e),
            };
        }

        ScanStartResponse {
            job_id: id.to_string(),
            status: "queued".into(),
            result: None,
            error: None,
        }
    }

    fn run_orchestrated_file_scan(
        self: Arc<Self>,
        job: OrchestratedScanJob,
        engine: Arc<ClamEngine>,
        token: crate::orchestrator::CancellationToken,
        live: Arc<ScanLiveState>,
    ) {
        let started = std::time::Instant::now();
        if token.is_cancelled() {
            self.complete_orchestrated_file_cancelled(&job, &live, started.elapsed());
            return;
        }

        live.set_status(ScanJobStatus::Running);
        {
            let mut inner = self.lock_inner();
            if let Some(ref mut active) = inner.active_scan {
                if active.id.to_string() == job.id {
                    active.status = ScanJobStatus::Running;
                }
            }
        }

        let path = PathBuf::from(&job.path);
        if !path.exists() {
            self.complete_orchestrated_file_error(
                &job,
                &live,
                started.elapsed(),
                "File not found".into(),
            );
            return;
        }
        let config = crate::config::Config::load(None).unwrap_or_default();
        if crate::scan::is_excluded(&path, &config.excluded_paths, &config.excluded_extensions) {
            self.complete_orchestrated_file_error(
                &job,
                &live,
                started.elapsed(),
                "Path excluded by configuration".into(),
            );
            return;
        }

        // Use the orchestrator token's flag (not a fresh AtomicBool nobody
        // ever sets) so scan.cancel can interrupt a long ClamAV scan of a
        // large file — the ARGUS phase below already honored it.
        let cancel_ref = token.flag();
        let result = self.scan_file_clamav(&engine, &path, &cancel_ref);
        if token.is_cancelled() {
            self.complete_orchestrated_file_cancelled(&job, &live, started.elapsed());
            return;
        }

        let (argus_verdict, worker_error) = self
            .analyze_argus_file(
                &path,
                &cancel_ref,
                &argus::budget::ScanExecutionBudget::manual(),
            )
            .unwrap_or_else(|e| {
                (
                    self.argus.analyze_file_with_budget(
                        &path,
                        argus::budget::ScanExecutionBudget::manual(),
                    ),
                    Some(e),
                )
            });
        if let Some(error) = worker_error {
            tracing::warn!(path = %job.path, error = %error, "ARGUS worker fallback used");
        }

        if token.is_cancelled() {
            self.complete_orchestrated_file_cancelled(&job, &live, started.elapsed());
            return;
        }

        let (infected, virus_name) = unify_detection_filtered(
            result.infected,
            result.virus_name.as_deref(),
            &argus_verdict,
            &self.detection_exclusions(),
        );
        let scan_result = ScanResultResponse {
            path: result.path,
            infected,
            virus_name,
            scanned_bytes: result.scanned_bytes,
            error: result.error,
        };
        self.complete_orchestrated_file_success(
            &job,
            &live,
            started.elapsed(),
            scan_result,
            argus_verdict,
        );
    }

    fn complete_orchestrated_file_success(
        &self,
        job: &OrchestratedScanJob,
        live: &ScanLiveState,
        elapsed: std::time::Duration,
        result: ScanResultResponse,
        argus_verdict: argus::ArgusVerdict,
    ) {
        let finished = chrono::Utc::now().timestamp();
        let threats = if result.infected { 1 } else { 0 };
        let status = if result.error.is_some() {
            "failed"
        } else {
            "completed"
        };
        live.files_scanned.store(1, Ordering::Relaxed);
        live.threats_found.store(threats, Ordering::Relaxed);
        live.set_status(ScanJobStatus::Completed);
        self.orchestrated_completed_file
            .fetch_add(1, Ordering::Relaxed);

        let (clamav_us, argus_us) = argus_verdict
            .timing
            .as_ref()
            .map(|t| (t.clamav_us, t.argus_total_us))
            .unwrap_or((0, 0));
        self.persist_scan(&ScanRow {
            scan_id: job.id.clone(),
            scan_type: "file".into(),
            status: status.into(),
            started_at: job.requested_at,
            finished_at: Some(finished),
            files_scanned: 1,
            threats_found: threats,
            errors_count: if result.error.is_some() { 1 } else { 0 },
            duration_ms: elapsed.as_millis() as u64,
            bytes_scanned: result.scanned_bytes,
            clamav_phase_us: clamav_us,
            argus_phase_us: argus_us,
        });
        self.persist_argus_verdict(&job.id, &argus_verdict);

        if result.infected {
            self.persist_detection(&DetectionRow {
                detection_id: Uuid::new_v4().to_string(),
                scan_id: job.id.clone(),
                path: job.path.clone(),
                virus_name: result.virus_name.clone().unwrap_or("Unknown".into()),
                detected_at: finished,
                action_taken: "none".into(),
            });
        }

        {
            let mut inner = self.lock_inner();
            if let Some(ref mut active) = inner.active_scan {
                if active.id.to_string() == job.id {
                    active.status = ScanJobStatus::Completed;
                    active.finished_at = Some(finished);
                    active.files_scanned = 1;
                    active.threats_found = threats;
                    active.current_path.clear();
                    if result.infected {
                        active.detections = vec![Detection {
                            path: job.path.clone(),
                            virus_name: result.virus_name.clone().unwrap_or("Unknown".into()),
                        }];
                    }
                    if let Some(error) = &result.error {
                        active.errors.push(error.clone());
                    }
                }
            }
            inner.scan_history.push(ScanRecord {
                job_id: job.id.clone(),
                scan_type: "file".into(),
                started_at: job.requested_at,
                finished_at: finished,
                files_scanned: 1,
                threats_found: threats,
                status: status.into(),
            });
            let hlen = inner.scan_history.len();
            if hlen > 200 {
                inner.scan_history.drain(..hlen - 200);
            }
        }

        let verdict = Some(argus_verdict.verdict.label().to_string());
        *self
            .last_orchestrated_job
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(OrchestratedJobResult {
            id: job.id.clone(),
            path: job.path.clone(),
            verdict,
            status: status.into(),
            duration_ms: elapsed.as_millis() as u64,
            error: result.error.clone(),
        });

        let severity = if result.infected { "critical" } else { "info" };
        let title = if result.infected {
            format!(
                "Threat: {}",
                result.virus_name.as_deref().unwrap_or("Unknown")
            )
        } else {
            "File scan: clean".into()
        };
        self.log_activity(severity, "scan", &title, &job.path, Some(&job.id));
    }

    fn complete_orchestrated_file_cancelled(
        &self,
        job: &OrchestratedScanJob,
        live: &ScanLiveState,
        elapsed: std::time::Duration,
    ) {
        let finished = chrono::Utc::now().timestamp();
        live.set_status(ScanJobStatus::Cancelled);
        self.orchestrated_cancelled_jobs
            .fetch_add(1, Ordering::Relaxed);

        {
            let mut inner = self.lock_inner();
            if let Some(ref mut active) = inner.active_scan {
                if active.id.to_string() == job.id {
                    active.status = ScanJobStatus::Cancelled;
                    active.finished_at = Some(finished);
                    active.current_path.clear();
                }
            }
            inner.scan_history.push(ScanRecord {
                job_id: job.id.clone(),
                scan_type: "file".into(),
                started_at: job.requested_at,
                finished_at: finished,
                files_scanned: 0,
                threats_found: 0,
                status: "cancelled".into(),
            });
        }

        *self
            .last_orchestrated_job
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(OrchestratedJobResult {
            id: job.id.clone(),
            path: job.path.clone(),
            verdict: None,
            status: "cancelled".into(),
            duration_ms: elapsed.as_millis() as u64,
            error: None,
        });
        self.log_activity(
            "warning",
            "scan",
            "File scan cancelled",
            &job.path,
            Some(&job.id),
        );
    }

    fn complete_orchestrated_file_error(
        &self,
        job: &OrchestratedScanJob,
        live: &ScanLiveState,
        elapsed: std::time::Duration,
        error: String,
    ) {
        self.complete_orchestrated_file_failure(
            job.id.clone(),
            job.path.clone(),
            job.requested_at,
            error.clone(),
        );
        live.set_status(ScanJobStatus::Failed);
        *self
            .last_orchestrated_job
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(OrchestratedJobResult {
            id: job.id.clone(),
            path: job.path.clone(),
            verdict: None,
            status: "failed".into(),
            duration_ms: elapsed.as_millis() as u64,
            error: Some(error),
        });
    }

    fn complete_orchestrated_file_failure(
        &self,
        id: String,
        path: String,
        requested_at: i64,
        error: String,
    ) {
        let finished = chrono::Utc::now().timestamp();
        self.orchestrated_failed_jobs
            .fetch_add(1, Ordering::Relaxed);
        self.persist_scan(&ScanRow {
            scan_id: id.clone(),
            scan_type: "file".into(),
            status: "failed".into(),
            started_at: requested_at,
            finished_at: Some(finished),
            files_scanned: 0,
            threats_found: 0,
            errors_count: 1,
            duration_ms: ((finished - requested_at).max(0) as u64) * 1000,
            ..ScanRow::default()
        });
        self.log_activity("warning", "scan", "File scan failed", &error, Some(&id));
        let mut inner = self.lock_inner();
        if let Some(ref mut active) = inner.active_scan {
            if active.id.to_string() == id {
                active.status = ScanJobStatus::Failed;
                active.finished_at = Some(finished);
                active.errors.push(error.clone());
                active.current_path.clear();
            }
        }
        inner.scan_history.push(ScanRecord {
            job_id: id.clone(),
            scan_type: "file".into(),
            started_at: requested_at,
            finished_at: finished,
            files_scanned: 0,
            threats_found: 0,
            status: "failed".into(),
        });
        *self
            .last_orchestrated_job
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(OrchestratedJobResult {
            id,
            path,
            verdict: None,
            status: "failed".into(),
            duration_ms: ((finished - requested_at).max(0) as u64) * 1000,
            error: Some(error),
        });
    }

    /// Submit-failure cleanup for orchestrated folder/quick/full scans.
    ///
    /// Those starters reserve the scan slot (`try_reserve_scan`, status
    /// `Pending`) BEFORE `orchestrator.submit`. If submit fails (queue
    /// depth ≥ cap, or the worker channel is closed after a worker panic)
    /// no worker will ever run — and the old code just returned the error,
    /// leaving the job `Pending` forever. `reserve_active_scan` rejects
    /// every future scan while a job is Pending, so one transient
    /// orchestrator failure bricked all manual scans until daemon restart.
    /// The file-scan path already handles this via
    /// `complete_orchestrated_file_failure`; mirror it here by marking the
    /// reserved job Failed (a terminal state), which releases the slot.
    fn fail_orchestrated_submit(&self, id: Uuid, live: &ScanLiveState, error: &str) {
        live.set_status(ScanJobStatus::Failed);
        let mut inner = self.lock_inner();
        if let Some(ref mut active) = inner.active_scan {
            if active.id == id {
                active.status = ScanJobStatus::Failed;
                active.finished_at = Some(chrono::Utc::now().timestamp());
                active.errors.push(error.to_string());
                active.current_path.clear();
            }
        }
    }

    /// Orchestrated folder scan — runs through worker queue with cancel support.
    fn start_orchestrated_folder_scan(
        self: &Arc<Self>,
        engine: Arc<ClamEngine>,
        target: Option<&str>,
    ) -> ScanStartResponse {
        // Fail-fast validation BEFORE reserving the scan slot.
        let folder = match target {
            Some(p) if std::path::Path::new(p).is_dir() => p.to_string(),
            Some(p) => {
                return ScanStartResponse {
                    job_id: Uuid::new_v4().to_string(),
                    status: "error".into(),
                    result: None,
                    error: Some(format!("Not a directory: {p}")),
                };
            }
            None => {
                return ScanStartResponse {
                    job_id: Uuid::new_v4().to_string(),
                    status: "error".into(),
                    result: None,
                    error: Some("No target directory specified".into()),
                };
            }
        };

        let id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();
        let cancel_flag = Arc::new(AtomicBool::new(false));
        let token = crate::orchestrator::CancellationToken::from_flag(Arc::clone(&cancel_flag));

        let live = Arc::new(ScanLiveState {
            id: id.to_string(),
            kind: "folder".into(),
            started_at: now,
            files_total: AtomicU64::new(0),
            files_scanned: AtomicU64::new(0),
            threats_found: AtomicU64::new(0),
            cancel_flag: Arc::clone(&cancel_flag),
            status: std::sync::atomic::AtomicU8::new(0), // queued
            current_path: Mutex::new(format!("Enumerating {folder}...")),
        });

        // Atomic check-and-reserve (TOCTOU fix) — single critical section.
        if let Err(reject) = self.try_reserve_scan(ScanJob {
            id,
            kind: "folder".into(),
            status: ScanJobStatus::Pending,
            started_at: now,
            finished_at: None,
            files_scanned: 0,
            files_total: 0,
            threats_found: 0,
            current_path: format!("Queued: {folder}"),
            detections: Vec::new(),
            errors: Vec::new(),
            cancel_flag: Arc::clone(&cancel_flag),
            perf_summary: ScanPerformanceSummary::default(),
            live: Some(Arc::clone(&live)),
        }) {
            return reject;
        }
        *self.scan_live.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::clone(&live));

        self.log_activity(
            "info",
            "scan",
            &format!("Folder scan queued: {folder}"),
            &folder,
            None,
        );

        let state = Arc::clone(self);
        let live_ref = Arc::clone(&live);
        let submit_result = self.orchestrator.submit(
            crate::orchestrator::QueueKind::Manual,
            token.clone(),
            move |token| {
                // Entry cancellation check: the job may have been cancelled
                // (and its slot re-reserved by a successor) while this
                // closure sat in the queue — running anyway would corrupt
                // the successor's scan state.
                if token.is_cancelled() {
                    return;
                }
                // Run through inner worker, passing live state to avoid overwrite.
                let cancel = Arc::clone(&live_ref.cancel_flag);
                let targets = vec![PathBuf::from(&folder)];
                folder_scan_worker_inner(
                    state,
                    id,
                    engine,
                    cancel,
                    targets,
                    "folder",
                    Some(live_ref),
                );
            },
        );

        if let Err(e) = submit_result {
            tracing::error!(%e, "orchestrator folder scan submit failed");
            // Slot was reserved above but no worker will run — mark the job
            // Failed (terminal) so future scans aren't rejected forever.
            self.fail_orchestrated_submit(id, &live, &e);
            return ScanStartResponse {
                job_id: id.to_string(),
                status: "error".into(),
                result: None,
                error: Some(e),
            };
        }

        ScanStartResponse {
            job_id: id.to_string(),
            status: "queued".into(),
            result: None,
            error: None,
        }
    }

    /// Orchestrated quick scan — same targets as legacy, routed through queue.
    fn start_orchestrated_quick_scan(
        self: &Arc<Self>,
        engine: Arc<ClamEngine>,
    ) -> ScanStartResponse {
        // Fail-fast validation BEFORE reserving the scan slot.
        let home = std::env::var("USERPROFILE").unwrap_or_default();
        let temp =
            std::env::var("TEMP").unwrap_or_else(|_| format!("{home}\\AppData\\Local\\Temp"));
        let targets: Vec<PathBuf> = [
            format!("{home}\\Downloads"),
            format!("{home}\\Desktop"),
            temp,
        ]
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect();

        if targets.is_empty() {
            return ScanStartResponse {
                job_id: Uuid::new_v4().to_string(),
                status: "error".into(),
                result: None,
                error: Some("No quick scan directories found".into()),
            };
        }

        let id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();
        let cancel_flag = Arc::new(AtomicBool::new(false));
        let token = crate::orchestrator::CancellationToken::from_flag(Arc::clone(&cancel_flag));

        let live = Arc::new(ScanLiveState {
            id: id.to_string(),
            kind: "quick".into(),
            started_at: now,
            files_total: AtomicU64::new(0),
            files_scanned: AtomicU64::new(0),
            threats_found: AtomicU64::new(0),
            cancel_flag: Arc::clone(&cancel_flag),
            status: std::sync::atomic::AtomicU8::new(0),
            current_path: Mutex::new("Queued: quick scan".into()),
        });

        // Atomic check-and-reserve (TOCTOU fix) — single critical section.
        if let Err(reject) = self.try_reserve_scan(ScanJob {
            id,
            kind: "quick".into(),
            status: ScanJobStatus::Pending,
            started_at: now,
            finished_at: None,
            files_scanned: 0,
            files_total: 0,
            threats_found: 0,
            current_path: "Queued".into(),
            detections: Vec::new(),
            errors: Vec::new(),
            cancel_flag: Arc::clone(&cancel_flag),
            perf_summary: ScanPerformanceSummary::default(),
            live: Some(Arc::clone(&live)),
        }) {
            return reject;
        }
        *self.scan_live.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::clone(&live));

        self.log_activity("info", "scan", "Quick scan queued (orchestrated)", "", None);

        let state = Arc::clone(self);
        let live_ref = Arc::clone(&live);
        let submit_result = self.orchestrator.submit(
            crate::orchestrator::QueueKind::Manual,
            token,
            move |token| {
                // Entry cancellation check — see the folder variant.
                if token.is_cancelled() {
                    return;
                }
                let cancel = Arc::clone(&live_ref.cancel_flag);
                folder_scan_worker_inner(
                    state,
                    id,
                    engine,
                    cancel,
                    targets,
                    "quick",
                    Some(live_ref),
                );
            },
        );

        if let Err(e) = submit_result {
            tracing::error!(%e, "orchestrator quick scan submit failed");
            // Slot was reserved above but no worker will run — mark the job
            // Failed (terminal) so future scans aren't rejected forever.
            self.fail_orchestrated_submit(id, &live, &e);
            return ScanStartResponse {
                job_id: id.to_string(),
                status: "error".into(),
                result: None,
                error: Some(e),
            };
        }

        ScanStartResponse {
            job_id: id.to_string(),
            status: "queued".into(),
            result: None,
            error: None,
        }
    }

    fn start_folder_scan(
        self: &Arc<Self>,
        engine: Arc<ClamEngine>,
        target: Option<&str>,
    ) -> ScanStartResponse {
        let folder = match target {
            Some(p) if std::path::Path::new(p).is_dir() => p.to_string(),
            Some(p) => {
                return ScanStartResponse {
                    job_id: Uuid::new_v4().to_string(),
                    status: "error".into(),
                    result: None,
                    error: Some(format!("Not a directory: {p}")),
                };
            }
            None => {
                return ScanStartResponse {
                    job_id: Uuid::new_v4().to_string(),
                    status: "error".into(),
                    result: None,
                    error: Some("No folder path specified".into()),
                };
            }
        };

        let id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();
        let cancel_flag = Arc::new(AtomicBool::new(false));
        // Atomic check-and-reserve (covers Running/Pending/Draining — also
        // rejects an in-flight orchestrated Pending job, which the old
        // Running-only check missed).
        if let Err(reject) = self.try_reserve_scan(ScanJob {
            id,
            kind: "folder".into(),
            status: ScanJobStatus::Running,
            started_at: now,
            finished_at: None,
            files_scanned: 0,
            files_total: 0,
            threats_found: 0,
            current_path: "Starting...".into(),
            detections: Vec::new(),
            errors: Vec::new(),
            cancel_flag: Arc::clone(&cancel_flag),
            perf_summary: ScanPerformanceSummary::default(),
            live: None,
        }) {
            return reject;
        }
        self.log_activity(
            "info",
            "scan",
            &format!("Folder scan started: {folder}"),
            &folder,
            None,
        );
        let state = Arc::clone(self);
        let targets = vec![std::path::PathBuf::from(folder)];
        std::thread::spawn(move || {
            folder_scan_worker(state, id, engine, cancel_flag, targets, "folder");
        });
        ScanStartResponse {
            job_id: id.to_string(),
            status: "running".into(),
            result: None,
            error: None,
        }
    }

    fn start_quick_scan(self: &Arc<Self>, engine: Arc<ClamEngine>) -> ScanStartResponse {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();
        let cancel_flag = Arc::new(AtomicBool::new(false));

        {
            let mut inner = self.lock_inner();
            // Atomic check-and-reserve (Running/Pending/Draining) in one lock.
            if let Err(reject) = reserve_active_scan(
                &mut inner,
                ScanJob {
                    id,
                    kind: "quick".into(),
                    status: ScanJobStatus::Running,
                    started_at: now,
                    finished_at: None,
                    files_scanned: 0,
                    files_total: 0,
                    threats_found: 0,
                    current_path: "Starting...".into(),
                    detections: Vec::new(),
                    errors: Vec::new(),
                    cancel_flag: Arc::clone(&cancel_flag),
                    perf_summary: ScanPerformanceSummary::default(),
                    live: None,
                },
            ) {
                return reject;
            }
            inner.activity.push(ActivityEntry {
                event_type: "scan_start".into(),
                message: "Quick scan started".into(),
                detail: Some("Scanning Downloads, Desktop, Temp".into()),
                timestamp: now,
            });
        }

        // Spawn background scan worker.
        let state = Arc::clone(self);
        std::thread::spawn(move || {
            quick_scan_worker(state, id, engine, cancel_flag);
        });

        ScanStartResponse {
            job_id: id.to_string(),
            status: "running".into(),
            result: None,
            error: None,
        }
    }

    // ═══════════════════════════════════════════════════════
    //  scan.start type="full" — all fixed drives
    // ═══════════════════════════════════════════════════════

    fn start_full_scan(self: &Arc<Self>, engine: Arc<ClamEngine>) -> ScanStartResponse {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();
        let cancel_flag = Arc::new(AtomicBool::new(false));

        // Atomic check-and-reserve (Running/Pending/Draining) in one lock.
        {
            let mut inner = self.lock_inner();
            if let Err(reject) = reserve_active_scan(
                &mut inner,
                ScanJob {
                    id,
                    kind: "full".into(),
                    status: ScanJobStatus::Running,
                    started_at: now,
                    finished_at: None,
                    files_scanned: 0,
                    files_total: 0,
                    threats_found: 0,
                    current_path: "Enumerating drives...".into(),
                    detections: Vec::new(),
                    errors: Vec::new(),
                    cancel_flag: Arc::clone(&cancel_flag),
                    perf_summary: ScanPerformanceSummary::default(),
                    live: None,
                },
            ) {
                return reject;
            }
            inner.activity.push(ActivityEntry {
                event_type: "scan_start".into(),
                message: "Full disk scan started".into(),
                detail: Some("Scanning all fixed drives".into()),
                timestamp: now,
            });
        }

        let state = Arc::clone(self);
        std::thread::spawn(move || {
            full_scan_worker(state, id, engine, cancel_flag);
        });

        ScanStartResponse {
            job_id: id.to_string(),
            status: "running".into(),
            result: None,
            error: None,
        }
    }

    // ═══════════════════════════════════════════════════════
    //  scan.start type="full" — orchestrator-routed
    // ═══════════════════════════════════════════════════════

    fn start_orchestrated_full_scan(
        self: &Arc<Self>,
        engine: Arc<ClamEngine>,
    ) -> ScanStartResponse {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();
        let cancel_flag = Arc::new(AtomicBool::new(false));
        let token = crate::orchestrator::CancellationToken::from_flag(Arc::clone(&cancel_flag));

        let live = Arc::new(ScanLiveState {
            id: id.to_string(),
            kind: "full".into(),
            started_at: now,
            files_total: AtomicU64::new(0),
            files_scanned: AtomicU64::new(0),
            threats_found: AtomicU64::new(0),
            cancel_flag: Arc::clone(&cancel_flag),
            status: std::sync::atomic::AtomicU8::new(0), // queued
            current_path: Mutex::new("Enumerating drives...".into()),
        });

        // Atomic check-and-reserve (TOCTOU fix) — single critical section.
        if let Err(reject) = self.try_reserve_scan(ScanJob {
            id,
            kind: "full".into(),
            status: ScanJobStatus::Pending,
            started_at: now,
            finished_at: None,
            files_scanned: 0,
            files_total: 0,
            threats_found: 0,
            current_path: "Queued: full disk scan".into(),
            detections: Vec::new(),
            errors: Vec::new(),
            cancel_flag: Arc::clone(&cancel_flag),
            perf_summary: ScanPerformanceSummary::default(),
            live: Some(Arc::clone(&live)),
        }) {
            return reject;
        }
        *self.scan_live.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::clone(&live));

        self.log_activity(
            "info",
            "scan",
            "Full disk scan queued (orchestrated)",
            "",
            None,
        );

        let state = Arc::clone(self);
        let live_ref = Arc::clone(&live);
        let submit_result = self.orchestrator.submit(
            crate::orchestrator::QueueKind::Manual,
            token.clone(),
            move |token| {
                // Entry cancellation check — see the folder variant.
                if token.is_cancelled() {
                    return;
                }
                use crate::targeting::{
                    TargetConfig, TargetProvider, dedup, full_disk::FullDiskTargets,
                };
                let config = TargetConfig {
                    full_scan_fixed_drives: true,
                    full_scan_max_depth: 15,
                    ..TargetConfig::default()
                };
                let targets = dedup::deduplicate(FullDiskTargets.collect(&config));
                tracing::info!(
                    drives = targets.len(),
                    "orchestrated full disk scan starting"
                );
                let cancel = Arc::clone(&live_ref.cancel_flag);
                folder_scan_worker_inner(
                    state,
                    id,
                    engine,
                    cancel,
                    targets,
                    "full",
                    Some(live_ref),
                );
            },
        );

        if let Err(e) = submit_result {
            tracing::error!(%e, "orchestrator full scan submit failed");
            // Slot was reserved above but no worker will run — mark the job
            // Failed (terminal) so future scans aren't rejected forever.
            self.fail_orchestrated_submit(id, &live, &e);
            return ScanStartResponse {
                job_id: id.to_string(),
                status: "error".into(),
                result: None,
                error: Some(e),
            };
        }

        ScanStartResponse {
            job_id: id.to_string(),
            status: "queued".into(),
            result: None,
            error: None,
        }
    }

    // ═══════════════════════════════════════════════════════
    //  scan.start type="startup" — autorun + recent executables
    // ═══════════════════════════════════════════════════════

    fn start_startup_scan(self: &Arc<Self>, engine: Arc<ClamEngine>) -> ScanStartResponse {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now().timestamp();
        let cancel_flag = Arc::new(AtomicBool::new(false));

        {
            let mut inner = self.lock_inner();
            // Atomic check-and-reserve (Running/Pending/Draining) in one lock.
            if let Err(reject) = reserve_active_scan(
                &mut inner,
                ScanJob {
                    id,
                    kind: "startup".into(),
                    status: ScanJobStatus::Running,
                    started_at: now,
                    finished_at: None,
                    files_scanned: 0,
                    files_total: 0,
                    threats_found: 0,
                    current_path: "Collecting startup targets...".into(),
                    detections: Vec::new(),
                    errors: Vec::new(),
                    cancel_flag: Arc::clone(&cancel_flag),
                    perf_summary: ScanPerformanceSummary::default(),
                    live: None,
                },
            ) {
                return reject;
            }
            inner.activity.push(ActivityEntry {
                event_type: "scan_start".into(),
                message: "Startup scan started".into(),
                detail: Some("Scanning autorun entries + recent executables".into()),
                timestamp: now,
            });
        }

        let state = Arc::clone(self);
        std::thread::spawn(move || {
            startup_scan_worker(state, id, engine, cancel_flag);
        });

        ScanStartResponse {
            job_id: id.to_string(),
            status: "running".into(),
            result: None,
            error: None,
        }
    }

    // ═══════════════════════════════════════════════════════
    //  scan.status
    // ═══════════════════════════════════════════════════════

    pub fn scan_status(&self) -> ScanStatusResponse {
        // ── Lock-free fast path: read from atomic live state ──
        // This avoids contending with scan worker locks during heavy scans.
        if let Ok(live_guard) = self.scan_live.try_lock() {
            if let Some(ref live) = *live_guard {
                let scanned = live.files_scanned.load(Ordering::Relaxed);
                let total = live.files_total.load(Ordering::Relaxed);
                let threats = live.threats_found.load(Ordering::Relaxed);
                let status = live.status_enum();
                let pct = if total > 0 {
                    (scanned as f32 * 100.0 / total as f32).min(100.0)
                } else {
                    0.0
                };
                let path = live
                    .current_path
                    .lock()
                    .map(|p| p.clone())
                    .unwrap_or_default();

                let inner = self.lock_inner();
                let scans_completed = inner.scan_history.len() as u64;
                let detections = inner
                    .active_scan
                    .as_ref()
                    .map(|j| j.detections.clone())
                    .unwrap_or_default();

                return ScanStatusResponse {
                    running: status == ScanJobStatus::Running || status == ScanJobStatus::Draining,
                    job_id: Some(live.id.clone()),
                    state: match status {
                        ScanJobStatus::Pending => "queued",
                        ScanJobStatus::Running => "running",
                        ScanJobStatus::Completed => "completed",
                        ScanJobStatus::Cancelled => "cancelled",
                        ScanJobStatus::Failed => "failed",
                        ScanJobStatus::Draining => "cancelling",
                    },
                    scan_type: Some(live.kind.clone()),
                    files_scanned: scanned,
                    files_total: total,
                    progress_percent: pct,
                    threats_found: threats,
                    current_path: Some(path),
                    scans_completed,
                    detections,
                    started_at: Some(live.started_at),
                    finished_at: None,
                    errors_count: 0,
                };
            }
        }

        // ── Fallback: read from inner (for completed/idle scans) ──
        let inner = self.lock_inner();
        match &inner.active_scan {
            Some(job) => {
                let pct = if job.files_total > 0 {
                    ((job.files_scanned as f32 * 100.0) / job.files_total as f32).min(100.0)
                } else {
                    0.0
                };
                ScanStatusResponse {
                    running: job.status == ScanJobStatus::Running,
                    job_id: Some(job.id.to_string()),
                    state: match job.status {
                        ScanJobStatus::Pending => "queued",
                        ScanJobStatus::Running => "running",
                        ScanJobStatus::Completed => "completed",
                        ScanJobStatus::Cancelled => "cancelled",
                        ScanJobStatus::Failed => "failed",
                        ScanJobStatus::Draining => "cancelling",
                    },
                    scan_type: Some(job.kind.clone()),
                    files_scanned: job.files_scanned,
                    files_total: job.files_total,
                    progress_percent: pct,
                    threats_found: job.threats_found,
                    current_path: Some(job.current_path.clone()),
                    scans_completed: inner.scan_history.len() as u64,
                    detections: job.detections.clone(),
                    started_at: Some(job.started_at),
                    finished_at: job.finished_at,
                    errors_count: job.errors.len() as u64,
                }
            }
            None => ScanStatusResponse {
                running: false,
                job_id: None,
                state: "idle",
                scan_type: None,
                files_scanned: 0,
                files_total: 0,
                progress_percent: 0.0,
                threats_found: 0,
                current_path: None,
                scans_completed: inner.scan_history.len() as u64,
                detections: vec![],
                started_at: None,
                finished_at: None,
                errors_count: 0,
            },
        }
    }

    // ═══════════════════════════════════════════════════════
    //  scan.cancel
    // ═══════════════════════════════════════════════════════

    pub fn cancel_scan(&self) -> bool {
        // Set cancel flag + mark as draining (lock-free for immediate UI response).
        if let Ok(live_guard) = self.scan_live.lock() {
            if let Some(ref live) = *live_guard {
                let previous = live.status_enum();
                // MED (audit): refuse to transition a terminal job. The old
                // code mapped ANY non-Pending status — including
                // Completed/Failed/Cancelled — to Draining, a non-terminal
                // state nothing ever leaves, permanently bricking every
                // future scan.start until daemon restart.
                let Some(next) = cancel_transition(previous) else {
                    return false;
                };
                live.cancel_flag.store(true, Ordering::Relaxed);
                live.set_status(next);
                let mut inner = self.lock_inner();
                if let Some(ref mut job) = inner.active_scan {
                    if job.id.to_string() == live.id {
                        job.cancel_flag.store(true, Ordering::Relaxed);
                        job.status = next;
                    }
                }
                return true;
            }
        }
        // Fallback: check inner.
        let mut inner = self.lock_inner();
        if let Some(ref mut job) = inner.active_scan {
            if let Some(next) = cancel_transition(job.status) {
                job.cancel_flag.store(true, Ordering::Relaxed);
                job.status = next;
                return true;
            }
        }
        false
    }

    // ═══════════════════════════════════════════════════════
    //  scan.history + remaining endpoints
    // ═══════════════════════════════════════════════════════

    pub fn scan_history(&self) -> Vec<ScanRow> {
        // Prefer SQLite for persistence across restarts.
        {
            let db_guard = self.lock_db();
            if let Some(ref db) = *db_guard {
                return db.recent_scans(50);
            }
        }
        // Fallback to in-memory.
        let inner = self.lock_inner();
        inner
            .scan_history
            .iter()
            .rev()
            .map(|r| ScanRow {
                scan_id: r.job_id.clone(),
                scan_type: r.scan_type.clone(),
                status: r.status.clone(),
                started_at: r.started_at,
                finished_at: Some(r.finished_at),
                files_scanned: r.files_scanned,
                threats_found: r.threats_found,
                errors_count: 0,
                duration_ms: ((r.finished_at - r.started_at).max(0) as u64) * 1000,
                // In-memory fallback (DB unavailable): the legacy ScanRecord
                // doesn't carry per-job perf aggregates, so these read 0.
                ..ScanRow::default()
            })
            .collect()
    }

    pub fn quarantine_list(&self) -> Vec<crate::db::QuarantineRow> {
        {
            let db_guard = self.lock_db();
            if let Some(ref db) = *db_guard {
                return db.list_quarantine();
            }
        }
        vec![]
    }

    pub fn quarantine_file(
        &self,
        path: &str,
        virus_name: &str,
        scan_id: &str,
    ) -> Result<crate::quarantine::QuarantineResult, String> {
        let vault_dir = crate::paths::paths().quarantine_dir();
        std::fs::create_dir_all(&vault_dir).map_err(|e| format!("Cannot create vault dir: {e}"))?;

        let prepared = crate::quarantine::prepare_quarantine_file(
            std::path::Path::new(path),
            &vault_dir,
            virus_name,
            scan_id,
        )?;
        {
            let db_guard = self.db.lock().map_err(|e| format!("DB lock: {e}"))?;
            let db = db_guard.as_ref().ok_or("Database not available")?;
            // Commit-ordering discipline (mirror of quarantine::quarantine_file):
            // on insert failure the just-written vault blob has no restorable
            // row — it would be an unlisted, never-GC'd orphan. Remove it and
            // surface the DB error; the original file stays in place.
            if let Err(e) = db.insert_quarantine_item(&prepared.row) {
                if prepared.vault_path.exists() {
                    let _ = std::fs::remove_file(&prepared.vault_path);
                }
                tracing::warn!(id = %prepared.row.quarantine_id, error = %e, "quarantine DB insert failed — vault file removed");
                return Err(e);
            }
        }
        if let Err(e) = crate::quarantine::finalize_quarantine_file(&prepared) {
            if let Ok(db_guard) = self.db.lock() {
                if let Some(ref db) = *db_guard {
                    let _ = db.update_quarantine_status(&prepared.row.quarantine_id, "failed");
                }
            }
            // Clean up orphaned vault file on failure.
            if prepared.vault_path.exists() {
                let _ = std::fs::remove_file(&prepared.vault_path);
            }
            tracing::warn!(id = %prepared.row.quarantine_id, error = %e, "quarantine finalize failed");
            return Err(e);
        }
        let result = prepared.result;

        // Log activity.
        self.log_activity(
            "critical",
            "quarantine",
            &format!("Quarantined: {virus_name}"),
            path,
            Some(scan_id),
        );

        Ok(result)
    }

    /// Quarantine F4: mark `path` as recently restored so the realtime watcher
    /// will skip it for the suppression TTL (30s). Called BEFORE the restore
    /// write hits disk so the CREATE event that ReadDirectoryChangesW emits is
    /// already inside the suppression window when the watcher dispatch sees it.
    /// Also evicts entries older than the TTL on every call (bounded-by-traffic
    /// GC — keeps the map small without a background sweeper).
    pub(crate) fn mark_restore_in_progress(&self, path: &Path) {
        const TTL: Duration = Duration::from_secs(30);
        let key = restore_suppress_key(path);
        if let Ok(mut map) = self.restore_suppress.lock() {
            let now = Instant::now();
            map.retain(|_, t| now.duration_since(*t) < TTL);
            map.insert(key, now);
        }
    }

    /// Quarantine F4: undo a mark_restore_in_progress when the restore then
    /// FAILED — otherwise the failed target stays suppressed for the full
    /// TTL and a watcher event for genuinely new content at that path would
    /// be skipped (detection gap). Key derivation must match the mark side.
    pub(crate) fn unmark_restore_in_progress(&self, path: &Path) {
        let key = restore_suppress_key(path);
        if let Ok(mut map) = self.restore_suppress.lock() {
            map.remove(&key);
        }
    }

    /// Quarantine F4: returns true if `path` was marked for restore-suppression
    /// within the last 30s. The watcher calls this per CREATE event to break
    /// the restore → re-quarantine loop.
    pub fn is_restore_suppressed(&self, path: &Path) -> bool {
        const TTL: Duration = Duration::from_secs(30);
        let key = restore_suppress_key(path);
        if let Ok(map) = self.restore_suppress.lock() {
            if let Some(t) = map.get(&key) {
                return Instant::now().duration_since(*t) < TTL;
            }
        }
        false
    }

    pub fn quarantine_restore(&self, id: &str) -> Result<String, String> {
        let item = {
            let db_guard = self.db.lock().map_err(|e| format!("DB lock: {e}"))?;
            let db = db_guard.as_ref().ok_or("Database not available")?;
            db.get_quarantine_item(id)?
                .ok_or_else(|| format!("Not found: {id}"))?
        };
        // F4: suppress watcher BEFORE the restore writes to original_path so
        // the CREATE event ReadDirectoryChangesW emits lands inside the TTL.
        self.mark_restore_in_progress(std::path::Path::new(&item.original_path));
        let path = match crate::quarantine::restore_file_from_row(&item) {
            Ok(p) => p,
            Err(e) => {
                // Restore failed — nothing was written, so the suppression
                // mark must not linger (it would blind the watcher to real
                // drops at this path for the next 30s).
                self.unmark_restore_in_progress(std::path::Path::new(&item.original_path));
                return Err(e);
            }
        };
        // Commit DB status BEFORE purging vault. If the DB write fails, the
        // restored plaintext file is already on disk (security-positive: user
        // gets their file back) AND the vault is retained so a future retry
        // can converge state. The previous order — vault-delete then
        // fire-and-forget DB write — left an unrecoverable window where a
        // crash between the two operations meant the row stayed
        // "quarantined" with no vault file. The realtime watcher could then
        // re-quarantine the restored file in a loop.
        {
            let db_guard = self.db.lock().map_err(|e| format!("DB lock: {e}"))?;
            let db = db_guard.as_ref().ok_or("Database not available")?;
            db.update_quarantine_status(id, "restored")?;
        }
        crate::quarantine::purge_vault_after_restore(&item.vault_path);
        self.log_activity(
            "warning",
            "quarantine",
            "File restored from quarantine",
            &path,
            None,
        );
        Ok(path)
    }

    pub fn quarantine_restore_as(&self, id: &str, dest: &str) -> Result<String, String> {
        let item = {
            let db_guard = self.db.lock().map_err(|e| format!("DB lock: {e}"))?;
            let db = db_guard.as_ref().ok_or("Database not available")?;
            db.get_quarantine_item(id)?
                .ok_or_else(|| format!("Not found: {id}"))?
        };
        let dest_path = std::path::Path::new(dest);
        // F4: suppress watcher BEFORE write — see quarantine_restore.
        self.mark_restore_in_progress(dest_path);
        let path = match crate::quarantine::restore_file_as(&item, dest_path) {
            Ok(p) => p,
            Err(e) => {
                // Restore failed — drop the suppression mark (see
                // quarantine_restore for why a stale mark is a detection gap).
                self.unmark_restore_in_progress(dest_path);
                return Err(e);
            }
        };
        // Same commit-then-cleanup ordering as quarantine_restore — see
        // that method for the unrecoverable-window rationale.
        {
            let db_guard = self.db.lock().map_err(|e| format!("DB lock: {e}"))?;
            let db = db_guard.as_ref().ok_or("Database not available")?;
            db.update_quarantine_status(id, "restored")?;
        }
        crate::quarantine::purge_vault_after_restore(&item.vault_path);
        self.log_activity(
            "warning",
            "quarantine",
            "File restored to alternate path",
            &path,
            None,
        );
        Ok(path)
    }

    pub fn quarantine_delete(&self, id: &str) -> Result<(), String> {
        let item = {
            let db_guard = self.db.lock().map_err(|e| format!("DB lock: {e}"))?;
            let db = db_guard.as_ref().ok_or("Database not available")?;
            db.get_quarantine_item(id)?
                .ok_or_else(|| format!("Not found: {id}"))?
        };
        // F3: refuse to delete the vault if a concurrent restore has already
        // flipped the status. Without this check the vault disappears while
        // the row is "restored" → next quarantine.list still shows the row
        // with restorable=false but no way to recover, masking the race.
        if item.status != "quarantined" {
            return Err(format!(
                "Cannot delete: status is '{}', not quarantined",
                item.status
            ));
        }
        crate::quarantine::delete_vault_file(&item)?;
        {
            let db_guard = self.db.lock().map_err(|e| format!("DB lock: {e}"))?;
            let db = db_guard.as_ref().ok_or("Database not available")?;
            // F3: surface the DB-write failure instead of swallowing it.
            // The vault is already gone, so we cannot un-delete; but ops
            // needs to see the inconsistency in the log to manually clean
            // the orphan row (status stays "quarantined" with no vault).
            if let Err(e) = db.update_quarantine_status(id, "deleted") {
                tracing::warn!(
                    id,
                    error = %e,
                    "quarantine.delete: vault unlinked but DB status update failed — row is now orphaned"
                );
            }
        }
        self.log_activity(
            "info",
            "quarantine",
            "Quarantine item permanently deleted",
            id,
            None,
        );
        Ok(())
    }

    pub fn watcher_status(&self) -> WatcherStatus {
        let guard = self.lock_watcher();
        match &*guard {
            Some(w) if w.is_running() => WatcherStatus {
                enabled: true,
                mode: WatcherMode::UserMode,
                watched_roots: w
                    .watched_roots()
                    .iter()
                    .map(|p| p.to_string_lossy().to_string())
                    .collect(),
                events_per_sec: 0.0,
                last_event: None,
            },
            _ => WatcherStatus {
                enabled: false,
                mode: WatcherMode::Disabled,
                watched_roots: vec![],
                events_per_sec: 0.0,
                last_event: None,
            },
        }
    }

    /// Reload the ClamAV engine after a signature update.
    ///
    /// State machine: idle → loading → ready/failed
    /// Rejects concurrent reloads. Drops old engine before loading new one
    /// to prevent 2× memory spike.
    pub fn is_engine_reloading(&self) -> bool {
        ENGINE_RELOAD_IN_PROGRESS.load(Ordering::Relaxed)
    }

    pub fn reload_engine(&self) -> Result<u64, String> {
        self.activity_tracker.record_reload();
        if ENGINE_RELOAD_IN_PROGRESS
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err("engine reload already in progress".into());
        }

        // RAII guard: flag MUST reset even if reload_engine_inner panics.
        // Without this, a panic during cl_engine_compile (e.g. corrupt CVD,
        // OOM) leaves the flag stuck true forever → policy.rs blocks ALL
        // mutating IPC permanently until daemon restart.
        struct ReloadGuard;
        impl Drop for ReloadGuard {
            fn drop(&mut self) {
                ENGINE_RELOAD_IN_PROGRESS.store(false, Ordering::SeqCst);
            }
        }
        let _guard = ReloadGuard;

        let reload_start = std::time::Instant::now();
        let result = self.reload_engine_inner();
        let reload_ms = reload_start.elapsed().as_millis();
        match &result {
            Ok(sigs) => tracing::info!(reload_ms, sigs, "engine reload complete"),
            Err(e) => tracing::error!(reload_ms, error = e.as_str(), "engine reload failed"),
        }
        self.emit_reload_telemetry(reload_ms as u64, &result);
        result
    }

    /// Append a dev-mode perf record for an engine reload (signature hot-load).
    /// Cheap no-op unless developer mode + telemetry are enabled. Reload is a
    /// natural perf checkpoint: it is the main memory-spike event and its
    /// duration is the scan-blind window users feel after an update.
    fn emit_reload_telemetry(&self, reload_ms: u64, result: &Result<u64, String>) {
        let dev = self
            .developer_config
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if !crate::devmode::telemetry::enabled(&dev) {
            return;
        }
        let snap = self.capture_footprint();
        let pressure = self.pressure_state();
        let (detail, sig_note) = match result {
            Ok(sigs) => ("ok", format!("signatures={sigs}")),
            Err(e) => ("failed", format!("error={e}")),
        };
        let rec = crate::devmode::telemetry::PerfRecord {
            duration_ms: reload_ms,
            working_set_mb: snap.working_set_mb,
            private_bytes_mb: snap.private_bytes_mb,
            peak_working_set_mb: snap.peak_working_set_mb,
            pressure: format!("{pressure:?}"),
            ..crate::devmode::telemetry::PerfRecord::new("reload", detail)
        }
        .note(sig_note);
        crate::devmode::telemetry::record(&dev, &rec);
    }

    fn reload_engine_inner(&self) -> Result<u64, String> {
        let (dll_dir, db_dir) = match (&self.dll_dir, &self.db_dir) {
            (Some(d), Some(db)) => (d, db),
            _ => return Err("DLL or DB directory not configured".into()),
        };

        tracing::info!("reloading ClamAV engine...");
        // Phase 2: announce the compile. The committed mirror is unchanged
        // until `commit_engine_state` runs, so concurrent `engine.status`
        // readers see `state = Ready` + `reload_phase = Compiling` and the
        // GUI can render an "Updating signatures…" badge without flipping
        // the shield.
        self.reload_phase
            .store(reload_phase_u8(ReloadPhase::Compiling), Ordering::Release);

        // FAIL-CLOSED reload: load NEW engine first into a local. Only on
        // success do we take the write lock + swap. Previously we dropped the
        // old engine BEFORE the load attempt to save ~1 GB peak — but a load
        // failure (corrupt sigs, disk full, OOM at exactly the wrong moment)
        // would leave the slot `None` AND fail to record the error, so all
        // realtime scans silently passed (fail-open AV). Brief 2x memory peak
        // is strictly preferable to running with no detection engine.
        match ClamEngine::load(dll_dir, db_dir) {
            Ok(new_engine) => {
                // Phase 2: compile done, entering the (very brief) swap.
                self.reload_phase
                    .store(reload_phase_u8(ReloadPhase::Activating), Ordering::Release);

                let sigs = new_engine.signature_count() as u64;
                self.scan_cache.invalidate_all();
                // Signatures changed → expire ARGUS per-hash trusted cache too,
                // so previously-clean signed/reputable files are re-analyzed
                // (the cache otherwise never invalidated in production).
                self.argus.trusted_cache.invalidate();
                let new_arc = Arc::new(new_engine);
                // Atomic swap: replace engine AND clear stale error in a
                // single critical section so concurrent readers never observe
                // (engine=new, error=Some(stale)) or (engine=old, error=None).
                //
                // Phase 3 + audit fix: engine and last_error are siblings
                // inside ONE atomic `EngineSnapshot` published via the
                // single `engine_state` ArcSwap. The publish delivers both
                // fields together — a reader can't observe an inconsistent
                // pair regardless of platform memory model.
                //
                // The returned `prev` Arc is the slot's previous strong
                // ref. When the last in-flight scan also releases its
                // clone, the old `ClamEngine`'s `cl_engine_free` runs.
                // Move the `drop(prev)` onto a dedicated thread so neither
                // the freshclam thread nor an IPC handler ever pays the
                // tear-down cost — audit MED #3.
                let prev = self.publish_engine_snapshot(EngineSnapshot {
                    engine: Some(new_arc),
                    last_error: None,
                });
                let _ = std::thread::Builder::new()
                    .name("engine-snap-drop".into())
                    .spawn(move || drop(prev));
                // Phase 2: commit (signature_count + db_version + db_timestamp)
                // atomically as the LAST observable state change, then mark
                // the phase Idle. A `engine.status` snapshot taken after
                // `commit_engine_state` returns is guaranteed (Release/Acquire)
                // to see the new triple consistently.
                self.commit_engine_state(sigs);
                self.reload_phase
                    .store(reload_phase_u8(ReloadPhase::Idle), Ordering::Release);
                self.log_activity(
                    "info",
                    "engine",
                    &format!("Engine reloaded — {sigs} signatures"),
                    "",
                    None,
                );
                Ok(sigs)
            }
            Err(e) => {
                tracing::error!(%e, "engine reload failed — keeping previous engine");
                // Phase 2: surface the failure to GUI as `reload_phase=Failed`.
                // The committed mirror is NOT touched — `signature_count`,
                // `db_version`, `db_timestamp` continue to reflect the
                // previous successful commit, which is what the still-serving
                // engine actually has loaded.
                self.reload_phase
                    .store(reload_phase_u8(ReloadPhase::Failed), Ordering::Release);
                // Record the error so callers (and the daemon health surface)
                // observe the failure. Old engine remains in place → scans
                // continue with prior signatures rather than failing open.
                self.record_engine_error(Some(e.clone()));
                self.log_activity("warning", "engine", "Engine reload failed", &e, None);
                Err(e)
            }
        }
    }

    /// Start the real-time watcher. Call after engine is loaded.
    pub fn start_watcher(self: &Arc<Self>) {
        let engine = match self.read_engine() {
            Some(e) => e,
            None => {
                tracing::warn!("cannot start watcher: engine not loaded");
                return;
            }
        };

        // Priority:
        //   1. config.realtime_roots (user-configured via Settings → save_settings)
        //      — honor explicit user choice when set.
        //   2. Hardcoded enumeration of C:\Users\* (when config empty or only
        //      contains LocalSystem-expanded garbage).
        //
        // Independent of that choice, well-known system/persistence locations
        // are ALWAYS watched: ProgramData, TEMP, C:\Windows\Temp, and (F-9,
        // v0.1.12) each real user's `AppData\Local\Programs`.
        //
        // When running as LocalSystem service, USERPROFILE expands to
        // C:\Windows\system32\config\systemprofile — NOT the logged-in user's
        // profile. Default config from config/mod.rs:171 contains paths like
        // "{home}\Downloads" that expand to the wrong place under SYSTEM. We
        // filter those out before deciding whether config is "really empty".
        let cfg = crate::config::Config::load(None).unwrap_or_default();
        let mut roots: Vec<std::path::PathBuf> = Vec::new();

        // Filter out config entries that point to non-existent paths or to
        // the systemprofile directory (LocalSystem-expanded bogus paths).
        let config_roots: Vec<std::path::PathBuf> = cfg
            .realtime_roots
            .iter()
            .map(std::path::PathBuf::from)
            .filter(|p| {
                let s = p.to_string_lossy().to_ascii_lowercase();
                !s.contains("\\config\\systemprofile\\") && p.exists()
            })
            .collect();

        if !config_roots.is_empty() {
            tracing::info!(count = config_roots.len(), "watcher: using config.realtime_roots");
            roots.extend(config_roots);
        } else {
            tracing::info!("watcher: config.realtime_roots empty or invalid; falling back to enumeration");
        }

        // System-level paths (always present, regardless of config).
        if let Ok(pd) = std::env::var("PROGRAMDATA") {
            roots.push(std::path::PathBuf::from(pd));
        } else {
            roots.push(std::path::PathBuf::from("C:\\ProgramData"));
        }
        if let Ok(t) = std::env::var("TEMP") {
            roots.push(std::path::PathBuf::from(t));
        }
        roots.push(std::path::PathBuf::from("C:\\Windows\\Temp"));

        // F-9 (v0.1.12): per-user `%LOCALAPPDATA%\Programs` — the canonical
        // per-user install/persistence location (VS Code, Chrome, Discord,
        // most NSIS/Squirrel per-user installers). VERIFIED missing from
        // realtime coverage in v0.1.11; a dropper landing there survived
        // until the next idle/scheduled scan. Added unconditionally, like
        // the ProgramData/TEMP roots above: this is a persistence location,
        // not a user preference, so it stays covered even when
        // config.realtime_roots is customized. Profiles are enumerated
        // (process LOCALAPPDATA is systemprofile under LocalSystem — never
        // what we want); missing dirs are skipped; duplicates are dropped
        // case-insensitively.
        for p in user_profile_subdirs(Path::new("C:\\Users"), "AppData\\Local\\Programs") {
            push_unique_existing_root(&mut roots, p);
        }

        // Enumerate C:\Users\* only as fallback when config gave us nothing.
        if roots.iter().filter(|p| {
            let s = p.to_string_lossy().to_ascii_lowercase();
            s.contains("\\downloads") || s.contains("\\desktop") || s.contains("\\documents")
        }).count() == 0 {
            let skip_users = ["Default", "Default User", "Public", "All Users", "defaultuser0", "WDAGUtilityAccount"];
            if let Ok(entries) = std::fs::read_dir("C:\\Users") {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if !path.is_dir() { continue; }
                    let name = match path.file_name().and_then(|n| n.to_str()) {
                        Some(n) => n,
                        None => continue,
                    };
                    if skip_users.iter().any(|s| s.eq_ignore_ascii_case(name)) { continue; }
                    for sub in &["Downloads", "Desktop", "Documents", "OneDrive",
                                 "AppData\\Roaming", "AppData\\Local\\Temp"] {
                        let p = path.join(sub);
                        if p.exists() {
                            roots.push(p);
                        }
                    }
                }
            }
        }

        // Dev/portable mode: also include process USERPROFILE if it points to a real user.
        if let Ok(home) = std::env::var("USERPROFILE") {
            let home_lower = home.to_ascii_lowercase();
            if !home_lower.contains("\\config\\systemprofile") {
                for sub in &["Downloads", "Desktop", "Documents"] {
                    let p = std::path::PathBuf::from(&home).join(sub);
                    if p.exists() && !roots.iter().any(|r| r == &p) {
                        roots.push(p);
                    }
                }
            }
        }

        // Canonicalize + dedupe (case-insensitive on Windows). Critical: notify
        // crate fails or behaves unpredictably if the same physical path is
        // registered twice with different casing (e.g., C:\WINDOWS\TEMP and
        // C:\Windows\Temp both exist as candidates).
        let mut canonical: Vec<std::path::PathBuf> = Vec::new();
        let mut seen_keys: std::collections::HashSet<String> = std::collections::HashSet::new();
        for p in roots.into_iter() {
            if p.as_os_str().is_empty() { continue; }
            // Prefer canonicalized form; fall back to raw if canonicalize fails.
            let resolved = p.canonicalize().unwrap_or_else(|_| p.clone());
            if !resolved.exists() { continue; }
            let key = resolved.to_string_lossy().to_lowercase();
            if seen_keys.insert(key) {
                canonical.push(resolved);
            }
        }
        let mut roots = canonical;

        // R3-22: cap watchable roots. ReadDirectoryChangesW + recursive watch
        // costs ~1 thread/handle per root. A malicious or careless config
        // listing thousands of paths would exhaust handles and starve the
        // event pump. 128 is well above any reasonable user need.
        const MAX_ROOTS: usize = 128;
        if roots.len() > MAX_ROOTS {
            tracing::warn!(
                count = roots.len(),
                cap = MAX_ROOTS,
                "watcher: too many roots, truncating"
            );
            roots.truncate(MAX_ROOTS);
        }

        if roots.is_empty() {
            tracing::warn!("no watchable directories found");
            return;
        }

        let root_count = roots.len();
        let root_names: Vec<_> = roots
            .iter()
            .filter_map(|p| {
                p.file_name()
                    .or_else(|| p.components().last().map(|c| c.as_os_str()))
            })
            .map(|n| n.to_string_lossy().to_string())
            .collect();

        match crate::watcher::RealtimeWatcher::start(roots, engine, Arc::clone(self)) {
            Ok(w) => {
                *self.lock_watcher() = Some(w);
                self.log_activity(
                    "info",
                    "watcher",
                    "Real-time protection started",
                    &format!(
                        "Monitoring {} directories: {}",
                        root_count,
                        root_names.join(", ")
                    ),
                    None,
                );
            }
            Err(e) => {
                tracing::error!(%e, "failed to start watcher");
                self.log_activity("warning", "watcher", "Watcher failed to start", &e, None);
            }
        }
    }

    /// Start the resource-aware idle background scanner.
    pub fn start_idle_scanner(self: &Arc<Self>) {
        let config = crate::config::Config::load(None).unwrap_or_default();
        if !config.idle_scan_enabled {
            tracing::info!("idle scanner disabled by config");
            return;
        }

        let engine = match self.read_engine() {
            Some(e) => e,
            None => {
                tracing::warn!("cannot start idle scanner: engine not loaded");
                return;
            }
        };

        let scanner = crate::idle_scanner::IdleScanner::start(
            config,
            engine,
            Arc::clone(self),
            Arc::clone(&self.scan_cache),
        );
        *self.idle_scanner.lock().unwrap_or_else(|e| e.into_inner()) = Some(scanner);
    }

    /// Run a lightweight startup critical areas scan.
    ///
    /// Fires AFTER watcher is running — realtime is never delayed.
    /// Scans: Startup folder, Run/RunOnce keys, recent Downloads/Desktop,
    /// Temp executables. 1 worker, BELOW_NORMAL priority, yields under pressure.
    /// Skips files already in scan cache.
    pub fn start_startup_critical_scan(self: &Arc<Self>) {
        let engine = match self.read_engine() {
            Some(e) => e,
            None => {
                tracing::info!("startup critical scan skipped: engine not loaded");
                return;
            }
        };

        let state = Arc::clone(self);
        let cache = Arc::clone(&self.scan_cache);

        if let Err(e) = std::thread::Builder::new()
            .name("startup-critical".into())
            .spawn(move || {
                startup_critical_scan(state, engine, cache);
            })
        {
            tracing::warn!(error = %e, "failed to spawn startup critical scan thread");
        }
    }

    /// Get idle scanner stats for IPC.
    pub fn idle_scanner_stats(&self) -> crate::idle_scanner::IdleScannerStats {
        let guard = self.idle_scanner.lock().unwrap_or_else(|e| e.into_inner());
        match &*guard {
            Some(scanner) => scanner.stats(),
            None => crate::idle_scanner::IdleScannerStats {
                state: crate::idle_scanner::IdleScannerState::Disabled,
                files_scanned_session: 0,
                current_target: String::new(),
                last_pause_reason: String::new(),
                last_completed: None,
            },
        }
    }

    /// Get last scan performance summary as JSON for diagnostics.
    pub fn last_scan_perf_json(&self) -> serde_json::Value {
        let inner = self.lock_inner();
        inner
            .active_scan
            .as_ref()
            .map(|j| serde_json::to_value(&j.perf_summary).unwrap_or_default())
            .unwrap_or(serde_json::Value::Null)
    }

    pub fn update_status(&self) -> UpdateStatus {
        let inner = self.lock_inner();

        let (state, percent, current_file) = if inner.update_running {
            match &inner.update_phase {
                UpdatePhase::Idle => (UpdateState::Idle, None, String::new()),
                UpdatePhase::Checking => (UpdateState::Checking, Some(5.0), String::new()),
                UpdatePhase::Downloading(file) => {
                    (UpdateState::Downloading, Some(30.0), file.clone())
                }
                UpdatePhase::Applying => (UpdateState::Applying, Some(70.0), String::new()),
                UpdatePhase::ReloadingEngine => (
                    UpdateState::Applying,
                    Some(85.0),
                    "Reloading ClamAV engine...".into(),
                ),
                UpdatePhase::ReloadingArgus => (
                    UpdateState::Applying,
                    Some(95.0),
                    "Reloading ARGUS rules...".into(),
                ),
                UpdatePhase::Completed => (UpdateState::Completed, Some(100.0), String::new()),
            }
        } else {
            match &inner.last_update_error {
                // A background failure is deliberately reported as Idle — see
                // `last_update_error_notifiable`. `last_error` below is still
                // populated either way, so the detail stays available for
                // diagnostics without the UI treating it as an alert.
                Some(_) if inner.last_update_error_notifiable => {
                    (UpdateState::Error, None, String::new())
                }
                _ => (UpdateState::Idle, None, String::new()),
            }
        };

        UpdateStatus {
            state,
            percent,
            bytes_downloaded: 0,
            bytes_total: None,
            last_error: inner.last_update_error.clone(),
            current_file: if current_file.is_empty() {
                None
            } else {
                Some(current_file)
            },
        }
    }

    /// Re-read both staleness thresholds from a freshly-saved config.
    ///
    /// Call after every write that can change them. Both are classified as
    /// hot-applied by `restart_requirement()`, so the GUI promises the change
    /// takes effect immediately; without this the daemon kept its boot values
    /// and the promise was false. Clamps mirror `Config::validate` so a config
    /// written by something other than `settings.set_full` cannot install an
    /// out-of-range threshold here.
    pub fn refresh_staleness_thresholds(&self, cfg: &crate::config::Config) {
        self.signature_stale_hours.store(
            cfg.signature_stale_days.clamp(1, 30) as u64 * 24,
            Ordering::Relaxed,
        );
        self.signature_stale_notify_hours.store(
            cfg.signature_stale_notify_days.clamp(3, 365) as u64 * 24,
            Ordering::Relaxed,
        );
    }

    /// Start a signature update in the background.
    /// Returns immediately so the IPC handler is NOT blocked.
    ///
    /// `manual` = the user pressed Update. It controls only whether a FAILURE
    /// is surfaced as `UpdateState::Error`; see `last_update_error_notifiable`.
    pub fn start_update(self: &Arc<Self>, manual: bool) -> serde_json::Value {
        // Record update activity — blocks quiet re-trim.
        self.activity_tracker.record_update();

        // Prevent concurrent updates.
        {
            let mut inner = self.lock_inner();
            if inner.update_running {
                // The user pressed Update while a SCHEDULED run was already in
                // flight. They are now watching that run, so adopt their
                // intent: if it fails they must see why, rather than having
                // their press silently inherit the background run's silence.
                // The window this covers is up to a full cycle wide.
                if manual {
                    inner.last_update_error_notifiable = true;
                }
                return serde_json::json!({"ok": false, "error": "Update already in progress"});
            }
            inner.update_running = true;
            inner.last_update_error = None;
            inner.last_update_error_notifiable = false;
        }

        self.log_activity(
            "info",
            "update",
            "Signature update started",
            "Running freshclam...",
            None,
        );

        // Find freshclam + config BEFORE spawning thread (cheap filesystem lookups).
        let freshclam = crate::updater::find_freshclam();
        let p = crate::paths::paths();
        let primary_conf = p.freshclam_config();
        let config_candidates = [
            primary_conf.clone(),
            std::path::PathBuf::from(r"C:\ProgramData\Sentinella\config\freshclam.conf"),
            std::env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(|d| d.join("config/freshclam.conf")))
                .unwrap_or_default(),
        ];
        let config_path = config_candidates
            .iter()
            .find(|cp| cp.exists())
            .cloned()
            .unwrap_or(primary_conf);

        let fc_path = match freshclam {
            Some(p) if config_path.exists() => p,
            _ => {
                let msg = if freshclam.is_none() {
                    "freshclam binary not found"
                } else {
                    "freshclam.conf not found"
                };
                {
                    let mut inner = self.lock_inner();
                    inner.update_running = false;
                    inner.last_update_error = Some(msg.to_string());
                    // |= not =: a manual press that arrived mid-run adopted
                    // this cycle by setting the flag true. Assigning would
                    // clobber that back to false and re-silence the failure
                    // they are watching.
                    inner.last_update_error_notifiable |= manual;
                }
                // SCOPE IS LOAD-BEARING. `inner` is a std::sync::Mutex guard
                // and std mutexes are NOT reentrant; log_activity takes the
                // same lock. Calling it inside the guard's scope self-
                // deadlocked this thread with the daemon's central lock held
                // forever — every later IPC request would block on it too.
                // Reached whenever freshclam.exe is missing (another AV
                // quarantined it, a partial install), so the daemon hung on
                // the first update attempt rather than reporting the problem.
                self.log_activity("warning", "update", "Update failed", msg, None);
                return serde_json::json!({"ok": false, "error": msg});
            }
        };

        // Spawn the heavy work on a background thread so IPC stays responsive.
        let state = Arc::clone(self);
        let db_dir = crate::paths::paths().signatures_dir();
        std::thread::spawn(move || {
            // RAII guard: `update_running` MUST be cleared even if this thread
            // panics (e.g. inside engine/YARA reload). Without it, one panic
            // left the flag stuck true and the re-entry guard at the top of
            // start_update rejected EVERY future update (scheduled + manual)
            // until a daemon restart — a plausible cause of "auto-update stops
            // working." Drop runs on both normal exit and unwind.
            struct UpdateGuard(Arc<AppState>);
            impl Drop for UpdateGuard {
                fn drop(&mut self) {
                    let mut inner = self.0.lock_inner();
                    inner.update_running = false;
                    inner.update_phase = UpdatePhase::Idle;
                    inner.update_current_file = String::new();
                }
            }
            let _update_guard = UpdateGuard(Arc::clone(&state));

            // Phase 1: Checking for updates.
            {
                let mut inner = state.lock_inner();
                inner.update_phase = UpdatePhase::Checking;
            }

            // Phase 2: Run freshclam with real-time output parsing.
            let (success, message) = crate::updater::run_freshclam_with_retry(
                &fc_path,
                &config_path,
                &db_dir,
                |line| {
                    // Parse freshclam output to detect download phases.
                    // freshclam outputs lines like:
                    //   "Downloading daily-27800.cdiff [100%]"
                    //   "daily.cvd database is up-to-date"
                    //   "main.cvd is up-to-date"
                    let mut inner = state.lock_inner();
                    if line.contains("Downloading") || line.contains("downloading") {
                        // Extract filename from "Downloading XXX [...]"
                        let file_name = line
                            .split_whitespace()
                            .nth(1)
                            .unwrap_or("definitions")
                            .to_string();
                        inner.update_phase = UpdatePhase::Downloading(file_name);
                    } else if line.contains("up-to-date") || line.contains("updated") {
                        inner.update_phase = UpdatePhase::Applying;
                    }
                },
            );

            // Exit code 0 is not the same thing as "signatures were fetched":
            // a CDN cool-down run downloads nothing and still exits 0. Split
            // that case out BEFORE anything stamps freshness — see
            // `freshclam_output_is_cooldown`.
            let cooldown = success && freshclam_output_is_cooldown(&message);

            if success && !cooldown {
                // Phase 3: Reload ClamAV engine.
                {
                    let mut inner = state.lock_inner();
                    inner.last_update_timestamp = Some(chrono::Utc::now().timestamp());
                    inner.update_phase = UpdatePhase::ReloadingEngine;
                }
                let trimmed = message.chars().take(200).collect::<String>();
                state.log_activity(
                    "info",
                    "update",
                    "Signatures updated successfully",
                    &trimmed,
                    None,
                );

                match state.reload_engine() {
                    Ok(_sigs) => { /* reload_engine() already logs activity */ }
                    Err(e) => {
                        state.log_activity(
                            "warning",
                            "update",
                            "Updated but engine reload failed",
                            &e,
                            None,
                        );
                    }
                }

                // Phase 4: Reload ARGUS YARA rules after signature update.
                {
                    let mut inner = state.lock_inner();
                    inner.update_phase = UpdatePhase::ReloadingArgus;
                }
                {
                    let yara_dirs = crate::paths::paths().yara_rule_dirs();
                    match state.argus().yara.load_rules_on_large_stack(&yara_dirs) {
                        Ok(count) => {
                            tracing::info!(count, "ARGUS YARA rules reloaded after update");
                        }
                        Err(e) => {
                            tracing::warn!(%e, "YARA reload failed after update — keeping existing rules");
                        }
                    }
                    // Reload IOC hashes.
                    for ip in &crate::paths::paths().ioc_hash_paths() {
                        if ip.exists() {
                            if let Ok(c) = state.argus().ioc.load_from_file(ip) {
                                tracing::info!(count = c, "IOC hashes reloaded after update");
                                break;
                            }
                        }
                    }
                }

                // Phase 5: Complete.
                {
                    let mut inner = state.lock_inner();
                    inner.update_phase = UpdatePhase::Completed;
                }
            } else if cooldown {
                // Nothing was downloaded, so nothing was reloaded and — the
                // point of this branch — `last_update_timestamp` is left
                // alone, so `runtime_stats` keeps ageing the DB off the real
                // signature file mtimes and the staleness card still fires.
                // The retry-after date is on the LAST warning line, which is
                // exactly what `freshclam_error_detail` surfaces.
                let detail = freshclam_error_detail(&message);
                let mut inner = state.lock_inner();
                inner.last_update_error = Some(detail.clone());
                // Same rule as the failure branch: a background cool-down is
                // not worth interrupting anyone over (there is nothing to do
                // but wait), but a user who just pressed Update must be told
                // why nothing happened instead of seeing a silent no-op.
                inner.last_update_error_notifiable |= manual;
                drop(inner);
                tracing::warn!(
                    detail = detail.as_str(),
                    "signature update skipped — ClamAV CDN cool-down (403/429)"
                );
                state.log_activity(
                    "warning",
                    "update",
                    "Signature update skipped — ClamAV CDN cool-down",
                    &detail,
                    None,
                );
            } else {
                // Surface the ACTIONABLE tail (exit code is already prefixed by
                // run_freshclam; the reason is on the last stderr line) so a
                // tray/scheduled update failure is diagnosable from the UI's
                // activity log instead of blind.
                let detail = freshclam_error_detail(&message);
                let mut inner = state.lock_inner();
                inner.last_update_error = Some(detail.clone());
                // |= not =: a manual press that arrived mid-run adopted this
                // cycle by setting the flag true. Assigning would clobber that
                // back to false and re-silence the failure they are watching.
                inner.last_update_error_notifiable |= manual;
                drop(inner);
                tracing::warn!(detail = detail.as_str(), "signature update failed");
                state.log_activity(
                    "warning",
                    "update",
                    "Signature update failed",
                    &detail,
                    None,
                );
            }

            // Web-protection blocklist refresh rides the SAME update cycle —
            // one update story. Deliberately outside the success/cooldown/
            // failure branches above: a failed freshclam must not skip the
            // list refresh (different host, usually a transient cause), and
            // a list-refresh failure must never mark the signature update
            // failed. It only rewrites files under rules\dns\managed — on
            // any error the previous list stays in force; it cannot disable
            // filtering or touch the proxy/NRPT.
            let report = crate::web_protection::lists::refresh_on_update_cycle();

            // A CHANGED list takes effect NOW, not at the next daemon start:
            // swap the proxy's whole filter engine through the shared
            // Arc<RwLock>. The serving loop takes engine.read() per query and
            // decide() runs before the cache lookup, so the next query already
            // filters with the new rules; the writer only waits out in-flight
            // decisions, never upstream exchanges. The engine is rebuilt from
            // the BOOT config (never a disk re-read) with the canary intact —
            // the invariants and the why live in
            // web_protection::service::apply_refresh_report. A swap can only
            // ever reduce to warn-and-skip per list, i.e. less filtering,
            // never no DNS.
            let wp_handle = state
                .web_protection
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            if let Some(handle) = wp_handle
                && let Some(rules) =
                    crate::web_protection::service::apply_refresh_report(&handle, report)
            {
                tracing::info!(
                    rules_added = rules,
                    "web protection: refreshed blocklist in force — filter engine swapped live, no restart"
                );
            }

            // Mark update as done.
            {
                let mut inner = state.lock_inner();
                inner.update_running = false;
                inner.update_phase = UpdatePhase::Idle;
                inner.update_current_file = String::new();
            }
        });

        serde_json::json!({"ok": true, "status": "running"})
    }

    pub fn activity_list(&self) -> Vec<ActivityRow> {
        // Prefer SQLite for persistence across restarts.
        {
            let db_guard = self.lock_db();
            if let Some(ref db) = *db_guard {
                return db.recent_activity(50);
            }
        }
        // Fallback to in-memory.
        let inner = self.lock_inner();
        inner
            .activity
            .iter()
            .rev()
            .take(50)
            .map(|e| ActivityRow {
                event_id: String::new(),
                timestamp: e.timestamp,
                severity: "info".into(),
                category: e.event_type.clone(),
                title: e.message.clone(),
                message: e.detail.clone().unwrap_or_default(),
                related_scan_id: None,
            })
            .collect()
    }

    pub fn runtime_stats(&self) -> RuntimeStats {
        let inner = self.lock_inner();
        let up = self.started_at.elapsed().as_secs();

        // Use SQLite totals if available (persisted across restarts).
        let (total_scans, total_threats) = {
            let db_guard = self.lock_db();
            if let Some(ref db) = *db_guard {
                (db.total_scans(), db.total_threats())
            } else {
                (
                    inner.scan_history.len() as u64,
                    inner.scan_history.iter().map(|s| s.threats_found).sum(),
                )
            }
        };

        // Compute stale DB status. Base freshness on the most-recent of:
        //   (a) this session's in-memory update timestamp, and
        //   (b) the newest signature FILE mtime (persists across restarts).
        // The old code used only (a), which reset to None on every daemon boot
        // and wrongly reported a freshly-updated DB as "out of date" until an
        // in-session update ran (the "updated DB but still shows out of date"
        // bug). Threshold raised to 3 days so the card only appears when the
        // definitions are genuinely behind, not after every restart.
        let now_ts = chrono::Utc::now().timestamp();
        let effective_ts = [
            inner.last_update_timestamp,
            self.newest_signature_db_mtime_secs(),
        ]
        .into_iter()
        .flatten()
        .max();
        let (db_stale_raw, db_stale_hours) =
            compute_db_stale(
                effective_ts,
                now_ts,
                self.signature_stale_hours.load(Ordering::Relaxed),
            );
        // v0.1.8 bug fix: compute_db_stale returns (true, 0) when
        // effective_ts is None — i.e. no in-RAM `last_update_timestamp`
        // AND no readable signature file mtime. This wrongly fired
        // "Signatures never updated" at boot whenever
        // newest_signature_db_mtime_secs failed to enumerate the .cld/
        // .cvd files (race against freshclam, transient I/O error, etc.)
        // even though the daemon HAD compiled an engine with hundreds of
        // signatures. Truth check: if the engine reports loaded
        // signatures, they can't be "never updated" — defer the stale
        // flag until we have a real timestamp to compare against.
        let sig_count = self.signature_count.load(Ordering::Relaxed);
        let db_stale = if sig_count > 0 && effective_ts.is_none() {
            false
        } else {
            db_stale_raw
        };
        let db_stale_notify = compute_db_stale_notify(
            effective_ts,
            now_ts,
            self.signature_stale_notify_hours.load(Ordering::Relaxed),
        );

        // Watcher status.
        let watcher_active = self.watcher_is_live();

        // Quarantine count from DB.
        let q_count = {
            let db_guard = self.lock_db();
            db_guard
                .as_ref()
                .map(|db| db.quarantine_count())
                .unwrap_or(0)
        };

        let argus_stats = self.argus.stats();

        RuntimeStats {
            uptime_secs: up,
            uptime_human: format_uptime(up),
            scans_completed: total_scans,
            threats_found_total: total_threats,
            ipc_requests_served: self.ipc_total_requests.load(Ordering::Relaxed),
            quarantine_count: q_count,
            activity_count: inner.activity.len() as u64,
            started_at: chrono::Utc::now().timestamp() - up as i64,
            engine_loaded: self.read_engine().is_some(),
            signature_count: self.signature_count.load(Ordering::Relaxed),
            db_stale,
            db_stale_hours,
            db_stale_notify,
            watcher_active,
            last_update_timestamp: inner.last_update_timestamp,
            total_files_scanned: inner.scan_history.iter().map(|s| s.files_scanned).sum(),
            total_detections: {
                let dg = self.lock_db();
                dg.as_ref().map(|d| d.total_detections()).unwrap_or(0)
            },
            argus_version: argus_stats.engine_version,
            argus_files_analyzed: argus_stats.files_analyzed,
            argus_threats_detected: argus_stats.threats_detected,
            argus_active_layers: argus_stats.active_layers,
            argus_avg_analysis_us: argus_stats.avg_analysis_time_us,
            argus_yara_rules: argus_stats.yara_rules_loaded,
            // Unified protection state.
            protection_state: {
                if self.user_disabled_protection.load(Ordering::Relaxed) {
                    "user_disabled".into()
                } else {
                    let engine_ok = self.read_engine().is_some();
                    let argus_ok = argus_stats.active_layers > 0;
                    let yara_ok = argus_stats.yara_rules_loaded > 0;

                    if engine_ok && watcher_active && argus_ok && yara_ok {
                        "fully_protected".into()
                    } else if engine_ok && argus_ok {
                        "degraded".into()
                    } else if engine_ok {
                        "minimal".into()
                    } else {
                        "unprotected".into()
                    }
                }
            },
            protection_detail: {
                let mut issues = Vec::new();
                if self.read_engine().is_none() {
                    issues.push("ClamAV engine unavailable");
                }
                if !watcher_active {
                    issues.push("Real-time watcher inactive");
                }
                if argus_stats.yara_rules_loaded == 0 {
                    issues.push("No YARA rules loaded");
                }
                if issues.is_empty() {
                    None
                } else {
                    Some(issues.join("; "))
                }
            },
            // Scan cache stats.
            cache_hits: {
                let (h, _, _) = self.scan_cache.stats();
                h
            },
            cache_misses: {
                let (_, m, _) = self.scan_cache.stats();
                m
            },
            cache_entries: {
                let (_, _, e) = self.scan_cache.stats();
                e as u64
            },
            // Idle scanner.
            idle_scanner_state: {
                let s = self.idle_scanner_stats();
                format!("{:?}", s.state).to_lowercase()
            },
            idle_scanner_files: self.idle_scanner_stats().files_scanned_session,
            ipc_reconnect_count: self.ipc_reconnect_count.load(Ordering::Relaxed),
            ipc_last_error_ts: self.ipc_last_error_ts.load(Ordering::Relaxed),
            footprint: self.capture_footprint(),
        }
    }

    /// Record a worker panic event.
    pub fn record_worker_panic(&self, reason: &str) {
        self.worker_panics_total.fetch_add(1, Ordering::Relaxed);
        *self
            .last_recovery_reason
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(format!("worker panic: {reason}"));
    }

    /// Record a worker timeout event.
    pub fn record_worker_timeout(&self, reason: &str) {
        self.worker_timeouts_total.fetch_add(1, Ordering::Relaxed);
        *self
            .last_recovery_reason
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(format!("worker timeout: {reason}"));
    }

    /// Is a real-time watcher installed and not torn down?
    ///
    /// `false` covers both "never started / stopped" (empty slot) and
    /// "stop requested or dropped" (`running` cleared). It does NOT prove the
    /// watcher thread is still pumping events — that needs a liveness tick
    /// from the loop itself; see `spawn_watcher_heartbeat_monitor`.
    /// A poisoned lock reads as not-live, which is the fail-loud answer:
    /// `runtime_stats` reports protection as down rather than claiming
    /// coverage it cannot verify.
    fn watcher_is_live(&self) -> bool {
        self.watcher
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|w| w.is_running()))
            .unwrap_or(false)
    }

    /// Update watcher heartbeat.
    pub fn touch_watcher_heartbeat(&self) {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.watcher_last_heartbeat.store(ts, Ordering::Relaxed);
    }

    /// Update orchestrator heartbeat.
    pub fn touch_orchestrator_heartbeat(&self) {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.orchestrator_last_heartbeat
            .store(ts, Ordering::Relaxed);
    }

    // ── Calibration ──────────────────────────────────────

    /// Record a detection event in the calibration log.
    /// Reserved for Phase 3: wiring into detection paths.
    #[allow(dead_code)]
    pub fn calibration_record_detection(&self, event: crate::calibration::DetectionEvent) {
        if let Ok(guard) = self.calibration.lock() {
            if let Some(ref log) = *guard {
                if let Err(e) = log.record_detection(&event) {
                    tracing::debug!(error = %e, "calibration record_detection failed");
                }
            }
        }
    }

    /// Record a restore event (likely FP) in the calibration log.
    pub fn calibration_record_restore(&self, event: crate::calibration::RestoreEvent) {
        if let Ok(guard) = self.calibration.lock() {
            if let Some(ref log) = *guard {
                if let Err(e) = log.record_restore(&event) {
                    tracing::debug!(error = %e, "calibration record_restore failed");
                }
            }
        }
    }

    /// Export calibration bundle for developer review.
    /// Reserved for Phase 3: CLI/IPC export endpoint.
    #[allow(dead_code)]
    pub fn calibration_export(&self) -> Option<crate::calibration::CalibrationBundle> {
        if let Ok(guard) = self.calibration.lock() {
            if let Some(ref log) = *guard {
                return Some(log.export_calibration_bundle());
            }
        }
        None
    }

    /// Get bounded execution diagnostics.
    /// Reserved: will be exposed via diagnostics.export IPC.
    #[allow(dead_code)]
    pub fn budget_diagnostics(&self) -> serde_json::Value {
        serde_json::json!({
            "files_with_timeouts": self.budget_files_with_timeouts.load(Ordering::Relaxed),
            "clamav_timeouts": self.budget_clamav_timeouts.load(Ordering::Relaxed),
            "yara_timeouts": self.budget_yara_timeouts.load(Ordering::Relaxed),
            "total_timeouts": self.budget_total_timeouts.load(Ordering::Relaxed),
            "partial_results": self.budget_partial_results.load(Ordering::Relaxed),
            "budget_exhausted": self.budget_exhausted.load(Ordering::Relaxed),
            "realtime_timeouts": self.budget_realtime_timeouts.load(Ordering::Relaxed),
            "idle_timeouts": self.budget_idle_timeouts.load(Ordering::Relaxed),
            "transient_skips": self.budget_transient_skips.load(Ordering::Relaxed),
        })
    }

    /// Get runtime intelligence diagnostics (PLM + AMSI).
    #[allow(dead_code)]
    pub fn runtime_intelligence_diagnostics(&self) -> serde_json::Value {
        let plm_diag = if let Some(ref plm) = self.plm {
            let mut d = plm.diagnostics.to_json(plm.graph.node_count());
            if let Some(obj) = d.as_object_mut() {
                obj.insert("mode".into(), serde_json::json!(format!("{:?}", plm.mode)));
                #[cfg(target_os = "windows")]
                if let Some(ref etw_d) = plm.etw_diagnostics {
                    obj.insert(
                        "etw_events".into(),
                        serde_json::json!(
                            etw_d.events_seen.load(std::sync::atomic::Ordering::Relaxed)
                        ),
                    );
                    // F-1 fix: etw_running is now CONSERVATIVE — true only
                    // once the consumer is attached (EtwStage::ConsumerOpened
                    // and beyond). StartTraceW success alone no longer reads
                    // as "running". Field name/type unchanged for protocol
                    // compatibility; the richer stage detail rides alongside.
                    obj.insert(
                        "etw_running".into(),
                        serde_json::json!(
                            etw_d.etw_running.load(std::sync::atomic::Ordering::Relaxed)
                        ),
                    );
                    obj.insert(
                        "etw_reconnects".into(),
                        serde_json::json!(
                            etw_d.reconnects.load(std::sync::atomic::Ordering::Relaxed)
                        ),
                    );
                    obj.insert(
                        "etw_stage".into(),
                        serde_json::json!(etw_d.stage_name()),
                    );
                    obj.insert(
                        "etw_failed_win32".into(),
                        serde_json::json!(
                            etw_d.failed_win32.load(std::sync::atomic::Ordering::Relaxed)
                        ),
                    );
                    obj.insert(
                        "etw_degraded_reason".into(),
                        serde_json::json!(
                            etw_d.degraded_reason.load(std::sync::atomic::Ordering::Relaxed)
                        ),
                    );
                    obj.insert(
                        "etw_zero_event_alarm".into(),
                        serde_json::json!(
                            etw_d.zero_event_alarm.load(std::sync::atomic::Ordering::Relaxed)
                        ),
                    );
                }
            }
            d
        } else {
            serde_json::json!({"enabled": false})
        };
        let ps_diag = self.ps_bridge_diagnostics();
        let trust_diag = self
            .trust_graph
            .as_ref()
            .map(|tg| tg.diagnostics())
            .unwrap_or(serde_json::json!({"enabled": false}));
        // WeedHack campaign correlator diagnostics. Hidden block when the
        // PLM monitor isn't running. The UI hides the panel further when
        // `active==0 && recent_findings empty && last_confirmed_unix==0`.
        let weedhack_diag = if let Some(ref plm) = self.plm {
            plm.weedhack_diagnostics_json()
        } else {
            serde_json::json!({
                "active": 0,
                "max_campaigns": 0,
                "expired": 0,
                "confirmed_total": 0,
                "high_confidence_total": 0,
                "suspicious_total": 0,
                "last_confirmed_unix": 0,
                "recent_findings": [],
            })
        };

        let amsi_registered = amsi_provider_registered();
        let amsi_note = if amsi_registered {
            "AMSI provider registered; requests_total counts scans that reached \
             the daemon via the provider path, which attributes a block to us \
             rather than to another registered AMSI provider"
        } else {
            "AMSI provider DLL is built but its CLSID is not enrolled under \
             HKLM AMSI\\Providers on this machine"
        };

        serde_json::json!({
            "plm": plm_diag,
            "powershell": ps_diag,
            "trust_graph": trust_diag,
            "ecosystem": self.ecosystem.diagnostics(),
            "amsi": {
                "enabled": amsi_registered,
                "registered": amsi_registered,
                "clsid": "{53E6920C-21B6-4826-9752-81485B3CBA2A}",
                "requests_total": AMSI_REQUESTS_TOTAL.load(Ordering::Relaxed),
                "blocks_total": AMSI_BLOCKS_TOTAL.load(Ordering::Relaxed),
                "last_seen_unix": AMSI_LAST_SEEN_UNIX.load(Ordering::Relaxed),
                "note": amsi_note,
            },
            "weedhack_campaigns": weedhack_diag,
        })
    }

    /// Get resilience diagnostics.
    pub fn resilience_diagnostics(&self) -> serde_json::Value {
        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let watcher_hb = self.watcher_last_heartbeat.load(Ordering::Relaxed);
        let orch_hb = self.orchestrator_last_heartbeat.load(Ordering::Relaxed);

        // Stale heartbeat detection (>120s without event = stale).
        let watcher_stale = watcher_hb > 0 && (now_ts - watcher_hb) > 120;
        let orch_stale = orch_hb > 0 && (now_ts - orch_hb) > 300;

        serde_json::json!({
            "worker_panics": self.worker_panics_total.load(Ordering::Relaxed),
            "worker_timeouts": self.worker_timeouts_total.load(Ordering::Relaxed),
            "argus_fallbacks": self.argus_worker_fallback_count.load(Ordering::Relaxed),
            "argus_timeouts": self.argus_worker_timeout_count.load(Ordering::Relaxed),
            "last_recovery_reason": self.last_recovery_reason.lock()
                .unwrap_or_else(|e| e.into_inner()).clone(),
            "watcher_heartbeat_ts": watcher_hb,
            "watcher_heartbeat_stale": watcher_stale,
            "orchestrator_heartbeat_ts": orch_hb,
            "orchestrator_heartbeat_stale": orch_stale,
            "watcher_restarts_total": self.watcher_restarts_total.load(Ordering::Relaxed),
            "binary_integrity_drift": self.binary_integrity_drift.load(Ordering::Relaxed),
            "config_drift": self.config_drift.load(Ordering::Relaxed),
        })
    }

    /// Set the binary-integrity drift flag (true = startup detected a hash
    /// mismatch against the TOFU manifest). Fail-loud surface for `health`.
    pub fn set_binary_integrity_drift(&self, drifted: bool) {
        self.binary_integrity_drift.store(drifted, Ordering::Relaxed);
    }

    /// Whether the daemon's binary or a sibling worker drifted from the
    /// stored hash baseline at startup.
    pub fn binary_integrity_drift(&self) -> bool {
        self.binary_integrity_drift.load(Ordering::Relaxed)
    }

    /// Set the config-file drift flag (HMAC sidecar mismatch at load).
    pub fn set_config_drift(&self, drifted: bool) {
        self.config_drift.store(drifted, Ordering::Relaxed);
    }

    /// Whether the on-disk config file was edited outside the daemon.
    pub fn config_drift(&self) -> bool {
        self.config_drift.load(Ordering::Relaxed)
    }

    /// Background watchdog: while realtime protection is supposed to be on,
    /// respawn the watcher whenever it is no longer installed and running.
    /// Uses `protection_toggle_lock` so a concurrent user pause/resume cannot
    /// race the restart. Spawned once from `main.rs` after the watcher starts.
    ///
    /// It deliberately does NOT restart on a stale `watcher_last_heartbeat`.
    /// That heartbeat is touched from the debounce flush, which only runs when
    /// filesystem events were actually queued, so "stale" means "the disk was
    /// quiet", not "the watcher stalled". Restarting on age alone tore down and
    /// rebuilt every `ReadDirectoryChangesW` registration roughly every 80 s on
    /// an idle or locked machine, threw away the watcher's realtime dedup cache
    /// each time, and inflated `watcher_restarts_total` — which `health`
    /// surfaces as a tamper signal — until it meant nothing.
    ///
    /// The residual gap: a watcher thread that panics or wedges leaves
    /// `is_running()` true, so this cannot see it. Closing that needs the
    /// watcher loop to tick the heartbeat once per iteration (it wakes on a
    /// recv timeout regardless of traffic); only then does heartbeat age
    /// become a liveness signal that may be acted on.
    pub fn spawn_watcher_heartbeat_monitor(self: &Arc<Self>) {
        let state = Arc::clone(self);
        // Use a blocking std thread — we touch a std Mutex
        // (`protection_toggle_lock`) and start_watcher() spawns its own
        // internal tasks, so we don't need to live on the tokio runtime.
        std::thread::Builder::new()
            .name("watcher-heartbeat-monitor".into())
            .spawn(move || {
                // Grace period after start so the initial watcher has time to
                // come up before we'd consider it missing.
                std::thread::sleep(std::time::Duration::from_secs(90));
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(20));
                    // Skip restart if user paused protection or realtime is off.
                    if state.is_user_disabled() {
                        continue;
                    }
                    let realtime_on = crate::config::Config::load(None)
                        .map(|c| c.realtime_enabled)
                        .unwrap_or(true);
                    if !realtime_on {
                        continue;
                    }
                    if state.watcher_is_live() {
                        continue;
                    }
                    tracing::warn!(
                        last_heartbeat = state.watcher_last_heartbeat.load(Ordering::Relaxed),
                        "realtime watcher is not running — restarting"
                    );
                    // Serialize against user pause/resume.
                    let _g = state
                        .protection_toggle_lock
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    // Re-check after acquiring the lock — the user may have
                    // just paused, and we MUST honor that.
                    if state.is_user_disabled() {
                        continue;
                    }
                    state.start_watcher();
                    state
                        .watcher_restarts_total
                        .fetch_add(1, Ordering::Relaxed);
                    // Refresh the heartbeat optimistically — start_watcher may
                    // not emit immediately, and `resilience_diagnostics` would
                    // otherwise keep reporting the pre-restart staleness.
                    state.touch_watcher_heartbeat();
                }
            })
            .ok();
    }

    /// Set ClamAV subprocess isolation mode.
    pub fn set_clamav_subprocess(&self, enabled: bool, timeout_sec: u64) {
        self.clamav_subprocess_enabled
            .store(enabled, Ordering::Relaxed);
        self.clamav_worker_timeout_sec
            .store(timeout_sec.max(10), Ordering::Relaxed);
    }

    /// Load FISH config (from daemon config file).
    ///
    /// Updates BOTH halves of the shield's state: the mutation window (which
    /// owns the thresholds) and the cached config (which owns `enabled`,
    /// `observe_only` and `active_response`). Updating only the window left
    /// `fish_diagnostics()` — and therefore the watcher's observe-vs-terminate
    /// decision — reading construction-time defaults forever.
    ///
    /// Re-validates because this is the only choke point that installs a
    /// `FishConfig` into the running daemon, and `active_response` is a
    /// process-kill primitive: a caller that skipped `Config::validate`
    /// must not be able to smuggle an off-allowlist value past it.
    pub fn load_fish_config(&self, mut config: crate::fish::FishConfig) {
        config.validate();
        // Both halves are written under both locks so a reader can never see
        // the new thresholds paired with the previous response mode. Lock
        // order is window-then-config here and in `fish_diagnostics`; taking
        // them in opposite orders in the two methods would deadlock.
        let mut window = self.fish_window.lock().unwrap_or_else(|e| e.into_inner());
        let mut cached = self.fish_config.write().unwrap_or_else(|e| e.into_inner());
        *window = crate::fish::MutationWindow::new(&config);
        *cached = config;
    }

    /// Get FISH diagnostics snapshot.
    pub fn fish_diagnostics(&self) -> crate::fish::FishDiagnostics {
        // Window before config — same order as `load_fish_config`.
        let window = self.fish_window.lock().unwrap_or_else(|e| e.into_inner());
        let config = self.fish_config.read().unwrap_or_else(|e| e.into_inner());
        window.diagnostics(&config)
    }

    /// Re-read the orchestrator routing flags from a freshly-saved config.
    ///
    /// Companion to `refresh_staleness_thresholds`, for the same reason: all
    /// four are classified hot-applied, so nothing else ever pushes them into
    /// the running daemon and `start_scan` kept routing by the boot values.
    fn refresh_scan_routing(&self, cfg: &crate::config::Config) {
        self.orchestrator_file_scan_enabled
            .store(cfg.scan.orchestrator_file_scan_enabled, Ordering::Relaxed);
        self.orchestrator_folder_scan_enabled
            .store(cfg.scan.orchestrator_folder_scan_enabled, Ordering::Relaxed);
        self.orchestrator_quick_scan_enabled
            .store(cfg.scan.orchestrator_quick_scan_enabled, Ordering::Relaxed);
        self.orchestrator_full_scan_enabled
            .store(cfg.scan.orchestrator_full_scan_enabled, Ordering::Relaxed);
    }

    /// Re-read the ClamAV worker timeout from a freshly-saved config.
    ///
    /// NOT hot-applied: `restart_requirement()` classifies
    /// `clamav_worker_timeout_sec` as `DaemonRestart`, so the GUI does show a
    /// restart pill for it. Refreshed anyway because it costs nothing and the
    /// pill is about the isolation MODE it travels with, not the timeout —
    /// picking the new timeout up early is strictly better than making the
    /// user restart for a number the running daemon can just read. Without
    /// this the boot value persisted: the only other writer is
    /// `set_clamav_subprocess`, which `main.rs` calls at boot and only when
    /// isolation is already `subprocess`. The isolation MODE is deliberately not touched
    /// here: it is classified `DaemonRestart`, and swapping the scan path under
    /// a running daemon is what that classification exists to prevent.
    fn refresh_clamav_worker_timeout(&self, cfg: &crate::config::Config) {
        // Same floor as `set_clamav_subprocess`.
        self.clamav_worker_timeout_sec
            .store(cfg.clamav_worker_timeout_sec.max(10), Ordering::Relaxed);
    }

    /// Push every hot-applied setting from a freshly-saved config into the
    /// running daemon.
    ///
    /// `restart_requirement()` returns `None` for these — except
    /// `clamav_worker_timeout_sec`, see that refresher for why it rides along
    /// anyway — which is the GUI's promise that saving is enough. Keeping
    /// that promise requires a single call after every successful config
    /// write, which is why both `settings.set_full` and
    /// `protection.set_critical` call THIS rather than the individual
    /// refreshers: a new hot-applied field then gets wired in one place
    /// instead of at every save site.
    ///
    /// FISH thresholds go through `load_fish_config`, which rebuilds the
    /// mutation window; the in-flight event history is intentionally reset,
    /// since counts collected under the old thresholds no longer mean the
    /// same thing.
    // The `allow` stands only until the call sites land in `ipc/mod.rs`
    // (`settings.set_full` and `protection.set_critical`, both owned by a
    // sibling change); drop it then, so a lost call site becomes a warning
    // rather than a silently un-applied setting.
    pub fn refresh_hot_config(&self, cfg: &crate::config::Config) {
        self.refresh_staleness_thresholds(cfg);
        self.refresh_scan_routing(cfg);
        self.refresh_clamav_worker_timeout(cfg);
        self.load_fish_config(cfg.fish.clone());
    }

    /// Record a FISH process suspension.
    pub fn fish_record_suspension(&self) {
        let mut guard = self.fish_window.lock().unwrap_or_else(|e| e.into_inner());
        guard.record_suspension();
    }

    /// Record a FISH process termination.
    pub fn fish_record_termination(&self) {
        let mut guard = self.fish_window.lock().unwrap_or_else(|e| e.into_inner());
        guard.record_termination();
    }

    /// Record a FISH mutation event and return the decision.
    pub fn fish_record(&self, event: crate::fish::FileMutationEvent) -> crate::fish::FishDecision {
        let mut guard = self.fish_window.lock().unwrap_or_else(|e| e.into_inner());
        guard.record(event)
    }

    /// Re-enable protection after intentional pause.
    /// User intentionally disables protection (pauses watcher).
    pub fn disable_protection(&self) {
        // Critical section: see `protection_toggle_lock` doc.
        let _g = self
            .protection_toggle_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        self.user_disabled_protection.store(true, Ordering::Relaxed);
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.protection_disabled_at.store(ts, Ordering::Relaxed);
        // Stop watcher.
        if let Ok(w) = self.watcher.lock() {
            if let Some(ref watcher) = *w {
                watcher.stop();
            }
        }
        tracing::warn!("protection disabled by user");
    }

    /// Re-enable protection after intentional pause.
    pub fn enable_protection(self: &Arc<Self>) {
        // Critical section: see `protection_toggle_lock` doc.
        let _g = self
            .protection_toggle_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        self.user_disabled_protection
            .store(false, Ordering::Relaxed);
        self.protection_disabled_at.store(0, Ordering::Relaxed);
        // Restart watcher.
        self.start_watcher();
        tracing::info!("protection re-enabled by user");
    }

    /// Whether protection is intentionally paused by user.
    pub fn is_user_disabled(&self) -> bool {
        self.user_disabled_protection.load(Ordering::Relaxed)
    }

    /// Capture current memory footprint snapshot and update pressure state.
    pub fn capture_footprint(&self) -> crate::footprint::FootprintSnapshot {
        let engine_loaded = self.read_engine().is_some();
        let sig_count = self.signature_count.load(Ordering::Relaxed);
        let argus_stats = self.argus.stats();
        let (_, _, cache_entries) = self.scan_cache.stats();

        let snap = crate::footprint::capture(
            engine_loaded,
            sig_count,
            argus_stats.yara_rules_loaded,
            cache_entries as u64,
            self.orchestrator_active_workers(),
            &self.footprint_baselines,
        );
        // Update pressure tracker on every capture.
        self.pressure_tracker
            .update(snap.working_set_mb, &self.performance_config);
        snap
    }

    /// Update memory pressure state from current footprint.
    pub fn update_pressure(&self) -> crate::footprint::pressure::PressureState {
        let snap = self.capture_footprint();
        self.pressure_tracker
            .update(snap.working_set_mb, &self.performance_config)
    }

    /// Get current memory pressure state (lock-free).
    pub fn pressure_state(&self) -> crate::footprint::pressure::PressureState {
        self.pressure_tracker.current()
    }

    /// Get full memory pressure policy for diagnostics.
    pub fn pressure_policy(&self) -> crate::footprint::pressure::PressurePolicy {
        let snap = self.capture_footprint();
        crate::footprint::pressure::PressurePolicy::evaluate(
            snap.working_set_mb,
            &self.performance_config,
        )
    }

    /// Load detection exclusions from config.
    pub fn load_detection_exclusions(&self, exclusions: Vec<String>) {
        *self
            .excluded_detections
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = exclusions;
    }

    /// Load trusted hashes from config.
    pub fn load_trusted_hashes(&self, hashes: Vec<String>) {
        *self
            .trusted_hashes
            .lock()
            .unwrap_or_else(|e| e.into_inner()) =
            hashes.into_iter().map(|h| h.to_lowercase()).collect();
    }

    /// Check if a file hash is in the trusted whitelist.
    pub fn is_hash_trusted(&self, sha256: &str) -> bool {
        let guard = self
            .trusted_hashes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        guard.iter().any(|h| h == &sha256.to_lowercase())
    }

    /// Get current detection exclusions.
    pub fn detection_exclusions(&self) -> Vec<String> {
        self.excluded_detections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Set audit mode.
    pub fn set_audit_mode(&self, enabled: bool) {
        self.audit_mode.store(enabled, Ordering::Relaxed);
    }

    /// Check if running in audit mode.
    pub fn is_audit_mode(&self) -> bool {
        self.audit_mode.load(Ordering::Relaxed)
    }

    /// Daemon operating mode label.
    pub fn daemon_mode(&self) -> &'static str {
        if self.is_user_disabled() {
            "user_disabled"
        } else if self.is_audit_mode() {
            "audit"
        } else {
            "normal"
        }
    }

    /// Whether idle scanner should pause due to memory pressure.
    pub fn should_pause_idle_for_pressure(&self) -> bool {
        self.pressure_tracker.should_pause_idle()
    }

    /// Record startup footprint baseline.
    pub fn record_startup_footprint(&self) {
        let snap = self.capture_footprint();
        self.footprint_baselines.record_startup(snap.working_set_mb);
    }

    /// Record post-scan footprint baseline.
    pub fn record_post_scan_footprint(&self) {
        let snap = self.capture_footprint();
        self.footprint_baselines
            .record_post_scan(snap.working_set_mb);
    }

    /// Auto-scan process memory if a running process matches a high-risk file path.
    /// Called after ARGUS produces a HighRisk/Malicious verdict on a file scan.
    pub fn auto_memory_scan_if_running(&self, file_path: &str, argus_score: u32) {
        // Only trigger for high-confidence detections.
        if argus_score < 76 {
            return;
        }

        let file_lower = file_path.to_lowercase();
        let processes = crate::memory_scanner::list_processes();

        for proc in &processes {
            if let Some(ref path) = proc.path {
                if path.to_lowercase() == file_lower {
                    tracing::warn!(
                        pid = proc.pid,
                        process = proc.name.as_str(),
                        argus_score,
                        "auto memory scan: suspicious process is running"
                    );
                    let result = crate::memory_scanner::scan_process_simple(proc.pid, self.argus());
                    let severity = if result.findings.is_empty() {
                        "info"
                    } else {
                        "warning"
                    };
                    self.log_activity(
                        severity,
                        "memory_scan",
                        &format!("Auto memory scan: {} (PID {})", proc.name, proc.pid),
                        &format!(
                            "{} regions, {} findings, {}ms",
                            result.regions_scanned,
                            result.findings.len(),
                            result.scan_time_ms
                        ),
                        None,
                    );
                    // Only scan first matching process.
                    break;
                }
            }
        }
    }

    /// Count active orchestrator workers.
    fn orchestrator_active_workers(&self) -> u32 {
        let diag = self.orchestrator.diagnostics();
        diag.workers.iter().filter(|w| w.active_jobs > 0).count() as u32
    }
}

// ═══════════════════════════════════════════════════════════════
//  Watcher root helpers (F-9: per-user %LOCALAPPDATA%\Programs)
// ═══════════════════════════════════════════════════════════════

/// Profile directories under `C:\Users` that never hold a real interactive
/// user's data. Same list the idle scanner and the watcher fallback
/// enumeration use — keep in sync.
const SKIP_USER_PROFILES: [&str; 6] = [
    "Default",
    "Default User",
    "Public",
    "All Users",
    "defaultuser0",
    "WDAGUtilityAccount",
];

/// Enumerate `<users_root>\<user>\<subdir>` for every real user profile,
/// skipping well-known non-user profiles and profiles where the subdir does
/// not exist.
///
/// WHY enumerate instead of expanding `%LOCALAPPDATA%`: the daemon runs as
/// LocalSystem in session 0, so the process env points at
/// `C:\Windows\System32\config\systemprofile` — NOT the logged-in user.
/// This is the same profile-enumeration pattern as
/// `idle_scanner::build_scan_targets`.
fn user_profile_subdirs(users_root: &Path, subdir: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(users_root) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let profile = entry.path();
        if !profile.is_dir() {
            continue;
        }
        let name = match profile.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if SKIP_USER_PROFILES.iter().any(|s| s.eq_ignore_ascii_case(name)) {
            continue;
        }
        let candidate = profile.join(subdir);
        // Missing dir is normal (fresh profiles never ran a per-user
        // installer) — skip, don't fail.
        if candidate.is_dir() {
            out.push(candidate);
        }
    }
    out
}

/// Push `candidate` into `roots` iff it is an existing directory that is not
/// already present under a case-insensitive comparison (Windows path
/// semantics). Trailing separators are ignored so `...\Programs` and
/// `...\Programs\` count as the same root. Returns true when pushed.
///
/// The final canonicalize+dedupe pass in `start_watcher` is the authoritative
/// dedupe; this early check keeps the root list small and gives the
/// no-duplicate-watch invariant a directly testable seam.
fn push_unique_existing_root(roots: &mut Vec<PathBuf>, candidate: PathBuf) -> bool {
    if !candidate.is_dir() {
        return false;
    }
    let key = candidate
        .to_string_lossy()
        .trim_end_matches(['\\', '/'])
        .to_lowercase();
    let duplicate = roots.iter().any(|r| {
        r.to_string_lossy()
            .trim_end_matches(['\\', '/'])
            .eq_ignore_ascii_case(&key)
    });
    if duplicate {
        return false;
    }
    roots.push(candidate);
    true
}

// ═══════════════════════════════════════════════════════════════
//  Quick scan background worker
// ═══════════════════════════════════════════════════════════════

fn quick_scan_worker(
    state: Arc<AppState>,
    job_id: Uuid,
    engine: Arc<ClamEngine>,
    cancel: Arc<AtomicBool>,
) {
    let home =
        std::env::var("USERPROFILE").unwrap_or_else(|_| std::env::var("HOME").unwrap_or_default());
    let temp = std::env::var("TEMP").unwrap_or_else(|_| format!("{home}\\AppData\\Local\\Temp"));
    let targets: Vec<PathBuf> = [
        format!("{home}\\Downloads"),
        format!("{home}\\Desktop"),
        temp,
    ]
    .iter()
    .map(PathBuf::from)
    .filter(|p| p.exists())
    .collect();
    folder_scan_worker(state, job_id, engine, cancel, targets, "quick");
}

fn full_scan_worker(
    state: Arc<AppState>,
    job_id: Uuid,
    engine: Arc<ClamEngine>,
    cancel: Arc<AtomicBool>,
) {
    use crate::targeting::{TargetConfig, TargetProvider, dedup, full_disk::FullDiskTargets};
    let config = TargetConfig {
        full_scan_fixed_drives: true,
        full_scan_max_depth: 15,
        ..TargetConfig::default()
    };
    let targets = dedup::deduplicate(FullDiskTargets.collect(&config));
    tracing::info!(job = %job_id, drives = targets.len(), "full disk scan starting");
    folder_scan_worker(state, job_id, engine, cancel, targets, "full");
}

fn startup_scan_worker(
    state: Arc<AppState>,
    job_id: Uuid,
    engine: Arc<ClamEngine>,
    cancel: Arc<AtomicBool>,
) {
    use crate::targeting::{TargetConfig, TargetProvider, dedup, startup::StartupTargets};
    let config = TargetConfig {
        startup_scan_enabled: true,
        startup_recent_days: 7,
        ..TargetConfig::default()
    };
    let mut targets = StartupTargets.collect(&config);
    // Startup scan also includes the quick scan dirs for completeness.
    let home = std::env::var("USERPROFILE").unwrap_or_default();
    let temp = std::env::var("TEMP").unwrap_or_else(|_| format!("{home}\\AppData\\Local\\Temp"));
    for dir in &[
        format!("{home}\\Downloads"),
        format!("{home}\\Desktop"),
        temp,
    ] {
        let p = PathBuf::from(dir);
        if p.exists() {
            targets.push(p);
        }
    }
    let targets = dedup::deduplicate(targets);
    tracing::info!(job = %job_id, targets = targets.len(), "startup scan starting");
    folder_scan_worker(state, job_id, engine, cancel, targets, "startup");
}

/// Lightweight post-boot scan of critical system areas.
///
/// Runs once after daemon startup. Not a user-visible scan — no progress bar,
/// no scan history entry. Just quiet background verification.
///
/// - 1 thread, BELOW_NORMAL priority
/// - Yields if memory pressure is Warning+
/// - Skips files already in scan cache
/// - Scans: Startup folder, Run keys, recent Downloads/Desktop, Temp executables
fn startup_critical_scan(
    state: Arc<AppState>,
    engine: Arc<ClamEngine>,
    cache: Arc<crate::scan::cache::ScanCache>,
) {
    use tracing::{debug, info, warn};

    // Set thread priority to BELOW_NORMAL — never compete with realtime or user scans.
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::System::Threading::{
            GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_BELOW_NORMAL,
        };
        unsafe {
            let _ = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
        }
    }

    // Brief delay — let watcher fully initialize first.
    std::thread::sleep(std::time::Duration::from_secs(5));

    info!("startup critical scan: collecting targets...");

    // Collect high-risk targets.
    use crate::targeting::{TargetConfig, TargetProvider, startup::StartupTargets};
    let config = TargetConfig {
        startup_scan_enabled: true,
        startup_recent_days: 7,
        ..TargetConfig::default()
    };
    let mut targets: Vec<PathBuf> = StartupTargets.collect(&config);

    // Also check Temp for recent executables (last 24h only — tighter than full startup scan).
    let temp = std::env::var("TEMP").unwrap_or_default();
    if !temp.is_empty() {
        let temp_dir = PathBuf::from(&temp);
        let cutoff = std::time::SystemTime::now() - std::time::Duration::from_secs(86400);
        if let Ok(entries) = std::fs::read_dir(&temp_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                if let Some(ext) = path.extension() {
                    let el = ext.to_string_lossy().to_lowercase();
                    if !matches!(
                        el.as_str(),
                        "exe" | "scr" | "bat" | "cmd" | "ps1" | "vbs" | "msi"
                    ) {
                        continue;
                    }
                } else {
                    continue;
                }
                if let Ok(meta) = path.metadata() {
                    if let Ok(mtime) = meta.modified() {
                        if mtime >= cutoff {
                            targets.push(path);
                        }
                    }
                }
            }
        }
    }

    // Dedup.
    targets.sort();
    targets.dedup();

    // Filter out Sentinella's own files and cached-clean files.
    let daemon_config = crate::config::Config::load(None).unwrap_or_default();
    targets.retain(|path| {
        if crate::scan::is_sentinella_path(path) {
            return false;
        }
        if crate::scan::is_excluded(
            path,
            &daemon_config.excluded_paths,
            &daemon_config.excluded_extensions,
        ) {
            return false;
        }
        if let Ok(meta) = path.metadata() {
            if let Some(true) = cache.check_with_metadata(path, &meta) {
                return false;
            }
        }
        true
    });

    if targets.is_empty() {
        info!("startup critical scan: all targets cached clean — nothing to do");
        state.log_activity(
            "info",
            "system",
            "Startup check: all clear",
            "Critical areas verified",
            None,
        );
        return;
    }

    info!(
        files = targets.len(),
        "startup critical scan: scanning critical areas"
    );
    state.log_activity(
        "info",
        "system",
        &format!(
            "Performing startup protection verification... ({} files)",
            targets.len()
        ),
        "Post-boot critical areas check",
        None,
    );

    let mut scanned = 0u64;
    let mut threats = 0u64;
    let no_cancel = AtomicBool::new(false);

    for path in &targets {
        // Yield under memory pressure.
        let pressure = state.update_pressure();
        if matches!(
            pressure,
            crate::footprint::pressure::PressureState::Warning
                | crate::footprint::pressure::PressureState::Critical
        ) {
            debug!("startup critical scan: pausing for memory pressure");
            std::thread::sleep(std::time::Duration::from_secs(10));
            continue; // Skip this file, will catch it on idle scan later.
        }

        // Check file still exists and is readable.
        if !path.exists() || !path.is_file() {
            continue;
        }
        if let Ok(meta) = path.metadata() {
            if meta.len() > 100 * 1024 * 1024 {
                continue;
            } // Skip >100MB.
            if meta.len() == 0 {
                continue;
            }
        }

        // ClamAV signature scan.
        let result = state.scan_file_clamav(&engine, path, &no_cancel);

        // ARGUS heuristic analysis — startup profile budget (fast,
        // persistence-focused) instead of the 60s manual default.
        let argus_verdict = state.argus().analyze_file_with_budget(
            path,
            argus::budget::ScanExecutionBudget::startup(),
        );

        scanned += 1;

        let (is_threat, threat_name_opt) = crate::ipc::unify_detection_filtered(
            result.infected,
            result.virus_name.as_deref(),
            &argus_verdict,
            &state.detection_exclusions(),
        );

        // Never cache an ARGUS analysis-error verdict (read failure /
        // sharing violation) as clean — leave it uncached so the next
        // pass retries.
        if let Ok(meta) = path.metadata() {
            if is_threat || argus_analysis_error(&argus_verdict).is_none() {
                cache.record_with_metadata(path, &meta, !is_threat);
            }
        }

        if is_threat {
            threats += 1;
            let threat_name = threat_name_opt.unwrap_or_default();
            warn!(
                file = %path.display(),
                threat = %threat_name,
                "STARTUP CRITICAL: threat in autorun/recent files"
            );
            // Auto-quarantine startup threats.
            let path_str = path.to_string_lossy().to_string();
            match state.quarantine_file(&path_str, &threat_name, "startup-critical") {
                Ok(q) => info!(id = %q.quarantine_id, "startup threat quarantined"),
                Err(e) => warn!(%e, "startup quarantine failed"),
            }
        }

        // Brief sleep between files — don't spike CPU on boot.
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    let summary = if threats > 0 {
        format!("Startup check: {threats} threat(s) found in {scanned} files")
    } else {
        format!("Startup verification complete: {scanned} critical files clean")
    };
    info!("{summary}");
    state.log_activity(
        if threats > 0 { "warning" } else { "info" },
        "system",
        &summary,
        "Post-boot critical areas verification",
        None,
    );
}

fn folder_scan_worker(
    state: Arc<AppState>,
    job_id: Uuid,
    engine: Arc<ClamEngine>,
    cancel: Arc<AtomicBool>,
    targets: Vec<PathBuf>,
    scan_type_name: &str,
) {
    folder_scan_worker_inner(state, job_id, engine, cancel, targets, scan_type_name, None);
}

/// Inner folder scan worker. Accepts optional pre-existing live state
/// for orchestrated scans (avoids overwriting the queued state).
fn folder_scan_worker_inner(
    state: Arc<AppState>,
    job_id: Uuid,
    engine: Arc<ClamEngine>,
    cancel: Arc<AtomicBool>,
    targets: Vec<PathBuf>,
    scan_type_name: &str,
    existing_live: Option<Arc<ScanLiveState>>,
) {
    let scan_type = scan_type_name.to_string();
    let is_quick = matches!(scan_type_name, "quick" | "startup");
    use tracing::{info, warn};

    info!(job = %job_id, dirs = targets.len(), mode = scan_type_name, "scan worker started");

    // Streaming traversal: a producer thread walks directories and feeds paths
    // into a bounded channel. Workers pull from the channel. This avoids
    // pre-collecting millions of PathBufs into a Vec for full-disk scans.
    let max_depth = if is_quick { 3 } else { 10 };
    let config = crate::config::Config::load(None).unwrap_or_default();
    // Hoisted out of the per-file hot loop: max_file_size() re-reads and
    // re-parses the TOML config on every call (millions of disk reads per
    // full-disk scan) and could flip the size policy mid-scan. Snapshot it
    // once per scan, like the exclusions config above.
    let max_file_size = max_file_size();
    let orchestrated_scan = existing_live.is_some();
    let target_summary = targets
        .iter()
        .map(|path| path.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join(";");

    // Bounded file channel: limits memory to ~4096 PathBufs in flight.
    let (file_tx, file_rx) = std::sync::mpsc::sync_channel::<PathBuf>(4096);
    let file_rx = Arc::new(Mutex::new(file_rx));

    // files_discovered counter — updated by producer, read by live state.
    let files_discovered = Arc::new(AtomicU64::new(0));

    // Create live state immediately (before collection starts).
    let live = if let Some(existing) = existing_live {
        existing.files_total.store(0, Ordering::Relaxed);
        existing.set_status(ScanJobStatus::Running);
        existing
    } else {
        let live = Arc::new(ScanLiveState {
            id: job_id.to_string(),
            kind: scan_type.clone(),
            started_at: chrono::Utc::now().timestamp(),
            files_total: AtomicU64::new(0),
            files_scanned: AtomicU64::new(0),
            threats_found: AtomicU64::new(0),
            cancel_flag: Arc::clone(&cancel),
            status: std::sync::atomic::AtomicU8::new(1),
            current_path: Mutex::new("Scanning...".into()),
        });
        *state.scan_live.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::clone(&live));
        live
    };

    {
        let mut inner = state.lock_inner();
        if let Some(ref mut job) = inner.active_scan {
            // Job-id guard (same pattern as complete_orchestrated_file_*):
            // a cancelled orchestrated closure can run AFTER a successor
            // scan reserved the slot — never install our live state into
            // the successor's job.
            if job.id == job_id {
                job.live = Some(Arc::clone(&live));
            }
        }
    }

    // Producer thread: walks directories, sends paths into bounded channel.
    let producer_cancel = Arc::clone(&cancel);
    let producer_discovered = Arc::clone(&files_discovered);
    let producer_live = Arc::clone(&live);
    let excluded_paths = config.excluded_paths.clone();
    let excluded_extensions = config.excluded_extensions.clone();
    let producer = std::thread::spawn(move || {
        for dir in &targets {
            if producer_cancel.load(Ordering::Relaxed) {
                break;
            }
            collect_files_streaming(
                dir,
                &file_tx,
                max_depth,
                &producer_cancel,
                is_quick,
                &excluded_paths,
                &excluded_extensions,
                &producer_discovered,
                &producer_live,
            );
        }
        // file_tx dropped here → workers see channel closed.
    });

    // ── Multi-threaded scan pipeline ──────────────────────────
    use std::sync::mpsc;

    enum ScanMsg {
        Progress(String),
        Threat(Detection, argus::ArgusVerdict),
        ArgusOnly(argus::ArgusVerdict),
        Error(String),
        Done,
    }

    let (tx, rx) = mpsc::channel::<ScanMsg>();
    let num_threads = scan_threads();

    let mut handles = Vec::new();
    for _ in 0..num_threads {
        let eng = Arc::clone(&engine);
        let state_ref = Arc::clone(&state);
        let cancel_ref = Arc::clone(&cancel);
        let live_w = Arc::clone(&live);
        let tx_ref = tx.clone();
        let file_rx_ref = Arc::clone(&file_rx);
        let scan_type_w = scan_type.clone();

        handles.push(std::thread::spawn(move || {
            loop {
                if cancel_ref.load(Ordering::Relaxed) {
                    break;
                }
                // Pull next file from the streaming channel.
                let file = {
                    let rx = file_rx_ref.lock().unwrap_or_else(|e| e.into_inner());
                    match rx.recv() {
                        Ok(f) => f,
                        Err(_) => break, // Channel closed — producer done.
                    }
                };
                let file = &file;

                let _ = tx_ref.send(ScanMsg::Progress(file.to_string_lossy().to_string()));

                // Check file size.
                let file_meta = match std::fs::metadata(file) {
                    Ok(meta) if meta.len() > max_file_size => {
                        live_w.files_scanned.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    Err(e) => {
                        let _ = tx_ref.send(ScanMsg::Error(format!("{}: {e}", file.display())));
                        live_w.files_scanned.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    Ok(meta) => meta,
                };

                if let Some(true) = state_ref.scan_cache.check_with_metadata(file, &file_meta) {
                    live_w.files_scanned.fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                // ── Per-file profile + budget enforcement ──────
                let scan_profile = argus::profile::ScanProfile::for_context(&scan_type_w);
                let tracker = argus::budget::BudgetTracker::new(scan_profile.budget.clone(), Arc::clone(&cancel_ref));

                // ClamAV scan (with budget check).
                let clamav_start = std::time::Instant::now();
                let result = state_ref.scan_file_clamav(&eng, file, &cancel_ref);
                if tracker.phase_expired(clamav_start, tracker.budget().max_clamav_duration) {
                    tracker.record_timeout(argus::budget::TimeoutReason::ClamAvTimeout);
                }

                // Check total budget before ARGUS.
                if tracker.is_expired() {
                    tracker.record_timeout(argus::budget::TimeoutReason::TotalTimeout);
                    // Partial result: ClamAV ran, ARGUS skipped.
                    live_w.files_scanned.fetch_add(1, Ordering::Relaxed);
                    if result.infected {
                        live_w.threats_found.fetch_add(1, Ordering::Relaxed);
                        let vname = result.virus_name.clone().unwrap_or("Unknown".into());
                        let _ = tx_ref.send(ScanMsg::Threat(
                            Detection { path: file.to_string_lossy().to_string(), virus_name: vname },
                            argus::ArgusVerdict {
                                path: file.to_string_lossy().to_string(),
                                file_size: file_meta.len(),
                                sha256: String::new(),
                                mime_type: None,
                                score: 0,
                                verdict: argus::verdict::Verdict::Clean,
                                findings: vec![],
                                analysis_time_us: 0,
                                engine_version: argus::ENGINE_VERSION,
                                timestamp: chrono::Utc::now().timestamp(),
                                explanation: argus::verdict::VerdictExplanation::default(),
                                timing: None,
                            },
                        ));
                    }
                    // Cache partial result — don't re-scan on next pass.
                    if !result.infected {
                        state_ref.scan_cache.record_with_metadata(file, &file_meta, true);
                    }
                    tracing::debug!(file = %file.display(), timeouts = ?tracker.timeouts(), "budget exhausted, partial result");
                    continue;
                }

                // ARGUS analysis (with budget check).
                let argus_start = std::time::Instant::now();
                let (mut argus_verdict, worker_error) =
                    match state_ref.analyze_argus_file(file, &cancel_ref, &scan_profile.budget) {
                        Ok(result) => result,
                        Err(e) => {
                            let _ = tx_ref.send(ScanMsg::Error(format!("{}: {e}", file.display())));
                            break;
                        }
                    };

                // Sharing-violation / read-failure mislabel fix (audit
                // cross-cutting): an ARGUS analysis-error verdict is NOT a
                // clean result. Surface it as a scan error and keep it OUT
                // of the clean cache so the next scan retries the file.
                // ClamAV positives still flow to the threat path below.
                if !result.infected {
                    if let Some(reason) = argus_analysis_error(&argus_verdict) {
                        let _ =
                            tx_ref.send(ScanMsg::Error(format!("{}: {reason}", file.display())));
                        live_w.files_scanned.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                }

                // Check YARA/structural phase budgets.
                if let Some(ref mut timing) = argus_verdict.timing {
                    let argus_elapsed = argus_start.elapsed();
                    if argus_elapsed >= tracker.budget().max_yara_duration {
                        tracker.record_timeout(argus::budget::TimeoutReason::YaraTimeout);
                    }
                    // Record timeout evidence in verdict.
                    timing.timeout_reasons = tracker.timeouts();
                    timing.completed_within_budget = !tracker.is_expired() && tracker.timeouts().is_empty();
                }

                // Add timeout suspicion to ARGUS score (timeouts = evidence).
                let timeout_weight = tracker.timeout_suspicion();
                if timeout_weight > 0 {
                    argus_verdict.score = argus_verdict.score.saturating_add(timeout_weight).min(100);
                    argus_verdict.verdict = argus::verdict::Verdict::from_score(argus_verdict.score);

                    // Increment diagnostics counters.
                    state_ref.budget_files_with_timeouts.fetch_add(1, Ordering::Relaxed);
                    for t in &tracker.timeouts() {
                        match t {
                            argus::budget::TimeoutReason::ClamAvTimeout => { state_ref.budget_clamav_timeouts.fetch_add(1, Ordering::Relaxed); }
                            argus::budget::TimeoutReason::YaraTimeout => { state_ref.budget_yara_timeouts.fetch_add(1, Ordering::Relaxed); }
                            argus::budget::TimeoutReason::TotalTimeout => { state_ref.budget_total_timeouts.fetch_add(1, Ordering::Relaxed); }
                            _ => {}
                        }
                    }
                    match tracker.outcome() {
                        argus::budget::BudgetOutcome::Partial | argus::budget::BudgetOutcome::Suspicious => {
                            state_ref.budget_partial_results.fetch_add(1, Ordering::Relaxed);
                        }
                        argus::budget::BudgetOutcome::Exhausted => {
                            state_ref.budget_exhausted.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {}
                    }
                }

                // ── ConvergenceLedger: single source of truth for post-ARGUS scoring ──
                // ARCH-1 fix: all post-ARGUS additions go through the ledger.
                // ARCH-2 fix: explanation recomputed from final state.
                let mut ledger = crate::convergence::ConvergenceLedger::new(&argus_verdict, result.infected);

                // ── ADS content scan (ASTRA, profile-aware) ───
                if !tracker.is_expired() {
                    let ads_policy = crate::scan::ads::ads_policy_for_profile(&scan_profile);
                    let streams = crate::scan::ads::enumerate_ads(file);
                    let filtered = crate::scan::ads::filter_streams(streams, ads_policy);
                    for stream in &filtered {
                        if tracker.is_expired() { break; }
                        let ads_result = crate::scan::ads::scan_ads_content(stream, state_ref.argus());
                        for finding in ads_result.content_findings {
                            ledger.add_evidence("ADS", finding);
                        }
                    }
                }

                // ── Persistence intelligence ───────────────
                if let Some(ptype) = crate::persistence::check_persistence_context(file) {
                    let finding = crate::persistence::persistence_finding(ptype, file, false);
                    ledger.add_evidence("Persistence", finding);
                }

                // ── PLM lineage correlation ──────────────
                if let Some(ref plm) = state_ref.plm {
                    if let Some(chain) = plm.query_by_image_path(file) {
                        if let Some(finding) = crate::plm::lineage_finding(&chain) {
                            ledger.add_evidence("PLM", finding);
                        }
                        // WeedHack campaign tracker — opt-in correlation
                        // through ConvergenceLedger; Suspicious is observe-only,
                        // tier dedupe avoids repeat-scan spam.
                        if let Some(leaf) = chain.nodes.last() {
                            for f in plm.observe_chain_for_weedhack(leaf.pid) {
                                ledger.add_evidence("WeedHack", f);
                            }
                        }
                    }
                }

                // ── Trust graph: query discount (H7 fix: observe deferred to clean only) ──
                let mut drift_esc: u32 = 0;
                if let Some(ref tg) = state_ref.trust_graph {
                    let file_key = file.to_string_lossy().to_lowercase();
                    // Query existing trust for discount — do NOT observe yet.
                    let trust_q = tg.query(&file_key);
                    if trust_q.confidence_discount > 0 {
                        let trust_finding = crate::trust_graph::trust_finding(&trust_q);
                        ledger.apply_trust_discount(trust_q.confidence_discount, trust_finding);
                    }
                    for f in &ledger.findings {
                        if f.description.to_lowercase().contains("drift") {
                            drift_esc += f.weight;
                        }
                    }
                }

                // ── Ecosystem convergence ─────────────────
                let mut eco_esc: u32 = 0;
                let mut recurrence_bonus: u32 = 0;
                if ledger.base_score > 0 {
                    let file_key = file.to_string_lossy().to_string();
                    if !ledger.findings.is_empty() {
                        state_ref.ecosystem.add_evidence(&file_key, crate::ecosystem::EcosystemEvidence {
                            source: crate::ecosystem::EvidenceSource::Argus,
                            timestamp: chrono::Utc::now().timestamp(),
                            description: format!("{} findings, score {}", ledger.findings.len(), ledger.base_score),
                            weight: (ledger.base_score / 10).min(10),
                        });
                    }
                    if let Some(eco) = state_ref.ecosystem.get(&file_key) {
                        eco_esc = eco.escalation;
                        recurrence_bonus = eco.recurrence_count.min(4) * 2;
                        if let Some(finding) = crate::ecosystem::ecosystem_finding(&eco) {
                            ledger.add_evidence("Ecosystem", finding);
                        }
                    }
                }

                // ── Finalize convergence: apply caps, recompute explanation ──
                let (final_score, final_verdict, _) = ledger.finalize();
                argus_verdict.score = final_score;
                argus_verdict.verdict = final_verdict;
                argus_verdict.findings = ledger.findings.clone();
                // ARCH-H3 fix: patch explanation to reflect post-ARGUS adjustments.
                ledger.patch_explanation(&mut argus_verdict.explanation, final_score);

                // Store convergence attribution.
                if ledger.base_score > 0 {
                    let file_key = file.to_string_lossy().to_string();
                    state_ref.ecosystem.set_attribution(
                        &file_key,
                        ledger.attribution(final_score, drift_esc, eco_esc, recurrence_bonus),
                    );
                }

                // H7 fix: deferred trust observation — only clean files build familiarity.
                // Signer-aware (audit cross-cutting): feeds the authenticode
                // signer into the observation so signer drift on a previously
                // trusted binary invalidates its trust instead of silently
                // extending it.
                if final_score == 0 && !result.infected {
                    if let Some(ref tg) = state_ref.trust_graph {
                        let file_key = file.to_string_lossy().to_lowercase();
                        let drift = tg.observe_with_signer(
                            &file_key,
                            crate::trust_graph::TrustNodeKind::Executable,
                            argus_verdict.explanation.signer.as_deref(),
                        );
                        if let Some(d) = drift {
                            warn!(file = %file.display(), drift = %d.explanation, "trust-graph signer drift");
                        }
                    }
                }

                live_w.files_scanned.fetch_add(1, Ordering::Relaxed);

                if let Some(e) = worker_error {
                    let _ = tx_ref.send(ScanMsg::Error(format!("{}: {e}", file.display())));
                }

                if let Some(ref err) = result.error {
                    let _ = tx_ref.send(ScanMsg::Error(format!("{}: {err}", file.display())));
                }

                let (is_threat, vname_opt) = unify_detection_filtered(
                    result.infected,
                    result.virus_name.as_deref(),
                    &argus_verdict,
                    &state_ref.detection_exclusions(),
                );
                if !is_threat && result.error.is_none() {
                    state_ref
                        .scan_cache
                        .record_with_metadata(file, &file_meta, true);
                }

                if is_threat {
                    live_w.threats_found.fetch_add(1, Ordering::Relaxed);
                    let vname = vname_opt.unwrap_or("Unknown".into());
                    let _ = tx_ref.send(ScanMsg::Threat(
                        Detection {
                            path: file.to_string_lossy().to_string(),
                            virus_name: vname,
                        },
                        argus_verdict,
                    ));
                } else if !argus_verdict.findings.is_empty() {
                    let _ = tx_ref.send(ScanMsg::ArgusOnly(argus_verdict));
                }
            }
            let _ = tx_ref.send(ScanMsg::Done);
        }));
    }
    drop(tx); // Close sender so rx iterator terminates.

    // Collect results from workers.
    let mut detections: Vec<Detection> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut threads_done = 0usize;

    for msg in rx {
        match msg {
            ScanMsg::Progress(path) => {
                // Update live state atomically — no inner lock needed.
                if let Ok(mut p) = live.current_path.lock() {
                    *p = path;
                }
            }
            ScanMsg::Threat(det, verdict) => {
                warn!(file = %det.path, threat = %det.virus_name, "THREAT DETECTED");
                // Record timing.
                if let Some(ref timing) = verdict.timing {
                    let mut inner = state.lock_inner();
                    if let Some(ref mut job) = inner.active_scan {
                        if job.id == job_id {
                            job.perf_summary
                                .record_file(&det.path, verdict.file_size, timing);
                        }
                    }
                }
                state.persist_argus_verdict(&job_id.to_string(), &verdict);
                detections.push(det);
            }
            ScanMsg::ArgusOnly(verdict) => {
                // Record timing.
                if let Some(ref timing) = verdict.timing {
                    let mut inner = state.lock_inner();
                    if let Some(ref mut job) = inner.active_scan {
                        if job.id == job_id {
                            job.perf_summary
                                .record_file(&verdict.path, verdict.file_size, timing);
                        }
                    }
                }
                state.persist_argus_verdict(&job_id.to_string(), &verdict);
            }
            ScanMsg::Error(e) => {
                errors.push(e);
            }
            ScanMsg::Done => {
                threads_done += 1;
                if threads_done >= num_threads {
                    break;
                }
            }
        }
    }

    // Wait for all threads to finish.
    for h in handles {
        let _ = h.join();
    }
    // Wait for producer to finish.
    let _ = producer.join();

    // Set final file total from producer's count.
    let total_discovered = files_discovered.load(Ordering::Relaxed);
    live.files_total.store(total_discovered, Ordering::Relaxed);
    {
        let mut inner = state.lock_inner();
        if let Some(ref mut job) = inner.active_scan {
            if job.id == job_id {
                job.files_total = total_discovered;
            }
        }
    }

    let scanned = live.files_scanned.load(Ordering::Relaxed);
    let threats = live.threats_found.load(Ordering::Relaxed);
    // Mark live state as completed/cancelled.
    live.set_status(if cancel.load(Ordering::Relaxed) {
        ScanJobStatus::Cancelled
    } else {
        ScanJobStatus::Completed
    });
    if let Ok(mut path) = live.current_path.lock() {
        path.clear();
    }

    // Finalize.
    let finished = chrono::Utc::now().timestamp();
    let cancelled = cancel.load(Ordering::Relaxed);
    let scan_id_str = job_id.to_string();
    let status_str = if cancelled {
        "cancelled"
    } else if threats > 0 {
        "threats"
    } else {
        "clean"
    };

    if orchestrated_scan {
        if cancelled {
            state
                .orchestrated_cancelled_jobs
                .fetch_add(1, Ordering::Relaxed);
        } else {
            match scan_type.as_str() {
                "full" => {
                    state
                        .orchestrated_completed_full
                        .fetch_add(1, Ordering::Relaxed);
                }
                "folder" => {
                    state
                        .orchestrated_completed_folder
                        .fetch_add(1, Ordering::Relaxed);
                }
                "quick" => {
                    state
                        .orchestrated_completed_quick
                        .fetch_add(1, Ordering::Relaxed);
                }
                _ => {}
            }
        }
        *state
            .last_orchestrated_job
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(OrchestratedJobResult {
            id: scan_id_str.clone(),
            path: target_summary,
            verdict: Some(status_str.to_string()),
            status: status_str.to_string(),
            duration_ms: ((finished - live.started_at).max(0) as u64) * 1000,
            error: None,
        });
    }

    // Log performance summary.
    {
        let inner = state.lock_inner();
        if let Some(ref job) = inner.active_scan {
            // Job-id guard: a successor scan may own the slot — its perf
            // summary is not ours to log.
            if job.id == job_id {
            let p = &job.perf_summary;
            info!(
                job = %job_id,
                full = p.strategy_full,
                light = p.strategy_light,
                sig_only = p.strategy_signature,
                skipped = p.strategy_skip,
                too_large = p.strategy_too_large,
                argus_ms = p.total_argus_us / 1000,
                yara_ms = p.total_yara_us / 1000,
                hash_ms = p.total_hash_us / 1000,
                slowest_count = p.slowest_files.len(),
                "scan performance summary",
            );
            if !p.slowest_files.is_empty() {
                for (path, us) in p.slowest_files.iter().take(5) {
                    let short = path.rsplit(['/', '\\']).next().unwrap_or(path);
                    info!(file = short, ms = us / 1000, "slow file");
                }
            }
            }
        }
    }

    // Update in-memory scan job state.
    {
        let mut inner = state.lock_inner();
        // Job-id guard (same pattern as the orchestrated-file completers):
        // a cancelled orchestrated closure can finalize AFTER a successor
        // scan reserved the slot — attribute status/stats/detections only
        // to our own job, never overwrite the successor's.
        let is_current = matches!(inner.active_scan.as_ref(), Some(j) if j.id == job_id);
        let errors_count = errors.len() as u64;
        if is_current {
            if let Some(ref mut job) = inner.active_scan {
                job.status = if cancelled {
                    ScanJobStatus::Cancelled
                } else {
                    ScanJobStatus::Completed
                };
                job.finished_at = Some(finished);
                job.files_scanned = scanned;
                job.threats_found = threats;
                job.detections = detections.clone();
                job.errors = errors;
                job.current_path = String::new();
            }
        }
        let scan_started_at = if is_current {
            inner
                .active_scan
                .as_ref()
                .map(|j| j.started_at)
                .unwrap_or(0)
        } else {
            live.started_at
        };
        inner.scan_history.push(ScanRecord {
            job_id: scan_id_str.clone(),
            scan_type: scan_type.clone(),
            started_at: scan_started_at,
            finished_at: finished,
            files_scanned: scanned,
            threats_found: threats,
            status: status_str.to_string(),
        });

        // Persist scan record to SQLite. The per-job perf aggregates come from
        // `perf_summary`, which `record_file` already populates per scanned file.
        let duration_ms = ((finished - scan_started_at).max(0) as u64) * 1000;
        let (bytes_scanned, clamav_phase_us, argus_phase_us, errors_count) = if is_current {
            inner
                .active_scan
                .as_ref()
                .map(|j| {
                    (
                        j.perf_summary.total_bytes_scanned,
                        j.perf_summary.total_clamav_us,
                        j.perf_summary.total_argus_us,
                        j.errors.len() as u64,
                    )
                })
                .unwrap_or((0, 0, 0, 0))
        } else {
            (0, 0, 0, errors_count)
        };
        state.persist_scan(&ScanRow {
            scan_id: scan_id_str.clone(),
            scan_type: scan_type.clone(),
            status: status_str.to_string(),
            started_at: scan_started_at,
            finished_at: Some(finished),
            files_scanned: scanned,
            threats_found: threats,
            errors_count,
            duration_ms,
            bytes_scanned,
            clamav_phase_us,
            argus_phase_us,
        });
    }

    // Persist detections to SQLite.
    for det in &detections {
        state.persist_detection(&DetectionRow {
            detection_id: Uuid::new_v4().to_string(),
            scan_id: scan_id_str.clone(),
            path: det.path.clone(),
            virus_name: det.virus_name.clone(),
            detected_at: finished,
            action_taken: "none".into(),
        });
    }

    // Activity event.
    let severity = if threats > 0 {
        "critical"
    } else if cancelled {
        "warning"
    } else {
        "info"
    };
    let title = if cancelled {
        format!("Quick scan cancelled — {scanned} files, {threats} threats")
    } else {
        format!("Quick scan complete — {scanned} files, {threats} threats")
    };
    let detail = if !detections.is_empty() {
        detections
            .iter()
            .map(|d| d.virus_name.clone())
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        String::new()
    };
    state.log_activity(severity, "scan", &title, &detail, Some(&scan_id_str));

    // Record post-scan footprint baseline + orchestrator heartbeat.
    state.record_post_scan_footprint();
    state.touch_orchestrator_heartbeat();
    let post_snap = state.capture_footprint();
    crate::footprint::log_footprint("post-scan", &post_snap);

    info!(job = %job_id, scanned, threats, cancelled, "quick scan worker finished");
}

/// Recursively collect files from a directory, respecting depth limit.
#[allow(dead_code)]
fn collect_files(
    dir: &Path,
    out: &mut Vec<PathBuf>,
    max_depth: u32,
    cancel: &AtomicBool,
    quick_mode: bool,
    excluded_paths: &[String],
    excluded_extensions: &[String],
) {
    if max_depth == 0 || cancel.load(Ordering::Relaxed) {
        return;
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();

        // Skip reparse points (symlinks AND NTFS junctions) to avoid loops
        // and scope-creep into unintended trees.
        if crate::scan::is_reparse_point(&path) {
            continue;
        }
        if crate::scan::is_excluded(&path, excluded_paths, excluded_extensions) {
            continue;
        }

        if path.is_dir() {
            if crate::scan::should_skip_dir(&path, quick_mode) {
                continue;
            }
            if crate::scan::is_sentinella_path(&path) {
                continue;
            }
            collect_files(
                &path,
                out,
                max_depth - 1,
                cancel,
                quick_mode,
                excluded_paths,
                excluded_extensions,
            );
        } else if path.is_file() {
            if crate::scan::should_skip_file(&path) {
                continue;
            }
            if crate::scan::is_sentinella_path(&path) {
                continue;
            }
            out.push(path);
        }
    }
}

/// Streaming variant of collect_files: sends paths into a bounded channel
/// instead of accumulating in a Vec. This keeps memory bounded for full-disk scans.
fn collect_files_streaming(
    dir: &Path,
    tx: &std::sync::mpsc::SyncSender<PathBuf>,
    max_depth: u32,
    cancel: &AtomicBool,
    quick_mode: bool,
    excluded_paths: &[String],
    excluded_extensions: &[String],
    discovered: &AtomicU64,
    live: &ScanLiveState,
) {
    if max_depth == 0 || cancel.load(Ordering::Relaxed) {
        return;
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();

        // Skip reparse points (symlinks AND NTFS junctions).
        if crate::scan::is_reparse_point(&path) {
            continue;
        }
        if crate::scan::is_excluded(&path, excluded_paths, excluded_extensions) {
            continue;
        }

        if path.is_dir() {
            if crate::scan::should_skip_dir(&path, quick_mode) {
                continue;
            }
            if crate::scan::is_sentinella_path(&path) {
                continue;
            }
            collect_files_streaming(
                &path,
                tx,
                max_depth - 1,
                cancel,
                quick_mode,
                excluded_paths,
                excluded_extensions,
                discovered,
                live,
            );
        } else if path.is_file() {
            if crate::scan::should_skip_file(&path) {
                continue;
            }
            if crate::scan::is_sentinella_path(&path) {
                continue;
            }
            let count = discovered.fetch_add(1, Ordering::Relaxed) + 1;
            // Update live total periodically (every 1000 files) to show progress.
            if count % 1000 == 0 {
                live.files_total.store(count, Ordering::Relaxed);
            }
            loop {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                match tx.try_send(path.clone()) {
                    Ok(()) => break,
                    Err(std::sync::mpsc::TrySendError::Full(_)) => {
                        std::thread::sleep(std::time::Duration::from_millis(25));
                    }
                    Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                        return; // Workers gone — stop traversal.
                    }
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Response types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize)]
pub struct ScanStartResponse {
    pub job_id: String,
    pub status: String,
    pub result: Option<ScanResultResponse>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanResultResponse {
    pub path: String,
    pub infected: bool,
    pub virus_name: Option<String>,
    pub scanned_bytes: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanStatusResponse {
    pub running: bool,
    pub job_id: Option<String>,
    pub state: &'static str,
    pub scan_type: Option<String>,
    pub files_scanned: u64,
    pub files_total: u64,
    pub progress_percent: f32,
    pub threats_found: u64,
    pub current_path: Option<String>,
    pub scans_completed: u64,
    pub detections: Vec<Detection>,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
    pub errors_count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanRecord {
    pub job_id: String,
    pub scan_type: String,
    pub started_at: i64,
    pub finished_at: i64,
    pub files_scanned: u64,
    pub threats_found: u64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActivityEntry {
    pub event_type: String,
    pub message: String,
    pub detail: Option<String>,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct OrchestratedScanJob {
    pub id: String,
    pub queue_kind: crate::orchestrator::QueueKind,
    pub path: String,
    pub requested_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct OrchestratedJobResult {
    pub id: String,
    pub path: String,
    pub verdict: Option<String>,
    pub status: String,
    pub duration_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeStats {
    pub uptime_secs: u64,
    pub uptime_human: String,
    pub scans_completed: u64,
    pub threats_found_total: u64,
    pub ipc_requests_served: u64,
    pub quarantine_count: u64,
    pub activity_count: u64,
    pub started_at: i64,
    pub engine_loaded: bool,
    pub signature_count: u64,
    pub db_stale: bool,
    pub db_stale_hours: u64,
    /// Signatures are old enough that it is worth interrupting the user
    /// (config.signature_stale_notify_days, default 14). This — not a failed
    /// update attempt — is what drives the user-facing update notification.
    #[serde(default)]
    pub db_stale_notify: bool,
    pub watcher_active: bool,
    pub last_update_timestamp: Option<i64>,
    pub total_files_scanned: u64,
    pub total_detections: u64,
    // ARGUS heuristics engine stats.
    pub argus_version: &'static str,
    pub argus_files_analyzed: u64,
    pub argus_threats_detected: u64,
    pub argus_active_layers: u32,
    pub argus_avg_analysis_us: u64,
    pub argus_yara_rules: u64,
    /// Unified protection state derived from all subsystems.
    pub protection_state: String,
    /// Detail about any degraded subsystem.
    pub protection_detail: Option<String>,
    // ── Scan cache stats ────────────────────────────────
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_entries: u64,
    // ── Idle scanner ────────────────────────────────────
    pub idle_scanner_state: String,
    pub idle_scanner_files: u64,
    // ── IPC health ─────────────────────────────────────
    pub ipc_reconnect_count: u64,
    pub ipc_last_error_ts: u64,
    // ── Memory footprint ───────────────────────────────
    pub footprint: crate::footprint::FootprintSnapshot,
}

fn format_uptime(secs: u64) -> String {
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m {s}s")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

/// Returns the error reason if this ARGUS verdict is an analysis-ERROR
/// placeholder (read failure, sharing violation, vanished file) rather
/// than a real verdict. The engine signals that path with a weight-0 Info
/// finding whose description starts with "Analysis incomplete:" (see
/// `ArgusEngine::error_verdict`) while still stamping `Verdict::Clean` on
/// the envelope — so daemon scan paths MUST check this before treating a
/// "clean" ARGUS result as cacheable-clean. Returns None for real verdicts.
pub fn argus_analysis_error(v: &argus::ArgusVerdict) -> Option<&str> {
    v.findings
        .iter()
        .find_map(|f| f.description.strip_prefix("Analysis incomplete: "))
}

/// Canonical key for the restore-suppression map (Quarantine F4).
///
/// Canonicalize the PARENT directory and re-join the file name — NOT the
/// full path. The full-path canonicalize is racy for restore_as: the dest
/// doesn't exist yet when mark_restore_in_progress runs before the write
/// (canonicalize fails → raw-path fallback), but DOES exist when the
/// watcher's CREATE event fires (canonicalize succeeds) → different map
/// keys → suppression miss → restore → re-quarantine loop. The parent
/// exists on both sides, so both derive the same key; the fallback
/// (unresolvable parent → raw parent) is likewise identical by construction
/// because mark / unmark / is_restore_suppressed all route through here.
fn restore_suppress_key(path: &Path) -> PathBuf {
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) if !parent.as_os_str().is_empty() => parent
            .canonicalize()
            .unwrap_or_else(|_| parent.to_path_buf())
            .join(name),
        _ => path.canonicalize().unwrap_or_else(|_| path.to_path_buf()),
    }
}

/// Unified detection logic — merges ClamAV signature + ARGUS heuristic
/// into a single coherent verdict. Never creates duplicate detections.
///
/// Returns `(is_threat, unified_name)`.
/// Unified detection with detection-name exclusion support.
/// ARGUS score required to auto-quarantine with NO ClamAV agreement.
///
/// Deliberately above `Verdict::from_score`'s "Malicious" line (76): a
/// structurally odd installer routinely lands in 76-84, and quarantining it
/// on ARGUS alone is the false positive that makes people uninstall an
/// antivirus. That band is recorded as a forensic verdict and left alone.
///
/// PUBLIC, and a constant rather than a literal, because it was a literal
/// in two places that then disagreed: the watcher's post-sandbox escalation
/// used 76 while claiming in a comment to match this function, so every
/// detonation landing in 76-84 quarantined a file this rule exists to spare.
pub const ARGUS_ONLY_QUARANTINE_SCORE: u32 = 85;

pub fn unify_detection_filtered(
    clamav_infected: bool,
    clamav_name: Option<&str>,
    argus: &argus::ArgusVerdict,
    excluded_detections: &[String],
) -> (bool, Option<String>) {
    // ClamAV signature match → always threat.
    // ARGUS-only → require higher confidence for auto-quarantine.
    // Score 76-84 ARGUS-only = labeled Malicious by the engine
    // (Verdict::from_score) but NOT a detection here: no detection row,
    // no quarantine, scan reported clean — only the raw ARGUS verdict is
    // persisted as a forensic record (persist_argus_verdict).
    // Score 85+ ARGUS-only = high confidence → auto-quarantine.
    // This prevents "Suspicious.Generic [78/100]" from quarantining
    // legitimate installers that happen to look structurally suspicious.
    let argus_threat = if clamav_infected {
        argus.is_threat() // When ClamAV agrees, normal threshold (76+)
    } else {
        argus.score >= ARGUS_ONLY_QUARANTINE_SCORE // higher confidence needed
    };
    let is_threat = clamav_infected || argus_threat;

    if !is_threat {
        return (false, None);
    }

    let name = if clamav_infected {
        // ClamAV is authoritative — use its specific name.
        let base = clamav_name.unwrap_or("Malware.Generic");
        if argus.score > 50 {
            // Both engines agree — note ARGUS confidence.
            format!("{base} [ARGUS: {}/100]", argus.score)
        } else {
            base.to_string()
        }
    } else {
        // ARGUS-only detection — build a descriptive name.
        let top_finding = argus
            .findings
            .first()
            .map(|f| f.layer)
            .unwrap_or(argus::verdict::Layer::PatternDetection);

        let category = match top_finding {
            argus::verdict::Layer::PatternDetection => {
                // Try to be more specific based on finding descriptions.
                let desc = argus
                    .findings
                    .first()
                    .map(|f| f.description.as_str())
                    .unwrap_or("");
                if desc.contains("Discord") || desc.contains("token") {
                    "Stealer.Discord"
                } else if desc.contains("credential") || desc.contains("browser") {
                    "Stealer.Credentials"
                } else if desc.contains("webhook") || desc.contains("exfiltrat") {
                    "Stealer.Exfiltration"
                } else if desc.contains("crypto") || desc.contains("mining") {
                    "Miner.CryptoJack"
                } else if desc.contains("persistence") {
                    "Persistence.Suspicious"
                } else {
                    "Suspicious.Behavior"
                }
            }
            argus::verdict::Layer::PackerDetection => "Packed.Suspicious",
            argus::verdict::Layer::ScriptAnalysis => "Script.Malicious",
            argus::verdict::Layer::FileDeception => "Deception.Disguised",
            argus::verdict::Layer::MimeValidation => "Deception.FakeExtension",
            argus::verdict::Layer::IocCorrelation => "IOC.KnownMalicious",
            argus::verdict::Layer::StructuralAnalysis => "Suspicious.Structure",
            _ => "Suspicious.Generic",
        };

        format!("ARGUS/{category} [{}/100]", argus.score)
    };

    // Check detection-name exclusions.
    if !excluded_detections.is_empty() {
        let name_lower = name.to_lowercase();
        for excl in excluded_detections {
            if name_lower.contains(&excl.to_lowercase()) {
                tracing::info!(
                    detection = name.as_str(),
                    exclusion = excl.as_str(),
                    "detection excluded by user rule"
                );
                return (false, None);
            }
        }
    }

    (true, Some(name))
}

// ── Unit tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use argus::verdict::{ArgusVerdict, Finding, Layer, Severity, Verdict, VerdictExplanation};

    // ── scan.start overlap TOCTOU regression ─────────────────────
    //
    // The IPC server spawns one task per pipe connection, so two scan.start
    // requests run in parallel. `try_reserve_scan` must perform the overlap
    // check AND the active_scan reservation in a single critical section, so a
    // second concurrent caller cannot also pass the check and orphan the first
    // job. This test exercises the serialization contract directly.
    fn empty_inner() -> Inner {
        Inner {
            active_scan: None,
            scan_history: Vec::new(),
            activity: Vec::new(),
            // Adversary A2: challenge_token shape is now
            // (token, method_scope, created_at).
            challenge_token: None,
            update_running: false,
            update_phase: UpdatePhase::default(),
            update_current_file: String::new(),
            last_update_timestamp: None,
            last_update_error: None,
            last_update_error_notifiable: false,
        }
    }

    fn mk_job(kind: &str) -> ScanJob {
        ScanJob {
            id: Uuid::new_v4(),
            kind: kind.into(),
            status: ScanJobStatus::Pending,
            started_at: 0,
            finished_at: None,
            files_scanned: 0,
            files_total: 0,
            threats_found: 0,
            current_path: String::new(),
            detections: Vec::new(),
            errors: Vec::new(),
            cancel_flag: Arc::new(AtomicBool::new(false)),
            perf_summary: ScanPerformanceSummary::default(),
            live: None,
        }
    }

    #[test]
    fn notify_threshold_is_far_later_than_the_ui_threshold() {
        let now = 1_700_000_000_i64;
        let day = 24 * 3600_i64;
        let ui = 3 * 24_u64;      // signature_stale_days default
        let notify = 14 * 24_u64; // signature_stale_notify_days default

        // Four days old: the UI tints its card, but nothing interrupts the
        // user. This is the whole point of the split — a few days behind is
        // worth showing to someone already looking, not worth a toast.
        let ts = Some(now - 4 * day);
        assert!(compute_db_stale(ts, now, ui).0);
        assert!(!compute_db_stale(ts, now, notify).0);

        // Fifteen days: now it is worth saying out loud.
        let ts = Some(now - 15 * day);
        assert!(compute_db_stale(ts, now, notify).0);

        // Exactly at the threshold is NOT past it (strict >), so the toast
        // fires a day after the age is reached, never a day early.
        let ts = Some(now - 14 * day);
        assert!(!compute_db_stale(ts, now, notify).0);
    }

    #[test]
    fn no_timestamp_never_fires_the_notification() {
        let now = 1_700_000_000_i64;
        let notify = 14 * 24_u64;

        // The trap this guards: compute_db_stale reports (true, 0) with no
        // timestamp, meaning "unknown age", not "old".
        assert!(compute_db_stale(None, now, notify).0);
        // ...but the notification decision must NOT inherit that true.
        // Asserting through compute_db_stale_notify (the function
        // runtime_stats actually calls) means deleting the guard fails this
        // test. An earlier version re-implemented the guard with local
        // literals and would have stayed green through exactly that deletion.
        assert!(!compute_db_stale_notify(None, now, notify));

        // And with a real timestamp it still answers the age question.
        let day = 24 * 3600_i64;
        assert!(!compute_db_stale_notify(Some(now - 4 * day), now, notify));
        assert!(compute_db_stale_notify(Some(now - 15 * day), now, notify));
    }

    #[test]
    fn db_stale_uses_3_day_threshold_and_handles_restart() {
        let now = 1_700_000_000_i64;
        let hour = 3600;
        let day = 24 * hour;
        // Freshly updated → not stale.
        assert_eq!(compute_db_stale(Some(now), now, 72), (false, 0));
        // 2 days old → still fresh (the restart-after-yesterday's-update case
        // that previously falsely showed "out of date").
        assert_eq!(compute_db_stale(Some(now - 2 * day), now, 72).0, false);
        // 4 days old → stale.
        assert_eq!(compute_db_stale(Some(now - 4 * day), now, 72).0, true);
        // Exactly 3 days (72h) → boundary, not yet stale (> threshold).
        assert_eq!(compute_db_stale(Some(now - 3 * day), now, 72), (false, 72));
        // No signatures at all → stale.
        assert_eq!(compute_db_stale(None, now, 72), (true, 0));
        // Clock skew (future ts) → clamped to 0, not stale.
        assert_eq!(compute_db_stale(Some(now + day), now, 72), (false, 0));
    }

    #[test]
    fn freshclam_error_detail_surfaces_tail_not_banner() {
        // Real freshclam failure: banner first, actionable reason last.
        let out = "Exit code 56: ClamAV update process started\n\
                   Current working dir is /tmp\n\
                   \n\
                   ERROR: Can't query current.cvd.clamav.net\n\
                   ERROR: Can't read DNS, mirror unreachable";
        let d = freshclam_error_detail(out);
        assert!(d.contains("mirror unreachable"), "must surface the last error: {d}");
        assert!(!d.contains("update process started"), "should drop the banner head");

        // No output → explicit fallback, not empty.
        assert_eq!(freshclam_error_detail(""), "freshclam failed (no output)");
        assert_eq!(freshclam_error_detail("   \n\n"), "freshclam failed (no output)");
    }

    #[test]
    fn freshclam_cooldown_is_not_a_successful_update() {
        // libfreshclam's cool-down branch in `fc_update_databases`: it prints
        // this, downloads nothing, sets FC_SUCCESS and exits 0.
        let still = "ClamAV update process started at Sat Aug  2 09:00:00 2026\n\
                     FreshClam previously received error code 429 or 403 from the ClamAV \
                     Content Delivery Network (CDN).\n\
                     This means that you have been rate limited or blocked by the CDN.\n\
                     You are still on cool-down until after: 2026-08-02 17:41:03";
        assert!(
            freshclam_output_is_cooldown(still),
            "a run that never left the cool-down branch must not stamp freshness"
        );

        // The in-run 429 path (`FC_ERETRYLATER` → `goto success`) prints the
        // same line without "still" and also exits 0.
        let hit_now = "FreshClam received error code 429 from the ClamAV Content Delivery \
                       Network (CDN).\n\
                       You are on cool-down until after: 2026-08-02 17:41:03";
        assert!(freshclam_output_is_cooldown(hit_now));

        // A run that found the cool-down EXPIRED goes on to update for real.
        // Matching the bare word "cool-down" would suppress the freshness
        // stamp on every recovery run — permanently stale, the inverse bug.
        let expired = "Cool-down expired, ok to try again.\n\
                       daily.cvd database is up-to-date (version: 27800, sigs: 2074109)";
        assert!(!freshclam_output_is_cooldown(expired));

        // And an ordinary run stays a success.
        let ok = "ClamAV update process started at Sat Aug  2 09:00:00 2026\n\
                  daily.cvd updated (version: 27801, sigs: 2074200)\n\
                  main.cvd database is up-to-date";
        assert!(!freshclam_output_is_cooldown(ok));

        // The detail the activity log shows must carry the retry-after date —
        // the one actionable fact in the whole banner. The old success path
        // logged the FIRST 200 chars, i.e. the banner, and never this.
        let detail = freshclam_error_detail(still);
        assert!(
            detail.contains("2026-08-02 17:41:03"),
            "cool-down detail must surface the retry-after date: {detail}"
        );
    }

    /// Every field `restart_requirement()` calls hot-applied has to actually
    /// reach the running daemon; otherwise the GUI's missing restart pill is
    /// a promise the daemon does not keep. Boot values are whatever this
    /// machine's `sentinelld.toml` says, so the test FLIPS each one and
    /// asserts the flip is observable through the same surfaces the daemon
    /// itself reads.
    #[test]
    fn hot_config_refresh_reaches_scan_routing_and_the_fish_shield() {
        crate::paths::init_auto();
        let state = AppState::new(None, None, None);

        let before = state.orchestrator_diagnostics();
        let flip = |v: &serde_json::Value| !v.as_bool().unwrap_or(false);
        let fish_before = state.fish_diagnostics();

        let mut cfg = crate::config::Config::default();
        cfg.scan.orchestrator_file_scan_enabled = flip(&before["enabled_file_scan"]);
        cfg.scan.orchestrator_folder_scan_enabled = flip(&before["enabled_folder_scan"]);
        cfg.scan.orchestrator_quick_scan_enabled = flip(&before["enabled_quick_scan"]);
        cfg.scan.orchestrator_full_scan_enabled = flip(&before["enabled_full_scan"]);
        cfg.fish.observe_only = !fish_before.observe_only;
        cfg.fish.active_response = if fish_before.active_response == "terminate" {
            "suspend".to_string()
        } else {
            "terminate".to_string()
        };

        state.refresh_hot_config(&cfg);

        // `start_scan` routes off these four; `orchestrator_diagnostics` is
        // the surface that reports them back to the GUI. As plain fields both
        // kept the boot values, so the diagnostics agreed with the wrong
        // behaviour instead of exposing it.
        let after = state.orchestrator_diagnostics();
        for key in [
            "enabled_file_scan",
            "enabled_folder_scan",
            "enabled_quick_scan",
            "enabled_full_scan",
        ] {
            assert_eq!(
                after[key].as_bool(),
                Some(cfg_flag(&cfg, key)),
                "{key} must follow the saved config, no restart required"
            );
            assert_ne!(after[key], before[key], "{key} did not change at all");
        }

        // FISH: `fish_handle_burst` chooses observe vs suspend/terminate from
        // exactly this snapshot. Frozen at the defaults it always read
        // observe_only=true, which made active response unreachable code.
        let fish_after = state.fish_diagnostics();
        assert_eq!(fish_after.observe_only, cfg.fish.observe_only);
        assert_eq!(fish_after.active_response, cfg.fish.active_response);

        // Same shape, same promise: the ClamAV worker budget was only ever
        // written at boot, and only when isolation was already subprocess.
        let mut cfg2 = crate::config::Config::default();
        cfg2.clamav_worker_timeout_sec = 47;
        state.refresh_hot_config(&cfg2);
        assert_eq!(
            state.clamav_worker_timeout_sec.load(Ordering::Relaxed),
            47,
            "a saved worker timeout must reach the running daemon"
        );
        // ...but never below the floor `set_clamav_subprocess` enforces.
        cfg2.clamav_worker_timeout_sec = 1;
        state.refresh_hot_config(&cfg2);
        assert_eq!(state.clamav_worker_timeout_sec.load(Ordering::Relaxed), 10);
    }

    /// Helper for the loop above — maps a diagnostics key back to the config
    /// field it is supposed to mirror.
    fn cfg_flag(cfg: &crate::config::Config, key: &str) -> bool {
        match key {
            "enabled_file_scan" => cfg.scan.orchestrator_file_scan_enabled,
            "enabled_folder_scan" => cfg.scan.orchestrator_folder_scan_enabled,
            "enabled_quick_scan" => cfg.scan.orchestrator_quick_scan_enabled,
            "enabled_full_scan" => cfg.scan.orchestrator_full_scan_enabled,
            other => panic!("unmapped orchestrator diagnostics key: {other}"),
        }
    }

    /// `active_response` is a process-kill primitive, so the choke point that
    /// installs a `FishConfig` into the live daemon must re-validate rather
    /// than trust its caller.
    #[test]
    fn load_fish_config_rejects_an_off_allowlist_active_response() {
        crate::paths::init_auto();
        let state = AppState::new(None, None, None);

        state.load_fish_config(crate::fish::FishConfig {
            observe_only: false,
            active_response: "reboot".into(),
            ..crate::fish::FishConfig::default()
        });

        assert_eq!(
            state.fish_diagnostics().active_response,
            "observe",
            "an unknown response mode must fall back to the safest one"
        );
    }

    #[test]
    fn scan_threads_in_sane_range() {
        // Core-relative pool: ~half logical CPUs, clamped [2,8] on any hardware.
        let n = scan_threads();
        assert!((2..=8).contains(&n), "scan threads {n} must be in [2,8]");
    }

    #[test]
    fn reserve_active_scan_serializes_and_recovers_on_terminal_state() {
        let mut inner = empty_inner();

        // 1. First reservation succeeds and installs active_scan.
        let first = mk_job("file");
        let first_id = first.id;
        assert!(
            reserve_active_scan(&mut inner, first).is_ok(),
            "first reserve must succeed"
        );

        // 2. A second reservation while the first is Pending is rejected, and
        //    the rejection references the IN-FLIGHT job — not the newcomer.
        //    (This is the TOCTOU guarantee: the check + the reservation are one
        //    critical section, so the second caller can never also install.)
        let reject = reserve_active_scan(&mut inner, mk_job("quick"))
            .expect_err("second reserve must be rejected while a scan is in flight");
        assert_eq!(reject.status, "error");
        assert_eq!(
            reject.job_id,
            first_id.to_string(),
            "rejection must name the in-flight job"
        );
        assert!(reject.error.unwrap_or_default().contains("already"));
        // active_scan must still be the first job (not overwritten).
        assert_eq!(
            inner.active_scan.as_ref().map(|j| j.id),
            Some(first_id),
            "rejected reserve must NOT overwrite the in-flight job"
        );

        // 3. After the in-flight job reaches each terminal state (as the
        //    completion handlers set it), a fresh reservation succeeds again.
        for terminal in [
            ScanJobStatus::Completed,
            ScanJobStatus::Cancelled,
            ScanJobStatus::Failed,
        ] {
            inner
                .active_scan
                .as_mut()
                .expect("active_scan present")
                .status = terminal;
            assert!(
                reserve_active_scan(&mut inner, mk_job("full")).is_ok(),
                "reserve must succeed once the prior scan is terminal"
            );
        }
    }

    // ── cancel-on-terminal race regression (audit MED) ────────────
    //
    // cancel_scan used to map ANY non-Pending status — including terminal
    // Completed/Failed/Cancelled — to non-terminal Draining. Nothing ever
    // moves a finished job out of Draining (the workers that write terminal
    // states are gone), so one unlucky cancel click landing exactly at scan
    // completion bricked every future scan.start until daemon restart.
    // ── SR-01: clamavd subprocess-failure fallback must fail CLOSED ──
    //
    // The bug: on any clamavd worker error the scan silently fell back to
    // `engine.scan_file()`, scanning a possibly-malicious file IN-PROCESS in
    // the SYSTEM daemon — dropping the isolation boundary the operator asked
    // for with clamav_isolation=subprocess. And user cancellation shared that
    // same error path, so a cancel could re-scan the file the user stopped.
    #[test]
    fn sr01_genuine_failure_does_not_fall_back_to_in_process() {
        use crate::clamav_worker::WorkerError;
        // A real subprocess failure (spawn/timeout/protocol/crash) must NOT
        // fall back — isolation stays enforced, the scan is reported errored.
        assert_eq!(
            clamav_fallback_decision(&WorkerError::Failed("clamavd timeout".into()), false),
            ClamFallback::Refuse,
            "a clamavd failure must fail CLOSED, never scan in-process (SR-01)"
        );
    }

    #[test]
    fn sr01_cancellation_never_falls_back() {
        use crate::clamav_worker::WorkerError;
        // Typed cancel from the worker: refuse.
        assert_eq!(
            clamav_fallback_decision(&WorkerError::Cancelled, false),
            ClamFallback::Refuse,
            "cancellation must never fall back to in-process (SR-01 restriction)"
        );
        // Even if the worker reported a generic Failed, a set cancel flag
        // (cancel raced in after the worker's own check) must still be treated
        // as a cancellation, never a fallback.
        assert_eq!(
            clamav_fallback_decision(&WorkerError::Failed("wait error".into()), true),
            ClamFallback::Refuse,
            "a cancel that races in must not become an in-process fallback"
        );
    }

    #[test]
    fn sr01_concurrency_loadshed_still_falls_back() {
        use crate::clamav_worker::WorkerError;
        // The counter-case: the concurrency limit is a deliberate load-shed,
        // NOT a failure. It must STILL fall back to in-process so closing the
        // failure hole does not break the frequent legitimate load flow
        // (MAX_CONCURRENT_WORKERS is only 2). If a cancel is also pending,
        // cancellation wins (refuse).
        assert_eq!(
            clamav_fallback_decision(&WorkerError::Busy, false),
            ClamFallback::InProcess,
            "concurrency load-shed must keep the in-process fallback"
        );
        assert_eq!(
            clamav_fallback_decision(&WorkerError::Busy, true),
            ClamFallback::Refuse,
            "a pending cancel overrides even the load-shed fallback"
        );
    }

    #[test]
    fn cancel_transition_refuses_terminal_states() {
        // Only Pending/Running may transition.
        assert!(cancel_transition(ScanJobStatus::Pending) == Some(ScanJobStatus::Cancelled));
        assert!(cancel_transition(ScanJobStatus::Running) == Some(ScanJobStatus::Draining));
        // Terminal states (and an in-progress drain) are left untouched.
        for terminal in [
            ScanJobStatus::Completed,
            ScanJobStatus::Cancelled,
            ScanJobStatus::Failed,
            ScanJobStatus::Draining,
        ] {
            assert!(
                cancel_transition(terminal).is_none(),
                "terminal/draining job must not be re-transitioned"
            );
        }
        // And the invariant this protects: a job stuck in Draining rejects
        // new reservations — which is exactly why flipping a terminal job
        // to Draining was permanent.
        let mut inner = empty_inner();
        let mut stuck = mk_job("folder");
        stuck.status = ScanJobStatus::Draining;
        inner.active_scan = Some(stuck);
        assert!(reserve_active_scan(&mut inner, mk_job("quick")).is_err());
    }

    // ── Helpers ──────────────────────────────────────────────────

    /// Build a minimal `ArgusVerdict` with a given score and no findings.
    fn make_verdict(score: u32) -> ArgusVerdict {
        ArgusVerdict {
            path: "C:\\test\\sample.exe".into(),
            file_size: 1024,
            sha256: "aa".repeat(32),
            mime_type: Some("application/x-dosexec".into()),
            score,
            verdict: Verdict::from_score(score),
            findings: Vec::new(),
            analysis_time_us: 100,
            engine_version: argus::ENGINE_VERSION,
            timestamp: 0,
            explanation: VerdictExplanation::default(),
            timing: None,
        }
    }

    /// Build an `ArgusVerdict` with a single finding in the given layer.
    fn make_verdict_with_finding(score: u32, layer: Layer, desc: &str) -> ArgusVerdict {
        let mut v = make_verdict(score);
        v.findings.push(Finding {
            layer,
            severity: Severity::High,
            weight: score,
            description: desc.to_string(),
            technical_detail: None,
        });
        v
    }

    // ── unify_detection_filtered ─────────────────────────────────

    // Regression guard for the documented threshold split (F-8):
    // the engine's Malicious *label* starts at 76 (argus Verdict::from_score),
    // but the daemon's ARGUS-only quarantine bar is 85. Docs once claimed
    // 76 was THE quarantine threshold — wrong.
    //
    // EDITORS: if you change the 85 bar below, you MUST also update
    // docs/ARGUS_CONVERGENCE_MODEL.md, docs/EXTERNAL_REVIEW_v0.1.12.md,
    // the comment block on unify_detection_filtered, and run
    // scripts/check-threshold-docs.ps1 to re-validate the docs.
    #[test]
    fn argus_only_quarantine_threshold_is_85_not_76() {
        // 84 = Malicious label from the engine, but silently dropped from
        // detection handling (no detection row, no quarantine).
        let argus = make_verdict(84);
        assert!(
            argus.is_threat(),
            "engine still labels 84 as Malicious (label threshold is 76)"
        );
        let (infected, name) = unify_detection_filtered(false, None, &argus, &[]);
        assert!(
            !infected && name.is_none(),
            "ARGUS-only 84 must NOT be quarantined (daemon bar is 85)"
        );

        // 85 = high-confidence ARGUS-only → quarantined.
        let argus = make_verdict(85);
        let (infected, _) = unify_detection_filtered(false, None, &argus, &[]);
        assert!(infected, "ARGUS-only 85 must be quarantined");

        // ClamAV confirmation keeps the engine's normal 76 bar.
        let argus = make_verdict(76);
        let (infected, _) =
            unify_detection_filtered(true, Some("Win.Trojan.Agent"), &argus, &[]);
        assert!(infected, "ClamAV-confirmed 76 must remain a threat");
    }

    #[test]
    fn clamav_positive_argus_low_score_is_infected() {
        // ClamAV says infected, ARGUS score is low (20).
        // ClamAV is authoritative — result should be infected.
        let argus = make_verdict(20);
        let (infected, name) =
            unify_detection_filtered(true, Some("Win.Trojan.Agent"), &argus, &[]);
        assert!(infected, "ClamAV positive should always be infected");
        let n = name.unwrap();
        assert!(
            n.contains("Win.Trojan.Agent"),
            "name should contain ClamAV detection: {n}"
        );
        // ARGUS score 20 is <= 50, so no ARGUS annotation expected.
        assert!(
            !n.contains("ARGUS"),
            "low ARGUS score should not be annotated: {n}"
        );
    }

    #[test]
    fn clamav_positive_argus_high_score_includes_argus_annotation() {
        // Both engines agree — ClamAV name should include ARGUS score.
        let argus = make_verdict(90);
        let (infected, name) =
            unify_detection_filtered(true, Some("Win.Trojan.Agent"), &argus, &[]);
        assert!(infected);
        let n = name.unwrap();
        assert!(
            n.contains("Win.Trojan.Agent"),
            "should contain ClamAV name: {n}"
        );
        assert!(
            n.contains("ARGUS: 90/100"),
            "should annotate ARGUS score when > 50: {n}"
        );
    }

    #[test]
    fn clamav_positive_no_name_defaults_to_malware_generic() {
        // ClamAV infected but virus_name is None → default name.
        let argus = make_verdict(10);
        let (infected, name) = unify_detection_filtered(true, None, &argus, &[]);
        assert!(infected);
        let n = name.unwrap();
        assert!(
            n.contains("Malware.Generic"),
            "missing ClamAV name should default to Malware.Generic: {n}"
        );
    }

    #[test]
    fn clamav_negative_argus_85_is_infected() {
        // ClamAV clean, ARGUS score 85 → ARGUS-only high confidence.
        let argus =
            make_verdict_with_finding(85, Layer::PatternDetection, "Discord token stealer pattern");
        let (infected, name) = unify_detection_filtered(false, None, &argus, &[]);
        assert!(
            infected,
            "ARGUS score >= 85 without ClamAV should be infected"
        );
        let n = name.unwrap();
        assert!(
            n.starts_with("ARGUS/"),
            "ARGUS-only detection should start with ARGUS/: {n}"
        );
        assert!(n.contains("85/100"), "should contain ARGUS score: {n}");
    }

    #[test]
    fn clamav_negative_argus_score_50_not_infected() {
        // ClamAV clean, ARGUS score 50 — below the 85 threshold for
        // ARGUS-only auto-quarantine.
        let argus = make_verdict(50);
        let (infected, name) = unify_detection_filtered(false, None, &argus, &[]);
        assert!(
            !infected,
            "ARGUS score 50 without ClamAV should NOT be infected"
        );
        assert!(name.is_none());
    }

    #[test]
    fn clamav_negative_argus_score_84_not_infected() {
        // Edge case: ARGUS score 84 (one below threshold).
        let argus = make_verdict(84);
        let (infected, name) = unify_detection_filtered(false, None, &argus, &[]);
        assert!(
            !infected,
            "ARGUS score 84 without ClamAV should NOT be infected (threshold is 85)"
        );
        assert!(name.is_none());
    }

    #[test]
    fn clamav_negative_argus_score_0_not_infected() {
        // Both clean — absolutely not infected.
        let argus = make_verdict(0);
        let (infected, name) = unify_detection_filtered(false, None, &argus, &[]);
        assert!(!infected);
        assert!(name.is_none());
    }

    #[test]
    fn clamav_negative_argus_100_is_infected() {
        // Maximum ARGUS score without ClamAV → definitely infected.
        let argus = make_verdict_with_finding(
            100,
            Layer::IocCorrelation,
            "SHA-256 matches known malware IOC",
        );
        let (infected, name) = unify_detection_filtered(false, None, &argus, &[]);
        assert!(infected);
        let n = name.unwrap();
        assert!(
            n.contains("IOC.KnownMalicious"),
            "IOC layer → IOC.KnownMalicious: {n}"
        );
    }

    // ── Detection exclusion ──────────────────────────────────────

    #[test]
    fn exclusion_suppresses_clamav_detection() {
        // ClamAV infected but detection name matches an exclusion rule.
        let argus = make_verdict(10);
        let exclusions = vec!["Win.Trojan.Agent".to_string()];
        let (infected, name) =
            unify_detection_filtered(true, Some("Win.Trojan.Agent-12345"), &argus, &exclusions);
        assert!(
            !infected,
            "excluded detection should NOT be reported as infected"
        );
        assert!(name.is_none());
    }

    #[test]
    fn exclusion_is_case_insensitive() {
        // Exclusion rule uses different casing — should still match.
        let argus = make_verdict(10);
        let exclusions = vec!["win.trojan.agent".to_string()];
        let (infected, name) =
            unify_detection_filtered(true, Some("Win.Trojan.Agent-999"), &argus, &exclusions);
        assert!(
            !infected,
            "case-insensitive exclusion should suppress detection"
        );
        assert!(name.is_none());
    }

    #[test]
    fn exclusion_substring_match() {
        // Exclusion is a substring of the detection name.
        let argus = make_verdict(60);
        let exclusions = vec!["Trojan".to_string()];
        let (infected, _) =
            unify_detection_filtered(true, Some("Win.Trojan.Generic-42"), &argus, &exclusions);
        assert!(!infected, "substring exclusion should match");
    }

    #[test]
    fn exclusion_no_match_still_infected() {
        // Exclusion list exists but does NOT match this detection.
        let argus = make_verdict(60);
        let exclusions = vec!["Ransomware".to_string()];
        let (infected, name) =
            unify_detection_filtered(true, Some("Win.Trojan.Agent"), &argus, &exclusions);
        assert!(
            infected,
            "non-matching exclusion should leave detection intact"
        );
        assert!(name.is_some());
    }

    #[test]
    fn exclusion_suppresses_argus_only_detection() {
        // ARGUS-only detection excluded by name.
        let argus = make_verdict_with_finding(90, Layer::PatternDetection, "Discord token stealer");
        let exclusions = vec!["Stealer.Discord".to_string()];
        let (infected, name) = unify_detection_filtered(false, None, &argus, &exclusions);
        assert!(
            !infected,
            "ARGUS-only detection should be suppressible by exclusion"
        );
        assert!(name.is_none());
    }

    #[test]
    fn empty_exclusion_list_does_not_suppress() {
        let argus = make_verdict(10);
        let (infected, name) =
            unify_detection_filtered(true, Some("Win.Trojan.Agent"), &argus, &[]);
        assert!(infected);
        assert!(name.is_some());
    }

    // ── ARGUS-only detection name classification ─────────────────

    #[test]
    fn argus_only_packer_layer_gives_packed_suspicious() {
        let argus = make_verdict_with_finding(90, Layer::PackerDetection, "UPX packer detected");
        let (infected, name) = unify_detection_filtered(false, None, &argus, &[]);
        assert!(infected);
        let n = name.unwrap();
        assert!(
            n.contains("Packed.Suspicious"),
            "PackerDetection layer should yield Packed.Suspicious: {n}"
        );
    }

    #[test]
    fn argus_only_script_layer_gives_script_malicious() {
        let argus =
            make_verdict_with_finding(92, Layer::ScriptAnalysis, "Obfuscated PowerShell dropper");
        let (infected, name) = unify_detection_filtered(false, None, &argus, &[]);
        assert!(infected);
        let n = name.unwrap();
        assert!(
            n.contains("Script.Malicious"),
            "ScriptAnalysis layer should yield Script.Malicious: {n}"
        );
    }

    #[test]
    fn argus_only_deception_layer_gives_deception_disguised() {
        let argus =
            make_verdict_with_finding(95, Layer::FileDeception, "RTLO character in filename");
        let (infected, name) = unify_detection_filtered(false, None, &argus, &[]);
        assert!(infected);
        let n = name.unwrap();
        assert!(
            n.contains("Deception.Disguised"),
            "FileDeception layer should yield Deception.Disguised: {n}"
        );
    }

    #[test]
    fn argus_only_no_findings_defaults_to_suspicious_behavior() {
        // score >= 85 but no findings → falls back to PatternDetection default.
        let argus = make_verdict(85);
        let (infected, name) = unify_detection_filtered(false, None, &argus, &[]);
        assert!(infected);
        let n = name.unwrap();
        // With empty findings, top_finding defaults to PatternDetection
        // and desc is "" so we get "Suspicious.Behavior".
        assert!(
            n.contains("Suspicious.Behavior"),
            "no findings should default to Suspicious.Behavior: {n}"
        );
    }

    // ── max_file_size ────────────────────────────────────────────

    #[test]
    fn max_file_size_returns_config_not_hardcoded() {
        // PathManager must be initialized for Config::load(None).
        crate::paths::init_auto();
        // Without a config file present in test environment, max_file_size()
        // should fall back to DEFAULT_MAX_FILE_SIZE (512 MB).
        let size = max_file_size();
        assert_eq!(
            size, DEFAULT_MAX_FILE_SIZE,
            "without config, max_file_size should equal DEFAULT_MAX_FILE_SIZE"
        );
        // Confirm DEFAULT_MAX_FILE_SIZE is 512 MB.
        assert_eq!(
            DEFAULT_MAX_FILE_SIZE,
            512 * 1024 * 1024,
            "DEFAULT_MAX_FILE_SIZE should be 512 MB"
        );
    }

    // ── ScanJobStatus transitions ────────────────────────────────

    /// Build a `ScanLiveState` in its default (Pending) state.
    fn make_live_state() -> ScanLiveState {
        ScanLiveState {
            id: "test-scan-001".into(),
            kind: "quick".into(),
            started_at: 0,
            files_total: AtomicU64::new(0),
            files_scanned: AtomicU64::new(0),
            threats_found: AtomicU64::new(0),
            cancel_flag: Arc::new(AtomicBool::new(false)),
            status: std::sync::atomic::AtomicU8::new(0), // 0 = Pending
            current_path: Mutex::new(String::new()),
        }
    }

    #[test]
    fn scan_job_status_pending_to_running() {
        let live = make_live_state();
        assert!(
            live.status_enum() == ScanJobStatus::Pending,
            "initial status should be Pending"
        );
        live.set_status(ScanJobStatus::Running);
        assert!(
            live.status_enum() == ScanJobStatus::Running,
            "should transition to Running"
        );
    }

    #[test]
    fn scan_job_status_running_to_completed() {
        let live = make_live_state();
        live.set_status(ScanJobStatus::Running);
        live.set_status(ScanJobStatus::Completed);
        assert!(
            live.status_enum() == ScanJobStatus::Completed,
            "should transition to Completed"
        );
    }

    #[test]
    fn scan_job_status_running_to_cancelled() {
        let live = make_live_state();
        live.set_status(ScanJobStatus::Running);
        live.set_status(ScanJobStatus::Cancelled);
        assert!(
            live.status_enum() == ScanJobStatus::Cancelled,
            "should transition to Cancelled"
        );
    }

    #[test]
    fn scan_job_status_running_to_draining_to_cancelled() {
        let live = make_live_state();
        live.set_status(ScanJobStatus::Running);
        live.set_status(ScanJobStatus::Draining);
        assert!(
            live.status_enum() == ScanJobStatus::Draining,
            "should transition to Draining"
        );
        live.set_status(ScanJobStatus::Cancelled);
        assert!(
            live.status_enum() == ScanJobStatus::Cancelled,
            "should transition from Draining to Cancelled"
        );
    }

    #[test]
    fn scan_job_status_running_to_failed() {
        let live = make_live_state();
        live.set_status(ScanJobStatus::Running);
        live.set_status(ScanJobStatus::Failed);
        assert!(
            live.status_enum() == ScanJobStatus::Failed,
            "should transition to Failed"
        );
    }

    #[test]
    fn scan_job_status_cancel_flag_is_initially_false() {
        let live = make_live_state();
        assert!(
            !live.cancel_flag.load(Ordering::Relaxed),
            "cancel flag should be false on construction"
        );
    }

    // ── Adversary A2: challenge token must be method-scoped ─────────
    //
    // Before this fix the token was stored as (token, instant) with no
    // method binding, so a token issued for "engine.reload" (which the
    // user UAC-approves) could be replayed against "settings.set" or
    // any other PrivilegedMutation handler in the same 60-second window.
    // This regression test locks in: a token issued for one method
    // MUST be rejected when presented to a different method, even if
    // the token bytes match exactly and the token is still fresh.
    #[test]
    fn challenge_token_is_bound_to_method_scope() {
        // PathManager must be initialized: AppState::new touches paths()
        // during boot (ARGUS IOC/YARA, scan cache, trust graph, etc.).
        crate::paths::init_auto();
        let state = AppState::new(None, None, None);

        // Issue a token scoped to engine.reload.
        let token = state.generate_challenge_token("engine.reload");
        assert!(!token.is_empty(), "issued token must be non-empty");

        // Replaying the same token against a different method MUST fail —
        // this is the whole point of method binding. If this assertion ever
        // regresses, the per-dangerous-op UAC consent model is bypassed.
        assert!(
            !state.validate_challenge_token(&token, "settings.set"),
            "token issued for engine.reload must NOT validate against settings.set"
        );

        // The mismatched attempt also burns the token (fail-closed), so a
        // subsequent legitimate attempt against engine.reload must also fail
        // until the user re-prompts. This prevents a TOCTOU race where the
        // attacker probes a different method first to "drain" while the
        // legitimate caller is mid-flight.
        let token2 = state.generate_challenge_token("engine.reload");
        // Correct scope succeeds and consumes the token.
        assert!(
            state.validate_challenge_token(&token2, "engine.reload"),
            "token issued for engine.reload must validate against engine.reload"
        );
        // Single-use: second attempt fails even with the correct scope.
        assert!(
            !state.validate_challenge_token(&token2, "engine.reload"),
            "challenge token must be single-use even on the correct scope"
        );
    }

    // ── v0.1.7 Phase 3 — A/B engine hot-swap regression ─────────────────
    //
    // These two tests drive `AppState`'s OWN snapshot API on purpose. The
    // versions they replace built a private `ArcSwap<Snap>` over stand-in
    // payloads and asserted things about the arc_swap crate, so they stayed
    // green through any daemon-side regression — including the exact revert
    // they were named to prevent (splitting the slot back into
    // `ArcSwap<Option<Arc<ClamEngine>>>` plus a sibling
    // `RwLock<Option<String>>`). Referencing `EngineSnapshot`,
    // `publish_engine_snapshot`, `record_engine_error` and
    // `read_engine_snapshot` means that revert no longer compiles here.
    //
    // A real `ClamEngine` needs libclamav plus a CVD on disk, so the engine
    // side is `None` in-test; the assertions are about snapshot identity and
    // immutability, which do not depend on the payload.

    /// A snapshot a reader already holds must be unaffected by a later
    /// publish — that is what lets an in-flight scan keep scanning with the
    /// engine it started with while a reload swaps a new one in.
    #[test]
    fn engine_snapshot_held_by_a_reader_survives_a_publish_unchanged() {
        crate::paths::init_auto();
        let state = AppState::new(None, None, None);

        // What a scan holds: one Arc covering BOTH fields.
        let held: Arc<EngineSnapshot> = Arc::clone(&state.read_engine_snapshot());
        let held_had_engine = held.engine.is_some();
        let held_error = held.last_error.clone();

        // What a reload does.
        let prev = state.publish_engine_snapshot(EngineSnapshot {
            engine: None,
            last_error: Some("reload failed: CL_EMALFDB".into()),
        });

        // `publish_engine_snapshot` must hand back the snapshot it
        // DISPLACED, not the one it installed: `reload_engine` relies on
        // that to move the old engine's drop off the IPC thread (audit
        // MED #3). Returning the new one would drop the live engine.
        assert!(
            Arc::ptr_eq(&held, &prev),
            "publish must return the previous snapshot, not the new one"
        );

        // The held snapshot is immutable — the swap cannot reach into it.
        assert_eq!(held.engine.is_some(), held_had_engine);
        assert_eq!(held.last_error, held_error);

        // Readers arriving after the swap get the new pair.
        assert_eq!(
            state.read_engine_snapshot().last_error.as_deref(),
            Some("reload failed: CL_EMALFDB")
        );

        // Dropping the displaced snapshot does not disturb the reader's.
        drop(prev);
        assert_eq!(held.last_error, held_error);
    }

    /// A failed reload annotates the error WITHOUT evicting the engine that
    /// is still serving scans, and does so by publishing a fresh snapshot
    /// rather than mutating the one readers already hold.
    #[test]
    fn record_engine_error_publishes_a_new_snapshot_and_keeps_the_engine() {
        crate::paths::init_auto();
        let state = AppState::new(None, None, None);

        // Start from a known-clean pair so the assertions below are about
        // `record_engine_error`, not about how this box happened to boot.
        state.publish_engine_snapshot(EngineSnapshot {
            engine: None,
            last_error: None,
        });
        let before: Arc<EngineSnapshot> = Arc::clone(&state.read_engine_snapshot());

        state.record_engine_error(Some("libclamav: CL_EMALFDB".into()));

        let after: Arc<EngineSnapshot> = Arc::clone(&state.read_engine_snapshot());
        assert!(
            !Arc::ptr_eq(&before, &after),
            "the RCU must publish a NEW snapshot, not mutate the live one"
        );
        assert_eq!(
            before.last_error, None,
            "a published snapshot must never change under a reader"
        );
        assert_eq!(after.last_error.as_deref(), Some("libclamav: CL_EMALFDB"));

        // The engine handle travels forward with the error, so
        // `read_engine()` and the snapshot's `last_error` can never
        // disagree about the same moment.
        assert_eq!(after.engine.is_some(), before.engine.is_some());
        assert_eq!(state.read_engine().is_some(), after.engine.is_some());
    }

    // ── F-9: per-user %LOCALAPPDATA%\Programs watched-root helpers ─────

    /// Unique temp dir per test invocation (no external tempfile dep).
    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "sentinella-f9-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            std::fs::create_dir_all(&p).expect("create temp dir");
            Self(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn f9_user_profile_subdirs_enumerates_real_profiles_only() {
        let users = TempDir::new("enum");
        // Real user with the Programs dir.
        std::fs::create_dir_all(users.0.join("alice\\AppData\\Local\\Programs")).unwrap();
        // Real user WITHOUT the subdir — must be skipped, not error.
        std::fs::create_dir_all(users.0.join("bob")).unwrap();
        // Well-known non-user profiles — must be skipped even with the dir.
        for skipped in ["Public", "Default", "defaultuser0"] {
            std::fs::create_dir_all(users.0.join(skipped).join("AppData\\Local\\Programs"))
                .unwrap();
        }
        // A stray *file* under the users root — must be skipped.
        std::fs::write(users.0.join("not-a-profile.txt"), b"x").unwrap();

        let found = user_profile_subdirs(&users.0, "AppData\\Local\\Programs");
        assert_eq!(
            found,
            vec![users.0.join("alice\\AppData\\Local\\Programs")],
            "only alice's existing Programs dir may be returned"
        );
    }

    #[test]
    fn f9_user_profile_subdirs_missing_users_root_is_empty_not_error() {
        let missing = std::env::temp_dir().join(format!(
            "sentinella-f9-no-such-root-{}",
            std::process::id()
        ));
        assert!(user_profile_subdirs(&missing, "AppData\\Local\\Programs").is_empty());
    }

    #[test]
    fn f9_push_unique_existing_root_dedupes_case_insensitively() {
        let dir = TempDir::new("dedup");
        let mut roots: Vec<std::path::PathBuf> = Vec::new();

        assert!(push_unique_existing_root(&mut roots, dir.0.clone()));
        // Same path, different casing (Windows paths are case-insensitive):
        // must NOT produce a second watch on the same physical directory —
        // notify/ReadDirectoryChangesW misbehaves on duplicate registrations.
        let upper = dir.0.to_string_lossy().to_uppercase();
        assert!(!push_unique_existing_root(&mut roots, std::path::PathBuf::from(upper)));
        // Trailing separator variant — same root.
        let trailing = format!("{}\\", dir.0.to_string_lossy());
        assert!(!push_unique_existing_root(&mut roots, std::path::PathBuf::from(trailing)));
        assert_eq!(roots.len(), 1, "no-duplicate-watch invariant violated");
    }

    #[test]
    fn f9_push_unique_existing_root_skips_missing_dir() {
        let dir = TempDir::new("skip");
        let missing = dir.0.join("does-not-exist");
        let mut roots: Vec<std::path::PathBuf> = Vec::new();
        assert!(!push_unique_existing_root(&mut roots, missing));
        assert!(roots.is_empty(), "missing dirs must be skipped gracefully");
    }
}
