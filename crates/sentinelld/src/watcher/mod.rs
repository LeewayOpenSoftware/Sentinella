//! Real-time filesystem watcher — user-mode, post-write detection.
//!
//! Uses the `notify` crate (ReadDirectoryChangesW on Windows, inotify on Linux).
//! Debounces rapid events and feeds new/modified files into the scan queue.

pub mod file_identity;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

use notify::event::{ModifyKind, RenameMode};
use notify::{Event, EventKind, RecursiveMode, Watcher as NotifyWatcher};
use tracing::{debug, error, info, warn};

use crate::engine::ClamEngine;
use crate::fish::response::{
    ResponseType, find_suspect_processes, suspend_process, terminate_process,
};
use crate::fish::{FileMutationEvent, FishDecision, MutationKind};

/// Max file size the watcher will scan (256 MB).
const WATCHER_MAX_FILE_SIZE: u64 = 256 * 1024 * 1024;

/// Debounce delay — wait for writes to stabilize. Reduced from 800ms in v0.1.4:
/// small files (downloaded EICAR, scripts, droppers) often write in a single
/// chunk and don't need long coalescing. Long debounce loses races against
/// other AVs with kernel filters. Large files still benefit because writes
/// continue to extend the debounce window.
const DEBOUNCE_MS: u64 = 150;
/// Maximum size of file to fast-path scan (skip debounce) on Create events.
/// Files written atomically (rename-from-temp) and small files (≤2 MB) are
/// scanned immediately. Larger files fall through to the normal debounce
/// path so multi-chunk writes coalesce.
const FAST_PATH_MAX_SIZE: u64 = 2 * 1024 * 1024;
const DEBOUNCE_CAP: usize = 10_000;
const OVERFLOW_RESCAN_CAP: usize = 2_000;

/// Simple guard: don't sandbox the same file twice within 60 seconds.
const SANDBOX_DEDUP_SECS: u64 = 60;

/// Maximum score_delta a single sandbox detonation can contribute.
const SANDBOX_MAX_SCORE_DELTA: i32 = 50;

/// State of the real-time watcher.
#[allow(dead_code)]
pub struct RealtimeWatcher {
    running: Arc<AtomicBool>,
    events_count: Arc<AtomicU64>,
    detections_count: Arc<AtomicU64>,
    watched_roots: Vec<PathBuf>,
    _thread: Option<std::thread::JoinHandle<()>>,
}

impl RealtimeWatcher {
    /// Start watching the given directories for file changes.
    pub fn start(
        roots: Vec<PathBuf>,
        engine: Arc<ClamEngine>,
        state: Arc<crate::ipc::AppState>,
    ) -> Result<Self, String> {
        let running = Arc::new(AtomicBool::new(true));
        let events_count = Arc::new(AtomicU64::new(0));
        let detections_count = Arc::new(AtomicU64::new(0));
        let cache = Arc::new(crate::scan::cache::ScanCache::new());

        let r = Arc::clone(&running);
        let ec = Arc::clone(&events_count);
        let dc = Arc::clone(&detections_count);
        let watched = roots.clone();
        let cache_clone = Arc::clone(&cache);

        let thread = std::thread::Builder::new()
            .name("realtime-watcher".into())
            .spawn(move || {
                watcher_loop(watched, engine, state, r, ec, dc, cache_clone);
            })
            .map_err(|e| format!("failed to spawn watcher thread: {e}"))?;

        info!(dirs = roots.len(), "real-time watcher started");

        Ok(Self {
            running,
            events_count,
            detections_count,
            watched_roots: roots,
            _thread: Some(thread),
        })
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    #[allow(dead_code)]
    pub fn events_count(&self) -> u64 {
        self.events_count.load(Ordering::Relaxed)
    }

    #[allow(dead_code)]
    pub fn detections_count(&self) -> u64 {
        self.detections_count.load(Ordering::Relaxed)
    }

    pub fn watched_roots(&self) -> &[PathBuf] {
        &self.watched_roots
    }

    #[allow(dead_code)]
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        info!("real-time watcher stop requested");
    }
}

impl Drop for RealtimeWatcher {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

/// Main watcher loop — runs in a dedicated thread.
fn watcher_loop(
    roots: Vec<PathBuf>,
    engine: Arc<ClamEngine>,
    state: Arc<crate::ipc::AppState>,
    running: Arc<AtomicBool>,
    events_count: Arc<AtomicU64>,
    detections_count: Arc<AtomicU64>,
    cache: Arc<crate::scan::cache::ScanCache>,
) {
    // Channel for debounced events.
    //
    // BOUNDED on purpose: the notify callback fires at filesystem speed. Under
    // a storm (ransomware mass-rewrite, archive unpack, recursive copy of a
    // large tree) the previous unbounded `channel()` queued every event,
    // letting the daemon grow without limit until OOM — exactly the scenario
    // the watcher exists to detect.
    //
    // With `sync_channel(NOTIFY_QUEUE_CAP)` + `try_send` the queue is capped
    // and surplus events get dropped (with a tracked counter), preserving
    // memory at the cost of some debounce coverage during the storm. The
    // post-storm rescan/overflow path then catches anything missed.
    const NOTIFY_QUEUE_CAP: usize = 8192;
    let (tx, rx) = std::sync::mpsc::sync_channel::<Event>(NOTIFY_QUEUE_CAP);
    let dropped_events = Arc::new(AtomicU64::new(0));
    let dropped_clone = Arc::clone(&dropped_events);

    // Create the filesystem watcher.
    let mut watcher =
        match notify::recommended_watcher(move |res: Result<Event, notify::Error>| match res {
            Ok(event) => {
                if tx.try_send(event).is_err() {
                    // Channel full — log periodically (every 1024th drop) to
                    // avoid spamming when the storm produces millions of events.
                    let n = dropped_clone.fetch_add(1, Ordering::Relaxed) + 1;
                    if n.is_power_of_two() || n % 1024 == 0 {
                        warn!(
                            dropped_total = n,
                            "watcher queue full — dropping events (FS event storm)"
                        );
                    }
                }
            }
            Err(e) => warn!(%e, "watcher error"),
        }) {
            Ok(w) => w,
            Err(e) => {
                error!(%e, "failed to create filesystem watcher");
                return;
            }
        };

    // Register watched directories.
    for root in &roots {
        if root.exists() {
            match watcher.watch(root, RecursiveMode::Recursive) {
                Ok(()) => info!(path = %root.display(), "watching directory"),
                Err(e) => warn!(path = %root.display(), %e, "failed to watch"),
            }
        } else {
            debug!(path = %root.display(), "skipping non-existent directory");
        }
    }

    // Debounce set — paths seen recently.
    let mut recent: HashSet<PathBuf> = HashSet::new();
    let mut overflow_dirs: HashSet<PathBuf> = HashSet::new();
    let mut last_flush = Instant::now();
    // Fast-path force flag — set by Create-of-small-file events to bypass
    // debounce wait on the next loop iteration. Replaces fragile
    // Instant::checked_sub trick which silently failed on low-uptime boots.
    let mut force_flush = false;

    // Sandbox dedup guard — tracks recently detonated files to prevent
    // double score_delta application when the watcher fires twice for
    // the same path in rapid succession.
    let mut sandbox_dedup: HashMap<PathBuf, Instant> = HashMap::new();

    // TOCTOU race prevention diagnostics.
    let race_diag = file_identity::RaceDiagnostics::new();
    // Snapshot of watched roots for identity revalidation (TOCTOU).
    let watched_roots_vec: Vec<PathBuf> = roots.clone();

    // FISH ransomware detection via AppState's shared MutationWindow.
    //
    // NOT observe-only, despite what this said until 0.1.13. A burst
    // decision runs `fish_handle_burst` INLINE on this thread, and when
    // `fish.observe_only` is false that enumerates every process on the box
    // (`find_suspect_processes`) and then suspends or terminates the
    // suspects. Two consequences a maintainer must know: the watcher thread
    // is blocked for the duration, which is precisely when a ransomware
    // burst is producing the most events; and active response is now
    // genuinely reachable, because until the config-refresh fix the shield
    // was pinned to its boot defaults and could never leave observe mode.

    // Watcher config snapshot, throttle-refreshed from disk.
    //
    // History: originally re-loaded on every flush (disk read every ~150ms
    // under busy filesystems — wasteful); then switched to load-once, which
    // meant GUI edits to exclusions/heuristics/sandbox had NO effect until a
    // daemon restart (silent UX gap). Compromise: keep an in-memory snapshot
    // (no per-flush disk I/O) but refresh it at most once per
    // CONFIG_RELOAD_INTERVAL. GUI exclusion edits take effect within ~5s.
    const CONFIG_RELOAD_INTERVAL: Duration = Duration::from_secs(5);
    let config = crate::config::Config::load(None).unwrap_or_default();
    let mut excluded_paths_static = config.excluded_paths.clone();
    let mut excluded_extensions_static = config.excluded_extensions.clone();
    let mut heuristic_alerts_static = config.heuristic_alerts;
    let mut sandbox_config_static = config.sandbox.clone();
    let mut last_config_reload = Instant::now();
    // mtime gate: only re-read when the file actually changed. This avoids a
    // periodic disk read on a stable config AND avoids re-triggering
    // Config::load's parse-error side effects (timestamped .bad backup +
    // defaults save) every interval when a config happens to be malformed.
    let config_path = crate::paths::paths().config_file();
    let config_mtime = |p: &std::path::Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    let mut last_config_mtime = config_mtime(&config_path);

    while running.load(Ordering::Relaxed) {
        // Throttled live-reload: every CONFIG_RELOAD_INTERVAL, cheaply stat the
        // config file; only when its mtime changed do we re-parse. Settings
        // changes apply within ~5s without a daemon restart.
        if last_config_reload.elapsed() >= CONFIG_RELOAD_INTERVAL {
            last_config_reload = Instant::now();
            let cur_mtime = config_mtime(&config_path);
            if cur_mtime != last_config_mtime {
                if let Ok(fresh) = crate::config::Config::load(None) {
                    excluded_paths_static = fresh.excluded_paths;
                    excluded_extensions_static = fresh.excluded_extensions;
                    heuristic_alerts_static = fresh.heuristic_alerts;
                    sandbox_config_static = fresh.sandbox;
                }
                // Re-stat: Config::load may have rewritten the file (parse
                // error → defaults saved), so record the post-load mtime to
                // avoid reloading the same content again next tick.
                last_config_mtime = config_mtime(&config_path);
            }
        }
        // Wait for events with timeout.
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(event) => {
                // ── FISH: feed all relevant events ──
                // May take ACTIVE response (suspend/terminate) inline; see
                // the note at the top of this function.
                fish_feed_event(&event, &state);

                // Only care about file creation and modification for scanning.
                //
                // MATCH THE KINDS THE BACKEND ACTUALLY EMITS. notify 7's
                // Windows backend (ReadDirectoryChangesW) emits exactly five:
                //   FILE_ACTION_ADDED           -> Create(CreateKind::Any)
                //   FILE_ACTION_REMOVED         -> Remove(RemoveKind::Any)
                //   FILE_ACTION_MODIFIED        -> Modify(ModifyKind::Any)
                //   FILE_ACTION_RENAMED_OLD_NAME-> Modify(Name(RenameMode::From))
                //   FILE_ACTION_RENAMED_NEW_NAME-> Modify(Name(RenameMode::To))
                // (verified in notify-7.0.0/src/windows.rs).
                //
                // `CreateKind::File`, `ModifyKind::Data(_)` and
                // `RenameMode::Both` are inotify/FSEvents shapes and NEVER
                // arrive here — so three of the five arms in this list were
                // dead, and `Create(CreateKind::Any)`, the actual
                // file-creation event on the only platform this ships to,
                // was not matched at all. A file created and never touched
                // again reached the scanner through no arm of this filter.
                // The generic arms below keep the non-Windows shapes working
                // and cost nothing.
                let dominated = matches!(
                    event.kind,
                    EventKind::Create(_)
                        | EventKind::Modify(ModifyKind::Data(_))
                        | EventKind::Modify(ModifyKind::Any)
                        | EventKind::Modify(ModifyKind::Name(RenameMode::Both))
                        | EventKind::Modify(ModifyKind::Name(RenameMode::To))
                );
                if !dominated {
                    continue;
                }

                // Fast-path: Create events for small files are scanned
                // immediately without waiting for debounce. EICAR, scripts,
                // and atomically-renamed downloads land here.
                //
                // `Create(_)`, not `Create(CreateKind::File)`: see above.
                // Pinned to `Create(CreateKind::File)` this was false for
                // every event Windows produces, so the v0.1.4 fast path had
                // never once run in production and every small file — the
                // EICAR-in-Downloads case it was written for — sat through
                // the full debounce instead.
                let is_create = matches!(event.kind, EventKind::Create(_));

                for path in event.paths {
                    if !path.is_file() {
                        continue;
                    }
                    if is_create {
                        // Check file size — if small enough, scan now and skip debounce.
                        if let Ok(meta) = std::fs::metadata(&path) {
                            if meta.len() <= FAST_PATH_MAX_SIZE {
                                // Audit fix: the fast-path previously inserted
                                // unconditionally, bypassing DEBOUNCE_CAP. A
                                // flood of small-file Create events could grow
                                // `recent` without bound. Respect the cap here
                                // too; over the cap, demote to a directory
                                // rescan like the slow path.
                                if recent.len() < DEBOUNCE_CAP {
                                    recent.insert(path);
                                    force_flush = true;
                                } else if let Some(parent) = path.parent() {
                                    overflow_dirs.insert(parent.to_path_buf());
                                }
                                continue;
                            }
                        }
                    }
                    if recent.len() < DEBOUNCE_CAP {
                        recent.insert(path);
                    } else if let Some(parent) = path.parent() {
                        overflow_dirs.insert(parent.to_path_buf());
                    }
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }

        // Flush debounce buffer after delay OR force_flush from fast-path.
        if (!recent.is_empty() || !overflow_dirs.is_empty())
            && (force_flush || last_flush.elapsed() >= Duration::from_millis(DEBOUNCE_MS))
        {
            force_flush = false;
            let mut batch: Vec<PathBuf> = recent.drain().collect();
            if !overflow_dirs.is_empty() {
                let dirs: Vec<PathBuf> = overflow_dirs.drain().collect();
                let before = batch.len();
                for dir in &dirs {
                    collect_overflow_rescan_files(dir, &mut batch, OVERFLOW_RESCAN_CAP);
                }
                warn!(
                    dirs = dirs.len(),
                    queued = batch.len().saturating_sub(before),
                    cap = DEBOUNCE_CAP,
                    "watcher debounce overflow; queued targeted directory rescan"
                );
            }
            last_flush = Instant::now();
            state.touch_watcher_heartbeat();

            for path in batch {
                events_count.fetch_add(1, Ordering::Relaxed);

                // Skip excluded / system files / own files / build dirs / transient artifacts.
                if crate::scan::should_skip_file(&path) {
                    continue;
                }
                if crate::scan::is_sentinella_path(&path) {
                    continue;
                }
                if crate::scan::is_build_or_dev_path(&path) {
                    continue;
                }
                if crate::scan::is_transient_build_artifact(&path) {
                    continue;
                }
                if crate::scan::is_excluded(
                    &path,
                    &excluded_paths_static,
                    &excluded_extensions_static,
                ) {
                    continue;
                }

                // Smart extension filtering — real-time watcher focuses on
                // file types that can contain executable content. Pure data
                // files (images, fonts, logs) are skipped for performance.
                if let Some(ext) = path.extension() {
                    let ext_lower = ext.to_string_lossy().to_lowercase();
                    // Skip known-safe data file types.
                    if matches!(
                        ext_lower.as_str(),
                        // Logs/temp/IDE artifacts.
                        "log" | "tmp" | "bak" | "swp" | "swo"
                        | "db-journal" | "db-wal" | "db-shm"
                        // Images (never executable).
                        | "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp"
                        | "svg" | "ico" | "tiff" | "tif"
                        // Fonts.
                        | "woff" | "woff2" | "ttf" | "otf" | "eot"
                        // Audio/video (scanned on-demand, not realtime).
                        | "mp3" | "mp4" | "mkv" | "avi" | "wav" | "flac"
                        | "ogg" | "m4a" | "webm"
                        // Build artifacts (Rust, C/C++, .NET, Node).
                        | "rlib" | "rmeta" | "fingerprint" | "incremental"
                        | "pdb" | "ilk" | "lib" | "exp" | "map"
                        | "d" | "o" | "obj" | "cache" | "lock"
                        // Pure text data.
                        | "csv" | "tsv" | "yaml" | "yml" | "toml"
                        | "json" | "xml" | "ini" | "cfg" | "conf"
                        | "md" | "txt" | "rst" | "tex"
                        // Quarantine vault files.
                        | "vault"
                    ) {
                        continue;
                    }
                }

                // Skip large files.
                let path_meta = match std::fs::metadata(&path) {
                    Ok(meta) if meta.len() > WATCHER_MAX_FILE_SIZE => continue,
                    Ok(meta) if meta.len() == 0 => continue, // Empty files.
                    Err(_) => continue,
                    Ok(meta) => meta,
                };

                // Cooldown: skip files created less than 500ms ago — but ONLY
                // for paths that look like build artifact zones. Originally
                // this applied to all files to dodge `cargo build` contention,
                // but it also added 500ms latency to every legit download
                // (EICAR landed in Downloads → 500ms cooldown → Defender wins).
                //
                // User-visible folders (Downloads, Desktop, Documents, OneDrive)
                // and download partials never need this cooldown — those are
                // exactly the paths where we MUST scan as fast as possible.
                // Exact-component match (case-insensitive). Substring matching
                // missed localized folders like German OneDrive's
                // "OneDrive - Persönlich" and falsely matched things like
                // "OneDrive2" or "Downloads2". Now we check each path
                // component against a set of recognized names. OneDrive
                // matches any component STARTING with "OneDrive" (covers
                // localized variants like "OneDrive - Personal").
                let is_user_visible_target = path.components().any(|c| {
                    let s = c.as_os_str().to_string_lossy();
                    let lower = s.to_ascii_lowercase();
                    matches!(lower.as_str(), "downloads" | "desktop" | "documents")
                        || lower.starts_with("onedrive")
                });
                if !is_user_visible_target {
                    if let Ok(created) = path_meta.created() {
                        if let Ok(age) = created.elapsed() {
                            if age < std::time::Duration::from_millis(500) {
                                continue;
                            }
                        }
                    }
                }

                // Quarantine F4: if this path was just restored from
                // quarantine, skip scanning it. The restore handler marks the
                // path BEFORE writing plaintext to disk so the CREATE event
                // emitted by the write lands inside the suppression window —
                // without this check, the watcher would re-detect and
                // re-quarantine the file before the caller commits the DB
                // status flip, creating an infinite restore→quarantine loop.
                if state.is_restore_suppressed(&path) {
                    debug!(file = %path.display(), "watcher: skip — recently restored");
                    continue;
                }

                // TOCTOU fix: capture file identity snapshot BEFORE scan.
                // Replaces old is_symlink() check — now detects ALL reparse
                // points (junctions, mount points) and captures canonical path +
                // metadata for revalidation before scan and quarantine.
                let file_id = match file_identity::FileIdentity::capture(&path) {
                    Some(id) => id,
                    None => {
                        // Reparse point or unresolvable → reject.
                        race_diag.reparse_rejected.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };

                // Check scan cache — skip if recently scanned and clean.
                if let Some(true) = cache.check_with_metadata(&path, &path_meta) {
                    debug!(file = %path.display(), "cache hit: clean");
                    continue;
                }

                // TOCTOU Phase 2: revalidate identity before scan.
                // Between debounce buffer flush and now, the file may have been
                // replaced by a symlink/junction. Reject if identity changed.
                if let Err(mismatch) = file_id.revalidate(&watched_roots_vec) {
                    debug!(
                        file = %path.display(),
                        reason = %mismatch,
                        "TOCTOU: identity changed before scan, skipping"
                    );
                    race_diag.race_skipped.fetch_add(1, Ordering::Relaxed);
                    race_diag.identity_changed.fetch_add(1, Ordering::Relaxed);
                    continue;
                }

                // Verify file is readable (not locked by another process).
                match std::fs::File::open(&path) {
                    Ok(_) => {} // File is accessible.
                    Err(_) => {
                        continue;
                    } // Skip locked/inaccessible files.
                }

                // ── Budget-bounded realtime scan ──────────────
                let rt_profile = argus::profile::ScanProfile::realtime();
                let rt_budget = rt_profile.budget.clone();
                let rt_cancel = std::sync::atomic::AtomicBool::new(false);
                let rt_tracker = argus::budget::BudgetTracker::new(
                    rt_budget,
                    std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                );

                // Record realtime scan activity for residency management.
                state.activity_tracker.record_realtime_scan();

                // Layer 0: ClamAV signature scan (with budget check).
                let clamav_start = std::time::Instant::now();
                let result = state.scan_file_clamav(&engine, &path, &rt_cancel);
                if rt_tracker.phase_expired(clamav_start, rt_tracker.budget().max_clamav_duration) {
                    rt_tracker.record_timeout(argus::budget::TimeoutReason::ClamAvTimeout);
                }

                if !path.exists() {
                    continue;
                }

                // Check total budget before ARGUS — realtime MUST NOT stall.
                let mut argus_verdict = if rt_tracker.is_expired() {
                    rt_tracker.record_timeout(argus::budget::TimeoutReason::TotalTimeout);
                    debug!(file = %path.display(), "realtime budget exhausted, skipping ARGUS");
                    // H4 fix: partial analysis (ARGUS skipped) → NEVER cache as clean.
                    // Budget exhaustion means incomplete analysis. Only cache ClamAV positives.
                    // Clean-looking files remain uncached → will be re-scanned next encounter.
                    if result.infected {
                        cache.record_with_metadata(&path, &path_meta, false);
                    }
                    // else: deliberately NOT cached — next scan attempt will retry.
                    if result.infected {
                        // ClamAV positive — still report threat even without ARGUS.
                        let threat_name = result.virus_name.clone().unwrap_or("Unknown".into());
                        warn!(file = %path.display(), threat = %threat_name, "REALTIME THREAT (budget-partial)");
                        detections_count.fetch_add(1, Ordering::Relaxed);

                        // TOCTOU Phase 3: revalidate identity BEFORE quarantine.
                        // This branch is only reachable when ClamAV alone blew
                        // the total budget — the longest capture→quarantine
                        // window in the module — so the swap race matters most
                        // exactly here. Mirror the main threat path below.
                        if let Err(mismatch) = file_id.revalidate(&watched_roots_vec) {
                            warn!(
                                file = %path.display(),
                                reason = %mismatch,
                                "TOCTOU: identity changed before quarantine — PREVENTED"
                            );
                            race_diag
                                .quarantine_race_prevented
                                .fetch_add(1, Ordering::Relaxed);
                            continue; // Skip quarantine, move to next file.
                        }

                        let path_str = path.to_string_lossy().to_string();
                        match state.quarantine_file(&path_str, &threat_name, "realtime") {
                            Ok(q) => {
                                info!(id = %q.quarantine_id, "auto-quarantined (budget-partial)")
                            }
                            Err(e) => warn!(%e, "auto-quarantine failed"),
                        }
                    }
                    continue;
                } else if heuristic_alerts_static {
                    let argus_start = std::time::Instant::now();
                    // Realtime profile budget: pass the tracker in so ARGUS
                    // enforces per-layer/total timeouts instead of running
                    // with the 60s manual default.
                    let v = state.argus().analyze_file_with_tracker(&path, &rt_tracker);
                    if rt_tracker.phase_expired(argus_start, rt_tracker.budget().max_yara_duration)
                    {
                        rt_tracker.record_timeout(argus::budget::TimeoutReason::YaraTimeout);
                    }
                    v
                } else {
                    argus::ArgusVerdict {
                        path: path.to_string_lossy().to_string(),
                        file_size: 0,
                        sha256: String::new(),
                        mime_type: None,
                        score: 0,
                        verdict: argus::verdict::Verdict::Clean,
                        findings: vec![],
                        analysis_time_us: 0,
                        engine_version: argus::ENGINE_VERSION,
                        timestamp: 0,
                        explanation: argus::verdict::VerdictExplanation::default(),
                        timing: None,
                    }
                };

                // ── v0.1.12: budget-TRUNCATED analysis is not a clean result ──
                //
                // The pre-ARGUS guard above only covers "ARGUS was skipped
                // entirely". It does NOT cover truncation *inside* ARGUS: every
                // layer after MIME/IOC is gated on `tracker.is_expired()`, and a
                // skipped layer records a timeout reason but emits NO finding. So
                // a file whose ClamAV phase burned most of the 10 s realtime
                // budget passes the check at :510, enters ARGUS, has PE/packer/
                // script/JAR/PDF/pattern/YARA/authenticode all silently skipped,
                // and returns score 0 / Clean with no error finding —
                // `argus_analysis_error()` only matches "Analysis incomplete: ",
                // which a budget timeout never produces.
                //
                // Caching that as clean wrote a PERSISTENT per-file whitelist
                // entry (survives daemon restarts until size/mtime/content
                // change), and the trust-graph observation below additionally
                // earned the file a confidence discount on later scans. Net: an
                // attacker-influenceable realtime detection bypass — feed the
                // watcher deliberately slow-to-scan input (nested archive,
                // large polyglot) and the file is whitelisted for good.
                //
                // Evaluated as a closure so each use site re-reads the tracker;
                // it only ever accumulates, so a later check is strictly more
                // conservative than a snapshot taken here.
                let rt_analysis_partial =
                    || rt_tracker.is_expired() || !rt_tracker.timeouts().is_empty();

                // Timeouts are themselves evidence — mirror the manual
                // full-scan path (ipc/state.rs), which the watcher never did.
                // Applied BEFORE the ledger, which reads the score.
                let rt_timeout_weight = rt_tracker.timeout_suspicion();
                if rt_timeout_weight > 0 {
                    argus_verdict.score = argus_verdict
                        .score
                        .saturating_add(rt_timeout_weight)
                        .min(100);
                    argus_verdict.verdict =
                        argus::verdict::Verdict::from_score(argus_verdict.score);
                }

                // ── ConvergenceLedger (ARCH-H1 fix: realtime uses same path as manual) ──
                let mut ledger =
                    crate::convergence::ConvergenceLedger::new(&argus_verdict, result.infected);

                // ── ADS content scan (ASTRA, realtime: exe streams only) ──
                if !rt_tracker.is_expired() {
                    let ads_policy = crate::scan::ads::ads_policy_for_profile(&rt_profile);
                    let streams = crate::scan::ads::enumerate_ads(&path);
                    let filtered = crate::scan::ads::filter_streams(streams, ads_policy);
                    for stream in &filtered {
                        if rt_tracker.is_expired() {
                            break;
                        }
                        let ads_result = crate::scan::ads::scan_ads_content(stream, state.argus());
                        for finding in ads_result.content_findings {
                            ledger.add_evidence("ADS", finding);
                        }
                    }
                }

                // ── Trust graph (realtime: query discount, defer observation) ──
                // H7 fix: observe() moved AFTER finalize — only clean files build trust.
                // Previously, malicious files observed BEFORE scoring → slowly earned trust.
                if let Some(tg) = state.trust_graph() {
                    let file_key = path.to_string_lossy().to_lowercase();
                    // Query existing trust level for discount (read-only).
                    let trust_q = tg.query(&file_key);
                    if trust_q.confidence_discount > 0 {
                        let trust_finding = crate::trust_graph::trust_finding(&trust_q);
                        ledger.apply_trust_discount(trust_q.confidence_discount, trust_finding);
                    }
                }

                // ── Persistence intelligence ──
                if let Some(ptype) = crate::persistence::check_persistence_context(&path) {
                    let finding = crate::persistence::persistence_finding(ptype, &path, false);
                    ledger.add_evidence("Persistence", finding);
                }

                // ── PLM lineage correlation ──
                if let Some(plm) = state.plm() {
                    if let Some(chain) = plm.query_by_image_path(&path) {
                        if let Some(finding) = crate::plm::lineage_finding(&chain) {
                            ledger.add_evidence("PLM", finding);
                        }
                        // ── WeedHack campaign observation ──
                        // Opt-in correlation: feeds chain signals through the
                        // campaign tracker. Tracker dedupes by tier so repeat
                        // scans of the same chain don't re-emit, and Suspicious
                        // tier maps to Medium/weight 10 → observe-only via the
                        // existing ConvergenceLedger (no bypass, no auto-kill).
                        if let Some(leaf) = chain.nodes.last() {
                            for f in plm.observe_chain_for_weedhack(leaf.pid) {
                                ledger.add_evidence("WeedHack", f);
                            }
                        }
                    }
                }

                // ── Ecosystem convergence ──
                if ledger.base_score > 0 {
                    let file_key = path.to_string_lossy().to_string();
                    if !ledger.findings.is_empty() {
                        state.ecosystem.add_evidence(
                            &file_key,
                            crate::ecosystem::EcosystemEvidence {
                                source: crate::ecosystem::EvidenceSource::Argus,
                                timestamp: chrono::Utc::now().timestamp(),
                                description: format!(
                                    "{} findings, score {}",
                                    ledger.findings.len(),
                                    ledger.base_score
                                ),
                                weight: (ledger.base_score / 10).min(10),
                            },
                        );
                    }
                    if let Some(eco) = state.ecosystem.get(&file_key) {
                        if let Some(finding) = crate::ecosystem::ecosystem_finding(&eco) {
                            ledger.add_evidence("Ecosystem", finding);
                        }
                    }
                }

                // ── Finalize convergence ──
                let (final_score, final_verdict, _) = ledger.finalize();
                argus_verdict.score = final_score;
                argus_verdict.verdict = final_verdict;
                argus_verdict.findings = ledger.findings.clone();
                ledger.patch_explanation(&mut argus_verdict.explanation, final_score);

                // H7 fix: deferred trust observation — only clean files build familiarity.
                // Prevents malware from slowly earning trust through repeated execution.
                // Signer-aware (audit cross-cutting): authenticode signer feeds
                // drift detection — a signer change invalidates prior trust.
                // v0.1.12: a budget-truncated verdict must not earn familiarity
                // either — otherwise a slow-to-scan file accrues a confidence
                // discount on future scans purely because we ran out of time.
                if final_score == 0 && !result.infected && !rt_analysis_partial() {
                    if let Some(tg) = state.trust_graph() {
                        let file_key = path.to_string_lossy().to_lowercase();
                        let drift = tg.observe_with_signer(
                            &file_key,
                            crate::trust_graph::TrustNodeKind::Executable,
                            argus_verdict.explanation.signer.as_deref(),
                        );
                        if let Some(d) = drift {
                            warn!(file = %path.display(), drift = %d.explanation, "trust-graph signer drift");
                        }
                    }
                }

                // ── Behavioral sandbox routing (async) ────────────
                // ARGUS 26-75 + sandbox enabled → detonate on background thread.
                // Watcher thread NEVER blocks on sandbox (up to 35s).
                // If sandbox raises score into threat range, background thread
                // handles quarantine + notification autonomously.
                let sandbox_config = sandbox_config_static.clone();
                if crate::sandbox_worker::should_sandbox(argus_verdict.score, &sandbox_config)
                    && !result.infected
                    && path
                        .extension()
                        .map(|e| {
                            let e = e.to_string_lossy().to_lowercase();
                            matches!(
                                e.as_str(),
                                "exe" | "scr" | "com" | "bat" | "cmd" | "ps1" | "vbs" | "msi"
                            )
                        })
                        .unwrap_or(false)
                // Only detonate executable types.
                {
                    // Guard: don't sandbox the same file twice within SANDBOX_DEDUP_SECS.
                    let now = Instant::now();
                    // Evict stale entries.
                    sandbox_dedup
                        .retain(|_, ts| now.duration_since(*ts).as_secs() < SANDBOX_DEDUP_SECS);

                    if sandbox_dedup.contains_key(&path) {
                        debug!(
                            file = %path.display(),
                            "sandbox skipped: same file detonated recently"
                        );
                    } else {
                        sandbox_dedup.insert(path.clone(), now);

                        // Fire-and-forget: sandbox runs on background thread.
                        // Watcher continues scanning the next file immediately.
                        let sb_path = path.clone();
                        let sb_state = Arc::clone(&state);
                        let sb_score = argus_verdict.score;
                        let sb_sha256 = argus_verdict.sha256.clone();
                        let sb_dc = Arc::clone(&detections_count);
                        let sb_config = sandbox_config.clone();
                        let sb_roots = watched_roots_vec.clone();
                        if let Err(e) = std::thread::Builder::new()
                            .name("watcher-sandbox".into())
                            .spawn(move || {
                                sandbox_detonation_background(
                                    sb_path, sb_state, sb_score, sb_sha256, sb_dc, sb_config,
                                    sb_roots,
                                );
                            })
                        {
                            warn!(error = %e, "failed to spawn sandbox background thread");
                            // Not fatal — file already got pre-sandbox verdict.
                        }
                    }
                }

                // Trusted hash whitelist — skip quarantine for manually trusted files.
                if state.is_hash_trusted(&argus_verdict.sha256) {
                    debug!(file = %path.display(), sha256 = argus_verdict.sha256.as_str(), "hash trusted — skipping");
                    cache.record_with_metadata(&path, &path_meta, true);
                    continue;
                }

                // Unified verdict — one file, one detection.
                let (is_threat, threat_name_opt) = crate::ipc::unify_detection_filtered(
                    result.infected,
                    result.virus_name.as_deref(),
                    &argus_verdict,
                    &state.detection_exclusions(),
                );
                let threat_name = threat_name_opt.unwrap_or_default();

                // Update cache. An ARGUS analysis-error verdict (read
                // failure / sharing violation) is NOT a clean result —
                // never cache it; leaving the file uncached retries it on
                // the next modify event. Likewise a budget-TRUNCATED verdict
                // (v0.1.12): heuristic layers were skipped, so "score 0" means
                // "we didn't look", not "clean". Threats are still cached (a
                // positive is a positive); clean-looking partials stay uncached
                // so the next modify event re-scans them.
                if result.error.is_none()
                    && (is_threat || crate::ipc::argus_analysis_error(&argus_verdict).is_none())
                    && (is_threat || !rt_analysis_partial())
                {
                    cache.record_with_metadata(&path, &path_meta, !is_threat);
                }

                if is_threat {
                    warn!(
                        file = %path.display(),
                        threat = %threat_name,
                        argus_score = argus_verdict.score,
                        "REAL-TIME THREAT DETECTED",
                    );
                    detections_count.fetch_add(1, Ordering::Relaxed);

                    // Auto memory scan if the detected file is a running process.
                    // Fire-and-forget on a background thread (same pattern as
                    // sandbox detonation): scan_process_simple can burn its full
                    // 30s budget — running it inline would stall the single
                    // watcher thread right after a real detection, exactly when
                    // follow-on payloads of the same intrusion are being written.
                    let path_str_for_mem = path.to_string_lossy().to_string();
                    let mem_state = Arc::clone(&state);
                    let mem_score = argus_verdict.score;
                    if let Err(e) = std::thread::Builder::new()
                        .name("watcher-memscan".into())
                        .spawn(move || {
                            mem_state.auto_memory_scan_if_running(&path_str_for_mem, mem_score);
                        })
                    {
                        warn!(error = %e, "failed to spawn auto memory scan thread");
                        // Not fatal — detection + quarantine still proceed.
                    }

                    // TOCTOU Phase 3: revalidate identity BEFORE quarantine.
                    // Scanning wrong file is bad. Quarantining wrong file is CRITICAL.
                    if let Err(mismatch) = file_id.revalidate(&watched_roots_vec) {
                        warn!(
                            file = %path.display(),
                            reason = %mismatch,
                            "TOCTOU: identity changed before quarantine — PREVENTED"
                        );
                        race_diag
                            .quarantine_race_prevented
                            .fetch_add(1, Ordering::Relaxed);
                        // Still log the detection, but do NOT quarantine the wrong file.
                        let path_str = path.to_string_lossy().to_string();
                        state.log_activity(
                            "critical",
                            "watcher",
                            &format!(
                                "Threat detected but quarantine blocked (TOCTOU): {threat_name}"
                            ),
                            &path_str,
                            None,
                        );
                        continue; // Skip quarantine, move to next file.
                    }

                    // Auto-quarantine (identity verified).
                    let path_str = path.to_string_lossy().to_string();
                    match state.quarantine_file(&path_str, &threat_name, "realtime") {
                        Ok(q) => {
                            info!(id = %q.quarantine_id, "auto-quarantined by watcher");
                        }
                        Err(e) => {
                            warn!(%e, "auto-quarantine failed");
                            state.log_activity(
                                "critical",
                                "watcher",
                                &format!("Threat detected: {threat_name}"),
                                &path_str,
                                None,
                            );
                        }
                    }
                } else if !argus_verdict.findings.is_empty() {
                    debug!(
                        file = %path.display(),
                        score = argus_verdict.score,
                        findings = argus_verdict.findings.len(),
                        "watcher: {} (ARGUS {}/100)",
                        argus_verdict.verdict.label(),
                        argus_verdict.score,
                    );
                } else {
                    debug!(file = %path.display(), "watcher scan: clean");
                }
            }
        }
    }

    info!("real-time watcher loop exited");
}

/// Background sandbox detonation for watcher.
///
/// Runs on a dedicated thread so the watcher loop is never blocked (up to 35s)
/// by sandbox detonation. If behavioral signals push the score into threat
/// range, this function handles quarantine + logging autonomously.
fn sandbox_detonation_background(
    path: PathBuf,
    state: Arc<crate::ipc::AppState>,
    pre_sandbox_score: u32,
    sha256: String,
    detections_count: Arc<AtomicU64>,
    sandbox_config: crate::config::SandboxConfig,
    watched_roots: Vec<PathBuf>,
) {
    use tracing::{debug, info, warn};

    // TOCTOU: capture file identity BEFORE detonation. The detonation window
    // (up to timeout_sec + 5, ~35s) is by far the longest capture→quarantine
    // gap in the module; revalidate before the escalation quarantine below so
    // a same-path file swap during detonation doesn't get a different file
    // object encrypted-and-deleted.
    let file_id = file_identity::FileIdentity::capture(&path);

    let no_cancel = std::sync::atomic::AtomicBool::new(false);
    match crate::sandbox_worker::detonate(&path, &sandbox_config, &no_cancel) {
        Ok(sb_result) => {
            let backend = sb_result.backend_used.as_deref().unwrap_or("unknown");
            info!(
                file = %path.display(),
                detonation_ms = sb_result.detonation_time_ms,
                monitor_ms = sb_result.monitor_duration_ms,
                backend,
                "sandbox detonation completed (async)"
            );

            if sb_result.score_delta > 0 {
                let capped_delta = sb_result.score_delta.min(SANDBOX_MAX_SCORE_DELTA);
                let final_score = pre_sandbox_score
                    .saturating_add(capped_delta as u32)
                    .min(100);
                let final_verdict = argus::verdict::Verdict::from_score(final_score);

                info!(
                    file = %path.display(),
                    pre_score = pre_sandbox_score,
                    raw_delta = sb_result.score_delta,
                    capped_delta,
                    final_score,
                    findings = sb_result.findings.len(),
                    "sandbox behavioral signals (async)"
                );

                state.log_activity(
                    "info",
                    "sandbox",
                    &format!(
                        "[BehavioralRuntime] Sandbox: {} — {} findings, score_delta={} (capped from {}), final_score={}",
                        path.file_name().unwrap_or_default().to_string_lossy(),
                        sb_result.findings.len(),
                        capped_delta,
                        sb_result.score_delta,
                        final_score,
                    ),
                    &sb_result.status,
                    None,
                );

                // If sandbox pushes score into threat range, quarantine now.
                //
                // ARGUS_ONLY_QUARANTINE_SCORE, not a literal. This path is
                // reached only under `!result.infected` (see the routing
                // guard), so it is ALWAYS an ARGUS-only decision — exactly
                // the case unify_detection_filtered raises the bar for. It
                // used a hardcoded 76 while its comment claimed to match
                // that function, so every detonation landing in 76-84
                // quarantined a file the main path deliberately spares. With
                // should_sandbox gating on 26-75 and the delta capped at
                // +50, that band is not a corner case: it is the common
                // outcome of a detonation that found something mild.
                if final_score >= crate::ipc::ARGUS_ONLY_QUARANTINE_SCORE && path.exists() {
                    // Re-check trusted hash in case user whitelisted during detonation.
                    if state.is_hash_trusted(&sha256) {
                        debug!(file = %path.display(), "sandbox escalation skipped: hash trusted");
                        return;
                    }

                    let threat_name =
                        format!("ARGUS.Behavioral.{}.{}", final_verdict.label(), final_score);

                    // TOCTOU: revalidate identity across the detonation window
                    // BEFORE quarantine (mirror of the main threat path).
                    match &file_id {
                        Some(fid) => {
                            if let Err(mismatch) = fid.revalidate(&watched_roots) {
                                warn!(
                                    file = %path.display(),
                                    reason = %mismatch,
                                    "TOCTOU: identity changed during detonation — quarantine PREVENTED"
                                );
                                return;
                            }
                        }
                        None => {
                            // Reparse point or unresolvable at capture → reject.
                            debug!(file = %path.display(), "sandbox escalation skipped: no valid file identity");
                            return;
                        }
                    }

                    warn!(
                        file = %path.display(),
                        threat = %threat_name,
                        "SANDBOX ESCALATION: quarantining post-detonation"
                    );
                    detections_count.fetch_add(1, Ordering::Relaxed);

                    let path_str = path.to_string_lossy().to_string();
                    state.auto_memory_scan_if_running(&path_str, final_score);

                    match state.quarantine_file(&path_str, &threat_name, "realtime-sandbox") {
                        Ok(q) => {
                            info!(id = %q.quarantine_id, "auto-quarantined by sandbox escalation");
                        }
                        Err(e) => {
                            warn!(%e, "sandbox escalation quarantine failed");
                            state.log_activity(
                                "critical",
                                "watcher",
                                &format!("Sandbox threat: {threat_name}"),
                                &path_str,
                                None,
                            );
                        }
                    }
                }
            }
        }
        Err(e) => {
            debug!(file = %path.display(), error = %e, "sandbox detonation skipped (async)");
        }
    }
}

/// Directories where high rewrite rates are normal (browser temp, build tools).
/// FISH should NOT count these as potential ransomware activity.
fn is_fish_excluded_path(path: &std::path::Path) -> bool {
    let p = path.to_string_lossy().to_lowercase();
    // Temp directories — browsers, apps, ClamAV constantly rewrite here.
    p.contains("\\temp\\") || p.contains("/temp/")
    || p.contains("\\tmp\\") || p.contains("/tmp/")
    // ClamAV extraction temp files.
    || p.contains("html-tmp.") || p.contains("ole2-tmp.") || p.contains("clamav-")
    // Browser caches.
    || p.contains("\\cache\\") || p.contains("\\code cache\\")
    || p.contains("\\gpucache\\") || p.contains("\\shadercache\\")
    // Build artifacts.
    || p.contains("\\target\\") || p.contains("\\node_modules\\")
    || p.contains("\\.git\\") || p.contains("\\dist\\")
    // Log rotation.
    || p.contains("\\logs\\") || p.ends_with(".log")
    // AppData noise — browser profiles, extensions, etc.
    || p.contains("\\appdata\\local\\") && (
        p.contains("\\user data\\") || p.contains("\\extensions\\")
        || p.contains("\\indexeddb\\") || p.contains("\\local storage\\")
    )
}

/// How long a `RenameMode::From` waits for its matching `To`.
///
/// ReadDirectoryChangesW emits the pair back to back out of one buffer, so
/// this only has to survive scheduling jitter. Short on purpose: a `From`
/// whose `To` never arrives (moved out of a watched root, or the watcher
/// restarted between them) must expire rather than pair with an unrelated
/// rename minutes later and invent an extension mutation that never happened.
const RENAME_PAIR_TTL: Duration = Duration::from_secs(2);

/// Classify a completed rename: extension change, or plain rename.
///
/// Split out so it is testable without a notify backend - which matters,
/// because the bug this replaced was invisible to every test that fed it
/// synthetic `RenameMode::Both` events the real backend never produces.
fn classify_rename(old: &std::path::Path, new: &std::path::Path) -> MutationKind {
    let ext = |p: &std::path::Path| {
        p.extension().unwrap_or_default().to_string_lossy().to_string()
    };
    let name = |p: &std::path::Path| {
        p.file_name().unwrap_or_default().to_string_lossy().to_string()
    };
    let (old_ext, new_ext) = (ext(old), ext(new));
    if old_ext != new_ext && !old_ext.is_empty() {
        MutationKind::ExtensionMutation { old_ext, new_ext }
    } else {
        MutationKind::Rename { old_name: name(old), new_name: name(new) }
    }
}

/// Feed a notify event into the FISH MutationWindow.
///
/// WINDOWS EMITS RENAMES AS TWO EVENTS. This used to key renames off
/// `Modify(Name(RenameMode::Both))`, which notify's Windows backend never
/// produces - it emits `RenameMode::From` then `RenameMode::To`
/// (notify-7.0.0/src/windows.rs, FILE_ACTION_RENAMED_OLD_NAME / _NEW_NAME).
/// So `MutationKind::Rename` and `ExtensionMutation` were unreachable in
/// production, and the two canonical ransomware signals FISH exists to
/// catch - mass rename, and mass mutation to .locked/.crypt - could never
/// fire. `MutationWindow::evaluate` counted both as permanently zero, which
/// left only RewriteBurst and SlowBurn live. The `From` is stashed here and
/// paired with the `To` that follows.
fn fish_feed_event(event: &Event, state: &Arc<crate::ipc::AppState>) {
    use std::sync::Mutex as StdMutex;
    use std::sync::OnceLock;
    static PENDING_RENAME: OnceLock<StdMutex<Option<(PathBuf, Instant)>>> = OnceLock::new();
    let pending = PENDING_RENAME.get_or_init(|| StdMutex::new(None));

    let now = Instant::now();

    let kind = match &event.kind {
        EventKind::Create(_) => Some(MutationKind::Create),
        EventKind::Modify(ModifyKind::Data(_)) | EventKind::Modify(ModifyKind::Any) => {
            Some(MutationKind::Rewrite)
        }
        EventKind::Modify(ModifyKind::Name(RenameMode::From)) => {
            // Stash and wait for the To. Nothing is recorded yet: a rename
            // is one mutation, not two.
            if let Some(p) = event.paths.first() {
                let mut g = pending.lock().unwrap_or_else(|e| e.into_inner());
                *g = Some((p.clone(), now));
            }
            None
        }
        EventKind::Modify(ModifyKind::Name(RenameMode::To)) => {
            let prev = {
                let mut g = pending.lock().unwrap_or_else(|e| e.into_inner());
                match g.take() {
                    Some((old, at)) if now.duration_since(at) <= RENAME_PAIR_TTL => Some(old),
                    // Expired, or none: fall through to treating this as a
                    // fresh arrival rather than pairing it with a stale From.
                    _ => None,
                }
            };
            match (prev, event.paths.first()) {
                (Some(old), Some(new)) => Some(classify_rename(&old, new)),
                // A To with no live From is a file appearing under a new
                // name from the watcher's point of view.
                _ => Some(MutationKind::Create),
            }
        }
        EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => {
            // notify sends both old + new paths in event.paths[0..2].
            if event.paths.len() >= 2 {
                let old = event.paths[0]
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                let new = event.paths[1]
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                // Check extension mutation.
                let old_ext = event.paths[0]
                    .extension()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                let new_ext = event.paths[1]
                    .extension()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                if old_ext != new_ext && !old_ext.is_empty() {
                    Some(MutationKind::ExtensionMutation { old_ext, new_ext })
                } else {
                    Some(MutationKind::Rename {
                        old_name: old,
                        new_name: new,
                    })
                }
            } else {
                None
            }
        }
        EventKind::Remove(_) => Some(MutationKind::Delete),
        _ => None,
    };

    if let Some(mutation_kind) = kind {
        for path in &event.paths {
            if fish_should_skip_path(path) {
                continue;
            }
            let decision = state.fish_record(FileMutationEvent {
                path: path.clone(),
                kind: mutation_kind.clone(),
                timestamp: now,
            });
            match &decision {
                FishDecision::Normal => {}
                FishDecision::RenameBurst { count, window_secs } => {
                    warn!(count, window_secs, "FISH: rename burst detected");
                    fish_handle_burst(
                        state,
                        path,
                        &format!("Rename burst: {count} files in {window_secs}s"),
                    );
                }
                FishDecision::RewriteBurst { count, window_secs } => {
                    warn!(count, window_secs, "FISH: rewrite burst detected");
                    fish_handle_burst(
                        state,
                        path,
                        &format!("Rewrite burst: {count} files in {window_secs}s"),
                    );
                }
                FishDecision::ExtensionMutation { count, pattern } => {
                    warn!(
                        count,
                        pattern = pattern.as_str(),
                        "FISH: extension mutation burst"
                    );
                    fish_handle_burst(
                        state,
                        path,
                        &format!("Extension mutation: {count} files → .{pattern}"),
                    );
                }
                FishDecision::SlowBurn { count, window_secs } => {
                    warn!(count, window_secs, "FISH: slow-burn mass mutation detected");
                    fish_handle_burst(
                        state,
                        path,
                        &format!("Slow-burn: {count} files mutated in {window_secs}s"),
                    );
                }
                FishDecision::Cooldown {
                    original,
                    suppressed_count,
                } => {
                    debug!(
                        original = original.as_str(),
                        suppressed = suppressed_count,
                        "FISH: cooldown"
                    );
                }
            }
            // Only record once per event batch (use first path).
            break;
        }
    }
}

fn fish_should_skip_path(path: &std::path::Path) -> bool {
    if crate::scan::is_sentinella_path(path) || crate::scan::is_build_or_dev_path(path) {
        return true;
    }
    // Exclude noisy directories from FISH — normal high-rewrite locations.
    if is_fish_excluded_path(path) {
        return true;
    }

    if let Some(ext) = path.extension().and_then(|v| v.to_str()) {
        let ext = ext.to_ascii_lowercase();
        if matches!(
            ext.as_str(),
            "tmp"
                | "temp"
                | "log"
                | "bak"
                | "swp"
                | "swo"
                | "lock"
                | "cache"
                | "db-journal"
                | "db-wal"
                | "db-shm"
        ) {
            return true;
        }
    }

    false
}

/// Handle a FISH burst — observe or take active response.
/// At most one observe-mode FISH row per this interval.
const OBSERVE_LOG_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// Should this observe-mode burst be written to the activity log, and how
/// many were folded into it?
///
/// `Some(n)` = write, having suppressed `n` since the last row.
/// `None` = stay quiet.
fn fish_observe_suppressed_since_last_log() -> Option<u64> {
    use std::sync::Mutex as StdMutex;
    use std::sync::OnceLock;
    static LAST: OnceLock<StdMutex<(Option<Instant>, u64)>> = OnceLock::new();
    let cell = LAST.get_or_init(|| StdMutex::new((None, 0)));
    let mut g = cell.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    match g.0 {
        Some(last) if now.duration_since(last) < OBSERVE_LOG_INTERVAL => {
            g.1 += 1;
            None
        }
        _ => {
            let folded = g.1;
            *g = (Some(now), 0);
            Some(folded)
        }
    }
}

fn fish_handle_burst(
    state: &Arc<crate::ipc::AppState>,
    affected_path: &std::path::Path,
    description: &str,
) {
    let fish_diag = state.fish_diagnostics();
    // observe_only is the master switch: a config with observe_only = true
    // must NEVER take process action, even if active_response says
    // "suspend"/"terminate" (stale or misread knob).
    let response_mode = if fish_diag.observe_only {
        ResponseType::Observe
    } else {
        ResponseType::from_config(&fish_diag.active_response)
    };

    match response_mode {
        ResponseType::Observe => {
            // TELEMETRY, and it must not crowd the activity log.
            //
            // In observe mode this is not an event the user can act on: FISH
            // saw volume, took no action, and the running totals live in
            // `fish_diagnostics`. Writing a row per burst filled the log on a
            // real machine — 50 entries covering 173 minutes, ALL of them
            // FISH, which evicted the engine and update events someone was
            // trying to read. The tracing line below keeps the full detail in
            // the daemon log, where telemetry belongs.
            //
            // One row per OBSERVE_LOG_INTERVAL, carrying however many bursts
            // were folded into it, so the signal survives without the flood.
            let suppressed = fish_observe_suppressed_since_last_log();
            if let Some(n) = suppressed {
                let detail = if n > 0 {
                    format!("Observe-only — no action taken ({n} similar since the last entry)")
                } else {
                    "Observe-only — no action taken".to_string()
                };
                state.log_activity("warning", "fish", description, &detail, None);
            }
        }
        ResponseType::Suspend | ResponseType::Terminate => {
            // Find suspect processes in the affected directory.
            let affected_dir = affected_path.parent().unwrap_or(affected_path);
            let suspects = find_suspect_processes(affected_dir);

            if suspects.is_empty() {
                warn!("FISH: no suspect process found — logging only");
                state.log_activity(
                    "warning",
                    "fish",
                    description,
                    "Active response: no suspect process identified",
                    None,
                );
                return;
            }

            #[allow(clippy::never_loop)]
            for suspect in &suspects {
                let action_name = if response_mode == ResponseType::Suspend {
                    "suspend"
                } else {
                    "terminate"
                };

                warn!(
                    pid = suspect.pid,
                    process = suspect.name.as_str(),
                    reason = suspect.suspicion_reason.as_str(),
                    action = action_name,
                    "FISH: active response on suspect process"
                );

                let result = if response_mode == ResponseType::Suspend {
                    suspend_process(suspect.pid)
                } else {
                    terminate_process(suspect.pid)
                };

                match result {
                    Ok(()) => {
                        state.log_activity(
                            "critical",
                            "fish",
                            &format!("FISH {action_name}: {} (PID {})", suspect.name, suspect.pid),
                            &format!("{description} — {}", suspect.suspicion_reason),
                            None,
                        );
                        // Record in FISH counters.
                        if response_mode == ResponseType::Suspend {
                            state.fish_record_suspension();
                        } else {
                            state.fish_record_termination();
                        }
                    }
                    Err(e) => {
                        error!(
                            pid = suspect.pid,
                            error = e.as_str(),
                            "FISH: active response failed"
                        );
                        state.log_activity(
                            "warning",
                            "fish",
                            &format!(
                                "FISH {action_name} failed: {} (PID {})",
                                suspect.name, suspect.pid
                            ),
                            &e,
                            None,
                        );
                    }
                }
                // Only act on first suspect per burst.
                break;
            }
        }
    }
}

fn collect_overflow_rescan_files(dir: &std::path::Path, out: &mut Vec<PathBuf>, cap: usize) {
    // Recurse (depth-limited) so dropped events in subdirectories are also
    // recovered after a storm — a flat top-level rescan missed any file
    // written deeper in the overflowed tree. Files still pass the full skip
    // filter chain (should_skip_file, exclusions, extension filter) in the
    // main scan loop, so only reparse-point and depth guards are needed here.
    const MAX_DEPTH: u32 = 8;
    fn walk(dir: &std::path::Path, out: &mut Vec<PathBuf>, max_len: usize, depth: u32) {
        if depth > MAX_DEPTH || out.len() >= max_len {
            return;
        }
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            if out.len() >= max_len {
                break;
            }
            let path = entry.path();
            // Never follow reparse points (symlink/junction loops).
            if file_identity::is_reparse_point(&path) {
                continue;
            }
            if path.is_file() {
                out.push(path);
            } else if path.is_dir() {
                walk(&path, out, max_len, depth + 1);
            }
        }
    }
    let max_len = DEBOUNCE_CAP.saturating_add(cap);
    walk(dir, out, max_len, 0);
}

#[cfg(test)]
mod windows_event_shape_tests {
    use super::*;
    use std::path::Path;

    /// The five kinds notify 7's ReadDirectoryChangesW backend actually
    /// emits, from notify-7.0.0/src/windows.rs. Every filter in this file
    /// has to be written against THESE, not against the inotify shapes.
    fn windows_kinds() -> Vec<EventKind> {
        vec![
            EventKind::Create(notify::event::CreateKind::Any),
            EventKind::Remove(notify::event::RemoveKind::Any),
            EventKind::Modify(ModifyKind::Any),
            EventKind::Modify(ModifyKind::Name(RenameMode::From)),
            EventKind::Modify(ModifyKind::Name(RenameMode::To)),
        ]
    }

    fn dominated(kind: &EventKind) -> bool {
        matches!(
            kind,
            EventKind::Create(_)
                | EventKind::Modify(ModifyKind::Data(_))
                | EventKind::Modify(ModifyKind::Any)
                | EventKind::Modify(ModifyKind::Name(RenameMode::Both))
                | EventKind::Modify(ModifyKind::Name(RenameMode::To))
        )
    }

    #[test]
    fn file_creation_on_windows_reaches_the_scanner() {
        // The defect: the filter listed Create(CreateKind::File), an inotify
        // shape the Windows backend never emits, and did NOT list
        // Create(CreateKind::Any), which is what it does emit. A created
        // file matched no arm at all. Pinning CreateKind::File again fails
        // this.
        let created = EventKind::Create(notify::event::CreateKind::Any);
        assert!(dominated(&created), "FILE_ACTION_ADDED must reach the scanner");
        assert!(
            matches!(created, EventKind::Create(_)),
            "the fast path keys off this and had never once run in production"
        );
    }

    #[test]
    fn every_windows_kind_is_classified_deliberately() {
        // Not "all pass" - Remove SHOULD be filtered out for scanning. The
        // point is that no Windows kind falls through by accident because
        // the filter was written for another platform's taxonomy.
        for k in windows_kinds() {
            let expected = !matches!(k, EventKind::Remove(_))
                && !matches!(k, EventKind::Modify(ModifyKind::Name(RenameMode::From)));
            assert_eq!(
                dominated(&k), expected,
                "{k:?} is classified wrong for the Windows backend"
            );
        }
    }

    #[test]
    fn an_extension_mutation_is_recognised_from_a_split_rename() {
        // The ransomware signal: notes.docx -> notes.docx.locked, delivered
        // by Windows as From then To. Keyed off RenameMode::Both (never
        // emitted) this was unreachable, so FISH could not see the single
        // most characteristic ransomware behaviour there is.
        let k = classify_rename(Path::new(r"C:\docs
otes.docx"), Path::new(r"C:\docs
otes.locked"));
        match k {
            MutationKind::ExtensionMutation { old_ext, new_ext } => {
                assert_eq!(old_ext, "docx");
                assert_eq!(new_ext, "locked");
            }
            other => panic!("expected ExtensionMutation, got {other:?}"),
        }
    }

    #[test]
    fn a_plain_rename_is_not_an_extension_mutation() {
        // Or every ordinary "draft.docx -> final.docx" would feed the
        // extension-mutation counter and FISH would alert on normal work.
        let k = classify_rename(Path::new(r"C:\d\draft.docx"), Path::new(r"C:\dinal.docx"));
        assert!(matches!(k, MutationKind::Rename { .. }), "got {k:?}");
        // An extensionless original is a rename too - not a mutation FROM
        // nothing, which would misfire on every file without a suffix.
        let k = classify_rename(Path::new(r"C:\d\README"), Path::new(r"C:\d\README.txt"));
        assert!(matches!(k, MutationKind::Rename { .. }), "got {k:?}");
    }
}
