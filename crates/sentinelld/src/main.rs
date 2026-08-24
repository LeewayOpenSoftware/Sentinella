//! `sentinelld` — the Sentinella daemon.
//!
//! Hosts the ClamAV scanning engine, serves the JSON-RPC IPC protocol,
//! manages the quarantine vault, drives the real-time watcher, and
//! orchestrates signature updates.

pub mod amsi;
mod acl;
mod argus_worker;
pub mod calibration;
#[allow(dead_code)]
mod clamav_worker;
mod config;
pub mod convergence;
mod devmode;
pub mod paths;
pub mod runtime_integrity;
// Sandbox worker is called from scan flow when config.sandbox.enabled = true.
pub mod db;
pub mod ecosystem;
mod engine;
mod fish;
mod footprint;
mod idle_scanner;
mod ipc;
mod memory_scanner;
mod orchestrator;
pub mod persistence;
pub mod plm;
mod quarantine;
#[allow(dead_code)]
mod sandbox_worker;
mod scan;
mod scheduler;
mod targeting;
pub mod trust_graph;
mod updater;
mod watcher;
mod web_protection;
mod win_process;

use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Clone)]
#[command(name = "sentinelld", about = "Sentinella antivirus daemon")]
struct Args {
    /// Run in foreground (console mode). When false, enters Windows service mode.
    #[arg(long)]
    foreground: bool,

    /// Config file path override.
    #[arg(long)]
    config: Option<String>,

    /// Log level override (trace, debug, info, warn, error).
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Directory containing libclamav.dll and its dependencies.
    #[arg(long)]
    dll_dir: Option<String>,

    /// Directory containing ClamAV signature databases (.cvd files).
    #[arg(long)]
    db_dir: Option<String>,

    /// Path to the SQLite state database.
    #[arg(long)]
    state_db: Option<String>,

    /// Override runtime root directory (PathManager).
    #[arg(long)]
    runtime_root: Option<String>,

    /// Audit mode: reduced features for stability after repeated crashes.
    #[arg(long)]
    audit_mode: bool,
}

/// Shared state for passing CLI args to the service entry point.
static SERVICE_ARGS: std::sync::OnceLock<Args> = std::sync::OnceLock::new();

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if args.foreground {
        // Foreground mode: run directly with tokio runtime.
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(run_daemon(args, None))
    } else {
        // Windows service mode.
        #[cfg(target_os = "windows")]
        {
            SERVICE_ARGS.set(args).ok();
            run_as_windows_service()
        }
        #[cfg(not(target_os = "windows"))]
        {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(run_daemon(args, None))
        }
    }
}

#[cfg(target_os = "windows")]
fn run_as_windows_service() -> anyhow::Result<()> {
    use windows_service::service_dispatcher;
    service_dispatcher::start("SentinellaDaemon", service_main)
        .map_err(|e| anyhow::anyhow!("service dispatcher failed: {e}"))?;
    Ok(())
}

#[cfg(target_os = "windows")]
extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    let args = SERVICE_ARGS.get().cloned().unwrap_or_else(|| Args {
        foreground: false,
        config: None,
        log_level: "info".into(),
        dll_dir: None,
        db_dir: None,
        state_db: None,
        runtime_root: None,
        audit_mode: false,
    });

    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown_flag = Arc::clone(&shutdown);

    let status_handle =
        match service_control_handler::register("SentinellaDaemon", move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                shutdown_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("service control handler registration failed: {e}");
                return;
            }
        };

    // Report: starting.
    let _ = status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::from_secs(30),
        process_id: None,
    });

    // Build and run tokio runtime.
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("tokio runtime failed: {e}");
            let _ = status_handle.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(1),
                checkpoint: 0,
                wait_hint: std::time::Duration::ZERO,
                process_id: None,
            });
            return;
        }
    };

    // Report: running.
    let _ = status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::ZERO,
        process_id: None,
    });

    // Audit fix: report StopPending promptly when the SCM Stop arrives, with
    // a wait_hint, so services.msc doesn't show "Running" during teardown and
    // SCM doesn't treat the stop as hung. A watcher task fires it once.
    {
        let h = status_handle;
        let sd = Arc::clone(&shutdown);
        rt.spawn(async move {
            loop {
                if sd.load(std::sync::atomic::Ordering::Relaxed) {
                    let _ = h.set_service_status(ServiceStatus {
                        service_type: ServiceType::OWN_PROCESS,
                        current_state: ServiceState::StopPending,
                        controls_accepted: ServiceControlAccept::empty(),
                        exit_code: ServiceExitCode::Win32(0),
                        checkpoint: 1,
                        wait_hint: std::time::Duration::from_secs(30),
                        process_id: None,
                    });
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        });
    }

    // Run daemon until shutdown signal. run_daemon now observes `shutdown`
    // itself and performs graceful cleanup before returning.
    let exit_code = match rt.block_on(run_daemon(args, Some(Arc::clone(&shutdown)))) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("daemon error: {e}");
            1
        }
    };

    // Report: stopped.
    let _ = status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(exit_code),
        checkpoint: 0,
        wait_hint: std::time::Duration::ZERO,
        process_id: None,
    });
}

async fn run_daemon(
    args: Args,
    shutdown: Option<Arc<std::sync::atomic::AtomicBool>>,
) -> anyhow::Result<()> {
    // Initialize PathManager — centralized path resolution.
    if let Some(ref root) = args.runtime_root {
        paths::init(std::path::PathBuf::from(root));
    } else {
        paths::init_auto();
    }
    let p = paths::paths();
    if let Err(e) = p.ensure_dirs() {
        // Audit fix: under the Windows service, `std::process::exit(1)` here
        // bypassed the SCM `Stopped` status report → SCM saw the process die
        // mid-StartPending with no clean exit code. Return an error so the
        // caller reports Stopped(exit_code) properly.
        return Err(anyhow::anyhow!("failed to create runtime directories: {e}"));
    }

    // Initialize tracing with file + stdout output.
    let log_dir = p.logs_dir();

    // Log rotation: if current log > 10 MB, rotate.
    let log_path = log_dir.join("sentinelld.log");
    if let Ok(meta) = std::fs::metadata(&log_path) {
        if meta.len() > 10 * 1024 * 1024 {
            // Rotate: .log.2 → delete, .log.1 → .log.2, .log → .log.1
            let _ = std::fs::remove_file(log_dir.join("sentinelld.log.2"));
            let _ = std::fs::rename(
                log_dir.join("sentinelld.log.1"),
                log_dir.join("sentinelld.log.2"),
            );
            let _ = std::fs::rename(&log_path, log_dir.join("sentinelld.log.1"));
        }
    }

    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .ok();

    if let Some(file) = log_file {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        // Build log filter: apply user-requested level but suppress noisy
        // third-party crates. wasmtime/cranelift emit huge volumes at debug;
        // ClamAV's scanned_bytes UINT32_MAX warning is a known harmless issue.
        let filter_str = format!(
            "{level},walrus=warn,wasmtime=warn,wasmtime_internal_cranelift=warn,cranelift_codegen=warn,regalloc2=warn,goblin=warn",
            level = args.log_level,
        );
        let filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&filter_str));

        let stdout_layer = tracing_subscriber::fmt::layer().with_target(true);
        let file_layer = tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(file));

        tracing_subscriber::registry()
            .with(filter)
            .with(stdout_layer)
            .with(file_layer)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new(&args.log_level)),
            )
            .init();
    }

    info!(
        version = sentinella_common::PRODUCT_VERSION,
        "sentinelld starting"
    );

    // ── Data-root DACL hardening (v0.1.12, workstream I) ───────────
    // Compare-first, idempotent: repairs the ProgramData root to a
    // SYSTEM+Administrators-only policy when it deviates (e.g. a tree
    // first created by a user-context process, or plain %ProgramData%
    // inheritance which grants Users create/append). Runs before config
    // load and before any subsystem touches secrets under the root.
    // Failure is logged loudly and never blocks startup (see acl.rs).
    acl::startup_hardening(p);

    // Load configuration.
    let config = config::load(args.config.as_deref())?;
    info!(?config.realtime_enabled, "configuration loaded");

    // ── Web protection (DNS-layer filtering) starts FIRST ───────────
    // It used to start after the ClamAV engine load below, which left a
    // minutes-long unfiltered window at every boot (the service is
    // delayed-auto and the engine compile is the slow part). Nothing
    // web protection touches depends on the engine, the state DB, or the
    // IPC server: it needs only the config, `paths` (initialized above)
    // and the DACL-hardened data root (hardened above). So it starts
    // here, and the handle is PUBLISHED later, once `server` exists.
    //
    // Default-OFF; `start` never fails the daemon — a refusal is reported
    // through the status surface and the log, because a daemon that will
    // not start because its DNS filter could not is worse than one that
    // starts with filtering off. A refusal classified transient is retried
    // in the background (spawn_retry below) instead of disabling the
    // feature until a manual service restart.
    //
    // When this succeeds AND the boot reconciler's task is registered, an
    // NRPT rule is installed and the machine's DNS goes through the proxy.
    // Without that task — any development build — it serves but installs
    // nothing, and you reach it directly: `nslookup name 127.0.0.1`.
    let web_protection = web_protection::WebProtection::start(&config.web_protection).await;
    let web_protection = Arc::new(tokio::sync::Mutex::new(web_protection));
    // Handle-publish channel: retries re-publish through the sender; the
    // forwarder (spawned once `server` exists) pushes them into AppState.
    let (wp_handle_tx, mut wp_handle_rx) =
        tokio::sync::watch::channel(web_protection.lock().await.handle());
    let wp_retry = web_protection::spawn_retry(
        Arc::clone(&web_protection),
        config.web_protection.clone(),
        wp_handle_tx,
    )
    .await;

    // Resolve ClamAV paths.
    // Priority: CLI args > auto-detect relative to exe.
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()));

    let dll_dir = args.dll_dir.map(PathBuf::from).or_else(|| {
        // Auto-detect: look for libclamav.dll in common locations.
        // The CWD-relative dev-tree path is only trusted in debug builds:
        // in release, a planted build/clamav/... under the daemon's CWD
        // (C:\Windows\System32 under the SCM, or wherever --foreground was
        // launched) must never be auto-selected as the engine DLL directory.
        #[cfg(debug_assertions)]
        let dev_candidate = Some(PathBuf::from("build/clamav/libclamav/Release"));
        #[cfg(not(debug_assertions))]
        let dev_candidate: Option<PathBuf> = None;
        let candidates = [exe_dir.as_ref().map(|d| d.join(".")), dev_candidate];
        for c in candidates.iter().flatten() {
            if c.join("libclamav.dll").exists() {
                info!(path = %c.display(), "auto-detected DLL directory");
                return Some(c.clone());
            }
        }
        None
    });

    let db_dir = args.db_dir.map(PathBuf::from).or_else(|| {
        let candidates = [
            Some(p.signatures_dir()),
            exe_dir.as_ref().map(|d| d.join("signatures")),
        ];
        for c in candidates.iter().flatten() {
            if c.exists() && c.is_dir() {
                info!(path = %c.display(), "auto-detected signature directory");
                return Some(c.clone());
            }
        }
        None
    });

    if dll_dir.is_none() {
        warn!("libclamav.dll directory not found — daemon will start without scanning");
    }
    if db_dir.is_none() {
        warn!("signature database directory not found — run freshclam first");
    }

    // Open persistent state database.
    let state_db_path = args
        .state_db
        .map(PathBuf::from)
        .unwrap_or_else(|| p.state_db());
    let database = match db::Database::open(&state_db_path) {
        Ok(d) => {
            info!(path = %state_db_path.display(), "state database opened");
            Some(d)
        }
        Err(e) => {
            warn!(%e, "failed to open state database — history will not persist");
            None
        }
    };

    // Start IPC server with engine + database.
    let server = ipc::Server::with_engine(dll_dir, db_dir, database)?;
    info!("IPC server listening");

    // ── Self-binary integrity (TOFU) ────────────────────────────────
    // Hash the daemon's own exe + sibling workers against the stored
    // baseline. First start creates the baseline; subsequent starts
    // surface drift via the `health` IPC's `binary_integrity_drift` flag.
    // Fail-loud (warn + flag), not fail-closed — admins upgrade binaries
    // legitimately, and a daemon that refuses to start can't tell anyone.
    {
        let state_dir = p.state_dir();
        // Reuse the runtime-integrity vault key — no second secret to manage.
        match runtime_integrity::IntegrityVault::init(&state_dir) {
            Ok(vault) => {
                let key = *vault.key_bytes();
                match runtime_integrity::verify_or_init_binaries(&state_dir, &key) {
                    Ok(report) => {
                        if report.baseline_lost {
                            // Baseline existed before but the manifest was
                            // deleted/emptied/corrupted — the classic way to
                            // get replaced binaries silently re-trusted.
                            // Already re-baselined (fail-open); flag drift.
                            error!("binary integrity: baseline manifest vanished/corrupt since last start — re-baselined, flagging drift");
                            server.state().set_binary_integrity_drift(true);
                        } else if report.tofu_initialized {
                            info!("binary integrity: TOFU baseline written");
                        } else if report.has_drift() {
                            for p in &report.drifted {
                                error!(path = %p.display(), "binary integrity: HASH MISMATCH (tamper signal)");
                            }
                            server.state().set_binary_integrity_drift(true);
                        } else {
                            if !report.new_entries.is_empty() {
                                for p in &report.new_entries {
                                    warn!(path = %p.display(), "binary integrity: new binary not in baseline");
                                }
                            }
                            if !report.missing.is_empty() {
                                for p in &report.missing {
                                    warn!(path = %p.display(), "binary integrity: baseline binary missing from disk");
                                }
                            }
                            info!(
                                verified = report.verified.len(),
                                "binary integrity: all known binaries match baseline"
                            );
                        }
                    }
                    Err(e) => warn!(%e, "binary integrity check failed"),
                }
            }
            Err(e) => warn!(%e, "integrity vault init failed — binary check skipped"),
        }
    }

    // ── Config tamper detection (HMAC sidecar) ──────────────────────
    // Verify the already-loaded config against the HMAC sidecar laid down
    // by the last save (no second load — that re-read/re-validated/re-saved
    // the file for nothing). Drift means someone edited sentinelld.toml
    // outside the daemon (manual TOML edit, GPO push, scripted tweak).
    // Fail-loud: keep the loaded values, surface via `health.config_drift`.
    match config::load_verified(args.config.as_deref(), config.clone()) {
        Ok((_cfg, drift)) => {
            if drift {
                error!("config drift: sentinelld.toml HMAC sidecar does NOT match file contents");
                server.state().set_config_drift(true);
            }
        }
        Err(e) => warn!(%e, "config verify failed — drift detection unavailable this start"),
    }

    // Load ClamAV isolation config.
    if config.clamav_isolation == "subprocess" {
        server
            .state()
            .set_clamav_subprocess(true, config.clamav_worker_timeout_sec);
        info!("ClamAV isolation: subprocess mode");
    }

    // Check sandbox binary availability.
    if config.sandbox.enabled {
        if sandbox_worker::find_sandboxd_public().is_some() {
            info!("behavioral sandbox enabled (experimental) — sandboxd found");
        } else {
            warn!(
                "sandbox.enabled=true but sandboxd.exe not found — sandbox detonation will not work"
            );
        }
    }

    // Load FISH config from config file.
    server.state().load_fish_config(config.fish.clone());

    // Publish the web-protection handle (the subsystem started BEFORE the
    // engine load — see above) so `webprotection.status` can answer, and
    // forward every retry-driven re-publish into AppState. The subsystem
    // itself stays owned here behind the mutex, because stop() needs to
    // rendezvous with whatever attempt is current and AppState outlives
    // process exit.
    server
        .state()
        .set_web_protection(wp_handle_rx.borrow_and_update().clone());
    {
        let wp_state = Arc::clone(server.state());
        tokio::spawn(async move {
            while wp_handle_rx.changed().await.is_ok() {
                wp_state.set_web_protection(wp_handle_rx.borrow_and_update().clone());
            }
        });
    }

    // Load detection exclusions from config.
    if !config.excluded_detections.is_empty() {
        info!(
            count = config.excluded_detections.len(),
            "detection exclusions loaded"
        );
        server
            .state()
            .load_detection_exclusions(config.excluded_detections.clone());
    }
    if !config.trusted_hashes.is_empty() {
        info!(count = config.trusted_hashes.len(), "trusted hashes loaded");
        server
            .state()
            .load_trusted_hashes(config.trusted_hashes.clone());
    }

    // Log memory footprint at startup (post-engine-load baseline).
    server.state().record_startup_footprint();
    let startup_footprint = server.state().capture_footprint();
    footprint::log_footprint("startup", &startup_footprint);
    let pressure = server.state().update_pressure();
    info!(?pressure, "initial memory pressure state");

    // Set daemon operating mode.
    if args.audit_mode {
        server.state().set_audit_mode(true);
        warn!("AUDIT MODE — reduced features for stability recovery");
        warn!("  idle scanner: disabled");
        warn!("  external ARGUS: forced");
        warn!("  worker concurrency: reduced");
    }

    // Start real-time watcher (if engine is available).
    // Watcher runs even in audit mode (minimal protection).
    //
    // ...but NOT when the master switch is off. `realtime_enabled` was
    // written by `protection.set_critical` (a UAC-gated, challenge-token
    // path) and persisted, yet startup called start_watcher()
    // unconditionally and start_watcher() itself only reads
    // `realtime_roots` — so every reboot silently turned protection back on
    // while Settings still rendered the switch as off from the same saved
    // config. `user_disabled_protection` did not cover it either: that is
    // an in-memory AtomicBool reset to false by AppState::new.
    if config.realtime_enabled {
        server.state().start_watcher();
    } else {
        warn!(
            "real-time protection is OFF in sentinelld.toml — watcher NOT started; only \
             on-demand scans will run"
        );
    }

    // Heartbeat-driven auto-restart: if the watcher stops ticking for >60s
    // while protection is supposed to be on, respawn it. A targeted attacker
    // who manages to crash the watcher silently otherwise wins until the
    // operator notices the stale `watcher_heartbeat_stale` flag in the GUI.
    server.state().spawn_watcher_heartbeat_monitor();

    // Post-boot critical areas scan — lightweight, 1 thread, BELOW_NORMAL.
    // Fires AFTER watcher so realtime is never delayed.
    // Skips in audit mode (minimal footprint).
    if !args.audit_mode && config.startup_critical_scan {
        server.state().start_startup_critical_scan();
    } else if !config.startup_critical_scan {
        info!("startup critical scan disabled by config");
    }

    // Start idle background scanner (resource-aware) — skip in audit mode.
    if !args.audit_mode {
        server.state().start_idle_scanner();
    } else {
        info!("idle scanner skipped (audit mode)");
    }

    // Start PowerShell Script Block Logging bridge (config-gated).
    if !args.audit_mode && config.powershell_bridge_enabled {
        server
            .state()
            .start_ps_bridge(config.powershell_poll_seconds);
    } else if !config.powershell_bridge_enabled {
        info!("PowerShell bridge disabled by config");
    }

    // Start scan scheduler — skip in audit mode.
    let scheduler = if !args.audit_mode {
        Some(scheduler::Scheduler::start(Arc::clone(server.state())))
    } else {
        info!("scheduler skipped (audit mode)");
        None
    };

    // Handle graceful shutdown on Ctrl+C — there IS no other handler:
    // `server.run()` has no Ctrl+C logic of its own (an earlier comment
    // here claimed it did; nothing in ipc/ touches tokio::signal), so a
    // foreground Ctrl+C used to kill the process without any of the
    // cleanup below — including NRPT rule removal, leaving the machine's
    // DNS pointed at a dead listener until the boot reconciler's next run.
    // The task sets a flag shaped exactly like the SCM's, and the
    // shutdown_signal arm below observes either one.
    let ctrl_c_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let flag = Arc::clone(&ctrl_c_flag);
        let shutdown_state = Arc::clone(server.state());
        tokio::spawn(async move {
            if let Ok(()) = tokio::signal::ctrl_c().await {
                info!("shutdown signal received");
                shutdown_state.log_activity(
                    "info",
                    "system",
                    "Daemon shutting down",
                    "Graceful shutdown",
                    None,
                );
                flag.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        });
    }
    // Service mode passes the SCM flag in; foreground gets the Ctrl+C one.
    let shutdown = shutdown.or(Some(ctrl_c_flag));

    // Race `server.run()` against the shutdown flag (SCM stop or Ctrl+C —
    // see above) so that on either stop we fall through to graceful
    // cleanup instead of cancelling the whole run_daemon future, which is
    // how the cleanup below (web protection stop, scheduler.stop, final
    // log) used to be skipped entirely.
    let run_result = {
        let shutdown_signal = async {
            match &shutdown {
                Some(flag) => loop {
                    if flag.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                },
                // Unreachable today (the flag is always installed above);
                // kept so a future caller without a flag compiles.
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            res = server.run() => res,
            _ = shutdown_signal => {
                info!("stop requested — beginning graceful shutdown");
                Ok(())
            }
        }
    };

    // Cleanup ALWAYS runs now (both error and stop paths).
    //
    // The retry loop goes FIRST: it must be told to stop (and joined)
    // before the subsystem is stopped, or it could swap a freshly serving
    // proxy — rule installed — into the box while we are tearing down.
    // RetryGuard::shutdown closes that window itself (a successful
    // in-flight attempt stops cleanly, rule first).
    if let Some(guard) = wp_retry {
        guard.shutdown().await;
    }
    // Web protection stops next and is JOINED, unlike the flag-store
    // stop() of the other subsystems: shutdown removes the NRPT rule, and
    // removing it while the sockets are still bound would leave a window
    // where the machine's DNS points at a listener that is going away.
    // Bounded at 5s against the SCM's 30s total stop budget.
    web_protection.lock().await.stop().await;

    if let Some(s) = scheduler {
        s.stop();
    }

    // PLM: PlmMonitor::Drop is unreachable in production (AppState is
    // Arc-shared by the IPC server and its tasks past process exit), so
    // the ETW kernel session must be stopped+joined explicitly — otherwise
    // the session orphans and burns one of the 8 system-logger slots until
    // the next boot's stale cleanup.
    if let Some(plm) = server.state().plm() {
        plm.shutdown();
    }

    if let Err(e) = run_result {
        error!(%e, "daemon shutting down due to error");
        return Err(e);
    }

    info!("sentinelld stopped gracefully");
    Ok(())
}
