//! `sandboxd` — behavioral sandbox worker (experimental).
//!
//! Detonates a suspicious executable in an isolated environment,
//! monitors behavior, and reports findings as JSON.
//!
//! Phase 1: Process monitoring via Windows Job Objects.
//!   - Copy sample to temp dir
//!   - Launch with timeout
//!   - Monitor child processes, file writes (basic)
//!   - Report JSON on stdout
//!
//! Phase 2C (current): Network containment via Windows Firewall rules.
//!   - Block outbound traffic for the detonated sample AND its child
//!     processes during execution (children are covered by a periodic
//!     process-tree sweep — best-effort, see `launch_and_monitor`)
//!   - Cleanup firewall rules after detonation
//!
//! Phase 3 (future): AppContainer isolation + ETW monitoring.
//! Phase 4 (future): Full Hyper-V sandbox integration.

#[cfg(target_os = "windows")]
mod etw;
// Pure ETW session-config builder (C-1 fix) — cross-platform by design so
// its bit-level invariant tests run everywhere.
mod etw_config;
#[cfg(target_os = "windows")]
mod restricted;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::Parser;
use serde::Serialize;

const EXIT_OK: i32 = 0;
const EXIT_THREAT: i32 = 1;
const EXIT_ERROR: i32 = 3;

#[derive(Parser)]
#[command(name = "sandboxd", version, about = "Sentinella behavioral sandbox")]
struct Cli {
    /// File to detonate.
    path: PathBuf,

    /// Detonation timeout in seconds.
    #[arg(long, default_value_t = 10)]
    timeout: u64,

    /// Emit JSON output.
    #[arg(long)]
    json: bool,

    /// Dry run — don't actually execute, just report structure.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Serialize)]
struct SandboxOutput {
    engine: &'static str,
    status: SandboxStatus,
    sample_path: String,
    sample_sha256: String,
    backend_used: String,
    // C-1 truthfulness fields (additive — no existing fields removed).
    // `backend_used` claims "etw_kernel_session" ONLY when the session
    // actually delivered events; these two make that claim auditable.
    etw_events_seen: u64,
    etw_degraded: bool,
    detonation_time_ms: u64,
    monitor_duration_ms: u64,
    findings: Vec<SandboxFinding>,
    score_delta: i32,
    errors: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum SandboxStatus {
    Completed,
    Timeout,
    Blocked,
    Error,
    DryRun,
}

#[derive(Debug, Clone, Serialize)]
struct SandboxFinding {
    kind: String,
    severity: String,
    detail: String,
    confidence: String,
    source: String,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    if !cli.path.exists() {
        emit_output(
            &cli,
            SandboxOutput {
                engine: "sandboxd",
                status: SandboxStatus::Error,
                sample_path: cli.path.to_string_lossy().to_string(),
                sample_sha256: String::new(),
                backend_used: "none".into(),
                etw_events_seen: 0,
                etw_degraded: false,
                detonation_time_ms: 0,
                monitor_duration_ms: 0,
                findings: vec![],
                score_delta: 0,
                errors: vec!["sample file not found".into()],
            },
        );
        std::process::exit(EXIT_ERROR);
    }

    let start = Instant::now();
    let sha256 = sha256_file(&cli.path).unwrap_or_default();

    if cli.dry_run {
        emit_output(
            &cli,
            SandboxOutput {
                engine: "sandboxd",
                status: SandboxStatus::DryRun,
                sample_path: cli.path.to_string_lossy().to_string(),
                sample_sha256: sha256,
                backend_used: "none".into(),
                etw_events_seen: 0,
                etw_degraded: false,
                detonation_time_ms: 0,
                monitor_duration_ms: 0,
                findings: vec![],
                score_delta: 0,
                errors: vec![],
            },
        );
        std::process::exit(EXIT_OK);
    }

    let _run_guard = match acquire_sandbox_lock() {
        Ok(guard) => guard,
        Err(e) => {
            emit_output(
                &cli,
                SandboxOutput {
                    engine: "sandboxd",
                    status: SandboxStatus::Blocked,
                    sample_path: cli.path.to_string_lossy().to_string(),
                    sample_sha256: sha256,
                    backend_used: "none".into(),
                    etw_events_seen: 0,
                    etw_degraded: false,
                    detonation_time_ms: start.elapsed().as_millis() as u64,
                    monitor_duration_ms: 0,
                    findings: vec![],
                    score_delta: 0,
                    errors: vec![e],
                },
            );
            std::process::exit(EXIT_ERROR);
        }
    };

    // Cleanup stale sandbox dirs + firewall rules from previous crashed runs.
    cleanup_stale_sandbox_dirs();
    cleanup_stale_firewall_rules();

    // ── Phase 1: Basic process detonation ─────────────────
    let result = detonate(&cli.path, Duration::from_secs(cli.timeout));
    let elapsed_ms = start.elapsed().as_millis() as u64;

    let raw_score_delta: i32 = result
        .findings
        .iter()
        .map(|f| match f.severity.as_str() {
            "critical" => 25,
            "high" => 15,
            "medium" => 10,
            "low" => 5,
            // Observational evidence that must NOT move the verdict:
            // loopback connections, which since web protection include the
            // sample's own DNS resolution. Explicit rather than relying on
            // the catch-all, so deleting this arm is a visible decision.
            "info" => 0,
            _ => 0,
        })
        .sum();
    let score_delta = raw_score_delta.min(50); // Cap at 50 — daemon also caps, belt+suspenders.

    let output = SandboxOutput {
        engine: "sandboxd",
        status: result.status,
        sample_path: cli.path.to_string_lossy().to_string(),
        // Prefer the post-copy hash (bytes actually detonated); fall back to
        // the pre-scan hash when detonation never reached the copy stage.
        sample_sha256: if result.sha256.is_empty() {
            sha256
        } else {
            result.sha256
        },
        backend_used: result.backend_used,
        etw_events_seen: result.etw_events_seen,
        etw_degraded: result.etw_degraded,
        detonation_time_ms: elapsed_ms,
        monitor_duration_ms: result.monitor_duration_ms,
        findings: result.findings,
        score_delta,
        errors: result.errors,
    };

    let exit = if output.score_delta > 20 {
        EXIT_THREAT
    } else {
        EXIT_OK
    };
    emit_output(&cli, output);
    std::process::exit(exit);
}

fn emit_output(cli: &Cli, output: SandboxOutput) {
    if cli.json {
        println!("{}", serde_json::to_string(&output).unwrap_or_default());
    } else {
        println!(
            "sandboxd: {} — {} findings, score_delta={}",
            match output.status {
                SandboxStatus::Completed => "completed",
                SandboxStatus::Timeout => "timeout",
                SandboxStatus::Blocked => "blocked",
                SandboxStatus::Error => "error",
                SandboxStatus::DryRun => "dry_run",
            },
            output.findings.len(),
            output.score_delta,
        );
        for f in &output.findings {
            println!("  [{}/{}] {}", f.kind, f.severity, f.detail);
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Detonation engine — Phase 1 (process monitoring)
// ═══════════════════════════════════════════════════════════════

struct DetonationResult {
    status: SandboxStatus,
    findings: Vec<SandboxFinding>,
    errors: Vec<String>,
    backend_used: String,
    etw_events_seen: u64,
    etw_degraded: bool,
    monitor_duration_ms: u64,
    /// SHA256 of the bytes ACTUALLY detonated (the sandbox copy), empty on error.
    sha256: String,
}

struct LaunchResult {
    status: SandboxStatus,
    backend_used: String,
    etw_events_seen: u64,
    etw_degraded: bool,
}

fn detonate(sample: &Path, timeout: Duration) -> DetonationResult {
    let mut findings = Vec::new();
    let mut errors = Vec::new();

    // Copy sample to isolated temp directory.
    let temp_dir = match create_sandbox_dir() {
        Ok(d) => d,
        Err(e) => {
            return DetonationResult {
                status: SandboxStatus::Error,
                findings: vec![],
                errors: vec![format!("temp dir creation failed: {e}")],
                backend_used: "none".into(),
                etw_events_seen: 0,
                etw_degraded: false,
                monitor_duration_ms: 0,
                sha256: String::new(),
            };
        }
    };

    let sample_name = sample.file_name().unwrap_or_default();
    let temp_sample = temp_dir.join(sample_name);
    if let Err(e) = std::fs::copy(sample, &temp_sample) {
        let _ = std::fs::remove_dir_all(&temp_dir);
        return DetonationResult {
            status: SandboxStatus::Error,
            findings: vec![],
            errors: vec![format!("sample copy failed: {e}")],
            backend_used: "none".into(),
            etw_events_seen: 0,
            etw_degraded: false,
            monitor_duration_ms: 0,
            sha256: String::new(),
        };
    }

    // Hash the COPY, not the original path: the original is a live user file
    // that can change between scan-trigger and copy — the report must match
    // the bytes that were actually detonated.
    let sha256 = sha256_file(&temp_sample).unwrap_or_default();

    // Launch process with timeout.
    let monitor_start = Instant::now();
    let launch_result = launch_and_monitor(&temp_sample, timeout, &mut findings, &mut errors);
    let monitor_duration_ms = monitor_start.elapsed().as_millis() as u64;

    // Cleanup temp dir — log failure (locked files from detonated sample).
    if let Err(e) = std::fs::remove_dir_all(&temp_dir) {
        eprintln!("sandbox cleanup warning: {e} — dir: {}", temp_dir.display());
    }

    DetonationResult {
        status: launch_result.status,
        findings,
        errors,
        backend_used: launch_result.backend_used,
        etw_events_seen: launch_result.etw_events_seen,
        etw_degraded: launch_result.etw_degraded,
        monitor_duration_ms,
        sha256,
    }
}

/// Remove stale sandbox directories from previous crashed runs.
fn cleanup_stale_sandbox_dirs() {
    let base = std::env::temp_dir().join("sentinella-sandbox");
    if let Ok(entries) = std::fs::read_dir(&base) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // If older than 5 minutes, it's stale.
                if let Ok(meta) = path.metadata() {
                    if let Ok(modified) = meta.modified() {
                        if modified.elapsed().unwrap_or_default() > Duration::from_secs(300) {
                            let _ = std::fs::remove_dir_all(&path);
                        }
                    }
                }
            }
        }
    }
}

/// Remove stale firewall rules from crashed sandboxd runs.
#[cfg(target_os = "windows")]
fn cleanup_stale_firewall_rules() {
    use std::os::windows::process::CommandExt;
    // List all firewall rules, find sentinella-sandbox-* patterns.
    let output = std::process::Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "show",
            "rule",
            "name=all",
            "dir=out",
        ])
        .creation_flags(0x08000000)
        .output();
    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if let Some(name) = line.strip_prefix("Rule Name:") {
                let name = name.trim();
                if name.starts_with("sentinella-sandbox-") {
                    let _ = std::process::Command::new("netsh")
                        .args([
                            "advfirewall",
                            "firewall",
                            "delete",
                            "rule",
                            &format!("name={name}"),
                        ])
                        .creation_flags(0x08000000)
                        .output();
                }
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn cleanup_stale_firewall_rules() {}

#[cfg(target_os = "windows")]
struct SandboxRunGuard(HANDLE);

#[cfg(target_os = "windows")]
impl Drop for SandboxRunGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}

#[cfg(not(target_os = "windows"))]
struct SandboxRunGuard;

#[cfg(target_os = "windows")]
fn acquire_sandbox_lock() -> Result<SandboxRunGuard, String> {
    const WAIT_OBJECT_0: u32 = 0x00000000;
    const WAIT_ABANDONED: u32 = 0x00000080;
    const WAIT_TIMEOUT: u32 = 0x00000102;

    let name: Vec<u16> = "Local\\SentinellaSandbox"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    if handle.is_null() {
        return Err("sandbox mutex creation failed".into());
    }

    let wait = unsafe { WaitForSingleObject(handle, 0) };
    match wait {
        WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(SandboxRunGuard(handle)),
        WAIT_TIMEOUT => {
            unsafe {
                CloseHandle(handle);
            }
            Err("sandbox busy — another detonation is active".into())
        }
        other => {
            unsafe {
                CloseHandle(handle);
            }
            Err(format!("sandbox mutex wait failed: {other}"))
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn acquire_sandbox_lock() -> Result<SandboxRunGuard, String> {
    Ok(SandboxRunGuard)
}

fn create_sandbox_dir() -> Result<PathBuf, String> {
    let base = std::env::temp_dir().join("sentinella-sandbox");
    std::fs::create_dir_all(&base).map_err(|e| e.to_string())?;
    let id = format!(
        "{:016x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let dir = base.join(id);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    set_low_integrity_label(&dir);
    Ok(dir)
}

/// Set a Low mandatory integrity label on the sandbox dir (best-effort).
///
/// The dir is created under the SYSTEM worker's temp (`C:\Windows\Temp`) with
/// the default Medium label — a low-integrity sample is then DENIED write by
/// No-Write-Up, which silently kills all behavioral file-drop detection.
/// The sample's token keeps the SYSTEM user SID, so the inherited DACL
/// already grants write once the label no longer blocks it.
#[cfg(target_os = "windows")]
fn set_low_integrity_label(dir: &Path) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let _ = std::process::Command::new("icacls")
        .arg(dir.as_os_str())
        .args(["/setintegritylevel", "Low"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
}

#[cfg(not(target_os = "windows"))]
fn set_low_integrity_label(_dir: &Path) {}

#[cfg(target_os = "windows")]
fn launch_and_monitor(
    sample: &Path,
    timeout: Duration,
    findings: &mut Vec<SandboxFinding>,
    errors: &mut Vec<String>,
) -> LaunchResult {
    // ── Create Job Object for process containment ─────
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        // Fail CLOSED: no Job Object means no kill-on-close containment, so we
        // must NOT detonate. (Do not "fall through to monitoring" — an
        // uncontained malware process could orphan children that survive
        // sandboxd exit.)
        errors.push("Failed to create Job Object".into());
        return LaunchResult {
            status: SandboxStatus::Error,
            backend_used: "none".into(),
            etw_events_seen: 0,
            etw_degraded: false,
        };
    } else {
        // Configure limits: kill on close + memory cap + process-count cap +
        // no child breakaway.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE      // Kill entire tree when job handle closed.
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY // Per-process memory limit.
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS; // Cap total processes (fork-bomb guard).
        // NOTE: BREAKAWAY_OK intentionally NOT set — children cannot escape the job.
        // 512 MB per-process memory limit.
        info.ProcessMemoryLimit = 512 * 1024 * 1024;
        // 64 concurrent processes max — bounds host resource pressure and
        // sandboxd telemetry growth from fork-bombing samples.
        info.BasicLimitInformation.ActiveProcessLimit = 64;

        let ok = unsafe {
            SetInformationJobObject(
                job,
                9, // JobObjectExtendedLimitInformation
                &info as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            errors.push("Failed to configure Job Object limits".into());
            unsafe {
                CloseHandle(job);
            }
            return LaunchResult {
                status: SandboxStatus::Error,
                backend_used: "none".into(),
                etw_events_seen: 0,
                etw_degraded: false,
            };
        }
    }

    // R9-LETHAL pattern: NEVER fall back to CWD when resolving where the
    // sample runs / ETW behavioural logs land. Sandboxd is spawned by the
    // daemon (SYSTEM) and a bare-filename `sample` would otherwise dump
    // telemetry to whatever CWD the parent inherited — potentially
    // user-writable. Use the per-process temp dir instead, which is bounded
    // to the sandboxd user profile. The sample also gets this as its CWD so
    // the low-integrity token can actually write there (see create_sandbox_dir).
    let sandbox_dir = sample
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!("sentinella-sandbox-{}", std::process::id()))
        });

    // Launch with restricted low-integrity token (CREATE_SUSPENDED).
    let launch = restricted::launch_restricted(sample, &sandbox_dir);
    for e in &launch.errors {
        errors.push(e.clone());
    }
    if launch.pid == 0 {
        findings.push(SandboxFinding {
            kind: "launch_blocked".into(),
            severity: "info".into(),
            detail: "Process launch failed — FAIL CLOSED, sample not detonated".into(),
            confidence: "observed".into(),
            source: "process_spawn".into(),
        });
        if !job.is_null() {
            unsafe {
                CloseHandle(job);
            }
        }
        return LaunchResult {
            status: SandboxStatus::Blocked,
            backend_used: "none".into(),
            etw_events_seen: 0,
            etw_degraded: false,
        };
    }

    if launch.restricted {
        let integrity = if launch.low_integrity {
            "low-integrity"
        } else {
            "medium-integrity (low failed)"
        };
        findings.push(SandboxFinding {
            kind: "containment".into(),
            severity: if launch.low_integrity {
                "info"
            } else {
                "medium"
            }
            .into(),
            detail: format!("Process launched with restricted {integrity} token"),
            confidence: "observed".into(),
            source: "restricted_token".into(),
        });
    } else {
        findings.push(SandboxFinding {
            kind: "containment_degraded".into(),
            severity: "medium".into(),
            detail: "Restricted token failed — running with normal privileges".into(),
            confidence: "observed".into(),
            source: "restricted_token".into(),
        });
    }

    // Assign to Job Object BEFORE resuming the suspended thread.
    if !job.is_null() {
        let ok = unsafe { AssignProcessToJobObject(job, launch.process_handle.0 as HANDLE) };
        if ok == 0 {
            // Job assignment failed — kill and abort.
            restricted::kill_process(launch.process_handle);
            restricted::close_handles(&launch);
            findings.push(SandboxFinding {
                kind: "containment_failed".into(),
                severity: "high".into(),
                detail: "Job Object assignment failed on suspended process — killed".into(),
                confidence: "observed".into(),
                source: "job_object".into(),
            });
            unsafe {
                CloseHandle(job);
            }
            return LaunchResult {
                status: SandboxStatus::Blocked,
                backend_used: "none".into(),
                etw_events_seen: 0,
                etw_degraded: false,
            };
        }
        findings.push(SandboxFinding {
            kind: "containment".into(),
            severity: "info".into(),
            detail: "Process contained in Job Object (kill-on-close + 512MB memory limit + 64-process limit)".into(),
            confidence: "observed".into(),
            source: "job_object".into(),
        });
    };

    let pid = launch.pid;
    findings.push(SandboxFinding {
        kind: "process_launched".into(),
        severity: "info".into(),
        detail: format!("Sample launched as PID {pid}"),
        confidence: "observed".into(),
        source: "process_spawn".into(),
    });

    // ── Block outbound network for the sample (best-effort) ──
    // NOTE: the `program=` rule only covers the ROOT process image — netsh
    // cannot scope a rule to a Job Object. Child processes are covered by the
    // periodic tree sweep in the monitor loop below (best-effort; a child
    // that exfiltrates within its first sweep interval escapes — closing that
    // race needs a WFP callout, not netsh).
    let mut firewall_guard = FirewallRuleGuard::new();
    if block_network(pid, sample, findings, errors) {
        firewall_guard.add(pid);
        findings.push(SandboxFinding {
            kind: "containment".into(),
            severity: "info".into(),
            detail: format!("Outbound network blocked via firewall rule for PID {pid}"),
            confidence: "observed".into(),
            source: "netsh_firewall".into(),
        });
    }

    // Resume only after job containment and best-effort network block.
    // ── ETW behavioral monitoring (runs in parallel with process) ──
    // Telemetry lands in `sandbox_dir` (computed above, R9-LETHAL: never CWD).
    let etw_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let etw_timeout = timeout;
    let etw_dir = sandbox_dir.clone();
    let etw_stop_thread = std::sync::Arc::clone(&etw_stop);
    let etw_handle = std::thread::spawn(move || {
        etw::monitor_process_until(pid, etw_timeout, &etw_dir, &etw_stop_thread)
    });
    std::thread::sleep(Duration::from_millis(50));
    restricted::resume_thread(launch.thread_handle);
    let mut timed_out = false;
    let etw_report = {
        let start = Instant::now();
        // Child-process network containment state: each newly discovered
        // descendant PID gets its own `program=` firewall rule (see NOTE at
        // the root block above). Tracked so we add each rule exactly once.
        let mut child_sweep = Instant::now();
        let mut blocked_children: std::collections::HashSet<u32> = std::collections::HashSet::new();

        loop {
            if start.elapsed() > timeout {
                timed_out = true;
                restricted::kill_process(launch.process_handle);
                findings.push(SandboxFinding {
                    kind: "timeout".into(),
                    severity: "medium".into(),
                    detail: format!(
                        "Process did not exit within {}s — killed entire process tree",
                        timeout.as_secs()
                    ),
                    confidence: "observed".into(),
                    source: "behavioral_monitor_polling".into(),
                });
                break;
            }

            // ── Child network containment sweep (every 500ms) ──
            if child_sweep.elapsed() >= Duration::from_millis(500) {
                child_sweep = Instant::now();
                for child_pid in descendant_pids(pid) {
                    if !blocked_children.insert(child_pid) {
                        continue;
                    }
                    // Whole image path is required for a `program=` rule.
                    let Some(image) = etw::get_process_image_path(child_pid) else {
                        continue;
                    };
                    if block_network(child_pid, Path::new(&image), findings, errors) {
                        firewall_guard.add(child_pid);
                        findings.push(SandboxFinding {
                            kind: "containment".into(),
                            severity: "info".into(),
                            detail: format!(
                                "Outbound network blocked for child process (PID {child_pid}): {image}"
                            ),
                            confidence: "observed".into(),
                            source: "netsh_firewall".into(),
                        });
                    }
                }
            }

            if let Some(exit_code) = restricted::try_wait(launch.process_handle) {
                if exit_code != 0 {
                    findings.push(SandboxFinding {
                        kind: "exit_code".into(),
                        severity: "low".into(),
                        detail: format!("Process exited with code {exit_code}"),
                        confidence: "observed".into(),
                        source: "process_spawn".into(),
                    });
                }
                break;
            } else {
                std::thread::sleep(Duration::from_millis(100));
            }
        }

        if !timed_out {
            std::thread::sleep(Duration::from_millis(250));
        }
        etw_stop.store(true, std::sync::atomic::Ordering::Relaxed);

        // Collect ETW results.
        etw_handle.join().unwrap_or_else(|_| {
            
            etw::EtwReport {
                findings: vec![],
                processes_spawned: vec![],
                dlls_loaded: vec![],
                registry_writes: vec![],
                network_connections: vec![],
                files_written: vec![],
                errors: vec!["ETW monitor thread panicked".into()],
                backend_used: "error".into(),
                events_seen: 0,
                etw_degraded: false,
            }
        })
    };

    // Merge ETW findings into main findings.
    for f in &etw_report.findings {
        // Deduplicate — don't add if we already have a finding with same kind+detail.
        if !findings
            .iter()
            .any(|existing| existing.kind == f.kind && existing.detail == f.detail)
        {
            findings.push(SandboxFinding {
                kind: f.kind.clone(),
                severity: f.severity.clone(),
                detail: f.detail.clone(),
                confidence: f.confidence.clone(),
                source: f.source.clone(),
            });
        }
    }
    for e in &etw_report.errors {
        errors.push(e.clone());
    }

    // Post-execution checks.
    check_sandbox_dir_changes(&sandbox_dir, findings);

    // Remove firewall rules (root + swept children) before closing job.
    if !firewall_guard.pids.is_empty() {
        for rule_pid in firewall_guard.pids.clone() {
            unblock_network(rule_pid, errors);
        }
        firewall_guard.disarm();
    }

    // Close Job Object — this kills any surviving processes in the tree.
    if !job.is_null() {
        unsafe {
            CloseHandle(job);
        }
    }

    // Close process/thread handles from the restricted launch.
    restricted::close_handles(&launch);

    if timed_out {
        LaunchResult {
            status: SandboxStatus::Timeout,
            backend_used: etw_report.backend_used,
            etw_events_seen: etw_report.events_seen,
            etw_degraded: etw_report.etw_degraded,
        }
    } else {
        LaunchResult {
            status: SandboxStatus::Completed,
            backend_used: etw_report.backend_used,
            etw_events_seen: etw_report.events_seen,
            etw_degraded: etw_report.etw_degraded,
        }
    }
}

#[cfg(target_os = "windows")]
#[allow(dead_code)]
fn check_child_processes(parent_pid: u32, findings: &mut Vec<SandboxFinding>) {
    use std::mem;

    // Snapshot all threads to find child processes.
    // Using ToolHelp — same as FISH response module.
    unsafe {
        let snap = windows_create_toolhelp_snapshot();
        if snap.is_none() {
            return;
        }
        let snap = snap.unwrap();

        let mut pe: PROCESSENTRY32W = mem::zeroed();
        pe.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;

        if process32_first(snap, &mut pe) {
            loop {
                if pe.th32ParentProcessID == parent_pid && pe.th32ProcessID != parent_pid {
                    let name = String::from_utf16_lossy(
                        &pe.szExeFile[..pe
                            .szExeFile
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(pe.szExeFile.len())],
                    );

                    let severity = if is_suspicious_child(&name) {
                        "high"
                    } else {
                        "medium"
                    };
                    // Deduplicate — only add if not already found.
                    let already = findings
                        .iter()
                        .any(|f| f.kind == "process_spawn" && f.detail.contains(&name));
                    if !already {
                        findings.push(SandboxFinding {
                            kind: "process_spawn".into(),
                            severity: severity.into(),
                            detail: format!("Spawned {name} (PID {})", pe.th32ProcessID),
                            confidence: "observed".into(),
                            source: "process_spawn".into(),
                        });
                    }
                }
                if !process32_next(snap, &mut pe) {
                    break;
                }
            }
        }
        close_handle(snap);
    }
}

#[cfg(target_os = "windows")]
#[allow(dead_code)]
fn is_suspicious_child(name: &str) -> bool {
    let lower = name.to_lowercase();
    matches!(
        lower.as_str(),
        "powershell.exe"
            | "cmd.exe"
            | "wscript.exe"
            | "cscript.exe"
            | "mshta.exe"
            | "regsvr32.exe"
            | "rundll32.exe"
            | "certutil.exe"
            | "bitsadmin.exe"
            | "msiexec.exe"
            | "net.exe"
            | "net1.exe"
            | "schtasks.exe"
            | "reg.exe"
            | "wmic.exe"
            | "vssadmin.exe"
    )
}

#[cfg(target_os = "windows")]
fn check_sandbox_dir_changes(sandbox_dir: &Path, findings: &mut Vec<SandboxFinding>) {
    // Check if the sample created new files in its directory.
    if let Ok(entries) = std::fs::read_dir(sandbox_dir) {
        let mut new_files = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                // Original sample is expected — count extras.
                new_files += 1;
            }
        }
        // More than just the original sample → created files.
        if new_files > 1 {
            findings.push(SandboxFinding {
                kind: "file_created".into(),
                severity: "medium".into(),
                detail: format!("Created {} new file(s) in sandbox directory", new_files - 1),
                confidence: "observed".into(),
                source: "filesystem_check".into(),
            });
        }
    }
}

// ── Network containment via Windows Firewall ─────────────────

/// Firewall rule name used for sandbox network blocking.
#[cfg(target_os = "windows")]
fn firewall_rule_name(pid: u32) -> String {
    format!("sentinella-sandbox-{pid}")
}

#[cfg(target_os = "windows")]
struct FirewallRuleGuard {
    /// PIDs whose `sentinella-sandbox-<pid>` rules are active (root + swept children).
    pids: Vec<u32>,
    active: bool,
}

#[cfg(target_os = "windows")]
impl FirewallRuleGuard {
    fn new() -> Self {
        Self {
            pids: Vec::new(),
            active: true,
        }
    }

    fn add(&mut self, pid: u32) {
        self.pids.push(pid);
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

#[cfg(target_os = "windows")]
impl Drop for FirewallRuleGuard {
    fn drop(&mut self) {
        if self.active {
            for pid in self.pids.drain(..) {
                unblock_network_silent(pid);
            }
        }
    }
}

/// All current descendant PIDs (children, grandchildren, …) of `root_pid`.
///
/// One ToolHelp process snapshot → parent map → BFS from the root. Used by
/// the child network-containment sweep; best-effort (a process that spawns
/// and exits between snapshots is missed).
#[cfg(target_os = "windows")]
fn descendant_pids(root_pid: u32) -> Vec<u32> {
    let mut result = Vec::new();
    unsafe {
        let Some(snap) = windows_create_toolhelp_snapshot() else {
            return result;
        };
        let mut pe: PROCESSENTRY32W = std::mem::zeroed();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut parent_of: Vec<(u32, u32)> = Vec::new(); // (pid, parent_pid)
        if process32_first(snap, &mut pe) {
            loop {
                parent_of.push((pe.th32ProcessID, pe.th32ParentProcessID));
                if !process32_next(snap, &mut pe) {
                    break;
                }
            }
        }
        close_handle(snap);

        let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::from([root_pid]);
        let mut queue = vec![root_pid];
        while let Some(parent) = queue.pop() {
            for &(pid, ppid) in &parent_of {
                if ppid == parent && seen.insert(pid) {
                    result.push(pid);
                    queue.push(pid);
                }
            }
        }
    }
    result
}

/// Block outbound network for a detonated process by adding a Windows Firewall
/// rule scoped to its executable image path. Best-effort: failures are logged
/// but do not abort detonation. NOTE: a `program=` rule matches only that one
/// process image — child processes need their own rules (see the containment
/// sweep in `launch_and_monitor`).
#[cfg(target_os = "windows")]
fn block_network(
    pid: u32,
    sample: &Path,
    _findings: &mut Vec<SandboxFinding>,
    errors: &mut Vec<String>,
) -> bool {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    let rule_name = firewall_rule_name(pid);
    let sample_path = sample.to_string_lossy();

    // CREATE_NO_WINDOW (0x08000000) — prevent netsh from flashing a console.
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    // The program path MUST be quoted: netsh re-parses its command line on
    // whitespace, so an attacker-controlled filename with spaces (e.g.
    // `invoice copy.exe`) would otherwise split into extra tokens, netsh
    // would error out, and the sample would run with NO network containment.
    let result = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={rule_name}"),
            "dir=out",
            &format!("program=\"{sample_path}\""),
            "action=block",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    match result {
        Ok(output) if output.status.success() => {
            tracing::info!("Firewall rule '{rule_name}' added for {sample_path}");
            true
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            errors.push(format!(
                "netsh firewall add failed (exit {}): {stdout} {stderr}",
                output.status.code().unwrap_or(-1),
            ));
            false
        }
        Err(e) => {
            errors.push(format!("netsh firewall add failed to execute: {e}"));
            false
        }
    }
}

/// Remove the outbound-block firewall rule after detonation cleanup.
/// Best-effort: failures are logged but do not cause errors.
#[cfg(target_os = "windows")]
fn unblock_network(pid: u32, errors: &mut Vec<String>) {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    let rule_name = firewall_rule_name(pid);

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let result = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={rule_name}"),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    match result {
        Ok(output) if output.status.success() => {
            tracing::info!("Firewall rule '{rule_name}' removed");
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            errors.push(format!(
                "netsh firewall delete failed (exit {}): {stdout} {stderr}",
                output.status.code().unwrap_or(-1),
            ));
        }
        Err(e) => {
            errors.push(format!("netsh firewall delete failed to execute: {e}"));
        }
    }
}

#[cfg(target_os = "windows")]
fn unblock_network_silent(pid: u32) {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let rule_name = firewall_rule_name(pid);
    let _ = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={rule_name}"),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
}

// ── Windows FFI for Job Objects ───────────────────────────────

#[cfg(target_os = "windows")]
const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x00002000;
#[cfg(target_os = "windows")]
const JOB_OBJECT_LIMIT_PROCESS_MEMORY: u32 = 0x00000100;
#[cfg(target_os = "windows")]
const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: u32 = 0x00000008;
#[cfg(target_os = "windows")]
#[repr(C)]
#[allow(non_snake_case)]
struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
    PerProcessUserTimeLimit: i64,
    PerJobUserTimeLimit: i64,
    LimitFlags: u32,
    MinimumWorkingSetSize: usize,
    MaximumWorkingSetSize: usize,
    ActiveProcessLimit: u32,
    Affinity: usize,
    PriorityClass: u32,
    SchedulingClass: u32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[allow(non_snake_case)]
struct IO_COUNTERS {
    ReadOperationCount: u64,
    WriteOperationCount: u64,
    OtherOperationCount: u64,
    ReadTransferCount: u64,
    WriteTransferCount: u64,
    OtherTransferCount: u64,
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[allow(non_snake_case)]
struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION,
    IoInfo: IO_COUNTERS,
    ProcessMemoryLimit: usize,
    JobMemoryLimit: usize,
    PeakProcessMemoryUsed: usize,
    PeakJobMemoryUsed: usize,
}

#[cfg(target_os = "windows")]
unsafe extern "system" {
    fn CreateJobObjectW(lpJobAttributes: *const std::ffi::c_void, lpName: *const u16) -> HANDLE;
    fn AssignProcessToJobObject(hJob: HANDLE, hProcess: HANDLE) -> i32;
    fn SetInformationJobObject(
        hJob: HANDLE,
        JobObjectInformationClass: u32,
        lpJobObjectInformation: *const std::ffi::c_void,
        cbJobObjectInformationLength: u32,
    ) -> i32;
}

// ── Windows FFI for ToolHelp (minimal, no windows crate dep) ──

#[cfg(target_os = "windows")]
#[repr(C)]
#[allow(dead_code)]
#[allow(non_snake_case)]
struct PROCESSENTRY32W {
    dwSize: u32,
    cntUsage: u32,
    th32ProcessID: u32,
    th32DefaultHeapID: usize,
    th32ModuleID: u32,
    cntThreads: u32,
    th32ParentProcessID: u32,
    pcPriClassBase: i32,
    dwFlags: u32,
    szExeFile: [u16; 260],
}

#[cfg(target_os = "windows")]
type HANDLE = *mut std::ffi::c_void;

#[cfg(target_os = "windows")]
#[allow(dead_code)]
unsafe extern "system" {
    fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> HANDLE;
    fn Process32FirstW(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> i32;
    fn Process32NextW(hSnapshot: HANDLE, lppe: *mut PROCESSENTRY32W) -> i32;
    fn CreateMutexW(
        lpMutexAttributes: *const std::ffi::c_void,
        bInitialOwner: i32,
        lpName: *const u16,
    ) -> HANDLE;
    fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: u32) -> u32;
    fn ReleaseMutex(hMutex: HANDLE) -> i32;
    fn CloseHandle(hObject: HANDLE) -> i32;
}

#[cfg(target_os = "windows")]
#[allow(dead_code)]
fn windows_create_toolhelp_snapshot() -> Option<HANDLE> {
    const TH32CS_SNAPPROCESS: u32 = 0x00000002;
    const INVALID_HANDLE: HANDLE = -1isize as HANDLE;
    let h = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if h == INVALID_HANDLE || h.is_null() {
        None
    } else {
        Some(h)
    }
}

#[cfg(target_os = "windows")]
#[allow(dead_code)]
fn process32_first(snap: HANDLE, pe: &mut PROCESSENTRY32W) -> bool {
    unsafe { Process32FirstW(snap, pe) != 0 }
}

#[cfg(target_os = "windows")]
#[allow(dead_code)]
fn process32_next(snap: HANDLE, pe: &mut PROCESSENTRY32W) -> bool {
    unsafe { Process32NextW(snap, pe) != 0 }
}

#[cfg(target_os = "windows")]
#[allow(dead_code)]
fn close_handle(h: HANDLE) {
    unsafe {
        CloseHandle(h);
    }
}

#[cfg(not(target_os = "windows"))]
fn launch_and_monitor(
    _sample: &Path,
    _timeout: Duration,
    _findings: &mut Vec<SandboxFinding>,
    errors: &mut Vec<String>,
) -> LaunchResult {
    errors.push("Sandbox only supported on Windows".into());
    LaunchResult {
        status: SandboxStatus::Error,
        backend_used: "none".into(),
        etw_events_seen: 0,
        etw_degraded: false,
    }
}

// ── Utility ───────────────────────────────────────────────────

fn sha256_file(path: &Path) -> Result<String, std::io::Error> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
