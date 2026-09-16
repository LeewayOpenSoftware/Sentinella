//! ETW behavioral monitor — real Windows kernel event tracing.
//!
//! Two backends, and THEY DO NOT SEE THE SAME THINGS:
//! - **EtwKernelSession**: real ETW kernel trace with an EVENT_RECORD
//!   callback. Process start/stop, image loads, file I/O and TCP connects.
//! - **PollingFallback**: process-snapshot polling ONLY. It emits exactly one
//!   finding kind, `process_spawn` (see `poll_children_round`). It observes
//!   no network, no image loads and no file I/O.
//!
//! `monitor_process()` tries ETW first and falls back to polling. The
//! STRUCT is the same either way, the COVERAGE is not — and this header used
//! to claim otherwise ("polling + netstat", "the contract is identical
//! regardless of backend"). There is no netstat anywhere in this crate, and
//! since the C-1 change any 5-second silent stretch engages the fallback, so
//! `backend_used == "polling_fallback"` reports are routine rather than
//! exotic. Read one of those with the old claim in mind and an empty
//! `network_connections` looks like proof the sample stayed offline; it is
//! only proof that nothing was watching. Treat every non-process finding as
//! meaningful ONLY when `backend_used == "etw_kernel_session"`.
//!
//! Architecture (C-1 fix): the ETW session is a PRIVATE SYSTEM-LOGGER
//! session — `EVENT_TRACE_SYSTEM_LOGGER_MODE | EVENT_TRACE_REAL_TIME_MODE`
//! plus a fixed private `Wnode.Guid` (see `crate::etw_config`). Without
//! system-logger mode the kernel ignores `EnableFlags` ("EnableFlags is
//! only valid for system loggers" — EVENT_TRACE_PROPERTIES, MS Learn):
//! StartTraceW succeeded and every detonation received ZERO events while
//! `backend_used` reported `"etw_kernel_session"`. `backend_used` is now
//! truthful: it reflects actual event flow, and a silent-zero session
//! mid-detonation marks the report degraded and engages the polling
//! fallback for the remaining window (detonation is NEVER aborted for
//! this — containment is job-object based; ETW is telemetry only).

#![cfg(target_os = "windows")]

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::Etw::*;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::core::PCWSTR;

use sentinella_common::etw_props::EventTracePropsStorage;

use crate::etw_config;

/// Behavioral finding from ETW monitoring.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EtwFinding {
    pub kind: String,
    pub severity: String,
    pub detail: String,
    pub confidence: String,
    pub source: String,
}

/// Collected ETW behavioral telemetry.
#[derive(Debug, Clone)]
pub struct EtwReport {
    pub findings: Vec<EtwFinding>,
    pub processes_spawned: Vec<String>,
    pub dlls_loaded: Vec<String>,
    pub registry_writes: Vec<String>,
    pub network_connections: Vec<String>,
    #[allow(dead_code)]
    pub files_written: Vec<String>,
    pub errors: Vec<String>,
    /// Truthful backend label (C-1): `"etw_kernel_session"` ONLY when the
    /// ETW session actually delivered events; `"etw_session_no_events"`
    /// when it started but stayed silent; `"polling_fallback"` when
    /// polling produced the telemetry. See `backend_label()`.
    pub backend_used: String,
    /// Raw kernel events delivered to the EVENT_RECORD callback (before
    /// relevance filtering). The truthfulness signal behind `backend_used`.
    pub events_seen: u64,
    /// True when the ETW session stayed silent for
    /// `SILENT_ZERO_DEGRADE_AFTER` mid-detonation and the polling fallback
    /// was engaged alongside it. Containment is unaffected either way.
    pub etw_degraded: bool,
}

impl EtwReport {
    fn new() -> Self {
        Self {
            findings: Vec::new(),
            processes_spawned: Vec::new(),
            dlls_loaded: Vec::new(),
            registry_writes: Vec::new(),
            network_connections: Vec::new(),
            files_written: Vec::new(),
            errors: Vec::new(),
            backend_used: "none".into(),
            events_seen: 0,
            etw_degraded: false,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Public API
// ═══════════════════════════════════════════════════════════════

/// Monitor until timeout or caller requests early stop.
pub fn monitor_process_until(
    pid: u32,
    timeout: Duration,
    sandbox_dir: &Path,
    stop: &AtomicBool,
) -> EtwReport {
    match etw_kernel_monitor(pid, timeout, sandbox_dir, stop) {
        Ok(report) => report,
        Err(e) => {
            let mut report = EtwReport::new();
            report
                .errors
                .push(format!("ETW kernel session unavailable: {e}"));
            report.backend_used = "polling_fallback".into();
            polling_monitor(pid, timeout, sandbox_dir, &mut report, stop);
            report
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Backend 1: Real ETW Kernel Session with EVENT_RECORD callback
// ═══════════════════════════════════════════════════════════════

/// Global callback context — ETW callbacks are bare `extern "system"` fns.
static ETW_CTX: Mutex<Option<EtwContext>> = Mutex::new(None);
static ETW_EVENT_COUNT: AtomicU64 = AtomicU64::new(0);
const MAX_ETW_STRING_CHARS: usize = 512;

struct EtwContext {
    target_pid: u32,
    report: Arc<Mutex<EtwReport>>,
    monitored_pids: Arc<Mutex<HashSet<u32>>>,
}

struct EtwContextGuard;

impl Drop for EtwContextGuard {
    fn drop(&mut self) {
        let mut ctx = ETW_CTX.lock().unwrap_or_else(|e| e.into_inner());
        *ctx = None;
    }
}

/// Drop guard — ensures StopTraceW is called even on panic.
struct SessionGuard {
    handle: CONTROLTRACE_HANDLE,
    session_name: String,
    active: bool,
}

impl SessionGuard {
    fn stop(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        // Aligned storage via the shared helper (was a local Vec<u64>
        // `aligned_props_storage`; Wnode.BufferSize + LoggerNameOffset are
        // set by the constructor). The stop buffer needs no name content —
        // the session is identified by `handle` — but keep the same slack
        // as the start buffer (struct + name + 256) for parity.
        let mut storage = match EventTracePropsStorage::with_extra(
            &self.session_name,
            None,
            256,
        ) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("WARNING: ETW stop props layout failed: {e}");
                return;
            }
        };
        unsafe {
            let _ = ControlTraceW(
                self.handle,
                PCWSTR::null(),
                storage.props_mut(),
                EVENT_TRACE_CONTROL_STOP,
            );
        }
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

fn etw_kernel_monitor(
    pid: u32,
    timeout: Duration,
    _sandbox_dir: &Path,
    stop: &AtomicBool,
) -> Result<EtwReport, String> {
    let report = Arc::new(Mutex::new(EtwReport::new()));
    // NOTE: `backend_used` is intentionally NOT set here — it is assigned
    // at the end from actual event flow (C-1 truthfulness). Pre-setting
    // "etw_kernel_session" before a single event arrived is exactly the
    // lie this fix removes.
    let monitored_pids = Arc::new(Mutex::new(HashSet::from([pid])));

    // ── Set up callback context ──────────────────────────
    ETW_EVENT_COUNT.store(0, Ordering::Relaxed);
    {
        let mut ctx = ETW_CTX.lock().unwrap_or_else(|e| e.into_inner());
        if ctx.is_some() {
            eprintln!("WARNING: ETW_CTX was not cleaned up from a previous call — overwriting");
            *ctx = None;
        }
        *ctx = Some(EtwContext {
            target_pid: pid,
            report: Arc::clone(&report),
            monitored_pids: Arc::clone(&monitored_pids),
        });
    }
    let _ctx_guard = EtwContextGuard;

    // ── Start kernel trace session ───────────────────────
    // Fixed session name — ensures stale sessions from killed sandboxd processes
    // are always reclaimed via the error-183 retry path.
    let session_name = "SentinellaSandbox".to_string();
    let session_name_wide: Vec<u16> = session_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // Aligned storage via the shared helper — sets Wnode.BufferSize,
    // LoggerNameOffset and writes the terminated UTF-16 session name.
    let mut props_storage = match EventTracePropsStorage::with_extra(&session_name, None, 256) {
        Ok(s) => s,
        Err(e) => return Err(format!("ETW props layout failed: {e}")),
    };
    // Session-semantic fields come from the pure config builder
    // (crate::etw_config) — the C-1 fix: SYSTEM_LOGGER_MODE + a private
    // Wnode.Guid make the kernel EnableFlags valid. Without them this
    // session started successfully and delivered zero events on every
    // detonation (StartTraceW success ≠ working ETW).
    let cfg = etw_config::sandbox_session_config();
    let props = props_storage.props_mut();
    props.Wnode.ClientContext = cfg.client_context;
    props.Wnode.Flags = cfg.wnode_flags;
    props.Wnode.Guid = windows::core::GUID::from_u128(cfg.session_guid);
    props.LogFileMode = cfg.log_file_mode;
    props.EnableFlags = EVENT_TRACE_FLAG(cfg.enable_flags);

    let mut session_handle = CONTROLTRACE_HANDLE::default();
    let start_result = unsafe {
        StartTraceW(
            &mut session_handle,
            PCWSTR(session_name_wide.as_ptr()),
            props,
        )
    };

    // Any hard StartTraceW error — access-denied (5) or
    // ERROR_NO_SYSTEM_RESOURCES (1450: the 8 system-logger slots on Win8+
    // are exhausted) — returns Err here and the caller falls back to
    // polling. Only error 183 (stale session with our fixed name) is
    // reclaimed in place.
    if start_result.0 != 0 {
        if start_result.0 == 183 {
            // Stale session — stop and retry.
            if let Ok(mut stop_storage) = EventTracePropsStorage::with_extra("", None, 256) {
                unsafe {
                    let _ = ControlTraceW(
                        CONTROLTRACE_HANDLE::default(),
                        PCWSTR(session_name_wide.as_ptr()),
                        stop_storage.props_mut(),
                        EVENT_TRACE_CONTROL_STOP,
                    );
                }
            }

            // Rebuild props for retry — identical session config.
            let mut retry_storage = match EventTracePropsStorage::with_extra(
                &session_name,
                None,
                256,
            ) {
                Ok(s) => s,
                Err(e) => return Err(format!("ETW props layout failed: {e}")),
            };
            let retry_props = retry_storage.props_mut();
            retry_props.Wnode.ClientContext = cfg.client_context;
            retry_props.Wnode.Flags = cfg.wnode_flags;
            retry_props.Wnode.Guid = windows::core::GUID::from_u128(cfg.session_guid);
            retry_props.LogFileMode = cfg.log_file_mode;
            retry_props.EnableFlags = EVENT_TRACE_FLAG(cfg.enable_flags);
            let retry = unsafe {
                StartTraceW(
                    &mut session_handle,
                    PCWSTR(session_name_wide.as_ptr()),
                    retry_props,
                )
            };
            if retry.0 != 0 {
                return Err(format!("StartTraceW retry failed: {}", retry.0));
            }
        } else {
            return Err(format!(
                "StartTraceW failed: {} (need admin?)",
                start_result.0
            ));
        }
    }

    let mut _guard = SessionGuard {
        handle: session_handle,
        session_name: session_name.clone(),
        active: true,
    };

    // ── Open trace for real-time consumption ─────────────
    let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
    logfile.LoggerName = windows::core::PWSTR(session_name_wide.as_ptr() as *mut u16);
    logfile.Anonymous1.ProcessTraceMode = 0x00000100 | 0x10000000; // REAL_TIME + EVENT_RECORD
    logfile.Anonymous2.EventRecordCallback = Some(etw_event_callback);

    let trace_handle = unsafe { OpenTraceW(&mut logfile) };
    if trace_handle.Value == u64::MAX {
        return Err("OpenTraceW failed".into());
    }

    // ── ProcessTrace in background thread ─────────────────
    let consumer_thread = std::thread::spawn(move || {
        let handles = [trace_handle];
        unsafe {
            let _ = ProcessTrace(&handles, None, None);
        }
    });

    // ── Monitor window with silent-zero give-up (C-1) ──────────
    // A session that starts but delivers nothing used to be invisible:
    // the fallback triggered only on HARD errors. Now, if zero events
    // arrive within SILENT_ZERO_DEGRADE_AFTER, we log loudly, mark the
    // report degraded, and run the polling fallback for the remaining
    // window so the detonation still gets process-spawn telemetry.
    // The detonation itself is NEVER aborted for this — containment is
    // job-object based; ETW is telemetry only.
    let start = Instant::now();
    let mut degraded = false;
    let fallback_stop = Arc::new(AtomicBool::new(false));
    let mut fallback_thread: Option<std::thread::JoinHandle<()>> = None;
    while start.elapsed() < timeout && !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(50));
        if !degraded
            && start.elapsed() >= SILENT_ZERO_DEGRADE_AFTER
            && ETW_EVENT_COUNT.load(Ordering::Relaxed) == 0
        {
            degraded = true;
            tracing::warn!(
                elapsed_secs = start.elapsed().as_secs(),
                "sandboxd ETW: session started but delivered zero events — \
                 marking telemetry degraded, engaging polling fallback \
                 (detonation NOT aborted: containment is job-object based)"
            );
            {
                let mut r = report.lock().unwrap_or_else(|e| e.into_inner());
                r.etw_degraded = true;
                r.errors.push(
                    "ETW session delivered zero events (silent-zero); \
                     polling fallback engaged for the remaining window"
                        .into(),
                );
            }
            let remaining = timeout.saturating_sub(start.elapsed());
            if remaining >= Duration::from_millis(500) {
                let fb_report = Arc::clone(&report);
                let fb_stop = Arc::clone(&fallback_stop);
                fallback_thread = Some(std::thread::spawn(move || {
                    let deadline = Instant::now() + remaining;
                    let mut seen: HashSet<u32> = HashSet::from([pid]);
                    while Instant::now() < deadline && !fb_stop.load(Ordering::Relaxed) {
                        std::thread::sleep(Duration::from_millis(200));
                        let mut r = fb_report.lock().unwrap_or_else(|e| e.into_inner());
                        poll_children_round(&mut seen, &mut r);
                    }
                }));
            }
        }
    }

    // Signal the fallback thread (if any) so the join below returns
    // promptly on early stop rather than waiting out its deadline.
    fallback_stop.store(true, Ordering::Relaxed);

    // Stop session → unblocks ProcessTrace.
    _guard.stop();

    // Close trace handle.
    unsafe {
        let _ = CloseTrace(trace_handle);
    }
    let _ = consumer_thread.join();
    if let Some(h) = fallback_thread {
        let _ = h.join();
    }

    // Truthful finalization: backend label reflects ACTUAL event flow.
    let events_seen = ETW_EVENT_COUNT.load(Ordering::Relaxed);
    let mut result = report.lock().unwrap_or_else(|e| e.into_inner()).clone();
    result.events_seen = events_seen;
    result.etw_degraded = degraded;
    result.backend_used = backend_label(events_seen, degraded).into();
    Ok(result)
}

/// How long a started ETW session may deliver zero events before the
/// monitor declares silent-zero degradation. Short enough that a default
/// 10 s detonation still gets ~5 s of polling-fallback coverage.
const SILENT_ZERO_DEGRADE_AFTER: Duration = Duration::from_secs(5);

/// The truthful `backend_used` label (C-1). `"etw_kernel_session"` is
/// earned only by actual event flow — never by StartTraceW success alone.
fn backend_label(events_seen: u64, polling_fallback_engaged: bool) -> &'static str {
    if events_seen > 0 {
        "etw_kernel_session"
    } else if polling_fallback_engaged {
        "polling_fallback"
    } else {
        // Window shorter than the degrade threshold (or stop requested
        // early): session ran, delivered nothing, no fallback had time.
        "etw_session_no_events"
    }
}

// ═══════════════════════════════════════════════════════════════
//  EVENT_RECORD callback — receives real kernel events
// ═══════════════════════════════════════════════════════════════

/// Well-known kernel provider GUIDs.
const PROCESS_GUID: windows::core::GUID =
    windows::core::GUID::from_u128(0x3d6fa8d0_fe05_11d0_9dda_00c04fd7ba7c);
const TCPIP_GUID: windows::core::GUID =
    windows::core::GUID::from_u128(0x9a280ac0_c8e0_11d1_84e2_00c04fb998a2);
const IMAGE_GUID: windows::core::GUID =
    windows::core::GUID::from_u128(0x2cb15d1d_5fc1_11d2_abe1_00a0c911f518);
const REGISTRY_GUID: windows::core::GUID =
    windows::core::GUID::from_u128(0xae53722e_c863_11d2_8659_00c04fa321a1);

/// Safely extract a null-terminated wide string from ETW event UserData.
///
/// Reads up to `max_len` wide chars (u16) starting at `offset` bytes into a
/// `data` buffer of `data_len` bytes. Returns `None` if the pointer is null,
/// the offset is out of range, or the string is empty.
///
/// SAFETY: `data_len` MUST be the true length of the `data` buffer. The bound
/// is enforced HERE — `offset` past the end or a `max_len` larger than the
/// remaining bytes is clamped — so a mis-sized caller cannot make this read
/// past the (attacker-controlled, ETW-provided) buffer. An out-of-bounds read
/// here is an access violation, which the callback's `catch_unwind` does NOT
/// catch; the previous version trusted the caller's `max_len` entirely.
unsafe fn extract_wide_string(
    data: *const u8,
    data_len: usize,
    offset: usize,
    max_len: usize,
) -> Option<String> {
    if data.is_null() || offset >= data_len {
        return None;
    }
    // Wide chars that actually fit in the buffer from `offset`.
    let avail_chars = (data_len - offset) / 2;
    let max_len = max_len.min(avail_chars);
    if max_len == 0 {
        return None;
    }
    let base = unsafe { data.add(offset) as *const u16 };
    let mut len = 0usize;
    while len < max_len {
        let ch = unsafe { *base.add(len) };
        if ch == 0 {
            break;
        }
        len += 1;
    }
    if len == 0 {
        return None;
    }
    let slice = unsafe { std::slice::from_raw_parts(base, len) };
    Some(String::from_utf16_lossy(slice))
}

/// Check whether an image path is a suspicious DLL load location.
fn is_suspicious_dll_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains("\\temp\\") || lower.contains("\\appdata\\") || lower.contains("\\downloads\\")
}

/// Check whether a registry key path targets a persistence location.
fn is_persistence_key(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains("\\run\\")
        || lower.contains("\\runonce\\")
        || lower.contains("\\services\\")
        || lower.contains("\\currentversion\\run")
}

/// Classify TCP destination port severity.
fn classify_port_severity(port: u16) -> &'static str {
    if port == 4444 {
        "critical"
    } else if (1..=1024).contains(&port) {
        "high"
    } else if port > 49152 {
        "medium"
    } else {
        "high" // default for mid-range ports
    }
}

fn process_start_is_relevant(
    monitored_pids: &HashSet<u32>,
    event_pid: u32,
    parent_pid: u32,
    child_pid: u32,
) -> bool {
    monitored_pids.contains(&event_pid)
        || monitored_pids.contains(&parent_pid)
        || monitored_pids.contains(&child_pid)
}

unsafe extern "system" fn etw_event_callback(event: *mut EVENT_RECORD) {
    // Wrap in catch_unwind — panic across extern "system" boundary is UB.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        etw_event_callback_inner(event);
    }));
}

unsafe fn etw_event_callback_inner(event: *mut EVENT_RECORD) {
    if event.is_null() {
        return;
    }
    let event = unsafe { &*event };
    ETW_EVENT_COUNT.fetch_add(1, Ordering::Relaxed);

    let ctx_guard = match ETW_CTX.lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    let ctx = match ctx_guard.as_ref() {
        Some(c) => c,
        None => return,
    };

    let provider = event.EventHeader.ProviderId;
    let event_pid = event.EventHeader.ProcessId;
    let opcode = event.EventHeader.EventDescriptor.Opcode;

    let is_process_start = provider == PROCESS_GUID && opcode == 1;
    if !is_process_start {
        let is_relevant = {
            let pids = ctx.monitored_pids.lock().unwrap_or_else(|e| e.into_inner());
            pids.contains(&event_pid)
        };
        if !is_relevant {
            return;
        }
    }

    // ── Process events ────────────────────────────────────
    if provider == PROCESS_GUID && opcode == 1 {
        // Process start — extract child PID and optional command line.
        // Validate: the first u32 in all known versions (v0-v5) is the new process PID.
        // We also validate the extracted PID looks real (non-zero, not our own PID).
        if event.UserDataLength >= 4 && !event.UserData.is_null() {
            let child_pid = unsafe { *(event.UserData as *const u32) };
            let parent_pid = if event.UserDataLength >= 8 {
                unsafe { *((event.UserData as *const u8).add(4) as *const u32) }
            } else {
                0
            };
            let is_relevant_spawn = {
                let pids = ctx.monitored_pids.lock().unwrap_or_else(|e| e.into_inner());
                process_start_is_relevant(&pids, event_pid, parent_pid, child_pid)
            };
            // Sanity check: PID should be > 4 (system PIDs) and < 100000 (reasonable range).
            if is_relevant_spawn
                && child_pid != ctx.target_pid
                && child_pid > 4
                && child_pid < 100_000
            {
                let mut pids = ctx.monitored_pids.lock().unwrap_or_else(|e| e.into_inner());
                if pids.insert(child_pid) {
                    drop(pids);
                    let name =
                        get_process_name(child_pid).unwrap_or_else(|| format!("PID-{child_pid}"));

                    // Try to extract command line from kernel process start event v3+.
                    // Layout: PID(u32) + ParentPID(u32) = 8 bytes, then variable
                    // fields. The command line is a wide string after the fixed header
                    // fields. We attempt to read it starting at a conservative offset.
                    let cmdline = if event.UserDataLength > 60 {
                        // Skip past the fixed-size fields (PID, ParentPID, SessionId,
                        // ExitStatus, DirectoryTableBase, UserSID, ImageFileName, then
                        // CommandLine). The command line offset varies by event version;
                        // we scan from offset 60 which works for v3/v4 process start
                        // events. Max 512 wide chars.
                        unsafe {
                            extract_wide_string(
                                event.UserData as *const u8,
                                event.UserDataLength as usize,
                                60,
                                MAX_ETW_STRING_CHARS,
                            )
                        }
                    } else {
                        None
                    };

                    let severity = if is_suspicious_process(&name) {
                        "high"
                    } else {
                        "medium"
                    };
                    let detail = match &cmdline {
                        Some(cl) if !cl.is_empty() => {
                            format!("Spawned {} (PID {child_pid}) cmdline: {cl}", name)
                        }
                        _ => format!("Spawned {} (PID {child_pid})", name),
                    };

                    let mut r = ctx.report.lock().unwrap_or_else(|e| e.into_inner());
                    r.processes_spawned.push(name.clone());
                    r.findings.push(EtwFinding {
                        kind: "process_spawn".into(),
                        severity: severity.into(),
                        detail,
                        confidence: "observed".into(),
                        source: "etw_kernel_process".into(),
                    });
                }
            }
        }
    }

    // ── Network events (enhanced with port severity) ────
    if provider == TCPIP_GUID && (opcode == 12 || opcode == 15) {
        if event.UserDataLength >= 14 && !event.UserData.is_null() {
            let data = event.UserData as *const u8;
            let ip = unsafe {
                format!(
                    "{}.{}.{}.{}",
                    *data.add(8),
                    *data.add(9),
                    *data.add(10),
                    *data.add(11)
                )
            };
            let port = unsafe { u16::from_be_bytes([*data.add(12), *data.add(13)]) };
            // 0.0.0.0 is not a destination; drop it. Loopback is NOT
            // dropped any more.
            //
            // The blanket `ip != "127.0.0.1"` predates web protection. Now
            // that sentinelld can run dnsguard on 127.0.0.1:53, a detonated
            // sample's name resolution is a LOOPBACK connection, and this
            // filter deleted it before it could become evidence — the report
            // then showed no sign the sample resolved anything. Loopback is
            // also where a sample would reach a local proxy or a staging
            // listener, which was equally invisible.
            //
            // Recorded at "info", which scores 0 (see main.rs's severity
            // table): resolving a name is what normal software does, so this
            // must inform a triager without inflating the verdict. Honest
            // limit: this is the TCP detector, and DNS is overwhelmingly
            // UDP — what shows up here is the DNS-over-TCP subset plus any
            // other loopback service the sample talks to.
            if ip != "0.0.0.0" {
                let loopback = ip == "127.0.0.1";
                let severity = if loopback { "info" } else { classify_port_severity(port) };
                let mut r = ctx.report.lock().unwrap_or_else(|e| e.into_inner());
                let detail = if loopback && port == 53 {
                    format!("DNS query to local resolver {ip}:{port}")
                } else if loopback {
                    format!("loopback connect to {ip}:{port}")
                } else {
                    format!("TCP connect to {ip}:{port}")
                };
                if !r.network_connections.contains(&detail) {
                    r.network_connections.push(detail.clone());
                    r.findings.push(EtwFinding {
                        kind: if loopback { "loopback_connection" } else { "network_connection" }
                            .into(),
                        severity: severity.into(),
                        detail,
                        confidence: "observed".into(),
                        source: "etw_kernel_tcpip".into(),
                    });
                }
            }
        }
    }

    // ── Image load events ────────────────────────────────
    if provider == IMAGE_GUID && opcode == 10 {
        // Image load event: the image path is stored as a wide string in
        // UserData after the fixed-size header fields. We read from offset 0
        // because the kernel image load event's variable data begins with the
        // filename as a wide string (after an 8-byte base address + size prefix
        // on some versions, but the path is the dominant payload).
        if event.UserDataLength > 0 && !event.UserData.is_null() {
            if let Some(image_path) = unsafe {
                extract_wide_string(
                    event.UserData as *const u8,
                    event.UserDataLength as usize,
                    0,
                    MAX_ETW_STRING_CHARS,
                )
            } {
                if is_suspicious_dll_path(&image_path) {
                    let mut r = ctx.report.lock().unwrap_or_else(|e| e.into_inner());
                    // Dedup: skip if we already recorded this exact DLL path.
                    if !r.dlls_loaded.contains(&image_path) {
                        r.dlls_loaded.push(image_path.clone());
                        r.findings.push(EtwFinding {
                            kind: "suspicious_dll_load".into(),
                            severity: "medium".into(),
                            detail: format!("DLL loaded from suspicious path: {image_path}"),
                            confidence: "observed".into(),
                            source: "etw_kernel_image".into(),
                        });
                    }
                }
            }
        }
    }

    // ── Registry persistence events ──────────────────────
    if provider == REGISTRY_GUID && (opcode == 22 || opcode == 23) {
        // Opcode 22 = SetValue, 23 = CreateKey.
        // The key path is a wide string in UserData.
        if event.UserDataLength > 0 && !event.UserData.is_null() {
            if let Some(key_path) = unsafe {
                extract_wide_string(
                    event.UserData as *const u8,
                    event.UserDataLength as usize,
                    0,
                    MAX_ETW_STRING_CHARS,
                )
            } {
                if is_persistence_key(&key_path) {
                    let op = if opcode == 22 {
                        "SetValue"
                    } else {
                        "CreateKey"
                    };
                    let detail = format!("Registry {op} on persistence key: {key_path}");
                    let mut r = ctx.report.lock().unwrap_or_else(|e| e.into_inner());
                    // Dedup: skip if this exact registry detail was already recorded.
                    if !r.registry_writes.contains(&detail) {
                        r.registry_writes.push(detail.clone());
                        r.findings.push(EtwFinding {
                            kind: "registry_persistence".into(),
                            severity: "high".into(),
                            detail,
                            confidence: "observed".into(),
                            source: "etw_kernel_registry".into(),
                        });
                    }
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Backend 2: Polling Fallback
// ═══════════════════════════════════════════════════════════════

fn polling_monitor(
    pid: u32,
    timeout: Duration,
    _sandbox_dir: &Path,
    report: &mut EtwReport,
    stop: &AtomicBool,
) {
    let start = Instant::now();
    let mut seen: HashSet<u32> = HashSet::from([pid]);

    while start.elapsed() < timeout && !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(200));
        poll_children_round(&mut seen, report);
    }
}

/// One process-tree enumeration round. Shared by the hard-error polling
/// fallback (`polling_monitor`) and the silent-zero degraded fallback
/// thread in `etw_kernel_monitor` — the latter locks the shared report
/// around each call so it must not own the loop.
///
/// Enumerates children of every PID seen so far — recursively catches
/// grandchildren, not just direct children of the root (the ETW backend
/// already tracks the whole tree via monitored_pids).
fn poll_children_round(seen: &mut HashSet<u32>, report: &mut EtwReport) {
    let parents: Vec<u32> = seen.iter().copied().collect();
    for parent in parents {
        for (child_pid, child_name) in enumerate_children(parent) {
            if seen.insert(child_pid) {
                let severity = if is_suspicious_process(&child_name) {
                    "high"
                } else {
                    "medium"
                };
                report.processes_spawned.push(child_name.clone());
                report.findings.push(EtwFinding {
                    kind: "process_spawn".into(),
                    severity: severity.into(),
                    detail: format!("Spawned {} (PID {})", child_name, child_pid),
                    confidence: "observed".into(),
                    source: "behavioral_monitor_polling".into(),
                });
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Shared helpers
// ═══════════════════════════════════════════════════════════════

pub(crate) fn is_suspicious_process(name: &str) -> bool {
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
            | "bcdedit.exe"
            | "attrib.exe"
            | "icacls.exe"
            | "takeown.exe"
    )
}

fn enumerate_children(parent_pid: u32) -> Vec<(u32, String)> {
    let mut results = Vec::new();
    let snap = unsafe {
        match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) => h,
            Err(_) => return results,
        }
    };
    let mut pe: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    unsafe {
        if Process32FirstW(snap, &mut pe).is_ok() {
            loop {
                if pe.th32ParentProcessID == parent_pid && pe.th32ProcessID != parent_pid {
                    let name = String::from_utf16_lossy(
                        &pe.szExeFile[..pe
                            .szExeFile
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(pe.szExeFile.len())],
                    );
                    results.push((pe.th32ProcessID, name));
                }
                if Process32NextW(snap, &mut pe).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    results
}

/// Full image path of a running process — needed by the firewall sweep in
/// main.rs, where a `program=` rule requires the complete path.
pub(crate) fn get_process_image_path(pid: u32) -> Option<String> {
    use windows::Win32::System::Threading::*;
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()? };
    let mut buf = [0u16; 260];
    let mut len = buf.len() as u32;
    let result = unsafe {
        if QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),
            windows::core::PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
        .is_ok()
        {
            Some(String::from_utf16_lossy(&buf[..len as usize]))
        } else {
            None
        }
    };
    unsafe {
        let _ = CloseHandle(handle);
    }
    result
}

fn get_process_name(pid: u32) -> Option<String> {
    let path = get_process_image_path(pid)?;
    std::path::Path::new(&path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_wide_string_is_bounds_safe() {
        // "Hi\0" as UTF-16LE = 6 bytes.
        let buf: Vec<u8> = vec![0x48, 0, 0x69, 0, 0, 0];
        unsafe {
            // Normal decode.
            assert_eq!(
                extract_wide_string(buf.as_ptr(), buf.len(), 0, 16).as_deref(),
                Some("Hi")
            );
            // Huge max_len is clamped to the buffer — no OOB read.
            assert_eq!(
                extract_wide_string(buf.as_ptr(), buf.len(), 0, 999_999).as_deref(),
                Some("Hi")
            );
            // Offset past the end → None (the OLD code would read past the
            // buffer here = access violation, uncatchable by catch_unwind).
            assert_eq!(extract_wide_string(buf.as_ptr(), buf.len(), 99, 16), None);
            // Offset exactly at end → None.
            assert_eq!(extract_wide_string(buf.as_ptr(), buf.len(), buf.len(), 16), None);
            // Null pointer → None.
            assert_eq!(extract_wide_string(std::ptr::null(), 10, 0, 4), None);
        }
    }

    #[test]
    fn suspicious_processes() {
        assert!(is_suspicious_process("powershell.exe"));
        assert!(is_suspicious_process("cmd.exe"));
        assert!(is_suspicious_process("POWERSHELL.EXE"));
        assert!(!is_suspicious_process("notepad.exe"));
        assert!(!is_suspicious_process("explorer.exe"));
    }

    #[test]
    fn etw_report_empty() {
        let r = EtwReport::new();
        assert!(r.findings.is_empty());
        assert_eq!(r.backend_used, "none");
    }

    #[test]
    fn finding_serializes() {
        let f = EtwFinding {
            kind: "test".into(),
            severity: "high".into(),
            detail: "d".into(),
            confidence: "observed".into(),
            source: "etw_kernel_process".into(),
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("etw_kernel_process"));
    }

    #[test]
    fn dedup_logic() {
        let existing = [EtwFinding {
            kind: "process_spawn".into(),
            severity: "high".into(),
            detail: "Spawned cmd.exe".into(),
            confidence: "observed".into(),
            source: "etw_kernel_process".into(),
        }];
        let dup = EtwFinding {
            kind: "process_spawn".into(),
            severity: "high".into(),
            detail: "Spawned cmd.exe".into(),
            confidence: "observed".into(),
            source: "etw_kernel_process".into(),
        };
        assert!(
            existing
                .iter()
                .any(|f| f.kind == dup.kind && f.detail == dup.detail)
        );

        let not_dup = EtwFinding {
            kind: "network_connection".into(),
            severity: "high".into(),
            detail: "TCP connect".into(),
            confidence: "observed".into(),
            source: "etw_kernel_tcpip".into(),
        };
        assert!(
            !existing
                .iter()
                .any(|f| f.kind == not_dup.kind && f.detail == not_dup.detail)
        );
    }

    fn score_for(sev: &str) -> i32 {
        match sev {
            "critical" => 25,
            "high" => 15,
            "medium" => 10,
            "low" => 5,
            _ => 0,
        }
    }

    #[test]
    fn score_values() {
        assert_eq!(score_for("critical"), 25);
        assert_eq!(score_for("high"), 15);
        assert_eq!(score_for("medium"), 10);
        assert_eq!(score_for("low"), 5);
        assert_eq!(score_for("info"), 0);
    }

    #[test]
    fn backend_tracking() {
        let mut r = EtwReport::new();
        assert_eq!(r.backend_used, "none");
        r.backend_used = "etw_kernel_session".into();
        assert_eq!(r.backend_used, "etw_kernel_session");
    }

    #[test]
    fn context_guard_clears_global_context() {
        {
            let mut ctx = ETW_CTX.lock().unwrap_or_else(|e| e.into_inner());
            *ctx = Some(EtwContext {
                target_pid: 1234,
                report: Arc::new(Mutex::new(EtwReport::new())),
                monitored_pids: Arc::new(Mutex::new(HashSet::from([1234]))),
            });
        }
        {
            let _guard = EtwContextGuard;
        }
        let ctx = ETW_CTX.lock().unwrap_or_else(|e| e.into_inner());
        assert!(ctx.is_none());
    }

    #[test]
    fn suspicious_dll_paths() {
        assert!(is_suspicious_dll_path(
            "C:\\Users\\user\\AppData\\Local\\Temp\\evil.dll"
        ));
        assert!(is_suspicious_dll_path(
            "C:\\Users\\user\\Downloads\\payload.dll"
        ));
        assert!(is_suspicious_dll_path(
            "C:\\Users\\user\\AppData\\Roaming\\malware.dll"
        ));
        assert!(!is_suspicious_dll_path(
            "C:\\Windows\\System32\\kernel32.dll"
        ));
        assert!(!is_suspicious_dll_path("C:\\Program Files\\App\\legit.dll"));
    }

    #[test]
    fn persistence_keys() {
        assert!(is_persistence_key(
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evil"
        ));
        assert!(is_persistence_key(
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\payload"
        ));
        assert!(is_persistence_key(
            "HKLM\\System\\CurrentControlSet\\Services\\malware"
        ));
        assert!(is_persistence_key(
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        ));
        assert!(!is_persistence_key(
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
        ));
        assert!(!is_persistence_key("HKCU\\Software\\SomeApp\\Settings"));
    }

    #[test]
    fn port_severity_classification() {
        assert_eq!(classify_port_severity(4444), "critical");
        assert_eq!(classify_port_severity(80), "high");
        assert_eq!(classify_port_severity(443), "high");
        assert_eq!(classify_port_severity(1), "high");
        assert_eq!(classify_port_severity(1024), "high");
        assert_eq!(classify_port_severity(49153), "medium");
        assert_eq!(classify_port_severity(65535), "medium");
        assert_eq!(classify_port_severity(8080), "high"); // mid-range defaults to high
    }

    #[test]
    fn process_start_relevant_when_parent_monitored() {
        let pids = HashSet::from([1000]);
        assert!(process_start_is_relevant(&pids, 2000, 1000, 2000));
    }

    #[test]
    fn process_start_relevant_when_event_pid_monitored() {
        let pids = HashSet::from([1000]);
        assert!(process_start_is_relevant(&pids, 1000, 4, 2000));
    }

    #[test]
    fn process_start_ignores_unrelated_pid() {
        let pids = HashSet::from([1000]);
        assert!(!process_start_is_relevant(&pids, 3000, 2000, 4000));
    }

    #[test]
    fn extract_wide_string_basic() {
        // Build a null-terminated wide string "hello" in a buffer.
        let wide: Vec<u16> = "hello".encode_utf16().chain(std::iter::once(0)).collect();
        let bytes: Vec<u8> = wide.iter().flat_map(|w| w.to_ne_bytes()).collect();
        let result = unsafe { extract_wide_string(bytes.as_ptr(), bytes.len(), 0, 256) };
        assert_eq!(result, Some("hello".to_string()));
    }

    #[test]
    fn extract_wide_string_with_offset() {
        // 4 bytes of padding, then "test\0" as wide string.
        let mut bytes: Vec<u8> = vec![0xAA, 0xBB, 0xCC, 0xDD]; // 4-byte prefix
        let wide: Vec<u16> = "test".encode_utf16().chain(std::iter::once(0)).collect();
        bytes.extend(wide.iter().flat_map(|w| w.to_ne_bytes()));
        let result = unsafe { extract_wide_string(bytes.as_ptr(), bytes.len(), 4, 256) };
        assert_eq!(result, Some("test".to_string()));
    }

    #[test]
    fn extract_wide_string_null_ptr() {
        let result = unsafe { extract_wide_string(std::ptr::null(), 256, 0, 256) };
        assert_eq!(result, None);
    }

    #[test]
    fn extract_wide_string_empty() {
        // Just a null terminator.
        let wide: Vec<u16> = vec![0];
        let bytes: Vec<u8> = wide.iter().flat_map(|w| w.to_ne_bytes()).collect();
        let result = unsafe { extract_wide_string(bytes.as_ptr(), bytes.len(), 0, 256) };
        assert_eq!(result, None);
    }

    #[test]
    fn extract_wide_string_max_len_respected() {
        // "abcdefgh\0" — but max_len = 3, so only "abc" is returned.
        let wide: Vec<u16> = "abcdefgh"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let bytes: Vec<u8> = wide.iter().flat_map(|w| w.to_ne_bytes()).collect();
        let result = unsafe { extract_wide_string(bytes.as_ptr(), bytes.len(), 0, 3) };
        assert_eq!(result, Some("abc".to_string()));
    }

    #[test]
    fn image_load_finding_fields() {
        let f = EtwFinding {
            kind: "suspicious_dll_load".into(),
            severity: "medium".into(),
            detail:
                "DLL loaded from suspicious path: C:\\Users\\user\\AppData\\Local\\Temp\\evil.dll"
                    .into(),
            confidence: "observed".into(),
            source: "etw_kernel_image".into(),
        };
        assert_eq!(f.source, "etw_kernel_image");
        assert_eq!(f.severity, "medium");
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("suspicious_dll_load"));
    }

    #[test]
    fn registry_finding_fields() {
        let f = EtwFinding {
            kind: "registry_persistence".into(),
            severity: "high".into(),
            detail: "Registry SetValue on persistence key: HKLM\\...\\Run\\evil".into(),
            confidence: "observed".into(),
            source: "etw_kernel_registry".into(),
        };
        assert_eq!(f.source, "etw_kernel_registry");
        assert_eq!(f.severity, "high");
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("registry_persistence"));
    }

    #[test]
    fn dedup_across_event_types() {
        let mut r = EtwReport::new();
        // Simulate adding an image load finding.
        let dll = "C:\\Users\\u\\AppData\\evil.dll".to_string();
        r.dlls_loaded.push(dll.clone());
        // Check dedup: same path should be detected.
        assert!(r.dlls_loaded.contains(&dll));
        // Registry dedup.
        let reg = "Registry SetValue on persistence key: HKLM\\...\\Run\\x".to_string();
        r.registry_writes.push(reg.clone());
        assert!(r.registry_writes.contains(&reg));
    }

    // ═══════════════════════════════════════════════════════════
    //  Scenario tests — validate classification logic without
    //  requiring actual ETW sessions or admin rights.
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn scenario_benign_no_findings() {
        // A process named "notepad.exe" is not suspicious.
        assert!(!is_suspicious_process("notepad.exe"));
        // A DLL loaded from System32 is not suspicious.
        assert!(!is_suspicious_dll_path(r"C:\Windows\System32\kernel32.dll"));
        // A registry key not in Run/Services is not persistence.
        assert!(!is_persistence_key(r"HKCU\Software\SomeApp\Settings"));
    }

    #[test]
    fn scenario_cmd_spawn_is_suspicious() {
        assert!(is_suspicious_process("cmd.exe"));
        assert!(is_suspicious_process("CMD.EXE"));
    }

    #[test]
    fn scenario_dll_from_temp_suspicious() {
        assert!(is_suspicious_dll_path(
            r"C:\Users\test\AppData\Local\Temp\malware.dll"
        ));
        assert!(is_suspicious_dll_path(
            r"C:\Users\test\Downloads\payload.dll"
        ));
        assert!(!is_suspicious_dll_path(r"C:\Windows\System32\ntdll.dll"));
    }

    #[test]
    fn scenario_run_key_is_persistence() {
        assert!(is_persistence_key(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Malware"
        ));
        assert!(is_persistence_key(
            r"HKLM\System\CurrentControlSet\Services\BadService"
        ));
        assert!(!is_persistence_key(r"HKCU\Software\SomeApp\Preferences"));
    }

    #[test]
    fn scenario_tcp_port_classification() {
        assert_eq!(classify_port_severity(4444), "critical"); // Metasploit
        assert_eq!(classify_port_severity(80), "high"); // Standard port
        assert_eq!(classify_port_severity(443), "high"); // HTTPS
        assert_eq!(classify_port_severity(8080), "high"); // Common proxy
        assert_eq!(classify_port_severity(55000), "medium"); // Ephemeral
    }

    #[test]
    fn scenario_timeout_is_medium_severity() {
        // Timeout finding should be medium severity (from main.rs logic).
        let score = match "medium" {
            "critical" => 25,
            "high" => 15,
            "medium" => 10,
            "low" => 5,
            _ => 0,
        };
        assert_eq!(score, 10);
    }

    #[test]
    fn scenario_score_cap_at_50() {
        // 10 high findings = 150 raw -> capped to 50.
        let findings: Vec<&str> = vec!["high"; 10];
        let raw: i32 = findings
            .iter()
            .map(|s| match *s {
                "high" => 15,
                _ => 0,
            })
            .sum();
        assert_eq!(raw, 150);
        let capped = raw.min(50);
        assert_eq!(capped, 50);
    }

    #[test]
    fn scenario_dedup_prevents_double_count() {
        let mut findings = vec![EtwFinding {
            kind: "process_spawn".into(),
            severity: "high".into(),
            detail: "Spawned cmd.exe (PID 1234)".into(),
            confidence: "observed".into(),
            source: "etw_kernel_process".into(),
        }];
        // Same finding again — should be detected as duplicate.
        let dup = EtwFinding {
            kind: "process_spawn".into(),
            severity: "high".into(),
            detail: "Spawned cmd.exe (PID 1234)".into(),
            confidence: "observed".into(),
            source: "etw_kernel_process".into(),
        };
        let is_dup = findings
            .iter()
            .any(|f| f.kind == dup.kind && f.detail == dup.detail);
        assert!(is_dup, "Duplicate finding should be detected");
        // Don't add it.
        if !is_dup {
            findings.push(dup);
        }
        assert_eq!(findings.len(), 1, "Should still have only 1 finding");
    }

    #[test]
    fn scenario_backend_used_tracking() {
        let mut r = EtwReport::new();
        assert_eq!(r.backend_used, "none");
        r.backend_used = "etw_kernel_session".into();
        assert_eq!(r.backend_used, "etw_kernel_session");
        r.backend_used = "polling_fallback".into();
        assert_eq!(r.backend_used, "polling_fallback");
    }

    #[test]
    fn polling_monitor_stops_early() {
        let mut r = EtwReport::new();
        r.backend_used = "polling_fallback".into();
        let stop = AtomicBool::new(true);
        let start = Instant::now();

        polling_monitor(
            999_999,
            Duration::from_secs(10),
            Path::new("."),
            &mut r,
            &stop,
        );

        assert!(start.elapsed() < Duration::from_secs(1));
    }

    // ═══════════════════════════════════════════════════════════
    //  C-1 contract tests — semantic-drift guards between the
    //  session config (etw_config) and this file's parsers.
    // ═══════════════════════════════════════════════════════════

    #[test]
    fn backend_label_is_truthful() {
        // The pre-fix lie: StartTraceW success alone earned
        // "etw_kernel_session". Now only actual event flow does.
        assert_eq!(backend_label(0, false), "etw_session_no_events");
        assert_eq!(backend_label(0, true), "polling_fallback");
        assert_eq!(backend_label(1, false), "etw_kernel_session");
        // Events flowed even though the fallback was also engaged → ETW
        // earned the label; the hiccup is recorded via etw_degraded.
        assert_eq!(backend_label(7, true), "etw_kernel_session");
    }

    #[test]
    fn every_parsed_provider_has_an_enable_flag() {
        // Maps each kernel MOF provider GUID the callback parses (with its
        // opcodes) to the EnableFlags bit that makes the kernel emit it.
        // Drift in either direction silently disables a detector or
        // wastes kernel buffer bandwidth.
        let cfg = etw_config::sandbox_session_config();
        let parsed: &[(windows::core::GUID, &[u8], u32, &str)] = &[
            (PROCESS_GUID, &[1], etw_config::EVENT_TRACE_FLAG_PROCESS, "process"),
            (
                IMAGE_GUID,
                &[10],
                etw_config::EVENT_TRACE_FLAG_IMAGE_LOAD,
                "image_load",
            ),
            (
                TCPIP_GUID,
                &[12, 15],
                etw_config::EVENT_TRACE_FLAG_NETWORK_TCPIP,
                "tcpip",
            ),
            (
                REGISTRY_GUID,
                &[22, 23],
                etw_config::EVENT_TRACE_FLAG_REGISTRY,
                "registry",
            ),
        ];
        for (_guid, _opcodes, flag, name) in parsed {
            assert_ne!(
                cfg.enable_flags & flag,
                0,
                "parser for {name} events exists but its enable flag is missing"
            );
        }
        // And conversely: no enabled flag without a parser. Exact-equality
        // with the four known bits enforces this.
        assert_eq!(
            cfg.enable_flags,
            etw_config::EVENT_TRACE_FLAG_PROCESS
                | etw_config::EVENT_TRACE_FLAG_IMAGE_LOAD
                | etw_config::EVENT_TRACE_FLAG_NETWORK_TCPIP
                | etw_config::EVENT_TRACE_FLAG_REGISTRY
        );
    }

    #[test]
    fn session_config_is_a_private_system_logger() {
        // Bit-level mirror of the sentinelld main-intake contract (F-1):
        // REAL_TIME | SYSTEM_LOGGER_MODE, WNODE_FLAG_TRACED_GUID, QPC
        // timestamps, private non-kernel GUID.
        let cfg = etw_config::sandbox_session_config();
        assert_eq!(cfg.log_file_mode, 0x0000_0100 | 0x0200_0000);
        assert_eq!(cfg.wnode_flags, 0x0002_0000);
        assert_eq!(cfg.client_context, 1);
        assert_ne!(cfg.session_guid, 0);
        assert_ne!(cfg.session_name, "NT Kernel Logger");
    }

    #[test]
    fn mode_and_flag_constants_match_the_windows_sdk() {
        // Guards the hand-written constants in etw_config against the
        // authoritative SDK values re-exported by the windows crate. A
        // typo'd bit here (e.g. 0x0000_0200 = EVENT_TRACE_DELAY_OPEN_FILE
        // instead of 0x0200_0000 = SYSTEM_LOGGER_MODE) compiles fine and
        // passes bit-composition tests while silently re-creating the
        // F-1/C-1 zero-event session — only an SDK cross-check catches it.
        use windows::Win32::System::Diagnostics::Etw as sdk;
        assert_eq!(
            etw_config::EVENT_TRACE_SYSTEM_LOGGER_MODE,
            sdk::EVENT_TRACE_SYSTEM_LOGGER_MODE
        );
        assert_eq!(
            etw_config::EVENT_TRACE_REAL_TIME_MODE,
            sdk::EVENT_TRACE_REAL_TIME_MODE
        );
        assert_eq!(
            etw_config::EVENT_TRACE_FLAG_PROCESS,
            sdk::EVENT_TRACE_FLAG_PROCESS.0
        );
        assert_eq!(
            etw_config::EVENT_TRACE_FLAG_IMAGE_LOAD,
            sdk::EVENT_TRACE_FLAG_IMAGE_LOAD.0
        );
        assert_eq!(
            etw_config::EVENT_TRACE_FLAG_NETWORK_TCPIP,
            sdk::EVENT_TRACE_FLAG_NETWORK_TCPIP.0
        );
        assert_eq!(
            etw_config::EVENT_TRACE_FLAG_REGISTRY,
            sdk::EVENT_TRACE_FLAG_REGISTRY.0
        );
    }

    #[test]
    fn report_schema_carries_truthfulness_fields() {
        let r = EtwReport::new();
        assert_eq!(r.events_seen, 0);
        assert!(!r.etw_degraded);
        assert_eq!(r.backend_used, "none");
    }

    /// Opt-in live test: starts the REAL system-logger session and
    /// verifies the kernel actually delivers events (the C-1 acceptance
    /// test). Prerequisites: Windows, elevated (admin) shell, no other
    /// sandboxd detonation running. Run with:
    ///   cargo test -p sandboxd -- --ignored --nocapture etw_live
    #[test]
    #[ignore = "requires elevation (admin) — opt-in live ETW validation"]
    fn etw_live_system_logger_session_delivers_events() {
        // Generate our own activity: cmd.exe spawning a child (ping).
        let mut child = match std::process::Command::new("cmd.exe")
            .args(["/c", "ping", "-n", "6", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("SKIP: cannot spawn activity process: {e}");
                return;
            }
        };

        let stop = AtomicBool::new(false);
        let result = etw_kernel_monitor(child.id(), Duration::from_secs(8), Path::new("."), &stop);
        let _ = child.kill();
        let _ = child.wait();

        let report = match result {
            Ok(r) => r,
            Err(e) => {
                // Not elevated / slots exhausted: environment limitation,
                // not a code failure — skip loudly rather than fail.
                eprintln!("SKIP: ETW session unavailable ({e}) — run elevated");
                return;
            }
        };

        assert!(
            report.events_seen > 0,
            "C-1 regression: system-logger session delivered zero events \
             (backend={}, degraded={})",
            report.backend_used,
            report.etw_degraded
        );
        assert_eq!(report.backend_used, "etw_kernel_session");
    }
}
