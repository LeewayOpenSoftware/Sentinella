//! IPC server — JSON-RPC 2.0 over named pipe (Windows) or Unix socket.
//!
//! Security hardening:
//! - Frame size bounds (min 2, max 1 MiB — `MAX_FRAME_SIZE`)
//! - Method name length limit (64 chars)
//! - catch_unwind around dispatch to prevent daemon crash
//! - Graceful error responses for all failure modes

use anyhow::Result;
use sentinella_ipc_proto::*;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};

mod client_auth;
// Consumed only by the Windows named-pipe accept loop; on other targets the
// unix-socket loop has no client-identity source to key it on (see mod note
// in run_unix_socket), so silence the dead-code lint there.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
mod fairness;
mod policy;
mod state;
pub use state::{
    ARGUS_ONLY_QUARANTINE_SCORE, AppState, argus_analysis_error, unify_detection_filtered,
};

/// Min valid JSON-RPC frame: `{}`
const MIN_FRAME_SIZE: usize = 2;

/// Single-flight guard for `sources.update` (see handler). The update
/// pipeline downloads + verifies + activates provider signature files and
/// can run for minutes; concurrent invocations would race the same staging
/// directories and double the network load.
static SOURCES_UPDATE_IN_PROGRESS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(target_os = "windows")]
struct PipeSecurity {
    descriptor: windows::Win32::Security::PSECURITY_DESCRIPTOR,
    attrs: windows::Win32::Security::SECURITY_ATTRIBUTES,
}

#[cfg(target_os = "windows")]
impl PipeSecurity {
    fn new() -> Result<Self> {
        use std::os::windows::ffi::OsStrExt;
        use windows::Win32::Foundation::BOOL;
        use windows::Win32::Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        };
        use windows::core::PCWSTR;

        // SYSTEM + Administrators: full access.
        // Authenticated Users: read+write (connect + IPC only).
        // Critical ops still gated by IPC auth + challenge token + elevation check.
        let mut wide: Vec<u16> = std::ffi::OsStr::new("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_mut_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )?;
        }
        let attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: BOOL(0),
        };
        Ok(Self { descriptor, attrs })
    }
}

#[cfg(target_os = "windows")]
impl Drop for PipeSecurity {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(
                self.descriptor.0,
            ));
        }
    }
}

#[cfg(target_os = "windows")]
fn create_pipe_server(
    pipe_name: &str,
    first_instance: bool,
    security: &PipeSecurity,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use tokio::net::windows::named_pipe::ServerOptions;
    let mut options = ServerOptions::new();
    options.first_pipe_instance(first_instance);
    unsafe {
        options.create_with_security_attributes_raw(
            pipe_name,
            (&security.attrs as *const windows::Win32::Security::SECURITY_ATTRIBUTES)
                .cast_mut()
                .cast(),
        )
    }
}

pub struct Server {
    state: Arc<AppState>,
}

impl Server {
    pub fn with_engine(
        dll_dir: Option<PathBuf>,
        db_dir: Option<PathBuf>,
        database: Option<crate::db::Database>,
    ) -> Result<Self> {
        Ok(Self {
            state: Arc::new(AppState::new(dll_dir, db_dir, database)),
        })
    }

    pub fn state(&self) -> &Arc<AppState> {
        &self.state
    }

    pub async fn run(&self) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            self.run_named_pipe().await
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.run_unix_socket().await
        }
    }

    #[cfg(target_os = "windows")]
    async fn run_named_pipe(&self) -> Result<()> {
        let pipe_name = sentinella_common::IPC_PIPE_NAME;
        info!(pipe = pipe_name, "listening on named pipe");
        let pipe_security = PipeSecurity::new()?;

        // Create first pipe instance. Retry on contention.
        // Strategy: first 10 attempts with FILE_FLAG_FIRST_PIPE_INSTANCE=true
        // (proper ownership). If an orphan holds the pipe and refuses to die,
        // last 10 attempts fall back to first_instance=false so we can at
        // least attach to the existing pipe and serve requests. Without the
        // fallback the service would crash indefinitely while an orphan
        // GUI-spawned daemon held the pipe forever.
        let mut server = {
            let mut last_err = None;
            let mut srv = None;
            for attempt in 0..20 {
                let first = attempt < 10;
                match create_pipe_server(pipe_name, first, &pipe_security) {
                    Ok(s) => {
                        if !first {
                            warn!(attempt, "attached to existing pipe (orphan owner)");
                        }
                        srv = Some(s);
                        break;
                    }
                    Err(e) => {
                        warn!(attempt, first_instance = first, %e, "pipe creation failed, retrying in 3s");
                        last_err = Some(e);
                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    }
                }
            }
            match srv {
                Some(s) => s,
                None => {
                    error!("pipe creation failed after 20 attempts (60s) — giving up");
                    return Err(last_err.map(|e| anyhow::anyhow!(e))
                        .unwrap_or_else(|| anyhow::anyhow!("pipe creation failed")));
                }
            }
        };

        // MED (audit): cap concurrent connections. Each client costs a
        // tokio task + pipe handle + up to MAX_FRAME_SIZE of payload buffer
        // held for the whole read timeout, and nothing else limited
        // simultaneous clients — any local user could hold thousands of
        // half-open connections against the SYSTEM daemon (task/handle
        // exhaustion, GiB-scale transient allocations).
        let conn_sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

        // MED (v0.1.12 audit): the global cap bounds TOTAL connections but
        // is blind to who holds them — one principal (e.g. malware running
        // as the console user, which client_auth deliberately Allows) could
        // park all 64 permits with keep-alive frames and starve every other
        // caller; the shed below would then reject the victim, not the
        // flooder. Per-principal quota keyed on the accept-time SID — see
        // fairness.rs for the identity/trust/cap-sizing rationale.
        let principal_quota = fairness::PrincipalQuota::new();

        loop {
            // Wait for client connection.
            if let Err(e) = server.connect().await {
                // Brief backoff before recreating — prevents tight retry under contention.
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                self.state.record_ipc_error();
                debug!(%e, "pipe connect error, recreating");
                server = match create_pipe_server(pipe_name, false, &pipe_security) {
                    Ok(s) => s,
                    Err(e) => {
                        error!(%e, "failed to recreate pipe, backing off");
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        continue;
                    }
                };
                continue;
            }

            // IMMEDIATELY create next pipe instance BEFORE handling connection.
            // This eliminates the PIPE_BUSY window — a new listener is always ready.
            let connected_pipe = server;

            // Retry-with-backoff loop instead of `?` propagation.
            // Old code escaped run() entirely on the second failure, killing
            // the daemon's IPC server forever (only SCM restart would bring
            // it back). Now retries indefinitely with capped backoff.
            server = match create_pipe_server(pipe_name, false, &pipe_security) {
                Ok(s) => s,
                Err(e) => {
                    error!(%e, "failed to create next pipe instance, retrying with backoff");
                    let mut backoff_ms: u64 = 100;
                    loop {
                        tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                        match create_pipe_server(pipe_name, false, &pipe_security) {
                            Ok(s) => break s,
                            Err(e2) => {
                                warn!(%e2, backoff_ms, "pipe recreate failed, backing off");
                                backoff_ms = (backoff_ms * 2).min(5000);
                                self.state.record_ipc_error();
                            }
                        }
                    }
                }
            };

            // Per-connection client-SID authorization — independent of the
            // shared secret (which is world-readable for GUI compat). Rejects
            // anonymous and cross-user/non-console unprivileged callers. Runs
            // AFTER the next listener is ready so a reject can't starve the
            // pipe. Fails OPEN inside `authorize_and_resolve_pipe_client`
            // only on a transient resolution error (no client PID), so an
            // API quirk never bricks a legit GUI; fails CLOSED when the
            // client process already vanished (dead-PID elevation-bypass
            // guard — see client_auth::ResolveOutcome).
            //
            // v0.1.9: we now ALSO keep the resolved `ClientIdentity` and pass
            // it through to the dispatcher so kill-vector handlers can apply
            // a daemon-side elevation gate (closing the UAC-bypass hole flagged
            // by the v0.1.8 audit — see client_auth::require_elevation).
            //
            // Env kill-switch for field debugging.
            let peer_identity: Option<client_auth::ClientIdentity>;
            #[cfg(target_os = "windows")]
            {
                use std::os::windows::io::AsRawHandle;
                let bypass = std::env::var("SENTINELLA_DISABLE_CLIENT_SID_CHECK")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
                if bypass {
                    // Kill-switch active — forwards `None` identity. SR-03:
                    // `require_elevation(None)` now fails CLOSED, so with the
                    // kill-switch set the connection still serves reads but
                    // privileged-mutation methods are denied (no resolved
                    // elevated identity to authorize them). Clear the
                    // kill-switch to perform kill-vector mutations.
                    peer_identity = None;
                } else {
                    match client_auth::authorize_and_resolve_pipe_client(
                        connected_pipe.as_raw_handle(),
                    ) {
                        client_auth::PipeAuth::Allow { identity } => {
                            peer_identity = identity;
                        }
                        client_auth::PipeAuth::Deny => {
                            // Unauthorized — close without serving; next listener is ready.
                            drop(connected_pipe);
                            self.state.record_ipc_error();
                            continue;
                        }
                    }
                }
            }
            #[cfg(not(target_os = "windows"))]
            {
                peer_identity = None;
            }

            // Spawn handler for connected client. Single spawn site regardless
            // of whether server recreation succeeded immediately or after retries.
            //
            // Bounded by conn_sem, but we SHED LOAD rather than park the
            // acceptor. Awaiting the permit here (the original form) was an
            // unauthenticated local availability kill: `client_auth::decide`
            // deliberately Allows any unelevated process in the active console
            // session, each `handle_connection` holds its permit for the whole
            // session, and the 60 s idle timer restarts on every frame — so 64
            // hold-open connections stalled this loop indefinitely. With the
            // loop parked, `server.connect()` is never polled again and every
            // GUI / tray / CLI request hangs, i.e. the entire management and
            // status control plane of an AV product dies. try_acquire keeps the
            // cap's handle/memory bound while guaranteeing the loop stays live;
            // rejected connections are dropped exactly like the Deny arm above.
            //
            // v0.1.12: the global cap alone let ONE principal occupy all 64
            // permits (each is held for the whole session and the idle timer
            // restarts per frame), starving every other caller — the shed
            // rejected the victim, not the flooder. We therefore also enforce
            // a per-principal quota keyed on the SID resolved above (or the
            // shared, separately-capped unidentified bucket on the fail-open
            // path). Identity is available BEFORE this point — auth runs at
            // accept time — so no reordering of resolution vs. acquisition is
            // needed. Order here: global try_acquire (existing shed) →
            // per-principal try_acquire (shed, releasing the global permit
            // via Drop). The quota's map mutex is never held across .await
            // and never while acquiring the semaphore, so there is no
            // lock-ordering between the two limits (see fairness.rs).
            debug!("client connected");
            let permit = match Arc::clone(&conn_sem).try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    warn!("connection cap reached; shedding client");
                    drop(connected_pipe);
                    self.state.record_ipc_error();
                    continue;
                }
            };
            let principal_permit = match principal_quota.try_acquire(peer_identity.as_ref()) {
                Some(p) => p,
                None => {
                    // NOT silent: the operator must be able to see which
                    // principal exhausted its allowance.
                    warn!(
                        sid = peer_identity.as_ref().map(|i| i.sid.as_str()).unwrap_or("unresolved"),
                        "per-principal connection cap reached; shedding client"
                    );
                    drop(connected_pipe);
                    self.state.record_ipc_error();
                    continue; // global permit released here by Drop
                }
            };
            let st = Arc::clone(&self.state);
            tokio::spawn(async move {
                let _permit = permit;
                let _principal_permit = principal_permit;
                if let Err(e) = handle_connection(connected_pipe, st, peer_identity).await {
                    warn!(%e, "client session error");
                }
            });
        }
    }

    #[cfg(not(target_os = "windows"))]
    async fn run_unix_socket(&self) -> Result<()> {
        use tokio::net::UnixListener;
        let sock_path = sentinella_common::IPC_SOCKET_PATH;
        let _ = std::fs::remove_file(sock_path);
        if let Some(p) = std::path::Path::new(sock_path).parent() {
            std::fs::create_dir_all(p)?;
        }
        let listener = UnixListener::bind(sock_path)?;
        info!(path = sock_path, "listening on unix socket");
        // Same concurrent-connection cap as the Windows named-pipe loop.
        let conn_sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
        loop {
            let (stream, _) = listener.accept().await?;
            debug!("client connected");
            // Shed load instead of parking the acceptor — see the Windows loop
            // above for why awaiting the permit here is a self-inflicted DoS.
            //
            // NOTE: the per-principal fairness quota (fairness.rs) is
            // Windows-only by design — this path has no client-identity
            // source to key it on, and bucketing every Unix connection as
            // "unidentified" would silently tighten this loop from 64 to 16
            // concurrent clients. The global cap plus socket-file
            // permissions remain the mitigation here (dev-oriented path).
            let permit = match Arc::clone(&conn_sem).try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    warn!("connection cap reached; shedding client");
                    drop(stream);
                    continue;
                }
            };
            let st = Arc::clone(&self.state);
            tokio::spawn(async move {
                let _permit = permit;
                // Unix has no equivalent ClientIdentity plumbing today; the
                // elevation gate fails-open on None (matching the Windows
                // unresolved-identity path).
                if let Err(e) = handle_connection(stream, st, None).await {
                    warn!(%e, "client session error");
                }
            });
        }
    }
}

/// Per-connection idle timeout — drop stalled connections.
const CONNECTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// Per-read timeout — prevent slow-read attacks.
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Per-write timeout — a client that stops reading must not pin the
/// connection task + response buffer forever.
const WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Max simultaneous client connections (see run_named_pipe).
const MAX_CONCURRENT_CONNECTIONS: usize = 64;

async fn handle_connection<S>(
    mut stream: S,
    state: Arc<AppState>,
    peer: Option<client_auth::ClientIdentity>,
) -> Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut len_buf = [0u8; 4];
    loop {
        // Idle timeout — disconnect if no new request within CONNECTION_TIMEOUT.
        match tokio::time::timeout(CONNECTION_TIMEOUT, stream.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!("client disconnected");
                return Ok(());
            }
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                debug!("client idle timeout");
                return Ok(());
            }
        }

        let frame_len = u32::from_be_bytes(len_buf) as usize;

        // Frame size validation.
        if frame_len < MIN_FRAME_SIZE {
            warn!(frame_len, "frame too small, dropping");
            return Ok(());
        }
        if frame_len > MAX_FRAME_SIZE {
            error!(frame_len, "frame too large, dropping");
            return Ok(());
        }

        let mut payload = vec![0u8; frame_len];
        // Read timeout — prevent slow-read DoS.
        match tokio::time::timeout(READ_TIMEOUT, stream.read_exact(&mut payload)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                warn!("client read timeout during payload");
                return Ok(());
            }
        }

        // Parse and dispatch with panic protection.
        let response = match serde_json::from_slice::<RpcRequest>(&payload) {
            Ok(ref req) => {
                // Method name length limit.
                if req.method.len() > 64 {
                    serde_json::to_vec(&RpcErrorResponse::err(
                        req.id,
                        error_codes::INVALID_REQUEST,
                        "method name too long",
                    ))
                    .unwrap_or_default()
                } else {
                    // Catch panics in dispatch to prevent daemon crash.
                    // peer is the per-connection ClientIdentity resolved at
                    // accept time (or None on fail-open); dispatch uses it
                    // for the v0.1.9 elevation gate on kill-vector methods.
                    let peer_ref = peer.as_ref();
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        // We can't use async inside catch_unwind easily,
                        // so dispatch is sync-safe (all our handlers are sync anyway).
                        dispatch_sync(req, &state, peer_ref)
                    })) {
                        Ok(resp) => resp,
                        Err(_) => {
                            error!(method = %req.method, "PANIC in dispatch handler — recovered");
                            serde_json::to_vec(&RpcErrorResponse::err(
                                req.id,
                                error_codes::INTERNAL_ERROR,
                                "internal error (recovered from panic)",
                            ))
                            .unwrap_or_default()
                        }
                    }
                }
            }
            Err(e) => {
                warn!(%e, "malformed JSON-RPC request");
                serde_json::to_vec(&RpcErrorResponse::err(
                    0,
                    error_codes::PARSE_ERROR,
                    format!("parse error: {e}"),
                ))
                .unwrap_or_default()
            }
        };

        // Fallback if serialization itself failed.
        const FALLBACK: &[u8] = b"{\"jsonrpc\":\"2.0\",\"id\":0,\"error\":{\"code\":-32603,\"message\":\"internal serialization error\"}}";
        let out: &[u8] = if response.is_empty() { FALLBACK } else { &response };
        let out_len = (out.len() as u32).to_be_bytes();
        // Write timeout — a client that stops reading must not block the
        // response write indefinitely (pins the task + buffer).
        match tokio::time::timeout(WRITE_TIMEOUT, stream.write_all(&out_len)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                debug!("client write timeout, dropping connection");
                return Ok(());
            }
        }
        match tokio::time::timeout(WRITE_TIMEOUT, stream.write_all(out)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                debug!("client write timeout, dropping connection");
                return Ok(());
            }
        }
    }
}

/// ☠️ R8-LETHAL: shared local-path validation for every IPC method that
/// makes the daemon touch a caller-supplied filesystem path (`scan.start`
/// target, `argus.analyze` path, …).
///
/// The daemon runs as SYSTEM. A path of `\\attacker.com\share\x` makes the
/// daemon authenticate to the remote SMB server using the machine-account
/// NTLM hash — captured by responder/inveigh and relayed to LDAP/CIFS/HTTP
/// for AD compromise. `\\.\PHYSICALDRIVE0` reads the raw disk as SYSTEM.
/// `\\?\GLOBALROOT\Device\…` bypasses path-canonicalization sanity checks
/// downstream. And because the IPC secret is intentionally readable by
/// BUILTIN\Users (see client_auth.rs), "authenticated" still means "any
/// logged-in user" — so EVERY path-accepting method needs this filter, not
/// just `scan.start` (the `argus.analyze` bypass was the audit finding
/// that prompted factoring this out).
///
/// We must still allow `\\?\C:\very-long-path` (Windows long-path
/// namespace — std::fs::canonicalize returns exactly this), so the filter
/// is precise.
fn validate_local_scan_path(t: &str) -> Result<(), &'static str> {
    if t.is_empty() {
        return Err("empty target path");
    }
    if t.len() > 4096 {
        return Err("target path too long");
    }
    // Refuse UNC / device-namespace targets.
    let lower = t.to_ascii_lowercase();
    let is_unc_share =
        (t.starts_with("\\\\") && !lower.starts_with(r"\\?\") && !lower.starts_with(r"\\.\"))
            || t.starts_with("//");
    let is_long_unc = lower.starts_with(r"\\?\unc\");
    let is_device_ns = lower.starts_with(r"\\.\")
        || lower.contains(r"\globalroot\")
        || lower.contains(r"\physicaldrive");
    if is_unc_share || is_long_unc || is_device_ns {
        return Err("scan target must be a local non-UNC path");
    }
    // Embedded NUL = win32 path-truncation trick.
    if t.contains('\0') {
        return Err("scan target contains embedded NUL");
    }
    Ok(())
}

/// Vault-blob plausibility check for the `quarantine.list` health flag.
/// Applies the minimum size of the format the blob actually carries:
/// chunked v1 = 16-byte header + 12-byte nonce + 16-byte tag = 44;
/// legacy one-shot = 12-byte nonce + 16-byte tag = 28. The previous
/// `len >= 12` accepted any truncated vault as "restorable".
fn vault_blob_plausible(path: &std::path::Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let Ok(len) = f.metadata().map(|m| m.len()) else {
        return false;
    };
    let mut magic = [0u8; 4];
    let n = f.read(&mut magic).unwrap_or(0);
    if n == 4 && magic == crate::quarantine::CHUNKED_MAGIC {
        len >= 44
    } else {
        len >= 28
    }
}

/// Adversary A2 — closed allowlist of methods that may be scoped by a
/// challenge token. Keep this list in lockstep with every handler call site
/// that invokes `validate_challenge_token`. An attacker who can request a
/// challenge for an arbitrary string could reuse it against any handler that
/// happens to validate against that same string, so we hard-code the legal
/// set here rather than echo whatever the caller asked for.
///
/// NOTE: `memory.scan_process` is the one entry whose handler does NOT
/// consume a challenge token — it is listed so the v0.1.9 elevation gate
/// (dispatch_sync) rejects unelevated callers: the response includes
/// ModuleInfo.base_address, a cross-privilege ASLR layout disclosure when
/// the caller is a normal user process. Its auth remains the IPC secret
/// (central AuthenticatedAction gate) + elevated-caller requirement.
fn is_challengeable_method(method: &str) -> bool {
    matches!(
        method,
        "engine.reload"
            | "argus.reload"
            | "settings.set"
            | "settings.set_full"
            | "sources.set"
            | "sources.update"
            | "sources.rollback"
            | "protection.set_critical"
            | "protection.disable"
            | "protection.enable"
            | "quarantine.add"
            | "quarantine.restore"
            | "quarantine.restore_as"
            | "quarantine.delete"
            | "memory.scan_process"
    )
}

/// Deep-merge `overlay` onto `base`, in place.
///
/// Objects merge key by key; every other JSON kind — arrays included — is
/// replaced wholesale, because a list-valued config knob is a single value
/// the caller either sets or doesn't, never something to append to. Merging
/// arrays element-wise would make it impossible to shorten a list.
fn json_merge_in_place(base: &mut serde_json::Value, overlay: &serde_json::Value) {
    match (base, overlay) {
        (serde_json::Value::Object(b), serde_json::Value::Object(o)) => {
            for (k, v) in o {
                json_merge_in_place(b.entry(k.clone()).or_insert(serde_json::Value::Null), v);
            }
        }
        (b, o) => *b = o.clone(),
    }
}

/// Build the `Config` that `settings.set` will persist, given the config
/// currently on disk and the raw IPC params object.
///
/// Two properties hold here. The handler up to v0.1.13 held neither: it
/// deserialized the params object on its own and pinned 15 of the 20
/// `CRITICAL_FIELDS`.
///
/// 1. **Omission is not mutation.** `Config` carries `#[serde(default)]`, so
///    `from_value::<Config>(params)` resurrects the *Default* for every key
///    the caller left out. A request as small as `{max_file_size_mb: 1024}`
///    therefore used to rewrite the entire file — silently flipping
///    `clamav_isolation` back to `"in_process"`, `fish.active_response` back
///    to `"observe"`, `sandbox.enabled` off and `web_protection` off with its
///    blocklists emptied. Merging the params ONTO the on-disk config first
///    means an absent key keeps its stored value.
///
/// 2. **Kill-vector fields are pinned even when sent explicitly.**
///    `settings.set` is not the elevated path; `protection.set_critical` is.
///    Every entry of `proto::full_config::CRITICAL_FIELDS` is restored from
///    `current` below — the `settings_set_pins_every_critical_field` test
///    walks that list and fails if a future addition is missed.
///    `[web_protection]` is pinned too. It IS bridged into `FullConfig`
///    (as an `Option`) and every `web_protection.*` path is in
///    `CRITICAL_FIELDS`, so the elevated `protection.set_critical`
///    handler is the one IPC mutation path for it. Letting plain
///    `settings.set` write the section would be an UNELEVATED way to
///    reroute or disable the machine's DNS filtering.
fn settings_set_merge(
    current: &crate::config::Config,
    params: &serde_json::Value,
) -> Result<crate::config::Config, String> {
    let mut merged = serde_json::to_value(current)
        .map_err(|e| format!("cannot serialize current config: {e}"))?;
    let mut overlay = params.clone();
    if let Some(obj) = overlay.as_object_mut() {
        // IPC envelope, not config schema (see the same strip in
        // settings.set_full).
        obj.remove("auth");
        obj.remove("token");
    }
    json_merge_in_place(&mut merged, &overlay);
    let mut config: crate::config::Config =
        serde_json::from_value(merged).map_err(|e| format!("invalid config: {e}"))?;

    // ── Security-critical fields restored from the on-disk config ──
    // These can ONLY be changed via protection.set_critical (challenge token
    // + UAC elevation on the GUI side).
    //
    // APT kill vector: attacker with the IPC secret calls settings.set to
    // inject exclusions that suppress all detection. Pinning forces the
    // attacker to have admin + challenge token.

    // Protection state.
    config.realtime_enabled = current.realtime_enabled;
    config.auto_quarantine = current.auto_quarantine;

    // Worker path (C2 fix).
    config.argus_worker_path = current.argus_worker_path.clone();
    config.argus_worker_enabled = current.argus_worker_enabled;
    config.scan.argus_worker_path = current.scan.argus_worker_path.clone();
    config.scan.argus_worker_enabled = current.scan.argus_worker_enabled;

    // ☠️ KILL VECTOR FIX: protect all detection-affecting fields.
    // An attacker setting excluded_detections=[""] kills ALL detection.
    // An attacker setting excluded_paths=["C:\\Users"] blinds the scanner.
    // An attacker adding to trusted_hashes whitelists specific malware.
    // An attacker emptying realtime_roots disables watcher coverage.
    config.excluded_paths = current.excluded_paths.clone();
    config.excluded_extensions = current.excluded_extensions.clone();
    config.excluded_detections = current.excluded_detections.clone();
    config.trusted_hashes = current.trusted_hashes.clone();
    config.realtime_roots = current.realtime_roots.clone();
    config.heuristic_alerts = current.heuristic_alerts;
    config.idle_scan_enabled = current.idle_scan_enabled;
    config.scheduled_scan_enabled = current.scheduled_scan_enabled;
    config.enhanced_signature_provider = current.enhanced_signature_provider.clone();

    // ☠️ KILL VECTOR FIX (v0.1.9 CRITICAL_FIELDS additions): ransomware
    // shield, behavioural sandbox and ClamAV isolation. Downgrading
    // clamav_isolation to "in_process" re-exposes the daemon to the
    // in-engine memory-corruption CVEs the subprocess mode exists to
    // contain; forcing fish.active_response to "observe" turns the
    // ransomware shield into a logger.
    config.fish.enabled = current.fish.enabled;
    config.fish.observe_only = current.fish.observe_only;
    config.fish.active_response = current.fish.active_response.clone();
    config.sandbox.enabled = current.sandbox.enabled;
    config.clamav_isolation = current.clamav_isolation.clone();

    // ☠️ [web_protection] is CRITICAL end-to-end: the elevated
    // protection.set_critical handler is its one IPC mutation path.
    // settings.set is the UNELEVATED path, so it must never write the
    // section — it would be a way to reroute or silently disable DNS
    // filtering without a challenge token or elevation.
    config.web_protection = current.web_protection.clone();

    // ☠️ KILL VECTOR FIX: preserve developer-mode password hash.
    // settings.get redacts password_sha256 to "" before returning, so a
    // round-trip GUI settings.set would otherwise wipe the provisioned hash.
    // Worse, an attacker with the IPC secret could inject a hash they know
    // the plaintext of, then unlock developer mode without ever knowing the
    // original password. The hash is provisioned out-of-band by editing the
    // config file directly (documented dev-mode setup); IPC settings.set must
    // never be a path to mutate it.
    config.developer.password_sha256 = current.developer.password_sha256.clone();

    Ok(config)
}

// ─── protection.set_critical — pure param application ────────────────

/// Outcome of [`apply_set_critical_params`]. The dispatch arm owns every
/// side effect; this struct carries only what the arm needs to finish.
struct SetCriticalApply {
    /// Human-readable applied changes, for the activity log and the reply.
    changes: Vec<String>,
    /// Non-empty = reject the whole request with INVALID_PARAMS, unchanged.
    errors: Vec<String>,
    /// Deferred realtime on/off toggle — applied by the arm AFTER the save
    /// (start_watcher re-reads the file, so toggling earlier would race it).
    realtime_toggle: Option<bool>,
    /// True when any `web_protection.*` key was present in the request.
    /// Drives `restart_required: true` in the Ok payload: the section is
    /// consumed once at daemon start (main.rs) and every field is
    /// classified DaemonRestart (proto::full_config::restart_requirement),
    /// so NOTHING below hot-applies and the caller must be told.
    web_protection_touched: bool,
}

/// The pure half of the `protection.set_critical` handler: apply every
/// recognised param key onto a config, validating strictly. No IO and no
/// `AppState` — the arm keeps the token gate, the write lock, the load,
/// the activity log, the save and every post-save side effect, so this
/// function is unit-testable (a full in-process daemon harness is
/// impractical; see the note in ipc/policy.rs).
///
/// Two cross-cutting rules live here rather than in the arm:
///
/// 1. **Unknown-key rejection.** Every branch reads its keys through the
///    `param!` macro, which records the key as handled; afterwards any
///    request key never recorded (other than the `token`/`auth` envelope)
///    is an error. An unmatched param used to fall through to
///    `ok:true, changes:[]` — reporting a setting applied that never was.
///    Rejecting unknown keys is what makes that lie impossible for every
///    future caller, not just the ones we know about. Verified callers
///    (GUI `set_critical_protection` / `set_critical_settings`,
///    sentinella-cli realtime toggle) send only keys handled below.
///
/// 2. **Transactional application.** Mutations happen on a clone and are
///    written back ONLY when `errors` is empty, so "rejected = nothing
///    changed" is true of the in-memory config too, not just of the disk
///    file the arm never reaches on failure.
fn apply_set_critical_params(
    config: &mut crate::config::Config,
    params: &serde_json::Value,
) -> SetCriticalApply {
    let mut work = config.clone();
    let mut changes = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut realtime_toggle: Option<bool> = None;
    let mut web_protection_touched = false;

    // Keys this request carried that some branch actually looked at,
    // pre-seeded with the IPC envelope. The unknown-key sweep at the
    // bottom rejects everything else.
    let mut handled: std::collections::HashSet<&'static str> =
        ["token", "auth"].into_iter().collect();
    // Read a param key and mark it as handled for the unknown-key sweep.
    macro_rules! param {
        ($key:literal) => {{
            handled.insert($key);
            params.get($key)
        }};
    }

    // ── Validation helpers ──
    const MAX_LIST_ENTRIES: usize = 64;
    const MAX_PATH_LEN: usize = 4096;
    // Hard-blocked paths: protect users from accidentally
    // excluding the world or feeding the watcher a path that
    // hangs the recursion.
    // Delegates to crate::config so there is ONE list, not two.
    // This used to be an inline copy and the copies diverged: this
    // one never gained "c:\users", so protection.set_critical
    // accepted that exclusion, reported changes=["excluded_paths=[1]"],
    // and Config::validate then dropped it on save. The admin was
    // told a setting applied that never did.
    fn is_dangerous_path(p: &str) -> bool {
        crate::config::is_dangerous_excluded_path(p)
    }
    fn is_hex64_lower(s: &str) -> bool {
        s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    }
    fn validate_string_list<F: Fn(&str) -> Result<(), String>>(
        key: &str,
        v: &serde_json::Value,
        check: F,
        errors: &mut Vec<String>,
    ) -> Option<Vec<String>> {
        let arr = v.as_array()?;
        if arr.len() > MAX_LIST_ENTRIES {
            errors.push(format!(
                "{key}: too many entries ({} > {MAX_LIST_ENTRIES})",
                arr.len()
            ));
            return None;
        }
        let mut out = Vec::with_capacity(arr.len());
        for (i, item) in arr.iter().enumerate() {
            match item.as_str() {
                Some(s) => match check(s) {
                    Ok(()) => out.push(s.to_string()),
                    Err(why) => errors.push(format!("{key}[{i}]: {why}")),
                },
                None => errors.push(format!("{key}[{i}]: not a string")),
            }
        }
        Some(out)
    }

    // ── Existing fields (v0.1.7) ───────────────────
    // The runtime side effect is DEFERRED to after config.save()
    // succeeds — see `realtime_toggle` in the dispatch arm.
    // Applying it here meant a request that failed validation (or
    // failed to save) still stopped the watcher, leaving real-time
    // protection down with config.toml and the GUI both still saying
    // it was up. It also meant enable_protection() → start_watcher()
    // re-read realtime_roots off disk BEFORE this handler wrote the
    // new roots, so a save that both re-enabled protection and added
    // a watched folder started the watcher on the old root set.
    if let Some(v) = param!("realtime_enabled").and_then(|v| v.as_bool()) {
        work.realtime_enabled = v;
        changes.push(format!("realtime_enabled={v}"));
        realtime_toggle = Some(v);
    }
    if let Some(v) = param!("auto_quarantine").and_then(|v| v.as_bool()) {
        work.auto_quarantine = v;
        changes.push(format!("auto_quarantine={v}"));
    }

    // ── New bool kill-vector toggles (v0.1.8) ──────
    if let Some(v) = param!("heuristic_alerts").and_then(|v| v.as_bool()) {
        work.heuristic_alerts = v;
        changes.push(format!("heuristic_alerts={v}"));
    }
    if let Some(v) = param!("idle_scan_enabled").and_then(|v| v.as_bool()) {
        work.idle_scan_enabled = v;
        changes.push(format!("idle_scan_enabled={v}"));
    }
    if let Some(v) = param!("scheduled_scan_enabled").and_then(|v| v.as_bool()) {
        work.scheduled_scan_enabled = v;
        changes.push(format!("scheduled_scan_enabled={v}"));
    }
    if let Some(v) = param!("argus_worker_enabled").and_then(|v| v.as_bool()) {
        work.argus_worker_enabled = v;
        // Keep the [scan] mirror in sync — orchestrator reads both.
        work.scan.argus_worker_enabled = v;
        changes.push(format!("argus_worker_enabled={v}"));
    }

    // ── String kill-vectors with validation ────────
    if let Some(v) = param!("enhanced_signature_provider").and_then(|v| v.as_str()) {
        // Strict allowlist — anything else is an engine-swap kill
        // vector. THE SAME predicate Config::validate uses: this had
        // its own list (none|enhanced|community) that overlapped
        // validate's only at "none", so real providers were rejected
        // and the two accepted names were silently reset to "none"
        // after being reported as a successful change.
        if crate::config::is_known_signature_provider(v) {
            work.enhanced_signature_provider = v.to_string();
            changes.push(format!("enhanced_signature_provider={v}"));
        } else {
            errors.push(format!(
                "enhanced_signature_provider={v:?} not in allowlist                          (none|securiteinfo|urlhaus|malwarepatrol)"
            ));
        }
    }
    if let Some(v) = param!("argus_worker_path").and_then(|v| v.as_str()) {
        // Must look like a plausible executable path.
        let trimmed = v.trim();
        if trimmed.is_empty() || trimmed.len() > MAX_PATH_LEN {
            errors.push("argus_worker_path: empty or too long".into());
        } else if is_dangerous_path(trimmed) || trimmed.contains("..") {
            errors.push(format!(
                "argus_worker_path={trimmed:?} rejected (dangerous or traversal)"
            ));
        } else if !trimmed.to_lowercase().ends_with(".exe") {
            errors.push(format!("argus_worker_path={trimmed:?} must end with .exe"));
        } else {
            work.argus_worker_path = trimmed.into();
            work.scan.argus_worker_path = trimmed.into();
            changes.push(format!("argus_worker_path={trimmed}"));
        }
    }

    // ── v0.1.9 newly-critical fields (audit HIGH-2 / LOW-19) ──
    //
    // fish.enabled / fish.observe_only / fish.active_response /
    // sandbox.enabled / clamav_isolation moved into CRITICAL_FIELDS;
    // they now travel through this handler with the same elevated-
    // caller + challenge-token gate as the other kill-vectors.
    if let Some(v) = param!("fish.enabled").and_then(|v| v.as_bool()) {
        work.fish.enabled = v;
        changes.push(format!("fish.enabled={v}"));
    }
    if let Some(v) = param!("fish.observe_only").and_then(|v| v.as_bool()) {
        work.fish.observe_only = v;
        changes.push(format!("fish.observe_only={v}"));
    }
    if let Some(v) = param!("fish.active_response").and_then(|v| v.as_str()) {
        // Strict allowlist — anything else would be a kill primitive
        // (terminate / unknown values that fall back to observe and
        // silently disable enforcement).
        if matches!(v, "observe" | "suspend" | "terminate") {
            work.fish.active_response = v.to_string();
            changes.push(format!("fish.active_response={v}"));
        } else {
            errors.push(format!(
                "fish.active_response={v:?} not in allowlist (observe|suspend|terminate)"
            ));
        }
    }
    if let Some(v) = param!("sandbox.enabled").and_then(|v| v.as_bool()) {
        work.sandbox.enabled = v;
        changes.push(format!("sandbox.enabled={v}"));
    }
    if let Some(v) = param!("clamav_isolation").and_then(|v| v.as_str()) {
        // Strict allowlist (also enforced in Config::validate, but
        // surfacing the error here gives the GUI a clear rejection
        // instead of a silent reset to "in_process").
        if matches!(v, "in_process" | "subprocess") {
            work.clamav_isolation = v.to_string();
            changes.push(format!("clamav_isolation={v}"));
        } else {
            errors.push(format!(
                "clamav_isolation={v:?} not in allowlist (in_process|subprocess)"
            ));
        }
    }

    // ── web_protection.* — DNS filtering kill-vectors ──
    //
    // Flat dotted keys, matching the fish.enabled / sandbox.enabled
    // precedent; all eight fields of CRITICAL_FIELDS' web_protection
    // block. STRICTLY TYPED: a present key with the wrong JSON type is
    // an error, never a silent no-op. Per-key validation feeds the
    // arm's all-or-nothing hard-fail; the composite gate at the bottom
    // then judges the merged section as a whole.
    //
    // Polarity, per web_protection::config's module docs: turning the
    // proxy ON when it cannot serve is the harm, turning it OFF is the
    // emergency fix — so nothing here may coerce a bad value into a
    // plausible one, and `enabled=false` is always accepted.
    {
        let wp = &mut work.web_protection;

        if let Some(v) = param!("web_protection.enabled") {
            web_protection_touched = true;
            match v.as_bool() {
                Some(b) => {
                    wp.enabled = b;
                    changes.push(format!("web_protection.enabled={b}"));
                }
                None => errors.push("web_protection.enabled: must be a boolean".into()),
            }
        }
        if let Some(v) = param!("web_protection.listen") {
            web_protection_touched = true;
            match v.as_str() {
                Some(s) => {
                    let t = s.trim();
                    if t.is_empty() || t.len() > 128 {
                        errors.push("web_protection.listen: empty or too long".into());
                    } else if t.parse::<std::net::SocketAddr>().is_err() {
                        // Rejected even while disabled: storing a listen
                        // that can never parse only defers the failure to
                        // the next enable attempt.
                        errors.push(format!(
                            "web_protection.listen={t:?} is not a valid IP:port"
                        ));
                    } else {
                        wp.listen = t.to_string();
                        changes.push(format!("web_protection.listen={t}"));
                    }
                }
                None => errors.push("web_protection.listen: must be a string".into()),
            }
        }
        if let Some(v) = param!("web_protection.upstreams") {
            web_protection_touched = true;
            if !v.is_array() {
                errors.push("web_protection.upstreams: must be an array of strings".into());
            } else if let Some(list) = validate_string_list(
                "web_protection.upstreams",
                v,
                |s| {
                    let t = s.trim();
                    if t == crate::web_protection::config::UPSTREAM_SYSTEM {
                        return Ok(());
                    }
                    if t.is_empty() {
                        return Err("empty entry".into());
                    }
                    t.parse::<std::net::SocketAddr>()
                        .map(|_| ())
                        .map_err(|_| format!("{t:?} is neither \"system\" nor a valid IP:port"))
                },
                &mut errors,
            ) {
                wp.upstreams = list;
                changes.push(format!("web_protection.upstreams=[{}]", wp.upstreams.len()));
            }
        }
        if let Some(v) = param!("web_protection.block_response") {
            web_protection_touched = true;
            match v.as_str() {
                Some(s)
                    if s == crate::web_protection::config::BLOCK_RESPONSE_NXDOMAIN
                        || s == crate::web_protection::config::BLOCK_RESPONSE_ZERO_IP =>
                {
                    wp.block_response = s.to_string();
                    changes.push(format!("web_protection.block_response={s}"));
                }
                Some(s) => errors.push(format!(
                    "web_protection.block_response={s:?} not in allowlist (nxdomain|zero_ip)"
                )),
                None => errors.push("web_protection.block_response: must be a string".into()),
            }
        }
        if let Some(v) = param!("web_protection.health_check_name") {
            web_protection_touched = true;
            match v.as_str() {
                Some(s) => {
                    let t = s.trim();
                    if t.is_empty() {
                        errors.push("web_protection.health_check_name: empty".into());
                    } else if t.len() > 253 {
                        errors.push(
                            "web_protection.health_check_name: longer than any legal DNS name"
                                .into(),
                        );
                    } else if t.contains('\\') {
                        // Same reason as WebProtectionConfig::check_enablable:
                        // dnsguard's query builder is escape-unaware, so a
                        // backslash would silently probe a different name.
                        errors.push(format!(
                            "web_protection.health_check_name={t:?} contains a backslash escape"
                        ));
                    } else {
                        wp.health_check_name = t.to_string();
                        changes.push(format!("web_protection.health_check_name={t}"));
                    }
                }
                None => errors.push("web_protection.health_check_name: must be a string".into()),
            }
        }
        if let Some(v) = param!("web_protection.blocklists") {
            web_protection_touched = true;
            if !v.is_array() {
                errors.push("web_protection.blocklists: must be an array of strings".into());
            } else if let Some(list) = validate_string_list(
                "web_protection.blocklists",
                v,
                |s| {
                    let t = s.trim();
                    // Entry syntax: `path`, `path|exact` or `path|suffix`
                    // ('|' cannot appear in a Windows path, so the first
                    // one is unambiguous). An unknown policy token is an
                    // ERROR here, not service.rs's warn-and-use-exact:
                    // over IPC, silently substituting the policy would
                    // report a filtering semantic the engine never got.
                    let (path, policy) = match t.split_once('|') {
                        Some((p, pol)) => (p.trim(), Some(pol)),
                        None => (t, None),
                    };
                    if path.is_empty() {
                        return Err("empty path".into());
                    }
                    if path.len() > MAX_PATH_LEN {
                        return Err("path too long".into());
                    }
                    match policy {
                        None | Some("exact") | Some("suffix") => Ok(()),
                        Some(other) => Err(format!(
                            "unknown policy {other:?} (expected exact|suffix)"
                        )),
                    }
                },
                &mut errors,
            ) {
                wp.blocklists = list;
                changes.push(format!("web_protection.blocklists=[{}]", wp.blocklists.len()));
            }
        }
        if let Some(v) = param!("web_protection.allowlist") {
            web_protection_touched = true;
            if !v.is_array() {
                errors.push("web_protection.allowlist: must be an array of strings".into());
            } else if let Some(list) = validate_string_list(
                "web_protection.allowlist",
                v,
                |s| {
                    let t = s.trim();
                    if t.is_empty() {
                        return Err("empty entry".into());
                    }
                    if t.len() > 253 {
                        return Err("entry longer than any legal DNS name".into());
                    }
                    if t.chars().any(|c| c.is_whitespace()) || t.contains('\\') {
                        // A name with spaces or a backslash can never
                        // match a query name — storing it would be a
                        // rule that silently does nothing.
                        return Err("whitespace and backslashes are not valid in a DNS name".into());
                    }
                    Ok(())
                },
                &mut errors,
            ) {
                wp.allowlist = list;
                changes.push(format!("web_protection.allowlist=[{}]", wp.allowlist.len()));
            }
        }
        if let Some(v) = param!("web_protection.log_queries") {
            web_protection_touched = true;
            match v.as_bool() {
                Some(b) => {
                    wp.log_queries = b;
                    changes.push(format!("web_protection.log_queries={b}"));
                }
                None => errors.push("web_protection.log_queries: must be a boolean".into()),
            }
        }

        // Composite gate — reject, never silently disable. Runs on the
        // FINAL merged section whenever the result is enabled=true, even
        // when the request never mentioned `enabled`: a listen-only
        // change against a stored enabled=true must still prove the
        // result can serve. Deliberately NOT delegated to
        // Config::validate() (the arm calls it before saving): validate
        // would force enabled=false with only a warn!, turning a
        // reported success into the silent-reset lie. An enabled=false
        // result skips the gate entirely — turning the proxy OFF is the
        // emergency fix and is always allowed.
        if wp.enabled {
            if let Err(reason) = wp.check_enablable() {
                errors.push(format!(
                    "web_protection: refusing to save enabled=true with an unservable config — {reason}"
                ));
            }
        }
    }

    // ── List kill-vectors with validation ──────────
    if let Some(v) = param!("excluded_paths") {
        if let Some(list) = validate_string_list(
            "excluded_paths",
            v,
            |s| {
                let t = s.trim();
                if t.is_empty() {
                    Err("empty entry".into())
                } else if t.len() > MAX_PATH_LEN {
                    Err("path too long".into())
                } else if is_dangerous_path(t) {
                    Err(format!("{t:?} would exclude critical system area"))
                } else {
                    Ok(())
                }
            },
            &mut errors,
        ) {
            work.excluded_paths = list;
            changes.push(format!("excluded_paths=[{}]", work.excluded_paths.len()));
        }
    }
    if let Some(v) = param!("excluded_extensions") {
        if let Some(list) = validate_string_list(
            "excluded_extensions",
            v,
            |s| {
                let t = s.trim().trim_start_matches('.');
                if t.is_empty() {
                    Err("empty entry".into())
                } else if t.len() > 16 {
                    Err("extension too long".into())
                } else if t.contains('*') || t.contains('?') || t.contains('\\') || t.contains('/') {
                    Err("globs and path separators rejected".into())
                } else if !t.chars().all(|c| c.is_ascii_alphanumeric()) {
                    Err("extension must be ASCII alphanumeric".into())
                } else {
                    Ok(())
                }
            },
            &mut errors,
        ) {
            // Normalize: strip dots, lowercase.
            let norm: Vec<String> = list
                .into_iter()
                .map(|s| s.trim().trim_start_matches('.').to_lowercase())
                .collect();
            work.excluded_extensions = norm;
            changes.push(format!(
                "excluded_extensions=[{}]",
                work.excluded_extensions.len()
            ));
        }
    }
    if let Some(v) = param!("excluded_detections") {
        if let Some(list) = validate_string_list(
            "excluded_detections",
            v,
            |s| {
                let t = s.trim();
                if t.is_empty() {
                    // R4-C1: empty entry would suppress ALL detections — kill switch.
                    Err("empty entry rejected (would silence ALL detections)".into())
                } else if t.len() > 256 {
                    Err("detection name too long".into())
                } else {
                    Ok(())
                }
            },
            &mut errors,
        ) {
            work.excluded_detections = list;
            changes.push(format!(
                "excluded_detections=[{}]",
                work.excluded_detections.len()
            ));
        }
    }
    if let Some(v) = param!("trusted_hashes") {
        if let Some(list) = validate_string_list(
            "trusted_hashes",
            v,
            |s| {
                let t = s.trim().to_lowercase();
                if !is_hex64_lower(&t) {
                    Err("must be 64-char lowercase hex SHA-256".into())
                } else {
                    Ok(())
                }
            },
            &mut errors,
        ) {
            let norm: Vec<String> = list.into_iter().map(|s| s.trim().to_lowercase()).collect();
            work.trusted_hashes = norm;
            changes.push(format!("trusted_hashes=[{}]", work.trusted_hashes.len()));
        }
    }
    if let Some(v) = param!("realtime_roots") {
        if let Some(list) = validate_string_list(
            "realtime_roots",
            v,
            |s| {
                let t = s.trim();
                if t.is_empty() {
                    Err("empty entry".into())
                } else if t.len() > MAX_PATH_LEN {
                    Err("path too long".into())
                } else if is_dangerous_path(t) {
                    Err(format!(
                        "{t:?} is too broad — would hang the watcher in reparse loops"
                    ))
                } else {
                    Ok(())
                }
            },
            &mut errors,
        ) {
            work.realtime_roots = list;
            changes.push(format!("realtime_roots=[{}]", work.realtime_roots.len()));
        }
    }

    // ── Unknown-key sweep ──
    // Any request key no branch looked at (token/auth pre-seeded above)
    // is a typo'd or fabricated field. Answering ok:true for it would be
    // the "applied but ignored" lie this handler was fixed for twice
    // before — the typo'd `web_protection.enable` must be REJECTED, not
    // ignored.
    if let Some(obj) = params.as_object() {
        for key in obj.keys() {
            if !handled.contains(key.as_str()) {
                errors.push(format!(
                    "unknown parameter {key:?} — not a protection.set_critical field"
                ));
            }
        }
    }

    if errors.is_empty() {
        *config = work;
    }

    SetCriticalApply {
        changes,
        errors,
        realtime_toggle,
        web_protection_touched,
    }
}

/// Synchronous dispatch — all handlers are sync (no async needed).
///
/// `peer` is the per-connection caller identity resolved at accept time
/// (Windows: from the named-pipe handle's process token). It threads
/// through dispatch only so the v0.1.9 elevation gate on kill-vector
/// methods can use it; per-handler logic that doesn't touch elevation
/// can keep ignoring it.
fn dispatch_sync(
    req: &RpcRequest,
    state: &Arc<AppState>,
    peer: Option<&client_auth::ClientIdentity>,
) -> Vec<u8> {
    debug!(method = %req.method, id = req.id, "dispatch");
    state.record_request();

    // ── v0.1.9 elevation gate ──────────────────────────
    //
    // Audit finding (HIGH): the v0.1.8 protection.set_critical /
    // settings.set_full / sources.* / engine.reload / quarantine.*
    // handlers all gated solely on the challenge token + IPC secret.
    // The IPC secret is BUILTIN\Users:(R) for unelevated-GUI compat,
    // so the secret alone is NOT an elevation boundary. Any unelevated
    // user-mode process could read the secret, request a token, and
    // mutate kill-vector fields without UAC — defeating the entire
    // "Restart as Administrator" affordance the v0.1.8 changelog
    // claimed.
    //
    // Fix: every method on `is_challengeable_method`'s allowlist also
    // requires the caller's process token to be elevated or SYSTEM.
    // SR-03: an unresolved identity (None peer) now fails CLOSED here —
    // a privileged mutation requires a positively-resolved elevated
    // caller. The connection still fails open for reads, so an OS quirk
    // never bricks the channel; it just can't authorize a kill-vector
    // method without proof of elevation.
    if is_challengeable_method(&req.method) {
        if let client_auth::Decision::Deny(reason) =
            client_auth::require_elevation(peer)
        {
            tracing::warn!(
                method = %req.method,
                sid = peer.map(|p| p.sid.as_str()).unwrap_or("?"),
                session = peer.map(|p| p.session_id).unwrap_or(u32::MAX),
                reason,
                "IPC: rejected privileged-mutation method from unelevated caller"
            );
            state.log_activity(
                "warning",
                "security",
                &format!(
                    "Rejected privileged method '{}' from unelevated caller",
                    req.method
                ),
                reason,
                None,
            );
            return serde_json::to_vec(&RpcErrorResponse::err(
                req.id,
                error_codes::INSUFFICIENT_PRIVILEGE,
                format!(
                    "method '{}' requires an elevated caller (run Sentinella as administrator)",
                    req.method
                ),
            ))
            .unwrap_or_default();
        }
    }

    // ── Policy enforcement (phases 1-3, 7) ─────────────
    {
        use std::collections::HashMap;
        use std::sync::OnceLock;
        static REGISTRY: OnceLock<HashMap<&'static str, policy::MethodPolicy>> = OnceLock::new();
        let reg = REGISTRY.get_or_init(policy::method_registry);

        if let Some(pol) = reg.get(req.method.as_str()) {
            // Phase 2: per-method payload cap.
            let payload_size = serde_json::to_vec(&req.params)
                .map(|v| v.len())
                .unwrap_or(0);
            if payload_size > pol.max_payload_bytes {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    policy::ipc_errors::PAYLOAD_TOO_LARGE,
                    format!(
                        "payload {} bytes exceeds limit {} for {}",
                        payload_size, pol.max_payload_bytes, req.method
                    ),
                ))
                .unwrap_or_default();
            }

            // Phase 3: rate limiting. Two layers (policy.rs): a
            // per-principal sub-budget keyed on the accept-time SID
            // (`peer`, same identity fairness.rs uses — kernel-owned, not
            // client-choosable; None falls into the shared unidentified
            // bucket), then the unchanged global per-class ceiling. Runs
            // BEFORE the Phase 8 auth gate on purpose: with per-principal
            // keying an unauthenticated flooder can only burn their own
            // sub-budget, and rate-first throttles UNAUTHORIZED-response
            // generation for unauthenticated garbage (see policy.rs
            // module docs for the full ordering analysis).
            if let Err(retry_secs) = state.rate_limiter.check(pol.rate_bucket, peer) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    policy::ipc_errors::RATE_LIMITED,
                    format!("rate limited — retry after {}s", retry_secs),
                ))
                .unwrap_or_default();
            }

            // Phase 7: degraded mode — block mutations if engine is reloading.
            if !pol.allowed_while_reloading && state.is_engine_reloading() {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    policy::ipc_errors::ENGINE_RELOADING,
                    "engine is reloading — try again shortly".to_string(),
                ))
                .unwrap_or_default();
            }

            // Phase 8 (audit cross-cutting): central MethodClass auth
            // enforcement. The registry always DECLARED AuthenticatedRead /
            // AuthenticatedAction, but enforcement was per-handler opt-in —
            // scan.history / stats.runtime / argus.packs / sources.status /
            // sources.list declared auth_read yet never checked, so the
            // declared class was a lie. Enforce it once, here.
            //
            // PrivilegedMutation / DangerousOperation are deliberately NOT
            // `auth`-gated here: those handlers authenticate via one-shot
            // challenge tokens (issuable only to authenticated + elevated
            // callers through security.challenge) and their envelopes carry
            // `token` / `challenge_token`, not `auth`.
            if matches!(
                pol.class,
                policy::MethodClass::AuthenticatedRead | policy::MethodClass::AuthenticatedAction
            ) {
                let auth = req
                    .params
                    .get("auth")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if !state.validate_ipc_auth(auth) {
                    return serde_json::to_vec(&RpcErrorResponse::err(
                        req.id,
                        policy::ipc_errors::UNAUTHORIZED,
                        format!("method '{}' requires IPC authentication", req.method),
                    ))
                    .unwrap_or_default();
                }
            }
        }
    }

    let result: Result<Value, (i32, String)> = match req.method.as_str() {
        "engine.status" => ok_json(state.engine_status()),
        "engine.reload" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC engine reload required".to_string(),
                ))
                .unwrap_or_default();
            }
            // Scanner-B Finding 1: policy declares engine.reload as
            // PrivilegedMutation (challenge required); the central
            // dispatcher enforces the Authenticated* classes but
            // challenge-token verification stays per-handler. Without the
            // token check below, an attacker with the IPC secret could
            // force unlimited engine reloads (~5-8s scan-blind window
            // each). Mirrors protection.set_critical.
            let token = req
                .params
                .get("token")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_challenge_token(token, "engine.reload") {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "challenge token required for engine reload".to_string(),
                ))
                .unwrap_or_default();
            }
            match state.reload_engine() {
                Ok(sigs) => Ok(serde_json::json!({"ok": true, "signatures": sigs})),
                Err(e) => Ok(serde_json::json!({"ok": false, "error": e})),
            }
        }

        "scan.start" => {
            let scan_type = req
                .params
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("quick");
            // R4-LETHAL-5: previously only full/startup required auth.
            // Quick scans were unauthenticated → any caller could spam
            // scan.start to chew disk I/O, evict the page cache and
            // induce sustained scan pressure as a DoS (and as cover for
            // payload drops happening in parallel).
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    format!("{scan_type} scans require IPC authentication"),
                ))
                .unwrap_or_default();
            }
            let target = req.params.get("target").and_then(|v| v.as_str());
            // Validate target path if provided (☠️ R8-LETHAL — see
            // `validate_local_scan_path` for the full threat model).
            if let Some(t) = target {
                if let Err(msg) = validate_local_scan_path(t) {
                    return serde_json::to_vec(&RpcErrorResponse::err(
                        req.id,
                        error_codes::INVALID_PARAMS,
                        msg,
                    ))
                    .unwrap_or_default();
                }
            }
            ok_json(state.start_scan(scan_type, target))
        }
        "scan.status" => ok_json(state.scan_status()),
        "scan.history" => ok_json(state.scan_history()),
        "scan.cancel" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC scan cancel required".to_string(),
                ))
                .unwrap_or_default();
            }
            let status = state.scan_status();
            if status.running || status.state == "queued" || status.state == "pending" {
                let cancelled = state.cancel_scan();
                state.log_activity("warning", "scan", "Scan cancelled by user", "", None);
                Ok(serde_json::json!({"ok": cancelled}))
            } else {
                // Scan already completed — not an error, just nothing to cancel.
                Ok(serde_json::json!({"ok": true, "note": "scan already completed"}))
            }
        }

        "quarantine.list" => {
            // R7-LETHAL: this endpoint returns the SHA-256 of every malware
            // Sentinella has ever caught + its original file path + virus
            // family name. Without auth, any IPC caller gathers exactly the
            // intel needed to (a) identify which malware variant the user
            // ran into via VirusTotal lookup, (b) craft a sibling payload
            // tuned to evade the same signature, (c) pick a drop location
            // the user demonstrably visits. Now requires the IPC secret.
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC quarantine list required".to_string(),
                ))
                .unwrap_or_default();
            }
            let rows = state.quarantine_list();
            // Bound the response by SERIALISED BYTES, not row count.
            //
            // The `.take(1000)` this replaces did not actually achieve its
            // stated goal: the limit being protected is a BYTE limit (the CLI
            // rejects frames over MAX_FRAME_SIZE = 1 MiB), while rows vary
            // enormously in size because a Windows path can reach 32,767 chars
            // via the \\?\ form — so 1000 rows could still overflow, and in the
            // common case it needlessly hid entries that would have fit.
            //
            // The hiding mattered: past 1000 items the older entries became
            // invisible in the GUI quarantine page and therefore un-restorable
            // through it — and since quarantining deletes the original, the
            // vault blob is the only copy — right up until the retention sweep
            // deleted them for good. Ordered by quarantined_at DESC, so the
            // newest entries survive. (The scheduler's retention sweep uses the
            // FULL list — do not push this cap down into db::list_quarantine.)
            const RESPONSE_BUDGET: usize = 768 * 1024; // headroom under 1 MiB
            let total_rows = rows.len();
            let mut used: usize = 2; // "[]"
            let mut items: Vec<serde_json::Value> = Vec::new();
            for r in rows {
                let vault_path = std::path::Path::new(&r.vault_path);
                let vault_ok = vault_blob_plausible(vault_path);
                let item = serde_json::json!({
                    "id": r.quarantine_id,
                    "original_path": r.original_path,
                    "original_size": r.original_size,
                    "signature": r.virus_name,
                    "sha256": r.sha256,
                    "quarantined_at": r.quarantined_at,
                    "restorable": vault_ok && r.status == "quarantined",
                    "scan_id": r.scan_id,
                });
                // +1 for the separating comma.
                let cost = serde_json::to_string(&item).map(|s| s.len()).unwrap_or(0) + 1;
                if used + cost > RESPONSE_BUDGET && !items.is_empty() {
                    break;
                }
                used += cost;
                items.push(item);
            }
            if items.len() < total_rows {
                // Not silent any more: the operator can see it in the log even
                // though the array shape gives us nowhere to put a flag without
                // breaking the GUI and CLI consumers.
                warn!(
                    returned = items.len(),
                    total = total_rows,
                    "quarantine.list truncated to fit the IPC frame — older entries omitted"
                );
            }
            ok_json(items)
        }
        "quarantine.add" => {
            // Dangerous command: this moves a file into encrypted quarantine and
            // deletes the original. Require the same one-shot challenge used by
            // restore/delete so arbitrary IPC clients cannot quarantine files
            // without first passing the guarded flow.
            let token = req
                .params
                .get("token")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_challenge_token(token, "quarantine.add") {
                Ok(
                    serde_json::json!({"ok": false, "error": "Challenge token required for quarantine add"}),
                )
            } else {
                // ARGUS-2 Phase 2: bound caller-controlled strings before they
                // hit the DB/log. virus_name/scan_id are attacker-influenced
                // when the caller is anything other than our own scanners,
                // and we previously stored them unbounded → log injection and
                // DB row bloat (rows are 1 SHA-256 from rare → effectively
                // permanent retention).
                const MAX_PATH_LEN: usize = 4096;
                const MAX_VIRUS_NAME: usize = 256;
                const MAX_SCAN_ID: usize = 128;
                let path = req
                    .params
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let virus = req
                    .params
                    .get("virus_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown");
                let scan_id = req
                    .params
                    .get("scan_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if path.len() > MAX_PATH_LEN
                    || virus.len() > MAX_VIRUS_NAME
                    || scan_id.len() > MAX_SCAN_ID
                {
                    return serde_json::to_vec(&RpcErrorResponse::err(
                        req.id,
                        error_codes::INVALID_PARAMS,
                        "quarantine.add param too long".to_string(),
                    ))
                    .unwrap_or_default();
                }
                match state.quarantine_file(path, virus, scan_id) {
                    Ok(r) => ok_json(r),
                    Err(e) => Ok(serde_json::json!({"ok": false, "error": e})),
                }
            }
        }
        "quarantine.restore" => {
            // Dangerous command — requires valid challenge token.
            let token = req
                .params
                .get("token")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_challenge_token(token, "quarantine.restore") {
                Ok(
                    serde_json::json!({"ok": false, "error": "Challenge token required for quarantine restore"}),
                )
            } else {
                let id = req.params.get("id").and_then(|v| v.as_str()).unwrap_or("");
                match state.quarantine_restore(id) {
                    Ok(path) => Ok(serde_json::json!({"ok": true, "restored_to": path})),
                    Err(e) => Ok(serde_json::json!({"ok": false, "error": e})),
                }
            }
        }
        "quarantine.restore_as" => {
            let token = req
                .params
                .get("token")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_challenge_token(token, "quarantine.restore_as") {
                Ok(
                    serde_json::json!({"ok": false, "error": "Challenge token required for quarantine restore"}),
                )
            } else {
                // ARGUS-2 Phase 2: cap dest length to keep validate_restore_path
                // from canonicalize-stalling on a 1-MB attacker path, and to
                // keep error/log lines bounded.
                const MAX_ID_LEN: usize = 128;
                const MAX_DEST_LEN: usize = 4096;
                let id = req.params.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let dest = req
                    .params
                    .get("dest")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if id.len() > MAX_ID_LEN || dest.len() > MAX_DEST_LEN {
                    Ok(serde_json::json!({"ok": false, "error": "id/dest param too long"}))
                } else if dest.is_empty() {
                    Ok(serde_json::json!({"ok": false, "error": "dest path required"}))
                } else {
                    match state.quarantine_restore_as(id, dest) {
                        Ok(path) => Ok(serde_json::json!({"ok": true, "restored_to": path})),
                        Err(e) => Ok(serde_json::json!({"ok": false, "error": e})),
                    }
                }
            }
        }
        "quarantine.delete" => {
            // Dangerous — permanently destroys quarantined file. Requires challenge token.
            let token = req
                .params
                .get("token")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_challenge_token(token, "quarantine.delete") {
                Ok(
                    serde_json::json!({"ok": false, "error": "Challenge token required for quarantine delete"}),
                )
            } else {
                let id = req.params.get("id").and_then(|v| v.as_str()).unwrap_or("");
                match state.quarantine_delete(id) {
                    Ok(()) => Ok(serde_json::json!({"ok": true})),
                    Err(e) => Ok(serde_json::json!({"ok": false, "error": e})),
                }
            }
        }

        "calibration.report_safe" => {
            // Record a restored file as likely false positive.
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC update required".to_string(),
                ))
                .unwrap_or_default();
            }
            let quarantine_id = req
                .params
                .get("quarantine_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let sha256 = req
                .params
                .get("sha256")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let file_path = req
                .params
                .get("file_path")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let detection_name = req
                .params
                .get("detection_name")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if sha256.is_empty() || file_path.is_empty() {
                Ok(serde_json::json!({"ok": false, "error": "missing sha256 or file_path"}))
            } else {
                let now = chrono::Utc::now().timestamp();
                let event = crate::calibration::RestoreEvent {
                    id: uuid::Uuid::new_v4().to_string(),
                    detection_event_id: quarantine_id.to_string(),
                    timestamp: now,
                    file_path: file_path.to_string(),
                    file_hash: sha256.to_string(),
                    fp_category: crate::calibration::guess_fp_category(file_path),
                    user_notes: None,
                };
                state.calibration_record_restore(event);

                tracing::info!(
                    sha256 = sha256,
                    detection = detection_name,
                    category = crate::calibration::guess_fp_category(file_path).as_str(),
                    "calibration: file reported as safe by user"
                );

                Ok(serde_json::json!({"ok": true}))
            }
        }

        "runtime.status" => {
            // Adversary A1: policy declared this auth_read but the handler had
            // no gate, so an unauth caller still received full PLM/ETW/ps_bridge
            // /trust diagnostics — useful intel for attackers profiling the
            // daemon's runtime surface (which probes are armed, which features
            // are configured, etc.). Mirror trust.status auth pattern.
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC runtime status required".to_string(),
                ))
                .unwrap_or_default();
            }
            let diag = state.runtime_intelligence_diagnostics();
            Ok(diag)
        }

        "trust.status" => {
            // R7-LETHAL: trust graph diagnostics reveal which signers and
            // binary identities the daemon trusts. Useful intel for
            // living-off-the-land selection — attacker picks a binary
            // the trust graph rates highly, knowing ARGUS will give
            // it a trust discount. Auth-gate.
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC trust status required".to_string(),
                ))
                .unwrap_or_default();
            }
            // Trust graph diagnostics + recent drift events.
            if let Some(tg) = state.trust_graph() {
                let mut diag = tg.diagnostics();
                let drifts = tg.recent_drifts(10);
                let drift_json: Vec<serde_json::Value> = drifts
                    .iter()
                    .map(|d| {
                        serde_json::json!({
                            "timestamp": d.timestamp,
                            "entity": d.entity_key,
                            "type": format!("{:?}", d.drift_type),
                            "old": d.old_value,
                            "new": d.new_value,
                            "impact": d.trust_impact,
                            "explanation": d.explanation,
                            "weight": d.drift_type.suspicion_weight(),
                        })
                    })
                    .collect();
                if let Some(obj) = diag.as_object_mut() {
                    obj.insert("recent_drift_events".into(), serde_json::json!(drift_json));
                }
                Ok(diag)
            } else {
                Ok(serde_json::json!({"enabled": false}))
            }
        }

        "runtime.scan_buffer" => {
            // Dev/test: scan a runtime buffer through ASTRA runtime pipeline.
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC required".to_string(),
                ))
                .unwrap_or_default();
            }

            let content_b64 = req
                .params
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let language = req
                .params
                .get("language")
                .and_then(|v| v.as_str())
                .unwrap_or("other");
            let source_app = req
                .params
                .get("source_app")
                .and_then(|v| v.as_str())
                .unwrap_or("dev-inject");
            let content_name = req
                .params
                .get("content_name")
                .and_then(|v| v.as_str())
                .unwrap_or("manual");

            // NOTE: the param is named `content_b64` for historical reasons,
            // but no base64 decode happens here — callers send raw UTF-8
            // text and we pass the bytes through as-is.
            let content = if content_b64.is_empty() {
                vec![]
            } else {
                content_b64.as_bytes().to_vec()
            };

            if content.is_empty() {
                Ok(serde_json::json!({"ok": false, "error": "empty content"}))
            } else {
                // Optional: the AMSI provider passes the host PID so the
                // PLM lineage boost below (previously dead, source_pid was
                // hardcoded 0) can correlate the script with its process.
                let source_pid = req
                    .params
                    .get("source_pid")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;
                let buffer = crate::amsi::RuntimeBuffer {
                    source_app: source_app.to_string(),
                    source_pid,
                    content_name: content_name.to_string(),
                    language: crate::amsi::ScriptLanguage::from_app_name(&format!(
                        "{language}.exe"
                    )),
                    content,
                    original_size: content_b64.len(),
                    timestamp: chrono::Utc::now().timestamp(),
                };

                let result = crate::amsi::scan_runtime_buffer(&buffer, state.argus());

                // PLM correlation: check if source process has suspicious lineage.
                let plm_boost = if let Some(plm) = state.plm() {
                    if buffer.source_pid > 0 {
                        let chain = plm.graph.get_chain(buffer.source_pid);
                        chain.chain_suspicion
                    } else {
                        0
                    }
                } else {
                    0
                };

                let total_score = result.score.saturating_add(plm_boost).min(100);

                // Observability: count scans that came through the AMSI
                // provider (origin=="amsi") so a block can be attributed to
                // our provider vs. another registered one (e.g. Defender).
                if req.params.get("origin").and_then(|v| v.as_str()) == Some("amsi") {
                    crate::ipc::state::record_amsi_scan(result.should_block);
                }

                Ok(serde_json::json!({
                    "ok": true,
                    "score": total_score,
                    "runtime_score": result.score,
                    "plm_boost": plm_boost,
                    "should_block": result.should_block,
                    "findings_count": result.findings.len(),
                    "scan_duration_us": result.scan_duration_us,
                    "language": format!("{:?}", buffer.language),
                    "findings": result.findings.iter().map(|f| {
                        serde_json::json!({
                            "layer": f.layer.display_name(),
                            "weight": f.weight,
                            "description": f.description,
                        })
                    }).collect::<Vec<_>>(),
                }))
            }
        }

        "detections.list" => {
            // R7-LETHAL: same intel-leak class as quarantine.list — returns
            // detection signature names + paths for every malware ever
            // found. Auth-gate so an unprivileged caller cannot enumerate
            // the user's malware history to fingerprint their environment.
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC detections list required".to_string(),
                ))
                .unwrap_or_default();
            }
            let scan_id = req
                .params
                .get("scan_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if scan_id.is_empty() {
                // Return recent detections across all scans.
                if let Ok(db_guard) = state.db_ref().lock() {
                    if let Some(ref db) = *db_guard {
                        ok_json(db.recent_detections(50))
                    } else {
                        Ok(serde_json::json!([]))
                    }
                } else {
                    Ok(serde_json::json!([]))
                }
            } else {
                if let Ok(db_guard) = state.db_ref().lock() {
                    if let Some(ref db) = *db_guard {
                        ok_json(db.detections_for_scan(scan_id))
                    } else {
                        Ok(serde_json::json!([]))
                    }
                } else {
                    Ok(serde_json::json!([]))
                }
            }
        }

        "webprotection.status" => {
            // Authenticated for the same reason as watcher.status: the
            // response discloses the machine's configured DNS servers and
            // how many block rules are loaded.
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC required for web protection status".to_string(),
                ))
                .unwrap_or_default();
            }
            ok_json(serde_json::to_value(state.web_protection_status()).unwrap_or_default())
        }
        "watcher.status" => {
            // Scanner-B Finding 2: response includes the full list of
            // watched roots — gives an unauth local caller an oracle for
            // "drop your payload in this sibling directory and it will
            // be missed." Now requires the IPC secret.
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC required for watcher status".to_string(),
                ))
                .unwrap_or_default();
            }
            ok_json(state.watcher_status())
        }
        "idle_scanner.status" => {
            // Scanner-B Finding 3: response includes current_target (the
            // path being scanned). Unauth poll = oracle for "where the
            // scanner is NOT looking right now" → window for drops.
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC required for idle scanner status".to_string(),
                ))
                .unwrap_or_default();
            }
            ok_json(state.idle_scanner_stats())
        }
        "update.status" => ok_json(state.update_status()),
        "update.start" => {
            // R4-LETHAL-4: no auth was required → any unprivileged caller
            // could trigger a signature update at will. That forces an
            // engine reload (~5-8s scan-blind window) and lets an attacker
            // open repeatable scanning gaps on demand to drop payloads.
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC update start required".to_string(),
                ))
                .unwrap_or_default();
            }
            let r = AppState::start_update(state, /* manual */ true);
            Ok(r)
        }
        "activity.list" => {
            // R7-LETHAL: activity log includes scan history, settings
            // changes, protection state transitions, recent errors.
            // Useful to an attacker for timing-attack scheduling
            // (drop right after the most-recent scheduled scan).
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC activity list required".to_string(),
                ))
                .unwrap_or_default();
            }
            ok_json(state.activity_list())
        }
        "activity.log" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC activity log required".to_string(),
                ))
                .unwrap_or_default();
            }
            let bounded = |name: &str, fallback: &str, max: usize| -> String {
                req.params
                    .get(name)
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or(fallback)
                    .chars()
                    .take(max)
                    .collect()
            };
            let severity_raw = bounded("severity", "info", 24);
            let category_raw = bounded("category", "general", 40);
            let title_raw = bounded("title", "Activity event", 154);
            let message = bounded("message", "", 512);
            // Scanner-B Finding 5: IPC-originated activity must never be
            // able to impersonate internal severities or categories used
            // by the daemon to flag real incidents. Otherwise an attacker
            // with the IPC secret can poison the defender's activity feed
            // with fake "critical/security" entries, burying genuine
            // alerts under decoy noise (defender-blinding primitive).
            //
            // - Restrict severity to {info, warning}. critical|error are
            //   reserved for internal categories (engine, security, etc.).
            // - Force category to start with "gui:" so internal categories
            //   ("security", "engine", "scan", "settings", "sources",
            //   "protection", ...) can never be impersonated from IPC.
            let severity = match severity_raw.as_str() {
                "info" | "warning" => severity_raw,
                _ => "info".to_string(),
            };
            let category = format!("gui:{}", category_raw);
            // Adversary A4: the gui: category prefix and severity allowlist
            // weren't enough — an attacker could still submit
            // `severity=warning, title="CRITICAL: malware ABC quarantined"`
            // and slip an authoritative-looking string into the GUI alert
            // feed + diagnostics.export.recent_errors. Force a "[gui] "
            // prefix on the title too so defenders can visually distinguish
            // (and grep-filter) IPC-injected events. Title length cap
            // remains 160 chars including prefix.
            let title = format!("[gui] {}", title_raw);
            state.log_activity(&severity, &category, &title, &message, None);
            Ok(serde_json::json!({"ok": true}))
        }
        "stats.runtime" => ok_json(state.runtime_stats()),

        // ARGUS heuristic analysis (requires auth — file content probing).
        "argus.analyze" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC required for ARGUS analysis".to_string(),
                ))
                .unwrap_or_default();
            }
            let target = req.params.get("path").and_then(|v| v.as_str());
            match target {
                Some(p) => {
                    // ☠️ R8-LETHAL (audit): this handler used to accept any
                    // path with only the BUILTIN\Users-readable secret as a
                    // gate, and `analyze_file` stats + reads the file as
                    // SYSTEM. A UNC path here is the same machine-account
                    // NTLM-relay primitive `scan.start` already blocks (plus
                    // a SYSTEM file-existence/read oracle for local paths).
                    if let Err(msg) = validate_local_scan_path(p) {
                        return serde_json::to_vec(&RpcErrorResponse::err(
                            req.id,
                            error_codes::INVALID_PARAMS,
                            msg,
                        ))
                        .unwrap_or_default();
                    }
                    let path = std::path::Path::new(p);
                    if path.exists() {
                        // User-initiated single-file analysis → manual
                        // profile budget (60s deep-analysis cap) instead of
                        // the engine's implicit default.
                        let verdict = state.argus().analyze_file_with_budget(
                            path,
                            argus::budget::ScanExecutionBudget::manual(),
                        );
                        ok_json(verdict)
                    } else {
                        Ok(serde_json::json!({"error": "File not found"}))
                    }
                }
                None => Ok(serde_json::json!({"error": "Missing 'path' parameter"})),
            }
        }

        // ARGUS verdict history.
        "argus.verdicts" => {
            // R7-LETHAL parity (audit): verdict history returns detection
            // signature names + file paths — the exact intel class
            // quarantine.list / detections.list are auth-gated for. The
            // central dispatcher now enforces the declared AuthenticatedRead
            // class; this in-handler check stays as defence in depth.
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC required for ARGUS verdict history".to_string(),
                ))
                .unwrap_or_default();
            }
            let scan_id = req.params.get("scan_id").and_then(|v| v.as_str());
            let db_guard = state.db_ref().lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ref db) = *db_guard {
                let rows = match scan_id {
                    Some(id) => db.argus_verdicts_for_scan(id),
                    None => db.recent_argus_verdicts(50),
                };
                ok_json(rows)
            } else {
                Ok(serde_json::json!([]))
            }
        }

        "argus.version" => {
            let stats = state.argus().stats();
            Ok(serde_json::json!({
                "engine": "ARGUS",
                "version": argus::ENGINE_VERSION,
                "layers": [
                    "signatures", "mime_validation", "structural_analysis",
                    "packer_detection", "script_analysis", "pattern_detection",
                    "file_deception", "ioc_correlation", "yara_rules",
                    "reputation", "authenticode"
                ],
                "stats": stats
            }))
        }

        // ── Signature Sources ─────────────────────────────
        // Read-only; auth enforced centrally (registry: AuthenticatedRead).
        "sources.status" | "sources.list" => {
            let sig_dir = crate::paths::paths().signatures_dir();
            let mut mgr = crate::engine::sources::SignatureSourceManager::new(&sig_dir);
            let config = crate::config::Config::load(None).unwrap_or_default();
            let provider = if config.enhanced_signature_provider == "none" {
                None
            } else {
                Some(config.enhanced_signature_provider.clone())
            };
            mgr.load_config(provider);
            Ok(mgr.diagnostics())
        }

        // Privileged: requires challenge token (changes security posture).
        "sources.set" => {
            // Require challenge token — provider change affects detection coverage.
            let token = req
                .params
                .get("challenge_token")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_challenge_token(token, "sources.set") {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INSUFFICIENT_PRIVILEGE,
                    "challenge token required to change signature sources".to_string(),
                ))
                .unwrap_or_default();
            }

            let provider_id = req
                .params
                .get("provider")
                .and_then(|v| v.as_str())
                .unwrap_or("none");

            // Validate provider exists.
            let sig_dir = crate::paths::paths().signatures_dir();
            let mut mgr = crate::engine::sources::SignatureSourceManager::new(&sig_dir);
            let new_provider = if provider_id == "none" {
                None
            } else {
                Some(provider_id)
            };
            if !mgr.set_enhanced(new_provider) && new_provider.is_some() {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    format!("unknown provider: {provider_id}"),
                ))
                .unwrap_or_default();
            }

            // Save to config (v0.1.9 Phase 2: serialise the load-modify-write
            // window against other config-saving handlers — see
            // AppState::lock_config_write doc).
            let _cfg_guard = state.lock_config_write();
            let mut config = crate::config::Config::load(None).unwrap_or_default();
            config.enhanced_signature_provider = provider_id.to_string();
            let config_path = crate::paths::paths().config_file();
            let _ = config.save(&config_path);
            drop(_cfg_guard);

            // Invalidate mpool cache — force rebuild with new provider.
            let cache_path = crate::paths::paths().mpool_cache();
            if cache_path.exists() {
                let _ = std::fs::remove_file(&cache_path);
                info!("sources.set: mpool cache invalidated");
            }
            let meta_path = crate::paths::paths().mpool_meta();
            let _ = std::fs::remove_file(&meta_path);

            // Audit trail.
            state.log_activity(
                "critical",
                "sources",
                &format!("Enhanced signature provider changed to: {provider_id}"),
                "",
                None,
            );

            info!(
                provider = provider_id,
                "signature source changed — restart required for activation"
            );

            Ok(serde_json::json!({
                "ok": true,
                "provider": provider_id,
                "restart_required": true,
                "cache_invalidated": true,
            }))
        }

        // Update enhanced signature provider files.
        // Challenge-token protected — modifies detection coverage.
        "sources.update" => {
            let token = req
                .params
                .get("challenge_token")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_challenge_token(token, "sources.update") {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INSUFFICIENT_PRIVILEGE,
                    "challenge token required for provider update".to_string(),
                ))
                .unwrap_or_default();
            }

            // Single-flight: a second update while one is running gets a
            // busy response instead of racing the staging directories.
            if SOURCES_UPDATE_IN_PROGRESS
                .compare_exchange(
                    false,
                    true,
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                )
                .is_err()
            {
                return serde_json::to_vec(&serde_json::json!({
                    "ok": false,
                    "error": "signature source update already in progress"
                }))
                .unwrap_or_default();
            }
            // RAII guard: flag MUST reset even if the pipeline panics —
            // a stuck flag would reject every future sources.update until
            // daemon restart (same pattern as ReloadGuard in state.rs).
            struct SourcesUpdateGuard;
            impl Drop for SourcesUpdateGuard {
                fn drop(&mut self) {
                    SOURCES_UPDATE_IN_PROGRESS
                        .store(false, std::sync::atomic::Ordering::SeqCst);
                }
            }
            let _update_guard = SourcesUpdateGuard;

            let config = crate::config::Config::load(None).unwrap_or_default();
            if config.enhanced_signature_provider == "none" {
                return serde_json::to_vec(&serde_json::json!({
                    "ok": false,
                    "error": "no enhanced provider configured"
                }))
                .unwrap_or_default();
            }

            // Find the active provider.
            let p = crate::paths::paths();
            let mut source_mgr =
                crate::engine::sources::SignatureSourceManager::new(&p.signatures_dir());
            source_mgr.load_config(Some(config.enhanced_signature_provider.clone()));

            let provider = match source_mgr.active_enhanced() {
                Some(prov) => prov.clone(),
                None => {
                    return serde_json::to_vec(&serde_json::json!({
                        "ok": false,
                        "error": "configured provider not found in registry"
                    }))
                    .unwrap_or_default();
                }
            };

            // Run the update pipeline OFF the tokio worker — it is minutes
            // of blocking network + disk I/O (see run_blocking).
            let provider_name = provider.name.clone();
            let result = match run_blocking(move || {
                let mut pipeline =
                    crate::engine::update_pipeline::SignatureUpdateManager::new();
                pipeline.update_provider(&provider)
            }) {
                Ok(r) => r,
                Err(e) => {
                    return serde_json::to_vec(&serde_json::json!({
                        "ok": false,
                        "error": format!("update pipeline task failed: {e}")
                    }))
                    .unwrap_or_default();
                }
            };

            if result.success {
                // Invalidate mpool cache — force rebuild with new signatures.
                let cache_path = p.mpool_cache();
                if cache_path.exists() {
                    let _ = std::fs::remove_file(&cache_path);
                }
                let _ = std::fs::remove_file(p.mpool_meta());

                state.log_activity(
                    "info",
                    "sources",
                    &format!(
                        "Enhanced signatures updated: {} ({} files)",
                        provider_name, result.files_activated
                    ),
                    "",
                    None,
                );
            } else {
                state.log_activity(
                    "critical",
                    "sources",
                    &format!(
                        "Enhanced signature update FAILED: {}",
                        result.error.as_deref().unwrap_or("unknown")
                    ),
                    "",
                    None,
                );
            }

            Ok(serde_json::json!({
                "ok": result.success,
                "files_downloaded": result.files_downloaded,
                "files_activated": result.files_activated,
                "error": result.error,
                "restart_required": result.success,
            }))
        }

        // Rollback enhanced signatures to official-only.
        "sources.rollback" => {
            let token = req
                .params
                .get("challenge_token")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_challenge_token(token, "sources.rollback") {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INSUFFICIENT_PRIVILEGE,
                    "challenge token required for rollback".to_string(),
                ))
                .unwrap_or_default();
            }

            let mut pipeline = crate::engine::update_pipeline::SignatureUpdateManager::new();
            pipeline.rollback();
            pipeline.cleanup_all_staging();

            // Invalidate cache.
            let p = crate::paths::paths();
            let _ = std::fs::remove_file(p.mpool_cache());
            let _ = std::fs::remove_file(p.mpool_meta());

            state.log_activity(
                "critical",
                "sources",
                "Enhanced signatures rolled back — official ClamAV only",
                "",
                None,
            );

            Ok(serde_json::json!({
                "ok": true,
                "mode": "official_only",
                "restart_required": true,
            }))
        }

        // ARGUS reload — hot-reload YARA rules + IOC hashes.
        "argus.reload" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC ARGUS reload required".to_string(),
                ))
                .unwrap_or_default();
            }
            // Adversary A3: argus.reload was the unfixed sibling of
            // engine.reload/update.start — same reload-stacking DoS class
            // (YARA reload + trusted_cache.invalidate() shortens the
            // ARGUS-effective window for seconds). Now PrivilegedMutation
            // and challenge-token gated; an attacker with the IPC secret
            // can no longer chain reloads to extend the scan-blind window.
            let token = req
                .params
                .get("token")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_challenge_token(token, "argus.reload") {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "challenge token required for ARGUS reload".to_string(),
                ))
                .unwrap_or_default();
            }
            let yara_dirs = crate::paths::paths().yara_rule_dirs();
            let yara_result = state.argus().yara.load_rules_on_large_stack(&yara_dirs);
            let yara_msg = match yara_result {
                Ok(count) => format!("{count} YARA rules reloaded"),
                Err(e) => format!("YARA reload error: {e}"),
            };

            // Reload IOC hashes.
            let mut ioc_count = 0u64;
            for ip in &crate::paths::paths().ioc_hash_paths() {
                if ip.exists() {
                    if let Ok(c) = state.argus().ioc.load_from_file(ip) {
                        ioc_count = c;
                        break;
                    }
                }
            }

            // Detection capability just changed — expire the per-hash trusted
            // cache so files previously scored clean are RE-analyzed against the
            // new rules/IOCs. Without this the cache's sig_generation never
            // advanced in production (only a test called invalidate()), so a
            // signed/reputable file cached clean would shortcut ARGUS forever,
            // even when a freshly-loaded YARA rule now matches it.
            state.argus().trusted_cache.invalidate();

            state.log_activity(
                "info",
                "argus",
                "ARGUS intelligence reloaded",
                &yara_msg,
                None,
            );
            Ok(serde_json::json!({
                "ok": true,
                "yara_rules": state.argus().yara.rule_count(),
                "ioc_hashes": ioc_count,
                "message": yara_msg,
            }))
        }

        // ARGUS intelligence packs — read manifest and return pack info.
        "argus.packs" => {
            let manifest_paths = [crate::paths::paths().pack_manifest()];
            let mut packs = serde_json::json!([]);
            for mp in &manifest_paths {
                if mp.exists() {
                    if let Ok(content) = std::fs::read_to_string(mp) {
                        if let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&content) {
                            if let Some(p) = manifest.get("packs") {
                                packs = p.clone();
                            }
                        }
                    }
                }
            }
            let stats = state.argus().stats();
            Ok(serde_json::json!({
                "packs": packs,
                "total_yara_rules": stats.yara_rules_loaded,
                "total_ioc_hashes": stats.ioc_hashes_loaded,
                "reputation_entries": argus::layers::reputation::reputation_count(),
                "engine_version": argus::ENGINE_VERSION,
            }))
        }

        // ── Memory Scanner ──────────────────────────────────
        "memory.list_processes" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC memory access required".to_string(),
                ))
                .unwrap_or_default();
            }
            ok_json(crate::memory_scanner::list_processes())
        }

        "memory.scan_process" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC memory access required".to_string(),
                ))
                .unwrap_or_default();
            }
            let pid_raw = req.params.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
            if pid_raw == 0 {
                Ok(serde_json::json!({"error": "pid required"}))
            } else if pid_raw > u32::MAX as u64 {
                // Reject instead of silently truncating u64→u32 and scanning
                // an arbitrary (wrong) process.
                Ok(serde_json::json!({"error": "pid out of range"}))
            } else {
                let pid = pid_raw as u32;
                // The scan walks every readable region of the target process
                // (up to ~30s of blocking ReadProcessMemory + ARGUS buffer
                // analysis). Run it on the blocking pool so this tokio worker
                // keeps serving other IPC connections (see run_blocking).
                let argus = state.argus_shared();
                let result = match run_blocking(move || {
                    crate::memory_scanner::scan_process_simple(pid, &argus)
                }) {
                    Ok(r) => r,
                    Err(e) => {
                        return serde_json::to_vec(&RpcErrorResponse::err(
                            req.id,
                            error_codes::INTERNAL_ERROR,
                            format!("memory scan task failed: {e}"),
                        ))
                        .unwrap_or_default();
                    }
                };
                state.log_activity(
                    if result.findings.is_empty() {
                        "info"
                    } else {
                        "warning"
                    },
                    "memory_scan",
                    &format!("Memory scan: {} (PID {})", result.process_name, pid),
                    &format!(
                        "{} regions, {} findings",
                        result.regions_scanned,
                        result.findings.len()
                    ),
                    None,
                );
                ok_json(result)
            }
        }

        "settings.get" => {
            // R4-LETHAL-6: previously no auth → any caller could read the
            // entire config including `excluded_paths`, `excluded_extensions`,
            // `excluded_detections`, `trusted_hashes` and `realtime_roots`.
            // That is *exactly* the intel an attacker needs to choose a
            // payload drop location the scanner will skip and a SHA the
            // scanner will trust. Reading the config is now authenticated.
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC settings read required".to_string(),
                ))
                .unwrap_or_default();
            }
            let mut config = crate::config::Config::load(None).unwrap_or_default();
            // Redact the developer-mode password hash — never expose it over IPC
            // even though it is one-way (the GUI never needs it; it sends the
            // plaintext password to dev.set_developer_mode for verification).
            config.developer.password_sha256.clear();
            ok_json(config)
        }
        // Challenge token — GUI requests before dangerous commands.
        "security.challenge" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC challenge required".to_string(),
                ))
                .unwrap_or_default();
            }
            // Adversary A2: tokens are method-scoped. The caller MUST declare
            // up-front which dangerous method this token is for; the server
            // rejects any presentation against a different method. The
            // registry is a closed allowlist so a typo or attacker-chosen
            // method string can't get a token issued for an unintended op.
            let method = req
                .params
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !is_challengeable_method(method) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "challenge token requires a known dangerous-method scope (param: method)".to_string(),
                ))
                .unwrap_or_default();
            }
            // v0.1.9: every challengeable method is privileged-mutation.
            // Refuse token issuance to unelevated callers up front so they
            // get a clean error instead of issue-then-reject churn; this
            // also stops the unelevated-token-spam audit-log noise primitive.
            // The dispatch-level gate above is the actual security boundary
            // (defence in depth — this is just early/cleaner refusal).
            if let client_auth::Decision::Deny(reason) =
                client_auth::require_elevation(peer)
            {
                tracing::warn!(
                    requested_method = method,
                    sid = peer.map(|p| p.sid.as_str()).unwrap_or("?"),
                    reason,
                    "IPC: refused to issue challenge token to unelevated caller"
                );
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INSUFFICIENT_PRIVILEGE,
                    format!(
                        "challenge token for '{method}' requires an elevated caller (run Sentinella as administrator)"
                    ),
                ))
                .unwrap_or_default();
            }
            let token = state.generate_challenge_token(method);
            Ok(serde_json::json!({"token": token, "method": method}))
        }

        "settings.set" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC settings update required".to_string(),
                ))
                .unwrap_or_default();
            }
            // Scanner-B Finding 1: settings.set is declared PrivilegedMutation
            // in policy; the central dispatcher enforces the Authenticated*
            // classes but challenge-token verification stays per-handler.
            // Without the token check below, anyone with the IPC secret could
            // mutate configuration without ever obtaining a challenge token,
            // downgrading effective protection to AuthenticatedAction. Even
            // though the kill-vector fields (excluded_*, trusted_hashes,
            // realtime_roots, etc.) are pinned to current values below, the
            // remaining mutable surface is still worth a token gate (e.g.
            // heuristic thresholds, scheduler windows).
            let token = req
                .params
                .get("token")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_challenge_token(token, "settings.set") {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "challenge token required for settings update".to_string(),
                ))
                .unwrap_or_default();
            }
            // v0.1.9 Phase 2: hold the config write lock for the entire
            // load-current → merge → save window so a parallel
            // settings.set_full / protection.set_critical can't clobber
            // our save (or have us clobber theirs).
            let _cfg_guard = state.lock_config_write();
            let current = crate::config::Config::load(None).unwrap_or_default();

            // settings_set_merge overlays the params onto `current` (so an
            // omitted key is left alone rather than reset to its serde
            // default) and then re-pins every kill-vector field. See its doc
            // comment for what each property protects.
            match settings_set_merge(&current, &req.params) {
                Ok(mut config) => {
                    // Validate the remaining mutable fields.
                    config.validate();

                    // Load safe (validated) detection exclusions.
                    state.load_detection_exclusions(config.excluded_detections.clone());

                    // Log any settings change for audit trail.
                    state.log_activity(
                        "info",
                        "settings",
                        "Configuration updated via IPC",
                        "",
                        None,
                    );

                    let path = crate::paths::paths().config_file();
                    match config.save(&path) {
                        Ok(()) => Ok(serde_json::json!({"ok": true})),
                        Err(e) => Ok(serde_json::json!({"ok": false, "error": e})),
                    }
                }
                // settings_set_merge already prefixes the deserialization
                // failure with "invalid config: " — don't double it.
                Err(e) => Ok(serde_json::json!({"ok": false, "error": e})),
            }
        }

        // ── v0.1.9 Phase 4: GUI-pushed fullscreen verdict ─────────
        //
        // Audit MED-8: the daemon runs as a Windows service (session 0)
        // and its `GetForegroundWindow` returns NULL, so the v0.1.8
        // foreground-window-style check in idle_scanner/resources.rs was
        // dead code in production. The GUI lives in the user session and
        // CAN call the API correctly; this method lets it push its
        // verdict so the idle scanner's pause-on-fullscreen actually
        // works for real games.
        //
        // Cheap auth: same as other status-bucket writes — IPC secret
        // check, no challenge token, no elevation. There's no
        // privilege-escalation primitive in flipping a bool that only
        // affects whether we DO LESS work (skip an idle scan tick).
        "system.fullscreen_report" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC required".to_string(),
                ))
                .unwrap_or_default();
            }
            let active = req
                .params
                .get("active")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            state.record_gui_fullscreen(active);
            ok_json(serde_json::json!({"ok": true}))
        }

        "health" => {
            // NOTE (v0.1.11 security fix): the v0.1.10 build exposed
            // `weedhack_active` + `weedhack_last_confirmed_unix` here. This
            // endpoint is PUBLIC / unauthenticated (policy.rs: pub_status),
            // so those fields handed any local process a yes/no + timestamp
            // oracle for "did Sentinella confirm a WeedHack campaign, and
            // when" — useful intel for an attacker timing evasion/cleanup,
            // and inconsistent with the auth-gating the same release applied
            // to runtime.status (the "Adversary A1" hardening). The full
            // weedhack_campaigns block lives on the auth-gated runtime.status
            // / diagnostics.export endpoints; it does NOT belong on health.
            Ok(serde_json::json!({
                "status": "ok",
                "version": sentinella_common::PRODUCT_VERSION,
                "uptime_secs": state.uptime_secs(),
                "user_disabled": state.is_user_disabled(),
                "daemon_mode": state.daemon_mode(),
                "audit_mode": state.is_audit_mode(),
                "memory_pressure": state.pressure_state(),
                "working_set": state.residency_diagnostics(),
                // Tamper-detection signals (fail-loud: daemon keeps running,
                // operator sees the drift via this health endpoint).
                "binary_integrity_drift": state.binary_integrity_drift(),
                "config_drift": state.config_drift(),
            }))
        },

        // ── v0.1.8 FullConfig surface ─────────────────────
        // Full config mirror (every TOML knob). Returns FullConfig with
        // developer.password_sha256 already redacted (the type doesn't carry it).
        "settings.get_full" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC settings read required".to_string(),
                ))
                .unwrap_or_default();
            }
            let config = crate::config::Config::load(None).unwrap_or_default();
            let full = sentinella_ipc_proto::full_config::FullConfig::from(&config);
            ok_json(full)
        }

        // Defaults for "reset to default" buttons in the GUI. Same auth as get_full.
        "settings.get_defaults" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC settings read required".to_string(),
                ))
                .unwrap_or_default();
            }
            ok_json(sentinella_ipc_proto::full_config::FullConfig::default())
        }

        // Restart-requirement map: which fields need engine reload vs full daemon restart.
        // Computed from the proto's static table; never touches disk or config.
        "settings.restart_requirements" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC settings read required".to_string(),
                ))
                .unwrap_or_default();
            }
            let map = sentinella_ipc_proto::full_config::RestartRequirementMap::build();
            ok_json(map)
        }

        // Apply NON-critical fields from a FullConfig. Kill-vector fields are
        // pinned to current values by `apply_non_critical`, AND additionally
        // verified via `critical_diff` — the request is REJECTED entirely if
        // any kill-vector field differs. Token-gated like settings.set.
        "settings.set_full" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC settings update required".to_string(),
                ))
                .unwrap_or_default();
            }
            let token = req
                .params
                .get("token")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_challenge_token(token, "settings.set_full") {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "challenge token required for settings update".to_string(),
                ))
                .unwrap_or_default();
            }
            // Strip the IPC envelope fields before deserializing into FullConfig.
            // Nothing in the FullConfig tree sets `deny_unknown_fields` (it is
            // `#[serde(default)]` throughout), so serde would ignore these two
            // keys anyway — the strip is hygiene, not a deserialization
            // requirement. It matters the day someone adds a config key named
            // `auth` or `token`: without the strip the IPC envelope would
            // silently overwrite it with the secret/challenge string.
            let mut params = req.params.clone();
            if let Some(obj) = params.as_object_mut() {
                obj.remove("auth");
                obj.remove("token");
            }
            match serde_json::from_value::<sentinella_ipc_proto::full_config::FullConfig>(params) {
                Ok(full) => {
                    // v0.1.9 Phase 2: serialise the read-modify-write window
                    // against parallel config writers (settings.set /
                    // protection.set_critical / sources.set / dev.set_developer_mode).
                    let _cfg_guard = state.lock_config_write();
                    let mut config = crate::config::Config::load(None).unwrap_or_default();
                    let diffs = config.critical_diff(&full);
                    if !diffs.is_empty() {
                        // SECOND-LAYER DEFENCE: even though apply_non_critical
                        // would silently ignore these, REJECTING the request
                        // surfaces the violation to the GUI so a misbehaving
                        // client doesn't think it succeeded. Also a clear
                        // audit-log signal of attempted kill-vector tampering.
                        state.log_activity(
                            "warning",
                            "settings",
                            &format!(
                                "settings.set_full rejected — kill-vector mutation: {}",
                                diffs.join(", ")
                            ),
                            "Use protection.set_critical (requires UAC) for these fields",
                            None,
                        );
                        return serde_json::to_vec(&RpcErrorResponse::err(
                            req.id,
                            error_codes::INSUFFICIENT_PRIVILEGE,
                            format!(
                                "rejected: kill-vector fields can only be changed via protection.set_critical: {}",
                                diffs.join(", ")
                            ),
                        ))
                        .unwrap_or_default();
                    }
                    config.apply_non_critical(&full);
                    config.validate();
                    let path = crate::paths::paths().config_file();
                    match config.save(&path) {
                        Ok(()) => {
                            // Push the hot-applied thresholds into AppState.
                            // Saving the TOML alone left the daemon running on
                            // its boot values, so the GUI's "no restart needed"
                            // pill was lying about these two fields.
                            // Every hot-applied setting, not just the two
                            // staleness thresholds. `restart_requirement()`
                            // tells the GUI these need no restart, so the
                            // daemon has to actually re-read them here; the
                            // FISH shield's active response was pinned to its
                            // boot value for the process lifetime because
                            // nothing did.
                            state.refresh_hot_config(&config);
                            state.log_activity(
                                "info",
                                "settings",
                                "Configuration updated via settings.set_full",
                                "",
                                None,
                            );
                            Ok(serde_json::json!({"ok": true}))
                        }
                        Err(e) => Ok(serde_json::json!({"ok": false, "error": e})),
                    }
                }
                Err(e) => Ok(
                    serde_json::json!({"ok": false, "error": format!("invalid FullConfig: {e}")}),
                ),
            }
        }

        // ── Protection critical settings (requires challenge token) ──
        // Mutates kill-vector fields (CRITICAL_FIELDS in proto::full_config).
        // GUI must request UAC elevation before calling this.
        //
        // v0.1.8 expansion: previously this handled only realtime_enabled +
        // auto_quarantine. The other 10 kill-vector fields had no IPC mutation
        // path at all — they could ONLY be changed by editing the TOML file
        // directly. v0.1.8 fills that gap so the Settings UI can edit
        // exclusions, watched roots, trusted hashes, etc., still gated behind
        // the challenge-token-plus-UAC defence. The eight web_protection.*
        // keys joined later, with the same gate.
        //
        // Validation here is STRICT: anything that smells malformed gets
        // rejected with an explicit reason rather than silently coerced, and
        // any param key no branch recognises is rejected too — an ignored
        // key answered with ok:true is the "applied but never did" lie.
        // The GUI surfaces the reason inline next to the field.
        //
        // All per-key branching lives in apply_set_critical_params (pure,
        // unit-tested); this arm owns the token gate, the write lock, the
        // load/save and every post-save side effect.
        "protection.set_critical" => {
            let token = req
                .params
                .get("token")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_challenge_token(token, "protection.set_critical") {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "challenge token required — call security.challenge first".to_string(),
                ))
                .unwrap_or_default();
            }

            // v0.1.9 Phase 2: serialise the read-modify-write window against
            // parallel config writers (see AppState::lock_config_write).
            let _cfg_guard = state.lock_config_write();
            let mut config = crate::config::Config::load(None).unwrap_or_default();
            let applied = apply_set_critical_params(&mut config, &req.params);

            // Hard-fail if any field had a validation error — partial success
            // would leave the user wondering which field actually got applied.
            if !applied.errors.is_empty() {
                state.log_activity(
                    "warning",
                    "protection",
                    &format!("protection.set_critical rejected: {}", applied.errors.join("; ")),
                    "",
                    None,
                );
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    format!("validation failed: {}", applied.errors.join("; ")),
                ))
                .unwrap_or_default();
            }

            // Re-validate the whole config — catches any cross-field invariants
            // (e.g. cleaning glob extensions, refusing reserved system paths
            // already enforced by Config::validate, etc.).
            config.validate();

            let path = crate::paths::paths().config_file();
            match config.save(&path) {
                Ok(()) => {
                    state.log_activity(
                        "warning",
                        "protection",
                        &format!("Critical settings changed: {}", applied.changes.join(", ")),
                        "Requires administrator elevation",
                        None,
                    );
                    // Reload exclusions immediately — the scanner reads these
                    // through state.load_detection_exclusions, which is the
                    // cache mirrors of the on-disk excluded_detections list.
                    state.load_detection_exclusions(config.excluded_detections.clone());
                    // …and the trusted-hash allowlist, which has exactly the
                    // same shape: watcher/mod.rs consults state.is_hash_trusted
                    // (an in-memory mirror), NOT the TOML. Without this the
                    // daemon kept honouring a hash the admin had just REMOVED
                    // after learning the file was malicious — for the rest of
                    // the daemon's uptime, since main.rs loads this mirror only
                    // at boot and engine reload does not touch it.
                    state.load_trusted_hashes(config.trusted_hashes.clone());
                    // set_critical writes fish.* and clamav_isolation too, and
                    // they are hot-applied by the same classification, so this
                    // path owes the same refresh as settings.set_full.
                    state.refresh_hot_config(&config);
                    // Real-time toggle applied last: start_watcher() re-reads
                    // config.toml, so it must run AFTER the save above or it
                    // picks up the previous realtime_roots. Enabling is
                    // unconditional — an explicit realtime_enabled=true from an
                    // elevated caller IS the request to resume, and gating it on
                    // !is_user_disabled() made re-enabling a no-op whenever the
                    // same handler (or protection.disable) had set that flag.
                    if let Some(v) = applied.realtime_toggle {
                        if v {
                            state.enable_protection();
                        } else {
                            state.disable_protection();
                        }
                    }
                    // web_protection.* is deliberately NOT hot-applied: the
                    // section is consumed once at daemon start (main.rs) and
                    // every field is classified DaemonRestart
                    // (proto::full_config::restart_requirement) — a
                    // half-applied DNS change is how an NRPT rule ends up
                    // pointing at a dead listener. restart_required tells the
                    // GUI to say so; additive, older GUIs ignore the key.
                    let mut payload = serde_json::json!({"ok": true, "changes": applied.changes});
                    if applied.web_protection_touched {
                        payload["restart_required"] = serde_json::json!(true);
                    }
                    Ok(payload)
                }
                Err(e) => Ok(serde_json::json!({"ok": false, "error": e})),
            }
        }

        // Quick protection pause/resume (uses disable_protection/enable_protection state).
        "protection.disable" => {
            let token = req
                .params
                .get("token")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_challenge_token(token, "protection.disable") {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "challenge token required".to_string(),
                ))
                .unwrap_or_default();
            }
            state.disable_protection();
            state.log_activity(
                "warning",
                "protection",
                "Protection paused by user",
                "",
                None,
            );
            Ok(serde_json::json!({"ok": true, "state": "user_disabled"}))
        }

        "protection.enable" => {
            let token = req
                .params
                .get("token")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_challenge_token(token, "protection.enable") {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "challenge token required".to_string(),
                ))
                .unwrap_or_default();
            }
            state.enable_protection();
            state.log_activity("info", "protection", "Protection resumed by user", "", None);
            Ok(serde_json::json!({"ok": true, "state": "restoring"}))
        }

        // Diagnostics snapshot — no file contents, no secrets, no personal data.
        "diagnostics.export" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC diagnostics export required".to_string(),
                ))
                .unwrap_or_default();
            }
            let stats = state.runtime_stats();
            let engine = state.engine_status();
            let idle = state.idle_scanner_stats();
            let watcher = state.watcher_status();
            let argus_stats = state.argus().stats();

            // Recent errors from activity log (last 10 warnings/errors only).
            let recent_errors: Vec<serde_json::Value> = {
                let db_guard = state.db_ref().lock().unwrap_or_else(|e| e.into_inner());
                if let Some(ref db) = *db_guard {
                    db.recent_activity(50)
                        .into_iter()
                        .filter(|a| {
                            a.severity == "warning"
                                || a.severity == "critical"
                                || a.severity == "error"
                        })
                        .take(10)
                        .map(|a| {
                            serde_json::json!({
                                "timestamp": a.timestamp,
                                "severity": a.severity,
                                "category": a.category,
                                "title": a.title,
                            })
                        })
                        .collect()
                } else {
                    vec![]
                }
            };

            // Quarantine metadata only (no file contents).
            let quarantine_summary: Vec<serde_json::Value> = state
                .quarantine_list()
                .into_iter()
                .take(20)
                .map(|r| {
                    serde_json::json!({
                        "signature": r.virus_name,
                        "quarantined_at": r.quarantined_at,
                        "original_size": r.original_size,
                        "status": r.status,
                    })
                })
                .collect();

            let last_scan_perf = state.last_scan_perf_json();
            let footprint = state.capture_footprint();

            Ok(serde_json::json!({
                "version": sentinella_common::PRODUCT_VERSION,
                "daemon_mode": state.daemon_mode(),
                "audit_mode": state.is_audit_mode(),
                "excluded_detections": state.detection_exclusions(),
                "engine_version": engine.engine_version,
                "argus_version": argus::ENGINE_VERSION,
                "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
                "system": crate::footprint::system_info_json(),
                "uptime_secs": stats.uptime_secs,
                "protection_state": stats.protection_state,
                "protection_detail": stats.protection_detail,
                "engine_state": engine.state,
                "signature_count": engine.signature_count,
                "argus_layers": argus_stats.active_layers,
                "argus_yara_rules": argus_stats.yara_rules_loaded,
                "argus_files_analyzed": argus_stats.files_analyzed,
                "argus_worker": state.argus_worker_diagnostics(),
                "orchestrator": state.orchestrator_diagnostics(),
                "watcher_active": watcher.enabled,
                "watcher_mode": watcher.mode,
                "idle_scanner": idle,
                "cache_hits": stats.cache_hits,
                "cache_misses": stats.cache_misses,
                "cache_entries": stats.cache_entries,
                "recent_errors": recent_errors,
                "quarantine_count": quarantine_summary.len(),
                "quarantine_summary": quarantine_summary,
                "last_scan_performance": last_scan_perf,
                "footprint": footprint,
                "fish": state.fish_diagnostics(),
                "resilience": state.resilience_diagnostics(),
                "memory_pressure": state.pressure_policy(),
                "residency": state.residency_diagnostics(),
                "weedhack_campaigns": state
                    .plm()
                    .map(|p| p.weedhack_diagnostics_json())
                    .unwrap_or_else(|| serde_json::json!({"active": 0})),
                "generated_at": chrono::Utc::now().to_rfc3339(),
            }))
        }

        // ── Developer mode (local-only perf telemetry gate) ──
        // Read current dev-mode status. Never returns the password hash.
        "dev.status" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC dev status read required".to_string(),
                ))
                .unwrap_or_default();
            }
            let dev = state.developer_config();
            Ok(serde_json::json!({
                "enabled": dev.enabled,
                "telemetry_enabled": dev.telemetry_enabled,
                // Whether an unlock password has been provisioned (never the hash).
                "provisioned": !dev.password_sha256.is_empty(),
                "telemetry_max_kb": dev.telemetry_max_kb,
                "dump_path": crate::devmode::telemetry::dump_path().to_string_lossy(),
                "dump_size_kb": crate::devmode::telemetry::dump_size_kb(),
            }))
        }

        // Toggle developer mode. Password-gated, local-only, low-harm. The GUI
        // sends the plaintext password (verified against the provisioned hash);
        // on success we flip `developer.enabled` (and optionally
        // `telemetry_enabled`), persist, and refresh the in-memory gate.
        "dev.set_developer_mode" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC dev toggle required".to_string(),
                ))
                .unwrap_or_default();
            }

            let password = req
                .params
                .get("password")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let enabled = req
                .params
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            // v0.1.9 Phase 2: serialise the read-modify-write window against
            // parallel config writers (see AppState::lock_config_write).
            let _cfg_guard = state.lock_config_write();
            let mut config = crate::config::Config::load(None).unwrap_or_default();

            // Verify against the provisioned hash. Empty hash = unprovisioned →
            // verify returns false → mode cannot be enabled. Constant-time.
            if !crate::config::verify_developer_password(
                password,
                &config.developer.password_sha256,
            ) {
                state.log_activity(
                    "warning",
                    "developer",
                    "Developer-mode toggle rejected (bad/absent password)",
                    "",
                    None,
                );
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "developer mode locked: invalid password or not provisioned".to_string(),
                ))
                .unwrap_or_default();
            }

            config.developer.enabled = enabled;
            // Optional sub-switch for the telemetry writer.
            if let Some(t) = req.params.get("telemetry_enabled").and_then(|v| v.as_bool()) {
                config.developer.telemetry_enabled = t;
            }
            // validate() keeps `enabled` only because the hash is provisioned.
            config.validate();

            let path = crate::paths::paths().config_file();
            match config.save(&path) {
                Ok(()) => {
                    // Refresh the in-memory gate so telemetry reflects the
                    // change now. This runs AFTER the save, not before: a
                    // failed save used to return {"ok": false} having already
                    // flipped the runtime gate and logged the flip, so the
                    // telemetry writer ran against a config.toml that still
                    // said developer mode was off — and stayed that way until
                    // the next daemon restart quietly turned it back.
                    state.load_developer_config(config.developer.clone());
                    state.log_activity(
                        "info",
                        "developer",
                        &format!(
                            "Developer mode {} (telemetry {})",
                            if config.developer.enabled { "enabled" } else { "disabled" },
                            if config.developer.telemetry_enabled { "on" } else { "off" },
                        ),
                        "",
                        None,
                    );
                    Ok(serde_json::json!({
                        "ok": true,
                        "enabled": config.developer.enabled,
                        "telemetry_enabled": config.developer.telemetry_enabled,
                    }))
                }
                Err(e) => Ok(serde_json::json!({"ok": false, "error": e})),
            }
        }

        // Run the ARGUS hardware-parity benchmark. Gated behind developer mode
        // (it is a hardware-testing aid, not a normal-user feature) and the
        // result is routed into the perf-telemetry file by the daemon.
        "benchmark.run" => {
            let auth = req
                .params
                .get("auth")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if !state.validate_ipc_auth(auth) {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "authenticated IPC benchmark run required".to_string(),
                ))
                .unwrap_or_default();
            }
            if !state.developer_config().enabled {
                return serde_json::to_vec(&RpcErrorResponse::err(
                    req.id,
                    error_codes::INVALID_PARAMS,
                    "benchmark requires developer mode".to_string(),
                ))
                .unwrap_or_default();
            }
            let passes = req
                .params
                .get("passes")
                .and_then(|v| v.as_u64())
                .unwrap_or(3)
                .clamp(1, 10) as u32;
            match state.run_benchmark(passes) {
                Ok(report) => Ok(report),
                Err(e) => Ok(serde_json::json!({"ok": false, "error": e})),
            }
        }

        _ => Err((
            error_codes::METHOD_NOT_FOUND,
            format!("unknown method: {}", req.method),
        )),
    };

    match result {
        Ok(val) => serde_json::to_vec(&RpcResponse::ok(req.id, val)).unwrap_or_default(),
        Err((code, msg)) => {
            serde_json::to_vec(&RpcErrorResponse::err(req.id, code, msg)).unwrap_or_default()
        }
    }
}

/// Run a blocking closure on tokio's blocking thread pool and wait for it.
///
/// `dispatch_sync` executes on a tokio WORKER thread; long blocking work
/// (signature-source downloads, a ~30s process memory scan) would otherwise
/// stall every unrelated task scheduled on that worker. `block_in_place`
/// lets the executor hand the worker's other tasks to a spare thread while
/// we park here awaiting the `spawn_blocking` result.
fn run_blocking<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, tokio::task::JoinError> {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(tokio::task::spawn_blocking(f))
    })
}

/// Helper: serialize a value into Ok(Value), catching serialization errors.
fn ok_json<T: serde::Serialize>(val: T) -> Result<Value, (i32, String)> {
    serde_json::to_value(val).map_err(|e| {
        (
            error_codes::INTERNAL_ERROR,
            format!("serialization error: {e}"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::validate_local_scan_path;

    // ── settings.set merge/pin helpers ─────────────────────

    /// Read a dotted config path out of a serialized `Config`.
    fn json_at<'a>(v: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
        let mut cur = v;
        for seg in path.split('.') {
            cur = cur.get(seg)?;
        }
        Some(cur)
    }

    /// Write a dotted config path into a params object, creating the
    /// intermediate tables (`fish`, `scan`, …) as needed.
    fn json_set(v: &mut serde_json::Value, path: &str, val: serde_json::Value) {
        let segs: Vec<&str> = path.split('.').collect();
        let mut cur = v;
        for seg in &segs[..segs.len() - 1] {
            let obj = cur.as_object_mut().expect("params node must be an object");
            cur = obj
                .entry((*seg).to_string())
                .or_insert_with(|| serde_json::json!({}));
        }
        cur.as_object_mut()
            .expect("params node must be an object")
            .insert(segs[segs.len() - 1].to_string(), val);
    }

    /// A value of the same JSON shape that is guaranteed to DIFFER from `v`,
    /// so "the pin held" is distinguishable from "the caller sent the value
    /// it already had".
    fn hostile(v: &serde_json::Value) -> serde_json::Value {
        use serde_json::Value;
        match v {
            Value::Bool(b) => Value::Bool(!b),
            Value::String(s) => Value::String(format!("{s}-tampered")),
            Value::Array(a) => {
                let mut out = a.clone();
                out.push(Value::String("tampered".into()));
                Value::Array(out)
            }
            Value::Number(n) => {
                if let Some(u) = n.as_u64() {
                    serde_json::json!(u + 1)
                } else if let Some(i) = n.as_i64() {
                    serde_json::json!(i + 1)
                } else {
                    serde_json::json!(n.as_f64().unwrap_or(0.0) + 1.0)
                }
            }
            _ => Value::String("tampered".into()),
        }
    }

    /// `Config` is `#[serde(default)]`, so deserializing the params object on
    /// its own turns every OMITTED key into that key's Default. A caller that
    /// only wanted to bump one scan limit used to silently revert ClamAV
    /// isolation, the FISH active-response mode, the sandbox and the whole
    /// [web_protection] section — none of which settings.set is allowed to
    /// touch — and persist the result.
    #[test]
    fn settings_set_leaves_omitted_keys_alone() {
        let mut current = crate::config::Config::default();
        // Non-critical, deliberately non-default: only the merge preserves
        // these; the pin list never mentions them.
        current.log_level = "debug".into();
        current.quarantine_retention_days = 30;
        current.scan_archives = false;
        // Critical, deliberately non-default.
        current.clamav_isolation = "subprocess".into();
        current.fish.observe_only = false;
        current.fish.active_response = "terminate".into();
        current.sandbox.enabled = true;
        current.web_protection.enabled = true;
        current.web_protection.blocklists = vec!["C:\\lists\\malware.txt|suffix".into()];

        // The whole request: an envelope plus ONE non-critical knob.
        let params = serde_json::json!({
            "auth": "ipc-secret",
            "token": "challenge",
            "max_file_size_mb": 1024u64,
        });

        let merged = super::settings_set_merge(&current, &params).expect("merge must succeed");

        // The one field the caller actually sent is applied.
        assert_eq!(merged.max_file_size_mb, 1024);

        // Everything omitted keeps its on-disk value.
        assert_eq!(merged.log_level, "debug");
        assert_eq!(merged.quarantine_retention_days, 30);
        assert!(!merged.scan_archives);
        assert_eq!(merged.clamav_isolation, "subprocess");
        assert!(!merged.fish.observe_only);
        assert_eq!(merged.fish.active_response, "terminate");
        assert!(merged.sandbox.enabled);
        assert!(merged.web_protection.enabled);
        assert_eq!(
            merged.web_protection.blocklists,
            vec!["C:\\lists\\malware.txt|suffix".to_string()]
        );
    }

    /// Regression guard for the pin list: walks `CRITICAL_FIELDS` and tries to
    /// mutate every one of them through settings.set. Adding a field to
    /// CRITICAL_FIELDS without pinning it here fails this test rather than
    /// shipping an unelevated mutation path for a kill-vector knob.
    #[test]
    fn settings_set_pins_every_critical_field() {
        use sentinella_ipc_proto::full_config::CRITICAL_FIELDS;

        let current = crate::config::Config::default();
        let current_json = serde_json::to_value(&current).expect("Config must serialize");

        let mut params = serde_json::json!({"auth": "ipc-secret", "token": "challenge"});
        for path in CRITICAL_FIELDS {
            let cur = json_at(&current_json, path)
                .unwrap_or_else(|| panic!("{path} is not a real Config field path"));
            json_set(&mut params, path, hostile(cur));
        }

        let merged = super::settings_set_merge(&current, &params).expect("merge must succeed");
        let merged_json = serde_json::to_value(&merged).expect("Config must serialize");

        for path in CRITICAL_FIELDS {
            assert_eq!(
                json_at(&merged_json, path),
                json_at(&current_json, path),
                "settings.set must not mutate critical field {path} \
                 (protection.set_critical is the elevated path for it)"
            );
        }
    }

    /// [web_protection] is bridged into `FullConfig` (as an `Option`), but
    /// every `web_protection.*` path is in `CRITICAL_FIELDS`, so plain
    /// settings.set_full can never write it — mutations require
    /// protection.set_critical (challenge + elevation). That leaves
    /// settings.set as the only IPC surface that could turn DNS filtering
    /// off — it must not be one.
    #[test]
    fn settings_set_cannot_disable_web_protection() {
        let mut current = crate::config::Config::default();
        current.web_protection.enabled = true;
        current.web_protection.allowlist = vec![".corp.example.com".into()];

        let params = serde_json::json!({
            "auth": "ipc-secret",
            "token": "challenge",
            "web_protection": { "enabled": false, "allowlist": [], "blocklists": [] },
        });

        let merged = super::settings_set_merge(&current, &params).expect("merge must succeed");
        assert!(merged.web_protection.enabled);
        assert_eq!(
            merged.web_protection.allowlist,
            vec![".corp.example.com".to_string()]
        );
    }

    // ── protection.set_critical param application ────────────
    //
    // These exercise apply_set_critical_params, the pure half of the arm
    // (the arm itself needs an AppState; ipc/policy.rs documents why a
    // full in-process harness is impractical). The token gate is NOT
    // covered here: it precedes the call to this function, applies to the
    // whole method uniformly, and is pinned by state.rs's challenge-token
    // tests — so a web_protection.* key without a token can never reach
    // the code tested below.

    /// Build a params object of the same flat shape the verified callers
    /// send: a challenge token plus flat (possibly dotted) field keys.
    fn set_critical_params(pairs: &[(&str, serde_json::Value)]) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert("token".into(), serde_json::json!("challenge"));
        for (k, v) in pairs {
            map.insert((*k).to_string(), v.clone());
        }
        serde_json::Value::Object(map)
    }

    fn config_json(c: &crate::config::Config) -> serde_json::Value {
        serde_json::to_value(c).expect("Config must serialize")
    }

    /// (i) enabled=true + garbage listen → error NAMING listen, and the
    /// config is untouched (transactional apply — the arm hard-fails on
    /// any error before save).
    #[test]
    fn set_critical_wp_enable_with_garbage_listen_rejected() {
        let mut config = crate::config::Config::default();
        let before = config_json(&config);
        let applied = super::apply_set_critical_params(
            &mut config,
            &set_critical_params(&[
                ("web_protection.enabled", serde_json::json!(true)),
                ("web_protection.listen", serde_json::json!("not-an-address")),
            ]),
        );
        assert!(
            applied
                .errors
                .iter()
                .any(|e| e.contains("web_protection.listen") && e.contains("not a valid IP:port")),
            "the error must name the key and the cause: {:?}",
            applied.errors
        );
        assert_eq!(
            config_json(&config),
            before,
            "a rejected request must leave the config untouched"
        );
    }

    /// (ii) A valid enable applies: the section changes, the key appears
    /// in `changes` for the activity log, and web_protection_touched is
    /// set — the flag the arm turns into `restart_required: true` in the
    /// Ok payload (nothing in web_protection hot-applies; DaemonRestart).
    #[test]
    fn set_critical_wp_valid_enable_applies() {
        let mut config = crate::config::Config::default();
        let applied = super::apply_set_critical_params(
            &mut config,
            &set_critical_params(&[("web_protection.enabled", serde_json::json!(true))]),
        );
        assert!(applied.errors.is_empty(), "{:?}", applied.errors);
        assert!(config.web_protection.enabled);
        assert!(applied.web_protection_touched);
        assert!(
            applied
                .changes
                .iter()
                .any(|c| c == "web_protection.enabled=true"),
            "changes must name the key: {:?}",
            applied.changes
        );
    }

    /// (iv) The typo'd key `web_protection.enable` must be REJECTED by the
    /// unknown-key sweep, not ignored — ignoring it while answering
    /// ok:true was the lie this sweep exists to close.
    #[test]
    fn set_critical_wp_typo_key_rejected_not_ignored() {
        let mut config = crate::config::Config::default();
        let before = config_json(&config);
        let applied = super::apply_set_critical_params(
            &mut config,
            &set_critical_params(&[("web_protection.enable", serde_json::json!(true))]),
        );
        assert!(
            applied
                .errors
                .iter()
                .any(|e| e.contains("unknown parameter") && e.contains("web_protection.enable")),
            "the typo must be rejected as unknown: {:?}",
            applied.errors
        );
        assert!(!config.web_protection.enabled);
        assert_eq!(config_json(&config), before);
    }

    /// (v) Composite gate: a request that only sets listen, against a
    /// stored enabled=true, must be judged on the MERGED result — a
    /// non-53 port cannot serve through NRPT, so the request is rejected
    /// even though it never mentioned `enabled`.
    #[test]
    fn set_critical_wp_listen_change_judged_against_stored_enabled() {
        let mut config = crate::config::Config::default();
        config.web_protection.enabled = true;
        let before = config_json(&config);
        let applied = super::apply_set_critical_params(
            &mut config,
            &set_critical_params(&[(
                "web_protection.listen",
                serde_json::json!("127.0.0.1:5353"),
            )]),
        );
        assert!(
            applied
                .errors
                .iter()
                .any(|e| e.contains("refusing to save enabled=true")),
            "the composite gate must reject: {:?}",
            applied.errors
        );
        assert_eq!(
            config_json(&config),
            before,
            "rejected — the stored, servable config must survive"
        );
    }

    /// (vi) A blocklists entry with an unknown policy token is an ERROR —
    /// over IPC, service.rs's silent degrade-to-exact would report a
    /// filtering semantic the engine never got.
    #[test]
    fn set_critical_wp_blocklist_unknown_policy_rejected() {
        let mut config = crate::config::Config::default();
        let applied = super::apply_set_critical_params(
            &mut config,
            &set_critical_params(&[(
                "web_protection.blocklists",
                serde_json::json!(["C:\\feeds\\md.txt|prefix"]),
            )]),
        );
        assert!(
            applied
                .errors
                .iter()
                .any(|e| e.contains("web_protection.blocklists") && e.contains("unknown policy")),
            "{:?}",
            applied.errors
        );
        assert!(config.web_protection.blocklists.is_empty());
    }

    /// (vii) The sweep rejects unknown keys on PRE-EXISTING config fields
    /// too, not just web_protection typos: max_file_size_mb is a real
    /// Config field that simply has no set_critical branch (it is not
    /// critical), and scan.argus_worker_enabled is CRITICAL_FIELDS-listed
    /// but mirrored by the argus_worker_enabled branch — neither may be
    /// written through this method.
    #[test]
    fn set_critical_unknown_preexisting_fields_rejected() {
        for key in ["max_file_size_mb", "scan.argus_worker_enabled"] {
            let mut config = crate::config::Config::default();
            let before = config_json(&config);
            let applied = super::apply_set_critical_params(
                &mut config,
                &set_critical_params(&[(key, serde_json::json!(false))]),
            );
            assert!(
                applied
                    .errors
                    .iter()
                    .any(|e| e.contains("unknown parameter") && e.contains(key)),
                "{key} must be rejected, not ignored: {:?}",
                applied.errors
            );
            assert_eq!(config_json(&config), before, "{key} must not apply");
        }
    }

    /// (viii) The exact param shapes the GUI's two callers send must pass
    /// the unknown-key sweep. Encoded from gui/src-tauri/src/lib.rs:
    /// set_critical_protection sends token + realtime_enabled /
    /// auto_quarantine only; set_critical_settings passes useFullConfig's
    /// criticalDiff, whose keys come from the TS CRITICAL_FIELDS set and
    /// are flat dotted paths (the scan.argus_worker_* entries of that set
    /// are never sent — no Settings tab writes them, and the daemon
    /// mirrors them from the top-level keys at save; grep-verified).
    #[test]
    fn set_critical_gui_caller_shapes_pass_the_sweep() {
        // set_critical_protection shape.
        let mut config = crate::config::Config::default();
        let applied = super::apply_set_critical_params(
            &mut config,
            &set_critical_params(&[
                ("realtime_enabled", serde_json::json!(false)),
                ("auto_quarantine", serde_json::json!(false)),
            ]),
        );
        assert!(applied.errors.is_empty(), "{:?}", applied.errors);
        assert_eq!(applied.realtime_toggle, Some(false));

        // set_critical_settings criticalDiff shape: flat dotted keys,
        // including the web_protection.* block a future Settings UI sends.
        let mut config = crate::config::Config::default();
        let applied = super::apply_set_critical_params(
            &mut config,
            &set_critical_params(&[
                ("excluded_extensions", serde_json::json!(["scr"])),
                ("fish.active_response", serde_json::json!("suspend")),
                ("web_protection.block_response", serde_json::json!("zero_ip")),
            ]),
        );
        assert!(applied.errors.is_empty(), "{:?}", applied.errors);
        assert_eq!(config.excluded_extensions, vec!["scr".to_string()]);
        assert_eq!(config.fish.active_response, "suspend");
        assert_eq!(config.web_protection.block_response, "zero_ip");
        assert!(applied.web_protection_touched);
    }

    /// Polarity pin: turning web protection OFF is the emergency fix and
    /// must always be accepted, even when the stored section could never
    /// serve. The composite gate runs only on an enabled RESULT.
    #[test]
    fn set_critical_wp_disable_always_allowed() {
        let mut config = crate::config::Config::default();
        config.web_protection.enabled = true;
        config.web_protection.listen = "not-an-address".into();
        let applied = super::apply_set_critical_params(
            &mut config,
            &set_critical_params(&[("web_protection.enabled", serde_json::json!(false))]),
        );
        assert!(applied.errors.is_empty(), "{:?}", applied.errors);
        assert!(!config.web_protection.enabled);
    }

    /// Strict types: a present web_protection.* key with the wrong JSON
    /// type is an error, never a silent no-op.
    #[test]
    fn set_critical_wp_wrong_types_rejected() {
        for (key, val) in [
            ("web_protection.enabled", serde_json::json!("yes")),
            ("web_protection.listen", serde_json::json!(53)),
            ("web_protection.upstreams", serde_json::json!("system")),
            ("web_protection.block_response", serde_json::json!(0)),
            ("web_protection.log_queries", serde_json::json!(1)),
        ] {
            let mut config = crate::config::Config::default();
            let before = config_json(&config);
            let applied = super::apply_set_critical_params(
                &mut config,
                &set_critical_params(&[(key, val)]),
            );
            assert!(
                applied.errors.iter().any(|e| e.contains(key)),
                "{key}: wrong type must be rejected: {:?}",
                applied.errors
            );
            assert_eq!(config_json(&config), before, "{key} must not apply");
        }
    }

    /// Per-key validation spot-checks for the remaining web_protection
    /// fields: upstream entries, block_response allowlist, health-check
    /// name and allowlist entries.
    #[test]
    fn set_critical_wp_field_validation() {
        // A garbage upstream (not "system", not IP:port).
        let mut config = crate::config::Config::default();
        let applied = super::apply_set_critical_params(
            &mut config,
            &set_critical_params(&[(
                "web_protection.upstreams",
                serde_json::json!(["9.9.9.9"]),
            )]),
        );
        assert!(applied.errors.iter().any(|e| e.contains("web_protection.upstreams")));

        // block_response outside the allowlist.
        let mut config = crate::config::Config::default();
        let applied = super::apply_set_critical_params(
            &mut config,
            &set_critical_params(&[(
                "web_protection.block_response",
                serde_json::json!("redirect"),
            )]),
        );
        assert!(
            applied
                .errors
                .iter()
                .any(|e| e.contains("not in allowlist (nxdomain|zero_ip)"))
        );

        // health_check_name with a backslash (escape-unaware probe).
        let mut config = crate::config::Config::default();
        let applied = super::apply_set_critical_params(
            &mut config,
            &set_critical_params(&[(
                "web_protection.health_check_name",
                serde_json::json!("ex\\ample.com"),
            )]),
        );
        assert!(
            applied
                .errors
                .iter()
                .any(|e| e.contains("web_protection.health_check_name"))
        );

        // allowlist entry with whitespace.
        let mut config = crate::config::Config::default();
        let applied = super::apply_set_critical_params(
            &mut config,
            &set_critical_params(&[(
                "web_protection.allowlist",
                serde_json::json!(["bad name.example"]),
            )]),
        );
        assert!(applied.errors.iter().any(|e| e.contains("web_protection.allowlist")));

        // …and the valid forms of all four sail through.
        let mut config = crate::config::Config::default();
        let applied = super::apply_set_critical_params(
            &mut config,
            &set_critical_params(&[
                (
                    "web_protection.upstreams",
                    serde_json::json!(["system", "9.9.9.9:53"]),
                ),
                ("web_protection.block_response", serde_json::json!("nxdomain")),
                ("web_protection.health_check_name", serde_json::json!("example.org")),
                (
                    "web_protection.blocklists",
                    serde_json::json!(["C:\\feeds\\md.txt|suffix", "C:\\feeds\\plain.txt"]),
                ),
                (
                    "web_protection.allowlist",
                    serde_json::json!([".corp.example.com", "host.example.com"]),
                ),
                ("web_protection.log_queries", serde_json::json!(true)),
            ]),
        );
        assert!(applied.errors.is_empty(), "{:?}", applied.errors);
        assert_eq!(
            config.web_protection.upstreams,
            vec!["system".to_string(), "9.9.9.9:53".to_string()]
        );
        assert_eq!(config.web_protection.health_check_name, "example.org");
        assert!(config.web_protection.log_queries);
    }

    /// The token/auth envelope keys never trip the unknown-key sweep.
    #[test]
    fn set_critical_envelope_keys_are_not_unknown() {
        let mut config = crate::config::Config::default();
        let params = serde_json::json!({
            "token": "challenge",
            "auth": "ipc-secret",
            "auto_quarantine": false,
        });
        let applied = super::apply_set_critical_params(&mut config, &params);
        assert!(applied.errors.is_empty(), "{:?}", applied.errors);
    }

    // ☠️ R8-LETHAL regression: every path-accepting IPC method (scan.start,
    // argus.analyze) routes through validate_local_scan_path. A miss here
    // lets any local user make the SYSTEM daemon authenticate to an
    // attacker SMB share (machine-account NTLM relay) or read the raw disk.
    #[test]
    fn unc_and_device_namespace_paths_rejected() {
        for bad in [
            r"\\attacker.com\share\x",
            r"\\10.0.0.5\share",
            "//attacker/share",
            r"\\?\UNC\host\share\x",
            r"\\?\unc\host\share\x",
            r"\\.\PHYSICALDRIVE0",
            r"\\.\C:",
            r"\\?\GLOBALROOT\Device\Harddisk0\DR0",
            r"C:\somewhere\PhysicalDrive1",
            "",
        ] {
            assert!(
                validate_local_scan_path(bad).is_err(),
                "must reject {bad:?}"
            );
        }
    }

    #[test]
    fn local_paths_still_allowed() {
        for good in [
            r"C:\Users\test\file.exe",
            r"D:\",
            // Windows long-path namespace (std::fs::canonicalize output)
            // must keep working — that is why the filter is precise.
            r"\\?\C:\very-long-path\file.txt",
            r"\\?\D:\folder",
        ] {
            assert!(
                validate_local_scan_path(good).is_ok(),
                "must allow {good:?}"
            );
        }
    }

    #[test]
    fn oversized_and_nul_paths_rejected() {
        let long = "C:\\".to_string() + &"a".repeat(5000);
        assert!(validate_local_scan_path(&long).is_err());
        assert!(validate_local_scan_path("C:\\foo\0bar").is_err());
    }

    #[test]
    fn vault_blob_plausible_enforces_per_format_minimum() {
        // The old `len >= 12` heuristic accepted truncated vaults as
        // "restorable". Chunked v1 min = 44 (16 header + 12 nonce + 16
        // tag); legacy one-shot min = 28 (12 nonce + 16 tag).
        let dir = std::env::temp_dir().join(format!("sent_vault_ok_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let write = |name: &str, bytes: &[u8]| {
            let p = dir.join(name);
            std::fs::write(&p, bytes).unwrap();
            p
        };

        // Truncated blob (< 12 even) and a 12-byte husk: not plausible.
        assert!(!super::vault_blob_plausible(&write("tiny.vault", &[0u8; 5])));
        assert!(!super::vault_blob_plausible(&write("husk.vault", &[0u8; 12])));

        // Legacy minimum (28) accepted; 27 rejected.
        assert!(!super::vault_blob_plausible(&write("legacy27.vault", &[1u8; 27])));
        assert!(super::vault_blob_plausible(&write("legacy28.vault", &[1u8; 28])));

        // Chunked magic present: 44 required.
        let mut chunked_short = crate::quarantine::CHUNKED_MAGIC.to_vec();
        chunked_short.extend_from_slice(&[0u8; 39]); // 43 total
        assert!(!super::vault_blob_plausible(&write("chunked43.vault", &chunked_short)));
        let mut chunked_ok = crate::quarantine::CHUNKED_MAGIC.to_vec();
        chunked_ok.extend_from_slice(&[0u8; 40]); // 44 total
        assert!(super::vault_blob_plausible(&write("chunked44.vault", &chunked_ok)));

        // Missing file: not plausible.
        assert!(!super::vault_blob_plausible(&dir.join("absent.vault")));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
