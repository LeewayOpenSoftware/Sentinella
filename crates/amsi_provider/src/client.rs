//! Minimal synchronous JSON-RPC client to the Sentinella daemon, for the
//! AMSI hot path.
//!
//! It reuses the daemon's existing `runtime.scan_buffer` method and the
//! exact framing every other client uses — a 4-byte big-endian length
//! prefix + a UTF-8 JSON body over the `\\.\pipe\sentinelld` named pipe,
//! with the `auth` secret read from
//! `%ProgramData%\Sentinella\state\ipc_secret` (world-readable by the R3
//! ACL design). It does NOT invent a new channel and does NOT pull in
//! tokio — it must stay tiny because it loads into every host process.
//!
//! `build_request` and `parse_response` are pure and unit-tested. The
//! actual pipe round-trip (`scan_once`) is Windows-only; on any other
//! target, and whenever the daemon is not reachable, it returns `None`
//! (fail open).

use crate::decision::DaemonVerdict;

/// Matches `sentinella_ipc_proto::MAX_FRAME_SIZE`.
pub const MAX_FRAME: usize = 1024 * 1024;

/// Build the `runtime.scan_buffer` request body. Pure and testable.
///
/// The daemon reads `content` as raw UTF-8 text (its param is historically
/// named `content_b64` but it does not base64-decode). `source_pid` lets
/// the daemon add PLM lineage correlation.
pub fn build_request(
    content: &str,
    language: &str,
    source_app: &str,
    content_name: &str,
    source_pid: u32,
    auth: Option<&str>,
) -> Vec<u8> {
    let mut params = serde_json::json!({
        "content": content,
        "language": language,
        "source_app": source_app,
        "content_name": content_name,
        "source_pid": source_pid,
    });
    if let Some(a) = auth {
        params["auth"] = serde_json::Value::String(a.to_string());
    }
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "runtime.scan_buffer",
        "params": params,
    });
    serde_json::to_vec(&req).unwrap_or_default()
}

/// Parse a daemon response body into a verdict. Pure and testable.
///
/// Returns `None` (fail open) for a JSON-RPC error, an `ok:false` result,
/// or anything unparseable. A missing `should_block` is treated as "do not
/// block".
pub fn parse_response(bytes: &[u8]) -> Option<DaemonVerdict> {
    let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    if v.get("error").is_some() {
        return None;
    }
    // runtime.scan_buffer nests its payload under `result`.
    let r = v.get("result").unwrap_or(&v);
    if r.get("ok").and_then(|x| x.as_bool()) == Some(false) {
        return None;
    }
    let should_block = r.get("should_block").and_then(|x| x.as_bool()).unwrap_or(false);
    let score = r.get("score").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
    Some(DaemonVerdict { score, should_block })
}

/// Read the IPC auth secret from ProgramData. `None` if missing/too short.
#[cfg(windows)]
fn load_secret() -> Option<String> {
    let pd = std::env::var("ProgramData").ok()?;
    let path = std::path::PathBuf::from(pd)
        .join("Sentinella")
        .join("state")
        .join("ipc_secret");
    let s = std::fs::read_to_string(path).ok()?;
    let t = s.trim().to_string();
    if t.len() >= 32 { Some(t) } else { None }
}

/// One blocking scan round-trip. `None` on ANY error (fail open). Windows
/// only — the named pipe does not exist elsewhere.
#[cfg(windows)]
pub fn scan_once(
    content: &str,
    language: &str,
    source_app: &str,
    content_name: &str,
    source_pid: u32,
) -> Option<DaemonVerdict> {
    use std::io::{Read, Write};

    let auth = load_secret();
    let body = build_request(content, language, source_app, content_name, source_pid, auth.as_deref());
    if body.is_empty() || body.len() > MAX_FRAME {
        return None;
    }

    let mut pipe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(sentinella_common::IPC_PIPE_NAME)
        .ok()?;

    pipe.write_all(&(body.len() as u32).to_be_bytes()).ok()?;
    pipe.write_all(&body).ok()?;
    pipe.flush().ok()?;

    let mut len = [0u8; 4];
    pipe.read_exact(&mut len).ok()?;
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > MAX_FRAME {
        return None;
    }
    let mut buf = vec![0u8; n];
    pipe.read_exact(&mut buf).ok()?;
    parse_response(&buf)
}

/// Non-Windows stub: there is no AMSI and no pipe, so always fail open.
#[cfg(not(windows))]
pub fn scan_once(
    _content: &str,
    _language: &str,
    _source_app: &str,
    _content_name: &str,
    _source_pid: u32,
) -> Option<DaemonVerdict> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_is_well_formed_jsonrpc() {
        let body = build_request("Write-Host hi", "powershell", "powershell.exe", "script", 1234, Some("s".repeat(32).as_str()));
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["method"], "runtime.scan_buffer");
        assert_eq!(v["params"]["content"], "Write-Host hi");
        assert_eq!(v["params"]["language"], "powershell");
        assert_eq!(v["params"]["source_pid"], 1234);
        assert!(v["params"]["auth"].is_string());
    }

    #[test]
    fn request_without_auth_omits_field() {
        let body = build_request("x", "other", "a.exe", "n", 0, None);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v["params"].get("auth").is_none());
    }

    #[test]
    fn parse_block_result() {
        let raw = br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true,"score":90,"should_block":true}}"#;
        let d = parse_response(raw).unwrap();
        assert!(d.should_block);
        assert_eq!(d.score, 90);
    }

    #[test]
    fn parse_clean_result() {
        let raw = br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true,"score":5,"should_block":false}}"#;
        let d = parse_response(raw).unwrap();
        assert!(!d.should_block);
    }

    #[test]
    fn parse_rpc_error_is_none() {
        let raw = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"bad"}}"#;
        assert!(parse_response(raw).is_none());
    }

    #[test]
    fn parse_ok_false_is_none() {
        let raw = br#"{"result":{"ok":false,"error":"empty content"}}"#;
        assert!(parse_response(raw).is_none());
    }

    #[test]
    fn parse_garbage_is_none() {
        assert!(parse_response(b"not json").is_none());
    }
}
