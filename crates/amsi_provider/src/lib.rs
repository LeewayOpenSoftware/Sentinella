//! Sentinella AMSI provider.
//!
//! An **in-process COM server** that Windows AMSI loads into every process
//! that calls `AmsiScanBuffer` — PowerShell, `wscript`/`cscript`, `mshta`,
//! Office macros, the .NET in-memory loader, WMI, etc. It gives Sentinella
//! **pre-execution** visibility into deobfuscated script content, the one
//! thing the file-watcher and sandbox cannot do because they only see a
//! file after it exists.
//!
//! # Shape
//!
//! - `com` (Windows only): implements [`IAntimalwareProvider`] plus an
//!   `IClassFactory` and the `Dll*` COM entry points. This is the code
//!   Windows actually loads.
//! - `decision`, `budget`, `client`, `registration`: pure logic split out
//!   so the parts that matter for correctness — the fail-open policy, the
//!   time budget, the request/response framing, the registry strings — are
//!   unit-tested without a COM host.
//!
//! # Hard constraints (it runs inside other people's processes)
//!
//! - **Never panic across the COM boundary.** A panic would corrupt the
//!   host's stack; `Scan` wraps its whole body in `catch_unwind`.
//! - **Never block.** The daemon round-trip runs under a strict wall-clock
//!   budget on a scratch thread; missing it fails open.
//! - **Fail OPEN.** If the daemon is slow, down, or unreachable, return
//!   `AMSI_RESULT_NOT_DETECTED`. This is the ONE place in Sentinella where
//!   fail-open is correct: blocking Word or PowerShell on a timeout is
//!   worse than missing a single detection. Everything else fails closed.
//!
//! The verdict itself is produced by the daemon (`runtime.scan_buffer`
//! over the existing named-pipe IPC), so the full engine never has to load
//! inside each host process.

pub mod budget;
pub mod client;
pub mod decision;
pub mod registration;

#[cfg(windows)]
pub mod com;

/// Map a host application name (from AMSI's `APP_NAME` attribute) to the
/// `language` token the daemon's `runtime.scan_buffer` expects. The daemon
/// re-maps it via `ScriptLanguage::from_app_name`, so we hand it a stem it
/// will recognise. Kept here (pure) so it is testable and shared.
pub fn language_from_app(app: &str) -> &'static str {
    let lower = app.to_ascii_lowercase();
    if lower.contains("powershell") || lower.contains("pwsh") {
        "powershell"
    } else if lower.contains("cscript") || lower.contains("wscript") {
        // Ambiguous between JScript and VBScript; the daemon defaults this
        // stem to JScript, matching the original amsi module.
        "cscript"
    } else if lower.contains("mshta") {
        "mshta"
    } else if lower.contains("dotnet") || lower.contains("clr") || lower.contains(".net") {
        "dotnet"
    } else {
        "other"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn language_mapping() {
        assert_eq!(language_from_app("powershell.exe"), "powershell");
        assert_eq!(
            language_from_app(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            "powershell"
        );
        assert_eq!(language_from_app("pwsh"), "powershell");
        assert_eq!(language_from_app("cscript.exe"), "cscript");
        assert_eq!(language_from_app("mshta.exe"), "mshta");
        assert_eq!(language_from_app("SomeApp.NET"), "dotnet");
        assert_eq!(language_from_app("winword.exe"), "other");
    }
}
