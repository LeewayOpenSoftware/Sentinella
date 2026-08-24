//! Registering (and removing) this binary's boot-time Scheduled Task.
//!
//! # Why the binary registers its own task
//!
//! The MSI decides WHEN the task should exist; this code knows HOW. The
//! split exists for one practical reason: the task XML has to name the
//! absolute path of the executable, and that path is only known at install
//! time. Templating it inside the MSI means patching a shipped XML file at
//! install; doing it here means `current_exe()` and no templating at all.
//!
//! # Why XML rather than the schtasks command line
//!
//! `schtasks /Create /SC ONSTART` looks simpler and is wrong. Tasks it
//! creates inherit `DisallowStartIfOnBatteries = true` and
//! `StopIfGoingOnBatteries = true`, neither of which is settable from the
//! command line. A laptop running on battery would therefore never
//! reconcile — and a laptop is exactly the machine most likely to be
//! carrying a stale rule after a crash or a suspended upgrade. Every
//! setting below that departs from the default is there because the
//! default would break the one job this task has.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Task path. The folder keeps it out of the root namespace and makes it
/// obvious in Task Scheduler who owns it.
pub const TASK_NAME: &str = r"\Sentinella\DnsReconcile";

/// The XML Task Scheduler consumes.
///
/// `S-1-5-18` rather than the name "SYSTEM" is deliberate and this project
/// has been bitten before: `runtime_integrity.rs` documents a real bug
/// where English account names silently failed on localized Windows and
/// left a key world-readable. `acl.rs` uses raw SIDs everywhere for the
/// same reason.
pub fn task_xml(exe: &Path) -> String {
    // The path goes into XML text, so the five predefined entities must be
    // escaped. A path cannot contain most of them, but "cannot" is how
    // injection bugs are written.
    let exe = xml_escape(&exe.display().to_string());
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Lucent Open Software</Author>
    <Description>Removes Sentinella's DNS policy rule at boot unless the Sentinella proxy is answering. Prevents a machine from losing name resolution when the service is stopped, crashed, disabled or mid-upgrade.</Description>
    <URI>{TASK_NAME}</URI>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT1M</ExecutionTimeLimit>
    <Priority>4</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{exe}</Command>
    </Exec>
  </Actions>
</Task>
"#
    )
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Register the task, pointing it at THIS executable.
pub fn install() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate self: {e}"))?;
    let xml = task_xml(&exe);

    // Task Scheduler reads the XML as UTF-16 when the declaration says so,
    // and a UTF-8 file with that declaration is rejected on some builds.
    // Writing UTF-16LE with a BOM removes the ambiguity.
    let mut bytes: Vec<u8> = vec![0xFF, 0xFE];
    for unit in xml.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    let tmp = std::env::temp_dir().join("sentinella-dnsreconcile-task.xml");
    std::fs::write(&tmp, &bytes).map_err(|e| format!("cannot write task xml: {e}"))?;

    let out = schtasks(&["/Create", "/TN", TASK_NAME, "/XML", &tmp.display().to_string(), "/F"]);
    // Best-effort cleanup; the file holds no secrets but leaving temp
    // litter on every install is sloppy.
    let _ = std::fs::remove_file(&tmp);
    out
}

/// Remove the task. Idempotent: an absent task is success, because the
/// uninstaller's job is to reach a state.
pub fn remove() -> Result<(), String> {
    match schtasks(&["/Delete", "/TN", TASK_NAME, "/F"]) {
        Ok(()) => Ok(()),
        Err(e) => delete_outcome(e, schtasks(&["/Query", "/TN", TASK_NAME])),
    }
}

/// What a failed delete means, decided WITHOUT reading its message text.
///
/// schtasks has no stable "not found" exit code, and its messages are
/// localized — matching "cannot find"/"does not exist" works only on
/// English Windows, which is exactly the class of bug this crate uses raw
/// SIDs to avoid (see `task_xml`). So absence is VERIFIED instead: a task
/// that no longer answers /Query is gone, whatever the delete said and in
/// whatever language. The residual wrong direction is a query that fails
/// for a reason other than absence (permissions) while the task exists;
/// every caller is elevated, and being wrong that way costs only a
/// spurious success during uninstall.
fn delete_outcome(delete_err: String, query: Result<(), String>) -> Result<(), String> {
    match query {
        // The task does not answer to its name: gone, which was the goal.
        Err(_) => Ok(()),
        // Still there: the delete genuinely failed, and the caller must
        // hear about it.
        Ok(()) => Err(delete_err),
    }
}

/// Invoke schtasks.exe from System32 by absolute path.
///
/// Never the bare name: a boot-time or installer context can have a
/// hostile or merely surprising PATH, and this project already had to fix
/// the same class of bug — `win_process::system32_tool` exists in the
/// daemon for exactly this. Resolved here rather than reused because this
/// binary deliberately does not depend on the daemon crate.
fn schtasks(args: &[&str]) -> Result<(), String> {
    let root = std::env::var("SystemRoot").map_err(|_| {
        // No fallback to the bare name. In the one context where SystemRoot
        // is missing, PATH search is exactly what must not happen.
        "SystemRoot is not set; refusing to resolve schtasks.exe by PATH".to_string()
    })?;
    let exe = PathBuf::from(root).join("System32").join("schtasks.exe");
    if !exe.exists() {
        return Err(format!("{} not found", exe.display()));
    }
    let out = Command::new(&exe)
        .args(args)
        .output()
        .map_err(|e| format!("schtasks: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    Err(format!(
        "schtasks exited {}: {}{}",
        out.status.code().unwrap_or(-1),
        stderr.trim(),
        stdout.trim()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_names_the_exact_executable_path() {
        let xml = task_xml(Path::new(r"C:\Program Files\Sentinella\sentinella-dnsreconcile.exe"));
        assert!(xml.contains(r"<Command>C:\Program Files\Sentinella\sentinella-dnsreconcile.exe</Command>"));
    }

    /// Every one of these departs from the schtasks command-line default,
    /// and each default would break the task's only job. Pinned so a later
    /// "simplification" to `/SC ONSTART` cannot pass review silently.
    #[test]
    fn settings_that_would_otherwise_break_a_laptop_are_explicit() {
        let xml = task_xml(Path::new(r"C:\x\y.exe"));
        // A laptop on battery is the machine MOST likely to carry a stale
        // rule after a crash or suspended upgrade. Defaults are true.
        assert!(xml.contains("<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"));
        assert!(xml.contains("<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"));
        // Must not wait for a network that may itself depend on DNS.
        assert!(xml.contains("<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>"));
        // Boot, not logon: no user may ever log in on a server.
        assert!(xml.contains("<BootTrigger>"));
        // Localized Windows breaks name-based principals; this project has
        // shipped that bug before.
        assert!(xml.contains("<UserId>S-1-5-18</UserId>"));
        // A reconciler that hangs must not hold boot forever.
        assert!(xml.contains("<ExecutionTimeLimit>PT1M</ExecutionTimeLimit>"));
    }

    #[test]
    fn a_path_with_xml_metacharacters_cannot_break_the_document() {
        let xml = task_xml(Path::new(r"C:\a&b\<c>\d'e\f.exe"));
        assert!(xml.contains(r"C:\a&amp;b\&lt;c&gt;\d&apos;e\f.exe"));
        // And the document still has exactly one Command element.
        assert_eq!(xml.matches("<Command>").count(), 1);
    }

    #[test]
    fn the_task_lives_in_our_own_folder() {
        assert_eq!(TASK_NAME, r"\Sentinella\DnsReconcile");
        assert!(task_xml(Path::new("x")).contains(r"<URI>\Sentinella\DnsReconcile</URI>"));
    }

    /// The localized-Windows case (audit F5): a delete that failed with a
    /// message in ANY language must still read as success when the task is
    /// actually gone — and must NOT read as success when it is not. The
    /// old message-text match ("cannot find"/"does not exist") passes the
    /// first case only on English Windows and is why the decision moved to
    /// a re-query.
    #[test]
    fn a_failed_delete_is_decided_by_requery_not_by_message_text() {
        // Delete failed, task is gone: success regardless of language.
        let localized = "schtasks exited 1: ERROR: no existe la tarea especificada".to_string();
        assert!(delete_outcome(localized, Err("query failed".into())).is_ok());
        // Delete failed, task is STILL there: the error must survive.
        let denied = "schtasks exited 1: ERROR: access is denied".to_string();
        match delete_outcome(denied.clone(), Ok(())) {
            Err(e) => assert_eq!(e, denied),
            Ok(()) => panic!("a live task must not read as removed"),
        }
    }
}
