//! Restricted token process launcher.
//!
//! Creates a low-integrity restricted token and launches the sample with it.
//! The sample cannot write to system directories, access admin resources,
//! or elevate privileges.

#![cfg(target_os = "windows")]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::Win32::Foundation::*;
use windows::Win32::Security::*;
use windows::Win32::System::Threading::*;

/// Result of launching with restricted token.
pub struct RestrictedLaunch {
    pub process_handle: HANDLE,
    pub thread_handle: HANDLE,
    pub pid: u32,
    pub restricted: bool,
    pub low_integrity: bool,
    pub errors: Vec<String>,
}

/// Launch a process with a restricted low-integrity token in suspended state.
///
/// CONTAINMENT MODEL — read before trusting this for isolation:
/// The restricted token is derived from sandboxd's OWN token via
/// `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)` with no restricting/deny SIDs.
/// sandboxd is spawned by the LocalSystem daemon, so that base token is SYSTEM:
/// the result is "SYSTEM with privileges disabled + low integrity", NOT an
/// identity-isolated low-privilege principal — the sample still runs under the
/// SYSTEM SID + admin groups. The **Job Object** (`KILL_ON_JOB_CLOSE`, no
/// breakaway, memory cap) + network block + low integrity are the REAL
/// containment; the token only reduces privilege, not identity.
///
/// On any token-setup or launch failure this FAILS CLOSED (pid == 0, no
/// process created; the caller reports `Blocked`). Detonating with sandboxd's
/// full SYSTEM token — the old fallback — gave the sample unrestricted
/// SYSTEM privileges for the whole timeout window: a containment failure
/// must never become a privilege upgrade.
///
/// v1.0 hardening (tracked in HANDOFF): run sandboxd under a dedicated
/// low-privilege account, or add restricting SIDs, so the sample is identity-
/// isolated and not merely privilege-disabled SYSTEM.
pub fn launch_restricted(sample: &Path, cwd: &Path) -> RestrictedLaunch {
    let mut errors = Vec::new();

    // Get current process token.
    let mut current_token = HANDLE::default();
    let ok = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
            &mut current_token,
        )
    };
    if ok.is_err() {
        errors.push("OpenProcessToken failed — FAIL CLOSED, no detonation".into());
        return failed_launch(errors);
    }

    // Create restricted token — strip most privileges.
    let mut restricted_token = HANDLE::default();
    let ok = unsafe {
        CreateRestrictedToken(
            current_token,
            DISABLE_MAX_PRIVILEGE,
            None,
            None,
            None,
            &mut restricted_token,
        )
    };
    unsafe {
        let _ = CloseHandle(current_token);
    }

    if ok.is_err() {
        errors.push("CreateRestrictedToken failed — FAIL CLOSED, no detonation".into());
        return failed_launch(errors);
    }

    // Set low integrity level via raw SetTokenInformation.
    //
    // SR-02 (fail-open closed): low integrity is one of the THREE real
    // containment layers (see the containment model above — Job Object +
    // network block + low integrity; the token only reduces privilege, not
    // identity). The v1.0 code CONTINUED to detonate when this failed, so a
    // sample could run at the sandbox's own (SYSTEM-derived) integrity level
    // — a silent downgrade of containment. Every other setup failure in this
    // function already fails closed; this one must too. Refuse to detonate
    // rather than run a sample without low integrity.
    let low_integrity_result = set_low_integrity(restricted_token);
    if !may_detonate(low_integrity_result.is_ok()) {
        unsafe {
            let _ = CloseHandle(restricted_token);
        }
        errors.push(format!(
            "Low integrity failed: {} — FAIL CLOSED, no detonation (SR-02)",
            low_integrity_result.err().unwrap_or_default()
        ));
        return failed_launch(errors);
    }
    let low_integrity = true;

    // Create process suspended with restricted token.
    // Quote the command line: with a NULL lpApplicationName, CreateProcess*
    // tokenizes an unquoted path on whitespace and may resolve a whitespace
    // prefix (e.g. `my.exe` for `my file.exe`) instead of the real sample.
    let mut cmd_line = to_wide(&format!("\"{}\"", sample.to_string_lossy()));
    let cwd_wide = to_wide(&cwd.to_string_lossy());
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let ok = unsafe {
        CreateProcessAsUserW(
            restricted_token,
            None,
            windows::core::PWSTR(cmd_line.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            None,
            windows::core::PCWSTR(cwd_wide.as_ptr()),
            &si,
            &mut pi,
        )
    };
    unsafe {
        let _ = CloseHandle(restricted_token);
    }

    if ok.is_err() {
        errors.push("CreateProcessAsUserW failed — FAIL CLOSED, no detonation".into());
        return failed_launch(errors);
    }

    RestrictedLaunch {
        process_handle: pi.hProcess,
        thread_handle: pi.hThread,
        pid: pi.dwProcessId,
        restricted: true,
        low_integrity,
        errors,
    }
}

pub fn resume_thread(thread_handle: HANDLE) {
    if !thread_handle.is_invalid() {
        unsafe {
            let _ = ResumeThread(thread_handle);
        }
    }
}

pub fn close_handles(launch: &RestrictedLaunch) {
    unsafe {
        if !launch.process_handle.is_invalid() {
            let _ = CloseHandle(launch.process_handle);
        }
        if !launch.thread_handle.is_invalid() {
            let _ = CloseHandle(launch.thread_handle);
        }
    }
}

pub fn try_wait(process_handle: HANDLE) -> Option<u32> {
    let result = unsafe { WaitForSingleObject(process_handle, 0) };
    if result == WAIT_OBJECT_0 {
        let mut exit_code = 0u32;
        unsafe {
            let _ = GetExitCodeProcess(process_handle, &mut exit_code);
        }
        Some(exit_code)
    } else {
        None
    }
}

pub fn kill_process(process_handle: HANDLE) {
    if !process_handle.is_invalid() {
        unsafe {
            let _ = TerminateProcess(process_handle, 1);
        }
    }
}

// ── Low integrity SID via raw API ────────────────────────

fn set_low_integrity(token: HANDLE) -> Result<(), String> {
    // Low integrity SID: S-1-16-4096 = 1 sub-authority (4096)
    // SID structure: revision=1, sub_auth_count=1, authority=SECURITY_MANDATORY_LABEL_AUTHORITY (16)
    // Sub-authority[0] = 4096 (SECURITY_MANDATORY_LOW_RID)

    #[repr(C)]
    #[allow(non_snake_case)]
    struct SID_LOW {
        Revision: u8,
        SubAuthorityCount: u8,
        IdentifierAuthority: [u8; 6],
        SubAuthority: [u32; 1],
    }

    let sid = SID_LOW {
        Revision: 1,
        SubAuthorityCount: 1,
        IdentifierAuthority: [0, 0, 0, 0, 0, 16], // SECURITY_MANDATORY_LABEL_AUTHORITY
        SubAuthority: [0x1000],                   // SECURITY_MANDATORY_LOW_RID = 4096
    };

    #[repr(C)]
    #[allow(non_snake_case)]
    struct TOKEN_MANDATORY_LABEL_RAW {
        Label: SID_AND_ATTRIBUTES_RAW,
    }

    #[repr(C)]
    #[allow(non_snake_case)]
    struct SID_AND_ATTRIBUTES_RAW {
        Sid: *const SID_LOW,
        Attributes: u32,
    }

    let label = TOKEN_MANDATORY_LABEL_RAW {
        Label: SID_AND_ATTRIBUTES_RAW {
            Sid: &sid,
            Attributes: 0x00000020, // SE_GROUP_INTEGRITY
        },
    };

    let ok = unsafe {
        SetTokenInformation(
            token,
            TokenIntegrityLevel,
            &label as *const _ as *const std::ffi::c_void,
            (std::mem::size_of::<TOKEN_MANDATORY_LABEL_RAW>()) as u32,
        )
    };

    if ok.is_err() {
        Err("SetTokenInformation(TokenIntegrityLevel) failed".into())
    } else {
        Ok(())
    }
}

/// SR-02 containment policy (pure, so it is unit-testable — a real
/// `SetTokenInformation` cannot be forced to fail on a valid token in a unit
/// test). A sample may detonate ONLY if every real containment layer was
/// established. Low integrity is one of those layers (see the containment
/// model on [`launch_restricted`]), so its failure must block detonation —
/// the same fail-closed rule the token-setup steps already follow.
fn may_detonate(low_integrity_ok: bool) -> bool {
    low_integrity_ok
}

/// Fail-closed launch result: no process was created, pid == 0 signals the
/// caller to report `Blocked` instead of detonating.
fn failed_launch(errors: Vec<String>) -> RestrictedLaunch {
    RestrictedLaunch {
        process_handle: HANDLE::default(),
        thread_handle: HANDLE::default(),
        pid: 0,
        restricted: false,
        low_integrity: false,
        errors,
    }
}

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn to_wide_produces_null_terminated() {
        let wide = to_wide("test");
        // "test" is 4 UTF-16 code units + 1 null terminator = 5
        assert_eq!(wide.len(), 5);
        assert_eq!(*wide.last().unwrap(), 0u16);
        // Verify the content matches 't', 'e', 's', 't', '\0'
        assert_eq!(wide[0], b't' as u16);
        assert_eq!(wide[1], b'e' as u16);
        assert_eq!(wide[2], b's' as u16);
        assert_eq!(wide[3], b't' as u16);
    }

    #[test]
    fn to_wide_handles_empty_string() {
        let wide = to_wide("");
        assert_eq!(wide, vec![0u16]);
    }

    #[test]
    fn sr02_low_integrity_failure_blocks_detonation() {
        // SR-02 regression: low integrity is a REAL containment layer, so a
        // failure to set it must block detonation — NOT continue at the
        // sandbox's own (SYSTEM-derived) integrity level as v1.0 did.
        assert!(
            !may_detonate(false),
            "low-integrity failure must FAIL CLOSED — no detonation (SR-02)"
        );
        // Counter-case: when low integrity IS established, detonation proceeds
        // (closing the hole must not block the legitimate isolated launch).
        assert!(
            may_detonate(true),
            "a fully-contained launch must still be allowed to detonate"
        );
    }

    #[test]
    fn restricted_launch_nonexistent_file_fails_closed() {
        let fake_path = PathBuf::from(r"C:\__nonexistent_sentinella_test_binary__.exe");
        let launch = launch_restricted(&fake_path, std::path::Path::new(r"C:\"));
        // FAIL CLOSED: launch failure must NEVER fall back to an unrestricted
        // (full SYSTEM token) process — pid 0 means no process was created.
        assert_eq!(launch.pid, 0, "fail-closed launch must not create a process");
        assert!(
            !launch.errors.is_empty(),
            "fail-closed launch must record why detonation was refused"
        );
        assert!(!launch.restricted);
    }

    #[test]
    fn restricted_launch_fields_initialized() {
        let launch = RestrictedLaunch {
            process_handle: HANDLE::default(),
            thread_handle: HANDLE::default(),
            pid: 0,
            restricted: false,
            low_integrity: false,
            errors: Vec::new(),
        };
        assert_eq!(launch.pid, 0);
        assert!(!launch.restricted);
        assert!(launch.errors.is_empty());
        assert_eq!(launch.process_handle, HANDLE::default());
        assert_eq!(launch.thread_handle, HANDLE::default());
    }

    #[test]
    fn resume_thread_handles_invalid() {
        // HANDLE::default() is HANDLE(0) — null handle.
        // The function should not panic regardless of the handle value.
        resume_thread(HANDLE::default());
    }

    #[test]
    fn kill_process_handles_invalid() {
        // Should not panic when given a null handle.
        kill_process(HANDLE::default());
    }

    #[test]
    fn try_wait_invalid_handle() {
        // A null handle is not a valid process handle, so WaitForSingleObject
        // will fail and the function should return None, not panic.
        let result = try_wait(HANDLE::default());
        assert_eq!(result, None);
    }

    #[test]
    fn close_handles_invalid_handles() {
        let launch = RestrictedLaunch {
            process_handle: HANDLE::default(),
            thread_handle: HANDLE::default(),
            pid: 0,
            restricted: false,
            low_integrity: false,
            errors: Vec::new(),
        };
        // Should not panic when closing null/invalid handles.
        close_handles(&launch);
    }

    #[test]
    fn sid_low_struct_size() {
        // The low integrity SID struct (S-1-16-4096) has 1 sub-authority.
        // SID layout: Revision (1) + SubAuthorityCount (1) + IdentifierAuthority (6)
        //             + SubAuthority[1] (4) = 12 bytes.
        #[repr(C)]
        struct SidLow {
            revision: u8,
            sub_authority_count: u8,
            identifier_authority: [u8; 6],
            sub_authority: [u32; 1],
        }
        assert_eq!(std::mem::size_of::<SidLow>(), 12);
    }
}
