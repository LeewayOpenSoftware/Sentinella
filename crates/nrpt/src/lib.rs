//! Reading and removing Windows NRPT rules.
//!
//! # Why removal ships first, and alone
//!
//! An NRPT rule points the whole machine's DNS at a nominated resolver. It
//! lives in the registry and SURVIVES REBOOTS. The dangerous state is
//! therefore not "our proxy is broken" — it is "the rule is installed and
//! nothing is answering", which is a machine with no name resolution at
//! all, on every subsequent boot, for a user who cannot search for the fix
//! because search does not resolve.
//!
//! So ownership is inverted from the obvious design: the rule may exist
//! only while the daemon is proven healthy, and a boot-time reconciler
//! running OUT OF PROCESS is what enforces that. This crate is shared by
//! the reconciler (which removes) and later by the daemon (which installs).
//! Removal lands first so that at no point in the commit series can a rule
//! exist with nothing able to take it away.
//!
//! # Registry, not PowerShell
//!
//! `Remove-DnsClientNrptRule` is the documented interface and the wrong one
//! here. The reconciler runs at boot as SYSTEM, must finish in
//! milliseconds, and must work where PowerShell is absent (Server Core,
//! Nano) or restricted (ConstrainedLanguage). Spawning powershell.exe costs
//! module autoload and can block for seconds. Deleting the rule's own
//! subkey is a handful of syscalls with no external dependency, and at boot
//! it lands before the DNS Client has read the policy at all.
//!
//! # Identity is the GUID, never the name
//!
//! Rules are identified by the GUID subkey they live under. Matching on
//! DisplayName or Comment would be check-then-act on a string an
//! administrator or another product can also set, and the failure mode is
//! deleting somebody else's DNS policy.
//!
//! THE INVARIANT THAT MAKES GUID-ONLY IDENTITY SAFE: whatever creates a
//! rule must write its GUID to disk BEFORE creating it. A missing GUID file
//! then means the rule was never created — not that we have lost track of
//! one. The installing side (commit C) has to honour that ordering; this
//! crate's `record_guid` exists to make it the easy thing to do, and to
//! make the record durable (fsync of the file AND its directory).
//! [`unrecorded_catchall_rules`] is the tripwire for the day the invariant
//! breaks anyway: it surfaces — never deletes — rules that match our shape
//! without a record.

use std::path::Path;

#[cfg(windows)]
mod registry;

#[cfg(not(windows))]
mod registry {
    use super::Error;
    pub fn subkey_exists(_path: &str, _guid: &str) -> Result<bool, Error> {
        Err(Error::Unsupported)
    }
    pub fn delete_subkey(_path: &str, _guid: &str) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    pub fn list_subkeys(_path: &str) -> Result<Vec<String>, Error> {
        Err(Error::Unsupported)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn write_rule(
        _path: &str,
        _guid: &str,
        _namespace: &str,
        _servers: &str,
        _config_options: u32,
        _version: u32,
        _comment: &str,
    ) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    pub fn read_rule_values(
        _path: &str,
        _guid: &str,
    ) -> Result<Option<(Vec<String>, String)>, Error> {
        Err(Error::Unsupported)
    }
}

/// Where local (non-GPO) NRPT rules live.
pub const DNS_POLICY_CONFIG: &str =
    r"SYSTEM\CurrentControlSet\Services\DnsCache\Parameters\DnsPolicyConfig";

/// Where GPO-deployed NRPT rules live. A separate container from the local
/// store, and group policy WINS over local rules: a rule here makes our
/// local rule inert. That fails safe (filtering-absent, never no-DNS), but
/// it is exactly the lie the design doc says to surface rather than tell:
/// "GPO presence → surface 'web protection ineffective (GPO NRPT present)',
/// don't silently degrade" (WEB_PROTECTION_DESIGN.md).
pub const GPO_DNS_POLICY_CONFIG: &str =
    r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig";

/// Is ANY rule present under the GPO NRPT container?
///
/// Read-only, and honest about failure the same way the rest of the crate
/// is: an unreadable container is `Err`, never "absent". A caller that
/// would surface "GPO present" to the user must not get to report
/// "definitely no GPO" on the strength of an access error.
pub fn gpo_nrpt_present() -> Result<bool, Error> {
    any_rule(registry::list_subkeys(GPO_DNS_POLICY_CONFIG))
}

/// The decision half of [`gpo_nrpt_present`], split out so it is testable
/// without a live registry.
fn any_rule(listing: Result<Vec<String>, Error>) -> Result<bool, Error> {
    match listing {
        // The container itself is absent on a machine that has never had a
        // GPO NRPT rule: genuinely no GPO rules, not an error.
        Err(Error::NoPolicyContainer) => Ok(false),
        Ok(rules) => Ok(!rules.is_empty()),
        Err(e) => Err(e),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The policy container itself is absent. Normal on a machine that has
    /// never had an NRPT rule, and NOT a failure for a reconciler.
    NoPolicyContainer,
    /// Almost always "not running as SYSTEM or Administrator".
    AccessDenied(String),
    Registry(String),
    /// The GUID was not shaped like a GUID. Refused rather than sanitized:
    /// this string names a key we are about to delete.
    MalformedGuid(String),
    Unsupported,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPolicyContainer => {
                write!(f, "no NRPT policy container (no rules have ever existed)")
            }
            Self::AccessDenied(d) => {
                write!(f, "access denied: {d} (SYSTEM or Administrator required)")
            }
            Self::Registry(d) => write!(f, "registry error: {d}"),
            Self::MalformedGuid(g) => write!(f, "not a GUID: {g:?}"),
            Self::Unsupported => write!(f, "NRPT is a Windows feature"),
        }
    }
}

impl std::error::Error for Error {}

/// Validate a rule GUID before it is ever used to build a registry path.
///
/// Accepts only the braced form Windows writes,
/// `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`. Anything else is refused
/// rather than cleaned up, because a lenient parser here turns a truncated
/// or corrupted state file into "delete some other subkey".
pub fn validate_guid(guid: &str) -> Result<(), Error> {
    let b = guid.as_bytes();
    if b.len() != 38 || b[0] != b'{' || b[37] != b'}' {
        return Err(Error::MalformedGuid(guid.to_string()));
    }
    const DASHES: [usize; 4] = [9, 14, 19, 24];
    for (i, c) in b.iter().enumerate().take(37).skip(1) {
        if DASHES.contains(&i) {
            if *c != b'-' {
                return Err(Error::MalformedGuid(guid.to_string()));
            }
        } else if !c.is_ascii_hexdigit() {
            return Err(Error::MalformedGuid(guid.to_string()));
        }
    }
    Ok(())
}

/// Is a rule with this GUID present?
pub fn rule_exists(guid: &str) -> Result<bool, Error> {
    validate_guid(guid)?;
    match registry::subkey_exists(DNS_POLICY_CONFIG, guid) {
        Err(Error::NoPolicyContainer) => Ok(false),
        other => other,
    }
}

/// Remove the rule with this GUID.
///
/// Idempotent: removing an absent rule is success. The reconciler's job is
/// to reach a STATE, not to perform an action, and an "already gone" error
/// would make every clean boot look like a failure.
pub fn remove_rule(guid: &str) -> Result<(), Error> {
    validate_guid(guid)?;
    match registry::delete_subkey(DNS_POLICY_CONFIG, guid) {
        Err(Error::NoPolicyContainer) => Ok(()),
        other => other,
    }
}

/// The catch-all namespace: every name on the machine.
pub const NAMESPACE_ALL: &str = ".";

/// NRPT rule schema version the DNS Client expects.
const RULE_VERSION: u32 = 2;

/// ConfigOptions bit meaning "generic DNS servers are configured". Without
/// it the DNS Client ignores `GenericDNSServers` and the rule routes
/// nothing — a rule that exists, looks installed, and does nothing.
const CONFIG_OPTION_DNS_SERVERS: u32 = 0x8;

/// Install a rule routing `namespace` to `servers`.
///
/// # THE PRECONDITION
///
/// The caller MUST have recorded the GUID (see [`record_guid`]) and MUST
/// have verified the boot reconciler's task exists (see
/// [`reconciler_task_installed`]) before calling this. Neither is checked
/// here, because this function is the primitive and the policy belongs
/// with the caller — but installing a rule without both is exactly the
/// state the whole design exists to prevent: a machine whose DNS points at
/// us with nothing able to undo it.
pub fn install_rule(guid: &str, namespace: &str, servers: &[std::net::IpAddr]) -> Result<(), Error> {
    validate_guid(guid)?;
    if servers.is_empty() {
        // A rule with no servers routes the namespace into a black hole.
        return Err(Error::Registry(
            "refusing to install a rule with no DNS servers".into(),
        ));
    }
    if namespace.is_empty() {
        return Err(Error::Registry("refusing to install an empty namespace".into()));
    }
    let joined = servers
        .iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(";");
    registry::write_rule(
        DNS_POLICY_CONFIG,
        guid,
        namespace,
        &joined,
        CONFIG_OPTION_DNS_SERVERS,
        RULE_VERSION,
        // Diagnostic only, for an administrator reading the registry or
        // Get-DnsClientNrptRule. Never an identity.
        "Sentinella web protection - removed automatically if the local DNS proxy stops answering",
    )
}

/// Is the boot reconciler's scheduled task registered AND able to run?
///
/// Checked by reading the task's definition file rather than spawning
/// `schtasks /Query`: this is on the daemon's startup path, and this
/// product's own ARGUS treats schtasks invocation as a persistence signal —
/// there is no reason to make our own detection noisier to answer a
/// question the filesystem already answers.
///
/// EXISTENCE IS NOT ENOUGH, and an earlier version of this function got
/// that wrong. Disabling a scheduled task does NOT remove its definition
/// file; it rewrites the file with `<Enabled>false</Enabled>`. So a
/// presence check returned true for a task that will never fire, and the
/// precondition it guards — "nothing could remove the rule if the service
/// stopped" — did not hold. Verified on a live machine: five disabled
/// system tasks, all five with their definition file still present.
///
/// The parse is deliberately crude and deliberately conservative: ANY
/// `<Enabled>false</Enabled>` in the document means "do not rely on this
/// task". A trigger-level disable is as fatal to us as a task-level one,
/// and being wrong in this direction costs FILTERING (we refuse to install
/// a rule), never DNS.
///
/// NEITHER IS THE DEFINITION FILE ENOUGH, and that was the next version of
/// the same mistake. Deleting the reconciler executable does not touch
/// `%SystemRoot%\System32\Tasks\Sentinella\DnsReconcile` — not when this
/// product's own quarantine takes it, not when a competing AV does, not
/// when a partial uninstall skips `--remove-task` because the exe it would
/// have invoked is already gone. The task then stays registered, fires at
/// boot, fails with 0x80070002, and removes nothing — while the daemon,
/// having passed this check, installed a catch-all rule. So the `<Command>`
/// is resolved and its existence is confirmed.
///
/// What that proves and what it does not: it proves a file is at the path
/// the task will launch. It does NOT prove the file is our reconciler or
/// that it will succeed. Full identity would mean hashing, on the startup
/// path, against a manifest this crate deliberately does not depend on —
/// and existence closes the failure that actually happens (the binary is
/// deleted), not a hypothetical substitution by someone who already has
/// SYSTEM.
pub fn reconciler_task_installed() -> bool {
    let Ok(root) = std::env::var("SystemRoot") else {
        return false;
    };
    let path = std::path::Path::new(&root)
        .join("System32")
        .join("Tasks")
        .join("Sentinella")
        .join("DnsReconcile");
    let Ok(bytes) = std::fs::read(&path) else {
        return false;
    };
    task_definition_is_usable(&bytes)
}

/// Both halves of the question, split out so it can be tested against a
/// definition file we wrote rather than against a registered task.
fn task_definition_is_usable(bytes: &[u8]) -> bool {
    if !task_definition_is_enabled(bytes) {
        return false;
    }
    match task_command(&decode_task_xml(bytes)) {
        // A relative command would be resolved against the task's working
        // directory, which we do not know; refuse rather than guess at a
        // path and then "confirm" it.
        Some(cmd) => Path::new(&cmd).is_absolute() && Path::new(&cmd).is_file(),
        None => false,
    }
}

/// The executable path from the task's `<Exec><Command>`, resolved.
///
/// Returns `None` when the document has no command — a task with no Exec
/// action cannot run the reconciler, so that reads as "not installed".
///
/// Handles the three shapes a real definition file can carry: XML entity
/// escapes (our own writer escapes all five, and a path CAN contain `&`),
/// surrounding quotes (what the Task Scheduler UI writes when a path has
/// spaces), and `%VAR%` environment references. An unset variable is left
/// untouched, so the resulting path fails the existence check rather than
/// collapsing into something shorter that might exist.
fn task_command(xml: &str) -> Option<String> {
    let open = xml.find("<Command>")? + "<Command>".len();
    let rest = &xml[open..];
    let close = rest.find("</Command>")?;
    let raw = xml_unescape(rest[..close].trim());
    let unquoted = raw.trim_matches('"').trim();
    if unquoted.is_empty() {
        return None;
    }
    Some(expand_env_vars(unquoted))
}

fn xml_unescape(s: &str) -> String {
    // &amp; LAST: doing it first would turn "&amp;lt;" into "<".
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Expand `%VAR%` references. An unpaired `%`, or a name that is not set,
/// is passed through verbatim.
fn expand_env_vars(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let name = &after[..end];
                match std::env::var(name) {
                    Ok(v) => out.push_str(&v),
                    // Unresolvable: keep the literal so the caller's
                    // existence check fails instead of silently succeeding
                    // against a truncated path.
                    Err(_) => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push('%');
                rest = after;
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Does this task definition describe a task that will actually run?
///
/// Split out so it can be tested without a registered task. Task Scheduler
/// writes these files as UTF-16LE with a BOM, but tolerates UTF-8, so both
/// are decoded.
fn task_definition_is_enabled(bytes: &[u8]) -> bool {
    let text = decode_task_xml(bytes);
    if text.is_empty() {
        // Unreadable is not "enabled". Refusing costs filtering only.
        return false;
    }
    // Whitespace between the tags is legal XML, so normalise before
    // looking. A crude contains() would miss `<Enabled> false </Enabled>`.
    let squashed: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    !squashed.contains("<Enabled>false</Enabled>")
}

fn decode_task_xml(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    String::from_utf8_lossy(bytes).into_owned()
}

/// Every rule GUID currently present — ours and other people's.
///
/// Diagnostic only. Never use this to decide what to delete: see the
/// identity note in the crate docs.
pub fn list_rules() -> Result<Vec<String>, Error> {
    match registry::list_subkeys(DNS_POLICY_CONFIG) {
        Err(Error::NoPolicyContainer) => Ok(Vec::new()),
        other => other,
    }
}

/// The loopback address our rules point at, as the DNS Client writes it
/// into `GenericDNSServers`.
const PROXY_SERVER: &str = "127.0.0.1";

/// The shape of a rule that routes the whole machine's DNS at our proxy:
/// catch-all namespace AND our loopback among the servers. Both halves are
/// required — either one alone matches other people's legitimate policy
/// (a loopback rule for one zone is split DNS; a catch-all pointing
/// elsewhere is somebody else's filter).
fn matches_orphan_pattern(names: &[String], servers: &str) -> bool {
    names.iter().any(|n| n.trim() == NAMESPACE_ALL)
        && servers.split(';').any(|s| s.trim() == PROXY_SERVER)
}

/// Is `guid` the one this installation recorded? Case-insensitive: the
/// registry preserves the case we wrote, but a hand-restored state file
/// may not.
fn is_recorded(recorded: Option<&str>, guid: &str) -> bool {
    recorded.is_some_and(|r| r.eq_ignore_ascii_case(guid))
}

/// Local-store rules that LOOK like ours — catch-all namespace, loopback
/// server — but that no recorded GUID names. SURFACE ONLY: this exists so
/// a caller can log and alarm, never so it can delete.
///
/// Why auto-delete is the trap: "matches our shape, no record" means one
/// of two things this process cannot tell apart. It can be our own
/// orphan — the record lost to power loss, a ProgramData cleanup, a
/// partial restore — and then deletion would be correct and urgent. Or it
/// can be somebody else's rule that happens to route at 127.0.0.1: another
/// product's DNS filter, an administrator's policy, a deliberate
/// honeypot — and then deletion is precisely the foreign-rule-deletion
/// failure the identity design refuses at every other layer. A GUID we
/// have no record of is a GUID we cannot claim, whatever it looks like.
/// So the contract is: surface loudly, let a human with
/// `Get-DnsClientNrptRule` decide.
pub fn unrecorded_catchall_rules(state_file: &Path) -> Result<Vec<String>, Error> {
    let recorded = recorded_guid(state_file);
    let mut out = Vec::new();
    for guid in list_rules()? {
        if is_recorded(recorded.as_deref(), &guid) {
            continue;
        }
        match registry::read_rule_values(DNS_POLICY_CONFIG, &guid)? {
            // Vanished between enumeration and read: a normal race.
            None => continue,
            Some((names, servers)) => {
                if matches_orphan_pattern(&names, &servers) {
                    out.push(guid);
                }
            }
        }
    }
    Ok(out)
}

/// Where the rule GUID is recorded, by convention shared with the daemon.
///
/// Deliberately NOT derived from the daemon's `paths` module: the
/// reconciler must run without loading the daemon's config, and a shared
/// constant that both sides compute the same way is the whole point. If
/// this ever disagrees with the daemon, the reconciler stops being able to
/// name our rule — see the identity note in the crate docs.
pub fn default_state_file() -> std::path::PathBuf {
    let root = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
    std::path::Path::new(&root)
        .join("Sentinella")
        .join("state")
        .join("nrpt-rule.guid")
}

/// Read the GUID this installation recorded, if any.
///
/// Anything unreadable, absent or malformed reads as `None` — "no rule was
/// recorded" — which is the safe direction: it makes the reconciler do
/// nothing rather than delete a key named by garbage.
pub fn recorded_guid(state_file: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(state_file).ok()?;
    let trimmed = raw.trim();
    validate_guid(trimmed).ok()?;
    Some(trimmed.to_string())
}

/// Record a GUID, durably, BEFORE the rule it names is created.
///
/// The ordering is the whole safety argument for identifying rules by GUID
/// alone: if this file is missing, the rule does not exist. Written to a
/// temporary file and renamed so a crash mid-write cannot leave a half
/// GUID that `recorded_guid` would reject and a rule that outlives it.
///
/// "Durably" is load-bearing and means two fsyncs, not zero: the temp file
/// is synced BEFORE the rename (the pattern the daemon's config and
/// signature-update writes already use), and the containing directory is
/// synced AFTER it — without the second, a power loss in the window can
/// drop the rename itself, and the machine is left with a live rule every
/// layer agrees was never created. A sync failure fails the whole call, so
/// the caller refuses to install the rule: that costs filtering, never DNS.
pub fn record_guid(state_file: &Path, guid: &str) -> Result<(), Error> {
    validate_guid(guid)?;
    if let Some(parent) = state_file.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Registry(format!("state dir: {e}")))?;
    }
    let tmp = state_file.with_extension("tmp");
    {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| Error::Registry(format!("state write: {e}")))?;
        f.write_all(guid.as_bytes())
            .map_err(|e| Error::Registry(format!("state write: {e}")))?;
        // Without this the rename below can complete and the system can
        // crash with the GUID never having reached the disk.
        f.sync_all()
            .map_err(|e| Error::Registry(format!("state sync: {e}")))?;
    }
    std::fs::rename(&tmp, state_file).map_err(|e| Error::Registry(format!("state rename: {e}")))?;
    if let Some(parent) = state_file.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

/// fsync a directory so the rename that just happened inside it survives
/// power loss.
///
/// Windows cannot open a directory with `File::open`; it needs
/// `FILE_FLAG_BACKUP_SEMANTICS`, which std's `custom_flags` reaches with
/// no extra dependency, and `FlushFileBuffers` (what `sync_all` calls)
/// requires GENERIC_WRITE on a directory handle — a read handle is
/// ERROR_ACCESS_DENIED. No other durable write in the codebase syncs its
/// directory; this one does because a lost rename here strands a rule
/// forever — the single worst failure mode in the design.
#[cfg(windows)]
fn sync_dir(dir: &Path) -> Result<(), Error> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let d = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(dir)
        .map_err(|e| Error::Registry(format!("state dir sync: {e}")))?;
    d.sync_all()
        .map_err(|e| Error::Registry(format!("state dir sync: {e}")))
}

#[cfg(not(windows))]
fn sync_dir(dir: &Path) -> Result<(), Error> {
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| Error::Registry(format!("state dir sync: {e}")))
}

/// Forget the recorded GUID. Call only AFTER the rule is gone: the reverse
/// order strands a rule nothing can name.
pub fn clear_guid(state_file: &Path) -> Result<(), Error> {
    match std::fs::remove_file(state_file) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Registry(format!("state remove: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0}";

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join("nrpt-tests");
        std::fs::create_dir_all(&d).unwrap();
        d.join(name)
    }

    #[test]
    fn accepts_the_braced_form_windows_writes() {
        assert!(validate_guid(GOOD).is_ok());
        assert!(validate_guid("{deadbeef-dead-beef-dead-beefdeadbeef}").is_ok());
    }

    /// This string names a registry key we are about to DELETE. Every one
    /// of these must be refused rather than cleaned up.
    #[test]
    fn refuses_anything_that_is_not_exactly_a_guid() {
        for bad in [
            "",
            "not-a-guid",
            "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0",
            "{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0",
            "{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F}",
            "{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F00}",
            "{0F1E2D3C_4B5A_6978_8796_A5B4C3D2E1F0}",
            "{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1G0}",
            r"{..\..\Services\Tcpip\Parameters}",
            r"{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0}\..\Other",
        ] {
            assert!(
                validate_guid(bad).is_err(),
                "must refuse {bad:?} — it names a key to delete"
            );
        }
    }

    /// Validation must sit in front of the registry calls, not beside them.
    #[test]
    fn a_malformed_guid_never_reaches_the_registry() {
        assert!(matches!(
            rule_exists(r"..\..\evil"),
            Err(Error::MalformedGuid(_))
        ));
        assert!(matches!(
            remove_rule(r"..\..\evil"),
            Err(Error::MalformedGuid(_))
        ));
        assert!(matches!(
            record_guid(&scratch("never.txt"), "nope"),
            Err(Error::MalformedGuid(_))
        ));
    }

    #[test]
    fn a_missing_state_file_reads_as_no_rule() {
        assert_eq!(recorded_guid(&scratch("absent.txt")), None);
    }

    /// A corrupted state file must read as "no rule recorded", never as a
    /// key name — otherwise a truncated write becomes a deletion target.
    #[test]
    fn a_corrupted_state_file_reads_as_no_rule() {
        let f = scratch("corrupt.txt");
        std::fs::write(&f, "\u{feff}not a guid at all\n").unwrap();
        assert_eq!(recorded_guid(&f), None);
        std::fs::write(&f, "{0F1E2D3C-4B5A-6978-87").unwrap(); // truncated
        assert_eq!(recorded_guid(&f), None);
        let _ = std::fs::remove_file(&f);
    }

    #[test]
    fn record_then_read_round_trips_and_tolerates_whitespace() {
        let f = scratch("roundtrip.txt");
        record_guid(&f, GOOD).unwrap();
        assert_eq!(recorded_guid(&f).as_deref(), Some(GOOD));
        std::fs::write(&f, format!("  {GOOD}\r\n")).unwrap();
        assert_eq!(recorded_guid(&f).as_deref(), Some(GOOD));
        let _ = std::fs::remove_file(&f);
    }

    #[test]
    fn clearing_is_idempotent() {
        let f = scratch("clear.txt");
        record_guid(&f, GOOD).unwrap();
        clear_guid(&f).unwrap();
        clear_guid(&f).expect("clearing an absent record must succeed");
        assert_eq!(recorded_guid(&f), None);
    }

    /// The temp file is a means, not a residue: after a successful record
    /// only the state file itself may remain.
    #[test]
    fn recording_leaves_no_temp_file_behind() {
        let f = scratch("notmp.txt");
        record_guid(&f, GOOD).unwrap();
        assert!(!f.with_extension("tmp").exists());
        assert_eq!(recorded_guid(&f).as_deref(), Some(GOOD));
        let _ = std::fs::remove_file(&f);
    }

    /// The surface logic, against the rule shapes it must classify. Each
    /// assertion is a distinct fixture; weakening the pattern (namespace OR
    /// server alone sufficing) or the recorded-GUID exclusion fails this.
    #[test]
    fn orphan_pattern_classification_fixtures() {
        // ours-with-record: pattern matches but the GUID is recorded, so it
        // is excluded — case-insensitively, because a hand-restored state
        // file may not preserve case.
        assert!(is_recorded(Some(GOOD), GOOD));
        assert!(is_recorded(Some(GOOD), &GOOD.to_lowercase()));

        // ours-no-record and foreign-GUID are the SAME fixture from inside
        // this crate: the pattern matches and nothing records the GUID.
        // Both are surfaced — and the doc on unrecorded_catchall_rules
        // explains why surfacing is ALL we may do.
        assert!(!is_recorded(None, GOOD));
        assert!(!is_recorded(
            Some(GOOD),
            "{11111111-2222-3333-4444-555555555555}"
        ));
        assert!(matches_orphan_pattern(&[".".to_string()], "127.0.0.1"));

        // wrong-namespace: a loopback rule for one zone is somebody's
        // split DNS, not a machine-wide orphan.
        assert!(!matches_orphan_pattern(
            &[".corp.example.com".to_string()],
            "127.0.0.1"
        ));
        // wrong-nameserver: a catch-all pointing elsewhere is not ours.
        assert!(!matches_orphan_pattern(&[".".to_string()], "10.0.0.53"));

        // The multi-entry shapes Windows actually writes.
        assert!(matches_orphan_pattern(
            &[".".to_string()],
            "127.0.0.1;127.0.0.2"
        ));
        assert!(matches_orphan_pattern(
            &[".".to_string(), "example.com".to_string()],
            " 127.0.0.1 "
        ));
    }

    /// The GPO decision must never collapse "could not read" into "no GPO
    /// rules": a caller surfaces one of those to the user as fact.
    #[test]
    fn gpo_decision_never_collapses_unreadable_into_absent() {
        assert_eq!(any_rule(Err(Error::NoPolicyContainer)), Ok(false));
        assert_eq!(any_rule(Ok(vec![])), Ok(false));
        assert_eq!(any_rule(Ok(vec![GOOD.to_string()])), Ok(true));
        match any_rule(Err(Error::AccessDenied("denied".into()))) {
            Err(Error::AccessDenied(_)) => {}
            other => panic!("access-denied must propagate, got {other:?}"),
        }
    }

    /// A rule with no servers routes its whole namespace into a black
    /// hole. On the catch-all namespace that is the machine's entire DNS,
    /// so it is refused at the primitive rather than trusted to callers.
    #[test]
    fn refuses_a_rule_that_would_black_hole_the_namespace() {
        assert!(matches!(
            install_rule(GOOD, NAMESPACE_ALL, &[]),
            Err(Error::Registry(_))
        ));
        assert!(matches!(
            install_rule(GOOD, "", &["1.1.1.1".parse().unwrap()]),
            Err(Error::Registry(_))
        ));
    }

    /// Same guarantee as the delete path: the GUID names a registry key,
    /// so validation happens before anything reaches the registry.
    #[test]
    fn install_validates_the_guid_first() {
        assert!(matches!(
            install_rule(r"..\..\evil", NAMESPACE_ALL, &["1.1.1.1".parse().unwrap()]),
            Err(Error::MalformedGuid(_))
        ));
    }

    /// REGRESSION. Disabling a scheduled task does not remove its
    /// definition file - it rewrites it with an Enabled-false setting. The
    /// old presence check therefore returned true for a task that would
    /// never fire, and the precondition it guards did not hold.
    #[test]
    fn a_disabled_task_definition_is_not_usable() {
        let enabled = b"<Task><Settings><Enabled>true</Enabled></Settings></Task>";
        let disabled = b"<Task><Settings><Enabled>false</Enabled></Settings></Task>";
        assert!(task_definition_is_enabled(enabled));
        assert!(!task_definition_is_enabled(disabled));
    }

    /// Whitespace between tags is legal XML; a naive contains() would miss
    /// it and call a disabled task usable.
    #[test]
    fn whitespace_cannot_hide_a_disable() {
        let spaced = b"<Task><Settings>
  <Enabled> false </Enabled>
</Settings></Task>";
        assert!(!task_definition_is_enabled(spaced));
    }

    /// Task Scheduler writes UTF-16LE with a BOM. Failing to decode it
    /// would make a disabled task read as enabled.
    #[test]
    fn utf16_definitions_are_decoded() {
        let mut utf16: Vec<u8> = vec![0xFF, 0xFE];
        for u in "<Task><Settings><Enabled>false</Enabled></Settings></Task>".encode_utf16() {
            utf16.extend_from_slice(&u.to_le_bytes());
        }
        assert!(
            !task_definition_is_enabled(&utf16),
            "a UTF-16 disabled task must not read as enabled"
        );
    }

    /// Unreadable is not enabled: refusing costs filtering, never DNS.
    #[test]
    fn garbage_is_not_enabled() {
        assert!(!task_definition_is_enabled(&[]));
        assert!(!task_definition_is_enabled(&[0xFF, 0xFE]));
    }

    /// The precondition check must be cheap and must never panic, whatever
    /// the environment looks like. A false "missing" only costs filtering.
    #[test]
    fn task_check_is_total() {
        let _ = reconciler_task_installed();
    }

    /// Build a definition file the way `sentinella-dnsreconcile` does.
    fn definition_for(command: &str) -> Vec<u8> {
        format!(
            "<Task><Settings><Enabled>true</Enabled></Settings>\
             <Actions Context=\"Author\"><Exec><Command>{command}</Command></Exec></Actions></Task>"
        )
        .into_bytes()
    }

    /// REGRESSION, and the second version of the same mistake: an enabled
    /// definition file proves nothing about whether the task can run.
    /// Deleting the reconciler executable — quarantine, a competing AV, a
    /// partial uninstall that skipped `--remove-task` precisely BECAUSE the
    /// exe was gone — leaves the definition untouched. The daemon then
    /// passed this precondition and installed a catch-all rule that nothing
    /// on the machine could remove.
    #[test]
    fn a_task_whose_executable_is_gone_is_not_usable() {
        let present = scratch("reconciler-stand-in.exe");
        std::fs::write(&present, b"not really an exe, but it is a file").unwrap();
        assert!(
            task_definition_is_usable(&definition_for(&present.display().to_string())),
            "a task naming a file that exists must be usable"
        );

        std::fs::remove_file(&present).unwrap();
        assert!(
            !task_definition_is_usable(&definition_for(&present.display().to_string())),
            "the definition survives the executable; the check must not"
        );
    }

    /// A definition with no Exec action cannot launch the reconciler, and a
    /// directory is not something Task Scheduler can start.
    #[test]
    fn a_definition_that_cannot_launch_anything_is_not_usable() {
        assert!(!task_definition_is_usable(
            b"<Task><Settings><Enabled>true</Enabled></Settings></Task>"
        ));
        assert!(!task_definition_is_usable(&definition_for("")));
        assert!(!task_definition_is_usable(&definition_for("   ")));
        // Relative: resolved against a working directory we do not know.
        assert!(!task_definition_is_usable(&definition_for(
            "sentinella-dnsreconcile.exe"
        )));
        // A directory exists but cannot be executed.
        let dir = std::env::temp_dir().join("nrpt-tests");
        assert!(!task_definition_is_usable(&definition_for(
            &dir.display().to_string()
        )));
        // Disabled still loses, even with a command that resolves.
        let f = scratch("disabled-but-present.exe");
        std::fs::write(&f, b"x").unwrap();
        let disabled = format!(
            "<Task><Settings><Enabled>false</Enabled></Settings>\
             <Actions><Exec><Command>{}</Command></Exec></Actions></Task>",
            f.display()
        );
        assert!(!task_definition_is_usable(disabled.as_bytes()));
        let _ = std::fs::remove_file(&f);
    }

    /// The path goes into XML text escaped, may be quoted by the Task
    /// Scheduler UI, and may carry `%VAR%`. Failing to undo any of those
    /// turns a healthy task into "missing" and silently costs filtering.
    #[test]
    fn the_command_is_read_back_the_way_it_was_written() {
        assert_eq!(
            task_command("<Command>C:\\a&amp;b\\d&apos;e\\f.exe</Command>").as_deref(),
            Some("C:\\a&b\\d'e\\f.exe")
        );
        assert_eq!(
            task_command("<Command>\"C:\\Program Files\\S\\r.exe\"</Command>").as_deref(),
            Some("C:\\Program Files\\S\\r.exe")
        );
        assert_eq!(task_command("<Task/>"), None);

        // %VAR% expansion, against a variable that certainly exists.
        let var = if cfg!(windows) { "SystemRoot" } else { "PATH" };
        if let Ok(v) = std::env::var(var) {
            assert_eq!(
                task_command(&format!("<Command>%{var}%\\marker.exe</Command>")).as_deref(),
                Some(format!("{v}\\marker.exe").as_str())
            );
        }

        // An unset variable must NOT collapse into a shorter path that
        // might exist — it stays literal and then fails the file check.
        let cmd = "<Command>%SENTINELLA_NO_SUCH_VAR%\\r.exe</Command>";
        assert_eq!(
            task_command(cmd).as_deref(),
            Some("%SENTINELLA_NO_SUCH_VAR%\\r.exe")
        );
        assert!(!task_definition_is_usable(&definition_for(
            "%SENTINELLA_NO_SUCH_VAR%\\r.exe"
        )));
    }

    /// The ONLY test that exercises the write path against the real
    /// registry, and it is deliberately harmless.
    ///
    /// It installs a rule for `.sentinella-selftest.invalid`, a namespace
    /// that resolves nothing and that no process will ever query, and
    /// removes it again. It does NOT use the catch-all namespace: a
    /// catch-all pointing at a proxy that is not running is exactly the
    /// machine-breaking state this crate exists to prevent, and a test is
    /// not a reason to create it even briefly.
    ///
    ///   cargo test -p nrpt real_write_cycle -- --ignored --nocapture
    ///
    /// Requires Administrator/SYSTEM. Cleans up on every exit path.
    #[test]
    #[ignore = "writes to HKLM: run deliberately, requires elevation"]
    fn real_write_cycle_on_a_harmless_namespace() {
        const TEST_GUID: &str = "{5E27E11A-0000-4000-8000-5E27E11A0001}";
        const TEST_NS: &str = ".sentinella-selftest.invalid";
        let server: std::net::IpAddr = "127.0.0.1".parse().unwrap();

        match install_rule(TEST_GUID, TEST_NS, &[server]) {
            Ok(()) => println!("installed test rule {TEST_GUID} for {TEST_NS}"),
            Err(Error::AccessDenied(d)) => {
                println!("SKIPPED - needs elevation: {d}");
                return;
            }
            Err(e) => panic!("install failed: {e}"),
        }

        // Always tear down, even if an assertion below fails.
        let cleanup = || {
            let r = remove_rule(TEST_GUID);
            println!("cleanup: {r:?}");
            assert!(
                !rule_exists(TEST_GUID).unwrap_or(true),
                "TEST RULE SURVIVED CLEANUP - remove it by hand: {TEST_GUID}"
            );
        };

        let present = rule_exists(TEST_GUID);
        if present != Ok(true) {
            cleanup();
            panic!("rule was installed but does not read back: {present:?}");
        }
        println!("rule reads back as present");

        let listed = list_rules().unwrap_or_default();
        if !listed.iter().any(|g| g.eq_ignore_ascii_case(TEST_GUID)) {
            cleanup();
            panic!("rule is not in the enumeration: {listed:?}");
        }
        println!("rule appears in the enumeration");

        cleanup();
        println!("removed; registry is back to its previous state");
    }

    /// Read-only look at the real machine. IGNORED because it depends on
    /// what this box has configured, but it is the only thing that
    /// exercises the registry FFI at all:
    ///
    ///   cargo test -p nrpt real_registry -- --ignored --nocapture
    ///
    /// Deliberately does NOT delete anything. The delete path is exercised
    /// by the reconciler's own end-to-end check against a rule it created.
    #[test]
    #[ignore = "environment-dependent: reads the live NRPT policy container"]
    fn real_registry_read_only() {
        match list_rules() {
            Ok(rules) if rules.is_empty() => {
                println!("no NRPT rules on this machine (expected)");
            }
            Ok(rules) => {
                println!("{} NRPT rule(s) present:", rules.len());
                for r in &rules {
                    println!("  {r}");
                }
            }
            Err(e) => println!("could not read the policy container: {e}"),
        }
        // A GUID we certainly did not create must read as absent, not as
        // an error, on any machine.
        match rule_exists(GOOD) {
            Ok(present) => assert!(!present, "a random GUID must not be present"),
            Err(e) => println!("rule_exists reported: {e}"),
        }
    }

    /// The reconciler runs on every boot, including boots where nothing
    /// was ever installed. "Never had a rule" must not look like an error.
    #[test]
    fn absent_policy_container_is_not_an_error() {
        // Exercised through the public wrappers, which map
        // NoPolicyContainer to the benign answer.
        #[cfg(not(windows))]
        {
            assert!(matches!(rule_exists(GOOD), Err(Error::Unsupported)));
        }
        #[cfg(windows)]
        {
            // On a real box the container usually exists and is empty;
            // either way neither of these may panic or report failure for
            // a machine that simply has no rules.
            let _ = rule_exists(GOOD);
            let _ = list_rules();
        }
    }

    /// Read-only look at the live GPO NRPT container. IGNORED because the
    /// answer depends on the box's group policy; the pure decision logic
    /// is covered by `gpo_decision_never_collapses_unreadable_into_absent`.
    ///
    ///   cargo test -p nrpt real_gpo -- --ignored --nocapture
    ///
    /// Prerequisites: none beyond Windows — the read needs no elevation.
    #[test]
    #[ignore = "environment-dependent: reads the live GPO NRPT container"]
    fn real_gpo_container_read_only() {
        match gpo_nrpt_present() {
            Ok(true) => println!("GPO NRPT rules ARE present - local rules are inert"),
            Ok(false) => println!("no GPO NRPT rules (expected on most machines)"),
            Err(e) => println!("could not read the GPO container: {e}"),
        }
    }

    /// Read-only run of the orphan-pattern scan against the live store.
    /// IGNORED: environment-dependent. Deletes nothing, ever — that is the
    /// whole point of the function.
    ///
    ///   cargo test -p nrpt real_orphan_scan -- --ignored --nocapture
    #[test]
    #[ignore = "environment-dependent: enumerates the live NRPT store"]
    fn real_orphan_scan_read_only() {
        match unrecorded_catchall_rules(&default_state_file()) {
            Ok(found) if found.is_empty() => println!("no orphan-pattern rules"),
            Ok(found) => println!("orphan-pattern rules (surfaced only): {found:?}"),
            Err(e) => println!("scan failed: {e}"),
        }
    }
}
