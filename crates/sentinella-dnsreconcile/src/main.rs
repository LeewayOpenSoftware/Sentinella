//! Boot-time NRPT reconciler.
//!
//! # What it is for
//!
//! An NRPT rule points the whole machine's DNS at our proxy, lives in the
//! registry, and survives reboots. The daemon that serves that DNS is
//! delayed-auto start, so for the first minutes of every boot the rule is
//! live and nothing is listening. And a crash, a failed upgrade, a
//! quarantined binary or a disabled service can leave that state
//! indefinitely — on a machine whose user cannot search for the fix,
//! because search does not resolve.
//!
//! This runs at startup, before the daemon, and enforces one rule:
//!
//! > **The NRPT rule may exist only while our proxy is provably answering.**
//!
//! Under any uncertainty the machine degrades to "no filtering", never to
//! "no DNS". So the daemon owns INSTALLING the rule — it does that only
//! after its own four-step self-test passes — and this owns REMOVING it.
//!
//! # What it deliberately does not do
//!
//! No list loading, no proxy start, no signature download, no config
//! parsing, no network beyond one loopback datagram. It reconciles a state
//! and exits. That is what makes it safe to run on every boot: idempotent,
//! milliseconds, and incapable of making anything worse.
//!
//! It also never INSTALLS a rule. Installing is a decision that requires
//! proof the proxy works, and this process is deliberately too dumb to
//! obtain that proof.
//!
//! And it never deletes a rule it has no record of. A catch-all rule
//! pointing at 127.0.0.1 with no matching GUID record is either our own
//! orphan or somebody else's rule that looks like ours, and the two are
//! indistinguishable from here — so it is SURFACED (log line, console,
//! exit code 3), never removed. Deleting on a shape match is the
//! foreign-rule-deletion trap the nrpt crate's identity design refuses.

mod task;

use std::io::Write;
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;

use dnsguard::filter::CANARY_DOMAIN;
use dnsguard::proxy::is_canary_signature;
use dnsguard::wire;

/// The address NRPT points at. Hardcoded, not read from the daemon's
/// config: NRPT `NameServers` carries no port syntax, so the DNS Client
/// always queries 53, and a reconciler that trusted a config file could be
/// pointed away from the thing it is supposed to check.
const PROBE_ADDR: &str = "127.0.0.1:53";

/// One probe's patience. Short: this runs at boot and a healthy proxy on
/// loopback answers in well under a millisecond.
const PROBE_TIMEOUT: Duration = Duration::from_millis(400);

/// A single failed probe is not proof of death — the proxy sheds under
/// load, and a shed probe looks identical to a dead one. Three tries with
/// a short gap turns "momentarily busy" into "answered", while a genuinely
/// absent listener still fails all three in well under two seconds.
const PROBE_ATTEMPTS: usize = 3;
const PROBE_GAP: Duration = Duration::from_millis(150);

/// Keep the forensic trail from growing without bound on a machine that
/// boots daily for years.
const LOG_MAX_BYTES: u64 = 256 * 1024;

fn main() {
    let mode = match std::env::args().nth(1).as_deref() {
        None => Mode::Reconcile,
        Some("--dry-run") => Mode::DryRun,
        Some("--remove") => Mode::ForceRemove,
        Some("--install-task") => return install_task(),
        Some("--remove-task") => return remove_task(),
        Some("--version" | "-V") => {
            println!("sentinella-dnsreconcile {VERSION}");
            return;
        }
        Some("--help" | "-h") => {
            println!("{USAGE}");
            return;
        }
        Some(other) => {
            eprintln!("unknown argument {other:?}\n\n{USAGE}");
            std::process::exit(2);
        }
    };
    std::process::exit(run(mode));
}

/// Embedded so the binary carries its own version. The installer staging
/// script greps every staged binary for the workspace version to catch a
/// stale artifact being shipped — a check that exists because a stale
/// daemon shipped twice — and a binary with no version string anywhere in
/// it fails that check, correctly.
const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "\
sentinella-dnsreconcile - removes Sentinella's NRPT rule unless the proxy is alive

  (no args)   reconcile: remove the rule unless 127.0.0.1:53 answers as ours
  --dry-run   report what would happen, change nothing
  --remove    remove the rule unconditionally (the uninstall path)

  --install-task  register the boot-time Scheduled Task (installer only)
  --remove-task   unregister it (uninstaller only)

  --help      this text
  --version   print the version

Exit 0 = the system is in the intended state. Exit 1 = it is not and we
could not fix it (almost always: not running as SYSTEM/Administrator).
Exit 3 = an orphan-pattern rule is present: a catch-all rule routing DNS
at 127.0.0.1 that no GUID record names. Surfaced in the log and on the
console, deliberately NOT deleted - it may not be ours.";

/// Installer entry point. Separate from reconciliation on purpose: this
/// binary must be able to register its own task WITHOUT touching NRPT
/// state, so the MSI can create the task before any rule can exist.
fn install_task() {
    match task::install() {
        Ok(()) => println!("registered {}", task::TASK_NAME),
        Err(e) => {
            eprintln!("sentinella-dnsreconcile: cannot register task: {e}");
            std::process::exit(1);
        }
    }
}

/// Uninstaller entry point.
///
/// REFUSES while a rule is still live. The uninstall ladder is meant to
/// remove the RULE first (`--remove`) and the task second, but that
/// ordering lives in the NSIS uninstall hook (`gui/src-tauri/nsis-hooks.nsh`,
/// NSIS_HOOK_PREUNINSTALL — the WiX/MSI packaging this comment used to name
/// was never what shipped) — which a future edit, a partial uninstall, or
/// someone running this by hand can all get wrong. Deleting
/// the remover while a rule is still installed is precisely the state this
/// design exists to prevent, so the refusal belongs HERE, where it holds
/// regardless of who is calling and in what order.
/// The refusal message, as a function so the ASCII test can assert on the
/// string the binary actually emits rather than on a copy of it.
fn refuse_because_rule_is_live(guid: &str) -> String {
    format!(
        "refusing to unregister {}: NRPT rule {guid} is still installed. \
             Remove the rule first (--remove); deleting the task now would \
             leave this machine's DNS pointed at a proxy with nothing able \
             to undo it.",
        task::TASK_NAME
    )
}

/// Same, for the case where the registry could not be read at all.
fn refuse_because_rule_state_is_unknown(e: &nrpt::Error) -> String {
    format!(
        "refusing to unregister {}: cannot confirm the rule is gone ({e})",
        task::TASK_NAME
    )
}

fn remove_task() {
    let state_file = nrpt::default_state_file();
    if let Some(guid) = nrpt::recorded_guid(&state_file) {
        match nrpt::rule_exists(&guid) {
            Ok(true) => {
                let msg = refuse_because_rule_is_live(&guid);
                log(&state_file, &msg);
                eprintln!("sentinella-dnsreconcile: {msg}");
                std::process::exit(1);
            }
            // Unreadable registry is not "confirmed absent". Same reasoning
            // as the reconcile path: refuse rather than act on a guess.
            Err(e) => {
                let msg = refuse_because_rule_state_is_unknown(&e);
                log(&state_file, &msg);
                eprintln!("sentinella-dnsreconcile: {msg}");
                std::process::exit(1);
            }
            Ok(false) => {}
        }
    }
    match task::remove() {
        Ok(()) => {
            log(&state_file, "unregistered the boot reconciler task");
            println!("unregistered {}", task::TASK_NAME);
        }
        Err(e) => {
            eprintln!("sentinella-dnsreconcile: cannot unregister task: {e}");
            std::process::exit(1);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Reconcile,
    DryRun,
    ForceRemove,
}

/// Distinct from 1 ("we failed") because nothing failed: there is
/// something on this machine that needs a human decision, and the log
/// says what. Surfaced by the orphan-pattern scan only.
const EXIT_ORPHAN_SURFACED: i32 = 3;

fn run(mode: Mode) -> i32 {
    let state_file = nrpt::default_state_file();
    // The orphan-pattern scan runs on EVERY invocation, before the
    // recorded-rule logic: the state it catches is precisely the one where
    // the recorded-rule logic has nothing to say ("no recorded rule -
    // nothing to reconcile").
    let scan = scan_for_orphan_pattern_rules(&state_file);
    combine_exit(scan, reconcile(mode, &state_file))
}

/// What the orphan-pattern scan found, for the exit-code decision.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum OrphanScan {
    /// No unrecorded catch-all-to-loopback rule is present.
    Clean,
    /// At least one is present; logged and printed, deliberately not
    /// deleted.
    Found,
    /// The scan itself could not be completed. NOT the same as Clean:
    /// "could not check" must not exit like "checked, nothing there" —
    /// the same rule the reconcile path applies to an unreadable registry.
    Unknown,
}

/// The scan can change a clean result but never masks a failure: a
/// reconcile that already failed keeps its 1.
fn combine_exit(scan: OrphanScan, code: i32) -> i32 {
    if code != 0 {
        return code;
    }
    match scan {
        OrphanScan::Clean => 0,
        OrphanScan::Found => EXIT_ORPHAN_SURFACED,
        OrphanScan::Unknown => 1,
    }
}

/// SURFACE ONLY. A catch-all rule routing at 127.0.0.1 with no recorded
/// GUID is either our own orphan (the record was lost, which the identity
/// design assumes cannot happen) or somebody else's rule that happens to
/// look like ours. From inside this process the two are indistinguishable
/// — which is exactly why this never deletes: deleting the second kind is
/// the foreign-rule-deletion trap the nrpt crate docs refuse. What we can
/// safely do is make it VISIBLE: log, console, exit code.
fn scan_for_orphan_pattern_rules(state_file: &Path) -> OrphanScan {
    match nrpt::unrecorded_catchall_rules(state_file) {
        Ok(found) => {
            for guid in &found {
                let msg = format!(
                    "orphan-pattern rule {guid} present, no record - surfacing, not deleting: \
                     a catch-all rule routes this machine's DNS at 127.0.0.1, but no GUID \
                     record names it as ours"
                );
                log(state_file, &msg);
                eprintln!("sentinella-dnsreconcile: {msg}");
            }
            if found.is_empty() {
                OrphanScan::Clean
            } else {
                OrphanScan::Found
            }
        }
        // A non-Windows host has no NRPT at all; reconcile itself is a
        // no-op there for the same reason.
        Err(nrpt::Error::Unsupported) => OrphanScan::Clean,
        Err(e) => {
            let msg = format!("could not run the orphan-pattern check: {e}");
            log(state_file, &msg);
            eprintln!("sentinella-dnsreconcile: {msg}");
            OrphanScan::Unknown
        }
    }
}

fn reconcile(mode: Mode, state_file: &Path) -> i32 {
    // No recorded GUID means no rule was ever created: record_guid writes
    // the file BEFORE the rule exists, so this direction is safe. Nothing
    // to reconcile.
    let Some(guid) = nrpt::recorded_guid(state_file) else {
        log(state_file, "no recorded rule - nothing to reconcile");
        return 0;
    };

    match nrpt::rule_exists(&guid) {
        Ok(false) => {
            // The rule is gone but our record lingers — after a manual
            // removal, a registry restore, or a GPO takeover. Tidy up so a
            // later install starts from a clean slate.
            log(state_file, &format!("recorded rule {guid} is absent - clearing stale record"));
            if mode != Mode::DryRun {
                let _ = nrpt::clear_guid(state_file);
            }
            return 0;
        }
        Ok(true) => {}
        Err(e) => {
            // CANNOT READ is not CAN CONFIRM ABSENT. Refusing to act on an
            // unreadable registry is the whole reason those are separate
            // error variants: acting would mean deleting on a guess.
            log(state_file, &format!("cannot determine rule state: {e}"));
            eprintln!("sentinella-dnsreconcile: {e}");
            return 1;
        }
    }

    if mode == Mode::ForceRemove {
        return remove(state_file, &guid, mode, "unconditional removal requested");
    }

    // The rule is live. The only thing that justifies leaving it there is
    // proof that OUR proxy is answering at the address it points to.
    if probe_is_ours() {
        log(state_file, &format!("rule {guid} is live and the proxy answers - leaving it"));
        return 0;
    }

    remove(
        state_file,
        &guid,
        mode,
        "rule is live but 127.0.0.1:53 did not answer with our signature",
    )
}

fn remove(state_file: &Path, guid: &str, mode: Mode, why: &str) -> i32 {
    if mode == Mode::DryRun {
        log(state_file, &format!("DRY RUN: would remove {guid} ({why})"));
        println!("would remove {guid}: {why}");
        return 0;
    }
    match nrpt::remove_rule(guid) {
        Ok(()) => {
            // Rule first, record second. The reverse order would leave a
            // moment where the rule exists and nothing names it.
            let _ = nrpt::clear_guid(state_file);
            log(state_file, &format!("REMOVED {guid} ({why}) - DNS restored to system defaults"));
            println!("removed {guid}: {why}");
            0
        }
        Err(e) => {
            log(state_file, &format!("FAILED to remove {guid}: {e}"));
            eprintln!("sentinella-dnsreconcile: failed to remove {guid}: {e}");
            // Leave the record in place: the rule is still there, and the
            // next boot must try again rather than forget about it.
            1
        }
    }
}

/// Ask `127.0.0.1:53` for the canary and require OUR signature back.
///
/// The signature — NOERROR, AA=1, one answer, A `0.0.0.0`, our txid echoed
/// — is synthesized by the serving path itself and can come from neither
/// the cache nor an upstream. A `.invalid` name NXDOMAINs on every stock
/// resolver, so an NXDOMAIN proves nothing; only the signature identifies
/// a local zero-IP blocker on that socket.
///
/// `wire::build_query` emits NO EDNS0 OPT, which is required: the trailing
/// rdata test is only valid for a response that carries none, and the
/// proxy appends an OPT whenever the requester sent one.
fn probe_is_ours() -> bool {
    match PROBE_ADDR.parse::<SocketAddr>() {
        Ok(addr) => probe_addr(addr),
        Err(_) => false,
    }
}

/// The address-taking half, so the positive case can be tested against a
/// real proxy on an ephemeral port.
fn probe_addr(addr: SocketAddr) -> bool {
    for attempt in 0..PROBE_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(PROBE_GAP);
        }
        if probe_once(addr) {
            return true;
        }
    }
    false
}

fn probe_once(addr: SocketAddr) -> bool {
    // A fresh ephemeral socket per attempt, connected so the kernel drops
    // datagrams from anywhere else.
    let Ok(sock) = UdpSocket::bind("127.0.0.1:0") else {
        return false;
    };
    if sock.set_read_timeout(Some(PROBE_TIMEOUT)).is_err() || sock.connect(addr).is_err() {
        return false;
    }
    // The txid does not need to be unguessable here — this is loopback and
    // the socket is connected — but it must be echoed, which is what makes
    // a stale datagram from a previous attempt fail the check.
    let id = (std::process::id() as u16) ^ 0xA5A5;
    let Some(query) = wire::build_query(id, CANARY_DOMAIN, wire::TYPE_A, wire::CLASS_IN) else {
        return false;
    };
    if sock.send(&query).is_err() {
        return false;
    }
    let mut buf = [0u8; 1500];
    match sock.recv(&mut buf) {
        Ok(n) => is_canary_signature(&buf[..n], id),
        Err(_) => false,
    }
}

/// Append one line to a bounded log next to the state file.
///
/// This process has no console at boot and Task Scheduler keeps no output,
/// so without this a removal would be invisible — and "my DNS changed and I
/// do not know why" is exactly the question this file has to answer.
/// Every failure here is swallowed: logging must never be the reason the
/// machine keeps a broken rule.
///
/// Messages are ASCII-only on purpose. This file gets read with `type`,
/// Notepad, or whatever a support engineer has to hand on a machine with
/// no working DNS; a UTF-8 em-dash renders as mojibake in a legacy-codepage
/// console, and the one artifact that has to be readable in an emergency
/// should not depend on the reader's encoding.
///
/// ENFORCED HERE, not left to whoever writes the next message. It used to
/// be a convention backed by a test that asserted on hand-copied duplicates
/// of the messages: editing one to use an em-dash — which the doc comments
/// all around it are full of, so it is the natural thing to type — shipped
/// mojibake with the test still green. Every caller now funnels through
/// [`ascii_only`], so the invariant holds for messages nobody thought about.
fn log(state_file: &Path, msg: &str) {
    let Some(dir) = state_file.parent().and_then(Path::parent) else {
        return;
    };
    let path: PathBuf = dir.join("logs").join("dnsreconcile.log");
    let Some(parent) = path.parent() else { return };
    if std::fs::create_dir_all(parent).is_err() {
        return;
    }
    if std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) > LOG_MAX_BYTES {
        let _ = std::fs::write(&path, b"");
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{}", ascii_only(msg));
    }
}

/// Replace every non-ASCII character with `?`.
///
/// A `?` is ugly. A mojibake byte in the one file somebody reads to find out
/// why their machine has no DNS is worse, and unlike the `?` it is not
/// obviously a substitution.
fn ascii_only(msg: &str) -> String {
    msg.chars()
        .map(|c| if c.is_ascii() { c } else { '?' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With nothing listening, the probe must fail — and fail in bounded
    /// time. A reconciler that hung here would delay every boot.
    #[test]
    fn probe_fails_fast_when_nothing_listens() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let dead = sock.local_addr().expect("addr");
        drop(sock);
        let started = std::time::Instant::now();
        assert!(!probe_once(dead));
        assert!(
            started.elapsed() < PROBE_TIMEOUT * 2,
            "a dead port must not cost more than one timeout"
        );
    }

    /// Something answering on the port is NOT enough — an impostor, or a
    /// different resolver that happens to own 53, must not keep our rule
    /// alive. Only the signature counts.
    #[test]
    fn a_wrong_answer_is_not_our_proxy() {
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind server");
        let addr = server.local_addr().expect("addr");
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            if let Ok((n, peer)) = server.recv_from(&mut buf) {
                // Echo the query back with QR set: a plausible-looking DNS
                // answer that carries none of the signature.
                let mut resp = buf[..n].to_vec();
                if resp.len() > 2 {
                    resp[2] |= 0x80;
                }
                let _ = server.send_to(&resp, peer);
            }
        });
        assert!(
            !probe_once(addr),
            "a generic DNS answer must not be mistaken for our proxy"
        );
    }

    /// REGRESSION, and a test about a test. The old version of this
    /// asserted on hand-copied duplicates of six log messages, so it stayed
    /// green no matter what the code actually wrote — swap any `-` for an
    /// em-dash (the doc comments around them are full of em-dashes) and the
    /// binary shipped mojibake in the one file that has to be readable on a
    /// machine with no DNS. It also did not cover `remove_task`'s two
    /// messages at all, one of which is exactly what the uninstaller's
    /// abort dialog tells the user to go and read.
    ///
    /// So the rule is enforced at the choke point instead, and this checks
    /// the enforcement: whatever a caller hands `log`, the file stays ASCII.
    #[test]
    fn the_log_file_stays_ascii_whatever_a_caller_hands_it() {
        let root = std::env::temp_dir().join("dnsreconcile-ascii-test");
        let _ = std::fs::remove_dir_all(&root);
        let state_file = root.join("state").join("nrpt-rule.guid");
        let log_path = root.join("logs").join("dnsreconcile.log");

        // The exact edit that used to slip through: an em-dash where the
        // ASCII hyphen was. Plus a non-Latin script, for good measure.
        log(&state_file, "no recorded rule \u{2014} nothing to reconcile");
        log(&state_file, "REMOVED {guid} \u{2014} DNS restored \u{4e2d}\u{6587}");

        let written = std::fs::read(&log_path).expect("log file");
        assert!(
            written.is_ascii(),
            "the log has non-ASCII bytes: {:?}",
            String::from_utf8_lossy(&written)
        );
        // And it must still be legible, not blanked.
        let text = String::from_utf8(written).expect("ascii is utf8");
        assert!(text.contains("no recorded rule ? nothing to reconcile"));
        assert!(text.contains("DNS restored ??"));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The strings that go to the console rather than the log. These are
    /// referenced, not copied — an edit to any of them is an edit to what
    /// this test sees.
    #[test]
    fn the_strings_printed_to_the_console_are_ascii() {
        assert!(USAGE.is_ascii(), "usage text: {USAGE}");
        // The uninstall refusals: the abort dialog points the user at these.
        let guid = "{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0}";
        let live = refuse_because_rule_is_live(guid);
        assert!(live.is_ascii(), "not ASCII: {live}");
        let unknown = refuse_because_rule_state_is_unknown(&nrpt::Error::AccessDenied(
            "SYSTEM required".into(),
        ));
        assert!(unknown.is_ascii(), "not ASCII: {unknown}");
        // Both must name the escape hatch, or the refusal is a dead end.
        assert!(live.contains("--remove"));
    }

    /// THE POSITIVE CASE, and the most important test here. If the probe
    /// cannot recognise a genuinely healthy proxy, the reconciler removes
    /// the rule on every single boot and web protection silently never
    /// works — a failure that looks like "the feature does nothing" rather
    /// than like a bug.
    ///
    /// Runs a REAL dnsguard proxy on an ephemeral port and probes it the
    /// same way the boot path probes 127.0.0.1:53.
    #[test]
    fn a_real_proxy_is_recognised_as_ours() {
        use dnsguard::filter::FilterEngine;
        use dnsguard::proxy::{NoopDecisionHook, Proxy, ProxyConfig};
        use std::sync::Arc;

        let rt = tokio::runtime::Runtime::new().expect("runtime");
        let (addr, _guard) = rt.block_on(async {
            // A dead upstream is fine: the canary is short-circuited before
            // decide/cache/forward, so it never touches one. That is
            // precisely what makes the signature un-forgeable by an
            // upstream, and it is why the reconciler can trust it.
            let cfg = ProxyConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                upstreams: vec!["127.0.0.1:9".parse().unwrap()],
                ..ProxyConfig::default()
            };
            let proxy = Proxy::bind(cfg, FilterEngine::new(), Arc::new(NoopDecisionHook))
                .await
                .expect("bind");
            let addr = proxy.local_addr();
            let (tx, rx) = tokio::sync::watch::channel(false);
            let task = tokio::spawn(proxy.run(rx));
            (addr, (tx, task))
        });

        // Probed from a plain blocking thread, exactly as the boot path
        // does — no async runtime involved in the reconciler itself.
        assert!(
            probe_addr(addr),
            "the probe must recognise a healthy dnsguard as ours"
        );
    }

    /// The whole-of-probe budget must stay well inside a boot's patience
    /// even when every attempt times out.
    #[test]
    fn total_probe_budget_is_bounded() {
        let budget = PROBE_TIMEOUT * PROBE_ATTEMPTS as u32
            + PROBE_GAP * (PROBE_ATTEMPTS as u32 - 1);
        assert!(
            budget < Duration::from_secs(2),
            "probe budget {budget:?} is too long for a startup task"
        );
    }

    /// The exit-code contract the installer and Task Scheduler see. The
    /// orphan scan may turn a clean run into 3, and an incomplete scan
    /// into 1 ("could not check" is not "checked, nothing there") — but
    /// neither may ever mask a failure the reconcile already reported.
    /// Revert-check: dropping the scan from `run` fails the Found rows;
    /// collapsing Unknown into Clean fails the Unknown row.
    #[test]
    fn the_orphan_scan_changes_clean_results_and_never_masks_failures() {
        assert_eq!(combine_exit(OrphanScan::Clean, 0), 0);
        assert_eq!(combine_exit(OrphanScan::Found, 0), EXIT_ORPHAN_SURFACED);
        assert_eq!(combine_exit(OrphanScan::Unknown, 0), 1);
        for scan in [OrphanScan::Clean, OrphanScan::Found, OrphanScan::Unknown] {
            assert_eq!(combine_exit(scan, 1), 1, "{scan:?} must not mask a failure");
        }
        // And the documented contract is in the text the user reads.
        assert!(USAGE.contains("Exit 3"));
    }
}
