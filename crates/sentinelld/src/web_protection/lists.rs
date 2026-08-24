//! Managed DNS blocklists: download, validate and install the lists the
//! web-protection proxy filters with.
//!
//! # Source and license
//!
//! The managed feed is the StevenBlack/hosts "unified hosts" list
//! (adware + malware), <https://github.com/StevenBlack/hosts>, used under
//! the MIT License. The same list is vendored into the installer at
//! `runtime/rules/dns/stevenblack.hosts` (attribution and license text in
//! that file's header, and in NOTICE.md) as the offline seed; this module
//! keeps a separate, refreshed copy under `rules\dns\managed\`.
//!
//! # The failure contract
//!
//! Same rule the rest of `web_protection` runs on: under ANY uncertainty
//! degrade to "no filtering", never "no DNS". Concretely, for this module:
//!
//! - a failed download leaves the previous list in force;
//! - an empty, oversized, truncated or unparseable download is NEVER
//!   installed over a working one;
//! - this module only rewrites files under `rules\dns\managed\` — it
//!   cannot disable filtering, and it never touches the proxy or the NRPT
//!   rule.
//!
//! # Reload
//!
//! A refreshed list takes effect WITHOUT a daemon restart: the update-cycle
//! call site (`ipc::state::start_update`) keys on [`RefreshReport::changed`]
//! and swaps the proxy's whole filter engine through the
//! `Arc<RwLock<FilterEngine>>` the serving loops read per query — see
//! `service.rs::apply_refresh_report`. This module stays pure I/O: it
//! rewrites files and reports what changed; the swap lives with the caller.

use std::io::Read;
use std::path::{Path, PathBuf};

use dnsguard::filter::{FilterEngine, ListKind};
use tracing::{info, warn};

/// The one managed feed. Hosts format, exact-host semantics (Pi-hole
/// style) — the file NAME is what makes `service.rs::load_lists` pick the
/// hosts parser over the domain-list one, so it must keep its `.hosts`
/// extension.
const MANAGED_FEED_URL: &str = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts";
const MANAGED_FEED_NAME: &str = "stevenblack.hosts";

/// Above this, the body cannot be the list. The real file is ~3 MB; an
/// HTML error page, a captive portal or a gzip served as text is either
/// far smaller (caught by "no rules parsed") or unbounded, so the cap only
/// needs to bound what we buffer and parse.
const MAX_LIST_BYTES: u64 = 32 * 1024 * 1024;

/// One update cycle already has a wall-clock budget; the list fetch must
/// not be able to eat a large slice of it waiting on a dead host.
const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Where the refreshed copies live, under the PathManager root
/// (`%ProgramData%\Sentinella` when installed). The full path of the
/// managed feed's copy — what a default config's
/// `web_protection.blocklists` entry should name — is
/// `managed_dir(root).join("stevenblack.hosts")`; there is deliberately
/// no helper for it until the default config exists to call it.
pub fn managed_dir(root: &Path) -> PathBuf {
    root.join("rules").join("dns").join("managed")
}

/// What one refresh cycle did. `changed` keys the live engine swap at the
/// update-cycle call site (`service.rs::apply_refresh_report`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RefreshReport {
    /// A validated new list was installed over (or instead of) the old.
    pub changed: bool,
}

/// Entry point for the daemon's signature-update cycle.
///
/// Never fails the cycle and never reports through the update's
/// success/failure channel: every error is a `warn!` here, because the
/// failure mode of this function is "filtering runs on yesterday's list",
/// which the next cycle retries.
///
/// Returns the report so the caller can swap the refreshed lists into the
/// running proxy on `changed` (`service.rs::apply_refresh_report`); this
/// function itself stays pure fetch-and-install.
pub fn refresh_on_update_cycle() -> RefreshReport {
    let root = crate::paths::paths().root().to_path_buf();
    refresh_managed_lists(&root)
}

/// Refresh every managed feed into `managed_dir(root)`. Failures are
/// logged and skipped per feed: one dead feed must not cost the others.
pub fn refresh_managed_lists(root: &Path) -> RefreshReport {
    let dir = managed_dir(root);
    let mut report = RefreshReport::default();
    match refresh_one(&dir, MANAGED_FEED_NAME, MANAGED_FEED_URL, fetch_https) {
        Ok(true) => {
            report.changed = true;
            info!(feed = MANAGED_FEED_NAME, "web protection: managed blocklist refreshed");
        }
        Ok(false) => {}
        Err(e) => warn!(
            feed = MANAGED_FEED_NAME,
            %e,
            "web protection: blocklist refresh failed — the previous list stays in force"
        ),
    }
    report
}

/// Download, validate and install one feed. `Ok(false)` means the remote
/// content is byte-identical to what is already installed.
///
/// Split from [`refresh_managed_lists`] with the fetch injected so the
/// rejection paths are testable without a network.
fn refresh_one(
    dir: &Path,
    name: &str,
    url: &str,
    fetch: impl FnOnce(&str) -> Result<Vec<u8>, String>,
) -> Result<bool, String> {
    let bytes = fetch(url)?;
    let rules = validate_candidate(&bytes)?;

    let dest = dir.join(name);
    if std::fs::read(&dest).is_ok_and(|current| current == bytes) {
        return Ok(false);
    }
    install_atomic(dir, name, &bytes).map_err(|e| format!("install {}: {e}", dest.display()))?;
    info!(path = %dest.display(), rules, "web protection: blocklist installed");
    Ok(true)
}

/// Is this body fit to replace a working list?
///
/// Returns the parsed rule count. Three rejection reasons, all of which
/// leave the previous file untouched:
///
/// - empty or over the size cap (the size cap is also enforced physically
///   during the download, so this is the belt to its braces);
/// - the parse FAILED (a read error before any rule was added — dnsguard's
///   contract is that `Err` means nothing was applied);
/// - the parse was TRUNCATED or added no rules. A truncated load hit a
///   load budget, so we have not seen the whole file and cannot vouch for
///   it; zero rules means whatever we downloaded is not a blocklist
///   (an error page parses to exactly this).
fn validate_candidate(bytes: &[u8]) -> Result<u64, String> {
    if bytes.is_empty() {
        return Err("download is empty".into());
    }
    if bytes.len() as u64 > MAX_LIST_BYTES {
        return Err(format!(
            "download is {} bytes, over the {}-byte cap",
            bytes.len(),
            MAX_LIST_BYTES
        ));
    }
    // Parse into a THROWAWAY engine: this is validation, not loading. The
    // running proxy's engine is untouched either way.
    let mut engine = FilterEngine::new();
    let stats = engine
        .load_hosts(ListKind::Block, std::io::Cursor::new(bytes))
        .map_err(|e| format!("download does not parse as a hosts file: {e}"))?;
    if stats.truncated {
        return Err(format!(
            "download hit a load budget after {} rules — incomplete, refusing to install",
            stats.rules_added
        ));
    }
    if stats.rules_added == 0 {
        return Err("download contains no usable rules".into());
    }
    Ok(stats.rules_added)
}

/// Write `bytes` to `dir/name` via a temp file in the SAME directory, then
/// rename over the destination.
///
/// The rename is the commit point: the live path is always either the old
/// complete file or the new complete file, never a partially written one.
/// `std::fs::rename` replaces an existing destination (on Windows it maps
/// to `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`), and same-directory
/// renames never degrade into a copy. A reader racing the swap gets one
/// whole file or the other.
fn install_atomic(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    // Per-process temp name: two daemons must not share one staging file,
    // and a stale temp from a killed process is just overwritten.
    let tmp = dir.join(format!("{name}.tmp-{}", std::process::id()));
    std::fs::write(&tmp, bytes)?;
    if let Err(e) = std::fs::rename(&tmp, dir.join(name)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// HTTPS GET with a hard byte ceiling.
///
/// The feed URL is an `https://` compile-time constant, so there is no
/// scheme downgrade to check for; the ceiling is enforced PHYSICALLY with
/// `take` because a `content-length` header is advisory and a chunked
/// response need not send one.
fn fetch_https(url: &str) -> Result<Vec<u8>, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(FETCH_TIMEOUT)
        .user_agent(concat!("sentinella/", env!("CARGO_PKG_VERSION")))
        .build();
    let response = agent.get(url).call().map_err(|e| match e {
        ureq::Error::Status(status, _) => format!("HTTP {status} for {url}"),
        other => format!("HTTP transport error for {url}: {other}"),
    })?;
    if let Some(len) = response
        .header("content-length")
        .and_then(|h| h.parse::<u64>().ok())
        && len > MAX_LIST_BYTES
    {
        return Err(format!("content-length {len} exceeds the {MAX_LIST_BYTES}-byte cap"));
    }
    let mut body = Vec::new();
    response
        .into_reader()
        .take(MAX_LIST_BYTES.saturating_add(1))
        .read_to_end(&mut body)
        .map_err(|e| format!("reading {url}: {e}"))?;
    if body.len() as u64 > MAX_LIST_BYTES {
        return Err(format!("body exceeds the {MAX_LIST_BYTES}-byte cap"));
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The smallest body that is a valid hosts-format blocklist: one rule.
    const GOOD_LIST: &[u8] = b"# a blocklist\n0.0.0.0 ads.example\n0.0.0.0 tracker.example\n";

    fn seed_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sentinella-lists-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_valid_download_is_installed_and_reports_the_rule_count() {
        let dir = seed_dir();
        let rules = validate_candidate(GOOD_LIST).unwrap();
        assert_eq!(rules, 2);
        install_atomic(&dir, "feed.hosts", GOOD_LIST).unwrap();
        assert_eq!(std::fs::read(dir.join("feed.hosts")).unwrap(), GOOD_LIST);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// THE core safety property: nothing bad may ever replace a working
    /// list. A 0-byte body (a truncated transfer that ended cleanly at the
    /// HTTP layer) and an unparseable one (an error page — HTML produces
    /// zero hosts rules) are both rejected, and the file on disk is still
    /// byte-identical to the previous good list afterwards.
    #[test]
    fn an_empty_or_unparseable_download_never_replaces_the_previous_list() {
        let dir = seed_dir();
        install_atomic(&dir, MANAGED_FEED_NAME, GOOD_LIST).unwrap();

        for bad in [
            &b""[..],
            b"<html><body>502 Bad Gateway</body></html>",
            b"\x00\x01\x02 not a hosts file at all",
        ] {
            let report = refresh_one(&dir, MANAGED_FEED_NAME, "https://unused", |_| {
                Ok(bad.to_vec())
            });
            assert!(report.is_err(), "must reject: {bad:?}");
            assert_eq!(
                std::fs::read(dir.join(MANAGED_FEED_NAME)).unwrap(),
                GOOD_LIST,
                "the previous list must survive a rejected download"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A failed FETCH leaves the previous list in force — the transport
    /// error path, distinct from the validation path above.
    #[test]
    fn a_failed_download_leaves_the_previous_list_in_force() {
        let dir = seed_dir();
        install_atomic(&dir, MANAGED_FEED_NAME, GOOD_LIST).unwrap();

        let report = refresh_one(&dir, MANAGED_FEED_NAME, "https://unused", |_| {
            Err("HTTP transport error: connection refused".into())
        });
        assert!(report.is_err());
        assert_eq!(std::fs::read(dir.join(MANAGED_FEED_NAME)).unwrap(), GOOD_LIST);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Re-downloading identical content must not churn the file (and must
    /// report "unchanged", so a future reload signal is not fired for
    /// nothing).
    #[test]
    fn identical_content_is_not_reinstalled() {
        let dir = seed_dir();
        let changed = refresh_one(&dir, MANAGED_FEED_NAME, "https://unused", |_| {
            Ok(GOOD_LIST.to_vec())
        })
        .unwrap();
        assert!(changed, "first install is a change");
        let changed = refresh_one(&dir, MANAGED_FEED_NAME, "https://unused", |_| {
            Ok(GOOD_LIST.to_vec())
        })
        .unwrap();
        assert!(!changed, "same bytes again is not a change");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A NEW valid list replaces the old one atomically — the other half
    /// of the contract, or the fetcher would be a no-op that only ever
    /// keeps the seed.
    #[test]
    fn a_new_valid_list_replaces_the_old_one() {
        let dir = seed_dir();
        install_atomic(&dir, MANAGED_FEED_NAME, GOOD_LIST).unwrap();
        let new_list = b"0.0.0.0 new-bad.example\n";
        let changed = refresh_one(&dir, MANAGED_FEED_NAME, "https://unused", |_| {
            Ok(new_list.to_vec())
        })
        .unwrap();
        assert!(changed);
        assert_eq!(std::fs::read(dir.join(MANAGED_FEED_NAME)).unwrap(), new_list);
        // The staging file must not be left behind.
        assert!(
            std::fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .all(|e| e.file_name() == MANAGED_FEED_NAME),
            "temp staging file leaked"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validation_rejects_oversize_without_parsing() {
        // A body over the cap whose CONTENT IS VALID (two good rules, then
        // padding comments): if the size check went away, this would parse
        // with rules_added > 0 and be ACCEPTED — so the test only passes
        // while the cap is really enforced. The padding lines are long on
        // purpose: enough of them to exceed the byte cap must still stay
        // under dnsguard's 2M-line budget, or the load would be TRUNCATED
        // and rejected for that reason instead of proving the size check.
        let mut big = Vec::new();
        big.extend_from_slice(GOOD_LIST);
        while big.len() as u64 <= MAX_LIST_BYTES {
            big.extend_from_slice(b"# padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding padding\n");
        }
        assert!(validate_candidate(&big).is_err());
    }

    /// The managed file name must keep its `.hosts` extension: that
    /// suffix is what `service.rs::load_lists` matches on to choose the
    /// hosts parser. Renaming the file to `.txt` would silently route it
    /// through the domain-list parser, where every hosts line is rejected.
    #[test]
    fn the_managed_feed_name_selects_the_hosts_parser() {
        assert!(MANAGED_FEED_NAME.ends_with(".hosts"));
        assert!(MANAGED_FEED_URL.starts_with("https://"));
    }

    /// The vendored starter list is release content: it must parse through
    /// the SAME validation the fetcher applies to downloads, or the
    /// installer would ship a seed that loads as zero rules — serving with
    /// no filtering behind it.
    #[test]
    fn the_vendored_starter_list_passes_fetch_validation() {
        let vendored = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../runtime/rules/dns/stevenblack.hosts");
        let bytes = std::fs::read(&vendored)
            .unwrap_or_else(|e| panic!("vendored blocklist missing at {}: {e}", vendored.display()));
        let rules = validate_candidate(&bytes).unwrap();
        // StevenBlack unified runs ~100k hosts; an order-of-magnitude floor
        // catches a silently truncated or stub replacement.
        assert!(rules > 10_000, "vendored list parsed only {rules} rules");
    }

    #[test]
    fn managed_paths_stay_under_the_root() {
        let root = Path::new("C:\\ProgramData\\Sentinella");
        let p = managed_dir(root);
        assert!(p.starts_with(root));
        assert_eq!(p, root.join("rules").join("dns").join("managed"));
    }
}
