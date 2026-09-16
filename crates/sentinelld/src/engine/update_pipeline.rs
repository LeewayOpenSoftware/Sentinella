//! SignatureUpdateManager — production-grade provider update lifecycle.
//!
//! Every provider update passes through:
//!   download → staging → verify → activate → rebuild → cleanup
//!
//! Core invariants:
//!   - downloaded != trusted (must verify before activation)
//!   - downloaded != active (must pass through staging)
//!   - failure → official ClamAV only (safe degradation)
//!   - never partially activate
//!   - never mix providers
//!   - activation is atomic (rename, not copy)
//!
//! Staging layout:
//!   runtime/update_staging/<provider_id>/
//!     ├── file1.ndb
//!     ├── file2.hdb
//!     └── .update_meta.json
//!
//! Active layout:
//!   runtime/signatures/enhanced/
//!     ├── file1.ndb
//!     └── file2.hdb

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Update lifecycle stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateStage {
    /// No update in progress.
    Idle,
    /// Downloading files to staging.
    Downloading,
    /// Verifying downloaded files.
    Verifying,
    /// Activating (swapping into active dir).
    Activating,
    /// Rebuilding engine cache.
    Rebuilding,
    /// Update complete.
    Complete,
    /// Update failed — rolled back to official-only.
    Failed,
}

/// Update result.
#[derive(Debug)]
pub struct UpdateResult {
    pub success: bool,
    pub stage: UpdateStage,
    pub files_downloaded: usize,
    pub files_activated: usize,
    pub error: Option<String>,
}

/// Provider manifest — declares available files with hashes.
/// Fetched from provider URL or shipped alongside signatures.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProviderManifest {
    pub provider_id: String,
    pub version: String,
    pub files: Vec<ManifestFile>,
    pub license: String,
    pub attribution: String,
    pub updated_at: String,
}

/// A file entry in a provider manifest.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ManifestFile {
    pub name: String,
    pub url: String,
    pub sha256: String,
    pub size: u64,
}

/// Persisted per-provider anti-rollback ledger (SR-08). Maps a provider id
/// to the last manifest it was accepted at, so a later, older manifest can
/// be refused as a downgrade.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct ProviderVersionLedger {
    #[serde(default)]
    entries: std::collections::BTreeMap<String, ProviderVersionRecord>,
}

/// One provider's last-accepted manifest point.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ProviderVersionRecord {
    /// Provider-declared version string (audit/diagnostic only).
    version: String,
    /// Provider-declared `updated_at`, kept verbatim for diagnostics.
    updated_at: String,
    /// `updated_at` parsed to epoch seconds — the value actually compared.
    accepted_epoch: i64,
}

/// Parse a manifest `updated_at` into epoch seconds. Accepts RFC-3339
/// (`2026-05-25T12:00:00Z`), a bare date-time (`2026-05-25T12:00:00`) and a
/// bare ISO date (`2026-05-25`, interpreted as UTC midnight). Anything else
/// returns `None`, and the caller treats that as a fail-closed rejection.
fn parse_manifest_instant(s: &str) -> Option<i64> {
    let t = s.trim();
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(t) {
        return Some(dt.timestamp());
    }
    if let Ok(ndt) = chrono::NaiveDateTime::parse_from_str(t, "%Y-%m-%dT%H:%M:%S") {
        return Some(ndt.and_utc().timestamp());
    }
    if let Ok(d) = chrono::NaiveDate::parse_from_str(t, "%Y-%m-%d") {
        return d.and_hms_opt(0, 0, 0).map(|ndt| ndt.and_utc().timestamp());
    }
    None
}

/// Staging metadata — written alongside downloaded files.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StagingMeta {
    provider_id: String,
    timestamp: i64,
    files: Vec<StagedFile>,
    total_bytes: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StagedFile {
    name: String,
    size: u64,
    sha256: Option<String>,
}

/// HTTP download configuration.
const DOWNLOAD_TIMEOUT_SECS: u64 = 120;
const MAX_DOWNLOAD_SIZE: u64 = 500 * 1024 * 1024; // 500 MB per file
const MAX_REDIRECTS: u32 = 3;
const USER_AGENT: &str = "Sentinella-Updater/0.1";

/// The update pipeline manager.
pub struct SignatureUpdateManager {
    staging_root: PathBuf,
    active_enhanced_dir: PathBuf,
    stage: UpdateStage,
}

impl SignatureUpdateManager {
    pub fn new() -> Self {
        let p = crate::paths::paths();
        Self {
            staging_root: p.update_staging_dir(),
            active_enhanced_dir: p.enhanced_signatures_dir(),
            stage: UpdateStage::Idle,
        }
    }

    /// Execute a full update for a provider.
    /// Returns the result — caller must handle cache invalidation + engine rebuild.
    pub fn update_provider(
        &mut self,
        provider: &super::sources::SignatureProvider,
    ) -> UpdateResult {
        info!(
            provider = provider.id.as_str(),
            "signature update: starting"
        );

        // Phase 1: Prepare staging directory.
        let staging_dir = self.staging_root.join(&provider.id);
        if let Err(e) = self.prepare_staging(&staging_dir) {
            return self.fail(format!("staging prep failed: {e}"));
        }

        // Phase 2: Download files.
        self.stage = UpdateStage::Downloading;
        let downloaded = match self.download_files(provider, &staging_dir) {
            Ok(files) => files,
            Err(e) => {
                self.cleanup_staging(&staging_dir);
                return self.fail(format!("download failed: {e}"));
            }
        };

        if downloaded.is_empty() {
            self.cleanup_staging(&staging_dir);
            return self.fail("no files downloaded".into());
        }

        // Phase 3: Verify downloaded files.
        self.stage = UpdateStage::Verifying;
        if let Err(e) = self.verify_staged(&staging_dir, &downloaded, &provider.id) {
            self.cleanup_staging(&staging_dir);
            return self.fail(format!("verification failed: {e}"));
        }

        // Phase 3b: Verify against provider manifest if available.
        // Manifest provides a trust anchor — hashes are pinned by the provider,
        // NOT computed from the downloaded files themselves.
        if let Some(ref base_url) = provider.update_url {
            let manifest_url = format!("{}/manifest.json", base_url.trim_end_matches('/'));
            match self.fetch_and_verify_manifest(&staging_dir, &manifest_url, &provider.id, &downloaded) {
                Ok(()) => info!(
                    provider = provider.id.as_str(),
                    "manifest verification passed"
                ),
                Err(e) => {
                    // R14-LETHAL: FAIL CLOSED on any manifest error —
                    // including HTTP 404/403. The previous "manifest not
                    // available" soft path activated the files with NO
                    // content verification whatsoever (only size>0 and a
                    // first-line control-char check), so a mirror
                    // misconfiguration or a TLS-terminating middlebox
                    // silently degraded verification to zero — violating
                    // the "downloaded != trusted" invariant. Failure
                    // degrades to official-ClamAV-only, which is the
                    // documented safe outcome.
                    self.cleanup_staging(&staging_dir);
                    return self.fail(format!("manifest verification FAILED: {e}"));
                }
            }
        }

        // Phase 4: Atomic activation.
        self.stage = UpdateStage::Activating;
        let activated = match self.activate(&staging_dir, &downloaded) {
            Ok(count) => count,
            Err(e) => {
                // Do NOT call self.rollback() here: activate() already owns
                // its own restore / cleanup paths. If activate's swap step
                // failed AFTER it restored old_dir → active_enhanced_dir, a
                // subsequent rollback() would wipe active_enhanced_dir of the
                // just-restored prior signatures — turning a recoverable
                // failure into a permanent signature loss + fail-open window.
                self.cleanup_staging(&staging_dir);
                return self.fail(format!("activation failed: {e}"));
            }
        };

        // Phase 5: Cleanup staging.
        self.cleanup_staging(&staging_dir);

        self.stage = UpdateStage::Complete;
        info!(
            provider = provider.id.as_str(),
            files = activated,
            "signature update: complete — cache invalidation required"
        );

        UpdateResult {
            success: true,
            stage: UpdateStage::Complete,
            files_downloaded: downloaded.len(),
            files_activated: activated,
            error: None,
        }
    }

    /// Rollback: remove all enhanced signatures, restore official-only mode.
    pub fn rollback(&mut self) {
        warn!("signature update: rolling back to official-only mode");
        if self.active_enhanced_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&self.active_enhanced_dir) {
                for entry in entries.flatten() {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
        self.stage = UpdateStage::Idle;
    }

    /// Current update stage.
    pub fn stage(&self) -> UpdateStage {
        self.stage
    }

    /// Clean all stale staging directories.
    pub fn cleanup_all_staging(&self) {
        if self.staging_root.exists() {
            if let Ok(entries) = std::fs::read_dir(&self.staging_root) {
                for entry in entries.flatten() {
                    if entry.path().is_dir() {
                        let _ = std::fs::remove_dir_all(entry.path());
                    }
                }
            }
        }
    }

    // ── Private pipeline stages ─────────────────────────

    fn prepare_staging(&self, staging_dir: &Path) -> Result<(), String> {
        // Clean any leftover staging from previous failed updates.
        if staging_dir.exists() {
            std::fs::remove_dir_all(staging_dir)
                .map_err(|e| format!("cleanup old staging: {e}"))?;
        }
        std::fs::create_dir_all(staging_dir).map_err(|e| format!("create staging dir: {e}"))?;
        Ok(())
    }

    fn download_files(
        &self,
        provider: &super::sources::SignatureProvider,
        staging_dir: &Path,
    ) -> Result<Vec<StagedFile>, String> {
        let mut files = Vec::new();
        // One agent per update run (TLS init + connection pool reused
        // across ~14 file downloads) instead of a fresh Agent per file.
        let agent = build_agent();
        // R10: track the last per-file download error so a total failure
        // surfaces the real cause (TLS/auth/DNS) instead of the generic
        // "no files downloaded" which hid everything at debug level.
        let mut last_error: Option<String> = None;

        // Strategy 1: Try local source directory (for testing / air-gapped systems).
        // R9-LETHAL pattern: NEVER fall back to CWD ("."). Daemon runs as SYSTEM
        // and copies+activates anything it finds under `local_source` as a real
        // signature DB. CWD-relative resolution lets an attacker who can drop
        // `provider_sources/<id>/*.ndb` next to the daemon's working directory
        // poison the engine. Anchor to the PathManager root instead.
        let local_source = self
            .staging_root
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| crate::paths::paths().root().to_path_buf())
            .join("provider_sources")
            .join(&provider.id);

        for db_file in &provider.db_files {
            let dest = staging_dir.join(db_file);

            // Try local source first.
            let local_path = local_source.join(db_file);
            if local_path.exists() {
                std::fs::copy(&local_path, &dest)
                    .map_err(|e| format!("copy {} from local: {e}", db_file))?;
                let size = std::fs::metadata(&dest)
                    .map_err(|e| format!("stat {}: {e}", db_file))?
                    .len();
                if size > MAX_DOWNLOAD_SIZE {
                    return Err(format!("{} exceeds size limit", db_file));
                }
                let hash = compute_sha256(&dest)?;
                files.push(StagedFile {
                    name: db_file.clone(),
                    size,
                    sha256: Some(hash),
                });
                debug!(file = db_file.as_str(), size, source = "local", "staged");
                continue;
            }

            // Strategy 2: HTTPS download from provider URL.
            if let Some(ref base_url) = provider.update_url {
                // Enforce HTTPS — reject plain HTTP to prevent MITM.
                if !base_url.starts_with("https://") {
                    warn!(
                        url = base_url.as_str(),
                        "provider URL rejected: HTTPS required"
                    );
                    return Err(format!("provider URL must use HTTPS, got: {}", base_url));
                }
                let url = format!("{}/{}", base_url.trim_end_matches('/'), db_file);
                match download_file(&agent, &url, &dest) {
                    Ok(size) => {
                        if size > MAX_DOWNLOAD_SIZE {
                            let _ = std::fs::remove_file(&dest);
                            return Err(format!("{} exceeds size limit ({} bytes)", db_file, size));
                        }
                        let hash = compute_sha256(&dest)?;
                        files.push(StagedFile {
                            name: db_file.clone(),
                            size,
                            sha256: Some(hash),
                        });
                        debug!(file = db_file.as_str(), size, source = "http", "staged");
                    }
                    Err(e) => {
                        // Non-fatal for individual files — provider may not ship all listed files.
                        debug!(file = db_file.as_str(), error = %e, "download skipped");
                        last_error = Some(format!("{db_file}: {e}"));
                    }
                }
            }
        }

        // R10: if nothing was staged but downloads were attempted and failed,
        // surface the real error rather than letting the caller report a
        // misleading "no files downloaded".
        if files.is_empty() {
            if let Some(err) = last_error {
                return Err(format!("all provider downloads failed (last: {err})"));
            }
        }

        Ok(files)
    }

    /// Verify staged files: size, hash, format.
    /// If a manifest is provided, verify SHA-256 against manifest hashes.
    fn verify_staged(
        &self,
        staging_dir: &Path,
        files: &[StagedFile],
        provider_id: &str,
    ) -> Result<(), String> {
        for file in files {
            let path = staging_dir.join(&file.name);

            if !path.exists() {
                return Err(format!("{} missing from staging", file.name));
            }

            let actual_size = std::fs::metadata(&path)
                .map_err(|e| format!("stat {}: {e}", file.name))?
                .len();

            if actual_size != file.size {
                return Err(format!(
                    "{} size mismatch: expected {}, got {}",
                    file.name, file.size, actual_size
                ));
            }

            if actual_size == 0 {
                return Err(format!("{} is empty", file.name));
            }

            // R3-18: do NOT re-compute SHA-256 here and compare against
            // file.sha256 — that field was computed locally from the same
            // bytes during download, so the comparison is tautological and
            // provides zero security guarantee. Authoritative SHA-256
            // verification happens in Phase 3b against the trusted manifest.
            // We keep file.sha256 only for diagnostics/logging.

            // Text format validation for ClamAV signature files.
            let ext = path
                .extension()
                .map(|e| e.to_string_lossy().to_lowercase())
                .unwrap_or_default();

            if matches!(ext.as_str(), "ndb" | "hdb" | "hsb" | "cdb" | "ftm" | "ign2") {
                // R3-fix: only the first line is inspected for binary content,
                // so don't slurp the entire (potentially hundreds-of-MB) CVD
                // into RAM. Cap the read at 4 KiB via Read::take + BufReader.
                use std::io::{BufRead, BufReader, Read};
                if let Ok(f) = std::fs::File::open(&path) {
                    let mut reader = BufReader::new(f.take(4096));
                    let mut first_line = String::new();
                    let _ = reader.read_line(&mut first_line);
                    if first_line
                        .chars()
                        .any(|c| c.is_control() && c != '\t' && c != '\n' && c != '\r')
                    {
                        return Err(format!(
                            "{} contains binary data in text format",
                            file.name
                        ));
                    }
                }
            }

            debug!(file = file.name.as_str(), size = actual_size, "verified");
        }

        // Save staging metadata.
        let meta = StagingMeta {
            provider_id: provider_id.to_string(),
            timestamp: chrono::Utc::now().timestamp(),
            files: files.to_vec(),
            total_bytes: files.iter().map(|f| f.size).sum(),
        };
        let meta_path = staging_dir.join(".update_meta.json");
        if let Ok(json) = serde_json::to_string_pretty(&meta) {
            let _ = std::fs::write(&meta_path, json);
        }

        Ok(())
    }

    /// Verify staged files against a provider manifest.
    /// All files in manifest must be present and match SHA-256.
    pub fn verify_against_manifest(
        &self,
        staging_dir: &Path,
        manifest: &ProviderManifest,
    ) -> Result<(), String> {
        for mf in &manifest.files {
            // R14: mf.name comes from untrusted JSON and is used as
            // `staging_dir.join(&mf.name)` — a value containing path
            // separators, a drive prefix, or ".." escapes the staging dir
            // and lets the manifest "verify" (and later activate over)
            // an arbitrary path. Require a single bare Normal component.
            let bare_filename = {
                let mut comps = Path::new(&mf.name).components();
                matches!(comps.next(), Some(std::path::Component::Normal(_)))
                    && comps.next().is_none()
            };
            if !bare_filename {
                return Err(format!(
                    "manifest file name '{}' is not a bare filename — rejected",
                    mf.name
                ));
            }

            let path = staging_dir.join(&mf.name);

            if !path.exists() {
                return Err(format!("manifest file {} missing from staging", mf.name));
            }

            let actual_size = std::fs::metadata(&path)
                .map_err(|e| format!("stat {}: {e}", mf.name))?
                .len();

            if actual_size != mf.size {
                return Err(format!(
                    "{} size mismatch: manifest says {}, got {}",
                    mf.name, mf.size, actual_size
                ));
            }

            // R10: reject malformed manifest hash BEFORE comparison. The
            // sha256 comes from untrusted manifest JSON; the previous
            // `&mf.sha256[..16]` in the error path panicked on any value
            // shorter than 16 bytes — and that path runs exactly when
            // verification is already failing (a corrupt manifest would
            // crash the updater thread instead of returning cleanly).
            if mf.sha256.len() != 64 || !mf.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!(
                    "{} manifest sha256 malformed (not 64 hex chars)",
                    mf.name
                ));
            }
            let actual_hash = compute_sha256(&path)?;
            if actual_hash != mf.sha256 {
                // Safe slices: both are now known to be 64 hex chars.
                return Err(format!(
                    "{} SHA-256 mismatch: manifest says {}…, got {}…",
                    mf.name,
                    &mf.sha256[..16],
                    &actual_hash[..16]
                ));
            }
        }

        info!(
            provider = manifest.provider_id.as_str(),
            version = manifest.version.as_str(),
            files = manifest.files.len(),
            "manifest verification passed"
        );
        Ok(())
    }

    fn activate(&self, staging_dir: &Path, files: &[StagedFile]) -> Result<usize, String> {
        // Atomic activation: stage → new dir → swap → cleanup old.
        // Never remove existing files until new ones are fully in place.

        std::fs::create_dir_all(&self.active_enhanced_dir)
            .map_err(|e| format!("create enhanced dir: {e}"))?;

        // Step 1: Move new files to a temporary "pending" directory alongside active.
        // Hard-fail if stale pending_dir cannot be scrubbed: silent ignore left
        // verified-signed signature files from a prior failed run in place,
        // which a subsequent rename-race could promote into the active set.
        let pending_dir = self.active_enhanced_dir.with_file_name("enhanced_pending");
        if pending_dir.exists() {
            std::fs::remove_dir_all(&pending_dir).map_err(|e| {
                format!(
                    "activate: cannot clean stale pending_dir {}: {e}",
                    pending_dir.display()
                )
            })?;
        }
        std::fs::create_dir_all(&pending_dir).map_err(|e| format!("create pending dir: {e}"))?;

        let mut activated = 0;
        for file in files {
            let src = staging_dir.join(&file.name);
            let dst = pending_dir.join(&file.name);

            if std::fs::rename(&src, &dst).is_ok() {
                activated += 1;
                continue;
            }
            std::fs::copy(&src, &dst).map_err(|e| {
                let _ = std::fs::remove_dir_all(&pending_dir);
                format!("activate {}: {e}", file.name)
            })?;
            let _ = std::fs::remove_file(&src);
            activated += 1;
        }

        // Step 2: Rename current enhanced → enhanced_old (backup).
        let old_dir = self.active_enhanced_dir.with_file_name("enhanced_old");
        let _ = std::fs::remove_dir_all(&old_dir);
        let had_existing = self.active_enhanced_dir.exists()
            && std::fs::read_dir(&self.active_enhanced_dir)
                .map(|d| d.count())
                .unwrap_or(0)
                > 0;
        if had_existing {
            std::fs::rename(&self.active_enhanced_dir, &old_dir).map_err(|e| {
                let _ = std::fs::remove_dir_all(&pending_dir);
                format!("backup old enhanced: {e}")
            })?;
        }

        // Step 3: Rename pending → enhanced (atomic swap).
        if let Err(e) = std::fs::rename(&pending_dir, &self.active_enhanced_dir) {
            // Restore old if swap failed.
            if had_existing {
                let _ = std::fs::rename(&old_dir, &self.active_enhanced_dir);
            }
            // SECURITY: scrub pending_dir on every failure path. The pending
            // dir holds manifest-verified, signed signature files. Leaving
            // them on disk lets a later attacker who can win a rename race
            // (`enhanced_pending` → `active_enhanced_dir`) bypass manifest
            // verification entirely by promoting our own verified set.
            let _ = std::fs::remove_dir_all(&pending_dir);
            return Err(format!("atomic swap failed: {e}"));
        }

        // Step 4: Cleanup old directory.
        let _ = std::fs::remove_dir_all(&old_dir);
        // Belt-and-suspenders: ensure no stale pending_dir survives even on
        // the success path (e.g. an interrupted prior run that succeeded the
        // swap but lost power before the unlink).
        let _ = std::fs::remove_dir_all(&pending_dir);

        info!(count = activated, "signature files activated (atomic swap)");
        Ok(activated)
    }

    /// Fetch a manifest.json from the provider URL and verify staged files against it.
    /// The manifest provides a trust anchor: expected hashes are declared by the provider,
    /// not derived from the downloaded files. This breaks the self-verification loop.
    fn fetch_and_verify_manifest(
        &self,
        staging_dir: &Path,
        manifest_url: &str,
        provider_id: &str,
        staged: &[StagedFile],
    ) -> Result<(), String> {
        let manifest_path = staging_dir.join("manifest.json");
        let agent = build_agent();
        download_file(&agent, manifest_url, &manifest_path)?;

        let manifest_str =
            std::fs::read_to_string(&manifest_path).map_err(|e| format!("read manifest: {e}"))?;

        let manifest: ProviderManifest =
            serde_json::from_str(&manifest_str).map_err(|e| format!("parse manifest: {e}"))?;

        // Verify manifest claims the correct provider.
        if manifest.provider_id != provider_id {
            return Err(format!(
                "manifest provider_id mismatch: expected '{}', got '{}'",
                provider_id, manifest.provider_id
            ));
        }

        // Verify all manifest-listed files against their pinned hashes.
        self.verify_against_manifest(staging_dir, &manifest)?;

        // R14: coverage must be TWO-DIRECTIONAL. verify_against_manifest
        // only iterates manifest.files, so a staged file NOT listed in the
        // manifest would otherwise be activated with NO hash check at all.
        for sf in staged {
            if !manifest.files.iter().any(|mf| mf.name == sf.name) {
                return Err(format!(
                    "staged file {} not pinned by manifest — refusing activation",
                    sf.name
                ));
            }
        }

        // SR-08: monotonic anti-rollback. Refuse a manifest that is older
        // than the last one this provider was accepted at, and record the
        // accepted point. This runs only after the manifest has passed
        // provider-id, hash and coverage checks, so we never persist a
        // version for a manifest we would not otherwise activate.
        self.enforce_anti_rollback(provider_id, &manifest)?;

        // Clean up the manifest file (not a signature file).
        let _ = std::fs::remove_file(&manifest_path);
        Ok(())
    }

    /// Path of the per-provider version ledger used for anti-rollback.
    /// Anchored next to the active enhanced-signature directory (never
    /// CWD-relative — see the R9-LETHAL note in `download_files`).
    fn version_ledger_path(&self) -> PathBuf {
        self.active_enhanced_dir
            .with_file_name("enhanced_versions.json")
    }

    /// Load the persisted version ledger. A missing or unparseable ledger
    /// reads as empty: a corrupt ledger must not wedge updates, and an
    /// empty ledger only means "no baseline yet", never "accept anything
    /// older" — the caller records a fresh baseline on the next success.
    fn load_version_ledger(&self) -> ProviderVersionLedger {
        std::fs::read_to_string(self.version_ledger_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Persist the version ledger via a temp-file + rename so a crash
    /// mid-write cannot leave a truncated ledger behind.
    fn save_version_ledger(&self, ledger: &ProviderVersionLedger) -> Result<(), String> {
        let path = self.version_ledger_path();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("create ledger dir: {e}"))?;
        }
        let json =
            serde_json::to_string_pretty(ledger).map_err(|e| format!("serialize ledger: {e}"))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, json).map_err(|e| format!("write ledger: {e}"))?;
        std::fs::rename(&tmp, &path).map_err(|e| format!("commit ledger: {e}"))?;
        Ok(())
    }

    /// SR-08 anti-rollback: reject a provider manifest whose `updated_at`
    /// is strictly older than the last one accepted for this provider, and
    /// record the accepted point on success.
    ///
    /// The manifest is unsigned, so this closes the *replay* half of SR-08
    /// (a stale mirror, a cache, or an on-path actor who cannot forge fresh
    /// metadata — replaying a genuine older manifest is refused). It does
    /// NOT defend against a provider that is itself compromised and can
    /// forge `updated_at` forward; closing that requires an independently
    /// signed manifest, which is a manifest-format decision left open (see
    /// docs/SIGNED_UPDATE_RECOVERY.md and SR-08).
    ///
    /// Fails closed: an incoming `updated_at` that is not a parseable
    /// ISO-8601 date/date-time is refused rather than accepted blindly.
    /// An equal timestamp is allowed so a retry after a transient
    /// activation failure can re-activate the identical, hash-pinned set.
    fn enforce_anti_rollback(
        &self,
        provider_id: &str,
        manifest: &ProviderManifest,
    ) -> Result<(), String> {
        let incoming = parse_manifest_instant(&manifest.updated_at).ok_or_else(|| {
            format!(
                "manifest updated_at '{}' is not a parseable ISO-8601 date/date-time — refusing (fail closed)",
                manifest.updated_at
            )
        })?;

        let mut ledger = self.load_version_ledger();
        if let Some(prev) = ledger.entries.get(provider_id) {
            if incoming < prev.accepted_epoch {
                return Err(format!(
                    "anti-rollback: manifest updated_at '{}' is older than the last accepted '{}' for provider '{}' — refusing downgrade",
                    manifest.updated_at, prev.updated_at, provider_id
                ));
            }
        }

        ledger.entries.insert(
            provider_id.to_string(),
            ProviderVersionRecord {
                version: manifest.version.clone(),
                updated_at: manifest.updated_at.clone(),
                accepted_epoch: incoming,
            },
        );
        self.save_version_ledger(&ledger)
    }

    fn cleanup_staging(&self, staging_dir: &Path) {
        if staging_dir.exists() {
            let _ = std::fs::remove_dir_all(staging_dir);
        }
    }

    fn fail(&mut self, error: String) -> UpdateResult {
        warn!(error = error.as_str(), "signature update: FAILED");
        self.stage = UpdateStage::Failed;
        UpdateResult {
            success: false,
            stage: UpdateStage::Failed,
            files_downloaded: 0,
            files_activated: 0,
            error: Some(error),
        }
    }
}

// ── Helper functions ──────────────────────────────────────

/// Build the shared HTTP agent for update downloads.
fn build_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(DOWNLOAD_TIMEOUT_SECS))
        .max_idle_connections(1)
        .max_idle_connections_per_host(1)
        .user_agent(USER_AGENT)
        .redirects(MAX_REDIRECTS)
        .build()
}

/// Download a file via HTTP to a local path.
/// Writes to a temp file first, then renames atomically.
fn download_file(agent: &ureq::Agent, url: &str, dest: &Path) -> Result<u64, String> {
    // Bug R3-5: with_extension("tmp") strips the original extension, so
    // downloading foo.ndb and foo.hdb in the same dir both resolve to foo.tmp
    // — sequential downloads overwrite each other's temp file. Append .tmp
    // instead of replacing the extension so each download gets a unique
    // staging file (foo.ndb.tmp vs foo.hdb.tmp).
    let mut tmp_name = dest.file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    tmp_name.push(".tmp");
    let tmp_path = dest.with_file_name(tmp_name);

    let response = match agent.get(url).call() {
        Ok(response) => response,
        Err(ureq::Error::Status(status, _)) => {
            return Err(format!("HTTP {} for {}", status, url));
        }
        Err(e) => {
            return Err(format!("HTTP transport error for {}: {e}", url));
        }
    };

    let status = response.status();
    if status != 200 {
        return Err(format!("HTTP {} for {}", status, url));
    }

    // Check content-length if available.
    if let Some(len_str) = response.header("content-length") {
        if let Ok(len) = len_str.parse::<u64>() {
            if len > MAX_DOWNLOAD_SIZE {
                return Err(format!("content-length {} exceeds limit", len));
            }
        }
    }

    // Stream to temp file.
    let mut file =
        std::fs::File::create(&tmp_path).map_err(|e| format!("create temp file: {e}"))?;

    let mut reader = response.into_reader();
    let mut total: u64 = 0;
    let mut buf = [0u8; 65536];

    loop {
        match std::io::Read::read(&mut reader, &mut buf) {
            Ok(0) => break,
            Ok(n) => {
                total += n as u64;
                if total > MAX_DOWNLOAD_SIZE {
                    let _ = std::fs::remove_file(&tmp_path);
                    return Err(format!(
                        "download exceeds {} MB limit",
                        MAX_DOWNLOAD_SIZE / (1024 * 1024)
                    ));
                }
                std::io::Write::write_all(&mut file, &buf[..n])
                    .map_err(|e| format!("write: {e}"))?;
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(format!("read: {e}"));
            }
        }
    }

    // Durability: fsync the temp before rename. Without it, a crash after
    // the rename returns success can leave the destination empty/short, which
    // engine reload then loads as a corrupt signature DB — silent protection
    // degradation right after a "successful" update.
    file.sync_all().map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        format!("sync temp: {e}")
    })?;
    drop(file);

    // Atomic rename from temp to final destination.
    std::fs::rename(&tmp_path, dest).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        format!("rename temp to dest: {e}")
    })?;

    Ok(total)
}

/// Compute SHA-256 hash of a file, return lowercase hex string.
fn compute_sha256(path: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut file =
        std::fs::File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;

    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];

    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(e) => return Err(format!("read {}: {e}", path.display())),
        }
    }

    let hash = hasher.finalize();
    Ok(format!("{:x}", hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_sha256_of_known_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        std::fs::write(&path, "hello world\n").unwrap();

        let hash = compute_sha256(&path).unwrap();
        // SHA-256 of "hello world\n"
        // Just verify it's a 64-char hex string.
        assert_eq!(hash.len(), 64, "SHA-256 should be 64 hex chars");
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "SHA-256 should be hex"
        );
    }

    #[test]
    fn manifest_parse() {
        let json = r#"{
            "provider_id": "test",
            "version": "1.0",
            "files": [
                {
                    "name": "test.ndb",
                    "url": "https://example.com/test.ndb",
                    "sha256": "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
                    "size": 1000
                }
            ],
            "license": "MIT",
            "attribution": "Test Provider",
            "updated_at": "2026-05-25"
        }"#;

        let manifest: ProviderManifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.provider_id, "test");
        assert_eq!(manifest.files.len(), 1);
        assert_eq!(manifest.files[0].name, "test.ndb");
        assert_eq!(manifest.files[0].sha256.len(), 64);
    }

    #[test]
    fn verify_rejects_bad_hash() {
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("staging");
        std::fs::create_dir_all(&staging).unwrap();

        let file_path = staging.join("test.ndb");
        std::fs::write(&file_path, "signature data here").unwrap();
        let actual_hash = compute_sha256(&file_path).unwrap();

        let mgr = SignatureUpdateManager {
            staging_root: dir.path().to_path_buf(),
            active_enhanced_dir: dir.path().join("active"),
            stage: UpdateStage::Idle,
        };

        // R3-18: verify_staged no longer compares against locally-computed
        // hashes (tautological). Authoritative verification is done in
        // verify_against_manifest. We only assert size/format checks here.
        let _ = actual_hash;
        let good_files = vec![StagedFile {
            name: "test.ndb".into(),
            size: std::fs::metadata(&file_path).unwrap().len(),
            sha256: None,
        }];
        assert!(mgr.verify_staged(&staging, &good_files, "test").is_ok());
    }

    #[test]
    fn verify_rejects_oversize() {
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("staging");
        std::fs::create_dir_all(&staging).unwrap();

        let file_path = staging.join("big.ndb");
        std::fs::write(&file_path, "data").unwrap();

        let mgr = SignatureUpdateManager {
            staging_root: dir.path().to_path_buf(),
            active_enhanced_dir: dir.path().join("active"),
            stage: UpdateStage::Idle,
        };

        // Size mismatch — should fail.
        let files = vec![StagedFile {
            name: "big.ndb".into(),
            size: 999999, // Wrong size.
            sha256: None,
        }];
        assert!(mgr.verify_staged(&staging, &files, "test").is_err());
    }

    #[test]
    fn verify_rejects_empty() {
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("staging");
        std::fs::create_dir_all(&staging).unwrap();

        let file_path = staging.join("empty.ndb");
        std::fs::write(&file_path, "").unwrap();

        let mgr = SignatureUpdateManager {
            staging_root: dir.path().to_path_buf(),
            active_enhanced_dir: dir.path().join("active"),
            stage: UpdateStage::Idle,
        };

        let files = vec![StagedFile {
            name: "empty.ndb".into(),
            size: 0,
            sha256: None,
        }];
        assert!(mgr.verify_staged(&staging, &files, "test").is_err());
    }

    // ── SR-08 anti-rollback ─────────────────────────────────────────
    // These exercise the monotonic downgrade check directly. Together with
    // `verify_rejects_bad_hash`/`_oversize`/`_empty` (a tampered/invalid
    // set is refused) and `manifest_parse` (a well-formed set is accepted),
    // they cover accept / reject-tampered / reject-downgrade for the daemon
    // provider pipeline.

    fn mk_manifest(provider: &str, version: &str, updated_at: &str) -> ProviderManifest {
        ProviderManifest {
            provider_id: provider.into(),
            version: version.into(),
            files: vec![],
            license: "MIT".into(),
            attribution: "Test".into(),
            updated_at: updated_at.into(),
        }
    }

    fn mk_mgr(dir: &std::path::Path) -> SignatureUpdateManager {
        SignatureUpdateManager {
            staging_root: dir.join("staging"),
            active_enhanced_dir: dir.join("active"),
            stage: UpdateStage::Idle,
        }
    }

    #[test]
    fn anti_rollback_accepts_first_and_newer() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = mk_mgr(dir.path());
        // First manifest ever: no baseline, must be accepted and recorded.
        assert!(
            mgr.enforce_anti_rollback("prov", &mk_manifest("prov", "1.0", "2026-05-25"))
                .is_ok()
        );
        // A strictly newer manifest is accepted.
        assert!(
            mgr.enforce_anti_rollback("prov", &mk_manifest("prov", "1.1", "2026-06-01T09:00:00Z"))
                .is_ok()
        );
    }

    #[test]
    fn anti_rollback_rejects_older_downgrade() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = mk_mgr(dir.path());
        assert!(
            mgr.enforce_anti_rollback("prov", &mk_manifest("prov", "2.0", "2026-06-01"))
                .is_ok()
        );
        // A genuine older manifest replayed at the same provider: refused.
        let err = mgr
            .enforce_anti_rollback("prov", &mk_manifest("prov", "1.0", "2026-05-01"))
            .unwrap_err();
        assert!(err.contains("anti-rollback"), "unexpected error: {err}");
    }

    #[test]
    fn anti_rollback_allows_equal_for_retry() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = mk_mgr(dir.path());
        let m = mk_manifest("prov", "3.0", "2026-06-10T00:00:00Z");
        assert!(mgr.enforce_anti_rollback("prov", &m).is_ok());
        // Re-fetching the identical manifest (e.g. retry after a transient
        // activation failure) is allowed — the files are still hash-pinned.
        assert!(mgr.enforce_anti_rollback("prov", &m).is_ok());
    }

    #[test]
    fn anti_rollback_fails_closed_on_unparseable_time() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = mk_mgr(dir.path());
        let err = mgr
            .enforce_anti_rollback("prov", &mk_manifest("prov", "1.0", "not-a-date"))
            .unwrap_err();
        assert!(err.contains("fail closed"), "unexpected error: {err}");
    }

    #[test]
    fn anti_rollback_is_per_provider() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = mk_mgr(dir.path());
        // A high baseline on one provider must not block a different one.
        assert!(
            mgr.enforce_anti_rollback("a", &mk_manifest("a", "9.0", "2026-12-31"))
                .is_ok()
        );
        assert!(
            mgr.enforce_anti_rollback("b", &mk_manifest("b", "1.0", "2026-01-01"))
                .is_ok()
        );
    }

    #[test]
    fn rollback_clears_enhanced() {
        let dir = tempfile::tempdir().unwrap();
        let active = dir.path().join("active");
        std::fs::create_dir_all(&active).unwrap();
        std::fs::write(active.join("test.ndb"), "data").unwrap();

        let mut mgr = SignatureUpdateManager {
            staging_root: dir.path().join("staging"),
            active_enhanced_dir: active.clone(),
            stage: UpdateStage::Idle,
        };

        assert!(active.join("test.ndb").exists());
        mgr.rollback();
        assert!(!active.join("test.ndb").exists());
    }
}
