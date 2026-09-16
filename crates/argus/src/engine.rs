//! ARGUS Engine — the core orchestrator.
//!
//! Coordinates all analysis layers, aggregates findings, and produces
//! the final scored verdict for every scanned target.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use serde::Serialize;
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use crate::budget::{BudgetTracker, ScanExecutionBudget, TimeoutReason};
use crate::layers;
use crate::layers::framework::FrameworkDetection;
use crate::verdict::*;

/// Engine version — embedded in every verdict for traceability.
pub const ENGINE_VERSION: &str = "0.1.0-alpha";

/// Configuration for the ARGUS engine.
#[derive(Debug, Clone)]
pub struct ArgusConfig {
    /// Maximum file size to analyze (bytes). Files larger than this are skipped.
    pub max_file_size: u64,

    /// Enable PE/ELF structural analysis.
    pub pe_heuristics: bool,

    /// Enable packer/protector detection.
    pub packer_detection: bool,

    /// Enable script content analysis.
    pub script_analysis: bool,

    /// Enable specialty malware pattern detection.
    pub pattern_detection: bool,

    /// Enable MIME/magic byte validation.
    pub mime_validation: bool,

    /// Enable file deception detection (extension tricks, RTLO, etc.).
    pub file_deception: bool,

    /// Enable JAR / Java-archive structural analysis (WeedHack family etc.).
    pub jar_analysis: bool,

    /// Enable PDF structural / action / JavaScript analysis (malicious-pdf family etc.).
    pub pdf_analysis: bool,
}

impl Default for ArgusConfig {
    fn default() -> Self {
        Self {
            max_file_size: 100 * 1024 * 1024, // 100 MB — larger files use ClamAV only
            pe_heuristics: true,
            packer_detection: true,
            script_analysis: true,
            pattern_detection: true,
            mime_validation: true,
            file_deception: true,
            jar_analysis: true,
            pdf_analysis: true,
        }
    }
}

/// Runtime statistics for the ARGUS engine.
#[derive(Debug, Clone, Serialize)]
pub struct ArgusStats {
    /// Total files analyzed since engine start.
    pub files_analyzed: u64,
    /// Total findings generated across all analyses.
    pub total_findings: u64,
    /// Files classified as Malicious (score 76+, matches `Verdict::Malicious`).
    pub threats_detected: u64,
    /// Files classified as clean (score == 0).
    pub clean_files: u64,
    /// Total analysis time in microseconds (cumulative).
    pub total_analysis_time_us: u64,
    /// Average analysis time per file in microseconds.
    pub avg_analysis_time_us: u64,
    /// Number of active analysis layers.
    pub active_layers: u32,
    /// Number of IOC hashes loaded.
    pub ioc_hashes_loaded: u64,
    /// Number of YARA rules loaded.
    pub yara_rules_loaded: u64,
    /// Engine version.
    pub engine_version: &'static str,
}

/// The ARGUS heuristics engine.
///
/// Thread-safe — create one instance and share it via `Arc`.
pub struct ArgusEngine {
    config: ArgusConfig,
    /// IOC hash matching database.
    pub ioc: layers::ioc::IocDatabase,
    /// YARA-X rule engine.
    pub yara: layers::yara::YaraEngine,
    /// Event correlator for short-term cross-file context.
    pub correlator: crate::correlation::EventCorrelator,
    /// Trusted hash cache — verified-clean files with trust signals.
    pub trusted_cache: layers::trusted_cache::TrustedCache,
    // Atomic counters for runtime stats.
    files_analyzed: AtomicU64,
    total_findings: AtomicU64,
    threats_detected: AtomicU64,
    clean_files: AtomicU64,
    total_analysis_time_us: AtomicU64,
}

impl ArgusEngine {
    /// Create a new ARGUS engine with the given configuration.
    pub fn new(config: ArgusConfig) -> Self {
        tracing::info!(
            version = ENGINE_VERSION,
            "ARGUS Heuristics Engine initialized",
        );
        Self {
            config,
            ioc: layers::ioc::IocDatabase::new(),
            yara: layers::yara::YaraEngine::new(),
            correlator: crate::correlation::EventCorrelator::new(),
            trusted_cache: layers::trusted_cache::TrustedCache::new(),
            files_analyzed: AtomicU64::new(0),
            total_findings: AtomicU64::new(0),
            threats_detected: AtomicU64::new(0),
            clean_files: AtomicU64::new(0),
            total_analysis_time_us: AtomicU64::new(0),
        }
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(ArgusConfig::default())
    }

    /// Get current engine statistics.
    pub fn stats(&self) -> ArgusStats {
        let analyzed = self.files_analyzed.load(Ordering::Relaxed);
        let total_time = self.total_analysis_time_us.load(Ordering::Relaxed);
        let yara_count = self.yara.rule_count();
        let active_layers = [
            self.config.mime_validation,
            self.config.pe_heuristics,
            self.config.packer_detection,
            self.config.script_analysis,
            self.config.pattern_detection,
            self.config.file_deception,
            self.config.jar_analysis,
            self.config.pdf_analysis,
            true,           // IOC (always active)
            yara_count > 0, // YARA (active if rules loaded)
        ]
        .iter()
        .filter(|&&v| v)
        .count() as u32;

        ArgusStats {
            files_analyzed: analyzed,
            total_findings: self.total_findings.load(Ordering::Relaxed),
            threats_detected: self.threats_detected.load(Ordering::Relaxed),
            clean_files: self.clean_files.load(Ordering::Relaxed),
            total_analysis_time_us: total_time,
            avg_analysis_time_us: if analyzed > 0 {
                total_time / analyzed
            } else {
                0
            },
            active_layers,
            ioc_hashes_loaded: self.ioc.len(),
            yara_rules_loaded: yara_count,
            engine_version: ENGINE_VERSION,
        }
    }

    /// Analyze a file at the given path. Returns a fully scored verdict.
    ///
    /// This is the primary entry point for file analysis. It:
    /// 1. Reads the file into memory (via mmap for large files)
    /// 2. Computes SHA-256 hash
    /// 3. Runs all enabled analysis layers
    /// 4. Aggregates findings into a scored verdict
    ///
    /// Uses the default `ScanExecutionBudget::manual()` budget. For bounded
    /// scans (realtime, idle, startup), use `analyze_file_with_budget`.
    pub fn analyze_file(&self, path: &Path) -> ArgusVerdict {
        let cancel = Arc::new(AtomicBool::new(false));
        let tracker = BudgetTracker::new(ScanExecutionBudget::manual(), cancel);
        self.analyze_file_with_tracker(path, &tracker)
    }

    /// Analyze a file with a caller-supplied execution budget.
    ///
    /// The tracker enforces total wall-clock time across all phases and
    /// records `TimeoutReason` evidence when a phase is skipped because the
    /// total budget is exhausted. Per-phase budgets (YARA) are also enforced
    /// where the engine has phase boundaries.
    pub fn analyze_file_with_budget(
        &self,
        path: &Path,
        budget: ScanExecutionBudget,
    ) -> ArgusVerdict {
        let cancel = Arc::new(AtomicBool::new(false));
        let tracker = BudgetTracker::new(budget, cancel);
        self.analyze_file_with_tracker(path, &tracker)
    }

    /// Analyze a file with a caller-managed `BudgetTracker`. Use this when
    /// the caller needs to share a cancellation flag or inspect timeout
    /// evidence after the scan returns.
    pub fn analyze_file_with_tracker(
        &self,
        path: &Path,
        tracker: &BudgetTracker,
    ) -> ArgusVerdict {
        let start = Instant::now();
        let path_str = path.to_string_lossy().to_string();

        // ── Read the file ──────────────────────────────────────
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                return self.error_verdict(&path_str, start, format!("Cannot read file: {e}"));
            }
        };

        let file_size = metadata.len();

        if file_size == 0 {
            return self.empty_verdict(&path_str, start);
        }

        // ── Strategy classification ─────────────────────────
        let strategy = ScanStrategy::classify(&path_str, file_size);
        if strategy == ScanStrategy::TooLarge {
            debug!(path = %path_str, size = file_size, "Skipped: too large for ARGUS");
            return self.empty_verdict(&path_str, start);
        }
        if strategy == ScanStrategy::SkipSafe {
            debug!(path = %path_str, "Skipped: safe file type");
            return self.empty_verdict(&path_str, start);
        }

        if file_size > self.config.max_file_size {
            debug!(path = %path_str, size = file_size, "Skipped: exceeds max file size");
            return self.empty_verdict(&path_str, start);
        }

        // ☠️ TOCTOU hardening: open the file with restricted Windows sharing
        // semantics (FILE_SHARE_READ only — NO write, NO delete/rename), then
        // hold the handle in `_scan_lock` for the full scan. The path that
        // subsequent layers (notably `authenticode::analyze_with_discount` →
        // WinVerifyTrust + extract_signer) re-open by name now refers to a
        // file an attacker can no longer swap or rename mid-scan, closing the
        // hash-then-verify race that previously let a poisoned `trusted_cache`
        // entry persist (sha256(malicious) cached with score=0 + "Trusted"
        // label because authenticode raced against benign_signed.exe). On Unix
        // share modes don't exist (and WinVerifyTrust doesn't either, so the
        // attack chain is Windows-only) — fall back to plain read.
        #[cfg(target_os = "windows")]
        let (data, _scan_lock) = {
            use std::io::Read as _;
            use std::os::windows::fs::OpenOptionsExt;
            // FILE_SHARE_READ = 0x1 (no FILE_SHARE_WRITE 0x2, no FILE_SHARE_DELETE 0x4).
            let mut f = match std::fs::OpenOptions::new()
                .read(true)
                .share_mode(0x1)
                .open(path)
            {
                Ok(f) => f,
                Err(e) => {
                    return self.error_verdict(&path_str, start, format!("Read error: {e}"));
                }
            };
            let mut buf = Vec::with_capacity(file_size as usize);
            if let Err(e) = f.read_to_end(&mut buf) {
                return self.error_verdict(&path_str, start, format!("Read error: {e}"));
            }
            (buf, f) // f kept alive in `_scan_lock`
        };
        #[cfg(not(target_os = "windows"))]
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                return self.error_verdict(&path_str, start, format!("Read error: {e}"));
            }
        };

        // ☠️ TOCTOU follow-up: size gating above used pre-read metadata. On
        // Unix there are no share modes, so a file growing between stat and
        // read would be fully loaded regardless of `max_file_size`. Enforce
        // the cap on what we actually read.
        if data.len() as u64 > self.config.max_file_size {
            debug!(path = %path_str, size = data.len(), "Skipped: grew past max file size during read");
            return self.empty_verdict(&path_str, start);
        }

        // ── Timing: SHA-256 ───────────────────────────────────
        let hash_start = Instant::now();
        let sha256 = {
            let mut hasher = Sha256::new();
            hasher.update(&data);
            hex::encode(hasher.finalize())
        };
        let hash_us = hash_start.elapsed().as_micros() as u64;

        // ── Trusted cache fast path ────────────────────────────
        // If this hash was previously verified clean with trust signals,
        // return cached verdict immediately. Saves full analysis time.
        if let Some(cached_score) = self.trusted_cache.check(&sha256) {
            let elapsed = start.elapsed().as_micros() as u64;
            self.files_analyzed.fetch_add(1, Ordering::Relaxed);
            self.clean_files.fetch_add(1, Ordering::Relaxed);
            self.total_analysis_time_us
                .fetch_add(elapsed, Ordering::Relaxed);

            let mime_type = infer::get(&data).map(|t| t.mime_type().to_string());
            return ArgusVerdict {
                path: path_str,
                file_size,
                sha256,
                mime_type,
                score: cached_score,
                verdict: Verdict::from_score(cached_score),
                findings: vec![],
                analysis_time_us: elapsed,
                engine_version: ENGINE_VERSION,
                timestamp: chrono::Utc::now().timestamp(),
                explanation: VerdictExplanation {
                    confidence_label: ConfidenceLabel::Trusted,
                    framework: None,
                    ..default_explanation()
                },
                timing: None, // Cached — no analysis performed.
            };
        }

        // ── Detect MIME type ───────────────────────────────────
        let mime_type = infer::get(&data).map(|t| t.mime_type().to_string());

        // ── Run analysis layers ────────────────────────────────
        let mut findings = Vec::new();

        // Layer: IOC hash matching (O(1) lookup — fastest check).
        findings.extend(self.ioc.check(&sha256));

        // Layer: File deception (path-only analysis — runs first, very fast).
        if self.config.file_deception {
            findings.extend(layers::file_deception::analyze_path(&path_str));
        }

        // Layer: MIME/magic validation.
        if self.config.mime_validation {
            findings.extend(layers::mime::analyze(&path_str, &data));
        }

        // Layer: PE/ELF structural analysis.
        // Total-budget gate — if we've already burned the wall-clock budget
        // on earlier I/O or hashing of a giant file, record evidence and
        // skip. A skipped phase is NOT failure; it's data for convergence.
        let is_pe = data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A;
        if tracker.is_expired() {
            // The TOTAL wall-clock budget expired before this phase ran —
            // record TotalTimeout, not StructuralTimeout (which weights a
            // phase-level fault that never actually happened).
            tracker.record_timeout(TimeoutReason::TotalTimeout);
        } else if tracker.is_cancelled() {
            debug!(path = %path_str, "Scan cancelled — skipping structural analysis");
        } else if is_pe {
            if let Ok(pe) = goblin::pe::PE::parse(&data) {
                if self.config.pe_heuristics {
                    findings.extend(layers::pe_heuristics::analyze(&pe, &data));
                }
                if self.config.packer_detection {
                    findings.extend(layers::packer::analyze(&pe, &data));
                }
            } else {
                debug!(path = %path_str, "PE parse failed — skipping structural analysis");
            }
        } else if self.config.packer_detection {
            // Non-PE packer checks (PyInstaller, Node SEA can be checked without PE parse).
            // Create a minimal PE stub to reuse packer::analyze structure.
            // For now, check raw data patterns directly.
            check_non_pe_packers(&data, &mut findings);
        }

        // Layer: Script analysis.
        // Budget/cancel gate — a skipped phase records TotalTimeout evidence
        // (surfaced via ScanTiming.timeout_reasons); cancellation just skips.
        if self.config.script_analysis {
            if tracker.is_expired() {
                tracker.record_timeout(TimeoutReason::TotalTimeout);
            } else if !tracker.is_cancelled() {
                let ext = path
                    .extension()
                    .map(|e| e.to_string_lossy().to_lowercase())
                    .unwrap_or_default();
                let is_script = matches!(
                    ext.as_str(),
                    "ps1" | "psm1" | "psd1" | "js" | "jse" | "vbs" | "vbe" | "bat" | "cmd" | "reg"
                );
                if is_script {
                    findings.extend(layers::script::analyze(&path_str, &data));
                }
            }
        }

        // Layer: JAR / Java-archive structural analysis (WeedHack family etc.).
        // Layer routes itself: returns empty findings if `data` isn't a ZIP or
        // if the ZIP doesn't look like a Java archive (no manifest, no .class).
        if self.config.jar_analysis {
            if tracker.is_expired() {
                tracker.record_timeout(TimeoutReason::TotalTimeout);
            } else if !tracker.is_cancelled() {
                findings.extend(layers::jar::analyze(&path_str, &data));
            }
        }

        // Layer: PDF structural / action / JavaScript analysis (malicious-pdf
        // family, etc.). Layer routes itself via the `%PDF-` header check;
        // returns empty findings on non-PDF input or on unparseable PDFs.
        if self.config.pdf_analysis {
            if tracker.is_expired() {
                tracker.record_timeout(TimeoutReason::TotalTimeout);
            } else if !tracker.is_cancelled() {
                findings.extend(layers::pdf::analyze(&path_str, &data));
            }
        }

        // Layer: Pattern detection (works on raw bytes).
        if self.config.pattern_detection {
            if tracker.is_expired() {
                tracker.record_timeout(TimeoutReason::TotalTimeout);
            } else if !tracker.is_cancelled() {
                findings.extend(layers::patterns::analyze(&path_str, &data));
            }
        }

        // Layer: YARA rule engine (runs compiled rules against buffer).
        // Skip YARA for SignatureOnly strategy (media, firmware, large blobs).
        // Enforces both the total wall-clock budget and the per-phase
        // `max_yara_duration` — a pathological rule that runs for tens of
        // seconds gets recorded as `YaraTimeout` (suspicion weight 5).
        let yara_start = Instant::now();
        let yara_phase_budget = tracker.budget().max_yara_duration;
        if tracker.is_expired() {
            tracker.record_timeout(TimeoutReason::TotalTimeout);
        } else if !tracker.is_cancelled()
            && (strategy == ScanStrategy::FullAnalysis
                || strategy == ScanStrategy::LightAnalysis)
        {
            findings.extend(self.yara.scan(&data));
            if tracker.phase_expired(yara_start, yara_phase_budget) {
                tracker.record_timeout(TimeoutReason::YaraTimeout);
            }
        }
        let yara_us = yara_start.elapsed().as_micros() as u64;

        // Layer: Authenticode signature verification (Windows PE only).
        // PERF: one call (`analyze_with_discount`) collapses what used to be
        // `analyze` + `signature_discount` — each of which called the expensive
        // WinVerifyTrust + cert-chain walk independently (2-3 calls/file).
        let mut authenticode_discount: u32 = 0;
        if is_pe {
            if tracker.is_expired() {
                tracker.record_timeout(TimeoutReason::TotalTimeout);
            } else if !tracker.is_cancelled() {
                let (ac_findings, discount) = layers::authenticode::analyze_with_discount(path);
                findings.extend(ac_findings);
                authenticode_discount = discount;
            }
        }

        // Layer: Software reputation — recognizes known publishers.
        // PERF: one call (`analyze_with_discount`) collapses what used to be
        // `analyze` + `reputation_discount` — each of which scanned the file
        // buffer for ~11 UTF-16 publisher strings independently (3 scans/file).
        let (rep_findings, reputation_discount) =
            layers::reputation::analyze_with_discount(&path_str, &data);
        findings.extend(rep_findings);

        // ── Installer framework detection & mitigation ───────
        // Replaces the legacy `is_known_installer` substring scan (deleted):
        // unanchored `windows(needle)` searches over the whole buffer were a
        // confirmed spoof primitive — any attacker could embed "Nullsoft Inst"
        // / "ASAR" / "Go build ID:" anywhere in a file they fully control and
        // earn the installer leniency discount (Structural/Packer /3,
        // installer-class YARA /2). Detection is now structural and
        // evidence-based (`layers::framework::detect`); the weight divisions
        // below apply ONLY when `FrameworkMitigation::evaluate` authorizes
        // them — see that function for the exact policy (Structural-grade
        // evidence required, WeakHint grants nothing, high-confidence veto,
        // one pass only).
        // Budget guard: framework detection scans the buffer (bounded linear
        // passes + capped candidate validation) — skip it entirely when the
        // execution budget is already spent or the scan was cancelled, so it
        // can never extend an over-budget scan, and record why. Detectors
        // themselves are cost-capped (see MAX_TABLE_CANDIDATES in inno.rs);
        // this guard covers the accumulated-cost case (many layers already
        // burned the budget before this point).
        let framework_detection = if tracker.is_expired() || tracker.is_cancelled() {
            tracing::debug!(
                path = %path_str,
                "framework detection skipped: scan budget exhausted or cancelled"
            );
            FrameworkDetection::unknown()
        } else {
            layers::framework::detect(&data, &path_str)
        };
        let framework_mitigation =
            FrameworkMitigation::evaluate(framework_detection, &mut findings);

        // ── Trusted binary noise suppression ───────────────────
        // If both Authenticode + reputation agree this is trusted,
        // suppress low-weight structural findings entirely to produce
        // cleaner verdicts for known-good software.
        if authenticode_discount >= 15 && reputation_discount >= 15 {
            findings.retain(|f| {
                // Keep behavioral/pattern findings (always important).
                // Suppress trivial structural noise.
                if f.weight <= 3
                    && matches!(f.layer, Layer::StructuralAnalysis | Layer::PackerDetection)
                {
                    false // Drop trivial structural findings for trusted binaries.
                } else {
                    true
                }
            });
        }

        // ── Contextual amplification ──────────────────────────
        // Runs after all content layers. Uses the pre-discount raw score
        // to decide whether to amplify — context alone never creates a threat.
        // SUPPRESSED for trusted signed binaries — they don't need context amplification.
        let pre_context_score: u32 = findings.iter().map(|f| f.weight).sum();
        let trust_suppresses_context = reputation_discount >= 15 || authenticode_discount >= 15;
        if pre_context_score > 0 && !trust_suppresses_context {
            findings.extend(layers::context::analyze(path, pre_context_score));
        }

        // ── Aggregate score + build explanation ────────────────
        // framework_mitigation was computed above — reuse instead of re-scanning.
        let (score, verdict, explanation) = aggregate_score(
            &mut findings,
            reputation_discount,
            authenticode_discount,
            &framework_mitigation,
        );
        let elapsed = start.elapsed();
        let elapsed_us = elapsed.as_micros() as u64;

        // ── Record event for correlation ──────────────────────
        // Surface the full suspicious middle band (26..=75) to the correlator
        // so directory-level burst detection can count partial-confidence hits,
        // not just Malicious (>=76). Low-suspicion noise (1..=25) still maps
        // to ScannedClean to avoid drowning the correlator in benign chatter.
        // NOTE: burst-detection consumers are not wired up yet — the
        // correlator is currently write-only outside its own tests.
        let event_type = if score >= 26 {
            crate::correlation::EventType::ScannedSuspicious
        } else {
            crate::correlation::EventType::ScannedClean
        };
        self.correlator.record(path.to_path_buf(), event_type, None);

        // ── Update stats ──────────────────────────────────────
        self.files_analyzed.fetch_add(1, Ordering::Relaxed);
        self.total_findings
            .fetch_add(findings.len() as u64, Ordering::Relaxed);
        self.total_analysis_time_us
            .fetch_add(elapsed_us, Ordering::Relaxed);
        // Stat buckets are keyed on the *final* verdict, not the raw score:
        //   Clean                       → clean_files
        //   Malicious | HighSuspicion   → threats_detected
        //   everything else             → uncounted (matches prior
        //                                 "neither bucket" semantics for
        //                                 LowSuspicion / PUA / Suspicious).
        // The previous gate (`score == 0`) silently dropped files with
        // score 1..=75 from both buckets while still bumping
        // `files_analyzed`, making the clean/threats sum drift below the
        // analyzed total.
        match verdict {
            Verdict::Clean => {
                self.clean_files.fetch_add(1, Ordering::Relaxed);
            }
            Verdict::Malicious | Verdict::HighSuspicion => {
                self.threats_detected.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }

        // Only log files with findings to avoid flooding logs during large scans.
        if !findings.is_empty() {
            debug!(
                path = %path_str,
                score,
                findings = findings.len(),
                time_us = elapsed_us,
                verdict = verdict.label(),
                "ARGUS analysis: findings detected",
            );
        }

        // ── Record in trusted cache if clean ─────────
        if score == 0 {
            self.trusted_cache.record(
                &sha256,
                score,
                explanation.signer.as_deref(),
                explanation.recognized_software.as_deref(),
            );
        }

        // ── Budget outcome evidence ───────────────────────────
        // Surface the tracker's recorded timeouts in the verdict instead of
        // dropping them with the tracker — engine-internal timeouts are
        // evasion-by-exhaustion evidence and must feed the convergence model.
        let timeout_reasons = tracker.timeouts();
        let completed_within_budget = !tracker.is_expired() && timeout_reasons.is_empty();

        ArgusVerdict {
            path: path_str,
            file_size,
            sha256,
            mime_type,
            score,
            verdict,
            findings,
            analysis_time_us: elapsed_us,
            engine_version: ENGINE_VERSION,
            timestamp: chrono::Utc::now().timestamp(),
            explanation,
            timing: Some(ScanTiming {
                hash_us,
                clamav_us: 0, // ClamAV is called separately by daemon
                argus_total_us: elapsed_us,
                yara_us,
                structural_us: 0, // TODO: instrument per-layer
                strategy: Some(strategy),
                timeout_reasons,
                completed_within_budget,
            }),
        }
    }

    /// Analyze raw bytes (for in-memory scanning, e.g., ASAR contents).
    pub fn analyze_buffer(&self, name: &str, data: &[u8]) -> ArgusVerdict {
        let start = Instant::now();
        let mut findings = Vec::new();

        let sha256 = {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        };

        let mime_type = infer::get(data).map(|t| t.mime_type().to_string());

        // Layer: IOC hash matching (O(1) lookup on the already-computed hash).
        // AMSI/ADS/memory content gets the same known-bad coverage as file
        // scans — skipping this was a pure false-negative gap.
        findings.extend(self.ioc.check(&sha256));

        // NOTE: YARA is deliberately not run on buffers. The primary callers
        // are memory regions (memory_scanner), where rule matches on raw
        // region bytes are FP-prone, plus AMSI/ADS content. Revisit per-caller
        // if AMSI/ADS YARA coverage is wanted.

        // Run applicable layers on the buffer.
        if self.config.mime_validation {
            findings.extend(layers::mime::analyze(name, data));
        }

        let is_pe = data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A;
        if is_pe {
            if let Ok(pe) = goblin::pe::PE::parse(data) {
                if self.config.pe_heuristics {
                    findings.extend(layers::pe_heuristics::analyze(&pe, data));
                }
                if self.config.packer_detection {
                    findings.extend(layers::packer::analyze(&pe, data));
                }
            }
        }

        if self.config.script_analysis {
            findings.extend(layers::script::analyze(name, data));
        }

        if self.config.jar_analysis {
            findings.extend(layers::jar::analyze(name, data));
        }

        if self.config.pdf_analysis {
            findings.extend(layers::pdf::analyze(name, data));
        }

        if self.config.pattern_detection {
            findings.extend(layers::patterns::analyze(name, data));
        }

        // Route through the unified scoring contract so buffer scans share
        // dedup, per-category caps, convergence, and explanation with file
        // scans. Reputation and Authenticode are path-only signals, so they
        // pass through as 0 here. Buffer scans (AMSI/ADS/memory regions)
        // deliberately get NO installer-framework mitigation: the file path
        // is a synthetic name, so filename evidence would be meaningless,
        // and a memory region is not an installer on disk. This preserves the
        // pre-refactor behavior (is_known_installer was never consulted here).
        let (score, verdict, explanation) =
            aggregate_score(&mut findings, 0, 0, &FrameworkMitigation::none());

        // ── Update stats ──────────────────────────────────────
        // Buffer scans (AMSI, ADS, memory regions) count too — otherwise
        // they're invisible in ArgusStats.
        let elapsed_us = start.elapsed().as_micros() as u64;
        self.files_analyzed.fetch_add(1, Ordering::Relaxed);
        self.total_findings
            .fetch_add(findings.len() as u64, Ordering::Relaxed);
        self.total_analysis_time_us
            .fetch_add(elapsed_us, Ordering::Relaxed);
        match verdict {
            Verdict::Clean => {
                self.clean_files.fetch_add(1, Ordering::Relaxed);
            }
            Verdict::Malicious | Verdict::HighSuspicion => {
                self.threats_detected.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }

        ArgusVerdict {
            path: name.to_string(),
            file_size: data.len() as u64,
            sha256,
            mime_type,
            score,
            verdict,
            findings,
            analysis_time_us: elapsed_us,
            engine_version: ENGINE_VERSION,
            timestamp: chrono::Utc::now().timestamp(),
            explanation,
            timing: None,
        }
    }

    fn empty_verdict(&self, path: &str, start: Instant) -> ArgusVerdict {
        ArgusVerdict {
            path: path.to_string(),
            file_size: 0,
            sha256: String::new(),
            mime_type: None,
            score: 0,
            verdict: Verdict::Clean,
            findings: vec![],
            analysis_time_us: start.elapsed().as_micros() as u64,
            engine_version: ENGINE_VERSION,
            timestamp: chrono::Utc::now().timestamp(),
            explanation: default_explanation(),
            timing: None,
        }
    }

    fn error_verdict(&self, path: &str, start: Instant, error: String) -> ArgusVerdict {
        // File-not-found is a normal race condition (temp files deleted between
        // watcher event and scan). Log at debug, not warn.
        if error.contains("os error 2") || error.contains("os error 3") {
            debug!(path, %error, "ARGUS: file vanished before scan");
        } else {
            warn!(path, %error, "ARGUS analysis error");
        }
        ArgusVerdict {
            path: path.to_string(),
            file_size: 0,
            sha256: String::new(),
            mime_type: None,
            score: 0,
            verdict: Verdict::Clean,
            findings: vec![Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Info,
                weight: 0,
                description: format!("Analysis incomplete: {error}"),
                technical_detail: None,
            }],
            analysis_time_us: start.elapsed().as_micros() as u64,
            engine_version: ENGINE_VERSION,
            timestamp: chrono::Utc::now().timestamp(),
            explanation: default_explanation(),
            timing: None,
        }
    }
}

fn default_explanation() -> VerdictExplanation {
    VerdictExplanation {
        raw_score: 0,
        reputation_discount: 0,
        authenticode_discount: 0,
        installer_discount_applied: false,
        final_score: 0,
        signer: None,
        recognized_software: None,
        suspicion_reasons: vec![],
        trust_reasons: vec![],
        confidence_label: ConfidenceLabel::Normal,
        framework: None,
        threat_maturity: ThreatMaturity::Benign,
        progression_depth: 0,
        framework_mitigation: None,
    }
}

/// Compute convergence assessment from weighted findings.
///
/// Identifies coherent attack chains from BehaviorTag combinations.
/// Chain strength reflects how dangerous the combination is, not just tag count.
fn compute_convergence(findings: &[Finding]) -> crate::verdict::ConvergenceInfo {
    use crate::verdict::{ChainStrength, ConvergenceInfo};
    use std::collections::HashSet;

    let active: Vec<_> = findings.iter().filter(|f| f.weight > 0).collect();

    let tags: HashSet<BehaviorTag> = active
        .iter()
        .filter_map(|f| f.behavior_tag())
        .filter(|t| *t != BehaviorTag::DownloadOriginContext)
        .collect();

    let layers: HashSet<Layer> = active.iter().map(|f| f.layer).collect();

    let has = |tag: BehaviorTag| tags.contains(&tag);

    // ── Detect chains ────────────────────────────────────
    let mut chains: Vec<(&'static str, ChainStrength)> = Vec::new();

    // STRONG chains — high-confidence malicious combinations.
    if has(BehaviorTag::KnownMalware) {
        chains.push(("known_malware_ioc", ChainStrength::Strong));
    }
    if has(BehaviorTag::CredentialTheft) && has(BehaviorTag::Exfiltration) {
        chains.push(("stealer", ChainStrength::Strong));
    }
    if has(BehaviorTag::Ransomware)
        && (has(BehaviorTag::Injection) || has(BehaviorTag::Persistence))
    {
        chains.push(("ransomware", ChainStrength::Strong));
    }
    if has(BehaviorTag::Persistence) && has(BehaviorTag::C2Communication) {
        chains.push(("backdoor", ChainStrength::Strong));
    }
    if has(BehaviorTag::WalletTheft)
        && (has(BehaviorTag::Exfiltration) || has(BehaviorTag::CredentialTheft))
    {
        chains.push(("crypto_stealer", ChainStrength::Strong));
    }

    // MODERATE chains — suspicious combinations that need more context.
    if has(BehaviorTag::FakeInstaller)
        && (has(BehaviorTag::Persistence) || has(BehaviorTag::DownloaderCapability))
    {
        chains.push(("fake_installer", ChainStrength::Moderate));
    }
    if has(BehaviorTag::ScriptAbuse)
        && (has(BehaviorTag::DownloaderCapability) || has(BehaviorTag::C2Communication))
    {
        chains.push(("script_malware", ChainStrength::Moderate));
    }
    if has(BehaviorTag::DownloaderCapability)
        && has(BehaviorTag::ArchiveStaging)
        && has(BehaviorTag::Evasion)
    {
        chains.push(("loader", ChainStrength::Moderate));
    }
    if has(BehaviorTag::Persistence) && has(BehaviorTag::DownloaderCapability) {
        chains.push(("persistent_downloader", ChainStrength::Moderate));
    }

    // WEAK chains — common combinations that are often benign.
    if has(BehaviorTag::DownloaderCapability) && tags.len() == 1 {
        chains.push(("downloader_only", ChainStrength::Weak));
    }
    if has(BehaviorTag::Packing) && has(BehaviorTag::Entropy) && tags.len() <= 2 {
        chains.push(("packed_only", ChainStrength::Weak));
    }

    // Strongest chain wins.
    let chain_strength = chains
        .iter()
        .map(|(_, s)| *s)
        .max()
        .unwrap_or(ChainStrength::None);

    let chain_names: Vec<&'static str> = chains
        .iter()
        .filter(|(_, s)| *s >= ChainStrength::Moderate)
        .map(|(name, _)| *name)
        .collect();

    // Compute attack progression score.
    let tag_vec: Vec<BehaviorTag> = tags.iter().copied().collect();
    let progression = crate::verdict::attack_progression_score(&tag_vec);

    ConvergenceInfo {
        distinct_behaviors: tags.len(),
        distinct_layers: layers.len(),
        chain_strength,
        chain_names,
        progression_score: progression,
    }
}

/// Deduplicate findings using structured BehaviorTags.
///
/// DEDUP RULE: Same behavior tag + same layer → redundant (keep only max weight).
/// Same behavior tag + different layers → convergence (both count — independent confirmation).
///
/// This preserves multi-layer agreement (YARA + Pattern both say "stealer" = stronger)
/// while preventing intra-layer redundancy (two structural entropy findings = one).
///
/// Context-layer findings are never deduplicated.
fn deduplicate_findings(findings: &mut Vec<Finding>) {
    use crate::verdict::BehaviorTag;

    // Sort by weight descending — highest-weight findings kept.
    findings.sort_by(|a, b| b.weight.cmp(&a.weight));

    // Track (tag, layer) pairs already counted.
    let mut seen: std::collections::HashSet<(BehaviorTag, Layer)> =
        std::collections::HashSet::new();

    for f in findings.iter_mut() {
        if let Some(tag) = f.behavior_tag() {
            // Context is never deduplicated.
            if tag == BehaviorTag::DownloadOriginContext {
                continue;
            }

            let key = (tag, f.layer);
            if seen.contains(&key) {
                // Same tag + same layer → redundant → zero weight.
                f.weight = 0;
                if f.severity > Severity::Info {
                    f.severity = Severity::Info;
                }
            } else {
                seen.insert(key);
            }
        }
    }
}

/// Installer-framework mitigation — the ONLY place in the engine where a
/// framework detection may reduce finding weights.
///
/// ## POLICY (calibration decisions, do not relax without a review)
///
/// 1. **Mitigation requires `confidence == Structural` AND
///    `mitigation_safe()`.** This is deliberately stricter than the
///    `FrameworkDetection::build` invariant (which marks Corroborated +
///    structural evidence as `mitigation_safe` for diagnostic purposes).
///    Corroborated results mean conflicting/tampered evidence — an NSIS
///    archive whose CRC does not verify, a truncated Inno setup, a Burn
///    container that cannot be validated. Failing conservatively costs a
///    damaged legitimate installer a few points; failing open hands a
///    tamper-for-leniency primitive to attackers. Structural-grade means the
///    file *verifiably is* the framework (validated header grammar at a
///    structural offset, integrity check passed or legitimately absent).
///
/// 2. **WeakHint grants NO discount — including every legacy substring
///    hint** (Electron "ASAR", "Go build ID:", Qt/Squirrel markers, the
///    name+body-hint heuristic, extension-only MSI). Embedding such a marker
///    is exactly the same attack as embedding "Nullsoft Inst" was; leaving
///    any of them discounted keeps the evasion CLASS alive. FP cost is
///    bounded and accepted: legit unsigned Go/Electron apps with structural
///    noise may now land in the Suspicious label band, but the daemon's
///    ARGUS-only quarantine bar is 85, so no auto-quarantine shift is
///    expected. Restoring leniency for these frameworks requires a
///    *structural* detector, not a marker string.
///
/// 3. **High-confidence veto:** installer mitigation must never suppress
///    independent high-confidence malicious evidence. If ANY finding
///    (evaluated pre-mitigation) has weight >= [`HIGH_CONFIDENCE_VETO_WEIGHT`]
///    mitigation does not apply AT ALL and the veto is recorded. The
///    threshold 40 covers the three known high-weight emitters — IoC hash
///    match (90), weight-40 YARA rules, MIME/magic mismatch (45) — while the
///    installer-class YARA findings the /2 division targets are <= ~25, so
///    an installer can still be flagged by ordinary detections (decision:
///    mitigation and conviction are separate dimensions). This also covers
///    the MIME-45 × system-path interaction (workstream W): a real installer
///    with a genuine MIME mismatch keeps the full 45 (veto, no division);
///    the authenticode system-path −20 discount is a *trust* discount applied
///    independently in `aggregate_score`, orthogonal to this pass.
///
/// 4. **One mitigation pass only.** A file gets at most one mitigation
///    application (no stacking of multiple hints/divisions).
///
/// 5. **Divisions unchanged:** Structural/Packer findings /3, installer-class
///    YARA findings /2 — the calibration of these ratios is preserved from
///    the legacy code.
struct FrameworkMitigation {
    /// The detection this decision was based on.
    detection: layers::framework::FrameworkDetection,
    /// Whether any weight division was applied.
    applied: bool,
    /// Why a qualifying (Structural-grade) detection was refused mitigation.
    veto_reason: Option<String>,
    /// Every weight reduction performed (the mitigation trace).
    ops: Vec<MitigationOp>,
    /// Sum of finding weights immediately before the pass.
    score_before: u32,
    /// Sum of finding weights immediately after the pass.
    score_after: u32,
}

/// One applied weight reduction (layer + before/after), for the provenance
/// trace.
struct MitigationOp {
    layer: Layer,
    weight_before: u32,
    weight_after: u32,
}

/// Findings at or above this weight veto installer-framework mitigation
/// (policy item 3 above). Covers IoC (90), weight-40 YARA, MIME mismatch (45).
const HIGH_CONFIDENCE_VETO_WEIGHT: u32 = 40;

impl FrameworkMitigation {
    /// No detection / no mitigation — the default for buffer scans and tests.
    fn none() -> Self {
        Self {
            detection: layers::framework::FrameworkDetection::unknown(),
            applied: false,
            veto_reason: None,
            ops: Vec::new(),
            score_before: 0,
            score_after: 0,
        }
    }

    /// Decide whether the detection authorizes mitigation and, if so, apply
    /// the divisions to `findings` in a single pass. This is the only
    /// mutation point for installer leniency in the engine.
    fn evaluate(
        detection: layers::framework::FrameworkDetection,
        findings: &mut [Finding],
    ) -> Self {
        use crate::layers::framework::Confidence;

        let score_before: u32 = findings.iter().map(|f| f.weight).sum();

        // Policy 1: Structural-grade evidence only. Corroborated (tampered /
        // truncated / unverifiable) is diagnostic-only; WeakHint (text and
        // filename hints, including all legacy substring heuristics) is
        // diagnostic-only (policy 2). Both are recorded in the provenance so
        // the decision is explainable.
        let qualifies =
            detection.confidence() == Confidence::Structural && detection.mitigation_safe();
        if !qualifies {
            return Self {
                detection,
                applied: false,
                veto_reason: None,
                ops: Vec::new(),
                score_before,
                score_after: score_before,
            };
        }

        // Policy 3: independent high-confidence malicious evidence vetoes
        // mitigation entirely — a structurally valid installer can still BE
        // malware, and leniency must never soften a strong independent signal.
        if let Some(f) = findings
            .iter()
            .filter(|f| f.weight >= HIGH_CONFIDENCE_VETO_WEIGHT)
            .max_by_key(|f| f.weight)
        {
            let veto_reason = format!(
                "mitigation vetoed: independent high-confidence evidence present \
                 ({:?} finding, weight {} >= {}): {}",
                f.layer, f.weight, HIGH_CONFIDENCE_VETO_WEIGHT, f.description
            );
            debug!(
                kind = ?detection.kind(),
                veto = %veto_reason,
                "installer mitigation suppressed by high-confidence veto"
            );
            return Self {
                detection,
                applied: false,
                veto_reason: Some(veto_reason),
                ops: Vec::new(),
                score_before,
                score_after: score_before,
            };
        }

        // Policy 4+5: exactly one pass; divisions preserved from the legacy
        // calibration (Structural/Packer /3, installer-class YARA /2).
        let mut ops = Vec::new();
        for f in findings.iter_mut() {
            let before = f.weight;
            match f.layer {
                // Structural/packer: aggressive reduction (/3).
                Layer::StructuralAnalysis | Layer::PackerDetection => {
                    f.weight /= 3;
                }
                // YARA: moderate reduction (/2) for installer-expected patterns.
                // Dropper, updater, and persistence rules fire on normal installers.
                Layer::YaraRules => {
                    if let Some(ref detail) = f.technical_detail {
                        let dl = detail.to_lowercase();
                        if dl.contains("dropper")
                            || dl.contains("updater")
                            || dl.contains("installer")
                            || dl.contains("persistence")
                            || dl.contains("temp_extraction")
                            || dl.contains("fake_updater")
                        {
                            f.weight /= 2;
                        }
                    }
                }
                _ => {}
            }
            if f.weight != before {
                ops.push(MitigationOp {
                    layer: f.layer,
                    weight_before: before,
                    weight_after: f.weight,
                });
            }
            if f.weight == 0 && f.severity > Severity::Info {
                f.severity = Severity::Info;
            }
        }

        let score_after: u32 = findings.iter().map(|f| f.weight).sum();
        debug!(
            kind = ?detection.kind(),
            ops = ops.len(),
            score_before,
            score_after,
            "installer-framework mitigation applied"
        );
        Self {
            detection,
            applied: true,
            veto_reason: None,
            ops,
            score_before,
            score_after,
        }
    }

    /// Build the additive serde provenance record (workstream U). Returns
    /// `Some` whenever the dispatcher recognized anything — including
    /// WeakHint detections that granted nothing, so "why no discount?" is
    /// answerable from the verdict alone.
    fn provenance(&self) -> Option<crate::verdict::FrameworkMitigationProvenance> {
        use crate::layers::framework::FrameworkKind;
        if self.detection.kind() == FrameworkKind::Unknown && !self.applied {
            return None;
        }
        Some(crate::verdict::FrameworkMitigationProvenance {
            kind: Some(self.detection.kind().label().to_string()),
            confidence: format!("{:?}", self.detection.confidence()),
            mitigation_safe: self.detection.mitigation_safe(),
            mitigation_applied: self.applied,
            evidence: self
                .detection
                .evidence()
                .iter()
                .map(|e| crate::verdict::FrameworkEvidenceRecord {
                    source: format!("{:?}", e.source),
                    offset: e.offset,
                    detail: e.detail.clone(),
                })
                .collect(),
            ops: self
                .ops
                .iter()
                .map(|op| crate::verdict::MitigationOpRecord {
                    layer: format!("{:?}", op.layer),
                    weight_before: op.weight_before,
                    weight_after: op.weight_after,
                })
                .collect(),
            score_before_mitigation: self.score_before,
            score_after_mitigation: self.score_after,
            veto_reason: self.veto_reason.clone(),
            warnings: self.detection.warnings().to_vec(),
        })
    }
}

/// Pure scoring function — computes final score, verdict, and explanation
/// from raw findings + discount values. Sorts findings by weight.
///
/// This is the single source of truth for score aggregation.
fn aggregate_score(
    findings: &mut Vec<Finding>,
    reputation_discount: u32,
    authenticode_discount: u32,
    framework_mitigation: &FrameworkMitigation,
) -> (u32, Verdict, VerdictExplanation) {
    // ── Evidence deduplication — prevent counting same behavior twice ──
    // When multiple layers detect the same semantic behavior (e.g., "downloader"
    // from YARA + "downloader" from patterns + "URL download" from imports),
    // keep only the highest-weight finding per behavior group.
    deduplicate_findings(findings);

    // ── Category caps — prevent single-category score inflation ──
    const CAP_STRUCTURAL: u32 = 30;
    const CAP_YARA: u32 = 40;
    const CAP_CONTEXT: u32 = 15;
    const CAP_PACKER: u32 = 20;
    const CAP_PATTERN: u32 = 25;
    const CAP_SCRIPT: u32 = 40;
    const CAP_DECEPTION: u32 = 50;

    // Apply per-category caps by proportionally reducing weights.
    // Floor (not round): rounding up can push the scaled category total past
    // the cap (e.g. [10,10,11] vs cap 30 → 31). Floor guarantees
    // sum(floor(w_i * ratio)) <= floor(total * ratio) = cap.
    let apply_cap = |findings: &mut Vec<Finding>, layer: Layer, cap: u32| {
        let total: u32 = findings
            .iter()
            .filter(|f| f.layer == layer)
            .map(|f| f.weight)
            .sum();
        if total > cap && total > 0 {
            let ratio = cap as f64 / total as f64;
            for f in findings.iter_mut() {
                if f.layer == layer {
                    f.weight = (f.weight as f64 * ratio).floor() as u32;
                }
            }
        }
    };

    apply_cap(findings, Layer::StructuralAnalysis, CAP_STRUCTURAL);
    apply_cap(findings, Layer::YaraRules, CAP_YARA);
    apply_cap(findings, Layer::Context, CAP_CONTEXT);
    apply_cap(findings, Layer::PackerDetection, CAP_PACKER);
    apply_cap(findings, Layer::PatternDetection, CAP_PATTERN);
    apply_cap(findings, Layer::ScriptAnalysis, CAP_SCRIPT);
    apply_cap(findings, Layer::FileDeception, CAP_DECEPTION);

    let raw_score: u32 = findings.iter().map(|f| f.weight).sum();
    // Discounts don't stack fully — use the larger.
    let total_discount = reputation_discount.max(authenticode_discount);
    let adjusted = raw_score.saturating_sub(total_discount);
    let score = adjusted.min(MAX_SCORE);

    // Sort findings by weight (highest first).
    findings.sort_by(|a, b| b.weight.cmp(&a.weight));

    let mut verdict = Verdict::from_score(score);

    // PUA reclassification: if dominant behavior is PUA-tagged and score
    // is in suspicious range, reclassify as PotentiallyUnwanted.
    if matches!(verdict, Verdict::Suspicious | Verdict::HighSuspicion) {
        let pua_weight: u32 = findings
            .iter()
            .filter(|f| f.behavior_tag() == Some(BehaviorTag::PotentiallyUnwanted))
            .map(|f| f.weight)
            .sum();
        if pua_weight > 0 && pua_weight >= raw_score / 2 {
            verdict = Verdict::PotentiallyUnwanted;
        }
    }

    // Build structured explanation — group by evidence type for readability.
    let mut seen = std::collections::HashSet::new();
    let suspicion_reasons: Vec<String> = findings
        .iter()
        .filter(|f| f.weight > 0 && f.layer != Layer::Reputation)
        .filter(|f| {
            let short = f.description.chars().take(60).collect::<String>();
            seen.insert(short)
        })
        .take(8)
        .map(|f| {
            // Prefix with weight for clarity in explanations.
            if f.weight >= 20 {
                format!("[+{}] {}", f.weight, f.description)
            } else {
                f.description.clone()
            }
        })
        .collect();

    let mut trust_reasons = Vec::new();
    if reputation_discount > 0 {
        let sw_name = findings
            .iter()
            .find(|f| f.layer == Layer::Reputation)
            .and_then(|f| f.technical_detail.as_ref())
            .and_then(|d| d.split("Publisher: ").nth(1))
            .map(|s| s.split(" |").next().unwrap_or(s).to_string());
        trust_reasons.push(format!(
            "Recognized software (−{reputation_discount} points)"
        ));
        if let Some(ref name) = sw_name {
            trust_reasons.push(format!("Publisher: {name}"));
        }
    }
    if authenticode_discount > 0 {
        trust_reasons.push(format!(
            "Valid digital signature (−{authenticode_discount} points)"
        ));
    }
    if framework_mitigation.applied {
        // Workstream T req 5/7: score transformations must be justified and
        // visible. Cite the framework kind, the evidence count behind the
        // classification, exactly what was divided, and the weight delta.
        let det = &framework_mitigation.detection;
        trust_reasons.push(format!(
            "Installer framework detected ({}; {} structural-grade evidence item{}) — \
             Structural/Packer weights ÷3, installer-class YARA weights ÷2 \
             ({} finding{} adjusted, {} → {})",
            det.kind().label(),
            det.evidence().len(),
            if det.evidence().len() == 1 { "" } else { "s" },
            framework_mitigation.ops.len(),
            if framework_mitigation.ops.len() == 1 { "" } else { "s" },
            framework_mitigation.score_before,
            framework_mitigation.score_after,
        ));
    }

    let signer = findings
        .iter()
        .find(|f| f.layer == Layer::Reputation && f.description.contains("Digitally signed"))
        .and_then(|f| f.technical_detail.as_ref())
        .map(|d| d.replace("Signer: ", ""));

    let recognized_software = findings
        .iter()
        .find(|f| f.layer == Layer::Reputation && f.description.contains("Recognized as"))
        .and_then(|f| f.technical_detail.as_ref())
        .and_then(|d| d.split("Publisher: ").nth(1))
        .map(|s| s.split(" |").next().unwrap_or(s).to_string());

    // Compute convergence — how many independent behavior categories + layers agree.
    let convergence = compute_convergence(findings);

    // Confidence label — convergence-aware assessment for UI.
    let confidence_label = ConfidenceLabel::from_convergence(
        score,
        authenticode_discount > 0,
        reputation_discount > 0,
        framework_mitigation.applied,
        &convergence,
    );

    // Detect framework: prefer the structural/evidence-based detection (even
    // a WeakHint names what was seen — the provenance record carries the
    // confidence tier, so the label alone cannot overstate it); fall back to
    // packer-finding inference (PyInstaller, Nuitka, ...) which the
    // dispatcher does not cover.
    let framework = if framework_mitigation.detection.kind()
        != crate::layers::framework::FrameworkKind::Unknown
    {
        Some(framework_mitigation.detection.kind().label().to_string())
    } else {
        detect_framework_from_findings(findings)
    };

    let threat_maturity = ThreatMaturity::from_convergence(&convergence, score);

    let explanation = VerdictExplanation {
        raw_score,
        reputation_discount,
        authenticode_discount,
        installer_discount_applied: framework_mitigation.applied,
        final_score: score,
        signer,
        recognized_software,
        suspicion_reasons,
        trust_reasons,
        confidence_label,
        framework,
        threat_maturity,
        progression_depth: convergence.progression_score,
        framework_mitigation: framework_mitigation.provenance(),
    };

    (score, verdict, explanation)
}

/// Extract framework name from findings (if detected).
fn detect_framework_from_findings(findings: &[Finding]) -> Option<String> {
    for f in findings {
        let desc = f.description.to_lowercase();
        let detail = f.technical_detail.as_deref().unwrap_or("").to_lowercase();
        let combined = format!("{desc} {detail}");

        if combined.contains("pyinstaller") {
            return Some("PyInstaller".into());
        }
        if combined.contains("electron") || combined.contains("asar") {
            return Some("Electron".into());
        }
        if combined.contains("node.js sea") || combined.contains("node_sea") {
            return Some("Node.js SEA".into());
        }
        if combined.contains("nuitka") {
            return Some("Nuitka".into());
        }
        if combined.contains("tauri") {
            return Some("Tauri".into());
        }
        if combined.contains("nw.js") || combined.contains("nwjs") {
            return Some("NW.js".into());
        }
    }
    None
}

/// Check for packer signatures in non-PE files.
fn check_non_pe_packers(data: &[u8], findings: &mut Vec<Finding>) {
    // PyInstaller magic.
    let magic = b"MEI\x0C\x0B\x0A\x0B\x0E";
    if data.len() > 64 {
        let search_start = data.len().saturating_sub(4096);
        let tail = &data[search_start..];
        if tail.windows(magic.len()).any(|w| w == magic) {
            findings.push(Finding {
                layer: Layer::PackerDetection,
                severity: Severity::Low,
                weight: 5,
                description: "File contains PyInstaller archive markers — legitimate Python packaging tool, also commonly used by Python-based malware.".into(),
                technical_detail: Some("PyInstaller CArchive magic found".into()),
            });
        }
    }

    // Node.js SEA.
    let fuse = b"NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2";
    if data.windows(fuse.len()).any(|w| w == fuse) {
        findings.push(Finding {
            layer: Layer::PackerDetection,
            severity: Severity::Low,
            weight: 5,
            description: "File is a Node.js Single Executable Application — legitimate packaging format, also used to conceal Node.js malware.".into(),
            technical_detail: Some("NODE_SEA_FUSE sentinel found".into()),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // ── framework-mitigation test helpers ────────────────────

    use crate::layers::framework::{
        Confidence, EvidenceItem, EvidenceSource, FrameworkDetection, FrameworkKind,
    };

    /// A synthetic Structural-grade NSIS detection (valid under build()'s
    /// invariant) for tests that need an "applied" mitigation without
    /// building PE bytes.
    fn structural_nsis_detection() -> FrameworkDetection {
        FrameworkDetection::build(
            FrameworkKind::Nsis,
            Confidence::Structural,
            vec![
                EvidenceItem::new(
                    EvidenceSource::Overlay,
                    Some(0x400),
                    "NSIS data block at 512-aligned overlay offset 0x400",
                ),
                EvidenceItem::new(
                    EvidenceSource::EmbeddedArchive,
                    Some(0x400),
                    "valid NSIS firstheader (test fixture)",
                ),
            ],
            Vec::new(),
        )
    }

    /// An "applied" mitigation for tests that exercise aggregate_score's
    /// installer flag without caring about the weight math (evaluated
    /// against an empty findings sink, so nothing is divided).
    fn applied_mitigation_stub() -> FrameworkMitigation {
        let mut sink = Vec::new();
        FrameworkMitigation::evaluate(structural_nsis_detection(), &mut sink)
    }

    /// A minimal PE whose overlay starts at 512-aligned 0x400, carrying a
    /// valid NSIS firstheader (NO_CRC) and `payload_len` payload bytes →
    /// Structural detection. Mirrors the nsis.rs detector fixtures.
    fn structural_nsis_pe(payload_len: u32) -> Vec<u8> {
        use crate::layers::framework::fixtures::{PeBuilder, SectionSpec};
        let arc_size = 28u32 + payload_len;
        let mut overlay = Vec::new();
        overlay.extend_from_slice(&4u32.to_le_bytes()); // FH_FLAGS_NO_CRC
        overlay.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // siginfo
        overlay.extend_from_slice(b"NullsoftInst");
        overlay.extend_from_slice(&0x100u32.to_le_bytes()); // length_of_header
        overlay.extend_from_slice(&arc_size.to_le_bytes()); // length_of_all_following_data
        overlay.extend(std::iter::repeat_n(0xCC, payload_len as usize));
        PeBuilder::new()
            .add_section(SectionSpec::new(".text", 0x200, 0x200).raw_ptr_override(0x200))
            .overlay(&overlay)
            .build()
    }

    /// Same PE shape with a CRC trailer whose stored value is deliberately
    /// wrong → Corroborated detection (tampered archive).
    fn nsis_pe_crc_mismatch(payload_len: u32) -> Vec<u8> {
        use crate::layers::framework::fixtures::{PeBuilder, SectionSpec};
        let arc_size = 28u32 + payload_len + 4;
        let mut overlay = Vec::new();
        overlay.extend_from_slice(&0u32.to_le_bytes()); // CRC present
        overlay.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        overlay.extend_from_slice(b"NullsoftInst");
        overlay.extend_from_slice(&0x100u32.to_le_bytes());
        overlay.extend_from_slice(&arc_size.to_le_bytes());
        overlay.extend(std::iter::repeat_n(0xCC, payload_len as usize));
        overlay.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // bogus stored CRC
        PeBuilder::new()
            .add_section(SectionSpec::new(".text", 0x200, 0x200).raw_ptr_override(0x200))
            .overlay(&overlay)
            .build()
    }

    /// Evaluate a detection against an empty findings sink and report
    /// whether mitigation was applied.
    fn mitigation_applied(data: &[u8], path: &str) -> bool {
        let d = layers::framework::detect(data, path);
        let mut sink = Vec::new();
        FrameworkMitigation::evaluate(d, &mut sink).applied
    }

    #[test]
    fn ole2_office_doc_is_not_treated_as_installer() {
        // OLE2 compound-file magic — shared by legacy .doc/.xls AND .msi.
        let mut ole2 = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        ole2.extend_from_slice(b"macro payload here, no installer markers");

        // A .doc with bare OLE2 magic must NOT get installer trust (else macro
        // droppers receive a structural+YARA detection discount).
        assert!(
            !mitigation_applied(&ole2, "C:\\Users\\me\\invoice.doc"),
            "bare OLE2 doc must not be treated as an installer"
        );

        // INTENTIONAL CHANGE (policy 2 — WeakHint grants nothing): a genuine
        // MSI is still DETECTED by extension (MsiOle2, diagnostically), but
        // no longer earns mitigation — filename evidence is forgeable, so
        // extension-only detection is WeakHint. Fail-safe direction; see
        // detect_msi docs for what a structural MSI validator would require.
        let d = layers::framework::detect(&ole2, "C:\\Downloads\\app-setup.msi");
        assert_eq!(d.kind(), FrameworkKind::MsiOle2);
        assert_eq!(d.confidence(), Confidence::WeakHint);
        assert!(!d.mitigation_safe());
        assert!(!mitigation_applied(&ole2, "C:\\Downloads\\app-setup.msi"));

        // An OLE2 file carrying the "Windows Installer" string but NOT named
        // .msi must NOT qualify. This assertion previously demanded the
        // opposite, locking in an attacker-forceable discount: any macro
        // dropper shipped as invoice.doc with that literal embedded anywhere
        // earned the /3 structural + /2 YARA suppression.
        let mut msi_marker = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        msi_marker.extend_from_slice(b"...Windows Installer...");
        assert!(
            !mitigation_applied(&msi_marker, "x.bin"),
            "OLE2 content markers must not grant the installer discount"
        );
        assert!(
            !mitigation_applied(&msi_marker, "C:\\Users\\me\\invoice.doc"),
            "macro dropper embedding 'Windows Installer' must not be discounted"
        );
        // The same bytes are still DETECTED (diagnostically) when named
        // .msi/.msp — but detection no longer implies mitigation.
        assert_eq!(
            layers::framework::detect(&msi_marker, "C:\\Downloads\\pkg.msi").kind(),
            FrameworkKind::MsiOle2,
            "real .msi must still be detected"
        );
        assert_eq!(
            layers::framework::detect(&ole2, "C:\\Downloads\\patch.msp").kind(),
            FrameworkKind::MsiOle2,
            ".msp patch must still be detected"
        );
        assert!(!mitigation_applied(&msi_marker, "C:\\Downloads\\pkg.msi"));

        // INTENTIONAL FLIP: MZ + "Nullsoft Inst" used to earn the discount
        // outright. The space-separated needle matches version-info
        // decoration — fully attacker-controlled; embedding it anywhere was
        // THE evasion this refactor closes (real NSIS detection is
        // structural now, see nsis.rs). Here there is no valid firstheader
        // and no 16-byte archive signature: not even a WeakHint, and never
        // mitigation.
        let nsis = b"MZ........Nullsoft Inst........".to_vec();
        let d = layers::framework::detect(&nsis, "whatever.exe");
        assert!(d.confidence() <= Confidence::WeakHint);
        assert!(!d.mitigation_safe());
        assert!(!mitigation_applied(&nsis, "whatever.exe"));

        // An OLE2 doc whose body merely mentions an installer framework is
        // NOT an installer — only the MSI branch may fire for OLE2.
        let mut ole2_nsis = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        ole2_nsis.extend_from_slice(b"body text citing Nullsoft Inst strings");
        assert!(
            !mitigation_applied(&ole2_nsis, "C:\\Users\\me\\notes.doc"),
            "OLE2 doc with incidental installer-marker strings must not get the discount"
        );
    }

    #[test]
    fn non_pe_marker_strings_do_not_earn_installer_discount() {
        // Fast-reject regression (preserved): framework-marker strings in a
        // file that is neither PE nor OLE2 (a PDF, a blob) must not even
        // register as a hint — the legacy substring path is PE-gated.
        let pdf = b"%PDF-1.7 body text citing Nullsoft Inst and electron.asar".to_vec();
        let d = layers::framework::detect(&pdf, "C:\\Users\\me\\doc.pdf");
        assert_eq!(d.kind(), FrameworkKind::Unknown);
        assert!(!mitigation_applied(&pdf, "C:\\Users\\me\\doc.pdf"));

        // A >3MB non-PE blob with the Go marker is not a Go binary.
        let mut blob = vec![0u8; 4_000_000];
        blob[1000..1012].copy_from_slice(b"Go build ID:");
        let d = layers::framework::detect(&blob, "C:\\Users\\me\\blob.bin");
        assert_eq!(d.kind(), FrameworkKind::Unknown);
        assert!(!mitigation_applied(&blob, "C:\\Users\\me\\blob.bin"));
    }

    #[test]
    fn name_only_installer_requires_content_hint() {
        // Malware renamed "setup.exe" + padded past 2 MB, PE header, but NO
        // installer body hint → nothing detected (rename bypass stays closed).
        let mut padded = vec![0u8; 2_000_064];
        padded[0] = 0x4D; // 'M'
        padded[1] = 0x5A; // 'Z'
        let d = layers::framework::detect(&padded, "C:\\Users\\me\\Downloads\\setup.exe");
        assert_eq!(
            d.kind(),
            FrameworkKind::Unknown,
            "name+size alone must not even register (rename bypass)"
        );

        // INTENTIONAL FLIP: name + size + a generic body hint ("uninstall")
        // used to earn the FULL discount. All three inputs are
        // attacker-controlled (rename, padding, an embedded substring), so
        // the combination is now a diagnostic WeakHint granting NO
        // mitigation — this was the same evasion class as the NSIS needle.
        let mut real = padded.clone();
        real.extend_from_slice(b"uninstall.exe");
        let d = layers::framework::detect(&real, "C:\\Users\\me\\Downloads\\setup.exe");
        assert_eq!(d.kind(), FrameworkKind::GenericFramework);
        assert_eq!(d.confidence(), Confidence::WeakHint);
        assert!(!d.mitigation_safe());
        assert!(
            !mitigation_applied(&real, "C:\\Users\\me\\Downloads\\setup.exe"),
            "name+size+substring-hint must never authorize mitigation"
        );
    }

    #[test]
    fn test_clean_text_file() {
        let engine = ArgusEngine::with_defaults();
        let dir = std::env::temp_dir().join("argus_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("clean.txt");
        std::fs::write(&path, b"Hello, world!").unwrap();

        let verdict = engine.analyze_file(&path);
        assert_eq!(verdict.score, 0);
        assert_eq!(verdict.verdict, Verdict::Clean);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_fake_pdf_exe() {
        let engine = ArgusEngine::with_defaults();
        let dir = std::env::temp_dir().join("argus_test_pdf");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("invoice.pdf");

        // Write MZ header.
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&[0x4D, 0x5A]).unwrap(); // MZ
        f.write_all(&[0; 200]).unwrap();
        drop(f);

        let verdict = engine.analyze_file(&path);
        assert!(
            verdict.score >= 40,
            "Expected high score for fake PDF, got {}",
            verdict.score
        );
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.layer == Layer::MimeValidation)
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_buffer_analysis() {
        let engine = ArgusEngine::with_defaults();
        let data = b"eval(eval(eval(atob('malicious code'))))";
        let verdict = engine.analyze_buffer("suspicious.js", data);
        assert!(verdict.score > 0, "Expected suspicion from eval chains");
    }

    #[test]
    fn test_analyze_buffer_ioc_hit() {
        // Buffer scans (AMSI/ADS/memory) must get IOC coverage too — a
        // blocklisted hash alone (weight 90) is Malicious.
        let engine = ArgusEngine::with_defaults();
        let data = b"known bad payload";
        let sha256 = {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hex::encode(hasher.finalize())
        };
        engine.ioc.add_hash(&sha256);

        let verdict = engine.analyze_buffer("amsi-script-content", data);
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.layer == Layer::IocCorrelation),
            "analyze_buffer must surface IOC hits"
        );
        assert_eq!(verdict.verdict, Verdict::Malicious);
    }

    #[test]
    fn test_budget_timeouts_recorded_in_timing() {
        // An exhausted tracker must leave evidence in the returned verdict:
        // timeout_reasons populated, completed_within_budget = false.
        let engine = ArgusEngine::with_defaults();
        let dir = std::env::temp_dir().join("argus_test_budget");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sample.exe");
        std::fs::write(&path, b"MZ budget test content").unwrap();

        let budget = ScanExecutionBudget {
            max_duration: std::time::Duration::from_millis(1),
            ..ScanExecutionBudget::realtime()
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let tracker = BudgetTracker::new(budget, cancel);
        std::thread::sleep(std::time::Duration::from_millis(2));

        let verdict = engine.analyze_file_with_tracker(&path, &tracker);
        let timing = verdict.timing.expect("file scans must carry timing");
        assert!(
            !timing.completed_within_budget,
            "expired budget must mark completed_within_budget = false"
        );
        assert!(
            timing
                .timeout_reasons
                .contains(&TimeoutReason::TotalTimeout),
            "expired budget must record TotalTimeout, got {:?}",
            timing.timeout_reasons
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_apply_cap_never_exceeds_cap() {
        // Rounding regression: [10, 10, 11] vs cap 30 scaled with .round()
        // lands back on 31 — over the cap. Floor must keep it ≤ cap.
        let mk = |weight: u32, desc: &str| Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Medium,
            weight,
            description: desc.into(),
            technical_detail: None,
        };
        let mut findings = vec![mk(10, "S1"), mk(10, "S2"), mk(11, "S3")];
        let _ = aggregate_score(&mut findings, 0, 0, &FrameworkMitigation::none());
        let structural_total: u32 = findings
            .iter()
            .filter(|f| f.layer == Layer::StructuralAnalysis)
            .map(|f| f.weight)
            .sum();
        assert!(
            structural_total <= 30,
            "category total must never exceed the cap, got {structural_total}"
        );
    }

    #[test]
    fn test_stats_threat_count_matches_verdict() {
        // Verify stats threat counting uses the same threshold as Verdict::is_threat().
        let engine = ArgusEngine::with_defaults();

        // Clean file → stats should NOT increment threats.
        let dir = std::env::temp_dir().join("argus_test_stats");
        std::fs::create_dir_all(&dir).unwrap();
        let clean = dir.join("clean.txt");
        std::fs::write(&clean, b"perfectly safe content").unwrap();
        let _ = engine.analyze_file(&clean);
        assert_eq!(
            engine.stats().threats_detected,
            0,
            "Clean file should not count as threat"
        );

        // Score 40-75 file → should NOT be a threat (only 76+ = Malicious).
        let v = engine.analyze_buffer("test.txt", b"safe content");
        assert!(!v.is_threat(), "Low-score file should not be a threat");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_aggregate_score_pure() {
        // Test the scoring aggregation helper directly.
        let mut findings = vec![
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 15,
                description: "Test finding 1".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::PatternDetection,
                severity: Severity::High,
                weight: 25,
                description: "Test finding 2".into(),
                technical_detail: None,
            },
        ];

        // No discounts → raw score.
        let (score, verdict, explanation) = aggregate_score(&mut findings, 0, 0, &FrameworkMitigation::none());
        assert_eq!(score, 40);
        assert_eq!(verdict, Verdict::Suspicious);
        assert_eq!(explanation.raw_score, 40);
        assert_eq!(explanation.final_score, 40);
        assert!(explanation.suspicion_reasons.len() == 2);

        // With reputation discount → reduced.
        let (score2, verdict2, _) = aggregate_score(&mut findings, 20, 0, &FrameworkMitigation::none());
        assert_eq!(score2, 20);
        assert_eq!(verdict2, Verdict::LowSuspicion);

        // With both discounts → uses max, not sum.
        let (score3, _, expl3) = aggregate_score(&mut findings, 20, 25, &FrameworkMitigation::none());
        assert_eq!(score3, 15); // 40 - max(20,25) = 15
        assert_eq!(expl3.reputation_discount, 20);
        assert_eq!(expl3.authenticode_discount, 25);
    }

    // ═══════════════════════════════════════════════════════════════════
    // A) Trusted cache tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_trusted_cache_hit() {
        use crate::layers::trusted_cache::TrustedCache;
        let cache = TrustedCache::new();
        cache.record("abc123hash", 0, Some("Microsoft Corporation"), None);
        let result = cache.check("abc123hash");
        assert_eq!(result, Some(0), "Cache should return the recorded score");
    }

    #[test]
    fn test_trusted_cache_rejects_unsigned() {
        use crate::layers::trusted_cache::TrustedCache;
        let cache = TrustedCache::new();
        // No signer, no reputation → should NOT be cached.
        cache.record("unsigned_hash", 0, None, None);
        let result = cache.check("unsigned_hash");
        assert_eq!(
            result, None,
            "Unsigned file without reputation should not be cached"
        );
    }

    #[test]
    fn test_trusted_cache_invalidation() {
        use crate::layers::trusted_cache::TrustedCache;
        let cache = TrustedCache::new();
        cache.record("valid_hash", 5, Some("Trusted Signer"), None);
        assert_eq!(cache.check("valid_hash"), Some(5));
        // Invalidate (simulates signature DB update).
        cache.invalidate();
        assert_eq!(
            cache.check("valid_hash"),
            None,
            "After invalidation, cache should return None"
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // B) Category cap tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_structural_cap() {
        // 3 structural findings totaling weight 50; cap is 30.
        let mut findings = vec![
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 20,
                description: "Structural A".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 15,
                description: "Structural B".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Low,
                weight: 15,
                description: "Structural C".into(),
                technical_detail: None,
            },
        ];
        let (score, _, _) = aggregate_score(&mut findings, 0, 0, &FrameworkMitigation::none());
        // After cap, structural contribution should be ≤30.
        let structural_total: u32 = findings
            .iter()
            .filter(|f| f.layer == Layer::StructuralAnalysis)
            .map(|f| f.weight)
            .sum();
        assert!(
            structural_total <= 30,
            "Structural cap should limit to 30, got {structural_total}"
        );
        assert!(score <= 30, "Total score should be ≤30, got {score}");
    }

    #[test]
    fn test_yara_cap() {
        // 3 YARA findings totaling weight 60; cap is 40.
        let mut findings = vec![
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::High,
                weight: 25,
                description: "YARA match A".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::Medium,
                weight: 20,
                description: "YARA match B".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::Medium,
                weight: 15,
                description: "YARA match C".into(),
                technical_detail: None,
            },
        ];
        let (score, _, _) = aggregate_score(&mut findings, 0, 0, &FrameworkMitigation::none());
        let yara_total: u32 = findings
            .iter()
            .filter(|f| f.layer == Layer::YaraRules)
            .map(|f| f.weight)
            .sum();
        assert!(
            yara_total <= 40,
            "YARA cap should limit to 40, got {yara_total}"
        );
        assert!(score <= 40, "Total score should be ≤40, got {score}");
    }

    // ═══════════════════════════════════════════════════════════════════
    // C) Confidence label tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_confidence_trusted_signed() {
        let label = ConfidenceLabel::from_context(0, true, true, false);
        assert_eq!(label, ConfidenceLabel::Trusted);
    }

    #[test]
    fn test_confidence_unusual_unsigned() {
        let label = ConfidenceLabel::from_context(20, false, false, false);
        assert_eq!(label, ConfidenceLabel::Unusual);
    }

    #[test]
    fn test_confidence_suspicious() {
        let label = ConfidenceLabel::from_context(50, false, false, false);
        assert_eq!(label, ConfidenceLabel::Suspicious);
    }

    // ═══════════════════════════════════════════════════════════════════
    // D) Context amplification tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_context_gate_blocks_low_score() {
        use std::path::PathBuf;
        let path = PathBuf::from("C:\\Users\\Test\\Downloads\\something.exe");
        let findings = crate::layers::context::analyze(&path, 3);
        assert!(
            findings.is_empty(),
            "Context gate should block score < 5, got {} findings",
            findings.len()
        );
    }

    #[test]
    fn test_context_gate_allows_above() {
        use std::path::PathBuf;
        // Use a path that triggers context (Downloads + exe).
        let path = PathBuf::from("C:\\Users\\Test\\Downloads\\suspicious.exe");
        let findings = crate::layers::context::analyze(&path, 10);
        // Downloads path with existing_score=10 should produce findings.
        assert!(
            !findings.is_empty(),
            "Context should amplify score >= 5 in Downloads"
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // E) Framework detection test
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_framework_detection() {
        let findings = vec![Finding {
            layer: Layer::PackerDetection,
            severity: Severity::Medium,
            weight: 10,
            description: "PyInstaller bundled executable detected".into(),
            technical_detail: None,
        }];
        let framework = detect_framework_from_findings(&findings);
        assert_eq!(framework, Some("PyInstaller".to_string()));
    }

    #[test]
    fn test_aggregate_score_with_installer() {
        let mut findings = vec![Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Low,
            weight: 10,
            description: "Structural finding".into(),
            technical_detail: None,
        }];

        let fm = FrameworkMitigation::evaluate(structural_nsis_detection(), &mut findings);
        assert!(fm.applied);
        assert_eq!(findings[0].weight, 10 / 3, "Structural findings divide by 3");

        let (_, _, expl) = aggregate_score(&mut findings, 0, 0, &fm);
        assert!(expl.installer_discount_applied);
        // Trust reason must cite the framework kind and what was divided.
        assert!(
            expl.trust_reasons
                .iter()
                .any(|r| r.contains("Installer") && r.contains("NSIS")),
            "trust reason must cite kind + division: {:?}",
            expl.trust_reasons
        );
        assert!(expl.framework_mitigation.is_some());
    }

    #[test]
    fn test_installer_detection() {
        // Every positive case below asserted the OLD substring semantics
        // (is_known_installer == true → /3 + /2 discount). Those positives
        // are now INTENTIONALLY NEGATIVE for mitigation: unanchored markers
        // are attacker-controlled decoration, so the detections they produce
        // are WeakHint-at-most and never mitigation_safe. The structural
        // positives live in the framework detector suites (nsis.rs, inno.rs,
        // wix.rs) and the mitigation_* tests below.
        let weak_at_most = |data: &[u8], path: &str| {
            let d = layers::framework::detect(data, path);
            assert!(
                d.confidence() <= Confidence::WeakHint,
                "{path}: {:?} must not exceed WeakHint",
                d.confidence()
            );
            assert!(!d.mitigation_safe(), "{path} must never be mitigation_safe");
            d
        };

        // NSIS version-info text — the classic spoof needle.
        let mut nsis_data = vec![0x4D, 0x5A]; // MZ header.
        nsis_data.extend_from_slice(&[0; 500]);
        nsis_data.extend_from_slice(b"Nullsoft Inst");
        weak_at_most(&nsis_data, "test.exe");

        // InnoSetup marker text.
        let mut inno_data = vec![0x4D, 0x5A];
        inno_data.extend_from_slice(&[0; 500]);
        inno_data.extend_from_slice(b"Inno Setup S");
        weak_at_most(&inno_data, "test.exe");

        // Filename-based: large PE + installer name + a generic body hint →
        // WeakHint GenericFramework (was: full discount — flipped, see
        // name_only_installer_requires_content_hint).
        let mut large_data = vec![0u8; 3_000_000];
        large_data[0] = 0x4D; // M
        large_data[1] = 0x5A; // Z
        large_data.extend_from_slice(b"uninstall");
        let d = weak_at_most(&large_data, "Notion Setup 7.6.1.exe");
        assert_eq!(d.kind(), FrameworkKind::GenericFramework);
        let d = weak_at_most(&large_data, "git-2.53.0-installer.exe");
        assert_eq!(d.kind(), FrameworkKind::GenericFramework);

        // Name + size + PE but NO installer body hint → not even a hint.
        let mut renamed = vec![0u8; 3_000_000];
        renamed[0] = 0x4D;
        renamed[1] = 0x5A;
        assert_eq!(
            layers::framework::detect(&renamed, "setup.exe").kind(),
            FrameworkKind::Unknown
        );

        // Large non-PE with installer name → nothing (PE gate preserved).
        let large_non_pe = vec![0u8; 3_000_000];
        assert_eq!(
            layers::framework::detect(&large_non_pe, "setup-files.zip").kind(),
            FrameworkKind::Unknown
        );

        // Small file with installer name → nothing.
        assert_eq!(
            layers::framework::detect(&[0x4D, 0x5A], "setup.exe").kind(),
            FrameworkKind::Unknown
        );
        assert_eq!(
            layers::framework::detect(&[0x4D, 0x5A], "malware.exe").kind(),
            FrameworkKind::Unknown
        );

        // Electron marker text → WeakHint ElectronBundle (was: full
        // discount — flipped: "electron.asar" is a 13-byte embeddable string).
        let mut electron_data = vec![0x4D, 0x5A];
        electron_data.extend_from_slice(&[0u8; 500]);
        electron_data.extend_from_slice(b"electron.asar");
        let d = weak_at_most(&electron_data, "app.exe");
        assert_eq!(d.kind(), FrameworkKind::ElectronBundle);
    }

    #[test]
    fn test_explanation_has_weights() {
        // High-weight findings should show [+N] prefix in explanations.
        // Uses IOC layer which has no category cap in aggregate_score.
        let mut findings = vec![Finding {
            layer: Layer::IocCorrelation,
            severity: Severity::Critical,
            weight: 35,
            description: "Critical IOC match detected".into(),
            technical_detail: None,
        }];
        let (_, _, expl) = aggregate_score(&mut findings, 0, 0, &FrameworkMitigation::none());
        assert!(
            expl.suspicion_reasons[0].starts_with("[+35]"),
            "High-weight reason should have weight prefix, got: {}",
            expl.suspicion_reasons[0]
        );
    }

    #[test]
    fn test_ioc_match_is_malicious_strength() {
        let mut findings = vec![Finding {
            layer: Layer::IocCorrelation,
            severity: Severity::Critical,
            weight: 90,
            description: "File hash matches a known-malicious indicator of compromise (IOC)."
                .into(),
            technical_detail: None,
        }];
        let (score, verdict, expl) = aggregate_score(&mut findings, 0, 0, &FrameworkMitigation::none());
        assert_eq!(score, 90);
        assert_eq!(verdict, Verdict::Malicious);
        assert_eq!(expl.confidence_label, ConfidenceLabel::HighRisk);
        assert_eq!(expl.threat_maturity, ThreatMaturity::ActiveMalware);
    }

    #[test]
    fn test_yara_rules_compile_cleanly() {
        // Verify all YARA rules in the runtime directory compile.
        let dirs = [std::path::PathBuf::from("../../runtime/argus/rules/yara")];
        let existing_dirs: Vec<_> = dirs.iter().filter(|d| d.exists()).cloned().collect();
        if existing_dirs.is_empty() {
            // Skip in CI where runtime dir may not exist.
            return;
        }
        let yara = crate::layers::yara::YaraEngine::new();
        let result = yara.load_rules(&existing_dirs);
        match result {
            Ok(count) => {
                assert!(count >= 100, "Expected at least 100 rules, got {count}");
                println!("YARA: {count} rules compiled successfully");
            }
            Err(e) => panic!("YARA compilation failed: {e}"),
        }
    }

    #[test]
    fn test_context_suppressed_for_trusted() {
        // Verify that trust_suppresses_context logic works:
        // When reputation or authenticode discount >= 15, context should not amplify.
        // Test via aggregate_score — if context was added, score would be higher.
        let mut findings = vec![Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Low,
            weight: 5,
            description: "Minor structural finding".into(),
            technical_detail: None,
        }];

        // Without trust discount — score = 5.
        let (score_no_trust, _, _) = aggregate_score(&mut findings, 0, 0, &FrameworkMitigation::none());
        assert_eq!(score_no_trust, 5);

        // With trust discount >= 15 — score should be 0 (5 - 15 = 0, clamped).
        let (score_trusted, _, _) = aggregate_score(&mut findings, 20, 0, &FrameworkMitigation::none());
        assert_eq!(
            score_trusted, 0,
            "Trusted binary should have score 0 after discount"
        );
    }

    // ── Invariant tests ────────────────────────────────────

    #[test]
    fn test_invariant_context_alone_never_threat() {
        // Context findings with weight 15 (max) + no other findings.
        // Even at max context, score < 76 (Malicious threshold).
        let mut findings = vec![Finding {
            layer: Layer::Context,
            severity: Severity::Medium,
            weight: 15,
            description: "Internet download context".into(),
            technical_detail: None,
        }];
        let (score, verdict, _) = aggregate_score(&mut findings, 0, 0, &FrameworkMitigation::none());
        assert!(
            score < 76,
            "Context alone should never reach Malicious. Score: {score}"
        );
        assert_ne!(verdict, Verdict::Malicious);
    }

    #[test]
    fn test_invariant_structural_alone_never_quarantine() {
        // Max structural cap (30) + max packer cap (20) = 50.
        // Even with every structural finding, still below 76.
        let mut findings = vec![
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 20,
                description: "S1".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 20,
                description: "S2".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Low,
                weight: 10,
                description: "S3".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::PackerDetection,
                severity: Severity::Medium,
                weight: 15,
                description: "P1".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::PackerDetection,
                severity: Severity::Low,
                weight: 10,
                description: "P2".into(),
                technical_detail: None,
            },
        ];
        let (score, verdict, _) = aggregate_score(&mut findings, 0, 0, &FrameworkMitigation::none());
        assert!(
            score <= 50,
            "Structural+packer alone capped at 50. Score: {score}"
        );
        assert_ne!(verdict, Verdict::Malicious);
    }

    #[test]
    fn test_invariant_signed_installer_never_malicious() {
        // Signed installer with structural noise — trust should suppress.
        let mut findings = vec![
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 15,
                description: "S1".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Low,
                weight: 8,
                description: "S2".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::PackerDetection,
                severity: Severity::Low,
                weight: 5,
                description: "P1".into(),
                technical_detail: None,
            },
        ];
        // Signed (25 discount) + reputation (20 discount) → max(25,20)=25 off.
        let (score, verdict, _) = aggregate_score(&mut findings, 20, 25, &applied_mitigation_stub());
        assert!(
            score < 76,
            "Signed installer should never be Malicious. Score: {score}"
        );
        assert_ne!(verdict, Verdict::Malicious);
    }

    #[test]
    fn test_multi_layer_stealer_crosses_threshold() {
        // Real stealer: YARA match + pattern match + structural.
        // Must cross Malicious threshold despite category caps.
        let mut findings = vec![
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::High,
                weight: 30,
                description: "Discord token stealer".into(),
                technical_detail: Some("Pack: stealers".into()),
            },
            Finding {
                layer: Layer::PatternDetection,
                severity: Severity::High,
                weight: 25,
                description: "Credential theft pattern".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 15,
                description: "Process injection imports".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::Context,
                severity: Severity::Medium,
                weight: 10,
                description: "Discord CDN download".into(),
                technical_detail: None,
            },
        ];
        let (score, _, _) = aggregate_score(&mut findings, 0, 0, &FrameworkMitigation::none());
        // YARA capped 30→30, Pattern capped 25→25, Structural capped 15→15, Context capped 10→10 = 80
        assert!(
            score >= 76,
            "Multi-layer stealer must cross Malicious threshold. Score: {score}"
        );
    }

    #[test]
    fn test_evidence_deduplication_same_layer() {
        // Two findings from SAME layer with SAME behavior tag → deduplicated.
        let mut findings = vec![
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 12,
                description: "Downloads remote content via URLDownloadToFileA".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Low,
                weight: 6,
                description: "InternetOpenUrlA download import".into(),
                technical_detail: None,
            },
        ];
        let (score, _, _) = aggregate_score(&mut findings, 0, 0, &FrameworkMitigation::none());
        // Same layer + same tag → only max (12) counts.
        assert!(
            score <= 12,
            "Same-layer same-tag findings should be deduplicated. Score: {score}"
        );
    }

    #[test]
    fn test_evidence_cross_layer_convergence() {
        // Two findings from DIFFERENT layers with same behavior tag → both count.
        // This is convergence: independent detections agreeing = higher confidence.
        let mut findings = vec![
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::High,
                weight: 25,
                description: "Credential theft pattern (YARA)".into(),
                technical_detail: Some("Pack: stealers".into()),
            },
            Finding {
                layer: Layer::PatternDetection,
                severity: Severity::High,
                weight: 20,
                description: "Credential theft indicators detected".into(),
                technical_detail: None,
            },
        ];
        let (score, _, _) = aggregate_score(&mut findings, 0, 0, &FrameworkMitigation::none());
        // Different layers → convergence → both count: 25 + 20 = 45.
        assert!(
            score >= 40,
            "Cross-layer convergence must count. Score: {score}"
        );
    }

    #[test]
    fn test_evidence_unique_findings_preserved() {
        // Two findings describing DIFFERENT behaviors → both counted.
        let mut findings = vec![
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::High,
                weight: 25,
                description: "Discord token stealer pattern".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 15,
                description: "Process injection imports detected".into(),
                technical_detail: None,
            },
        ];
        let (score, _, _) = aggregate_score(&mut findings, 0, 0, &FrameworkMitigation::none());
        // Different behaviors → both counted.
        assert_eq!(
            score, 40,
            "Unique behaviors should both count. Score: {score}"
        );
    }

    #[test]
    fn test_go_binary_installer_detection() {
        // Go binary (PE, >3MB with "Go build ID:" marker) is still DETECTED,
        // but as a diagnostic WeakHint granting NO mitigation — INTENTIONAL
        // CHANGE (was: full framework treatment). "Go build ID:" is a
        // 12-byte string any binary can embed, so the old discount was the
        // same evasion primitive as the NSIS needle. Accepted FP cost: legit
        // unsigned Go apps may score higher (Suspicious labels), but the
        // daemon's ARGUS-only quarantine bar is 85 — no auto-quarantine
        // shift. Restoring leniency requires a structural Go detector.
        let mut data = vec![0u8; 4_000_000];
        data[0] = 0x4D; // 'M'
        data[1] = 0x5A; // 'Z'
        data[1000..1012].copy_from_slice(b"Go build ID:");
        let d = layers::framework::detect(&data, "mytool.exe");
        assert_eq!(d.kind(), FrameworkKind::GoStatic);
        assert_eq!(d.confidence(), Confidence::WeakHint);
        assert!(!d.mitigation_safe());
        assert!(!mitigation_applied(&data, "mytool.exe"));
    }

    #[test]
    fn test_confidence_label_framework_unsigned() {
        // Unsigned framework binary at score 45 → should be Unusual (not Suspicious)
        // if installer detected.
        let label = ConfidenceLabel::from_context(45, false, false, true);
        assert_eq!(
            label,
            ConfidenceLabel::Unusual,
            "Unsigned installer at score 45 should be Unusual"
        );
    }

    #[test]
    fn test_confidence_label_signed_installer_trusted() {
        // Signed installer at residual score 10 → Trusted.
        let label = ConfidenceLabel::from_context(10, true, true, true);
        assert_eq!(
            label,
            ConfidenceLabel::Trusted,
            "Signed installer should be Trusted"
        );
    }

    // ── Malware chain regression tests ─────────────────────

    #[test]
    fn test_stealer_chain_credential_plus_exfil() {
        // Credential theft + exfiltration are DIFFERENT behaviors → both counted.
        let mut findings = vec![
            Finding {
                layer: Layer::PatternDetection,
                severity: Severity::High,
                weight: 25,
                description: "Credential theft: Login Data and browser cookies accessed".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::High,
                weight: 22,
                description: "Data exfiltration via Discord webhook".into(),
                technical_detail: Some("Pack: stealer_exfil".into()),
            },
            Finding {
                layer: Layer::Context,
                severity: Severity::Medium,
                weight: 10,
                description: "Downloaded from Discord CDN".into(),
                technical_detail: None,
            },
        ];
        let (score, _, _) = aggregate_score(&mut findings, 0, 0, &FrameworkMitigation::none());
        // All three are different groups → all counted.
        // Pattern 25 (capped 25), YARA 22 (capped 22), Context 10 (capped 10) = 57
        assert!(
            score >= 50,
            "Stealer chain must maintain high score. Score: {score}"
        );
    }

    #[test]
    fn test_ransomware_chain_encrypt_plus_delete() {
        // Ransomware: file enumeration + encryption + shadow copy deletion.
        let mut findings = vec![
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::Critical,
                weight: 35,
                description: "Ransomware behavior: file encryption and ransom note creation".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::PatternDetection,
                severity: Severity::High,
                weight: 20,
                description: "Process kill list targeting security software".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 15,
                description: "Process injection imports detected".into(),
                technical_detail: None,
            },
        ];
        let (score, _, _) = aggregate_score(&mut findings, 0, 0, &FrameworkMitigation::none());
        // Different behaviors → all counted. 35+20+15 = 70 (under caps).
        assert!(
            score >= 65,
            "Ransomware chain must remain high risk. Score: {score}"
        );
    }

    #[test]
    fn test_downloader_only_not_malicious() {
        // Just downloader capability — suspicious but not malicious.
        let mut findings = vec![
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Low,
                weight: 8,
                description: "URLDownloadToFileA import detected".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::Medium,
                weight: 15,
                description: "File downloads remote content via HTTP".into(),
                technical_detail: None,
            },
        ];
        let (score, verdict, _) = aggregate_score(&mut findings, 0, 0, &FrameworkMitigation::none());
        // Deduplicated: both are "downloader_capability" → only max (15) counts.
        assert!(
            score < 76,
            "Downloader-only should not be Malicious. Score: {score}"
        );
        assert_ne!(verdict, Verdict::Malicious);
    }

    #[test]
    fn test_packer_only_not_malicious() {
        // Just packing indicators — unusual but not malicious.
        // Cross-layer convergence: PackerDetection + Structural both detect packing → both count.
        let mut findings = vec![
            Finding {
                layer: Layer::PackerDetection,
                severity: Severity::Medium,
                weight: 15,
                description: "UPX packed executable".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Low,
                weight: 6,
                description: "Section has packed characteristics".into(),
                technical_detail: None,
            },
        ];
        let (score, verdict, _) = aggregate_score(&mut findings, 0, 0, &FrameworkMitigation::none());
        // Cross-layer convergence: 15 + 6 = 21. Still well below Malicious (76).
        assert!(score <= 25, "Packer-only should be low. Score: {score}");
        assert_ne!(verdict, Verdict::Malicious);
    }

    #[test]
    fn test_context_not_deduplicated_with_downloader() {
        // "Downloaded from internet" (context) + "has download APIs" (structural)
        // must NOT be deduplicated — they're different signals.
        let mut findings = vec![
            Finding {
                layer: Layer::Context,
                severity: Severity::Low,
                weight: 5,
                description: "Downloaded from the internet (Zone.Identifier)".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Low,
                weight: 8,
                description: "URLDownloadToFileA import — downloads remote content".into(),
                technical_detail: None,
            },
        ];
        let (score, _, _) = aggregate_score(&mut findings, 0, 0, &FrameworkMitigation::none());
        // Context is never deduplicated. Both count: 5 + 8 = 13.
        assert_eq!(
            score, 13,
            "Context + downloader must both count. Score: {score}"
        );
    }

    #[test]
    fn test_credential_theft_and_exfil_both_count() {
        // Credential theft + exfiltration are different attack stages → both count.
        let mut findings = vec![
            Finding {
                layer: Layer::PatternDetection,
                severity: Severity::High,
                weight: 20,
                description: "Credential theft indicators detected".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::High,
                weight: 18,
                description: "Data exfiltration via Telegram Bot API".into(),
                technical_detail: None,
            },
        ];
        let (score, _, _) = aggregate_score(&mut findings, 0, 0, &FrameworkMitigation::none());
        assert_eq!(
            score, 38,
            "Credential theft + exfil must both count. Score: {score}"
        );
    }

    #[test]
    fn test_fake_updater_unsigned_crosses_threshold() {
        // Fake updater: downloader + persistence + evasion + unsigned + context.
        let mut findings = vec![
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::High,
                weight: 20,
                description: "Fake updater with download and execution".into(),
                technical_detail: Some("Pack: suspicious_updater".into()),
            },
            Finding {
                layer: Layer::PatternDetection,
                severity: Severity::High,
                weight: 20,
                description: "Persistence via registry Run key".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 12,
                description: "Anti-debugging checks detected".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::Context,
                severity: Severity::Medium,
                weight: 12,
                description: "Downloaded from link monetizer".into(),
                technical_detail: None,
            },
        ];
        let (score, _, _) = aggregate_score(&mut findings, 0, 0, &FrameworkMitigation::none());
        // Different groups: downloader(20) + persistence(20) + evasion(12) + context(12) = 64
        // No trust discounts → 64. Not auto-quarantine (ARGUS-only needs 85) but high suspicion.
        assert!(
            score >= 50,
            "Fake updater chain must be high risk. Score: {score}"
        );
    }

    #[test]
    fn test_entropy_dedup_within_structural() {
        // Two entropy findings from structural layer → deduplicated.
        let mut findings = vec![
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Low,
                weight: 6,
                description: "Section has near-random entropy (7.8/8.0)".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 12,
                description: "Resource section contains high-entropy encrypted payload".into(),
                technical_detail: None,
            },
        ];
        let (score, _, _) = aggregate_score(&mut findings, 0, 0, &FrameworkMitigation::none());
        // Both are "entropy" group, same layer → only max (12) counts.
        assert!(
            score <= 12,
            "Entropy findings should be deduplicated. Score: {score}"
        );
    }

    // ── BehaviorTag tests ──────────────────────────────────

    #[test]
    fn test_behavior_tag_context_is_origin() {
        let f = Finding {
            layer: Layer::Context,
            severity: Severity::Low,
            weight: 5,
            description: "Downloaded from internet".into(),
            technical_detail: None,
        };
        assert_eq!(f.behavior_tag(), Some(BehaviorTag::DownloadOriginContext));
    }

    #[test]
    fn test_behavior_tag_packer_detection() {
        let f = Finding {
            layer: Layer::PackerDetection,
            severity: Severity::Medium,
            weight: 10,
            description: "UPX packed binary".into(),
            technical_detail: None,
        };
        assert_eq!(f.behavior_tag(), Some(BehaviorTag::Packing));
    }

    #[test]
    fn test_behavior_tag_yara_stealer() {
        let f = Finding {
            layer: Layer::YaraRules,
            severity: Severity::High,
            weight: 25,
            description: "Discord stealer".into(),
            technical_detail: Some("Pack: stealers".into()),
        };
        assert_eq!(f.behavior_tag(), Some(BehaviorTag::CredentialTheft));
    }

    #[test]
    fn test_behavior_tag_yara_exfil() {
        let f = Finding {
            layer: Layer::YaraRules,
            severity: Severity::High,
            weight: 20,
            description: "Webhook exfil".into(),
            technical_detail: Some("Pack: stealer_exfil".into()),
        };
        assert_eq!(f.behavior_tag(), Some(BehaviorTag::Exfiltration));
    }

    #[test]
    fn test_behavior_tag_yara_c2() {
        let f = Finding {
            layer: Layer::YaraRules,
            severity: Severity::High,
            weight: 20,
            description: "C2 beacon".into(),
            technical_detail: Some("Pack: c2_indicators".into()),
        };
        assert_eq!(f.behavior_tag(), Some(BehaviorTag::C2Communication));
    }

    #[test]
    fn test_behavior_tag_yara_ransomware() {
        let f = Finding {
            layer: Layer::YaraRules,
            severity: Severity::Critical,
            weight: 35,
            description: "Ransom note".into(),
            technical_detail: Some("Pack: ransomware".into()),
        };
        assert_eq!(f.behavior_tag(), Some(BehaviorTag::Ransomware));
    }

    #[test]
    fn test_behavior_tag_structural_entropy() {
        let f = Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Low,
            weight: 6,
            description: "Near-random entropy section".into(),
            technical_detail: None,
        };
        assert_eq!(f.behavior_tag(), Some(BehaviorTag::Entropy));
    }

    #[test]
    fn test_behavior_tag_structural_injection() {
        let f = Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::High,
            weight: 30,
            description: "Process injection triad imports".into(),
            technical_detail: None,
        };
        assert_eq!(f.behavior_tag(), Some(BehaviorTag::Injection));
    }

    #[test]
    fn test_behavior_tag_unique_finding() {
        // Generic structural finding with no specific behavior → None (always counted).
        let f = Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Info,
            weight: 3,
            description: "Small import table".into(),
            technical_detail: None,
        };
        assert_eq!(f.behavior_tag(), None);
    }

    #[test]
    fn test_behavior_tag_script_abuse() {
        let f = Finding {
            layer: Layer::YaraRules,
            severity: Severity::High,
            weight: 25,
            description: "PowerShell download cradle".into(),
            technical_detail: Some("Pack: powershell_advanced".into()),
        };
        assert_eq!(f.behavior_tag(), Some(BehaviorTag::ScriptAbuse));
    }

    // ── Convergence + confidence tests ─────────────────────

    #[test]
    fn test_convergence_stealer_chain() {
        use crate::verdict::ChainStrength;
        let findings = vec![
            Finding {
                layer: Layer::PatternDetection,
                severity: Severity::High,
                weight: 25,
                description: "Credential theft indicators".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::High,
                weight: 20,
                description: "Exfiltration webhook".into(),
                technical_detail: Some("Pack: stealer_exfil".into()),
            },
        ];
        let conv = compute_convergence(&findings);
        assert_eq!(
            conv.chain_strength,
            ChainStrength::Strong,
            "CredentialTheft + Exfiltration = Strong chain"
        );
        assert!(conv.chain_names.contains(&"stealer"));
        assert!(conv.distinct_behaviors >= 2);
    }

    #[test]
    fn test_convergence_backdoor_chain() {
        use crate::verdict::ChainStrength;
        let findings = vec![
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::High,
                weight: 20,
                description: "Persistence via registry".into(),
                technical_detail: Some("Pack: persistence".into()),
            },
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::High,
                weight: 18,
                description: "C2 beacon communication".into(),
                technical_detail: Some("Pack: c2_indicators".into()),
            },
        ];
        let conv = compute_convergence(&findings);
        assert_eq!(
            conv.chain_strength,
            ChainStrength::Strong,
            "Persistence + C2 = Strong chain"
        );
        assert!(conv.chain_names.contains(&"backdoor"));
    }

    #[test]
    fn test_convergence_fake_installer_moderate() {
        use crate::verdict::ChainStrength;
        let findings = vec![
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::High,
                weight: 20,
                description: "Fake updater detected".into(),
                technical_detail: Some("Pack: suspicious_updater".into()),
            },
            Finding {
                layer: Layer::PatternDetection,
                severity: Severity::Medium,
                weight: 15,
                description: "Persistence via registry Run key".into(),
                technical_detail: None,
            },
        ];
        let conv = compute_convergence(&findings);
        assert!(
            conv.chain_strength >= ChainStrength::Moderate,
            "FakeInstaller + Persistence = Moderate+"
        );
    }

    #[test]
    fn test_convergence_script_malware_moderate() {
        use crate::verdict::ChainStrength;
        let findings = vec![
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::High,
                weight: 25,
                description: "PowerShell download cradle".into(),
                technical_detail: Some("Pack: powershell_advanced".into()),
            },
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Low,
                weight: 8,
                description: "Downloads remote content via InternetOpenUrlA".into(),
                technical_detail: None,
            },
        ];
        let conv = compute_convergence(&findings);
        assert!(
            conv.chain_strength >= ChainStrength::Moderate,
            "ScriptAbuse + Downloader = Moderate+"
        );
    }

    #[test]
    fn test_convergence_weak_downloader_only() {
        use crate::verdict::ChainStrength;
        let findings = vec![Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Low,
            weight: 8,
            description: "URLDownloadToFileA import — downloads remote content".into(),
            technical_detail: None,
        }];
        let conv = compute_convergence(&findings);
        assert!(
            conv.chain_strength <= ChainStrength::Weak,
            "Downloader-only = Weak or None"
        );
    }

    #[test]
    fn test_confidence_single_category_not_highrisk() {
        use crate::verdict::{ChainStrength, ConvergenceInfo};
        let conv = ConvergenceInfo {
            distinct_behaviors: 1,
            distinct_layers: 1,
            chain_strength: ChainStrength::None,
            chain_names: vec![],
            progression_score: 0,
        };
        let label = ConfidenceLabel::from_convergence(80, false, false, false, &conv);
        assert_eq!(
            label,
            ConfidenceLabel::Suspicious,
            "Single-category score 80 should be Suspicious, not HighRisk"
        );
    }

    #[test]
    fn test_confidence_strong_chain_promotes_highrisk() {
        use crate::verdict::{ChainStrength, ConvergenceInfo};
        let conv = ConvergenceInfo {
            distinct_behaviors: 3,
            distinct_layers: 2,
            chain_strength: ChainStrength::Strong,
            chain_names: vec!["stealer"],
            progression_score: 2,
        };
        let label = ConfidenceLabel::from_convergence(55, false, false, false, &conv);
        assert_eq!(
            label,
            ConfidenceLabel::HighRisk,
            "Score 55 + Strong chain + 3 behaviors → HighRisk"
        );
    }

    #[test]
    fn test_confidence_high_score_strong_convergence_malicious() {
        use crate::verdict::{ChainStrength, ConvergenceInfo};
        let conv = ConvergenceInfo {
            distinct_behaviors: 4,
            distinct_layers: 3,
            chain_strength: ChainStrength::Strong,
            chain_names: vec!["stealer"],
            progression_score: 2,
        };
        let label = ConfidenceLabel::from_convergence(95, false, false, false, &conv);
        assert_eq!(
            label,
            ConfidenceLabel::Malicious,
            "Score 95 + Strong chain + 4 behaviors → Malicious"
        );
    }

    #[test]
    fn test_confidence_high_score_weak_convergence_highrisk() {
        use crate::verdict::{ChainStrength, ConvergenceInfo};
        let conv = ConvergenceInfo {
            distinct_behaviors: 1,
            distinct_layers: 1,
            chain_strength: ChainStrength::None,
            chain_names: vec![],
            progression_score: 0,
        };
        let label = ConfidenceLabel::from_convergence(95, false, false, false, &conv);
        assert_eq!(
            label,
            ConfidenceLabel::HighRisk,
            "Score 95 + weak convergence → HighRisk, not Malicious label"
        );
    }

    #[test]
    fn test_convergence_wallet_theft_chain() {
        use crate::verdict::ChainStrength;
        let findings = vec![
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::High,
                weight: 20,
                description: "Crypto wallet theft".into(),
                technical_detail: Some("Pack: crypto_threats".into()),
            },
            Finding {
                layer: Layer::PatternDetection,
                severity: Severity::High,
                weight: 18,
                description: "Credential theft: browser cookies".into(),
                technical_detail: None,
            },
        ];
        let conv = compute_convergence(&findings);
        assert_eq!(
            conv.chain_strength,
            ChainStrength::Strong,
            "WalletTheft + CredentialTheft = Strong"
        );
    }

    #[test]
    fn test_weak_diverse_tags_not_auto_highrisk() {
        // Many weak unrelated tags should NOT auto-promote to HighRisk.
        use crate::verdict::{ChainStrength, ConvergenceInfo};
        let conv = ConvergenceInfo {
            distinct_behaviors: 5,
            distinct_layers: 2,
            chain_strength: ChainStrength::Weak,
            chain_names: vec![],
            progression_score: 0,
        };
        let label = ConfidenceLabel::from_convergence(50, false, false, false, &conv);
        // 5 behaviors but only Weak chain → Suspicious, not HighRisk.
        assert_eq!(
            label,
            ConfidenceLabel::Suspicious,
            "Many weak tags at score 50 should be Suspicious, not HighRisk"
        );
    }

    #[test]
    fn test_score_70_with_strong_chain_highrisk() {
        use crate::verdict::{ChainStrength, ConvergenceInfo};
        let conv = ConvergenceInfo {
            distinct_behaviors: 3,
            distinct_layers: 3,
            chain_strength: ChainStrength::Strong,
            chain_names: vec!["stealer"],
            progression_score: 2,
        };
        let label = ConfidenceLabel::from_convergence(70, false, false, false, &conv);
        assert_eq!(
            label,
            ConfidenceLabel::HighRisk,
            "Score 70 + Strong chain → HighRisk"
        );
    }

    #[test]
    fn test_yara_category_backdoor_maps_to_c2() {
        let f = Finding {
            layer: Layer::YaraRules,
            severity: Severity::High,
            weight: 30,
            description: "RAT behavior".into(),
            technical_detail: Some("Pack: backdoor".into()),
        };
        assert_eq!(f.behavior_tag(), Some(BehaviorTag::C2Communication));
    }

    #[test]
    fn test_yara_category_miner_maps_to_pua() {
        // Crypto miners are PUA (potentially unwanted), not wallet theft.
        let f = Finding {
            layer: Layer::YaraRules,
            severity: Severity::Medium,
            weight: 15,
            description: "Crypto mining".into(),
            technical_detail: Some("Pack: miner".into()),
        };
        assert_eq!(f.behavior_tag(), Some(BehaviorTag::PotentiallyUnwanted));
    }

    #[test]
    fn test_yara_category_spyware_maps_to_credential() {
        let f = Finding {
            layer: Layer::YaraRules,
            severity: Severity::High,
            weight: 20,
            description: "Keylogger".into(),
            technical_detail: Some("Pack: spyware".into()),
        };
        assert_eq!(f.behavior_tag(), Some(BehaviorTag::CredentialTheft));
    }

    // ── Attack progression tests ───────────────────────────

    #[test]
    fn test_progression_score_coherent_chain() {
        // InitialAccess → Execution → CredentialAccess → Exfiltration = 3 transitions.
        let tags = vec![
            BehaviorTag::DownloaderCapability, // InitialAccess (0)
            BehaviorTag::ScriptAbuse,          // Execution (1)
            BehaviorTag::CredentialTheft,      // CredentialAccess (4)
            BehaviorTag::Exfiltration,         // Exfiltration (6)
        ];
        let score = crate::verdict::attack_progression_score(&tags);
        assert!(
            score >= 2,
            "Coherent 4-stage chain should have progression ≥2. Got: {score}"
        );
    }

    #[test]
    fn test_progression_score_single_stage() {
        // All DefenseEvasion → no transitions.
        let tags = vec![
            BehaviorTag::Packing,
            BehaviorTag::Entropy,
            BehaviorTag::Evasion,
        ];
        let score = crate::verdict::attack_progression_score(&tags);
        assert_eq!(score, 0, "Same-stage tags should have 0 progression");
    }

    #[test]
    fn test_progression_score_two_stages() {
        // InitialAccess → Exfiltration = 1 transition (big gap but still 1).
        let tags = vec![BehaviorTag::DownloaderCapability, BehaviorTag::Exfiltration];
        let score = crate::verdict::attack_progression_score(&tags);
        // Gap of 6 stages — too large for "meaningful transition" (gap > 4).
        assert_eq!(score, 0, "Huge gap should not count as transition");
    }

    #[test]
    fn test_progression_close_stages() {
        // InitialAccess(0) → Execution(1) → Persistence(2) = 2 transitions.
        let tags = vec![
            BehaviorTag::FakeInstaller, // InitialAccess (0)
            BehaviorTag::ScriptAbuse,   // Execution (1)
            BehaviorTag::Persistence,   // Persistence (2)
        ];
        let score = crate::verdict::attack_progression_score(&tags);
        assert_eq!(score, 2, "Three consecutive stages = 2 transitions");
    }

    // ── Process lineage tests ──────────────────────────────

    #[test]
    fn test_lineage_office_to_powershell() {
        let hint = crate::verdict::ProcessLineageHint {
            parent: Some("winword.exe".into()),
            process: Some("powershell.exe".into()),
        };
        assert_eq!(
            hint.suspicion_score(),
            15,
            "Office → PowerShell = max suspicion"
        );
    }

    #[test]
    fn test_lineage_explorer_to_installer() {
        let hint = crate::verdict::ProcessLineageHint {
            parent: Some("explorer.exe".into()),
            process: Some("setup.exe".into()),
        };
        assert_eq!(hint.suspicion_score(), 0, "Explorer → installer = normal");
    }

    #[test]
    fn test_lineage_browser_to_temp() {
        let hint = crate::verdict::ProcessLineageHint {
            parent: Some("chrome.exe".into()),
            process: Some("C:\\Users\\user\\AppData\\Local\\Temp\\malware.exe".into()),
        };
        assert_eq!(
            hint.suspicion_score(),
            10,
            "Browser → temp exe = suspicious"
        );
    }

    #[test]
    fn test_lineage_steam_to_game() {
        let hint = crate::verdict::ProcessLineageHint {
            parent: Some("steam.exe".into()),
            process: Some("game.exe".into()),
        };
        assert_eq!(hint.suspicion_score(), 0, "Steam → game = normal");
    }

    #[test]
    fn test_lineage_no_parent() {
        let hint = crate::verdict::ProcessLineageHint {
            parent: None,
            process: Some("something.exe".into()),
        };
        assert_eq!(hint.suspicion_score(), 0, "No parent = no suspicion");
    }

    // ── ThreatMaturity tests ───────────────────────────────

    #[test]
    fn test_maturity_benign() {
        use crate::verdict::{ConvergenceInfo, ThreatMaturity};
        let conv = ConvergenceInfo::default();
        assert_eq!(
            ThreatMaturity::from_convergence(&conv, 0),
            ThreatMaturity::Benign
        );
    }

    #[test]
    fn test_maturity_suspicious_utility() {
        use crate::verdict::{ChainStrength, ConvergenceInfo, ThreatMaturity};
        let conv = ConvergenceInfo {
            chain_strength: ChainStrength::Weak,
            ..Default::default()
        };
        assert_eq!(
            ThreatMaturity::from_convergence(&conv, 25),
            ThreatMaturity::SuspiciousUtility
        );
    }

    #[test]
    fn test_maturity_loader() {
        use crate::verdict::{ChainStrength, ConvergenceInfo, ThreatMaturity};
        let conv = ConvergenceInfo {
            chain_strength: ChainStrength::Moderate,
            chain_names: vec!["fake_installer"],
            ..Default::default()
        };
        assert_eq!(
            ThreatMaturity::from_convergence(&conv, 50),
            ThreatMaturity::Loader
        );
    }

    #[test]
    fn test_maturity_active_malware() {
        use crate::verdict::{ChainStrength, ConvergenceInfo, ThreatMaturity};
        let conv = ConvergenceInfo {
            chain_strength: ChainStrength::Strong,
            chain_names: vec!["stealer"],
            ..Default::default()
        };
        assert_eq!(
            ThreatMaturity::from_convergence(&conv, 80),
            ThreatMaturity::ActiveMalware
        );
    }

    #[test]
    fn test_maturity_destructive() {
        use crate::verdict::{ChainStrength, ConvergenceInfo, ThreatMaturity};
        let conv = ConvergenceInfo {
            chain_strength: ChainStrength::Strong,
            chain_names: vec!["ransomware"],
            ..Default::default()
        };
        assert_eq!(
            ThreatMaturity::from_convergence(&conv, 90),
            ThreatMaturity::DestructiveMalware
        );
    }

    // ── Signed abuse test ──────────────────────────────────

    #[test]
    fn test_signed_malicious_convergence_stays_highrisk() {
        // Signed binary with strong malicious chain → still HighRisk, not Trusted.
        use crate::verdict::{ChainStrength, ConvergenceInfo};
        let conv = ConvergenceInfo {
            distinct_behaviors: 3,
            distinct_layers: 3,
            chain_strength: ChainStrength::Strong,
            chain_names: vec!["backdoor"],
            progression_score: 2,
        };
        // Score 60 + signed → trust would normally make this Unusual.
        // But strong chain overrides trust.
        let label = ConfidenceLabel::from_convergence(60, true, true, false, &conv);
        assert_eq!(
            label,
            ConfidenceLabel::HighRisk,
            "Signed binary with strong malicious chain must be HighRisk"
        );
    }

    #[test]
    fn test_signed_no_chain_stays_trusted() {
        // Signed binary with NO chain → stays trusted.
        use crate::verdict::{ChainStrength, ConvergenceInfo};
        let conv = ConvergenceInfo {
            distinct_behaviors: 1,
            distinct_layers: 1,
            chain_strength: ChainStrength::None,
            chain_names: vec![],
            progression_score: 0,
        };
        let label = ConfidenceLabel::from_convergence(15, true, true, true, &conv);
        assert_eq!(
            label,
            ConfidenceLabel::Trusted,
            "Signed installer with no chain should remain Trusted"
        );
    }

    // ── Scan strategy tests ────────────────────────────────

    #[test]
    fn test_strategy_exe_full() {
        assert_eq!(
            ScanStrategy::classify("malware.exe", 5_000_000),
            ScanStrategy::FullAnalysis
        );
    }

    #[test]
    fn test_strategy_dll_full() {
        assert_eq!(
            ScanStrategy::classify("library.dll", 2_000_000),
            ScanStrategy::FullAnalysis
        );
    }

    #[test]
    fn test_strategy_script_full() {
        assert_eq!(
            ScanStrategy::classify("payload.ps1", 50_000),
            ScanStrategy::FullAnalysis
        );
    }

    #[test]
    fn test_strategy_archive_full() {
        assert_eq!(
            ScanStrategy::classify("archive.zip", 10_000_000),
            ScanStrategy::FullAnalysis
        );
    }

    #[test]
    fn test_strategy_pdf_full() {
        assert_eq!(
            ScanStrategy::classify("document.pdf", 1_000_000),
            ScanStrategy::FullAnalysis
        );
    }

    #[test]
    fn test_strategy_log_skip() {
        assert_eq!(
            ScanStrategy::classify("app.log", 100_000),
            ScanStrategy::SkipSafe
        );
    }

    #[test]
    fn test_strategy_rlib_skip() {
        assert_eq!(
            ScanStrategy::classify("libargus.rlib", 5_000_000),
            ScanStrategy::SkipSafe
        );
    }

    #[test]
    fn test_strategy_json_skip() {
        assert_eq!(
            ScanStrategy::classify("config.json", 10_000),
            ScanStrategy::SkipSafe
        );
    }

    #[test]
    fn test_strategy_image_signature_only() {
        assert_eq!(
            ScanStrategy::classify("photo.jpg", 3_000_000),
            ScanStrategy::SignatureOnly
        );
    }

    #[test]
    fn test_strategy_video_signature_only() {
        assert_eq!(
            ScanStrategy::classify("movie.mp4", 50_000_000),
            ScanStrategy::SignatureOnly
        );
    }

    #[test]
    fn test_strategy_firmware_signature_only() {
        assert_eq!(
            ScanStrategy::classify("firmware.bin", 60_000_000),
            ScanStrategy::SignatureOnly
        );
    }

    #[test]
    fn test_strategy_too_large() {
        assert_eq!(
            ScanStrategy::classify("huge.exe", 200_000_000),
            ScanStrategy::TooLarge
        );
    }

    #[test]
    fn test_strategy_unknown_ext_light() {
        assert_eq!(
            ScanStrategy::classify("something.xyz", 500_000),
            ScanStrategy::LightAnalysis
        );
    }

    #[test]
    fn test_strategy_large_non_exe_signature_only() {
        // 60MB DLL → still full (DLLs are executable)
        assert_eq!(
            ScanStrategy::classify("driver.dll", 60_000_000),
            ScanStrategy::FullAnalysis
        );
        // 60MB DAT → signature only
        assert_eq!(
            ScanStrategy::classify("data.dat", 60_000_000),
            ScanStrategy::SignatureOnly
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // Installer-mitigation scoring integration (workstreams T + U)
    // ═══════════════════════════════════════════════════════════════

    /// (a) Structural NSIS detection → /3 applied to Structural/Packer
    /// findings; the mitigation trace records every op with before/after.
    #[test]
    fn mitigation_structural_nsis_applies_div3_and_records_trace() {
        let data = structural_nsis_pe(200);
        let detection = layers::framework::detect(&data, "setup.exe");
        assert_eq!(detection.kind(), FrameworkKind::Nsis);
        assert_eq!(detection.confidence(), Confidence::Structural);
        assert!(detection.mitigation_safe());

        let mut findings = vec![
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 30,
                description: "high entropy section".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::PackerDetection,
                severity: Severity::Low,
                weight: 15,
                description: "large overlay".into(),
                technical_detail: None,
            },
        ];
        let fm = FrameworkMitigation::evaluate(detection, &mut findings);
        assert!(fm.applied);
        assert!(fm.veto_reason.is_none());
        assert_eq!(findings[0].weight, 10, "Structural /3");
        assert_eq!(findings[1].weight, 5, "Packer /3");
        assert_eq!(fm.ops.len(), 2);
        assert!(fm.ops.iter().any(|op| op.layer == Layer::StructuralAnalysis
            && op.weight_before == 30
            && op.weight_after == 10));
        assert!(fm.ops.iter().any(|op| op.layer == Layer::PackerDetection
            && op.weight_before == 15
            && op.weight_after == 5));
        assert_eq!(fm.score_before, 45);
        assert_eq!(fm.score_after, 15);

        // End-to-end through aggregate_score.
        let (score, _, expl) = aggregate_score(&mut findings, 0, 0, &fm);
        assert_eq!(score, 15);
        assert!(expl.installer_discount_applied);
        assert_eq!(expl.framework.as_deref(), Some("NSIS"));
    }

    /// (b) Appended "Nullsoft Inst" text changes nothing: on a plain PE it
    /// is WeakHint-at-most (no mitigation, weights and score unchanged).
    #[test]
    fn mitigation_appended_marker_text_changes_nothing() {
        use crate::layers::framework::fixtures::PeBuilder;
        let data = PeBuilder::new()
            .section(".text", 0x200, 0x200)
            .overlay(b"Nullsoft Inst")
            .build();
        let detection = layers::framework::detect(&data, "setup.exe");
        assert!(detection.confidence() <= Confidence::WeakHint);
        assert!(!detection.mitigation_safe());

        let mk_findings = || {
            vec![Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 30,
                description: "high entropy section".into(),
                technical_detail: None,
            }]
        };

        let mut f_plain = mk_findings();
        let (score_plain, _, _) =
            aggregate_score(&mut f_plain, 0, 0, &FrameworkMitigation::none());

        let mut f_marked = mk_findings();
        let fm = FrameworkMitigation::evaluate(detection, &mut f_marked);
        assert!(!fm.applied);
        assert_eq!(f_marked[0].weight, 30, "WeakHint must not divide weights");
        let (score_marked, _, _) = aggregate_score(&mut f_marked, 0, 0, &fm);
        assert_eq!(
            score_marked, score_plain,
            "appended installer text must not lower the final score"
        );
    }

    /// (c) A weight-40 finding vetoes mitigation on a structurally valid
    /// installer; the veto is recorded in the trace. A fake marker with the
    /// same finding never qualifies in the first place (fail-closed either
    /// way).
    #[test]
    fn mitigation_high_confidence_finding_vetoes() {
        let data = structural_nsis_pe(200);
        let detection = layers::framework::detect(&data, "setup.exe");
        assert_eq!(detection.confidence(), Confidence::Structural);

        let mut findings = vec![
            Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 30,
                description: "high entropy section".into(),
                technical_detail: None,
            },
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::High,
                weight: 40,
                description: "Ransomware note pattern".into(),
                technical_detail: Some("Pack: ransomware".into()),
            },
        ];
        let fm = FrameworkMitigation::evaluate(detection, &mut findings);
        assert!(!fm.applied, "weight-40 finding must veto mitigation");
        let veto = fm.veto_reason.clone().expect("veto must be recorded");
        assert!(veto.contains("vetoed"), "veto reason: {veto}");
        assert_eq!(
            findings[0].weight, 30,
            "vetoed mitigation must leave weights untouched"
        );
        assert!(fm.provenance().unwrap().veto_reason.is_some());

        // Fake marker + the same weight-40 finding: the detection never
        // qualifies (WeakHint), so there is nothing to veto — also closed.
        use crate::layers::framework::fixtures::PeBuilder;
        let fake = PeBuilder::new()
            .section(".text", 0x200, 0x200)
            .overlay(b"Nullsoft Inst")
            .build();
        let d = layers::framework::detect(&fake, "setup.exe");
        let mut findings2 = vec![Finding {
            layer: Layer::YaraRules,
            severity: Severity::High,
            weight: 40,
            description: "Ransomware note pattern".into(),
            technical_detail: Some("Pack: ransomware".into()),
        }];
        let fm2 = FrameworkMitigation::evaluate(d, &mut findings2);
        assert!(!fm2.applied);
        assert_eq!(findings2[0].weight, 40);
    }

    /// (W) The MIME-45 emitter is covered by the same ≥40 veto: a
    /// structurally valid installer with a genuine MIME/magic mismatch
    /// keeps the full 45 (mitigation must not soften independent
    /// high-confidence evidence). The authenticode system-path −20 is a
    /// trust discount applied independently in aggregate_score — no
    /// interaction with this pass.
    #[test]
    fn mitigation_mime45_finding_vetoes() {
        let data = structural_nsis_pe(200);
        let detection = layers::framework::detect(&data, "setup.exe");
        assert_eq!(detection.confidence(), Confidence::Structural);
        let mut findings = vec![Finding {
            layer: Layer::MimeValidation,
            severity: Severity::High,
            weight: 45,
            description: "File extension does not match magic bytes".into(),
            technical_detail: None,
        }];
        let fm = FrameworkMitigation::evaluate(detection, &mut findings);
        assert!(!fm.applied, "MIME-45 must veto installer mitigation");
        assert!(fm.veto_reason.is_some());
        assert_eq!(findings[0].weight, 45);
    }

    /// (d) NSIS with a CRC mismatch is Corroborated — `mitigation_safe`
    /// under the build() invariant, but mitigation policy 1 requires
    /// Structural confidence, so NO mitigation applies. Tampered/damaged
    /// archives fail conservatively.
    #[test]
    fn mitigation_nsis_crc_mismatch_gets_no_mitigation() {
        let data = nsis_pe_crc_mismatch(200);
        let detection = layers::framework::detect(&data, "setup.exe");
        assert_eq!(detection.kind(), FrameworkKind::Nsis);
        assert_eq!(detection.confidence(), Confidence::Corroborated);
        assert!(
            detection.mitigation_safe(),
            "build() invariant marks Corroborated+structural as safe (diagnostic)"
        );
        assert!(
            detection.warnings().iter().any(|w| w.contains("CRC32 mismatch")),
            "warnings: {:?}",
            detection.warnings()
        );

        let mut findings = vec![Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Medium,
            weight: 30,
            description: "high entropy section".into(),
            technical_detail: None,
        }];
        let fm = FrameworkMitigation::evaluate(detection, &mut findings);
        assert!(
            !fm.applied,
            "Corroborated (tampered) detection must not authorize mitigation"
        );
        assert_eq!(findings[0].weight, 30);
    }

    /// (e) Structural NSIS + installer-class YARA (weight ≤ 25) → /2 still
    /// applies and the veto does NOT trigger: an installer can still be
    /// flagged by ordinary detections — mitigation and conviction are
    /// separate dimensions.
    #[test]
    fn mitigation_installer_class_yara_halved_without_veto() {
        let data = structural_nsis_pe(200);
        let detection = layers::framework::detect(&data, "setup.exe");
        assert_eq!(detection.confidence(), Confidence::Structural);

        let mut findings = vec![
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::Medium,
                weight: 20,
                description: "Drops and executes a second-stage payload".into(),
                technical_detail: Some("Rule: Dropper_Generic dropper".into()),
            },
            Finding {
                layer: Layer::YaraRules,
                severity: Severity::Medium,
                weight: 20,
                description: "Discord token stealer".into(),
                technical_detail: Some("Pack: stealers".into()),
            },
        ];
        let fm = FrameworkMitigation::evaluate(detection, &mut findings);
        assert!(fm.applied);
        assert!(fm.veto_reason.is_none(), "weight ≤ 25 must not veto");
        assert_eq!(findings[0].weight, 10, "installer-class YARA /2");
        assert_eq!(findings[1].weight, 20, "non-installer-class YARA untouched");
        assert_eq!(fm.ops.len(), 1);
    }

    /// (f-i / Y) Metamorphic: stacking multiple weak markers must not
    /// combine into any mitigation.
    #[test]
    fn mitigation_stacked_weak_markers_grant_nothing() {
        let mut data = vec![0x4D, 0x5A];
        data.extend_from_slice(&[0u8; 600]);
        data.extend_from_slice(
            b"Nullsoft Inst Inno Setup S electron.asar ASAR Windows Installer",
        );
        let detection = layers::framework::detect(&data, "setup.exe");
        assert!(detection.confidence() <= Confidence::WeakHint);
        let mut findings = vec![Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Medium,
            weight: 30,
            description: "high entropy section".into(),
            technical_detail: None,
        }];
        let fm = FrameworkMitigation::evaluate(detection, &mut findings);
        assert!(
            !fm.applied,
            "stacked weak markers must not combine into mitigation"
        );
        assert_eq!(findings[0].weight, 30);
    }

    /// (f-ii) Metamorphic: adding independent malicious evidence to a valid
    /// installer must not lower its score.
    #[test]
    fn mitigation_adding_malicious_evidence_never_lowers_score() {
        let data = structural_nsis_pe(200);
        let mk_struct = || {
            vec![Finding {
                layer: Layer::StructuralAnalysis,
                severity: Severity::Medium,
                weight: 30,
                description: "high entropy section".into(),
                technical_detail: None,
            }]
        };

        let mut f1 = mk_struct();
        let fm1 = FrameworkMitigation::evaluate(
            layers::framework::detect(&data, "setup.exe"),
            &mut f1,
        );
        assert!(fm1.applied);
        let (score_installer, _, _) = aggregate_score(&mut f1, 0, 0, &fm1);

        let mut f2 = mk_struct();
        f2.push(Finding {
            layer: Layer::IocCorrelation,
            severity: Severity::Critical,
            weight: 90,
            description: "File hash matches a known-malicious indicator of compromise (IOC)."
                .into(),
            technical_detail: None,
        });
        let fm2 = FrameworkMitigation::evaluate(
            layers::framework::detect(&data, "setup.exe"),
            &mut f2,
        );
        assert!(!fm2.applied, "IoC-90 must veto mitigation");
        assert!(fm2.veto_reason.is_some());
        let (score_with_ioc, _, _) = aggregate_score(&mut f2, 0, 0, &fm2);
        assert!(
            score_with_ioc >= score_installer,
            "adding malicious evidence must not lower the score ({score_with_ioc} < {score_installer})"
        );
        assert_eq!(score_with_ioc, 100, "30 + 90, clamped at MAX_SCORE");
    }

    /// (g) Legacy Go/Electron hints are still detected diagnostically but
    /// grant NO mitigation (documented calibration change, policy 2).
    #[test]
    fn mitigation_legacy_go_and_electron_hints_grant_nothing() {
        let mut go = vec![0u8; 3_500_000];
        go[0] = 0x4D;
        go[1] = 0x5A;
        go.extend_from_slice(b"Go build ID:");
        let d = layers::framework::detect(&go, "tool.exe");
        assert_eq!(d.kind(), FrameworkKind::GoStatic);
        assert_eq!(d.confidence(), Confidence::WeakHint);
        let mut sink = Vec::new();
        assert!(!FrameworkMitigation::evaluate(d, &mut sink).applied);

        let mut el = vec![0x4D, 0x5A];
        el.extend_from_slice(&[0u8; 500]);
        el.extend_from_slice(b"electron.asar");
        let d = layers::framework::detect(&el, "app.exe");
        assert_eq!(d.kind(), FrameworkKind::ElectronBundle);
        assert_eq!(d.confidence(), Confidence::WeakHint);
        let mut sink = Vec::new();
        assert!(!FrameworkMitigation::evaluate(d, &mut sink).applied);
    }

    /// (h) Provenance is populated and serializes (serde_json round-trip);
    /// old JSON without the additive field still deserializes.
    #[test]
    fn mitigation_provenance_populates_and_round_trips() {
        let data = structural_nsis_pe(200);
        let detection = layers::framework::detect(&data, "setup.exe");
        let mut findings = vec![Finding {
            layer: Layer::StructuralAnalysis,
            severity: Severity::Medium,
            weight: 30,
            description: "high entropy section".into(),
            technical_detail: None,
        }];
        let fm = FrameworkMitigation::evaluate(detection, &mut findings);
        let (_, _, expl) = aggregate_score(&mut findings, 0, 0, &fm);

        let prov = expl
            .framework_mitigation
            .as_ref()
            .expect("provenance must be populated for a detected framework");
        assert_eq!(prov.kind.as_deref(), Some("NSIS"));
        assert_eq!(prov.confidence, "Structural");
        assert!(prov.mitigation_safe);
        assert!(prov.mitigation_applied);
        assert!(!prov.evidence.is_empty());
        assert!(prov
            .evidence
            .iter()
            .any(|e| e.source == "Overlay" && e.offset == Some(0x400)));
        assert_eq!(prov.ops.len(), 1);
        assert_eq!(prov.ops[0].layer, "StructuralAnalysis");
        assert_eq!((prov.ops[0].weight_before, prov.ops[0].weight_after), (30, 10));
        assert_eq!(
            (
                prov.score_before_mitigation,
                prov.score_after_mitigation
            ),
            (30, 10)
        );
        assert!(prov.veto_reason.is_none());

        // Round-trip.
        let json = serde_json::to_string(&expl).unwrap();
        let back: VerdictExplanation = serde_json::from_str(&json).unwrap();
        let prov2 = back.framework_mitigation.unwrap();
        assert_eq!(prov2.kind.as_deref(), Some("NSIS"));
        assert_eq!(prov2.ops.len(), 1);
        assert_eq!(prov2.evidence.len(), prov.evidence.len());

        // Additive compat: JSON without the new key (old argusd worker)
        // still deserializes.
        let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
        v.as_object_mut().unwrap().remove("framework_mitigation");
        let old: VerdictExplanation = serde_json::from_value(v).unwrap();
        assert!(old.framework_mitigation.is_none());
    }

    /// (Y) Metamorphic: truncating a valid installer structure must never
    /// increase mitigation — every cut inside the archive drops confidence
    /// below Structural, so no cut receives mitigation at all.
    #[test]
    fn mitigation_truncation_never_increases_mitigation() {
        let full = structural_nsis_pe(200);
        let overlay_start = 0x400usize;
        for cut in overlay_start..full.len() {
            let d = layers::framework::detect(&full[..cut], "setup.exe");
            let mut sink = Vec::new();
            let fm = FrameworkMitigation::evaluate(d, &mut sink);
            assert!(!fm.applied, "cut at {cut} must not receive mitigation");
        }
    }
}

/// Adversarial scoring suite (workstreams X+Y) — see the module docs.
#[cfg(test)]
mod adversarial;
