//! Verdict types — the unified output of every ARGUS analysis.
//!
//! Every finding carries a weight, a human-readable description, and
//! the layer that produced it. The final verdict aggregates all findings
//! into a score with full traceability.

use serde::{Deserialize, Serialize};

/// Maximum suspicion score (100-point scale).
pub const MAX_SCORE: u32 = 100;

// ── Scan strategy ─────────────────────────────────────────────────

/// Determines how deeply a file is analyzed based on its type, size, and trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStrategy {
    /// Full analysis: all layers, all rules. For executables, scripts, archives.
    FullAnalysis,
    /// Light analysis: default for unknown/unclassified extensions. Runs the
    /// same ARGUS content layers as FullAnalysis today (including YARA).
    LightAnalysis,
    /// Signature-oriented: for large files, media, firmware. Skips YARA rule
    /// matching; all other ARGUS layers (MIME, deception, structural, script,
    /// JAR, PDF, patterns, reputation, context) still run. ClamAV runs daemon-side.
    SignatureOnly,
    /// Skip entirely: build artifacts, logs, safe extensions.
    SkipSafe,
    /// Too large for ARGUS analysis (>100MB). ClamAV handles these.
    TooLarge,
}

impl ScanStrategy {
    /// Classify a file based on extension and size.
    pub fn classify(path: &str, file_size: u64) -> Self {
        // Size-based.
        if file_size > 100 * 1024 * 1024 {
            return Self::TooLarge;
        }

        let ext = path.rsplit('.').next().unwrap_or("").to_lowercase();

        // Skip safe: build artifacts, logs, data files.
        if matches!(
            ext.as_str(),
            "log"
                | "tmp"
                | "bak"
                | "lock"
                | "cache"
                | "rlib"
                | "rmeta"
                | "pdb"
                | "ilk"
                | "d"
                | "o"
                | "obj"
                | "map"
                | "fingerprint"
                | "incremental"
                | "csv"
                | "tsv"
                | "yaml"
                | "yml"
                | "toml"
                | "json"
                | "xml"
                | "md"
                | "txt"
                | "rst"
                | "ini"
                | "cfg"
                | "conf"
                | "vault"
        ) {
            return Self::SkipSafe;
        }

        // Signature-only: media, fonts, large non-executable blobs.
        if matches!(
            ext.as_str(),
            "jpg"
                | "jpeg"
                | "png"
                | "gif"
                | "bmp"
                | "webp"
                | "svg"
                | "ico"
                | "tiff"
                | "mp3"
                | "mp4"
                | "mkv"
                | "avi"
                | "wav"
                | "flac"
                | "ogg"
                | "webm"
                | "m4a"
                | "woff"
                | "woff2"
                | "ttf"
                | "otf"
                | "eot"
                | "dat"
                | "bin"
                | "rom"
                | "fw"
                | "img"
        ) {
            return Self::SignatureOnly;
        }

        // Signature-only for large non-script files.
        if file_size > 50 * 1024 * 1024
            && !matches!(
                ext.as_str(),
                "exe" | "dll" | "scr" | "com" | "sys" | "drv" | "msi" | "msix" | "appx"
            )
        {
            return Self::SignatureOnly;
        }

        // Full analysis: executables, scripts, archives, documents.
        if matches!(
            ext.as_str(),
            "exe"
                | "dll"
                | "scr"
                | "com"
                | "pif"
                | "sys"
                | "drv"
                | "bat"
                | "cmd"
                | "ps1"
                | "vbs"
                | "js"
                | "wsh"
                | "wsf"
                | "reg"
                | "msi"
                | "msix"
                | "appx"
                | "zip"
                | "rar"
                | "7z"
                | "tar"
                | "gz"
                | "iso"
                | "cab"
                | "doc"
                | "docx"
                | "docm"
                | "xls"
                | "xlsx"
                | "xlsm"
                | "ppt"
                | "pptx"
                | "pptm"
                | "pdf"
                | "lnk"
                | "url"
                | "hta"
                | "inf"
        ) {
            return Self::FullAnalysis;
        }

        // Default: light analysis for unknown extensions.
        Self::LightAnalysis
    }
}

/// Per-layer timing for a single file analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanTiming {
    /// SHA-256 hash computation time (microseconds).
    pub hash_us: u64,
    /// ClamAV signature scan time (microseconds). 0 if not run in ARGUS.
    pub clamav_us: u64,
    /// Total ARGUS analysis time (microseconds).
    pub argus_total_us: u64,
    /// YARA rule scan time (microseconds).
    pub yara_us: u64,
    /// PE structural analysis time (microseconds).
    pub structural_us: u64,
    /// Strategy applied to this file.
    pub strategy: Option<ScanStrategy>,
    /// Timeout events that occurred during this scan.
    #[serde(default)]
    pub timeout_reasons: Vec<crate::budget::TimeoutReason>,
    /// Whether the scan completed within its execution budget.
    #[serde(default = "default_true")]
    pub completed_within_budget: bool,
}

fn default_true() -> bool {
    true
}

// ── Verdict ────────────────────────────────────────────────────────

/// The final ARGUS verdict for a scanned target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArgusVerdict {
    /// Absolute path of the analyzed file.
    pub path: String,

    /// File size in bytes.
    pub file_size: u64,

    /// SHA-256 hash of the file (hex-encoded).
    pub sha256: String,

    /// Detected MIME type (by magic bytes), e.g. "application/x-dosexec".
    pub mime_type: Option<String>,

    /// Aggregated suspicion score (0–100).
    pub score: u32,

    /// Classification derived from the score.
    pub verdict: Verdict,

    /// Ordered list of findings that contributed to the score.
    pub findings: Vec<Finding>,

    /// Wall-clock analysis time in microseconds.
    pub analysis_time_us: u64,

    /// Engine version that produced this verdict.
    pub engine_version: &'static str,

    /// Timestamp (Unix seconds) when the analysis completed.
    pub timestamp: i64,

    /// Structured explanation — why this score was reached.
    pub explanation: VerdictExplanation,

    /// Per-layer timing breakdown.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub timing: Option<ScanTiming>,
}

/// Structured explanation of how the verdict was reached.
/// Shows both what increased and what decreased suspicion.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerdictExplanation {
    /// Raw score before discounts.
    pub raw_score: u32,
    /// Reputation discount applied (known software).
    pub reputation_discount: u32,
    /// Authenticode discount applied (valid signature).
    pub authenticode_discount: u32,
    /// Installer framework discount applied.
    pub installer_discount_applied: bool,
    /// Final score after all adjustments.
    pub final_score: u32,
    /// Signer name if Authenticode verified.
    pub signer: Option<String>,
    /// Recognized software name from reputation DB.
    pub recognized_software: Option<String>,
    /// Summary reasons for suspicion increases (from findings).
    pub suspicion_reasons: Vec<String>,
    /// Summary reasons for trust reductions.
    pub trust_reasons: Vec<String>,
    /// Confidence label — softer assessment for UI display.
    /// Complements the numeric score without replacing it.
    pub confidence_label: ConfidenceLabel,
    /// Detected framework/packaging technology (if any).
    pub framework: Option<String>,
    /// Operational threat classification (loader/stealer/destructive).
    pub threat_maturity: ThreatMaturity,
    /// Attack stage progression depth (0-3).
    pub progression_depth: u8,
    /// Installer-framework mitigation provenance (workstream U).
    ///
    /// Present whenever the framework dispatcher recognized anything at all
    /// (including WeakHint-only detections that granted NO mitigation), so an
    /// analyst can see *why* a file did or did not receive the installer
    /// weight reductions. Additive field: `#[serde(default)]` keeps old JSON
    /// (argusd worker output, cached state) deserializable, and
    /// `skip_serializing_if` keeps the common no-detection payload unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framework_mitigation: Option<FrameworkMitigationProvenance>,
}

/// A single piece of framework-detection evidence, serialized for provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkEvidenceRecord {
    /// Evidence source as a stable string (e.g. "Overlay", "TextHint").
    pub source: String,
    /// Absolute file offset of the evidence, when it has one.
    pub offset: Option<u64>,
    /// Human-readable description (what was found and why it indicates the
    /// framework).
    pub detail: String,
}

/// One weight-reduction operation applied by installer-framework mitigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationOpRecord {
    /// Layer of the finding whose weight was reduced (Debug name).
    pub layer: String,
    /// Weight before mitigation.
    pub weight_before: u32,
    /// Weight after mitigation.
    pub weight_after: u32,
}

/// Full provenance of one installer-framework mitigation decision
/// (workstream T/U): what was detected, on what evidence, whether mitigation
/// was authorized and applied, every weight reduction performed, the score
/// before/after mitigation, and the veto reason when independent
/// high-confidence evidence suppressed mitigation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FrameworkMitigationProvenance {
    /// Detected framework kind (e.g. "NSIS"), if any.
    pub kind: Option<String>,
    /// Confidence tier after invariant enforcement ("Structural",
    /// "Corroborated", "WeakHint", "Unknown").
    pub confidence: String,
    /// Whether the detection satisfied the centralized build() invariant
    /// (confidence >= Corroborated + structural evidence present).
    pub mitigation_safe: bool,
    /// Whether mitigation was actually applied (stricter than
    /// `mitigation_safe` — requires Structural confidence and no
    /// high-confidence veto; see engine.rs `FrameworkMitigation::evaluate`).
    pub mitigation_applied: bool,
    /// Evidence summaries backing the detection.
    pub evidence: Vec<FrameworkEvidenceRecord>,
    /// Every weight-reduction op applied (empty when not applied).
    pub ops: Vec<MitigationOpRecord>,
    /// Sum of finding weights immediately before the mitigation pass.
    pub score_before_mitigation: u32,
    /// Sum of finding weights immediately after the mitigation pass
    /// (equal to `score_before_mitigation` when mitigation was not applied).
    pub score_after_mitigation: u32,
    /// Why mitigation was suppressed despite a qualifying (Structural-grade)
    /// detection — e.g. independent high-confidence evidence present.
    pub veto_reason: Option<String>,
    /// Non-fatal detection warnings (tamper indicators, downgrades, ...).
    pub warnings: Vec<String>,
}

/// Confidence label — a human-friendly assessment that complements the score.
///
/// The numeric score remains authoritative for engine decisions.
/// This label helps users understand the assessment quality.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceLabel {
    /// Trusted: signed + recognized, clean history. No concern.
    Trusted,
    /// Normal: no suspicious indicators. Standard software.
    #[default]
    Normal,
    /// Unusual: minor anomalies. Likely benign but noted.
    Unusual,
    /// Suspicious: multiple indicators. Warrants attention.
    Suspicious,
    /// HighRisk: strong behavioral signals. Review recommended.
    HighRisk,
    /// Malicious: confirmed threat signals from multiple layers.
    Malicious,
}

impl ConfidenceLabel {
    /// Legacy: derive from score + trust context (no convergence info).
    pub fn from_context(
        score: u32,
        has_signer: bool,
        has_reputation: bool,
        installer: bool,
    ) -> Self {
        // Delegate to convergence-aware version with empty convergence.
        Self::from_convergence(
            score,
            has_signer,
            has_reputation,
            installer,
            &ConvergenceInfo::default(),
        )
    }

    /// Convergence-aware confidence assessment.
    ///
    /// Uses score + trust signals + multi-layer convergence to produce
    /// a confidence label that reflects evidence quality, not just accumulation.
    pub fn from_convergence(
        score: u32,
        has_signer: bool,
        has_reputation: bool,
        installer: bool,
        convergence: &ConvergenceInfo,
    ) -> Self {
        let has_trust = has_signer || has_reputation;
        let has_strong_trust = has_signer && has_reputation;
        let chain = convergence.chain_strength;
        let strong_convergence = chain >= ChainStrength::Strong
            || (chain >= ChainStrength::Moderate && convergence.distinct_behaviors >= 3)
            || (chain >= ChainStrength::Moderate && convergence.progression_score >= 2);

        match score {
            // ── Clean / Trusted zone ──────────────────────
            // Trusted is clamped to the Clean/LowSuspicion band (0..=25)
            // so the UI label cannot contradict Verdict::Suspicious (26..=50).
            // Anything 26+ falls through to Normal/Unusual even with strong trust.
            0 if has_trust => Self::Trusted,
            0 => Self::Normal,
            1..=25 if has_strong_trust && installer => Self::Trusted,
            1..=15 if has_trust => Self::Trusted,
            1..=15 => Self::Unusual,
            16..=40 if has_trust => Self::Normal,
            16..=40 => Self::Unusual,

            // ── Suspicious zone (41-75) ───────────────────
            // Trust or installer without chain → Unusual (benefit of doubt).
            41..=60 if installer && chain == ChainStrength::None => Self::Unusual,
            41..=60 if has_trust && chain == ChainStrength::None => Self::Unusual,
            // Strong chain promotes to HighRisk even at moderate score.
            41..=75 if strong_convergence => Self::HighRisk,
            41..=75 => Self::Suspicious,

            // ── High score zone (76-90) ───────────────────
            // Weak convergence: high score from one category = Suspicious (possible FP inflation).
            76..=90 if chain <= ChainStrength::Weak && convergence.distinct_behaviors <= 1 => {
                Self::Suspicious
            }
            76..=90 => Self::HighRisk,

            // ── Very high score zone (91+) ────────────────
            // Strong convergence or 3+ layers → Malicious label.
            _ if strong_convergence => Self::Malicious,
            _ if convergence.distinct_layers >= 3 && chain >= ChainStrength::Moderate => {
                Self::Malicious
            }
            // High score but weak convergence → HighRisk, not Malicious.
            _ => Self::HighRisk,
        }
    }
}

/// Chain strength — how coherent and dangerous a detected behavior chain is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum ChainStrength {
    /// No coherent chain detected.
    #[default]
    None,
    /// Weak chain: common combinations that may be benign (downloader + context).
    Weak,
    /// Moderate chain: suspicious combinations (script + downloader, fake installer + persistence).
    Moderate,
    /// Strong chain: high-confidence malicious combination (stealer + exfil, ransomware + destruct).
    Strong,
}


/// Convergence info passed from engine to verdict.
#[derive(Debug, Clone, Default)]
pub struct ConvergenceInfo {
    /// Count of distinct behavior tags with weight > 0 (excluding context).
    pub distinct_behaviors: usize,
    /// Count of distinct analysis layers with weight > 0 findings.
    pub distinct_layers: usize,
    /// Strongest detected attack chain.
    pub chain_strength: ChainStrength,
    /// Detected chain names (for explainability).
    pub chain_names: Vec<&'static str>,
    /// Attack progression score (0-3): forward stage transitions.
    pub progression_score: u8,
}

impl ConfidenceLabel {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Trusted => "Trusted",
            Self::Normal => "Normal",
            Self::Unusual => "Unusual",
            Self::Suspicious => "Suspicious",
            Self::HighRisk => "High Risk",
            Self::Malicious => "Malicious",
        }
    }

    pub fn color_hint(&self) -> &'static str {
        match self {
            Self::Trusted => "green",
            Self::Normal => "green",
            Self::Unusual => "blue",
            Self::Suspicious => "amber",
            Self::HighRisk => "orange",
            Self::Malicious => "red",
        }
    }
}

impl ArgusVerdict {
    /// True if the score reaches the engine's Malicious *label* threshold
    /// (76+, see `Verdict::from_score`).
    ///
    /// This is a label only — it is NOT the daemon's quarantine bar.
    /// `sentinelld`'s `unify_detection_filtered` treats a ClamAV-confirmed
    /// file as a threat at this level, but requires score >= 85 for
    /// ARGUS-only auto-quarantine; ARGUS-only 76-84 is labeled Malicious
    /// here yet produces no detection record and no quarantine.
    ///
    /// Critical findings alone do NOT make a file a threat — they need
    /// corroboration from other layers to push the score above 76.
    /// This prevents false positives from single-layer detections.
    pub fn is_threat(&self) -> bool {
        matches!(self.verdict, Verdict::Malicious)
    }

    /// Produce a one-line summary suitable for logs and UI.
    pub fn summary(&self) -> String {
        if self.findings.is_empty() {
            return format!("{}: Clean (0/100)", short_path(&self.path));
        }
        let top = self
            .findings
            .first()
            .map(|f| f.description.as_str())
            .unwrap_or("—");
        format!(
            "{}: {} ({}/100) — {}",
            short_path(&self.path),
            self.verdict.label(),
            self.score,
            top,
        )
    }
}

/// Shorten a path for display — show only the last 2 components.
fn short_path(path: &str) -> &str {
    let sep_count = path.matches(['/', '\\']).count();
    if sep_count <= 1 {
        return path;
    }
    // Find second-to-last separator.
    let bytes = path.as_bytes();
    let mut seps_seen = 0;
    for i in (0..bytes.len()).rev() {
        if bytes[i] == b'/' || bytes[i] == b'\\' {
            seps_seen += 1;
            if seps_seen == 2 {
                return &path[i + 1..];
            }
        }
    }
    path
}

// ── Verdict classification ─────────────────────────────────────────

/// Classification derived from the aggregated suspicion score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Score 0: no suspicious indicators found.
    Clean,
    /// Score 1–25: minor anomalies, likely benign.
    LowSuspicion,
    /// Potentially Unwanted Application — not malware but undesirable.
    /// Adware, bundleware, browser toolbars, miners without consent.
    PotentiallyUnwanted,
    /// Score 26–50: multiple indicators warrant attention.
    Suspicious,
    /// Score 51–75: high confidence of malicious behavior.
    HighSuspicion,
    /// Score 76+: strong evidence of malware.
    Malicious,
}

impl Verdict {
    /// Derive a verdict from a numeric score.
    pub fn from_score(score: u32) -> Self {
        match score {
            0 => Self::Clean,
            1..=25 => Self::LowSuspicion,
            26..=50 => Self::Suspicious,
            51..=75 => Self::HighSuspicion,
            _ => Self::Malicious,
        }
    }

    /// Human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Clean => "Clean",
            Self::LowSuspicion => "Low Suspicion",
            Self::PotentiallyUnwanted => "Potentially Unwanted",
            Self::Suspicious => "Suspicious",
            Self::HighSuspicion => "High Suspicion",
            Self::Malicious => "Malicious",
        }
    }

    /// Short color hint for UI rendering.
    pub fn color_hint(&self) -> &'static str {
        match self {
            Self::Clean => "green",
            Self::PotentiallyUnwanted => "amber",
            Self::LowSuspicion => "blue",
            Self::Suspicious => "amber",
            Self::HighSuspicion => "orange",
            Self::Malicious => "red",
        }
    }
}

// ── Behavior tags ─────────────────────────────────────────────────

/// Structured behavior classification for evidence deduplication.
///
/// When multiple findings from different layers describe the same semantic
/// behavior, the deduplication engine uses this tag to group them and count
/// only the highest-weight finding per group.
///
/// IMPORTANT: Tags represent capabilities/behaviors, NOT attack stages.
/// CredentialTheft and Exfiltration are DIFFERENT tags because they represent
/// different stages of an attack chain that should both count toward scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorTag {
    /// File has download/fetch capability (API imports, HTTP client code).
    DownloaderCapability,
    /// File origin context (Zone.Identifier, directory location). Never deduped with capability.
    DownloadOriginContext,
    /// Hash matched curated known-malicious threat intelligence.
    KnownMalware,
    /// Binary is packed, compressed, or obfuscated.
    Packing,
    /// Section/resource has high entropy (compressed/encrypted data).
    Entropy,
    /// Establishes persistence (registry Run keys, scheduled tasks, startup).
    Persistence,
    /// Accesses stored credentials (browser data, DPAPI, password stores).
    CredentialTheft,
    /// Sends stolen data to external destination (webhooks, Telegram, HTTP POST).
    Exfiltration,
    /// Ransomware behavior (file encryption, shadow copy deletion, ransom notes).
    Ransomware,
    /// Process injection / hollowing (cross-process memory manipulation).
    Injection,
    /// Anti-analysis / sandbox evasion / debugger detection.
    Evasion,
    /// Malicious script execution (PowerShell, VBS, JS abuse).
    ScriptAbuse,
    /// Command-and-control communication patterns.
    C2Communication,
    /// Cryptocurrency wallet theft.
    WalletTheft,
    /// Archive-based payload staging (SFX extraction + execution).
    ArchiveStaging,
    /// Masquerades as legitimate installer/updater.
    FakeInstaller,
    /// Potentially unwanted: adware, bundleware, browser hijacker, miner.
    PotentiallyUnwanted,
}

// ── Individual finding ─────────────────────────────────────────────

/// A single finding from an ARGUS analysis layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Which analysis layer produced this finding.
    pub layer: Layer,

    /// Severity of this individual finding.
    pub severity: Severity,

    /// Weight added to the suspicion score (0–50 per finding).
    pub weight: u32,

    /// Human-readable description of what was observed.
    pub description: String,

    /// Technical detail for advanced users / forensic export.
    /// May include rule names, section data, hash values, etc.
    pub technical_detail: Option<String>,
}

impl Finding {
    /// Compute the behavior tag for this finding.
    /// Used by the deduplication engine to group correlated evidence.
    /// This is computed rather than stored to avoid changing 136+ construction sites.
    pub fn behavior_tag(&self) -> Option<BehaviorTag> {
        // Context layer → always unique (never deduplicated with capabilities).
        if self.layer == Layer::Context {
            return Some(BehaviorTag::DownloadOriginContext);
        }

        // Layer-based tags (highest confidence).
        if self.layer == Layer::PackerDetection {
            return Some(BehaviorTag::Packing);
        }
        if self.layer == Layer::IocCorrelation {
            return Some(BehaviorTag::KnownMalware);
        }

        // YARA category from technical_detail (contains pack/category info).
        if self.layer == Layer::YaraRules {
            if let Some(ref detail) = self.technical_detail {
                let dl = detail.to_lowercase();
                // Check exfil BEFORE stealer — "stealer_exfil" should be Exfiltration, not CredentialTheft.
                if dl.contains("exfil") {
                    return Some(BehaviorTag::Exfiltration);
                }
                if dl.contains("stealer")
                    || dl.contains("credential")
                    || dl.contains("spyware")
                    || dl.contains("browser_hijack")
                {
                    return Some(BehaviorTag::CredentialTheft);
                }
                if dl.contains("ransomware") {
                    return Some(BehaviorTag::Ransomware);
                }
                if dl.contains("c2") || dl.contains("beacon") || dl.contains("backdoor") {
                    return Some(BehaviorTag::C2Communication);
                }
                if dl.contains("updater") || dl.contains("fake") {
                    return Some(BehaviorTag::FakeInstaller);
                }
                if dl.contains("persistence") {
                    return Some(BehaviorTag::Persistence);
                }
                if dl.contains("evasion") || dl.contains("anti") {
                    return Some(BehaviorTag::Evasion);
                }
                if dl.contains("script") || dl.contains("powershell") || dl.contains("lolbin") {
                    return Some(BehaviorTag::ScriptAbuse);
                }
                if dl.contains("crypto") || dl.contains("wallet") {
                    return Some(BehaviorTag::WalletTheft);
                }
                if dl.contains("pua")
                    || dl.contains("adware")
                    || dl.contains("bundleware")
                    || dl.contains("miner")
                {
                    return Some(BehaviorTag::PotentiallyUnwanted);
                }
                if dl.contains("dropper") || dl.contains("archive") {
                    return Some(BehaviorTag::ArchiveStaging);
                }
                if dl.contains("packed") || dl.contains("obfuscated") || dl.contains("packer") {
                    return Some(BehaviorTag::Packing);
                }
            }
        }

        // Description-based fallback (lower confidence).
        let desc = self.description.to_lowercase();

        // Structural entropy → Entropy group.
        if self.layer == Layer::StructuralAnalysis
            && (desc.contains("entropy")
                || desc.contains("encrypted")
                || desc.contains("near-random"))
        {
            return Some(BehaviorTag::Entropy);
        }

        // Structural packing reference.
        if self.layer == Layer::StructuralAnalysis
            && (desc.contains("packed") || desc.contains("packer"))
        {
            return Some(BehaviorTag::Packing);
        }

        // Downloader capability (NOT context origin).
        if desc.contains("urldownload")
            || desc.contains("internetopen")
            || desc.contains("winhttp")
            || (desc.contains("download") && desc.contains("remote"))
        {
            if !desc.contains("downloaded from") && !desc.contains("download origin") {
                return Some(BehaviorTag::DownloaderCapability);
            }
        }

        // Injection.
        if desc.contains("injection")
            || desc.contains("hollowing")
            || desc.contains("remote thread")
            || desc.contains("code injection")
        {
            return Some(BehaviorTag::Injection);
        }

        // Persistence.
        if desc.contains("persistence")
            || desc.contains("currentversion\\run")
            || desc.contains("scheduled task")
            || desc.contains("autorun")
        {
            return Some(BehaviorTag::Persistence);
        }

        // Credential theft.
        if desc.contains("credential")
            || desc.contains("login data")
            || desc.contains("dpapi")
            || desc.contains("mimikatz")
            || desc.contains("lsass")
        {
            return Some(BehaviorTag::CredentialTheft);
        }

        // Exfiltration.
        if desc.contains("exfiltrat") || desc.contains("webhook") || desc.contains("telegram bot") {
            return Some(BehaviorTag::Exfiltration);
        }

        // Ransomware.
        if desc.contains("ransom") || desc.contains("shadow cop") || desc.contains("vssadmin") {
            return Some(BehaviorTag::Ransomware);
        }

        // Evasion.
        if desc.contains("anti-debug")
            || desc.contains("anti-analysis")
            || desc.contains("sandbox")
            || desc.contains("virtual machine detect")
        {
            return Some(BehaviorTag::Evasion);
        }

        // PUA — potentially unwanted software.
        if desc.contains("adware")
            || desc.contains("bundleware")
            || desc.contains("browser hijack")
            || desc.contains("toolbar")
            || desc.contains("potentially unwanted")
            || desc.contains("pua")
            || desc.contains("crypto miner")
        {
            return Some(BehaviorTag::PotentiallyUnwanted);
        }

        // No match → unique finding, always counted.
        None
    }
}

// ── Layer identifier ───────────────────────────────────────────────

/// Identifies the analysis layer that produced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    /// ClamAV signature match.
    Signatures,
    /// YARA rule match.
    YaraRules,
    /// MIME/magic byte validation.
    MimeValidation,
    /// PE/ELF structural analysis.
    StructuralAnalysis,
    /// Packer/protector detection.
    PackerDetection,
    /// Script content analysis.
    ScriptAnalysis,
    /// IOC/reputation correlation.
    IocCorrelation,
    /// Specialty pattern detection (stealers, fake docs, etc.).
    PatternDetection,
    /// File deception detection (extension mismatch, RTLO, etc.).
    FileDeception,
    /// Software reputation (recognized publisher/software).
    Reputation,
    /// File origin and execution context.
    Context,
    /// Behavioral runtime analysis (sandbox detonation findings).
    BehavioralRuntime,
    /// NTFS Alternate Data Stream detection.
    AlternateDataStream,
    /// Persistence location intelligence (autorun, scheduled tasks, services).
    Persistence,
}

impl Layer {
    /// Display name for UI.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Signatures => "Signature Analysis",
            Self::YaraRules => "Behavioral Rules",
            Self::MimeValidation => "File Integrity",
            Self::StructuralAnalysis => "Structural Analysis",
            Self::PackerDetection => "Packer Detection",
            Self::ScriptAnalysis => "Script Analysis",
            Self::IocCorrelation => "Threat Intelligence",
            Self::PatternDetection => "Pattern Detection",
            Self::FileDeception => "Deception Detection",
            Self::Reputation => "Software Reputation",
            Self::Context => "Origin Context",
            Self::BehavioralRuntime => "Behavioral Analysis",
            Self::AlternateDataStream => "Alternate Data Streams",
            Self::Persistence => "Persistence Intelligence",
        }
    }
}

// ── Severity ───────────────────────────────────────────────────────

/// Severity level of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational — context only, no suspicion added.
    Info,
    /// Low — minor anomaly, small weight.
    Low,
    /// Medium — notable indicator.
    Medium,
    /// High — strong indicator of malicious behavior.
    High,
    /// Critical — near-certain malicious activity.
    Critical,
}

// ── Attack stage progression ──────────────────────────────────────

/// MITRE ATT&CK-inspired attack stages for temporal coherence.
/// Findings are mapped to stages. A coherent forward progression
/// (access → execution → persistence → exfil) is more suspicious
/// than random unordered tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackStage {
    /// File arrives on system (download, drop, delivery).
    InitialAccess,
    /// Code runs (script execution, process launch).
    Execution,
    /// Survives reboot (registry, scheduled task, startup).
    Persistence,
    /// Avoids detection (anti-debug, packing, evasion).
    DefenseEvasion,
    /// Accesses stored credentials (browser data, DPAPI).
    CredentialAccess,
    /// Gathers data for exfil (screenshots, keylog, file enum).
    Collection,
    /// Sends stolen data out (webhook, Telegram, HTTP POST).
    Exfiltration,
    /// Communicates with attacker infrastructure.
    CommandAndControl,
    /// Destructive action (encryption, wipe, ransom).
    Impact,
}

impl AttackStage {
    /// Ordinal position in the attack lifecycle (0 = earliest).
    pub fn ordinal(&self) -> u8 {
        match self {
            Self::InitialAccess => 0,
            Self::Execution => 1,
            Self::Persistence => 2,
            Self::DefenseEvasion => 3,
            Self::CredentialAccess => 4,
            Self::Collection => 5,
            Self::Exfiltration => 6,
            Self::CommandAndControl => 7,
            Self::Impact => 8,
        }
    }
}

impl BehaviorTag {
    /// Map behavior tag to primary attack stage.
    pub fn attack_stage(&self) -> AttackStage {
        match self {
            Self::DownloaderCapability
            | Self::DownloadOriginContext
            | Self::KnownMalware
            | Self::FakeInstaller
            | Self::ArchiveStaging => AttackStage::InitialAccess,
            Self::ScriptAbuse => AttackStage::Execution,
            Self::Persistence => AttackStage::Persistence,
            Self::Evasion | Self::Packing | Self::Entropy => AttackStage::DefenseEvasion,
            Self::CredentialTheft | Self::WalletTheft => AttackStage::CredentialAccess,
            Self::Injection => AttackStage::Collection, // injection often for data collection
            Self::Exfiltration => AttackStage::Exfiltration,
            Self::C2Communication => AttackStage::CommandAndControl,
            Self::Ransomware => AttackStage::Impact,
            Self::PotentiallyUnwanted => AttackStage::Execution, // PUA runs unwanted software
        }
    }
}

/// Compute attack progression score from a set of behavior tags.
///
/// Rewards coherent forward progression through attack stages.
/// Returns 0-3: number of meaningful stage transitions.
///
/// Example high progression:
///   InitialAccess → Execution → CredentialAccess → Exfiltration = 3 transitions
///
/// Example low progression:
///   DefenseEvasion + DefenseEvasion + DefenseEvasion = 0 transitions
pub fn attack_progression_score(tags: &[BehaviorTag]) -> u8 {
    let mut stages: Vec<u8> = tags
        .iter()
        .filter(|t| **t != BehaviorTag::DownloadOriginContext) // context is not an attack stage
        .map(|t| t.attack_stage().ordinal())
        .collect();
    stages.sort();
    stages.dedup();

    if stages.len() <= 1 {
        return 0;
    }

    // Count meaningful forward transitions (gaps of 1-4 stages apart).
    let mut transitions: u8 = 0;
    for window in stages.windows(2) {
        let gap = window[1] - window[0];
        if (1..=4).contains(&gap) {
            transitions += 1;
        }
    }
    transitions.min(3) // cap at 3
}

// ── Process lineage model ─────────────────────────────────────────

/// Lightweight process lineage hint — describes parent-child relationship.
/// NOT runtime-tracked yet. Used for scoring suspicious spawn chains.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessLineageHint {
    /// Parent process name (e.g., "winword.exe").
    pub parent: Option<String>,
    /// Current process name.
    pub process: Option<String>,
}

impl ProcessLineageHint {
    /// Score the suspiciousness of this parent-child relationship.
    /// Returns 0 (normal) to 15 (highly suspicious).
    pub fn suspicion_score(&self) -> u32 {
        let parent = self
            .parent
            .as_deref()
            .map(|s| s.to_lowercase())
            .unwrap_or_default();
        let _child = self
            .process
            .as_deref()
            .map(|s| s.to_lowercase())
            .unwrap_or_default();

        if parent.is_empty() {
            return 0;
        }

        // HIGH suspicion: Office → shell/script (macro exploitation).
        let office_parents = [
            "winword.exe",
            "excel.exe",
            "powerpnt.exe",
            "outlook.exe",
            "msaccess.exe",
        ];
        let shell_children_indicators = [
            "cmd",
            "powershell",
            "wscript",
            "cscript",
            "mshta",
            "certutil",
        ];
        if office_parents.iter().any(|p| parent.contains(p)) {
            if shell_children_indicators.iter().any(|c| _child.contains(c)) {
                return 15; // Office spawning shell = macro exploitation.
            }
            return 8; // Office spawning any child executable.
        }

        // MEDIUM suspicion: Browser → temp executable.
        let browser_parents = [
            "chrome.exe",
            "firefox.exe",
            "msedge.exe",
            "brave.exe",
            "opera.exe",
        ];
        if browser_parents.iter().any(|p| parent.contains(p)) {
            if _child.contains("temp") || _child.contains("appdata") {
                return 10; // Browser spawning executable from temp.
            }
        }

        // LOW suspicion: Explorer → anything (normal user action).
        if parent.contains("explorer.exe") {
            return 0;
        }

        // LOW: Game launcher → game (normal).
        let launcher_parents = ["steam.exe", "epicgameslauncher", "riotclient"];
        if launcher_parents.iter().any(|p| parent.contains(p)) {
            return 0;
        }

        // MEDIUM: Interpreter → suspicious child.
        let interpreters = ["python.exe", "pythonw.exe", "node.exe", "java.exe"];
        if interpreters.iter().any(|p| parent.contains(p)) {
            if _child.contains("cmd") || _child.contains("powershell") {
                return 5;
            }
        }

        0 // Unknown or normal lineage.
    }
}

// ── Threat maturity classification ────────────────────────────────

/// Operational classification of threat maturity — separate from Verdict.
///
/// Verdict measures score threshold. ThreatMaturity describes what
/// the malware IS and how developed its capabilities are.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatMaturity {
    /// Not a threat — normal software.
    #[default]
    Benign,
    /// Has suspicious capability but no malicious chain (e.g., downloader-only).
    SuspiciousUtility,
    /// Fetches and stages payloads (downloader + persistence or staging).
    Loader,
    /// Actively malicious with clear attack chain (stealer, backdoor).
    ActiveMalware,
    /// Destructive with data-loss potential (ransomware, wiper).
    DestructiveMalware,
}

impl ThreatMaturity {
    /// Derive from convergence info + chain strength.
    pub fn from_convergence(conv: &ConvergenceInfo, score: u32) -> Self {
        if score == 0 {
            return Self::Benign;
        }

        // Destructive: ransomware chain detected.
        if conv.chain_names.contains(&"ransomware") {
            return Self::DestructiveMalware;
        }

        // Active malware: stealer, backdoor, or crypto stealer chains.
        if conv.chain_strength >= ChainStrength::Strong {
            return Self::ActiveMalware;
        }

        // Loader: moderate chains (fake installer, persistent downloader, loader).
        if conv.chain_strength >= ChainStrength::Moderate {
            return Self::Loader;
        }

        // Suspicious utility: has some suspicious capability but no chain.
        if score >= 20 {
            return Self::SuspiciousUtility;
        }

        Self::Benign
    }
}
