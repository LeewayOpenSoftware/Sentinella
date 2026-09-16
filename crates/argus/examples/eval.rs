//! ARGUS evaluation harness — external review workstreams A + Z.
//!
//! Scan a file or directory with the real ArgusEngine and print per-file
//! verdicts with per-layer weight attribution (TSV, default), machine-readable
//! NDJSON (`--json`), or an old-vs-new installer-mitigation transition
//! analysis (`--compare-old-new`).
//!
//! Usage:
//!   cargo run --example eval -p argus -- <path> [options]
//!
//! Options:
//!   --max-files N     cap number of files scanned (default 1000)
//!   --max-size MB     skip files larger than this (default 50)
//!   --ext exe,dll     only scan these extensions (default: all)
//!   --sort size|name  scan order (default: name; size = smallest first)
//!   --verbose         print every finding per file
//!   --json            emit one NDJSON record per file (schema below) instead
//!                     of TSV; summary still goes to stderr-comment lines
//!   --compare-old-new read-only old-vs-new installer mitigation comparison
//!                     (see COMPARISON MODE below); implies per-file CMP lines
//!   --report PATH     transition report file for --compare-old-new
//!                     (default: transition-report.txt in the cwd)
//!   --yara-dir PATH   YARA rule dir (default: <repo>/runtime/argus/rules/yara)
//!   --ioc-file PATH   IOC hash file (default: <repo>/runtime/rules/ioc_hashes.txt)
//!   --eicar-buffer    scan the EICAR string IN MEMORY (no disk read, so host
//!                     AV cannot interpose with io error 225) and exit
//!
//! TSV output (default mode, stdout):
//!   FILE\tpath\tverdict\tscore\traw_score\trep_disc\tauth_disc\tinstaller\tconfidence\tsize
//!   FINDING\tpath\tlayer\tseverity\tweight\tdescription        (verbose or score>0)
//!   RECON\tpath\tscore_without_installer_discount              (REPLICA, see below)
//!   Summary block at the end (prefixed with '#').
//!
//! NDJSON output (--json, one record per line):
//!   path                  file path as scanned (backslashes preserved)
//!   sha256                hex SHA-256 (computed inside the engine, reused)
//!   file_size             bytes
//!   file_type             "pe" | "ole2" | "other" — from offset-0 magic only
//!   mime_type             engine MIME guess (infer crate, magic bytes)
//!   category              verdict label (Clean .. Malicious)
//!   score                 final score 0-100 after all discounts
//!   raw_score             post-mitigation, post-cap weight sum (explanation.raw_score)
//!   score_before_mitigation   weight sum immediately before the mitigation pass
//!                         (null when the framework dispatcher saw nothing —
//!                         no detection, so no pass could run)
//!   score_after_mitigation    weight sum immediately after the pass
//!   framework_kind        e.g. "NSIS", "Inno Setup", "WiX Burn" (null if none)
//!   framework_confidence  "Structural" | "Corroborated" | "WeakHint" | "Unknown"
//!   mitigation_safe       detection met the centralized build() invariant
//!   mitigation_applied    weight divisions actually applied (stricter: needs
//!                         Structural confidence + no high-confidence veto)
//!   evidence              [{source, offset, detail}] backing the detection
//!   mitigation_ops        [{layer, weight_before, weight_after}] per division
//!   warnings              non-fatal detection warnings (tamper indicators...)
//!   veto_reason           why a qualifying detection was refused mitigation
//!   reputation_discount   known-software discount (0/10/20-ish, halved if
//!                         filename-only unconfirmed match)
//!   authenticode_discount signature/system-path discount actually applied
//!   system_path_discount_eligible  REPLICA of authenticode.rs
//!                         `is_windows_system_path` (exact-dir-or-child match
//!                         against the protected-dir list) — eligibility only;
//!                         the engine still requires its own gates to grant it
//!   quarantine_threshold_argus_only  constant 85 — the daemon's ARGUS-only
//!                         auto-quarantine bar (crates/sentinelld/src/ipc/
//!                         state.rs:6541-6547 `argus.score >= 85`). The harness
//!                         has no ClamAV, so only the ARGUS-only bar is shown.
//!   would_quarantine_argus_only  score >= 85
//!   argus_only            always true — this harness runs no ClamAV layer
//!   analysis_time_us      engine wall-clock analysis time
//!
//! COMPARISON MODE (--compare-old-new):
//!   Per file the CURRENT engine runs once (it already applies the new
//!   evidence-aware FrameworkMitigation). Then the deleted legacy
//!   `is_known_installer` substring heuristic — a verbatim REPLICA, see
//!   `old_replica_is_known_installer` below — is evaluated on the same bytes
//!   to derive what the old logic would have decided, and an old-score
//!   estimate is computed (see `old_score_estimate` for the exact/lower-bound
//!   rules). Emits per-file lines (`CMP\t...` TSV, or NDJSON with --json)
//!   plus a transition report on stdout and in --report PATH:
//!     unchanged_mitigated    old=installer, new applied mitigation (same
//!                            divisions at the same pipeline point → scores
//!                            identical by construction)
//!     unchanged_strict       old=no-installer, new=no mitigation
//!     new_only_mitigation    old=no-installer, new applied mitigation
//!     rejected_weak_marker   old=installer, new saw only WeakHint-grade
//!                            evidence (the spoofable substring markers)
//!     rejected_corroborated  old=installer, new Corroborated but not
//!                            mitigation_safe
//!     vetoed_high_confidence old=installer, new Structural-grade detection
//!                            refused mitigation due to independent
//!                            high-confidence evidence (weight >= 40)
//!     lost_classification    old=installer, new saw NOTHING (FP watch:
//!                            genuine installers that lose leniency entirely)
//!   The mode NEVER quarantines/moves/deletes anything — read-only.
//!
//! RECON is a REPLICA: the API does not expose a "disable installer discount"
//! switch, so for files where installer_discount_applied is true we multiply
//! Structural/Packer finding weights by 3 and installer-class YARA weights by
//! 2 (the inverse of the engine's mitigation divisions), re-apply the
//! category caps, and re-derive the score. Because the original division
//! truncated (w/3 loses remainder), the reconstruction is a LOWER BOUND on
//! the pre-discount score. Dedup zeroing is preserved (0 * n = 0).

use argus::budget::ScanExecutionBudget;
use argus::verdict::{Layer, Verdict};
use argus::{ArgusConfig, ArgusEngine, ArgusVerdict};
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};

/// The daemon's ARGUS-only auto-quarantine bar — a constant here, cited from
/// crates/sentinelld/src/ipc/state.rs:6541-6547 (`argus.score >= 85`,
/// "ARGUS-only needs higher confidence"). This harness has no ClamAV layer,
/// so only the ARGUS-only threshold can ever apply to its scores.
const QUARANTINE_THRESHOLD_ARGUS_ONLY: u32 = 85;

struct Opts {
    target: PathBuf,
    max_files: usize,
    max_size: u64,
    exts: Option<Vec<String>>,
    sort_size: bool,
    verbose: bool,
    json: bool,
    compare: bool,
    report: PathBuf,
    yara_dir: PathBuf,
    ioc_file: PathBuf,
}

fn parse_args() -> Opts {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    let repo = manifest.join("../..");
    let mut opts = Opts {
        target: PathBuf::from("."),
        max_files: 1000,
        max_size: 50 * 1024 * 1024,
        exts: None,
        sort_size: false,
        verbose: false,
        json: false,
        compare: false,
        report: PathBuf::from("transition-report.txt"),
        yara_dir: repo.join("runtime/argus/rules/yara"),
        ioc_file: repo.join("runtime/rules/ioc_hashes.txt"),
    };
    let mut args = std::env::args().skip(1);
    let mut target_set = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--max-files" => opts.max_files = args.next().unwrap().parse().unwrap(),
            "--max-size" => opts.max_size = args.next().unwrap().parse::<u64>().unwrap() * 1024 * 1024,
            "--ext" => {
                opts.exts = Some(
                    args.next()
                        .unwrap()
                        .split(',')
                        .map(|s| s.trim().to_lowercase())
                        .collect(),
                )
            }
            "--sort" => opts.sort_size = args.next().unwrap() == "size",
            "--verbose" => opts.verbose = true,
            "--json" => opts.json = true,
            "--compare-old-new" => opts.compare = true,
            "--report" => opts.report = PathBuf::from(args.next().unwrap()),
            "--yara-dir" => opts.yara_dir = PathBuf::from(args.next().unwrap()),
            "--ioc-file" => opts.ioc_file = PathBuf::from(args.next().unwrap()),
            other if !other.starts_with("--") && !target_set => {
                opts.target = PathBuf::from(other);
                target_set = true;
            }
            other => eprintln!("unknown arg: {other}"),
        }
    }
    opts
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(&p, out);
        } else if p.is_file() {
            out.push(p);
        }
    }
}

/// File type from offset-0 magic bytes only (never content-derived):
/// PE ("MZ") and OLE2 compound files are the two domains the legacy
/// installer heuristic and the new framework dispatcher both gate on.
fn file_type_from_magic(data: &[u8]) -> &'static str {
    if data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A {
        "pe"
    } else if data.len() >= 8 && data[0..8] == [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] {
        "ole2"
    } else {
        "other"
    }
}

/// Read just the leading magic bytes (cheap; full reads happen in compare mode).
fn read_magic(path: &Path) -> Vec<u8> {
    let mut buf = vec![0u8; 8];
    match std::fs::File::open(path) {
        Ok(mut f) => {
            let n = f.read(&mut buf).unwrap_or(0);
            buf.truncate(n);
            buf
        }
        Err(_) => Vec::new(),
    }
}

/// Caps from engine.rs `aggregate_score` — duplicated here ONLY for the
/// REPLICA reconstructions (the real caps run inside the engine on real scans).
fn replica_caps() -> [(Layer, u32); 7] {
    [
        (Layer::StructuralAnalysis, 30),
        (Layer::YaraRules, 40),
        (Layer::Context, 15),
        (Layer::PackerDetection, 20),
        (Layer::PatternDetection, 25),
        (Layer::ScriptAnalysis, 40),
        (Layer::FileDeception, 50),
    ]
}

/// The installer-class YARA detail keywords, shared by the old and new
/// division logic (identical list in both — preserved calibration).
fn replica_is_installer_class_yara(technical_detail: Option<&str>) -> bool {
    let dl = technical_detail.unwrap_or("").to_lowercase();
    ["dropper", "updater", "installer", "persistence", "temp_extraction", "fake_updater"]
        .iter()
        .any(|k| dl.contains(k))
}

/// Re-apply the per-category caps with the same floor-scaling as the
/// engine's `aggregate_score` (floor guarantees sum <= cap).
fn replica_apply_caps(weights: &mut [(Layer, u32)]) {
    for (layer, cap) in replica_caps() {
        let total: u32 = weights
            .iter()
            .filter(|(l, _)| *l == layer)
            .map(|(_, w)| *w)
            .sum();
        if total > cap && total > 0 {
            let ratio = cap as f64 / total as f64;
            for (l, w) in weights.iter_mut() {
                if *l == layer {
                    *w = (*w as f64 * ratio).floor() as u32;
                }
            }
        }
    }
}

/// REPLICA: reconstruct an approximate pre-installer-discount score.
/// Lower bound (integer division in the engine truncated remainders).
fn reconstruct_without_installer_discount(v: &ArgusVerdict) -> u32 {
    // (layer, weight) after undoing the engine's /3 and /2 reductions.
    let mut undone: Vec<(Layer, u32)> = v
        .findings
        .iter()
        .map(|f| {
            let w = match f.layer {
                Layer::StructuralAnalysis | Layer::PackerDetection => f.weight * 3,
                Layer::YaraRules => {
                    if replica_is_installer_class_yara(f.technical_detail.as_deref()) {
                        f.weight * 2
                    } else {
                        f.weight
                    }
                }
                _ => f.weight,
            };
            (f.layer, w)
        })
        .collect();

    replica_apply_caps(&mut undone);

    let raw: u32 = undone.iter().map(|(_, w)| *w).sum();
    let discount = v
        .explanation
        .reputation_discount
        .max(v.explanation.authenticode_discount);
    raw.saturating_sub(discount).min(100)
}

// ════════════════════════════════════════════════════════════════════════
// OLD-LOGIC REPLICA (workstream Z, comparison mode)
//
// `old_replica_is_known_installer` below is a VERBATIM copy of the deleted
// legacy heuristic `engine.rs::is_known_installer`, recovered from
// `git show 03376b5:crates/argus/src/engine.rs` (lines 1164-1260). It was
// deleted from the engine because its unanchored full-buffer substring
// scans were a confirmed spoof primitive (embed "Nullsoft Inst" / "ASAR" /
// "Go build ID:" in a file you control → earn the installer leniency
// discount). It exists here ONLY to answer "what would the old logic have
// decided?" in --compare-old-new mode. Do not resurrect it in the engine.
// ════════════════════════════════════════════════════════════════════════

/// REPLICA of the deleted legacy heuristic. See the banner comment above.
fn old_replica_is_known_installer(data: &[u8], path: &str) -> bool {
    let is_pe = data.len() >= 2 && data[0] == 0x4D && data[1] == 0x5A;
    let is_ole2 =
        data.len() >= 8 && data[0..8] == [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    if !is_pe && !is_ole2 {
        return false;
    }

    // Binary content checks for known installer frameworks.
    let contains = |needle: &[u8]| data.windows(needle.len()).any(|w| w == needle);
    let has_nsis = contains(b"Nullsoft Inst") || contains(b"NullsoftInst");
    let has_inno = contains(b"Inno Setup S") || contains(b"InnoSetupLdr");
    let has_wix = contains(b"Windows Installer");
    let msi_ext = {
        let lower = path.to_lowercase();
        lower.ends_with(".msi") || lower.ends_with(".msp")
    };
    let has_msi = is_ole2 && msi_ext;
    if is_ole2 && !is_pe {
        return has_msi;
    }
    let has_installshield = contains(b"InstallShiel");
    let has_ai = contains(b"Advanced Installer");

    // Framework detection — Electron, Tauri, Qt, Squirrel, and similar bundle frameworks.
    let has_electron = contains(b"ASAR")
        || contains(b"electron.asar")
        || contains(b"Electron Framework")
        || contains(b"electron.exe");
    let has_nwjs = contains(b"nw.exe") || contains(b"nwjs");
    let has_tauri = contains(b"tauri") && contains(b"webview");
    let has_squirrel = contains(b"Squirrel") && contains(b"Update.exe");
    let has_qt_installer = contains(b"Qt Installer Framework") || contains(b"QtInstallerFramework");
    let has_flutter = contains(b"flutter_engine") || contains(b"FlutterDesktop");
    let has_unity = contains(b"UnityPlayer") || contains(b"Unity Technologies");
    let has_unreal = contains(b"UnrealEngine") || contains(b"EpicGames");

    // Filename heuristic — only applies if binary also has framework markers.
    let path_lower = path.to_lowercase();
    let name_indicators = [
        "setup",
        "install",
        "installer",
        "update",
        "updater",
        "_setup",
        "-setup",
    ];
    let has_installer_name = name_indicators.iter().any(|p| path_lower.contains(p));

    // Framework detected → always installer.
    if has_nsis || has_inno || has_wix || has_msi || has_installshield || has_ai {
        return true;
    }
    // Framework → installer treatment (structural noise reduction).
    if has_electron
        || has_nwjs
        || has_tauri
        || has_squirrel
        || has_qt_installer
        || has_flutter
        || has_unity
        || has_unreal
    {
        return true;
    }
    // Go binaries — large static binaries with unusual sections but NOT packed/malicious.
    let has_go = contains(b"Go build ID:") || contains(b"runtime.main");
    if has_go && data.len() > 3_000_000 {
        return true;
    }

    // Rust binaries — large static binaries via musl or similar.
    let has_rust_static = contains(b"rust_begin_unwind") || contains(b"rust_panic");
    if has_rust_static && data.len() > 2_000_000 {
        return true;
    }

    // Name heuristic — required at least one generic installer body hint.
    let has_generic_installer_hint = contains(b"uninstall")
        || contains(b"Uninstall")
        || contains(b".cab")
        || contains(b"Cabinet")
        || contains(b"SFX")
        || contains(b"7-Zip")
        || contains(b"setup.ico");
    if has_installer_name && is_pe && data.len() > 2_000_000 && has_generic_installer_hint {
        return true;
    }
    false
}

/// REPLICA: apply the legacy installer weight divisions (Structural/Packer
/// /3, installer-class YARA /2) to the verdict's findings, re-apply the
/// category caps, and re-derive the score with the same discounts.
///
/// Used when the old logic said "installer" but the new engine applied NO
/// mitigation. The verdict's finding weights are post-cap/post-dedup, so
/// dividing them here is an APPROXIMATION — typically a lower bound on the
/// true old score (dividing already-capped weights divides less mass, and
/// the old pass ran before dedup/caps on the raw weights). Second-order
/// effects of the old pass on trusted-binary noise suppression and context
/// amplification (both downstream of the divisions) are NOT modeled.
fn old_replica_score_with_divisions(v: &ArgusVerdict) -> u32 {
    let mut divided: Vec<(Layer, u32)> = v
        .findings
        .iter()
        .map(|f| {
            let w = match f.layer {
                Layer::StructuralAnalysis | Layer::PackerDetection => f.weight / 3,
                Layer::YaraRules => {
                    if replica_is_installer_class_yara(f.technical_detail.as_deref()) {
                        f.weight / 2
                    } else {
                        f.weight
                    }
                }
                _ => f.weight,
            };
            (f.layer, w)
        })
        .collect();

    replica_apply_caps(&mut divided);

    let raw: u32 = divided.iter().map(|(_, w)| *w).sum();
    let discount = v
        .explanation
        .reputation_discount
        .max(v.explanation.authenticode_discount);
    raw.saturating_sub(discount).min(100)
}

/// REPLICA of authenticode.rs `is_windows_system_path` (exact directory
/// match or child path — a bare starts_with would match attacker-created
/// siblings like `C:\Windows\system32evil\`). Duplicated here because the
/// engine function is private; the WHY comment about forward slashes lives
/// in the transition report (paths must reach the engine with backslashes
/// for this check to ever fire, so scan roots must use backslash form).
fn replica_system_path_eligible(path: &str) -> bool {
    const SYSTEM_DIRS: &[&str] = &[
        "c:\\windows\\system32",
        "c:\\windows\\syswow64",
        "c:\\windows\\winsxs",
        "c:\\windows\\servicing",
        "c:\\program files\\windows defender",
        "c:\\program files\\windowsapps",
        "c:\\program files\\windows nt",
        "c:\\program files\\windows mail",
        "c:\\program files\\windows media player",
        "c:\\program files\\windows photo viewer",
        "c:\\program files\\windows sidebar",
        "c:\\program files (x86)\\windows defender",
        "c:\\program files (x86)\\windowsapps",
        "c:\\program files (x86)\\windows nt",
        "c:\\program files (x86)\\windows mail",
        "c:\\program files (x86)\\windows media player",
        "c:\\program files (x86)\\windows photo viewer",
        "c:\\program files (x86)\\windows sidebar",
    ];
    let p = path.to_lowercase();
    SYSTEM_DIRS.iter().any(|dir| {
        p == *dir || p.strip_prefix(dir).is_some_and(|rest| rest.starts_with('\\'))
    })
}

// ── JSON records (workstream Z) ─────────────────────────────────────

#[derive(Serialize)]
struct EvidenceJson {
    source: String,
    offset: Option<u64>,
    detail: String,
}

#[derive(Serialize)]
struct OpJson {
    layer: String,
    weight_before: u32,
    weight_after: u32,
}

/// One NDJSON record per scanned file (--json mode). Field meanings are
/// documented in the header comment above.
#[derive(Serialize)]
struct FileRecord {
    path: String,
    sha256: String,
    file_size: u64,
    file_type: String,
    mime_type: Option<String>,
    category: String,
    score: u32,
    raw_score: u32,
    score_before_mitigation: Option<u32>,
    score_after_mitigation: Option<u32>,
    framework_kind: Option<String>,
    framework_confidence: Option<String>,
    mitigation_safe: Option<bool>,
    mitigation_applied: bool,
    evidence: Vec<EvidenceJson>,
    mitigation_ops: Vec<OpJson>,
    warnings: Vec<String>,
    veto_reason: Option<String>,
    reputation_discount: u32,
    authenticode_discount: u32,
    system_path_discount_eligible: bool,
    quarantine_threshold_argus_only: u32,
    would_quarantine_argus_only: bool,
    argus_only: bool,
    analysis_time_us: u64,
}

fn build_file_record(v: &ArgusVerdict, file_type: &str) -> FileRecord {
    let ex = &v.explanation;
    let prov = ex.framework_mitigation.as_ref();
    FileRecord {
        path: v.path.clone(),
        sha256: v.sha256.clone(),
        file_size: v.file_size,
        file_type: file_type.to_string(),
        mime_type: v.mime_type.clone(),
        category: v.verdict.label().to_string(),
        score: v.score,
        raw_score: ex.raw_score,
        score_before_mitigation: prov.map(|p| p.score_before_mitigation),
        score_after_mitigation: prov.map(|p| p.score_after_mitigation),
        framework_kind: prov.and_then(|p| p.kind.clone()),
        framework_confidence: prov.map(|p| p.confidence.clone()),
        mitigation_safe: prov.map(|p| p.mitigation_safe),
        mitigation_applied: ex.installer_discount_applied,
        evidence: prov
            .map(|p| {
                p.evidence
                    .iter()
                    .map(|e| EvidenceJson {
                        source: e.source.clone(),
                        offset: e.offset,
                        detail: e.detail.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        mitigation_ops: prov
            .map(|p| {
                p.ops
                    .iter()
                    .map(|op| OpJson {
                        layer: op.layer.clone(),
                        weight_before: op.weight_before,
                        weight_after: op.weight_after,
                    })
                    .collect()
            })
            .unwrap_or_default(),
        warnings: prov.map(|p| p.warnings.clone()).unwrap_or_default(),
        veto_reason: prov.and_then(|p| p.veto_reason.clone()),
        reputation_discount: ex.reputation_discount,
        authenticode_discount: ex.authenticode_discount,
        system_path_discount_eligible: replica_system_path_eligible(&v.path),
        quarantine_threshold_argus_only: QUARANTINE_THRESHOLD_ARGUS_ONLY,
        would_quarantine_argus_only: v.score >= QUARANTINE_THRESHOLD_ARGUS_ONLY,
        argus_only: true,
        analysis_time_us: v.analysis_time_us,
    }
}

/// One NDJSON record per scanned file in --compare-old-new --json mode.
#[derive(Serialize)]
struct CompareRecord {
    path: String,
    sha256: String,
    file_type: String,
    transition: String,
    old_installer: bool,
    old_score_estimate: u32,
    /// "exact" | "lower_bound" | "approx_lower_bound" — see old_score_estimate.
    old_score_bound: String,
    old_category: String,
    new_score: u32,
    new_category: String,
    new_mitigation_applied: bool,
    new_framework_kind: Option<String>,
    new_framework_confidence: Option<String>,
    new_veto_reason: Option<String>,
    score_delta_new_minus_old: i64,
    old_would_quarantine_argus_only: bool,
    new_would_quarantine_argus_only: bool,
    quarantine_threshold_argus_only: u32,
    argus_only: bool,
}

/// Compute what the OLD logic would have scored, given the current verdict
/// and the old replica's installer decision. Returns (score, bound_kind):
///
/// - old=no-installer, new didn't mitigate → EXACT: identical code path.
/// - old=no-installer, new mitigated → LOWER BOUND: the RECON replica
///   (undo the divisions; truncation makes this a lower bound).
/// - old=installer, new mitigated → EXACT: the old code applied the same
///   divisions at the same pipeline point with no veto gate, so both
///   pipelines produce byte-identical findings → identical score.
/// - old=installer, new didn't mitigate → APPROX LOWER BOUND: the division
///   replica over post-cap weights (see old_replica_score_with_divisions).
fn old_score_estimate(old_installer: bool, new_applied: bool, v: &ArgusVerdict) -> (u32, &'static str) {
    if !old_installer {
        if new_applied {
            (reconstruct_without_installer_discount(v), "lower_bound")
        } else {
            (v.score, "exact")
        }
    } else if new_applied {
        (v.score, "exact")
    } else {
        (old_replica_score_with_divisions(v), "approx_lower_bound")
    }
}

/// Classify the old→new transition for one file. Category meanings are
/// documented in the header comment (COMPARISON MODE).
fn classify_transition(
    old_installer: bool,
    new_applied: bool,
    new_confidence: Option<&str>,
    new_vetoed: bool,
) -> &'static str {
    if !old_installer {
        return if new_applied {
            "new_only_mitigation"
        } else {
            "unchanged_strict"
        };
    }
    if new_applied {
        return "unchanged_mitigated";
    }
    if new_vetoed {
        return "vetoed_high_confidence";
    }
    match new_confidence {
        Some("WeakHint") => "rejected_weak_marker",
        Some("Corroborated") => "rejected_corroborated",
        // Unknown confidence / no provenance at all: the new dispatcher saw
        // nothing — the genuine-installer FP watch category.
        _ => "lost_classification",
    }
}

fn main() {
    let opts = parse_args();

    // --eicar-buffer: build the EICAR test string IN MEMORY and scan it via
    // analyze_buffer (no disk read — host AV cannot interpose).
    if std::env::args().any(|a| a == "--eicar-buffer") {
        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let engine = ArgusEngine::new(ArgusConfig::default());
        eprintln!("# yara={:?}", engine.yara.load_rules_on_large_stack(&[opts.yara_dir.clone()]));
        eprintln!("# ioc={:?}", engine.ioc.load_from_file(&opts.ioc_file));
        let v = engine.analyze_buffer("eicar.com", eicar);
        println!(
            "FILE\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:?}\t{}",
            v.path, v.verdict.label(), v.score, v.explanation.raw_score,
            v.explanation.reputation_discount, v.explanation.authenticode_discount,
            v.explanation.installer_discount_applied, v.explanation.confidence_label, v.file_size,
        );
        for f in &v.findings {
            println!("FINDING\t{}\t{:?}\t{:?}\t{}\t{}", v.path, f.layer, f.severity, f.weight,
                f.description.replace('\t', " "));
        }
        return;
    }

    let engine = ArgusEngine::new(ArgusConfig::default());
    let yara_loaded = engine
        .yara
        .load_rules_on_large_stack(&[opts.yara_dir.clone()]);
    let ioc_loaded = engine.ioc.load_from_file(&opts.ioc_file);
    eprintln!(
        "# engine init: yara={:?} ioc={:?} (yara_dir={}, ioc_file={})",
        yara_loaded, ioc_loaded, opts.yara_dir.display(), opts.ioc_file.display()
    );

    // ── Collect files ─────────────────────────────────────────
    let mut files: Vec<PathBuf> = Vec::new();
    if opts.target.is_file() {
        files.push(opts.target.clone());
    } else {
        walk(&opts.target, &mut files);
    }
    if let Some(exts) = &opts.exts {
        files.retain(|p| {
            p.extension()
                .map(|e| exts.contains(&e.to_string_lossy().to_lowercase()))
                .unwrap_or(false)
        });
    }
    if opts.sort_size {
        files.sort_by_key(|p| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0));
    } else {
        files.sort();
    }
    files.truncate(opts.max_files);

    // ── Scan ──────────────────────────────────────────────────
    let mut verdict_counts: BTreeMap<String, u64> = BTreeMap::new();
    // layer -> (total weight, files with findings, files where layer sum == cap)
    let mut layer_stats: BTreeMap<String, (u64, u64, u64)> = BTreeMap::new();
    let mut skipped_size = 0u64;
    let mut installer_count = 0u64;
    let mut scanned = 0u64;

    // ── Compare-mode accumulators (deterministic: BTreeMap + push order is
    // the sorted scan order) ───────────────────────────────────
    let mut transition_counts: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut old_installer_true = 0u64;
    let mut cmp_errors: Vec<(String, String)> = Vec::new();
    let mut category_changes: Vec<(String, String, String, u32, u32)> = Vec::new();
    let mut quarantine_enter: Vec<(String, u32, u32)> = Vec::new();
    let mut quarantine_exit: Vec<(String, u32, u32)> = Vec::new();
    let mut fp_watch: Vec<(String, String)> = Vec::new();
    let mut weak_rejected: Vec<(String, String)> = Vec::new();
    let mut vetoed: Vec<(String, String)> = Vec::new();
    let mut delta_min: Option<i64> = None;
    let mut delta_max: Option<i64> = None;
    let mut delta_sum: i64 = 0;

    let caps = replica_caps();

    for path in &files {
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if size > opts.max_size {
            skipped_size += 1;
            continue;
        }

        // Compare mode needs the file bytes for the old-logic replica. Read
        // failures (e.g. EICAR-on-disk blocked by host AV, io error 225) are
        // recorded and skipped — the harness never panics on a corpus file.
        let data: Option<Vec<u8>> = if opts.compare {
            match std::fs::read(path) {
                Ok(d) => Some(d),
                Err(e) => {
                    cmp_errors.push((path.display().to_string(), format!("read failed: {e}")));
                    None
                }
            }
        } else {
            None
        };
        if opts.compare && data.is_none() {
            continue;
        }

        let v = engine.analyze_file_with_budget(path, ScanExecutionBudget::manual());
        scanned += 1;

        let magic = data.as_deref().map(|d| d.to_vec()).unwrap_or_else(|| read_magic(path));
        let ftype = file_type_from_magic(&magic);

        // ── Per-file output ───────────────────────────────────
        if opts.compare {
            let ex = &v.explanation;
            let prov = ex.framework_mitigation.as_ref();
            let new_applied = prov.map(|p| p.mitigation_applied).unwrap_or(false);
            let new_confidence = prov.map(|p| p.confidence.as_str());
            let new_kind = prov.and_then(|p| p.kind.clone());
            let new_veto = prov.and_then(|p| p.veto_reason.clone());

            let bytes = data.as_deref().unwrap_or(&[]);
            let old_installer = old_replica_is_known_installer(bytes, &v.path);
            let (old_score, bound) = old_score_estimate(old_installer, new_applied, &v);
            let transition =
                classify_transition(old_installer, new_applied, new_confidence, new_veto.is_some());
            let old_category = Verdict::from_score(old_score).label();
            let old_q = old_score >= QUARANTINE_THRESHOLD_ARGUS_ONLY;
            let new_q = v.score >= QUARANTINE_THRESHOLD_ARGUS_ONLY;
            let delta = v.score as i64 - old_score as i64;

            if opts.json {
                let rec = CompareRecord {
                    path: v.path.clone(),
                    sha256: v.sha256.clone(),
                    file_type: ftype.to_string(),
                    transition: transition.to_string(),
                    old_installer,
                    old_score_estimate: old_score,
                    old_score_bound: bound.to_string(),
                    old_category: old_category.to_string(),
                    new_score: v.score,
                    new_category: v.verdict.label().to_string(),
                    new_mitigation_applied: new_applied,
                    new_framework_kind: new_kind.clone(),
                    new_framework_confidence: new_confidence.map(|c| c.to_string()),
                    new_veto_reason: new_veto.clone(),
                    score_delta_new_minus_old: delta,
                    old_would_quarantine_argus_only: old_q,
                    new_would_quarantine_argus_only: new_q,
                    quarantine_threshold_argus_only: QUARANTINE_THRESHOLD_ARGUS_ONLY,
                    argus_only: true,
                };
                println!("{}", serde_json::to_string(&rec).unwrap());
            } else {
                println!(
                    "CMP\t{}\t{}\told={}\told_score~{}\t{}\tnew={}\t{}\told_q={}\tnew_q={}\tkind={}\tconf={}",
                    v.path,
                    transition,
                    old_installer,
                    old_score,
                    bound,
                    v.score,
                    v.verdict.label(),
                    old_q,
                    new_q,
                    new_kind.as_deref().unwrap_or("-"),
                    new_confidence.unwrap_or("-"),
                );
            }

            // ── Accumulate transition stats ───────────────────
            *transition_counts.entry(transition).or_insert(0) += 1;
            if old_installer {
                old_installer_true += 1;
            }
            delta_sum += delta;
            delta_min = Some(delta_min.map_or(delta, |m: i64| m.min(delta)));
            delta_max = Some(delta_max.map_or(delta, |m: i64| m.max(delta)));
            if old_category != v.verdict.label() {
                category_changes.push((
                    v.path.clone(),
                    old_category.to_string(),
                    v.verdict.label().to_string(),
                    old_score,
                    v.score,
                ));
            }
            match (old_q, new_q) {
                (false, true) => quarantine_enter.push((v.path.clone(), old_score, v.score)),
                (true, false) => quarantine_exit.push((v.path.clone(), old_score, v.score)),
                _ => {}
            }
            match transition {
                "lost_classification" => {
                    fp_watch.push((v.path.clone(), format!("old_score~{old_score} new={}", v.score)))
                }
                "rejected_weak_marker" => weak_rejected.push((
                    v.path.clone(),
                    new_kind.unwrap_or_else(|| "?".into()),
                )),
                "vetoed_high_confidence" => {
                    vetoed.push((v.path.clone(), new_veto.unwrap_or_default()))
                }
                _ => {}
            }
        } else if opts.json {
            let rec = build_file_record(&v, ftype);
            println!("{}", serde_json::to_string(&rec).unwrap());
        } else {
            let ex = &v.explanation;
            println!(
                "FILE\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:?}\t{}",
                path.display(),
                v.verdict.label(),
                v.score,
                ex.raw_score,
                ex.reputation_discount,
                ex.authenticode_discount,
                ex.installer_discount_applied,
                ex.confidence_label,
                size,
            );

            if opts.verbose || v.score > 0 {
                for f in &v.findings {
                    println!(
                        "FINDING\t{}\t{:?}\t{:?}\t{}\t{}",
                        path.display(),
                        f.layer,
                        f.severity,
                        f.weight,
                        f.description.replace(['\t', '\n'], " "),
                    );
                }
            }

            if ex.installer_discount_applied {
                installer_count += 1;
                let recon = reconstruct_without_installer_discount(&v);
                println!("RECON\t{}\t{}", path.display(), recon);
            }
        }

        *verdict_counts.entry(v.verdict.label().to_string()).or_insert(0) += 1;

        // Per-layer attribution for this file.
        let mut per_layer: BTreeMap<String, u64> = BTreeMap::new();
        for f in &v.findings {
            *per_layer.entry(format!("{:?}", f.layer)).or_insert(0) += f.weight as u64;
        }
        for (layer, w) in per_layer {
            let st = layer_stats.entry(layer.clone()).or_insert((0, 0, 0));
            st.0 += w;
            st.1 += 1;
            // Cap-saturation inference: post-cap layer total equals the cap
            // ⇒ the cap was (almost certainly) hit. Labeled as inference.
            if let Some(l) = caps.iter().find(|(cl, _)| format!("{cl:?}") == layer) {
                if w == l.1 as u64 {
                    st.2 += 1;
                }
            }
        }
    }

    // ── Summary ───────────────────────────────────────────────
    println!("# SUMMARY");
    println!("# scanned={scanned} skipped_size={skipped_size} total_listed={}", files.len());
    println!("# verdict_buckets:");
    for (k, n) in &verdict_counts {
        println!("#\t{k}\t{n}");
    }
    println!("# installer_discount_applied={installer_count}");
    println!("# layer_totals (layer\ttotal_weight\tfiles_with_findings\tcap_saturation_inferred):");
    let mut layers: Vec<_> = layer_stats.iter().collect();
    layers.sort_by_key(|(_, (w, _, _))| std::cmp::Reverse(*w));
    for (layer, (w, nf, sat)) in layers {
        println!("#\t{layer}\t{w}\t{nf}\t{sat}");
    }

    // ── Transition report (--compare-old-new) ─────────────────
    if opts.compare {
        let mut r = String::new();
        let push = |r: &mut String, line: String| {
            r.push_str(&line);
            r.push('\n');
        };
        push(&mut r, "ARGUS old-vs-new installer mitigation transition report".into());
        push(&mut r, format!("target={}", opts.target.display()));
        push(&mut r, format!(
            "quarantine_threshold_argus_only={QUARANTINE_THRESHOLD_ARGUS_ONLY} \
             (crates/sentinelld/src/ipc/state.rs:6541-6547 — daemon ARGUS-only bar; \
             this harness runs no ClamAV, argus_only=true)"
        ));
        push(
            &mut r,
            "old logic = verbatim REPLICA of deleted engine.rs::is_known_installer \
             (git show 03376b5), divisions replicated on the finding list; \
             bounds labeled per record (exact | lower_bound | approx_lower_bound)."
                .into(),
        );
        push(
            &mut r,
            "NOTE: paths must use backslash roots (C:\\...) — forward slashes break \
             the system-path discount replica and the engine's own path checks."
                .into(),
        );
        push(&mut r, format!("scanned={scanned} errors={}", cmp_errors.len()));
        push(&mut r, format!("old_installer_true={old_installer_true}"));
        push(&mut r, "transitions:".into());
        for (k, n) in &transition_counts {
            push(&mut r, format!("  {k}\t{n}"));
        }
        if scanned > 0 {
            let mean = delta_sum as f64 / scanned as f64;
            push(
                &mut r,
                format!(
                    "score_delta_new_minus_old: min={} max={} mean={mean:.2}",
                    delta_min.unwrap_or(0),
                    delta_max.unwrap_or(0),
                ),
            );
        }
        push(&mut r, format!("category_changes={}", category_changes.len()));
        for (p, oc, nc, os, ns) in &category_changes {
            push(&mut r, format!("  {p}\t{oc} ({os}) -> {nc} ({ns})"));
        }
        push(
            &mut r,
            format!("quarantine_decision_changes: enter={} exit={}",
                quarantine_enter.len(), quarantine_exit.len()),
        );
        for (p, os, ns) in &quarantine_enter {
            push(&mut r, format!("  ENTER\t{p}\t{os} -> {ns}"));
        }
        for (p, os, ns) in &quarantine_exit {
            push(&mut r, format!("  EXIT\t{p}\t{os} -> {ns}"));
        }
        push(
            &mut r,
            format!("fp_watch_lost_classification (old=installer, new saw NOTHING)={}", fp_watch.len()),
        );
        for (p, d) in &fp_watch {
            push(&mut r, format!("  {p}\t{d}"));
        }
        push(&mut r, format!("rejected_weak_markers (old=installer via spoofable substring, new WeakHint only)={}", weak_rejected.len()));
        for (p, k) in &weak_rejected {
            push(&mut r, format!("  {p}\t{k}"));
        }
        push(&mut r, format!("vetoed_high_confidence={}", vetoed.len()));
        for (p, v) in &vetoed {
            push(&mut r, format!("  {p}\t{v}"));
        }
        if !cmp_errors.is_empty() {
            push(&mut r, "errors:".into());
            for (p, e) in &cmp_errors {
                push(&mut r, format!("  {p}\t{e}"));
            }
        }

        print!("{r}");
        if let Err(e) = std::fs::write(&opts.report, &r) {
            eprintln!("# failed to write report {}: {e}", opts.report.display());
        } else {
            eprintln!("# transition report written to {}", opts.report.display());
        }
    }
}
