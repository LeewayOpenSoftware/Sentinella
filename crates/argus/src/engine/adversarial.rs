//! Adversarial scoring suite (workstreams X+Y) — the score-level half of
//! the installer-spoofing regression suite.
//!
//! WHY lib-side: `FrameworkMitigation` and `aggregate_score` are private to
//! the engine module by design (the mitigation pass has exactly one mutation
//! point and we keep it that way), so weight math, veto behavior, and final
//! score/verdict assertions cannot live in `tests/installer_spoofing.rs`.
//! That file covers the detection-level half through the public API; this
//! module covers the scoring half. The split is the minimal-visibility
//! choice — no production visibility was widened for tests.
//!
//! Fixture construction reuses `layers::framework::fixtures::PeBuilder`
//! (crate-internal, cfg(test)) — the same builder the detector unit tests
//! pin, so these fixtures cannot drift from the detectors' own.

use super::*;
use crate::layers::framework::fixtures::{PeBuilder, SectionSpec, patch_u32_le};
use crate::layers::framework::{Confidence, FrameworkKind, detect};

// ── fixture helpers ──────────────────────────────────────────────

/// NSIS overlay: valid NO_CRC firstheader + payload (Structural-grade).
fn nsis_overlay_no_crc(payload_len: u32) -> Vec<u8> {
    let arc_size = 28 + payload_len;
    let mut v = Vec::new();
    v.extend_from_slice(&4u32.to_le_bytes()); // FH_FLAGS_NO_CRC
    v.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    v.extend_from_slice(b"NullsoftInst");
    v.extend_from_slice(&0x100u32.to_le_bytes());
    v.extend_from_slice(&arc_size.to_le_bytes());
    v.extend(std::iter::repeat_n(0xCC, payload_len as usize));
    v
}

/// Minimal PE with a 512-aligned overlay at 0x400 carrying `overlay`.
fn pe_with_aligned_overlay(overlay: &[u8]) -> Vec<u8> {
    PeBuilder::new()
        .add_section(SectionSpec::new(".text", 0x200, 0x200).raw_ptr_override(0x200))
        .overlay(overlay)
        .build()
}

fn structural_nsis_pe(payload_len: u32) -> Vec<u8> {
    pe_with_aligned_overlay(&nsis_overlay_no_crc(payload_len))
}

/// Standard zlib CRC-32 (bitwise; inputs here are ≤ 64 bytes).
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

const INNO_TABLE_ID: [u8; 12] = [
    b'r', b'D', b'l', b'P', b't', b'S', 0xCD, 0xE6, 0xD7, 0x7B, 0x0B, 0x2A,
];

fn inno_write_table_v2(buf: &mut [u8], off: usize, total: u64, exe: u64, o0: u64, o1: u64) {
    let mut rec = vec![0u8; 64];
    rec[..12].copy_from_slice(&INNO_TABLE_ID);
    rec[12..16].copy_from_slice(&2u32.to_le_bytes());
    rec[16..24].copy_from_slice(&total.to_le_bytes());
    rec[24..32].copy_from_slice(&exe.to_le_bytes());
    rec[40..48].copy_from_slice(&o0.to_le_bytes());
    rec[48..56].copy_from_slice(&o1.to_le_bytes());
    let crc = crc32(&rec[..60]);
    rec[60..].copy_from_slice(&crc.to_le_bytes());
    buf[off..off + 64].copy_from_slice(&rec);
}

/// Coherent structural Inno fixture (mirrors inno.rs's own fixture):
/// `.text` + zeroed `.rsrc` + overlay [file data][SetupID][setup-0][e32],
/// v2 offset table written into `.rsrc`. `declared_extra` inflates the
/// declared TotalSize to model a truncated download (→ Corroborated).
fn inno_pe(declared_extra: u64) -> Vec<u8> {
    let mut overlay = Vec::new();
    overlay.extend_from_slice(&[0x61; 32]);
    let off0 = overlay.len() as u64;
    let mut setup_id = [0u8; 64];
    let s = b"Inno Setup Setup Data (6.5.0)";
    setup_id[..s.len()].copy_from_slice(s);
    overlay.extend_from_slice(&setup_id);
    overlay.extend_from_slice(&[0x62; 100]);
    let offexe = overlay.len() as u64;
    overlay.extend_from_slice(&[0x63; 50]);

    let mut data = PeBuilder::new()
        .section(".text", 0x200, 0x200)
        .add_section(SectionSpec::new(".rsrc", 0x200, 0x200).fill(0))
        .overlay(&overlay)
        .build();
    let pe = crate::layers::framework::pe::parse(&data).expect("fixture parses");
    let rsrc = pe.sections.iter().find(|s| s.name == ".rsrc").unwrap();
    let table_off = u64::from(rsrc.raw_ptr) + 0x20;
    let overlay_start = pe.overlay_start;
    let total = data.len() as u64 + declared_extra;
    inno_write_table_v2(
        &mut data,
        table_off as usize,
        total,
        overlay_start + offexe,
        overlay_start + off0,
        overlay_start,
    );
    data
}

/// Coherent structural WiX Burn fixture (mirrors wix.rs's own fixture).
fn burn_pe() -> Vec<u8> {
    let mut overlay = vec![0u8; 0x80];
    overlay[..4].copy_from_slice(b"MSCF");
    let ux_len = overlay.len() as u32;
    let mut data = PeBuilder::new()
        .section(".text", 0x100, 0x100)
        .add_section(SectionSpec::new(".wixburn", 0x200, 0x200))
        .overlay(&overlay)
        .build();
    let pe = crate::layers::framework::pe::parse(&data).expect("fixture parses");
    let base = pe
        .sections
        .iter()
        .find(|s| s.name == ".wixburn")
        .unwrap()
        .raw_ptr as usize;
    patch_u32_le(&mut data, base, 0x00F1_4300); // BURN_SECTION_MAGIC
    patch_u32_le(&mut data, base + 0x04, 2); // BURN_SECTION_VERSION
    patch_u32_le(&mut data, base + 0x18, pe.overlay_start as u32); // dwStubSize
    patch_u32_le(&mut data, base + 0x28, 1); // CABINET
    patch_u32_le(&mut data, base + 0x2C, 1); // cContainers
    patch_u32_le(&mut data, base + 0x30, ux_len); // UX size
    data
}

fn finding(layer: Layer, weight: u32, desc: &str, detail: Option<&str>) -> Finding {
    Finding {
        layer,
        severity: Severity::Medium,
        weight,
        description: desc.into(),
        technical_detail: detail.map(Into::into),
    }
}

fn score_of(data: &[u8], findings: &mut Vec<Finding>) -> (u32, Verdict, FrameworkMitigation) {
    let d = detect(data, "setup.exe");
    let fm = FrameworkMitigation::evaluate(d, findings);
    let (score, verdict, _) = aggregate_score(findings, 0, 0, &fm);
    (score, verdict, fm)
}

// ═══════════════════════════════════════════════════════════════
//  TASK 1 (scoring half) — fixture → mitigation eligibility, each
//  mitigation op, raw score, final score, verdict.
// ═══════════════════════════════════════════════════════════════

/// Fake NSIS marker + packer-like structure: the packer/structural
/// findings must NOT be divided — the full score stands.
#[test]
fn adversarial_fake_nsis_packer_like_structure_gets_no_mitigation() {
    // High-entropy-looking section fill (deterministic pattern), NSIS
    // marker planted in the section body.
    let mut data = PeBuilder::new()
        .add_section(
            SectionSpec::new(".text", 0x400, 0x400)
                .raw_ptr_override(0x200)
                .characteristics(0xE000_0020),
        )
        .overlay(&[0x55; 0x200])
        .build();
    for (i, b) in data[0x200..0x600].iter_mut().enumerate() {
        *b = (i as u32).wrapping_mul(2654435761) as u8; // deterministic "entropy"
    }
    data[0x300..0x310].copy_from_slice(&[
        0xEF, 0xBE, 0xAD, 0xDE, b'N', b'u', b'l', b'l', b's', b'o', b'f', b't', b'I', b'n',
        b's', b't',
    ]);
    let d = detect(&data, "packed_setup.exe");
    assert!(d.confidence() <= Confidence::WeakHint);

    let mut findings = vec![
        finding(Layer::StructuralAnalysis, 30, "high entropy section", None),
        finding(Layer::PackerDetection, 15, "large overlay", None),
    ];
    let fm = FrameworkMitigation::evaluate(d, &mut findings);
    assert!(!fm.applied, "planted marker must not authorize mitigation");
    assert_eq!(findings[0].weight, 30);
    assert_eq!(findings[1].weight, 15);
    assert_eq!(fm.score_before, 45);
    assert_eq!(fm.score_after, 45);
    let (score, verdict, _) = aggregate_score(&mut findings, 0, 0, &fm);
    assert_eq!(score, 45, "full packer score stands");
    assert_eq!(verdict, Verdict::from_score(45));
}

/// Fake Inno marker + malicious YARA evidence: the detection never
/// qualifies, so the weight-40 finding is never even at risk of division.
/// The genuine-structure veto twin is covered by the existing engine tests
/// (mitigation_high_confidence_finding_vetoes); this pins the spoof side.
#[test]
fn adversarial_fake_inno_marker_with_malicious_yara_stays_unmitigated() {
    let mut overlay = b"prefix Inno Setup S trailing".to_vec();
    overlay.extend_from_slice(&[0u8; 64]);
    let data = pe_with_aligned_overlay(&overlay);
    let d = detect(&data, "setup.exe");
    assert!(d.confidence() <= Confidence::WeakHint);

    let mut findings = vec![finding(
        Layer::YaraRules,
        40,
        "Ransomware note pattern",
        Some("Pack: ransomware"),
    )];
    let fm = FrameworkMitigation::evaluate(d, &mut findings);
    assert!(!fm.applied);
    assert!(fm.veto_reason.is_none(), "nothing to veto — never qualified");
    assert_eq!(findings[0].weight, 40);
    let (score, _, _) = aggregate_score(&mut findings, 0, 0, &fm);
    assert_eq!(score, 40);
}

/// Structural NSIS: every mitigation op + raw/final score + verdict.
#[test]
fn adversarial_structural_nsis_scoring_end_to_end() {
    let data = structural_nsis_pe(200);
    let d = detect(&data, "setup.exe");
    assert_eq!(d.confidence(), Confidence::Structural);
    assert!(d.mitigation_safe());

    let mut findings = vec![
        finding(Layer::StructuralAnalysis, 30, "high entropy section", None),
        finding(Layer::PackerDetection, 15, "large overlay", None),
        finding(
            Layer::YaraRules,
            20,
            "Drops and executes a second-stage payload",
            Some("Rule: Dropper_Generic dropper"),
        ),
    ];
    let fm = FrameworkMitigation::evaluate(d, &mut findings);
    assert!(fm.applied);
    // Each mitigation: Structural /3, Packer /3, installer-class YARA /2.
    assert_eq!(findings[0].weight, 10);
    assert_eq!(findings[1].weight, 5);
    assert_eq!(findings[2].weight, 10);
    assert_eq!(fm.ops.len(), 3);
    assert_eq!(fm.score_before, 65);
    assert_eq!(fm.score_after, 25);

    let (score, verdict, expl) = aggregate_score(&mut findings, 0, 0, &fm);
    assert_eq!(score, 25, "raw score == final score (no caps/discounts hit)");
    assert_eq!(verdict, Verdict::from_score(25));
    assert!(expl.installer_discount_applied);
    assert_eq!(expl.framework.as_deref(), Some("NSIS"));
}

/// Structural Inno: mitigation eligibility + score path for the second
/// framework (only NSIS was pinned by the pre-existing engine tests).
#[test]
fn adversarial_structural_inno_scoring_end_to_end() {
    let data = inno_pe(0);
    let d = detect(&data, "setup.exe");
    assert_eq!(d.kind(), FrameworkKind::InnoSetup);
    assert_eq!(d.confidence(), Confidence::Structural);
    assert!(d.mitigation_safe());

    let mut findings = vec![
        finding(Layer::StructuralAnalysis, 30, "high entropy section", None),
        finding(Layer::PackerDetection, 18, "few imports", None),
    ];
    let fm = FrameworkMitigation::evaluate(d, &mut findings);
    assert!(fm.applied);
    assert_eq!(findings[0].weight, 10);
    assert_eq!(findings[1].weight, 6);
    assert_eq!(fm.score_before, 48);
    assert_eq!(fm.score_after, 16);
    let (score, verdict, expl) = aggregate_score(&mut findings, 0, 0, &fm);
    assert_eq!(score, 16);
    assert_eq!(verdict, Verdict::from_score(16));
    assert_eq!(expl.framework.as_deref(), Some("Inno Setup"));
}

/// Structural WiX Burn: mitigation eligibility + score path for the third
/// framework.
#[test]
fn adversarial_structural_burn_scoring_end_to_end() {
    let data = burn_pe();
    let d = detect(&data, "bundle.exe");
    assert_eq!(d.kind(), FrameworkKind::WixBurn);
    assert_eq!(d.confidence(), Confidence::Structural);
    assert!(d.mitigation_safe());

    let mut findings = vec![finding(Layer::PackerDetection, 15, "large overlay", None)];
    let fm = FrameworkMitigation::evaluate(d, &mut findings);
    assert!(fm.applied);
    assert_eq!(findings[0].weight, 5);
    let (score, verdict, expl) = aggregate_score(&mut findings, 0, 0, &fm);
    assert_eq!(score, 5);
    assert_eq!(verdict, Verdict::from_score(5));
    assert_eq!(expl.framework.as_deref(), Some("WiX Burn"));
}

/// Installer-shaped file with an independent IoC-weight finding: veto →
/// no division → still a high score and a malicious-band verdict.
#[test]
fn adversarial_installer_with_ioc_finding_vetoes_and_stays_high() {
    let data = structural_nsis_pe(200);
    let mut findings = vec![
        finding(Layer::StructuralAnalysis, 30, "high entropy section", None),
        finding(
            Layer::IocCorrelation,
            90,
            "File hash matches a known-malicious indicator of compromise (IOC).",
            None,
        ),
    ];
    let (score, verdict, fm) = score_of(&data, &mut findings);
    assert!(!fm.applied, "IoC-90 must veto installer mitigation");
    assert!(fm.veto_reason.is_some());
    // aggregate_score sorts by weight — assert the multiset is untouched.
    let mut weights: Vec<u32> = findings.iter().map(|f| f.weight).collect();
    weights.sort_unstable();
    assert_eq!(weights, [30, 90], "veto leaves weights untouched");
    assert_eq!(score, 100, "30 + 90 clamped at MAX_SCORE");
    assert_eq!(verdict, Verdict::from_score(100));
}

// ═══════════════════════════════════════════════════════════════
//  TASK 2 (scoring half) — metamorphic invariants over the score.
// ═══════════════════════════════════════════════════════════════

/// M1 (score half): appending arbitrary installer text cannot lower the
/// threat score — sweep every marker text; final score must be identical
/// to the no-marker baseline.
#[test]
fn adversarial_appending_installer_text_never_lowers_score() {
    let markers: [&[u8]; 6] = [
        b"Nullsoft Inst",
        &[
            0xEF, 0xBE, 0xAD, 0xDE, b'N', b'u', b'l', b'l', b's', b'o', b'f', b't', b'I', b'n',
            b's', b't',
        ],
        b"Inno Setup",
        b"Windows Installer",
        b".wixburn",
        b"InnoSetupLdr",
    ];
    let base = PeBuilder::new().section(".text", 0x200, 0x200).build();
    let mk = || {
        vec![
            finding(Layer::StructuralAnalysis, 30, "high entropy section", None),
            finding(Layer::PackerDetection, 15, "large overlay", None),
        ]
    };
    let mut f0 = mk();
    let (baseline, _, _) = aggregate_score(&mut f0, 0, 0, &FrameworkMitigation::none());

    for (i, marker) in markers.iter().enumerate() {
        let mut data = base.clone();
        data.extend_from_slice(marker);
        let mut f = mk();
        let fm = FrameworkMitigation::evaluate(detect(&data, "setup.exe"), &mut f);
        assert!(!fm.applied, "marker {i} authorized mitigation");
        let (score, _, _) = aggregate_score(&mut f, 0, 0, &fm);
        assert_eq!(score, baseline, "marker {i} lowered the score");
    }
}

/// M4 (score half): adding independent malicious evidence to a valid
/// installer cannot make it safer — score is monotone in the added weight
/// across the three known high-weight emitters (YARA-40, MIME-45, IoC-90).
#[test]
fn adversarial_adding_malicious_evidence_never_makes_safer() {
    let data = structural_nsis_pe(200);
    let mk = || vec![finding(Layer::StructuralAnalysis, 30, "high entropy section", None)];

    let mut f_plain = mk();
    let (score_plain, _, _) = score_of(&data, &mut f_plain);

    for (layer, weight, desc) in [
        (Layer::YaraRules, 40, "Ransomware note pattern"),
        (Layer::MimeValidation, 45, "File extension does not match magic bytes"),
        (Layer::IocCorrelation, 90, "hash matches known-malicious IOC"),
    ] {
        let mut f = mk();
        f.push(finding(layer, weight, desc, None));
        let (score, _, fm) = score_of(&data, &mut f);
        assert!(!fm.applied, "weight-{weight} {layer:?} must veto");
        assert!(
            score >= score_plain,
            "adding {layer:?}@{weight} lowered the score ({score} < {score_plain})"
        );
    }
}

/// M5 (score half): multiple weak strings cannot stack mitigation — all
/// markers at once, score identical to baseline.
#[test]
fn adversarial_stacked_weak_strings_never_stack_mitigation() {
    let mut data = PeBuilder::new().section(".text", 0x200, 0x200).build();
    data.extend_from_slice(
        b"Nullsoft Inst Inno Setup InnoSetupLdr Windows Installer .wixburn",
    );
    let mut findings = vec![
        finding(Layer::StructuralAnalysis, 30, "high entropy section", None),
        finding(Layer::PackerDetection, 15, "large overlay", None),
    ];
    let fm = FrameworkMitigation::evaluate(detect(&data, "setup.exe"), &mut findings);
    assert!(!fm.applied, "stacked weak markers must not combine");
    assert_eq!(findings[0].weight, 30);
    assert_eq!(findings[1].weight, 15);
    let (score, _, _) = aggregate_score(&mut findings, 0, 0, &fm);
    assert_eq!(score, 45);
}

/// M6 (score half): parser failure cannot become mitigation — the
/// malformed-PE matrix (each carrying a fully valid NSIS archive) must
/// receive zero weight reduction.
#[test]
fn adversarial_parser_failure_never_applies_mitigation() {
    let archive = nsis_overlay_no_crc(200);

    let mut e_lfanew_past_eof = pe_with_aligned_overlay(&archive);
    let past = e_lfanew_past_eof.len() as u32 + 0x1000;
    patch_u32_le(&mut e_lfanew_past_eof, 0x3C, past);

    let mut e_lfanew_max = pe_with_aligned_overlay(&archive);
    patch_u32_le(&mut e_lfanew_max, 0x3C, u32::MAX);

    let zero_sections = PeBuilder::new()
        .section(".text", 0x200, 0x200)
        .section_count_override(0)
        .overlay(&archive)
        .build();

    let over_count = PeBuilder::new()
        .section(".text", 0x200, 0x200)
        .section_count_override(97)
        .overlay(&archive)
        .build();

    for (name, data) in [
        ("e_lfanew past EOF", e_lfanew_past_eof),
        ("e_lfanew = u32::MAX", e_lfanew_max),
        ("zero sections", zero_sections),
        ("97 sections", over_count),
    ] {
        let mut findings = vec![finding(Layer::StructuralAnalysis, 30, "entropy", None)];
        let fm = FrameworkMitigation::evaluate(detect(&data, "setup.exe"), &mut findings);
        assert!(!fm.applied, "{name}: parser failure applied mitigation");
        assert!(!fm.detection.mitigation_safe(), "{name}");
        assert_eq!(findings[0].weight, 30, "{name}");
    }
}

/// M3 (score half): truncating a valid structure cannot increase
/// mitigation — the truncated-Inno Corroborated case is the interesting
/// one (NSIS truncation is pinned detector-side and by the existing
/// engine test mitigation_truncation_never_increases_mitigation).
#[test]
fn adversarial_truncated_inno_corroborated_gets_no_mitigation() {
    // Declared TotalSize beyond EOF: every present byte verifies, so the
    // detection is Corroborated AND mitigation_safe at the detection level
    // — but engine policy 1 requires Structural, so no division happens.
    let data = inno_pe(0x10_000);
    let d = detect(&data, "setup.exe");
    assert_eq!(d.kind(), FrameworkKind::InnoSetup);
    assert_eq!(d.confidence(), Confidence::Corroborated);
    assert!(d.mitigation_safe(), "build() invariant allows Corroborated+structural");

    let mut findings = vec![finding(Layer::StructuralAnalysis, 30, "entropy", None)];
    let fm = FrameworkMitigation::evaluate(d, &mut findings);
    assert!(!fm.applied, "Corroborated (truncated) must not be mitigated");
    assert_eq!(findings[0].weight, 30);
}

/// Polyglots at the scoring level: MZ+ZIP / MZ+PDF carriers with planted
/// markers receive no weight reduction.
#[test]
fn adversarial_polyglots_get_no_mitigation() {
    let mut zip_overlay = Vec::new();
    zip_overlay.extend_from_slice(b"PK\x03\x04");
    zip_overlay.extend_from_slice(&[0u8; 60]);
    zip_overlay.extend_from_slice(b"Nullsoft Inst");
    zip_overlay.extend_from_slice(&[0u8; 64]);

    let mut pdf_overlay = b"%PDF-1.7\n1 0 obj\n<<>>\n".to_vec();
    pdf_overlay.extend_from_slice(b"Windows Installer");
    pdf_overlay.extend_from_slice(&[0u8; 64]);

    for (name, overlay) in [("MZ+ZIP", zip_overlay), ("MZ+PDF", pdf_overlay)] {
        let data = pe_with_aligned_overlay(&overlay);
        let mut findings = vec![finding(Layer::StructuralAnalysis, 30, "entropy", None)];
        let fm = FrameworkMitigation::evaluate(detect(&data, "poly.exe"), &mut findings);
        assert!(!fm.applied, "{name} polyglot applied mitigation");
        assert_eq!(findings[0].weight, 30, "{name}");
    }
}

/// Signed-ordinary-software analog at the scoring level: a WeakHint-only
/// detection (installer terminology, no structure) with a reputation
/// discount present — the framework pass must not add any reduction on
/// top of the trust discount.
#[test]
fn adversarial_weak_hint_adds_nothing_on_top_of_trust_discount() {
    let mut overlay = b"Windows Installer is required. uninstall included.".to_vec();
    overlay.extend_from_slice(&[0u8; 64]);
    let data = pe_with_aligned_overlay(&overlay);
    let d = detect(&data, "MyApp_setup.exe");
    assert!(d.confidence() <= Confidence::WeakHint);

    let mut findings = vec![finding(Layer::StructuralAnalysis, 30, "entropy", None)];
    let fm = FrameworkMitigation::evaluate(d, &mut findings);
    assert!(!fm.applied);
    assert_eq!(findings[0].weight, 30);
    // 30 raw − 20 reputation discount = 10; the WeakHint framework pass
    // must not have shaved anything further.
    let (score, _, _) = aggregate_score(&mut findings, 20, 0, &fm);
    assert_eq!(score, 10);
}
