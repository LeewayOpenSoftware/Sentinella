//! NSIS (Nullsoft Scriptable Install System) detector — bounded structural
//! detection of the NSIS data block in the PE overlay.
//!
//! ## Format anchors (verified against primary sources)
//!
//! The NSIS installer file layout is `exehead (PE stub) || archive || [CRC] ||
//! [trailing data]`. The archive begins with the 28-byte `firstheader`
//! (`sizeof(int) * 7`, `#pragma pack(1)`):
//!
//! ```text
//! offset  field
//!   0     flags                       (FH_FLAGS_MASK 0xF; UNINSTALL=1,
//!                                    SILENT=2, NO_CRC=4, FORCE_CRC=8)
//!   4     siginfo  = 0xDEADBEEF (LE: EF BE AD DE)
//!   8     nsinst[3]= "NullsoftInst"  (FH_INT1..3 = 0x6C6C754E, 0x74666F73,
//!                                    0x74736E49 — LE dwords "Null"/"soft"/"Inst")
//!  20     length_of_header           (UNcompressed size of the header block)
//!  24     length_of_all_following_data ("ArcSize": compressed header +
//!                                    datablock + sizeof(firstheader) +
//!                                    (CRC ? 4 : 0), measured FROM archive start)
//! ```
//!
//! Sources:
//! - NSIS `Source/exehead/fileform.h` — firstheader layout, FH_SIG/FH_INT1..3,
//!   flag bits, "length of all the data (including the firstheader and CRC)":
//!   <https://github.com/kichik/nsis/blob/master/Source/exehead/fileform.h>
//! - NSIS `Source/exehead/fileform.c::loadHeaders` — the exehead's own
//!   acceptance checks: `(flags & ~FH_FLAGS_MASK) == 0`, siginfo, all three
//!   nsinst ints, and `length_of_all_following_data <= remaining file bytes`;
//!   the file is scanned in 512-byte chunks and the firstheader is only ever
//!   checked at a chunk start ⇒ **archive start is 512-byte aligned**:
//!   <https://github.com/kichik/nsis/blob/master/Source/exehead/fileform.c>
//! - NSIS `Source/build.cpp::write_output` — makensis writes the exehead then
//!   the firstheader immediately (no padding), the firstheader is written
//!   uncompressed even in solid (`build_compress_whole`) mode, and the CRC
//!   covers file bytes `[512, archive_start + ArcSize - 4)` with the stored
//!   CRC32 (standard zlib CRC-32, poly 0xEDB88320) at
//!   `archive_start + ArcSize - 4`:
//!   <https://github.com/kichik/nsis/blob/master/Source/build.cpp>
//! - NSIS `Source/crc32.c` — "based on the (slow,small) CRC32 implementation
//!   from zlib" (reflected, init/xorout 0xFFFFFFFF):
//!   <https://github.com/kichik/nsis/blob/master/Source/crc32.c>
//! - 7-Zip `CPP/7zip/Archive/Nsis/NsisIn.cpp` / `NsisIn.h` — 16-byte signature
//!   `{ EF BE AD DE, "NullsoftInst" }` at firstheader+4, `kStep = 512`
//!   ("nsis start is aligned for 512"), `kFlagsMask = 0xF`,
//!   `ArcSize > sizeof(firstheader)` required:
//!   <https://github.com/mcmilk/7-Zip-zstd/blob/master/CPP/7zip/Archive/Nsis/NsisIn.cpp>
//!
//! ## Consequences for this detector
//!
//! - **Uninstallers** use the identical firstheader with `FH_FLAGS_UNINSTALL`
//!   set (same scan path in the exehead) — detected identically, flagged in
//!   the evidence detail.
//! - **Solid vs non-solid compression** only changes what follows the
//!   firstheader; the firstheader itself is always stored raw, so detection
//!   needs NO decompression and we never decompress for classification.
//! - **Trailing data after the archive is legitimate** (default non-CRC_ANAL
//!   builds: "you can tack stuff on the end and it'll still work" —
//!   fileform.c; Authenticode signatures on installers live there), so
//!   `archive_start + ArcSize <= file_len` is the check, never `==`.
//! - The old `Nullsoft Inst` (with space) substring needle matches the
//!   *version-info text* "Nullsoft Install System …" — attacker-controlled
//!   decoration. This detector never scans for it. The only text-grade signal
//!   we emit is a diagnostic WeakHint when the real 16-byte archive signature
//!   is found somewhere the structure does not support (a probable spoof).
//!
//! ## Confidence policy
//!
//! - `Structural`: a firstheader at a 512-aligned offset inside the overlay
//!   probe window whose flags/header_len/arc_size all pass the exehead's own
//!   sanity checks, with the CRC either disabled (NO_CRC) or verified.
//! - `Corroborated`: same, but the CRC is present and does NOT verify
//!   (corrupt/tampered archive, or a rare NSIS_CONFIG_CRC_ANAL build whose
//!   CRC covers the whole file — we follow the default layout). Still
//!   structurally NSIS-shaped; the mismatch is recorded as a warning.
//! - `WeakHint`: no valid firstheader, but the 16-byte archive signature was
//!   found elsewhere in the buffer (sections, resources, unaligned overlay
//!   offset). Diagnostic only, never mitigation-safe (enforced centrally by
//!   `FrameworkDetection::build` — TextHint evidence can never authorize
//!   mitigation, and we never claim Corroborated on text).
//! - `Unknown`: nothing.
//!
//! ## Deliberate non-goals / unresolved uncertainties
//!
//! - No section-name heuristics (".ndata" etc.): not verified as reliable
//!   NSIS markers in any primary source consulted; skipped.
//! - No version-info corroboration: `PeInfo` exposes only `has_resources`
//!   (no resource parser), and a bool is too weak to cite as `VersionInfo`
//!   evidence; skipped rather than hand-rolled here.
//! - `length_of_header` is the UNCOMPRESSED header size; with solid
//!   compression it can legitimately exceed ArcSize, so we only require it
//!   to be non-zero (and in int range). No tighter relation is enforced.
//! - NSIS_CONFIG_CRC_ANAL builds CRC the entire file including the stub;
//!   our CRC check follows the DEFAULT layout (`[512, arc_end-4)`), so such
//!   installers (rare compile-time variant) downgrade to Corroborated.
//! - Stubs carrying their own overlay larger than one 512-block before the
//!   archive are outside the probe window and are missed (fail-closed).
//! - Totality: all reads go through `pe::get`/`read_u32_le`, all offset math
//!   is u64-widened and checked, no allocation is driven by file contents
//!   (the CRC pass is a bounded linear scan over in-memory bytes).

use super::pe::{PeInfo, get, read_u32_le};
use super::{Confidence, EvidenceItem, EvidenceSource, FrameworkDetection, FrameworkKind};

/// `sizeof(firstheader)` = 7 ints (C_ASSERT in fileform.c).
const FIRSTHEADER_LEN: u64 = 28;
/// `FH_SIG` (fileform.h), stored little-endian.
const SIGINFO: u32 = 0xDEAD_BEEF;
/// `FH_INT1..3` as bytes: "NullsoftInst" at firstheader+8.
const NSINST: &[u8; 12] = b"NullsoftInst";
/// `FH_FLAGS_MASK` (fileform.h) / `kFlagsMask` (7-Zip): only low 4 bits valid.
const FH_FLAGS_MASK: u32 = 0xF;
/// `FH_FLAGS_UNINSTALL` — uninstaller data block (same firstheader layout).
const FH_FLAGS_UNINSTALL: u32 = 1;
/// `FH_FLAGS_NO_CRC` — no CRC trailer follows the archive.
const FH_FLAGS_NO_CRC: u32 = 4;
/// The full 16-byte archive signature at firstheader+4 (7-Zip NSIS_SIGNATURE).
const SIGNATURE: [u8; 16] = [
    0xEF, 0xBE, 0xAD, 0xDE, b'N', b'u', b'l', b'l', b's', b'o', b'f', b't', b'I', b'n', b's',
    b't',
];
/// Archive start is 512-aligned (exehead scans 512-byte chunks; 7-Zip kStep).
const ARCHIVE_ALIGN: u64 = 512;
/// Probe window: 512-aligned archive-start candidates within this span from
/// the overlay start (covers stubs with up to one block of their own overlay;
/// fail-closed beyond it — documented in the module docs).
const PROBE_SPAN: u64 = 512;
/// The NSIS CRC covers file bytes from offset 512 (not 0) through the end of
/// the archive minus the 4-byte CRC trailer (build.cpp: `CRC32(crc,
/// m_exehead+512, m_exehead_size-512)` + firstheader + header + datablock;
/// fileform.c: chunks before offset 512 are not accumulated).
const CRC_REGION_START: u64 = 512;
/// firstheader int fields are C `int`s; values above INT32_MAX are invalid.
/// Also `NSIS_MAX_EXEDATASIZE` = 0x7fffffff (fileform.h).
const MAX_INT_FIELD: u32 = 0x7FFF_FFFF;

/// A candidate firstheader that passed all structural sanity checks.
struct FirstHeader {
    flags: u32,
    header_len: u32,
    arc_size: u32,
}

/// Detect NSIS installers from parsed PE structure.
///
/// Total on any input: no panics, no indexing, no unchecked arithmetic, no
/// content-driven allocation, no decompression.
pub(crate) fn detect(data: &[u8], pe: &PeInfo) -> FrameworkDetection {
    let mut warnings: Vec<String> = Vec::new();
    let file_len = data.len() as u64;

    if pe.overlay_len >= FIRSTHEADER_LEN {
        // Candidates: 512-aligned offsets in [overlay_start, overlay_start +
        // PROBE_SPAN] with room for a firstheader. At most two iterations.
        let mut candidate = pe.overlay_start / ARCHIVE_ALIGN * ARCHIVE_ALIGN;
        if candidate < pe.overlay_start {
            candidate += ARCHIVE_ALIGN;
        }
        let probe_end = pe.overlay_start.saturating_add(PROBE_SPAN).min(file_len);
        while candidate <= probe_end {
            let Some(_) = get(data, candidate, FIRSTHEADER_LEN as usize) else {
                break;
            };
            if let Some(fh) = check_firstheader(data, candidate, file_len, &mut warnings) {
                return finalize(data, candidate, fh, warnings);
            }
            candidate += ARCHIVE_ALIGN;
        }
    }

    // No structural anchor. Diagnostic-only pass: is the raw 16-byte archive
    // signature floating somewhere the structure doesn't support (spoof
    // attempt, corrupt file, marker planted in a section/resource)? This is
    // the old evasion primitive — it is reported as a WeakHint with TextHint
    // evidence, which the centralized invariant keeps non-mitigation-safe.
    if let Some(off) = find_signature(data) {
        return FrameworkDetection::build(
            FrameworkKind::Nsis,
            Confidence::WeakHint,
            vec![EvidenceItem::new(
                EvidenceSource::TextHint,
                Some(off),
                "raw NSIS archive signature (DEADBEEF+\"NullsoftInst\") found at a \
                 non-structural offset (no valid firstheader at a 512-aligned \
                 overlay offset) — diagnostic only, a planted marker never \
                 authorizes mitigation",
            )],
            warnings,
        );
    }

    let mut d = FrameworkDetection::unknown();
    d.append_warnings(warnings);
    d
}

/// Validate a candidate firstheader at `off` against the exehead's own
/// acceptance checks (fileform.c::loadHeaders) plus 7-Zip's ArcSize rule.
///
/// Returns `Some` only when the archive signature matches AND every field is
/// sane; signature-present-but-invalid candidates produce a warning (they are
/// the interesting near-miss / tamper cases) and `None`.
fn check_firstheader(
    data: &[u8],
    off: u64,
    file_len: u64,
    warnings: &mut Vec<String>,
) -> Option<FirstHeader> {
    let siginfo = read_u32_le(data, off + 4)?;
    let nsinst = get(data, off + 8, 12)?;
    if siginfo != SIGINFO || nsinst != NSINST {
        return None; // Not NSIS-shaped at all — silent, not a candidate.
    }

    let flags = read_u32_le(data, off)?;
    let header_len = read_u32_le(data, off + 20)?;
    let arc_size = read_u32_le(data, off + 24)?;

    // (flags & ~FH_FLAGS_MASK) must be 0 — exehead rejects anything else.
    if flags & !FH_FLAGS_MASK != 0 {
        warnings.push(format!(
            "NSIS candidate at 0x{off:X}: flags 0x{flags:08X} set bits outside \
             FH_FLAGS_MASK — rejected (exehead would reject it too)"
        ));
        return None;
    }
    // The header block must exist (exehead GlobalAlloc's and reads it).
    if header_len == 0 || header_len > MAX_INT_FIELD {
        warnings.push(format!(
            "NSIS candidate at 0x{off:X}: length_of_header {header_len} is zero or \
             negative-as-int — rejected"
        ));
        return None;
    }
    // ArcSize must exceed sizeof(firstheader) (7-Zip: ArcSize <= 28 → reject).
    if arc_size <= FIRSTHEADER_LEN as u32 || arc_size > MAX_INT_FIELD {
        warnings.push(format!(
            "NSIS candidate at 0x{off:X}: length_of_all_following_data {arc_size} \
             out of range — rejected"
        ));
        return None;
    }
    // Exehead: length_of_all_following_data <= bytes remaining from the
    // archive start to EOF. u64-widened, cannot wrap.
    if u64::from(arc_size) > file_len - off {
        warnings.push(format!(
            "NSIS candidate at 0x{off:X}: declared archive size {arc_size} runs past \
             EOF (0x{file_len:X}) — rejected"
        ));
        return None;
    }

    Some(FirstHeader {
        flags,
        header_len,
        arc_size,
    })
}

/// Build the detection result for a structurally valid firstheader at `off`,
/// strengthening (or downgrading) via the CRC trailer when present.
fn finalize(
    data: &[u8],
    off: u64,
    fh: FirstHeader,
    mut warnings: Vec<String>,
) -> FrameworkDetection {
    let role = if fh.flags & FH_FLAGS_UNINSTALL != 0 {
        "uninstaller"
    } else {
        "installer"
    };
    let arc_end = off + u64::from(fh.arc_size); // ≤ file_len, checked above

    let mut evidence = vec![
        EvidenceItem::new(
            EvidenceSource::Overlay,
            Some(off),
            format!(
                "NSIS data block begins at 512-aligned overlay offset 0x{off:X} \
                 ({role}; archive size {}, header block size {})",
                fh.arc_size, fh.header_len
            ),
        ),
        EvidenceItem::new(
            EvidenceSource::EmbeddedArchive,
            Some(off),
            format!(
                "valid NSIS firstheader: siginfo 0xDEADBEEF at +4, \"NullsoftInst\" \
                 at +8, flags 0x{:X} within FH_FLAGS_MASK, archive bounds \
                 0x{off:X}..0x{arc_end:X} within file",
                fh.flags
            ),
        ),
    ];

    if fh.flags & FH_FLAGS_NO_CRC != 0 {
        // CRCCheck off — no trailer to verify. The validated firstheader at a
        // structural offset is the strong anchor on its own.
        evidence.push(EvidenceItem::new(
            EvidenceSource::EmbeddedArchive,
            Some(off),
            "FH_FLAGS_NO_CRC set: makensis emitted no CRC trailer for this archive",
        ));
        return FrameworkDetection::build(
            FrameworkKind::Nsis,
            Confidence::Structural,
            evidence,
            warnings,
        );
    }

    // CRC present: stored LE CRC32 at arc_end - 4, computed over file bytes
    // [512, arc_end - 4) — the default (non-CRC_ANAL) layout; see module docs.
    let Some(crc_field_off) = arc_end.checked_sub(4) else {
        warnings.push("NSIS archive too small to hold a CRC trailer".into());
        return corroborated(evidence, warnings);
    };
    if off < CRC_REGION_START {
        // Candidates are 512-aligned and inside a PE overlay, so this is
        // effectively unreachable — but never trust that; fail to
        // Corroborated instead of computing a wrong-region CRC.
        warnings.push(format!(
            "NSIS archive at 0x{off:X} starts before the CRC region base 0x200 — \
             CRC not verifiable under the default layout"
        ));
        return corroborated(evidence, warnings);
    }
    let (Some(stored), Some(region)) = (
        read_u32_le(data, crc_field_off),
        get(
            data,
            CRC_REGION_START,
            (crc_field_off - CRC_REGION_START) as usize,
        ),
    ) else {
        warnings.push("NSIS CRC trailer or CRC region not readable — bounds error".into());
        return corroborated(evidence, warnings);
    };

    let computed = crc32(region);
    if computed == stored {
        evidence.push(EvidenceItem::new(
            EvidenceSource::EmbeddedArchive,
            Some(crc_field_off),
            format!(
                "NSIS CRC32 verified: stored 0x{stored:08X} matches CRC of file bytes \
                 [0x200, 0x{crc_field_off:X}) — archive is intact"
            ),
        ));
        FrameworkDetection::build(FrameworkKind::Nsis, Confidence::Structural, evidence, warnings)
    } else {
        warnings.push(format!(
            "NSIS CRC32 mismatch at 0x{crc_field_off:X}: stored 0x{stored:08X} != \
             computed 0x{computed:08X} — archive corrupt/tampered (or a rare \
             CRC_ANAL build); the exehead would refuse to run it"
        ));
        corroborated(evidence, warnings)
    }
}

/// A structurally valid firstheader whose integrity check failed or could not
/// run: still NSIS-shaped, but not Structural-grade.
fn corroborated(evidence: Vec<EvidenceItem>, warnings: Vec<String>) -> FrameworkDetection {
    FrameworkDetection::build(FrameworkKind::Nsis, Confidence::Corroborated, evidence, warnings)
}

/// Bounded scan for the raw 16-byte archive signature — diagnostic WeakHint
/// path only, never evidence for a structural claim. O(file_len), no
/// allocation; reports the first occurrence.
fn find_signature(data: &[u8]) -> Option<u64> {
    data.windows(SIGNATURE.len())
        .position(|w| w == SIGNATURE)
        .map(|p| p as u64)
}

/// Standard zlib CRC-32 (reflected, poly 0xEDB88320, init/xorout 0xFFFFFFFF),
/// exactly the variant NSIS uses (Source/crc32.c). Table generated at compile
/// time; no allocation, no unsafe.
const fn crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut n = 0usize;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
            k += 1;
        }
        table[n] = c;
        n += 1;
    }
    table
}

const CRC32_TABLE: [u32; 256] = crc32_table();

fn crc32(buf: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in buf {
        crc = CRC32_TABLE[((crc ^ u32::from(b)) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::framework::fixtures::{PeBuilder, SectionSpec, patch_u32_le};
    use crate::layers::framework::pe;

    // ── fixture helpers ────────────────────────────────────────────

    /// Serialize a firstheader (28 bytes).
    fn firstheader(flags: u32, header_len: u32, arc_size: u32) -> Vec<u8> {
        let mut v = Vec::with_capacity(28);
        v.extend_from_slice(&flags.to_le_bytes());
        v.extend_from_slice(&SIGINFO.to_le_bytes());
        v.extend_from_slice(NSINST);
        v.extend_from_slice(&header_len.to_le_bytes());
        v.extend_from_slice(&arc_size.to_le_bytes());
        v
    }

    /// A minimal PE whose overlay starts at a 512-aligned offset (0x400).
    ///
    /// Layout: headers end at 0x1A0; the single section's raw body occupies
    /// [0x200, 0x400); the overlay follows at 0x400.
    fn base_pe(overlay: &[u8]) -> Vec<u8> {
        PeBuilder::new()
            .add_section(SectionSpec::new(".text", 0x200, 0x200).raw_ptr_override(0x200))
            .overlay(overlay)
            .build()
    }

    const OVERLAY_START: u64 = 0x400;

    fn overlay_start_of(data: &[u8]) -> u64 {
        pe::parse(data).expect("fixture must parse").overlay_start
    }

    /// A structurally valid NSIS overlay: firstheader + payload, NO_CRC.
    /// `arc_size` covers firstheader + payload; extra trailing bytes may
    /// follow (legitimate — signatures, appended junk).
    fn nsis_overlay_no_crc(payload_len: u32, trailing: &[u8]) -> Vec<u8> {
        let arc_size = FIRSTHEADER_LEN as u32 + payload_len;
        let mut v = firstheader(FH_FLAGS_NO_CRC, 0x100, arc_size);
        v.extend(std::iter::repeat_n(0xCC, payload_len as usize));
        v.extend_from_slice(trailing);
        v
    }

    /// A structurally valid NSIS overlay with a CORRECT CRC trailer.
    /// Built by constructing the whole file first, then computing the CRC
    /// over [0x200, arc_end-4) and patching the trailer.
    fn nsis_pe_with_crc(payload_len: u32, trailing: &[u8]) -> Vec<u8> {
        let arc_size = FIRSTHEADER_LEN as u32 + payload_len + 4;
        let mut overlay = firstheader(0, 0x100, arc_size);
        overlay.extend(std::iter::repeat_n(0xCC, payload_len as usize));
        overlay.extend_from_slice(&[0u8; 4]); // CRC placeholder
        overlay.extend_from_slice(trailing);
        let mut data = base_pe(&overlay);
        let crc_end = OVERLAY_START as usize + arc_size as usize - 4;
        let computed = crc32(&data[CRC_REGION_START as usize..crc_end]);
        data[crc_end..crc_end + 4].copy_from_slice(&computed.to_le_bytes());
        data
    }

    fn run(data: &[u8]) -> FrameworkDetection {
        let pe = pe::parse(data).expect("fixture must parse");
        detect(data, &pe)
    }

    fn has_source(d: &FrameworkDetection, src: EvidenceSource) -> bool {
        d.evidence().iter().any(|e| e.source == src)
    }

    // ── positive cases ─────────────────────────────────────────────

    #[test]
    fn valid_firstheader_at_overlay_start_no_crc_is_structural() {
        let data = base_pe(&nsis_overlay_no_crc(200, &[]));
        assert_eq!(overlay_start_of(&data), OVERLAY_START);
        let d = run(&data);
        assert_eq!(d.kind(), FrameworkKind::Nsis);
        assert_eq!(d.confidence(), Confidence::Structural);
        assert!(d.mitigation_safe());
        assert!(has_source(&d, EvidenceSource::Overlay));
        assert!(has_source(&d, EvidenceSource::EmbeddedArchive));
        assert!(
            d.evidence().iter().any(|e| e.offset == Some(OVERLAY_START)),
            "evidence must cite the archive start offset: {:?}",
            d.evidence()
        );
        assert!(d.warnings().is_empty(), "warnings: {:?}", d.warnings());
    }

    #[test]
    fn valid_firstheader_with_verified_crc_is_structural() {
        let data = nsis_pe_with_crc(200, &[]);
        let d = run(&data);
        assert_eq!(d.confidence(), Confidence::Structural);
        assert!(d.mitigation_safe());
        assert!(
            d.evidence().iter().any(|e| e.detail.contains("CRC32 verified")),
            "evidence: {:?}",
            d.evidence()
        );
        assert!(d.warnings().is_empty(), "warnings: {:?}", d.warnings());
    }

    #[test]
    fn trailing_data_after_archive_is_allowed() {
        // Authenticode-signed installers carry bytes after the CRC; the
        // exehead explicitly tolerates trailing data (fileform.c).
        let data = nsis_pe_with_crc(100, &[0xAA; 64]);
        let d = run(&data);
        assert_eq!(d.confidence(), Confidence::Structural);
        assert!(d.mitigation_safe());
    }

    #[test]
    fn uninstaller_flag_is_detected_and_noted() {
        let arc_size = FIRSTHEADER_LEN as u32 + 64;
        let mut overlay = firstheader(FH_FLAGS_UNINSTALL | FH_FLAGS_NO_CRC, 0x80, arc_size);
        overlay.extend(std::iter::repeat_n(0x42, 64));
        let data = base_pe(&overlay);
        let d = run(&data);
        assert_eq!(d.confidence(), Confidence::Structural);
        assert!(d.mitigation_safe());
        assert!(
            d.evidence().iter().any(|e| e.detail.contains("uninstaller")),
            "evidence: {:?}",
            d.evidence()
        );
    }

    #[test]
    fn archive_at_second_aligned_candidate_is_accepted() {
        // Stub carrying its own small overlay: archive at overlay_start+512.
        let mut overlay = vec![0u8; 512];
        overlay.extend_from_slice(&nsis_overlay_no_crc(64, &[]));
        let data = base_pe(&overlay);
        let d = run(&data);
        assert_eq!(d.confidence(), Confidence::Structural);
        assert!(
            d.evidence()
                .iter()
                .any(|e| e.offset == Some(OVERLAY_START + 512))
        );
    }

    // ── downgrade case: CRC mismatch ───────────────────────────────

    #[test]
    fn crc_mismatch_downgrades_to_corroborated_with_warning() {
        let mut data = nsis_pe_with_crc(200, &[]);
        // Corrupt one payload byte inside the CRC region (after the
        // firstheader so the header still validates).
        let pos = OVERLAY_START as usize + FIRSTHEADER_LEN as usize + 10;
        data[pos] ^= 0xFF;
        let d = run(&data);
        assert_eq!(d.confidence(), Confidence::Corroborated);
        // Corroborated + structural evidence is still mitigation-safe per the
        // centralized invariant — the file genuinely IS NSIS-structured, just
        // damaged. The mismatch is loud in warnings.
        assert!(d.mitigation_safe());
        assert!(
            d.warnings().iter().any(|w| w.contains("CRC32 mismatch")),
            "warnings: {:?}",
            d.warnings()
        );
    }

    // ── rejection cases ────────────────────────────────────────────

    #[test]
    fn marker_appended_to_arbitrary_overlay_is_weak_hint_at_most() {
        // The classic evasion: random overlay with the raw signature embedded
        // at an unaligned offset, no valid firstheader anywhere.
        let mut overlay = vec![0x11; 300];
        overlay[100..116].copy_from_slice(&SIGNATURE);
        let data = base_pe(&overlay);
        let d = run(&data);
        assert!(d.confidence() <= Confidence::WeakHint);
        assert!(!d.mitigation_safe());
        if d.confidence() == Confidence::WeakHint {
            assert!(d.evidence().iter().all(|e| !e.source.is_structural()));
        }
    }

    #[test]
    fn marker_inside_pe_section_never_exceeds_weak_hint() {
        let mut data = base_pe(&[0x22; 100]);
        // Plant the signature in the section body [0x200, 0x400).
        data[0x280..0x290].copy_from_slice(&SIGNATURE);
        let d = run(&data);
        assert!(d.confidence() <= Confidence::WeakHint);
        assert!(!d.mitigation_safe());
    }

    #[test]
    fn marker_inside_resource_never_exceeds_weak_hint() {
        let mut data = PeBuilder::new()
            .add_section(SectionSpec::new(".text", 0x200, 0x200).raw_ptr_override(0x200))
            .add_section(SectionSpec::new(".rsrc", 0x200, 0x200).raw_ptr_override(0x600))
            .resource_directory(0x2000, 0x80)
            .overlay(&[0x33; 64])
            .build();
        assert!(pe::parse(&data).unwrap().has_resources);
        // Plant the signature inside the .rsrc body [0x600, 0x800).
        data[0x640..0x650].copy_from_slice(&SIGNATURE);
        let d = run(&data);
        assert!(d.confidence() <= Confidence::WeakHint);
        assert!(!d.mitigation_safe());
    }

    #[test]
    fn overlay_too_small_for_firstheader_is_not_structural() {
        // 24 bytes: full 16-byte signature present but header truncated.
        let overlay = &firstheader(FH_FLAGS_NO_CRC, 0x100, 128)[..24];
        let data = base_pe(overlay);
        let d = run(&data);
        assert!(d.confidence() <= Confidence::WeakHint);
        assert!(!d.mitigation_safe());
    }

    #[test]
    fn truncated_archive_past_eof_is_rejected() {
        // Full firstheader, but the declared archive size runs past EOF.
        let data = base_pe(&firstheader(FH_FLAGS_NO_CRC, 0x100, 0x1000));
        let d = run(&data);
        assert!(d.confidence() <= Confidence::WeakHint);
        assert!(!d.mitigation_safe());
        assert!(
            d.warnings().iter().any(|w| w.contains("past EOF")),
            "warnings: {:?}",
            d.warnings()
        );
    }

    #[test]
    fn siginfo_at_unaligned_overlay_offset_is_not_structural() {
        // Overlay starts at 0x300 (NOT 512-aligned): the exehead only probes
        // 512-aligned chunk starts, so a firstheader there is not loadable.
        let mut overlay = nsis_overlay_no_crc(64, &[]);
        let data = PeBuilder::new()
            .add_section(SectionSpec::new(".text", 0x100, 0x100).raw_ptr_override(0x200))
            .overlay(&overlay)
            .build();
        assert_eq!(overlay_start_of(&data), 0x300);
        let d = run(&data);
        assert!(d.confidence() <= Confidence::WeakHint);
        assert!(!d.mitigation_safe());

        // Control: the SAME header at the next aligned offset (still inside
        // the overlay) IS structural.
        let mut padded = vec![0u8; 0x100];
        padded.append(&mut overlay);
        let data2 = PeBuilder::new()
            .add_section(SectionSpec::new(".text", 0x100, 0x100).raw_ptr_override(0x200))
            .overlay(&padded)
            .build();
        let d2 = run(&data2);
        assert_eq!(d2.confidence(), Confidence::Structural);
        assert!(d2.mitigation_safe());
    }

    #[test]
    fn header_length_fields_overflowing_overlay_are_rejected() {
        // ArcSize = INT32_MAX with a small overlay — exehead's
        // "length_of_all_following_data > remaining" check must fire.
        let mut overlay = firstheader(FH_FLAGS_NO_CRC, 0x100, MAX_INT_FIELD);
        overlay.extend(std::iter::repeat_n(0x55, 256));
        let data = base_pe(&overlay);
        let d = run(&data);
        assert!(d.confidence() <= Confidence::WeakHint);
        assert!(!d.mitigation_safe());
    }

    #[test]
    fn degenerate_archive_size_is_rejected() {
        // ArcSize <= sizeof(firstheader): 7-Zip rejects; a real archive
        // always carries at least the compressed header block.
        let mut overlay = firstheader(FH_FLAGS_NO_CRC, 0x100, FIRSTHEADER_LEN as u32);
        overlay.extend(std::iter::repeat_n(0x55, 64));
        let data = base_pe(&overlay);
        let d = run(&data);
        assert!(d.confidence() <= Confidence::WeakHint);
        assert!(!d.mitigation_safe());
    }

    #[test]
    fn zero_header_length_is_rejected() {
        let arc_size = FIRSTHEADER_LEN as u32 + 64;
        let mut overlay = firstheader(FH_FLAGS_NO_CRC, 0, arc_size);
        overlay.extend(std::iter::repeat_n(0x55, 64));
        let data = base_pe(&overlay);
        let d = run(&data);
        assert!(d.confidence() <= Confidence::WeakHint);
        assert!(!d.mitigation_safe());
    }

    #[test]
    fn flags_outside_mask_are_rejected() {
        let arc_size = FIRSTHEADER_LEN as u32 + 64;
        let mut overlay = firstheader(0x10, 0x100, arc_size);
        overlay.extend(std::iter::repeat_n(0x55, 64));
        let data = base_pe(&overlay);
        let d = run(&data);
        assert!(d.confidence() <= Confidence::WeakHint);
        assert!(!d.mitigation_safe());
        assert!(
            d.warnings().iter().any(|w| w.contains("FH_FLAGS_MASK")),
            "warnings: {:?}",
            d.warnings()
        );
    }

    #[test]
    fn conflicting_candidates_first_valid_wins() {
        // Two plausible firstheaders at both candidate offsets: the first
        // (lowest offset, deterministic order) is reported.
        let mut overlay = nsis_overlay_no_crc(64, &[]);
        // Second candidate at +512, also structurally valid.
        let second_at = 512usize;
        overlay.resize(second_at, 0x77);
        overlay.extend_from_slice(&nsis_overlay_no_crc(32, &[]));
        let data = base_pe(&overlay);
        let d = run(&data);
        assert_eq!(d.confidence(), Confidence::Structural);
        assert!(
            d.evidence()
                .iter()
                .filter(|e| e.source == EvidenceSource::Overlay)
                .all(|e| e.offset == Some(OVERLAY_START)),
            "first candidate must win: {:?}",
            d.evidence()
        );
    }

    #[test]
    fn malformed_pe_with_nsis_marker_is_never_safe_end_to_end() {
        // End-to-end through the dispatcher: a malformed PE (e_lfanew past
        // EOF) carrying a fully valid NSIS archive must not reach the
        // structural detector at all.
        let mut data = base_pe(&nsis_overlay_no_crc(200, &[]));
        let past_eof = data.len() as u32 + 0x1000;
        patch_u32_le(&mut data, 0x3C, past_eof);
        let d = crate::layers::framework::detect(&data, "setup.exe");
        assert!(d.confidence() <= Confidence::WeakHint);
        assert!(!d.mitigation_safe());
    }

    #[test]
    fn old_space_separated_needle_is_not_even_a_hint() {
        // The legacy needle 'Nullsoft Inst' (version-info text) must not
        // register: our diagnostic pass looks for the real archive signature.
        let mut overlay = b"some bytes Nullsoft Install System v3.08 more".to_vec();
        overlay.extend_from_slice(&[0u8; 64]);
        let data = base_pe(&overlay);
        let d = run(&data);
        assert_eq!(d.confidence(), Confidence::Unknown);
        assert!(!d.mitigation_safe());
    }

    #[test]
    fn plain_random_overlay_is_unknown() {
        let data = base_pe(&[0x99; 256]);
        let d = run(&data);
        assert_eq!(d.kind(), FrameworkKind::Unknown);
        assert!(!d.mitigation_safe());
    }

    // ── metamorphic cases ──────────────────────────────────────────

    #[test]
    fn moving_header_one_byte_deeper_loses_structural() {
        let mut overlay = vec![0u8; 1];
        overlay.extend_from_slice(&nsis_overlay_no_crc(200, &[]));
        let data = base_pe(&overlay);
        let d = run(&data);
        assert!(d.confidence() < Confidence::Structural);
        assert!(!d.mitigation_safe());
    }

    #[test]
    fn moving_header_64_bytes_deeper_loses_structural() {
        let mut overlay = vec![0u8; 64];
        overlay.extend_from_slice(&nsis_overlay_no_crc(200, &[]));
        let data = base_pe(&overlay);
        let d = run(&data);
        assert!(d.confidence() < Confidence::Structural);
        assert!(!d.mitigation_safe());
    }

    #[test]
    fn truncating_the_header_never_increases_confidence() {
        let overlay = nsis_overlay_no_crc(200, &[]);
        let full = base_pe(&overlay);
        let full_len = full.len();
        let full_conf = run(&full).confidence();
        assert_eq!(full_conf, Confidence::Structural);
        // Cut at every point inside the archive: never Structural, never a
        // panic, never mitigation-safe (and monotonicity: never ABOVE the
        // full file's confidence).
        for cut in OVERLAY_START as usize..full_len {
            let data = &full[..cut];
            let Some(pe) = pe::parse(data) else { continue };
            let d = detect(data, &pe);
            assert!(
                d.confidence() < Confidence::Structural,
                "cut at {cut}: {:?}",
                d.confidence()
            );
            assert!(!d.mitigation_safe(), "cut at {cut} must not be safe");
        }
    }

    #[test]
    fn appending_nullsoft_inst_to_random_pe_never_exceeds_weak_hint() {
        let data = PeBuilder::new()
            .section(".text", 0x200, 0x200)
            .overlay(b"Nullsoft Inst")
            .build();
        let d = run(&data);
        assert!(d.confidence() <= Confidence::WeakHint);
        assert!(!d.mitigation_safe());
    }

    // ── totality sweeps ────────────────────────────────────────────

    #[test]
    fn truncation_at_every_length_never_panics() {
        let data = nsis_pe_with_crc(128, &[0xAA; 32]);
        for cut in 0..=data.len() {
            let d = &data[..cut];
            if let Some(pe) = pe::parse(d) {
                let _ = detect(d, &pe);
            }
        }
    }

    #[test]
    fn byte_mutation_of_overlay_never_panics() {
        let base = nsis_pe_with_crc(64, &[]);
        let start = OVERLAY_START as usize;
        for off in start..base.len() {
            for val in [0x00u8, 0xFF, 0xEF, 0xDE] {
                let mut m = base.clone();
                m[off] = val;
                if m[off] == base[off] {
                    continue; // no-op mutation is not a mutation
                }
                if let Some(pe) = pe::parse(&m) {
                    let d = detect(&m, &pe);
                    // Every overlay byte is either part of the firstheader
                    // (mutation breaks it or is caught by the CRC) or inside
                    // the CRC region / CRC field itself (mutation breaks the
                    // CRC) — a single byte flip must never PRESERVE Structural.
                    assert_ne!(
                        d.confidence(),
                        Confidence::Structural,
                        "mutation at 0x{off:X} to 0x{val:02X} kept Structural"
                    );
                }
            }
        }
    }

    // ── CRC32 self-test ────────────────────────────────────────────

    #[test]
    fn crc32_matches_zlib_known_vectors() {
        // zlib crc32("123456789") = 0xCBF43926 — the standard check value.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(&[0u8; 32]), 0x190A_55AD);
    }
}
