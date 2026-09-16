//! Inno Setup detector — bounded structural detection for Inno Setup 5.x/6.x/7.x
//! (`UseSetupLdr=yes` single-file installers, the default since forever).
//!
//! ## Format anchors (all verified against primary sources)
//!
//! Modern Inno Setup does NOT carry a loader signature at a fixed offset or at
//! the end of the file. Since at least 5.4.3 (the oldest tagged release on
//! GitHub), the setup loader's `TSetupLdrOffsetTable` is stored **inside the
//! stub's resources** as RCDATA resource ID 11111
//! (`SetupLdrOffsetTableResID`), and the compiler rewrites that resource
//! in-place in the compiled `setup.exe`:
//!
//! - Record definition + IDs:
//!   <https://github.com/jrsoftware/issrc/blob/main/Projects/Src/Shared.Struct.pas>
//!   (`TSetupLdrOffsetTable`, `SetupLdrOffsetTableResID = 11111`,
//!   `SetupLdrOffsetTableID = 'rDlPtS'#$CD#$E6#$D7#$7B#$0B#$2A`,
//!   `SetupLdrOffsetTableVersion = 2`)
//! - v1 layout (44 bytes, all 32-bit fields, `SetupLdrOffsetTableVersion = 1`),
//!   used from (at least) 5.4.3 through 6.4.x:
//!   <https://github.com/jrsoftware/issrc/blob/is-5_5_9/Projects/Struct.pas>
//!   <https://github.com/jrsoftware/issrc/blob/is-6_0_0/Projects/Struct.pas>
//! - v2 layout (64 bytes, Int64 `TotalSize`/`OffsetEXE`/`Offset0`/`Offset1`,
//!   `SetupLdrOffsetTableVersion = 2`), used from 6.5.0 onward:
//!   <https://github.com/jrsoftware/issrc/blob/is-6_5_0/Projects/Src/Shared.Struct.pas>
//! - Runtime validation performed by SetupLdr itself (Version equality,
//!   `TableCRC == GetCRC32(record minus last field)`, `file size >= TotalSize`,
//!   then a 64-byte `SetupID` read at `Offset0` compared byte-for-byte):
//!   <https://github.com/jrsoftware/issrc/blob/main/Projects/SetupLdr.dpr>
//!   (`GetSetupLdrOffsetTable`, main block). Note the comment there: the loader
//!   deliberately does NOT check `OffsetTable.ID` so that external tools can
//!   locate the table uniquely by scanning for the ID — the ID is expected to
//!   appear exactly once, in the resource.
//! - `GetCRC32` is the standard zlib CRC-32 (poly 0xEDB88320, init/xorout
//!   0xFFFFFFFF):
//!   <https://github.com/jrsoftware/issrc/blob/main/Projects/Src/Compression.Base.pas>
//! - Compiler-side write: `SeekToResourceData(ExeFile, RT_RCDATA, 11111)` then
//!   `WriteBuffer(SetupLdrOffsetTable)`; `Offset0` = start of the embedded
//!   setup-0 data (appended past the stub PE, i.e. the overlay), `Offset1` =
//!   start of embedded file data (0 when disk spanning), `TotalSize` = exe size
//!   after appending (so an appended Authenticode signature leaves
//!   `file size > TotalSize`):
//!   <https://github.com/jrsoftware/issrc/blob/main/Projects/Src/Compiler.SetupCompiler.pas>
//! - `WriteSetup0` writes the 64-byte `SetupID` first, so the bytes at
//!   `Offset0` start with `Inno Setup Setup Data (x.y.z[.w])[ (u)]` NUL-padded
//!   to 64 bytes. Verified spellings across tags: `(5.5.7)[ (u)]` (is-5_5_9),
//!   `(6.0.0)[ (u)]` (is-6_0_0), `(6.1.0)[ (u)]` (is-6_1_0), `(6.4.0.1)`
//!   (is-6_4_0), `(6.5.0)` (is-6_5_0), `(7.0.0.3)` (is-7_0_0). The version in
//!   the ID is the *format* version, which can lag the release version.
//!
//! ## Corrections to the task briefing (verified, not guessed)
//!
//! - The `'rDlPtS0Xe87ev'` loader-signature family does NOT appear in any
//!   tagged Inno source >= 5.4.3 (checked is-5_4_3, is-5_5_9, is-6_0_0,
//!   is-6_5_0, is-7_0_0, main). It is presumed to be a pre-5.x scheme (the
//!   GitHub history starts at 5.4.3, so this could not be verified further);
//!   pre-5.x installers are simply not detected here (fail-safe direction).
//!   The 5.x+ signature is the 12-byte `'rDlPtS' + CD E6 D7 7B 0B 2A`, and it
//!   lives in an RCDATA resource, not "near the end of file / overlay".
//! - Version-info corroboration was deliberately DROPPED: Inno's compiler
//!   overwrites the stub's version info with application-provided values
//!   (`UpdateVersionInfo` call in Compiler.SetupCompiler.pas; the documented
//!   `VersionInfo*` defaults contain no "Inno Setup" string — e.g.
//!   `VersionInfoDescription` defaults to `"AppName Setup"`,
//!   <https://jrsoftware.org/ishelp/>). There is no stable "Inno Setup"
//!   version string in compiled installers to corroborate against.
//!
//! ## Search window (justification)
//!
//! The offset table is accepted only when found inside the raw range of a
//! section named exactly `.rsrc` — where the Delphi-built SetupLdr stub keeps
//! its resources, and where the compiler writes the table via the resource
//! API. Occurrences anywhere else (overlay, other sections, headers) are
//! reported as WeakHint diagnostics at most, even if the record would
//! otherwise validate. Genuine files whose stub was relinked/packed after
//! compilation lose detection — the fail-safe direction.
//!
//! ## Confidence policy
//!
//! - `Structural`: table in-window + known Version + valid TableCRC +
//!   coherent offsets (`Offset0+64 <= TotalSize`, `Offset0 <= OffsetEXE <
//!   TotalSize`, `Offset1 == 0 || Offset1 <= Offset0`, setup data past the
//!   section space) + `TotalSize <= file size` + 64-byte SetupID at `Offset0`
//!   matching the documented grammar.
//! - `Corroborated`: everything above except `TotalSize > file size` (a
//!   truncated download — every byte still present verifies), with the SetupID
//!   still readable and valid. Monotonic: further truncation that cuts into
//!   the SetupID drops to WeakHint.
//! - `WeakHint`: table ID found but anything fails (unknown version, bad CRC,
//!   incoherent offsets, unreadable/grammar-mismatching SetupID), the ID found
//!   out-of-window, or any free-floating `Inno Setup` / `InnoSetupLdr` text.
//!   Never mitigation-safe, per the centralized invariant.
//!
//! ## Residual spoof analysis (honest)
//!
//! CRC-32 is not cryptographic: a determined attacker can hand-craft a fully
//! "valid" offset table + setup-data header without running Inno's compiler.
//! Doing so requires replicating the entire container structure (resource-held
//! CRC'd table, coherent offsets, SetupID at the pointed overlay offset) —
//! i.e. shipping the Inno structure itself, which is exactly the cost the
//! evidence model in `super::mod.rs` accepts for structural evidence. What
//! this detector closes is the free win: injected strings, copied version
//! resources, and markers at wrong offsets can never exceed WeakHint.
//!
//! Totality: all multi-byte reads go through `pe::get`/`read_u32_le` or the
//! local `read_u64_le`, all offset arithmetic is u64-widened and
//! `checked_add`-guarded, needle scans are bounded by section raw ranges (or
//! one linear pass over the file for diagnostics), and nothing here allocates
//! attacker-controlled sizes or decompresses anything.

use super::pe::{self, PeInfo};
use super::{Confidence, EvidenceItem, EvidenceSource, FrameworkDetection, FrameworkKind};

/// `SetupLdrOffsetTableID`: `'rDlPtS'` followed by bytes CD E6 D7 7B 0B 2A.
/// Expected to appear exactly once in a genuine file — inside the RCDATA
/// resource 11111 (see module docs).
const LDR_TABLE_ID: [u8; 12] = [b'r', b'D', b'l', b'P', b't', b'S', 0xCD, 0xE6, 0xD7, 0x7B, 0x0B, 0x2A];

/// `SizeOf(TSetupLdrOffsetTable)` for table version 1 (packed, 32-bit fields).
const V1_RECORD_LEN: u64 = 44;
/// `SizeOf(TSetupLdrOffsetTable)` for table version 2 (Int64 size/offset fields).
const V2_RECORD_LEN: u64 = 64;
/// `SizeOf(TSetupID)` — the versioned setup-data header at `Offset0`.
const SETUP_ID_LEN: u64 = 64;
/// Fixed prefix of the setup-data header.
const SETUP_ID_PREFIX: &[u8] = b"Inno Setup Setup Data (";

/// Free-floating text markers — diagnostic WeakHint only, never structural.
const TEXT_MARKERS: [&[u8]; 2] = [b"Inno Setup", b"InnoSetupLdr"];

/// Cap on recorded rejected-candidate warnings (each .rsrc needle hit that
/// fails validation) so a hostile file cannot flood diagnostics.
const MAX_REJECTED: usize = 8;

/// Hard cap on needle candidates VALIDATED across all .rsrc sections.
/// The 12-byte table ID contains 5 binary bytes, so a genuine file has
/// ~zero accidental hits (the real table validates on the first candidate).
/// Without this cap, a hostile file filled with the ID forces a CRC
/// validation per occurrence — measured 472 s on one crafted 100 MB file
/// through the full scanner (47× the 10 s realtime budget). 32 rejected
/// candidates means "needle flood", not "Inno file": fail closed to
/// Unknown with a diagnostic, at bounded cost.
const MAX_TABLE_CANDIDATES: usize = 32;

/// Standard zlib CRC-32 (poly 0xEDB88320, init/xorout 0xFFFFFFFF) — the exact
/// algorithm of Inno's `GetCRC32`. Bitwise (no table): inputs here are at most
/// 64 bytes, so the extra cycles are noise and there is one less thing to
/// get wrong.
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

/// Bounded little-endian u64 read (pe.rs exports only u16/u32; the v2 table
/// has Int64 fields).
fn read_u64_le(data: &[u8], offset: u64) -> Option<u64> {
    let bytes: [u8; 8] = pe::get(data, offset, 8)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

/// A parsed and CRC-validated `TSetupLdrOffsetTable` (either layout, widened).
#[derive(Debug, Clone, Copy)]
struct OffsetTable {
    version: u32,
    total_size: u64,
    offset_exe: u64,
    offset0: u64,
    offset1: u64,
}

/// Why a needle hit failed to validate as an offset table.
#[derive(Debug, Clone, Copy)]
enum TableRejection {
    /// Record would run past the section raw range or EOF.
    Truncated,
    /// `Version` field is neither 1 nor 2.
    BadVersion(u32),
    /// `TableCRC` does not match the CRC-32 of the preceding record bytes.
    BadCrc,
}

impl std::fmt::Display for TableRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TableRejection::Truncated => write!(f, "record truncated"),
            TableRejection::BadVersion(v) => write!(f, "unknown table version {v}"),
            TableRejection::BadCrc => write!(f, "TableCRC mismatch"),
        }
    }
}

/// Parse the offset table whose 12-byte ID starts at absolute file offset
/// `abs`. The record must fit within `limit` (the end of the containing
/// section's raw range) so bytes past the section cannot be smuggled into
/// the "resource".
fn parse_offset_table(data: &[u8], abs: u64, limit: u64) -> Result<OffsetTable, TableRejection> {
    let version =
        pe::read_u32_le(data, abs.checked_add(12).ok_or(TableRejection::Truncated)?)
            .ok_or(TableRejection::Truncated)?;
    let rec_len = match version {
        1 => V1_RECORD_LEN,
        2 => V2_RECORD_LEN,
        other => return Err(TableRejection::BadVersion(other)),
    };
    let end = abs.checked_add(rec_len).ok_or(TableRejection::Truncated)?;
    if end > limit || end > data.len() as u64 {
        return Err(TableRejection::Truncated);
    }
    let rec = pe::get(data, abs, rec_len as usize).ok_or(TableRejection::Truncated)?;
    let stored_crc = pe::read_u32_le(data, end - 4).ok_or(TableRejection::Truncated)?;
    if crc32(&rec[..rec_len as usize - 4]) != stored_crc {
        return Err(TableRejection::BadCrc);
    }
    // All field offsets are in-record (checked above); reads cannot fail, but
    // stay total anyway.
    let table = match version {
        1 => OffsetTable {
            version,
            total_size: u64::from(pe::read_u32_le(data, abs + 16).ok_or(TableRejection::Truncated)?),
            offset_exe: u64::from(pe::read_u32_le(data, abs + 20).ok_or(TableRejection::Truncated)?),
            offset0: u64::from(pe::read_u32_le(data, abs + 32).ok_or(TableRejection::Truncated)?),
            offset1: u64::from(pe::read_u32_le(data, abs + 36).ok_or(TableRejection::Truncated)?),
        },
        _ => OffsetTable {
            version,
            total_size: read_u64_le(data, abs + 16).ok_or(TableRejection::Truncated)?,
            offset_exe: read_u64_le(data, abs + 24).ok_or(TableRejection::Truncated)?,
            offset0: read_u64_le(data, abs + 40).ok_or(TableRejection::Truncated)?,
            offset1: read_u64_le(data, abs + 48).ok_or(TableRejection::Truncated)?,
        },
    };
    Ok(table)
}

/// Cross-field coherence, mirroring the invariants of the compiler-written
/// layout (see module docs): the embedded setup-0 header must fit in the
/// declared total, the setup.e32 blob follows the setup-0 data, the embedded
/// file data (when present) precedes it, and the setup data must live past
/// the parsed section space (it is appended after the stub PE).
fn coherence_failure(t: &OffsetTable, pe: &PeInfo) -> Option<&'static str> {
    let Some(setup_id_end) = t.offset0.checked_add(SETUP_ID_LEN) else {
        return Some("Offset0 overflows u64");
    };
    if t.total_size < setup_id_end {
        return Some("TotalSize smaller than Offset0 + SetupID header");
    }
    if t.offset_exe < t.offset0 || t.offset_exe >= t.total_size {
        return Some("OffsetEXE outside [Offset0, TotalSize)");
    }
    if t.offset1 != 0 && t.offset1 > t.offset0 {
        return Some("Offset1 beyond Offset0");
    }
    if t.offset0 < pe.overlay_start || t.offset0 < pe.headers_end {
        return Some("Offset0 points into the parsed section/header space");
    }
    None
}

/// Validate the 64-byte `TSetupID` field and extract the format version
/// string. Grammar (verified spellings in module docs):
/// `"Inno Setup Setup Data ("` + 2..=4 dot-separated numeric components of
/// 1..=3 digits + `")"` + optional `" (u)"`, then NUL padding to 64 bytes.
fn setup_id_version(field: &[u8]) -> Option<String> {
    let rest = field.strip_prefix(SETUP_ID_PREFIX)?;
    let mut i = 0usize;
    let mut components = 0usize;
    loop {
        let mut digits = 0usize;
        while digits < 4 {
            match rest.get(i) {
                Some(b) if b.is_ascii_digit() => {
                    i += 1;
                    digits += 1;
                }
                _ => break,
            }
        }
        if digits == 0 || digits > 3 {
            return None;
        }
        components += 1;
        match rest.get(i) {
            Some(b'.') if components < 4 => {
                i += 1;
            }
            _ => break,
        }
    }
    if components < 2 {
        return None;
    }
    let version_end = i;
    if rest.get(i) != Some(&b')') {
        return None;
    }
    i += 1;
    if rest.len() >= i + 4 && &rest[i..i + 4] == b" (u)" {
        i += 4;
    }
    // Everything after the ID string must be NUL padding.
    if rest[i..].iter().any(|&b| b != 0) {
        return None;
    }
    let version: String = rest[..version_end]
        .iter()
        .map(|&b| char::from(b))
        .collect();
    Some(version)
}

/// Find `needle` in `haystack` at or after `from`. Bounded by the haystack.
fn find_needle(haystack: &[u8], needle: &[u8; 12], from: usize) -> Option<usize> {
    let start = from.min(haystack.len());
    haystack[start..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + start)
}

/// Locate a validating offset table inside the raw ranges of `.rsrc`
/// sections. Also collects (capped) rejection diagnostics for needle hits
/// that did not validate.
fn find_table_in_rsrc(data: &[u8], pe: &PeInfo, warnings: &mut Vec<String>) -> Option<(u64, OffsetTable)> {
    let mut rejected = 0usize;
    let mut candidates = 0usize;
    'sections: for sec in pe.sections.iter().filter(|s| s.name == ".rsrc") {
        let Some(range) = sec.raw_range(data.len()) else {
            continue;
        };
        let Some(bytes) = pe::get(data, range.start as u64, range.len()) else {
            continue;
        };
        let mut from = 0usize;
        while let Some(pos) = find_needle(bytes, &LDR_TABLE_ID, from) {
            // DoS bound: the candidate cap is checked BEFORE any CRC work.
            candidates += 1;
            if candidates > MAX_TABLE_CANDIDATES {
                warnings.push(format!(
                    "more than {MAX_TABLE_CANDIDATES} Inno loader table ID candidates \
                     in .rsrc — needle flood, not an Inno file; giving up (fail closed)"
                ));
                break 'sections;
            }
            let abs = range.start as u64 + pos as u64;
            match parse_offset_table(data, abs, range.end as u64) {
                Ok(table) => return Some((abs, table)),
                Err(why) => {
                    if rejected < MAX_REJECTED {
                        rejected += 1;
                        warnings.push(format!(
                            "Inno loader table ID at 0x{abs:X} inside .rsrc rejected: {why}"
                        ));
                    }
                }
            }
            from = pos + 1;
        }
    }
    None
}

/// Emit the WeakHint diagnostic result for non-structural Inno-ish signals:
/// free-floating text markers and/or out-of-window table IDs.
fn weak_hint_result(
    data: &[u8],
    mut evidence: Vec<EvidenceItem>,
    warnings: Vec<String>,
) -> FrameworkDetection {
    for marker in TEXT_MARKERS {
        if let Some(pos) = data
            .windows(marker.len())
            .position(|w| w == marker)
        {
            evidence.push(EvidenceItem::new(
                EvidenceSource::TextHint,
                Some(pos as u64),
                format!(
                    "unanchored {:?} text marker; diagnostic only — \
                     attacker-controlled decoration, never mitigation-safe",
                    String::from_utf8_lossy(marker)
                ),
            ));
            break; // one representative text hint is enough
        }
    }
    if evidence.is_empty() && warnings.is_empty() {
        return FrameworkDetection::unknown();
    }
    FrameworkDetection::build(FrameworkKind::InnoSetup, Confidence::WeakHint, evidence, warnings)
}

/// Detect Inno Setup installers from parsed PE structure. Total: no panics,
/// no unsafe, no unbounded reads/allocation, no decompression.
pub(crate) fn detect(data: &[u8], pe: &PeInfo) -> FrameworkDetection {
    let mut warnings: Vec<String> = Vec::new();
    let file_len = data.len() as u64;

    let Some((table_off, table)) = find_table_in_rsrc(data, pe, &mut warnings) else {
        // No valid in-window table. Check for an out-of-window table ID
        // (diagnostic only, per the window policy) before falling back to
        // pure text markers. Positions inside .rsrc raw ranges were already
        // diagnosed by find_table_in_rsrc — skip them here.
        let rsrc_ranges: Vec<std::ops::Range<usize>> = pe
            .sections
            .iter()
            .filter(|s| s.name == ".rsrc")
            .filter_map(|s| s.raw_range(data.len()))
            .collect();
        let mut evidence: Vec<EvidenceItem> = Vec::new();
        let mut from = 0usize;
        while let Some(pos) = find_needle(data, &LDR_TABLE_ID, from) {
            from = pos + 1;
            if rsrc_ranges.iter().any(|r| r.contains(&pos)) {
                continue;
            }
            warnings.push(format!(
                "Inno loader table ID found at 0x{pos:X} OUTSIDE the .rsrc resource \
                 section window — not accepted as a structural anchor"
            ));
            evidence.push(EvidenceItem::new(
                EvidenceSource::TextHint,
                Some(pos as u64),
                "Inno loader table ID outside the resource-section window \
                 (wrong region — possible marker injection)",
            ));
            break;
        }
        return weak_hint_result(data, evidence, warnings);
    };

    let table_evidence = |detail: String| {
        EvidenceItem::new(EvidenceSource::Resource, Some(table_off), detail)
    };

    // Fixed-structure checks (offsets/sizes). A failure here means the bytes
    // are not a compiler-written table pointing at real setup data.
    if let Some(why) = coherence_failure(&table, pe) {
        warnings.push(format!(
            "Inno loader offset table at 0x{table_off:X} has incoherent fields: {why}"
        ));
        let evidence = vec![table_evidence(format!(
            "CRC-valid TSetupLdrOffsetTable v{} with incoherent offsets ({why}); \
             treated as decoration, not structure",
            table.version
        ))];
        return weak_hint_result(data, evidence, warnings);
    }

    let setup_id = pe::get(data, table.offset0, SETUP_ID_LEN as usize)
        .and_then(setup_id_version);

    let mut evidence: Vec<EvidenceItem> = vec![table_evidence(format!(
        "Inno Setup loader offset table (TSetupLdrOffsetTable v{}, RCDATA resource \
         11111) in .rsrc raw data: ID, Version and TableCRC valid",
        table.version
    ))];
    if table.offset0 >= pe.overlay_start && pe.overlay_len > 0 {
        evidence.push(EvidenceItem::new(
            EvidenceSource::Overlay,
            Some(table.offset0),
            "setup data (Offset0) lies in the PE overlay, past the last section's \
             raw range — the SetupLdr + appended-data layout",
        ));
    }

    match setup_id {
        Some(version) => {
            evidence.push(EvidenceItem::new(
                EvidenceSource::EmbeddedArchive,
                Some(table.offset0),
                format!(
                    "Inno Setup setup-data header 'Inno Setup Setup Data ({version})' \
                     at the offset table's Offset0"
                ),
            ));
            if table.total_size <= file_len {
                // Full chain: table (ID+Version+CRC) -> coherent offsets ->
                // TotalSize within file -> versioned SetupID at Offset0.
                FrameworkDetection::build(
                    FrameworkKind::InnoSetup,
                    Confidence::Structural,
                    evidence,
                    warnings,
                )
            } else {
                // Everything present verifies; only the declared total runs
                // past EOF — a truncated (partially downloaded) installer.
                warnings.push(format!(
                    "Inno offset table declares TotalSize {} beyond EOF ({file_len}); \
                     all in-file structure verifies — truncated installer",
                    table.total_size
                ));
                FrameworkDetection::build(
                    FrameworkKind::InnoSetup,
                    Confidence::Corroborated,
                    evidence,
                    warnings,
                )
            }
        }
        None => {
            // The table is genuine structure, but the setup data it points at
            // is missing or does not parse — tampering/sever truncation.
            // Never above WeakHint (and never mitigation-safe regardless).
            warnings.push(format!(
                "Inno offset table at 0x{table_off:X} is CRC-valid, but no valid \
                 'Inno Setup Setup Data (x.y.z)' header at Offset0 (0x{:X})",
                table.offset0
            ));
            weak_hint_result(data, evidence, warnings)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::framework::fixtures::{patch_u32_le, PeBuilder, SectionSpec};

    // ── fixture helpers ────────────────────────────────────────────

    /// Build a 64-byte TSetupID field.
    fn setup_id(version: &str, unicode_suffix: bool) -> [u8; 64] {
        let mut id = [0u8; 64];
        let s = format!("Inno Setup Setup Data ({version}){}", if unicode_suffix { " (u)" } else { "" });
        id[..s.len()].copy_from_slice(s.as_bytes());
        id
    }

    /// Write a CRC-valid TSetupLdrOffsetTable into `buf` at `off`.
    #[allow(clippy::too_many_arguments)]
    fn write_table(
        buf: &mut [u8],
        off: usize,
        version: u32,
        total_size: u64,
        offset_exe: u64,
        offset0: u64,
        offset1: u64,
    ) {
        let rec_len = match version {
            1 => V1_RECORD_LEN as usize,
            _ => V2_RECORD_LEN as usize,
        };
        let mut rec = vec![0u8; rec_len];
        rec[..12].copy_from_slice(&LDR_TABLE_ID);
        let put32 = |rec: &mut [u8], at: usize, v: u32| {
            rec[at..at + 4].copy_from_slice(&v.to_le_bytes());
        };
        let put64 = |rec: &mut [u8], at: usize, v: u64| {
            rec[at..at + 8].copy_from_slice(&v.to_le_bytes());
        };
        put32(&mut rec, 12, version);
        match version {
            1 => {
                put32(&mut rec, 16, total_size as u32);
                put32(&mut rec, 20, offset_exe as u32);
                put32(&mut rec, 32, offset0 as u32);
                put32(&mut rec, 36, offset1 as u32);
            }
            _ => {
                put64(&mut rec, 16, total_size);
                put64(&mut rec, 24, offset_exe);
                put64(&mut rec, 40, offset0);
                put64(&mut rec, 48, offset1);
            }
        }
        let crc = crc32(&rec[..rec_len - 4]);
        rec[rec_len - 4..].copy_from_slice(&crc.to_le_bytes());
        buf[off..off + rec_len].copy_from_slice(&rec);
    }

    struct InnoFixture {
        data: Vec<u8>,
        table_off: u64,
        offset0: u64,
        total_size: u64,
    }

    /// A coherent Inno-like fixture: `.text` + `.rsrc` (zeroed) + overlay laid
    /// out as [embedded file data][64-byte SetupID][setup-0 payload][setup.e32].
    /// The table is written into `.rsrc` with fields matching the layout.
    /// `tail_extra` appends bytes beyond TotalSize (Authenticode signature);
    /// `declared_extra` inflates the declared TotalSize (truncation model).
    fn inno_fixture(
        version: u32,
        setup_id_bytes: [u8; 64],
        tail_extra: usize,
        declared_extra: u64,
    ) -> InnoFixture {
        let mut overlay = Vec::new();
        overlay.extend_from_slice(&[0x61; 32]); // embedded setup-1 file data
        let off0_in_overlay = overlay.len() as u64;
        overlay.extend_from_slice(&setup_id_bytes);
        overlay.extend_from_slice(&[0x62; 100]); // rest of setup-0
        let offexe_in_overlay = overlay.len() as u64;
        overlay.extend_from_slice(&[0x63; 50]); // compressed setup.e32

        let mut data = PeBuilder::new()
            .section(".text", 0x200, 0x200)
            .add_section(SectionSpec::new(".rsrc", 0x200, 0x200).fill(0))
            .overlay(&overlay)
            .build();
        let pe = pe::parse(&data).expect("fixture must parse");
        let rsrc = pe
            .sections
            .iter()
            .find(|s| s.name == ".rsrc")
            .expect("fixture has .rsrc");
        let table_off = u64::from(rsrc.raw_ptr) + 0x20;
        let overlay_start = pe.overlay_start;
        let offset1 = overlay_start; // embedded file data starts at the overlay
        let offset0 = overlay_start + off0_in_overlay;
        let offset_exe = overlay_start + offexe_in_overlay;
        let total_size = data.len() as u64 + declared_extra;
        write_table(
            &mut data,
            table_off as usize,
            version,
            total_size,
            offset_exe,
            offset0,
            offset1,
        );
        data.extend(std::iter::repeat_n(0xAA, tail_extra));
        InnoFixture {
            data,
            table_off,
            offset0,
            total_size,
        }
    }

    fn detect_fixture(data: &[u8]) -> FrameworkDetection {
        let pe = pe::parse(data).expect("fixture must parse");
        detect(data, &pe)
    }

    fn assert_weak_or_unknown(d: &FrameworkDetection) {
        assert!(
            d.confidence() <= Confidence::WeakHint,
            "expected <= WeakHint, got {:?}",
            d.confidence()
        );
        assert!(!d.mitigation_safe());
    }

    // ── unit: crc32 / grammar ──────────────────────────────────────

    #[test]
    fn crc32_known_vector() {
        // Standard zlib CRC-32 check value.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn setup_id_grammar_accepts_documented_spellings() {
        for (v, u) in [
            ("5.5.7", false),
            ("5.5.7", true),
            ("6.0.0", true),
            ("6.4.0.1", false),
            ("6.5.0", false),
            ("7.0.0.3", false),
        ] {
            let id = setup_id(v, u);
            assert_eq!(setup_id_version(&id).as_deref(), Some(v), "v={v} u={u}");
        }
    }

    #[test]
    fn setup_id_grammar_rejects_garbage() {
        assert_eq!(setup_id_version(&[0u8; 64]), None);
        // 2-component versions are accepted by the grammar.
        assert_eq!(setup_id_version(&setup_id("6.5", true)).as_deref(), Some("6.5"));
        let mut bad = setup_id("6.5.0", false);
        bad[20] = b'X'; // corrupt inside prefix region
        assert_eq!(setup_id_version(&bad), None);
        let mut bad2 = setup_id("6.5.0", false);
        bad2[63] = b'Z'; // non-NUL padding
        assert_eq!(setup_id_version(&bad2), None);
        let mut bad3 = [0u8; 64];
        let s = b"Inno Setup Setup Data (6.5.0)";
        bad3[..s.len()].copy_from_slice(s);
        bad3[s.len() - 1] = b'!'; // ')' replaced
        assert_eq!(setup_id_version(&bad3), None);
    }

    // ── positive detection ─────────────────────────────────────────

    #[test]
    fn valid_v2_installer_is_structural_and_mitigation_safe() {
        let f = inno_fixture(2, setup_id("6.5.0", false), 0, 0);
        let d = detect_fixture(&f.data);
        assert_eq!(d.kind(), FrameworkKind::InnoSetup);
        assert_eq!(d.confidence(), Confidence::Structural);
        assert!(d.mitigation_safe());
        let sources: Vec<_> = d.evidence().iter().map(|e| e.source).collect();
        assert!(sources.contains(&EvidenceSource::Resource));
        assert!(sources.contains(&EvidenceSource::EmbeddedArchive));
        assert!(sources.contains(&EvidenceSource::Overlay));
        // Offsets are real.
        assert_eq!(
            d.evidence()[0].offset,
            Some(f.table_off),
            "table evidence must cite the real offset"
        );
    }

    #[test]
    fn valid_v1_installer_is_structural() {
        let f = inno_fixture(1, setup_id("5.5.7", true), 0, 0);
        let d = detect_fixture(&f.data);
        assert_eq!(d.confidence(), Confidence::Structural);
        assert!(d.mitigation_safe());
    }

    #[test]
    fn signed_installer_with_appended_signature_stays_structural() {
        // file size > TotalSize (Authenticode signature appended after the
        // declared end) must not lose detection.
        let f = inno_fixture(2, setup_id("7.0.0.3", false), 600, 0);
        let d = detect_fixture(&f.data);
        assert_eq!(d.confidence(), Confidence::Structural);
        assert!(d.mitigation_safe());
    }

    #[test]
    fn truncated_installer_with_verifiable_remainder_is_corroborated() {
        // Declared TotalSize runs past EOF, but every byte still present
        // verifies. Corroborated (still structural evidence), never Structural.
        let f = inno_fixture(2, setup_id("6.5.0", false), 0, 4096);
        assert!(f.total_size > f.data.len() as u64);
        let d = detect_fixture(&f.data);
        assert_eq!(d.confidence(), Confidence::Corroborated);
        assert!(d.mitigation_safe());
        assert!(d.warnings().iter().any(|w| w.contains("truncated")));
    }

    // ── rejection: injected decoration never exceeds WeakHint ──────

    #[test]
    fn arbitrary_inno_string_injection_is_weak_hint() {
        // The exact legacy-evasion primitive: marker strings embedded in an
        // otherwise ordinary PE (.text body + appended overlay text).
        let mut text = vec![0x41u8; 0x200];
        text[0x40..0x40 + 12].copy_from_slice(b"Inno Setup S");
        let data = PeBuilder::new()
            .add_section(SectionSpec::new(".text", 0x200, 0x200).fill(0x41))
            .overlay(b"padding InnoSetupLdr padding")
            .build();
        let mut data = data;
        let pe = pe::parse(&data).unwrap();
        let raw = pe.sections[0].raw_ptr as usize;
        data[raw..raw + 0x200].copy_from_slice(&text);
        let d = detect_fixture(&data);
        assert_eq!(d.confidence(), Confidence::WeakHint);
        assert!(!d.mitigation_safe());
        assert!(d
            .evidence()
            .iter()
            .all(|e| e.source == EvidenceSource::TextHint));
    }

    #[test]
    fn copied_version_metadata_only_never_exceeds_weak_hint() {
        // A .rsrc section full of UTF-16LE version-info-like strings copied
        // from a real Inno installer — no offset table.
        let mut rsrc_body = Vec::new();
        for s in ["ProductName", "Inno Setup", "FileDescription", "My App Setup"] {
            for unit in s.encode_utf16() {
                rsrc_body.extend_from_slice(&unit.to_le_bytes());
            }
            rsrc_body.extend_from_slice(&[0, 0]);
        }
        rsrc_body.resize(0x200, 0);
        let mut data = PeBuilder::new()
            .section(".text", 0x200, 0x200)
            .add_section(SectionSpec::new(".rsrc", 0x200, 0x200).fill(0))
            .build();
        let pe = pe::parse(&data).unwrap();
        let raw = pe.sections[1].raw_ptr as usize;
        data[raw..raw + 0x200].copy_from_slice(&rsrc_body);
        let d = detect_fixture(&data);
        assert_weak_or_unknown(&d);
    }

    #[test]
    fn fully_valid_table_in_overlay_is_rejected_as_wrong_region() {
        // Even a byte-perfect, CRC-valid table planted in the OVERLAY (with
        // coherent offsets and a real SetupID) must not count: wrong window.
        let mut f = inno_fixture(2, setup_id("6.5.0", false), 0, 0);
        // Move the table bytes into the overlay tail; zero the .rsrc copy.
        let pe = pe::parse(&f.data).unwrap();
        let rsrc = pe.sections.iter().find(|s| s.name == ".rsrc").unwrap();
        let rec_len = V2_RECORD_LEN as usize;
        let rec = f.data[f.table_off as usize..f.table_off as usize + rec_len].to_vec();
        let new_off = f.data.len() - rec_len;
        f.data[new_off..].copy_from_slice(&rec);
        let rsrc_raw = rsrc.raw_ptr as usize;
        for b in &mut f.data[rsrc_raw..rsrc_raw + 0x200] {
            *b = 0;
        }
        let d = detect_fixture(&f.data);
        assert_eq!(d.confidence(), Confidence::WeakHint);
        assert!(!d.mitigation_safe());
        assert!(d.warnings().iter().any(|w| w.contains("OUTSIDE")));
    }

    #[test]
    fn fully_valid_table_in_text_section_is_rejected_as_wrong_region() {
        let mut f = inno_fixture(2, setup_id("6.5.0", false), 0, 0);
        let pe = pe::parse(&f.data).unwrap();
        let text_raw = pe.sections[0].raw_ptr as usize;
        let rsrc_raw = pe.sections[1].raw_ptr as usize;
        let rec_len = V2_RECORD_LEN as usize;
        let rec = f.data[f.table_off as usize..f.table_off as usize + rec_len].to_vec();
        f.data[text_raw..text_raw + rec_len].copy_from_slice(&rec);
        for b in &mut f.data[rsrc_raw..rsrc_raw + 0x200] {
            *b = 0;
        }
        let d = detect_fixture(&f.data);
        assert_eq!(d.confidence(), Confidence::WeakHint);
        assert!(!d.mitigation_safe());
    }

    #[test]
    fn unreadable_setup_data_is_weak_hint() {
        // Table valid + coherent, but Offset0 points past EOF: the setup data
        // was cut entirely. WeakHint — the key evidence is missing.
        let mut f = inno_fixture(2, setup_id("6.5.0", false), 0, 0);
        let pe = pe::parse(&f.data).unwrap();
        let overlay_start = pe.overlay_start;
        // Point Offset0 past EOF while keeping coherence: Offset0 < OffsetEXE
        // < TotalSize must hold, so inflate everything consistently.
        let far = f.data.len() as u64 + 0x10_000;
        write_table(
            &mut f.data,
            f.table_off as usize,
            2,
            far + 0x20_000,
            far + 0x10_000,
            far,
            overlay_start,
        );
        let d = detect_fixture(&f.data);
        assert_eq!(d.confidence(), Confidence::WeakHint);
        assert!(!d.mitigation_safe());
    }

    #[test]
    fn length_field_wraparound_never_panics_never_exceeds_weak_hint() {
        // u32::MAX offsets in a v1 table (CRC re-valid so the fields are
        // actually read): checked math must hold, detection must fail closed.
        let mut f = inno_fixture(1, setup_id("5.5.7", true), 0, 0);
        write_table(
            &mut f.data,
            f.table_off as usize,
            1,
            u64::from(u32::MAX),
            u64::from(u32::MAX),
            u64::from(u32::MAX),
            u64::from(u32::MAX),
        );
        let d = detect_fixture(&f.data);
        assert_weak_or_unknown(&d);

        // Same for v2 u64::MAX fields.
        let mut f2 = inno_fixture(2, setup_id("6.5.0", false), 0, 0);
        write_table(
            &mut f2.data,
            f2.table_off as usize,
            2,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX,
        );
        let d2 = detect_fixture(&f2.data);
        assert_weak_or_unknown(&d2);
    }

    #[test]
    fn bad_table_crc_is_weak_hint() {
        let mut f = inno_fixture(2, setup_id("6.5.0", false), 0, 0);
        // Corrupt one field without fixing the CRC.
        patch_u32_le(&mut f.data, f.table_off as usize + 12, 2);
        f.data[f.table_off as usize + 20] ^= 0xFF;
        let d = detect_fixture(&f.data);
        assert_eq!(d.confidence(), Confidence::WeakHint);
        assert!(!d.mitigation_safe());
        assert!(d.warnings().iter().any(|w| w.contains("CRC")));
    }

    #[test]
    fn unknown_table_version_is_weak_hint() {
        let mut f = inno_fixture(2, setup_id("6.5.0", false), 0, 0);
        // Version 99 with a re-computed CRC over the v2 record is still not a
        // known layout — rejected before field interpretation.
        let rec_len = V2_RECORD_LEN as usize;
        patch_u32_le(&mut f.data, f.table_off as usize + 12, 99);
        let rec = f.data[f.table_off as usize..f.table_off as usize + rec_len].to_vec();
        let crc = crc32(&rec[..rec_len - 4]);
        patch_u32_le(&mut f.data, f.table_off as usize + rec_len - 4, crc);
        let d = detect_fixture(&f.data);
        assert_eq!(d.confidence(), Confidence::WeakHint);
        assert!(!d.mitigation_safe());
        assert!(d.warnings().iter().any(|w| w.contains("version 99")));
    }

    #[test]
    fn grammar_mismatching_setup_data_is_weak_hint() {
        // Valid table pointing at 64 bytes that are NOT a SetupID.
        let mut f = inno_fixture(2, setup_id("6.5.0", false), 0, 0);
        for i in 0..64 {
            f.data[f.offset0 as usize + i] = 0x7E;
        }
        let d = detect_fixture(&f.data);
        assert_eq!(d.confidence(), Confidence::WeakHint);
        assert!(!d.mitigation_safe());
    }

    #[test]
    fn polyglot_mz_pdf_never_exceeds_weak_hint() {
        // Valid PE headers with a PDF payload and Inno text in the overlay.
        let data = PeBuilder::new()
            .section(".text", 0x200, 0x200)
            .overlay(b"%PDF-1.7 ... Inno Setup ... %%EOF")
            .build();
        let d = detect_fixture(&data);
        assert_weak_or_unknown(&d);
    }

    #[test]
    fn all_markers_in_one_malformed_pe_never_exceeds_weak_hint() {
        // Every known Inno marker at once: text strings, a garbage table ID
        // in .rsrc, a SetupID-looking string in the overlay. No coherent
        // structure anywhere.
        let mut rsrc_body = vec![0u8; 0x200];
        rsrc_body[0x10..0x10 + 12].copy_from_slice(&LDR_TABLE_ID); // ID only, no valid record
        let mut overlay = Vec::new();
        overlay.extend_from_slice(&setup_id("6.5.0", false)); // free-floating SetupID
        overlay.extend_from_slice(b"InnoSetupLdr Inno Setup S");
        let mut data = PeBuilder::new()
            .add_section(SectionSpec::new(".text", 0x200, 0x200).fill(0x41))
            .add_section(SectionSpec::new(".rsrc", 0x200, 0x200).fill(0))
            .overlay(&overlay)
            .build();
        let pe = pe::parse(&data).unwrap();
        let raw = pe.sections[1].raw_ptr as usize;
        data[raw..raw + 0x200].copy_from_slice(&rsrc_body);
        let d = detect_fixture(&data);
        assert_eq!(d.confidence(), Confidence::WeakHint);
        assert!(!d.mitigation_safe());
        assert!(d.evidence().iter().all(|e| !e.source.is_structural()
            || e.source == EvidenceSource::Resource
            || e.source == EvidenceSource::Overlay
            || e.source == EvidenceSource::EmbeddedArchive));
    }

    // ── metamorphic properties ─────────────────────────────────────

    #[test]
    fn moving_marker_outside_window_loses_structural() {
        let good = inno_fixture(2, setup_id("6.5.0", false), 0, 0);
        assert_eq!(detect_fixture(&good.data).confidence(), Confidence::Structural);

        // Same bytes, but the table now lives in the overlay: the detection
        // must collapse to WeakHint (window policy), never stay Structural.
        let mut moved = good.data.clone();
        let pe = pe::parse(&moved).unwrap();
        let rsrc_raw = pe
            .sections
            .iter()
            .find(|s| s.name == ".rsrc")
            .unwrap()
            .raw_ptr as usize;
        let rec = moved[good.table_off as usize..good.table_off as usize + V2_RECORD_LEN as usize]
            .to_vec();
        let tail = moved.len() - V2_RECORD_LEN as usize;
        moved[tail..].copy_from_slice(&rec);
        for b in &mut moved[rsrc_raw..rsrc_raw + 0x200] {
            *b = 0;
        }
        let d = detect_fixture(&moved);
        assert!(d.confidence() < Confidence::Structural);
        assert!(!d.mitigation_safe());
    }

    #[test]
    fn truncation_never_increases_confidence() {
        let f = inno_fixture(2, setup_id("6.5.0", false), 0, 0);
        let full = detect_fixture(&f.data).confidence();
        assert_eq!(full, Confidence::Structural);
        let mut best = Confidence::Unknown;
        for cut in 0..f.data.len() {
            let Some(p) = pe::parse(&f.data[..cut]) else {
                continue;
            };
            let d = detect(&f.data[..cut], &p);
            assert!(
                d.confidence() <= full,
                "cut {cut}: confidence {:?} exceeds full-file {:?}",
                d.confidence(),
                full
            );
            best = best.max(d.confidence());
        }
    }

    #[test]
    fn appended_inno_text_to_arbitrary_pe_stays_weak_hint() {
        let data = PeBuilder::new()
            .section(".text", 0x200, 0x200)
            .overlay(b"Inno Setup Setup Data (6.5.0) InnoSetupLdr")
            .build();
        let d = detect_fixture(&data);
        assert_eq!(d.confidence(), Confidence::WeakHint);
        assert!(!d.mitigation_safe());
    }

    #[test]
    fn no_overlay_no_inno_is_unknown() {
        let data = PeBuilder::new().section(".text", 0x200, 0x200).build();
        let d = detect_fixture(&data);
        assert_eq!(d.kind(), FrameworkKind::Unknown);
        assert_eq!(d.confidence(), Confidence::Unknown);
    }

    // ── totality sweeps ────────────────────────────────────────────

    #[test]
    fn truncation_at_every_length_never_panics() {
        let f = inno_fixture(2, setup_id("6.5.0", false), 32, 0);
        for cut in 0..f.data.len() {
            if let Some(p) = pe::parse(&f.data[..cut]) {
                let _ = detect(&f.data[..cut], &p);
            }
        }
    }

    #[test]
    fn byte_mutation_fuzz_never_panics() {
        let f = inno_fixture(2, setup_id("6.5.0", false), 0, 0);
        // Mutate every byte of the headers + .rsrc (table region) + the
        // SetupID area through hostile values.
        let pe = pe::parse(&f.data).unwrap();
        let setup_id_start = f.offset0 as usize;
        let region_end = (setup_id_start + 64).min(f.data.len());
        for off in 0..region_end {
            for val in [0x00u8, 0xFF, 0x7F, 0x80] {
                let mut m = f.data.clone();
                m[off] = val;
                if let Some(p) = pe::parse(&m) {
                    let _ = detect(&m, &p);
                }
            }
        }
        let _ = pe;
    }

    // ── DoS bound ──────────────────────────────────────────────────

    /// A .rsrc section filled with the loader table ID must hit the
    /// candidate cap and fail closed — never a per-hit CRC storm, never
    /// Structural. Regression for the measured 472 s / 100 MB needle-flood
    /// scan reported by adversarial verification.
    #[test]
    fn needle_flood_hits_candidate_cap_and_fails_closed() {
        let mut data = PeBuilder::new()
            .section(".text", 0x200, 0x200)
            .section(".rsrc", 0x4000, 0x4000)
            .overlay(b"pad")
            .build();
        // Fill .rsrc's raw range with back-to-back copies of the table ID.
        let pe = pe::parse(&data).unwrap();
        let rsrc = pe
            .sections
            .iter()
            .find(|s| s.name == ".rsrc")
            .expect("fixture has .rsrc");
        let range = rsrc.raw_range(data.len()).unwrap();
        for chunk in data[range].chunks_mut(LDR_TABLE_ID.len()) {
            chunk.copy_from_slice(&LDR_TABLE_ID[..chunk.len()]);
        }
        let pe = pe::parse(&data).unwrap();
        let d = detect(&data, &pe);
        assert!(
            d.confidence() < Confidence::Structural,
            "a needle flood must never reach Structural confidence"
        );
        assert!(!d.mitigation_safe());
        assert!(
            d.warnings().iter().any(|w| w.contains("needle flood")),
            "candidate-cap diagnostic must be recorded: {:?}",
            d.warnings()
        );
    }
}
