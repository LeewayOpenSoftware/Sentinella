//! Central storage for `EVENT_TRACE_PROPERTIES` buffers.
//!
//! WHY this exists: ETW trace control APIs (`StartTraceW`, `ControlTraceW`)
//! take an `EVENT_TRACE_PROPERTIES` struct followed in the SAME allocation by
//! the session (logger) name and optional log-file name as null-terminated
//! UTF-16 strings, located via `LoggerNameOffset` / `LogFileNameOffset`.
//! Three separate crates (sentinelld PLM intake, sandboxd, etw_probe) each
//! hand-rolled this buffer. sentinelld built it as `vec![0u8; size]` and cast
//! the pointer to `*mut EVENT_TRACE_PROPERTIES` — but the struct contains
//! 8-byte-aligned members (`WNODE_HEADER.BufferHandle`, `CONTROLTRACE_HANDLE`,
//! u64/i64 counters), so a `Vec<u8>` buffer is NOT guaranteed aligned and
//! forming `&mut EVENT_TRACE_PROPERTIES` over it is misaligned-reference UB
//! on every call (R<n>-LETHAL class: UB in a SYSTEM-service hot path).
//! sandboxd/etw_probe had a local `Vec<u64>` fix for the same bug class.
//! This module is the ONE correct abstraction; all crates migrate to it.
//!
//! Contract:
//! - Alignment: storage is `Vec<u64>` (8-byte aligned). On x64,
//!   `align_of::<EVENT_TRACE_PROPERTIES>() == 8` (asserted by test); a
//!   compile-time assert rejects any platform where the struct needs more.
//! - Checked size arithmetic: `size_of::<EVENT_TRACE_PROPERTIES>()`
//!   + logger name bytes + logfile name bytes + caller slack, all
//!   `checked_add`/`checked_mul`; anything that does not fit `u32`
//!   (`Wnode.BufferSize` is a u32) is rejected.
//! - Offsets: `LoggerNameOffset` = struct size; `LogFileNameOffset` =
//!   struct size + logger name bytes; both written by the constructor.
//! - Zero-initialized, names written as UTF-16LE with an exact NUL
//!   terminator (empty name = just the terminator).
//! - Stable address: the backing heap allocation never moves for the
//!   lifetime of the value — the type exposes no method that reallocates,
//!   so a pointer taken via `props_mut()` stays valid across MOVES of the
//!   `EventTracePropsStorage` itself (only the `Vec` header moves).
//!
//! The layout math is factored into pure functions so it is unit-tested on
//! every platform; the Windows-only storage type is a thin shell over it.

use std::fmt;

/// Computed byte layout of an `EVENT_TRACE_PROPERTIES` buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropsLayout {
    /// Total logical buffer size in bytes (what `Wnode.BufferSize` reports).
    pub total_size: usize,
    /// Byte offset of the null-terminated UTF-16 logger (session) name.
    pub logger_name_offset: u32,
    /// Logger name byte count including the NUL terminator.
    pub logger_name_bytes: usize,
    /// Byte offset of the null-terminated UTF-16 logfile name, if present.
    pub logfile_name_offset: Option<u32>,
    /// Logfile name byte count including the NUL terminator (0 if absent).
    pub logfile_name_bytes: usize,
}

/// Why a layout could not be computed. Fail-closed: no partial buffers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropsLayoutError {
    /// `checked_mul`/`checked_add` overflowed, or the total does not fit
    /// the u32 `Wnode.BufferSize` field.
    SizeOverflow,
    /// A name offset does not fit the u32 offset fields.
    OffsetOverflow,
}

impl fmt::Display for PropsLayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SizeOverflow => write!(f, "properties buffer size overflows u32/usize"),
            Self::OffsetOverflow => write!(f, "name offset overflows u32"),
        }
    }
}

impl std::error::Error for PropsLayoutError {}

/// Byte count of a UTF-16 name of `units` code units plus its NUL
/// terminator, with checked arithmetic.
fn name_bytes(units: usize) -> Result<usize, PropsLayoutError> {
    units
        .checked_mul(2)
        .and_then(|b| b.checked_add(2))
        .ok_or(PropsLayoutError::SizeOverflow)
}

/// Compute the full buffer layout. Pure function — tested cross-platform.
///
/// - `struct_size`: `size_of::<EVENT_TRACE_PROPERTIES>()` for the target.
/// - `logger_name_units`: UTF-16 code units of the session name (0 = empty).
/// - `logfile_name_units`: UTF-16 code units of the logfile name, if any.
/// - `extra_bytes`: caller slack appended after the names (ETW may write
///   back into the buffer; historical callers reserve 256–512 bytes).
pub fn compute_layout(
    struct_size: usize,
    logger_name_units: usize,
    logfile_name_units: Option<usize>,
    extra_bytes: usize,
) -> Result<PropsLayout, PropsLayoutError> {
    let logger_bytes = name_bytes(logger_name_units)?;
    let logger_name_offset =
        u32::try_from(struct_size).map_err(|_| PropsLayoutError::OffsetOverflow)?;
    let after_logger = struct_size
        .checked_add(logger_bytes)
        .ok_or(PropsLayoutError::SizeOverflow)?;

    let (logfile_name_offset, logfile_bytes) = match logfile_name_units {
        Some(units) => {
            let bytes = name_bytes(units)?;
            let offset =
                u32::try_from(after_logger).map_err(|_| PropsLayoutError::OffsetOverflow)?;
            (Some(offset), bytes)
        }
        None => (None, 0),
    };

    let total_size = after_logger
        .checked_add(logfile_bytes)
        .and_then(|t| t.checked_add(extra_bytes))
        .ok_or(PropsLayoutError::SizeOverflow)?;
    // Wnode.BufferSize is a u32 — a larger buffer could not even describe
    // itself to the kernel API.
    if total_size > u32::MAX as usize {
        return Err(PropsLayoutError::SizeOverflow);
    }

    Ok(PropsLayout {
        total_size,
        logger_name_offset,
        logger_name_bytes: logger_bytes,
        logfile_name_offset,
        logfile_name_bytes: logfile_bytes,
    })
}

// ═══════════════════════════════════════════════════════════════
//  Windows-only storage type
// ═══════════════════════════════════════════════════════════════

#[cfg(target_os = "windows")]
mod imp {
    use super::{PropsLayout, PropsLayoutError, compute_layout};
    use std::fmt;
    use windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_PROPERTIES;

    // The whole point of the Vec<u64> backing: EVENT_TRACE_PROPERTIES
    // contains 8-byte-aligned members, so its alignment must not exceed
    // u64's. Compile-time rejection if a future windows-crate version or
    // target ever breaks this (on x64 both are 8).
    const _: () = assert!(
        std::mem::align_of::<EVENT_TRACE_PROPERTIES>() <= std::mem::align_of::<u64>(),
        "EVENT_TRACE_PROPERTIES alignment exceeds u64 — Vec<u64> backing is insufficient"
    );

    /// Why a properties buffer could not be built. Fail-closed.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum EventTracePropsError {
        /// A name contains an interior NUL, which would silently truncate
        /// the wide string the kernel reads.
        InteriorNul,
        /// Size/offset arithmetic overflowed (see `PropsLayoutError`).
        Layout(PropsLayoutError),
    }

    impl fmt::Display for EventTracePropsError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::InteriorNul => write!(f, "name contains an interior NUL character"),
                Self::Layout(e) => write!(f, "invalid properties layout: {e}"),
            }
        }
    }

    impl std::error::Error for EventTracePropsError {}

    /// Owned, correctly-aligned, zero-initialized storage for an
    /// `EVENT_TRACE_PROPERTIES` buffer plus its trailing names.
    ///
    /// Invariants (upheld by the constructor; no method can break them):
    /// - `buf` is a `Vec<u64>` → 8-byte aligned, never reallocated after
    ///   construction (no mutating methods touch the Vec).
    /// - `buf.len() * 8 >= layout.total_size >= size_of::<EVENT_TRACE_PROPERTIES>()`.
    /// - Names at the layout offsets are valid null-terminated UTF-16LE.
    pub struct EventTracePropsStorage {
        buf: Vec<u64>,
        layout: PropsLayout,
    }

    impl fmt::Debug for EventTracePropsStorage {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("EventTracePropsStorage")
                .field("total_size", &self.layout.total_size)
                .field("layout", &self.layout)
                .finish_non_exhaustive()
        }
    }

    impl EventTracePropsStorage {
        /// Buffer with only a logger (session) name and no slack.
        pub fn new(logger_name: &str) -> Result<Self, EventTracePropsError> {
            Self::with_extra(logger_name, None, 0)
        }

        /// Buffer with a logger name and a logfile name, no slack.
        pub fn with_logfile_name(
            logger_name: &str,
            logfile_name: &str,
        ) -> Result<Self, EventTracePropsError> {
            Self::with_extra(logger_name, Some(logfile_name), 0)
        }

        /// Buffer with names plus `extra_bytes` of trailing slack.
        ///
        /// On success the returned value has `Wnode.BufferSize`,
        /// `LoggerNameOffset`, and `LogFileNameOffset` already set and the
        /// names written; callers only set session-semantic fields
        /// (flags, mode, EnableFlags).
        pub fn with_extra(
            logger_name: &str,
            logfile_name: Option<&str>,
            extra_bytes: usize,
        ) -> Result<Self, EventTracePropsError> {
            if logger_name.contains('\0')
                || logfile_name.is_some_and(|n| n.contains('\0'))
            {
                return Err(EventTracePropsError::InteriorNul);
            }

            let logger_units = logger_name.encode_utf16().count();
            let logfile_units = logfile_name.map(|n| n.encode_utf16().count());
            let layout = compute_layout(
                std::mem::size_of::<EVENT_TRACE_PROPERTIES>(),
                logger_units,
                logfile_units,
                extra_bytes,
            )
            .map_err(EventTracePropsError::Layout)?;

            let mut buf = vec![0u64; layout.total_size.div_ceil(8)];

            // Byte view over the aligned storage for the name writes.
            // SAFETY: `buf` is alive and exclusively borrowed here;
            // `buf.len() * 8` is the true byte extent of the allocation,
            // so the slice covers exactly the Vec's memory.
            let bytes = unsafe {
                std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, buf.len() * 8)
            };
            write_utf16_name(bytes, layout.logger_name_offset as usize, logger_name);
            if let (Some(offset), Some(name)) = (layout.logfile_name_offset, logfile_name) {
                write_utf16_name(bytes, offset as usize, name);
            }

            let mut storage = Self { buf, layout };
            let props = storage.props_mut();
            props.Wnode.BufferSize = layout.total_size as u32;
            props.LoggerNameOffset = layout.logger_name_offset;
            props.LogFileNameOffset = layout.logfile_name_offset.unwrap_or(0);
            Ok(storage)
        }

        /// Logical buffer size in bytes (== `Wnode.BufferSize`).
        pub fn total_size(&self) -> usize {
            self.layout.total_size
        }

        /// The computed layout (offsets, name byte counts).
        pub fn layout(&self) -> PropsLayout {
            self.layout
        }

        /// Borrow the buffer as `EVENT_TRACE_PROPERTIES`.
        ///
        /// SAFETY (why this is a SAFE fn): the constructor guarantees
        /// (1) alignment — `Vec<u64>` is 8-byte aligned and the
        /// compile-time assert above proves the struct needs no more;
        /// (2) size — `buf.len() * 8 >= size_of::<EVENT_TRACE_PROPERTIES>()`
        /// by the layout invariant; (3) validity — the buffer is fully
        /// initialized (zeroed + names) and all-zero is a valid bit
        /// pattern for this all-POD C struct. No method on this type can
        /// reallocate or shrink `buf`, so the reference cannot dangle
        /// while `self` is borrowed.
        pub fn props_mut(&mut self) -> &mut EVENT_TRACE_PROPERTIES {
            unsafe { &mut *(self.buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) }
        }

        /// Raw mutable pointer to the buffer, for FFI calls that take
        /// `*mut EVENT_TRACE_PROPERTIES`. The pointer stays valid across
        /// moves of this value (the heap allocation does not move) until
        /// the value is dropped.
        pub fn as_mut_ptr(&mut self) -> *mut EVENT_TRACE_PROPERTIES {
            self.buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES
        }
    }

    /// Write `name` as UTF-16LE at `offset`, leaving the NUL terminator
    /// slot (reserved by the layout, already zero) intact.
    fn write_utf16_name(bytes: &mut [u8], offset: usize, name: &str) {
        let units: Vec<u16> = name.encode_utf16().collect();
        let len = units.len() * 2;
        // In-bounds by the layout invariant: offset + units*2 + 2 <=
        // layout.total_size <= bytes.len(). Slicing (not raw pointers)
        // keeps this panic-free-or-bug: a broken invariant panics in a
        // test long before it reaches a SYSTEM service.
        let dst = &mut bytes[offset..offset + len];
        for (i, unit) in units.iter().enumerate() {
            dst[i * 2..i * 2 + 2].copy_from_slice(&unit.to_le_bytes());
        }
    }
}

#[cfg(target_os = "windows")]
pub use imp::{EventTracePropsError, EventTracePropsStorage};

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // A stand-in struct size. The real EVENT_TRACE_PROPERTIES is 120 bytes
    // on x64; layout math must hold for any struct size.
    const STRUCT: usize = 120;

    #[test]
    fn logger_name_offset_is_struct_size() {
        let l = compute_layout(STRUCT, 5, None, 0).unwrap();
        assert_eq!(l.logger_name_offset, STRUCT as u32);
        // 5 units + NUL = 12 bytes after the struct.
        assert_eq!(l.logger_name_bytes, 12);
        assert_eq!(l.total_size, STRUCT + 12);
        assert_eq!(l.logfile_name_offset, None);
    }

    #[test]
    fn logfile_name_offset_follows_logger_name() {
        let l = compute_layout(STRUCT, 5, Some(3), 0).unwrap();
        assert_eq!(l.logfile_name_offset, Some((STRUCT + 12) as u32));
        assert_eq!(l.logfile_name_bytes, 8); // 3 units + NUL
        assert_eq!(l.total_size, STRUCT + 12 + 8);
    }

    #[test]
    fn extra_bytes_appended_after_names() {
        let l = compute_layout(STRUCT, 5, None, 256).unwrap();
        assert_eq!(l.total_size, STRUCT + 12 + 256);
    }

    #[test]
    fn exact_size_boundary_smallest_valid() {
        // Empty logger name = just a terminator: struct + 2 bytes.
        let l = compute_layout(STRUCT, 0, None, 0).unwrap();
        assert_eq!(l.total_size, STRUCT + 2);
        assert_eq!(l.logger_name_bytes, 2);
    }

    #[test]
    fn overflow_rejected_usize_max_name() {
        assert_eq!(
            compute_layout(STRUCT, usize::MAX, None, 0),
            Err(PropsLayoutError::SizeOverflow)
        );
        assert_eq!(
            compute_layout(STRUCT, usize::MAX / 2, None, 0),
            Err(PropsLayoutError::SizeOverflow)
        );
        assert_eq!(
            compute_layout(STRUCT, 0, Some(usize::MAX), 0),
            Err(PropsLayoutError::SizeOverflow)
        );
        assert_eq!(
            compute_layout(STRUCT, 0, None, usize::MAX),
            Err(PropsLayoutError::SizeOverflow)
        );
        assert_eq!(
            compute_layout(usize::MAX, 0, None, 0),
            Err(PropsLayoutError::OffsetOverflow)
        );
    }

    #[test]
    fn total_larger_than_u32_rejected() {
        // 2.1e9 units → ~4.2e9 bytes > u32::MAX: BufferSize could not
        // describe it. Must be rejected, not truncated.
        let units = (u32::MAX as usize) / 2 + 1;
        assert_eq!(
            compute_layout(STRUCT, units, None, 0),
            Err(PropsLayoutError::SizeOverflow)
        );
    }

    #[test]
    fn max_accepted_name_below_u32() {
        // Largest-ish name that still fits u32 with struct + terminator.
        let units = (u32::MAX as usize - STRUCT - 2) / 2;
        let l = compute_layout(STRUCT, units, None, 0).unwrap();
        assert!(l.total_size <= u32::MAX as usize);
    }

    #[test]
    fn struct_size_offset_overflow_rejected() {
        assert_eq!(
            compute_layout(u32::MAX as usize + 1, 0, None, 0),
            Err(PropsLayoutError::OffsetOverflow)
        );
    }

    // ── adversarial sweeps (workstreams X+Y) ────────────────────
    //
    // `compute_layout` is the cross-platform pure core of the ETW aligned
    // storage; these tests pin its totality and its output invariants
    // against arbitrary (seeded, deterministic) parameters, and replay the
    // committed cargo-fuzz seed corpus through the SAME decoding the
    // `etw_props_layout` fuzz target uses (no cargo-fuzz required).

    /// xorshift64* — deterministic, no rand crate, no thread_rng.
    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
    }

    /// Decode a 32-byte param blob exactly like the `etw_props_layout`
    /// fuzz target (and the corpus generator): four u64 LE fields —
    /// struct_size, logger units, logfile units (u64::MAX = None), extra.
    fn decode_params(blob: &[u8; 32]) -> (usize, usize, Option<usize>, usize) {
        let u64_at = |i: usize| u64::from_le_bytes(blob[i * 8..i * 8 + 8].try_into().unwrap());
        let as_usize = |v: u64| usize::try_from(v).unwrap_or(usize::MAX);
        let logfile = match u64_at(2) {
            u64::MAX => None,
            v => Some(as_usize(v)),
        };
        (as_usize(u64_at(0)), as_usize(u64_at(1)), logfile, as_usize(u64_at(3)))
    }

    /// Assert the invariants every successful layout must satisfy.
    fn assert_layout_invariants(
        struct_size: usize,
        logger_units: usize,
        logfile_units: Option<usize>,
        extra: usize,
        l: &PropsLayout,
    ) {
        let logger_bytes = logger_units * 2 + 2;
        let logfile_bytes = logfile_units.map(|u| u * 2 + 2).unwrap_or(0);
        assert_eq!(l.logger_name_offset as usize, struct_size);
        assert_eq!(l.logger_name_bytes, logger_bytes);
        assert_eq!(l.logfile_name_bytes, logfile_bytes);
        if let Some(off) = l.logfile_name_offset {
            assert_eq!(off as usize, struct_size + logger_bytes);
        } else {
            assert!(logfile_units.is_none());
        }
        assert_eq!(l.total_size, struct_size + logger_bytes + logfile_bytes + extra);
        assert!(l.total_size <= u32::MAX as usize, "BufferSize is a u32");
    }

    /// Seeded sweep over the full parameter space (including values chosen
    /// to straddle the u32 BufferSize boundary and the usize overflow
    /// edges): must never panic, and every Ok must satisfy the invariants.
    #[test]
    fn seeded_param_sweep_never_panics_and_preserves_invariants() {
        let mut rng = XorShift(0xE700_0001_5EED_5EED);
        // Mix the raw PRNG stream with boundary-magnet values so the
        // overflow paths are hit every run, deterministically.
        const MAGNETS: [u64; 8] = [
            0,
            1,
            120,
            u32::MAX as u64 - 1,
            u32::MAX as u64,
            u32::MAX as u64 + 1,
            usize::MAX as u64 - 1,
            usize::MAX as u64,
        ];
        for i in 0..4096 {
            let pick = |rng: &mut XorShift| {
                let r = rng.next();
                if r.is_multiple_of(2) {
                    MAGNETS[(r >> 32) as usize % MAGNETS.len()]
                } else {
                    r
                }
            };
            let struct_size = usize::try_from(pick(&mut rng)).unwrap_or(usize::MAX);
            let logger = usize::try_from(pick(&mut rng)).unwrap_or(usize::MAX);
            let logfile_raw = pick(&mut rng);
            let logfile = if i % 3 == 0 {
                None
            } else {
                Some(usize::try_from(logfile_raw).unwrap_or(usize::MAX))
            };
            let extra = usize::try_from(pick(&mut rng)).unwrap_or(usize::MAX);
            if let Ok(l) = compute_layout(struct_size, logger, logfile, extra) {
                assert_layout_invariants(struct_size, logger, logfile, extra, &l);
            }
            // Err is always acceptable (fail-closed); a panic is not.
        }
    }

    /// Replay the committed cargo-fuzz seed corpus for `etw_props_layout`
    /// through the same decoding + entry point. Seeds are generated by
    /// fuzz/tools/gen_framework_corpus.py (deterministic).
    #[test]
    fn seed_corpus_replays_cleanly() {
        let seeds: [&[u8; 32]; 4] = [
            include_bytes!("../../../fuzz/corpus/etw_props_layout/seed00-typical.bin"),
            include_bytes!("../../../fuzz/corpus/etw_props_layout/seed01-empty-names.bin"),
            include_bytes!("../../../fuzz/corpus/etw_props_layout/seed02-u32-boundary.bin"),
            include_bytes!("../../../fuzz/corpus/etw_props_layout/seed03-overflow.bin"),
        ];
        for blob in seeds {
            let (s, lg, lf, ex) = decode_params(blob);
            if let Ok(l) = compute_layout(s, lg, lf, ex) {
                assert_layout_invariants(s, lg, lf, ex, &l);
            }
        }

        // Per-seed expectations (the corpus is fixed → exact values).
        let (s, lg, lf, ex) = decode_params(seeds[0]);
        let l = compute_layout(s, lg, lf, ex).expect("typical seed must be valid");
        assert_eq!(l.total_size, 120 + 28 + 256);
        assert_eq!(l.logfile_name_offset, None);

        let (s, lg, lf, ex) = decode_params(seeds[1]);
        let l = compute_layout(s, lg, lf, ex).expect("empty-names seed must be valid");
        assert_eq!(l.total_size, 120 + 2 + 2);

        let (s, lg, lf, ex) = decode_params(seeds[2]);
        let l = compute_layout(s, lg, lf, ex).expect("boundary seed must fit u32");
        assert!(l.total_size <= u32::MAX as usize);

        let (s, lg, lf, ex) = decode_params(seeds[3]);
        assert!(compute_layout(s, lg, lf, ex).is_err(), "overflow seed must fail closed");
    }

    // ── Windows-only storage tests ──────────────────────────────
    #[cfg(target_os = "windows")]
    mod windows_storage {
        use super::super::{EventTracePropsError, EventTracePropsStorage};
        use std::mem::{align_of, size_of};
        use windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_PROPERTIES;

        fn props_bytes(s: &mut EventTracePropsStorage) -> &[u8] {
            // Read-only byte view for assertions.
            // SAFETY: ptr is valid for total_size bytes (layout invariant);
            // the storage outlives the returned slice via the &mut borrow.
            unsafe {
                std::slice::from_raw_parts(s.as_mut_ptr() as *const u8, s.total_size())
            }
        }

        #[test]
        fn struct_alignment_is_8_on_this_target() {
            // Documents the x64 assumption the Vec<u64> backing relies on.
            assert_eq!(align_of::<EVENT_TRACE_PROPERTIES>(), 8);
        }

        #[test]
        fn pointer_is_aligned() {
            let mut s = EventTracePropsStorage::new("SentinellaPLM").unwrap();
            let ptr = s.as_mut_ptr() as usize;
            assert_eq!(ptr % align_of::<EVENT_TRACE_PROPERTIES>(), 0);
        }

        #[test]
        fn buffer_size_equals_total_allocated() {
            let mut s = EventTracePropsStorage::with_extra("Name", None, 256).unwrap();
            assert_eq!(s.props_mut().Wnode.BufferSize as usize, s.total_size());
            assert_eq!(
                s.total_size(),
                size_of::<EVENT_TRACE_PROPERTIES>() + "Name".len() * 2 + 2 + 256
            );
        }

        #[test]
        fn logger_name_written_and_terminated() {
            let mut s = EventTracePropsStorage::new("Test").unwrap();
            let off = s.layout().logger_name_offset as usize;
            let bytes = props_bytes(&mut s);
            let expected: Vec<u16> = "Test".encode_utf16().collect();
            for (i, u) in expected.iter().enumerate() {
                assert_eq!(&bytes[off + i * 2..off + i * 2 + 2], u.to_le_bytes());
            }
            // Exact NUL terminator right after the last unit.
            assert_eq!(&bytes[off + 8..off + 10], &[0, 0]);
            assert_eq!(s.props_mut().LoggerNameOffset, off as u32);
        }

        #[test]
        fn logfile_name_written_and_terminated() {
            let mut s = EventTracePropsStorage::with_logfile_name("Log", "C:\\t.etl").unwrap();
            let l = s.layout();
            let off = l.logfile_name_offset.unwrap() as usize;
            assert_eq!(off, l.logger_name_offset as usize + l.logger_name_bytes);
            let bytes = props_bytes(&mut s);
            let expected: Vec<u16> = "C:\\t.etl".encode_utf16().collect();
            for (i, u) in expected.iter().enumerate() {
                assert_eq!(&bytes[off + i * 2..off + i * 2 + 2], u.to_le_bytes());
            }
            assert_eq!(&bytes[off + 16..off + 18], &[0, 0]);
            assert_eq!(s.props_mut().LogFileNameOffset, off as u32);
        }

        #[test]
        fn empty_names_supported() {
            let mut s = EventTracePropsStorage::with_logfile_name("", "").unwrap();
            let l = s.layout();
            assert_eq!(
                l.total_size,
                size_of::<EVENT_TRACE_PROPERTIES>() + 2 + 2
            );
            let bytes = props_bytes(&mut s);
            // Both names are just a NUL terminator.
            assert_eq!(&bytes[l.logger_name_offset as usize..][..2], &[0, 0]);
            assert_eq!(&bytes[l.logfile_name_offset.unwrap() as usize..][..2], &[0, 0]);
        }

        #[test]
        fn interior_nul_rejected() {
            assert_eq!(
                EventTracePropsStorage::new("a\0b").unwrap_err(),
                EventTracePropsError::InteriorNul
            );
            assert_eq!(
                EventTracePropsStorage::with_logfile_name("ok", "a\0b").unwrap_err(),
                EventTracePropsError::InteriorNul
            );
        }

        #[test]
        fn max_reasonable_names_accepted() {
            let long = "S".repeat(1024);
            let s = EventTracePropsStorage::with_logfile_name(&long, &long).unwrap();
            assert!(s.total_size() > 1024 * 4);
        }

        #[test]
        fn address_stable_across_move_of_owner() {
            let mut s = EventTracePropsStorage::with_extra("Stable", None, 512).unwrap();
            let p1 = s.as_mut_ptr() as usize;
            // Move the owner: by value, into a Box, into an Option. The
            // heap allocation backing the Vec must not move.
            let mut boxed = Box::new(s);
            assert_eq!(boxed.as_mut_ptr() as usize, p1);
            let mut opt = Some(boxed);
            assert_eq!(opt.as_mut().unwrap().as_mut_ptr() as usize, p1);
            // Buffer contents intact after the moves.
            assert_eq!(
                opt.as_mut().unwrap().props_mut().Wnode.BufferSize as usize,
                p1_total(size_of::<EVENT_TRACE_PROPERTIES>(), "Stable", 512)
            );
            fn p1_total(struct_size: usize, name: &str, extra: usize) -> usize {
                struct_size + name.len() * 2 + 2 + extra
            }
        }

        #[test]
        fn zero_initialized_beyond_names() {
            let mut s = EventTracePropsStorage::with_extra("Z", None, 64).unwrap();
            let l = s.layout();
            let bytes = props_bytes(&mut s);
            // The trailing slack stays zeroed.
            let slack_start = l.logger_name_offset as usize + l.logger_name_bytes;
            assert!(bytes[slack_start..].iter().all(|&b| b == 0));
        }
    }
}
