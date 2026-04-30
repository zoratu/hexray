//! Parser for the private `.AMDGPU.kinfo` ELF section emitted by
//! SCALE-free (Spectral Compute's `scale-free` 1.x package).
//!
//! # Why this exists
//!
//! Standard AMDGPU code objects produced by clang / hipcc carry
//! kernel-arg layout in the `NT_AMDGPU_METADATA` MessagePack note
//! (decoded in [`super::metadata`]). SCALE-free 1.4.2 omits that note
//! entirely and instead serialises a much smaller per-kernel summary
//! into a private section called `.AMDGPU.kinfo`. Each kernel's
//! summary is pointed at by a symbol named `<kernel>.ki` (`STT_OBJECT`,
//! sitting *inside* the `.AMDGPU.kinfo` section, with `st_size` equal
//! to the summary record length).
//!
//! Without parsing this section, `hexray cmp` between two SCALE-free
//! binaries cannot show per-arg size rows — the kernel metadata is
//! simply absent.
//!
//! # Layout (reverse-engineered from the v1.4.2 corpus)
//!
//! All fields are little-endian. Observed on
//! `tests/corpus/scale-lang/vector_add.gfx{1030,1100}.co` (44 bytes
//! for a 4-arg kernel):
//!
//! ```text
//!   u32 flags        — observed 0x00000400 on every record. Purpose
//!                      unknown; possibly an ABI / kernarg-segment
//!                      version tag. Preserved verbatim.
//!   u32 reserved     — observed 0. Preserved verbatim.
//!   u32 arg_count    — number of kernel-argument records that follow.
//!
//!   for i in 0..arg_count:
//!       u32 offset   — byte offset of arg[i] within the kernarg
//!                      segment.
//!       u32 size     — size of arg[i] in bytes.
//! ```
//!
//! Total record length is `12 + 8 * arg_count` bytes. Arg ordering
//! matches source-declaration order.
//!
//! For `vector_add(const float* a, const float* b, float* c, int n)`
//! we observe `arg_count = 4` and pairs
//! `(off=0, size=8) (off=8, size=8) (off=16, size=8) (off=24, size=4)`,
//! consistent with three pointer args followed by an `i32`.
//!
//! # Forward compatibility
//!
//! - Trailing bytes beyond `12 + 8 * arg_count` are *not* an error —
//!   SCALE may extend the record format. They're returned in
//!   [`ScaleKinfo::trailing`] for forensic inspection but otherwise
//!   ignored.
//! - The `flags` and `reserved` u32s are stashed in
//!   [`ScaleKinfo::flags`] / [`ScaleKinfo::reserved`] so that future
//!   format probes don't have to re-read the bytes.
//! - We do *not* trust `arg_count` blindly: a value larger than the
//!   bytes can carry is rejected with [`ScaleKinfoError::Truncated`].

// File-level allow: bit-math + slice indexing in this parser/decoder
// is bounds-checked at function entry. Per-site annotations would be
// noise; the runtime fuzz gate (`scripts/run-fuzz-corpus`) catches
// actual crashes. New code should prefer `.get()` + `checked_*`.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

/// Decoded `.AMDGPU.kinfo` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScaleKinfo {
    /// First u32 of the record. Observed `0x400` on every SCALE-free
    /// 1.4.2 binary in the corpus. Likely an ABI version / kernarg
    /// flag; preserved verbatim until the meaning is confirmed.
    pub flags: u32,
    /// Second u32. Observed `0` everywhere; preserved for diagnostics.
    pub reserved: u32,
    /// Decoded argument records, in source-declaration order.
    pub args: Vec<ScaleKinfoArg>,
    /// Bytes past the last well-formed `(offset, size)` pair, kept for
    /// forward compatibility (e.g. if SCALE adds a per-arg flags
    /// trailer in a later release).
    pub trailing: Vec<u8>,
}

/// One kernel-argument record from `.AMDGPU.kinfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScaleKinfoArg {
    /// Offset within the kernarg segment, in bytes.
    pub offset: u32,
    /// Size of this argument, in bytes.
    pub size: u32,
}

/// Errors raised while parsing a `.AMDGPU.kinfo` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScaleKinfoError {
    /// Fewer than the 12-byte fixed header could be read.
    HeaderTruncated { len: usize },
    /// The declared `arg_count` would require more bytes than the
    /// section provides. Carries the requested vs. available counts so
    /// the caller can render a useful diagnostic.
    Truncated {
        declared_args: u32,
        available_bytes: usize,
    },
    /// `arg_count` is implausibly large (above the cap we apply to
    /// avoid attacker-controlled allocation). The cap is generous
    /// (1024) — real kernels stay well under this.
    ArgCountOutOfRange { count: u32 },
}

impl std::fmt::Display for ScaleKinfoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeaderTruncated { len } => write!(
                f,
                ".AMDGPU.kinfo too small: need 12-byte header, got {len} byte(s)"
            ),
            Self::Truncated {
                declared_args,
                available_bytes,
            } => write!(
                f,
                ".AMDGPU.kinfo declares {declared_args} arg(s) but only {available_bytes} byte(s) remain after header"
            ),
            Self::ArgCountOutOfRange { count } => {
                write!(f, ".AMDGPU.kinfo arg_count {count} exceeds sanity cap")
            }
        }
    }
}

impl std::error::Error for ScaleKinfoError {}

/// Sanity cap: a real AMDGPU kernel can have ~64 args before the ABI
/// stops being practical; we cap at 1024 to leave plenty of slack
/// while still rejecting obvious garbage like `0xFFFFFFFF`.
const MAX_ARG_COUNT: u32 = 1024;

impl ScaleKinfo {
    /// Convenience method that delegates to [`parse`].
    pub fn parse(bytes: &[u8]) -> Result<Self, ScaleKinfoError> {
        parse(bytes)
    }
}

/// Parse a `.AMDGPU.kinfo` record.
pub fn parse(bytes: &[u8]) -> Result<ScaleKinfo, ScaleKinfoError> {
    if bytes.len() < 12 {
        return Err(ScaleKinfoError::HeaderTruncated { len: bytes.len() });
    }
    let flags = read_u32(&bytes[0..4]);
    let reserved = read_u32(&bytes[4..8]);
    let arg_count = read_u32(&bytes[8..12]);

    if arg_count > MAX_ARG_COUNT {
        return Err(ScaleKinfoError::ArgCountOutOfRange { count: arg_count });
    }

    let needed = (arg_count as usize)
        .checked_mul(8)
        .ok_or(ScaleKinfoError::ArgCountOutOfRange { count: arg_count })?;
    let body = &bytes[12..];
    if body.len() < needed {
        return Err(ScaleKinfoError::Truncated {
            declared_args: arg_count,
            available_bytes: body.len(),
        });
    }

    let mut args = Vec::with_capacity(arg_count as usize);
    for i in 0..arg_count as usize {
        let off = i * 8;
        let offset = read_u32(&body[off..off + 4]);
        let size = read_u32(&body[off + 4..off + 8]);
        args.push(ScaleKinfoArg { offset, size });
    }

    let trailing = body[needed..].to_vec();
    Ok(ScaleKinfo {
        flags,
        reserved,
        args,
        trailing,
    })
}

/// Helper: read a little-endian u32 from a 4-byte slice. The caller
/// guarantees `bytes.len() == 4`.
fn read_u32(bytes: &[u8]) -> u32 {
    // Caller guarantees bytes.len() == 4. Inline byte construction
    // rather than going through try_into().expect() — same
    // generated code but without the panic surface clippy
    // expect_used complains about.
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact bytes observed in
    /// `tests/corpus/scale-lang/vector_add.gfx1030.co` and `…gfx1100.co`.
    const VECTOR_ADD_KINFO: [u8; 44] = [
        0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // flags=0x400, reserved=0
        0x04, 0x00, 0x00, 0x00, // arg_count=4
        0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, // arg0: off=0, size=8
        0x08, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, // arg1: off=8, size=8
        0x10, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, // arg2: off=16, size=8
        0x18, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, // arg3: off=24, size=4
    ];

    /// Encode a synthetic `.AMDGPU.kinfo` record. Used by tests and
    /// also as a documentation example: the on-disk layout really is
    /// just `flags || reserved || arg_count || (offset, size)*N`.
    fn encode(flags: u32, reserved: u32, args: &[ScaleKinfoArg], trailing: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + args.len() * 8 + trailing.len());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&reserved.to_le_bytes());
        out.extend_from_slice(&(args.len() as u32).to_le_bytes());
        for a in args {
            out.extend_from_slice(&a.offset.to_le_bytes());
            out.extend_from_slice(&a.size.to_le_bytes());
        }
        out.extend_from_slice(trailing);
        out
    }

    #[test]
    fn parses_real_vector_add_blob() {
        // Matches the actual fixture bytes in tests/corpus/scale-lang.
        let info = parse(&VECTOR_ADD_KINFO).expect("parse");
        assert_eq!(info.flags, 0x400);
        assert_eq!(info.reserved, 0);
        assert_eq!(info.args.len(), 4);
        let sizes: Vec<u32> = info.args.iter().map(|a| a.size).collect();
        let offsets: Vec<u32> = info.args.iter().map(|a| a.offset).collect();
        assert_eq!(sizes, vec![8, 8, 8, 4]);
        assert_eq!(offsets, vec![0, 8, 16, 24]);
        assert!(info.trailing.is_empty());
    }

    #[test]
    fn round_trip_synthetic() {
        let args = vec![
            ScaleKinfoArg { offset: 0, size: 8 },
            ScaleKinfoArg { offset: 8, size: 4 },
        ];
        let encoded = encode(0x400, 0, &args, &[]);
        assert_eq!(encoded.len(), 12 + 16);
        let decoded = parse(&encoded).expect("parse synthetic");
        assert_eq!(decoded.flags, 0x400);
        assert_eq!(decoded.reserved, 0);
        assert_eq!(decoded.args, args);
        assert!(decoded.trailing.is_empty());
    }

    #[test]
    fn rejects_truncated_header() {
        // Anything shorter than 12 bytes should fail at the header.
        let err = parse(&[0u8; 11]).unwrap_err();
        assert!(matches!(err, ScaleKinfoError::HeaderTruncated { len: 11 }));
    }

    #[test]
    fn rejects_truncated_body() {
        // Header says 4 args but only 1 (size, offset) pair follows.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x400u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&4u32.to_le_bytes()); // arg_count
        bytes.extend_from_slice(&0u32.to_le_bytes()); // offset
        bytes.extend_from_slice(&8u32.to_le_bytes()); // size
        let err = parse(&bytes).unwrap_err();
        assert_eq!(
            err,
            ScaleKinfoError::Truncated {
                declared_args: 4,
                available_bytes: 8,
            }
        );
    }

    #[test]
    fn rejects_implausible_arg_count() {
        // 0xFFFFFFFF would overflow if we trusted it.
        let mut bytes = vec![0u8; 12];
        bytes[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        let err = parse(&bytes).unwrap_err();
        assert!(matches!(
            err,
            ScaleKinfoError::ArgCountOutOfRange { count: u32::MAX }
        ));
    }

    #[test]
    fn zero_arg_count_yields_empty_args() {
        // A kernel with no arguments is *legal* — `__global__ void f()`.
        // We must not reject that case.
        let bytes = encode(0x400, 0, &[], &[]);
        let info = parse(&bytes).expect("zero-arg kernel parses");
        assert_eq!(info.flags, 0x400);
        assert!(info.args.is_empty());
        assert!(info.trailing.is_empty());
    }

    #[test]
    fn preserves_trailing_unknown_bytes() {
        // SCALE could extend the record with new trailing fields. We
        // surface them via `trailing` for forensics rather than
        // rejecting the parse.
        let args = vec![ScaleKinfoArg { offset: 0, size: 8 }];
        let extra = b"\xde\xad\xbe\xef\xca\xfe";
        let bytes = encode(0x400, 0, &args, extra);
        let info = parse(&bytes).expect("trailing bytes are tolerated");
        assert_eq!(info.args.len(), 1);
        assert_eq!(info.trailing, extra);
    }

    #[test]
    fn many_args_round_trip() {
        // Construct a 16-arg kernel with mixed sizes and contiguous
        // offsets, exercising the loop bounds.
        let mut args = Vec::new();
        let mut off = 0u32;
        for i in 0..16u32 {
            let size = if i % 2 == 0 { 8 } else { 4 };
            args.push(ScaleKinfoArg { offset: off, size });
            off += size;
        }
        let bytes = encode(0x400, 0, &args, &[]);
        assert_eq!(bytes.len(), 12 + 16 * 8);
        let info = parse(&bytes).expect("16-arg kernel");
        assert_eq!(info.args, args);
    }

    #[test]
    fn flags_and_reserved_round_trip_unchanged() {
        // Even non-canonical values for flags/reserved are preserved
        // — we don't yet know what they encode.
        let bytes = encode(0xdead_beef, 0xcafe_babe, &[], &[]);
        let info = parse(&bytes).unwrap();
        assert_eq!(info.flags, 0xdead_beef);
        assert_eq!(info.reserved, 0xcafe_babe);
    }
}
