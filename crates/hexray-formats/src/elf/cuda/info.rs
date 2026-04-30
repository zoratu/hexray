//! TLV framing parser for NVIDIA `.nv.info` / `.nv.info.<kernel>` blobs.
//!
//! The `.nv.info` family of ELF sections carries per-module and per-kernel
//! attributes (parameter layout, register count, shared/local/const sizes,
//! exit offsets, launch bounds, …). Each section is a packed sequence of
//! *entries* on a 4-byte grid. Each entry is:
//!
//! ```text
//!   u8  format       (EIFMT_NVAL | EIFMT_BVAL | EIFMT_HVAL | EIFMT_SVAL)
//!   u8  attribute    (EIATTR_*)
//!   payload...       (size depends on `format`)
//!   padding to next 4-byte boundary
//! ```
//!
//! Payload sizes per format (the logical payload — the 4-byte alignment
//! is applied on top, not included):
//!
//! - `EIFMT_NVAL` (0x01) — no payload (2-byte entry, 2 bytes padding)
//! - `EIFMT_BVAL` (0x02) — 1 byte (3-byte entry, 1 byte padding)
//! - `EIFMT_HVAL` (0x03) — 2 bytes (4-byte entry, 0 padding)
//! - `EIFMT_SVAL` (0x04) — `u16 length` + `length` bytes, then padding
//!
//! The 4-byte grid is critical: without it, an NVAL or BVAL entry
//! throws the parser out of sync on the next header byte. Confirmed on
//! real CUDA 13.2 sm_80 cubins (cuobjdump dump of the same sections
//! shows the padding).
//!
//! Reference: CuAssembler `CuAsm/CuNVInfo.py` (attribute IDs), plus
//! empirical verification against cubins emitted by `nvcc 13.2`
//! (`tests/corpus/cuda/`). NVIDIA does not publish a spec for this.

// File-level allow: bit-math + slice indexing in this parser/decoder
// is bounds-checked at function entry. Per-site annotations would be
// noise; the runtime fuzz gate (`scripts/run-fuzz-corpus`) catches
// actual crashes. New code should prefer `.get()` + `checked_*`.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

/// The four `.nv.info` framing formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvInfoFormat {
    /// `EIFMT_NVAL` — no payload.
    NVal,
    /// `EIFMT_BVAL` — 1-byte payload.
    BVal,
    /// `EIFMT_HVAL` — 2-byte payload.
    HVal,
    /// `EIFMT_SVAL` — `u16 length` + `length` bytes of payload.
    SVal,
}

impl NvInfoFormat {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::NVal),
            0x02 => Some(Self::BVal),
            0x03 => Some(Self::HVal),
            0x04 => Some(Self::SVal),
            _ => None,
        }
    }
}

/// `EIATTR_*` attribute identifiers. Values come from CuAssembler's
/// `CuAsm/CuNVInfo.py` attribute map; NVIDIA does not document these
/// publicly. Unknown values are preserved as [`NvInfoAttribute::Unknown`]
/// rather than rejected.
///
/// Only attributes M5 will care about are named explicitly. Keep adding as
/// corpus evidence comes in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvInfoAttribute {
    /// `EIATTR_PAD` — padding entry used to align following records.
    Pad,
    /// `EIATTR_IMAGE_SLOT`
    ImageSlot,
    /// `EIATTR_JUMPTABLE_RELOCS`
    JumptableRelocs,
    /// `EIATTR_CTAIDZ_USED` — kernel reads `%ctaid.z`.
    CtaidzUsed,
    /// `EIATTR_MAX_THREADS` — launch bound maximum thread count.
    MaxThreads,
    /// `EIATTR_PARAM_CBANK` — constant-bank region holding kernel params.
    ParamCbank,
    /// `EIATTR_EXTERNS`
    Externs,
    /// `EIATTR_REQNTID` — `__launch_bounds__(blockDim)`.
    ReqNtid,
    /// `EIATTR_FRAME_SIZE` — per-thread stack frame size.
    FrameSize,
    /// `EIATTR_MIN_STACK_SIZE`
    MinStackSize,
    /// `EIATTR_MAX_REG_COUNT`
    MaxRegCount,
    /// `EIATTR_KPARAM_INFO` — one-per-parameter layout record.
    KparamInfo,
    /// `EIATTR_CBANK_PARAM_SIZE` — total size of param cbank.
    CbankParamSize,
    /// `EIATTR_EXIT_INSTR_OFFSETS`
    ExitInstrOffsets,
    /// `EIATTR_S2RCTAID_INSTR_OFFSETS`
    S2RCtaidInstrOffsets,
    /// `EIATTR_MAXNTID`
    MaxNtid,
    /// `EIATTR_MAX_STACK_SIZE`
    MaxStackSize,
    /// `EIATTR_SW_WAR` — software workaround marker.
    SwWar,
    /// Any attribute byte we don't recognise — stored verbatim so callers
    /// can still iterate and surface diagnostics.
    Unknown(u8),
}

impl NvInfoAttribute {
    // Attribute IDs from CuAssembler `CuAsm/CuNVInfo.py` and corroborated by
    // the cuda_parsers Rust crate. Not an NVIDIA-published spec — any drift
    // should be caught by the M6 differential harness against real cubins.
    fn from_byte(b: u8) -> Self {
        match b {
            0x01 => Self::Pad,
            0x02 => Self::ImageSlot,
            0x03 => Self::JumptableRelocs,
            0x04 => Self::CtaidzUsed,
            0x05 => Self::MaxThreads,
            0x0a => Self::ParamCbank,
            0x0f => Self::Externs,
            0x10 => Self::ReqNtid,
            0x11 => Self::FrameSize,
            0x12 => Self::MinStackSize,
            0x1b => Self::MaxRegCount,
            0x17 => Self::KparamInfo,
            0x19 => Self::CbankParamSize,
            0x1c => Self::ExitInstrOffsets,
            0x1d => Self::S2RCtaidInstrOffsets,
            0x1f => Self::MaxNtid,
            0x23 => Self::MaxStackSize,
            0x36 => Self::SwWar,
            other => Self::Unknown(other),
        }
    }

    /// Returns the raw attribute byte.
    pub fn as_byte(self) -> u8 {
        match self {
            Self::Pad => 0x01,
            Self::ImageSlot => 0x02,
            Self::JumptableRelocs => 0x03,
            Self::CtaidzUsed => 0x04,
            Self::MaxThreads => 0x05,
            Self::ParamCbank => 0x0a,
            Self::Externs => 0x0f,
            Self::ReqNtid => 0x10,
            Self::FrameSize => 0x11,
            Self::MinStackSize => 0x12,
            Self::MaxRegCount => 0x1b,
            Self::KparamInfo => 0x17,
            Self::CbankParamSize => 0x19,
            Self::ExitInstrOffsets => 0x1c,
            Self::S2RCtaidInstrOffsets => 0x1d,
            Self::MaxNtid => 0x1f,
            Self::MaxStackSize => 0x23,
            Self::SwWar => 0x36,
            Self::Unknown(b) => b,
        }
    }
}

/// A single parsed `.nv.info` entry, identifying where in the raw blob its
/// header and payload live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvInfoEntryRef {
    /// Offset of the 2-byte entry header within the blob's raw bytes.
    pub entry_offset: u32,
    /// Framing format (dictates payload size).
    pub format: NvInfoFormat,
    /// Attribute identifier.
    pub attribute: NvInfoAttribute,
    /// Offset of the first payload byte within the blob's raw bytes.
    /// (For `NVAL` entries this points just past the header; `payload_size`
    /// is 0 so the slice is empty.)
    pub payload_offset: u32,
    /// Payload size in bytes. For `SVAL` this excludes the 2-byte length
    /// prefix — callers see only the payload proper.
    pub payload_size: u16,
}

/// A parsed `.nv.info` or `.nv.info.<kernel>` blob. Holds the raw bytes
/// plus an index of every entry; payload decoding is the caller's job.
#[derive(Debug, Clone)]
pub struct NvInfoBlob<'a> {
    /// Raw section bytes (not including the ELF section header itself).
    pub raw: &'a [u8],
    /// One entry per TLV record.
    pub entries: Vec<NvInfoEntryRef>,
    /// True if parsing hit a malformed record and bailed early. The entries
    /// collected before the malformed byte are still usable.
    pub truncated: bool,
}

impl<'a> NvInfoBlob<'a> {
    /// Returns the payload slice for a given entry. The slice excludes the
    /// `u16` length prefix for `SVAL` entries.
    pub fn payload(&self, entry: &NvInfoEntryRef) -> &'a [u8] {
        let start = entry.payload_offset as usize;
        let end = start.saturating_add(entry.payload_size as usize);
        if end > self.raw.len() {
            &[]
        } else {
            &self.raw[start..end]
        }
    }

    /// Iterate over all entries whose attribute matches `attr`.
    pub fn entries_with(&self, attr: NvInfoAttribute) -> impl Iterator<Item = &NvInfoEntryRef> {
        self.entries.iter().filter(move |e| e.attribute == attr)
    }
}

/// Parse the TLV framing of a `.nv.info` blob.
///
/// Unknown attribute bytes are preserved as [`NvInfoAttribute::Unknown`]
/// and parsing continues — the one place we bail is an invalid *format*
/// byte, because we then no longer know the payload size.
pub fn parse_nv_info(raw: &[u8]) -> NvInfoBlob<'_> {
    let mut entries = Vec::new();
    let mut offset = 0usize;
    let mut truncated = false;

    while offset + 2 <= raw.len() {
        let entry_offset = offset as u32;
        let format_byte = raw[offset];
        let attr_byte = raw[offset + 1];
        let Some(format) = NvInfoFormat::from_byte(format_byte) else {
            // Unknown framing; we can't safely step past this entry. Bail.
            truncated = true;
            break;
        };
        let attribute = NvInfoAttribute::from_byte(attr_byte);
        offset += 2;

        let (payload_offset, payload_size) = match format {
            NvInfoFormat::NVal => (offset as u32, 0u16),
            NvInfoFormat::BVal => (offset as u32, 1),
            NvInfoFormat::HVal => (offset as u32, 2),
            NvInfoFormat::SVal => {
                if offset + 2 > raw.len() {
                    truncated = true;
                    break;
                }
                let len = u16::from_le_bytes([raw[offset], raw[offset + 1]]);
                offset += 2;
                (offset as u32, len)
            }
        };

        let advance = payload_size as usize;
        if offset.saturating_add(advance) > raw.len() {
            truncated = true;
            break;
        }
        offset += advance;

        entries.push(NvInfoEntryRef {
            entry_offset,
            format,
            attribute,
            payload_offset,
            payload_size,
        });

        // Advance past the 4-byte alignment padding. NVAL entries need
        // 2 bytes of padding, BVAL 1 byte, HVAL 0, SVAL varies with its
        // `length` field. Running past the end is fine — the outer
        // while-loop will exit on the next iteration's header check.
        let rem = offset % 4;
        if rem != 0 {
            let pad = 4 - rem;
            offset = offset.saturating_add(pad).min(raw.len());
        }
    }

    if offset != raw.len() {
        // Trailing byte that couldn't form an entry header.
        if !entries.is_empty() || offset != 0 {
            truncated = true;
        }
    }

    NvInfoBlob {
        raw,
        entries,
        truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pad an entry's encoded bytes up to the next 4-byte boundary so a
    /// chain of entries stays aligned on the wire, matching what real
    /// cubins do.
    fn pad4(mut v: Vec<u8>) -> Vec<u8> {
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    fn sval_entry(attr: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(0x04); // EIFMT_SVAL
        v.push(attr);
        v.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        v.extend_from_slice(payload);
        pad4(v)
    }

    fn hval_entry(attr: u8, payload: u16) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(0x03); // EIFMT_HVAL
        v.push(attr);
        v.extend_from_slice(&payload.to_le_bytes());
        pad4(v)
    }

    fn bval_entry(attr: u8, b: u8) -> Vec<u8> {
        pad4(vec![0x02, attr, b]) // EIFMT_BVAL + 1 byte padding
    }

    fn nval_entry(attr: u8) -> Vec<u8> {
        pad4(vec![0x01, attr]) // EIFMT_NVAL + 2 bytes padding
    }

    #[test]
    fn parses_mixed_blob() {
        let mut blob = Vec::new();
        blob.extend(hval_entry(0x05, 0x0100)); // MaxThreads = 256
        blob.extend(bval_entry(0x1b, 64)); // MaxRegCount = 64
        blob.extend(sval_entry(
            0x17,                                  // KparamInfo
            &[0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0], // mock 12-byte payload
        ));
        blob.extend(nval_entry(0x04)); // CtaidzUsed (no payload)

        let parsed = parse_nv_info(&blob);
        assert!(!parsed.truncated);
        assert_eq!(parsed.entries.len(), 4);

        assert_eq!(parsed.entries[0].format, NvInfoFormat::HVal);
        assert_eq!(parsed.entries[0].attribute, NvInfoAttribute::MaxThreads);
        assert_eq!(parsed.payload(&parsed.entries[0]), &[0x00, 0x01]);

        assert_eq!(parsed.entries[1].format, NvInfoFormat::BVal);
        assert_eq!(parsed.entries[1].attribute, NvInfoAttribute::MaxRegCount);
        assert_eq!(parsed.payload(&parsed.entries[1]), &[64]);

        assert_eq!(parsed.entries[2].format, NvInfoFormat::SVal);
        assert_eq!(parsed.entries[2].attribute, NvInfoAttribute::KparamInfo);
        assert_eq!(parsed.entries[2].payload_size, 12);

        assert_eq!(parsed.entries[3].format, NvInfoFormat::NVal);
        assert_eq!(parsed.entries[3].attribute, NvInfoAttribute::CtaidzUsed);
        assert_eq!(parsed.payload(&parsed.entries[3]), &[] as &[u8]);
    }

    #[test]
    fn preserves_unknown_attributes() {
        // attr 0xFF is not currently mapped.
        let blob = hval_entry(0xFF, 0x1234);
        let parsed = parse_nv_info(&blob);
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].attribute, NvInfoAttribute::Unknown(0xFF));
        assert!(!parsed.truncated);
    }

    #[test]
    fn bails_on_invalid_format_byte() {
        // 0x42 is not a valid EIFMT_*; we truncate rather than misread.
        let blob = vec![0x01, 0x05, /* next entry */ 0x42, 0x01, 0xff];
        let parsed = parse_nv_info(&blob);
        assert_eq!(parsed.entries.len(), 1);
        assert!(parsed.truncated);
    }

    #[test]
    fn bails_on_sval_length_overrun() {
        // SVAL claims 100 bytes but the blob only has 5.
        let blob = vec![0x04, 0x17, 0x64, 0x00, 0xaa];
        let parsed = parse_nv_info(&blob);
        assert!(parsed.entries.is_empty());
        assert!(parsed.truncated);
    }

    #[test]
    fn empty_blob_parses_cleanly() {
        let parsed = parse_nv_info(&[]);
        assert!(parsed.entries.is_empty());
        assert!(!parsed.truncated);
    }

    #[test]
    fn trailing_single_byte_is_truncated() {
        let mut blob = nval_entry(0x01);
        blob.push(0x01); // odd trailing byte
        let parsed = parse_nv_info(&blob);
        assert_eq!(parsed.entries.len(), 1);
        assert!(parsed.truncated);
    }

    #[test]
    fn attribute_roundtrip() {
        for raw in 0u8..=0xff {
            let attr = NvInfoAttribute::from_byte(raw);
            assert_eq!(attr.as_byte(), raw);
        }
    }
}
