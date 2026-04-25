//! NVIDIA fatbin container parser.
//!
//! A "fatbin" is a thin wrapper `nvcc` uses to collect per-SM cubins
//! (and sometimes PTX blobs) into a single payload that a host binary
//! can embed. It ships two ways:
//!
//! - standalone on disk (the output of `cuobjdump --extract-fatbin`),
//! - inside a host ELF/PE/Mach-O as the content of the `__nv_fatbin`
//!   symbol or `.nv_fatbin` section.
//!
//! Both use the same inner layout. The wrapper has a 16-byte header
//! starting with magic `0xBA55_ED50`, followed by a packed list of
//! entry headers each describing a payload: a cubin or a PTX blob for
//! a particular compute capability. Entries don't include relocation
//! info — it's a pure container.
//!
//! Our parser is tolerant: unknown entry kinds are surfaced as
//! [`FatbinEntryKind::Unknown`]; truncated or misaligned wrappers
//! produce a [`FatbinError`] rather than panic.
//!
//! References: `cuobjdump` output, CuAssembler's fatbin reader, and
//! `nvidia-ptxjit-compiler`'s public fatbin.h.

/// Magic word at the start of an NVIDIA fatbin wrapper.
pub const FATBIN_MAGIC: u32 = 0xBA55_ED50;

/// Byte length of the outer wrapper header. All entry offsets below
/// are measured from the start of the wrapper.
pub const WRAPPER_HEADER_SIZE: usize = 16;

/// Byte length of each entry header in the payload table.
pub const ENTRY_HEADER_SIZE: usize = 64;

/// Errors from parsing a fatbin wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FatbinError {
    /// Input too short to hold even the 16-byte wrapper header.
    Truncated { needed: usize, have: usize },
    /// Wrapper magic word didn't match.
    BadMagic(u32),
    /// An entry header extended past the wrapper payload.
    EntryOverflow {
        entry_index: usize,
        entry_offset: usize,
        entry_end: usize,
        wrapper_end: usize,
    },
    /// The wrapper's declared payload size exceeds the input buffer.
    PayloadOverflow {
        payload_end: usize,
        buffer_len: usize,
    },
}

impl std::fmt::Display for FatbinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated { needed, have } => {
                write!(f, "fatbin truncated: need {needed} bytes, have {have}")
            }
            Self::BadMagic(m) => write!(f, "fatbin bad magic: {m:#x}"),
            Self::EntryOverflow { entry_index, .. } => {
                write!(f, "fatbin entry #{entry_index} extends past payload")
            }
            Self::PayloadOverflow { .. } => f.write_str("fatbin payload size exceeds buffer"),
        }
    }
}

impl std::error::Error for FatbinError {}

/// Entry kind as reported by the fatbin entry header's `kind` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatbinEntryKind {
    /// Raw PTX text blob (`.kind == 1`).
    Ptx,
    /// Compiled cubin ELF (`.kind == 2`).
    Cubin,
    /// Unknown / extended kind.
    Unknown(u16),
}

impl FatbinEntryKind {
    fn from_raw(k: u16) -> Self {
        match k {
            1 => Self::Ptx,
            2 => Self::Cubin,
            other => Self::Unknown(other),
        }
    }
}

/// One entry inside a fatbin wrapper.
#[derive(Debug, Clone)]
pub struct FatbinEntry<'a> {
    /// Entry kind (PTX / cubin / …).
    pub kind: FatbinEntryKind,
    /// SM compute capability the payload targets (`10 * major + minor`,
    /// e.g. `80` for sm_80, `90` for sm_90).
    pub sm: u16,
    /// Payload bytes (the cubin or PTX text blob proper).
    pub payload: &'a [u8],
    /// Compressed-flag as reported by the header. Current `ptxas` leaves
    /// this unset on handwritten builds but compressed entries exist in
    /// the wild (release-mode fatbins).
    pub compressed: bool,
}

impl<'a> FatbinEntry<'a> {
    /// Convenience: returns the payload slice regardless of type.
    pub fn data(&self) -> &'a [u8] {
        self.payload
    }
}

/// A parsed fatbin wrapper.
#[derive(Debug, Clone)]
pub struct FatbinWrapper<'a> {
    /// Raw bytes of the full wrapper (header + payload).
    pub raw: &'a [u8],
    /// Layout version the wrapper declares.
    pub version: u32,
    /// One entry per embedded cubin / PTX blob.
    pub entries: Vec<FatbinEntry<'a>>,
}

impl<'a> FatbinWrapper<'a> {
    /// Parse a fatbin wrapper from its own bytes. The slice must start
    /// at the wrapper magic; callers extracting from a host binary
    /// should first slice out the `.nv_fatbin` section's content.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, FatbinError> {
        if bytes.len() < WRAPPER_HEADER_SIZE {
            return Err(FatbinError::Truncated {
                needed: WRAPPER_HEADER_SIZE,
                have: bytes.len(),
            });
        }
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != FATBIN_MAGIC {
            return Err(FatbinError::BadMagic(magic));
        }
        let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        // Offset to first entry header, from the start of the wrapper.
        let header_offset = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
        let header_size = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
        let payload_end = header_offset.saturating_add(header_size);
        if payload_end > bytes.len() {
            return Err(FatbinError::PayloadOverflow {
                payload_end,
                buffer_len: bytes.len(),
            });
        }

        let mut entries = Vec::new();
        let mut cursor = header_offset;
        let mut entry_index = 0usize;
        while cursor + ENTRY_HEADER_SIZE <= payload_end {
            let kind_raw = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]);
            let flags = u16::from_le_bytes([bytes[cursor + 2], bytes[cursor + 3]]);
            let header_len = u32::from_le_bytes([
                bytes[cursor + 4],
                bytes[cursor + 5],
                bytes[cursor + 6],
                bytes[cursor + 7],
            ]) as usize;
            let payload_size = u64::from_le_bytes([
                bytes[cursor + 8],
                bytes[cursor + 9],
                bytes[cursor + 10],
                bytes[cursor + 11],
                bytes[cursor + 12],
                bytes[cursor + 13],
                bytes[cursor + 14],
                bytes[cursor + 15],
            ]) as usize;
            let sm = u16::from_le_bytes([bytes[cursor + 28], bytes[cursor + 29]]);

            let payload_start = cursor.saturating_add(header_len);
            let payload_cap = payload_start.saturating_add(payload_size);
            if payload_cap > payload_end {
                return Err(FatbinError::EntryOverflow {
                    entry_index,
                    entry_offset: cursor,
                    entry_end: payload_cap,
                    wrapper_end: payload_end,
                });
            }
            entries.push(FatbinEntry {
                kind: FatbinEntryKind::from_raw(kind_raw),
                sm,
                payload: &bytes[payload_start..payload_cap],
                compressed: (flags & 0x1) != 0,
            });
            cursor = payload_cap;
            entry_index += 1;
        }

        Ok(Self {
            raw: bytes,
            version,
            entries,
        })
    }

    /// Only cubin entries (`kind == Cubin`).
    pub fn cubins(&self) -> impl Iterator<Item = &FatbinEntry<'a>> {
        self.entries
            .iter()
            .filter(|e| e.kind == FatbinEntryKind::Cubin)
    }

    /// Only PTX entries (`kind == Ptx`).
    pub fn ptx_entries(&self) -> impl Iterator<Item = &FatbinEntry<'a>> {
        self.entries
            .iter()
            .filter(|e| e.kind == FatbinEntryKind::Ptx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthesise a fatbin wrapper around one or more payloads. Layout:
    ///
    /// ```text
    ///   bytes 0..16   wrapper header
    ///   bytes 16..    concatenated entry (header + payload) records
    /// ```
    fn build_wrapper(entries: &[(FatbinEntryKind, u16, &[u8])]) -> Vec<u8> {
        let mut out = vec![0u8; WRAPPER_HEADER_SIZE];
        // Magic + version
        out[0..4].copy_from_slice(&FATBIN_MAGIC.to_le_bytes());
        out[4..8].copy_from_slice(&1u32.to_le_bytes());
        // header_offset = 16 (right after wrapper header)
        out[8..12].copy_from_slice(&16u32.to_le_bytes());
        // header_size: filled in after we know payload length
        let payload_start = out.len();

        for (kind, sm, payload) in entries {
            let kind_raw: u16 = match kind {
                FatbinEntryKind::Ptx => 1,
                FatbinEntryKind::Cubin => 2,
                FatbinEntryKind::Unknown(x) => *x,
            };
            let mut hdr = vec![0u8; ENTRY_HEADER_SIZE];
            hdr[0..2].copy_from_slice(&kind_raw.to_le_bytes());
            hdr[2..4].copy_from_slice(&0u16.to_le_bytes()); // flags
            hdr[4..8].copy_from_slice(&(ENTRY_HEADER_SIZE as u32).to_le_bytes()); // header_len
            hdr[8..16].copy_from_slice(&(payload.len() as u64).to_le_bytes());
            hdr[28..30].copy_from_slice(&sm.to_le_bytes());
            out.extend_from_slice(&hdr);
            out.extend_from_slice(payload);
        }

        let payload_size = (out.len() - payload_start) as u32;
        out[12..16].copy_from_slice(&payload_size.to_le_bytes());
        out
    }

    #[test]
    fn parses_a_round_tripped_wrapper() {
        let cubin = b"ELFISHBYTES_SM80_CUBIN_CONTENT";
        let ptx = b".version 9.2\n.target sm_80\n";
        let blob = build_wrapper(&[
            (FatbinEntryKind::Cubin, 80, cubin),
            (FatbinEntryKind::Ptx, 80, ptx),
        ]);
        let w = FatbinWrapper::parse(&blob).expect("round-trip parse");
        assert_eq!(w.version, 1);
        assert_eq!(w.entries.len(), 2);
        assert_eq!(w.entries[0].kind, FatbinEntryKind::Cubin);
        assert_eq!(w.entries[0].sm, 80);
        assert_eq!(w.entries[0].payload, cubin);
        assert_eq!(w.entries[1].kind, FatbinEntryKind::Ptx);
        assert_eq!(w.entries[1].payload, ptx);
        assert_eq!(w.cubins().count(), 1);
        assert_eq!(w.ptx_entries().count(), 1);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut blob = build_wrapper(&[(FatbinEntryKind::Cubin, 80, b"x")]);
        blob[0] = 0xDE;
        assert!(matches!(
            FatbinWrapper::parse(&blob),
            Err(FatbinError::BadMagic(_))
        ));
    }

    #[test]
    fn rejects_truncated_header() {
        assert!(matches!(
            FatbinWrapper::parse(&[0u8; 8]),
            Err(FatbinError::Truncated {
                needed: 16,
                have: 8
            })
        ));
    }

    #[test]
    fn rejects_payload_overflow() {
        let mut blob = build_wrapper(&[(FatbinEntryKind::Cubin, 80, b"hello")]);
        // Claim a huge payload size in the wrapper header.
        blob[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            FatbinWrapper::parse(&blob),
            Err(FatbinError::PayloadOverflow { .. })
        ));
    }

    #[test]
    fn unknown_entry_kind_is_preserved() {
        let blob = build_wrapper(&[(FatbinEntryKind::Unknown(7), 90, b"future")]);
        let w = FatbinWrapper::parse(&blob).unwrap();
        assert_eq!(w.entries[0].kind, FatbinEntryKind::Unknown(7));
        assert_eq!(w.entries[0].sm, 90);
    }

    #[test]
    fn wraps_a_real_cubin_and_recovers_it_bit_for_bit() {
        // Use one of the corpus cubins if available; otherwise fall
        // back to a short dummy payload so CI without the corpus still
        // exercises the happy path.
        let corpus =
            std::path::Path::new("../..").join("tests/corpus/cuda/build/sm_80/vector_add.cubin");
        let cubin_bytes = std::fs::read(&corpus).unwrap_or_else(|_| b"CUBIN_PLACEHOLDER".to_vec());
        let blob = build_wrapper(&[(FatbinEntryKind::Cubin, 80, &cubin_bytes)]);
        let w = FatbinWrapper::parse(&blob).unwrap();
        let e = w.cubins().next().expect("cubin entry");
        assert_eq!(e.payload, cubin_bytes.as_slice());
    }
}
