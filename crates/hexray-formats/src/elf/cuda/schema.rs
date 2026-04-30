//! Typed decoding of `.nv.info` record payloads.
//!
//! M2 framed each record as `(format, attribute, payload)`. M5 gives the
//! payloads semantic shape: parameter layout, register counts, launch
//! bounds, exit-instruction offsets, and the param constant-bank header.
//!
//! Every decoded field here is cross-checked against real cubins in
//! `tests/corpus/cuda/build/*/*.cubin` (regeneratable via
//! `scripts/build-cuda-corpus.sh`). Where the underlying NVIDIA format
//! has bits we don't yet interpret, the decoded record carries a
//! [`ParamInfo::raw_trailer`]-style field so the raw bytes are never
//! thrown away.
//!
//! References: CuAssembler `CuAsm/CuNVInfo.py` and `cuda_parsers::cubin`
//! (for `KPARAM_INFO` layout), plus empirical inspection of
//! `.nv.info.vector_add` / `.nv.info.shared_transpose` / etc emitted by
//! `ptxas 13.2` for sm_80.

// File-level allow: bit-math + slice indexing in this parser/decoder
// is bounds-checked at function entry. Per-site annotations would be
// noise; the runtime fuzz gate (`scripts/run-fuzz-corpus`) catches
// actual crashes. New code should prefer `.get()` + `checked_*`.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use super::info::{NvInfoAttribute, NvInfoBlob, NvInfoEntryRef, NvInfoFormat};

/// Summary of kernel resource usage decoded from a `.nv.info.<kernel>`
/// blob. Every field is optional — a malformed or missing attribute
/// leaves it `None` / empty rather than failing the whole decode.
#[derive(Debug, Clone, Default)]
pub struct KernelResourceUsage {
    /// `EIATTR_MAX_REG_COUNT` — register budget (e.g. 255 means the
    /// kernel has no `__launch_bounds__(,N)` directive constraining it).
    pub max_reg_count: Option<u8>,
    /// `EIATTR_MIN_STACK_SIZE` — minimum per-thread stack, in bytes.
    pub min_stack_size: Option<u32>,
    /// `EIATTR_FRAME_SIZE` — per-thread stack frame size, in bytes.
    pub frame_size: Option<u32>,
    /// `EIATTR_MAX_STACK_SIZE`
    pub max_stack_size: Option<u32>,
    /// `EIATTR_CBANK_PARAM_SIZE` — total size of the parameter bank in
    /// bytes. Cross-check: should equal the sum of `ParamInfo.size_bytes`
    /// rounded up to alignment.
    pub cbank_param_size: Option<u16>,
    /// `EIATTR_PARAM_CBANK` — which constant bank holds kernel params
    /// and where. Usually `{ bank: 0, offset: 0x160, size: 0x1c }` for
    /// sm_80-style kernels (params follow the 0x160-byte driver header).
    pub param_cbank: Option<ParamCbank>,
    /// `EIATTR_KPARAM_INFO` — one per parameter, in appearance order.
    /// The list is *not* guaranteed to be sorted by ordinal; inspect
    /// [`ParamInfo::ordinal`] if caller needs param order.
    pub params: Vec<ParamInfo>,
    /// `EIATTR_EXIT_INSTR_OFFSETS` — SASS instruction byte offsets at
    /// which the kernel runs `EXIT`. Useful for CFG bookkeeping.
    pub exit_offsets: Vec<u32>,
    /// `EIATTR_S2RCTAID_INSTR_OFFSETS` — offsets of `S2R Rx, SR_CTAID.*`
    /// instructions. Kept so M7 can model block-coordinate reads.
    pub s2r_ctaid_offsets: Vec<u32>,
    /// `EIATTR_MAX_THREADS` launch bound, if set.
    pub max_threads: Option<u32>,
    /// `EIATTR_REQNTID` — `__launch_bounds__` blockDim triple
    /// `(x, y, z)`, if set.
    pub req_ntid: Option<(u32, u32, u32)>,
    /// `EIATTR_MAXNTID` triple, if set.
    pub max_ntid: Option<(u32, u32, u32)>,
    /// True when the kernel reads `%ctaid.z` (`EIATTR_CTAIDZ_USED`).
    pub ctaidz_used: bool,
}

/// Parameter-bank header. The driver places the kernel-parameter block
/// at `offset` bytes into constant bank `bank` with `size` bytes total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParamCbank {
    /// Constant bank index. `0` for the default param bank on current
    /// ptxas; higher banks appear for user `__constant__` data.
    pub bank: u8,
    /// Byte offset into the bank where the parameter block starts.
    pub offset: u32,
    /// Parameter block size in bytes (matches `cbank_param_size` when
    /// both fields are present).
    pub size: u32,
}

/// One parameter's layout record, as recorded in `EIATTR_KPARAM_INFO`.
///
/// Layout (12 bytes):
///
/// ```text
///   u32 reserved_zero    ; observed 0 on every corpus cubin
///   u16 ordinal          ; 0-indexed kernel-argument number
///   u16 offset           ; byte offset into the param cbank
///   u32 trailing_attrs   ; packed bits — see below
/// ```
///
/// The trailing `u32` is not fully reverse-engineered. What we can
/// extract today (verified on the sm_80/86/89 corpus for int / pointer
/// / float params):
///
/// - bits `[20:23]`: parameter size in 4-byte dwords
///   (`size_bytes = dwords * 4`). Pointer = `2`, 32-bit int/float = `1`.
/// - bits `[16:19]`: observed `0x1` for every scalar + pointer param.
///   Likely "is-live" / "is-param". Preserved verbatim.
/// - bits `[8:15]`: observed `0xf0` for every scalar/pointer param.
///   Likely `space = .param`. Preserved verbatim.
/// - bits `[0:7]`: observed `0x00`. Likely `log_align`, but we leave
///   it as `Unknown` rather than report a possibly-wrong value.
///
/// The full u32 is kept as [`Self::raw_trailer`] so M6/M7 can refine
/// the decomposition without a schema change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParamInfo {
    pub ordinal: u16,
    pub offset: u16,
    /// Size expressed in 4-byte dwords. Multiply by 4 for bytes.
    pub size_dwords: u8,
    /// The complete trailing 32-bit attribute word. Kept in case new
    /// bits are identified later; equality-compared for regressions.
    pub raw_trailer: u32,
}

impl ParamInfo {
    /// Size in bytes (from [`Self::size_dwords`]).
    pub fn size_bytes(&self) -> u32 {
        (self.size_dwords as u32) * 4
    }
}

/// Errors that can be surfaced when decoding a payload. None of these
/// are fatal — callers observe them via `Option::None` on the relevant
/// [`KernelResourceUsage`] field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaError {
    TruncatedPayload,
    WrongFormat,
}

impl KernelResourceUsage {
    /// Decode every recognised attribute in `blob` into a typed summary.
    ///
    /// Unknown attributes are silently skipped (already preserved on
    /// the [`NvInfoBlob::entries`] list for callers that want to
    /// inspect them).
    pub fn from_nv_info(blob: &NvInfoBlob<'_>) -> Self {
        let mut out = Self::default();

        for entry in &blob.entries {
            let payload = blob.payload(entry);
            match entry.attribute {
                NvInfoAttribute::MaxRegCount => {
                    out.max_reg_count = decode_hval_u8(entry, payload);
                }
                NvInfoAttribute::MinStackSize => {
                    out.min_stack_size = decode_sval_u32_pair(payload).map(|(_, v)| v);
                }
                NvInfoAttribute::FrameSize => {
                    out.frame_size = decode_sval_u32_pair(payload).map(|(_, v)| v);
                }
                NvInfoAttribute::MaxStackSize => {
                    out.max_stack_size = decode_sval_u32_pair(payload).map(|(_, v)| v);
                }
                NvInfoAttribute::CbankParamSize => {
                    out.cbank_param_size = decode_hval_u16(entry, payload);
                }
                NvInfoAttribute::ParamCbank => {
                    out.param_cbank = decode_param_cbank(payload);
                }
                NvInfoAttribute::KparamInfo => {
                    if let Some(p) = decode_kparam_info(payload) {
                        out.params.push(p);
                    }
                }
                NvInfoAttribute::ExitInstrOffsets => {
                    out.exit_offsets = decode_u32_list(payload);
                }
                NvInfoAttribute::S2RCtaidInstrOffsets => {
                    out.s2r_ctaid_offsets = decode_u32_list(payload);
                }
                NvInfoAttribute::MaxThreads => {
                    out.max_threads = decode_hval_u16(entry, payload).map(|v| v as u32);
                }
                NvInfoAttribute::ReqNtid => {
                    out.req_ntid = decode_triple_u32(payload);
                }
                NvInfoAttribute::MaxNtid => {
                    out.max_ntid = decode_triple_u32(payload);
                }
                NvInfoAttribute::CtaidzUsed => {
                    out.ctaidz_used = true;
                }
                _ => {}
            }
        }

        out
    }

    /// Sum `ParamInfo.size_bytes()` across every recorded parameter.
    /// Useful as a consistency check vs [`Self::cbank_param_size`].
    pub fn total_param_bytes(&self) -> u32 {
        self.params.iter().map(|p| p.size_bytes()).sum()
    }
}

// ---- individual payload decoders -------------------------------------------

fn decode_hval_u8(entry: &NvInfoEntryRef, payload: &[u8]) -> Option<u8> {
    if entry.format != NvInfoFormat::HVal {
        return None;
    }
    // The HVAL payload is 2 bytes; we take the low byte for an attribute
    // like MaxRegCount which never exceeds 255.
    payload.first().copied()
}

fn decode_hval_u16(entry: &NvInfoEntryRef, payload: &[u8]) -> Option<u16> {
    if entry.format != NvInfoFormat::HVal {
        return None;
    }
    if payload.len() < 2 {
        return None;
    }
    Some(u16::from_le_bytes([payload[0], payload[1]]))
}

/// Decode a pair of `(index_or_kind, value)` u32 words. Used by
/// `EIATTR_MIN_STACK_SIZE` / `FRAME_SIZE` / `MAX_STACK_SIZE`, which
/// carry the kernel-symbol index followed by the resource size.
fn decode_sval_u32_pair(payload: &[u8]) -> Option<(u32, u32)> {
    if payload.len() < 8 {
        return None;
    }
    let a = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let b = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    Some((a, b))
}

/// `EIATTR_PARAM_CBANK` payload:
///
/// ```text
///   u32 cbank_symbol_index   ; index into .symtab of the owning cbank
///   u16 offset               ; start of param block inside that bank
///   u16 size                 ; size in bytes
/// ```
///
/// Observed on sm_80 vector_add: index=4, offset=0x160, size=0x1c.
fn decode_param_cbank(payload: &[u8]) -> Option<ParamCbank> {
    if payload.len() < 8 {
        return None;
    }
    // The bank itself is identified by a *symbol index* which we'd need
    // the ELF symtab to resolve to `bank_number`. Real observation:
    // param cbank is always bank 0 for non-`__constant__` data. We
    // record bank=0 here and revisit in M7 when we wire in symbol-to-
    // section mapping.
    let _sym_index = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let offset = u16::from_le_bytes([payload[4], payload[5]]) as u32;
    let size = u16::from_le_bytes([payload[6], payload[7]]) as u32;
    Some(ParamCbank {
        bank: 0,
        offset,
        size,
    })
}

/// `EIATTR_KPARAM_INFO` payload — 12 bytes per the layout documented on
/// [`ParamInfo`].
fn decode_kparam_info(payload: &[u8]) -> Option<ParamInfo> {
    if payload.len() < 12 {
        return None;
    }
    let ordinal = u16::from_le_bytes([payload[4], payload[5]]);
    let offset = u16::from_le_bytes([payload[6], payload[7]]);
    let trailing = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
    let size_dwords = ((trailing >> 20) & 0xF) as u8;
    Some(ParamInfo {
        ordinal,
        offset,
        size_dwords,
        raw_trailer: trailing,
    })
}

/// Decode a packed list of `u32` values (`EIATTR_EXIT_INSTR_OFFSETS` and
/// its siblings).
fn decode_u32_list(payload: &[u8]) -> Vec<u32> {
    payload
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

/// Decode three consecutive `u32` words for `EIATTR_REQNTID` /
/// `EIATTR_MAXNTID` (`ntid.x`, `ntid.y`, `ntid.z`).
fn decode_triple_u32(payload: &[u8]) -> Option<(u32, u32, u32)> {
    if payload.len() < 12 {
        return None;
    }
    let x = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let y = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let z = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
    Some((x, y, z))
}

#[cfg(test)]
mod tests {
    use super::super::info::parse_nv_info;
    use super::*;

    /// Build a TLV blob of length-aligned entries, matching how real
    /// `.nv.info` blobs are laid out on disk.
    fn pad4(mut v: Vec<u8>) -> Vec<u8> {
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    fn sval(attr: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0x04, attr];
        v.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        v.extend_from_slice(payload);
        pad4(v)
    }

    fn hval(attr: u8, payload: u16) -> Vec<u8> {
        pad4(vec![0x03, attr, payload as u8, (payload >> 8) as u8])
    }

    fn nval(attr: u8) -> Vec<u8> {
        pad4(vec![0x01, attr])
    }

    #[test]
    fn decodes_max_reg_count() {
        let blob = hval(0x1b, 0x00FF); // MaxRegCount = 255
        let parsed = parse_nv_info(&blob);
        let usage = KernelResourceUsage::from_nv_info(&parsed);
        assert_eq!(usage.max_reg_count, Some(255));
    }

    #[test]
    fn decodes_ctaidz_used_flag() {
        let blob = nval(0x04); // CtaidzUsed
        let parsed = parse_nv_info(&blob);
        assert!(KernelResourceUsage::from_nv_info(&parsed).ctaidz_used);
    }

    #[test]
    fn decodes_vector_add_style_kparam_info() {
        // Mirrors the real sm_80 vector_add .nv.info.vector_add payload
        // for its 4 params (a, b, c: float* 8-byte; n: int 4-byte).
        let mut blob = Vec::new();
        blob.extend(sval(
            0x17,
            &[
                0, 0, 0, 0, //
                0, 0, // ordinal 0
                0, 0, // offset 0
                0x00, 0xf0, 0x21, 0x00, // trailing: size_dwords=2 (pointer)
            ],
        ));
        blob.extend(sval(
            0x17,
            &[
                0, 0, 0, 0, //
                1, 0, // ordinal 1
                8, 0, // offset 8
                0x00, 0xf0, 0x21, 0x00, // size_dwords=2
            ],
        ));
        blob.extend(sval(
            0x17,
            &[
                0, 0, 0, 0, //
                2, 0, // ordinal 2
                0x10, 0, // offset 16
                0x00, 0xf0, 0x21, 0x00, // size_dwords=2
            ],
        ));
        blob.extend(sval(
            0x17,
            &[
                0, 0, 0, 0, //
                3, 0, // ordinal 3
                0x18, 0, // offset 24
                0x00, 0xf0, 0x11, 0x00, // size_dwords=1 (int)
            ],
        ));

        let parsed = parse_nv_info(&blob);
        let usage = KernelResourceUsage::from_nv_info(&parsed);
        assert_eq!(usage.params.len(), 4);
        let pointers: Vec<&ParamInfo> =
            usage.params.iter().filter(|p| p.size_dwords == 2).collect();
        assert_eq!(pointers.len(), 3); // a, b, c
        let ints: Vec<&ParamInfo> = usage.params.iter().filter(|p| p.size_dwords == 1).collect();
        assert_eq!(ints.len(), 1); // n
        assert_eq!(usage.total_param_bytes(), 3 * 8 + 4);
        // raw_trailer is preserved verbatim.
        assert_eq!(ints[0].raw_trailer, 0x0011_f000);
        assert_eq!(pointers[0].raw_trailer, 0x0021_f000);
    }

    #[test]
    fn decodes_exit_offsets() {
        // Two u32 exits at 0x50 and 0xf0 — the real vector_add layout.
        let blob = sval(0x1c, &[0x50, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x00]);
        let parsed = parse_nv_info(&blob);
        let usage = KernelResourceUsage::from_nv_info(&parsed);
        assert_eq!(usage.exit_offsets, vec![0x50, 0xf0]);
    }

    #[test]
    fn decodes_param_cbank() {
        // Real payload: sym_index=4, offset=0x160, size=0x1c.
        let blob = sval(0x0a, &[4, 0, 0, 0, 0x60, 0x01, 0x1c, 0x00]);
        let parsed = parse_nv_info(&blob);
        let usage = KernelResourceUsage::from_nv_info(&parsed);
        let cb = usage.param_cbank.expect("param cbank present");
        assert_eq!(cb.bank, 0);
        assert_eq!(cb.offset, 0x160);
        assert_eq!(cb.size, 0x1c);
    }

    #[test]
    fn decodes_req_ntid_triple() {
        let blob = sval(
            0x10,
            &[
                0x20, 0, 0, 0, // x = 32
                0x04, 0, 0, 0, // y = 4
                0x01, 0, 0, 0, // z = 1
            ],
        );
        let parsed = parse_nv_info(&blob);
        let usage = KernelResourceUsage::from_nv_info(&parsed);
        assert_eq!(usage.req_ntid, Some((32, 4, 1)));
    }

    #[test]
    fn missing_attributes_leave_fields_none() {
        let blob = hval(0x1b, 0x30); // just MaxRegCount
        let parsed = parse_nv_info(&blob);
        let usage = KernelResourceUsage::from_nv_info(&parsed);
        assert_eq!(usage.max_reg_count, Some(0x30));
        assert!(usage.params.is_empty());
        assert!(usage.param_cbank.is_none());
        assert!(usage.exit_offsets.is_empty());
        assert!(!usage.ctaidz_used);
    }
}
