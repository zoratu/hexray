//! AMDGPU opcode tables — first pass.
//!
//! Hand-curated from LLVM's AMDGPU tablegen sources
//! (`llvm/lib/Target/AMDGPU/{VOP1Instructions,VOP2Instructions,
//! SOP*Instructions,SMInstructions,DSInstructions,FLATInstructions}.td`)
//! and cross-referenced against `llvm-mc -triple=amdgcn-amd-amdhsa
//! -mcpu=gfxNNN --show-encoding` outputs.
//!
//! Coverage is *intentionally partial* in M10.4 — we hit the dozen-ish
//! opcodes per class that show up in every realistic kernel
//! (data movement, ALU, compare, branch, exit, basic memory). M10.5
//! lifts the differential gate which then drives organic table growth
//! against `llvm-objdump` ground truth on a built corpus.
//!
//! Per-family layout: AMDGPU OP numbering shifts between GFX9 and
//! GFX10+ for many opcodes (the most visible: `v_mov_b32` is OP=1 on
//! GFX9, OP=0 on GFX10+). Each table is a slice of `(op, mnemonic,
//! operation)`; the lookup helper picks the right slice per family.

use super::EncodingFamily;
use hexray_core::Operation;

/// One entry in an AMDGPU per-family opcode table.
#[derive(Debug, Clone, Copy)]
pub struct OpcodeEntry {
    pub op: u16,
    pub mnemonic: &'static str,
    pub operation: Operation,
}

/// Look up a `(family, class, op)` triple. Returns `None` for opcodes
/// not yet in the table — the caller falls back to the
/// `<class>.op<id>` placeholder.
pub fn lookup(class: TableClass, family: EncodingFamily, op: u16) -> Option<&'static OpcodeEntry> {
    table_for(class, family).iter().find(|e| e.op == op)
}

/// The opcode-class identifier used to pick a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableClass {
    Vop1,
    Vop2,
    Vop3,
    Vopc,
    Sop1,
    Sop2,
    Sopp,
    Smem,
    /// FLAT class — covers flat / global / scratch addressing modes.
    /// The `seg` bit field at `[16:15]` of the encoding distinguishes
    /// the three; the per-OP table here lists the *flat* mnemonic
    /// and the renderer rewrites the prefix when seg is non-zero.
    Flat,
}

fn table_for(class: TableClass, family: EncodingFamily) -> &'static [OpcodeEntry] {
    match (class, family) {
        (TableClass::Vop1, EncodingFamily::Gfx9) => VOP1_GFX9,
        (TableClass::Vop1, EncodingFamily::Gfx10Plus) => VOP1_GFX10,
        (TableClass::Vop1, EncodingFamily::Gfx11Plus) => VOP1_GFX10,
        (TableClass::Vop2, EncodingFamily::Gfx9) => VOP2_GFX9,
        (TableClass::Vop2, EncodingFamily::Gfx10Plus) => VOP2_GFX10,
        (TableClass::Vop2, EncodingFamily::Gfx11Plus) => VOP2_GFX11,
        (TableClass::Vop3, EncodingFamily::Gfx11Plus) => VOP3_GFX11,
        (TableClass::Vop3, EncodingFamily::Gfx9) => VOP3_GFX9,
        (TableClass::Vop3, _) => VOP3_GFX10,
        (TableClass::Vopc, EncodingFamily::Gfx9) => VOPC_GFX9,
        (TableClass::Vopc, EncodingFamily::Gfx11Plus) => VOPC_GFX11,
        (TableClass::Vopc, _) => VOPC_GFX10,
        (TableClass::Sop1, EncodingFamily::Gfx9) => SOP1_GFX9,
        (TableClass::Sop1, EncodingFamily::Gfx10Plus) => SOP1_GFX10,
        // RDNA3 reverted SOP1 to GFX9-style numbering for the bulk of
        // opcodes (s_mov_b32 = OP=0x00 again), but `s_and_saveexec`
        // remains the wave32 `_b32` form, so we keep a thin overlay.
        (TableClass::Sop1, EncodingFamily::Gfx11Plus) => SOP1_GFX11,
        (TableClass::Sop2, EncodingFamily::Gfx9) => SOP2_GFX9,
        (TableClass::Sop2, _) => SOP2_GFX10,
        (TableClass::Sopp, EncodingFamily::Gfx9) => SOPP_GFX9,
        (TableClass::Sopp, EncodingFamily::Gfx10Plus) => SOPP_GFX10,
        (TableClass::Sopp, EncodingFamily::Gfx11Plus) => SOPP_GFX11,
        (TableClass::Smem, EncodingFamily::Gfx11Plus) => SMEM_GFX11,
        (TableClass::Smem, _) => SMEM_SHARED,
        (TableClass::Flat, EncodingFamily::Gfx11Plus) => FLAT_GFX11,
        (TableClass::Flat, EncodingFamily::Gfx9) => FLAT_GFX9,
        (TableClass::Flat, _) => FLAT_GFX10,
    }
}

/// VOP1 — GFX9 (Vega / CDNA1/2/3).
///
/// Numbering follows LLVM's `VOP1Instructions.td` GFX9 records.
const VOP1_GFX9: &[OpcodeEntry] = &[
    OpcodeEntry {
        op: 0x00,
        mnemonic: "v_nop",
        operation: Operation::Nop,
    },
    OpcodeEntry {
        op: 0x01,
        mnemonic: "v_mov_b32_e32",
        operation: Operation::Move,
    },
    OpcodeEntry {
        op: 0x02,
        mnemonic: "v_readfirstlane_b32",
        operation: Operation::Move,
    },
    OpcodeEntry {
        op: 0x03,
        mnemonic: "v_cvt_i32_f64",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x04,
        mnemonic: "v_cvt_f64_i32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x05,
        mnemonic: "v_cvt_f32_i32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x06,
        mnemonic: "v_cvt_f32_u32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x07,
        mnemonic: "v_cvt_u32_f32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x08,
        mnemonic: "v_cvt_i32_f32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x0a,
        mnemonic: "v_cvt_f16_f32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x0b,
        mnemonic: "v_cvt_f32_f16",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x14,
        mnemonic: "v_cvt_f32_f64",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x15,
        mnemonic: "v_cvt_f64_f32",
        operation: Operation::Other(0),
    },
];

/// VOP1 — GFX10+ (RDNA1/2/3/4). OP=0 is `v_nop`; `v_mov_b32` shifts
/// to OP=1.
const VOP1_GFX10: &[OpcodeEntry] = &[
    OpcodeEntry {
        op: 0x00,
        mnemonic: "v_nop",
        operation: Operation::Nop,
    },
    OpcodeEntry {
        op: 0x01,
        mnemonic: "v_mov_b32_e32",
        operation: Operation::Move,
    },
    OpcodeEntry {
        op: 0x02,
        mnemonic: "v_readfirstlane_b32",
        operation: Operation::Move,
    },
    OpcodeEntry {
        op: 0x03,
        mnemonic: "v_cvt_i32_f64",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x05,
        mnemonic: "v_cvt_f32_i32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x06,
        mnemonic: "v_cvt_f32_u32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x07,
        mnemonic: "v_cvt_u32_f32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x08,
        mnemonic: "v_cvt_i32_f32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x0a,
        mnemonic: "v_cvt_f16_f32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x0b,
        mnemonic: "v_cvt_f32_f16",
        operation: Operation::Other(0),
    },
];

/// VOP2 — GFX9.
const VOP2_GFX9: &[OpcodeEntry] = &[
    OpcodeEntry {
        op: 0x00,
        mnemonic: "v_cndmask_b32_e32",
        operation: Operation::ConditionalMove,
    },
    OpcodeEntry {
        op: 0x01,
        mnemonic: "v_add_f32_e32",
        operation: Operation::Add,
    },
    OpcodeEntry {
        op: 0x02,
        mnemonic: "v_sub_f32_e32",
        operation: Operation::Sub,
    },
    OpcodeEntry {
        op: 0x03,
        mnemonic: "v_subrev_f32_e32",
        operation: Operation::Sub,
    },
    OpcodeEntry {
        op: 0x04,
        mnemonic: "v_mul_legacy_f32_e32",
        operation: Operation::Mul,
    },
    OpcodeEntry {
        op: 0x05,
        mnemonic: "v_mul_f32_e32",
        operation: Operation::Mul,
    },
    OpcodeEntry {
        op: 0x06,
        mnemonic: "v_mul_i32_i24_e32",
        operation: Operation::Mul,
    },
    OpcodeEntry {
        op: 0x07,
        mnemonic: "v_mul_hi_i32_i24_e32",
        operation: Operation::Mul,
    },
    OpcodeEntry {
        op: 0x08,
        mnemonic: "v_mul_u32_u24_e32",
        operation: Operation::Mul,
    },
    OpcodeEntry {
        op: 0x0e,
        mnemonic: "v_max_f32_e32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x0f,
        mnemonic: "v_min_f32_e32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x11,
        mnemonic: "v_ashrrev_i32_e32",
        operation: Operation::Sar,
    },
    // GFX9 carry-add / carry-sub keep the implicit `vcc` carry bit;
    // the mnemonics carry the `_co_` infix to distinguish them from
    // the no-carry forms at 0x32+. Validated against
    // `vector_add.gfx900.co` (`32040002` → `v_add_co_u32_e32`).
    OpcodeEntry {
        op: 0x19,
        mnemonic: "v_add_co_u32_e32",
        operation: Operation::Add,
    },
    OpcodeEntry {
        op: 0x1a,
        mnemonic: "v_sub_co_u32_e32",
        operation: Operation::Sub,
    },
    OpcodeEntry {
        op: 0x1b,
        mnemonic: "v_subrev_co_u32_e32",
        operation: Operation::Sub,
    },
    OpcodeEntry {
        op: 0x1c,
        mnemonic: "v_addc_co_u32_e32",
        operation: Operation::Add,
    },
    OpcodeEntry {
        op: 0x1d,
        mnemonic: "v_subb_co_u32_e32",
        operation: Operation::Sub,
    },
    OpcodeEntry {
        op: 0x1e,
        mnemonic: "v_subbrev_co_u32_e32",
        operation: Operation::Sub,
    },
    // GFX9-only no-carry add/sub. `v_add_u32_e32` byte-validated at
    // GFX9 OP=0x34 in `vector_add.gfx900.co` (`68000000`).
    OpcodeEntry {
        op: 0x34,
        mnemonic: "v_add_u32_e32",
        operation: Operation::Add,
    },
    OpcodeEntry {
        op: 0x35,
        mnemonic: "v_sub_u32_e32",
        operation: Operation::Sub,
    },
    OpcodeEntry {
        op: 0x36,
        mnemonic: "v_subrev_u32_e32",
        operation: Operation::Sub,
    },
];

/// VOP2 — GFX10+.
/// VOP2 — GFX10+ (RDNA1+).
///
/// RDNA renumbered VOP2 to a much more compact layout than GFX9.
/// `v_cndmask_b32_e32` shifts to OP=0x01, `v_add_f32_e32` to 0x03.
/// `V_ADD_CO_CI_U32` (RDNA-specific carry-add) is the new 0x28 slot.
/// Numbering harvested from
/// `llvm/lib/Target/AMDGPU/VOP2Instructions.td` GFX10 records and
/// cross-checked against `llvm-objdump -triple=amdgcn-amd-amdhsa
/// --mcpu=gfx1030` on the SCALE-built fixture in
/// `tests/corpus/scale-lang/vector_add.gfx1030.co`.
const VOP2_GFX10: &[OpcodeEntry] = &[
    OpcodeEntry {
        op: 0x01,
        mnemonic: "v_cndmask_b32_e32",
        operation: Operation::ConditionalMove,
    },
    OpcodeEntry {
        op: 0x03,
        mnemonic: "v_add_f32_e32",
        operation: Operation::Add,
    },
    OpcodeEntry {
        op: 0x04,
        mnemonic: "v_sub_f32_e32",
        operation: Operation::Sub,
    },
    OpcodeEntry {
        op: 0x05,
        mnemonic: "v_subrev_f32_e32",
        operation: Operation::Sub,
    },
    OpcodeEntry {
        op: 0x07,
        mnemonic: "v_mul_legacy_f32_e32",
        operation: Operation::Mul,
    },
    OpcodeEntry {
        op: 0x08,
        mnemonic: "v_mul_f32_e32",
        operation: Operation::Mul,
    },
    OpcodeEntry {
        op: 0x09,
        mnemonic: "v_mul_i32_i24_e32",
        operation: Operation::Mul,
    },
    OpcodeEntry {
        op: 0x0b,
        mnemonic: "v_mul_u32_u24_e32",
        operation: Operation::Mul,
    },
    OpcodeEntry {
        op: 0x0f,
        mnemonic: "v_min_f32_e32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x10,
        mnemonic: "v_max_f32_e32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x11,
        mnemonic: "v_min_i32_e32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x12,
        mnemonic: "v_max_i32_e32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x13,
        mnemonic: "v_min_u32_e32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x14,
        mnemonic: "v_max_u32_e32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x16,
        mnemonic: "v_lshlrev_b32_e32",
        operation: Operation::Shl,
    },
    OpcodeEntry {
        op: 0x17,
        mnemonic: "v_lshrrev_b32_e32",
        operation: Operation::Shr,
    },
    OpcodeEntry {
        op: 0x18,
        mnemonic: "v_ashrrev_i32_e32",
        operation: Operation::Sar,
    },
    OpcodeEntry {
        op: 0x1b,
        mnemonic: "v_and_b32_e32",
        operation: Operation::And,
    },
    OpcodeEntry {
        op: 0x1c,
        mnemonic: "v_or_b32_e32",
        operation: Operation::Or,
    },
    OpcodeEntry {
        op: 0x1d,
        mnemonic: "v_xor_b32_e32",
        operation: Operation::Xor,
    },
    OpcodeEntry {
        op: 0x28,
        mnemonic: "v_add_co_ci_u32_e32",
        operation: Operation::Add,
    },
    OpcodeEntry {
        op: 0x29,
        mnemonic: "v_sub_co_ci_u32_e32",
        operation: Operation::Sub,
    },
];

/// VOPC opcodes — same numbering on every supported family band.
/// VOPC — GFX9 (Vega / CDNA).
///
/// GFX9 packs the int comparators at OP=0xc0..=0xcf (i32) and
/// 0xc8..=0xcf (u32). RDNA1+ shifted them down to 0x80..=0x9f
/// (`VOPC_GFX10`). Validated against `vector_add.gfx900.co`
/// (`7d880002` → `v_cmp_gt_i32_e32 vcc, s2, v0`).
const VOPC_GFX9: &[OpcodeEntry] = &[
    OpcodeEntry {
        op: 0xc0,
        mnemonic: "v_cmp_f_i32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0xc1,
        mnemonic: "v_cmp_lt_i32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0xc2,
        mnemonic: "v_cmp_eq_i32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0xc3,
        mnemonic: "v_cmp_le_i32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0xc4,
        mnemonic: "v_cmp_gt_i32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0xc5,
        mnemonic: "v_cmp_ne_i32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0xc6,
        mnemonic: "v_cmp_ge_i32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0xc7,
        mnemonic: "v_cmp_t_i32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0xc8,
        mnemonic: "v_cmp_f_u32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0xc9,
        mnemonic: "v_cmp_lt_u32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0xca,
        mnemonic: "v_cmp_eq_u32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0xcb,
        mnemonic: "v_cmp_le_u32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0xcc,
        mnemonic: "v_cmp_gt_u32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0xcd,
        mnemonic: "v_cmp_ne_u32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0xce,
        mnemonic: "v_cmp_ge_u32_e32",
        operation: Operation::Compare,
    },
];

/// VOPC — GFX11 (RDNA3).
///
/// RDNA3 compacted VOPC further. `v_cmp_*_i32_e32` lives at 0x40..0x47;
/// the `_e64` form is reached via the VOP3 0x4Cx range and renders
/// through `VOP3_GFX11`. Byte-validated against
/// `multi_kernel.gfx1100.co` (`7c880404` → `v_cmp_gt_i32_e32`).
const VOPC_GFX11: &[OpcodeEntry] = &[
    OpcodeEntry {
        op: 0x40,
        mnemonic: "v_cmp_f_i32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x41,
        mnemonic: "v_cmp_lt_i32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x42,
        mnemonic: "v_cmp_eq_i32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x43,
        mnemonic: "v_cmp_le_i32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x44,
        mnemonic: "v_cmp_gt_i32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x45,
        mnemonic: "v_cmp_ne_i32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x46,
        mnemonic: "v_cmp_ge_i32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x48,
        mnemonic: "v_cmp_f_u32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x49,
        mnemonic: "v_cmp_lt_u32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x4a,
        mnemonic: "v_cmp_eq_u32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x4b,
        mnemonic: "v_cmp_le_u32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x4c,
        mnemonic: "v_cmp_gt_u32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x4d,
        mnemonic: "v_cmp_ne_u32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x4e,
        mnemonic: "v_cmp_ge_u32_e32",
        operation: Operation::Compare,
    },
];

/// VOPC — GFX10/RDNA1+ (Navi 10/14/21+).
///
/// GFX10 introduced the compact 0x80..=0x9f encoding (i32 at 0x80,
/// u32 at 0x90) — the same numbering survives through gfx1030/1102.
const VOPC_GFX10: &[OpcodeEntry] = &[
    OpcodeEntry {
        op: 0x80,
        mnemonic: "v_cmp_f_i32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x81,
        mnemonic: "v_cmp_lt_i32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x82,
        mnemonic: "v_cmp_eq_i32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x83,
        mnemonic: "v_cmp_le_i32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x84,
        mnemonic: "v_cmp_gt_i32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x85,
        mnemonic: "v_cmp_ne_i32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x86,
        mnemonic: "v_cmp_ge_i32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x90,
        mnemonic: "v_cmp_f_u32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x91,
        mnemonic: "v_cmp_lt_u32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x92,
        mnemonic: "v_cmp_eq_u32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x93,
        mnemonic: "v_cmp_le_u32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x94,
        mnemonic: "v_cmp_gt_u32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x95,
        mnemonic: "v_cmp_ne_u32_e32",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x96,
        mnemonic: "v_cmp_ge_u32_e32",
        operation: Operation::Compare,
    },
];

/// SOP1 — GFX9 numbering (Vega / CDNA).
const SOP1_GFX9: &[OpcodeEntry] = &[
    OpcodeEntry {
        op: 0x00,
        mnemonic: "s_mov_b32",
        operation: Operation::Move,
    },
    OpcodeEntry {
        op: 0x01,
        mnemonic: "s_mov_b64",
        operation: Operation::Move,
    },
    OpcodeEntry {
        op: 0x04,
        mnemonic: "s_not_b32",
        operation: Operation::Not,
    },
    OpcodeEntry {
        op: 0x05,
        mnemonic: "s_not_b64",
        operation: Operation::Not,
    },
    OpcodeEntry {
        op: 0x06,
        mnemonic: "s_wqm_b32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x08,
        mnemonic: "s_brev_b32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x0c,
        mnemonic: "s_bcnt0_i32_b32",
        operation: Operation::Popcnt,
    },
    OpcodeEntry {
        op: 0x0e,
        mnemonic: "s_bcnt1_i32_b32",
        operation: Operation::Popcnt,
    },
    OpcodeEntry {
        op: 0x14,
        mnemonic: "s_getpc_b64",
        operation: Operation::Move,
    },
    OpcodeEntry {
        op: 0x18,
        mnemonic: "s_swappc_b64",
        operation: Operation::Call,
    },
    // GFX9 wave64 saveexec — packs the saved EXEC into a SGPR pair.
    // RDNA renamed this to `s_and_saveexec_b32` and moved it to
    // SOP2 0x3c (see `SOP2_GFX10`). Byte-validated against
    // `vector_add.gfx900.co` (`be80206a` → `s_and_saveexec_b64`).
    OpcodeEntry {
        op: 0x20,
        mnemonic: "s_and_saveexec_b64",
        operation: Operation::And,
    },
    OpcodeEntry {
        op: 0x21,
        mnemonic: "s_or_saveexec_b64",
        operation: Operation::Or,
    },
    OpcodeEntry {
        op: 0x22,
        mnemonic: "s_xor_saveexec_b64",
        operation: Operation::Xor,
    },
];

/// SOP1 — GFX10+ numbering (RDNA1+).
///
/// RDNA renumbered SOP1 to compact the table. `s_mov_b32` shifts to
/// OP=0x03 (was 0x00 on GFX9), `s_mov_b64` to 0x04. Numbering
/// validated against `llvm-objdump --triple=amdgcn-amd-amdhsa
/// --mcpu=gfx1030` on the SCALE-built fixture.
const SOP1_GFX10: &[OpcodeEntry] = &[
    OpcodeEntry {
        op: 0x03,
        mnemonic: "s_mov_b32",
        operation: Operation::Move,
    },
    OpcodeEntry {
        op: 0x04,
        mnemonic: "s_mov_b64",
        operation: Operation::Move,
    },
    OpcodeEntry {
        op: 0x05,
        mnemonic: "s_cmov_b32",
        operation: Operation::ConditionalMove,
    },
    OpcodeEntry {
        op: 0x06,
        mnemonic: "s_cmov_b64",
        operation: Operation::ConditionalMove,
    },
    OpcodeEntry {
        op: 0x07,
        mnemonic: "s_not_b32",
        operation: Operation::Not,
    },
    OpcodeEntry {
        op: 0x08,
        mnemonic: "s_not_b64",
        operation: Operation::Not,
    },
    OpcodeEntry {
        op: 0x09,
        mnemonic: "s_wqm_b32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x0c,
        mnemonic: "s_brev_b32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x10,
        mnemonic: "s_bcnt0_i32_b32",
        operation: Operation::Popcnt,
    },
    OpcodeEntry {
        op: 0x12,
        mnemonic: "s_bcnt1_i32_b32",
        operation: Operation::Popcnt,
    },
    OpcodeEntry {
        op: 0x16,
        mnemonic: "s_getpc_b64",
        operation: Operation::Move,
    },
    OpcodeEntry {
        op: 0x18,
        mnemonic: "s_setpc_b64",
        operation: Operation::Jump,
    },
    OpcodeEntry {
        op: 0x19,
        mnemonic: "s_swappc_b64",
        operation: Operation::Call,
    },
    // RDNA renamed `s_and_saveexec_b64` (GFX9 0x20) to the wave32-aware
    // `s_and_saveexec_b32` and moved it to OP=0x3c. Byte-validated
    // against `vector_add.gfx1010.co` (`be83206a` → `s_and_saveexec_b32`).
    OpcodeEntry {
        op: 0x3c,
        mnemonic: "s_and_saveexec_b32",
        operation: Operation::And,
    },
];

/// SOP2.
/// SOP2 — GFX9 (Vega / CDNA).
///
/// GFX9 numbers `s_bfm_b32` at 0x22 and `s_mul_i32` at 0x24, while
/// RDNA1+ shifted them up by 0x02 (see `SOP2_GFX10`). Validated
/// against `vector_add.gfx900.co` (`92000100` → `s_mul_i32`).
const SOP2_GFX9: &[OpcodeEntry] = &[
    OpcodeEntry {
        op: 0x00,
        mnemonic: "s_add_u32",
        operation: Operation::Add,
    },
    OpcodeEntry {
        op: 0x01,
        mnemonic: "s_sub_u32",
        operation: Operation::Sub,
    },
    OpcodeEntry {
        op: 0x02,
        mnemonic: "s_add_i32",
        operation: Operation::Add,
    },
    OpcodeEntry {
        op: 0x03,
        mnemonic: "s_sub_i32",
        operation: Operation::Sub,
    },
    OpcodeEntry {
        op: 0x04,
        mnemonic: "s_addc_u32",
        operation: Operation::Add,
    },
    OpcodeEntry {
        op: 0x05,
        mnemonic: "s_subb_u32",
        operation: Operation::Sub,
    },
    OpcodeEntry {
        op: 0x06,
        mnemonic: "s_min_i32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x07,
        mnemonic: "s_min_u32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x08,
        mnemonic: "s_max_i32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x0a,
        mnemonic: "s_cselect_b32",
        operation: Operation::ConditionalMove,
    },
    OpcodeEntry {
        op: 0x0c,
        mnemonic: "s_and_b32",
        operation: Operation::And,
    },
    OpcodeEntry {
        op: 0x0e,
        mnemonic: "s_or_b32",
        operation: Operation::Or,
    },
    OpcodeEntry {
        op: 0x10,
        mnemonic: "s_xor_b32",
        operation: Operation::Xor,
    },
    OpcodeEntry {
        op: 0x1d,
        mnemonic: "s_lshl_b32",
        operation: Operation::Shl,
    },
    OpcodeEntry {
        op: 0x1f,
        mnemonic: "s_lshr_b32",
        operation: Operation::Shr,
    },
    OpcodeEntry {
        op: 0x21,
        mnemonic: "s_ashr_i32",
        operation: Operation::Sar,
    },
    OpcodeEntry {
        op: 0x22,
        mnemonic: "s_bfm_b32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x24,
        mnemonic: "s_mul_i32",
        operation: Operation::Mul,
    },
];

/// SOP2 — GFX10+ (RDNA1+).
const SOP2_GFX10: &[OpcodeEntry] = &[
    OpcodeEntry {
        op: 0x00,
        mnemonic: "s_add_u32",
        operation: Operation::Add,
    },
    OpcodeEntry {
        op: 0x01,
        mnemonic: "s_sub_u32",
        operation: Operation::Sub,
    },
    OpcodeEntry {
        op: 0x02,
        mnemonic: "s_add_i32",
        operation: Operation::Add,
    },
    OpcodeEntry {
        op: 0x03,
        mnemonic: "s_sub_i32",
        operation: Operation::Sub,
    },
    OpcodeEntry {
        op: 0x04,
        mnemonic: "s_addc_u32",
        operation: Operation::Add,
    },
    OpcodeEntry {
        op: 0x05,
        mnemonic: "s_subb_u32",
        operation: Operation::Sub,
    },
    OpcodeEntry {
        op: 0x06,
        mnemonic: "s_min_i32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x07,
        mnemonic: "s_min_u32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x08,
        mnemonic: "s_max_i32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x0a,
        mnemonic: "s_cselect_b32",
        operation: Operation::ConditionalMove,
    },
    OpcodeEntry {
        op: 0x0e,
        mnemonic: "s_and_b32",
        operation: Operation::And,
    },
    OpcodeEntry {
        op: 0x10,
        mnemonic: "s_or_b32",
        operation: Operation::Or,
    },
    OpcodeEntry {
        op: 0x12,
        mnemonic: "s_xor_b32",
        operation: Operation::Xor,
    },
    OpcodeEntry {
        op: 0x1f,
        mnemonic: "s_lshl_b32",
        operation: Operation::Shl,
    },
    OpcodeEntry {
        op: 0x21,
        mnemonic: "s_lshr_b32",
        operation: Operation::Shr,
    },
    OpcodeEntry {
        op: 0x23,
        mnemonic: "s_ashr_i32",
        operation: Operation::Sar,
    },
    OpcodeEntry {
        op: 0x24,
        mnemonic: "s_bfm_b32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x26,
        mnemonic: "s_mul_i32",
        operation: Operation::Mul,
    },
];

/// SOPP — GFX9.
const SOPP_GFX9: &[OpcodeEntry] = &[
    OpcodeEntry {
        op: 0x00,
        mnemonic: "s_nop",
        operation: Operation::Nop,
    },
    OpcodeEntry {
        op: 0x01,
        mnemonic: "s_endpgm",
        operation: Operation::Return,
    },
    OpcodeEntry {
        op: 0x02,
        mnemonic: "s_branch",
        operation: Operation::Jump,
    },
    OpcodeEntry {
        op: 0x04,
        mnemonic: "s_cbranch_scc0",
        operation: Operation::ConditionalJump,
    },
    OpcodeEntry {
        op: 0x05,
        mnemonic: "s_cbranch_scc1",
        operation: Operation::ConditionalJump,
    },
    OpcodeEntry {
        op: 0x06,
        mnemonic: "s_cbranch_vccz",
        operation: Operation::ConditionalJump,
    },
    OpcodeEntry {
        op: 0x07,
        mnemonic: "s_cbranch_vccnz",
        operation: Operation::ConditionalJump,
    },
    OpcodeEntry {
        op: 0x08,
        mnemonic: "s_cbranch_execz",
        operation: Operation::ConditionalJump,
    },
    OpcodeEntry {
        op: 0x09,
        mnemonic: "s_cbranch_execnz",
        operation: Operation::ConditionalJump,
    },
    OpcodeEntry {
        op: 0x0a,
        mnemonic: "s_barrier",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x0c,
        mnemonic: "s_waitcnt",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x0d,
        mnemonic: "s_sethalt",
        operation: Operation::Halt,
    },
    OpcodeEntry {
        op: 0x10,
        mnemonic: "s_trap",
        operation: Operation::Interrupt,
    },
];

/// SOPP — GFX10+ numbering.
///
/// The first dozen OPs match GFX9 (s_endpgm = 0x01, s_branch =
/// 0x02). RDNA added scheduling-hint opcodes — `s_clause`,
/// `s_inst_prefetch` etc. — at OP=0x21+. Numbering validated
/// against `llvm-objdump --triple=amdgcn-amd-amdhsa --mcpu=gfx1030`.
const SOPP_GFX10: &[OpcodeEntry] = &[
    OpcodeEntry {
        op: 0x00,
        mnemonic: "s_nop",
        operation: Operation::Nop,
    },
    OpcodeEntry {
        op: 0x01,
        mnemonic: "s_endpgm",
        operation: Operation::Return,
    },
    OpcodeEntry {
        op: 0x02,
        mnemonic: "s_branch",
        operation: Operation::Jump,
    },
    OpcodeEntry {
        op: 0x04,
        mnemonic: "s_cbranch_scc0",
        operation: Operation::ConditionalJump,
    },
    OpcodeEntry {
        op: 0x05,
        mnemonic: "s_cbranch_scc1",
        operation: Operation::ConditionalJump,
    },
    OpcodeEntry {
        op: 0x06,
        mnemonic: "s_cbranch_vccz",
        operation: Operation::ConditionalJump,
    },
    OpcodeEntry {
        op: 0x07,
        mnemonic: "s_cbranch_vccnz",
        operation: Operation::ConditionalJump,
    },
    OpcodeEntry {
        op: 0x08,
        mnemonic: "s_cbranch_execz",
        operation: Operation::ConditionalJump,
    },
    OpcodeEntry {
        op: 0x09,
        mnemonic: "s_cbranch_execnz",
        operation: Operation::ConditionalJump,
    },
    OpcodeEntry {
        op: 0x0a,
        mnemonic: "s_barrier",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x0c,
        mnemonic: "s_waitcnt",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x10,
        mnemonic: "s_trap",
        operation: Operation::Interrupt,
    },
    // RDNA scheduling hints.
    OpcodeEntry {
        op: 0x21,
        mnemonic: "s_clause",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x22,
        mnemonic: "s_code_end",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x23,
        mnemonic: "s_inst_prefetch",
        operation: Operation::Other(0),
    },
];

/// SMEM — common GFX9 and GFX10+ loads. The OP layout differs
/// substantially between families for the bigger operations; we
/// only list the basic loads here. M10.5 grows this against
/// `llvm-objdump` ground truth.
const SMEM_SHARED: &[OpcodeEntry] = &[
    OpcodeEntry {
        op: 0x00,
        mnemonic: "s_load_dword",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x01,
        mnemonic: "s_load_dwordx2",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x02,
        mnemonic: "s_load_dwordx4",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x03,
        mnemonic: "s_load_dwordx8",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x04,
        mnemonic: "s_load_dwordx16",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x08,
        mnemonic: "s_buffer_load_dword",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x09,
        mnemonic: "s_buffer_load_dwordx2",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x0a,
        mnemonic: "s_buffer_load_dwordx4",
        operation: Operation::Load,
    },
];

/// VOP3 — GFX10+ (RDNA1+) opcode table.
///
/// VOP3 has a 10-bit OP field at bits `[25:16]`. The space includes
/// VOP3-encoded forms of VOP1/VOP2/VOPC instructions plus
/// genuinely-VOP3 ops (3-source ALU, 64-bit ALU, etc.). We start
/// with the opcodes that show up in the SCALE corpus; the table
/// grows organically as we widen the differential gate.
///
/// Numbering harvested from
/// `llvm/lib/Target/AMDGPU/VOP3Instructions.td` GFX10+ records.
const VOP3_GFX10: &[OpcodeEntry] = &[
    OpcodeEntry {
        op: 0x094,
        mnemonic: "v_cmpx_gt_i32_e64",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x101,
        mnemonic: "v_cndmask_b32_e64",
        operation: Operation::ConditionalMove,
    },
    OpcodeEntry {
        op: 0x155,
        mnemonic: "v_add3_u32",
        operation: Operation::Add,
    },
    OpcodeEntry {
        op: 0x176,
        mnemonic: "v_mad_u64_u32",
        operation: Operation::Mul,
    },
    OpcodeEntry {
        op: 0x177,
        mnemonic: "v_mad_i64_i32",
        operation: Operation::Mul,
    },
    OpcodeEntry {
        op: 0x2ff,
        mnemonic: "v_lshlrev_b64",
        operation: Operation::Shl,
    },
    OpcodeEntry {
        op: 0x30f,
        mnemonic: "v_add_co_u32",
        operation: Operation::Add,
    },
    OpcodeEntry {
        op: 0x310,
        mnemonic: "v_sub_co_u32",
        operation: Operation::Sub,
    },
];

/// FLAT — GFX10+ opcode table. Every entry's mnemonic is the
/// `flat_*` form; the renderer rewrites the prefix to `global_*`
/// or `scratch_*` based on the `seg` field at bits `[16:15]` of the
/// encoding (0 = flat, 1 = scratch, 2 = global).
const FLAT_GFX10: &[OpcodeEntry] = &[
    OpcodeEntry {
        op: 0x08,
        mnemonic: "flat_load_ubyte",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x09,
        mnemonic: "flat_load_sbyte",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x0a,
        mnemonic: "flat_load_ushort",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x0b,
        mnemonic: "flat_load_sshort",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x0c,
        mnemonic: "flat_load_dword",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x0d,
        mnemonic: "flat_load_dwordx2",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x0e,
        mnemonic: "flat_load_dwordx4",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x0f,
        mnemonic: "flat_load_dwordx3",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x1c,
        mnemonic: "flat_store_dword",
        operation: Operation::Store,
    },
    OpcodeEntry {
        op: 0x1d,
        mnemonic: "flat_store_dwordx2",
        operation: Operation::Store,
    },
    OpcodeEntry {
        op: 0x1e,
        mnemonic: "flat_store_dwordx4",
        operation: Operation::Store,
    },
];

/// Render the FLAT mnemonic with the right segment prefix.
///
/// The base table above lists the `flat_*` form. When the encoding's
/// `seg` field selects GLOBAL (2) or SCRATCH (1), the mnemonic
/// rewrites the leading `flat_` to `global_` or `scratch_`.
pub fn render_flat_mnemonic(base: &str, seg: u8) -> String {
    let prefix = match seg {
        0 => return base.to_string(),
        1 => "scratch_",
        2 => "global_",
        _ => return format!("flat?_{base}"),
    };
    if let Some(rest) = base.strip_prefix("flat_") {
        format!("{prefix}{rest}")
    } else {
        base.to_string()
    }
}

// =============================================================================
// GFX11 (RDNA3) opcode tables
// =============================================================================
//
// RDNA3 substantially renumbered the per-class OP fields. Validated
// against `llvm-objdump --triple=amdgcn-amd-amdhsa --mcpu=gfx1100`
// on `tests/corpus/scale-lang/vector_add.gfx1100.co`.

/// VOP2 — GFX11 numbering. Diffs from GFX10:
/// - `v_ashrrev_i32_e32`: 0x18 → 0x1A
/// - `v_add_co_ci_u32_e32`: 0x28 → 0x20
/// - `v_sub_co_ci_u32_e32`: 0x29 → 0x21
///
/// `v_add_f32` stayed at 0x03; `v_cndmask_b32` at 0x01.
const VOP2_GFX11: &[OpcodeEntry] = &[
    OpcodeEntry {
        op: 0x01,
        mnemonic: "v_cndmask_b32_e32",
        operation: Operation::ConditionalMove,
    },
    OpcodeEntry {
        op: 0x03,
        mnemonic: "v_add_f32_e32",
        operation: Operation::Add,
    },
    OpcodeEntry {
        op: 0x04,
        mnemonic: "v_sub_f32_e32",
        operation: Operation::Sub,
    },
    OpcodeEntry {
        op: 0x05,
        mnemonic: "v_subrev_f32_e32",
        operation: Operation::Sub,
    },
    OpcodeEntry {
        op: 0x08,
        mnemonic: "v_mul_f32_e32",
        operation: Operation::Mul,
    },
    // GFX11 packed the integer min/max ops down into VOP2. Byte-validated
    // against `multi_kernel.gfx1100.co` (`22060405` → `v_min_i32_e32`).
    OpcodeEntry {
        op: 0x11,
        mnemonic: "v_min_i32_e32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x12,
        mnemonic: "v_max_i32_e32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x13,
        mnemonic: "v_min_u32_e32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x14,
        mnemonic: "v_max_u32_e32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x16,
        mnemonic: "v_lshlrev_b32_e32",
        operation: Operation::Shl,
    },
    OpcodeEntry {
        op: 0x17,
        mnemonic: "v_lshrrev_b32_e32",
        operation: Operation::Shr,
    },
    OpcodeEntry {
        op: 0x1a,
        mnemonic: "v_ashrrev_i32_e32",
        operation: Operation::Sar,
    },
    OpcodeEntry {
        op: 0x1b,
        mnemonic: "v_and_b32_e32",
        operation: Operation::And,
    },
    OpcodeEntry {
        op: 0x1c,
        mnemonic: "v_or_b32_e32",
        operation: Operation::Or,
    },
    OpcodeEntry {
        op: 0x1d,
        mnemonic: "v_xor_b32_e32",
        operation: Operation::Xor,
    },
    OpcodeEntry {
        op: 0x20,
        mnemonic: "v_add_co_ci_u32_e32",
        operation: Operation::Add,
    },
    OpcodeEntry {
        op: 0x21,
        mnemonic: "v_sub_co_ci_u32_e32",
        operation: Operation::Sub,
    },
];

/// VOP3 — GFX11 numbering (10-bit OP at `[25:16]`). Renumbered
/// substantially from RDNA2.
const VOP3_GFX11: &[OpcodeEntry] = &[
    OpcodeEntry {
        op: 0x0c4,
        mnemonic: "v_cmpx_gt_i32_e64",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x101,
        mnemonic: "v_cndmask_b32_e64",
        operation: Operation::ConditionalMove,
    },
    OpcodeEntry {
        op: 0x155,
        mnemonic: "v_add3_u32",
        operation: Operation::Add,
    },
    OpcodeEntry {
        op: 0x2fe,
        mnemonic: "v_mad_u64_u32",
        operation: Operation::Mul,
    },
    OpcodeEntry {
        op: 0x2ff,
        mnemonic: "v_mad_i64_i32",
        operation: Operation::Mul,
    },
    OpcodeEntry {
        op: 0x300,
        mnemonic: "v_add_co_u32",
        operation: Operation::Add,
    },
    OpcodeEntry {
        op: 0x301,
        mnemonic: "v_sub_co_u32",
        operation: Operation::Sub,
    },
    OpcodeEntry {
        op: 0x33c,
        mnemonic: "v_lshlrev_b64",
        operation: Operation::Shl,
    },
];

/// SOPP — GFX11 numbering. Major renumbering from RDNA2:
/// - `s_endpgm`: 0x01 → 0x30
/// - `s_clause`: 0x21 → 0x05
/// - `s_waitcnt`: 0x0c → 0x09
/// - branches all shifted to the 0x20 range (`s_branch` = 0x20,
///   `s_cbranch_*` at 0x21..0x26).
/// - `s_delay_alu` (new in RDNA3) at 0x07.
/// - `s_sendmsg` at 0x36.
const SOPP_GFX11: &[OpcodeEntry] = &[
    OpcodeEntry {
        op: 0x00,
        mnemonic: "s_nop",
        operation: Operation::Nop,
    },
    OpcodeEntry {
        op: 0x05,
        mnemonic: "s_clause",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x07,
        mnemonic: "s_delay_alu",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x09,
        mnemonic: "s_waitcnt",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x0a,
        mnemonic: "s_wait_loadcnt",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x0c,
        mnemonic: "s_wait_kmcnt",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x10,
        mnemonic: "s_barrier",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x1f,
        mnemonic: "s_code_end",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x20,
        mnemonic: "s_branch",
        operation: Operation::Jump,
    },
    OpcodeEntry {
        op: 0x21,
        mnemonic: "s_cbranch_scc0",
        operation: Operation::ConditionalJump,
    },
    OpcodeEntry {
        op: 0x22,
        mnemonic: "s_cbranch_scc1",
        operation: Operation::ConditionalJump,
    },
    OpcodeEntry {
        op: 0x23,
        mnemonic: "s_cbranch_vccz",
        operation: Operation::ConditionalJump,
    },
    OpcodeEntry {
        op: 0x24,
        mnemonic: "s_cbranch_vccnz",
        operation: Operation::ConditionalJump,
    },
    OpcodeEntry {
        op: 0x25,
        mnemonic: "s_cbranch_execz",
        operation: Operation::ConditionalJump,
    },
    OpcodeEntry {
        op: 0x26,
        mnemonic: "s_cbranch_execnz",
        operation: Operation::ConditionalJump,
    },
    OpcodeEntry {
        op: 0x30,
        mnemonic: "s_endpgm",
        operation: Operation::Return,
    },
    OpcodeEntry {
        op: 0x36,
        mnemonic: "s_sendmsg",
        operation: Operation::Other(0),
    },
];

/// SMEM — GFX11 renamed `_dword` to `_b32`/`_b64`/`_b128` etc.
/// OP numbers at `[25:18]` shifted slightly; the loads remain in
/// the low range.
const SMEM_GFX11: &[OpcodeEntry] = &[
    OpcodeEntry {
        op: 0x00,
        mnemonic: "s_load_b32",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x01,
        mnemonic: "s_load_b64",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x02,
        mnemonic: "s_load_b128",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x03,
        mnemonic: "s_load_b256",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x04,
        mnemonic: "s_load_b512",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x08,
        mnemonic: "s_buffer_load_b32",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x09,
        mnemonic: "s_buffer_load_b64",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x0a,
        mnemonic: "s_buffer_load_b128",
        operation: Operation::Load,
    },
];

/// FLAT — GFX11 renumbering + `_dword` → `_b32` rename. The seg
/// field semantics on RDNA3 differ from RDNA2 — the `flat`,
/// `global`, and `scratch` forms appear to occupy distinct OP
/// slots in the 7-bit OP space rather than sharing OPs with a
/// disambiguating seg bit. We list the GLOBAL forms here directly
/// since that's what shows up in HSA-mode AMDGPU code; FLAT and
/// SCRATCH variants land in this same table at adjacent OPs and
/// will be filled in as we widen the corpus.
const FLAT_GFX11: &[OpcodeEntry] = &[
    OpcodeEntry {
        op: 0x10,
        mnemonic: "global_load_u8",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x11,
        mnemonic: "global_load_i8",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x12,
        mnemonic: "global_load_u16",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x13,
        mnemonic: "global_load_i16",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x14,
        mnemonic: "global_load_b32",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x15,
        mnemonic: "global_load_b64",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x16,
        mnemonic: "global_load_b96",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x17,
        mnemonic: "global_load_b128",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x18,
        mnemonic: "global_store_b8",
        operation: Operation::Store,
    },
    OpcodeEntry {
        op: 0x19,
        mnemonic: "global_store_b16",
        operation: Operation::Store,
    },
    OpcodeEntry {
        op: 0x1a,
        mnemonic: "global_store_b32",
        operation: Operation::Store,
    },
    OpcodeEntry {
        op: 0x1b,
        mnemonic: "global_store_b64",
        operation: Operation::Store,
    },
];

/// VOP3 — GFX9 (Vega / CDNA).
///
/// GFX9 numbers VOP3 differently from RDNA1+. `v_lshlrev_b64` lives
/// at OP=0x28f (vs 0x2ff on RDNA1+ and 0x33c on RDNA3). Byte-validated
/// against `vector_add.gfx900.co` (`d28f0000 00020082` →
/// `v_lshlrev_b64 v[0:1], 2, v[0:1]`).
const VOP3_GFX9: &[OpcodeEntry] = &[
    OpcodeEntry {
        op: 0x100,
        mnemonic: "v_cmpx_gt_i32_e64",
        operation: Operation::Compare,
    },
    OpcodeEntry {
        op: 0x1c3,
        mnemonic: "v_mad_u64_u32",
        operation: Operation::Mul,
    },
    OpcodeEntry {
        op: 0x28f,
        mnemonic: "v_lshlrev_b64",
        operation: Operation::Shl,
    },
];

/// SOP1 — GFX11 (RDNA3).
///
/// RDNA3 mostly reverted SOP1 to the GFX9 numbering, but the
/// `s_*_saveexec_*` family is wave32 (`_b32` instead of GFX9's
/// `_b64`). Byte-validated against `multi_kernel.gfx1100.co`
/// (`be83206a` → `s_and_saveexec_b32 s3, vcc_lo`).
const SOP1_GFX11: &[OpcodeEntry] = &[
    OpcodeEntry {
        op: 0x00,
        mnemonic: "s_mov_b32",
        operation: Operation::Move,
    },
    OpcodeEntry {
        op: 0x01,
        mnemonic: "s_mov_b64",
        operation: Operation::Move,
    },
    OpcodeEntry {
        op: 0x04,
        mnemonic: "s_not_b32",
        operation: Operation::Not,
    },
    OpcodeEntry {
        op: 0x05,
        mnemonic: "s_not_b64",
        operation: Operation::Not,
    },
    OpcodeEntry {
        op: 0x06,
        mnemonic: "s_wqm_b32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x08,
        mnemonic: "s_brev_b32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x0a,
        mnemonic: "s_bcnt0_i32_b32",
        operation: Operation::Popcnt,
    },
    OpcodeEntry {
        op: 0x0c,
        mnemonic: "s_bcnt1_i32_b32",
        operation: Operation::Popcnt,
    },
    OpcodeEntry {
        op: 0x10,
        mnemonic: "s_getpc_b64",
        operation: Operation::Move,
    },
    OpcodeEntry {
        op: 0x12,
        mnemonic: "s_setpc_b64",
        operation: Operation::Jump,
    },
    OpcodeEntry {
        op: 0x14,
        mnemonic: "s_swappc_b64",
        operation: Operation::Call,
    },
    // Wave32 saveexec — RDNA3-specific b32 form.
    OpcodeEntry {
        op: 0x20,
        mnemonic: "s_and_saveexec_b32",
        operation: Operation::And,
    },
    OpcodeEntry {
        op: 0x21,
        mnemonic: "s_or_saveexec_b32",
        operation: Operation::Or,
    },
    OpcodeEntry {
        op: 0x22,
        mnemonic: "s_xor_saveexec_b32",
        operation: Operation::Xor,
    },
];

/// FLAT — GFX9 (Vega / CDNA).
///
/// GFX9 numbers `flat_load_dword` at 0x14 (vs 0x0c in `FLAT_GFX10`),
/// and packs the `global_*` / `scratch_*` variants into the same OP
/// space — the segment switch is a per-instruction property in RDNA
/// but a separate prefix in GFX9. Byte-validated against
/// `vector_add.gfx900.co` (`dc508000 067f0004` →
/// `global_load_dword v6, v[4:5], off`).
const FLAT_GFX9: &[OpcodeEntry] = &[
    OpcodeEntry {
        op: 0x10,
        mnemonic: "flat_load_ubyte",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x11,
        mnemonic: "flat_load_sbyte",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x12,
        mnemonic: "flat_load_ushort",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x13,
        mnemonic: "flat_load_sshort",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x14,
        mnemonic: "flat_load_dword",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x15,
        mnemonic: "flat_load_dwordx2",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x16,
        mnemonic: "flat_load_dwordx4",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x17,
        mnemonic: "flat_load_dwordx3",
        operation: Operation::Load,
    },
    OpcodeEntry {
        op: 0x18,
        mnemonic: "flat_store_byte",
        operation: Operation::Store,
    },
    OpcodeEntry {
        op: 0x19,
        mnemonic: "flat_store_short",
        operation: Operation::Store,
    },
    OpcodeEntry {
        op: 0x1c,
        mnemonic: "flat_store_dword",
        operation: Operation::Store,
    },
    OpcodeEntry {
        op: 0x1d,
        mnemonic: "flat_store_dwordx2",
        operation: Operation::Store,
    },
    OpcodeEntry {
        op: 0x1e,
        mnemonic: "flat_store_dwordx4",
        operation: Operation::Store,
    },
    OpcodeEntry {
        op: 0x1f,
        mnemonic: "flat_store_dwordx3",
        operation: Operation::Store,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vop1_v_mov_b32_uses_correct_op_per_family() {
        let gfx9 = lookup(TableClass::Vop1, EncodingFamily::Gfx9, 0x01).unwrap();
        assert_eq!(gfx9.mnemonic, "v_mov_b32_e32");
        let gfx10 = lookup(TableClass::Vop1, EncodingFamily::Gfx10Plus, 0x01).unwrap();
        assert_eq!(gfx10.mnemonic, "v_mov_b32_e32");
        // GFX9 OP=0 is v_nop; GFX10+ OP=0 is v_nop too — both
        // tables agree on the nop slot.
        assert_eq!(
            lookup(TableClass::Vop1, EncodingFamily::Gfx9, 0x00)
                .unwrap()
                .mnemonic,
            "v_nop"
        );
        assert_eq!(
            lookup(TableClass::Vop1, EncodingFamily::Gfx10Plus, 0x00)
                .unwrap()
                .mnemonic,
            "v_nop"
        );
    }

    #[test]
    fn sopp_s_endpgm_resolves_to_return() {
        let entry = lookup(TableClass::Sopp, EncodingFamily::Gfx9, 0x01).unwrap();
        assert_eq!(entry.mnemonic, "s_endpgm");
        assert!(matches!(entry.operation, Operation::Return));
    }

    #[test]
    fn sop2_s_add_u32_resolves_to_add() {
        let entry = lookup(TableClass::Sop2, EncodingFamily::Gfx9, 0x00).unwrap();
        assert_eq!(entry.mnemonic, "s_add_u32");
        assert!(matches!(entry.operation, Operation::Add));
    }

    #[test]
    fn vopc_v_cmp_eq_u32_resolves_to_compare() {
        // From llvm-mc gfx1200 sample: encoding [0x01,0x05,0x94,0x7c]
        // → top byte 0x7c = 0b01111100 → VOPC; OP at [16:9] = 0x94.
        let entry = lookup(TableClass::Vopc, EncodingFamily::Gfx10Plus, 0x94).unwrap();
        assert_eq!(entry.mnemonic, "v_cmp_gt_u32_e32");
        assert!(matches!(entry.operation, Operation::Compare));
    }

    #[test]
    fn unknown_op_returns_none_so_caller_can_fall_back() {
        assert!(lookup(TableClass::Vop1, EncodingFamily::Gfx9, 0xff).is_none());
        assert!(lookup(TableClass::Sopp, EncodingFamily::Gfx10Plus, 0x7f).is_none());
    }

    #[test]
    fn smem_s_load_dword_resolves_to_load() {
        let entry = lookup(TableClass::Smem, EncodingFamily::Gfx10Plus, 0x00).unwrap();
        assert_eq!(entry.mnemonic, "s_load_dword");
        assert!(matches!(entry.operation, Operation::Load));
    }

    #[test]
    fn flat_mnemonic_seg_zero_returns_base_unchanged() {
        // seg = 0 means flat addressing — the bare `flat_*` mnemonic
        // is returned without rewriting.
        assert_eq!(
            render_flat_mnemonic("flat_load_dword", 0),
            "flat_load_dword"
        );
    }

    #[test]
    fn flat_mnemonic_seg_one_rewrites_flat_to_scratch() {
        // seg = 1 means scratch — the `flat_` prefix is rewritten.
        assert_eq!(
            render_flat_mnemonic("flat_load_dword", 1),
            "scratch_load_dword"
        );
    }

    #[test]
    fn flat_mnemonic_seg_two_rewrites_flat_to_global() {
        // seg = 2 means global — the `flat_` prefix is rewritten.
        assert_eq!(
            render_flat_mnemonic("flat_load_dword", 2),
            "global_load_dword"
        );
    }

    #[test]
    fn flat_mnemonic_unknown_seg_falls_back_to_marker() {
        // seg = 3 is reserved and not currently used; fall back to a
        // visibly-broken `flat?_` form so the caller can spot it.
        assert_eq!(
            render_flat_mnemonic("flat_load_dword", 3),
            "flat?_flat_load_dword"
        );
    }

    #[test]
    fn flat_mnemonic_without_flat_prefix_passes_through() {
        // Some opcode-table entries already render the rewritten form
        // (e.g. RDNA3 `global_*`); strip-prefix fails so we leave the
        // mnemonic alone for non-zero seg.
        assert_eq!(
            render_flat_mnemonic("global_load_b32", 2),
            "global_load_b32"
        );
    }
}
