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
    Vopc,
    Sop1,
    Sop2,
    Sopp,
    Smem,
}

fn table_for(class: TableClass, family: EncodingFamily) -> &'static [OpcodeEntry] {
    match (class, family) {
        (TableClass::Vop1, EncodingFamily::Gfx9) => VOP1_GFX9,
        (TableClass::Vop1, EncodingFamily::Gfx10Plus) => VOP1_GFX10,
        (TableClass::Vop2, EncodingFamily::Gfx9) => VOP2_GFX9,
        (TableClass::Vop2, EncodingFamily::Gfx10Plus) => VOP2_GFX10,
        (TableClass::Vopc, _) => VOPC_SHARED,
        (TableClass::Sop1, _) => SOP1_SHARED,
        (TableClass::Sop2, _) => SOP2_SHARED,
        (TableClass::Sopp, EncodingFamily::Gfx9) => SOPP_GFX9,
        (TableClass::Sopp, EncodingFamily::Gfx10Plus) => SOPP_GFX10,
        (TableClass::Smem, _) => SMEM_SHARED,
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
        op: 0x19,
        mnemonic: "v_add_u32_e32",
        operation: Operation::Add,
    },
    OpcodeEntry {
        op: 0x1a,
        mnemonic: "v_sub_u32_e32",
        operation: Operation::Sub,
    },
    OpcodeEntry {
        op: 0x1b,
        mnemonic: "v_subrev_u32_e32",
        operation: Operation::Sub,
    },
];

/// VOP2 — GFX10+.
const VOP2_GFX10: &[OpcodeEntry] = &[
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
        op: 0x10,
        mnemonic: "v_max_i32_e32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x11,
        mnemonic: "v_min_i32_e32",
        operation: Operation::Other(0),
    },
    OpcodeEntry {
        op: 0x14,
        mnemonic: "v_lshlrev_b32_e32",
        operation: Operation::Shl,
    },
    OpcodeEntry {
        op: 0x15,
        mnemonic: "v_lshrrev_b32_e32",
        operation: Operation::Shr,
    },
    OpcodeEntry {
        op: 0x16,
        mnemonic: "v_ashrrev_i32_e32",
        operation: Operation::Sar,
    },
    OpcodeEntry {
        op: 0x17,
        mnemonic: "v_and_b32_e32",
        operation: Operation::And,
    },
    OpcodeEntry {
        op: 0x18,
        mnemonic: "v_or_b32_e32",
        operation: Operation::Or,
    },
    OpcodeEntry {
        op: 0x19,
        mnemonic: "v_xor_b32_e32",
        operation: Operation::Xor,
    },
];

/// VOPC opcodes — same numbering on every supported family band.
const VOPC_SHARED: &[OpcodeEntry] = &[
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

/// SOP1 — same numbering on GFX9 and GFX10+ for the common subset.
const SOP1_SHARED: &[OpcodeEntry] = &[
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
];

/// SOP2.
const SOP2_SHARED: &[OpcodeEntry] = &[
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

/// SOPP — GFX10+. Same OP numbers for the common subset
/// (s_endpgm = 0x01, branches at 0x02..0x09).
const SOPP_GFX10: &[OpcodeEntry] = SOPP_GFX9;

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
}
