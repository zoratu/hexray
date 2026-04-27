//! End-to-end AMDGPU decoder tests.
//!
//! These exercise the variable-length walker against
//! `llvm-mc`-validated encodings. The byte sequences below were
//! captured by running `llvm-mc -triple=amdgcn-amd-amdhsa
//! --show-encoding` against gfx906 / gfx1030 source — they're the
//! same bytes the AMDGPU runtime would see.

use super::*;
use crate::Disassembler;

/// `v_mov_b32_e32 v0, v1` from `llvm-mc -mcpu=gfx906`. VOP1, OP=1
/// in GFX9 numbering — GFX10+ shifts the same mnemonic to OP=0.
const V_MOV_B32: [u8; 4] = [0x01, 0x03, 0x00, 0x7e];

/// `s_add_u32 s0, s1, s2` — SOP2 OP=0.
const S_ADD_U32: [u8; 4] = [0x01, 0x02, 0x00, 0x80];

/// `s_endpgm` — SOPP OP=1.
const S_ENDPGM: [u8; 4] = [0x00, 0x00, 0x81, 0xbf];

/// `v_add_f32_e32 v0, v1, v2` — VOP2 (gfx906).
const V_ADD_F32_GFX9: [u8; 4] = [0x01, 0x05, 0x00, 0x02];

#[test]
fn gfx906_disassembler_targets_correct_arch() {
    let d = AmdgpuDisassembler::gfx906();
    assert_eq!(d.target().canonical_name(), "gfx906");
    assert_eq!(d.encoding_family(), EncodingFamily::Gfx9);
}

#[test]
fn gfx1030_falls_into_gfx10plus_band() {
    let d = AmdgpuDisassembler::gfx1030();
    assert_eq!(d.encoding_family(), EncodingFamily::Gfx10Plus);
}

#[test]
fn vop1_v_mov_b32_decodes_end_to_end() {
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&V_MOV_B32, 0x1000).unwrap();
    assert_eq!(decoded.size, 4);
    assert_eq!(decoded.instruction.mnemonic, "v_mov_b32_e32");
    assert_eq!(decoded.instruction.address, 0x1000);
    assert_eq!(decoded.instruction.size, 4);
    assert_eq!(decoded.instruction.bytes, V_MOV_B32.to_vec());
}

#[test]
fn sop2_s_add_u32_resolves_to_real_mnemonic() {
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&S_ADD_U32, 0x1000).unwrap();
    assert_eq!(decoded.size, 4);
    assert_eq!(decoded.instruction.mnemonic, "s_add_u32");
}

#[test]
fn sopp_s_endpgm_marks_return_control_flow() {
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&S_ENDPGM, 0x1000).unwrap();
    assert_eq!(decoded.size, 4);
    assert!(matches!(
        decoded.instruction.control_flow,
        hexray_core::ControlFlow::Return
    ));
}

#[test]
fn truncated_input_returns_truncation_error() {
    let d = AmdgpuDisassembler::gfx906();
    let err = d.decode_instruction(&[0x00, 0x00], 0x1000).unwrap_err();
    matches!(err, crate::DecodeError::Truncated { .. });
}

#[test]
fn block_walker_advances_dword_at_a_time() {
    // Concatenate four 32-bit instructions; the walker should yield
    // exactly four `Ok` results.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&V_MOV_B32);
    bytes.extend_from_slice(&S_ADD_U32);
    bytes.extend_from_slice(&V_ADD_F32_GFX9);
    bytes.extend_from_slice(&S_ENDPGM);

    let d = AmdgpuDisassembler::gfx906();
    let result = d.disassemble_block(&bytes, 0x1000);
    assert_eq!(result.len(), 4);
    for (i, item) in result.iter().enumerate() {
        let instr = item.as_ref().expect("decode succeeds");
        assert_eq!(instr.address, 0x1000 + (i as u64) * 4);
    }
    let mnemonics: Vec<&str> = result
        .iter()
        .map(|r| r.as_ref().unwrap().mnemonic.as_str())
        .collect();
    assert_eq!(
        mnemonics,
        vec!["v_mov_b32_e32", "s_add_u32", "v_add_f32_e32", "s_endpgm"]
    );
}

#[test]
fn block_walker_recovers_after_unknown_byte_pattern() {
    // Build a 32-bit garbage word followed by a real v_mov_b32. The
    // walker should advance 4 bytes after the bad word (Unknown class
    // is treated as 32-bit) and successfully decode the next.
    let mut bytes = Vec::new();
    // Unknown class — bits [31:30] = 11 with no matching prefix
    // (top6 = 110010 = 0xC8 — not in either family table).
    bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0xc8]);
    bytes.extend_from_slice(&V_MOV_B32);

    let d = AmdgpuDisassembler::gfx906();
    let result = d.disassemble_block(&bytes, 0x1000);
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].as_ref().unwrap().mnemonic, "unknown");
    assert_eq!(result[1].as_ref().unwrap().mnemonic, "v_mov_b32_e32");
}

#[test]
fn block_walker_flags_trailing_fragment() {
    // 4 bytes of v_mov_b32 + 2 bytes of garbage = trailing fragment
    // should surface as a truncation error.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&V_MOV_B32);
    bytes.extend_from_slice(&[0xab, 0xcd]);

    let d = AmdgpuDisassembler::gfx906();
    let result = d.disassemble_block(&bytes, 0x1000);
    assert_eq!(result.len(), 2);
    assert!(result[0].is_ok());
    assert!(result[1].is_err());
}

#[test]
fn vop3_64bit_consumes_two_dwords() {
    // From llvm-mc gfx1200 sample (codex):
    //   v_add3_u32 v0, v1, v2, v3
    //   ; encoding: [0x00,0x00,0x55,0xd6,0x01,0x05,0x0e,0x04]
    // VOP3 prefix on GFX10+: top6 = 110101 → 0xD5.
    let bytes = [0x00, 0x00, 0x55, 0xd6, 0x01, 0x05, 0x0e, 0x04];
    let d = AmdgpuDisassembler::gfx1030();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert_eq!(decoded.size, 8);
    // Mnemonic placeholder until M10.4.
    assert!(decoded.instruction.mnemonic.starts_with("vop3"));
    assert_eq!(decoded.instruction.bytes.len(), 8);
}

#[test]
fn architecture_round_trips_through_disassembler() {
    let d = AmdgpuDisassembler::gfx1100();
    match d.architecture() {
        hexray_core::Architecture::Amdgpu(g) => {
            assert_eq!(g.canonical_name(), "gfx1100");
        }
        other => panic!("expected Amdgpu, got {other:?}"),
    }
}

#[test]
fn vop1_v_mov_b32_renders_v0_v1_operands() {
    // v_mov_b32_e32 v0, v1 ; encoding [0x01,0x03,0x00,0x7e]
    // VDST=0 (v0, written), SRC0=257 (v1, read).
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&V_MOV_B32, 0x1000).unwrap();
    let instr = &decoded.instruction;
    assert_eq!(instr.operands.len(), 2);
    let rendered = format!("{}", instr);
    assert!(
        rendered.contains("v_mov_b32_e32 v0, v1"),
        "expected 'v_mov_b32_e32 v0, v1' in {rendered:?}"
    );
}

#[test]
fn sop2_s_add_u32_renders_three_sgpr_operands() {
    // s_add_u32 s0, s1, s2 ; encoding [0x01,0x02,0x00,0x80]
    // SDST=0 (s0, written), SSRC0=1 (s1), SSRC1=2 (s2).
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&S_ADD_U32, 0x1000).unwrap();
    let instr = &decoded.instruction;
    assert_eq!(instr.operands.len(), 3);
    let rendered = format!("{}", instr);
    assert!(
        rendered.contains("s_add_u32 s0, s1, s2"),
        "expected 's_add_u32 s0, s1, s2' in {rendered:?}"
    );
}

#[test]
fn vopc_renders_two_source_operands_no_destination() {
    // v_cmp_eq_u32_e32 vcc_lo, v1, v2 ; encoding [0x01,0x05,0x94,0x7c]
    // SRC0=0x101=v1, VSRC1=2 (v2). Implicit write to vcc_lo not
    // pushed as a printed operand.
    let d = AmdgpuDisassembler::gfx1030();
    let bytes = [0x01, 0x05, 0x94, 0x7c];
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    let rendered = format!("{}", decoded.instruction);
    assert!(
        rendered.contains(" v1, v2"),
        "expected ' v1, v2' in {rendered:?}"
    );
}

#[test]
fn sopp_s_endpgm_takes_no_operands() {
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&S_ENDPGM, 0x1000).unwrap();
    assert_eq!(decoded.instruction.operands.len(), 0);
}

#[test]
fn sopp_s_branch_renders_pc_relative_target() {
    // s_branch +0x10 (in dwords). SOPP OP=0x02, SIMM16=0x10.
    // Target = address + (0x10 * 4 + 4) = 0x1000 + 0x44 = 0x1044.
    let mut bytes = [0u8; 4];
    let dword: u32 = 0xbf820000 | 0x10; // SOPP base | SIMM16=0x10
    bytes.copy_from_slice(&dword.to_le_bytes());
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert_eq!(decoded.instruction.operands.len(), 1);
    let rendered = format!("{}", decoded.instruction);
    // PC-relative formats as "+offset" via Operand display.
    assert!(rendered.contains("0x1044"), "got {rendered:?}");
}

#[test]
fn vop2_inline_constant_renders_as_immediate() {
    // v_add_f32_e32 v0, 1.0, v1 — encoded as VOP2 op=1, src0=242 (1.0),
    // vsrc1=1 (v1), vdst=0 (v0).
    // Build: op=1 (in [30:25]) | vdst=0 [24:17] | vsrc1=1 [16:9] | src0=242 [8:0]
    let dword: u32 = (1u32 << 25) | (1u32 << 9) | 242;
    let bytes = dword.to_le_bytes();
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    let rendered = format!("{}", decoded.instruction);
    // 1.0 inline constant should render via the register-name path
    // since it's not in the integer inline-constant range.
    assert!(rendered.contains("v0"), "got {rendered:?}");
    assert!(rendered.contains("v1"), "got {rendered:?}");
}

// ---------------------------------------------------------------------------
// Tests targeting cargo-mutants gaps. The blocks below exercise behaviours
// that the original tests asserted on indirectly (e.g. via "rendered text
// contains v0") but never pinned to specific mnemonics, addresses, sizes, or
// operand identities.
// ---------------------------------------------------------------------------

#[test]
fn disassembler_advertises_amdgpu_size_bounds() {
    // The Disassembler trait surfaces min / max / fixed-width bounds the
    // walker uses for safety budgets. AMDGPU is a 4/8 variable-width
    // architecture; lock those values in so they can't drift.
    let d = AmdgpuDisassembler::gfx906();
    assert_eq!(d.min_instruction_size(), 4);
    assert_eq!(d.max_instruction_size(), 8);
    assert!(!d.is_fixed_width());
}

#[test]
fn block_walker_trailing_fragment_carries_correct_address_and_size() {
    // A 4-byte v_mov_b32 followed by a 2-byte fragment: the trailing
    // truncation error must report the address of the fragment (start +
    // 4) and `available = 2` (not 4 or anything else). This pins the
    // arithmetic in `disassemble_block`'s tail handling.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&V_MOV_B32);
    bytes.extend_from_slice(&[0xab, 0xcd]);

    let d = AmdgpuDisassembler::gfx906();
    let result = d.disassemble_block(&bytes, 0x2000);
    assert_eq!(result.len(), 2);
    let err = result[1]
        .as_ref()
        .expect_err("trailing fragment is an error");
    match err {
        crate::DecodeError::Truncated {
            address,
            needed,
            available,
        } => {
            assert_eq!(*address, 0x2004, "trailing fragment address wrong");
            assert_eq!(*needed, 4);
            assert_eq!(*available, 2, "should report 2 remaining bytes");
        }
        other => panic!("expected Truncated, got {other:?}"),
    }
}

#[test]
fn block_walker_advances_after_decode_error_without_panicking() {
    // A 4-byte SMEM prefix on its own cannot decode (SMEM is a
    // 64-bit class needing 8 bytes). `disassemble_block` must
    // surface the error and step the offset by exactly 4 — a
    // mutation that turns `offset += 4` into `offset -= 4` (or
    // `*= 4`) would underflow on the first iteration and panic.
    let bytes = [0x00, 0x00, 0x00, 0xc0]; // SMEM prefix, only 4 bytes total
    let d = AmdgpuDisassembler::gfx906();
    let result = d.disassemble_block(&bytes, 0x1000);
    // We expect exactly one Err entry from the truncated-decode
    // arm. If the walker mutated to `-=` we would have panicked
    // before getting here; if it had mutated to `*=` the offset
    // would have stayed at 0 and the walker would loop forever
    // (timing out).
    assert_eq!(result.len(), 1);
    assert!(result[0].is_err());
}

#[test]
fn block_walker_advances_one_dword_after_unknown() {
    // After an Unknown-classed dword, `disassemble_block` must step
    // exactly 4 bytes (not 0, not 8) so it doesn't desync. We chain
    // two unknown dwords then a real instruction at offset 8 and
    // verify the addresses on each result.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0xc8]); // Unknown
    bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0xc8]); // Unknown
    bytes.extend_from_slice(&V_MOV_B32);

    let d = AmdgpuDisassembler::gfx906();
    let result = d.disassemble_block(&bytes, 0x3000);
    assert_eq!(result.len(), 3);
    // Two unknown classes (size = 4 each), then v_mov_b32 at +8.
    let third = result[2].as_ref().expect("third instruction decodes");
    assert_eq!(third.address, 0x3008, "walker desynced after Unknown");
    assert_eq!(third.mnemonic, "v_mov_b32_e32");
}

#[test]
fn vopc_renders_v_cmp_gt_u32_mnemonic() {
    // VOPC layout: top7 = 0b011_1110, OP at [24:17], VSRC1 at [16:9],
    // SRC0 at [8:0]. Encode v_cmp_gt_u32_e32 (OP = 0x94) v1, v2:
    //   bits[31:25] = 0b011_1110, bits[24:17] = 0x94, bits[16:9] = 2,
    //   bits[8:0] = 257 (v1).
    let dword: u32 = (0b011_1110u32 << 25) | (0x94u32 << 17) | (2u32 << 9) | 257;
    let bytes = dword.to_le_bytes();
    let d = AmdgpuDisassembler::gfx1030();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    // Pin the mnemonic so the VOPC arm in `render_mnemonic` and the
    // OP-extraction shift can't be deleted or mutated silently.
    assert_eq!(decoded.instruction.mnemonic, "v_cmp_gt_u32_e32");
    let rendered = format!("{}", decoded.instruction);
    assert!(rendered.contains(" v1, v2"), "got {rendered:?}");
}

#[test]
fn sop1_s_mov_b32_renders_real_mnemonic_and_operands() {
    // SOP1 layout (per LLVM SIInstrFormats.td):
    //   [31:23] = 1011_1110_1 (SOP1 prefix)
    //   [22:16] = SDST
    //   [15:8]  = OP
    //   [7:0]   = SSRC0
    // s_mov_b32 s0, s1: SDST=0, OP=0x00, SSRC0=1.
    //   dword = 0xBE_80_00_01.
    let bytes = [0x01, 0x00, 0x80, 0xbe];
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert_eq!(decoded.instruction.mnemonic, "s_mov_b32");
    let rendered = format!("{}", decoded.instruction);
    assert!(
        rendered.contains("s_mov_b32 s0, s1"),
        "expected 's_mov_b32 s0, s1' in {rendered:?}"
    );
    // Two operands (sdst written, ssrc0 read).
    assert_eq!(decoded.instruction.operands.len(), 2);
    assert_eq!(decoded.instruction.writes.len(), 1);
    assert_eq!(decoded.instruction.reads.len(), 1);
}

#[test]
fn smem_s_load_dword_renders_real_mnemonic() {
    // SMEM is a 64-bit instruction: GFX9 prefix at top6 = 110000.
    // Layout: OP at [25:18]. OP = 0 → s_load_dword.
    //   dword0 high byte = 1100_00xx → 0xC0..=0xC3 with OP=0 in bits
    //   [25:18] gives the OP bits zero → top byte 0xC0, byte 2 = 0.
    //   Concretely: dword0 = 0xC0_00_00_00, dword1 = anything.
    let bytes = [0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00];
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert_eq!(decoded.size, 8);
    assert!(
        decoded.instruction.mnemonic.starts_with("s_load_dword"),
        "mnemonic should start with s_load_dword (v1.3.5 appends operands to SMEM mnemonics); got {}",
        decoded.instruction.mnemonic
    );
}

#[test]
fn vop3_v_add3_u32_renders_real_mnemonic_on_gfx10() {
    // VOP3 OP at [25:16]. v_add3_u32 = 0x155 on GFX10/GFX11.
    // dword0 high 6 bits = 110101 (Vop3a/b on GFX10+) and OP = 0x155.
    //   prefix bits [31:26] = 0b110101 → top byte template
    //   1101 01xx; OP = 0x155 spans [25:16] = 0001_0101_0101.
    //   Compose: dword0 = (0b110101 << 26) | (0x155 << 16)
    //          = 0xD400_0000 | 0x0155_0000 = 0xD555_0000.
    let dword0: u32 = (0b110101u32 << 26) | (0x155u32 << 16);
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&dword0.to_le_bytes());
    let d = AmdgpuDisassembler::gfx1030();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert_eq!(decoded.size, 8);
    assert!(
        decoded.instruction.mnemonic.starts_with("v_add3_u32"),
        "mnemonic should start with v_add3_u32 (v1.3.5 appends operands to VOP3 mnemonics); got {}",
        decoded.instruction.mnemonic
    );
}

#[test]
fn flat_global_load_dword_uses_seg_field_to_pick_global_prefix() {
    // FLAT layout: OP at [24:18], seg at [16:14] (we currently read
    // bits [15:14] as a 2-bit `seg`). GFX10 FLAT prefix: top6 = 110111.
    // OP = 0x0c → flat_load_dword. seg = 2 → rewrite to global_load_dword.
    //   dword0 = (0b110111 << 26) | (0x0c << 18) | (0b10 << 14)
    //          = 0xDC00_0000 | 0x0030_0000 | 0x0000_8000
    //          = 0xDC30_8000.
    let dword0: u32 = (0b110111u32 << 26) | (0x0cu32 << 18) | (0b10u32 << 14);
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&dword0.to_le_bytes());
    let d = AmdgpuDisassembler::gfx1030();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert_eq!(decoded.size, 8);
    assert!(
        decoded
            .instruction
            .mnemonic
            .starts_with("global_load_dword"),
        "seg=2 should rewrite the flat_ prefix to global_; got {}",
        decoded.instruction.mnemonic
    );
}

#[test]
fn flat_seg_zero_keeps_flat_prefix() {
    // Same as above but seg = 0 → leave the `flat_` prefix intact.
    let dword0: u32 = (0b110111u32 << 26) | (0x0cu32 << 18); // seg = 0
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&dword0.to_le_bytes());
    let d = AmdgpuDisassembler::gfx1030();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert!(
        decoded.instruction.mnemonic.starts_with("flat_load_dword"),
        "got {}",
        decoded.instruction.mnemonic
    );
}

#[test]
fn flat_seg_one_rewrites_to_scratch() {
    // seg = 1 → rewrite to scratch_*.
    let dword0: u32 = (0b110111u32 << 26) | (0x0cu32 << 18) | (0b01u32 << 14);
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&dword0.to_le_bytes());
    let d = AmdgpuDisassembler::gfx1030();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert!(
        decoded
            .instruction
            .mnemonic
            .starts_with("scratch_load_dword"),
        "got {}",
        decoded.instruction.mnemonic
    );
}

#[test]
fn vop1_default_operation_is_move_for_unknown_op() {
    // VOP1 OP=0xff isn't in any table; the class-level default is
    // `Operation::Move`. This pins the per-class default match arm
    // for VOP1 in `derive_operation`.
    // VOP1 layout: prefix at [31:25] = 0b011_1111. OP at [16:9] = 0xff.
    let dword: u32 = (0b011_1111u32 << 25) | (0xffu32 << 9);
    let bytes = dword.to_le_bytes();
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert!(
        matches!(decoded.instruction.operation, hexray_core::Operation::Move),
        "VOP1 unknown OP should default to Move; got {:?}",
        decoded.instruction.operation
    );
    // And the placeholder mnemonic format.
    assert_eq!(decoded.instruction.mnemonic, "vop1.op0xff");
}

#[test]
fn vopc_default_operation_is_compare_for_unknown_op() {
    // VOPC OP=0xff (not in shared table) → default to Compare.
    // VOPC layout: top7 = 0b011_1110. OP at [24:17].
    let dword: u32 = (0b011_1110u32 << 25) | (0xffu32 << 17);
    let bytes = dword.to_le_bytes();
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert!(
        matches!(
            decoded.instruction.operation,
            hexray_core::Operation::Compare
        ),
        "VOPC unknown OP should default to Compare; got {:?}",
        decoded.instruction.operation
    );
}

#[test]
fn smem_default_operation_is_load_for_unknown_op() {
    // SMEM OP=0xff isn't in the shared table; class default = Load.
    // SMEM layout: top6 = 110000 on GFX9. OP at [25:18].
    let dword0: u32 = (0b110000u32 << 26) | (0xffu32 << 18);
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&dword0.to_le_bytes());
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert!(matches!(
        decoded.instruction.operation,
        hexray_core::Operation::Load
    ));
}

#[test]
fn flat_default_operation_is_load_for_unknown_op() {
    // FLAT OP=0x7f isn't in any table; class default = Load.
    let dword0: u32 = (0b110111u32 << 26) | (0x7fu32 << 18);
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&dword0.to_le_bytes());
    let d = AmdgpuDisassembler::gfx1030();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert!(matches!(
        decoded.instruction.operation,
        hexray_core::Operation::Load
    ));
    // And the placeholder mnemonic when no FLAT entry matches.
    assert!(
        decoded.instruction.mnemonic.starts_with("flat.op"),
        "unmatched FLAT op should yield placeholder; got {:?}",
        decoded.instruction.mnemonic
    );
}

#[test]
fn vop3_default_operation_is_other_for_unknown_op() {
    // VOP3 OP=0x3ff isn't in any table; class default = Other(0).
    let dword0: u32 = (0b110101u32 << 26) | (0x3ffu32 << 16);
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&dword0.to_le_bytes());
    let d = AmdgpuDisassembler::gfx1030();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert!(matches!(
        decoded.instruction.operation,
        hexray_core::Operation::Other(0)
    ));
}

#[test]
fn sop1_default_operation_is_other_for_unknown_op() {
    // SOP1 OP=0xff isn't in any table; class default = Other(0).
    // dword: top9 = 1011_11101 (SOP1), OP=0xff.
    let dword: u32 = (0b1_0111_1101u32 << 23) | (0xffu32 << 8);
    let bytes = dword.to_le_bytes();
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert!(matches!(
        decoded.instruction.operation,
        hexray_core::Operation::Other(0)
    ));
}

#[test]
fn sop2_default_operation_is_other_for_unknown_op() {
    // SOP2 OP=0x7f isn't in any table; class default = Other(0).
    // SOP2 layout: top2 = 10, top4 != 1011, OP at [29:23].
    // top2 = 10, top4 != 1011 → put bits[31:28] = 1010 (top4 = 0xA).
    //   dword[31:30] = 10, dword[29:23] = 0x7f (OP).
    //   bits[31:23] = 1_0111_1111 = 0x17F.
    //   But that pattern is 0b10_1111111 → SOPP, not SOP2! So pick a
    //   different OP for SOP2 default.
    // SOP2 fallthrough: not VOP, not SOP1/C/P, not SOPK. Use OP that
    // doesn't exist — the SOP2 table tops out around 0x26. Use 0x5e.
    // top9 = 10_1011110 → top4 = 1010, top2 = 10 → SOP2 fallthrough.
    let dword: u32 = 0b1_0101_1110u32 << 23;
    let bytes = dword.to_le_bytes();
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    // OP = 0b10_1011110 >> 0 ... wait, OP at [29:23] is the low 7
    // bits of top9 = 0b0101_1110 = 0x5E. Not in the table → default.
    assert!(matches!(
        decoded.instruction.operation,
        hexray_core::Operation::Other(0)
    ));
    // And the mnemonic should be the placeholder (sop2.opNN).
    assert_eq!(decoded.instruction.mnemonic, "sop2.op0x5e");
}

#[test]
fn sopp_default_operation_is_other_for_unknown_op() {
    // SOPP OP=0x7f isn't in any table; class default = Other(0).
    // top9 = 0b1_0111_1111. OP at [22:16]. The remaining bits =
    // dword[22:16] = OP = 0x7f → bits[31:16] = 0xBFFF.
    // Construct: top byte = 0xBF, byte 2 = 0xFF.
    let bytes = [0x00, 0x00, 0xff, 0xbf];
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert!(matches!(
        decoded.instruction.operation,
        hexray_core::Operation::Other(0)
    ));
}

#[test]
fn sopp_branch_target_uses_simm16_times_four_plus_four() {
    // s_branch +0x1 → target = address + (1 * 4 + 4) = address + 8.
    // SOPP OP=0x02 (s_branch on GFX9), SIMM16=0x0001.
    // Construct dword: top9 = 1_01111111 = 0x17F (SOPP), OP=0x02 in
    // [22:16], SIMM16=1 in [15:0].
    // bits[31:23] = 0x17F → top byte 0xBF, bit 23 = 1.
    // bits[22:16] = OP = 0x02 → byte 2 low 7 bits.
    // byte 2 = (1 << 7) | 0x02 = 0x82, byte 1 = 0x00, byte 0 = 0x01.
    let bytes = [0x01, 0x00, 0x82, 0xbf];
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x4000).unwrap();
    assert_eq!(decoded.instruction.mnemonic, "s_branch");
    assert_eq!(decoded.instruction.operands.len(), 1);
    let rendered = format!("{}", decoded.instruction);
    // Target address = 0x4000 + (1 * 4 + 4) = 0x4008. The PC-relative
    // operand renders the absolute target.
    assert!(rendered.contains("0x4008"), "got {rendered:?}");
}

#[test]
fn sopp_negative_branch_target_handles_signed_simm16() {
    // s_branch -1 (SIMM16 = 0xFFFF as i16 = -1).
    // target = address + (-1 * 4 + 4) = address.
    let bytes = [0xff, 0xff, 0x82, 0xbf];
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x4000).unwrap();
    let rendered = format!("{}", decoded.instruction);
    assert!(rendered.contains("0x4000"), "got {rendered:?}");
}

#[test]
fn sopp_non_branch_op_takes_no_operand() {
    // s_endpgm (SOPP OP=0x01) should not push a PC-relative operand.
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&S_ENDPGM, 0x1000).unwrap();
    assert_eq!(decoded.instruction.mnemonic, "s_endpgm");
    assert_eq!(decoded.instruction.operands.len(), 0);
}

#[test]
fn vop1_inline_constant_negative_renders_as_signed_immediate() {
    // SRC0 = 200 → inline constant -8 (signed range 193..=208 maps to
    // -1..-16). Build a v_mov_b32_e32 with src0=200.
    // VOP1: top7 = 0b011_1111. OP=1 (v_mov_b32). VDST=0. SRC0=200.
    let dword: u32 = (0b011_1111u32 << 25) | (1u32 << 9) | 200;
    let bytes = dword.to_le_bytes();
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    let imm = decoded
        .instruction
        .operands
        .iter()
        .find_map(|op| match op {
            hexray_core::Operand::Immediate(imm) => Some(imm.value),
            _ => None,
        })
        .expect("inline constant should render as an immediate");
    assert_eq!(imm, -8, "200 should decode to inline constant -8");
}

#[test]
fn vop1_inline_constant_zero_renders_as_signed_immediate() {
    // SRC0 = 128 → inline constant 0.
    let dword: u32 = (0b011_1111u32 << 25) | (1u32 << 9) | 128;
    let bytes = dword.to_le_bytes();
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    let imm = decoded
        .instruction
        .operands
        .iter()
        .find_map(|op| match op {
            hexray_core::Operand::Immediate(imm) => Some(imm.value),
            _ => None,
        })
        .expect("inline constant should render as an immediate");
    assert_eq!(imm, 0);
}

#[test]
fn vop1_inline_constant_positive_max_renders_as_signed_immediate() {
    // SRC0 = 192 → inline constant 64.
    let dword: u32 = (0b011_1111u32 << 25) | (1u32 << 9) | 192;
    let bytes = dword.to_le_bytes();
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    let imm = decoded
        .instruction
        .operands
        .iter()
        .find_map(|op| match op {
            hexray_core::Operand::Immediate(imm) => Some(imm.value),
            _ => None,
        })
        .expect("inline constant should render as an immediate");
    assert_eq!(imm, 64);
}

#[test]
fn vop1_non_inline_src0_renders_as_register() {
    // SRC0 = 256 (v0): a real VGPR, not an inline constant. Confirms
    // `inline_constant_value` returns None for IDs outside 128..=208.
    let dword: u32 = (0b011_1111u32 << 25) | (1u32 << 9) | 256;
    let bytes = dword.to_le_bytes();
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    let has_imm = decoded
        .instruction
        .operands
        .iter()
        .any(|op| matches!(op, hexray_core::Operand::Immediate(_)));
    assert!(!has_imm, "v0 should render as a register, not an immediate");
    let rendered = format!("{}", decoded.instruction);
    assert!(rendered.contains("v0"), "got {rendered:?}");
}

#[test]
fn vop2_extracts_operand_fields_from_correct_bit_positions() {
    // v_add_f32_e32 v1, v2, v3: VOP2 OP=1, VDST=1, VSRC1=3, SRC0=258 (v2).
    //   layout: [30:25] OP | [24:17] VDST | [16:9] VSRC1 | [8:0] SRC0
    let dword: u32 = (1u32 << 25) | (1u32 << 17) | (3u32 << 9) | 258;
    let bytes = dword.to_le_bytes();
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    let rendered = format!("{}", decoded.instruction);
    // Three operands: vdst (write), src0, vsrc1 (reads).
    assert_eq!(decoded.instruction.operands.len(), 3);
    assert!(
        rendered.contains("v_add_f32_e32 v1, v2, v3"),
        "got {rendered:?}"
    );
}

#[test]
fn vop1_v_nop_resolves_to_nop_operation() {
    // VOP1 OP=0x00 → v_nop with Operation::Nop. Picking Nop here
    // (rather than Move, which is also the class-level default for
    // VOP1) means a `delete match arm EncodingClass::Vop1` mutation
    // in `derive_operation` would fall back to Move and visibly
    // differ from the expected Nop.
    let dword: u32 = 0b011_1111u32 << 25;
    let bytes = dword.to_le_bytes();
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert_eq!(decoded.instruction.mnemonic, "v_nop");
    assert!(
        matches!(decoded.instruction.operation, hexray_core::Operation::Nop),
        "expected Nop, got {:?}",
        decoded.instruction.operation
    );
}

#[test]
fn vop1_v_mov_resolves_to_move_operation() {
    // OP-table entry for v_mov_b32 carries Operation::Move; the
    // table-lookup path in `derive_operation` must surface it.
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&V_MOV_B32, 0x1000).unwrap();
    assert!(matches!(
        decoded.instruction.operation,
        hexray_core::Operation::Move
    ));
}

#[test]
fn vop2_v_add_f32_resolves_to_add_operation() {
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&V_ADD_F32_GFX9, 0x1000).unwrap();
    assert!(matches!(
        decoded.instruction.operation,
        hexray_core::Operation::Add
    ));
}

#[test]
fn vopc_v_cmp_resolves_to_compare_operation() {
    // Same VOPC encoding as the rendered-mnemonic test; pin the
    // resulting `Operation` to ensure the OP is fed through the
    // table lookup, not just rendered.
    let dword: u32 = (0b011_1110u32 << 25) | (0x94u32 << 17) | (2u32 << 9) | 257;
    let bytes = dword.to_le_bytes();
    let d = AmdgpuDisassembler::gfx1030();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert!(matches!(
        decoded.instruction.operation,
        hexray_core::Operation::Compare
    ));
}

#[test]
fn sop1_s_mov_resolves_to_move_operation() {
    // s_mov_b32 entry: Operation::Move.
    let bytes = [0x01, 0x00, 0x80, 0xbe];
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert!(matches!(
        decoded.instruction.operation,
        hexray_core::Operation::Move
    ));
}

#[test]
fn sop2_s_add_resolves_to_add_operation() {
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&S_ADD_U32, 0x1000).unwrap();
    assert!(matches!(
        decoded.instruction.operation,
        hexray_core::Operation::Add
    ));
}

#[test]
fn sopp_s_endpgm_resolves_to_return_operation() {
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&S_ENDPGM, 0x1000).unwrap();
    assert!(matches!(
        decoded.instruction.operation,
        hexray_core::Operation::Return
    ));
}

#[test]
fn smem_s_load_dword_resolves_to_load_operation() {
    // SMEM OP=0x00 → s_load_dword → Operation::Load (table entry).
    let bytes = [0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00];
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert!(matches!(
        decoded.instruction.operation,
        hexray_core::Operation::Load
    ));
}

#[test]
fn smem_s_buffer_load_dword_uses_op_8_mnemonic() {
    // SMEM OP=0x08 → s_buffer_load_dword. A non-zero OP catches
    // shift mutations that would zero out the OP field. Layout:
    // top6=110000 on GFX9, OP at [25:18].
    //   dword0 = (0b110000 << 26) | (0x08 << 18) = 0xC0_00_00_00 | 0x20_00_00 = 0xC0_20_00_00.
    let dword0: u32 = (0b110000u32 << 26) | (0x08u32 << 18);
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&dword0.to_le_bytes());
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert!(
        decoded
            .instruction
            .mnemonic
            .starts_with("s_buffer_load_dword"),
        "got {}",
        decoded.instruction.mnemonic
    );
}

#[test]
fn flat_global_store_dword_uses_op_0x1c_mnemonic() {
    // FLAT OP=0x1c → flat_store_dword → Operation::Store. Use a
    // non-zero OP to catch shift mutations.
    let dword0: u32 = (0b110111u32 << 26) | (0x1cu32 << 18);
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&dword0.to_le_bytes());
    let d = AmdgpuDisassembler::gfx1030();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert!(
        decoded.instruction.mnemonic.starts_with("flat_store_dword"),
        "got {}",
        decoded.instruction.mnemonic
    );
    assert!(matches!(
        decoded.instruction.operation,
        hexray_core::Operation::Store
    ));
}

#[test]
fn vop1_v_readfirstlane_uses_op_2_mnemonic() {
    // VOP1 OP=0x02 → v_readfirstlane_b32 → Operation::Move. Use a
    // non-zero OP to catch `<<` mutations on the OP shift in
    // both render_mnemonic and derive_operation.
    let dword: u32 = (0b011_1111u32 << 25) | (0x02u32 << 9);
    let bytes = dword.to_le_bytes();
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert_eq!(decoded.instruction.mnemonic, "v_readfirstlane_b32");
}

#[test]
fn vop2_v_mul_f32_uses_op_5_mnemonic_on_gfx9() {
    // VOP2 OP=0x05 (v_mul_f32 on GFX9) → Operation::Mul. Catches
    // shift mutations on the [30:25] OP extraction.
    let dword: u32 = 0x05u32 << 25;
    let bytes = dword.to_le_bytes();
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert_eq!(decoded.instruction.mnemonic, "v_mul_f32_e32");
    assert!(matches!(
        decoded.instruction.operation,
        hexray_core::Operation::Mul
    ));
}

#[test]
fn vop3_v_add3_resolves_to_add_operation() {
    let dword0: u32 = (0b110101u32 << 26) | (0x155u32 << 16);
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&dword0.to_le_bytes());
    let d = AmdgpuDisassembler::gfx1030();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert!(matches!(
        decoded.instruction.operation,
        hexray_core::Operation::Add
    ));
}

#[test]
fn flat_load_dword_resolves_to_load_operation() {
    // FLAT OP=0x0c → flat_load_dword → Operation::Load.
    let dword0: u32 = (0b110111u32 << 26) | (0x0cu32 << 18);
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&dword0.to_le_bytes());
    let d = AmdgpuDisassembler::gfx1030();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert!(matches!(
        decoded.instruction.operation,
        hexray_core::Operation::Load
    ));
}

#[test]
fn populate_operands_pushes_correct_register_ids_for_sop1() {
    // s_not_b32 s5, s3: OP=0x04, SDST=5, SSRC0=3. Confirm that the
    // SOP1 arm in `populate_operands` extracts SDST from [22:16]
    // and SSRC0 from [7:0]. Use non-zero values so a `<<` mutation
    // on the SDST shift would visibly produce a different id.
    //   dword = (0x17D << 23) | (5 << 16) | (0x04 << 8) | 3
    //         = 0xBE800000 | 0x00050000 | 0x00000400 | 0x00000003
    //         = 0xBE850403.
    let dword: u32 = (0b1_0111_1101u32 << 23) | (5u32 << 16) | (0x04u32 << 8) | 3;
    let bytes = dword.to_le_bytes();
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    let writes = &decoded.instruction.writes;
    let reads = &decoded.instruction.reads;
    assert_eq!(writes.len(), 1, "expected 1 write");
    assert_eq!(reads.len(), 1, "expected 1 read");
    // SDST = 5 → s5.
    assert_eq!(writes[0].id, 5, "SDST should be id 5 (s5)");
    // SSRC0 = 3 → s3.
    assert_eq!(reads[0].id, 3, "SSRC0 should be id 3 (s3)");
}

#[test]
fn populate_operands_pushes_correct_register_ids_for_sop2() {
    // s_add_u32 s7, s11, s17: OP=0x00, SDST=7, SSRC1=17, SSRC0=11.
    // Use non-zero values in every field so a `<<` mutation on
    // SDST or SSRC1's shift would visibly change the id.
    //   SOP2 layout: [29:23] OP | [22:16] SDST | [15:8] SSRC1 | [7:0] SSRC0
    //   top9 = 1_0_0000000 → bit[31:30]=10, bit[29:23]=OP=0.
    //   dword = (0x100 << 23) | (7 << 16) | (17 << 8) | 11
    //         = 0x80000000 | 0x00070000 | 0x00001100 | 0x0000000B
    //         = 0x8007_110B.
    let dword: u32 = (0x100u32 << 23) | (7u32 << 16) | (17u32 << 8) | 11;
    let bytes = dword.to_le_bytes();
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert_eq!(decoded.instruction.mnemonic, "s_add_u32");
    let writes = &decoded.instruction.writes;
    let reads = &decoded.instruction.reads;
    assert_eq!(writes.len(), 1);
    assert_eq!(reads.len(), 2);
    assert_eq!(writes[0].id, 7, "SDST = s7");
    assert_eq!(reads[0].id, 11, "SSRC0 = s11");
    assert_eq!(reads[1].id, 17, "SSRC1 = s17");
}

#[test]
fn populate_operands_pushes_vdst_with_offset_256_for_vop1() {
    // VDST = 5 in a v_mov_b32 — must be stored as Register id (5 +
    // 256) so the unified amdgpu_reg_name table works.
    let dword: u32 = (0b011_1111u32 << 25) | (1u32 << 9) | (5u32 << 17) | 257;
    let bytes = dword.to_le_bytes();
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert_eq!(decoded.instruction.writes.len(), 1);
    assert_eq!(
        decoded.instruction.writes[0].id,
        256 + 5,
        "VDST = 5 should map to id 261 (v5 with the +256 offset)"
    );
}

#[test]
fn sop2_s_mul_i32_resolves_to_mul_operation() {
    // SOP2 `s_mul_i32` → Operation::Mul. The OP differs by family:
    // GFX9 places it at 0x24, RDNA1+ at 0x26. v1.3.5 split SOP2_GFX9
    // out from the shared table; gfx906 uses the GFX9 numbering.
    // Use a non-zero OP so a `<<` mutation on the OP-extraction
    // shift would change the lookup result.
    // SOP2 layout: top9 = bits [31:23], OP at [29:23]. For gfx906 +
    // OP=0x24: top9 = 1_0_0010_0100 = 0x124.
    let dword: u32 = 0x124u32 << 23;
    let bytes = dword.to_le_bytes();
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert!(
        decoded.instruction.mnemonic.starts_with("s_mul_i32"),
        "got {}",
        decoded.instruction.mnemonic
    );
    assert!(matches!(
        decoded.instruction.operation,
        hexray_core::Operation::Mul
    ));
}

#[test]
fn sop1_s_not_b32_resolves_to_not_operation() {
    // SOP1 OP=0x04 (s_not_b32) on GFX9. Use a non-zero OP so
    // `<<` mutations on the OP-extraction shift would change the
    // lookup result.
    // SOP1 layout: top9 = 1011_11101, OP at [15:8] = 0x04.
    //   bits[31:23] = 0x17D, OP = 0x04 in bits [15:8].
    let dword: u32 = (0b1_0111_1101u32 << 23) | (0x04u32 << 8);
    let bytes = dword.to_le_bytes();
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert_eq!(decoded.instruction.mnemonic, "s_not_b32");
    assert!(matches!(
        decoded.instruction.operation,
        hexray_core::Operation::Not
    ));
}

#[test]
fn sopp_s_branch_resolves_to_jump_operation() {
    // SOPP OP=0x02 (s_branch) → Operation::Jump. Use this to
    // exercise the OP=0x02 lookup against `<<` and `&`-mask
    // mutations on the OP-extraction shift.
    let bytes = [0x00, 0x00, 0x82, 0xbf];
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert_eq!(decoded.instruction.mnemonic, "s_branch");
    assert!(matches!(
        decoded.instruction.operation,
        hexray_core::Operation::Jump
    ));
    // And the control_flow gate: branches are not Return, but
    // populate_operands marks them as branches (PcRelative pushed).
    assert_eq!(decoded.instruction.operands.len(), 1);
}

#[test]
fn sopp_branch_offset_pinpoints_simm_quadrupling() {
    // Catch the `* 4` mutations on lines 441 and 438 by computing
    // the absolute target and verifying it's exactly +offset*4 + 4
    // beyond the instruction address.
    let bytes = [0x04, 0x00, 0x82, 0xbf]; // s_branch +4 (in dwords)
    let d = AmdgpuDisassembler::gfx906();
    let decoded = d.decode_instruction(&bytes, 0x5000).unwrap();
    assert_eq!(decoded.instruction.operands.len(), 1);
    match &decoded.instruction.operands[0] {
        hexray_core::Operand::PcRelative { offset, target } => {
            // offset stored as bytes (simm * 4).
            assert_eq!(*offset, 16, "simm=4 should yield byte-offset 16");
            // target = address + simm * 4 + 4 = 0x5000 + 16 + 4 = 0x5014.
            assert_eq!(*target, 0x5014);
        }
        other => panic!("expected PcRelative, got {other:?}"),
    }
}

// ---- v1.3.6 — VOP3 ABS modifier, MUBUF / DS rendering, RDNA3 SOP2 ----

#[test]
fn vop3_abs_bit_wraps_src_in_pipes() {
    // Construct a synthetic VOP3 with `v_lshlrev_b64` mnemonic and
    // ABS[0] set on src0. v_lshlrev_b64 isn't naturally an ABS-using
    // op (it's integer), but the renderer just trusts the ABS bit —
    // this lets us prove the bit-extraction + `|...|` framing without
    // needing a fixture that uses a real-FP op.
    //
    // VOP3 layout for gfx1030: prefix top6 = 110101.
    //   dword0 = (0b110101 << 26) | (op << 16) | (abs[2:0] << 8) | vdst
    //   For v_lshlrev_b64 op=0x2ff, abs[0]=1 (src0), vdst=0:
    //   dword0 = 0xD400_0000 | 0x02FF_0000 | 0x0000_0100 = 0xD6FF_0100
    let dword0: u32 = (0b110101u32 << 26) | (0x2ffu32 << 16) | (1u32 << 8);
    // dword1: src0=2 (inline 2), src1=v0+1 = 257, no NEG.
    //   src0 in [8:0] = 2, src1 in [17:9] = 257.
    let dword1: u32 = 130 | (257u32 << 9); // src0 = inline constant 2 (id=128+2)
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&dword0.to_le_bytes());
    bytes[4..].copy_from_slice(&dword1.to_le_bytes());
    let d = AmdgpuDisassembler::gfx1030();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert!(
        decoded.instruction.mnemonic.contains("|2|"),
        "ABS[0]=1 on inline-2 should render as |2|; got {}",
        decoded.instruction.mnemonic
    );
}

#[test]
fn vop3_abs_and_neg_combine_as_minus_pipes() {
    // ABS[0]=1 + NEG[0]=1 → llvm-objdump renders `-|src|`.
    let dword0: u32 = (0b110101u32 << 26) | (0x2ffu32 << 16) | (1u32 << 8);
    let dword1: u32 = 130 | (257u32 << 9) | (1u32 << 29); // src0=inline-2, NEG[0]=1
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&dword0.to_le_bytes());
    bytes[4..].copy_from_slice(&dword1.to_le_bytes());
    let d = AmdgpuDisassembler::gfx1030();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert!(
        decoded.instruction.mnemonic.contains("-|2|"),
        "NEG+ABS should render as -|src|; got {}",
        decoded.instruction.mnemonic
    );
}

#[test]
fn vop3b_does_not_apply_abs_to_sdst_bits() {
    // VOP3B uses dword0[14:8] as SDST, so a stray "ABS-ish" bit in
    // that range must NOT be interpreted as an ABS modifier on src0.
    // v_add_co_u32 is a VOP3B form. Set bits [10:8] = 0b111 (looks
    // like ABS for all 3 srcs in VOP3A) but in VOP3B those are SDST
    // bits 2:0 = 7 → SDST=s7.
    //   dword0 = (0b110101 << 26) | (0x30f << 16) | (0x07 << 8) | vdst
    let dword0: u32 = (0b110101u32 << 26) | (0x30fu32 << 16) | (0x07u32 << 8);
    let dword1: u32 = 130 | (257u32 << 9); // src0 = inline constant 2 (id=128+2)
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&dword0.to_le_bytes());
    bytes[4..].copy_from_slice(&dword1.to_le_bytes());
    let d = AmdgpuDisassembler::gfx1030();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert!(
        !decoded.instruction.mnemonic.contains("|"),
        "VOP3B SDST bits must not be misread as ABS modifiers; got {}",
        decoded.instruction.mnemonic
    );
}

#[test]
fn sop2_gfx11_routes_to_gfx11_table() {
    // RDNA3 placed `s_mul_i32` at SOP2 OP=0x2c (was 0x26 on GFX10
    // and 0x24 on GFX9). Hitting OP=0x2c on a Gfx11Plus disassembler
    // should resolve to s_mul_i32; the same OP on gfx1030 (Gfx10Plus)
    // doesn't.
    // SOP2 layout: top9 = bits[31:23], OP at bits[29:23]. For OP=0x2c:
    //   top9 = 1_0_010_1100 = 0x12c.
    let dword: u32 = 0x12cu32 << 23;
    let bytes = dword.to_le_bytes();

    let d11 = AmdgpuDisassembler::gfx1100();
    let decoded11 = d11.decode_instruction(&bytes, 0x1000).unwrap();
    assert!(
        decoded11.instruction.mnemonic.starts_with("s_mul_i32"),
        "GFX11 SOP2 op=0x2c should resolve to s_mul_i32; got {}",
        decoded11.instruction.mnemonic
    );

    let d10 = AmdgpuDisassembler::gfx1030();
    let decoded10 = d10.decode_instruction(&bytes, 0x1000).unwrap();
    assert!(
        !decoded10.instruction.mnemonic.starts_with("s_mul_i32"),
        "GFX10 SOP2 op=0x2c should NOT resolve to s_mul_i32 (lives at 0x26 there); got {}",
        decoded10.instruction.mnemonic
    );
}

#[test]
fn sop2_gfx11_min_i32_at_op_0x12() {
    // RDNA3 `s_min_i32` moved from OP=0x06 to OP=0x12.
    let dword: u32 = 0x112u32 << 23;
    let bytes = dword.to_le_bytes();
    let d11 = AmdgpuDisassembler::gfx1100();
    let decoded = d11.decode_instruction(&bytes, 0x1000).unwrap();
    assert!(
        decoded.instruction.mnemonic.starts_with("s_min_i32"),
        "got {}",
        decoded.instruction.mnemonic
    );
}

#[test]
fn mubuf_buffer_load_dword_renders_resource_descriptor_pair() {
    // MUBUF prefix top6 = 111000. Pick `buffer_load_dword`:
    //   dword0 = (0b111000 << 26) | (op << 18) | offset
    //   We don't have an opcode-table entry yet for MUBUF mnemonics
    //   so the rendered mnemonic falls back to `mubuf.op0xNN`. The
    //   point of this test is that `populate_mubuf_operands` still
    //   wires the operand fields. Use OP=0 (any), OFFSET=0x40,
    //   GLC=1, OFFEN=1.
    let op = 0u32;
    let offset = 0x40u32;
    let dword0: u32 = (0b111000u32 << 26) | (op << 18) | offset | (1 << 12) | (1 << 14);
    // dword1: VADDR=v3 (id 3), VDATA=v5 (id 5), SRSRC quad=0 → s[0:3],
    // SOFFSET = s2.
    let dword1: u32 = 3 | (5u32 << 8) | (2u32 << 24); // SRSRC quad=0 stays implicit
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&dword0.to_le_bytes());
    bytes[4..].copy_from_slice(&dword1.to_le_bytes());
    let d = AmdgpuDisassembler::gfx1030();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert!(
        decoded.instruction.mnemonic.contains("s[0:3]"),
        "MUBUF SRSRC should render as `s[0:3]` (4-SGPR resource descriptor); got {}",
        decoded.instruction.mnemonic
    );
    assert!(
        decoded.instruction.mnemonic.contains("offset:64"),
        "MUBUF should render `offset:64` for OFFSET=0x40; got {}",
        decoded.instruction.mnemonic
    );
    assert!(
        decoded.instruction.mnemonic.contains("offen"),
        "MUBUF should render the `offen` flag; got {}",
        decoded.instruction.mnemonic
    );
    assert!(
        decoded.instruction.mnemonic.contains("glc"),
        "MUBUF should render the `glc` flag; got {}",
        decoded.instruction.mnemonic
    );
}

#[test]
fn ds_op_renders_addr_and_offset0() {
    // DS prefix top6 = 110110. With OFFSET0=0x10, OFFSET1=0,
    // ADDR=v7. The DS opcode table is not populated yet, so the
    // mnemonic will be `ds.op0xNN` — the test verifies that
    // populate_ds_operands renders the address and offset0 fields
    // regardless of mnemonic resolution.
    let op = 0u32;
    let offset0 = 0x10u32;
    let dword0: u32 = (0b110110u32 << 26) | (op << 18) | offset0;
    // dword1: ADDR=v7 (id 7), DATA0=v0, DATA1=v0, VDST=v0.
    let dword1: u32 = 7;
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&dword0.to_le_bytes());
    bytes[4..].copy_from_slice(&dword1.to_le_bytes());
    let d = AmdgpuDisassembler::gfx1030();
    let decoded = d.decode_instruction(&bytes, 0x1000).unwrap();
    assert!(
        decoded.instruction.mnemonic.contains("v7"),
        "DS should render the ADDR vgpr; got {}",
        decoded.instruction.mnemonic
    );
    assert!(
        decoded.instruction.mnemonic.contains("offset0:16"),
        "DS should render `offset0:16` for OFFSET0=0x10; got {}",
        decoded.instruction.mnemonic
    );
}
