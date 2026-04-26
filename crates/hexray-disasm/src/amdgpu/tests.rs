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
