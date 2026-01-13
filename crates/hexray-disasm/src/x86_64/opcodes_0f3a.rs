//! VEX/EVEX 0F3A opcode table (map 3).
//!
//! This table covers instructions with escape bytes 0x0F 0x3A:
//! - SSE4.1 blend/round/extract/insert instructions
//! - PCLMULQDQ (carry-less multiplication)
//! - AVX permutation instructions
//! - AES key generation

use super::opcodes::{OpcodeEntry, OperandEncoding};
use hexray_core::Operation;

/// Opcode table for 0F 3A escape (VEX.mmmmm = 3).
/// Indexed by the opcode byte following 0F 3A.
/// These instructions take an immediate byte operand.
pub static OPCODE_TABLE_0F3A: [Option<OpcodeEntry>; 256] = {
    let mut table: [Option<OpcodeEntry>; 256] = [None; 256];

    // SSE4.1 instructions with immediate

    // 0x08: ROUNDPS
    table[0x08] = Some(OpcodeEntry::new("roundps", Operation::Other(0x3A_08), OperandEncoding::ModRmReg_Rm));

    // 0x09: ROUNDPD
    table[0x09] = Some(OpcodeEntry::new("roundpd", Operation::Other(0x3A_09), OperandEncoding::ModRmReg_Rm));

    // 0x0A: ROUNDSS
    table[0x0A] = Some(OpcodeEntry::new("roundss", Operation::Other(0x3A_0A), OperandEncoding::ModRmReg_Rm));

    // 0x0B: ROUNDSD
    table[0x0B] = Some(OpcodeEntry::new("roundsd", Operation::Other(0x3A_0B), OperandEncoding::ModRmReg_Rm));

    // 0x0C: BLENDPS
    table[0x0C] = Some(OpcodeEntry::new("blendps", Operation::Other(0x3A_0C), OperandEncoding::ModRmReg_Rm));

    // 0x0D: BLENDPD
    table[0x0D] = Some(OpcodeEntry::new("blendpd", Operation::Other(0x3A_0D), OperandEncoding::ModRmReg_Rm));

    // 0x0E: PBLENDW
    table[0x0E] = Some(OpcodeEntry::new("pblendw", Operation::Other(0x3A_0E), OperandEncoding::ModRmReg_Rm));

    // 0x0F: PALIGNR
    table[0x0F] = Some(OpcodeEntry::new("palignr", Operation::Other(0x3A_0F), OperandEncoding::ModRmReg_Rm));

    // 0x14: PEXTRB - Extract byte
    table[0x14] = Some(OpcodeEntry::new("pextrb", Operation::Other(0x3A_14), OperandEncoding::ModRmReg_Rm));

    // 0x15: PEXTRW - Extract word (SSE4.1 form)
    table[0x15] = Some(OpcodeEntry::new("pextrw", Operation::Other(0x3A_15), OperandEncoding::ModRmReg_Rm));

    // 0x16: PEXTRD/PEXTRQ - Extract dword/qword
    table[0x16] = Some(OpcodeEntry::new("pextrd", Operation::Other(0x3A_16), OperandEncoding::ModRmReg_Rm));

    // 0x17: EXTRACTPS - Extract float
    table[0x17] = Some(OpcodeEntry::new("extractps", Operation::Other(0x3A_17), OperandEncoding::ModRmReg_Rm));

    // 0x20: PINSRB - Insert byte
    table[0x20] = Some(OpcodeEntry::new("pinsrb", Operation::Other(0x3A_20), OperandEncoding::ModRmReg_Rm));

    // 0x21: INSERTPS - Insert float
    table[0x21] = Some(OpcodeEntry::new("insertps", Operation::Other(0x3A_21), OperandEncoding::ModRmReg_Rm));

    // 0x22: PINSRD/PINSRQ - Insert dword/qword
    table[0x22] = Some(OpcodeEntry::new("pinsrd", Operation::Other(0x3A_22), OperandEncoding::ModRmReg_Rm));

    // 0x40: DPPS - Dot product of packed single
    table[0x40] = Some(OpcodeEntry::new("dpps", Operation::Other(0x3A_40), OperandEncoding::ModRmReg_Rm));

    // 0x41: DPPD - Dot product of packed double
    table[0x41] = Some(OpcodeEntry::new("dppd", Operation::Other(0x3A_41), OperandEncoding::ModRmReg_Rm));

    // 0x42: MPSADBW - Multiple packed sums of absolute differences
    table[0x42] = Some(OpcodeEntry::new("mpsadbw", Operation::Other(0x3A_42), OperandEncoding::ModRmReg_Rm));

    // 0x44: PCLMULQDQ - Carry-less multiplication
    table[0x44] = Some(OpcodeEntry::new("pclmulqdq", Operation::Other(0x3A_44), OperandEncoding::ModRmReg_Rm));

    // SSE4.2 string instructions
    // 0x60: PCMPESTRM
    table[0x60] = Some(OpcodeEntry::new("pcmpestrm", Operation::Other(0x3A_60), OperandEncoding::ModRmReg_Rm));

    // 0x61: PCMPESTRI
    table[0x61] = Some(OpcodeEntry::new("pcmpestri", Operation::Other(0x3A_61), OperandEncoding::ModRmReg_Rm));

    // 0x62: PCMPISTRM
    table[0x62] = Some(OpcodeEntry::new("pcmpistrm", Operation::Other(0x3A_62), OperandEncoding::ModRmReg_Rm));

    // 0x63: PCMPISTRI
    table[0x63] = Some(OpcodeEntry::new("pcmpistri", Operation::Other(0x3A_63), OperandEncoding::ModRmReg_Rm));

    // AES key generation
    // 0xDF: AESKEYGENASSIST
    table[0xDF] = Some(OpcodeEntry::new("aeskeygenassist", Operation::Other(0x3A_DF), OperandEncoding::ModRmReg_Rm));

    // AVX2 permutation instructions
    // 0x00: VPERMQ (VEX.256.66.0F3A.W1)
    table[0x00] = Some(OpcodeEntry::new("vpermq", Operation::Other(0x3A_00), OperandEncoding::ModRmReg_Rm));

    // 0x01: VPERMPD (VEX.256.66.0F3A.W1)
    table[0x01] = Some(OpcodeEntry::new("vpermpd", Operation::Other(0x3A_01), OperandEncoding::ModRmReg_Rm));

    // 0x02: VPBLENDD
    table[0x02] = Some(OpcodeEntry::new("vpblendd", Operation::Other(0x3A_02), OperandEncoding::ModRmReg_Rm));

    // 0x04: VPERMILPS (imm8)
    table[0x04] = Some(OpcodeEntry::new("vpermilps", Operation::Other(0x3A_04), OperandEncoding::ModRmReg_Rm));

    // 0x05: VPERMILPD (imm8)
    table[0x05] = Some(OpcodeEntry::new("vpermilpd", Operation::Other(0x3A_05), OperandEncoding::ModRmReg_Rm));

    // 0x06: VPERM2F128
    table[0x06] = Some(OpcodeEntry::new("vperm2f128", Operation::Other(0x3A_06), OperandEncoding::ModRmReg_Rm));

    // 0x18: VINSERTF128
    table[0x18] = Some(OpcodeEntry::new("vinsertf128", Operation::Other(0x3A_18), OperandEncoding::ModRmReg_Rm));

    // 0x19: VEXTRACTF128
    table[0x19] = Some(OpcodeEntry::new("vextractf128", Operation::Other(0x3A_19), OperandEncoding::ModRmReg_Rm));

    // 0x38: VINSERTI128
    table[0x38] = Some(OpcodeEntry::new("vinserti128", Operation::Other(0x3A_38), OperandEncoding::ModRmReg_Rm));

    // 0x39: VEXTRACTI128
    table[0x39] = Some(OpcodeEntry::new("vextracti128", Operation::Other(0x3A_39), OperandEncoding::ModRmReg_Rm));

    // 0x46: VPERM2I128
    table[0x46] = Some(OpcodeEntry::new("vperm2i128", Operation::Other(0x3A_46), OperandEncoding::ModRmReg_Rm));

    // 0x4A: VBLENDVPS (4 operands)
    table[0x4A] = Some(OpcodeEntry::new("vblendvps", Operation::Other(0x3A_4A), OperandEncoding::ModRmReg_Rm));

    // 0x4B: VBLENDVPD (4 operands)
    table[0x4B] = Some(OpcodeEntry::new("vblendvpd", Operation::Other(0x3A_4B), OperandEncoding::ModRmReg_Rm));

    // 0x4C: VPBLENDVB (4 operands)
    table[0x4C] = Some(OpcodeEntry::new("vpblendvb", Operation::Other(0x3A_4C), OperandEncoding::ModRmReg_Rm));

    // SHA1RNDS4 xmm, xmm/m128, imm8 (0F 3A CC - legacy SSE, not VEX)
    table[0xCC] = Some(OpcodeEntry::new("sha1rnds4", Operation::Other(0x3A_CC), OperandEncoding::ModRmReg_Rm));

    // BMI2 RORX instruction
    // 0xF0: RORX (VEX.LZ.F2.0F3A.W0/W1)
    table[0xF0] = Some(OpcodeEntry::new("rorx", Operation::Other(0x3A_F0), OperandEncoding::ModRmReg_Rm));

    // Additional AVX/AVX2 instructions with immediate
    // 0x1D: VCVTPS2PH (VEX.128/256.66.0F3A.W0)
    table[0x1D] = Some(OpcodeEntry::new("cvtps2ph", Operation::Move, OperandEncoding::ModRmReg_Rm));

    // GF2P8AFFINEINVQB/GF2P8AFFINEQB (GFNI instructions - 66 prefix)
    // 0xCE: GF2P8AFFINEINVQB xmm, xmm/m128, imm8
    table[0xCE] = Some(OpcodeEntry::new("gf2p8affineinvqb", Operation::Other(0x3A_CE), OperandEncoding::ModRmReg_Rm));

    // 0xCF: GF2P8AFFINEQB xmm, xmm/m128, imm8
    table[0xCF] = Some(OpcodeEntry::new("gf2p8affineqb", Operation::Other(0x3A_CF), OperandEncoding::ModRmReg_Rm));

    table
};

/// Get mnemonic variants based on VEX.W bit for 64-bit operations.
#[allow(dead_code)]
pub fn pextr_mnemonic(w: bool) -> &'static str {
    if w { "pextrq" } else { "pextrd" }
}

/// Get mnemonic variants based on VEX.W bit for 64-bit operations.
#[allow(dead_code)]
pub fn pinsr_mnemonic(w: bool) -> &'static str {
    if w { "pinsrq" } else { "pinsrd" }
}

/// Get PCLMULQDQ mnemonic based on immediate value.
#[allow(dead_code)]
pub fn pclmulqdq_mnemonic(imm: u8) -> &'static str {
    match imm {
        0x00 => "pclmullqlqdq",
        0x01 => "pclmulhqlqdq",
        0x10 => "pclmullqhqdq",
        0x11 => "pclmulhqhqdq",
        _ => "pclmulqdq",
    }
}
