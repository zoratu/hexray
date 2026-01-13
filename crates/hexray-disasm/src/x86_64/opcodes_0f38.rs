//! VEX/EVEX 0F38 opcode table (map 2).
//!
//! This table covers instructions with escape bytes 0x0F 0x38:
//! - FMA3 instructions (vfmadd*, vfmsub*, vfnmadd*, vfnmsub*)
//! - AVX2 advanced operations (vperm*, vgather*)
//! - BMI1/BMI2 instructions
//! - AES-NI instructions

use super::opcodes::{OpcodeEntry, OperandEncoding};
use hexray_core::Operation;

/// Opcode table for 0F 38 escape (VEX.mmmmm = 2).
/// Indexed by the opcode byte following 0F 38.
pub static OPCODE_TABLE_0F38: [Option<OpcodeEntry>; 256] = {
    let mut table: [Option<OpcodeEntry>; 256] = [const { None }; 256];

    // SSSE3/SSE4 style instructions (also VEX-encoded)

    // 0x00: PSHUFB
    table[0x00] = Some(OpcodeEntry::new("pshufb", Operation::Other(0x38_00), OperandEncoding::ModRmReg_Rm));

    // 0x01: PHADDW
    table[0x01] = Some(OpcodeEntry::new("phaddw", Operation::Other(0x38_01), OperandEncoding::ModRmReg_Rm));

    // 0x02: PHADDD
    table[0x02] = Some(OpcodeEntry::new("phaddd", Operation::Other(0x38_02), OperandEncoding::ModRmReg_Rm));

    // 0x03: PHADDSW
    table[0x03] = Some(OpcodeEntry::new("phaddsw", Operation::Other(0x38_03), OperandEncoding::ModRmReg_Rm));

    // 0x04: PMADDUBSW
    table[0x04] = Some(OpcodeEntry::new("pmaddubsw", Operation::Other(0x38_04), OperandEncoding::ModRmReg_Rm));

    // 0x05: PHSUBW
    table[0x05] = Some(OpcodeEntry::new("phsubw", Operation::Other(0x38_05), OperandEncoding::ModRmReg_Rm));

    // 0x06: PHSUBD
    table[0x06] = Some(OpcodeEntry::new("phsubd", Operation::Other(0x38_06), OperandEncoding::ModRmReg_Rm));

    // 0x07: PHSUBSW
    table[0x07] = Some(OpcodeEntry::new("phsubsw", Operation::Other(0x38_07), OperandEncoding::ModRmReg_Rm));

    // 0x08: PSIGNB
    table[0x08] = Some(OpcodeEntry::new("psignb", Operation::Other(0x38_08), OperandEncoding::ModRmReg_Rm));

    // 0x09: PSIGNW
    table[0x09] = Some(OpcodeEntry::new("psignw", Operation::Other(0x38_09), OperandEncoding::ModRmReg_Rm));

    // 0x0A: PSIGND
    table[0x0A] = Some(OpcodeEntry::new("psignd", Operation::Other(0x38_0A), OperandEncoding::ModRmReg_Rm));

    // 0x0B: PMULHRSW
    table[0x0B] = Some(OpcodeEntry::new("pmulhrsw", Operation::Other(0x38_0B), OperandEncoding::ModRmReg_Rm));

    // 0x17: PTEST (SSE4.1)
    table[0x17] = Some(OpcodeEntry::new("ptest", Operation::Other(0x38_17), OperandEncoding::ModRmReg_Rm));

    // 0x1C: PABSB
    table[0x1C] = Some(OpcodeEntry::new("pabsb", Operation::Other(0x38_1C), OperandEncoding::ModRmReg_Rm));

    // 0x1D: PABSW
    table[0x1D] = Some(OpcodeEntry::new("pabsw", Operation::Other(0x38_1D), OperandEncoding::ModRmReg_Rm));

    // 0x1E: PABSD
    table[0x1E] = Some(OpcodeEntry::new("pabsd", Operation::Other(0x38_1E), OperandEncoding::ModRmReg_Rm));

    // SSE4.1 packed extend instructions
    // 0x20: PMOVSXBW
    table[0x20] = Some(OpcodeEntry::new("pmovsxbw", Operation::Other(0x38_20), OperandEncoding::ModRmReg_Rm));

    // 0x21: PMOVSXBD
    table[0x21] = Some(OpcodeEntry::new("pmovsxbd", Operation::Other(0x38_21), OperandEncoding::ModRmReg_Rm));

    // 0x22: PMOVSXBQ
    table[0x22] = Some(OpcodeEntry::new("pmovsxbq", Operation::Other(0x38_22), OperandEncoding::ModRmReg_Rm));

    // 0x23: PMOVSXWD
    table[0x23] = Some(OpcodeEntry::new("pmovsxwd", Operation::Other(0x38_23), OperandEncoding::ModRmReg_Rm));

    // 0x24: PMOVSXWQ
    table[0x24] = Some(OpcodeEntry::new("pmovsxwq", Operation::Other(0x38_24), OperandEncoding::ModRmReg_Rm));

    // 0x25: PMOVSXDQ
    table[0x25] = Some(OpcodeEntry::new("pmovsxdq", Operation::Other(0x38_25), OperandEncoding::ModRmReg_Rm));

    // 0x28: PMULDQ
    table[0x28] = Some(OpcodeEntry::new("pmuldq", Operation::Other(0x38_28), OperandEncoding::ModRmReg_Rm));

    // 0x29: PCMPEQQ
    table[0x29] = Some(OpcodeEntry::new("pcmpeqq", Operation::Other(0x38_29), OperandEncoding::ModRmReg_Rm));

    // 0x2A: MOVNTDQA
    table[0x2A] = Some(OpcodeEntry::new("movntdqa", Operation::Other(0x38_2A), OperandEncoding::ModRmReg_Rm));

    // 0x2B: PACKUSDW
    table[0x2B] = Some(OpcodeEntry::new("packusdw", Operation::Other(0x38_2B), OperandEncoding::ModRmReg_Rm));

    // 0x30: PMOVZXBW
    table[0x30] = Some(OpcodeEntry::new("pmovzxbw", Operation::Other(0x38_30), OperandEncoding::ModRmReg_Rm));

    // 0x31: PMOVZXBD
    table[0x31] = Some(OpcodeEntry::new("pmovzxbd", Operation::Other(0x38_31), OperandEncoding::ModRmReg_Rm));

    // 0x32: PMOVZXBQ
    table[0x32] = Some(OpcodeEntry::new("pmovzxbq", Operation::Other(0x38_32), OperandEncoding::ModRmReg_Rm));

    // 0x33: PMOVZXWD
    table[0x33] = Some(OpcodeEntry::new("pmovzxwd", Operation::Other(0x38_33), OperandEncoding::ModRmReg_Rm));

    // 0x34: PMOVZXWQ
    table[0x34] = Some(OpcodeEntry::new("pmovzxwq", Operation::Other(0x38_34), OperandEncoding::ModRmReg_Rm));

    // 0x35: PMOVZXDQ
    table[0x35] = Some(OpcodeEntry::new("pmovzxdq", Operation::Other(0x38_35), OperandEncoding::ModRmReg_Rm));

    // 0x37: PCMPGTQ
    table[0x37] = Some(OpcodeEntry::new("pcmpgtq", Operation::Other(0x38_37), OperandEncoding::ModRmReg_Rm));

    // 0x38: PMINSB
    table[0x38] = Some(OpcodeEntry::new("pminsb", Operation::Other(0x38_38), OperandEncoding::ModRmReg_Rm));

    // 0x39: PMINSD
    table[0x39] = Some(OpcodeEntry::new("pminsd", Operation::Other(0x38_39), OperandEncoding::ModRmReg_Rm));

    // 0x3A: PMINUW
    table[0x3A] = Some(OpcodeEntry::new("pminuw", Operation::Other(0x38_3A), OperandEncoding::ModRmReg_Rm));

    // 0x3B: PMINUD
    table[0x3B] = Some(OpcodeEntry::new("pminud", Operation::Other(0x38_3B), OperandEncoding::ModRmReg_Rm));

    // 0x3C: PMAXSB
    table[0x3C] = Some(OpcodeEntry::new("pmaxsb", Operation::Other(0x38_3C), OperandEncoding::ModRmReg_Rm));

    // 0x3D: PMAXSD
    table[0x3D] = Some(OpcodeEntry::new("pmaxsd", Operation::Other(0x38_3D), OperandEncoding::ModRmReg_Rm));

    // 0x3E: PMAXUW
    table[0x3E] = Some(OpcodeEntry::new("pmaxuw", Operation::Other(0x38_3E), OperandEncoding::ModRmReg_Rm));

    // 0x3F: PMAXUD
    table[0x3F] = Some(OpcodeEntry::new("pmaxud", Operation::Other(0x38_3F), OperandEncoding::ModRmReg_Rm));

    // 0x40: PMULLD
    table[0x40] = Some(OpcodeEntry::new("pmulld", Operation::Other(0x38_40), OperandEncoding::ModRmReg_Rm));

    // 0x41: PHMINPOSUW
    table[0x41] = Some(OpcodeEntry::new("phminposuw", Operation::Other(0x38_41), OperandEncoding::ModRmReg_Rm));

    // AVX instructions
    // 0x0C: VPERMILPS (VEX.NDS.128/256.66.0F38.W0)
    table[0x0C] = Some(OpcodeEntry::new("permilps", Operation::Other(0x38_0C), OperandEncoding::ModRmReg_Rm));

    // 0x0D: VPERMILPD (VEX.NDS.128/256.66.0F38.W0)
    table[0x0D] = Some(OpcodeEntry::new("permilpd", Operation::Other(0x38_0D), OperandEncoding::ModRmReg_Rm));

    // 0x0E: VTESTPS (VEX.128/256.66.0F38.W0)
    table[0x0E] = Some(OpcodeEntry::new("testps", Operation::Test, OperandEncoding::ModRmReg_Rm));

    // 0x0F: VTESTPD (VEX.128/256.66.0F38.W0)
    table[0x0F] = Some(OpcodeEntry::new("testpd", Operation::Test, OperandEncoding::ModRmReg_Rm));

    // 0x13: VCVTPH2PS (VEX.128/256.66.0F38.W0)
    table[0x13] = Some(OpcodeEntry::new("cvtph2ps", Operation::Move, OperandEncoding::ModRmReg_Rm));

    // 0x16: VPERMPS (VEX.256.66.0F38.W0)
    table[0x16] = Some(OpcodeEntry::new("permps", Operation::Other(0x38_16), OperandEncoding::ModRmReg_Rm));

    // 0x18: VBROADCASTSS (VEX.128/256.66.0F38.W0)
    table[0x18] = Some(OpcodeEntry::new("broadcastss", Operation::Other(0x38_18), OperandEncoding::ModRmReg_Rm));

    // 0x19: VBROADCASTSD (VEX.256.66.0F38.W0)
    table[0x19] = Some(OpcodeEntry::new("broadcastsd", Operation::Other(0x38_19), OperandEncoding::ModRmReg_Rm));

    // 0x1A: VBROADCASTF128 (VEX.256.66.0F38.W0)
    table[0x1A] = Some(OpcodeEntry::new("broadcastf128", Operation::Other(0x38_1A), OperandEncoding::ModRmReg_Rm));

    // 0x2C: VMASKMOVPS (VEX.NDS.128/256.66.0F38.W0) - load form
    table[0x2C] = Some(OpcodeEntry::new("maskmovps", Operation::Load, OperandEncoding::ModRmReg_Rm));

    // 0x2D: VMASKMOVPD (VEX.NDS.128/256.66.0F38.W0) - load form
    table[0x2D] = Some(OpcodeEntry::new("maskmovpd", Operation::Load, OperandEncoding::ModRmReg_Rm));

    // 0x2E: VMASKMOVPS (VEX.NDS.128/256.66.0F38.W0) - store form
    table[0x2E] = Some(OpcodeEntry::new("maskmovps", Operation::Store, OperandEncoding::ModRmReg_Rm));

    // 0x2F: VMASKMOVPD (VEX.NDS.128/256.66.0F38.W0) - store form
    table[0x2F] = Some(OpcodeEntry::new("maskmovpd", Operation::Store, OperandEncoding::ModRmReg_Rm));

    // 0x36: VPERMD (VEX.NDS.256.66.0F38.W0)
    table[0x36] = Some(OpcodeEntry::new("permd", Operation::Other(0x38_36), OperandEncoding::ModRmReg_Rm));

    // 0x45: VPSRLVD/VPSRLVQ
    table[0x45] = Some(OpcodeEntry::new("psrlv", Operation::Shr, OperandEncoding::ModRmReg_Rm));

    // 0x46: VPSRAVD
    table[0x46] = Some(OpcodeEntry::new("psravd", Operation::Sar, OperandEncoding::ModRmReg_Rm));

    // 0x47: VPSLLVD/VPSLLVQ
    table[0x47] = Some(OpcodeEntry::new("psllv", Operation::Shl, OperandEncoding::ModRmReg_Rm));

    // 0x58: VPBROADCASTD (VEX.128/256.66.0F38.W0)
    table[0x58] = Some(OpcodeEntry::new("pbroadcastd", Operation::Other(0x38_58), OperandEncoding::ModRmReg_Rm));

    // 0x59: VPBROADCASTQ (VEX.128/256.66.0F38.W0)
    table[0x59] = Some(OpcodeEntry::new("pbroadcastq", Operation::Other(0x38_59), OperandEncoding::ModRmReg_Rm));

    // 0x5A: VBROADCASTI128 (VEX.256.66.0F38.W0)
    table[0x5A] = Some(OpcodeEntry::new("broadcasti128", Operation::Other(0x38_5A), OperandEncoding::ModRmReg_Rm));

    // 0x78: VPBROADCASTB (VEX.128/256.66.0F38.W0)
    table[0x78] = Some(OpcodeEntry::new("pbroadcastb", Operation::Other(0x38_78), OperandEncoding::ModRmReg_Rm));

    // 0x79: VPBROADCASTW (VEX.128/256.66.0F38.W0)
    table[0x79] = Some(OpcodeEntry::new("pbroadcastw", Operation::Other(0x38_79), OperandEncoding::ModRmReg_Rm));

    // 0x8C: VPMASKMOVD/VPMASKMOVQ (VEX.NDS.128/256.66.0F38.W0/W1) - load form
    table[0x8C] = Some(OpcodeEntry::new("pmaskmovd", Operation::Load, OperandEncoding::ModRmReg_Rm));

    // 0x8E: VPMASKMOVD/VPMASKMOVQ (VEX.NDS.128/256.66.0F38.W0/W1) - store form
    table[0x8E] = Some(OpcodeEntry::new("pmaskmovd", Operation::Store, OperandEncoding::ModRmReg_Rm));

    // 0x90: VPGATHERDD/VPGATHERDQ (VEX.DDS.128/256.66.0F38.W0/W1)
    table[0x90] = Some(OpcodeEntry::new("pgatherdd", Operation::Load, OperandEncoding::ModRmReg_Rm));

    // 0x91: VPGATHERQD/VPGATHERQQ (VEX.DDS.128/256.66.0F38.W0/W1)
    table[0x91] = Some(OpcodeEntry::new("pgatherqd", Operation::Load, OperandEncoding::ModRmReg_Rm));

    // 0x92: VGATHERDPS/VGATHERDPD (VEX.DDS.128/256.66.0F38.W0/W1)
    table[0x92] = Some(OpcodeEntry::new("gatherdps", Operation::Load, OperandEncoding::ModRmReg_Rm));

    // 0x93: VGATHERQPS/VGATHERQPD (VEX.DDS.128/256.66.0F38.W0/W1)
    table[0x93] = Some(OpcodeEntry::new("gatherqps", Operation::Load, OperandEncoding::ModRmReg_Rm));

    // SHA extension instructions (0F 38 xx - need VEX.L=0, no prefix or 66 prefix)
    // 0xC8: SHA1NEXTE
    table[0xC8] = Some(OpcodeEntry::new("sha1nexte", Operation::Other(0x38_C8), OperandEncoding::ModRmReg_Rm));

    // 0xC9: SHA1MSG1
    table[0xC9] = Some(OpcodeEntry::new("sha1msg1", Operation::Other(0x38_C9), OperandEncoding::ModRmReg_Rm));

    // 0xCA: SHA1MSG2
    table[0xCA] = Some(OpcodeEntry::new("sha1msg2", Operation::Other(0x38_CA), OperandEncoding::ModRmReg_Rm));

    // 0xCB: SHA256RNDS2
    table[0xCB] = Some(OpcodeEntry::new("sha256rnds2", Operation::Other(0x38_CB), OperandEncoding::ModRmReg_Rm));

    // 0xCC: SHA256MSG1
    table[0xCC] = Some(OpcodeEntry::new("sha256msg1", Operation::Other(0x38_CC), OperandEncoding::ModRmReg_Rm));

    // 0xCD: SHA256MSG2
    table[0xCD] = Some(OpcodeEntry::new("sha256msg2", Operation::Other(0x38_CD), OperandEncoding::ModRmReg_Rm));

    // CRC32 instructions (need F2 prefix)
    // 0xF0: CRC32 r32, r/m8
    table[0xF0] = Some(OpcodeEntry::new("crc32", Operation::Other(0x38_F0), OperandEncoding::ModRmReg_Rm));

    // 0xF1: CRC32 r32, r/m16/32/64
    table[0xF1] = Some(OpcodeEntry::new("crc32", Operation::Other(0x38_F1), OperandEncoding::ModRmReg_Rm));

    // FMA3 instructions (VEX-encoded only)
    // 0x96-0x9F: VFMADDSUB* / VFMSUBADD*
    // 0xA6-0xAF: VFMADDSUB* / VFMSUBADD* (alternate forms)
    // 0xB6-0xBF: VFNMADD* / VFNMSUB*

    // VFMADD132PS/PD (0x98)
    table[0x98] = Some(OpcodeEntry::new("vfmadd132ps", Operation::Other(0x38_98), OperandEncoding::ModRmReg_Rm));

    // VFMADD213PS/PD (0xA8)
    table[0xA8] = Some(OpcodeEntry::new("vfmadd213ps", Operation::Other(0x38_A8), OperandEncoding::ModRmReg_Rm));

    // VFMADD231PS/PD (0xB8)
    table[0xB8] = Some(OpcodeEntry::new("vfmadd231ps", Operation::Other(0x38_B8), OperandEncoding::ModRmReg_Rm));

    // VFMADD132SS/SD (0x99)
    table[0x99] = Some(OpcodeEntry::new("vfmadd132ss", Operation::Other(0x38_99), OperandEncoding::ModRmReg_Rm));

    // VFMADD213SS/SD (0xA9)
    table[0xA9] = Some(OpcodeEntry::new("vfmadd213ss", Operation::Other(0x38_A9), OperandEncoding::ModRmReg_Rm));

    // VFMADD231SS/SD (0xB9)
    table[0xB9] = Some(OpcodeEntry::new("vfmadd231ss", Operation::Other(0x38_B9), OperandEncoding::ModRmReg_Rm));

    // VFMSUB132PS/PD (0x9A)
    table[0x9A] = Some(OpcodeEntry::new("vfmsub132ps", Operation::Other(0x38_9A), OperandEncoding::ModRmReg_Rm));

    // VFMSUB213PS/PD (0xAA)
    table[0xAA] = Some(OpcodeEntry::new("vfmsub213ps", Operation::Other(0x38_AA), OperandEncoding::ModRmReg_Rm));

    // VFMSUB231PS/PD (0xBA)
    table[0xBA] = Some(OpcodeEntry::new("vfmsub231ps", Operation::Other(0x38_BA), OperandEncoding::ModRmReg_Rm));

    // VFNMADD132PS/PD (0x9C)
    table[0x9C] = Some(OpcodeEntry::new("vfnmadd132ps", Operation::Other(0x38_9C), OperandEncoding::ModRmReg_Rm));

    // VFNMADD213PS/PD (0xAC)
    table[0xAC] = Some(OpcodeEntry::new("vfnmadd213ps", Operation::Other(0x38_AC), OperandEncoding::ModRmReg_Rm));

    // VFNMADD231PS/PD (0xBC)
    table[0xBC] = Some(OpcodeEntry::new("vfnmadd231ps", Operation::Other(0x38_BC), OperandEncoding::ModRmReg_Rm));

    // VFNMSUB132PS/PD (0x9E)
    table[0x9E] = Some(OpcodeEntry::new("vfnmsub132ps", Operation::Other(0x38_9E), OperandEncoding::ModRmReg_Rm));

    // VFNMSUB213PS/PD (0xAE)
    table[0xAE] = Some(OpcodeEntry::new("vfnmsub213ps", Operation::Other(0x38_AE), OperandEncoding::ModRmReg_Rm));

    // VFNMSUB231PS/PD (0xBE)
    table[0xBE] = Some(OpcodeEntry::new("vfnmsub231ps", Operation::Other(0x38_BE), OperandEncoding::ModRmReg_Rm));

    // AES-NI instructions
    // 0xDB: AESIMC
    table[0xDB] = Some(OpcodeEntry::new("aesimc", Operation::Other(0x38_DB), OperandEncoding::ModRmReg_Rm));

    // 0xDC: AESENC
    table[0xDC] = Some(OpcodeEntry::new("aesenc", Operation::Other(0x38_DC), OperandEncoding::ModRmReg_Rm));

    // 0xDD: AESENCLAST
    table[0xDD] = Some(OpcodeEntry::new("aesenclast", Operation::Other(0x38_DD), OperandEncoding::ModRmReg_Rm));

    // 0xDE: AESDEC
    table[0xDE] = Some(OpcodeEntry::new("aesdec", Operation::Other(0x38_DE), OperandEncoding::ModRmReg_Rm));

    // 0xDF: AESDECLAST
    table[0xDF] = Some(OpcodeEntry::new("aesdeclast", Operation::Other(0x38_DF), OperandEncoding::ModRmReg_Rm));

    // =========================================================================
    // BMI1/BMI2 instructions (VEX-encoded, use GPRs not XMM registers)
    // These need special handling in the decoder for prefix-dependent behavior
    // =========================================================================

    // 0xF2: ANDN (VEX.NDS.LZ.0F38.W0/W1 F2 /r)
    // dest = ~vvvv & r/m (logical AND NOT)
    table[0xF2] = Some(OpcodeEntry::new("andn", Operation::AndNot, OperandEncoding::ModRmReg_Rm));

    // 0xF3: BMI1 Group 17 (VEX.NDD.LZ.0F38.W0/W1 F3 /reg)
    // ModR/M.reg selects the operation:
    //   /1 = BLSR:   dest = (src - 1) & src  (reset lowest set bit)
    //   /2 = BLSMSK: dest = (src - 1) ^ src  (mask up to lowest set bit)
    //   /3 = BLSI:   dest = (-src) & src     (extract lowest set bit)
    table[0xF3] = Some(OpcodeEntry::new("bmi1_group", Operation::Other(0x38_F3), OperandEncoding::ModRmRmOnly));

    // 0xF5: Prefix-dependent BMI2 instructions
    //   pp=0 (no prefix): BZHI  (VEX.NDS.LZ.0F38.W0/W1 F5 /r) - zero high bits
    //   pp=3 (F2 prefix): PDEP  (VEX.NDS.LZ.F2.0F38.W0/W1 F5 /r) - parallel deposit
    //   pp=2 (F3 prefix): PEXT  (VEX.NDS.LZ.F3.0F38.W0/W1 F5 /r) - parallel extract
    table[0xF5] = Some(OpcodeEntry::new("bzhi", Operation::ZeroHighBits, OperandEncoding::ModRmReg_Rm));

    // 0xF6: MULX (VEX.NDD.LZ.F2.0F38.W0/W1 F6 /r)
    // Unsigned multiply without affecting flags: EDX:EAX = vvvv * r/m
    table[0xF6] = Some(OpcodeEntry::new("mulx", Operation::MulNoFlags, OperandEncoding::ModRmReg_Rm));

    // 0xF7: Prefix-dependent instructions
    //   pp=0 (no prefix): BEXTR (VEX.NDS.LZ.0F38.W0/W1 F7 /r) - bit field extract
    //   pp=1 (66 prefix): SHLX  (VEX.NDS.LZ.66.0F38.W0/W1 F7 /r) - shift left logical
    //   pp=3 (F2 prefix): SHRX  (VEX.NDS.LZ.F2.0F38.W0/W1 F7 /r) - shift right logical
    //   pp=2 (F3 prefix): SARX  (VEX.NDS.LZ.F3.0F38.W0/W1 F7 /r) - shift right arithmetic
    table[0xF7] = Some(OpcodeEntry::new("bextr", Operation::BitExtract, OperandEncoding::ModRmReg_Rm));

    table
};

/// BMI1 Group 17 instruction info based on ModR/M reg field.
/// Returns (mnemonic, operation) for the given reg value.
pub fn bmi1_group_info(reg: u8) -> (&'static str, Operation) {
    match reg {
        1 => ("blsr", Operation::ResetLowestBit),
        2 => ("blsmsk", Operation::MaskUpToLowest),
        3 => ("blsi", Operation::ExtractLowestBit),
        _ => ("bmi1_unknown", Operation::Other(0x38_F3)),
    }
}

/// Get mnemonic for BMI1 Group 17 instruction based on reg field.
#[allow(dead_code)]
pub fn bmi1_group_mnemonic(reg: u8) -> &'static str {
    bmi1_group_info(reg).0
}

/// BMI2 0xF5 instruction info based on VEX.pp field.
/// Returns (mnemonic, operation) for the given pp value.
pub fn f5_info(pp: u8) -> (&'static str, Operation) {
    match pp {
        0 => ("bzhi", Operation::ZeroHighBits),    // VEX.NDS.LZ.0F38.W0/W1 F5
        3 => ("pdep", Operation::ParallelDeposit), // VEX.NDS.LZ.F2.0F38.W0/W1 F5
        2 => ("pext", Operation::ParallelExtract), // VEX.NDS.LZ.F3.0F38.W0/W1 F5
        _ => ("bzhi", Operation::ZeroHighBits),    // Default to BZHI
    }
}

/// BMI 0xF7 instruction info based on VEX.pp field.
/// Returns (mnemonic, operation) for the given pp value.
pub fn f7_info(pp: u8) -> (&'static str, Operation) {
    match pp {
        0 => ("bextr", Operation::BitExtract), // VEX.NDS.LZ.0F38.W0/W1 F7
        1 => ("shlx", Operation::Shl),         // VEX.NDS.LZ.66.0F38.W0/W1 F7
        2 => ("sarx", Operation::Sar),         // VEX.NDS.LZ.F3.0F38.W0/W1 F7
        3 => ("shrx", Operation::Shr),         // VEX.NDS.LZ.F2.0F38.W0/W1 F7
        _ => ("bextr", Operation::BitExtract), // Default
    }
}

/// Get mnemonic for 0xF7 instruction based on prefix.
#[allow(dead_code)]
pub fn f7_mnemonic(pp: u8) -> &'static str {
    f7_info(pp).0
}

// ============================================================================
// AMX (Advanced Matrix Extensions) instruction lookup
// ============================================================================

/// AMX 0x49 instruction info based on VEX.pp field and ModR/M byte.
/// Returns (mnemonic, operation) for the given pp and modrm_byte values.
///
/// VEX.128.NP.0F38.W0 49 /0 - LDTILECFG m512
/// VEX.128.66.0F38.W0 49 /0 - STTILECFG m512
/// VEX.128.NP.0F38.W0 49 C0 - TILERELEASE (no operands)
/// VEX.128.F2.0F38.W0 49 /r - TILEZERO tmm
pub fn amx_49_info(pp: u8, modrm_byte: u8) -> Option<(&'static str, Operation)> {
    let modrm_mod = (modrm_byte >> 6) & 0x3;
    let modrm_reg = (modrm_byte >> 3) & 0x7;

    match (pp, modrm_byte, modrm_mod, modrm_reg) {
        // TILERELEASE: VEX.128.NP.0F38.W0 49 C0
        (0, 0xC0, _, _) => Some(("tilerelease", Operation::AmxTileRelease)),
        // TILEZERO: VEX.128.F2.0F38.W0 49 /r (mod=11)
        (3, _, 0b11, _) => Some(("tilezero", Operation::AmxTileZero)),
        // LDTILECFG: VEX.128.NP.0F38.W0 49 /0 (mod != 11, reg = 0)
        (0, _, mod_, 0) if mod_ != 0b11 => Some(("ldtilecfg", Operation::AmxLoadTileConfig)),
        // STTILECFG: VEX.128.66.0F38.W0 49 /0 (mod != 11, reg = 0)
        (1, _, mod_, 0) if mod_ != 0b11 => Some(("sttilecfg", Operation::AmxStoreTileConfig)),
        _ => None,
    }
}

/// AMX 0x4B instruction info based on VEX.pp field.
/// Returns (mnemonic, operation) for the given pp value.
///
/// VEX.128.F2.0F38.W0 4B /r - TILELOADD tmm, sibmem
/// VEX.128.66.0F38.W0 4B /r - TILELOADDT1 tmm, sibmem
/// VEX.128.F3.0F38.W0 4B /r - TILESTORED sibmem, tmm
pub fn amx_4b_info(pp: u8) -> Option<(&'static str, Operation)> {
    match pp {
        3 => Some(("tileloadd", Operation::AmxTileLoad)),   // F2 prefix
        1 => Some(("tileloaddt1", Operation::AmxTileLoad)), // 66 prefix
        2 => Some(("tilestored", Operation::AmxTileStore)), // F3 prefix
        _ => None,
    }
}

/// AMX 0x5C instruction info (FP16 matrix multiply).
/// VEX.128.F2.0F38.W0 5C /r - TDPFP16PS tmm, tmm, tmm
pub fn amx_5c_info(pp: u8) -> Option<(&'static str, Operation)> {
    match pp {
        3 => Some(("tdpfp16ps", Operation::AmxFp16Multiply)), // F2 prefix
        _ => None,
    }
}

/// AMX 0x5E instruction info based on VEX.pp field.
/// Returns (mnemonic, operation) for the given pp value.
///
/// VEX.128.F2.0F38.W0 5E /r - TDPBSSD tmm, tmm, tmm
/// VEX.128.F3.0F38.W0 5E /r - TDPBSUD tmm, tmm, tmm
/// VEX.128.66.0F38.W0 5E /r - TDPBUSD tmm, tmm, tmm
/// VEX.128.NP.0F38.W0 5E /r - TDPBUUD tmm, tmm, tmm
pub fn amx_5e_info(pp: u8) -> Option<(&'static str, Operation)> {
    match pp {
        3 => Some(("tdpbssd", Operation::AmxDotProductSS)), // F2 prefix
        2 => Some(("tdpbsud", Operation::AmxDotProductSU)), // F3 prefix
        1 => Some(("tdpbusd", Operation::AmxDotProductUS)), // 66 prefix
        0 => Some(("tdpbuud", Operation::AmxDotProductUU)), // no prefix
        _ => None,
    }
}

/// Check if the opcode is an AMX instruction that needs special handling.
pub fn is_amx_opcode(opcode: u8) -> bool {
    matches!(opcode, 0x49 | 0x4B | 0x5C | 0x5E)
}

// ============================================================================
// CET (Control-flow Enforcement Technology) shadow stack write instructions
// ============================================================================

/// CET shadow stack write instruction info.
/// These are non-VEX encodings in the 0F38 map.
///
/// 0F 38 F6 /r - WRSSD/WRSSQ r/m32/64, r32/64 (write to shadow stack)
/// 66 0F 38 F5 /r - WRUSSD/WRUSSQ r/m32/64, r32/64 (write to user shadow stack)
#[allow(dead_code)]
pub fn cet_shadow_stack_info(opcode: u8, has_66_prefix: bool) -> Option<(&'static str, Operation, bool)> {
    match (opcode, has_66_prefix) {
        // WRSSD/WRSSQ: 0F 38 F6 (no prefix required)
        (0xF6, false) => Some(("wrss", Operation::CetWriteSs, false)),
        // WRUSSD/WRUSSQ: 66 0F 38 F5
        (0xF5, true) => Some(("wruss", Operation::CetWriteUss, true)),
        _ => None,
    }
}

/// Check if the opcode is a CET shadow stack write instruction.
#[allow(dead_code)]
pub fn is_cet_shadow_stack_opcode(opcode: u8, has_66_prefix: bool) -> bool {
    matches!((opcode, has_66_prefix), (0xF6, false) | (0xF5, true))
}
