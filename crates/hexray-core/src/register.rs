//! Architecture-agnostic register representation.

use crate::Architecture;

/// Register class (general purpose, floating point, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RegisterClass {
    /// General purpose register (rax, x0, a0, etc.)
    General,
    /// Floating point register (xmm0, d0, f0, etc.)
    FloatingPoint,
    /// Vector/SIMD register (ymm0, zmm0, v0, etc.)
    Vector,
    /// SVE scalable vector register (z0-z31)
    ScalableVector,
    /// SVE predicate register (p0-p15)
    Predicate,
    /// SME ZA matrix register (tile storage)
    MatrixArray,
    /// SME streaming SVE mode control
    StreamingMode,
    /// AMX tile register (tmm0-tmm7) - x86 specific
    Tile,
    /// x87 FPU stack register (st0-st7) - x86 specific
    X87,
    /// Segment register (cs, ds, etc.) - x86 specific
    Segment,
    /// Control register (cr0, etc.)
    Control,
    /// Debug register (dr0, etc.)
    Debug,
    /// Stack pointer (rsp, sp, etc.)
    StackPointer,
    /// Program counter / instruction pointer (rip, pc, etc.)
    ProgramCounter,
    /// Flags / status register (rflags, nzcv, etc.)
    Flags,
    /// Other special registers
    Other,
}

/// Architecture-agnostic register representation.
///
/// Each register is identified by its architecture, class, and a numeric ID.
/// The ID is architecture-specific and should be interpreted accordingly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Register {
    /// The architecture this register belongs to.
    pub arch: Architecture,
    /// The class of register.
    pub class: RegisterClass,
    /// Architecture-specific register ID.
    pub id: u16,
    /// Size of the register in bits.
    pub size: u16,
}

impl Register {
    /// Creates a new register.
    pub fn new(arch: Architecture, class: RegisterClass, id: u16, size: u16) -> Self {
        Self {
            arch,
            class,
            id,
            size,
        }
    }

    /// Returns the canonical name for this register.
    pub fn name(&self) -> &'static str {
        match self.arch {
            Architecture::X86_64 | Architecture::X86 => x86_reg_name(self.id, self.size),
            Architecture::Arm64 => arm64_reg_name(self.id, self.size),
            Architecture::RiscV64 | Architecture::RiscV32 => riscv_reg_name(self.id),
            _ => "unknown",
        }
    }
}

// x86/x86_64 register IDs
pub mod x86 {
    // 64-bit GPRs
    pub const RAX: u16 = 0;
    pub const RCX: u16 = 1;
    pub const RDX: u16 = 2;
    pub const RBX: u16 = 3;
    pub const RSP: u16 = 4;
    pub const RBP: u16 = 5;
    pub const RSI: u16 = 6;
    pub const RDI: u16 = 7;
    pub const R8: u16 = 8;
    pub const R9: u16 = 9;
    pub const R10: u16 = 10;
    pub const R11: u16 = 11;
    pub const R12: u16 = 12;
    pub const R13: u16 = 13;
    pub const R14: u16 = 14;
    pub const R15: u16 = 15;

    // Instruction pointer
    pub const RIP: u16 = 16;

    // Flags
    pub const RFLAGS: u16 = 17;

    // Segment registers
    pub const CS: u16 = 32;
    pub const DS: u16 = 33;
    pub const ES: u16 = 34;
    pub const FS: u16 = 35;
    pub const GS: u16 = 36;
    pub const SS: u16 = 37;

    // XMM registers (128-bit, SSE)
    pub const XMM0: u16 = 64;
    pub const XMM1: u16 = 65;
    pub const XMM2: u16 = 66;
    pub const XMM3: u16 = 67;
    pub const XMM4: u16 = 68;
    pub const XMM5: u16 = 69;
    pub const XMM6: u16 = 70;
    pub const XMM7: u16 = 71;
    pub const XMM8: u16 = 72;
    pub const XMM9: u16 = 73;
    pub const XMM10: u16 = 74;
    pub const XMM11: u16 = 75;
    pub const XMM12: u16 = 76;
    pub const XMM13: u16 = 77;
    pub const XMM14: u16 = 78;
    pub const XMM15: u16 = 79;

    // YMM registers (256-bit, AVX) - same IDs as XMM but different size
    pub const YMM0: u16 = 64;
    pub const YMM1: u16 = 65;
    pub const YMM2: u16 = 66;
    pub const YMM3: u16 = 67;
    pub const YMM4: u16 = 68;
    pub const YMM5: u16 = 69;
    pub const YMM6: u16 = 70;
    pub const YMM7: u16 = 71;
    pub const YMM8: u16 = 72;
    pub const YMM9: u16 = 73;
    pub const YMM10: u16 = 74;
    pub const YMM11: u16 = 75;
    pub const YMM12: u16 = 76;
    pub const YMM13: u16 = 77;
    pub const YMM14: u16 = 78;
    pub const YMM15: u16 = 79;

    // Extended vector registers (AVX-512, XMM16-XMM31/YMM16-YMM31/ZMM16-ZMM31)
    pub const XMM16: u16 = 80;
    pub const XMM17: u16 = 81;
    pub const XMM18: u16 = 82;
    pub const XMM19: u16 = 83;
    pub const XMM20: u16 = 84;
    pub const XMM21: u16 = 85;
    pub const XMM22: u16 = 86;
    pub const XMM23: u16 = 87;
    pub const XMM24: u16 = 88;
    pub const XMM25: u16 = 89;
    pub const XMM26: u16 = 90;
    pub const XMM27: u16 = 91;
    pub const XMM28: u16 = 92;
    pub const XMM29: u16 = 93;
    pub const XMM30: u16 = 94;
    pub const XMM31: u16 = 95;

    // Opmask registers (AVX-512)
    pub const K0: u16 = 96;
    pub const K1: u16 = 97;
    pub const K2: u16 = 98;
    pub const K3: u16 = 99;
    pub const K4: u16 = 100;
    pub const K5: u16 = 101;
    pub const K6: u16 = 102;
    pub const K7: u16 = 103;

    // AMX tile registers (tmm0-tmm7)
    pub const TMM0: u16 = 112;
    pub const TMM1: u16 = 113;
    pub const TMM2: u16 = 114;
    pub const TMM3: u16 = 115;
    pub const TMM4: u16 = 116;
    pub const TMM5: u16 = 117;
    pub const TMM6: u16 = 118;
    pub const TMM7: u16 = 119;

    // x87 FPU stack registers (st0-st7)
    // Note: these use ID 0-7 with the X87 register class
    pub const ST0: u16 = 0;
    pub const ST1: u16 = 1;
    pub const ST2: u16 = 2;
    pub const ST3: u16 = 3;
    pub const ST4: u16 = 4;
    pub const ST5: u16 = 5;
    pub const ST6: u16 = 6;
    pub const ST7: u16 = 7;
}

fn x86_reg_name(id: u16, size: u16) -> &'static str {
    match (id, size) {
        // 64-bit
        (x86::RAX, 64) => "rax",
        (x86::RCX, 64) => "rcx",
        (x86::RDX, 64) => "rdx",
        (x86::RBX, 64) => "rbx",
        (x86::RSP, 64) => "rsp",
        (x86::RBP, 64) => "rbp",
        (x86::RSI, 64) => "rsi",
        (x86::RDI, 64) => "rdi",
        (x86::R8, 64) => "r8",
        (x86::R9, 64) => "r9",
        (x86::R10, 64) => "r10",
        (x86::R11, 64) => "r11",
        (x86::R12, 64) => "r12",
        (x86::R13, 64) => "r13",
        (x86::R14, 64) => "r14",
        (x86::R15, 64) => "r15",
        (x86::RIP, 64) => "rip",
        (x86::RFLAGS, 64) => "rflags",

        // 32-bit
        (x86::RAX, 32) => "eax",
        (x86::RCX, 32) => "ecx",
        (x86::RDX, 32) => "edx",
        (x86::RBX, 32) => "ebx",
        (x86::RSP, 32) => "esp",
        (x86::RBP, 32) => "ebp",
        (x86::RSI, 32) => "esi",
        (x86::RDI, 32) => "edi",
        (x86::R8, 32) => "r8d",
        (x86::R9, 32) => "r9d",
        (x86::R10, 32) => "r10d",
        (x86::R11, 32) => "r11d",
        (x86::R12, 32) => "r12d",
        (x86::R13, 32) => "r13d",
        (x86::R14, 32) => "r14d",
        (x86::R15, 32) => "r15d",

        // 16-bit
        (x86::RAX, 16) => "ax",
        (x86::RCX, 16) => "cx",
        (x86::RDX, 16) => "dx",
        (x86::RBX, 16) => "bx",
        (x86::RSP, 16) => "sp",
        (x86::RBP, 16) => "bp",
        (x86::RSI, 16) => "si",
        (x86::RDI, 16) => "di",

        // 8-bit low
        (x86::RAX, 8) => "al",
        (x86::RCX, 8) => "cl",
        (x86::RDX, 8) => "dl",
        (x86::RBX, 8) => "bl",
        (x86::RSP, 8) => "spl",
        (x86::RBP, 8) => "bpl",
        (x86::RSI, 8) => "sil",
        (x86::RDI, 8) => "dil",
        (x86::R8, 8) => "r8b",
        (x86::R9, 8) => "r9b",
        (x86::R10, 8) => "r10b",
        (x86::R11, 8) => "r11b",
        (x86::R12, 8) => "r12b",
        (x86::R13, 8) => "r13b",
        (x86::R14, 8) => "r14b",
        (x86::R15, 8) => "r15b",

        // 16-bit extended registers (r8w-r15w)
        (x86::R8, 16) => "r8w",
        (x86::R9, 16) => "r9w",
        (x86::R10, 16) => "r10w",
        (x86::R11, 16) => "r11w",
        (x86::R12, 16) => "r12w",
        (x86::R13, 16) => "r13w",
        (x86::R14, 16) => "r14w",
        (x86::R15, 16) => "r15w",

        // Segment registers
        (x86::CS, _) => "cs",
        (x86::DS, _) => "ds",
        (x86::ES, _) => "es",
        (x86::FS, _) => "fs",
        (x86::GS, _) => "gs",
        (x86::SS, _) => "ss",

        // XMM registers (128-bit)
        (x86::XMM0, 128) => "xmm0",
        (x86::XMM1, 128) => "xmm1",
        (x86::XMM2, 128) => "xmm2",
        (x86::XMM3, 128) => "xmm3",
        (x86::XMM4, 128) => "xmm4",
        (x86::XMM5, 128) => "xmm5",
        (x86::XMM6, 128) => "xmm6",
        (x86::XMM7, 128) => "xmm7",
        (x86::XMM8, 128) => "xmm8",
        (x86::XMM9, 128) => "xmm9",
        (x86::XMM10, 128) => "xmm10",
        (x86::XMM11, 128) => "xmm11",
        (x86::XMM12, 128) => "xmm12",
        (x86::XMM13, 128) => "xmm13",
        (x86::XMM14, 128) => "xmm14",
        (x86::XMM15, 128) => "xmm15",

        // YMM registers (256-bit)
        (x86::YMM0, 256) => "ymm0",
        (x86::YMM1, 256) => "ymm1",
        (x86::YMM2, 256) => "ymm2",
        (x86::YMM3, 256) => "ymm3",
        (x86::YMM4, 256) => "ymm4",
        (x86::YMM5, 256) => "ymm5",
        (x86::YMM6, 256) => "ymm6",
        (x86::YMM7, 256) => "ymm7",
        (x86::YMM8, 256) => "ymm8",
        (x86::YMM9, 256) => "ymm9",
        (x86::YMM10, 256) => "ymm10",
        (x86::YMM11, 256) => "ymm11",
        (x86::YMM12, 256) => "ymm12",
        (x86::YMM13, 256) => "ymm13",
        (x86::YMM14, 256) => "ymm14",
        (x86::YMM15, 256) => "ymm15",

        // ZMM registers (512-bit, AVX-512) - same IDs as XMM/YMM
        (x86::XMM0, 512) => "zmm0",
        (x86::XMM1, 512) => "zmm1",
        (x86::XMM2, 512) => "zmm2",
        (x86::XMM3, 512) => "zmm3",
        (x86::XMM4, 512) => "zmm4",
        (x86::XMM5, 512) => "zmm5",
        (x86::XMM6, 512) => "zmm6",
        (x86::XMM7, 512) => "zmm7",
        (x86::XMM8, 512) => "zmm8",
        (x86::XMM9, 512) => "zmm9",
        (x86::XMM10, 512) => "zmm10",
        (x86::XMM11, 512) => "zmm11",
        (x86::XMM12, 512) => "zmm12",
        (x86::XMM13, 512) => "zmm13",
        (x86::XMM14, 512) => "zmm14",
        (x86::XMM15, 512) => "zmm15",

        // Extended XMM registers (AVX-512)
        (x86::XMM16, 128) => "xmm16",
        (x86::XMM17, 128) => "xmm17",
        (x86::XMM18, 128) => "xmm18",
        (x86::XMM19, 128) => "xmm19",
        (x86::XMM20, 128) => "xmm20",
        (x86::XMM21, 128) => "xmm21",
        (x86::XMM22, 128) => "xmm22",
        (x86::XMM23, 128) => "xmm23",
        (x86::XMM24, 128) => "xmm24",
        (x86::XMM25, 128) => "xmm25",
        (x86::XMM26, 128) => "xmm26",
        (x86::XMM27, 128) => "xmm27",
        (x86::XMM28, 128) => "xmm28",
        (x86::XMM29, 128) => "xmm29",
        (x86::XMM30, 128) => "xmm30",
        (x86::XMM31, 128) => "xmm31",

        // Extended YMM registers (AVX-512)
        (x86::XMM16, 256) => "ymm16",
        (x86::XMM17, 256) => "ymm17",
        (x86::XMM18, 256) => "ymm18",
        (x86::XMM19, 256) => "ymm19",
        (x86::XMM20, 256) => "ymm20",
        (x86::XMM21, 256) => "ymm21",
        (x86::XMM22, 256) => "ymm22",
        (x86::XMM23, 256) => "ymm23",
        (x86::XMM24, 256) => "ymm24",
        (x86::XMM25, 256) => "ymm25",
        (x86::XMM26, 256) => "ymm26",
        (x86::XMM27, 256) => "ymm27",
        (x86::XMM28, 256) => "ymm28",
        (x86::XMM29, 256) => "ymm29",
        (x86::XMM30, 256) => "ymm30",
        (x86::XMM31, 256) => "ymm31",

        // Extended ZMM registers (AVX-512)
        (x86::XMM16, 512) => "zmm16",
        (x86::XMM17, 512) => "zmm17",
        (x86::XMM18, 512) => "zmm18",
        (x86::XMM19, 512) => "zmm19",
        (x86::XMM20, 512) => "zmm20",
        (x86::XMM21, 512) => "zmm21",
        (x86::XMM22, 512) => "zmm22",
        (x86::XMM23, 512) => "zmm23",
        (x86::XMM24, 512) => "zmm24",
        (x86::XMM25, 512) => "zmm25",
        (x86::XMM26, 512) => "zmm26",
        (x86::XMM27, 512) => "zmm27",
        (x86::XMM28, 512) => "zmm28",
        (x86::XMM29, 512) => "zmm29",
        (x86::XMM30, 512) => "zmm30",
        (x86::XMM31, 512) => "zmm31",

        // Opmask registers (AVX-512)
        (x86::K0, _) => "k0",
        (x86::K1, _) => "k1",
        (x86::K2, _) => "k2",
        (x86::K3, _) => "k3",
        (x86::K4, _) => "k4",
        (x86::K5, _) => "k5",
        (x86::K6, _) => "k6",
        (x86::K7, _) => "k7",

        // AMX tile registers
        (x86::TMM0, _) => "tmm0",
        (x86::TMM1, _) => "tmm1",
        (x86::TMM2, _) => "tmm2",
        (x86::TMM3, _) => "tmm3",
        (x86::TMM4, _) => "tmm4",
        (x86::TMM5, _) => "tmm5",
        (x86::TMM6, _) => "tmm6",
        (x86::TMM7, _) => "tmm7",

        // x87 FPU stack registers (80-bit extended precision)
        (x86::ST0, 80) => "st(0)",
        (x86::ST1, 80) => "st(1)",
        (x86::ST2, 80) => "st(2)",
        (x86::ST3, 80) => "st(3)",
        (x86::ST4, 80) => "st(4)",
        (x86::ST5, 80) => "st(5)",
        (x86::ST6, 80) => "st(6)",
        (x86::ST7, 80) => "st(7)",

        _ => "unknown",
    }
}

// ARM64 register IDs
pub mod arm64 {
    // General purpose registers X0-X30
    pub const X0: u16 = 0;
    pub const X1: u16 = 1;
    pub const X2: u16 = 2;
    pub const X3: u16 = 3;
    // ... X4-X28 follow the pattern
    pub const X29: u16 = 29; // Frame pointer (FP)
    pub const X30: u16 = 30; // Link register (LR)
    pub const SP: u16 = 31; // Stack pointer
    pub const XZR: u16 = 32; // Zero register (reads as 0, writes discarded)
    pub const PC: u16 = 33; // Program counter

    // SIMD/FP vector registers V0-V31
    // These can be accessed as B/H/S/D/Q (8/16/32/64/128 bit) or V (128-bit vector)
    pub const V0: u16 = 64;
    pub const V1: u16 = 65;
    pub const V2: u16 = 66;
    pub const V3: u16 = 67;
    pub const V4: u16 = 68;
    pub const V5: u16 = 69;
    pub const V6: u16 = 70;
    pub const V7: u16 = 71;
    pub const V8: u16 = 72;
    pub const V9: u16 = 73;
    pub const V10: u16 = 74;
    pub const V11: u16 = 75;
    pub const V12: u16 = 76;
    pub const V13: u16 = 77;
    pub const V14: u16 = 78;
    pub const V15: u16 = 79;
    pub const V16: u16 = 80;
    pub const V17: u16 = 81;
    pub const V18: u16 = 82;
    pub const V19: u16 = 83;
    pub const V20: u16 = 84;
    pub const V21: u16 = 85;
    pub const V22: u16 = 86;
    pub const V23: u16 = 87;
    pub const V24: u16 = 88;
    pub const V25: u16 = 89;
    pub const V26: u16 = 90;
    pub const V27: u16 = 91;
    pub const V28: u16 = 92;
    pub const V29: u16 = 93;
    pub const V30: u16 = 94;
    pub const V31: u16 = 95;

    // SVE scalable vector registers Z0-Z31 (128-2048 bits)
    pub const Z0: u16 = 128;
    pub const Z1: u16 = 129;
    pub const Z2: u16 = 130;
    pub const Z3: u16 = 131;
    pub const Z4: u16 = 132;
    pub const Z5: u16 = 133;
    pub const Z6: u16 = 134;
    pub const Z7: u16 = 135;
    pub const Z8: u16 = 136;
    pub const Z9: u16 = 137;
    pub const Z10: u16 = 138;
    pub const Z11: u16 = 139;
    pub const Z12: u16 = 140;
    pub const Z13: u16 = 141;
    pub const Z14: u16 = 142;
    pub const Z15: u16 = 143;
    pub const Z16: u16 = 144;
    pub const Z17: u16 = 145;
    pub const Z18: u16 = 146;
    pub const Z19: u16 = 147;
    pub const Z20: u16 = 148;
    pub const Z21: u16 = 149;
    pub const Z22: u16 = 150;
    pub const Z23: u16 = 151;
    pub const Z24: u16 = 152;
    pub const Z25: u16 = 153;
    pub const Z26: u16 = 154;
    pub const Z27: u16 = 155;
    pub const Z28: u16 = 156;
    pub const Z29: u16 = 157;
    pub const Z30: u16 = 158;
    pub const Z31: u16 = 159;

    // SVE predicate registers P0-P15
    pub const P0: u16 = 160;
    pub const P1: u16 = 161;
    pub const P2: u16 = 162;
    pub const P3: u16 = 163;
    pub const P4: u16 = 164;
    pub const P5: u16 = 165;
    pub const P6: u16 = 166;
    pub const P7: u16 = 167;
    pub const P8: u16 = 168;
    pub const P9: u16 = 169;
    pub const P10: u16 = 170;
    pub const P11: u16 = 171;
    pub const P12: u16 = 172;
    pub const P13: u16 = 173;
    pub const P14: u16 = 174;
    pub const P15: u16 = 175;

    // SVE First Fault Register
    pub const FFR: u16 = 176;

    // SME (Scalable Matrix Extension) registers
    // ZA - The matrix register array
    pub const ZA: u16 = 192;

    // SME tile registers (sub-portions of ZA)
    // ZA0-ZA7 for various element sizes
    pub const ZA0_B: u16 = 193; // Byte tiles
    pub const ZA0_H: u16 = 201; // Halfword tiles (ZA0.H-ZA1.H)
    pub const ZA1_H: u16 = 202;
    pub const ZA0_S: u16 = 209; // Word tiles (ZA0.S-ZA3.S)
    pub const ZA1_S: u16 = 210;
    pub const ZA2_S: u16 = 211;
    pub const ZA3_S: u16 = 212;
    pub const ZA0_D: u16 = 217; // Doubleword tiles (ZA0.D-ZA7.D)
    pub const ZA1_D: u16 = 218;
    pub const ZA2_D: u16 = 219;
    pub const ZA3_D: u16 = 220;
    pub const ZA4_D: u16 = 221;
    pub const ZA5_D: u16 = 222;
    pub const ZA6_D: u16 = 223;
    pub const ZA7_D: u16 = 224;

    // SME streaming mode control (pseudo-register for tracking mode)
    pub const SVCR: u16 = 240; // Streaming Vector Control Register
}

fn arm64_reg_name(id: u16, size: u16) -> &'static str {
    match (id, size) {
        // 64-bit X registers
        (0, 64) => "x0",
        (1, 64) => "x1",
        (2, 64) => "x2",
        (3, 64) => "x3",
        (4, 64) => "x4",
        (5, 64) => "x5",
        (6, 64) => "x6",
        (7, 64) => "x7",
        (8, 64) => "x8",
        (9, 64) => "x9",
        (10, 64) => "x10",
        (11, 64) => "x11",
        (12, 64) => "x12",
        (13, 64) => "x13",
        (14, 64) => "x14",
        (15, 64) => "x15",
        (16, 64) => "x16",
        (17, 64) => "x17",
        (18, 64) => "x18",
        (19, 64) => "x19",
        (20, 64) => "x20",
        (21, 64) => "x21",
        (22, 64) => "x22",
        (23, 64) => "x23",
        (24, 64) => "x24",
        (25, 64) => "x25",
        (26, 64) => "x26",
        (27, 64) => "x27",
        (28, 64) => "x28",
        (29, 64) => "x29", // fp
        (30, 64) => "x30", // lr
        (arm64::SP, 64) => "sp",
        (arm64::XZR, 64) => "xzr",
        (arm64::PC, 64) => "pc",

        // 32-bit W registers
        (0, 32) => "w0",
        (1, 32) => "w1",
        (2, 32) => "w2",
        (3, 32) => "w3",
        (4, 32) => "w4",
        (5, 32) => "w5",
        (6, 32) => "w6",
        (7, 32) => "w7",
        (8, 32) => "w8",
        (9, 32) => "w9",
        (10, 32) => "w10",
        (11, 32) => "w11",
        (12, 32) => "w12",
        (13, 32) => "w13",
        (14, 32) => "w14",
        (15, 32) => "w15",
        (16, 32) => "w16",
        (17, 32) => "w17",
        (18, 32) => "w18",
        (19, 32) => "w19",
        (20, 32) => "w20",
        (21, 32) => "w21",
        (22, 32) => "w22",
        (23, 32) => "w23",
        (24, 32) => "w24",
        (25, 32) => "w25",
        (26, 32) => "w26",
        (27, 32) => "w27",
        (28, 32) => "w28",
        (29, 32) => "w29",
        (30, 32) => "w30",
        (arm64::SP, 32) => "wsp",
        (arm64::XZR, 32) => "wzr",

        // 128-bit V registers (SIMD)
        (arm64::V0, 128) => "v0",
        (arm64::V1, 128) => "v1",
        (arm64::V2, 128) => "v2",
        (arm64::V3, 128) => "v3",
        (arm64::V4, 128) => "v4",
        (arm64::V5, 128) => "v5",
        (arm64::V6, 128) => "v6",
        (arm64::V7, 128) => "v7",
        (arm64::V8, 128) => "v8",
        (arm64::V9, 128) => "v9",
        (arm64::V10, 128) => "v10",
        (arm64::V11, 128) => "v11",
        (arm64::V12, 128) => "v12",
        (arm64::V13, 128) => "v13",
        (arm64::V14, 128) => "v14",
        (arm64::V15, 128) => "v15",
        (arm64::V16, 128) => "v16",
        (arm64::V17, 128) => "v17",
        (arm64::V18, 128) => "v18",
        (arm64::V19, 128) => "v19",
        (arm64::V20, 128) => "v20",
        (arm64::V21, 128) => "v21",
        (arm64::V22, 128) => "v22",
        (arm64::V23, 128) => "v23",
        (arm64::V24, 128) => "v24",
        (arm64::V25, 128) => "v25",
        (arm64::V26, 128) => "v26",
        (arm64::V27, 128) => "v27",
        (arm64::V28, 128) => "v28",
        (arm64::V29, 128) => "v29",
        (arm64::V30, 128) => "v30",
        (arm64::V31, 128) => "v31",

        // 64-bit D registers (FP/lower half of V)
        (arm64::V0, 64) => "d0",
        (arm64::V1, 64) => "d1",
        (arm64::V2, 64) => "d2",
        (arm64::V3, 64) => "d3",
        (arm64::V4, 64) => "d4",
        (arm64::V5, 64) => "d5",
        (arm64::V6, 64) => "d6",
        (arm64::V7, 64) => "d7",
        (arm64::V8, 64) => "d8",
        (arm64::V9, 64) => "d9",
        (arm64::V10, 64) => "d10",
        (arm64::V11, 64) => "d11",
        (arm64::V12, 64) => "d12",
        (arm64::V13, 64) => "d13",
        (arm64::V14, 64) => "d14",
        (arm64::V15, 64) => "d15",
        (arm64::V16, 64) => "d16",
        (arm64::V17, 64) => "d17",
        (arm64::V18, 64) => "d18",
        (arm64::V19, 64) => "d19",
        (arm64::V20, 64) => "d20",
        (arm64::V21, 64) => "d21",
        (arm64::V22, 64) => "d22",
        (arm64::V23, 64) => "d23",
        (arm64::V24, 64) => "d24",
        (arm64::V25, 64) => "d25",
        (arm64::V26, 64) => "d26",
        (arm64::V27, 64) => "d27",
        (arm64::V28, 64) => "d28",
        (arm64::V29, 64) => "d29",
        (arm64::V30, 64) => "d30",
        (arm64::V31, 64) => "d31",

        // 32-bit S registers (FP single)
        (arm64::V0, 32) => "s0",
        (arm64::V1, 32) => "s1",
        (arm64::V2, 32) => "s2",
        (arm64::V3, 32) => "s3",
        (arm64::V4, 32) => "s4",
        (arm64::V5, 32) => "s5",
        (arm64::V6, 32) => "s6",
        (arm64::V7, 32) => "s7",
        (arm64::V8, 32) => "s8",
        (arm64::V9, 32) => "s9",
        (arm64::V10, 32) => "s10",
        (arm64::V11, 32) => "s11",
        (arm64::V12, 32) => "s12",
        (arm64::V13, 32) => "s13",
        (arm64::V14, 32) => "s14",
        (arm64::V15, 32) => "s15",
        (arm64::V16, 32) => "s16",
        (arm64::V17, 32) => "s17",
        (arm64::V18, 32) => "s18",
        (arm64::V19, 32) => "s19",
        (arm64::V20, 32) => "s20",
        (arm64::V21, 32) => "s21",
        (arm64::V22, 32) => "s22",
        (arm64::V23, 32) => "s23",
        (arm64::V24, 32) => "s24",
        (arm64::V25, 32) => "s25",
        (arm64::V26, 32) => "s26",
        (arm64::V27, 32) => "s27",
        (arm64::V28, 32) => "s28",
        (arm64::V29, 32) => "s29",
        (arm64::V30, 32) => "s30",
        (arm64::V31, 32) => "s31",

        // 16-bit H registers (FP half)
        (arm64::V0, 16) => "h0",
        (arm64::V1, 16) => "h1",
        (arm64::V2, 16) => "h2",
        (arm64::V3, 16) => "h3",
        (arm64::V4, 16) => "h4",
        (arm64::V5, 16) => "h5",
        (arm64::V6, 16) => "h6",
        (arm64::V7, 16) => "h7",
        (arm64::V8, 16) => "h8",
        (arm64::V9, 16) => "h9",
        (arm64::V10, 16) => "h10",
        (arm64::V11, 16) => "h11",
        (arm64::V12, 16) => "h12",
        (arm64::V13, 16) => "h13",
        (arm64::V14, 16) => "h14",
        (arm64::V15, 16) => "h15",
        (arm64::V16, 16) => "h16",
        (arm64::V17, 16) => "h17",
        (arm64::V18, 16) => "h18",
        (arm64::V19, 16) => "h19",
        (arm64::V20, 16) => "h20",
        (arm64::V21, 16) => "h21",
        (arm64::V22, 16) => "h22",
        (arm64::V23, 16) => "h23",
        (arm64::V24, 16) => "h24",
        (arm64::V25, 16) => "h25",
        (arm64::V26, 16) => "h26",
        (arm64::V27, 16) => "h27",
        (arm64::V28, 16) => "h28",
        (arm64::V29, 16) => "h29",
        (arm64::V30, 16) => "h30",
        (arm64::V31, 16) => "h31",

        // 8-bit B registers (byte)
        (arm64::V0, 8) => "b0",
        (arm64::V1, 8) => "b1",
        (arm64::V2, 8) => "b2",
        (arm64::V3, 8) => "b3",
        (arm64::V4, 8) => "b4",
        (arm64::V5, 8) => "b5",
        (arm64::V6, 8) => "b6",
        (arm64::V7, 8) => "b7",
        (arm64::V8, 8) => "b8",
        (arm64::V9, 8) => "b9",
        (arm64::V10, 8) => "b10",
        (arm64::V11, 8) => "b11",
        (arm64::V12, 8) => "b12",
        (arm64::V13, 8) => "b13",
        (arm64::V14, 8) => "b14",
        (arm64::V15, 8) => "b15",
        (arm64::V16, 8) => "b16",
        (arm64::V17, 8) => "b17",
        (arm64::V18, 8) => "b18",
        (arm64::V19, 8) => "b19",
        (arm64::V20, 8) => "b20",
        (arm64::V21, 8) => "b21",
        (arm64::V22, 8) => "b22",
        (arm64::V23, 8) => "b23",
        (arm64::V24, 8) => "b24",
        (arm64::V25, 8) => "b25",
        (arm64::V26, 8) => "b26",
        (arm64::V27, 8) => "b27",
        (arm64::V28, 8) => "b28",
        (arm64::V29, 8) => "b29",
        (arm64::V30, 8) => "b30",
        (arm64::V31, 8) => "b31",

        // SVE Z registers (scalable vector, all sizes map to z0-z31)
        (arm64::Z0, _) => "z0",
        (arm64::Z1, _) => "z1",
        (arm64::Z2, _) => "z2",
        (arm64::Z3, _) => "z3",
        (arm64::Z4, _) => "z4",
        (arm64::Z5, _) => "z5",
        (arm64::Z6, _) => "z6",
        (arm64::Z7, _) => "z7",
        (arm64::Z8, _) => "z8",
        (arm64::Z9, _) => "z9",
        (arm64::Z10, _) => "z10",
        (arm64::Z11, _) => "z11",
        (arm64::Z12, _) => "z12",
        (arm64::Z13, _) => "z13",
        (arm64::Z14, _) => "z14",
        (arm64::Z15, _) => "z15",
        (arm64::Z16, _) => "z16",
        (arm64::Z17, _) => "z17",
        (arm64::Z18, _) => "z18",
        (arm64::Z19, _) => "z19",
        (arm64::Z20, _) => "z20",
        (arm64::Z21, _) => "z21",
        (arm64::Z22, _) => "z22",
        (arm64::Z23, _) => "z23",
        (arm64::Z24, _) => "z24",
        (arm64::Z25, _) => "z25",
        (arm64::Z26, _) => "z26",
        (arm64::Z27, _) => "z27",
        (arm64::Z28, _) => "z28",
        (arm64::Z29, _) => "z29",
        (arm64::Z30, _) => "z30",
        (arm64::Z31, _) => "z31",

        // SVE predicate registers P0-P15
        (arm64::P0, _) => "p0",
        (arm64::P1, _) => "p1",
        (arm64::P2, _) => "p2",
        (arm64::P3, _) => "p3",
        (arm64::P4, _) => "p4",
        (arm64::P5, _) => "p5",
        (arm64::P6, _) => "p6",
        (arm64::P7, _) => "p7",
        (arm64::P8, _) => "p8",
        (arm64::P9, _) => "p9",
        (arm64::P10, _) => "p10",
        (arm64::P11, _) => "p11",
        (arm64::P12, _) => "p12",
        (arm64::P13, _) => "p13",
        (arm64::P14, _) => "p14",
        (arm64::P15, _) => "p15",

        // SVE First Fault Register
        (arm64::FFR, _) => "ffr",

        // SME ZA matrix register
        (arm64::ZA, _) => "za",

        // SME tile registers
        (arm64::ZA0_B, _) => "za0.b",
        (arm64::ZA0_H, _) => "za0.h",
        (arm64::ZA1_H, _) => "za1.h",
        (arm64::ZA0_S, _) => "za0.s",
        (arm64::ZA1_S, _) => "za1.s",
        (arm64::ZA2_S, _) => "za2.s",
        (arm64::ZA3_S, _) => "za3.s",
        (arm64::ZA0_D, _) => "za0.d",
        (arm64::ZA1_D, _) => "za1.d",
        (arm64::ZA2_D, _) => "za2.d",
        (arm64::ZA3_D, _) => "za3.d",
        (arm64::ZA4_D, _) => "za4.d",
        (arm64::ZA5_D, _) => "za5.d",
        (arm64::ZA6_D, _) => "za6.d",
        (arm64::ZA7_D, _) => "za7.d",

        // SME streaming mode control
        (arm64::SVCR, _) => "svcr",

        _ => "unknown",
    }
}

// RISC-V register IDs
pub mod riscv {
    // General purpose registers x0-x31
    pub const X0: u16 = 0; // zero
    pub const X1: u16 = 1; // ra (return address)
    pub const X2: u16 = 2; // sp (stack pointer)
    pub const X3: u16 = 3; // gp (global pointer)
    pub const X4: u16 = 4; // tp (thread pointer)
    pub const X5: u16 = 5; // t0
    pub const X6: u16 = 6; // t1
    pub const X7: u16 = 7; // t2
    pub const X8: u16 = 8; // s0/fp (saved/frame pointer)
    pub const X9: u16 = 9; // s1
    pub const X10: u16 = 10; // a0
    pub const X11: u16 = 11; // a1
    pub const X12: u16 = 12; // a2
    pub const X13: u16 = 13; // a3
    pub const X14: u16 = 14; // a4
    pub const X15: u16 = 15; // a5
    pub const X16: u16 = 16; // a6
    pub const X17: u16 = 17; // a7
    pub const X18: u16 = 18; // s2
    pub const X19: u16 = 19; // s3
    pub const X20: u16 = 20; // s4
    pub const X21: u16 = 21; // s5
    pub const X22: u16 = 22; // s6
    pub const X23: u16 = 23; // s7
    pub const X24: u16 = 24; // s8
    pub const X25: u16 = 25; // s9
    pub const X26: u16 = 26; // s10
    pub const X27: u16 = 27; // s11
    pub const X28: u16 = 28; // t3
    pub const X29: u16 = 29; // t4
    pub const X30: u16 = 30; // t5
    pub const X31: u16 = 31; // t6
    pub const PC: u16 = 32;

    // Floating-point registers f0-f31 (F/D extensions)
    // IDs 64-95 for floating-point registers
    pub const F0: u16 = 64; // ft0
    pub const F1: u16 = 65; // ft1
    pub const F2: u16 = 66; // ft2
    pub const F3: u16 = 67; // ft3
    pub const F4: u16 = 68; // ft4
    pub const F5: u16 = 69; // ft5
    pub const F6: u16 = 70; // ft6
    pub const F7: u16 = 71; // ft7
    pub const F8: u16 = 72; // fs0
    pub const F9: u16 = 73; // fs1
    pub const F10: u16 = 74; // fa0
    pub const F11: u16 = 75; // fa1
    pub const F12: u16 = 76; // fa2
    pub const F13: u16 = 77; // fa3
    pub const F14: u16 = 78; // fa4
    pub const F15: u16 = 79; // fa5
    pub const F16: u16 = 80; // fa6
    pub const F17: u16 = 81; // fa7
    pub const F18: u16 = 82; // fs2
    pub const F19: u16 = 83; // fs3
    pub const F20: u16 = 84; // fs4
    pub const F21: u16 = 85; // fs5
    pub const F22: u16 = 86; // fs6
    pub const F23: u16 = 87; // fs7
    pub const F24: u16 = 88; // fs8
    pub const F25: u16 = 89; // fs9
    pub const F26: u16 = 90; // fs10
    pub const F27: u16 = 91; // fs11
    pub const F28: u16 = 92; // ft8
    pub const F29: u16 = 93; // ft9
    pub const F30: u16 = 94; // ft10
    pub const F31: u16 = 95; // ft11

    // Vector registers v0-v31 (V extension)
    // IDs 128-159 for vector registers
    pub const V0: u16 = 128;
    pub const V1: u16 = 129;
    pub const V2: u16 = 130;
    pub const V3: u16 = 131;
    pub const V4: u16 = 132;
    pub const V5: u16 = 133;
    pub const V6: u16 = 134;
    pub const V7: u16 = 135;
    pub const V8: u16 = 136;
    pub const V9: u16 = 137;
    pub const V10: u16 = 138;
    pub const V11: u16 = 139;
    pub const V12: u16 = 140;
    pub const V13: u16 = 141;
    pub const V14: u16 = 142;
    pub const V15: u16 = 143;
    pub const V16: u16 = 144;
    pub const V17: u16 = 145;
    pub const V18: u16 = 146;
    pub const V19: u16 = 147;
    pub const V20: u16 = 148;
    pub const V21: u16 = 149;
    pub const V22: u16 = 150;
    pub const V23: u16 = 151;
    pub const V24: u16 = 152;
    pub const V25: u16 = 153;
    pub const V26: u16 = 154;
    pub const V27: u16 = 155;
    pub const V28: u16 = 156;
    pub const V29: u16 = 157;
    pub const V30: u16 = 158;
    pub const V31: u16 = 159;
}

fn riscv_reg_name(id: u16) -> &'static str {
    match id {
        // General purpose registers
        0 => "zero",
        1 => "ra",
        2 => "sp",
        3 => "gp",
        4 => "tp",
        5 => "t0",
        6 => "t1",
        7 => "t2",
        8 => "s0",
        9 => "s1",
        10 => "a0",
        11 => "a1",
        12 => "a2",
        13 => "a3",
        14 => "a4",
        15 => "a5",
        16 => "a6",
        17 => "a7",
        18 => "s2",
        19 => "s3",
        20 => "s4",
        21 => "s5",
        22 => "s6",
        23 => "s7",
        24 => "s8",
        25 => "s9",
        26 => "s10",
        27 => "s11",
        28 => "t3",
        29 => "t4",
        30 => "t5",
        31 => "t6",
        riscv::PC => "pc",

        // Floating-point registers (F/D extensions)
        riscv::F0 => "ft0",
        riscv::F1 => "ft1",
        riscv::F2 => "ft2",
        riscv::F3 => "ft3",
        riscv::F4 => "ft4",
        riscv::F5 => "ft5",
        riscv::F6 => "ft6",
        riscv::F7 => "ft7",
        riscv::F8 => "fs0",
        riscv::F9 => "fs1",
        riscv::F10 => "fa0",
        riscv::F11 => "fa1",
        riscv::F12 => "fa2",
        riscv::F13 => "fa3",
        riscv::F14 => "fa4",
        riscv::F15 => "fa5",
        riscv::F16 => "fa6",
        riscv::F17 => "fa7",
        riscv::F18 => "fs2",
        riscv::F19 => "fs3",
        riscv::F20 => "fs4",
        riscv::F21 => "fs5",
        riscv::F22 => "fs6",
        riscv::F23 => "fs7",
        riscv::F24 => "fs8",
        riscv::F25 => "fs9",
        riscv::F26 => "fs10",
        riscv::F27 => "fs11",
        riscv::F28 => "ft8",
        riscv::F29 => "ft9",
        riscv::F30 => "ft10",
        riscv::F31 => "ft11",

        // Vector registers (V extension)
        riscv::V0 => "v0",
        riscv::V1 => "v1",
        riscv::V2 => "v2",
        riscv::V3 => "v3",
        riscv::V4 => "v4",
        riscv::V5 => "v5",
        riscv::V6 => "v6",
        riscv::V7 => "v7",
        riscv::V8 => "v8",
        riscv::V9 => "v9",
        riscv::V10 => "v10",
        riscv::V11 => "v11",
        riscv::V12 => "v12",
        riscv::V13 => "v13",
        riscv::V14 => "v14",
        riscv::V15 => "v15",
        riscv::V16 => "v16",
        riscv::V17 => "v17",
        riscv::V18 => "v18",
        riscv::V19 => "v19",
        riscv::V20 => "v20",
        riscv::V21 => "v21",
        riscv::V22 => "v22",
        riscv::V23 => "v23",
        riscv::V24 => "v24",
        riscv::V25 => "v25",
        riscv::V26 => "v26",
        riscv::V27 => "v27",
        riscv::V28 => "v28",
        riscv::V29 => "v29",
        riscv::V30 => "v30",
        riscv::V31 => "v31",

        _ => "unknown",
    }
}
