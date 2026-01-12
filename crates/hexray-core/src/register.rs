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
    pub const SP: u16 = 31;  // Stack pointer
    pub const XZR: u16 = 32; // Zero register (reads as 0, writes discarded)
    pub const PC: u16 = 33;  // Program counter

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

        _ => "unknown",
    }
}

// RISC-V register IDs (x0-x31)
pub mod riscv {
    pub const X0: u16 = 0;   // zero
    pub const X1: u16 = 1;   // ra (return address)
    pub const X2: u16 = 2;   // sp (stack pointer)
    pub const X3: u16 = 3;   // gp (global pointer)
    pub const X4: u16 = 4;   // tp (thread pointer)
    pub const X5: u16 = 5;   // t0
    pub const X6: u16 = 6;   // t1
    pub const X7: u16 = 7;   // t2
    pub const X8: u16 = 8;   // s0/fp (saved/frame pointer)
    pub const X9: u16 = 9;   // s1
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
}

fn riscv_reg_name(id: u16) -> &'static str {
    match id {
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
        _ => "unknown",
    }
}
