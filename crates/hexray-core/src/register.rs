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
