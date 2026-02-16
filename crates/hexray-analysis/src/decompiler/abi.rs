//! ABI-specific register and calling convention helpers.
//!
//! This module provides architecture-neutral functions for determining
//! register roles across different ABIs (x86-64 System V, ARM64 AAPCS64, RISC-V).
//!
//! # Calling Conventions Supported
//!
//! ## x86-64 System V ABI (Linux, macOS, BSD)
//! - Arguments: rdi, rsi, rdx, rcx, r8, r9 (integers/pointers)
//! - FP arguments: xmm0-xmm7
//! - Return: rax, rdx (128-bit)
//! - Callee-saved: rbx, rbp, r12-r15
//! - Red zone: 128 bytes below rsp
//!
//! ## ARM64 AAPCS64 (Procedure Call Standard for Arm 64-bit)
//! - Arguments: x0-x7 (integers/pointers), v0-v7 (FP/SIMD)
//! - Return: x0, x1 (128-bit), v0-v3 for FP
//! - Callee-saved: x19-x28, x29 (FP), x30 (LR)
//! - Special: x16/x17 (IP0/IP1), x18 (platform), x29 (FP), x30 (LR)
//!
//! ## RISC-V LP64/ILP32 (RV64I/RV32I)
//! - Arguments: a0-a7 (integers), fa0-fa7 (FP with F/D extension)
//! - Return: a0, a1 (64/128-bit), fa0-fa1 for FP
//! - Callee-saved: s0-s11, ra
//! - Special: sp (x2), gp (x3), tp (x4), zero (x0)

/// Calling convention identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingConvention {
    /// x86-64 System V ABI (Linux, macOS, BSD)
    X86_64SystemV,
    /// Windows x64 calling convention
    X86_64Win64,
    /// ARM64 AAPCS64
    Arm64Aapcs,
    /// RISC-V LP64D (64-bit with D extension)
    RiscVLp64d,
    /// RISC-V LP64 (64-bit without FP)
    RiscVLp64,
    /// RISC-V ILP32D (32-bit with D extension)
    RiscVIlp32d,
    /// RISC-V ILP32 (32-bit without FP)
    RiscVIlp32,
    /// Unknown calling convention
    Unknown,
}

impl CallingConvention {
    /// Returns the argument registers for this calling convention.
    pub fn argument_registers(&self) -> &'static [&'static str] {
        match self {
            Self::X86_64SystemV => &["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
            Self::X86_64Win64 => &["rcx", "rdx", "r8", "r9"],
            Self::Arm64Aapcs => &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
            Self::RiscVLp64d | Self::RiscVLp64 | Self::RiscVIlp32d | Self::RiscVIlp32 => {
                &["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"]
            }
            Self::Unknown => &[],
        }
    }

    /// Returns the FP argument registers for this calling convention.
    pub fn fp_argument_registers(&self) -> &'static [&'static str] {
        match self {
            Self::X86_64SystemV | Self::X86_64Win64 => &[
                "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
            ],
            Self::Arm64Aapcs => &["v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7"],
            Self::RiscVLp64d | Self::RiscVIlp32d => {
                &["fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7"]
            }
            Self::RiscVLp64 | Self::RiscVIlp32 => &[], // No FP registers without F/D extension
            Self::Unknown => &[],
        }
    }

    /// Returns the return registers for this calling convention.
    pub fn return_registers(&self) -> &'static [&'static str] {
        match self {
            Self::X86_64SystemV | Self::X86_64Win64 => &["rax", "rdx"],
            Self::Arm64Aapcs => &["x0", "x1"],
            Self::RiscVLp64d | Self::RiscVLp64 | Self::RiscVIlp32d | Self::RiscVIlp32 => {
                &["a0", "a1"]
            }
            Self::Unknown => &[],
        }
    }

    /// Returns the callee-saved registers for this calling convention.
    pub fn callee_saved_registers(&self) -> &'static [&'static str] {
        match self {
            Self::X86_64SystemV => &["rbx", "rbp", "r12", "r13", "r14", "r15"],
            Self::X86_64Win64 => &["rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15"],
            Self::Arm64Aapcs => &[
                "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30",
            ],
            Self::RiscVLp64d | Self::RiscVLp64 | Self::RiscVIlp32d | Self::RiscVIlp32 => &[
                "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "ra",
            ],
            Self::Unknown => &[],
        }
    }

    /// Returns the stack pointer register name.
    pub fn stack_pointer(&self) -> &'static str {
        match self {
            Self::X86_64SystemV | Self::X86_64Win64 => "rsp",
            Self::Arm64Aapcs => "sp",
            Self::RiscVLp64d | Self::RiscVLp64 | Self::RiscVIlp32d | Self::RiscVIlp32 => "sp",
            Self::Unknown => "sp",
        }
    }

    /// Returns the frame pointer register name.
    pub fn frame_pointer(&self) -> &'static str {
        match self {
            Self::X86_64SystemV | Self::X86_64Win64 => "rbp",
            Self::Arm64Aapcs => "x29",
            Self::RiscVLp64d | Self::RiscVLp64 | Self::RiscVIlp32d | Self::RiscVIlp32 => "s0",
            Self::Unknown => "fp",
        }
    }

    /// Returns the link register (return address) name, if applicable.
    pub fn link_register(&self) -> Option<&'static str> {
        match self {
            Self::X86_64SystemV | Self::X86_64Win64 => None, // Uses stack for return address
            Self::Arm64Aapcs => Some("x30"),
            Self::RiscVLp64d | Self::RiscVLp64 | Self::RiscVIlp32d | Self::RiscVIlp32 => Some("ra"),
            Self::Unknown => None,
        }
    }

    /// Returns the red zone size (stack space below SP that's safe to use).
    pub fn red_zone_size(&self) -> usize {
        match self {
            Self::X86_64SystemV => 128,
            Self::X86_64Win64 => 0, // No red zone
            Self::Arm64Aapcs => 0,  // No red zone (but 16-byte alignment)
            Self::RiscVLp64d | Self::RiscVLp64 | Self::RiscVIlp32d | Self::RiscVIlp32 => 0,
            Self::Unknown => 0,
        }
    }

    /// Returns the stack alignment requirement in bytes.
    pub fn stack_alignment(&self) -> usize {
        match self {
            Self::X86_64SystemV => 16,
            Self::X86_64Win64 => 16,
            Self::Arm64Aapcs => 16,
            Self::RiscVLp64d | Self::RiscVLp64 => 16,
            Self::RiscVIlp32d | Self::RiscVIlp32 => 8, // 32-bit uses 8-byte alignment
            Self::Unknown => 8,
        }
    }

    /// Returns the pointer size in bytes.
    pub fn pointer_size(&self) -> usize {
        match self {
            Self::X86_64SystemV | Self::X86_64Win64 => 8,
            Self::Arm64Aapcs => 8,
            Self::RiscVLp64d | Self::RiscVLp64 => 8,
            Self::RiscVIlp32d | Self::RiscVIlp32 => 4,
            Self::Unknown => 8,
        }
    }
}

/// ARM64-specific register roles.
pub mod arm64 {
    /// Returns true if the register is an intra-procedure-call scratch register.
    /// IP0 (x16) and IP1 (x17) are used by linkers for veneers and PLT entries.
    pub fn is_ip_register(name: &str) -> bool {
        matches!(name, "x16" | "w16" | "x17" | "w17" | "ip0" | "ip1")
    }

    /// Returns true if the register is the platform register.
    /// x18 is reserved on some platforms (iOS, Windows on ARM).
    pub fn is_platform_register(name: &str) -> bool {
        matches!(name, "x18" | "w18")
    }

    /// Returns the condition code name for ARM64 conditional instructions.
    pub fn condition_name(code: u8) -> &'static str {
        match code & 0xF {
            0x0 => "eq", // Equal (Z=1)
            0x1 => "ne", // Not equal (Z=0)
            0x2 => "cs", // Carry set / unsigned higher or same
            0x3 => "cc", // Carry clear / unsigned lower
            0x4 => "mi", // Minus / negative
            0x5 => "pl", // Plus / positive or zero
            0x6 => "vs", // Overflow
            0x7 => "vc", // No overflow
            0x8 => "hi", // Unsigned higher
            0x9 => "ls", // Unsigned lower or same
            0xA => "ge", // Signed greater or equal
            0xB => "lt", // Signed less than
            0xC => "gt", // Signed greater than
            0xD => "le", // Signed less or equal
            0xE => "al", // Always
            0xF => "nv", // Never (but encodes as always)
            _ => unreachable!(),
        }
    }

    /// Inverts an ARM64 condition code.
    pub fn invert_condition(code: u8) -> u8 {
        code ^ 1
    }
}

/// RISC-V-specific register roles.
pub mod riscv {
    /// Returns the ABI name for a RISC-V register number.
    pub fn register_abi_name(reg: u8) -> &'static str {
        match reg {
            0 => "zero",
            1 => "ra",
            2 => "sp",
            3 => "gp",
            4 => "tp",
            5 => "t0",
            6 => "t1",
            7 => "t2",
            8 => "s0", // Also fp (frame pointer)
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
            _ => "unknown",
        }
    }

    /// Returns the FP register ABI name.
    pub fn fp_register_abi_name(reg: u8) -> &'static str {
        match reg {
            0 => "ft0",
            1 => "ft1",
            2 => "ft2",
            3 => "ft3",
            4 => "ft4",
            5 => "ft5",
            6 => "ft6",
            7 => "ft7",
            8 => "fs0",
            9 => "fs1",
            10 => "fa0",
            11 => "fa1",
            12 => "fa2",
            13 => "fa3",
            14 => "fa4",
            15 => "fa5",
            16 => "fa6",
            17 => "fa7",
            18 => "fs2",
            19 => "fs3",
            20 => "fs4",
            21 => "fs5",
            22 => "fs6",
            23 => "fs7",
            24 => "fs8",
            25 => "fs9",
            26 => "fs10",
            27 => "fs11",
            28 => "ft8",
            29 => "ft9",
            30 => "ft10",
            31 => "ft11",
            _ => "unknown",
        }
    }

    /// Returns true if the register is the global pointer.
    pub fn is_global_pointer(name: &str) -> bool {
        matches!(name, "gp" | "x3")
    }

    /// Returns true if the register is the thread pointer.
    pub fn is_thread_pointer(name: &str) -> bool {
        matches!(name, "tp" | "x4")
    }

    /// Returns true if this is the zero register.
    pub fn is_zero_register(name: &str) -> bool {
        matches!(name, "zero" | "x0")
    }
}

/// Returns the argument index (0-based) for an argument register, or None if not an arg register.
///
/// Supports:
/// - x86-64 System V ABI: rdi, rsi, rdx, rcx, r8, r9 (args 0-5)
/// - ARM64 AAPCS64: x0-x7/w0-w7 (args 0-7)
/// - RISC-V: a0-a7 (args 0-7)
pub fn get_arg_register_index(name: &str) -> Option<usize> {
    match name {
        // x86-64 System V ABI
        "edi" | "rdi" => Some(0),
        "esi" | "rsi" => Some(1),
        "edx" | "rdx" => Some(2),
        "ecx" | "rcx" => Some(3),
        "r8d" | "r8" => Some(4),
        "r9d" | "r9" => Some(5),
        // ARM64 AAPCS64
        "x0" | "w0" => Some(0),
        "x1" | "w1" => Some(1),
        "x2" | "w2" => Some(2),
        "x3" | "w3" => Some(3),
        "x4" | "w4" => Some(4),
        "x5" | "w5" => Some(5),
        "x6" | "w6" => Some(6),
        "x7" | "w7" => Some(7),
        // RISC-V
        "a0" => Some(0),
        "a1" => Some(1),
        "a2" => Some(2),
        "a3" => Some(3),
        "a4" => Some(4),
        "a5" => Some(5),
        "a6" => Some(6),
        "a7" => Some(7),
        _ => None,
    }
}

/// Checks if a register is a return value register.
///
/// Supports:
/// - x86-64: eax/rax
/// - ARM64: x0/w0
/// - RISC-V: a0
pub fn is_return_register(name: &str) -> bool {
    matches!(name, "eax" | "rax" | "x0" | "w0" | "a0")
}

/// Checks if a register is callee-saved (preserved across function calls).
///
/// These registers must be saved by called functions if they are modified.
/// They are commonly used in prologue/epilogue sequences.
///
/// Supports:
/// - x86-64 SysV ABI: rbp, rbx, r12-r15 (and 32-bit variants)
/// - ARM64 AAPCS64: x19-x28, x29 (fp), x30 (lr)
/// - RISC-V: s0-s11 (saved registers)
pub fn is_callee_saved_register(name: &str) -> bool {
    matches!(
        name,
        // x86-64 SysV ABI callee-saved: rbp, rbx, r12-r15
        "ebx" | "rbx" | "ebp" | "rbp" |
        "r12" | "r12d" | "r13" | "r13d" | "r14" | "r14d" | "r15" | "r15d" |
        // ARM64 AAPCS64 callee-saved: x19-x28, x29 (fp), x30 (lr)
        "x19" | "x20" | "x21" | "x22" | "x23" | "x24" | "x25" | "x26" | "x27" | "x28" |
        "x29" | "x30" |
        "w19" | "w20" | "w21" | "w22" | "w23" | "w24" | "w25" | "w26" | "w27" | "w28" |
        // RISC-V callee-saved registers (s0-s11)
        "s0" | "s1" | "s2" | "s3" | "s4" | "s5" | "s6" | "s7" | "s8" | "s9" | "s10" | "s11"
    )
}

/// Checks if a register is caller-saved (scratch register, not preserved).
///
/// These registers can be freely modified by called functions without saving.
///
/// Supports:
/// - x86-64 SysV ABI: rax, rcx, rdx, rsi, rdi, r8-r11
/// - ARM64 AAPCS64: x0-x18 (including x16/x17 IP0/IP1, x18 platform register)
/// - RISC-V: t0-t6 (temporaries), a0-a7 (arguments/return)
pub fn is_caller_saved_register(name: &str) -> bool {
    matches!(
        name,
        // x86-64 SysV ABI caller-saved
        "eax" | "rax" | "ecx" | "rcx" | "edx" | "rdx" |
        "esi" | "rsi" | "edi" | "rdi" |
        "r8" | "r8d" | "r9" | "r9d" | "r10" | "r10d" | "r11" | "r11d" |
        // ARM64 AAPCS64 caller-saved (x0-x18)
        "x0" | "x1" | "x2" | "x3" | "x4" | "x5" | "x6" | "x7" |
        "x8" | "x9" | "x10" | "x11" | "x12" | "x13" | "x14" | "x15" |
        "x16" | "x17" | "x18" |
        "w0" | "w1" | "w2" | "w3" | "w4" | "w5" | "w6" | "w7" |
        "w8" | "w9" | "w10" | "w11" | "w12" | "w13" | "w14" | "w15" |
        "w16" | "w17" | "w18" |
        // RISC-V caller-saved (temporaries and arguments)
        "t0" | "t1" | "t2" | "t3" | "t4" | "t5" | "t6" |
        "a0" | "a1" | "a2" | "a3" | "a4" | "a5" | "a6" | "a7"
    )
}

/// Checks if a register is a frame pointer.
///
/// Supports:
/// - x86-64: rbp/ebp/bp
/// - ARM64: x29/fp
/// - RISC-V: s0/fp
pub fn is_frame_pointer(name: &str) -> bool {
    matches!(name, "rbp" | "ebp" | "bp" | "x29" | "fp" | "s0")
}

/// Checks if a register is a stack pointer.
///
/// Supports:
/// - x86-64: rsp/esp/sp
/// - ARM64: sp
/// - RISC-V: sp
pub fn is_stack_pointer(name: &str) -> bool {
    matches!(name, "rsp" | "esp" | "sp")
}

/// Checks if a register is a temporary (can be eliminated during decompilation).
///
/// This includes all caller-saved registers: arguments, return values, and scratch.
/// Callee-saved registers are NOT temps as they persist across calls.
///
/// Supports:
/// - x86-64 SysV ABI: rax, rcx, rdx, rsi, rdi, r8-r11
/// - ARM64 AAPCS64: x0-x18
/// - RISC-V: a0-a7, t0-t6
pub fn is_temp_register(name: &str) -> bool {
    matches!(
        name,
        // x86-64 caller-saved registers (SysV ABI)
        // Note: rbx, rbp, r12-r15 are callee-saved and should NOT be temps
        // 64-bit
        "rax" | "rcx" | "rdx" | "rsi" | "rdi" | "r8" | "r9" | "r10" | "r11" |
        // 32-bit
        "eax" | "ecx" | "edx" | "esi" | "edi" | "r8d" | "r9d" | "r10d" | "r11d" |
        // 16-bit
        "ax" | "cx" | "dx" | "si" | "di" | "r8w" | "r9w" | "r10w" | "r11w" |
        // 8-bit
        "al" | "ah" | "cl" | "ch" | "dl" | "dh" | "sil" | "dil" |
        "r8b" | "r9b" | "r10b" | "r11b" |
        // ARM64 registers (x0-x18 and w0-w18 are caller-saved/temp)
        // Note: x19-x28 are callee-saved
        "x0" | "x1" | "x2" | "x3" | "x4" | "x5" | "x6" | "x7" |
        "x8" | "x9" | "x10" | "x11" | "x12" | "x13" | "x14" | "x15" |
        "x16" | "x17" | "x18" |
        "w0" | "w1" | "w2" | "w3" | "w4" | "w5" | "w6" | "w7" |
        "w8" | "w9" | "w10" | "w11" | "w12" | "w13" | "w14" | "w15" |
        "w16" | "w17" | "w18" |
        // RISC-V registers (a0-a7 are argument/caller-saved)
        "a0" | "a1" | "a2" | "a3" | "a4" | "a5" | "a6" | "a7" |
        "t0" | "t1" | "t2" | "t3" | "t4" | "t5" | "t6"
    )
}

/// Checks if a register is an argument-passing register.
///
/// These should be protected from removal even if they appear unused,
/// because they may be setting up arguments for tail calls via indirect jumps.
///
/// Supports:
/// - x86-64 SysV ABI: rdi, rsi, rdx, rcx, r8, r9 (and their 32-bit variants)
/// - ARM64 AAPCS64: x0-x7 / w0-w7
/// - RISC-V: a0-a7
pub fn is_argument_register(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        // x86-64 argument registers (System V ABI)
        "rdi" | "edi" | "rsi" | "esi" | "rdx" | "edx" | "rcx" | "ecx" |
        "r8" | "r8d" | "r9" | "r9d" |
        // ARM64 argument registers
        "x0" | "x1" | "x2" | "x3" | "x4" | "x5" | "x6" | "x7" |
        "w0" | "w1" | "w2" | "w3" | "w4" | "w5" | "w6" | "w7" |
        // RISC-V argument registers
        "a0" | "a1" | "a2" | "a3" | "a4" | "a5" | "a6" | "a7"
    )
}

/// Normalizes an x86-64 register name to its 64-bit form.
///
/// This maps partial register names to their full 64-bit counterparts:
/// - 8-bit: al, ah, bl, bh, cl, ch, dl, dh → rax, rbx, rcx, rdx
/// - 8-bit: sil, dil, bpl, spl → rsi, rdi, rbp, rsp
/// - 8-bit: r8b-r15b → r8-r15
/// - 16-bit: ax, bx, cx, dx, si, di, bp, sp → rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp
/// - 16-bit: r8w-r15w → r8-r15
/// - 32-bit: eax, ebx, ecx, edx, esi, edi, ebp, esp → rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp
/// - 32-bit: r8d-r15d → r8-r15
///
/// Returns Some((normalized_name, original_size)) if the register is a known x86-64 GPR,
/// or None if it's not a standard GPR (like rip, xmm0, etc.).
pub fn normalize_x86_64_register(name: &str, size_bytes: u8) -> Option<(&'static str, u8)> {
    // Map partial registers to their 64-bit form
    let result = match name {
        // 64-bit registers - already normalized
        "rax" => ("rax", size_bytes),
        "rbx" => ("rbx", size_bytes),
        "rcx" => ("rcx", size_bytes),
        "rdx" => ("rdx", size_bytes),
        "rsi" => ("rsi", size_bytes),
        "rdi" => ("rdi", size_bytes),
        "rbp" => ("rbp", size_bytes),
        "rsp" => ("rsp", size_bytes),
        "r8" => ("r8", size_bytes),
        "r9" => ("r9", size_bytes),
        "r10" => ("r10", size_bytes),
        "r11" => ("r11", size_bytes),
        "r12" => ("r12", size_bytes),
        "r13" => ("r13", size_bytes),
        "r14" => ("r14", size_bytes),
        "r15" => ("r15", size_bytes),

        // 8-bit low registers (al, bl, cl, dl)
        "al" => ("rax", 1),
        "bl" => ("rbx", 1),
        "cl" => ("rcx", 1),
        "dl" => ("rdx", 1),

        // 8-bit high registers (ah, bh, ch, dh)
        "ah" => ("rax", 1),
        "bh" => ("rbx", 1),
        "ch" => ("rcx", 1),
        "dh" => ("rdx", 1),

        // 8-bit extended registers
        "sil" => ("rsi", 1),
        "dil" => ("rdi", 1),
        "bpl" => ("rbp", 1),
        "spl" => ("rsp", 1),
        "r8b" => ("r8", 1),
        "r9b" => ("r9", 1),
        "r10b" => ("r10", 1),
        "r11b" => ("r11", 1),
        "r12b" => ("r12", 1),
        "r13b" => ("r13", 1),
        "r14b" => ("r14", 1),
        "r15b" => ("r15", 1),

        // 16-bit registers
        "ax" => ("rax", 2),
        "bx" => ("rbx", 2),
        "cx" => ("rcx", 2),
        "dx" => ("rdx", 2),
        "si" => ("rsi", 2),
        "di" => ("rdi", 2),
        "bp" => ("rbp", 2),
        "sp" => ("rsp", 2),
        "r8w" => ("r8", 2),
        "r9w" => ("r9", 2),
        "r10w" => ("r10", 2),
        "r11w" => ("r11", 2),
        "r12w" => ("r12", 2),
        "r13w" => ("r13", 2),
        "r14w" => ("r14", 2),
        "r15w" => ("r15", 2),

        // 32-bit registers
        "eax" => ("rax", 4),
        "ebx" => ("rbx", 4),
        "ecx" => ("rcx", 4),
        "edx" => ("rdx", 4),
        "esi" => ("rsi", 4),
        "edi" => ("rdi", 4),
        "ebp" => ("rbp", 4),
        "esp" => ("rsp", 4),
        "r8d" => ("r8", 4),
        "r9d" => ("r9", 4),
        "r10d" => ("r10", 4),
        "r11d" => ("r11", 4),
        "r12d" => ("r12", 4),
        "r13d" => ("r13", 4),
        "r14d" => ("r14", 4),
        "r15d" => ("r15", 4),

        // Not a partial x86-64 GPR
        _ => return None,
    };

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arg_register_x86_64() {
        assert_eq!(get_arg_register_index("rdi"), Some(0));
        assert_eq!(get_arg_register_index("rsi"), Some(1));
        assert_eq!(get_arg_register_index("rdx"), Some(2));
        assert_eq!(get_arg_register_index("rcx"), Some(3));
        assert_eq!(get_arg_register_index("r8"), Some(4));
        assert_eq!(get_arg_register_index("r9"), Some(5));
        // 32-bit variants
        assert_eq!(get_arg_register_index("edi"), Some(0));
        assert_eq!(get_arg_register_index("r8d"), Some(4));
    }

    #[test]
    fn test_arg_register_arm64() {
        assert_eq!(get_arg_register_index("x0"), Some(0));
        assert_eq!(get_arg_register_index("x7"), Some(7));
        assert_eq!(get_arg_register_index("w0"), Some(0));
        assert_eq!(get_arg_register_index("w7"), Some(7));
    }

    #[test]
    fn test_arg_register_riscv() {
        assert_eq!(get_arg_register_index("a0"), Some(0));
        assert_eq!(get_arg_register_index("a7"), Some(7));
    }

    #[test]
    fn test_non_arg_register() {
        assert_eq!(get_arg_register_index("rbx"), None);
        assert_eq!(get_arg_register_index("x19"), None);
        assert_eq!(get_arg_register_index("s0"), None);
    }

    #[test]
    fn test_return_register() {
        assert!(is_return_register("rax"));
        assert!(is_return_register("eax"));
        assert!(is_return_register("x0"));
        assert!(is_return_register("w0"));
        assert!(is_return_register("a0"));
        assert!(!is_return_register("rbx"));
    }

    #[test]
    fn test_callee_saved() {
        // x86-64
        assert!(is_callee_saved_register("rbx"));
        assert!(is_callee_saved_register("rbp"));
        assert!(is_callee_saved_register("r12"));
        assert!(!is_callee_saved_register("rax"));

        // ARM64
        assert!(is_callee_saved_register("x19"));
        assert!(is_callee_saved_register("x29"));
        assert!(!is_callee_saved_register("x0"));

        // RISC-V
        assert!(is_callee_saved_register("s0"));
        assert!(is_callee_saved_register("s11"));
        assert!(!is_callee_saved_register("a0"));
    }

    #[test]
    fn test_frame_pointer() {
        assert!(is_frame_pointer("rbp"));
        assert!(is_frame_pointer("ebp"));
        assert!(is_frame_pointer("x29"));
        assert!(is_frame_pointer("fp"));
        assert!(is_frame_pointer("s0"));
        assert!(!is_frame_pointer("rsp"));
    }

    #[test]
    fn test_stack_pointer() {
        assert!(is_stack_pointer("rsp"));
        assert!(is_stack_pointer("esp"));
        assert!(is_stack_pointer("sp"));
        assert!(!is_stack_pointer("rbp"));
    }

    #[test]
    fn test_normalize_x86_64_register_8bit() {
        assert_eq!(normalize_x86_64_register("al", 1), Some(("rax", 1)));
        assert_eq!(normalize_x86_64_register("ah", 1), Some(("rax", 1)));
        assert_eq!(normalize_x86_64_register("bl", 1), Some(("rbx", 1)));
        assert_eq!(normalize_x86_64_register("bh", 1), Some(("rbx", 1)));
        assert_eq!(normalize_x86_64_register("cl", 1), Some(("rcx", 1)));
        assert_eq!(normalize_x86_64_register("ch", 1), Some(("rcx", 1)));
        assert_eq!(normalize_x86_64_register("dl", 1), Some(("rdx", 1)));
        assert_eq!(normalize_x86_64_register("dh", 1), Some(("rdx", 1)));
        assert_eq!(normalize_x86_64_register("sil", 1), Some(("rsi", 1)));
        assert_eq!(normalize_x86_64_register("dil", 1), Some(("rdi", 1)));
        assert_eq!(normalize_x86_64_register("bpl", 1), Some(("rbp", 1)));
        assert_eq!(normalize_x86_64_register("spl", 1), Some(("rsp", 1)));
        assert_eq!(normalize_x86_64_register("r8b", 1), Some(("r8", 1)));
        assert_eq!(normalize_x86_64_register("r15b", 1), Some(("r15", 1)));
    }

    #[test]
    fn test_normalize_x86_64_register_16bit() {
        assert_eq!(normalize_x86_64_register("ax", 2), Some(("rax", 2)));
        assert_eq!(normalize_x86_64_register("bx", 2), Some(("rbx", 2)));
        assert_eq!(normalize_x86_64_register("cx", 2), Some(("rcx", 2)));
        assert_eq!(normalize_x86_64_register("dx", 2), Some(("rdx", 2)));
        assert_eq!(normalize_x86_64_register("si", 2), Some(("rsi", 2)));
        assert_eq!(normalize_x86_64_register("di", 2), Some(("rdi", 2)));
        assert_eq!(normalize_x86_64_register("bp", 2), Some(("rbp", 2)));
        assert_eq!(normalize_x86_64_register("sp", 2), Some(("rsp", 2)));
        assert_eq!(normalize_x86_64_register("r8w", 2), Some(("r8", 2)));
        assert_eq!(normalize_x86_64_register("r15w", 2), Some(("r15", 2)));
    }

    #[test]
    fn test_normalize_x86_64_register_32bit() {
        assert_eq!(normalize_x86_64_register("eax", 4), Some(("rax", 4)));
        assert_eq!(normalize_x86_64_register("ebx", 4), Some(("rbx", 4)));
        assert_eq!(normalize_x86_64_register("ecx", 4), Some(("rcx", 4)));
        assert_eq!(normalize_x86_64_register("edx", 4), Some(("rdx", 4)));
        assert_eq!(normalize_x86_64_register("esi", 4), Some(("rsi", 4)));
        assert_eq!(normalize_x86_64_register("edi", 4), Some(("rdi", 4)));
        assert_eq!(normalize_x86_64_register("ebp", 4), Some(("rbp", 4)));
        assert_eq!(normalize_x86_64_register("esp", 4), Some(("rsp", 4)));
        assert_eq!(normalize_x86_64_register("r8d", 4), Some(("r8", 4)));
        assert_eq!(normalize_x86_64_register("r15d", 4), Some(("r15", 4)));
    }

    #[test]
    fn test_normalize_x86_64_register_64bit() {
        // 64-bit registers should remain unchanged
        assert_eq!(normalize_x86_64_register("rax", 8), Some(("rax", 8)));
        assert_eq!(normalize_x86_64_register("rbx", 8), Some(("rbx", 8)));
        assert_eq!(normalize_x86_64_register("r8", 8), Some(("r8", 8)));
        assert_eq!(normalize_x86_64_register("r15", 8), Some(("r15", 8)));
    }

    #[test]
    fn test_normalize_x86_64_register_non_gpr() {
        // Non-GPR registers should return None
        assert_eq!(normalize_x86_64_register("xmm0", 16), None);
        assert_eq!(normalize_x86_64_register("rip", 8), None);
        assert_eq!(normalize_x86_64_register("cs", 2), None);
    }

    // === CallingConvention tests ===

    #[test]
    fn test_x86_64_sysv_args() {
        let cc = CallingConvention::X86_64SystemV;
        let args = cc.argument_registers();
        assert_eq!(args.len(), 6);
        assert_eq!(args[0], "rdi");
        assert_eq!(args[5], "r9");
    }

    #[test]
    fn test_arm64_aapcs_args() {
        let cc = CallingConvention::Arm64Aapcs;
        let args = cc.argument_registers();
        assert_eq!(args.len(), 8);
        assert_eq!(args[0], "x0");
        assert_eq!(args[7], "x7");
    }

    #[test]
    fn test_riscv_args() {
        let cc = CallingConvention::RiscVLp64d;
        let args = cc.argument_registers();
        assert_eq!(args.len(), 8);
        assert_eq!(args[0], "a0");
        assert_eq!(args[7], "a7");
    }

    #[test]
    fn test_calling_convention_stack_alignment() {
        assert_eq!(CallingConvention::X86_64SystemV.stack_alignment(), 16);
        assert_eq!(CallingConvention::Arm64Aapcs.stack_alignment(), 16);
        assert_eq!(CallingConvention::RiscVLp64d.stack_alignment(), 16);
        assert_eq!(CallingConvention::RiscVIlp32.stack_alignment(), 8);
    }

    #[test]
    fn test_calling_convention_red_zone() {
        assert_eq!(CallingConvention::X86_64SystemV.red_zone_size(), 128);
        assert_eq!(CallingConvention::X86_64Win64.red_zone_size(), 0);
        assert_eq!(CallingConvention::Arm64Aapcs.red_zone_size(), 0);
    }

    #[test]
    fn test_calling_convention_link_register() {
        assert_eq!(CallingConvention::X86_64SystemV.link_register(), None);
        assert_eq!(CallingConvention::Arm64Aapcs.link_register(), Some("x30"));
        assert_eq!(CallingConvention::RiscVLp64d.link_register(), Some("ra"));
    }

    // === ARM64 module tests ===

    #[test]
    fn test_arm64_ip_registers() {
        assert!(arm64::is_ip_register("x16"));
        assert!(arm64::is_ip_register("x17"));
        assert!(arm64::is_ip_register("ip0"));
        assert!(!arm64::is_ip_register("x0"));
    }

    #[test]
    fn test_arm64_condition_names() {
        assert_eq!(arm64::condition_name(0x0), "eq");
        assert_eq!(arm64::condition_name(0x1), "ne");
        assert_eq!(arm64::condition_name(0xA), "ge");
        assert_eq!(arm64::condition_name(0xB), "lt");
    }

    #[test]
    fn test_arm64_invert_condition() {
        assert_eq!(arm64::invert_condition(0x0), 0x1); // eq -> ne
        assert_eq!(arm64::invert_condition(0x1), 0x0); // ne -> eq
        assert_eq!(arm64::invert_condition(0xA), 0xB); // ge -> lt
    }

    // === RISC-V module tests ===

    #[test]
    fn test_riscv_register_names() {
        assert_eq!(riscv::register_abi_name(0), "zero");
        assert_eq!(riscv::register_abi_name(1), "ra");
        assert_eq!(riscv::register_abi_name(2), "sp");
        assert_eq!(riscv::register_abi_name(10), "a0");
        assert_eq!(riscv::register_abi_name(17), "a7");
    }

    #[test]
    fn test_riscv_fp_register_names() {
        assert_eq!(riscv::fp_register_abi_name(0), "ft0");
        assert_eq!(riscv::fp_register_abi_name(10), "fa0");
        assert_eq!(riscv::fp_register_abi_name(17), "fa7");
    }

    #[test]
    fn test_riscv_special_registers() {
        assert!(riscv::is_zero_register("zero"));
        assert!(riscv::is_zero_register("x0"));
        assert!(riscv::is_global_pointer("gp"));
        assert!(riscv::is_thread_pointer("tp"));
    }
}
