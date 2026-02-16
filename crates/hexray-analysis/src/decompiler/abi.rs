//! ABI-specific register and calling convention helpers.
//!
//! This module provides architecture-neutral functions for determining
//! register roles across different ABIs (x86-64 System V, ARM64 AAPCS64, RISC-V).

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
}
