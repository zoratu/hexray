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
}
