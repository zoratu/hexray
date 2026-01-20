//! Property-based tests for instruction decoders.
//!
//! These tests verify invariants that should hold for all decoders:
//! - Decoding never panics on arbitrary input
//! - Decoded instruction size is within valid bounds
//! - Decoded instructions have valid structure
//! - Deterministic decoding (same input → same output)

use proptest::prelude::*;

use hexray_disasm::traits::Disassembler;
use hexray_disasm::x86_64::X86_64Disassembler;

// =============================================================================
// X86_64 Decoder Properties
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10000))]

    /// Decoding arbitrary bytes should never panic.
    #[test]
    fn x86_64_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..32)) {
        let disasm = X86_64Disassembler::new();
        // This should not panic - errors are fine
        let _ = disasm.decode_instruction(&bytes, 0x1000);
    }

    /// Successfully decoded instructions have valid size.
    #[test]
    fn x86_64_decoded_size_is_valid(bytes in prop::collection::vec(any::<u8>(), 1..32)) {
        let disasm = X86_64Disassembler::new();
        if let Ok(decoded) = disasm.decode_instruction(&bytes, 0x1000) {
            // x86_64 instructions are 1-15 bytes
            prop_assert!(decoded.size >= 1, "Instruction size must be at least 1");
            prop_assert!(decoded.size <= 15, "Instruction size must be at most 15");
            prop_assert!(decoded.size <= bytes.len(), "Instruction size cannot exceed input length");
        }
    }

    /// Decoding is deterministic: same input always produces same output.
    #[test]
    fn x86_64_decode_is_deterministic(bytes in prop::collection::vec(any::<u8>(), 1..32)) {
        let disasm = X86_64Disassembler::new();
        let result1 = disasm.decode_instruction(&bytes, 0x1000);
        let result2 = disasm.decode_instruction(&bytes, 0x1000);

        match (&result1, &result2) {
            (Ok(d1), Ok(d2)) => {
                prop_assert_eq!(d1.size, d2.size, "Sizes should match");
                prop_assert_eq!(&d1.instruction.mnemonic, &d2.instruction.mnemonic, "Mnemonics should match");
                prop_assert_eq!(d1.instruction.operands.len(), d2.instruction.operands.len(), "Operand count should match");
            }
            (Err(_), Err(_)) => {
                // Both failed - this is consistent
            }
            _ => {
                prop_assert!(false, "Decode results should be consistent: got {:?} and {:?}", result1, result2);
            }
        }
    }

    /// Successfully decoded instructions have valid address.
    #[test]
    fn x86_64_decoded_address_matches(
        bytes in prop::collection::vec(any::<u8>(), 1..32),
        addr in 0x1000u64..0xFFFF_FFFF_FFFF_0000u64
    ) {
        let disasm = X86_64Disassembler::new();
        if let Ok(decoded) = disasm.decode_instruction(&bytes, addr) {
            prop_assert_eq!(decoded.instruction.address, addr, "Decoded address should match input address");
        }
    }

    /// Decoded instructions have non-empty mnemonics.
    #[test]
    fn x86_64_decoded_has_mnemonic(bytes in prop::collection::vec(any::<u8>(), 1..32)) {
        let disasm = X86_64Disassembler::new();
        if let Ok(decoded) = disasm.decode_instruction(&bytes, 0x1000) {
            prop_assert!(!decoded.instruction.mnemonic.is_empty(), "Mnemonic should not be empty");
        }
    }

    /// Sequential decoding covers all bytes (no gaps or overlaps).
    #[test]
    fn x86_64_sequential_decode_covers_all_bytes(bytes in prop::collection::vec(any::<u8>(), 16..128)) {
        let disasm = X86_64Disassembler::new();
        let mut offset = 0;
        let mut covered = vec![false; bytes.len()];
        let mut iterations = 0;
        let max_iterations = bytes.len() + 1;

        while offset < bytes.len() && iterations < max_iterations {
            iterations += 1;

            match disasm.decode_instruction(&bytes[offset..], 0x1000 + offset as u64) {
                Ok(inst) => {
                    prop_assert!(inst.size > 0, "Decoded size must be positive");
                    // Mark bytes as covered
                    let end = (offset + inst.size).min(bytes.len());
                    for (i, covered_byte) in covered[offset..end].iter_mut().enumerate() {
                        prop_assert!(!*covered_byte, "Byte {} covered twice", offset + i);
                        *covered_byte = true;
                    }
                    offset += inst.size;
                }
                Err(_) => {
                    // Skip one byte on decode error
                    covered[offset] = true;
                    offset += 1;
                }
            }
        }

        // All bytes should be covered
        for (i, &c) in covered.iter().enumerate() {
            prop_assert!(c, "Byte {} was not covered", i);
        }
    }
}

// =============================================================================
// Specific Instruction Pattern Tests
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// REX prefix handling: REX.W should not crash.
    #[test]
    fn x86_64_rex_prefix_handling(
        rex in 0x40u8..=0x4F,
        opcode in any::<u8>(),
        modrm in any::<u8>()
    ) {
        let disasm = X86_64Disassembler::new();
        let bytes = [rex, opcode, modrm];
        let _ = disasm.decode_instruction(&bytes, 0x1000);
    }

    /// VEX prefix handling: 2-byte and 3-byte VEX should not crash.
    #[test]
    fn x86_64_vex_prefix_handling(
        vex_type in prop::bool::ANY,
        b1 in any::<u8>(),
        b2 in any::<u8>(),
        b3 in any::<u8>(),
        opcode in any::<u8>()
    ) {
        let disasm = X86_64Disassembler::new();
        let bytes = if vex_type {
            // 2-byte VEX: C5 xx opcode
            vec![0xC5, b1, opcode, b2, b3]
        } else {
            // 3-byte VEX: C4 xx xx opcode
            vec![0xC4, b1, b2, opcode, b3]
        };
        let _ = disasm.decode_instruction(&bytes, 0x1000);
    }

    /// EVEX prefix handling (AVX-512): should not crash.
    #[test]
    fn x86_64_evex_prefix_handling(
        p0 in any::<u8>(),
        p1 in any::<u8>(),
        p2 in any::<u8>(),
        opcode in any::<u8>(),
        modrm in any::<u8>()
    ) {
        let disasm = X86_64Disassembler::new();
        // EVEX prefix: 62 P0 P1 P2 opcode modrm
        let bytes = [0x62, p0, p1, p2, opcode, modrm];
        let _ = disasm.decode_instruction(&bytes, 0x1000);
    }

    /// Escape sequences (0F, 0F38, 0F3A) should not crash.
    #[test]
    fn x86_64_escape_sequences(
        escape_type in 0u8..3,
        opcode in any::<u8>(),
        modrm in any::<u8>(),
        extra in any::<u8>()
    ) {
        let disasm = X86_64Disassembler::new();
        let bytes = match escape_type {
            0 => vec![0x0F, opcode, modrm, extra],           // 0F escape
            1 => vec![0x0F, 0x38, opcode, modrm, extra],     // 0F 38 escape
            _ => vec![0x0F, 0x3A, opcode, modrm, extra],     // 0F 3A escape
        };
        let _ = disasm.decode_instruction(&bytes, 0x1000);
    }
}

// =============================================================================
// ARM64 Decoder Properties (if feature enabled)
// =============================================================================

#[cfg(feature = "arm64")]
mod arm64_tests {
    use super::*;
    use hexray_disasm::arm64::Arm64Disassembler;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10000))]

        /// ARM64 decoding never panics on arbitrary 4-byte input.
        #[test]
        fn arm64_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 4..36)) {
            let disasm = Arm64Disassembler::new();
            let _ = disasm.decode_instruction(&bytes, 0x1000);
        }

        /// ARM64 instructions are always 4 bytes.
        #[test]
        fn arm64_decoded_size_is_4(bytes in prop::collection::vec(any::<u8>(), 4..36)) {
            let disasm = Arm64Disassembler::new();
            if let Ok(decoded) = disasm.decode_instruction(&bytes, 0x1000) {
                prop_assert_eq!(decoded.size, 4, "ARM64 instructions are always 4 bytes");
            }
        }

        /// ARM64 address alignment: addresses should be 4-byte aligned.
        #[test]
        fn arm64_address_alignment(
            bytes in prop::collection::vec(any::<u8>(), 4..36),
            addr_base in 0x1000u64..0xFFFF_FFFF_FFFF_0000u64
        ) {
            let disasm = Arm64Disassembler::new();
            let aligned_addr = addr_base & !3; // Align to 4 bytes
            if let Ok(decoded) = disasm.decode_instruction(&bytes, aligned_addr) {
                prop_assert_eq!(decoded.instruction.address % 4, 0, "ARM64 addresses should be 4-byte aligned");
            }
        }

        /// ARM64 decoding is deterministic.
        #[test]
        fn arm64_decode_is_deterministic(bytes in prop::collection::vec(any::<u8>(), 4..36)) {
            let disasm = Arm64Disassembler::new();
            let result1 = disasm.decode_instruction(&bytes, 0x1000);
            let result2 = disasm.decode_instruction(&bytes, 0x1000);

            match (&result1, &result2) {
                (Ok(d1), Ok(d2)) => {
                    prop_assert_eq!(&d1.instruction.mnemonic, &d2.instruction.mnemonic);
                    prop_assert_eq!(d1.instruction.operands.len(), d2.instruction.operands.len());
                }
                (Err(_), Err(_)) => {}
                _ => prop_assert!(false, "Results should be consistent"),
            }
        }
    }
}

// =============================================================================
// RISC-V Decoder Properties (if feature enabled)
// =============================================================================

#[cfg(feature = "riscv")]
mod riscv_tests {
    use super::*;
    use hexray_disasm::riscv::RiscVDisassembler;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10000))]

        /// RISC-V decoding never panics.
        #[test]
        fn riscv_decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 2..32)) {
            let disasm = RiscVDisassembler::new(); // RV64
            let _ = disasm.decode_instruction(&bytes, 0x1000);
        }

        /// RISC-V instruction size is 2 or 4 bytes (compressed or standard).
        #[test]
        fn riscv_decoded_size_is_valid(bytes in prop::collection::vec(any::<u8>(), 2..32)) {
            let disasm = RiscVDisassembler::new();
            if let Ok(decoded) = disasm.decode_instruction(&bytes, 0x1000) {
                prop_assert!(
                    decoded.size == 2 || decoded.size == 4,
                    "RISC-V instructions are 2 (compressed) or 4 bytes, got {}",
                    decoded.size
                );
            }
        }

        /// Compressed instructions (bits 0-1 != 11) should decode to 2 bytes.
        #[test]
        fn riscv_compressed_detection(
            low_byte in any::<u8>().prop_filter("not standard", |b| (b & 0b11) != 0b11),
            high_byte in any::<u8>()
        ) {
            let disasm = RiscVDisassembler::new();
            let bytes = [low_byte, high_byte, 0, 0];
            if let Ok(decoded) = disasm.decode_instruction(&bytes, 0x1000) {
                // If low bits are not 11, it should be compressed (2 bytes)
                prop_assert_eq!(decoded.size, 2, "Low bits {:02b} indicate compressed instruction", low_byte & 0b11);
            }
        }

        /// RISC-V decoding is deterministic.
        #[test]
        fn riscv_decode_is_deterministic(bytes in prop::collection::vec(any::<u8>(), 2..32)) {
            let disasm = RiscVDisassembler::new();
            let result1 = disasm.decode_instruction(&bytes, 0x1000);
            let result2 = disasm.decode_instruction(&bytes, 0x1000);

            match (&result1, &result2) {
                (Ok(d1), Ok(d2)) => {
                    prop_assert_eq!(d1.size, d2.size);
                    prop_assert_eq!(&d1.instruction.mnemonic, &d2.instruction.mnemonic);
                }
                (Err(_), Err(_)) => {}
                _ => prop_assert!(false, "Results should be consistent"),
            }
        }
    }
}
