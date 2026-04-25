//! Property-based tests for instruction decoders.
//!
//! These tests verify invariants that should hold for all decoders:
//! - Decoding never panics on arbitrary input
//! - Decoded instruction size is within valid bounds
//! - Decoded instructions have valid structure
//! - Deterministic decoding (same input → same output)

#[cfg(any(feature = "x86_64", feature = "arm64", feature = "riscv"))]
use proptest::prelude::*;

#[cfg(any(feature = "x86_64", feature = "arm64", feature = "riscv"))]
use hexray_disasm::traits::Disassembler;

#[cfg(feature = "x86_64")]
use hexray_disasm::x86_64::X86_64Disassembler;

// =============================================================================
// X86_64 Decoder Properties
// =============================================================================

#[cfg(feature = "x86_64")]
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

#[cfg(feature = "x86_64")]
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

// =============================================================================
// CUDA SASS Decoder Properties
// =============================================================================

#[cfg(feature = "cuda")]
mod cuda_props {
    use proptest::prelude::*;

    use hexray_disasm::cuda::sass::{
        bits::SassWord, control::ControlBits, SassDisassembler, SASS_INSTRUCTION_SIZE,
    };
    use hexray_disasm::traits::Disassembler;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        /// `SassWord::from_bytes(x).to_bytes() == x` on any 16-byte input.
        #[test]
        fn sass_word_byte_roundtrip(bytes in prop::array::uniform16(any::<u8>())) {
            let w = SassWord::from_bytes(&bytes);
            prop_assert_eq!(w.to_bytes(), bytes);
        }

        /// The 21 meaningful bits of the control slot round-trip cleanly.
        /// Bits 21..=22 are observed zero in real cubins; the decoder
        /// intentionally discards them, so the round-trip property holds
        /// only over the low 21 bits.
        #[test]
        fn control_bits_roundtrip(raw in 0u32..(1 << 21)) {
            let cb = ControlBits::from_raw(raw);
            prop_assert_eq!(cb.to_raw(), raw);
        }

        /// from_raw masks reserved bits — any 32-bit input round-trips as
        /// from_raw(x).to_raw() == x & 0x1F_FFFF.
        #[test]
        fn control_bits_masks_reserved(raw in any::<u32>()) {
            let cb = ControlBits::from_raw(raw);
            prop_assert_eq!(cb.to_raw(), raw & 0x1F_FFFF);
        }

        /// `ControlBits::from_raw` is total — no panics on any 32-bit input,
        /// even though only 23 bits are meaningful.
        #[test]
        fn control_bits_from_raw_total(raw in any::<u32>()) {
            let _ = ControlBits::from_raw(raw);
        }

        /// `bit_range` is total over any contiguous slice with width ≤ 64.
        /// Tests random low/high pairs along with random 128-bit words.
        #[test]
        fn bit_range_total(low_high in any::<u64>(), high in any::<u64>(), lo in 0u32..128, width in 1u32..=64) {
            let hi = (lo + width - 1).min(127);
            if hi < lo { return Ok(()); }
            let w = SassWord { low: low_high, high };
            let _ = w.bit_range(lo, hi);
        }

        /// Decoder never panics on arbitrary 16-byte input.
        #[test]
        fn sass_decode_never_panics(bytes in prop::array::uniform16(any::<u8>())) {
            let d = SassDisassembler::ampere();
            // Ok or Err — never panic.
            let _ = d.decode_instruction(&bytes, 0x1000);
        }

        /// `disassemble_block` produces exactly `bytes.len() / 16` results
        /// when the input is 16-aligned, and never desyncs (every result
        /// represents one 16-byte slot).
        #[test]
        fn block_walker_strides_by_16(blocks in 1usize..32) {
            // Synthesise random byte streams that are exact multiples of 16.
            let mut bytes = Vec::with_capacity(blocks * 16);
            for i in 0..(blocks * 16) {
                bytes.push((i as u32).wrapping_mul(2654435761) as u8);
            }
            let d = SassDisassembler::ampere();
            let results = d.disassemble_block(&bytes, 0);
            prop_assert_eq!(
                results.len(),
                blocks,
                "16-aligned input must produce exactly len/16 result slots"
            );
            for (i, r) in results.iter().enumerate() {
                if let Ok(ins) = r {
                    prop_assert_eq!(ins.size, SASS_INSTRUCTION_SIZE);
                    prop_assert_eq!(ins.address, (i * SASS_INSTRUCTION_SIZE) as u64);
                }
            }
        }

        /// On non-16-aligned input, `disassemble_block` reports a single
        /// trailing Truncated error rather than skipping bytes silently.
        #[test]
        fn block_walker_flags_trailing_partial(suffix_len in 1usize..16) {
            let mut bytes = vec![0u8; 16 + suffix_len];
            for (i, slot) in bytes.iter_mut().enumerate() {
                *slot = (i as u32).wrapping_mul(0x9E37_79B1) as u8;
            }
            let d = SassDisassembler::ampere();
            let results = d.disassemble_block(&bytes, 0);
            prop_assert_eq!(results.len(), 2);
            let truncated = matches!(
                results[1],
                Err(hexray_disasm::DecodeError::Truncated { .. })
            );
            prop_assert!(truncated, "expected trailing Truncated error");
        }

        /// Decoding is deterministic.
        #[test]
        fn sass_decode_is_deterministic(bytes in prop::array::uniform16(any::<u8>())) {
            let d = SassDisassembler::ampere();
            let a = d.decode_instruction(&bytes, 0x1000);
            let b = d.decode_instruction(&bytes, 0x1000);
            match (&a, &b) {
                (Ok(x), Ok(y)) => {
                    prop_assert_eq!(&x.instruction.mnemonic, &y.instruction.mnemonic);
                    prop_assert_eq!(&x.instruction.bytes, &y.instruction.bytes);
                    prop_assert_eq!(x.instruction.guard.is_some(), y.instruction.guard.is_some());
                }
                (Err(_), Err(_)) => {}
                _ => prop_assert!(false, "decode determinism violated"),
            }
        }

        /// Decoded instructions always have `size == 16` when Ok.
        #[test]
        fn sass_decoded_size_is_16(bytes in prop::array::uniform16(any::<u8>())) {
            let d = SassDisassembler::ampere();
            if let Ok(decoded) = d.decode_instruction(&bytes, 0x1000) {
                prop_assert_eq!(decoded.size, SASS_INSTRUCTION_SIZE);
                prop_assert_eq!(decoded.instruction.size, SASS_INSTRUCTION_SIZE);
                prop_assert_eq!(decoded.instruction.bytes.len(), SASS_INSTRUCTION_SIZE);
            }
        }
    }
}
