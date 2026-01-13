//! ARM64 SME (Scalable Matrix Extension) instruction decoder.
//!
//! SME introduces matrix operations with the ZA register array:
//! - ZA: 2D array of vector-length x vector-length bytes
//! - Streaming SVE mode for matrix operations
//!
//! Key SME instructions:
//! - SMSTART/SMSTOP: Enable/disable streaming SVE mode
//! - ZERO {ZA}: Zero the ZA array
//! - LDR/STR ZA[...]: Load/store ZA rows
//! - MOVA: Move to/from ZA tiles
//! - FMOPA/FMOPS: FP outer product accumulate/subtract
//! - BFMOPA: BFloat16 outer product
//! - SMOPA/UMOPA: Integer outer product

use crate::DecodedInstruction;
use hexray_core::{
    Architecture, Instruction, MemoryRef, Operand, Operation,
    Register, RegisterClass,
    register::arm64,
};

/// SME decoder implementation.
pub struct SmeDecoder;

impl SmeDecoder {
    /// Create a new SME decoder.
    pub fn new() -> Self {
        Self
    }

    /// Check if an instruction is an SME instruction.
    pub fn is_sme_instruction(insn: u32) -> bool {
        let bits_31_24 = (insn >> 24) & 0xFF;
        let bits_23_21 = (insn >> 21) & 0x7;

        // SME outer product instructions: 1000_0001_xxxx_xxxx...
        // bits[31:25] = 1000_000
        if (insn >> 25) == 0b1000000 {
            return true;
        }

        // SMSTART/SMSTOP: 1101_0101_0000_0011_0100_xxxx...
        // These are MSR instructions to SVCR register
        if bits_31_24 == 0xD5 {
            let bits_23_16 = (insn >> 16) & 0xFF;
            let bits_15_12 = (insn >> 12) & 0xF;
            // MSR SVCR, Xt or MSR SVCRZA/SVCRMA, #imm
            if bits_23_16 == 0x03 && bits_15_12 == 0x4 {
                return true;
            }
        }

        // SME ZA memory operations (LDR/STR ZA): 1110_0001_00xx_xxxx...
        if bits_31_24 == 0xE1 && bits_23_21 == 0b000 {
            return true;
        }

        // ZERO {ZA}: 1100_0000_0000_1000_0000_0000_0000_0000
        // bits[31:24] = 0xC0, bits[23:16] = 0x08
        if bits_31_24 == 0xC0 {
            let bits_23_16 = (insn >> 16) & 0xFF;
            if bits_23_16 == 0x08 {
                return true;
            }
        }

        // SME MOVA instructions: 1100_0000_xxxx_xxxx...
        if bits_31_24 == 0xC0 {
            return true;
        }

        false
    }

    /// Decode an SME instruction.
    pub fn decode(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Option<DecodedInstruction> {
        let bits_31_24 = (insn >> 24) & 0xFF;

        // Check for SMSTART/SMSTOP first (MSR encoding)
        if bits_31_24 == 0xD5 {
            return self.decode_sme_control(insn, address, bytes);
        }

        // Check for ZERO {ZA}
        if bits_31_24 == 0xC0 {
            let bits_23_16 = (insn >> 16) & 0xFF;
            if bits_23_16 == 0x08 {
                return self.decode_sme_zero_za(insn, address, bytes);
            }
            // MOVA instructions
            return self.decode_sme_mova(insn, address, bytes);
        }

        // Check for ZA memory operations
        if bits_31_24 == 0xE1 {
            return self.decode_sme_za_memory(insn, address, bytes);
        }

        // Check for outer product instructions
        if (insn >> 25) == 0b1000000 {
            return self.decode_sme_outer_product(insn, address, bytes);
        }

        None
    }

    /// Decode SMSTART/SMSTOP instructions.
    fn decode_sme_control(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Option<DecodedInstruction> {
        // SMSTART/SMSTOP are encoded as MSR to SVCR-related registers
        // SMSTART: 1101_0101_0000_0011_0100_0xxx_01x_11111
        // SMSTOP:  1101_0101_0000_0011_0100_0xxx_00x_11111

        let bits_15_12 = (insn >> 12) & 0xF;
        let bits_11_8 = (insn >> 8) & 0xF;
        let bits_7_5 = (insn >> 5) & 0x7;

        if bits_15_12 != 0x4 {
            return None;
        }

        // Determine if SMSTART or SMSTOP based on bit patterns
        let is_start = (bits_7_5 & 0x2) != 0;
        let sm = (bits_11_8 & 0x1) != 0;  // Streaming mode
        let za = (bits_11_8 & 0x2) != 0;  // ZA array

        let mnemonic = if is_start {
            match (sm, za) {
                (true, true) => "smstart",
                (true, false) => "smstart sm",
                (false, true) => "smstart za",
                (false, false) => "smstart",
            }
        } else {
            match (sm, za) {
                (true, true) => "smstop",
                (true, false) => "smstop sm",
                (false, true) => "smstop za",
                (false, false) => "smstop",
            }
        };

        let operation = if is_start {
            Operation::SmeStart
        } else {
            Operation::SmeStop
        };

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(operation);

        Some(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Decode ZERO {ZA} instruction.
    fn decode_sme_zero_za(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Option<DecodedInstruction> {
        // ZERO {ZA}: 1100_0000_0000_1000_0000_0000_xxxx_xxxx
        // The mask in bits[7:0] indicates which tiles to zero
        let _mask = insn & 0xFF;

        let za_reg = Self::za_reg();

        let inst = Instruction::new(address, 4, bytes, "zero")
            .with_operation(Operation::SmeZeroZa)
            .with_operands(vec![Operand::reg(za_reg)]);

        Some(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Decode SME MOVA instructions (move to/from ZA).
    fn decode_sme_mova(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Option<DecodedInstruction> {
        // MOVA has various forms for moving between Z registers and ZA tiles
        // Basic encoding: 1100_0000_xxxx_xxxx_xxxx_xxxx_xxxx_xxxx

        let bits_23_22 = (insn >> 22) & 0x3;  // Size
        let v = ((insn >> 16) & 0x3) as u16;  // Tile vertical slice index register (W12-W15)
        let pg = ((insn >> 10) & 0x7) as u16; // Predicate
        let zn_or_za = ((insn >> 5) & 0x1F) as u16;
        let zd_or_za = (insn & 0x1F) as u16;

        let is_to_za = ((insn >> 15) & 0x1) == 0;  // Direction

        let _suffix = Self::sme_size_suffix(bits_23_22);
        let pred = Self::preg(pg);

        let (mnemonic, operands) = if is_to_za {
            // MOVA ZA[Wv, #imm], Pg/M, Zn
            let za_reg = Self::za_tile_reg(bits_23_22, zd_or_za as u32);
            let zn_reg = Self::zreg(zn_or_za);
            let wv = Self::wreg(12 + v);  // W12-W15
            (
                "mova",
                vec![
                    Operand::reg(za_reg),
                    Operand::reg(wv),
                    Operand::reg(pred),
                    Operand::reg(zn_reg),
                ],
            )
        } else {
            // MOVA Zd, Pg/M, ZA[Wv, #imm]
            let zd_reg = Self::zreg(zd_or_za);
            let za_reg = Self::za_tile_reg(bits_23_22, zn_or_za as u32);
            let wv = Self::wreg(12 + v);
            (
                "mova",
                vec![
                    Operand::reg(zd_reg),
                    Operand::reg(pred),
                    Operand::reg(za_reg),
                    Operand::reg(wv),
                ],
            )
        };

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(Operation::SmeMova)
            .with_operands(operands);

        Some(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Decode SME ZA memory operations (LDR/STR ZA).
    fn decode_sme_za_memory(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Option<DecodedInstruction> {
        // LDR ZA[Wv, #imm], [Xn, #imm, MUL VL]
        // STR ZA[Wv, #imm], [Xn, #imm, MUL VL]
        // Encoding: 1110_0001_00_L_xxxxx_xxx_xxx_nnnnn_vvvvv
        // L = 0 for STR, L = 1 for LDR

        let is_load = ((insn >> 21) & 0x1) != 0;
        let imm4 = ((insn >> 16) & 0xF) as i64;
        let rv = ((insn >> 13) & 0x3) as u16;  // W12-W15 selector
        let rn = ((insn >> 5) & 0x1F) as u16;
        let imm_off = (insn & 0xF) as u32;

        let mnemonic = if is_load { "ldr" } else { "str" };
        let operation = if is_load {
            Operation::SmeLoadZa
        } else {
            Operation::SmeStoreZa
        };

        let za_reg = Self::za_reg();
        let wv = Self::wreg(12 + rv);
        let base = Self::xreg_sp(rn);

        // Memory reference with VL-scaled immediate
        let mem = if imm4 == 0 {
            MemoryRef::base(base, 0)
        } else {
            MemoryRef::base_disp(base, imm4, 0)
        };

        // Operands: ZA[Wv, #imm_off], [Xn, #imm]
        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(operation)
            .with_operands(vec![
                Operand::reg(za_reg),
                Operand::reg(wv),
                Operand::imm_unsigned(imm_off as u64, 8),
                Operand::Memory(mem),
            ]);

        Some(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Decode SME outer product instructions (FMOPA, FMOPS, BFMOPA, SMOPA, UMOPA, etc.).
    fn decode_sme_outer_product(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Option<DecodedInstruction> {
        // Outer product instructions: 1000_000x_xxxx_xxxx...
        // Various encodings for FP, BF16, and integer outer products

        let bits_24 = (insn >> 24) & 0x1;
        let bits_23_22 = (insn >> 22) & 0x3;  // Size/type
        let zm = ((insn >> 16) & 0x1F) as u16;
        let pm = ((insn >> 13) & 0x7) as u16;
        let pn = ((insn >> 10) & 0x7) as u16;
        let zn = ((insn >> 5) & 0x1F) as u16;
        let s = ((insn >> 4) & 0x1) != 0;  // Subtract flag
        let zad = (insn & 0xF) as u32;

        // Determine instruction type based on encoding
        let (mnemonic, operation) = if bits_24 == 1 {
            // Integer outer products
            let u_n = ((insn >> 4) & 0x1) != 0;  // Unsigned Zn
            let u_m = ((insn >> 3) & 0x1) != 0;  // Unsigned Zm
            match (u_n, u_m, s) {
                (false, false, false) => ("smopa", Operation::SmeSmop),
                (false, false, true) => ("smops", Operation::SmeSmop),
                (true, true, false) => ("umopa", Operation::SmeUmop),
                (true, true, true) => ("umops", Operation::SmeUmop),
                (false, true, false) => ("sumopa", Operation::SmeSumop),
                (true, false, false) => ("usmopa", Operation::SmeSumop),
                _ => ("sme_op", Operation::Other(0x300)),
            }
        } else {
            // Floating-point outer products
            match (bits_23_22, s) {
                (0b00, false) => ("bfmopa", Operation::SmeBfmop),  // BFloat16
                (0b00, true) => ("bfmops", Operation::SmeBfmop),
                (0b10, false) => ("fmopa", Operation::SmeFmopa),   // FP32
                (0b10, true) => ("fmops", Operation::SmeFmops),
                (0b11, false) => ("fmopa", Operation::SmeFmopa),   // FP64
                (0b11, true) => ("fmops", Operation::SmeFmops),
                _ => ("sme_fmop", Operation::Other(0x301)),
            }
        };

        let za_reg = Self::za_tile_reg(bits_23_22, zad);
        let pn_reg = Self::preg(pn);
        let pm_reg = Self::preg(pm);
        let zn_reg = Self::zreg(zn);
        let zm_reg = Self::zreg(zm);

        // FMOPA ZAda.S, Pn/M, Pm/M, Zn.S, Zm.S
        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(operation)
            .with_operands(vec![
                Operand::reg(za_reg),
                Operand::reg(pn_reg),
                Operand::reg(pm_reg),
                Operand::reg(zn_reg),
                Operand::reg(zm_reg),
            ]);

        Some(DecodedInstruction { instruction: inst, size: 4 })
    }

    // Helper functions for register creation

    /// Create the ZA matrix register.
    fn za_reg() -> Register {
        Register::new(
            Architecture::Arm64,
            RegisterClass::MatrixArray,
            arm64::ZA,
            0, // Size is scalable
        )
    }

    /// Create a ZA tile register based on size.
    fn za_tile_reg(size: u32, tile: u32) -> Register {
        let id = match size {
            0 => arm64::ZA0_B,                    // Byte tiles (only ZA0.B)
            1 => arm64::ZA0_H + (tile & 0x1) as u16,  // Halfword tiles (ZA0.H-ZA1.H)
            2 => arm64::ZA0_S + (tile & 0x3) as u16,  // Word tiles (ZA0.S-ZA3.S)
            3 => arm64::ZA0_D + (tile & 0x7) as u16,  // Doubleword tiles (ZA0.D-ZA7.D)
            _ => arm64::ZA,
        };
        Register::new(
            Architecture::Arm64,
            RegisterClass::MatrixArray,
            id,
            0,
        )
    }

    /// Create an SVE Z register.
    fn zreg(id: u16) -> Register {
        Register::new(
            Architecture::Arm64,
            RegisterClass::ScalableVector,
            arm64::Z0 + id,
            0,
        )
    }

    /// Create an SVE predicate register.
    fn preg(id: u16) -> Register {
        Register::new(
            Architecture::Arm64,
            RegisterClass::Predicate,
            arm64::P0 + id,
            0,
        )
    }

    /// Create a 32-bit W register.
    fn wreg(id: u16) -> Register {
        Register::new(
            Architecture::Arm64,
            RegisterClass::General,
            if id == 31 { arm64::XZR } else { id },
            32,
        )
    }

    /// Create an X register with SP interpretation for id 31.
    fn xreg_sp(id: u16) -> Register {
        Register::new(
            Architecture::Arm64,
            if id == 31 {
                RegisterClass::StackPointer
            } else {
                RegisterClass::General
            },
            if id == 31 { arm64::SP } else { id },
            64,
        )
    }

    /// Get SME element size suffix.
    fn sme_size_suffix(size: u32) -> &'static str {
        match size {
            0 => ".b",
            1 => ".h",
            2 => ".s",
            3 => ".d",
            _ => "",
        }
    }
}

impl Default for SmeDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_sme_instruction() {
        // SMSTART: 1101_0101_0000_0011_0100_xxxx_011_11111
        // Example encoding
        let smstart = 0xD503417Fu32;
        assert!(SmeDecoder::is_sme_instruction(smstart));

        // Regular ARM64 NOP should not be SME
        assert!(!SmeDecoder::is_sme_instruction(0xD503201F));
    }

    #[test]
    fn test_za_reg_creation() {
        let za = SmeDecoder::za_reg();
        assert_eq!(za.id, arm64::ZA);
        assert_eq!(za.class, RegisterClass::MatrixArray);
    }

    #[test]
    fn test_za_tile_reg_creation() {
        // Word tile ZA0.S
        let za0_s = SmeDecoder::za_tile_reg(2, 0);
        assert_eq!(za0_s.id, arm64::ZA0_S);

        // Word tile ZA3.S
        let za3_s = SmeDecoder::za_tile_reg(2, 3);
        assert_eq!(za3_s.id, arm64::ZA3_S);

        // Doubleword tile ZA7.D
        let za7_d = SmeDecoder::za_tile_reg(3, 7);
        assert_eq!(za7_d.id, arm64::ZA7_D);
    }

    #[test]
    fn test_decode_zero_za() {
        let decoder = SmeDecoder::new();
        // ZERO {ZA}: 1100_0000_0000_1000_0000_0000_0000_0000
        let zero_za = 0xC0080000u32;
        let bytes = zero_za.to_le_bytes().to_vec();
        let result = decoder.decode(zero_za, 0x1000, bytes);

        assert!(result.is_some());
        let decoded = result.unwrap();
        assert_eq!(decoded.instruction.mnemonic, "zero");
        assert_eq!(decoded.instruction.operation, Operation::SmeZeroZa);
    }

    #[test]
    fn test_outer_product_recognized() {
        // FMOPA outer product instructions start with 1000_000x
        // Example: bits[31:25] = 0b1000000
        let fmopa = 0x80800000u32;
        assert!(SmeDecoder::is_sme_instruction(fmopa));
    }

    #[test]
    fn test_decode_fmopa() {
        let decoder = SmeDecoder::new();
        // FMOPA ZA0.S, P0/M, P0/M, Z0.S, Z0.S
        // Encoding: 1000_0000_1000_0000_0000_0000_0000_0000
        let fmopa = 0x80800000u32;
        let bytes = fmopa.to_le_bytes().to_vec();
        let result = decoder.decode(fmopa, 0x1000, bytes);

        assert!(result.is_some());
        let decoded = result.unwrap();
        // Should decode to some outer product variant
        assert!(decoded.instruction.mnemonic.contains("mop") || decoded.instruction.mnemonic.contains("sme"));
    }
}
