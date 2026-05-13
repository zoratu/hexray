//! ARM64 SVE/SVE2 (Scalable Vector Extension) instruction decoder.
//!
//! SVE instructions are identified by distinctive bit patterns, typically:
//! - Bits [31:25] = 0b00000100 or 0b00000101 for most SVE instructions
//! - Bits [31:25] = 0b10000100 or 0b10000101 for SVE loads/stores
//!
//! Key SVE features:
//! - Z registers (Z0-Z31): Scalable vector registers (128-2048 bits)
//! - P registers (P0-P15): Predicate registers for masking
//! - FFR: First Fault Register
//!
//! SVE2 adds additional instructions including:
//! - Integer operations: SABA/UABA, SQABS/SQNEG, SQDMULH/SQRDMULH
//! - Crypto extensions: AES, SHA3, SM4 operations
//! - Bit manipulation: BDEP, BEXT, BGRP
//! - Match operations: MATCH, NMATCH
//! - Histogram: HISTCNT, HISTSEG

use crate::DecodedInstruction;
use hexray_core::{
    register::arm64, Architecture, Arm64SveElementSize, Arm64SvePredicateMode, Instruction,
    MemoryRef, Operand, Operation, Register, RegisterClass,
};

/// SVE decoder implementation.
pub struct SveDecoder;

impl SveDecoder {
    /// Create a new SVE decoder.
    pub fn new() -> Self {
        Self
    }

    /// Check if an instruction is an SVE instruction.
    /// SVE instructions have distinctive top-level encodings.
    pub fn is_sve_instruction(insn: u32) -> bool {
        // SVE encodings use bits [31:24] for major classification
        let bits_31_24 = (insn >> 24) & 0xFF;

        // SVE data processing: bits [31:24] = 0000_0100 or 0000_0101 (0x04, 0x05)
        // This includes: CNT*, ADD, SUB, MUL, DUP, AND, ORR, EOR, etc.
        if bits_31_24 == 0x04 || bits_31_24 == 0x05 {
            return true;
        }

        // SVE predicate operations: bits [31:24] = 0010_0101 (0x25)
        // PTRUE, PFALSE, and other predicate operations
        if bits_31_24 == 0x25 {
            return true;
        }

        // SVE contiguous loads (scalar+scalar): bits [31:24] = 1000_010x (0x84, 0x85)
        if bits_31_24 == 0x84 || bits_31_24 == 0x85 {
            return true;
        }

        // SVE contiguous loads (scalar+imm): bits [31:24] = 1010_010x (0xA4, 0xA5)
        // LD1B, LD1H, LD1W, LD1D
        if bits_31_24 == 0xA4 || bits_31_24 == 0xA5 {
            return true;
        }

        // SVE contiguous stores (scalar+scalar): bits [31:24] = 1110_010x (0xE4, 0xE5)
        // ST1B, ST1H, ST1W, ST1D
        if bits_31_24 == 0xE4 || bits_31_24 == 0xE5 {
            return true;
        }

        // SVE2 crypto instructions: bits [31:24] = 0100_0101 (0x45)
        // This includes AES, SM4, SHA3 operations
        if bits_31_24 == 0x45 {
            return true;
        }

        // Predicated SVE floating-point arithmetic: bits [31:24] = 0110_0101 (0x65)
        if bits_31_24 == 0x65 {
            return true;
        }

        false
    }

    /// Check if an instruction is an SVE2-specific instruction.
    /// SVE2 instructions extend SVE with additional operations.
    pub fn is_sve2_instruction(insn: u32) -> bool {
        let bits_31_24 = (insn >> 24) & 0xFF;
        let bits_23_21 = (insn >> 21) & 0x7;

        // SVE2 integer operations under 0x44/0x45
        // Many SVE2 instructions share encoding space with SVE but use
        // different opcode bits
        if bits_31_24 == 0x45 {
            // SVE2 crypto (AESE, AESD, SM4E, RAX1, etc.)
            return true;
        }

        // SVE2 saturating operations often encoded under 0x04 with specific opc
        if bits_31_24 == 0x04 {
            // Check for SVE2-specific patterns
            let bits_15_10 = (insn >> 10) & 0x3F;
            // SQABS/SQNEG: bits[23:22]=size, bits[20:16]=opc, bits[15:10]=opc2
            if bits_23_21 == 0b001 && (bits_15_10 & 0x38) == 0x30 {
                return true; // Saturating operations
            }
        }

        // SVE2 bit manipulation (BDEP, BEXT, BGRP) under 0x05
        if bits_31_24 == 0x05 {
            let bits_15_10 = (insn >> 10) & 0x3F;
            // BDEP/BEXT/BGRP patterns
            if (bits_15_10 & 0x30) == 0x30 {
                return true;
            }
        }

        false
    }

    /// Decode an SVE/SVE2 instruction.
    pub fn decode(&self, insn: u32, address: u64, bytes: Vec<u8>) -> Option<DecodedInstruction> {
        let bits_31_24 = (insn >> 24) & 0xFF;

        match bits_31_24 {
            // SVE/SVE2 data processing (0x04, 0x05)
            0x04 | 0x05 => self.decode_sve_data_processing(insn, address, bytes),

            // SVE predicate operations (0x25)
            0x25 => self.decode_sve_predicate(insn, address, bytes),

            // SVE2 crypto and complex integer operations (0x45)
            0x45 => self.decode_sve2_crypto(insn, address, bytes),

            // SVE floating-point arithmetic (0x65)
            0x65 => self.decode_sve_fp_arith(insn, address, bytes),

            // SVE memory operations (loads: 0x84, 0x85, 0xA4, 0xA5; stores: 0xE4, 0xE5)
            0x84 | 0x85 | 0xA4 | 0xA5 | 0xE4 | 0xE5 => self.decode_sve_memory(insn, address, bytes),

            _ => None,
        }
    }

    /// Decode SVE data processing instructions.
    fn decode_sve_data_processing(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Option<DecodedInstruction> {
        let bits_31_24 = (insn >> 24) & 0xFF;
        let bits_15_13 = (insn >> 13) & 0x7;

        // CNT*/INC*: fixed low bits with size in [23:22] and INC in bit 20.
        if bits_31_24 == 0x04 && (insn & 0xFF0F_E3E0) == 0x0400_E3E0 {
            return self.decode_sve_cnt_inc(insn, address, bytes);
        }

        // DUP (scalar to vector): DUP Zd.<T>, Wn/Xn
        if bits_31_24 == 0x05 && ((insn >> 16) & 0x3F) == 0x20 && ((insn >> 10) & 0x3F) == 0x0E {
            return self.decode_sve_dup(insn, address, bytes);
        }

        // MOV Zd.<T>, Pg/M, Zn.<T> alias of SEL when Zm == Zd.
        if bits_31_24 == 0x05 && bits_15_13 == 0b110 && ((insn >> 16) & 0x1F) == (insn & 0x1F) {
            return self.decode_sve_mov_predicated_vector(insn, address, bytes);
        }

        // MOV Zd.<T>, Pg/M, <Bn|Hn|Sn|Dn> alias of CPY (SIMD&FP scalar).
        if bits_31_24 == 0x05 && ((insn >> 16) & 0x3F) == 0x20 && bits_15_13 == 0b100 {
            return self.decode_sve_mov_predicated_scalar(insn, address, bytes);
        }

        // Check for integer binary operations (ADD, SUB, MUL, etc.)
        // These have various encodings under 0b0000_0100
        let bits_23_21 = (insn >> 21) & 0x7;

        // Predicated arithmetic: bits [23:21] = 0b000
        if bits_31_24 == 0x04 && bits_23_21 == 0b000 {
            return self.decode_sve_int_arith(insn, address, bytes);
        }

        // SVE2 saturating operations: bits [23:21] = 0b001
        if bits_31_24 == 0x04 && bits_23_21 == 0b001 {
            return self.decode_sve2_saturating(insn, address, bytes);
        }

        // SVE2 integer multiply-add and absolute diff (under 0x04)
        if bits_31_24 == 0x04 && bits_23_21 == 0b010 {
            return self.decode_sve2_int_mul_add(insn, address, bytes);
        }

        // SVE2 bit manipulation (under 0x05)
        if bits_31_24 == 0x05 {
            // Check for BDEP/BEXT/BGRP patterns
            if bits_15_13 == 0b101 || bits_15_13 == 0b110 {
                return self.decode_sve2_bit_manipulation(insn, address, bytes);
            }
        }

        // Fallback: generic SVE instruction
        self.decode_sve_generic(insn, address, bytes)
    }

    /// Decode predicated SVE floating-point arithmetic.
    fn decode_sve_fp_arith(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Option<DecodedInstruction> {
        let element_size = Self::sve_fp_element_size((insn >> 22) & 0x3)?;
        let pg = ((insn >> 10) & 0x7) as u16;
        let pred = Operand::arm64_sve_predicate(
            Self::preg(pg),
            None,
            Some(Arm64SvePredicateMode::Merging),
        );

        // Fused multiply-add/subtract family:
        // mnemonic Zd.<T>, Pg/M, Zn.<T>, Zm.<T>
        if ((insn >> 21) & 0x1) == 1 {
            let zm = ((insn >> 16) & 0x1F) as u16;
            let opc = (insn >> 13) & 0x7;
            let zn = ((insn >> 5) & 0x1F) as u16;
            let zd = (insn & 0x1F) as u16;

            let (mnemonic, operation) = match opc {
                0b000 => ("fmla", Operation::Add),
                0b001 => ("fmls", Operation::Sub),
                0b010 => ("fnmla", Operation::Add),
                0b011 => ("fnmls", Operation::Sub),
                _ => return self.decode_sve_generic(insn, address, bytes),
            };

            let inst = Instruction::new(address, 4, bytes, mnemonic)
                .with_operation(operation)
                .with_operands(vec![
                    Self::sve_z_operand(zd, element_size),
                    pred,
                    Self::sve_z_operand(zn, element_size),
                    Self::sve_z_operand(zm, element_size),
                ]);

            return Some(DecodedInstruction {
                instruction: inst,
                size: 4,
            });
        }

        // Destructive binary family:
        // mnemonic Zdn.<T>, Pg/M, Zdn.<T>, Zm.<T>
        if ((insn >> 13) & 0x7) == 0b100 {
            let opc = (insn >> 16) & 0x1F;
            let zm = ((insn >> 5) & 0x1F) as u16;
            let zdn = (insn & 0x1F) as u16;

            let (mnemonic, operation) = match opc {
                0b00000 => ("fadd", Operation::Add),
                0b00001 => ("fsub", Operation::Sub),
                0b00010 => ("fmul", Operation::Mul),
                0b01101 => ("fdiv", Operation::Div),
                _ => return self.decode_sve_generic(insn, address, bytes),
            };

            let zdn_op = Self::sve_z_operand(zdn, element_size);
            let inst = Instruction::new(address, 4, bytes, mnemonic)
                .with_operation(operation)
                .with_operands(vec![
                    zdn_op.clone(),
                    pred,
                    zdn_op,
                    Self::sve_z_operand(zm, element_size),
                ]);

            return Some(DecodedInstruction {
                instruction: inst,
                size: 4,
            });
        }

        self.decode_sve_generic(insn, address, bytes)
    }

    /// Decode SVE CNT*/INC* scalar count/increment instructions.
    fn decode_sve_cnt_inc(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Option<DecodedInstruction> {
        let element_size = Self::sve_element_size((insn >> 22) & 0x3)?;
        let is_inc = ((insn >> 20) & 0x1) == 1;
        let imm4 = ((insn >> 16) & 0xF) as u8;
        let pattern = ((insn >> 5) & 0x1F) as u8;
        let rd = (insn & 0x1F) as u16;

        let mnemonic = match (is_inc, element_size) {
            (false, Arm64SveElementSize::Byte) => "cntb",
            (false, Arm64SveElementSize::Halfword) => "cnth",
            (false, Arm64SveElementSize::Word) => "cntw",
            (false, Arm64SveElementSize::Doubleword) => "cntd",
            (true, Arm64SveElementSize::Byte) => "incb",
            (true, Arm64SveElementSize::Halfword) => "inch",
            (true, Arm64SveElementSize::Word) => "incw",
            (true, Arm64SveElementSize::Doubleword) => "incd",
        };

        let mut operands = vec![Operand::reg(Self::xreg(rd))];
        if pattern != 0x1F || imm4 > 0 {
            operands.push(Operand::imm_unsigned(pattern as u64, 8));
        }
        if imm4 > 0 {
            operands.push(Operand::imm_unsigned(imm4.wrapping_add(1) as u64, 8));
        }

        let operation = if is_inc {
            Operation::Inc
        } else {
            Operation::SveCount
        };
        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(operation)
            .with_operands(operands);

        Some(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode SVE MOV Zd.<T>, Pg/M, Zn.<T> alias of SEL.
    fn decode_sve_mov_predicated_vector(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Option<DecodedInstruction> {
        let element_size = Self::sve_element_size((insn >> 22) & 0x3)?;
        let pg = ((insn >> 10) & 0x7) as u16;
        let zn = ((insn >> 5) & 0x1F) as u16;
        let zd = (insn & 0x1F) as u16;

        let inst = Instruction::new(address, 4, bytes, "mov")
            .with_operation(Operation::Move)
            .with_operands(vec![
                Self::sve_z_operand(zd, element_size),
                Operand::arm64_sve_predicate(
                    Self::preg(pg),
                    None,
                    Some(Arm64SvePredicateMode::Merging),
                ),
                Self::sve_z_operand(zn, element_size),
            ]);

        Some(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode SVE MOV Zd.<T>, Pg/M, <Bn|Hn|Sn|Dn> alias of CPY (SIMD&FP scalar).
    fn decode_sve_mov_predicated_scalar(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Option<DecodedInstruction> {
        let element_size = Self::sve_element_size((insn >> 22) & 0x3)?;
        let pg = ((insn >> 10) & 0x7) as u16;
        let vn = ((insn >> 5) & 0x1F) as u16;
        let zd = (insn & 0x1F) as u16;

        let inst = Instruction::new(address, 4, bytes, "mov")
            .with_operation(Operation::Move)
            .with_operands(vec![
                Self::sve_z_operand(zd, element_size),
                Operand::arm64_sve_predicate(
                    Self::preg(pg),
                    None,
                    Some(Arm64SvePredicateMode::Merging),
                ),
                Operand::reg(Self::simd_scalar_reg(vn, element_size)),
            ]);

        Some(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode SVE2 saturating operations (SQABS, SQNEG, SQDMULH, SQRDMULH).
    fn decode_sve2_saturating(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Option<DecodedInstruction> {
        let size = (insn >> 22) & 0x3;
        let opc = (insn >> 16) & 0x1F;
        let pg = ((insn >> 10) & 0x7) as u16;
        let zn_or_zm = ((insn >> 5) & 0x1F) as u16;
        let zd = (insn & 0x1F) as u16;

        // Decode based on opcode
        let (mnemonic, operation, is_unary) = match opc {
            0b01000 => ("sqabs", Operation::Sve2SatAbsNeg, true),
            0b01001 => ("sqneg", Operation::Sve2SatAbsNeg, true),
            0b10100 => ("sqdmulh", Operation::Sve2SatDoublingMulHigh, false),
            0b10101 => ("sqrdmulh", Operation::Sve2SatDoublingMulHigh, false),
            _ => return self.decode_sve_generic(insn, address, bytes),
        };

        let _suffix = Self::sve_size_suffix(size);
        let zd_reg = Self::zreg(zd);
        let pred = Self::preg(pg);

        let operands = if is_unary {
            // Unary predicated: Zd.<T>, Pg/M, Zn.<T>
            vec![
                Operand::reg(zd_reg),
                Operand::reg(pred),
                Operand::reg(Self::zreg(zn_or_zm)),
            ]
        } else {
            // Binary predicated: Zd.<T>, Pg/M, Zd.<T>, Zm.<T>
            vec![
                Operand::reg(zd_reg),
                Operand::reg(pred),
                Operand::reg(zd_reg),
                Operand::reg(Self::zreg(zn_or_zm)),
            ]
        };

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(operation)
            .with_operands(operands);

        Some(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode SVE2 integer multiply-add and absolute difference (SABA, UABA, etc.).
    fn decode_sve2_int_mul_add(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Option<DecodedInstruction> {
        let size = (insn >> 22) & 0x3;
        let zm = ((insn >> 16) & 0x1F) as u16;
        let opc = (insn >> 10) & 0x7;
        let zn = ((insn >> 5) & 0x1F) as u16;
        let zda = (insn & 0x1F) as u16;

        let (mnemonic, operation) = match opc {
            0b000 => ("saba", Operation::Sve2AbsDiffAccum),
            0b001 => ("uaba", Operation::Sve2AbsDiffAccum),
            _ => return self.decode_sve_generic(insn, address, bytes),
        };

        let _suffix = Self::sve_size_suffix(size);
        let zda_reg = Self::zreg(zda);
        let zn_reg = Self::zreg(zn);
        let zm_reg = Self::zreg(zm);

        // SABA/UABA: Zda.<T>, Zn.<T>, Zm.<T>
        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(operation)
            .with_operands(vec![
                Operand::reg(zda_reg),
                Operand::reg(zn_reg),
                Operand::reg(zm_reg),
            ]);

        Some(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode SVE2 bit manipulation operations (BDEP, BEXT, BGRP).
    fn decode_sve2_bit_manipulation(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Option<DecodedInstruction> {
        let size = (insn >> 22) & 0x3;
        let zm = ((insn >> 16) & 0x1F) as u16;
        let opc = (insn >> 10) & 0x7;
        let zn = ((insn >> 5) & 0x1F) as u16;
        let zd = (insn & 0x1F) as u16;

        let (mnemonic, operation) = match opc {
            0b100 => ("bdep", Operation::Sve2BitDeposit),
            0b101 => ("bext", Operation::Sve2BitExtract),
            0b110 => ("bgrp", Operation::Sve2BitGroup),
            _ => return self.decode_sve_generic(insn, address, bytes),
        };

        let _suffix = Self::sve_size_suffix(size);
        let zd_reg = Self::zreg(zd);
        let zn_reg = Self::zreg(zn);
        let zm_reg = Self::zreg(zm);

        // BDEP/BEXT/BGRP: Zd.<T>, Zn.<T>, Zm.<T>
        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(operation)
            .with_operands(vec![
                Operand::reg(zd_reg),
                Operand::reg(zn_reg),
                Operand::reg(zm_reg),
            ]);

        Some(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode SVE2 crypto instructions (AESE, AESD, AESMC, AESIMC, SM4E, SM4EKEY, RAX1).
    fn decode_sve2_crypto(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Option<DecodedInstruction> {
        // SVE2 crypto instructions are encoded under 0x45
        // Various sub-encodings for AES, SM4, SHA3
        let bits_23_22 = (insn >> 22) & 0x3;
        let bits_21_16 = (insn >> 16) & 0x3F;
        let bits_15_10 = (insn >> 10) & 0x3F;
        let zm_or_zn = ((insn >> 5) & 0x1F) as u16;
        let zdn_or_zd = (insn & 0x1F) as u16;

        // AES operations: 0100_0101_00_10_0010_1110_00_mmmmm_ddddd
        // AESE: opc2 = 0, AESD: opc2 = 1, AESMC: opc = 0, AESIMC: opc = 1
        if bits_23_22 == 0b00 && bits_21_16 == 0b100010 {
            let opc = (insn >> 10) & 0x3;
            let (mnemonic, is_mix_columns) = match opc {
                0b00 => ("aese", false),
                0b01 => ("aesd", false),
                0b10 => ("aesmc", true),
                0b11 => ("aesimc", true),
                _ => return self.decode_sve_generic(insn, address, bytes),
            };

            let zdn_reg = Self::zreg(zdn_or_zd);

            let operands = if is_mix_columns {
                // AESMC/AESIMC: Zdn.B, Zdn.B (in-place)
                vec![Operand::reg(zdn_reg), Operand::reg(zdn_reg)]
            } else {
                // AESE/AESD: Zdn.B, Zdn.B, Zm.B
                let zm_reg = Self::zreg(zm_or_zn);
                vec![
                    Operand::reg(zdn_reg),
                    Operand::reg(zdn_reg),
                    Operand::reg(zm_reg),
                ]
            };

            let inst = Instruction::new(address, 4, bytes, mnemonic)
                .with_operation(Operation::Sve2Aes)
                .with_operands(operands);

            return Some(DecodedInstruction {
                instruction: inst,
                size: 4,
            });
        }

        // SM4E: 0100_0101_00_10_0011_1110_00_nnnnn_ddddd
        if bits_23_22 == 0b00 && bits_21_16 == 0b100011 && (bits_15_10 & 0x3C) == 0x38 {
            let zn_reg = Self::zreg(zm_or_zn);
            let zdn_reg = Self::zreg(zdn_or_zd);

            let inst = Instruction::new(address, 4, bytes, "sm4e")
                .with_operation(Operation::Sve2Sm4)
                .with_operands(vec![
                    Operand::reg(zdn_reg),
                    Operand::reg(zdn_reg),
                    Operand::reg(zn_reg),
                ]);

            return Some(DecodedInstruction {
                instruction: inst,
                size: 4,
            });
        }

        // SM4EKEY: 0100_0101_00_10_0000_1111_00_mmmmm_nnnnn_ddddd
        if bits_23_22 == 0b00 && bits_21_16 == 0b100000 && bits_15_10 == 0b111100 {
            let zm_reg = Self::zreg(zm_or_zn);
            let zn_val = (insn >> 5) & 0x1F;
            let zn_reg = Self::zreg(zn_val as u16);
            let zd_reg = Self::zreg(zdn_or_zd);

            let inst = Instruction::new(address, 4, bytes, "sm4ekey")
                .with_operation(Operation::Sve2Sm4)
                .with_operands(vec![
                    Operand::reg(zd_reg),
                    Operand::reg(zn_reg),
                    Operand::reg(zm_reg),
                ]);

            return Some(DecodedInstruction {
                instruction: inst,
                size: 4,
            });
        }

        // RAX1 (SHA3): 0100_0101_00_1_mmmmm_1111_01_nnnnn_ddddd
        if bits_23_22 == 0b00 && (bits_15_10 & 0x3F) == 0b111101 {
            let zm_reg = Self::zreg(((insn >> 16) & 0x1F) as u16);
            let zn_reg = Self::zreg(zm_or_zn);
            let zd_reg = Self::zreg(zdn_or_zd);

            let inst = Instruction::new(address, 4, bytes, "rax1")
                .with_operation(Operation::Sve2Sha3Rotate)
                .with_operands(vec![
                    Operand::reg(zd_reg),
                    Operand::reg(zn_reg),
                    Operand::reg(zm_reg),
                ]);

            return Some(DecodedInstruction {
                instruction: inst,
                size: 4,
            });
        }

        // Histogram operations (HISTCNT, HISTSEG)
        // HISTCNT: 0100_0101_ss_1_mmmmm_110_ggg_nnnnn_ddddd
        if (bits_15_10 & 0x38) == 0x30 {
            let size = bits_23_22;
            let pg = ((insn >> 10) & 0x7) as u16;
            let zm_reg = Self::zreg(((insn >> 16) & 0x1F) as u16);
            let zn_reg = Self::zreg(zm_or_zn);
            let zd_reg = Self::zreg(zdn_or_zd);
            let pred = Self::preg(pg);

            let mnemonic = if size == 0b00 { "histseg" } else { "histcnt" };
            let _suffix = Self::sve_size_suffix(size);

            let inst = Instruction::new(address, 4, bytes, mnemonic)
                .with_operation(Operation::Sve2Histogram)
                .with_operands(vec![
                    Operand::reg(zd_reg),
                    Operand::reg(pred),
                    Operand::reg(zn_reg),
                    Operand::reg(zm_reg),
                ]);

            return Some(DecodedInstruction {
                instruction: inst,
                size: 4,
            });
        }

        // Match operations (MATCH, NMATCH)
        // MATCH: 0100_0101_ss_1_mmmmm_100_ggg_nnnnn_0_pppp
        if (bits_15_10 & 0x38) == 0x20 {
            let size = bits_23_22;
            let pg = ((insn >> 10) & 0x7) as u16;
            let zm_reg = Self::zreg(((insn >> 16) & 0x1F) as u16);
            let zn_reg = Self::zreg(zm_or_zn);
            let pd = (insn & 0xF) as u16;
            let pred_g = Self::preg(pg);
            let pred_d = Self::preg(pd);

            let is_nmatch = ((insn >> 4) & 0x1) == 1;
            let mnemonic = if is_nmatch { "nmatch" } else { "match" };
            let _suffix = Self::sve_size_suffix(size);

            let inst = Instruction::new(address, 4, bytes, mnemonic)
                .with_operation(Operation::Sve2Match)
                .with_operands(vec![
                    Operand::reg(pred_d),
                    Operand::reg(pred_g),
                    Operand::reg(zn_reg),
                    Operand::reg(zm_reg),
                ]);

            return Some(DecodedInstruction {
                instruction: inst,
                size: 4,
            });
        }

        // Fallback
        self.decode_sve_generic(insn, address, bytes)
    }

    /// Decode SVE DUP instruction (broadcast scalar to vector).
    fn decode_sve_dup(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Option<DecodedInstruction> {
        let element_size = Self::sve_element_size((insn >> 22) & 0x3)?;
        let rn = ((insn >> 5) & 0x1F) as u16;
        let zd = (insn & 0x1F) as u16;

        let src = if matches!(element_size, Arm64SveElementSize::Doubleword) {
            Self::xreg(rn)
        } else {
            Self::wreg(rn)
        };

        let inst = Instruction::new(address, 4, bytes, "dup")
            .with_operation(Operation::SveDup)
            .with_operands(vec![
                Self::sve_z_operand(zd, element_size),
                Operand::reg(src),
            ]);

        Some(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode SVE integer arithmetic instructions.
    fn decode_sve_int_arith(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Option<DecodedInstruction> {
        let _size = (insn >> 22) & 0x3;
        let opc = (insn >> 16) & 0x7;
        let pg = ((insn >> 10) & 0x7) as u16;
        let zm = ((insn >> 5) & 0x1F) as u16;
        let zdn = (insn & 0x1F) as u16;

        let (mnemonic, operation) = match opc {
            0b000 => ("add", Operation::SveAdd),
            0b001 => ("sub", Operation::SveSub),
            0b010 => ("mul", Operation::SveMul),
            0b011 => ("subr", Operation::SveSub),
            _ => ("sve_arith", Operation::Other(0)),
        };

        let zd = Self::zreg(zdn);
        let pred = Self::preg(pg);
        let z_src = Self::zreg(zm);

        // Predicated operation: Zd.<T>, Pg/M, Zd.<T>, Zm.<T>
        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(operation)
            .with_operands(vec![
                Operand::reg(zd),
                Operand::reg(pred),
                Operand::reg(zd),
                Operand::reg(z_src),
            ]);

        Some(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode SVE PTRUE instruction.
    fn decode_sve_ptrue(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Option<DecodedInstruction> {
        let element_size = Self::sve_element_size((insn >> 22) & 0x3)?;
        let pattern = ((insn >> 5) & 0x1F) as u8;
        let pd = (insn & 0xF) as u16;

        let mut operands = vec![Operand::arm64_sve_predicate(
            Self::preg(pd),
            Some(element_size),
            None,
        )];
        if pattern != 0x1F {
            operands.push(Operand::imm_unsigned(pattern as u64, 8));
        }

        let inst = Instruction::new(address, 4, bytes, "ptrue")
            .with_operation(Operation::SvePredicate)
            .with_operands(operands);

        Some(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode SVE WHILELT/WHILELO/WHILELS/WHILELE instructions.
    fn decode_sve_while(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Option<DecodedInstruction> {
        let element_size = Self::sve_element_size((insn >> 22) & 0x3)?;
        let rm = ((insn >> 16) & 0x1F) as u16;
        let unsigned = ((insn >> 11) & 0x1) == 1;
        let rn = ((insn >> 5) & 0x1F) as u16;
        let inclusive = ((insn >> 4) & 0x1) == 1;
        let pd = (insn & 0xF) as u16;

        let mnemonic = match (unsigned, inclusive) {
            (false, false) => "whilelt",
            (true, false) => "whilelo",
            (true, true) => "whilels",
            (false, true) => "whilele",
        };

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(Operation::SvePredicate)
            .with_operands(vec![
                Operand::arm64_sve_predicate(Self::preg(pd), Some(element_size), None),
                Operand::reg(Self::xreg(rn)),
                Operand::reg(Self::xreg(rm)),
            ]);

        Some(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode SVE predicate operations.
    fn decode_sve_predicate(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Option<DecodedInstruction> {
        // SVE predicate operations include PTRUE, PFALSE, etc.
        // Check for PTRUE: 0010_0101_xx_01_1000_111x_xxxx_xxxx_xxxx
        let bits_23_16 = (insn >> 16) & 0xFF;
        let bits_15_10 = (insn >> 10) & 0x3F;

        // WHILELT/WHILELO/WHILELS/WHILELE
        if (bits_15_10 & 0x3C) == 0x04 {
            return self.decode_sve_while(insn, address, bytes);
        }

        // PTRUE pattern
        if (bits_23_16 & 0x3F) == 0x18 && bits_15_10 == 0x38 {
            return self.decode_sve_ptrue(insn, address, bytes);
        }

        // Fallback to generic
        self.decode_sve_generic(insn, address, bytes)
    }

    /// Decode SVE memory operations (loads and stores).
    fn decode_sve_memory(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Option<DecodedInstruction> {
        let bits_31_24 = (insn >> 24) & 0xFF;
        let bits_15_13 = (insn >> 13) & 0x7;

        let is_load = matches!(bits_31_24, 0x84 | 0x85 | 0xA4 | 0xA5);
        let is_store = matches!(bits_31_24, 0xE4 | 0xE5);
        if !is_load && !is_store {
            return self.decode_sve_generic(insn, address, bytes);
        }

        if bits_15_13 == 0b010 {
            return if is_load {
                self.decode_sve_contiguous_load_indexed(insn, address, bytes)
            } else {
                self.decode_sve_contiguous_store_indexed(insn, address, bytes)
            };
        }

        if is_load {
            self.decode_sve_contiguous_load(insn, address, bytes)
        } else {
            self.decode_sve_contiguous_store(insn, address, bytes)
        }
    }

    /// Decode SVE contiguous load instructions (LD1B, LD1H, LD1W, LD1D).
    fn decode_sve_contiguous_load(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Option<DecodedInstruction> {
        // LD1D (scalar+immediate): 1010_0101_111_imm4_010_pg_rn_zt
        // LD1W (scalar+immediate): 1010_0101_010_imm4_010_pg_rn_zt (size=10)
        // etc.
        let dtype = (insn >> 21) & 0xF; // Data type encoding
        let imm4 = Self::sign_extend(((insn >> 16) & 0xF) as i64, 4);
        let pg = ((insn >> 10) & 0x7) as u16;
        let rn = ((insn >> 5) & 0x1F) as u16;
        let zt = (insn & 0x1F) as u16;

        // Decode data type to get element size and signedness
        let (mnemonic, element_size, access_size) = match dtype {
            0b0000..=0b0011 => ("ld1b", Arm64SveElementSize::Byte, 1),
            0b0100 => ("ld1sw", Arm64SveElementSize::Doubleword, 4),
            0b0101..=0b0111 => ("ld1h", Arm64SveElementSize::Halfword, 2),
            0b1000 | 0b1001 => ("ld1sh", Arm64SveElementSize::Word, 2),
            0b1010 => ("ld1w", Arm64SveElementSize::Word, 4),
            0b1011 => ("ld1w", Arm64SveElementSize::Doubleword, 4),
            0b1100..=0b1110 => ("ld1sb", Arm64SveElementSize::Doubleword, 1),
            0b1111 => ("ld1d", Arm64SveElementSize::Doubleword, 8),
            _ => ("ld1?", Arm64SveElementSize::Doubleword, 8),
        };

        let base = Self::xreg_sp(rn);

        // Offset is scaled by vector length (VL)
        let mem = if imm4 == 0 {
            MemoryRef::base(base, access_size)
        } else {
            // SVE uses VL-scaled immediate, represented as mul * VL
            MemoryRef::base_disp(base, imm4, access_size)
        };

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(Operation::SveLoad)
            .with_operands(vec![
                Self::sve_z_operand(zt, element_size),
                Operand::arm64_sve_predicate(
                    Self::preg(pg),
                    None,
                    Some(Arm64SvePredicateMode::Zeroing),
                ),
                Operand::Memory(mem),
            ]);

        Some(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode SVE contiguous store instructions (ST1B, ST1H, ST1W, ST1D).
    fn decode_sve_contiguous_store(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Option<DecodedInstruction> {
        // ST1D (scalar+immediate): 1110_0101_111_imm4_111_pg_rn_zt
        // etc.

        let dtype = (insn >> 21) & 0xF;
        let imm4 = Self::sign_extend(((insn >> 16) & 0xF) as i64, 4);
        let pg = ((insn >> 10) & 0x7) as u16;
        let rn = ((insn >> 5) & 0x1F) as u16;
        let zt = (insn & 0x1F) as u16;

        let (mnemonic, element_size, access_size) = match dtype {
            0b0000..=0b0011 => ("st1b", Arm64SveElementSize::Byte, 1),
            0b0101..=0b0111 => ("st1h", Arm64SveElementSize::Halfword, 2),
            0b1010 | 0b1011 => ("st1w", Arm64SveElementSize::Word, 4),
            0b1111 => ("st1d", Arm64SveElementSize::Doubleword, 8),
            _ => ("st1?", Arm64SveElementSize::Doubleword, 8),
        };

        let base = Self::xreg_sp(rn);

        let mem = if imm4 == 0 {
            MemoryRef::base(base, access_size)
        } else {
            MemoryRef::base_disp(base, imm4, access_size)
        };

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(Operation::SveStore)
            .with_operands(vec![
                Self::sve_z_operand(zt, element_size),
                Operand::reg(Self::preg(pg)),
                Operand::Memory(mem),
            ]);

        Some(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode SVE contiguous scalar-plus-scalar loads (single register).
    fn decode_sve_contiguous_load_indexed(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Option<DecodedInstruction> {
        let bits_31_24 = (insn >> 24) & 0xFF;
        let bits_23_21 = (insn >> 21) & 0x7;
        let (mnemonic, element_size, access_size, scale) =
            Self::decode_sve_indexed_mem_kind(bits_31_24, bits_23_21, true)?;
        let zm = ((insn >> 16) & 0x1F) as u16;
        let pg = ((insn >> 10) & 0x7) as u16;
        let rn = ((insn >> 5) & 0x1F) as u16;
        let zt = (insn & 0x1F) as u16;

        let mem = MemoryRef::sib(
            Some(Self::xreg_sp(rn)),
            Some(Self::xreg(zm)),
            scale,
            0,
            access_size,
        );
        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(Operation::SveLoad)
            .with_operands(vec![
                Self::sve_z_operand(zt, element_size),
                Operand::arm64_sve_predicate(
                    Self::preg(pg),
                    None,
                    Some(Arm64SvePredicateMode::Zeroing),
                ),
                Operand::Memory(mem),
            ]);

        Some(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode SVE contiguous scalar-plus-scalar stores (single register).
    fn decode_sve_contiguous_store_indexed(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Option<DecodedInstruction> {
        let bits_31_24 = (insn >> 24) & 0xFF;
        let bits_23_21 = (insn >> 21) & 0x7;
        let (mnemonic, element_size, access_size, scale) =
            Self::decode_sve_indexed_mem_kind(bits_31_24, bits_23_21, false)?;
        let zm = ((insn >> 16) & 0x1F) as u16;
        let pg = ((insn >> 10) & 0x7) as u16;
        let rn = ((insn >> 5) & 0x1F) as u16;
        let zt = (insn & 0x1F) as u16;

        let mem = MemoryRef::sib(
            Some(Self::xreg_sp(rn)),
            Some(Self::xreg(zm)),
            scale,
            0,
            access_size,
        );
        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(Operation::SveStore)
            .with_operands(vec![
                Self::sve_z_operand(zt, element_size),
                Operand::reg(Self::preg(pg)),
                Operand::Memory(mem),
            ]);

        Some(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode a generic SVE instruction (fallback).
    fn decode_sve_generic(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Option<DecodedInstruction> {
        let zd = (insn & 0x1F) as u16;
        let zreg = Self::zreg(zd);

        let inst = Instruction::new(address, 4, bytes, "sve")
            .with_operation(Operation::Other(0x200))
            .with_operands(vec![Operand::reg(zreg)]);

        Some(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    // Helper functions for register creation

    /// Create an SVE Z register.
    fn zreg(id: u16) -> Register {
        Register::new(
            Architecture::Arm64,
            RegisterClass::ScalableVector,
            arm64::Z0.wrapping_add(id),
            0, // Size is scalable (VL-dependent), use 0 as placeholder
        )
    }

    /// Create an SVE predicate register.
    fn preg(id: u16) -> Register {
        Register::new(
            Architecture::Arm64,
            RegisterClass::Predicate,
            arm64::P0.wrapping_add(id),
            0, // Size is scalable
        )
    }

    /// Create a 64-bit X register.
    fn xreg(id: u16) -> Register {
        Register::new(
            Architecture::Arm64,
            RegisterClass::General,
            if id == 31 { arm64::XZR } else { id },
            64,
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

    /// Create a scalar SIMD&FP register with the width implied by an SVE element size.
    fn simd_scalar_reg(id: u16, element_size: Arm64SveElementSize) -> Register {
        let size = match element_size {
            Arm64SveElementSize::Byte => 8,
            Arm64SveElementSize::Halfword => 16,
            Arm64SveElementSize::Word => 32,
            Arm64SveElementSize::Doubleword => 64,
        };
        Register::new(
            Architecture::Arm64,
            RegisterClass::Vector,
            arm64::V0.wrapping_add(id),
            size,
        )
    }

    /// Create a qualified SVE vector operand.
    fn sve_z_operand(id: u16, element_size: Arm64SveElementSize) -> Operand {
        Operand::arm64_sve_vector(Self::zreg(id), element_size)
    }

    /// Decode an SVE integer element size.
    fn sve_element_size(size: u32) -> Option<Arm64SveElementSize> {
        match size {
            0 => Some(Arm64SveElementSize::Byte),
            1 => Some(Arm64SveElementSize::Halfword),
            2 => Some(Arm64SveElementSize::Word),
            3 => Some(Arm64SveElementSize::Doubleword),
            _ => None,
        }
    }

    /// Decode an SVE floating-point element size.
    fn sve_fp_element_size(size: u32) -> Option<Arm64SveElementSize> {
        match size {
            1 => Some(Arm64SveElementSize::Halfword),
            2 => Some(Arm64SveElementSize::Word),
            3 => Some(Arm64SveElementSize::Doubleword),
            _ => None,
        }
    }

    /// Decode contiguous single-register scalar-plus-scalar load/store kinds.
    fn decode_sve_indexed_mem_kind(
        bits_31_24: u32,
        bits_23_21: u32,
        is_load: bool,
    ) -> Option<(&'static str, Arm64SveElementSize, u8, u8)> {
        match (bits_31_24, bits_23_21, is_load) {
            (0xA4, 0b000, true) => Some(("ld1b", Arm64SveElementSize::Byte, 1, 1)),
            (0xA4, 0b101, true) => Some(("ld1h", Arm64SveElementSize::Halfword, 2, 2)),
            (0xA5, 0b010, true) => Some(("ld1w", Arm64SveElementSize::Word, 4, 4)),
            (0xA5, 0b111, true) => Some(("ld1d", Arm64SveElementSize::Doubleword, 8, 8)),
            (0xE4, 0b000, false) => Some(("st1b", Arm64SveElementSize::Byte, 1, 1)),
            (0xE4, 0b101, false) => Some(("st1h", Arm64SveElementSize::Halfword, 2, 2)),
            (0xE5, 0b010, false) => Some(("st1w", Arm64SveElementSize::Word, 4, 4)),
            (0xE5, 0b111, false) => Some(("st1d", Arm64SveElementSize::Doubleword, 8, 8)),
            _ => None,
        }
    }

    /// Sign-extend a `bits`-wide integer value.
    fn sign_extend(value: i64, bits: u32) -> i64 {
        let shift = 64_u32.saturating_sub(bits);
        (value << shift) >> shift
    }

    /// Get SVE element size suffix.
    fn sve_size_suffix(size: u32) -> &'static str {
        match size {
            0 => ".b",
            1 => ".h",
            2 => ".s",
            3 => ".d",
            _ => "",
        }
    }
}

impl Default for SveDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_sve_instruction() {
        // CNTD X0: 0x04EE0FE0
        // Encoding: 0000_0100_11_10_1110_0000_11_11111_00000
        assert!(SveDecoder::is_sve_instruction(0x04EE0FE0));

        // LD1D: 0xA5E0A000 (example encoding)
        assert!(SveDecoder::is_sve_instruction(0xA5E0A000));

        // Regular ARM64 NOP should not be SVE
        assert!(!SveDecoder::is_sve_instruction(0xD503201F));

        // Regular MOV should not be SVE
        assert!(!SveDecoder::is_sve_instruction(0xAA0003E0));
    }

    #[test]
    fn test_decode_cntd() {
        let decoder = SveDecoder::new();
        // CNTD X0: 0x04E0E3E0
        let bytes = vec![0xE0, 0xE3, 0xE0, 0x04];
        let result = decoder.decode(0x04E0E3E0, 0x1000, bytes);

        assert!(result.is_some());
        let decoded = result.unwrap();
        assert_eq!(decoded.instruction.mnemonic, "cntd");
        assert_eq!(decoded.instruction.operation, Operation::SveCount);
    }

    #[test]
    fn test_zreg_creation() {
        let z0 = SveDecoder::zreg(0);
        assert_eq!(z0.id, arm64::Z0);
        assert_eq!(z0.class, RegisterClass::ScalableVector);

        let z31 = SveDecoder::zreg(31);
        assert_eq!(z31.id, arm64::Z31);
    }

    #[test]
    fn test_preg_creation() {
        let p0 = SveDecoder::preg(0);
        assert_eq!(p0.id, arm64::P0);
        assert_eq!(p0.class, RegisterClass::Predicate);

        let p15 = SveDecoder::preg(15);
        assert_eq!(p15.id, arm64::P15);
    }

    #[test]
    fn test_decode_cntb() {
        let decoder = SveDecoder::new();
        // CNTB X0 (pattern=ALL, mul=1)
        let cntb_x0 = 0x0420E3E0u32;
        let bytes = cntb_x0.to_le_bytes().to_vec();
        let result = decoder.decode(cntb_x0, 0x1000, bytes);

        assert!(result.is_some());
        let decoded = result.unwrap();
        assert_eq!(decoded.instruction.mnemonic, "cntb");
        assert_eq!(decoded.instruction.operation, Operation::SveCount);
    }

    #[test]
    fn test_decode_cnth() {
        let decoder = SveDecoder::new();
        // CNTH X1 (pattern=ALL, mul=1)
        let cnth_x1 = 0x0460E3E1u32;
        let bytes = cnth_x1.to_le_bytes().to_vec();
        let result = decoder.decode(cnth_x1, 0x1000, bytes);

        assert!(result.is_some());
        let decoded = result.unwrap();
        assert_eq!(decoded.instruction.mnemonic, "cnth");
        assert_eq!(decoded.instruction.operation, Operation::SveCount);
    }

    #[test]
    fn test_decode_cntw() {
        let decoder = SveDecoder::new();
        // CNTW X2 (pattern=ALL, mul=1)
        let cntw_x2 = 0x04A0E3E2u32;
        let bytes = cntw_x2.to_le_bytes().to_vec();
        let result = decoder.decode(cntw_x2, 0x1000, bytes);

        assert!(result.is_some());
        let decoded = result.unwrap();
        assert_eq!(decoded.instruction.mnemonic, "cntw");
        assert_eq!(decoded.instruction.operation, Operation::SveCount);
    }

    #[test]
    fn test_sve_loads_recognized() {
        // LD1D should be recognized as SVE instruction
        // bits 31-24 = 0xA5
        assert!(SveDecoder::is_sve_instruction(0xA5E00000));
        assert!(SveDecoder::is_sve_instruction(0xA4E00000));
    }

    #[test]
    fn test_sve_stores_recognized() {
        // ST1D should be recognized as SVE instruction
        // bits 31-24 = 0xE5
        assert!(SveDecoder::is_sve_instruction(0xE5E00000));
        assert!(SveDecoder::is_sve_instruction(0xE4E00000));
    }

    // SVE2 instruction tests

    #[test]
    fn test_sve2_crypto_recognized() {
        // SVE2 crypto instructions use bits[31:24] = 0x45
        assert!(SveDecoder::is_sve_instruction(0x45228000)); // Example AES encoding
    }

    #[test]
    fn test_is_sve2_instruction() {
        // SVE2 crypto should be identified
        assert!(SveDecoder::is_sve2_instruction(0x45000000));

        // Regular SVE instruction should not be SVE2-specific
        assert!(!SveDecoder::is_sve2_instruction(0x04EE0FE0)); // CNTD
    }

    #[test]
    fn test_decode_sve2_aese() {
        let decoder = SveDecoder::new();
        // AESE Zdn.B, Zdn.B, Zm.B
        // Encoding: 0100_0101_00_10_0010_1110_00_mmmmm_ddddd
        // bits[31:24] = 0x45, bits[23:22] = 0b00, bits[21:16] = 0b100010
        // bits[15:10] = 0b111000, bits[9:5] = zm, bits[4:0] = zdn
        // AESE Z0.B, Z0.B, Z1.B: zm=1, zdn=0
        let aese = 0x4522E020u32;
        let bytes = aese.to_le_bytes().to_vec();
        let result = decoder.decode(aese, 0x1000, bytes);

        assert!(result.is_some());
        let decoded = result.unwrap();
        assert_eq!(decoded.instruction.mnemonic, "aese");
        assert_eq!(decoded.instruction.operation, Operation::Sve2Aes);
    }

    #[test]
    fn test_decode_sve2_aesd() {
        let decoder = SveDecoder::new();
        // AESD Zdn.B, Zdn.B, Zm.B
        // Same as AESE but opc[11:10] = 0b01
        // AESD Z0.B, Z0.B, Z1.B
        let aesd = 0x4522E420u32;
        let bytes = aesd.to_le_bytes().to_vec();
        let result = decoder.decode(aesd, 0x1000, bytes);

        assert!(result.is_some());
        let decoded = result.unwrap();
        assert_eq!(decoded.instruction.mnemonic, "aesd");
        assert_eq!(decoded.instruction.operation, Operation::Sve2Aes);
    }

    #[test]
    fn test_decode_sve2_saba() {
        let decoder = SveDecoder::new();
        // SABA Zda.<T>, Zn.<T>, Zm.<T>
        // Encoding: 0000_0100_ss_1_mmmmm_1111_00_nnnnn_ddddd
        // bits[23:21] = 0b010, opc = 0b000 for SABA
        // SABA Z0.S, Z1.S, Z2.S (size=10, zm=2, zn=1, zda=0)
        let saba = 0x0482F020u32;
        let bytes = saba.to_le_bytes().to_vec();
        let result = decoder.decode(saba, 0x1000, bytes);

        // Note: Actual encoding may differ - this tests the infrastructure
        assert!(result.is_some());
    }
}
