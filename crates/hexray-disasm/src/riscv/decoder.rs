//! RISC-V instruction decoder implementation.
//!
//! Implements decoding for RV64I/RV32I base integer instruction set
//! with support for extensions:
//! - M: Multiply/Divide
//! - A: Atomics
//! - C: Compressed instructions
//! - F: Single-precision floating-point
//! - D: Double-precision floating-point
//! - V: Vector operations

use crate::{DecodeError, DecodedInstruction, Disassembler};
use hexray_core::{
    Architecture, Condition, ControlFlow, Instruction, MemoryRef, Operand, Operation, Register,
    RegisterClass,
};

use super::float::FloatDecoder;
use super::vector::VectorDecoder;

// Standard 32-bit opcodes (bits 6:0)
const OP_LUI: u32 = 0b0110111; // 0x37
const OP_AUIPC: u32 = 0b0010111; // 0x17
const OP_JAL: u32 = 0b1101111; // 0x6F
const OP_JALR: u32 = 0b1100111; // 0x67
const OP_BRANCH: u32 = 0b1100011; // 0x63
const OP_LOAD: u32 = 0b0000011; // 0x03
const OP_STORE: u32 = 0b0100011; // 0x23
const OP_IMM: u32 = 0b0010011; // 0x13
const OP_REG: u32 = 0b0110011; // 0x33
const OP_IMM32: u32 = 0b0011011; // 0x1B (RV64 only)
const OP_REG32: u32 = 0b0111011; // 0x3B (RV64 only)
const OP_SYSTEM: u32 = 0b1110011; // 0x73
const OP_FENCE: u32 = 0b0001111; // 0x0F
const OP_AMO: u32 = 0b0101111; // 0x2F (A extension)

// Floating-point opcodes (F/D extensions)
const OP_LOAD_FP: u32 = 0b0000111; // 0x07 - FLW, FLD, vector loads
const OP_STORE_FP: u32 = 0b0100111; // 0x27 - FSW, FSD, vector stores
const OP_MADD: u32 = 0b1000011; // 0x43 - FMADD.S, FMADD.D
const OP_MSUB: u32 = 0b1000111; // 0x47 - FMSUB.S, FMSUB.D
const OP_NMSUB: u32 = 0b1001011; // 0x4B - FNMSUB.S, FNMSUB.D
const OP_NMADD: u32 = 0b1001111; // 0x4F - FNMADD.S, FNMADD.D
const OP_FP: u32 = 0b1010011; // 0x53 - All other FP ops

// Vector opcode (V extension)
const OP_V: u32 = 0b1010111; // 0x57 - Vector operations

/// RISC-V disassembler.
pub struct RiscVDisassembler {
    /// Whether to decode as 64-bit (RV64) or 32-bit (RV32).
    is_64bit: bool,
    /// Float decoder for F/D extensions.
    float_decoder: FloatDecoder,
    /// Vector decoder for V extension.
    vector_decoder: VectorDecoder,
}

impl RiscVDisassembler {
    /// Creates a new RISC-V disassembler for RV64I.
    pub fn new() -> Self {
        Self {
            is_64bit: true,
            float_decoder: FloatDecoder::new(true),
            vector_decoder: VectorDecoder::new(true),
        }
    }

    /// Creates a new RISC-V disassembler for RV32I.
    pub fn new_rv32() -> Self {
        Self {
            is_64bit: false,
            float_decoder: FloatDecoder::new(false),
            vector_decoder: VectorDecoder::new(false),
        }
    }

    /// Creates a general-purpose register.
    fn gpr(&self, id: u16) -> Register {
        let class = match id {
            0 => RegisterClass::Other, // x0 is always zero
            2 => RegisterClass::StackPointer,
            _ => RegisterClass::General,
        };
        Register::new(
            if self.is_64bit {
                Architecture::RiscV64
            } else {
                Architecture::RiscV32
            },
            class,
            id,
            if self.is_64bit { 64 } else { 32 },
        )
    }

    /// Decode a single instruction.
    fn decode(&self, bytes: &[u8], address: u64) -> Result<DecodedInstruction, DecodeError> {
        // Check for compressed instruction (bits 1:0 != 11)
        if bytes.len() >= 2 && bytes[0] & 0x3 != 0x3 {
            // Compressed instruction (16-bit)
            let insn = u16::from_le_bytes([bytes[0], bytes[1]]);
            return self.decode_compressed(insn, address);
        }

        if bytes.len() < 4 {
            return Err(DecodeError::truncated(address, 4, bytes.len()));
        }

        // Standard 32-bit instruction
        let insn = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let raw_bytes = bytes[0..4].to_vec();

        let opcode = insn & 0x7F;

        match opcode {
            OP_LUI => self.decode_lui(insn, address, raw_bytes),
            OP_AUIPC => self.decode_auipc(insn, address, raw_bytes),
            OP_JAL => self.decode_jal(insn, address, raw_bytes),
            OP_JALR => self.decode_jalr(insn, address, raw_bytes),
            OP_BRANCH => self.decode_branch(insn, address, raw_bytes),
            OP_LOAD => self.decode_load(insn, address, raw_bytes),
            OP_STORE => self.decode_store(insn, address, raw_bytes),
            OP_IMM => self.decode_op_imm(insn, address, raw_bytes),
            OP_REG => self.decode_op_reg(insn, address, raw_bytes),
            OP_IMM32 if self.is_64bit => self.decode_op_imm32(insn, address, raw_bytes),
            OP_REG32 if self.is_64bit => self.decode_op_reg32(insn, address, raw_bytes),
            OP_SYSTEM => self.decode_system(insn, address, raw_bytes),
            OP_FENCE => self.decode_fence(insn, address, raw_bytes),
            OP_AMO => self.decode_amo(insn, address, raw_bytes),
            // Floating-point extension (F/D)
            OP_LOAD_FP => {
                // Check if this is a vector load or FP load
                if VectorDecoder::is_vector_load(insn) {
                    self.vector_decoder
                        .decode_vector_load(insn, address, raw_bytes)
                } else {
                    self.float_decoder.decode_load(insn, address, raw_bytes)
                }
            }
            OP_STORE_FP => {
                // Check if this is a vector store or FP store
                if VectorDecoder::is_vector_store(insn) {
                    self.vector_decoder
                        .decode_vector_store(insn, address, raw_bytes)
                } else {
                    self.float_decoder.decode_store(insn, address, raw_bytes)
                }
            }
            OP_MADD => self.float_decoder.decode_fmadd(insn, address, raw_bytes),
            OP_MSUB => self.float_decoder.decode_fmsub(insn, address, raw_bytes),
            OP_NMSUB => self.float_decoder.decode_fnmsub(insn, address, raw_bytes),
            OP_NMADD => self.float_decoder.decode_fnmadd(insn, address, raw_bytes),
            OP_FP => self.float_decoder.decode_op_fp(insn, address, raw_bytes),
            // Vector extension (V)
            OP_V => self
                .vector_decoder
                .decode_vector_arith(insn, address, raw_bytes),
            _ => Err(DecodeError::unknown_opcode(address, &raw_bytes)),
        }
    }

    /// Extract rd field (bits 11:7)
    fn rd(insn: u32) -> u16 {
        ((insn >> 7) & 0x1F) as u16
    }

    /// Extract rs1 field (bits 19:15)
    fn rs1(insn: u32) -> u16 {
        ((insn >> 15) & 0x1F) as u16
    }

    /// Extract rs2 field (bits 24:20)
    fn rs2(insn: u32) -> u16 {
        ((insn >> 20) & 0x1F) as u16
    }

    /// Extract funct3 field (bits 14:12)
    fn funct3(insn: u32) -> u32 {
        (insn >> 12) & 0x7
    }

    /// Extract funct7 field (bits 31:25)
    fn funct7(insn: u32) -> u32 {
        (insn >> 25) & 0x7F
    }

    /// Extract I-type immediate (sign-extended)
    fn imm_i(insn: u32) -> i32 {
        (insn as i32) >> 20
    }

    /// Extract S-type immediate (sign-extended)
    fn imm_s(insn: u32) -> i32 {
        let imm11_5 = (insn >> 25) & 0x7F;
        let imm4_0 = (insn >> 7) & 0x1F;
        let imm = (imm11_5 << 5) | imm4_0;
        // Sign-extend from 12 bits
        ((imm as i32) << 20) >> 20
    }

    /// Extract B-type immediate (sign-extended)
    fn imm_b(insn: u32) -> i32 {
        let imm12 = (insn >> 31) & 1;
        let imm10_5 = (insn >> 25) & 0x3F;
        let imm4_1 = (insn >> 8) & 0xF;
        let imm11 = (insn >> 7) & 1;
        let imm = (imm12 << 12) | (imm11 << 11) | (imm10_5 << 5) | (imm4_1 << 1);
        // Sign-extend from 13 bits
        ((imm as i32) << 19) >> 19
    }

    /// Extract U-type immediate (already shifted)
    fn imm_u(insn: u32) -> i32 {
        (insn & 0xFFFFF000) as i32
    }

    /// Extract J-type immediate (sign-extended)
    fn imm_j(insn: u32) -> i32 {
        let imm20 = (insn >> 31) & 1;
        let imm10_1 = (insn >> 21) & 0x3FF;
        let imm11 = (insn >> 20) & 1;
        let imm19_12 = (insn >> 12) & 0xFF;
        let imm = (imm20 << 20) | (imm19_12 << 12) | (imm11 << 11) | (imm10_1 << 1);
        // Sign-extend from 21 bits
        ((imm as i32) << 11) >> 11
    }

    /// Decode LUI instruction.
    fn decode_lui(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let rd = Self::rd(insn);
        let imm = Self::imm_u(insn);

        let inst = Instruction::new(address, 4, bytes, "lui")
            .with_operation(Operation::Move)
            .with_operands(vec![
                Operand::reg(self.gpr(rd)),
                Operand::imm(imm as i128, 32),
            ]);

        Ok(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode AUIPC instruction.
    fn decode_auipc(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let rd = Self::rd(insn);
        let imm = Self::imm_u(insn);
        let target = (address as i64 + imm as i64) as u64;

        let inst = Instruction::new(address, 4, bytes, "auipc")
            .with_operation(Operation::LoadEffectiveAddress)
            .with_operands(vec![
                Operand::reg(self.gpr(rd)),
                Operand::pc_rel(imm as i64, target),
            ]);

        Ok(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode JAL instruction.
    fn decode_jal(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let rd = Self::rd(insn);
        let imm = Self::imm_j(insn);
        let target = (address as i64 + imm as i64) as u64;

        // JAL with rd=x0 is just a jump (J pseudo-instruction)
        // JAL with rd=x1 or other is a call
        let (mnemonic, operation, cf) = if rd == 0 {
            (
                "j",
                Operation::Jump,
                ControlFlow::UnconditionalBranch { target },
            )
        } else {
            (
                "jal",
                Operation::Call,
                ControlFlow::Call {
                    target,
                    return_addr: address + 4,
                },
            )
        };

        let operands = if rd == 0 {
            vec![Operand::pc_rel(imm as i64, target)]
        } else {
            vec![
                Operand::reg(self.gpr(rd)),
                Operand::pc_rel(imm as i64, target),
            ]
        };

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(operation)
            .with_operands(operands)
            .with_control_flow(cf);

        Ok(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode JALR instruction.
    fn decode_jalr(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let rd = Self::rd(insn);
        let rs1 = Self::rs1(insn);
        let imm = Self::imm_i(insn);

        // JALR with rd=x0 and rs1=x1 and imm=0 is RET
        let (mnemonic, operation, cf, operands) = if rd == 0 && rs1 == 1 && imm == 0 {
            ("ret", Operation::Return, ControlFlow::Return, vec![])
        } else if rd == 0 {
            // JR pseudo-instruction
            let ops = if imm == 0 {
                vec![Operand::reg(self.gpr(rs1))]
            } else {
                vec![Operand::reg(self.gpr(rs1)), Operand::imm(imm as i128, 12)]
            };
            (
                "jr",
                Operation::Jump,
                ControlFlow::IndirectBranch {
                    possible_targets: vec![],
                },
                ops,
            )
        } else if rd == 1 && imm == 0 {
            // JALR rd, rs1 (indirect call)
            (
                "jalr",
                Operation::Call,
                ControlFlow::IndirectCall {
                    return_addr: address + 4,
                },
                vec![Operand::reg(self.gpr(rd)), Operand::reg(self.gpr(rs1))],
            )
        } else {
            let ops = if imm == 0 {
                vec![Operand::reg(self.gpr(rd)), Operand::reg(self.gpr(rs1))]
            } else {
                vec![
                    Operand::reg(self.gpr(rd)),
                    Operand::reg(self.gpr(rs1)),
                    Operand::imm(imm as i128, 12),
                ]
            };
            (
                "jalr",
                Operation::Call,
                ControlFlow::IndirectCall {
                    return_addr: address + 4,
                },
                ops,
            )
        };

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(operation)
            .with_operands(operands)
            .with_control_flow(cf);

        Ok(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode branch instructions.
    fn decode_branch(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let rs1 = Self::rs1(insn);
        let rs2 = Self::rs2(insn);
        let imm = Self::imm_b(insn);
        let funct3 = Self::funct3(insn);
        let target = (address as i64 + imm as i64) as u64;

        let (mnemonic, condition) = match funct3 {
            0b000 => ("beq", Condition::Equal),
            0b001 => ("bne", Condition::NotEqual),
            0b100 => ("blt", Condition::Less),
            0b101 => ("bge", Condition::GreaterOrEqual),
            0b110 => ("bltu", Condition::Below),
            0b111 => ("bgeu", Condition::AboveOrEqual),
            _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
        };

        // Check for pseudo-instructions
        let (final_mnemonic, operands) = if rs2 == 0 {
            // Comparing with zero
            match funct3 {
                0b000 => (
                    "beqz",
                    vec![
                        Operand::reg(self.gpr(rs1)),
                        Operand::pc_rel(imm as i64, target),
                    ],
                ),
                0b001 => (
                    "bnez",
                    vec![
                        Operand::reg(self.gpr(rs1)),
                        Operand::pc_rel(imm as i64, target),
                    ],
                ),
                0b100 => (
                    "bltz",
                    vec![
                        Operand::reg(self.gpr(rs1)),
                        Operand::pc_rel(imm as i64, target),
                    ],
                ),
                0b101 => (
                    "bgez",
                    vec![
                        Operand::reg(self.gpr(rs1)),
                        Operand::pc_rel(imm as i64, target),
                    ],
                ),
                _ => (
                    mnemonic,
                    vec![
                        Operand::reg(self.gpr(rs1)),
                        Operand::reg(self.gpr(rs2)),
                        Operand::pc_rel(imm as i64, target),
                    ],
                ),
            }
        } else if rs1 == 0 {
            // Zero on left side
            match funct3 {
                0b100 => (
                    "bgtz",
                    vec![
                        Operand::reg(self.gpr(rs2)),
                        Operand::pc_rel(imm as i64, target),
                    ],
                ),
                0b101 => (
                    "blez",
                    vec![
                        Operand::reg(self.gpr(rs2)),
                        Operand::pc_rel(imm as i64, target),
                    ],
                ),
                _ => (
                    mnemonic,
                    vec![
                        Operand::reg(self.gpr(rs1)),
                        Operand::reg(self.gpr(rs2)),
                        Operand::pc_rel(imm as i64, target),
                    ],
                ),
            }
        } else {
            (
                mnemonic,
                vec![
                    Operand::reg(self.gpr(rs1)),
                    Operand::reg(self.gpr(rs2)),
                    Operand::pc_rel(imm as i64, target),
                ],
            )
        };

        let inst = Instruction::new(address, 4, bytes, final_mnemonic)
            .with_operation(Operation::ConditionalJump)
            .with_operands(operands)
            .with_control_flow(ControlFlow::ConditionalBranch {
                target,
                condition,
                fallthrough: address + 4,
            });

        Ok(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode load instructions.
    fn decode_load(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let rd = Self::rd(insn);
        let rs1 = Self::rs1(insn);
        let imm = Self::imm_i(insn);
        let funct3 = Self::funct3(insn);

        let (mnemonic, size) = match funct3 {
            0b000 => ("lb", 1),
            0b001 => ("lh", 2),
            0b010 => ("lw", 4),
            0b011 if self.is_64bit => ("ld", 8),
            0b100 => ("lbu", 1),
            0b101 => ("lhu", 2),
            0b110 if self.is_64bit => ("lwu", 4),
            _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
        };

        let mem = if imm == 0 {
            MemoryRef::base(self.gpr(rs1), size)
        } else {
            MemoryRef::base_disp(self.gpr(rs1), imm as i64, size)
        };

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(Operation::Load)
            .with_operands(vec![Operand::reg(self.gpr(rd)), Operand::Memory(mem)]);

        Ok(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode store instructions.
    fn decode_store(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let rs1 = Self::rs1(insn);
        let rs2 = Self::rs2(insn);
        let imm = Self::imm_s(insn);
        let funct3 = Self::funct3(insn);

        let (mnemonic, size) = match funct3 {
            0b000 => ("sb", 1),
            0b001 => ("sh", 2),
            0b010 => ("sw", 4),
            0b011 if self.is_64bit => ("sd", 8),
            _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
        };

        let mem = if imm == 0 {
            MemoryRef::base(self.gpr(rs1), size)
        } else {
            MemoryRef::base_disp(self.gpr(rs1), imm as i64, size)
        };

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(Operation::Store)
            .with_operands(vec![Operand::reg(self.gpr(rs2)), Operand::Memory(mem)]);

        Ok(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode OP-IMM instructions (ADDI, SLTI, etc.)
    fn decode_op_imm(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let rd = Self::rd(insn);
        let rs1 = Self::rs1(insn);
        let imm = Self::imm_i(insn);
        let funct3 = Self::funct3(insn);
        let funct7 = Self::funct7(insn);

        let shamt = if self.is_64bit {
            (insn >> 20) & 0x3F // 6-bit shift amount for RV64
        } else {
            (insn >> 20) & 0x1F // 5-bit shift amount for RV32
        };

        let (mnemonic, operation, use_shamt) = match funct3 {
            0b000 => {
                // ADDI - check for pseudo-instructions
                if rs1 == 0 {
                    ("li", Operation::Move, false) // LI pseudo-instruction
                } else if imm == 0 {
                    ("mv", Operation::Move, false) // MV pseudo-instruction
                } else {
                    ("addi", Operation::Add, false)
                }
            }
            0b010 => ("slti", Operation::Compare, false),
            0b011 => {
                if rs1 == 0 && imm == 1 {
                    ("seqz", Operation::Compare, false) // SEQZ pseudo-instruction
                } else {
                    ("sltiu", Operation::Compare, false)
                }
            }
            0b100 => ("xori", Operation::Xor, false),
            0b110 => ("ori", Operation::Or, false),
            0b111 => ("andi", Operation::And, false),
            0b001 => ("slli", Operation::Shl, true),
            0b101 => {
                if funct7 & 0x20 != 0 {
                    ("srai", Operation::Sar, true)
                } else {
                    ("srli", Operation::Shr, true)
                }
            }
            _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
        };

        // Handle pseudo-instructions
        let (final_mnemonic, operands) = if mnemonic == "li" {
            (
                "li",
                vec![Operand::reg(self.gpr(rd)), Operand::imm(imm as i128, 12)],
            )
        } else if mnemonic == "mv" {
            (
                "mv",
                vec![Operand::reg(self.gpr(rd)), Operand::reg(self.gpr(rs1))],
            )
        } else if mnemonic == "seqz" {
            (
                "seqz",
                vec![Operand::reg(self.gpr(rd)), Operand::reg(self.gpr(rs1))],
            )
        } else if use_shamt {
            (
                mnemonic,
                vec![
                    Operand::reg(self.gpr(rd)),
                    Operand::reg(self.gpr(rs1)),
                    Operand::imm_unsigned(shamt as u64, 6),
                ],
            )
        } else {
            (
                mnemonic,
                vec![
                    Operand::reg(self.gpr(rd)),
                    Operand::reg(self.gpr(rs1)),
                    Operand::imm(imm as i128, 12),
                ],
            )
        };

        let inst = Instruction::new(address, 4, bytes, final_mnemonic)
            .with_operation(operation)
            .with_operands(operands);

        Ok(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode OP instructions (ADD, SUB, etc.)
    fn decode_op_reg(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let rd = Self::rd(insn);
        let rs1 = Self::rs1(insn);
        let rs2 = Self::rs2(insn);
        let funct3 = Self::funct3(insn);
        let funct7 = Self::funct7(insn);

        // Check for M extension (multiply/divide)
        if funct7 == 0b0000001 {
            return self.decode_m_extension(insn, address, bytes, false);
        }

        let (mnemonic, operation) = match (funct3, funct7) {
            (0b000, 0b0000000) => ("add", Operation::Add),
            (0b000, 0b0100000) => {
                // SUB - check for NEG pseudo-instruction
                if rs1 == 0 {
                    ("neg", Operation::Neg)
                } else {
                    ("sub", Operation::Sub)
                }
            }
            (0b001, 0b0000000) => ("sll", Operation::Shl),
            (0b010, 0b0000000) => {
                if rs1 == 0 {
                    ("sgtz", Operation::Compare) // SGTZ pseudo
                } else {
                    ("slt", Operation::Compare)
                }
            }
            (0b011, 0b0000000) => {
                if rs1 == 0 {
                    ("snez", Operation::Compare) // SNEZ pseudo
                } else {
                    ("sltu", Operation::Compare)
                }
            }
            (0b100, 0b0000000) => ("xor", Operation::Xor),
            (0b101, 0b0000000) => ("srl", Operation::Shr),
            (0b101, 0b0100000) => ("sra", Operation::Sar),
            (0b110, 0b0000000) => ("or", Operation::Or),
            (0b111, 0b0000000) => ("and", Operation::And),
            _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
        };

        let operands = if mnemonic == "neg" || mnemonic == "sgtz" || mnemonic == "snez" {
            vec![Operand::reg(self.gpr(rd)), Operand::reg(self.gpr(rs2))]
        } else {
            vec![
                Operand::reg(self.gpr(rd)),
                Operand::reg(self.gpr(rs1)),
                Operand::reg(self.gpr(rs2)),
            ]
        };

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(operation)
            .with_operands(operands);

        Ok(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode OP-IMM-32 instructions (RV64 only: ADDIW, SLLIW, etc.)
    fn decode_op_imm32(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let rd = Self::rd(insn);
        let rs1 = Self::rs1(insn);
        let imm = Self::imm_i(insn);
        let funct3 = Self::funct3(insn);
        let funct7 = Self::funct7(insn);
        let shamt = ((insn >> 20) & 0x1F) as u64; // 5-bit shift

        let (mnemonic, operation, use_shamt) = match funct3 {
            0b000 => {
                if rs1 == 0 {
                    // sext.w pseudo-instruction (addiw rd, x0, 0)
                    ("sext.w", Operation::Move, false)
                } else {
                    ("addiw", Operation::Add, false)
                }
            }
            0b001 => ("slliw", Operation::Shl, true),
            0b101 => {
                if funct7 & 0x20 != 0 {
                    ("sraiw", Operation::Sar, true)
                } else {
                    ("srliw", Operation::Shr, true)
                }
            }
            _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
        };

        let operands = if mnemonic == "sext.w" {
            vec![Operand::reg(self.gpr(rd)), Operand::reg(self.gpr(rs1))]
        } else if use_shamt {
            vec![
                Operand::reg(self.gpr(rd)),
                Operand::reg(self.gpr(rs1)),
                Operand::imm_unsigned(shamt, 5),
            ]
        } else {
            vec![
                Operand::reg(self.gpr(rd)),
                Operand::reg(self.gpr(rs1)),
                Operand::imm(imm as i128, 12),
            ]
        };

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(operation)
            .with_operands(operands);

        Ok(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode OP-32 instructions (RV64 only: ADDW, SUBW, etc.)
    fn decode_op_reg32(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let rd = Self::rd(insn);
        let rs1 = Self::rs1(insn);
        let rs2 = Self::rs2(insn);
        let funct3 = Self::funct3(insn);
        let funct7 = Self::funct7(insn);

        // Check for M extension (multiply/divide 32-bit)
        if funct7 == 0b0000001 {
            return self.decode_m_extension(insn, address, bytes, true);
        }

        let (mnemonic, operation) = match (funct3, funct7) {
            (0b000, 0b0000000) => ("addw", Operation::Add),
            (0b000, 0b0100000) => {
                if rs1 == 0 {
                    ("negw", Operation::Neg)
                } else {
                    ("subw", Operation::Sub)
                }
            }
            (0b001, 0b0000000) => ("sllw", Operation::Shl),
            (0b101, 0b0000000) => ("srlw", Operation::Shr),
            (0b101, 0b0100000) => ("sraw", Operation::Sar),
            _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
        };

        let operands = if mnemonic == "negw" {
            vec![Operand::reg(self.gpr(rd)), Operand::reg(self.gpr(rs2))]
        } else {
            vec![
                Operand::reg(self.gpr(rd)),
                Operand::reg(self.gpr(rs1)),
                Operand::reg(self.gpr(rs2)),
            ]
        };

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(operation)
            .with_operands(operands);

        Ok(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode M extension instructions (MUL, DIV, etc.)
    fn decode_m_extension(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
        is_32bit: bool,
    ) -> Result<DecodedInstruction, DecodeError> {
        let rd = Self::rd(insn);
        let rs1 = Self::rs1(insn);
        let rs2 = Self::rs2(insn);
        let funct3 = Self::funct3(insn);

        let suffix = if is_32bit { "w" } else { "" };

        let (base_mnemonic, operation) = match funct3 {
            0b000 => ("mul", Operation::Mul),
            0b001 => ("mulh", Operation::Mul),
            0b010 => ("mulhsu", Operation::Mul),
            0b011 => ("mulhu", Operation::Mul),
            0b100 => ("div", Operation::Div),
            0b101 => ("divu", Operation::Div),
            0b110 => ("rem", Operation::Div),
            0b111 => ("remu", Operation::Div),
            _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
        };

        let mnemonic = format!("{}{}", base_mnemonic, suffix);

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(operation)
            .with_operands(vec![
                Operand::reg(self.gpr(rd)),
                Operand::reg(self.gpr(rs1)),
                Operand::reg(self.gpr(rs2)),
            ]);

        Ok(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode system instructions (ECALL, EBREAK, CSR)
    fn decode_system(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let rd = Self::rd(insn);
        let rs1 = Self::rs1(insn);
        let funct3 = Self::funct3(insn);
        let csr = (insn >> 20) & 0xFFF;

        if funct3 == 0 {
            // ECALL, EBREAK, or privileged instructions
            match csr {
                0 => {
                    let inst = Instruction::new(address, 4, bytes, "ecall")
                        .with_operation(Operation::Syscall)
                        .with_control_flow(ControlFlow::Syscall);
                    return Ok(DecodedInstruction {
                        instruction: inst,
                        size: 4,
                    });
                }
                1 => {
                    let inst = Instruction::new(address, 4, bytes, "ebreak")
                        .with_operation(Operation::Halt)
                        .with_control_flow(ControlFlow::Halt);
                    return Ok(DecodedInstruction {
                        instruction: inst,
                        size: 4,
                    });
                }
                0x002 => {
                    let inst = Instruction::new(address, 4, bytes, "uret")
                        .with_operation(Operation::Return)
                        .with_control_flow(ControlFlow::Return);
                    return Ok(DecodedInstruction {
                        instruction: inst,
                        size: 4,
                    });
                }
                0x102 => {
                    let inst = Instruction::new(address, 4, bytes, "sret")
                        .with_operation(Operation::Return)
                        .with_control_flow(ControlFlow::Return);
                    return Ok(DecodedInstruction {
                        instruction: inst,
                        size: 4,
                    });
                }
                0x302 => {
                    let inst = Instruction::new(address, 4, bytes, "mret")
                        .with_operation(Operation::Return)
                        .with_control_flow(ControlFlow::Return);
                    return Ok(DecodedInstruction {
                        instruction: inst,
                        size: 4,
                    });
                }
                0x105 => {
                    let inst =
                        Instruction::new(address, 4, bytes, "wfi").with_operation(Operation::Nop);
                    return Ok(DecodedInstruction {
                        instruction: inst,
                        size: 4,
                    });
                }
                _ => {}
            }
        }

        // CSR instructions
        let (mnemonic, use_imm) = match funct3 {
            0b001 => ("csrrw", false),
            0b010 => ("csrrs", false),
            0b011 => ("csrrc", false),
            0b101 => ("csrrwi", true),
            0b110 => ("csrrsi", true),
            0b111 => ("csrrci", true),
            _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
        };

        // Check for pseudo-instructions
        let (final_mnemonic, operands) = if funct3 == 0b010 && rs1 == 0 {
            // csrrs rd, csr, x0 -> csrr rd, csr
            (
                "csrr",
                vec![
                    Operand::reg(self.gpr(rd)),
                    Operand::imm_unsigned(csr as u64, 12),
                ],
            )
        } else if funct3 == 0b001 && rd == 0 {
            // csrrw x0, csr, rs1 -> csrw csr, rs1
            (
                "csrw",
                vec![
                    Operand::imm_unsigned(csr as u64, 12),
                    Operand::reg(self.gpr(rs1)),
                ],
            )
        } else if use_imm {
            (
                mnemonic,
                vec![
                    Operand::reg(self.gpr(rd)),
                    Operand::imm_unsigned(csr as u64, 12),
                    Operand::imm_unsigned(rs1 as u64, 5),
                ],
            )
        } else {
            (
                mnemonic,
                vec![
                    Operand::reg(self.gpr(rd)),
                    Operand::imm_unsigned(csr as u64, 12),
                    Operand::reg(self.gpr(rs1)),
                ],
            )
        };

        let inst = Instruction::new(address, 4, bytes, final_mnemonic)
            .with_operation(Operation::Other(0))
            .with_operands(operands);

        Ok(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode FENCE instruction.
    fn decode_fence(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let funct3 = Self::funct3(insn);

        let mnemonic = match funct3 {
            0b000 => "fence",
            0b001 => "fence.i",
            _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
        };

        let inst =
            Instruction::new(address, 4, bytes, mnemonic).with_operation(Operation::Other(0));

        Ok(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode atomic memory operations (A extension).
    fn decode_amo(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let rd = Self::rd(insn);
        let rs1 = Self::rs1(insn);
        let rs2 = Self::rs2(insn);
        let funct3 = Self::funct3(insn);
        let funct5 = (insn >> 27) & 0x1F;
        let aq = (insn >> 26) & 1;
        let rl = (insn >> 25) & 1;

        let width = match funct3 {
            0b010 => "w",
            0b011 if self.is_64bit => "d",
            _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
        };

        let base_mnemonic = match funct5 {
            0b00010 => "lr",
            0b00011 => "sc",
            0b00001 => "amoswap",
            0b00000 => "amoadd",
            0b00100 => "amoxor",
            0b01100 => "amoand",
            0b01000 => "amoor",
            0b10000 => "amomin",
            0b10100 => "amomax",
            0b11000 => "amominu",
            0b11100 => "amomaxu",
            _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
        };

        let suffix = match (aq, rl) {
            (0, 0) => "",
            (1, 0) => ".aq",
            (0, 1) => ".rl",
            (1, 1) => ".aqrl",
            _ => unreachable!(),
        };

        let mnemonic = format!("{}.{}{}", base_mnemonic, width, suffix);

        let mem = MemoryRef::base(self.gpr(rs1), if funct3 == 0b010 { 4 } else { 8 });

        let operands = if funct5 == 0b00010 {
            // LR - no rs2
            vec![Operand::reg(self.gpr(rd)), Operand::Memory(mem)]
        } else {
            vec![
                Operand::reg(self.gpr(rd)),
                Operand::reg(self.gpr(rs2)),
                Operand::Memory(mem),
            ]
        };

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(Operation::Other(0))
            .with_operands(operands);

        Ok(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    // ==================== Compressed (RVC) Extension ====================

    /// Decode a compressed (16-bit) instruction.
    fn decode_compressed(
        &self,
        insn: u16,
        address: u64,
    ) -> Result<DecodedInstruction, DecodeError> {
        let raw_bytes = insn.to_le_bytes().to_vec();
        let quadrant = insn & 0x3;
        let funct3 = (insn >> 13) & 0x7;

        match quadrant {
            0b00 => self.decode_c0(insn, address, raw_bytes, funct3 as u8),
            0b01 => self.decode_c1(insn, address, raw_bytes, funct3 as u8),
            0b10 => self.decode_c2(insn, address, raw_bytes, funct3 as u8),
            _ => Err(DecodeError::unknown_opcode(address, &raw_bytes)),
        }
    }

    /// Get compressed register (3-bit encoding maps to x8-x15).
    fn c_reg(&self, id: u16) -> Register {
        self.gpr(id + 8)
    }

    /// Decode quadrant 0 (C0) instructions.
    fn decode_c0(
        &self,
        insn: u16,
        address: u64,
        bytes: Vec<u8>,
        funct3: u8,
    ) -> Result<DecodedInstruction, DecodeError> {
        match funct3 {
            0b000 => {
                // C.ADDI4SPN: addi rd', sp, nzuimm
                let rd = self.c_reg((insn >> 2) & 0x7);
                // nzuimm[5:4|9:6|2|3] from bits 12:5
                let nzuimm = (((insn >> 6) & 0x1) << 2)   // bit 2
                           | (((insn >> 5) & 0x1) << 3)   // bit 3
                           | (((insn >> 11) & 0x3) << 4)  // bits 5:4
                           | (((insn >> 7) & 0xF) << 6); // bits 9:6

                if nzuimm == 0 {
                    // Illegal instruction (reserved)
                    return Err(DecodeError::unknown_opcode(address, &bytes));
                }

                let inst = Instruction::new(address, 2, bytes, "c.addi4spn")
                    .with_operation(Operation::Add)
                    .with_operands(vec![
                        Operand::reg(rd),
                        Operand::reg(self.gpr(2)), // sp
                        Operand::imm_unsigned(nzuimm as u64, 10),
                    ]);
                Ok(DecodedInstruction {
                    instruction: inst,
                    size: 2,
                })
            }
            0b001 => {
                // C.FLD (RV32/64) or C.LQ (RV128) - floating point load double
                let rd = self.c_reg((insn >> 2) & 0x7);
                let rs1 = self.c_reg((insn >> 7) & 0x7);
                // uimm[5:3|7:6] from bits 12:10, 6:5
                let uimm = (((insn >> 10) & 0x7) << 3) | (((insn >> 5) & 0x3) << 6);

                let mem = MemoryRef::base_disp(rs1, uimm as i64, 8);
                let inst = Instruction::new(address, 2, bytes, "c.fld")
                    .with_operation(Operation::Load)
                    .with_operands(vec![Operand::reg(rd), Operand::Memory(mem)]);
                Ok(DecodedInstruction {
                    instruction: inst,
                    size: 2,
                })
            }
            0b010 => {
                // C.LW: lw rd', offset(rs1')
                let rd = self.c_reg((insn >> 2) & 0x7);
                let rs1 = self.c_reg((insn >> 7) & 0x7);
                // uimm[5:3|2|6] from bits 12:10, 6, 5
                let uimm = (((insn >> 6) & 0x1) << 2)
                    | (((insn >> 10) & 0x7) << 3)
                    | (((insn >> 5) & 0x1) << 6);

                let mem = MemoryRef::base_disp(rs1, uimm as i64, 4);
                let inst = Instruction::new(address, 2, bytes, "c.lw")
                    .with_operation(Operation::Load)
                    .with_operands(vec![Operand::reg(rd), Operand::Memory(mem)]);
                Ok(DecodedInstruction {
                    instruction: inst,
                    size: 2,
                })
            }
            0b011 => {
                if self.is_64bit {
                    // C.LD: ld rd', offset(rs1') (RV64/128)
                    let rd = self.c_reg((insn >> 2) & 0x7);
                    let rs1 = self.c_reg((insn >> 7) & 0x7);
                    // uimm[5:3|7:6] from bits 12:10, 6:5
                    let uimm = (((insn >> 10) & 0x7) << 3) | (((insn >> 5) & 0x3) << 6);

                    let mem = MemoryRef::base_disp(rs1, uimm as i64, 8);
                    let inst = Instruction::new(address, 2, bytes, "c.ld")
                        .with_operation(Operation::Load)
                        .with_operands(vec![Operand::reg(rd), Operand::Memory(mem)]);
                    Ok(DecodedInstruction {
                        instruction: inst,
                        size: 2,
                    })
                } else {
                    // C.FLW: flw rd', offset(rs1') (RV32 only)
                    let rd = self.c_reg((insn >> 2) & 0x7);
                    let rs1 = self.c_reg((insn >> 7) & 0x7);
                    let uimm = (((insn >> 6) & 0x1) << 2)
                        | (((insn >> 10) & 0x7) << 3)
                        | (((insn >> 5) & 0x1) << 6);

                    let mem = MemoryRef::base_disp(rs1, uimm as i64, 4);
                    let inst = Instruction::new(address, 2, bytes, "c.flw")
                        .with_operation(Operation::Load)
                        .with_operands(vec![Operand::reg(rd), Operand::Memory(mem)]);
                    Ok(DecodedInstruction {
                        instruction: inst,
                        size: 2,
                    })
                }
            }
            0b100 => {
                // Reserved
                Err(DecodeError::unknown_opcode(address, &bytes))
            }
            0b101 => {
                // C.FSD: fsd rs2', offset(rs1')
                let rs2 = self.c_reg((insn >> 2) & 0x7);
                let rs1 = self.c_reg((insn >> 7) & 0x7);
                let uimm = (((insn >> 10) & 0x7) << 3) | (((insn >> 5) & 0x3) << 6);

                let mem = MemoryRef::base_disp(rs1, uimm as i64, 8);
                let inst = Instruction::new(address, 2, bytes, "c.fsd")
                    .with_operation(Operation::Store)
                    .with_operands(vec![Operand::reg(rs2), Operand::Memory(mem)]);
                Ok(DecodedInstruction {
                    instruction: inst,
                    size: 2,
                })
            }
            0b110 => {
                // C.SW: sw rs2', offset(rs1')
                let rs2 = self.c_reg((insn >> 2) & 0x7);
                let rs1 = self.c_reg((insn >> 7) & 0x7);
                let uimm = (((insn >> 6) & 0x1) << 2)
                    | (((insn >> 10) & 0x7) << 3)
                    | (((insn >> 5) & 0x1) << 6);

                let mem = MemoryRef::base_disp(rs1, uimm as i64, 4);
                let inst = Instruction::new(address, 2, bytes, "c.sw")
                    .with_operation(Operation::Store)
                    .with_operands(vec![Operand::reg(rs2), Operand::Memory(mem)]);
                Ok(DecodedInstruction {
                    instruction: inst,
                    size: 2,
                })
            }
            0b111 => {
                if self.is_64bit {
                    // C.SD: sd rs2', offset(rs1') (RV64/128)
                    let rs2 = self.c_reg((insn >> 2) & 0x7);
                    let rs1 = self.c_reg((insn >> 7) & 0x7);
                    let uimm = (((insn >> 10) & 0x7) << 3) | (((insn >> 5) & 0x3) << 6);

                    let mem = MemoryRef::base_disp(rs1, uimm as i64, 8);
                    let inst = Instruction::new(address, 2, bytes, "c.sd")
                        .with_operation(Operation::Store)
                        .with_operands(vec![Operand::reg(rs2), Operand::Memory(mem)]);
                    Ok(DecodedInstruction {
                        instruction: inst,
                        size: 2,
                    })
                } else {
                    // C.FSW: fsw rs2', offset(rs1') (RV32 only)
                    let rs2 = self.c_reg((insn >> 2) & 0x7);
                    let rs1 = self.c_reg((insn >> 7) & 0x7);
                    let uimm = (((insn >> 6) & 0x1) << 2)
                        | (((insn >> 10) & 0x7) << 3)
                        | (((insn >> 5) & 0x1) << 6);

                    let mem = MemoryRef::base_disp(rs1, uimm as i64, 4);
                    let inst = Instruction::new(address, 2, bytes, "c.fsw")
                        .with_operation(Operation::Store)
                        .with_operands(vec![Operand::reg(rs2), Operand::Memory(mem)]);
                    Ok(DecodedInstruction {
                        instruction: inst,
                        size: 2,
                    })
                }
            }
            _ => Err(DecodeError::unknown_opcode(address, &bytes)),
        }
    }

    /// Decode quadrant 1 (C1) instructions.
    fn decode_c1(
        &self,
        insn: u16,
        address: u64,
        bytes: Vec<u8>,
        funct3: u8,
    ) -> Result<DecodedInstruction, DecodeError> {
        match funct3 {
            0b000 => {
                // C.NOP (rd=0) or C.ADDI
                let rd = (insn >> 7) & 0x1F;
                // imm[5|4:0] sign-extended
                let imm5 = ((insn >> 12) & 0x1) as i32;
                let imm4_0 = ((insn >> 2) & 0x1F) as i32;
                let imm = (imm5 << 5) | imm4_0;
                let imm = (imm << 26) >> 26; // sign extend from 6 bits

                if rd == 0 {
                    let inst =
                        Instruction::new(address, 2, bytes, "c.nop").with_operation(Operation::Nop);
                    Ok(DecodedInstruction {
                        instruction: inst,
                        size: 2,
                    })
                } else {
                    let inst = Instruction::new(address, 2, bytes, "c.addi")
                        .with_operation(Operation::Add)
                        .with_operands(vec![
                            Operand::reg(self.gpr(rd)),
                            Operand::reg(self.gpr(rd)),
                            Operand::imm(imm as i128, 6),
                        ]);
                    Ok(DecodedInstruction {
                        instruction: inst,
                        size: 2,
                    })
                }
            }
            0b001 => {
                if self.is_64bit {
                    // C.ADDIW (RV64/128): addiw rd, rd, imm
                    let rd = (insn >> 7) & 0x1F;
                    let imm5 = ((insn >> 12) & 0x1) as i32;
                    let imm4_0 = ((insn >> 2) & 0x1F) as i32;
                    let imm = (imm5 << 5) | imm4_0;
                    let imm = (imm << 26) >> 26;

                    if rd == 0 {
                        return Err(DecodeError::unknown_opcode(address, &bytes));
                    }

                    let inst = Instruction::new(address, 2, bytes, "c.addiw")
                        .with_operation(Operation::Add)
                        .with_operands(vec![
                            Operand::reg(self.gpr(rd)),
                            Operand::reg(self.gpr(rd)),
                            Operand::imm(imm as i128, 6),
                        ]);
                    Ok(DecodedInstruction {
                        instruction: inst,
                        size: 2,
                    })
                } else {
                    // C.JAL (RV32): jal x1, offset
                    let offset = self.decode_c_j_imm(insn);
                    let target = (address as i64 + offset as i64) as u64;

                    let inst = Instruction::new(address, 2, bytes, "c.jal")
                        .with_operation(Operation::Call)
                        .with_operands(vec![Operand::pc_rel(offset as i64, target)])
                        .with_control_flow(ControlFlow::Call {
                            target,
                            return_addr: address + 2,
                        });
                    Ok(DecodedInstruction {
                        instruction: inst,
                        size: 2,
                    })
                }
            }
            0b010 => {
                // C.LI: li rd, imm (addi rd, x0, imm)
                let rd = (insn >> 7) & 0x1F;
                let imm5 = ((insn >> 12) & 0x1) as i32;
                let imm4_0 = ((insn >> 2) & 0x1F) as i32;
                let imm = (imm5 << 5) | imm4_0;
                let imm = (imm << 26) >> 26;

                let inst = Instruction::new(address, 2, bytes, "c.li")
                    .with_operation(Operation::Move)
                    .with_operands(vec![
                        Operand::reg(self.gpr(rd)),
                        Operand::imm(imm as i128, 6),
                    ]);
                Ok(DecodedInstruction {
                    instruction: inst,
                    size: 2,
                })
            }
            0b011 => {
                let rd = (insn >> 7) & 0x1F;
                if rd == 2 {
                    // C.ADDI16SP: addi sp, sp, nzimm
                    // nzimm[9|4|6|8:7|5]
                    let imm9 = ((insn >> 12) & 0x1) as i32;
                    let imm4 = ((insn >> 6) & 0x1) as i32;
                    let imm6 = ((insn >> 5) & 0x1) as i32;
                    let imm8_7 = ((insn >> 3) & 0x3) as i32;
                    let imm5 = ((insn >> 2) & 0x1) as i32;
                    let imm = (imm9 << 9) | (imm8_7 << 7) | (imm6 << 6) | (imm5 << 5) | (imm4 << 4);
                    let imm = (imm << 22) >> 22; // sign extend from 10 bits

                    if imm == 0 {
                        return Err(DecodeError::unknown_opcode(address, &bytes));
                    }

                    let inst = Instruction::new(address, 2, bytes, "c.addi16sp")
                        .with_operation(Operation::Add)
                        .with_operands(vec![
                            Operand::reg(self.gpr(2)), // sp
                            Operand::reg(self.gpr(2)),
                            Operand::imm(imm as i128, 10),
                        ]);
                    Ok(DecodedInstruction {
                        instruction: inst,
                        size: 2,
                    })
                } else {
                    // C.LUI: lui rd, nzimm
                    let imm17 = ((insn >> 12) & 0x1) as i32;
                    let imm16_12 = ((insn >> 2) & 0x1F) as i32;
                    let imm = (imm17 << 17) | (imm16_12 << 12);
                    let imm = (imm << 14) >> 14; // sign extend from 18 bits

                    if imm == 0 || rd == 0 {
                        return Err(DecodeError::unknown_opcode(address, &bytes));
                    }

                    let inst = Instruction::new(address, 2, bytes, "c.lui")
                        .with_operation(Operation::Move)
                        .with_operands(vec![
                            Operand::reg(self.gpr(rd)),
                            Operand::imm(imm as i128, 20),
                        ]);
                    Ok(DecodedInstruction {
                        instruction: inst,
                        size: 2,
                    })
                }
            }
            0b100 => {
                // Arithmetic operations
                let funct2 = (insn >> 10) & 0x3;
                let rd = self.c_reg((insn >> 7) & 0x7);

                match funct2 {
                    0b00 => {
                        // C.SRLI: srli rd', rd', shamt
                        let shamt = self.decode_c_shamt(insn);
                        let inst = Instruction::new(address, 2, bytes, "c.srli")
                            .with_operation(Operation::Shr)
                            .with_operands(vec![
                                Operand::reg(rd),
                                Operand::reg(rd),
                                Operand::imm_unsigned(shamt as u64, 6),
                            ]);
                        Ok(DecodedInstruction {
                            instruction: inst,
                            size: 2,
                        })
                    }
                    0b01 => {
                        // C.SRAI: srai rd', rd', shamt
                        let shamt = self.decode_c_shamt(insn);
                        let inst = Instruction::new(address, 2, bytes, "c.srai")
                            .with_operation(Operation::Sar)
                            .with_operands(vec![
                                Operand::reg(rd),
                                Operand::reg(rd),
                                Operand::imm_unsigned(shamt as u64, 6),
                            ]);
                        Ok(DecodedInstruction {
                            instruction: inst,
                            size: 2,
                        })
                    }
                    0b10 => {
                        // C.ANDI: andi rd', rd', imm
                        let imm5 = ((insn >> 12) & 0x1) as i32;
                        let imm4_0 = ((insn >> 2) & 0x1F) as i32;
                        let imm = (imm5 << 5) | imm4_0;
                        let imm = (imm << 26) >> 26;

                        let inst = Instruction::new(address, 2, bytes, "c.andi")
                            .with_operation(Operation::And)
                            .with_operands(vec![
                                Operand::reg(rd),
                                Operand::reg(rd),
                                Operand::imm(imm as i128, 6),
                            ]);
                        Ok(DecodedInstruction {
                            instruction: inst,
                            size: 2,
                        })
                    }
                    0b11 => {
                        // Register-register operations
                        let funct1 = (insn >> 12) & 0x1;
                        let funct2_low = (insn >> 5) & 0x3;
                        let rs2 = self.c_reg((insn >> 2) & 0x7);

                        if funct1 == 0 {
                            let (mnemonic, operation) = match funct2_low {
                                0b00 => ("c.sub", Operation::Sub),
                                0b01 => ("c.xor", Operation::Xor),
                                0b10 => ("c.or", Operation::Or),
                                0b11 => ("c.and", Operation::And),
                                _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
                            };
                            let inst = Instruction::new(address, 2, bytes, mnemonic)
                                .with_operation(operation)
                                .with_operands(vec![
                                    Operand::reg(rd),
                                    Operand::reg(rd),
                                    Operand::reg(rs2),
                                ]);
                            Ok(DecodedInstruction {
                                instruction: inst,
                                size: 2,
                            })
                        } else if self.is_64bit {
                            let (mnemonic, operation) = match funct2_low {
                                0b00 => ("c.subw", Operation::Sub),
                                0b01 => ("c.addw", Operation::Add),
                                _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
                            };
                            let inst = Instruction::new(address, 2, bytes, mnemonic)
                                .with_operation(operation)
                                .with_operands(vec![
                                    Operand::reg(rd),
                                    Operand::reg(rd),
                                    Operand::reg(rs2),
                                ]);
                            Ok(DecodedInstruction {
                                instruction: inst,
                                size: 2,
                            })
                        } else {
                            Err(DecodeError::unknown_opcode(address, &bytes))
                        }
                    }
                    _ => Err(DecodeError::unknown_opcode(address, &bytes)),
                }
            }
            0b101 => {
                // C.J: jal x0, offset
                let offset = self.decode_c_j_imm(insn);
                let target = (address as i64 + offset as i64) as u64;

                let inst = Instruction::new(address, 2, bytes, "c.j")
                    .with_operation(Operation::Jump)
                    .with_operands(vec![Operand::pc_rel(offset as i64, target)])
                    .with_control_flow(ControlFlow::UnconditionalBranch { target });
                Ok(DecodedInstruction {
                    instruction: inst,
                    size: 2,
                })
            }
            0b110 => {
                // C.BEQZ: beq rs1', x0, offset
                let rs1 = self.c_reg((insn >> 7) & 0x7);
                let offset = self.decode_c_b_imm(insn);
                let target = (address as i64 + offset as i64) as u64;

                let inst = Instruction::new(address, 2, bytes, "c.beqz")
                    .with_operation(Operation::ConditionalJump)
                    .with_operands(vec![
                        Operand::reg(rs1),
                        Operand::pc_rel(offset as i64, target),
                    ])
                    .with_control_flow(ControlFlow::ConditionalBranch {
                        target,
                        condition: Condition::Equal,
                        fallthrough: address + 2,
                    });
                Ok(DecodedInstruction {
                    instruction: inst,
                    size: 2,
                })
            }
            0b111 => {
                // C.BNEZ: bne rs1', x0, offset
                let rs1 = self.c_reg((insn >> 7) & 0x7);
                let offset = self.decode_c_b_imm(insn);
                let target = (address as i64 + offset as i64) as u64;

                let inst = Instruction::new(address, 2, bytes, "c.bnez")
                    .with_operation(Operation::ConditionalJump)
                    .with_operands(vec![
                        Operand::reg(rs1),
                        Operand::pc_rel(offset as i64, target),
                    ])
                    .with_control_flow(ControlFlow::ConditionalBranch {
                        target,
                        condition: Condition::NotEqual,
                        fallthrough: address + 2,
                    });
                Ok(DecodedInstruction {
                    instruction: inst,
                    size: 2,
                })
            }
            _ => Err(DecodeError::unknown_opcode(address, &bytes)),
        }
    }

    /// Decode quadrant 2 (C2) instructions.
    fn decode_c2(
        &self,
        insn: u16,
        address: u64,
        bytes: Vec<u8>,
        funct3: u8,
    ) -> Result<DecodedInstruction, DecodeError> {
        match funct3 {
            0b000 => {
                // C.SLLI: slli rd, rd, shamt
                let rd = (insn >> 7) & 0x1F;
                let shamt = self.decode_c_shamt(insn);

                if rd == 0 {
                    return Err(DecodeError::unknown_opcode(address, &bytes));
                }

                let inst = Instruction::new(address, 2, bytes, "c.slli")
                    .with_operation(Operation::Shl)
                    .with_operands(vec![
                        Operand::reg(self.gpr(rd)),
                        Operand::reg(self.gpr(rd)),
                        Operand::imm_unsigned(shamt as u64, 6),
                    ]);
                Ok(DecodedInstruction {
                    instruction: inst,
                    size: 2,
                })
            }
            0b001 => {
                // C.FLDSP: fld rd, offset(sp)
                let rd = (insn >> 7) & 0x1F;
                // uimm[5|4:3|8:6]
                let uimm = (((insn >> 12) & 0x1) << 5)
                    | (((insn >> 5) & 0x3) << 3)
                    | (((insn >> 2) & 0x7) << 6);

                let mem = MemoryRef::base_disp(self.gpr(2), uimm as i64, 8);
                let inst = Instruction::new(address, 2, bytes, "c.fldsp")
                    .with_operation(Operation::Load)
                    .with_operands(vec![Operand::reg(self.gpr(rd)), Operand::Memory(mem)]);
                Ok(DecodedInstruction {
                    instruction: inst,
                    size: 2,
                })
            }
            0b010 => {
                // C.LWSP: lw rd, offset(sp)
                let rd = (insn >> 7) & 0x1F;
                // uimm[5|4:2|7:6]
                let uimm = (((insn >> 12) & 0x1) << 5)
                    | (((insn >> 4) & 0x7) << 2)
                    | (((insn >> 2) & 0x3) << 6);

                if rd == 0 {
                    return Err(DecodeError::unknown_opcode(address, &bytes));
                }

                let mem = MemoryRef::base_disp(self.gpr(2), uimm as i64, 4);
                let inst = Instruction::new(address, 2, bytes, "c.lwsp")
                    .with_operation(Operation::Load)
                    .with_operands(vec![Operand::reg(self.gpr(rd)), Operand::Memory(mem)]);
                Ok(DecodedInstruction {
                    instruction: inst,
                    size: 2,
                })
            }
            0b011 => {
                if self.is_64bit {
                    // C.LDSP: ld rd, offset(sp) (RV64/128)
                    let rd = (insn >> 7) & 0x1F;
                    // uimm[5|4:3|8:6]
                    let uimm = (((insn >> 12) & 0x1) << 5)
                        | (((insn >> 5) & 0x3) << 3)
                        | (((insn >> 2) & 0x7) << 6);

                    if rd == 0 {
                        return Err(DecodeError::unknown_opcode(address, &bytes));
                    }

                    let mem = MemoryRef::base_disp(self.gpr(2), uimm as i64, 8);
                    let inst = Instruction::new(address, 2, bytes, "c.ldsp")
                        .with_operation(Operation::Load)
                        .with_operands(vec![Operand::reg(self.gpr(rd)), Operand::Memory(mem)]);
                    Ok(DecodedInstruction {
                        instruction: inst,
                        size: 2,
                    })
                } else {
                    // C.FLWSP: flw rd, offset(sp) (RV32 only)
                    let rd = (insn >> 7) & 0x1F;
                    let uimm = (((insn >> 12) & 0x1) << 5)
                        | (((insn >> 4) & 0x7) << 2)
                        | (((insn >> 2) & 0x3) << 6);

                    let mem = MemoryRef::base_disp(self.gpr(2), uimm as i64, 4);
                    let inst = Instruction::new(address, 2, bytes, "c.flwsp")
                        .with_operation(Operation::Load)
                        .with_operands(vec![Operand::reg(self.gpr(rd)), Operand::Memory(mem)]);
                    Ok(DecodedInstruction {
                        instruction: inst,
                        size: 2,
                    })
                }
            }
            0b100 => {
                let bit12 = (insn >> 12) & 0x1;
                let rd = (insn >> 7) & 0x1F;
                let rs2 = (insn >> 2) & 0x1F;

                if bit12 == 0 {
                    if rs2 == 0 {
                        // C.JR: jalr x0, rs1, 0
                        if rd == 0 {
                            return Err(DecodeError::unknown_opcode(address, &bytes));
                        }
                        let inst = Instruction::new(address, 2, bytes, "c.jr")
                            .with_operation(Operation::Jump)
                            .with_operands(vec![Operand::reg(self.gpr(rd))])
                            .with_control_flow(ControlFlow::IndirectBranch {
                                possible_targets: vec![],
                            });
                        Ok(DecodedInstruction {
                            instruction: inst,
                            size: 2,
                        })
                    } else {
                        // C.MV: add rd, x0, rs2
                        if rd == 0 {
                            return Err(DecodeError::unknown_opcode(address, &bytes));
                        }
                        let inst = Instruction::new(address, 2, bytes, "c.mv")
                            .with_operation(Operation::Move)
                            .with_operands(vec![
                                Operand::reg(self.gpr(rd)),
                                Operand::reg(self.gpr(rs2)),
                            ]);
                        Ok(DecodedInstruction {
                            instruction: inst,
                            size: 2,
                        })
                    }
                } else if rs2 == 0 && rd == 0 {
                    // C.EBREAK
                    let inst = Instruction::new(address, 2, bytes, "c.ebreak")
                        .with_operation(Operation::Halt)
                        .with_control_flow(ControlFlow::Halt);
                    Ok(DecodedInstruction {
                        instruction: inst,
                        size: 2,
                    })
                } else if rs2 == 0 {
                    // C.JALR: jalr x1, rs1, 0
                    if rd == 1 {
                        // c.jalr ra is basically ret from a called function perspective
                        let inst = Instruction::new(address, 2, bytes, "c.jalr")
                            .with_operation(Operation::Call)
                            .with_operands(vec![Operand::reg(self.gpr(rd))])
                            .with_control_flow(ControlFlow::IndirectCall {
                                return_addr: address + 2,
                            });
                        Ok(DecodedInstruction {
                            instruction: inst,
                            size: 2,
                        })
                    } else {
                        let inst = Instruction::new(address, 2, bytes, "c.jalr")
                            .with_operation(Operation::Call)
                            .with_operands(vec![Operand::reg(self.gpr(rd))])
                            .with_control_flow(ControlFlow::IndirectCall {
                                return_addr: address + 2,
                            });
                        Ok(DecodedInstruction {
                            instruction: inst,
                            size: 2,
                        })
                    }
                } else {
                    // C.ADD: add rd, rd, rs2
                    if rd == 0 {
                        return Err(DecodeError::unknown_opcode(address, &bytes));
                    }
                    let inst = Instruction::new(address, 2, bytes, "c.add")
                        .with_operation(Operation::Add)
                        .with_operands(vec![
                            Operand::reg(self.gpr(rd)),
                            Operand::reg(self.gpr(rd)),
                            Operand::reg(self.gpr(rs2)),
                        ]);
                    Ok(DecodedInstruction {
                        instruction: inst,
                        size: 2,
                    })
                }
            }
            0b101 => {
                // C.FSDSP: fsd rs2, offset(sp)
                let rs2 = (insn >> 2) & 0x1F;
                // uimm[5:3|8:6]
                let uimm = (((insn >> 10) & 0x7) << 3) | (((insn >> 7) & 0x7) << 6);

                let mem = MemoryRef::base_disp(self.gpr(2), uimm as i64, 8);
                let inst = Instruction::new(address, 2, bytes, "c.fsdsp")
                    .with_operation(Operation::Store)
                    .with_operands(vec![Operand::reg(self.gpr(rs2)), Operand::Memory(mem)]);
                Ok(DecodedInstruction {
                    instruction: inst,
                    size: 2,
                })
            }
            0b110 => {
                // C.SWSP: sw rs2, offset(sp)
                let rs2 = (insn >> 2) & 0x1F;
                // uimm[5:2|7:6]
                let uimm = (((insn >> 9) & 0xF) << 2) | (((insn >> 7) & 0x3) << 6);

                let mem = MemoryRef::base_disp(self.gpr(2), uimm as i64, 4);
                let inst = Instruction::new(address, 2, bytes, "c.swsp")
                    .with_operation(Operation::Store)
                    .with_operands(vec![Operand::reg(self.gpr(rs2)), Operand::Memory(mem)]);
                Ok(DecodedInstruction {
                    instruction: inst,
                    size: 2,
                })
            }
            0b111 => {
                if self.is_64bit {
                    // C.SDSP: sd rs2, offset(sp) (RV64/128)
                    let rs2 = (insn >> 2) & 0x1F;
                    // uimm[5:3|8:6]
                    let uimm = (((insn >> 10) & 0x7) << 3) | (((insn >> 7) & 0x7) << 6);

                    let mem = MemoryRef::base_disp(self.gpr(2), uimm as i64, 8);
                    let inst = Instruction::new(address, 2, bytes, "c.sdsp")
                        .with_operation(Operation::Store)
                        .with_operands(vec![Operand::reg(self.gpr(rs2)), Operand::Memory(mem)]);
                    Ok(DecodedInstruction {
                        instruction: inst,
                        size: 2,
                    })
                } else {
                    // C.FSWSP: fsw rs2, offset(sp) (RV32 only)
                    let rs2 = (insn >> 2) & 0x1F;
                    let uimm = (((insn >> 9) & 0xF) << 2) | (((insn >> 7) & 0x3) << 6);

                    let mem = MemoryRef::base_disp(self.gpr(2), uimm as i64, 4);
                    let inst = Instruction::new(address, 2, bytes, "c.fswsp")
                        .with_operation(Operation::Store)
                        .with_operands(vec![Operand::reg(self.gpr(rs2)), Operand::Memory(mem)]);
                    Ok(DecodedInstruction {
                        instruction: inst,
                        size: 2,
                    })
                }
            }
            _ => Err(DecodeError::unknown_opcode(address, &bytes)),
        }
    }

    /// Decode C.J/C.JAL immediate (11-bit signed, scaled by 2).
    fn decode_c_j_imm(&self, insn: u16) -> i32 {
        // imm[11|4|9:8|10|6|7|3:1|5] from bits 12:2
        let imm11 = ((insn >> 12) & 0x1) as i32;
        let imm4 = ((insn >> 11) & 0x1) as i32;
        let imm9_8 = ((insn >> 9) & 0x3) as i32;
        let imm10 = ((insn >> 8) & 0x1) as i32;
        let imm6 = ((insn >> 7) & 0x1) as i32;
        let imm7 = ((insn >> 6) & 0x1) as i32;
        let imm3_1 = ((insn >> 3) & 0x7) as i32;
        let imm5 = ((insn >> 2) & 0x1) as i32;

        let imm = (imm11 << 11)
            | (imm10 << 10)
            | (imm9_8 << 8)
            | (imm7 << 7)
            | (imm6 << 6)
            | (imm5 << 5)
            | (imm4 << 4)
            | (imm3_1 << 1);
        // Sign extend from 12 bits
        (imm << 20) >> 20
    }

    /// Decode C.BEQZ/C.BNEZ immediate (8-bit signed, scaled by 2).
    fn decode_c_b_imm(&self, insn: u16) -> i32 {
        // imm[8|4:3|7:6|2:1|5] from bits 12:10, 6:2
        let imm8 = ((insn >> 12) & 0x1) as i32;
        let imm4_3 = ((insn >> 10) & 0x3) as i32;
        let imm7_6 = ((insn >> 5) & 0x3) as i32;
        let imm2_1 = ((insn >> 3) & 0x3) as i32;
        let imm5 = ((insn >> 2) & 0x1) as i32;

        let imm = (imm8 << 8) | (imm7_6 << 6) | (imm5 << 5) | (imm4_3 << 3) | (imm2_1 << 1);
        // Sign extend from 9 bits
        (imm << 23) >> 23
    }

    /// Decode shift amount for C.SLLI/C.SRLI/C.SRAI.
    fn decode_c_shamt(&self, insn: u16) -> u32 {
        let shamt5 = ((insn >> 12) & 0x1) as u32;
        let shamt4_0 = ((insn >> 2) & 0x1F) as u32;
        if self.is_64bit {
            (shamt5 << 5) | shamt4_0
        } else {
            shamt4_0 // RV32 only uses 5-bit shamt
        }
    }
}

impl Default for RiscVDisassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Disassembler for RiscVDisassembler {
    fn decode_instruction(
        &self,
        bytes: &[u8],
        address: u64,
    ) -> Result<DecodedInstruction, DecodeError> {
        self.decode(bytes, address)
    }

    fn min_instruction_size(&self) -> usize {
        2 // Compressed instructions are 16-bit
    }

    fn max_instruction_size(&self) -> usize {
        4 // Standard instructions are 32-bit
    }

    fn is_fixed_width(&self) -> bool {
        false // Can have compressed 16-bit instructions
    }

    fn architecture(&self) -> Architecture {
        if self.is_64bit {
            Architecture::RiscV64
        } else {
            Architecture::RiscV32
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addi() {
        let disasm = RiscVDisassembler::new();
        // addi x1, x0, 42 (li x1, 42)
        // imm=42, rs1=0, funct3=000, rd=1, opcode=0010011
        let insn: u32 = (42 << 20) | (1 << 7) | 0b0010011;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "li");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_add() {
        let disasm = RiscVDisassembler::new();
        // add x3, x1, x2
        // funct7=0, rs2=2, rs1=1, funct3=000, rd=3, opcode=0110011
        let insn: u32 = ((2 << 20) | (1 << 15)) | (3 << 7) | 0b0110011;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "add");
    }

    #[test]
    fn test_jal() {
        let disasm = RiscVDisassembler::new();
        // jal x1, +8 (call to pc+8)
        // The J-immediate encoding is complex, let's test a simple case
        // jal x0, 0 (j 0x1000 - infinite loop)
        let insn: u32 = 0b1101111; // JAL with all imm bits 0, rd=0
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "j");
    }

    #[test]
    fn test_ret() {
        let disasm = RiscVDisassembler::new();
        // ret = jalr x0, x1, 0
        let insn: u32 = (1 << 15) | 0b1100111;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ret");
        assert!(result.instruction.is_return());
    }

    #[test]
    fn test_beq() {
        let disasm = RiscVDisassembler::new();
        // beq x1, x2, +8
        // B-type: imm[12|10:5] rs2 rs1 funct3 imm[4:1|11] opcode
        // For offset +8: imm12=0, imm11=0, imm10:5=0, imm4:1=4
        let imm = 8i32;
        let imm12 = ((imm >> 12) & 1) as u32;
        let imm11 = ((imm >> 11) & 1) as u32;
        let imm10_5 = ((imm >> 5) & 0x3F) as u32;
        let imm4_1 = ((imm >> 1) & 0xF) as u32;
        let insn: u32 = ((imm12 << 31) | (imm10_5 << 25) | (2 << 20) | (1 << 15))
            | (imm4_1 << 8)
            | (imm11 << 7)
            | 0b1100011;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "beq");
    }

    #[test]
    fn test_lw() {
        let disasm = RiscVDisassembler::new();
        // lw x1, 4(x2)
        let insn: u32 = (4 << 20) | (2 << 15) | (0b010 << 12) | (1 << 7) | 0b0000011;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "lw");
    }

    #[test]
    fn test_ecall() {
        let disasm = RiscVDisassembler::new();
        // ecall
        let insn: u32 = 0b1110011;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ecall");
    }

    // ==================== Compressed (RVC) Tests ====================

    #[test]
    fn test_c_nop() {
        let disasm = RiscVDisassembler::new();
        // c.nop: 0x0001 (funct3=000, imm=0, rd=0, op=01)
        let insn: u16 = 0x0001;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "c.nop");
        assert_eq!(result.size, 2);
    }

    #[test]
    fn test_c_addi() {
        let disasm = RiscVDisassembler::new();
        // c.addi x10, 5: funct3=000, imm[5]=0, rd=10, imm[4:0]=5, op=01
        // Encoding: 000 0 01010 00101 01 = 0x0515
        let insn: u16 = (10 << 7) | (5 << 2) | 0b01;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "c.addi");
        assert_eq!(result.size, 2);
    }

    #[test]
    fn test_c_li() {
        let disasm = RiscVDisassembler::new();
        // c.li x10, 42: funct3=010, imm[5]=1, rd=10, imm[4:0]=10, op=01
        // imm = 42 = 0b101010, but only 6 bits: 42 won't fit, use 10 instead
        // c.li x10, 10: funct3=010, imm[5]=0, rd=10, imm[4:0]=10, op=01
        let insn: u16 = (0b010 << 13) | (10 << 7) | (10 << 2) | 0b01;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "c.li");
        assert_eq!(result.size, 2);
    }

    #[test]
    fn test_c_lwsp() {
        let disasm = RiscVDisassembler::new();
        // c.lwsp x10, 0(sp): funct3=010, uimm[5]=0, rd=10, uimm[4:2]=0, uimm[7:6]=0, op=10
        let insn: u16 = ((0b010 << 13) | (10 << 7)) | 0b10;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "c.lwsp");
        assert_eq!(result.size, 2);
    }

    #[test]
    fn test_c_swsp() {
        let disasm = RiscVDisassembler::new();
        // c.swsp x10, 0(sp): funct3=110, uimm[5:2]=0, uimm[7:6]=0, rs2=10, op=10
        let insn: u16 = (0b110 << 13) | (10 << 2) | 0b10;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "c.swsp");
        assert_eq!(result.size, 2);
    }

    #[test]
    fn test_c_lw() {
        let disasm = RiscVDisassembler::new();
        // c.lw x8, 0(x8): funct3=010, uimm[5:3]=0, rs1'=0(x8), uimm[2|6]=0, rd'=0(x8), op=00
        let insn: u16 = 0b010 << 13;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "c.lw");
        assert_eq!(result.size, 2);
    }

    #[test]
    fn test_c_sw() {
        let disasm = RiscVDisassembler::new();
        // c.sw x8, 0(x8): funct3=110, uimm[5:3]=0, rs1'=0(x8), uimm[2|6]=0, rs2'=0(x8), op=00
        let insn: u16 = 0b110 << 13;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "c.sw");
        assert_eq!(result.size, 2);
    }

    #[test]
    fn test_c_j() {
        let disasm = RiscVDisassembler::new();
        // c.j 0 (jump to self): funct3=101, imm=0, op=01
        let insn: u16 = (0b101 << 13) | 0b01;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "c.j");
        assert_eq!(result.size, 2);
    }

    #[test]
    fn test_c_beqz() {
        let disasm = RiscVDisassembler::new();
        // c.beqz x8, 0: funct3=110, offset=0, rs1'=0(x8), op=01
        let insn: u16 = (0b110 << 13) | 0b01;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "c.beqz");
        assert_eq!(result.size, 2);
    }

    #[test]
    fn test_c_bnez() {
        let disasm = RiscVDisassembler::new();
        // c.bnez x8, 0: funct3=111, offset=0, rs1'=0(x8), op=01
        let insn: u16 = (0b111 << 13) | 0b01;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "c.bnez");
        assert_eq!(result.size, 2);
    }

    #[test]
    fn test_c_mv() {
        let disasm = RiscVDisassembler::new();
        // c.mv x10, x11: funct4=1000, rd=10, rs2=11, op=10
        let insn: u16 = (0b100 << 13) | (10 << 7) | (11 << 2) | 0b10;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "c.mv");
        assert_eq!(result.size, 2);
    }

    #[test]
    fn test_c_add() {
        let disasm = RiscVDisassembler::new();
        // c.add x10, x11: funct4=1001, rd=10, rs2=11, op=10
        let insn: u16 = (0b100 << 13) | (1 << 12) | (10 << 7) | (11 << 2) | 0b10;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "c.add");
        assert_eq!(result.size, 2);
    }

    #[test]
    fn test_c_jr() {
        let disasm = RiscVDisassembler::new();
        // c.jr x10: funct4=1000, rd=10, rs2=0, op=10
        let insn: u16 = ((0b100 << 13) | (10 << 7)) | 0b10;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "c.jr");
        assert_eq!(result.size, 2);
    }

    #[test]
    fn test_c_jalr() {
        let disasm = RiscVDisassembler::new();
        // c.jalr x10: funct4=1001, rd=10, rs2=0, op=10
        let insn: u16 = ((0b100 << 13) | (1 << 12) | (10 << 7)) | 0b10;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "c.jalr");
        assert_eq!(result.size, 2);
    }

    #[test]
    fn test_c_slli() {
        let disasm = RiscVDisassembler::new();
        // c.slli x10, 5: funct3=000, shamt[5]=0, rd=10, shamt[4:0]=5, op=10
        let insn: u16 = (10 << 7) | (5 << 2) | 0b10;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "c.slli");
        assert_eq!(result.size, 2);
    }

    #[test]
    fn test_c_ebreak() {
        let disasm = RiscVDisassembler::new();
        // c.ebreak: 0x9002 (funct4=1001, rd=0, rs2=0, op=10)
        let insn: u16 = ((0b100 << 13) | (1 << 12)) | 0b10;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "c.ebreak");
        assert_eq!(result.size, 2);
    }

    #[test]
    fn test_c_ldsp_rv64() {
        let disasm = RiscVDisassembler::new();
        // c.ldsp x10, 0(sp): funct3=011, uimm[5]=0, rd=10, uimm[4:3]=0, uimm[8:6]=0, op=10
        let insn: u16 = ((0b011 << 13) | (10 << 7)) | 0b10;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "c.ldsp");
        assert_eq!(result.size, 2);
    }

    #[test]
    fn test_c_sdsp_rv64() {
        let disasm = RiscVDisassembler::new();
        // c.sdsp x10, 0(sp): funct3=111, uimm[5:3]=0, uimm[8:6]=0, rs2=10, op=10
        let insn: u16 = (0b111 << 13) | (10 << 2) | 0b10;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "c.sdsp");
        assert_eq!(result.size, 2);
    }

    // ==================== Floating-Point Extension (F/D) Tests ====================

    #[test]
    fn test_flw() {
        let disasm = RiscVDisassembler::new();
        // flw f1, 0(x2): imm=0, rs1=2, funct3=010, rd=1, opcode=0000111
        let insn: u32 = (2 << 15) | (0b010 << 12) | (1 << 7) | 0b0000111;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "flw");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_fld() {
        let disasm = RiscVDisassembler::new();
        // fld f1, 8(x2): imm=8, rs1=2, funct3=011, rd=1, opcode=0000111
        let insn: u32 = (8 << 20) | (2 << 15) | (0b011 << 12) | (1 << 7) | 0b0000111;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "fld");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_fsw() {
        let disasm = RiscVDisassembler::new();
        // fsw f1, 0(x2): imm[11:5]=0, rs2=1, rs1=2, funct3=010, imm[4:0]=0, opcode=0100111
        let insn: u32 = ((1 << 20) | (2 << 15) | (0b010 << 12)) | 0b0100111;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "fsw");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_fsd() {
        let disasm = RiscVDisassembler::new();
        // fsd f1, 8(x2): imm[11:5]=0, rs2=1, rs1=2, funct3=011, imm[4:0]=8, opcode=0100111
        let insn: u32 = (1 << 20) | (2 << 15) | (0b011 << 12) | (8 << 7) | 0b0100111;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "fsd");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_fadd_s() {
        let disasm = RiscVDisassembler::new();
        // fadd.s f3, f1, f2: funct7=0000000, rs2=2, rs1=1, rm=000, rd=3, opcode=1010011
        let insn: u32 = ((2 << 20) | (1 << 15)) | (3 << 7) | 0b1010011;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "fadd.s");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_fadd_d() {
        let disasm = RiscVDisassembler::new();
        // fadd.d f3, f1, f2: funct7=0000001, rs2=2, rs1=1, rm=000, rd=3, opcode=1010011
        let insn: u32 = ((0b0000001 << 25) | (2 << 20) | (1 << 15)) | (3 << 7) | 0b1010011;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "fadd.d");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_fsub_s() {
        let disasm = RiscVDisassembler::new();
        // fsub.s f3, f1, f2: funct7=0000100, rs2=2, rs1=1, rm=000, rd=3, opcode=1010011
        let insn: u32 = ((0b0000100 << 25) | (2 << 20) | (1 << 15)) | (3 << 7) | 0b1010011;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "fsub.s");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_fmul_s() {
        let disasm = RiscVDisassembler::new();
        // fmul.s f3, f1, f2: funct7=0001000, rs2=2, rs1=1, rm=000, rd=3, opcode=1010011
        let insn: u32 = ((0b0001000 << 25) | (2 << 20) | (1 << 15)) | (3 << 7) | 0b1010011;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "fmul.s");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_fdiv_s() {
        let disasm = RiscVDisassembler::new();
        // fdiv.s f3, f1, f2: funct7=0001100, rs2=2, rs1=1, rm=000, rd=3, opcode=1010011
        let insn: u32 = ((0b0001100 << 25) | (2 << 20) | (1 << 15)) | (3 << 7) | 0b1010011;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "fdiv.s");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_fsqrt_s() {
        let disasm = RiscVDisassembler::new();
        // fsqrt.s f2, f1: funct7=0101100, rs2=0, rs1=1, rm=000, rd=2, opcode=1010011
        let insn: u32 = ((0b0101100 << 25) | (1 << 15)) | (2 << 7) | 0b1010011;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "fsqrt.s");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_fmin_s() {
        let disasm = RiscVDisassembler::new();
        // fmin.s f3, f1, f2: funct7=0010100, rs2=2, rs1=1, rm=000, rd=3, opcode=1010011
        let insn: u32 = ((0b0010100 << 25) | (2 << 20) | (1 << 15)) | (3 << 7) | 0b1010011;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "fmin.s");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_fmax_s() {
        let disasm = RiscVDisassembler::new();
        // fmax.s f3, f1, f2: funct7=0010100, rs2=2, rs1=1, rm=001, rd=3, opcode=1010011
        let insn: u32 =
            (0b0010100 << 25) | (2 << 20) | (1 << 15) | (0b001 << 12) | (3 << 7) | 0b1010011;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "fmax.s");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_feq_s() {
        let disasm = RiscVDisassembler::new();
        // feq.s x3, f1, f2: funct7=1010000, rs2=2, rs1=1, rm=010, rd=3, opcode=1010011
        let insn: u32 =
            (0b1010000 << 25) | (2 << 20) | (1 << 15) | (0b010 << 12) | (3 << 7) | 0b1010011;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "feq.s");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_flt_s() {
        let disasm = RiscVDisassembler::new();
        // flt.s x3, f1, f2: funct7=1010000, rs2=2, rs1=1, rm=001, rd=3, opcode=1010011
        let insn: u32 =
            (0b1010000 << 25) | (2 << 20) | (1 << 15) | (0b001 << 12) | (3 << 7) | 0b1010011;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "flt.s");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_fle_s() {
        let disasm = RiscVDisassembler::new();
        // fle.s x3, f1, f2: funct7=1010000, rs2=2, rs1=1, rm=000, rd=3, opcode=1010011
        let insn: u32 = ((0b1010000 << 25) | (2 << 20) | (1 << 15)) | (3 << 7) | 0b1010011;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "fle.s");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_fmadd_s() {
        let disasm = RiscVDisassembler::new();
        // fmadd.s f4, f1, f2, f3: rs3=3, fmt=00, rs2=2, rs1=1, rm=000, rd=4, opcode=1000011
        let insn: u32 = ((3 << 27) | (2 << 20) | (1 << 15)) | (4 << 7) | 0b1000011;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "fmadd.s");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_fmsub_s() {
        let disasm = RiscVDisassembler::new();
        // fmsub.s f4, f1, f2, f3: rs3=3, fmt=00, rs2=2, rs1=1, rm=000, rd=4, opcode=1000111
        let insn: u32 = ((3 << 27) | (2 << 20) | (1 << 15)) | (4 << 7) | 0b1000111;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "fmsub.s");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_fcvt_w_s() {
        let disasm = RiscVDisassembler::new();
        // fcvt.w.s x3, f1: funct7=1100000, rs2=0, rs1=1, rm=000, rd=3, opcode=1010011
        let insn: u32 = ((0b1100000 << 25) | (1 << 15)) | (3 << 7) | 0b1010011;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "fcvt.w.s");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_fcvt_s_w() {
        let disasm = RiscVDisassembler::new();
        // fcvt.s.w f3, x1: funct7=1101000, rs2=0, rs1=1, rm=000, rd=3, opcode=1010011
        let insn: u32 = ((0b1101000 << 25) | (1 << 15)) | (3 << 7) | 0b1010011;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "fcvt.s.w");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_fmv_x_w() {
        let disasm = RiscVDisassembler::new();
        // fmv.x.w x3, f1: funct7=1110000, rs2=0, rs1=1, rm=000, rd=3, opcode=1010011
        let insn: u32 = ((0b1110000 << 25) | (1 << 15)) | (3 << 7) | 0b1010011;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "fmv.x.w");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_fmv_w_x() {
        let disasm = RiscVDisassembler::new();
        // fmv.w.x f3, x1: funct7=1111000, rs2=0, rs1=1, rm=000, rd=3, opcode=1010011
        let insn: u32 = ((0b1111000 << 25) | (1 << 15)) | (3 << 7) | 0b1010011;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "fmv.w.x");
        assert_eq!(result.size, 4);
    }

    // ==================== Vector Extension (V) Tests ====================

    #[test]
    fn test_vsetvli() {
        let disasm = RiscVDisassembler::new();
        // vsetvli x1, x2, e32,m1: bit31=0, zimm=0x008, rs1=2, funct3=111, rd=1, opcode=1010111
        let insn: u32 = (0x008 << 20) | (2 << 15) | (0b111 << 12) | (1 << 7) | 0b1010111;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "vsetvli");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_vsetivli() {
        let disasm = RiscVDisassembler::new();
        // vsetivli x1, 8, e32,m1: bit31=1, bit30=1, zimm=0x008, uimm=8, funct3=111, rd=1, opcode=1010111
        let insn: u32 =
            (0b11 << 30) | (0x008 << 20) | (8 << 15) | (0b111 << 12) | (1 << 7) | 0b1010111;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "vsetivli");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_vsetvl() {
        let disasm = RiscVDisassembler::new();
        // vsetvl x1, x2, x3: bit31=1, bit30=0, rs2=3, rs1=2, funct3=111, rd=1, opcode=1010111
        let insn: u32 = (0b10 << 30) | (3 << 20) | (2 << 15) | (0b111 << 12) | (1 << 7) | 0b1010111;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "vsetvl");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_vadd_vv() {
        let disasm = RiscVDisassembler::new();
        // vadd.vv v1, v2, v3: funct6=000000, vm=1, vs2=2, vs1=3, funct3=000, vd=1, opcode=1010111
        let insn: u32 = ((1 << 25) | (2 << 20) | (3 << 15)) | (1 << 7) | 0b1010111;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "vadd.vv");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_vadd_vx() {
        let disasm = RiscVDisassembler::new();
        // vadd.vx v1, v2, x3: funct6=000000, vm=1, vs2=2, rs1=3, funct3=100, vd=1, opcode=1010111
        let insn: u32 = (1 << 25) | (2 << 20) | (3 << 15) | (0b100 << 12) | (1 << 7) | 0b1010111;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "vadd.vx");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_vadd_vi() {
        let disasm = RiscVDisassembler::new();
        // vadd.vi v1, v2, 5: funct6=000000, vm=1, vs2=2, imm=5, funct3=011, vd=1, opcode=1010111
        let insn: u32 = (1 << 25) | (2 << 20) | (5 << 15) | (0b011 << 12) | (1 << 7) | 0b1010111;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "vadd.vi");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_vsub_vv() {
        let disasm = RiscVDisassembler::new();
        // vsub.vv v1, v2, v3: funct6=000010, vm=1, vs2=2, vs1=3, funct3=000, vd=1, opcode=1010111
        let insn: u32 =
            ((0b000010 << 26) | (1 << 25) | (2 << 20) | (3 << 15)) | (1 << 7) | 0b1010111;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "vsub.vv");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_vmul_vv() {
        let disasm = RiscVDisassembler::new();
        // vmul.vv v1, v2, v3: funct6=100100, vm=1, vs2=2, vs1=3, funct3=010, vd=1, opcode=1010111
        let insn: u32 = (0b100100 << 26)
            | (1 << 25)
            | (2 << 20)
            | (3 << 15)
            | (0b010 << 12)
            | (1 << 7)
            | 0b1010111;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "vmul.vv");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_vdiv_vv() {
        let disasm = RiscVDisassembler::new();
        // vdiv.vv v1, v2, v3: funct6=100001, vm=1, vs2=2, vs1=3, funct3=010, vd=1, opcode=1010111
        let insn: u32 = (0b100001 << 26)
            | (1 << 25)
            | (2 << 20)
            | (3 << 15)
            | (0b010 << 12)
            | (1 << 7)
            | 0b1010111;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "vdiv.vv");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_vand_vv() {
        let disasm = RiscVDisassembler::new();
        // vand.vv v1, v2, v3: funct6=001001, vm=1, vs2=2, vs1=3, funct3=000, vd=1, opcode=1010111
        let insn: u32 =
            ((0b001001 << 26) | (1 << 25) | (2 << 20) | (3 << 15)) | (1 << 7) | 0b1010111;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "vand.vv");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_vor_vv() {
        let disasm = RiscVDisassembler::new();
        // vor.vv v1, v2, v3: funct6=001010, vm=1, vs2=2, vs1=3, funct3=000, vd=1, opcode=1010111
        let insn: u32 =
            ((0b001010 << 26) | (1 << 25) | (2 << 20) | (3 << 15)) | (1 << 7) | 0b1010111;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "vor.vv");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_vxor_vv() {
        let disasm = RiscVDisassembler::new();
        // vxor.vv v1, v2, v3: funct6=001011, vm=1, vs2=2, vs1=3, funct3=000, vd=1, opcode=1010111
        let insn: u32 =
            ((0b001011 << 26) | (1 << 25) | (2 << 20) | (3 << 15)) | (1 << 7) | 0b1010111;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "vxor.vv");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_vmseq_vv() {
        let disasm = RiscVDisassembler::new();
        // vmseq.vv v1, v2, v3: funct6=011000, vm=1, vs2=2, vs1=3, funct3=000, vd=1, opcode=1010111
        let insn: u32 =
            ((0b011000 << 26) | (1 << 25) | (2 << 20) | (3 << 15)) | (1 << 7) | 0b1010111;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "vmseq.vv");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_vle32() {
        let disasm = RiscVDisassembler::new();
        // vle32.v v1, (x2): nf=000, mop=00, vm=1, rs2=0, rs1=2, width=110, vd=1, opcode=0000111
        let insn: u32 = (1 << 25) | (2 << 15) | (0b110 << 12) | (1 << 7) | 0b0000111;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "vle32.v");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_vse32() {
        let disasm = RiscVDisassembler::new();
        // vse32.v v1, (x2): nf=000, mop=00, vm=1, rs2=0, rs1=2, width=110, vs3=1, opcode=0100111
        let insn: u32 = (1 << 25) | (2 << 15) | (0b110 << 12) | (1 << 7) | 0b0100111;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "vse32.v");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_vfadd_vf() {
        let disasm = RiscVDisassembler::new();
        // vfadd.vf v1, v2, f3: funct6=000000, vm=1, vs2=2, rs1=3, funct3=101, vd=1, opcode=1010111
        let insn: u32 = (1 << 25) | (2 << 20) | (3 << 15) | (0b101 << 12) | (1 << 7) | 0b1010111;
        let bytes = insn.to_le_bytes();
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "vfadd.vf");
        assert_eq!(result.size, 4);
    }
}
