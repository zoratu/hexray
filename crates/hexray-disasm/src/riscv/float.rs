//! RISC-V F (single-precision) and D (double-precision) floating-point extension decoder.
//!
//! This module handles decoding of:
//! - F extension: 32-bit single-precision floating-point operations
//! - D extension: 64-bit double-precision floating-point operations

use crate::{DecodeError, DecodedInstruction};
use hexray_core::{
    Architecture, Instruction, MemoryRef, Operand, Operation, Register, RegisterClass,
};

/// Floating-point decoder for RISC-V F/D extensions.
pub struct FloatDecoder {
    is_64bit: bool,
}

impl FloatDecoder {
    pub fn new(is_64bit: bool) -> Self {
        Self { is_64bit }
    }

    /// Creates a floating-point register.
    fn fpr(&self, id: u16) -> Register {
        Register::new(
            if self.is_64bit {
                Architecture::RiscV64
            } else {
                Architecture::RiscV32
            },
            RegisterClass::FloatingPoint,
            id + 64, // F0 starts at 64
            if self.is_64bit { 64 } else { 32 },
        )
    }

    /// Creates a general-purpose register.
    fn gpr(&self, id: u16) -> Register {
        let class = match id {
            0 => RegisterClass::Other,
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

    /// Extract rs3 field (bits 31:27) for R4-type
    fn rs3(insn: u32) -> u16 {
        ((insn >> 27) & 0x1F) as u16
    }

    /// Extract funct3/rm field (bits 14:12)
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
        ((imm as i32) << 20) >> 20
    }

    /// Decode floating-point load instruction (FLW, FLD).
    pub fn decode_load(
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
            0b010 => ("flw", 4), // FLW - load 32-bit float
            0b011 => ("fld", 8), // FLD - load 64-bit double
            _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
        };

        let mem = if imm == 0 {
            MemoryRef::base(self.gpr(rs1), size)
        } else {
            MemoryRef::base_disp(self.gpr(rs1), imm as i64, size)
        };

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(Operation::FloatLoad)
            .with_operands(vec![Operand::reg(self.fpr(rd)), Operand::Memory(mem)]);

        Ok(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode floating-point store instruction (FSW, FSD).
    pub fn decode_store(
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
            0b010 => ("fsw", 4), // FSW - store 32-bit float
            0b011 => ("fsd", 8), // FSD - store 64-bit double
            _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
        };

        let mem = if imm == 0 {
            MemoryRef::base(self.gpr(rs1), size)
        } else {
            MemoryRef::base_disp(self.gpr(rs1), imm as i64, size)
        };

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(Operation::FloatStore)
            .with_operands(vec![Operand::reg(self.fpr(rs2)), Operand::Memory(mem)]);

        Ok(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode FMADD instruction.
    pub fn decode_fmadd(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        self.decode_r4_type(insn, address, bytes, "fmadd", Operation::FloatMulAdd)
    }

    /// Decode FMSUB instruction.
    pub fn decode_fmsub(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        self.decode_r4_type(insn, address, bytes, "fmsub", Operation::FloatMulSub)
    }

    /// Decode FNMSUB instruction.
    pub fn decode_fnmsub(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        self.decode_r4_type(insn, address, bytes, "fnmsub", Operation::FloatNegMulSub)
    }

    /// Decode FNMADD instruction.
    pub fn decode_fnmadd(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        self.decode_r4_type(insn, address, bytes, "fnmadd", Operation::FloatNegMulAdd)
    }

    /// Decode R4-type (fused multiply-add) instruction.
    fn decode_r4_type(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
        base_mnemonic: &str,
        operation: Operation,
    ) -> Result<DecodedInstruction, DecodeError> {
        let rd = Self::rd(insn);
        let rs1 = Self::rs1(insn);
        let rs2 = Self::rs2(insn);
        let rs3 = Self::rs3(insn);
        let fmt = (insn >> 25) & 0x3;

        let suffix = match fmt {
            0b00 => ".s",
            0b01 => ".d",
            _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
        };

        let mnemonic = format!("{}{}", base_mnemonic, suffix);

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(operation)
            .with_operands(vec![
                Operand::reg(self.fpr(rd)),
                Operand::reg(self.fpr(rs1)),
                Operand::reg(self.fpr(rs2)),
                Operand::reg(self.fpr(rs3)),
            ]);

        Ok(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode OP-FP instructions (arithmetic, compare, convert, etc.).
    pub fn decode_op_fp(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let rd = Self::rd(insn);
        let rs1 = Self::rs1(insn);
        let rs2 = Self::rs2(insn);
        let rm = Self::funct3(insn);
        let funct7 = Self::funct7(insn);

        // Determine precision from bits 26:25 (fmt field)
        let fmt = (funct7 & 0x3) as u8;
        let is_double = fmt == 0b01;
        let suffix = if is_double { ".d" } else { ".s" };

        // High bits of funct7 determine operation
        let op = funct7 >> 2;

        match op {
            0b00000 => {
                // FADD
                let mnemonic = format!("fadd{}", suffix);
                let inst = Instruction::new(address, 4, bytes, mnemonic)
                    .with_operation(Operation::FloatAdd)
                    .with_operands(vec![
                        Operand::reg(self.fpr(rd)),
                        Operand::reg(self.fpr(rs1)),
                        Operand::reg(self.fpr(rs2)),
                    ]);
                Ok(DecodedInstruction {
                    instruction: inst,
                    size: 4,
                })
            }
            0b00001 => {
                // FSUB
                let mnemonic = format!("fsub{}", suffix);
                let inst = Instruction::new(address, 4, bytes, mnemonic)
                    .with_operation(Operation::FloatSub)
                    .with_operands(vec![
                        Operand::reg(self.fpr(rd)),
                        Operand::reg(self.fpr(rs1)),
                        Operand::reg(self.fpr(rs2)),
                    ]);
                Ok(DecodedInstruction {
                    instruction: inst,
                    size: 4,
                })
            }
            0b00010 => {
                // FMUL
                let mnemonic = format!("fmul{}", suffix);
                let inst = Instruction::new(address, 4, bytes, mnemonic)
                    .with_operation(Operation::FloatMul)
                    .with_operands(vec![
                        Operand::reg(self.fpr(rd)),
                        Operand::reg(self.fpr(rs1)),
                        Operand::reg(self.fpr(rs2)),
                    ]);
                Ok(DecodedInstruction {
                    instruction: inst,
                    size: 4,
                })
            }
            0b00011 => {
                // FDIV
                let mnemonic = format!("fdiv{}", suffix);
                let inst = Instruction::new(address, 4, bytes, mnemonic)
                    .with_operation(Operation::FloatDiv)
                    .with_operands(vec![
                        Operand::reg(self.fpr(rd)),
                        Operand::reg(self.fpr(rs1)),
                        Operand::reg(self.fpr(rs2)),
                    ]);
                Ok(DecodedInstruction {
                    instruction: inst,
                    size: 4,
                })
            }
            0b01011 => {
                // FSQRT (rs2 must be 0)
                if rs2 != 0 {
                    return Err(DecodeError::unknown_opcode(address, &bytes));
                }
                let mnemonic = format!("fsqrt{}", suffix);
                let inst = Instruction::new(address, 4, bytes, mnemonic)
                    .with_operation(Operation::FloatSqrt)
                    .with_operands(vec![
                        Operand::reg(self.fpr(rd)),
                        Operand::reg(self.fpr(rs1)),
                    ]);
                Ok(DecodedInstruction {
                    instruction: inst,
                    size: 4,
                })
            }
            0b00100 => {
                // FSGNJ/FSGNJN/FSGNJX
                let (mnemonic, operation) = match rm {
                    0b000 => {
                        // FSGNJ - if rs1 == rs2, it's FMV pseudo-instruction
                        if rs1 == rs2 {
                            (format!("fmv{}", suffix), Operation::FloatMove)
                        } else {
                            (format!("fsgnj{}", suffix), Operation::FloatSignInject)
                        }
                    }
                    0b001 => {
                        // FSGNJN - if rs1 == rs2, it's FNEG pseudo-instruction
                        if rs1 == rs2 {
                            (format!("fneg{}", suffix), Operation::FloatSignInject)
                        } else {
                            (format!("fsgnjn{}", suffix), Operation::FloatSignInject)
                        }
                    }
                    0b010 => {
                        // FSGNJX - if rs1 == rs2, it's FABS pseudo-instruction
                        if rs1 == rs2 {
                            (format!("fabs{}", suffix), Operation::FloatSignInject)
                        } else {
                            (format!("fsgnjx{}", suffix), Operation::FloatSignInject)
                        }
                    }
                    _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
                };

                let operands = if rs1 == rs2 && rm <= 0b010 {
                    // Pseudo-instructions (fmv, fneg, fabs)
                    vec![Operand::reg(self.fpr(rd)), Operand::reg(self.fpr(rs1))]
                } else {
                    vec![
                        Operand::reg(self.fpr(rd)),
                        Operand::reg(self.fpr(rs1)),
                        Operand::reg(self.fpr(rs2)),
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
            0b00101 => {
                // FMIN/FMAX
                let (mnemonic, operation) = match rm {
                    0b000 => (format!("fmin{}", suffix), Operation::FloatMin),
                    0b001 => (format!("fmax{}", suffix), Operation::FloatMax),
                    _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
                };
                let inst = Instruction::new(address, 4, bytes, mnemonic)
                    .with_operation(operation)
                    .with_operands(vec![
                        Operand::reg(self.fpr(rd)),
                        Operand::reg(self.fpr(rs1)),
                        Operand::reg(self.fpr(rs2)),
                    ]);
                Ok(DecodedInstruction {
                    instruction: inst,
                    size: 4,
                })
            }
            0b01000 => {
                // FCVT.S.D / FCVT.D.S (conversion between float formats)
                let mnemonic = if is_double {
                    "fcvt.d.s" // Convert single to double
                } else {
                    "fcvt.s.d" // Convert double to single
                };
                let inst = Instruction::new(address, 4, bytes, mnemonic)
                    .with_operation(Operation::FloatConvert)
                    .with_operands(vec![
                        Operand::reg(self.fpr(rd)),
                        Operand::reg(self.fpr(rs1)),
                    ]);
                Ok(DecodedInstruction {
                    instruction: inst,
                    size: 4,
                })
            }
            0b10100 => {
                // FEQ/FLT/FLE (compare, result to integer register)
                let mnemonic = match rm {
                    0b010 => format!("feq{}", suffix),
                    0b001 => format!("flt{}", suffix),
                    0b000 => format!("fle{}", suffix),
                    _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
                };
                let inst = Instruction::new(address, 4, bytes, mnemonic)
                    .with_operation(Operation::FloatCompare)
                    .with_operands(vec![
                        Operand::reg(self.gpr(rd)),
                        Operand::reg(self.fpr(rs1)),
                        Operand::reg(self.fpr(rs2)),
                    ]);
                Ok(DecodedInstruction {
                    instruction: inst,
                    size: 4,
                })
            }
            0b11100 => {
                // FCLASS / FMV.X.W / FMV.X.D
                if rm == 0b001 {
                    // FCLASS
                    let mnemonic = format!("fclass{}", suffix);
                    let inst = Instruction::new(address, 4, bytes, mnemonic)
                        .with_operation(Operation::FloatClassify)
                        .with_operands(vec![
                            Operand::reg(self.gpr(rd)),
                            Operand::reg(self.fpr(rs1)),
                        ]);
                    Ok(DecodedInstruction {
                        instruction: inst,
                        size: 4,
                    })
                } else if rm == 0b000 {
                    // FMV.X.W or FMV.X.D (float bits to integer register)
                    let mnemonic = if is_double { "fmv.x.d" } else { "fmv.x.w" };
                    let inst = Instruction::new(address, 4, bytes, mnemonic)
                        .with_operation(Operation::FloatMove)
                        .with_operands(vec![
                            Operand::reg(self.gpr(rd)),
                            Operand::reg(self.fpr(rs1)),
                        ]);
                    Ok(DecodedInstruction {
                        instruction: inst,
                        size: 4,
                    })
                } else {
                    Err(DecodeError::unknown_opcode(address, &bytes))
                }
            }
            0b11110 => {
                // FMV.W.X or FMV.D.X (integer bits to float register)
                let mnemonic = if is_double { "fmv.d.x" } else { "fmv.w.x" };
                let inst = Instruction::new(address, 4, bytes, mnemonic)
                    .with_operation(Operation::FloatMove)
                    .with_operands(vec![
                        Operand::reg(self.fpr(rd)),
                        Operand::reg(self.gpr(rs1)),
                    ]);
                Ok(DecodedInstruction {
                    instruction: inst,
                    size: 4,
                })
            }
            0b11000 => {
                // FCVT.W.S/D, FCVT.WU.S/D (float to signed/unsigned 32-bit int)
                let mnemonic = match (rs2, is_double) {
                    (0, false) => "fcvt.w.s",
                    (1, false) => "fcvt.wu.s",
                    (0, true) => "fcvt.w.d",
                    (1, true) => "fcvt.wu.d",
                    (2, false) if self.is_64bit => "fcvt.l.s",
                    (3, false) if self.is_64bit => "fcvt.lu.s",
                    (2, true) if self.is_64bit => "fcvt.l.d",
                    (3, true) if self.is_64bit => "fcvt.lu.d",
                    _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
                };
                let inst = Instruction::new(address, 4, bytes, mnemonic)
                    .with_operation(Operation::FloatConvert)
                    .with_operands(vec![
                        Operand::reg(self.gpr(rd)),
                        Operand::reg(self.fpr(rs1)),
                    ]);
                Ok(DecodedInstruction {
                    instruction: inst,
                    size: 4,
                })
            }
            0b11010 => {
                // FCVT.S.W/WU, FCVT.D.W/WU (signed/unsigned 32-bit int to float)
                let mnemonic = match (rs2, is_double) {
                    (0, false) => "fcvt.s.w",
                    (1, false) => "fcvt.s.wu",
                    (0, true) => "fcvt.d.w",
                    (1, true) => "fcvt.d.wu",
                    (2, false) if self.is_64bit => "fcvt.s.l",
                    (3, false) if self.is_64bit => "fcvt.s.lu",
                    (2, true) if self.is_64bit => "fcvt.d.l",
                    (3, true) if self.is_64bit => "fcvt.d.lu",
                    _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
                };
                let inst = Instruction::new(address, 4, bytes, mnemonic)
                    .with_operation(Operation::FloatConvert)
                    .with_operands(vec![
                        Operand::reg(self.fpr(rd)),
                        Operand::reg(self.gpr(rs1)),
                    ]);
                Ok(DecodedInstruction {
                    instruction: inst,
                    size: 4,
                })
            }
            _ => Err(DecodeError::unknown_opcode(address, &bytes)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flw() {
        let decoder = FloatDecoder::new(true);
        // flw f1, 0(x2): imm=0, rs1=2, funct3=010, rd=1, opcode=0000111
        let insn: u32 = (2 << 15) | (0b010 << 12) | (1 << 7) | 0b0000111;
        let bytes = insn.to_le_bytes().to_vec();
        let result = decoder.decode_load(insn, 0x1000, bytes).unwrap();
        assert_eq!(result.instruction.mnemonic, "flw");
    }

    #[test]
    fn test_fld() {
        let decoder = FloatDecoder::new(true);
        // fld f1, 8(x2): imm=8, rs1=2, funct3=011, rd=1, opcode=0000111
        let insn: u32 = (8 << 20) | (2 << 15) | (0b011 << 12) | (1 << 7) | 0b0000111;
        let bytes = insn.to_le_bytes().to_vec();
        let result = decoder.decode_load(insn, 0x1000, bytes).unwrap();
        assert_eq!(result.instruction.mnemonic, "fld");
    }

    #[test]
    fn test_fsw() {
        let decoder = FloatDecoder::new(true);
        // fsw f1, 0(x2): imm=0, rs2=1, rs1=2, funct3=010, opcode=0100111
        let insn: u32 = ((1 << 20) | (2 << 15) | (0b010 << 12)) | 0b0100111;
        let bytes = insn.to_le_bytes().to_vec();
        let result = decoder.decode_store(insn, 0x1000, bytes).unwrap();
        assert_eq!(result.instruction.mnemonic, "fsw");
    }

    #[test]
    fn test_fadd_s() {
        let decoder = FloatDecoder::new(true);
        // fadd.s f3, f1, f2: funct7=0000000, rs2=2, rs1=1, rm=000, rd=3, opcode=1010011
        let insn: u32 = ((2 << 20) | (1 << 15)) | (3 << 7) | 0b1010011;
        let bytes = insn.to_le_bytes().to_vec();
        let result = decoder.decode_op_fp(insn, 0x1000, bytes).unwrap();
        assert_eq!(result.instruction.mnemonic, "fadd.s");
    }

    #[test]
    fn test_fadd_d() {
        let decoder = FloatDecoder::new(true);
        // fadd.d f3, f1, f2: funct7=0000001, rs2=2, rs1=1, rm=000, rd=3, opcode=1010011
        let insn: u32 = ((0b0000001 << 25) | (2 << 20) | (1 << 15)) | (3 << 7) | 0b1010011;
        let bytes = insn.to_le_bytes().to_vec();
        let result = decoder.decode_op_fp(insn, 0x1000, bytes).unwrap();
        assert_eq!(result.instruction.mnemonic, "fadd.d");
    }
}
