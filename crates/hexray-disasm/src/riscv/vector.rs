//! RISC-V V (Vector) extension decoder.
//!
//! This module handles decoding of the RISC-V Vector extension instructions,
//! including vector configuration, loads/stores, and arithmetic operations.

use crate::{DecodeError, DecodedInstruction};
use hexray_core::{
    Architecture, Instruction, MemoryRef, Operand, Operation, Register, RegisterClass,
};

// Vector extension opcodes (documented for reference, used in decoder.rs)
#[allow(dead_code)]
pub const OP_V: u32 = 0b1010111; // 0x57 - Vector arithmetic
#[allow(dead_code)]
pub const OP_LOAD_FP: u32 = 0b0000111; // 0x07 - Vector loads (shared with FP loads)
#[allow(dead_code)]
pub const OP_STORE_FP: u32 = 0b0100111; // 0x27 - Vector stores (shared with FP stores)

/// Vector decoder for RISC-V V extension.
pub struct VectorDecoder {
    is_64bit: bool,
}

impl VectorDecoder {
    pub fn new(is_64bit: bool) -> Self {
        Self { is_64bit }
    }

    /// Creates a vector register.
    fn vreg(&self, id: u16) -> Register {
        Register::new(
            if self.is_64bit {
                Architecture::RiscV64
            } else {
                Architecture::RiscV32
            },
            RegisterClass::Vector,
            id + 128, // V0 starts at 128
            0,        // Size is configurable, use 0
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

    /// Creates a floating-point register.
    fn fpr(&self, id: u16) -> Register {
        Register::new(
            if self.is_64bit {
                Architecture::RiscV64
            } else {
                Architecture::RiscV32
            },
            RegisterClass::FloatingPoint,
            id + 64,
            if self.is_64bit { 64 } else { 32 },
        )
    }

    /// Extract rd/vd field (bits 11:7)
    fn rd(insn: u32) -> u16 {
        ((insn >> 7) & 0x1F) as u16
    }

    /// Extract rs1 field (bits 19:15)
    fn rs1(insn: u32) -> u16 {
        ((insn >> 15) & 0x1F) as u16
    }

    /// Extract rs2/vs2 field (bits 24:20)
    fn rs2(insn: u32) -> u16 {
        ((insn >> 20) & 0x1F) as u16
    }

    /// Extract vs3 field (bits 11:7) - same position as rd but for stores
    fn vs3(insn: u32) -> u16 {
        ((insn >> 7) & 0x1F) as u16
    }

    /// Extract funct3 field (bits 14:12)
    fn funct3(insn: u32) -> u32 {
        (insn >> 12) & 0x7
    }

    /// Extract funct6 field (bits 31:26)
    fn funct6(insn: u32) -> u32 {
        (insn >> 26) & 0x3F
    }

    /// Extract vm bit (bit 25) - 0 = masked, 1 = unmasked
    fn vm(insn: u32) -> bool {
        ((insn >> 25) & 1) == 1
    }

    /// Extract width field for vector loads/stores (bits 14:12)
    fn width(insn: u32) -> u32 {
        (insn >> 12) & 0x7
    }

    /// Extract mop field for vector loads/stores (bits 27:26)
    fn mop(insn: u32) -> u32 {
        (insn >> 26) & 0x3
    }

    /// Extract nf field for segment loads/stores (bits 31:29)
    fn nf(insn: u32) -> u32 {
        (insn >> 29) & 0x7
    }

    /// Check if this is a vector load instruction.
    pub fn is_vector_load(insn: u32) -> bool {
        let opcode = insn & 0x7F;
        let width = (insn >> 12) & 0x7;
        // Vector loads use LOAD-FP opcode with width not equal to 010 (FLW) or 011 (FLD)
        opcode == OP_LOAD_FP && (width == 0 || width == 5 || width == 6 || width == 7)
    }

    /// Check if this is a vector store instruction.
    pub fn is_vector_store(insn: u32) -> bool {
        let opcode = insn & 0x7F;
        let width = (insn >> 12) & 0x7;
        // Vector stores use STORE-FP opcode with width not equal to 010 (FSW) or 011 (FSD)
        opcode == OP_STORE_FP && (width == 0 || width == 5 || width == 6 || width == 7)
    }

    /// Decode vector configuration instruction (VSETVLI, VSETIVLI, VSETVL).
    pub fn decode_vset(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let rd = Self::rd(insn);
        let rs1 = Self::rs1(insn);
        let funct3 = Self::funct3(insn);

        // Bit 31 distinguishes VSETVLI/VSETIVLI from VSETVL
        let bit31 = (insn >> 31) & 1;
        // Bit 30 distinguishes VSETVLI from VSETIVLI
        let bit30 = (insn >> 30) & 1;

        if funct3 == 0b111 {
            if bit31 == 0 {
                // VSETVLI: vsetvli rd, rs1, vtypei
                let zimm = (insn >> 20) & 0x7FF; // 11-bit immediate
                let inst = Instruction::new(address, 4, bytes, "vsetvli")
                    .with_operation(Operation::VectorConfig)
                    .with_operands(vec![
                        Operand::reg(self.gpr(rd)),
                        Operand::reg(self.gpr(rs1)),
                        Operand::imm_unsigned(zimm as u64, 11),
                    ]);
                Ok(DecodedInstruction {
                    instruction: inst,
                    size: 4,
                })
            } else if bit30 == 1 {
                // VSETIVLI: vsetivli rd, uimm, vtypei
                let uimm = rs1; // rs1 field is used as immediate
                let zimm = (insn >> 20) & 0x3FF; // 10-bit immediate
                let inst = Instruction::new(address, 4, bytes, "vsetivli")
                    .with_operation(Operation::VectorConfig)
                    .with_operands(vec![
                        Operand::reg(self.gpr(rd)),
                        Operand::imm_unsigned(uimm as u64, 5),
                        Operand::imm_unsigned(zimm as u64, 10),
                    ]);
                Ok(DecodedInstruction {
                    instruction: inst,
                    size: 4,
                })
            } else {
                // VSETVL: vsetvl rd, rs1, rs2
                let rs2 = Self::rs2(insn);
                let inst = Instruction::new(address, 4, bytes, "vsetvl")
                    .with_operation(Operation::VectorConfig)
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
        } else {
            Err(DecodeError::unknown_opcode(address, &bytes))
        }
    }

    /// Decode vector load instruction.
    pub fn decode_vector_load(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let vd = Self::rd(insn);
        let rs1 = Self::rs1(insn);
        let rs2 = Self::rs2(insn);
        let width = Self::width(insn);
        let mop = Self::mop(insn);
        let vm = Self::vm(insn);
        let nf = Self::nf(insn);

        // Element width
        let eew = match width {
            0b000 => 8,
            0b101 => 16,
            0b110 => 32,
            0b111 => 64,
            _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
        };

        // Memory operation type
        let (base_mnemonic, operation) = match mop {
            0b00 => {
                // Unit-stride
                if rs2 == 0 {
                    (format!("vle{}.v", eew), Operation::VectorLoad)
                } else {
                    // Whole register load or mask load
                    match rs2 {
                        8 => (format!("vl{}re{}.v", nf + 1, eew), Operation::VectorLoad),
                        11 => ("vlm.v".to_string(), Operation::VectorLoad),
                        _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
                    }
                }
            }
            0b01 => {
                // Indexed unordered
                (format!("vluxei{}.v", eew), Operation::VectorIndexedLoad)
            }
            0b10 => {
                // Strided
                (format!("vlse{}.v", eew), Operation::VectorStridedLoad)
            }
            0b11 => {
                // Indexed ordered
                (format!("vloxei{}.v", eew), Operation::VectorIndexedLoad)
            }
            _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
        };

        let mem = MemoryRef::base(self.gpr(rs1), (eew / 8) as u8);

        let mut operands = vec![Operand::reg(self.vreg(vd)), Operand::Memory(mem)];

        // Add stride/index register for strided/indexed loads
        if mop == 0b01 || mop == 0b10 || mop == 0b11 {
            operands.push(Operand::reg(if mop == 0b10 {
                self.gpr(rs2)
            } else {
                self.vreg(rs2)
            }));
        }

        // Add mask annotation if masked
        let mnemonic = if vm {
            base_mnemonic
        } else {
            format!("{}, v0.t", base_mnemonic)
        };

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(operation)
            .with_operands(operands);

        Ok(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode vector store instruction.
    pub fn decode_vector_store(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let vs3 = Self::vs3(insn);
        let rs1 = Self::rs1(insn);
        let rs2 = Self::rs2(insn);
        let width = Self::width(insn);
        let mop = Self::mop(insn);
        let vm = Self::vm(insn);
        let nf = Self::nf(insn);

        // Element width
        let eew = match width {
            0b000 => 8,
            0b101 => 16,
            0b110 => 32,
            0b111 => 64,
            _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
        };

        // Memory operation type
        let (base_mnemonic, operation) = match mop {
            0b00 => {
                // Unit-stride
                if rs2 == 0 {
                    (format!("vse{}.v", eew), Operation::VectorStore)
                } else {
                    // Whole register store or mask store
                    match rs2 {
                        8 => (format!("vs{}r.v", nf + 1), Operation::VectorStore),
                        11 => ("vsm.v".to_string(), Operation::VectorStore),
                        _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
                    }
                }
            }
            0b01 => {
                // Indexed unordered
                (format!("vsuxei{}.v", eew), Operation::VectorIndexedStore)
            }
            0b10 => {
                // Strided
                (format!("vsse{}.v", eew), Operation::VectorStridedStore)
            }
            0b11 => {
                // Indexed ordered
                (format!("vsoxei{}.v", eew), Operation::VectorIndexedStore)
            }
            _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
        };

        let mem = MemoryRef::base(self.gpr(rs1), (eew / 8) as u8);

        let mut operands = vec![Operand::reg(self.vreg(vs3)), Operand::Memory(mem)];

        // Add stride/index register for strided/indexed stores
        if mop == 0b01 || mop == 0b10 || mop == 0b11 {
            operands.push(Operand::reg(if mop == 0b10 {
                self.gpr(rs2)
            } else {
                self.vreg(rs2)
            }));
        }

        let mnemonic = if vm {
            base_mnemonic
        } else {
            format!("{}, v0.t", base_mnemonic)
        };

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(operation)
            .with_operands(operands);

        Ok(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }

    /// Decode vector arithmetic instruction.
    pub fn decode_vector_arith(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let vd = Self::rd(insn);
        let vs1_rs1 = Self::rs1(insn);
        let vs2 = Self::rs2(insn);
        let funct3 = Self::funct3(insn);
        let funct6 = Self::funct6(insn);
        let vm = Self::vm(insn);

        // Check for VSET* first (funct3 == 0b111)
        if funct3 == 0b111 {
            return self.decode_vset(insn, address, bytes);
        }

        // Determine operand type from funct3
        let suffix = match funct3 {
            0b000 => ".vv", // OPIVV - vector-vector
            0b001 => ".vf", // OPFVV - vector-scalar (FP)
            0b010 => ".vv", // OPMVV - vector-vector (masks)
            0b011 => ".vi", // OPIVI - vector-immediate
            0b100 => ".vx", // OPIVX - vector-scalar
            0b101 => ".vf", // OPFVF - vector-scalar (FP)
            0b110 => ".vx", // OPMVX - vector-scalar (masks)
            _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
        };

        // Decode based on funct6 and funct3 combination
        // Note: Guards must be checked first for overlapping funct6 values
        let (base_mnemonic, operation) = match (funct6, funct3) {
            // Floating-point operations (funct3 = 0b001 or 0b101)
            (0b000000, 0b001) | (0b000000, 0b101) => ("vfadd", Operation::VectorFloatAdd),
            (0b000010, 0b001) | (0b000010, 0b101) => ("vfsub", Operation::VectorFloatSub),
            (0b100000, 0b001) | (0b100000, 0b101) => ("vfdiv", Operation::VectorFloatDiv),
            (0b100100, 0b001) | (0b100100, 0b101) => ("vfmul", Operation::VectorFloatMul),
            (0b101000, 0b001) | (0b101000, 0b101) => ("vfmadd", Operation::VectorFloatMulAdd),
            (0b101001, 0b001) | (0b101001, 0b101) => ("vfnmadd", Operation::VectorFloatMulAdd),
            (0b101010, 0b001) | (0b101010, 0b101) => ("vfmsub", Operation::VectorFloatMulAdd),
            (0b101011, 0b001) | (0b101011, 0b101) => ("vfnmsub", Operation::VectorFloatMulAdd),
            (0b101100, 0b001) | (0b101100, 0b101) => ("vfmacc", Operation::VectorFloatMulAdd),
            (0b101101, 0b001) | (0b101101, 0b101) => ("vfnmacc", Operation::VectorFloatMulAdd),
            (0b101110, 0b001) | (0b101110, 0b101) => ("vfmsac", Operation::VectorFloatMulAdd),
            (0b101111, 0b001) | (0b101111, 0b101) => ("vfnmsac", Operation::VectorFloatMulAdd),
            // Multiply/Divide operations (funct3 = 0b010, OPMVV)
            (0b100000, 0b010) => ("vdivu", Operation::VectorDiv),
            (0b100001, 0b010) => ("vdiv", Operation::VectorDiv),
            (0b100010, 0b010) => ("vremu", Operation::VectorRem),
            (0b100011, 0b010) => ("vrem", Operation::VectorRem),
            (0b100100, 0b010) => ("vmul", Operation::VectorMul),
            (0b100101, 0b010) => ("vmulh", Operation::VectorMul),
            (0b100110, 0b010) => ("vmulhu", Operation::VectorMul),
            (0b100111, 0b010) => ("vmulhsu", Operation::VectorMul),
            // Integer operations (default for other funct3 values)
            (0b000000, _) => ("vadd", Operation::VectorAdd),
            (0b000010, _) => ("vsub", Operation::VectorSub),
            (0b000011, _) => ("vrsub", Operation::VectorSub),
            (0b000100, _) => ("vminu", Operation::VectorMin),
            (0b000101, _) => ("vmin", Operation::VectorMin),
            (0b000110, _) => ("vmaxu", Operation::VectorMax),
            (0b000111, _) => ("vmax", Operation::VectorMax),
            (0b001001, _) => ("vand", Operation::VectorAnd),
            (0b001010, _) => ("vor", Operation::VectorOr),
            (0b001011, _) => ("vxor", Operation::VectorXor),
            (0b001100, _) => ("vrgather", Operation::VectorGather),
            (0b001110, _) => ("vslideup", Operation::VectorSlide),
            (0b001111, _) => ("vslidedown", Operation::VectorSlide),
            (0b010000, _) => ("vadc", Operation::VectorAdd),
            (0b010001, _) => ("vmadc", Operation::VectorMask),
            (0b010010, _) => ("vsbc", Operation::VectorSub),
            (0b010011, _) => ("vmsbc", Operation::VectorMask),
            (0b010111, _) => {
                if vm {
                    ("vmerge", Operation::VectorMerge)
                } else {
                    ("vmv", Operation::VectorMerge)
                }
            }
            (0b011000, _) => ("vmseq", Operation::VectorCompare),
            (0b011001, _) => ("vmsne", Operation::VectorCompare),
            (0b011010, _) => ("vmsltu", Operation::VectorCompare),
            (0b011011, _) => ("vmslt", Operation::VectorCompare),
            (0b011100, _) => ("vmsleu", Operation::VectorCompare),
            (0b011101, _) => ("vmsle", Operation::VectorCompare),
            (0b011110, _) => ("vmsgtu", Operation::VectorCompare),
            (0b011111, _) => ("vmsgt", Operation::VectorCompare),
            (0b100000, _) => ("vsaddu", Operation::VectorAdd),
            (0b100001, _) => ("vsadd", Operation::VectorAdd),
            (0b100010, _) => ("vssubu", Operation::VectorSub),
            (0b100011, _) => ("vssub", Operation::VectorSub),
            (0b100101, _) => ("vsll", Operation::VectorShl),
            (0b100111, _) => ("vsmul", Operation::VectorMul),
            (0b101000, _) => ("vsrl", Operation::VectorShr),
            (0b101001, _) => ("vsra", Operation::VectorSar),
            (0b101010, _) => ("vssrl", Operation::VectorShr),
            (0b101011, _) => ("vssra", Operation::VectorSar),
            (0b101100, _) => ("vnsrl", Operation::VectorNarrow),
            (0b101101, _) => ("vnsra", Operation::VectorNarrow),
            (0b101110, _) => ("vnclipu", Operation::VectorNarrow),
            (0b101111, _) => ("vnclip", Operation::VectorNarrow),
            (0b110000, _) => ("vwredsumu", Operation::VectorReduce),
            (0b110001, _) => ("vwredsum", Operation::VectorReduce),
            _ => return Err(DecodeError::unknown_opcode(address, &bytes)),
        };

        let mnemonic = format!("{}{}", base_mnemonic, suffix);

        // Build operands
        let mut operands = vec![Operand::reg(self.vreg(vd))];

        // Add vs2
        operands.push(Operand::reg(self.vreg(vs2)));

        // Add vs1/rs1/imm based on funct3
        match funct3 {
            0b000 | 0b010 => {
                // Vector-vector
                operands.push(Operand::reg(self.vreg(vs1_rs1)));
            }
            0b001 | 0b101 => {
                // Vector-FP scalar
                operands.push(Operand::reg(self.fpr(vs1_rs1)));
            }
            0b011 => {
                // Vector-immediate (sign-extended 5-bit)
                let imm = ((vs1_rs1 as i32) << 27) >> 27;
                operands.push(Operand::imm(imm as i128, 5));
            }
            0b100 | 0b110 => {
                // Vector-integer scalar
                operands.push(Operand::reg(self.gpr(vs1_rs1)));
            }
            _ => {}
        }

        let final_mnemonic = if vm {
            mnemonic
        } else {
            format!("{}, v0.t", mnemonic)
        };

        let inst = Instruction::new(address, 4, bytes, final_mnemonic)
            .with_operation(operation)
            .with_operands(operands);

        Ok(DecodedInstruction {
            instruction: inst,
            size: 4,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vsetvli() {
        let decoder = VectorDecoder::new(true);
        // vsetvli x1, x2, e32,m1 (zimm = 0x008)
        // funct3=111, rd=1, rs1=2, zimm[10:0]=0x008
        let insn: u32 = (0x008 << 20) | (2 << 15) | (0b111 << 12) | (1 << 7) | 0b1010111;
        let bytes = insn.to_le_bytes().to_vec();
        let result = decoder.decode_vset(insn, 0x1000, bytes).unwrap();
        assert_eq!(result.instruction.mnemonic, "vsetvli");
    }

    #[test]
    fn test_vle32() {
        let decoder = VectorDecoder::new(true);
        // vle32.v v1, (x2)
        // mop=00, vm=1, rs2=0, rs1=2, width=110, vd=1, opcode=0000111
        let insn: u32 = (1 << 25) | (2 << 15) | (0b110 << 12) | (1 << 7) | 0b0000111;
        let bytes = insn.to_le_bytes().to_vec();
        let result = decoder.decode_vector_load(insn, 0x1000, bytes).unwrap();
        assert_eq!(result.instruction.mnemonic, "vle32.v");
    }

    #[test]
    fn test_vadd_vv() {
        let decoder = VectorDecoder::new(true);
        // vadd.vv v1, v2, v3
        // funct6=000000, vm=1, vs2=2, vs1=3, funct3=000, vd=1, opcode=1010111
        let insn: u32 = ((1 << 25) | (2 << 20) | (3 << 15)) | (1 << 7) | 0b1010111;
        let bytes = insn.to_le_bytes().to_vec();
        let result = decoder.decode_vector_arith(insn, 0x1000, bytes).unwrap();
        assert_eq!(result.instruction.mnemonic, "vadd.vv");
    }

    #[test]
    fn test_vadd_vi() {
        let decoder = VectorDecoder::new(true);
        // vadd.vi v1, v2, 5
        // funct6=000000, vm=1, vs2=2, imm=5, funct3=011, vd=1, opcode=1010111
        let insn: u32 = (1 << 25) | (2 << 20) | (5 << 15) | (0b011 << 12) | (1 << 7) | 0b1010111;
        let bytes = insn.to_le_bytes().to_vec();
        let result = decoder.decode_vector_arith(insn, 0x1000, bytes).unwrap();
        assert_eq!(result.instruction.mnemonic, "vadd.vi");
    }
}
