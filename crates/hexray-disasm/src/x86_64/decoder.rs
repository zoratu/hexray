//! x86_64 instruction decoder.

use super::modrm::{decode_gpr, decode_modrm_reg, decode_modrm_rm, ModRM};
use super::opcodes::{OperandEncoding, OPCODE_TABLE, OPCODE_TABLE_0F, GROUP1_OPS};
use super::prefix::Prefixes;
use crate::error::DecodeError;
use crate::traits::{DecodedInstruction, Disassembler};
use hexray_core::{
    register::x86, Architecture, Condition, ControlFlow, Instruction, Operand, Operation, Register,
    RegisterClass,
};

/// x86_64 instruction decoder.
pub struct X86_64Disassembler {
    /// Whether to use Intel syntax (true) or AT&T syntax (false).
    pub intel_syntax: bool,
}

impl X86_64Disassembler {
    /// Creates a new x86_64 disassembler.
    pub fn new() -> Self {
        Self { intel_syntax: true }
    }

    /// Decodes the condition for a conditional jump based on opcode.
    fn decode_condition(opcode: u8) -> Condition {
        match opcode & 0x0F {
            0x0 => Condition::Overflow,
            0x1 => Condition::NotOverflow,
            0x2 => Condition::Below,
            0x3 => Condition::AboveOrEqual,
            0x4 => Condition::Equal,
            0x5 => Condition::NotEqual,
            0x6 => Condition::BelowOrEqual,
            0x7 => Condition::Above,
            0x8 => Condition::Sign,
            0x9 => Condition::NotSign,
            0xA => Condition::Parity,
            0xB => Condition::NotParity,
            0xC => Condition::Less,
            0xD => Condition::GreaterOrEqual,
            0xE => Condition::LessOrEqual,
            0xF => Condition::Greater,
            _ => unreachable!(),
        }
    }
}

impl Default for X86_64Disassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Disassembler for X86_64Disassembler {
    fn decode_instruction(&self, bytes: &[u8], address: u64) -> Result<DecodedInstruction, DecodeError> {
        if bytes.is_empty() {
            return Err(DecodeError::truncated(address, 1, 0));
        }

        // Parse prefixes
        let (prefixes, prefix_len) = Prefixes::parse(bytes);
        let mut offset = prefix_len;

        if offset >= bytes.len() {
            return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
        }

        // Check for two-byte opcode escape
        let (opcode, is_two_byte) = if bytes[offset] == 0x0F {
            offset += 1;
            if offset >= bytes.len() {
                return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
            }
            (bytes[offset], true)
        } else {
            (bytes[offset], false)
        };
        offset += 1;

        // Look up opcode in table
        let entry = if is_two_byte {
            OPCODE_TABLE_0F[opcode as usize].as_ref()
        } else {
            // Handle group 1 (0x80-0x83) specially
            if opcode >= 0x80 && opcode <= 0x83 {
                return self.decode_group1(bytes, address, &prefixes, offset, opcode);
            }
            // Handle group 2 (shift/rotate: 0xC0-0xC1, 0xD0-0xD3)
            if opcode == 0xC0 || opcode == 0xC1 || (opcode >= 0xD0 && opcode <= 0xD3) {
                return self.decode_group2(bytes, address, &prefixes, offset, opcode);
            }
            OPCODE_TABLE[opcode as usize].as_ref()
        };

        let entry = entry.ok_or_else(|| {
            let end = (offset).min(bytes.len());
            DecodeError::unknown_opcode(address, &bytes[..end])
        })?;

        // Determine operand size
        let operand_size = if entry.default_size > 0 {
            entry.default_size
        } else {
            prefixes.operand_size(entry.default_64)
        };

        // Decode operands based on encoding
        let mut operands = Vec::new();
        let remaining = &bytes[offset..];

        match entry.encoding {
            OperandEncoding::None => {}

            OperandEncoding::OpReg => {
                // Register encoded in opcode
                let reg_num = (opcode & 0x07) | (prefixes.rex.map(|r| (r.b as u8) << 3).unwrap_or(0));
                let reg = decode_gpr(reg_num, operand_size);
                operands.push(Operand::Register(reg));

                // For MOV r, imm variants (B0-BF), also read immediate
                if opcode >= 0xB0 && opcode <= 0xBF {
                    let imm_size = if opcode >= 0xB8 {
                        if prefixes.rex.map(|r| r.w).unwrap_or(false) {
                            8 // 64-bit immediate for REX.W
                        } else if prefixes.operand_size {
                            2
                        } else {
                            4
                        }
                    } else {
                        1
                    };

                    if remaining.len() < imm_size {
                        return Err(DecodeError::truncated(address, offset + imm_size, bytes.len()));
                    }

                    let imm = match imm_size {
                        1 => remaining[0] as i128,
                        2 => i16::from_le_bytes([remaining[0], remaining[1]]) as i128,
                        4 => i32::from_le_bytes([remaining[0], remaining[1], remaining[2], remaining[3]]) as i128,
                        8 => i64::from_le_bytes([
                            remaining[0], remaining[1], remaining[2], remaining[3],
                            remaining[4], remaining[5], remaining[6], remaining[7],
                        ]) as i128,
                        _ => unreachable!(),
                    };
                    operands.push(Operand::imm(imm, (imm_size * 8) as u8));
                    offset += imm_size;
                }
            }

            OperandEncoding::ModRmRm_Reg | OperandEncoding::ModRmReg_Rm | OperandEncoding::ModRmRmOnly => {
                if remaining.is_empty() {
                    return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
                }
                let modrm = ModRM::parse(remaining[0], prefixes.rex);
                offset += 1;

                let rm_bytes = &bytes[offset..];
                let (rm_operand, rm_consumed) = decode_modrm_rm(rm_bytes, modrm, &prefixes, operand_size)
                    .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
                offset += rm_consumed;

                match entry.encoding {
                    OperandEncoding::ModRmRm_Reg => {
                        operands.push(rm_operand);
                        operands.push(decode_modrm_reg(modrm, operand_size));
                    }
                    OperandEncoding::ModRmReg_Rm => {
                        operands.push(decode_modrm_reg(modrm, operand_size));
                        operands.push(rm_operand);
                    }
                    OperandEncoding::ModRmRmOnly => {
                        operands.push(rm_operand);
                    }
                    _ => unreachable!(),
                }
            }

            OperandEncoding::Acc_Imm => {
                let acc = Register::new(Architecture::X86_64, RegisterClass::General, x86::RAX, operand_size);
                operands.push(Operand::Register(acc));

                let imm_size = match operand_size {
                    8 => 1,
                    16 => 2,
                    32 | 64 => 4, // 64-bit mode still uses 32-bit immediate (sign-extended)
                    _ => 4,
                };

                if remaining.len() < imm_size {
                    return Err(DecodeError::truncated(address, offset + imm_size, bytes.len()));
                }

                let imm = match imm_size {
                    1 => remaining[0] as i8 as i128,
                    2 => i16::from_le_bytes([remaining[0], remaining[1]]) as i128,
                    4 => i32::from_le_bytes([remaining[0], remaining[1], remaining[2], remaining[3]]) as i128,
                    _ => unreachable!(),
                };
                operands.push(Operand::imm(imm, (imm_size * 8) as u8));
                offset += imm_size;
            }

            OperandEncoding::Rel8 => {
                if remaining.is_empty() {
                    return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
                }
                let rel = remaining[0] as i8 as i64;
                let target = (address as i64 + offset as i64 + 1 + rel) as u64;
                operands.push(Operand::pc_rel(rel, target));
                offset += 1;
            }

            OperandEncoding::Rel32 => {
                if remaining.len() < 4 {
                    return Err(DecodeError::truncated(address, offset + 4, bytes.len()));
                }
                let rel = i32::from_le_bytes([remaining[0], remaining[1], remaining[2], remaining[3]]) as i64;
                let target = (address as i64 + offset as i64 + 4 + rel) as u64;
                operands.push(Operand::pc_rel(rel, target));
                offset += 4;
            }

            OperandEncoding::Imm8 => {
                if remaining.is_empty() {
                    return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
                }
                operands.push(Operand::imm(remaining[0] as i128, 8));
                offset += 1;
            }

            OperandEncoding::Imm16 => {
                if remaining.len() < 2 {
                    return Err(DecodeError::truncated(address, offset + 2, bytes.len()));
                }
                let imm = i16::from_le_bytes([remaining[0], remaining[1]]) as i128;
                operands.push(Operand::imm(imm, 16));
                offset += 2;
            }

            OperandEncoding::Imm32 => {
                if remaining.len() < 4 {
                    return Err(DecodeError::truncated(address, offset + 4, bytes.len()));
                }
                let imm = i32::from_le_bytes([remaining[0], remaining[1], remaining[2], remaining[3]]) as i128;
                operands.push(Operand::imm(imm, 32));
                offset += 4;
            }

            OperandEncoding::Imm64 => {
                if remaining.len() < 8 {
                    return Err(DecodeError::truncated(address, offset + 8, bytes.len()));
                }
                let imm = i64::from_le_bytes([
                    remaining[0], remaining[1], remaining[2], remaining[3],
                    remaining[4], remaining[5], remaining[6], remaining[7],
                ]) as i128;
                operands.push(Operand::imm(imm, 64));
                offset += 8;
            }

            OperandEncoding::Rm_Imm | OperandEncoding::Rm_Imm8 => {
                // r/m operand with immediate
                if remaining.is_empty() {
                    return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
                }
                let modrm = ModRM::parse(remaining[0], prefixes.rex);
                offset += 1;

                let rm_bytes = &bytes[offset..];
                let (rm_operand, rm_consumed) = decode_modrm_rm(rm_bytes, modrm, &prefixes, operand_size)
                    .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
                offset += rm_consumed;

                // Decode immediate
                let remaining = &bytes[offset..];
                let (imm, imm_size) = if matches!(entry.encoding, OperandEncoding::Rm_Imm8) {
                    if remaining.is_empty() {
                        return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
                    }
                    (remaining[0] as i8 as i128, 1)
                } else {
                    // Full-size immediate (32-bit even in 64-bit mode)
                    let size = if prefixes.operand_size { 2 } else { 4 };
                    if remaining.len() < size {
                        return Err(DecodeError::truncated(address, offset + size, bytes.len()));
                    }
                    let imm = if size == 2 {
                        i16::from_le_bytes([remaining[0], remaining[1]]) as i128
                    } else {
                        i32::from_le_bytes([remaining[0], remaining[1], remaining[2], remaining[3]]) as i128
                    };
                    (imm, size)
                };
                offset += imm_size;

                operands.push(rm_operand);
                operands.push(Operand::imm(imm, (imm_size * 8) as u8));
            }
        }

        // Build control flow
        let control_flow = match entry.operation {
            Operation::Jump => {
                if let Some(Operand::PcRelative { target, .. }) = operands.first() {
                    ControlFlow::UnconditionalBranch { target: *target }
                } else {
                    ControlFlow::IndirectBranch {
                        possible_targets: vec![],
                    }
                }
            }
            Operation::ConditionalJump => {
                if let Some(Operand::PcRelative { target, .. }) = operands.first() {
                    let condition = Self::decode_condition(opcode);
                    ControlFlow::ConditionalBranch {
                        target: *target,
                        condition,
                        fallthrough: address + offset as u64,
                    }
                } else {
                    ControlFlow::Sequential
                }
            }
            Operation::Call => {
                if let Some(Operand::PcRelative { target, .. }) = operands.first() {
                    ControlFlow::Call {
                        target: *target,
                        return_addr: address + offset as u64,
                    }
                } else {
                    ControlFlow::IndirectCall {
                        return_addr: address + offset as u64,
                    }
                }
            }
            Operation::Return => ControlFlow::Return,
            Operation::Syscall => ControlFlow::Syscall,
            Operation::Halt | Operation::Interrupt => ControlFlow::Halt,
            _ => ControlFlow::Sequential,
        };

        let instruction = Instruction {
            address,
            size: offset,
            bytes: bytes[..offset].to_vec(),
            operation: entry.operation,
            mnemonic: entry.mnemonic.to_string(),
            operands,
            control_flow,
            reads: vec![],
            writes: vec![],
        };

        Ok(DecodedInstruction {
            instruction,
            size: offset,
        })
    }

    fn min_instruction_size(&self) -> usize {
        1
    }

    fn max_instruction_size(&self) -> usize {
        15
    }

    fn is_fixed_width(&self) -> bool {
        false
    }

    fn architecture(&self) -> Architecture {
        Architecture::X86_64
    }
}

impl X86_64Disassembler {
    /// Decode group 1 instructions (0x80-0x83).
    fn decode_group1(
        &self,
        bytes: &[u8],
        address: u64,
        prefixes: &Prefixes,
        mut offset: usize,
        opcode: u8,
    ) -> Result<DecodedInstruction, DecodeError> {
        let remaining = &bytes[offset..];
        if remaining.is_empty() {
            return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
        }

        let modrm = ModRM::parse(remaining[0], prefixes.rex);
        offset += 1;

        // Determine operation from ModR/M reg field
        let (mnemonic, operation) = GROUP1_OPS[(modrm.reg & 0x7) as usize];

        // Determine operand size
        let operand_size = if opcode == 0x80 {
            8
        } else {
            prefixes.operand_size(false)
        };

        // Decode r/m operand
        let rm_bytes = &bytes[offset..];
        let (rm_operand, rm_consumed) = decode_modrm_rm(rm_bytes, modrm, prefixes, operand_size)
            .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
        offset += rm_consumed;

        // Decode immediate
        let remaining = &bytes[offset..];
        let (imm, imm_size) = if opcode == 0x80 || opcode == 0x83 {
            // 8-bit immediate (sign-extended for 0x83)
            if remaining.is_empty() {
                return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
            }
            (remaining[0] as i8 as i128, 1)
        } else if opcode == 0x81 {
            // 32-bit immediate (or 16-bit with 0x66 prefix)
            let size = if prefixes.operand_size { 2 } else { 4 };
            if remaining.len() < size {
                return Err(DecodeError::truncated(address, offset + size, bytes.len()));
            }
            let imm = if size == 2 {
                i16::from_le_bytes([remaining[0], remaining[1]]) as i128
            } else {
                i32::from_le_bytes([remaining[0], remaining[1], remaining[2], remaining[3]]) as i128
            };
            (imm, size)
        } else {
            // 0x82 is not valid in 64-bit mode
            return Err(DecodeError::invalid_encoding(address, "opcode 0x82 invalid in 64-bit mode"));
        };
        offset += imm_size;

        let instruction = Instruction {
            address,
            size: offset,
            bytes: bytes[..offset].to_vec(),
            operation,
            mnemonic: mnemonic.to_string(),
            operands: vec![rm_operand, Operand::imm(imm, (imm_size * 8) as u8)],
            control_flow: ControlFlow::Sequential,
            reads: vec![],
            writes: vec![],
        };

        Ok(DecodedInstruction {
            instruction,
            size: offset,
        })
    }

    /// Decode group 2 instructions (shift/rotate: 0xC0-0xC1, 0xD0-0xD3).
    fn decode_group2(
        &self,
        bytes: &[u8],
        address: u64,
        prefixes: &Prefixes,
        mut offset: usize,
        opcode: u8,
    ) -> Result<DecodedInstruction, DecodeError> {
        use super::opcodes::GROUP2_OPS;

        let remaining = &bytes[offset..];
        if remaining.is_empty() {
            return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
        }

        let modrm = ModRM::parse(remaining[0], prefixes.rex);
        offset += 1;

        // Determine operation from ModR/M reg field
        let (mnemonic, operation) = GROUP2_OPS[(modrm.reg & 0x7) as usize];

        // Determine operand size
        let operand_size = if opcode == 0xC0 || opcode == 0xD0 || opcode == 0xD2 {
            8 // 8-bit operand
        } else {
            prefixes.operand_size(false)
        };

        // Decode r/m operand
        let rm_bytes = &bytes[offset..];
        let (rm_operand, rm_consumed) = decode_modrm_rm(rm_bytes, modrm, prefixes, operand_size)
            .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
        offset += rm_consumed;

        // Decode shift amount based on opcode
        let mut operands = vec![rm_operand];
        match opcode {
            0xD0 | 0xD1 => {
                // Shift by 1
                operands.push(Operand::imm(1, 8));
            }
            0xD2 | 0xD3 => {
                // Shift by CL
                operands.push(Operand::Register(Register::new(
                    Architecture::X86_64,
                    RegisterClass::General,
                    x86::RCX,
                    8,
                )));
            }
            0xC0 | 0xC1 => {
                // Shift by immediate
                let remaining = &bytes[offset..];
                if remaining.is_empty() {
                    return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
                }
                operands.push(Operand::imm(remaining[0] as i128, 8));
                offset += 1;
            }
            _ => {}
        }

        let instruction = Instruction {
            address,
            size: offset,
            bytes: bytes[..offset].to_vec(),
            operation,
            mnemonic: mnemonic.to_string(),
            operands,
            control_flow: ControlFlow::Sequential,
            reads: vec![],
            writes: vec![],
        };

        Ok(DecodedInstruction {
            instruction,
            size: offset,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nop() {
        let disasm = X86_64Disassembler::new();
        let result = disasm.decode_instruction(&[0x90], 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "nop");
        assert_eq!(result.size, 1);
    }

    #[test]
    fn test_push_rbp() {
        let disasm = X86_64Disassembler::new();
        let result = disasm.decode_instruction(&[0x55], 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "push");
        assert_eq!(result.size, 1);
    }

    #[test]
    fn test_mov_rbp_rsp() {
        let disasm = X86_64Disassembler::new();
        // mov rbp, rsp (48 89 e5)
        let result = disasm.decode_instruction(&[0x48, 0x89, 0xe5], 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "mov");
        assert_eq!(result.size, 3);
    }

    #[test]
    fn test_ret() {
        let disasm = X86_64Disassembler::new();
        let result = disasm.decode_instruction(&[0xc3], 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ret");
        assert!(matches!(result.instruction.control_flow, ControlFlow::Return));
    }

    #[test]
    fn test_call_rel32() {
        let disasm = X86_64Disassembler::new();
        // call +0x100
        let result = disasm.decode_instruction(&[0xe8, 0x00, 0x01, 0x00, 0x00], 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "call");
        assert!(matches!(result.instruction.control_flow, ControlFlow::Call { target: 0x1105, .. }));
    }

    #[test]
    fn test_jne_rel8() {
        let disasm = X86_64Disassembler::new();
        // jne +0x10
        let result = disasm.decode_instruction(&[0x75, 0x10], 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "jne");
        assert!(matches!(
            result.instruction.control_flow,
            ControlFlow::ConditionalBranch { target: 0x1012, condition: Condition::NotEqual, .. }
        ));
    }

    #[test]
    fn test_add_rax_imm() {
        let disasm = X86_64Disassembler::new();
        // add eax, 0x42
        let result = disasm.decode_instruction(&[0x05, 0x42, 0x00, 0x00, 0x00], 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "add");
        assert_eq!(result.instruction.operands.len(), 2);
    }

    #[test]
    fn test_syscall() {
        let disasm = X86_64Disassembler::new();
        let result = disasm.decode_instruction(&[0x0f, 0x05], 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "syscall");
        assert!(matches!(result.instruction.control_flow, ControlFlow::Syscall));
    }
}
