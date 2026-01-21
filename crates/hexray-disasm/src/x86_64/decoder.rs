//! x86_64 instruction decoder.

use super::modrm::{
    decode_gpr, decode_modrm_reg, decode_modrm_reg_xmm, decode_modrm_rm, decode_modrm_rm_xmm,
    decode_tmm, decode_xmm, ModRM,
};
use super::opcodes::{
    lookup_sse_opcode, OperandEncoding, SseEncoding, GROUP1_OPS, GROUP3_OPS, GROUP5_OPS,
    GROUP8_OPS, OPCODE_TABLE, OPCODE_TABLE_0F,
};
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
    fn decode_instruction(
        &self,
        bytes: &[u8],
        address: u64,
    ) -> Result<DecodedInstruction, DecodeError> {
        if bytes.is_empty() {
            return Err(DecodeError::truncated(address, 1, 0));
        }

        // Parse prefixes
        let (prefixes, prefix_len) = Prefixes::parse(bytes);
        let mut offset = prefix_len;

        if offset >= bytes.len() {
            return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
        }

        // Check if this is a VEX-encoded instruction
        if prefixes.is_vex() {
            // VEX-encoded: the opcode follows immediately after the VEX prefix
            // The escape bytes are encoded in VEX.mmmmm
            let vex = prefixes.vex.unwrap();
            let opcode = bytes[offset];
            offset += 1;

            // Look up in SSE tables based on VEX.pp (implied prefix)
            let prefix_66 = vex.pp == 1;
            let prefix_f2 = vex.pp == 3;
            let prefix_f3 = vex.pp == 2;

            // For VEX.mmmmm == 1 (0x0F escape), look up in SSE tables
            if vex.mmmmm == 1 {
                if let Some(sse) = lookup_sse_opcode(opcode, prefix_66, prefix_f2, prefix_f3) {
                    return self
                        .decode_sse_instruction(bytes, address, &prefixes, offset, opcode, sse);
                }
            }
            // For VEX.mmmmm == 2 (0x0F 0x38 escape)
            if vex.mmmmm == 2 {
                // Check for AMX instructions (tile operations)
                if super::opcodes_0f38::is_amx_opcode(opcode) {
                    return self.decode_amx_instruction(bytes, address, &prefixes, offset, opcode);
                }
                // Check for BMI1/BMI2 instructions (F2-F7 range) which use GPRs
                if (0xF2..=0xF7).contains(&opcode) {
                    return self.decode_bmi_instruction(bytes, address, &prefixes, offset, opcode);
                }
                if let Some(entry) =
                    super::opcodes_0f38::OPCODE_TABLE_0F38[opcode as usize].as_ref()
                {
                    return self
                        .decode_vex_instruction(bytes, address, &prefixes, offset, opcode, entry);
                }
            }
            // For VEX.mmmmm == 3 (0x0F 0x3A escape) - instructions with immediate
            if vex.mmmmm == 3 {
                if let Some(entry) =
                    super::opcodes_0f3a::OPCODE_TABLE_0F3A[opcode as usize].as_ref()
                {
                    return self
                        .decode_vex_instruction(bytes, address, &prefixes, offset, opcode, entry);
                }
            }
            // Unknown VEX opcode
            let end = offset.min(bytes.len());
            return Err(DecodeError::unknown_opcode(address, &bytes[..end]));
        }

        // Check if this is an EVEX-encoded instruction (AVX-512)
        if prefixes.is_evex() {
            return self.decode_evex_instruction(bytes, address, &prefixes, offset);
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
            // Handle CET instructions with F3 prefix before SSE lookup
            if prefixes.rep {
                // F3 0F 1E: ENDBR64/ENDBR32/RDSSPD/RDSSPQ
                if opcode == 0x1E {
                    let remaining = &bytes[offset..];
                    if !remaining.is_empty() {
                        let modrm_byte = remaining[0];
                        offset += 1;
                        return self.decode_cet_instruction(
                            bytes, address, &prefixes, offset, opcode, modrm_byte,
                        );
                    }
                }
                // F3 0F AE /5: INCSSPD/INCSSPQ
                if opcode == 0xAE {
                    let remaining = &bytes[offset..];
                    if !remaining.is_empty() {
                        let modrm_byte = remaining[0];
                        let modrm = ModRM::parse(modrm_byte, prefixes.rex);
                        if modrm.is_register() && (modrm.reg & 0x7) == 5 {
                            offset += 1;
                            return self.decode_cet_instruction(
                                bytes, address, &prefixes, offset, opcode, modrm_byte,
                            );
                        }
                    }
                }
                // F3 0F 01 EA: SAVEPREVSSP, F3 0F 01 /5: RSTORSSP
                if opcode == 0x01 {
                    let remaining = &bytes[offset..];
                    if !remaining.is_empty() {
                        let modrm_byte = remaining[0];
                        // Check for SAVEPREVSSP or RSTORSSP
                        if modrm_byte == 0xEA || ((modrm_byte >> 3) & 0x7) == 5 {
                            offset += 1;
                            return self
                                .decode_cet_0f01(bytes, address, &prefixes, offset, modrm_byte);
                        }
                    }
                }
            }

            // Handle 0F 38 three-byte escape (SSSE3, SSE4.1, SSE4.2)
            if opcode == 0x38 {
                if offset >= bytes.len() {
                    return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
                }
                let opcode3 = bytes[offset];
                offset += 1;
                return self.decode_0f38_instruction(bytes, address, &prefixes, offset, opcode3);
            }

            // Handle 0F 3A three-byte escape (SSE4.1, SSE4.2 with immediate)
            if opcode == 0x3A {
                if offset >= bytes.len() {
                    return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
                }
                let opcode3 = bytes[offset];
                offset += 1;
                return self.decode_0f3a_instruction(bytes, address, &prefixes, offset, opcode3);
            }

            // First check if this is an SSE instruction
            let sse_entry = lookup_sse_opcode(
                opcode,
                prefixes.operand_size, // 66 prefix
                prefixes.repne,        // F2 prefix
                prefixes.rep,          // F3 prefix
            );

            if let Some(sse) = sse_entry {
                // Decode SSE instruction
                return self.decode_sse_instruction(bytes, address, &prefixes, offset, opcode, sse);
            }

            // Handle 0F 01 system instructions (SGDT, SIDT, LGDT, LIDT, SMSW, LMSW, INVLPG, RDTSCP)
            if opcode == 0x01 {
                return self.decode_0f01_group(bytes, address, &prefixes, offset);
            }

            // Handle 0F BA group 8 (BT/BTS/BTR/BTC with immediate)
            if opcode == 0xBA {
                return self.decode_group8(bytes, address, &prefixes, offset);
            }

            OPCODE_TABLE_0F[opcode as usize].as_ref()
        } else {
            // Handle group 1 (0x80-0x83) specially
            if (0x80..=0x83).contains(&opcode) {
                return self.decode_group1(bytes, address, &prefixes, offset, opcode);
            }
            // Handle group 2 (shift/rotate: 0xC0-0xC1, 0xD0-0xD3)
            if opcode == 0xC0 || opcode == 0xC1 || (0xD0..=0xD3).contains(&opcode) {
                return self.decode_group2(bytes, address, &prefixes, offset, opcode);
            }
            // Handle group 3 (0xF6/0xF7: TEST/NOT/NEG/MUL/DIV)
            if opcode == 0xF6 || opcode == 0xF7 {
                return self.decode_group3(bytes, address, &prefixes, offset, opcode);
            }
            // Handle group 5 (0xFF: INC/DEC/CALL/JMP/PUSH)
            if opcode == 0xFF {
                return self.decode_group5(bytes, address, &prefixes, offset);
            }
            // Handle x87 FPU instructions (0xD8-0xDF)
            if (0xD8..=0xDF).contains(&opcode) {
                return self.decode_x87(bytes, address, &prefixes, offset, opcode);
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
                let reg_num =
                    (opcode & 0x07) | (prefixes.rex.map(|r| (r.b as u8) << 3).unwrap_or(0));
                let reg = decode_gpr(reg_num, operand_size);
                operands.push(Operand::Register(reg));

                // For MOV r, imm variants (B0-BF), also read immediate
                if (0xB0..=0xBF).contains(&opcode) {
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
                        return Err(DecodeError::truncated(
                            address,
                            offset + imm_size,
                            bytes.len(),
                        ));
                    }

                    let imm = match imm_size {
                        1 => remaining[0] as i128,
                        2 => i16::from_le_bytes([remaining[0], remaining[1]]) as i128,
                        4 => i32::from_le_bytes([
                            remaining[0],
                            remaining[1],
                            remaining[2],
                            remaining[3],
                        ]) as i128,
                        8 => i64::from_le_bytes([
                            remaining[0],
                            remaining[1],
                            remaining[2],
                            remaining[3],
                            remaining[4],
                            remaining[5],
                            remaining[6],
                            remaining[7],
                        ]) as i128,
                        _ => unreachable!(),
                    };
                    operands.push(Operand::imm(imm, (imm_size * 8) as u8));
                    offset += imm_size;
                }
            }

            OperandEncoding::ModRmRm_Reg
            | OperandEncoding::ModRmReg_Rm
            | OperandEncoding::ModRmRmOnly => {
                if remaining.is_empty() {
                    return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
                }
                let modrm = ModRM::parse(remaining[0], prefixes.rex);
                offset += 1;

                let rm_bytes = &bytes[offset..];
                let (rm_operand, rm_consumed) =
                    decode_modrm_rm(rm_bytes, modrm, &prefixes, operand_size)
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
                let acc = Register::new(
                    Architecture::X86_64,
                    RegisterClass::General,
                    x86::RAX,
                    operand_size,
                );
                operands.push(Operand::Register(acc));

                let imm_size = match operand_size {
                    8 => 1,
                    16 => 2,
                    32 | 64 => 4, // 64-bit mode still uses 32-bit immediate (sign-extended)
                    _ => 4,
                };

                if remaining.len() < imm_size {
                    return Err(DecodeError::truncated(
                        address,
                        offset + imm_size,
                        bytes.len(),
                    ));
                }

                let imm = match imm_size {
                    1 => remaining[0] as i8 as i128,
                    2 => i16::from_le_bytes([remaining[0], remaining[1]]) as i128,
                    4 => {
                        i32::from_le_bytes([remaining[0], remaining[1], remaining[2], remaining[3]])
                            as i128
                    }
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
                let rel =
                    i32::from_le_bytes([remaining[0], remaining[1], remaining[2], remaining[3]])
                        as i64;
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
                let imm =
                    i32::from_le_bytes([remaining[0], remaining[1], remaining[2], remaining[3]])
                        as i128;
                operands.push(Operand::imm(imm, 32));
                offset += 4;
            }

            OperandEncoding::Imm64 => {
                if remaining.len() < 8 {
                    return Err(DecodeError::truncated(address, offset + 8, bytes.len()));
                }
                let imm = i64::from_le_bytes([
                    remaining[0],
                    remaining[1],
                    remaining[2],
                    remaining[3],
                    remaining[4],
                    remaining[5],
                    remaining[6],
                    remaining[7],
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
                let (rm_operand, rm_consumed) =
                    decode_modrm_rm(rm_bytes, modrm, &prefixes, operand_size)
                        .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
                offset += rm_consumed;

                // Decode immediate
                // For Rm_Imm8 or when entry.default_size is 8, use 8-bit immediate
                let remaining = &bytes[offset..];
                let (imm, imm_size) = if matches!(entry.encoding, OperandEncoding::Rm_Imm8)
                    || entry.default_size == 8
                {
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
                        i32::from_le_bytes([remaining[0], remaining[1], remaining[2], remaining[3]])
                            as i128
                    };
                    (imm, size)
                };
                offset += imm_size;

                operands.push(rm_operand);
                operands.push(Operand::imm(imm, (imm_size * 8) as u8));
            }

            OperandEncoding::ModRmRm_Reg_Imm8 => {
                // SHLD/SHRD r/m, reg, imm8
                if remaining.is_empty() {
                    return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
                }
                let modrm = ModRM::parse(remaining[0], prefixes.rex);
                offset += 1;

                let rm_bytes = &bytes[offset..];
                let (rm_operand, rm_consumed) =
                    decode_modrm_rm(rm_bytes, modrm, &prefixes, operand_size)
                        .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
                offset += rm_consumed;

                // Get immediate
                let remaining = &bytes[offset..];
                if remaining.is_empty() {
                    return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
                }
                let imm = remaining[0];
                offset += 1;

                operands.push(rm_operand);
                operands.push(decode_modrm_reg(modrm, operand_size));
                operands.push(Operand::imm_unsigned(imm as u64, 8));
            }

            OperandEncoding::ModRmRm_Reg_Cl => {
                // SHLD/SHRD r/m, reg, CL
                if remaining.is_empty() {
                    return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
                }
                let modrm = ModRM::parse(remaining[0], prefixes.rex);
                offset += 1;

                let rm_bytes = &bytes[offset..];
                let (rm_operand, rm_consumed) =
                    decode_modrm_rm(rm_bytes, modrm, &prefixes, operand_size)
                        .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
                offset += rm_consumed;

                operands.push(rm_operand);
                operands.push(decode_modrm_reg(modrm, operand_size));
                operands.push(Operand::Register(Register::new(
                    Architecture::X86_64,
                    RegisterClass::General,
                    x86::RCX,
                    8,
                ))); // CL
            }

            OperandEncoding::OpReg0F => {
                // BSWAP: register encoded in 0F opcode byte (0F C8+rd)
                // The register number is the lower 3 bits of the second opcode byte
                // plus REX.B extension
                let reg_num =
                    (opcode & 0x07) | (prefixes.rex.map(|r| (r.b as u8) << 3).unwrap_or(0));
                let reg_size = if prefixes.rex.map(|r| r.w).unwrap_or(false) {
                    64
                } else {
                    32
                };
                let reg = decode_gpr(reg_num, reg_size);
                operands.push(Operand::Register(reg));
            }

            OperandEncoding::Imm16_Imm8 => {
                // ENTER imm16, imm8
                let remaining = &bytes[offset..];
                if remaining.len() < 3 {
                    return Err(DecodeError::truncated(address, offset + 3, bytes.len()));
                }
                let imm16 = u16::from_le_bytes([remaining[0], remaining[1]]);
                let imm8 = remaining[2];
                offset += 3;
                operands.push(Operand::imm(imm16 as i128, 16));
                operands.push(Operand::imm(imm8 as i128, 8));
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

        // Select correct mnemonic for sign-extension instructions based on operand size
        let mnemonic = if opcode == 0x98 {
            // CBW (16) / CWDE (32) / CDQE (64)
            match operand_size {
                16 => "cbw",
                64 => "cdqe",
                _ => "cwde",
            }
        } else if opcode == 0x99 {
            // CWD (16) / CDQ (32) / CQO (64)
            match operand_size {
                16 => "cwd",
                64 => "cqo",
                _ => "cdq",
            }
        } else {
            entry.mnemonic
        };

        let instruction = Instruction {
            address,
            size: offset,
            bytes: bytes[..offset].to_vec(),
            operation: entry.operation,
            mnemonic: mnemonic.to_string(),
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
            return Err(DecodeError::invalid_encoding(
                address,
                "opcode 0x82 invalid in 64-bit mode",
            ));
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

    /// Decode group 3 instructions (0xF6/0xF7: TEST/NOT/NEG/MUL/DIV r/m).
    fn decode_group3(
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
        let (mnemonic, operation) = GROUP3_OPS[(modrm.reg & 0x7) as usize];

        // Operand size: F6 = 8-bit, F7 = 16/32/64-bit
        let operand_size = if opcode == 0xF6 {
            8
        } else {
            prefixes.operand_size(false)
        };

        // Decode r/m operand
        let rm_bytes = &bytes[offset..];
        let (rm_operand, rm_consumed) = decode_modrm_rm(rm_bytes, modrm, prefixes, operand_size)
            .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
        offset += rm_consumed;

        // For TEST (reg field 0 or 1), we need an immediate operand
        let operands = if (modrm.reg & 0x7) <= 1 {
            let imm_remaining = &bytes[offset..];
            let imm_size = if opcode == 0xF6 {
                1
            } else {
                std::cmp::min(operand_size as usize, 4)
            };
            if imm_remaining.len() < imm_size {
                return Err(DecodeError::truncated(
                    address,
                    offset + imm_size,
                    bytes.len(),
                ));
            }
            let imm = match imm_size {
                1 => imm_remaining[0] as i8 as i128,
                2 => i16::from_le_bytes([imm_remaining[0], imm_remaining[1]]) as i128,
                4 => i32::from_le_bytes([
                    imm_remaining[0],
                    imm_remaining[1],
                    imm_remaining[2],
                    imm_remaining[3],
                ]) as i128,
                _ => unreachable!(),
            };
            offset += imm_size;
            vec![rm_operand, Operand::imm(imm, (imm_size * 8) as u8)]
        } else {
            // NOT/NEG/MUL/IMUL/DIV/IDIV - just r/m operand
            vec![rm_operand]
        };

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

    /// Decode group 5 instructions (0xFF: INC/DEC/CALL/JMP/PUSH r/m).
    fn decode_group5(
        &self,
        bytes: &[u8],
        address: u64,
        prefixes: &Prefixes,
        mut offset: usize,
    ) -> Result<DecodedInstruction, DecodeError> {
        let remaining = &bytes[offset..];
        if remaining.is_empty() {
            return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
        }

        let modrm = ModRM::parse(remaining[0], prefixes.rex);
        offset += 1;

        // Determine operation from ModR/M reg field
        let (mnemonic, operation) = GROUP5_OPS[(modrm.reg & 0x7) as usize];

        // Reserved opcode extension
        if mnemonic.is_empty() {
            return Err(DecodeError::invalid_encoding(
                address,
                "reserved opcode extension in group 5",
            ));
        }

        // Operand size: CALL/JMP are always 64-bit in 64-bit mode, others depend on prefix
        let operand_size = match modrm.reg & 0x7 {
            2..=5 => 64,                       // CALL/JMP always 64-bit
            6 => 64,                           // PUSH always 64-bit in 64-bit mode
            _ => prefixes.operand_size(false), // INC/DEC use normal size
        };

        // Decode r/m operand
        let rm_bytes = &bytes[offset..];
        let (rm_operand, rm_consumed) = decode_modrm_rm(rm_bytes, modrm, prefixes, operand_size)
            .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
        offset += rm_consumed;

        // Determine control flow
        let control_flow = match modrm.reg & 0x7 {
            2 | 3 => {
                // CALL r/m64 (indirect call)
                ControlFlow::IndirectCall {
                    return_addr: address + offset as u64,
                }
            }
            4 | 5 => {
                // JMP r/m64 (indirect jump)
                ControlFlow::IndirectBranch {
                    possible_targets: vec![],
                }
            }
            _ => ControlFlow::Sequential,
        };

        let instruction = Instruction {
            address,
            size: offset,
            bytes: bytes[..offset].to_vec(),
            operation,
            mnemonic: mnemonic.to_string(),
            operands: vec![rm_operand],
            control_flow,
            reads: vec![],
            writes: vec![],
        };

        Ok(DecodedInstruction {
            instruction,
            size: offset,
        })
    }

    /// Decode group 8 instructions (0x0F BA: BT/BTS/BTR/BTC with immediate).
    fn decode_group8(
        &self,
        bytes: &[u8],
        address: u64,
        prefixes: &Prefixes,
        mut offset: usize,
    ) -> Result<DecodedInstruction, DecodeError> {
        let remaining = &bytes[offset..];
        if remaining.is_empty() {
            return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
        }

        let modrm = ModRM::parse(remaining[0], prefixes.rex);
        offset += 1;

        // Determine operation from ModR/M reg field
        let (mnemonic, operation) = GROUP8_OPS[(modrm.reg & 0x7) as usize];

        // Reserved opcode extension (reg = 0-3 are reserved)
        if mnemonic.is_empty() {
            return Err(DecodeError::invalid_encoding(
                address,
                "reserved opcode extension in group 8",
            ));
        }

        // Operand size depends on prefix
        let operand_size = prefixes.operand_size(false);

        // Decode r/m operand
        let rm_bytes = &bytes[offset..];
        let (rm_operand, rm_consumed) = decode_modrm_rm(rm_bytes, modrm, prefixes, operand_size)
            .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
        offset += rm_consumed;

        // Read immediate byte (bit position)
        if offset >= bytes.len() {
            return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
        }
        let imm = bytes[offset];
        offset += 1;

        let instruction = Instruction {
            address,
            size: offset,
            bytes: bytes[..offset].to_vec(),
            operation,
            mnemonic: mnemonic.to_string(),
            operands: vec![rm_operand, Operand::imm_unsigned(imm as u64, 8)],
            control_flow: ControlFlow::Sequential,
            reads: vec![],
            writes: vec![],
        };

        Ok(DecodedInstruction {
            instruction,
            size: offset,
        })
    }

    /// Decode x87 FPU instructions (0xD8-0xDF).
    fn decode_x87(
        &self,
        bytes: &[u8],
        address: u64,
        prefixes: &Prefixes,
        mut offset: usize,
        escape: u8,
    ) -> Result<DecodedInstruction, DecodeError> {
        let remaining = &bytes[offset..];
        if remaining.is_empty() {
            return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
        }

        let modrm_byte = remaining[0];
        offset += 1;

        // Look up the x87 instruction
        let entry = super::x87::decode_x87(escape, modrm_byte)
            .ok_or_else(|| DecodeError::unknown_opcode(address, &bytes[..offset]))?;

        let modrm = ModRM::parse(modrm_byte, prefixes.rex);
        let is_memory = modrm_byte < 0xC0;

        // Build operands
        let mut operands = Vec::new();

        if is_memory {
            // Memory operand
            let rm_bytes = &bytes[offset..];
            // Use the mem_size from entry to determine effective size, but decode_modrm_rm
            // just needs a size for register addressing (not used for memory)
            let (rm_operand, rm_consumed) = decode_modrm_rm(rm_bytes, modrm, prefixes, 64)
                .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
            offset += rm_consumed;
            operands.push(rm_operand);
        } else {
            // Register operand - ST(i)
            let st_idx = modrm_byte & 0x07;

            // Helper to create ST(n) register
            let st_reg =
                |n: u8| Register::new(Architecture::X86_64, RegisterClass::X87, n as u16, 80);

            match entry.operand_count {
                0 => {
                    // No operands (e.g., FNOP, FSIN, FCOS)
                }
                1 => {
                    // Single ST(i) operand
                    operands.push(Operand::Register(st_reg(st_idx)));
                }
                2 => {
                    // Two operands: ST(0), ST(i) or ST(i), ST(0)
                    // For D8: ST(0), ST(i)
                    // For DC/DE: ST(i), ST(0)
                    if escape == 0xDC || escape == 0xDE {
                        operands.push(Operand::Register(st_reg(st_idx)));
                        operands.push(Operand::Register(st_reg(0)));
                    } else {
                        operands.push(Operand::Register(st_reg(0)));
                        operands.push(Operand::Register(st_reg(st_idx)));
                    }
                }
                _ => {}
            }
        }

        // Special case: FNSTSW AX (DF E0)
        if escape == 0xDF && modrm_byte == 0xE0 {
            operands.clear();
            // AX is RAX with 16-bit size
            operands.push(Operand::Register(Register::new(
                Architecture::X86_64,
                RegisterClass::General,
                x86::RAX,
                16,
            )));
        }

        let instruction = Instruction {
            address,
            size: offset,
            bytes: bytes[..offset].to_vec(),
            operation: entry.operation,
            mnemonic: entry.mnemonic.to_string(),
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

    /// Decode SSE/AVX instructions.
    fn decode_sse_instruction(
        &self,
        bytes: &[u8],
        address: u64,
        prefixes: &Prefixes,
        mut offset: usize,
        _opcode: u8,
        sse: &super::opcodes::SseOpcodeEntry,
    ) -> Result<DecodedInstruction, DecodeError> {
        let remaining = &bytes[offset..];
        if remaining.is_empty() {
            return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
        }

        // Get effective REX prefix (from REX or VEX)
        let effective_rex = prefixes.effective_rex();

        // Parse ModR/M
        let modrm = ModRM::parse(remaining[0], effective_rex);
        offset += 1;

        // Determine vector size (XMM=128 or YMM=256 for VEX)
        let vector_size = prefixes.vector_size();

        // Determine mnemonic (use VEX mnemonic if VEX-encoded)
        let mnemonic = if prefixes.is_vex() {
            sse.vex_mnemonic.unwrap_or(sse.mnemonic)
        } else {
            sse.mnemonic
        };

        // Decode operands based on encoding
        let mut operands = Vec::new();

        match sse.encoding {
            SseEncoding::XmmRm => {
                // xmm, xmm/m128
                let rm_bytes = &bytes[offset..];
                let (rm_operand, rm_consumed) =
                    decode_modrm_rm_xmm(rm_bytes, modrm, prefixes, vector_size)
                        .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
                offset += rm_consumed;

                // For VEX 3-operand form, add vvvv register
                if prefixes.is_vex() {
                    let vex = prefixes.vex.unwrap();
                    // VEX dest is reg, src1 is vvvv, src2 is rm
                    operands.push(decode_modrm_reg_xmm(modrm, vector_size));
                    operands.push(Operand::Register(decode_xmm(vex.vvvv, vector_size)));
                    operands.push(rm_operand);
                } else {
                    // SSE: dest is reg, src is rm
                    operands.push(decode_modrm_reg_xmm(modrm, vector_size));
                    operands.push(rm_operand);
                }
            }

            SseEncoding::RmXmm => {
                // xmm/m128, xmm
                let rm_bytes = &bytes[offset..];
                let (rm_operand, rm_consumed) =
                    decode_modrm_rm_xmm(rm_bytes, modrm, prefixes, vector_size)
                        .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
                offset += rm_consumed;

                operands.push(rm_operand);
                operands.push(decode_modrm_reg_xmm(modrm, vector_size));
            }

            SseEncoding::XmmRmImm8 => {
                // xmm, xmm/m128, imm8
                let rm_bytes = &bytes[offset..];
                let (rm_operand, rm_consumed) =
                    decode_modrm_rm_xmm(rm_bytes, modrm, prefixes, vector_size)
                        .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
                offset += rm_consumed;

                // For VEX 4-operand form
                if prefixes.is_vex() {
                    let vex = prefixes.vex.unwrap();
                    operands.push(decode_modrm_reg_xmm(modrm, vector_size));
                    operands.push(Operand::Register(decode_xmm(vex.vvvv, vector_size)));
                    operands.push(rm_operand);
                } else {
                    operands.push(decode_modrm_reg_xmm(modrm, vector_size));
                    operands.push(rm_operand);
                }

                // Read immediate
                let imm_remaining = &bytes[offset..];
                if imm_remaining.is_empty() {
                    return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
                }
                operands.push(Operand::imm(imm_remaining[0] as i128, 8));
                offset += 1;
            }

            SseEncoding::XmmXmmRm => {
                // xmm, xmm, xmm/m128 (VEX 3-operand)
                let rm_bytes = &bytes[offset..];
                let (rm_operand, rm_consumed) =
                    decode_modrm_rm_xmm(rm_bytes, modrm, prefixes, vector_size)
                        .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
                offset += rm_consumed;

                if prefixes.is_vex() {
                    let vex = prefixes.vex.unwrap();
                    operands.push(decode_modrm_reg_xmm(modrm, vector_size));
                    operands.push(Operand::Register(decode_xmm(vex.vvvv, vector_size)));
                    operands.push(rm_operand);
                } else {
                    operands.push(decode_modrm_reg_xmm(modrm, vector_size));
                    operands.push(rm_operand);
                }
            }

            SseEncoding::XmmRmScalar64 => {
                // xmm, xmm/m64
                let rm_bytes = &bytes[offset..];
                // For scalar, memory is 64-bit but registers are full vector size
                let (rm_operand, rm_consumed) = if modrm.is_register() {
                    decode_modrm_rm_xmm(rm_bytes, modrm, prefixes, vector_size)
                } else {
                    decode_modrm_rm(rm_bytes, modrm, prefixes, 64)
                }
                .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
                offset += rm_consumed;

                if prefixes.is_vex() {
                    let vex = prefixes.vex.unwrap();
                    operands.push(decode_modrm_reg_xmm(modrm, vector_size));
                    operands.push(Operand::Register(decode_xmm(vex.vvvv, vector_size)));
                    operands.push(rm_operand);
                } else {
                    operands.push(decode_modrm_reg_xmm(modrm, vector_size));
                    operands.push(rm_operand);
                }
            }

            SseEncoding::XmmRmScalar32 => {
                // xmm, xmm/m32
                let rm_bytes = &bytes[offset..];
                let (rm_operand, rm_consumed) = if modrm.is_register() {
                    decode_modrm_rm_xmm(rm_bytes, modrm, prefixes, vector_size)
                } else {
                    decode_modrm_rm(rm_bytes, modrm, prefixes, 32)
                }
                .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
                offset += rm_consumed;

                if prefixes.is_vex() {
                    let vex = prefixes.vex.unwrap();
                    operands.push(decode_modrm_reg_xmm(modrm, vector_size));
                    operands.push(Operand::Register(decode_xmm(vex.vvvv, vector_size)));
                    operands.push(rm_operand);
                } else {
                    operands.push(decode_modrm_reg_xmm(modrm, vector_size));
                    operands.push(rm_operand);
                }
            }

            SseEncoding::XmmGpr => {
                // xmm, r/m32/64
                let rm_bytes = &bytes[offset..];
                let gpr_size = if prefixes.rex.map(|r| r.w).unwrap_or(false) {
                    64
                } else {
                    32
                };
                let (rm_operand, rm_consumed) =
                    decode_modrm_rm(rm_bytes, modrm, prefixes, gpr_size)
                        .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
                offset += rm_consumed;

                if prefixes.is_vex() {
                    let vex = prefixes.vex.unwrap();
                    operands.push(decode_modrm_reg_xmm(modrm, vector_size));
                    operands.push(Operand::Register(decode_xmm(vex.vvvv, vector_size)));
                    operands.push(rm_operand);
                } else {
                    operands.push(decode_modrm_reg_xmm(modrm, vector_size));
                    operands.push(rm_operand);
                }
            }

            SseEncoding::GprXmm => {
                // r32/64, xmm/m
                let rm_bytes = &bytes[offset..];
                let (rm_operand, rm_consumed) =
                    decode_modrm_rm_xmm(rm_bytes, modrm, prefixes, vector_size)
                        .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
                offset += rm_consumed;

                let gpr_size = if prefixes.rex.map(|r| r.w).unwrap_or(false) {
                    64
                } else {
                    32
                };
                operands.push(Operand::Register(decode_gpr(modrm.reg, gpr_size)));
                operands.push(rm_operand);
            }

            SseEncoding::XmmOnly => {
                // Single xmm operand
                operands.push(decode_modrm_reg_xmm(modrm, vector_size));
            }

            SseEncoding::GprGprRm => {
                // r, r/m (GPR to GPR, for POPCNT/LZCNT/TZCNT)
                let rm_bytes = &bytes[offset..];
                let gpr_size = if prefixes.rex.map(|r| r.w).unwrap_or(false) {
                    64
                } else {
                    32
                };
                let (rm_operand, rm_consumed) =
                    decode_modrm_rm(rm_bytes, modrm, prefixes, gpr_size)
                        .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
                offset += rm_consumed;

                operands.push(Operand::Register(decode_gpr(modrm.reg, gpr_size)));
                operands.push(rm_operand);
            }
        }

        let instruction = Instruction {
            address,
            size: offset,
            bytes: bytes[..offset].to_vec(),
            operation: sse.operation,
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

    /// Decode non-VEX 0F 38 three-byte escape instructions (SSSE3, SSE4.1, SSE4.2).
    fn decode_0f38_instruction(
        &self,
        bytes: &[u8],
        address: u64,
        prefixes: &Prefixes,
        mut offset: usize,
        opcode: u8,
    ) -> Result<DecodedInstruction, DecodeError> {
        // Look up the opcode in the 0F38 table
        let entry = super::opcodes_0f38::OPCODE_TABLE_0F38[opcode as usize]
            .as_ref()
            .ok_or_else(|| DecodeError::unknown_opcode(address, &bytes[..offset]))?;

        let remaining = &bytes[offset..];
        if remaining.is_empty() {
            return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
        }

        // Parse ModR/M
        let modrm = ModRM::parse(remaining[0], prefixes.rex);
        offset += 1;

        // Decode operands
        let mut operands = Vec::new();

        // Get the rm operand
        let rm_bytes = &bytes[offset..];
        let (rm_operand, rm_consumed) = decode_modrm_rm_xmm(rm_bytes, modrm, prefixes, 128)
            .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
        offset += rm_consumed;

        // For SSE4.1 PBLENDVB and similar, the implicit xmm0 operand is used
        // Order: dest, src, [implicit xmm0]
        operands.push(decode_modrm_reg_xmm(modrm, 128));
        operands.push(rm_operand);

        // PBLENDVB (0x10), BLENDVPS (0x14), BLENDVPD (0x15), PTEST (0x17) have implicit XMM0
        if opcode == 0x10 || opcode == 0x14 || opcode == 0x15 {
            operands.push(Operand::Register(decode_xmm(0, 128))); // xmm0
        }

        let instruction = Instruction {
            address,
            size: offset,
            bytes: bytes[..offset].to_vec(),
            operation: entry.operation,
            mnemonic: entry.mnemonic.to_string(),
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

    /// Decode non-VEX 0F 3A three-byte escape instructions (SSE4.1, SSE4.2 with immediate).
    fn decode_0f3a_instruction(
        &self,
        bytes: &[u8],
        address: u64,
        prefixes: &Prefixes,
        mut offset: usize,
        opcode: u8,
    ) -> Result<DecodedInstruction, DecodeError> {
        // Look up the opcode in the 0F3A table
        let entry = super::opcodes_0f3a::OPCODE_TABLE_0F3A[opcode as usize]
            .as_ref()
            .ok_or_else(|| DecodeError::unknown_opcode(address, &bytes[..offset]))?;

        let remaining = &bytes[offset..];
        if remaining.is_empty() {
            return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
        }

        // Parse ModR/M
        let modrm = ModRM::parse(remaining[0], prefixes.rex);
        offset += 1;

        // Decode operands
        let mut operands = Vec::new();

        // Get the rm operand
        let rm_bytes = &bytes[offset..];
        let (rm_operand, rm_consumed) = decode_modrm_rm_xmm(rm_bytes, modrm, prefixes, 128)
            .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
        offset += rm_consumed;

        // Order: dest (reg), src (rm), imm8
        operands.push(decode_modrm_reg_xmm(modrm, 128));
        operands.push(rm_operand);

        // Read immediate byte
        let imm_remaining = &bytes[offset..];
        if imm_remaining.is_empty() {
            return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
        }
        operands.push(Operand::imm(imm_remaining[0] as i128, 8));
        offset += 1;

        let instruction = Instruction {
            address,
            size: offset,
            bytes: bytes[..offset].to_vec(),
            operation: entry.operation,
            mnemonic: entry.mnemonic.to_string(),
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

    /// Decode a VEX-encoded instruction from 0F38 or 0F3A tables.
    fn decode_vex_instruction(
        &self,
        bytes: &[u8],
        address: u64,
        prefixes: &Prefixes,
        mut offset: usize,
        _opcode: u8,
        entry: &super::opcodes::OpcodeEntry,
    ) -> Result<DecodedInstruction, DecodeError> {
        let remaining = &bytes[offset..];
        if remaining.is_empty() {
            return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
        }

        // Get effective REX prefix from VEX
        let effective_rex = prefixes.effective_rex();

        // Parse ModR/M
        let modrm = ModRM::parse(remaining[0], effective_rex);
        offset += 1;

        // Determine vector size (XMM=128, YMM=256, ZMM=512 for EVEX)
        let vector_size = prefixes.vector_size();

        // Add 'v' prefix for VEX-encoded instructions (unless mnemonic already starts with 'v')
        let mnemonic =
            if (prefixes.is_vex() || prefixes.is_evex()) && !entry.mnemonic.starts_with('v') {
                format!("v{}", entry.mnemonic)
            } else {
                entry.mnemonic.to_string()
            };

        // Decode operands
        let mut operands = Vec::new();

        // Get the rm operand first
        let rm_bytes = &bytes[offset..];
        let (rm_operand, rm_consumed) = decode_modrm_rm_xmm(rm_bytes, modrm, prefixes, vector_size)
            .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
        offset += rm_consumed;

        // Build operands based on encoding
        // For 3-operand VEX: dest=reg, src1=vvvv, src2=rm
        if let Some(vex) = prefixes.vex {
            operands.push(decode_modrm_reg_xmm(modrm, vector_size));
            operands.push(Operand::Register(decode_xmm(vex.vvvv, vector_size)));
            operands.push(rm_operand);
        } else if let Some(evex) = prefixes.evex {
            operands.push(decode_modrm_reg_xmm(modrm, vector_size));
            operands.push(Operand::Register(decode_xmm(evex.vvvvv(), vector_size)));
            operands.push(rm_operand);
        } else {
            operands.push(decode_modrm_reg_xmm(modrm, vector_size));
            operands.push(rm_operand);
        }

        // For 0F3A instructions, read immediate byte
        if prefixes.opcode_map() == 3 {
            let imm_remaining = &bytes[offset..];
            if imm_remaining.is_empty() {
                return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
            }
            operands.push(Operand::imm(imm_remaining[0] as i128, 8));
            offset += 1;
        }

        let instruction = Instruction {
            address,
            size: offset,
            bytes: bytes[..offset].to_vec(),
            operation: entry.operation,
            mnemonic,
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

    /// Decode an EVEX-encoded instruction (AVX-512).
    ///
    /// EVEX is a 4-byte prefix that extends VEX with support for:
    /// - 512-bit vector registers (ZMM)
    /// - 32 vector registers (zmm0-zmm31)
    /// - 8 opmask registers (k0-k7)
    /// - Embedded broadcast, rounding, and exception control
    fn decode_evex_instruction(
        &self,
        bytes: &[u8],
        address: u64,
        prefixes: &Prefixes,
        mut offset: usize,
    ) -> Result<DecodedInstruction, DecodeError> {
        let evex = prefixes
            .evex
            .ok_or_else(|| DecodeError::invalid_encoding(address, "expected EVEX prefix"))?;

        // Read the opcode byte
        if offset >= bytes.len() {
            return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
        }
        let opcode = bytes[offset];
        offset += 1;

        // Read ModR/M byte
        if offset >= bytes.len() {
            return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
        }
        let modrm = ModRM::parse_evex(bytes[offset], &evex);
        offset += 1;

        // Determine vector size from EVEX.L'L
        let vector_size = evex.vector_size();

        // Look up opcode based on EVEX.mm (opcode map)
        // mm=1 -> 0F, mm=2 -> 0F38, mm=3 -> 0F3A
        let (mnemonic, operation) = match evex.mm {
            1 => self.lookup_evex_opcode_0f(opcode, &evex),
            2 => self.lookup_evex_opcode_0f38(opcode, &evex),
            3 => self.lookup_evex_opcode_0f3a(opcode, &evex),
            _ => None,
        }
        .ok_or_else(|| {
            let end = offset.min(bytes.len());
            DecodeError::unknown_opcode(address, &bytes[..end])
        })?;

        // Decode operands
        let mut operands = Vec::new();

        // Decode r/m operand
        let rm_bytes = &bytes[offset..];
        let (rm_operand, rm_consumed) = self
            .decode_evex_modrm_rm(rm_bytes, modrm, prefixes, &evex, vector_size)
            .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
        offset += rm_consumed;

        // Build operand list: dest=reg, src1=vvvv, src2=rm
        // For EVEX, dest uses extended reg (R, R')
        operands.push(Operand::Register(decode_xmm(modrm.reg, vector_size)));
        // vvvv operand (5-bit with V')
        operands.push(Operand::Register(decode_xmm(evex.vvvvv(), vector_size)));
        operands.push(rm_operand);

        // For 0F3A map, read immediate byte
        if evex.mm == 3 {
            if offset >= bytes.len() {
                return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
            }
            operands.push(Operand::imm(bytes[offset] as i128, 8));
            offset += 1;
        }

        // Build the mnemonic with opmask suffix if needed
        let full_mnemonic = self.format_evex_mnemonic(&mnemonic, &evex);

        let instruction = Instruction {
            address,
            size: offset,
            bytes: bytes[..offset].to_vec(),
            operation,
            mnemonic: full_mnemonic,
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

    /// Look up EVEX opcode in map 1 (0F prefix).
    fn lookup_evex_opcode_0f(
        &self,
        opcode: u8,
        evex: &super::prefix::Evex,
    ) -> Option<(String, Operation)> {
        // Determine mnemonic based on EVEX.pp (implied prefix)
        // pp=0: no prefix, pp=1: 66, pp=2: F3, pp=3: F2
        match (opcode, evex.pp) {
            // VMOVAPS zmm, zmm/m512 (EVEX.512.0F.W0 28 /r)
            (0x28, 0) => Some(("vmovaps".to_string(), Operation::Move)),
            // VMOVAPD zmm, zmm/m512 (EVEX.512.66.0F.W1 28 /r)
            (0x28, 1) => Some(("vmovapd".to_string(), Operation::Move)),
            // VMOVAPS zmm/m512, zmm (EVEX.512.0F.W0 29 /r)
            (0x29, 0) => Some(("vmovaps".to_string(), Operation::Store)),
            // VMOVAPD zmm/m512, zmm (EVEX.512.66.0F.W1 29 /r)
            (0x29, 1) => Some(("vmovapd".to_string(), Operation::Store)),
            // VMOVUPS zmm, zmm/m512 (EVEX.512.0F.W0 10 /r)
            (0x10, 0) => Some(("vmovups".to_string(), Operation::Move)),
            // VMOVUPD zmm, zmm/m512 (EVEX.512.66.0F.W1 10 /r)
            (0x10, 1) => Some(("vmovupd".to_string(), Operation::Move)),
            // VMOVSS xmm, xmm, xmm/m32 (EVEX.LIG.F3.0F.W0 10 /r)
            (0x10, 2) => Some(("vmovss".to_string(), Operation::Move)),
            // VMOVSD xmm, xmm, xmm/m64 (EVEX.LIG.F2.0F.W1 10 /r)
            (0x10, 3) => Some(("vmovsd".to_string(), Operation::Move)),
            // VMOVUPS zmm/m512, zmm (EVEX.512.0F.W0 11 /r)
            (0x11, 0) => Some(("vmovups".to_string(), Operation::Store)),
            // VMOVUPD zmm/m512, zmm (EVEX.512.66.0F.W1 11 /r)
            (0x11, 1) => Some(("vmovupd".to_string(), Operation::Store)),
            // VMOVSS xmm/m32, xmm (EVEX.LIG.F3.0F.W0 11 /r)
            (0x11, 2) => Some(("vmovss".to_string(), Operation::Store)),
            // VMOVSD xmm/m64, xmm (EVEX.LIG.F2.0F.W1 11 /r)
            (0x11, 3) => Some(("vmovsd".to_string(), Operation::Store)),
            // VADDPS zmm, zmm, zmm/m512 (EVEX.512.0F.W0 58 /r)
            (0x58, 0) => Some(("vaddps".to_string(), Operation::Add)),
            // VADDPD zmm, zmm, zmm/m512 (EVEX.512.66.0F.W1 58 /r)
            (0x58, 1) => Some(("vaddpd".to_string(), Operation::Add)),
            // VADDSS xmm, xmm, xmm/m32 (EVEX.LIG.F3.0F.W0 58 /r)
            (0x58, 2) => Some(("vaddss".to_string(), Operation::Add)),
            // VADDSD xmm, xmm, xmm/m64 (EVEX.LIG.F2.0F.W1 58 /r)
            (0x58, 3) => Some(("vaddsd".to_string(), Operation::Add)),
            // VMULPS zmm, zmm, zmm/m512 (EVEX.512.0F.W0 59 /r)
            (0x59, 0) => Some(("vmulps".to_string(), Operation::Mul)),
            // VMULPD zmm, zmm, zmm/m512 (EVEX.512.66.0F.W1 59 /r)
            (0x59, 1) => Some(("vmulpd".to_string(), Operation::Mul)),
            // VMULSS xmm, xmm, xmm/m32 (EVEX.LIG.F3.0F.W0 59 /r)
            (0x59, 2) => Some(("vmulss".to_string(), Operation::Mul)),
            // VMULSD xmm, xmm, xmm/m64 (EVEX.LIG.F2.0F.W1 59 /r)
            (0x59, 3) => Some(("vmulsd".to_string(), Operation::Mul)),
            // VSUBPS zmm, zmm, zmm/m512 (EVEX.512.0F.W0 5C /r)
            (0x5C, 0) => Some(("vsubps".to_string(), Operation::Sub)),
            // VSUBPD zmm, zmm, zmm/m512 (EVEX.512.66.0F.W1 5C /r)
            (0x5C, 1) => Some(("vsubpd".to_string(), Operation::Sub)),
            // VSUBSS xmm, xmm, xmm/m32 (EVEX.LIG.F3.0F.W0 5C /r)
            (0x5C, 2) => Some(("vsubss".to_string(), Operation::Sub)),
            // VSUBSD xmm, xmm, xmm/m64 (EVEX.LIG.F2.0F.W1 5C /r)
            (0x5C, 3) => Some(("vsubsd".to_string(), Operation::Sub)),
            // VDIVPS zmm, zmm, zmm/m512 (EVEX.512.0F.W0 5E /r)
            (0x5E, 0) => Some(("vdivps".to_string(), Operation::Div)),
            // VDIVPD zmm, zmm, zmm/m512 (EVEX.512.66.0F.W1 5E /r)
            (0x5E, 1) => Some(("vdivpd".to_string(), Operation::Div)),
            // VDIVSS xmm, xmm, xmm/m32 (EVEX.LIG.F3.0F.W0 5E /r)
            (0x5E, 2) => Some(("vdivss".to_string(), Operation::Div)),
            // VDIVSD xmm, xmm, xmm/m64 (EVEX.LIG.F2.0F.W1 5E /r)
            (0x5E, 3) => Some(("vdivsd".to_string(), Operation::Div)),
            // VXORPS zmm, zmm, zmm/m512 (EVEX.512.0F.W0 57 /r)
            (0x57, 0) => Some(("vxorps".to_string(), Operation::Xor)),
            // VXORPD zmm, zmm, zmm/m512 (EVEX.512.66.0F.W1 57 /r)
            (0x57, 1) => Some(("vxorpd".to_string(), Operation::Xor)),
            // VANDPS zmm, zmm, zmm/m512 (EVEX.512.0F.W0 54 /r)
            (0x54, 0) => Some(("vandps".to_string(), Operation::And)),
            // VANDPD zmm, zmm, zmm/m512 (EVEX.512.66.0F.W1 54 /r)
            (0x54, 1) => Some(("vandpd".to_string(), Operation::And)),
            // VORPS zmm, zmm, zmm/m512 (EVEX.512.0F.W0 56 /r)
            (0x56, 0) => Some(("vorps".to_string(), Operation::Or)),
            // VORPD zmm, zmm, zmm/m512 (EVEX.512.66.0F.W1 56 /r)
            (0x56, 1) => Some(("vorpd".to_string(), Operation::Or)),
            // VMOVDQA32/64 zmm, zmm/m512 (EVEX.512.66.0F.W0/W1 6F /r)
            (0x6F, 1) => {
                if evex.w {
                    Some(("vmovdqa64".to_string(), Operation::Move))
                } else {
                    Some(("vmovdqa32".to_string(), Operation::Move))
                }
            }
            // VMOVDQU32/64 zmm, zmm/m512 (EVEX.512.F3.0F.W0/W1 6F /r)
            (0x6F, 2) => {
                if evex.w {
                    Some(("vmovdqu64".to_string(), Operation::Move))
                } else {
                    Some(("vmovdqu32".to_string(), Operation::Move))
                }
            }
            // VMOVDQA32/64 zmm/m512, zmm (EVEX.512.66.0F.W0/W1 7F /r)
            (0x7F, 1) => {
                if evex.w {
                    Some(("vmovdqa64".to_string(), Operation::Store))
                } else {
                    Some(("vmovdqa32".to_string(), Operation::Store))
                }
            }
            // VMOVDQU32/64 zmm/m512, zmm (EVEX.512.F3.0F.W0/W1 7F /r)
            (0x7F, 2) => {
                if evex.w {
                    Some(("vmovdqu64".to_string(), Operation::Store))
                } else {
                    Some(("vmovdqu32".to_string(), Operation::Store))
                }
            }
            _ => None,
        }
    }

    /// Look up EVEX opcode in map 2 (0F38 prefix).
    fn lookup_evex_opcode_0f38(
        &self,
        opcode: u8,
        evex: &super::prefix::Evex,
    ) -> Option<(String, Operation)> {
        match (opcode, evex.pp) {
            // VPBROADCASTD zmm, xmm/m32 (EVEX.512.66.0F38.W0 58 /r)
            (0x58, 1) => Some(("vpbroadcastd".to_string(), Operation::Other(0x58))),
            // VPBROADCASTQ zmm, xmm/m64 (EVEX.512.66.0F38.W1 59 /r)
            (0x59, 1) => Some(("vpbroadcastq".to_string(), Operation::Other(0x59))),
            // VPMOVZXBD zmm, xmm/m128 (EVEX.512.66.0F38.WIG 31 /r)
            (0x31, 1) => Some(("vpmovzxbd".to_string(), Operation::Other(0x31))),
            // VPMOVZXBQ zmm, xmm/m64 (EVEX.512.66.0F38.WIG 32 /r)
            (0x32, 1) => Some(("vpmovzxbq".to_string(), Operation::Other(0x32))),
            // VPMOVZXWD zmm, ymm/m256 (EVEX.512.66.0F38.WIG 33 /r)
            (0x33, 1) => Some(("vpmovzxwd".to_string(), Operation::Other(0x33))),
            // VPMOVZXWQ zmm, xmm/m128 (EVEX.512.66.0F38.WIG 34 /r)
            (0x34, 1) => Some(("vpmovzxwq".to_string(), Operation::Other(0x34))),
            // VPMOVZXDQ zmm, ymm/m256 (EVEX.512.66.0F38.W0 35 /r)
            (0x35, 1) => Some(("vpmovzxdq".to_string(), Operation::Other(0x35))),
            _ => None,
        }
    }

    /// Look up EVEX opcode in map 3 (0F3A prefix).
    fn lookup_evex_opcode_0f3a(
        &self,
        opcode: u8,
        evex: &super::prefix::Evex,
    ) -> Option<(String, Operation)> {
        match (opcode, evex.pp) {
            // VSHUFPS zmm, zmm, zmm/m512, imm8 (EVEX.512.0F3A.W0 C6 /r ib)
            (0xC6, 0) => Some(("vshufps".to_string(), Operation::Other(0xC6))),
            // VSHUFPD zmm, zmm, zmm/m512, imm8 (EVEX.512.66.0F3A.W1 C6 /r ib)
            (0xC6, 1) => Some(("vshufpd".to_string(), Operation::Other(0xC6))),
            // VINSERTF32X4 zmm, zmm, xmm/m128, imm8 (EVEX.512.66.0F3A.W0 18 /r ib)
            (0x18, 1) if !evex.w => Some(("vinsertf32x4".to_string(), Operation::Other(0x18))),
            // VINSERTF64X2 zmm, zmm, xmm/m128, imm8 (EVEX.512.66.0F3A.W1 18 /r ib)
            (0x18, 1) if evex.w => Some(("vinsertf64x2".to_string(), Operation::Other(0x18))),
            // VINSERTF32X8 zmm, zmm, ymm/m256, imm8 (EVEX.512.66.0F3A.W0 1A /r ib)
            (0x1A, 1) if !evex.w => Some(("vinsertf32x8".to_string(), Operation::Other(0x1A))),
            // VINSERTF64X4 zmm, zmm, ymm/m256, imm8 (EVEX.512.66.0F3A.W1 1A /r ib)
            (0x1A, 1) if evex.w => Some(("vinsertf64x4".to_string(), Operation::Other(0x1A))),
            // VEXTRACTF32X4 xmm/m128, zmm, imm8 (EVEX.512.66.0F3A.W0 19 /r ib)
            (0x19, 1) if !evex.w => Some(("vextractf32x4".to_string(), Operation::Other(0x19))),
            // VEXTRACTF64X2 xmm/m128, zmm, imm8 (EVEX.512.66.0F3A.W1 19 /r ib)
            (0x19, 1) if evex.w => Some(("vextractf64x2".to_string(), Operation::Other(0x19))),
            _ => None,
        }
    }

    /// Decode EVEX ModR/M r/m operand, handling extended registers and broadcast.
    fn decode_evex_modrm_rm(
        &self,
        bytes: &[u8],
        modrm: ModRM,
        prefixes: &Prefixes,
        evex: &super::prefix::Evex,
        vector_size: u16,
    ) -> Option<(Operand, usize)> {
        // If it's a register operand, decode as XMM/YMM/ZMM
        if modrm.is_register() {
            // For register-register, rm uses B and X bits
            // rm = modrm.rm[2:0] | B << 3 | X << 4
            let rm_reg = (modrm.rm & 0x0F) | ((evex.x as u8) << 4);
            return Some((Operand::Register(decode_xmm(rm_reg, vector_size)), 0));
        }

        // Memory operand - use standard decoding but potentially with broadcast
        // For now, just use standard memory decoding
        // TODO: Add broadcast indicator to memory operand
        decode_modrm_rm(bytes, modrm, prefixes, vector_size)
    }

    /// Format EVEX mnemonic with opmask and zeroing suffix.
    fn format_evex_mnemonic(&self, base: &str, evex: &super::prefix::Evex) -> String {
        let mut mnemonic = base.to_string();

        // Add opmask suffix if not k0
        if evex.aaa != 0 {
            mnemonic.push_str(&format!(" {{k{}}}", evex.aaa));
        }

        // Add zeroing suffix if enabled
        if evex.z && evex.aaa != 0 {
            mnemonic.push_str("{z}");
        }

        mnemonic
    }

    /// Decode VEX-encoded BMI1/BMI2 instructions (opcodes 0xF2-0xF7 in 0F38 map).
    ///
    /// These instructions use GPR operands (not XMM) and have prefix-dependent behavior:
    ///
    /// BMI1 instructions:
    /// - 0xF2: ANDN r, vvvv, r/m (VEX.NDS.LZ.0F38.W0/W1)
    /// - 0xF3: Group 17 - BLSR/BLSMSK/BLSI vvvv, r/m (VEX.NDD.LZ.0F38.W0/W1)
    /// - 0xF7 (pp=0): BEXTR r, r/m, vvvv (VEX.NDS.LZ.0F38.W0/W1)
    ///
    /// BMI2 instructions:
    /// - 0xF5 (pp=0): BZHI r, r/m, vvvv (VEX.NDS.LZ.0F38.W0/W1)
    /// - 0xF5 (pp=3/F2): PDEP r, vvvv, r/m (VEX.NDS.LZ.F2.0F38.W0/W1)
    /// - 0xF5 (pp=2/F3): PEXT r, vvvv, r/m (VEX.NDS.LZ.F3.0F38.W0/W1)
    /// - 0xF6 (pp=3/F2): MULX r, vvvv, r/m (VEX.NDD.LZ.F2.0F38.W0/W1)
    /// - 0xF7 (pp=1/66): SHLX r, r/m, vvvv (VEX.NDS.LZ.66.0F38.W0/W1)
    /// - 0xF7 (pp=2/F3): SARX r, r/m, vvvv (VEX.NDS.LZ.F3.0F38.W0/W1)
    /// - 0xF7 (pp=3/F2): SHRX r, r/m, vvvv (VEX.NDS.LZ.F2.0F38.W0/W1)
    fn decode_bmi_instruction(
        &self,
        bytes: &[u8],
        address: u64,
        prefixes: &Prefixes,
        mut offset: usize,
        opcode: u8,
    ) -> Result<DecodedInstruction, DecodeError> {
        let vex = prefixes.vex.ok_or_else(|| {
            DecodeError::invalid_encoding(address, "BMI instruction requires VEX prefix")
        })?;

        let remaining = &bytes[offset..];
        if remaining.is_empty() {
            return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
        }

        // Get effective REX from VEX
        let effective_rex = Some(vex.to_rex());

        // Parse ModR/M
        let modrm = ModRM::parse(remaining[0], effective_rex);
        offset += 1;

        // Determine operand size from VEX.W (32 or 64-bit)
        let operand_size: u16 = if vex.w { 64 } else { 32 };

        // Decode based on opcode and VEX.pp
        let (mnemonic, operation, operands) = match opcode {
            // 0xF2: ANDN r, vvvv, r/m
            0xF2 => {
                let rm_bytes = &bytes[offset..];
                let (rm_operand, rm_consumed) =
                    decode_modrm_rm(rm_bytes, modrm, prefixes, operand_size)
                        .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
                offset += rm_consumed;

                // ANDN: dest=reg, src1=vvvv (to be inverted), src2=r/m
                let operands = vec![
                    decode_modrm_reg(modrm, operand_size),
                    Operand::Register(decode_gpr(vex.vvvv, operand_size)),
                    rm_operand,
                ];
                ("andn", Operation::AndNot, operands)
            }

            // 0xF3: Group 17 - BLSR/BLSMSK/BLSI vvvv, r/m
            0xF3 => {
                let rm_bytes = &bytes[offset..];
                let (rm_operand, rm_consumed) =
                    decode_modrm_rm(rm_bytes, modrm, prefixes, operand_size)
                        .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
                offset += rm_consumed;

                // Instruction is determined by ModR/M.reg field
                let (mnemonic, operation) = super::opcodes_0f38::bmi1_group_info(modrm.reg & 0x7);

                // VEX.vvvv is the destination, r/m is the source
                let operands = vec![
                    Operand::Register(decode_gpr(vex.vvvv, operand_size)),
                    rm_operand,
                ];
                (mnemonic, operation, operands)
            }

            // 0xF5: BZHI/PDEP/PEXT (prefix-dependent)
            0xF5 => {
                let rm_bytes = &bytes[offset..];
                let (rm_operand, rm_consumed) =
                    decode_modrm_rm(rm_bytes, modrm, prefixes, operand_size)
                        .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
                offset += rm_consumed;

                let (mnemonic, operation) = super::opcodes_0f38::f5_info(vex.pp);

                // Operand order depends on instruction:
                // BZHI: r, r/m, vvvv (dest=reg, src=r/m, index=vvvv)
                // PDEP/PEXT: r, vvvv, r/m (dest=reg, src1=vvvv, mask=r/m)
                let operands = if vex.pp == 0 {
                    // BZHI: dest, src, index
                    vec![
                        decode_modrm_reg(modrm, operand_size),
                        rm_operand,
                        Operand::Register(decode_gpr(vex.vvvv, operand_size)),
                    ]
                } else {
                    // PDEP/PEXT: dest, src1, mask
                    vec![
                        decode_modrm_reg(modrm, operand_size),
                        Operand::Register(decode_gpr(vex.vvvv, operand_size)),
                        rm_operand,
                    ]
                };
                (mnemonic, operation, operands)
            }

            // 0xF6: MULX r, vvvv, r/m (requires F2 prefix, pp=3)
            0xF6 => {
                if vex.pp != 3 {
                    return Err(DecodeError::invalid_encoding(
                        address,
                        "MULX requires F2 prefix (VEX.pp=3)",
                    ));
                }

                let rm_bytes = &bytes[offset..];
                let (rm_operand, rm_consumed) =
                    decode_modrm_rm(rm_bytes, modrm, prefixes, operand_size)
                        .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
                offset += rm_consumed;

                // MULX: dest1=reg, dest2=vvvv, src=r/m
                // Note: This is a 3-operand form where reg and vvvv are both destinations
                // The implicit source is EDX/RDX
                let operands = vec![
                    decode_modrm_reg(modrm, operand_size),
                    Operand::Register(decode_gpr(vex.vvvv, operand_size)),
                    rm_operand,
                ];
                ("mulx", Operation::MulNoFlags, operands)
            }

            // 0xF7: BEXTR/SHLX/SARX/SHRX (prefix-dependent)
            0xF7 => {
                let rm_bytes = &bytes[offset..];
                let (rm_operand, rm_consumed) =
                    decode_modrm_rm(rm_bytes, modrm, prefixes, operand_size)
                        .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
                offset += rm_consumed;

                let (mnemonic, operation) = super::opcodes_0f38::f7_info(vex.pp);

                // All F7 variants: dest=reg, src=r/m, control=vvvv
                let operands = vec![
                    decode_modrm_reg(modrm, operand_size),
                    rm_operand,
                    Operand::Register(decode_gpr(vex.vvvv, operand_size)),
                ];
                (mnemonic, operation, operands)
            }

            _ => {
                return Err(DecodeError::unknown_opcode(address, &bytes[..offset]));
            }
        };

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

    /// Decode 0F 01 group instructions (SGDT, SIDT, LGDT, LIDT, SMSW, LMSW, INVLPG, RDTSCP).
    ///
    /// These instructions use the ModRM.reg field (and sometimes ModRM.rm for register forms)
    /// to determine the specific operation:
    /// - /0: SGDT m - Store Global Descriptor Table
    /// - /1: SIDT m - Store Interrupt Descriptor Table
    /// - /2: LGDT m - Load Global Descriptor Table
    /// - /3: LIDT m - Load Interrupt Descriptor Table
    /// - /4: SMSW r/m16 - Store Machine Status Word
    /// - /6: LMSW r/m16 - Load Machine Status Word
    /// - /7: INVLPG m - Invalidate TLB Entry
    ///
    /// Special register-form encodings (mod=11):
    /// - 0F 01 F9: RDTSCP - Read Time Stamp Counter and Processor ID
    fn decode_0f01_group(
        &self,
        bytes: &[u8],
        address: u64,
        prefixes: &Prefixes,
        mut offset: usize,
    ) -> Result<DecodedInstruction, DecodeError> {
        let remaining = &bytes[offset..];
        if remaining.is_empty() {
            return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
        }

        let modrm_byte = remaining[0];
        let modrm = ModRM::parse(modrm_byte, prefixes.rex);
        offset += 1;

        // Check for special register-form encodings first
        // RDTSCP: 0F 01 F9 (mod=11, reg=7, rm=1 => modrm_byte = 0xF9)
        if modrm_byte == 0xF9 {
            let instruction = Instruction {
                address,
                size: offset,
                bytes: bytes[..offset].to_vec(),
                operation: Operation::ReadTscP,
                mnemonic: "rdtscp".to_string(),
                operands: vec![],
                control_flow: ControlFlow::Sequential,
                reads: vec![],
                writes: vec![],
            };
            return Ok(DecodedInstruction {
                instruction,
                size: offset,
            });
        }

        // Determine instruction from reg field
        let reg = modrm.reg & 0x7;

        let (mnemonic, operation, needs_memory_operand) = match reg {
            0 => ("sgdt", Operation::StoreGdt, true),  // /0: SGDT m
            1 => ("sidt", Operation::StoreIdt, true),  // /1: SIDT m
            2 => ("lgdt", Operation::LoadGdt, true),   // /2: LGDT m
            3 => ("lidt", Operation::LoadIdt, true),   // /3: LIDT m
            4 => ("smsw", Operation::StoreMsw, false), // /4: SMSW r/m16 (both reg and mem)
            5 => {
                // /5 is reserved in most contexts, but can be other instructions
                return Err(DecodeError::invalid_encoding(
                    address,
                    "reserved 0F 01 /5 encoding",
                ));
            }
            6 => ("lmsw", Operation::LoadMsw, false), // /6: LMSW r/m16 (both reg and mem)
            7 => ("invlpg", Operation::InvalidateTlb, true), // /7: INVLPG m (memory only)
            _ => unreachable!(),
        };

        // For SGDT, SIDT, LGDT, LIDT, INVLPG - must be memory operand
        if needs_memory_operand && modrm.is_register() {
            // Register form for these is invalid (except special cases handled above)
            return Err(DecodeError::invalid_encoding(
                address,
                format!("{} requires memory operand", mnemonic),
            ));
        }

        // Decode operand
        let operands = if modrm.is_register() {
            // SMSW/LMSW can use register
            let operand_size = 16; // These instructions use 16-bit operand
            vec![Operand::Register(decode_gpr(modrm.rm, operand_size))]
        } else {
            // Memory operand
            let rm_bytes = &bytes[offset..];
            // SGDT/SIDT/LGDT/LIDT use 10-byte memory (48-bit limit + 64-bit base in 64-bit mode)
            // SMSW/LMSW use 16-bit memory
            // INVLPG uses byte granularity
            let operand_size = match reg {
                0..=3 => 80, // 10 bytes for descriptor table pointers
                4 | 6 => 16, // 16 bits for machine status word
                7 => 8,      // INVLPG technically doesn't have a size, use byte
                _ => 16,
            };
            let (rm_operand, rm_consumed) =
                decode_modrm_rm(rm_bytes, modrm, prefixes, operand_size)
                    .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
            offset += rm_consumed;
            vec![rm_operand]
        };

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

    /// Decode AMX (Advanced Matrix Extensions) instructions.
    ///
    /// AMX instructions use VEX encoding in the 0F38 map and operate on tile registers (tmm0-tmm7).
    ///
    /// Tile configuration:
    /// - LDTILECFG: VEX.128.NP.0F38.W0 49 /0 - Load tile configuration
    /// - STTILECFG: VEX.128.66.0F38.W0 49 /0 - Store tile configuration
    /// - TILERELEASE: VEX.128.NP.0F38.W0 49 C0 - Release tile resources
    ///
    /// Tile loads/stores:
    /// - TILELOADD: VEX.128.F2.0F38.W0 4B - Load tile (row data)
    /// - TILELOADDT1: VEX.128.66.0F38.W0 4B - Load tile (temporal hint)
    /// - TILESTORED: VEX.128.F3.0F38.W0 4B - Store tile
    ///
    /// Tile computation:
    /// - TDPBSSD: VEX.128.F2.0F38.W0 5E - Dot product of signed bytes
    /// - TDPBSUD: VEX.128.F3.0F38.W0 5E - Dot product of signed/unsigned bytes
    /// - TDPBUSD: VEX.128.66.0F38.W0 5E - Dot product of unsigned/signed bytes
    /// - TDPBUUD: VEX.128.NP.0F38.W0 5E - Dot product of unsigned bytes
    /// - TDPFP16PS: VEX.128.F2.0F38.W0 5C - FP16 matrix multiply
    /// - TILEZERO: VEX.128.F2.0F38.W0 49 - Zero tile
    fn decode_amx_instruction(
        &self,
        bytes: &[u8],
        address: u64,
        prefixes: &Prefixes,
        mut offset: usize,
        opcode: u8,
    ) -> Result<DecodedInstruction, DecodeError> {
        let vex = prefixes.vex.ok_or_else(|| {
            DecodeError::invalid_encoding(address, "AMX instruction requires VEX prefix")
        })?;

        let remaining = &bytes[offset..];
        if remaining.is_empty() {
            return Err(DecodeError::truncated(address, offset + 1, bytes.len()));
        }

        let modrm_byte = remaining[0];
        let effective_rex = Some(vex.to_rex());
        let modrm = ModRM::parse(modrm_byte, effective_rex);
        offset += 1;

        match opcode {
            // 0x49: LDTILECFG / STTILECFG / TILERELEASE / TILEZERO
            0x49 => {
                let (mnemonic, operation) = super::opcodes_0f38::amx_49_info(vex.pp, modrm_byte)
                    .ok_or_else(|| {
                        DecodeError::invalid_encoding(address, "invalid AMX 0x49 encoding")
                    })?;

                let operands = match operation {
                    // TILERELEASE has no operands
                    Operation::AmxTileRelease => vec![],
                    // TILEZERO has one tmm register operand (from modrm.reg)
                    Operation::AmxTileZero => {
                        vec![Operand::Register(decode_tmm(modrm.reg & 0x7))]
                    }
                    // LDTILECFG/STTILECFG have one memory operand
                    _ => {
                        let rm_bytes = &bytes[offset..];
                        let (rm_operand, rm_consumed) =
                            decode_modrm_rm(rm_bytes, modrm, prefixes, 512).ok_or_else(|| {
                                DecodeError::truncated(address, offset + 1, bytes.len())
                            })?;
                        offset += rm_consumed;
                        vec![rm_operand]
                    }
                };

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

            // 0x4B: TILELOADD / TILELOADDT1 / TILESTORED
            0x4B => {
                let (mnemonic, operation) =
                    super::opcodes_0f38::amx_4b_info(vex.pp).ok_or_else(|| {
                        DecodeError::invalid_encoding(address, "invalid AMX 0x4B encoding")
                    })?;

                // These instructions use SIB addressing for the memory operand
                let rm_bytes = &bytes[offset..];
                let (rm_operand, rm_consumed) = decode_modrm_rm(rm_bytes, modrm, prefixes, 0)
                    .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
                offset += rm_consumed;

                let operands = if operation == Operation::AmxTileStore {
                    // TILESTORED: sibmem, tmm
                    vec![rm_operand, Operand::Register(decode_tmm(modrm.reg & 0x7))]
                } else {
                    // TILELOADD/TILELOADDT1: tmm, sibmem
                    vec![Operand::Register(decode_tmm(modrm.reg & 0x7)), rm_operand]
                };

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

            // 0x5C: TDPFP16PS (FP16 matrix multiply)
            0x5C => {
                let (mnemonic, operation) =
                    super::opcodes_0f38::amx_5c_info(vex.pp).ok_or_else(|| {
                        DecodeError::invalid_encoding(address, "invalid AMX 0x5C encoding")
                    })?;

                // TDPFP16PS tmm1, tmm2, tmm3
                // tmm1 = dest (modrm.reg), tmm2 = vvvv, tmm3 = modrm.rm
                let operands = vec![
                    Operand::Register(decode_tmm(modrm.reg & 0x7)),
                    Operand::Register(decode_tmm(vex.vvvv & 0x7)),
                    Operand::Register(decode_tmm(modrm.rm & 0x7)),
                ];

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

            // 0x5E: TDPBSSD / TDPBSUD / TDPBUSD / TDPBUUD (tile dot product)
            0x5E => {
                let (mnemonic, operation) =
                    super::opcodes_0f38::amx_5e_info(vex.pp).ok_or_else(|| {
                        DecodeError::invalid_encoding(address, "invalid AMX 0x5E encoding")
                    })?;

                // TDP* tmm1, tmm2, tmm3
                // tmm1 = dest/src (modrm.reg), tmm2 = src (vvvv), tmm3 = src (modrm.rm)
                let operands = vec![
                    Operand::Register(decode_tmm(modrm.reg & 0x7)),
                    Operand::Register(decode_tmm(vex.vvvv & 0x7)),
                    Operand::Register(decode_tmm(modrm.rm & 0x7)),
                ];

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

            _ => Err(DecodeError::unknown_opcode(address, &bytes[..offset])),
        }
    }

    /// Decode CET (Control-flow Enforcement Technology) instructions.
    ///
    /// Shadow Stack instructions:
    /// - INCSSPD/INCSSPQ: F3 0F AE /5 - Increment shadow stack pointer
    /// - RDSSPD/RDSSPQ: F3 0F 1E /1 - Read shadow stack pointer
    /// - SAVEPREVSSP: F3 0F 01 EA - Save previous shadow stack pointer
    /// - RSTORSSP: F3 0F 01 /5 - Restore shadow stack pointer
    /// - WRSSD/WRSSQ: 0F 38 F6 - Write to shadow stack
    /// - WRUSSD/WRUSSQ: 66 0F 38 F5 - Write to user shadow stack
    ///
    /// Indirect Branch Tracking:
    /// - ENDBR32: F3 0F 1E FB - End branch 32-bit
    /// - ENDBR64: F3 0F 1E FA - End branch 64-bit
    fn decode_cet_instruction(
        &self,
        bytes: &[u8],
        address: u64,
        prefixes: &Prefixes,
        offset: usize,
        opcode: u8,
        modrm_byte: u8,
    ) -> Result<DecodedInstruction, DecodeError> {
        let effective_rex = prefixes.rex;
        let modrm = ModRM::parse(modrm_byte, effective_rex);
        let is_64bit = prefixes.rex.map(|r| r.w).unwrap_or(false);

        match opcode {
            // F3 0F 1E: RDSSPD/RDSSPQ (/1) or ENDBR32/ENDBR64 (FB/FA)
            0x1E => {
                match modrm_byte {
                    // ENDBR64: F3 0F 1E FA
                    0xFA => {
                        let instruction = Instruction {
                            address,
                            size: offset,
                            bytes: bytes[..offset].to_vec(),
                            operation: Operation::CetEndBranch64,
                            mnemonic: "endbr64".to_string(),
                            operands: vec![],
                            control_flow: ControlFlow::Sequential,
                            reads: vec![],
                            writes: vec![],
                        };
                        Ok(DecodedInstruction {
                            instruction,
                            size: offset,
                        })
                    }
                    // ENDBR32: F3 0F 1E FB
                    0xFB => {
                        let instruction = Instruction {
                            address,
                            size: offset,
                            bytes: bytes[..offset].to_vec(),
                            operation: Operation::CetEndBranch32,
                            mnemonic: "endbr32".to_string(),
                            operands: vec![],
                            control_flow: ControlFlow::Sequential,
                            reads: vec![],
                            writes: vec![],
                        };
                        Ok(DecodedInstruction {
                            instruction,
                            size: offset,
                        })
                    }
                    // RDSSPD/RDSSPQ: F3 0F 1E /1 (mod=11, reg=1)
                    _ if modrm.is_register() && (modrm.reg & 0x7) == 1 => {
                        let operand_size = if is_64bit { 64 } else { 32 };
                        let mnemonic = if is_64bit { "rdsspq" } else { "rdsspd" };
                        let instruction = Instruction {
                            address,
                            size: offset,
                            bytes: bytes[..offset].to_vec(),
                            operation: Operation::CetReadSsp,
                            mnemonic: mnemonic.to_string(),
                            operands: vec![Operand::Register(decode_gpr(modrm.rm, operand_size))],
                            control_flow: ControlFlow::Sequential,
                            reads: vec![],
                            writes: vec![],
                        };
                        Ok(DecodedInstruction {
                            instruction,
                            size: offset,
                        })
                    }
                    // Other F3 0F 1E encodings - treat as NOP (like the original code)
                    _ => {
                        let instruction = Instruction {
                            address,
                            size: offset,
                            bytes: bytes[..offset].to_vec(),
                            operation: Operation::Nop,
                            mnemonic: "nop".to_string(),
                            operands: vec![],
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
            }

            // F3 0F AE /5: INCSSPD/INCSSPQ
            0xAE if (modrm.reg & 0x7) == 5 && modrm.is_register() => {
                let operand_size = if is_64bit { 64 } else { 32 };
                let mnemonic = if is_64bit { "incsspq" } else { "incsspd" };
                let instruction = Instruction {
                    address,
                    size: offset,
                    bytes: bytes[..offset].to_vec(),
                    operation: Operation::CetIncSsp,
                    mnemonic: mnemonic.to_string(),
                    operands: vec![Operand::Register(decode_gpr(modrm.rm, operand_size))],
                    control_flow: ControlFlow::Sequential,
                    reads: vec![],
                    writes: vec![],
                };
                Ok(DecodedInstruction {
                    instruction,
                    size: offset,
                })
            }

            _ => Err(DecodeError::invalid_encoding(
                address,
                "unrecognized CET instruction",
            )),
        }
    }

    /// Decode CET 0F 01 group instructions (SAVEPREVSSP, RSTORSSP).
    fn decode_cet_0f01(
        &self,
        bytes: &[u8],
        address: u64,
        prefixes: &Prefixes,
        mut offset: usize,
        modrm_byte: u8,
    ) -> Result<DecodedInstruction, DecodeError> {
        let modrm = ModRM::parse(modrm_byte, prefixes.rex);

        match modrm_byte {
            // SAVEPREVSSP: F3 0F 01 EA
            0xEA if prefixes.rep => {
                let instruction = Instruction {
                    address,
                    size: offset,
                    bytes: bytes[..offset].to_vec(),
                    operation: Operation::CetSavePrevSsp,
                    mnemonic: "saveprevssp".to_string(),
                    operands: vec![],
                    control_flow: ControlFlow::Sequential,
                    reads: vec![],
                    writes: vec![],
                };
                Ok(DecodedInstruction {
                    instruction,
                    size: offset,
                })
            }
            // RSTORSSP: F3 0F 01 /5 (memory operand)
            _ if prefixes.rep && (modrm.reg & 0x7) == 5 && !modrm.is_register() => {
                let rm_bytes = &bytes[offset..];
                let (rm_operand, rm_consumed) = decode_modrm_rm(rm_bytes, modrm, prefixes, 64)
                    .ok_or_else(|| DecodeError::truncated(address, offset + 1, bytes.len()))?;
                offset += rm_consumed;

                let instruction = Instruction {
                    address,
                    size: offset,
                    bytes: bytes[..offset].to_vec(),
                    operation: Operation::CetRestoreSsp,
                    mnemonic: "rstorssp".to_string(),
                    operands: vec![rm_operand],
                    control_flow: ControlFlow::Sequential,
                    reads: vec![],
                    writes: vec![],
                };
                Ok(DecodedInstruction {
                    instruction,
                    size: offset,
                })
            }
            _ => Err(DecodeError::invalid_encoding(
                address,
                "not a CET 0F 01 instruction",
            )),
        }
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
        let result = disasm
            .decode_instruction(&[0x48, 0x89, 0xe5], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "mov");
        assert_eq!(result.size, 3);
    }

    #[test]
    fn test_ret() {
        let disasm = X86_64Disassembler::new();
        let result = disasm.decode_instruction(&[0xc3], 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ret");
        assert!(matches!(
            result.instruction.control_flow,
            ControlFlow::Return
        ));
    }

    #[test]
    fn test_call_rel32() {
        let disasm = X86_64Disassembler::new();
        // call +0x100
        let result = disasm
            .decode_instruction(&[0xe8, 0x00, 0x01, 0x00, 0x00], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "call");
        assert!(matches!(
            result.instruction.control_flow,
            ControlFlow::Call { target: 0x1105, .. }
        ));
    }

    #[test]
    fn test_jne_rel8() {
        let disasm = X86_64Disassembler::new();
        // jne +0x10
        let result = disasm.decode_instruction(&[0x75, 0x10], 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "jne");
        assert!(matches!(
            result.instruction.control_flow,
            ControlFlow::ConditionalBranch {
                target: 0x1012,
                condition: Condition::NotEqual,
                ..
            }
        ));
    }

    #[test]
    fn test_add_rax_imm() {
        let disasm = X86_64Disassembler::new();
        // add eax, 0x42
        let result = disasm
            .decode_instruction(&[0x05, 0x42, 0x00, 0x00, 0x00], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "add");
        assert_eq!(result.instruction.operands.len(), 2);
    }

    #[test]
    fn test_syscall() {
        let disasm = X86_64Disassembler::new();
        let result = disasm.decode_instruction(&[0x0f, 0x05], 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "syscall");
        assert!(matches!(
            result.instruction.control_flow,
            ControlFlow::Syscall
        ));
    }

    #[test]
    fn test_endbr64() {
        let disasm = X86_64Disassembler::new();
        // F3 0F 1E FA = ENDBR64
        let result = disasm
            .decode_instruction(&[0xf3, 0x0f, 0x1e, 0xfa], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "endbr64");
        assert_eq!(result.instruction.operation, Operation::CetEndBranch64);
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_endbr32() {
        let disasm = X86_64Disassembler::new();
        // F3 0F 1E FB = ENDBR32
        let result = disasm
            .decode_instruction(&[0xf3, 0x0f, 0x1e, 0xfb], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "endbr32");
        assert_eq!(result.instruction.operation, Operation::CetEndBranch32);
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_indirect_call_rip() {
        let disasm = X86_64Disassembler::new();
        // FF 15 xx xx xx xx = CALL [rip+disp32]
        let result = disasm
            .decode_instruction(&[0xff, 0x15, 0x10, 0x00, 0x00, 0x00], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "call");
        assert!(matches!(
            result.instruction.control_flow,
            ControlFlow::IndirectCall { .. }
        ));
    }

    #[test]
    fn test_indirect_jmp_reg() {
        let disasm = X86_64Disassembler::new();
        // FF E0 = JMP rax
        let result = disasm.decode_instruction(&[0xff, 0xe0], 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "jmp");
        assert!(matches!(
            result.instruction.control_flow,
            ControlFlow::IndirectBranch { .. }
        ));
    }

    #[test]
    fn test_movaps_xmm_xmm() {
        let disasm = X86_64Disassembler::new();
        // 0F 28 C1 = movaps xmm0, xmm1
        let result = disasm
            .decode_instruction(&[0x0f, 0x28, 0xc1], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "movaps");
        assert_eq!(result.size, 3);
        assert_eq!(result.instruction.operands.len(), 2);
    }

    #[test]
    fn test_xorps_xmm_xmm() {
        let disasm = X86_64Disassembler::new();
        // 0F 57 C0 = xorps xmm0, xmm0
        let result = disasm
            .decode_instruction(&[0x0f, 0x57, 0xc0], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "xorps");
        assert_eq!(result.size, 3);
    }

    #[test]
    fn test_addps_xmm_xmm() {
        let disasm = X86_64Disassembler::new();
        // 0F 58 C1 = addps xmm0, xmm1
        let result = disasm
            .decode_instruction(&[0x0f, 0x58, 0xc1], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "addps");
        assert_eq!(result.size, 3);
    }

    #[test]
    fn test_movsd_xmm_mem() {
        let disasm = X86_64Disassembler::new();
        // F2 0F 10 04 25 00 10 00 00 = movsd xmm0, [0x1000]
        let result = disasm
            .decode_instruction(
                &[0xf2, 0x0f, 0x10, 0x04, 0x25, 0x00, 0x10, 0x00, 0x00],
                0x1000,
            )
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "movsd");
    }

    #[test]
    fn test_movss_xmm_mem() {
        let disasm = X86_64Disassembler::new();
        // F3 0F 10 00 = movss xmm0, [rax]
        let result = disasm
            .decode_instruction(&[0xf3, 0x0f, 0x10, 0x00], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "movss");
    }

    #[test]
    fn test_addpd_xmm_xmm() {
        let disasm = X86_64Disassembler::new();
        // 66 0F 58 C1 = addpd xmm0, xmm1
        let result = disasm
            .decode_instruction(&[0x66, 0x0f, 0x58, 0xc1], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "addpd");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_vex_vmovaps_ymm() {
        let disasm = X86_64Disassembler::new();
        // C5 FC 28 C1 = vmovaps ymm0, ymm1 (VEX.256.0F.WIG 28 /r)
        let result = disasm
            .decode_instruction(&[0xc5, 0xfc, 0x28, 0xc1], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "vmovaps");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_vex_vxorps_ymm() {
        let disasm = X86_64Disassembler::new();
        // C5 FC 57 C0 = vxorps ymm0, ymm0, ymm0
        let result = disasm
            .decode_instruction(&[0xc5, 0xfc, 0x57, 0xc0], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "vxorps");
        assert_eq!(result.size, 4);
        // Should have 3 operands for VEX encoding
        assert_eq!(result.instruction.operands.len(), 3);
    }

    #[test]
    fn test_vex_vaddps_xmm() {
        let disasm = X86_64Disassembler::new();
        // C5 F0 58 C2 = vaddps xmm0, xmm1, xmm2
        let result = disasm
            .decode_instruction(&[0xc5, 0xf0, 0x58, 0xc2], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "vaddps");
        assert_eq!(result.size, 4);
        assert_eq!(result.instruction.operands.len(), 3);
    }

    // ==========================================================================
    // System instruction tests
    // ==========================================================================

    #[test]
    fn test_rdmsr() {
        let disasm = X86_64Disassembler::new();
        // 0F 32 = RDMSR
        let result = disasm.decode_instruction(&[0x0f, 0x32], 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "rdmsr");
        assert_eq!(result.instruction.operation, Operation::ReadMsr);
        assert_eq!(result.size, 2);
        assert!(result.instruction.operands.is_empty());
    }

    #[test]
    fn test_wrmsr() {
        let disasm = X86_64Disassembler::new();
        // 0F 30 = WRMSR
        let result = disasm.decode_instruction(&[0x0f, 0x30], 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "wrmsr");
        assert_eq!(result.instruction.operation, Operation::WriteMsr);
        assert_eq!(result.size, 2);
        assert!(result.instruction.operands.is_empty());
    }

    #[test]
    fn test_cpuid() {
        let disasm = X86_64Disassembler::new();
        // 0F A2 = CPUID
        let result = disasm.decode_instruction(&[0x0f, 0xa2], 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "cpuid");
        assert_eq!(result.instruction.operation, Operation::CpuId);
        assert_eq!(result.size, 2);
        assert!(result.instruction.operands.is_empty());
    }

    #[test]
    fn test_rdtsc() {
        let disasm = X86_64Disassembler::new();
        // 0F 31 = RDTSC
        let result = disasm.decode_instruction(&[0x0f, 0x31], 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "rdtsc");
        assert_eq!(result.instruction.operation, Operation::ReadTsc);
        assert_eq!(result.size, 2);
        assert!(result.instruction.operands.is_empty());
    }

    #[test]
    fn test_rdtscp() {
        let disasm = X86_64Disassembler::new();
        // 0F 01 F9 = RDTSCP
        let result = disasm
            .decode_instruction(&[0x0f, 0x01, 0xf9], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "rdtscp");
        assert_eq!(result.instruction.operation, Operation::ReadTscP);
        assert_eq!(result.size, 3);
        assert!(result.instruction.operands.is_empty());
    }

    #[test]
    fn test_sgdt_mem() {
        let disasm = X86_64Disassembler::new();
        // 0F 01 00 = SGDT [rax]
        let result = disasm
            .decode_instruction(&[0x0f, 0x01, 0x00], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "sgdt");
        assert_eq!(result.instruction.operation, Operation::StoreGdt);
        assert_eq!(result.size, 3);
        assert_eq!(result.instruction.operands.len(), 1);
    }

    #[test]
    fn test_sidt_mem() {
        let disasm = X86_64Disassembler::new();
        // 0F 01 08 = SIDT [rax]
        let result = disasm
            .decode_instruction(&[0x0f, 0x01, 0x08], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "sidt");
        assert_eq!(result.instruction.operation, Operation::StoreIdt);
        assert_eq!(result.size, 3);
        assert_eq!(result.instruction.operands.len(), 1);
    }

    #[test]
    fn test_lgdt_mem() {
        let disasm = X86_64Disassembler::new();
        // 0F 01 10 = LGDT [rax]
        let result = disasm
            .decode_instruction(&[0x0f, 0x01, 0x10], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "lgdt");
        assert_eq!(result.instruction.operation, Operation::LoadGdt);
        assert_eq!(result.size, 3);
        assert_eq!(result.instruction.operands.len(), 1);
    }

    #[test]
    fn test_lidt_mem() {
        let disasm = X86_64Disassembler::new();
        // 0F 01 18 = LIDT [rax]
        let result = disasm
            .decode_instruction(&[0x0f, 0x01, 0x18], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "lidt");
        assert_eq!(result.instruction.operation, Operation::LoadIdt);
        assert_eq!(result.size, 3);
        assert_eq!(result.instruction.operands.len(), 1);
    }

    #[test]
    fn test_smsw_reg() {
        let disasm = X86_64Disassembler::new();
        // 0F 01 E0 = SMSW eax (mod=11, reg=4, rm=0)
        let result = disasm
            .decode_instruction(&[0x0f, 0x01, 0xe0], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "smsw");
        assert_eq!(result.instruction.operation, Operation::StoreMsw);
        assert_eq!(result.size, 3);
        assert_eq!(result.instruction.operands.len(), 1);
    }

    #[test]
    fn test_smsw_mem() {
        let disasm = X86_64Disassembler::new();
        // 0F 01 20 = SMSW [rax]
        let result = disasm
            .decode_instruction(&[0x0f, 0x01, 0x20], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "smsw");
        assert_eq!(result.instruction.operation, Operation::StoreMsw);
        assert_eq!(result.size, 3);
        assert_eq!(result.instruction.operands.len(), 1);
    }

    #[test]
    fn test_lmsw_reg() {
        let disasm = X86_64Disassembler::new();
        // 0F 01 F0 = LMSW eax (mod=11, reg=6, rm=0)
        let result = disasm
            .decode_instruction(&[0x0f, 0x01, 0xf0], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "lmsw");
        assert_eq!(result.instruction.operation, Operation::LoadMsw);
        assert_eq!(result.size, 3);
        assert_eq!(result.instruction.operands.len(), 1);
    }

    #[test]
    fn test_lmsw_mem() {
        let disasm = X86_64Disassembler::new();
        // 0F 01 30 = LMSW [rax]
        let result = disasm
            .decode_instruction(&[0x0f, 0x01, 0x30], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "lmsw");
        assert_eq!(result.instruction.operation, Operation::LoadMsw);
        assert_eq!(result.size, 3);
        assert_eq!(result.instruction.operands.len(), 1);
    }

    #[test]
    fn test_invlpg_mem() {
        let disasm = X86_64Disassembler::new();
        // 0F 01 38 = INVLPG [rax]
        let result = disasm
            .decode_instruction(&[0x0f, 0x01, 0x38], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "invlpg");
        assert_eq!(result.instruction.operation, Operation::InvalidateTlb);
        assert_eq!(result.size, 3);
        assert_eq!(result.instruction.operands.len(), 1);
    }

    #[test]
    fn test_invlpg_with_displacement() {
        let disasm = X86_64Disassembler::new();
        // 0F 01 78 10 = INVLPG [rax+0x10]
        let result = disasm
            .decode_instruction(&[0x0f, 0x01, 0x78, 0x10], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "invlpg");
        assert_eq!(result.instruction.operation, Operation::InvalidateTlb);
        assert_eq!(result.size, 4);
        assert_eq!(result.instruction.operands.len(), 1);
    }

    // ==========================================================================
    // Bit manipulation instruction tests (POPCNT, LZCNT, TZCNT)
    // ==========================================================================

    #[test]
    fn test_popcnt_r32_r32() {
        let disasm = X86_64Disassembler::new();
        // F3 0F B8 C1 = popcnt eax, ecx
        let result = disasm
            .decode_instruction(&[0xf3, 0x0f, 0xb8, 0xc1], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "popcnt");
        assert_eq!(result.size, 4);
        assert_eq!(result.instruction.operands.len(), 2);
        assert_eq!(result.instruction.operation, Operation::Popcnt);
    }

    #[test]
    fn test_popcnt_r64_r64() {
        let disasm = X86_64Disassembler::new();
        // F3 48 0F B8 C1 = popcnt rax, rcx
        let result = disasm
            .decode_instruction(&[0xf3, 0x48, 0x0f, 0xb8, 0xc1], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "popcnt");
        assert_eq!(result.size, 5);
        assert_eq!(result.instruction.operands.len(), 2);
        assert_eq!(result.instruction.operation, Operation::Popcnt);
    }

    #[test]
    fn test_lzcnt_r32_r32() {
        let disasm = X86_64Disassembler::new();
        // F3 0F BD C1 = lzcnt eax, ecx
        let result = disasm
            .decode_instruction(&[0xf3, 0x0f, 0xbd, 0xc1], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "lzcnt");
        assert_eq!(result.size, 4);
        assert_eq!(result.instruction.operands.len(), 2);
        assert_eq!(result.instruction.operation, Operation::Lzcnt);
    }

    #[test]
    fn test_lzcnt_r64_r64() {
        let disasm = X86_64Disassembler::new();
        // F3 48 0F BD C1 = lzcnt rax, rcx
        let result = disasm
            .decode_instruction(&[0xf3, 0x48, 0x0f, 0xbd, 0xc1], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "lzcnt");
        assert_eq!(result.size, 5);
        assert_eq!(result.instruction.operands.len(), 2);
        assert_eq!(result.instruction.operation, Operation::Lzcnt);
    }

    #[test]
    fn test_tzcnt_r32_r32() {
        let disasm = X86_64Disassembler::new();
        // F3 0F BC C1 = tzcnt eax, ecx
        let result = disasm
            .decode_instruction(&[0xf3, 0x0f, 0xbc, 0xc1], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "tzcnt");
        assert_eq!(result.size, 4);
        assert_eq!(result.instruction.operands.len(), 2);
        assert_eq!(result.instruction.operation, Operation::Tzcnt);
    }

    #[test]
    fn test_tzcnt_r64_r64() {
        let disasm = X86_64Disassembler::new();
        // F3 48 0F BC C1 = tzcnt rax, rcx
        let result = disasm
            .decode_instruction(&[0xf3, 0x48, 0x0f, 0xbc, 0xc1], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "tzcnt");
        assert_eq!(result.size, 5);
        assert_eq!(result.instruction.operands.len(), 2);
        assert_eq!(result.instruction.operation, Operation::Tzcnt);
    }

    #[test]
    fn test_popcnt_r32_mem() {
        let disasm = X86_64Disassembler::new();
        // F3 0F B8 00 = popcnt eax, [rax]
        let result = disasm
            .decode_instruction(&[0xf3, 0x0f, 0xb8, 0x00], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "popcnt");
        assert_eq!(result.size, 4);
        assert_eq!(result.instruction.operands.len(), 2);
        assert_eq!(result.instruction.operation, Operation::Popcnt);
    }

    // ========================================================================
    // VEX 0F38 (mmmmm=2) tests
    // ========================================================================

    #[test]
    fn test_vex_0f38_vpshufb() {
        let disasm = X86_64Disassembler::new();
        // C4 E2 71 00 C2 = vpshufb xmm0, xmm1, xmm2 (VEX.NDS.128.66.0F38.WIG 00 /r)
        let result = disasm
            .decode_instruction(&[0xc4, 0xe2, 0x71, 0x00, 0xc2], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "vpshufb");
        assert_eq!(result.size, 5);
        assert_eq!(result.instruction.operands.len(), 3);
    }

    #[test]
    fn test_vex_0f38_vphaddw() {
        let disasm = X86_64Disassembler::new();
        // C4 E2 71 01 C2 = vphaddw xmm0, xmm1, xmm2
        let result = disasm
            .decode_instruction(&[0xc4, 0xe2, 0x71, 0x01, 0xc2], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "vphaddw");
        assert_eq!(result.size, 5);
    }

    #[test]
    fn test_vex_0f38_vpmulld() {
        let disasm = X86_64Disassembler::new();
        // C4 E2 71 40 C2 = vpmulld xmm0, xmm1, xmm2 (VEX.NDS.128.66.0F38.WIG 40 /r)
        let result = disasm
            .decode_instruction(&[0xc4, 0xe2, 0x71, 0x40, 0xc2], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "vpmulld");
        assert_eq!(result.size, 5);
    }

    #[test]
    fn test_vex_0f38_vaesenc() {
        let disasm = X86_64Disassembler::new();
        // C4 E2 71 DC C2 = vaesenc xmm0, xmm1, xmm2 (VEX.NDS.128.66.0F38.WIG DC /r)
        let result = disasm
            .decode_instruction(&[0xc4, 0xe2, 0x71, 0xdc, 0xc2], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "vaesenc");
        assert_eq!(result.size, 5);
    }

    #[test]
    fn test_vex_0f38_vfmadd132ps() {
        let disasm = X86_64Disassembler::new();
        // C4 E2 71 98 C2 = vfmadd132ps xmm0, xmm1, xmm2 (VEX.NDS.128.66.0F38.W0 98 /r)
        let result = disasm
            .decode_instruction(&[0xc4, 0xe2, 0x71, 0x98, 0xc2], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "vfmadd132ps");
        assert_eq!(result.size, 5);
    }

    #[test]
    fn test_vex_0f38_ymm() {
        let disasm = X86_64Disassembler::new();
        // C4 E2 75 00 C2 = vpshufb ymm0, ymm1, ymm2 (VEX.NDS.256.66.0F38.WIG 00 /r)
        let result = disasm
            .decode_instruction(&[0xc4, 0xe2, 0x75, 0x00, 0xc2], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "vpshufb");
        assert_eq!(result.size, 5);
        assert_eq!(result.instruction.operands.len(), 3);
    }

    // ========================================================================
    // VEX 0F3A (mmmmm=3) tests - instructions with immediate byte
    // ========================================================================

    #[test]
    fn test_vex_0f3a_vpalignr() {
        let disasm = X86_64Disassembler::new();
        // C4 E3 71 0F C2 08 = vpalignr xmm0, xmm1, xmm2, 8 (VEX.NDS.128.66.0F3A.WIG 0F /r ib)
        let result = disasm
            .decode_instruction(&[0xc4, 0xe3, 0x71, 0x0f, 0xc2, 0x08], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "vpalignr");
        assert_eq!(result.size, 6);
        assert_eq!(result.instruction.operands.len(), 4);
    }

    #[test]
    fn test_vex_0f3a_vpclmulqdq() {
        let disasm = X86_64Disassembler::new();
        // C4 E3 71 44 C2 00 = vpclmulqdq xmm0, xmm1, xmm2, 0 (VEX.NDS.128.66.0F3A.WIG 44 /r ib)
        let result = disasm
            .decode_instruction(&[0xc4, 0xe3, 0x71, 0x44, 0xc2, 0x00], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "vpclmulqdq");
        assert_eq!(result.size, 6);
        assert_eq!(result.instruction.operands.len(), 4);
    }

    #[test]
    fn test_vex_0f3a_vaeskeygenassist() {
        let disasm = X86_64Disassembler::new();
        // C4 E3 79 DF C1 01 = vaeskeygenassist xmm0, xmm1, 1 (VEX.128.66.0F3A.WIG DF /r ib)
        let result = disasm
            .decode_instruction(&[0xc4, 0xe3, 0x79, 0xdf, 0xc1, 0x01], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "vaeskeygenassist");
        assert_eq!(result.size, 6);
    }

    #[test]
    fn test_vex_0f3a_vroundps() {
        let disasm = X86_64Disassembler::new();
        // C4 E3 79 08 C1 00 = vroundps xmm0, xmm1, 0 (VEX.128.66.0F3A.WIG 08 /r ib)
        let result = disasm
            .decode_instruction(&[0xc4, 0xe3, 0x79, 0x08, 0xc1, 0x00], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "vroundps");
        assert_eq!(result.size, 6);
    }

    #[test]
    fn test_vex_0f3a_vblendps() {
        let disasm = X86_64Disassembler::new();
        // C4 E3 71 0C C2 0F = vblendps xmm0, xmm1, xmm2, 0xF (VEX.NDS.128.66.0F3A.WIG 0C /r ib)
        let result = disasm
            .decode_instruction(&[0xc4, 0xe3, 0x71, 0x0c, 0xc2, 0x0f], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "vblendps");
        assert_eq!(result.size, 6);
        assert_eq!(result.instruction.operands.len(), 4);
    }

    #[test]
    fn test_vex_0f3a_vpermq_ymm() {
        let disasm = X86_64Disassembler::new();
        // C4 E3 FD 00 C1 E4 = vpermq ymm0, ymm1, 0xE4 (VEX.256.66.0F3A.W1 00 /r ib)
        let result = disasm
            .decode_instruction(&[0xc4, 0xe3, 0xfd, 0x00, 0xc1, 0xe4], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "vpermq");
        assert_eq!(result.size, 6);
    }

    // ==========================================================================
    // BMI1 instruction tests
    // ==========================================================================

    #[test]
    fn test_andn_r32_r32_r32() {
        let disasm = X86_64Disassembler::new();
        // VEX.NDS.LZ.0F38.W0 F2 /r
        // C4 E2 70 F2 C2 = andn eax, ecx, edx
        // 3-byte VEX: C4 [RXB.mmmmm] [W.vvvv.L.pp]
        // E2 = 11100010 -> R=1, X=1, B=1, mmmmm=00010 (0F38)
        // 70 = 01110000 -> W=0, vvvv=~1110=0001 (ecx), L=0, pp=00
        let result = disasm
            .decode_instruction(&[0xc4, 0xe2, 0x70, 0xf2, 0xc2], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "andn");
        assert_eq!(result.instruction.operation, Operation::AndNot);
        assert_eq!(result.size, 5);
        assert_eq!(result.instruction.operands.len(), 3);
    }

    #[test]
    fn test_andn_r64_r64_r64() {
        let disasm = X86_64Disassembler::new();
        // VEX.NDS.LZ.0F38.W1 F2 /r
        // C4 E2 F0 F2 C2 = andn rax, rcx, rdx (W=1 for 64-bit)
        let result = disasm
            .decode_instruction(&[0xc4, 0xe2, 0xf0, 0xf2, 0xc2], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "andn");
        assert_eq!(result.instruction.operation, Operation::AndNot);
        assert_eq!(result.size, 5);
        assert_eq!(result.instruction.operands.len(), 3);
    }

    #[test]
    fn test_bextr_r32_r32_r32() {
        let disasm = X86_64Disassembler::new();
        // VEX.NDS.LZ.0F38.W0 F7 /r (pp=0, no prefix)
        // C4 E2 70 F7 C2 = bextr eax, edx, ecx
        let result = disasm
            .decode_instruction(&[0xc4, 0xe2, 0x70, 0xf7, 0xc2], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "bextr");
        assert_eq!(result.instruction.operation, Operation::BitExtract);
        assert_eq!(result.size, 5);
        assert_eq!(result.instruction.operands.len(), 3);
    }

    #[test]
    fn test_blsi_r32_r32() {
        let disasm = X86_64Disassembler::new();
        // VEX.NDD.LZ.0F38.W0 F3 /3
        // C4 E2 70 F3 DA = blsi ecx, edx (reg field = 3)
        // ModR/M DA = 11 011 010 = mod=3, reg=3 (blsi), rm=2 (edx)
        let result = disasm
            .decode_instruction(&[0xc4, 0xe2, 0x70, 0xf3, 0xda], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "blsi");
        assert_eq!(result.instruction.operation, Operation::ExtractLowestBit);
        assert_eq!(result.size, 5);
        assert_eq!(result.instruction.operands.len(), 2);
    }

    #[test]
    fn test_blsmsk_r32_r32() {
        let disasm = X86_64Disassembler::new();
        // VEX.NDD.LZ.0F38.W0 F3 /2
        // C4 E2 70 F3 D2 = blsmsk ecx, edx (reg field = 2)
        // ModR/M D2 = 11 010 010 = mod=3, reg=2 (blsmsk), rm=2 (edx)
        let result = disasm
            .decode_instruction(&[0xc4, 0xe2, 0x70, 0xf3, 0xd2], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "blsmsk");
        assert_eq!(result.instruction.operation, Operation::MaskUpToLowest);
        assert_eq!(result.size, 5);
        assert_eq!(result.instruction.operands.len(), 2);
    }

    #[test]
    fn test_blsr_r32_r32() {
        let disasm = X86_64Disassembler::new();
        // VEX.NDD.LZ.0F38.W0 F3 /1
        // C4 E2 70 F3 CA = blsr ecx, edx (reg field = 1)
        // ModR/M CA = 11 001 010 = mod=3, reg=1 (blsr), rm=2 (edx)
        let result = disasm
            .decode_instruction(&[0xc4, 0xe2, 0x70, 0xf3, 0xca], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "blsr");
        assert_eq!(result.instruction.operation, Operation::ResetLowestBit);
        assert_eq!(result.size, 5);
        assert_eq!(result.instruction.operands.len(), 2);
    }

    // ==========================================================================
    // BMI2 instruction tests
    // ==========================================================================

    #[test]
    fn test_bzhi_r32_r32_r32() {
        let disasm = X86_64Disassembler::new();
        // VEX.NDS.LZ.0F38.W0 F5 /r (no prefix, pp=0)
        // C4 E2 70 F5 C2 = bzhi eax, edx, ecx
        let result = disasm
            .decode_instruction(&[0xc4, 0xe2, 0x70, 0xf5, 0xc2], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "bzhi");
        assert_eq!(result.instruction.operation, Operation::ZeroHighBits);
        assert_eq!(result.size, 5);
        assert_eq!(result.instruction.operands.len(), 3);
    }

    #[test]
    fn test_pdep_r32_r32_r32() {
        let disasm = X86_64Disassembler::new();
        // VEX.NDS.LZ.F2.0F38.W0 F5 /r (pp=3 for F2)
        // C4 E2 73 F5 C2 = pdep eax, ecx, edx
        let result = disasm
            .decode_instruction(&[0xc4, 0xe2, 0x73, 0xf5, 0xc2], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "pdep");
        assert_eq!(result.instruction.operation, Operation::ParallelDeposit);
        assert_eq!(result.size, 5);
        assert_eq!(result.instruction.operands.len(), 3);
    }

    #[test]
    fn test_pext_r32_r32_r32() {
        let disasm = X86_64Disassembler::new();
        // VEX.NDS.LZ.F3.0F38.W0 F5 /r (pp=2 for F3)
        // C4 E2 72 F5 C2 = pext eax, ecx, edx
        let result = disasm
            .decode_instruction(&[0xc4, 0xe2, 0x72, 0xf5, 0xc2], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "pext");
        assert_eq!(result.instruction.operation, Operation::ParallelExtract);
        assert_eq!(result.size, 5);
        assert_eq!(result.instruction.operands.len(), 3);
    }

    #[test]
    fn test_mulx_r32_r32_r32() {
        let disasm = X86_64Disassembler::new();
        // VEX.NDD.LZ.F2.0F38.W0 F6 /r
        // C4 E2 73 F6 C2 = mulx eax, ecx, edx
        let result = disasm
            .decode_instruction(&[0xc4, 0xe2, 0x73, 0xf6, 0xc2], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "mulx");
        assert_eq!(result.instruction.operation, Operation::MulNoFlags);
        assert_eq!(result.size, 5);
        assert_eq!(result.instruction.operands.len(), 3);
    }

    #[test]
    fn test_shlx_r32_r32_r32() {
        let disasm = X86_64Disassembler::new();
        // VEX.NDS.LZ.66.0F38.W0 F7 /r (pp=1 for 66)
        // C4 E2 71 F7 C2 = shlx eax, edx, ecx
        let result = disasm
            .decode_instruction(&[0xc4, 0xe2, 0x71, 0xf7, 0xc2], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "shlx");
        assert_eq!(result.instruction.operation, Operation::Shl);
        assert_eq!(result.size, 5);
        assert_eq!(result.instruction.operands.len(), 3);
    }

    #[test]
    fn test_shrx_r32_r32_r32() {
        let disasm = X86_64Disassembler::new();
        // VEX.NDS.LZ.F2.0F38.W0 F7 /r (pp=3 for F2)
        // C4 E2 73 F7 C2 = shrx eax, edx, ecx
        let result = disasm
            .decode_instruction(&[0xc4, 0xe2, 0x73, 0xf7, 0xc2], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "shrx");
        assert_eq!(result.instruction.operation, Operation::Shr);
        assert_eq!(result.size, 5);
        assert_eq!(result.instruction.operands.len(), 3);
    }

    #[test]
    fn test_sarx_r32_r32_r32() {
        let disasm = X86_64Disassembler::new();
        // VEX.NDS.LZ.F3.0F38.W0 F7 /r (pp=2 for F3)
        // C4 E2 72 F7 C2 = sarx eax, edx, ecx
        let result = disasm
            .decode_instruction(&[0xc4, 0xe2, 0x72, 0xf7, 0xc2], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "sarx");
        assert_eq!(result.instruction.operation, Operation::Sar);
        assert_eq!(result.size, 5);
        assert_eq!(result.instruction.operands.len(), 3);
    }

    #[test]
    fn test_bzhi_r64_r64_r64() {
        let disasm = X86_64Disassembler::new();
        // VEX.NDS.LZ.0F38.W1 F5 /r (64-bit version)
        // C4 E2 F0 F5 C2 = bzhi rax, rdx, rcx
        let result = disasm
            .decode_instruction(&[0xc4, 0xe2, 0xf0, 0xf5, 0xc2], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "bzhi");
        assert_eq!(result.instruction.operation, Operation::ZeroHighBits);
        assert_eq!(result.size, 5);
        assert_eq!(result.instruction.operands.len(), 3);
    }

    #[test]
    fn test_mulx_r64_r64_r64() {
        let disasm = X86_64Disassembler::new();
        // VEX.NDD.LZ.F2.0F38.W1 F6 /r (64-bit version)
        // C4 E2 F3 F6 C2 = mulx rax, rcx, rdx
        let result = disasm
            .decode_instruction(&[0xc4, 0xe2, 0xf3, 0xf6, 0xc2], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "mulx");
        assert_eq!(result.instruction.operation, Operation::MulNoFlags);
        assert_eq!(result.size, 5);
        assert_eq!(result.instruction.operands.len(), 3);
    }

    // ==========================================================================
    // EVEX (AVX-512) instruction tests
    // ==========================================================================

    #[test]
    fn test_evex_vmovaps_zmm_zmm() {
        let disasm = X86_64Disassembler::new();
        // EVEX.512.0F.W0 28 /r = vmovaps zmm0, zmm1
        // 62 F1 7C 48 28 C1
        // 62 = EVEX prefix
        // F1 = P0: R=1, X=1, B=1, R'=1, mm=01 (0F map)
        // 7C = P1: W=0, vvvv=1111, pp=00 (no prefix)
        // 48 = P2: z=0, L'L=10 (512-bit), b=0, V'=1, aaa=000
        // 28 = opcode
        // C1 = ModR/M: mod=11, reg=0 (zmm0), rm=1 (zmm1)
        let result = disasm
            .decode_instruction(&[0x62, 0xf1, 0x7c, 0x48, 0x28, 0xc1], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "vmovaps");
        assert_eq!(result.instruction.operation, Operation::Move);
        assert_eq!(result.size, 6);
        assert_eq!(result.instruction.operands.len(), 3);
    }

    #[test]
    fn test_evex_vaddps_zmm() {
        let disasm = X86_64Disassembler::new();
        // EVEX.512.0F.W0 58 /r = vaddps zmm0, zmm1, zmm2
        // 62 F1 74 48 58 C2
        // vvvv=~0001=1110 (zmm1)
        let result = disasm
            .decode_instruction(&[0x62, 0xf1, 0x74, 0x48, 0x58, 0xc2], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "vaddps");
        assert_eq!(result.instruction.operation, Operation::Add);
        assert_eq!(result.size, 6);
        assert_eq!(result.instruction.operands.len(), 3);
    }

    #[test]
    fn test_evex_vmulpd_zmm() {
        let disasm = X86_64Disassembler::new();
        // EVEX.512.66.0F.W1 59 /r = vmulpd zmm0, zmm1, zmm2
        // 62 F1 F5 48 59 C2
        // W=1 for double precision, pp=01 for 66 prefix
        let result = disasm
            .decode_instruction(&[0x62, 0xf1, 0xf5, 0x48, 0x59, 0xc2], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "vmulpd");
        assert_eq!(result.instruction.operation, Operation::Mul);
        assert_eq!(result.size, 6);
        assert_eq!(result.instruction.operands.len(), 3);
    }

    #[test]
    fn test_evex_vxorps_zmm() {
        let disasm = X86_64Disassembler::new();
        // EVEX.512.0F.W0 57 /r = vxorps zmm0, zmm0, zmm0 (common idiom to zero register)
        // 62 F1 7C 48 57 C0
        let result = disasm
            .decode_instruction(&[0x62, 0xf1, 0x7c, 0x48, 0x57, 0xc0], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "vxorps");
        assert_eq!(result.instruction.operation, Operation::Xor);
        assert_eq!(result.size, 6);
        assert_eq!(result.instruction.operands.len(), 3);
    }

    #[test]
    fn test_evex_with_opmask() {
        let disasm = X86_64Disassembler::new();
        // EVEX.512.0F.W0 28 /r with k1 opmask = vmovaps zmm0 {k1}, zmm1
        // 62 F1 7C 49 28 C1
        // aaa=001 (k1)
        let result = disasm
            .decode_instruction(&[0x62, 0xf1, 0x7c, 0x49, 0x28, 0xc1], 0x1000)
            .unwrap();
        assert!(result.instruction.mnemonic.contains("{k1}"));
        assert_eq!(result.instruction.operation, Operation::Move);
        assert_eq!(result.size, 6);
    }

    #[test]
    fn test_evex_with_opmask_and_zeroing() {
        let disasm = X86_64Disassembler::new();
        // EVEX.512.0F.W0 28 /r with k1 opmask and zeroing = vmovaps zmm0 {k1}{z}, zmm1
        // 62 F1 7C C9 28 C1
        // z=1, aaa=001 (k1)
        let result = disasm
            .decode_instruction(&[0x62, 0xf1, 0x7c, 0xc9, 0x28, 0xc1], 0x1000)
            .unwrap();
        assert!(result.instruction.mnemonic.contains("{k1}"));
        assert!(result.instruction.mnemonic.contains("{z}"));
        assert_eq!(result.instruction.operation, Operation::Move);
        assert_eq!(result.size, 6);
    }

    #[test]
    fn test_evex_vmovdqa32_zmm() {
        let disasm = X86_64Disassembler::new();
        // EVEX.512.66.0F.W0 6F /r = vmovdqa32 zmm0, zmm1
        // 62 F1 7D 48 6F C1
        let result = disasm
            .decode_instruction(&[0x62, 0xf1, 0x7d, 0x48, 0x6f, 0xc1], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "vmovdqa32");
        assert_eq!(result.instruction.operation, Operation::Move);
        assert_eq!(result.size, 6);
    }

    #[test]
    fn test_evex_vmovdqa64_zmm() {
        let disasm = X86_64Disassembler::new();
        // EVEX.512.66.0F.W1 6F /r = vmovdqa64 zmm0, zmm1
        // 62 F1 FD 48 6F C1
        let result = disasm
            .decode_instruction(&[0x62, 0xf1, 0xfd, 0x48, 0x6f, 0xc1], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "vmovdqa64");
        assert_eq!(result.instruction.operation, Operation::Move);
        assert_eq!(result.size, 6);
    }

    #[test]
    fn test_evex_128bit_xmm() {
        let disasm = X86_64Disassembler::new();
        // EVEX.128.0F.W0 28 /r = vmovaps xmm0, xmm1
        // 62 F1 7C 08 28 C1
        // L'L=00 (128-bit)
        let result = disasm
            .decode_instruction(&[0x62, 0xf1, 0x7c, 0x08, 0x28, 0xc1], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "vmovaps");
        assert_eq!(result.instruction.operation, Operation::Move);
        assert_eq!(result.size, 6);
    }

    #[test]
    fn test_evex_256bit_ymm() {
        let disasm = X86_64Disassembler::new();
        // EVEX.256.0F.W0 28 /r = vmovaps ymm0, ymm1
        // 62 F1 7C 28 28 C1
        // L'L=01 (256-bit)
        let result = disasm
            .decode_instruction(&[0x62, 0xf1, 0x7c, 0x28, 0x28, 0xc1], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "vmovaps");
        assert_eq!(result.instruction.operation, Operation::Move);
        assert_eq!(result.size, 6);
    }

    // ==========================================================================
    // AMX (Advanced Matrix Extensions) instruction tests
    // ==========================================================================

    #[test]
    fn test_amx_tilerelease() {
        let disasm = X86_64Disassembler::new();
        // VEX.128.NP.0F38.W0 49 C0 = tilerelease
        // C4 E2 78 49 C0
        // C4 = 3-byte VEX prefix
        // E2 = R=1, X=1, B=1, mmmmm=00010 (0F38)
        // 78 = W=0, vvvv=1111, L=0, pp=00 (no prefix)
        // 49 = opcode
        // C0 = ModR/M: mod=11, reg=0, rm=0 (special encoding for TILERELEASE)
        let result = disasm
            .decode_instruction(&[0xc4, 0xe2, 0x78, 0x49, 0xc0], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "tilerelease");
        assert_eq!(result.instruction.operation, Operation::AmxTileRelease);
        assert_eq!(result.size, 5);
        assert_eq!(result.instruction.operands.len(), 0);
    }

    #[test]
    fn test_amx_tilezero() {
        let disasm = X86_64Disassembler::new();
        // VEX.128.F2.0F38.W0 49 /r (mod=11) = tilezero tmm
        // C4 E2 7B 49 C0 = tilezero tmm0
        // pp=11 (F2 prefix)
        let result = disasm
            .decode_instruction(&[0xc4, 0xe2, 0x7b, 0x49, 0xc0], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "tilezero");
        assert_eq!(result.instruction.operation, Operation::AmxTileZero);
        assert_eq!(result.size, 5);
        assert_eq!(result.instruction.operands.len(), 1);
    }

    #[test]
    fn test_amx_tdpbssd() {
        let disasm = X86_64Disassembler::new();
        // VEX.128.F2.0F38.W0 5E /r = tdpbssd tmm1, tmm2, tmm3
        // C4 E2 63 5E C9 = tdpbssd tmm1, tmm3, tmm1
        // pp=11 (F2), vvvv=~3=1100
        let result = disasm
            .decode_instruction(&[0xc4, 0xe2, 0x63, 0x5e, 0xc9], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "tdpbssd");
        assert_eq!(result.instruction.operation, Operation::AmxDotProductSS);
        assert_eq!(result.size, 5);
        assert_eq!(result.instruction.operands.len(), 3);
    }

    #[test]
    fn test_amx_tdpbuud() {
        let disasm = X86_64Disassembler::new();
        // VEX.128.NP.0F38.W0 5E /r = tdpbuud tmm1, tmm2, tmm3
        // C4 E2 60 5E C9 = tdpbuud tmm1, tmm3, tmm1
        // pp=00 (no prefix)
        let result = disasm
            .decode_instruction(&[0xc4, 0xe2, 0x60, 0x5e, 0xc9], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "tdpbuud");
        assert_eq!(result.instruction.operation, Operation::AmxDotProductUU);
        assert_eq!(result.size, 5);
        assert_eq!(result.instruction.operands.len(), 3);
    }

    // ==========================================================================
    // CET (Control-flow Enforcement Technology) instruction tests
    // ==========================================================================

    #[test]
    fn test_cet_incsspd() {
        let disasm = X86_64Disassembler::new();
        // F3 0F AE /5 (mod=11) = incsspd r32
        // F3 0F AE E8 = incsspd eax
        // ModR/M: E8 = mod=11, reg=5, rm=0 (eax)
        let result = disasm
            .decode_instruction(&[0xf3, 0x0f, 0xae, 0xe8], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "incsspd");
        assert_eq!(result.instruction.operation, Operation::CetIncSsp);
        assert_eq!(result.size, 4);
        assert_eq!(result.instruction.operands.len(), 1);
    }

    #[test]
    fn test_cet_rdsspd() {
        let disasm = X86_64Disassembler::new();
        // F3 0F 1E /1 (mod=11) = rdsspd r32
        // F3 0F 1E C8 = rdsspd eax
        // ModR/M: C8 = mod=11, reg=1, rm=0 (eax)
        let result = disasm
            .decode_instruction(&[0xf3, 0x0f, 0x1e, 0xc8], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "rdsspd");
        assert_eq!(result.instruction.operation, Operation::CetReadSsp);
        assert_eq!(result.size, 4);
        assert_eq!(result.instruction.operands.len(), 1);
    }

    #[test]
    fn test_cet_saveprevssp() {
        let disasm = X86_64Disassembler::new();
        // F3 0F 01 EA = saveprevssp
        let result = disasm
            .decode_instruction(&[0xf3, 0x0f, 0x01, 0xea], 0x1000)
            .unwrap();
        assert_eq!(result.instruction.mnemonic, "saveprevssp");
        assert_eq!(result.instruction.operation, Operation::CetSavePrevSsp);
        assert_eq!(result.size, 4);
        assert_eq!(result.instruction.operands.len(), 0);
    }
}
