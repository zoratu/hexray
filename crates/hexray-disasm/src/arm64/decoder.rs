//! ARM64 instruction decoder implementation.

#![allow(unused_variables)]

use crate::{DecodeError, DecodedInstruction, Disassembler};
use hexray_core::{
    Architecture, Condition, ControlFlow, Instruction, MemoryRef, Operand, Operation,
    Register, RegisterClass,
    register::arm64,
};
use super::sme::SmeDecoder;
use super::sve::SveDecoder;

/// ARM64 disassembler.
pub struct Arm64Disassembler {
    sve_decoder: SveDecoder,
    sme_decoder: SmeDecoder,
}

impl Arm64Disassembler {
    /// Creates a new ARM64 disassembler.
    pub fn new() -> Self {
        Self {
            sve_decoder: SveDecoder::new(),
            sme_decoder: SmeDecoder::new(),
        }
    }

    /// Creates an ARM64 general-purpose register with SP interpretation for register 31.
    /// Use this for base address registers where register 31 means SP.
    fn gpr_sp(id: u16, is_64bit: bool) -> Register {
        Register::new(
            Architecture::Arm64,
            if id == 31 {
                RegisterClass::StackPointer
            } else {
                RegisterClass::General
            },
            if id == 31 { arm64::SP } else { id },
            if is_64bit { 64 } else { 32 },
        )
    }

    /// Creates an ARM64 general-purpose register with ZR interpretation for register 31.
    /// Use this for data registers where register 31 means XZR/WZR (zero register).
    fn gpr_zr(id: u16, is_64bit: bool) -> Register {
        Register::new(
            Architecture::Arm64,
            RegisterClass::General,
            if id == 31 { arm64::XZR } else { id },
            if is_64bit { 64 } else { 32 },
        )
    }

    /// Creates an X register (64-bit) with ZR interpretation for register 31.
    fn xreg(id: u16) -> Register {
        Self::gpr_zr(id, true)
    }

    /// Creates a W register (32-bit) with ZR interpretation for register 31.
    fn wreg(id: u16) -> Register {
        Self::gpr_zr(id, false)
    }

    /// Creates an X register (64-bit) with SP interpretation for register 31.
    fn xreg_sp(id: u16) -> Register {
        Self::gpr_sp(id, true)
    }

    /// Creates a W register (32-bit) with SP interpretation for register 31.
    #[allow(dead_code)]
    fn wreg_sp(id: u16) -> Register {
        Self::gpr_sp(id, false)
    }

    /// Creates a B register (8-bit SIMD/FP scalar).
    #[allow(dead_code)]
    fn breg(id: u16) -> Register {
        Register::new(
            Architecture::Arm64,
            RegisterClass::FloatingPoint,
            hexray_core::register::arm64::V0 + id,
            8,
        )
    }

    /// Creates an H register (16-bit SIMD/FP scalar).
    #[allow(dead_code)]
    fn hreg(id: u16) -> Register {
        Register::new(
            Architecture::Arm64,
            RegisterClass::FloatingPoint,
            hexray_core::register::arm64::V0 + id,
            16,
        )
    }

    /// Creates an S register (32-bit SIMD/FP scalar).
    fn sreg(id: u16) -> Register {
        Register::new(
            Architecture::Arm64,
            RegisterClass::FloatingPoint,
            hexray_core::register::arm64::V0 + id,
            32,
        )
    }

    /// Creates a D register (64-bit SIMD/FP scalar).
    fn dreg(id: u16) -> Register {
        Register::new(
            Architecture::Arm64,
            RegisterClass::FloatingPoint,
            hexray_core::register::arm64::V0 + id,
            64,
        )
    }

    /// Creates a Q register (128-bit SIMD/FP vector).
    fn qreg(id: u16) -> Register {
        Register::new(
            Architecture::Arm64,
            RegisterClass::Vector,
            hexray_core::register::arm64::V0 + id,
            128,
        )
    }

    /// Creates a SIMD/FP register based on size encoding.
    /// size: 0=B(8), 1=H(16), 2=S(32), 3=D(64), 4=Q(128)
    fn simd_reg(id: u16, size: u32) -> Register {
        let (class, bits) = match size {
            0 => (RegisterClass::FloatingPoint, 8),
            1 => (RegisterClass::FloatingPoint, 16),
            2 => (RegisterClass::FloatingPoint, 32),
            3 => (RegisterClass::FloatingPoint, 64),
            _ => (RegisterClass::Vector, 128),
        };
        Register::new(
            Architecture::Arm64,
            class,
            hexray_core::register::arm64::V0 + id,
            bits,
        )
    }

    /// Decode the instruction at the given address.
    fn decode(&self, bytes: &[u8], address: u64) -> Result<DecodedInstruction, DecodeError> {
        if bytes.len() < 4 {
            return Err(DecodeError::truncated(address, 4, bytes.len()));
        }

        // ARM64 instructions are little-endian 32-bit
        let insn = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let raw_bytes = bytes[0..4].to_vec();

        // Check for SME instructions first (they have distinctive bit patterns)
        if SmeDecoder::is_sme_instruction(insn) {
            if let Some(decoded) = self.sme_decoder.decode(insn, address, raw_bytes.clone()) {
                return Ok(decoded);
            }
            // Fall through to SVE/standard decode if SME decoder can't handle it
        }

        // Check for SVE/SVE2 instructions (they have distinctive bit patterns)
        if SveDecoder::is_sve_instruction(insn) {
            if let Some(decoded) = self.sve_decoder.decode(insn, address, raw_bytes.clone()) {
                return Ok(decoded);
            }
            // Fall through to standard decode if SVE decoder can't handle it
        }

        // Extract op0 (bits 25-28) for major classification
        let op0 = (insn >> 25) & 0xF;

        match op0 {
            // Data processing - immediate
            0b1000 | 0b1001 => self.decode_dp_imm(insn, address, raw_bytes),

            // Branches, exception generating, system instructions
            0b1010 | 0b1011 => self.decode_branch_system(insn, address, raw_bytes),

            // Loads and stores
            0b0100 | 0b0110 | 0b1100 | 0b1110 => self.decode_load_store(insn, address, raw_bytes),

            // Data processing - register
            0b0101 | 0b1101 => self.decode_dp_reg(insn, address, raw_bytes),

            // Data processing - SIMD and floating-point
            0b0111 | 0b1111 => self.decode_simd_fp(insn, address, raw_bytes),

            _ => self.decode_unknown(insn, address, raw_bytes),
        }
    }

    /// Decode data processing - immediate instructions.
    fn decode_dp_imm(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let op0 = (insn >> 23) & 0x7;
        let sf = (insn >> 31) & 1; // 64-bit if set
        let is_64bit = sf == 1;

        match op0 {
            // PC-relative addressing (ADR, ADRP)
            0b000 | 0b001 => {
                let rd = (insn & 0x1F) as u16;
                let immlo = (insn >> 29) & 0x3;
                let immhi = (insn >> 5) & 0x7FFFF;
                let is_adrp = (insn >> 31) & 1 == 1;

                let imm = if is_adrp {
                    // ADRP: page address (4KB aligned)
                    let imm21 = ((immhi << 2) | immlo) as i64;
                    let imm = sign_extend(imm21 as u64, 21) << 12;
                    (address & !0xFFF) as i64 + imm
                } else {
                    // ADR: byte address
                    let imm21 = ((immhi << 2) | immlo) as i64;
                    let imm = sign_extend(imm21 as u64, 21);
                    address as i64 + imm
                };

                let mnemonic = if is_adrp { "adrp" } else { "adr" };
                let inst = Instruction::new(address, 4, bytes, mnemonic)
                    .with_operation(Operation::LoadEffectiveAddress)
                    .with_operands(vec![
                        Operand::reg(Self::xreg(rd)),
                        Operand::pc_rel(imm - address as i64, imm as u64),
                    ]);

                Ok(DecodedInstruction { instruction: inst, size: 4 })
            }

            // Add/subtract immediate
            0b010 | 0b011 => {
                let rd = (insn & 0x1F) as u16;
                let rn = ((insn >> 5) & 0x1F) as u16;
                let imm12 = ((insn >> 10) & 0xFFF) as u64;
                let shift = ((insn >> 22) & 0x3) as u8;
                let is_sub = (insn >> 30) & 1 == 1;
                let set_flags = (insn >> 29) & 1 == 1;

                let imm = if shift == 1 { imm12 << 12 } else { imm12 };

                // Special cases for aliases
                let (mnemonic, operands, operation) = if set_flags && rd == 31 {
                    // CMP/CMN (comparing with zero register)
                    // Rn can be SP (register 31 = SP in CMP/CMN)
                    let mnemonic = if is_sub { "cmp" } else { "cmn" };
                    let reg = if is_64bit { Self::xreg_sp(rn) } else { Self::wreg_sp(rn) };
                    (mnemonic, vec![Operand::reg(reg), Operand::imm_unsigned(imm, 64)], Operation::Compare)
                } else if !set_flags && is_sub && rn == 31 {
                    // MOV (from SP) - sub from SP with 0
                    // Without flags, register 31 = SP for both Rd and Rn
                    let dst = if is_64bit { Self::xreg_sp(rd) } else { Self::wreg_sp(rd) };
                    let src = if is_64bit { Self::xreg_sp(rn) } else { Self::wreg_sp(rn) };
                    if imm == 0 {
                        ("mov", vec![Operand::reg(dst), Operand::reg(src)], Operation::Move)
                    } else {
                        let mnemonic = if is_sub { "sub" } else { "add" };
                        (mnemonic, vec![Operand::reg(dst), Operand::reg(src), Operand::imm_unsigned(imm, 64)], if is_sub { Operation::Sub } else { Operation::Add })
                    }
                } else {
                    let mnemonic = match (is_sub, set_flags) {
                        (false, false) => "add",
                        (false, true) => "adds",
                        (true, false) => "sub",
                        (true, true) => "subs",
                    };
                    // Without flags (S=0): Rd and Rn use SP interpretation for reg 31
                    // With flags (S=1): Rd uses ZR, Rn uses SP
                    let (dst, src) = if set_flags {
                        (
                            if is_64bit { Self::xreg(rd) } else { Self::wreg(rd) },
                            if is_64bit { Self::xreg_sp(rn) } else { Self::wreg_sp(rn) },
                        )
                    } else {
                        (
                            if is_64bit { Self::xreg_sp(rd) } else { Self::wreg_sp(rd) },
                            if is_64bit { Self::xreg_sp(rn) } else { Self::wreg_sp(rn) },
                        )
                    };
                    (mnemonic, vec![Operand::reg(dst), Operand::reg(src), Operand::imm_unsigned(imm, 64)], if is_sub { Operation::Sub } else { Operation::Add })
                };

                let inst = Instruction::new(address, 4, bytes, mnemonic)
                    .with_operation(operation)
                    .with_operands(operands);

                Ok(DecodedInstruction { instruction: inst, size: 4 })
            }

            // Logical immediate
            0b100 => {
                let rd = (insn & 0x1F) as u16;
                let rn = ((insn >> 5) & 0x1F) as u16;
                let opc = (insn >> 29) & 0x3;

                // Decode bitmask immediate (complex encoding)
                let n = ((insn >> 22) & 1) as u8;
                let immr = ((insn >> 16) & 0x3F) as u8;
                let imms = ((insn >> 10) & 0x3F) as u8;
                let imm = decode_bitmask_imm(n, imms, immr, is_64bit);

                let (mnemonic, operation, set_flags) = match opc {
                    0b00 => ("and", Operation::And, false),
                    0b01 => ("orr", Operation::Or, false),
                    0b10 => ("eor", Operation::Xor, false),
                    0b11 => ("ands", Operation::And, true),
                    _ => unreachable!(),
                };

                let operands = if set_flags && rd == 31 {
                    // TST alias
                    let reg = if is_64bit { Self::xreg(rn) } else { Self::wreg(rn) };
                    vec![Operand::reg(reg), Operand::imm_unsigned(imm, 64)]
                } else if opc == 0b01 && rn == 31 {
                    // MOV (bitmask immediate) alias
                    let dst = if is_64bit { Self::xreg(rd) } else { Self::wreg(rd) };
                    vec![Operand::reg(dst), Operand::imm_unsigned(imm, 64)]
                } else {
                    let dst = if is_64bit { Self::xreg(rd) } else { Self::wreg(rd) };
                    let src = if is_64bit { Self::xreg(rn) } else { Self::wreg(rn) };
                    vec![Operand::reg(dst), Operand::reg(src), Operand::imm_unsigned(imm, 64)]
                };

                let final_mnemonic = if set_flags && rd == 31 {
                    "tst"
                } else if opc == 0b01 && rn == 31 {
                    "mov"
                } else {
                    mnemonic
                };

                let inst = Instruction::new(address, 4, bytes, final_mnemonic)
                    .with_operation(if final_mnemonic == "tst" { Operation::Test } else if final_mnemonic == "mov" { Operation::Move } else { operation })
                    .with_operands(operands);

                Ok(DecodedInstruction { instruction: inst, size: 4 })
            }

            // Move wide immediate (MOVN, MOVZ, MOVK)
            0b101 => {
                let rd = (insn & 0x1F) as u16;
                let imm16 = ((insn >> 5) & 0xFFFF) as u64;
                let hw = ((insn >> 21) & 0x3) as u8;
                let opc = (insn >> 29) & 0x3;
                let shift = hw * 16;

                let (mnemonic, operation) = match opc {
                    0b00 => ("movn", Operation::Move),
                    0b10 => ("movz", Operation::Move),
                    0b11 => ("movk", Operation::Move),
                    _ => return self.decode_unknown(insn, address, bytes),
                };

                // Check for MOV alias (MOVZ with no shift, or MOVN producing simple value)
                let is_mov_alias = opc == 0b10 && hw == 0;

                let dst = if is_64bit { Self::xreg(rd) } else { Self::wreg(rd) };
                let shifted_imm = imm16 << shift;

                let (final_mnemonic, operands) = if is_mov_alias {
                    ("mov", vec![Operand::reg(dst), Operand::imm_unsigned(imm16, 64)])
                } else if shift > 0 {
                    (mnemonic, vec![Operand::reg(dst), Operand::imm_unsigned(imm16, 16), Operand::imm_unsigned(shift as u64, 8)])
                } else {
                    (mnemonic, vec![Operand::reg(dst), Operand::imm_unsigned(shifted_imm, 64)])
                };

                let inst = Instruction::new(address, 4, bytes, final_mnemonic)
                    .with_operation(operation)
                    .with_operands(operands);

                Ok(DecodedInstruction { instruction: inst, size: 4 })
            }

            // Bitfield (BFM, SBFM, UBFM)
            0b110 => {
                let rd = (insn & 0x1F) as u16;
                let rn = ((insn >> 5) & 0x1F) as u16;
                let imms = ((insn >> 10) & 0x3F) as u8;
                let immr = ((insn >> 16) & 0x3F) as u8;
                let opc = (insn >> 29) & 0x3;

                let reg_size = if is_64bit { 64 } else { 32 };
                let dst = if is_64bit { Self::xreg(rd) } else { Self::wreg(rd) };
                let src = if is_64bit { Self::xreg(rn) } else { Self::wreg(rn) };

                // Check for common aliases
                let (mnemonic, operands) = match opc {
                    0b00 => {
                        // SBFM aliases
                        if imms == reg_size - 1 {
                            // ASR
                            ("asr", vec![Operand::reg(dst), Operand::reg(src), Operand::imm_unsigned(immr as u64, 8)])
                        } else if immr == 0 && imms == 7 {
                            ("sxtb", vec![Operand::reg(dst), Operand::reg(src)])
                        } else if immr == 0 && imms == 15 {
                            ("sxth", vec![Operand::reg(dst), Operand::reg(src)])
                        } else if immr == 0 && imms == 31 {
                            ("sxtw", vec![Operand::reg(dst), Operand::reg(src)])
                        } else {
                            ("sbfm", vec![Operand::reg(dst), Operand::reg(src), Operand::imm_unsigned(immr as u64, 8), Operand::imm_unsigned(imms as u64, 8)])
                        }
                    }
                    0b01 => {
                        // BFM - bit field move
                        ("bfm", vec![Operand::reg(dst), Operand::reg(src), Operand::imm_unsigned(immr as u64, 8), Operand::imm_unsigned(imms as u64, 8)])
                    }
                    0b10 => {
                        // UBFM aliases
                        if imms + 1 == immr {
                            // LSL
                            let shift = reg_size.wrapping_sub(immr) & (reg_size - 1);
                            ("lsl", vec![Operand::reg(dst), Operand::reg(src), Operand::imm_unsigned(shift as u64, 8)])
                        } else if imms == reg_size - 1 {
                            // LSR
                            ("lsr", vec![Operand::reg(dst), Operand::reg(src), Operand::imm_unsigned(immr as u64, 8)])
                        } else if immr == 0 && imms == 7 {
                            ("uxtb", vec![Operand::reg(dst), Operand::reg(src)])
                        } else if immr == 0 && imms == 15 {
                            ("uxth", vec![Operand::reg(dst), Operand::reg(src)])
                        } else {
                            ("ubfm", vec![Operand::reg(dst), Operand::reg(src), Operand::imm_unsigned(immr as u64, 8), Operand::imm_unsigned(imms as u64, 8)])
                        }
                    }
                    _ => return self.decode_unknown(insn, address, bytes),
                };

                let operation = match mnemonic {
                    "asr" => Operation::Sar,
                    "lsl" => Operation::Shl,
                    "lsr" => Operation::Shr,
                    _ => Operation::Other(0),
                };

                let inst = Instruction::new(address, 4, bytes, mnemonic)
                    .with_operation(operation)
                    .with_operands(operands);

                Ok(DecodedInstruction { instruction: inst, size: 4 })
            }

            // Extract
            0b111 => {
                let rd = (insn & 0x1F) as u16;
                let rn = ((insn >> 5) & 0x1F) as u16;
                let rm = ((insn >> 16) & 0x1F) as u16;
                let imms = ((insn >> 10) & 0x3F) as u8;

                let dst = if is_64bit { Self::xreg(rd) } else { Self::wreg(rd) };
                let src1 = if is_64bit { Self::xreg(rn) } else { Self::wreg(rn) };
                let src2 = if is_64bit { Self::xreg(rm) } else { Self::wreg(rm) };

                let (mnemonic, operands) = if rn == rm {
                    // ROR alias
                    ("ror", vec![Operand::reg(dst), Operand::reg(src1), Operand::imm_unsigned(imms as u64, 8)])
                } else {
                    ("extr", vec![Operand::reg(dst), Operand::reg(src1), Operand::reg(src2), Operand::imm_unsigned(imms as u64, 8)])
                };

                let inst = Instruction::new(address, 4, bytes, mnemonic)
                    .with_operation(if mnemonic == "ror" { Operation::Ror } else { Operation::Other(0) })
                    .with_operands(operands);

                Ok(DecodedInstruction { instruction: inst, size: 4 })
            }

            _ => self.decode_unknown(insn, address, bytes),
        }
    }

    /// Decode branch and system instructions.
    fn decode_branch_system(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let op0 = (insn >> 29) & 0x7;
        let op1 = (insn >> 22) & 0xF;

        match op0 {
            // Unconditional branch immediate
            0b000 | 0b100 => {
                let is_bl = (insn >> 31) & 1 == 1;
                let imm26 = (insn & 0x3FFFFFF) as i64;
                let offset = sign_extend((imm26 << 2) as u64, 28);
                let target = (address as i64 + offset) as u64;

                let mnemonic = if is_bl { "bl" } else { "b" };
                let cf = if is_bl {
                    ControlFlow::Call { target, return_addr: address + 4 }
                } else {
                    ControlFlow::UnconditionalBranch { target }
                };

                let inst = Instruction::new(address, 4, bytes, mnemonic)
                    .with_operation(if is_bl { Operation::Call } else { Operation::Jump })
                    .with_operand(Operand::pc_rel(offset, target))
                    .with_control_flow(cf);

                Ok(DecodedInstruction { instruction: inst, size: 4 })
            }

            // Compare and branch
            0b001 | 0b101 => {
                let is_cbnz = (insn >> 24) & 1 == 1;
                let sf = (insn >> 31) & 1 == 1;
                let rt = (insn & 0x1F) as u16;
                let imm19 = ((insn >> 5) & 0x7FFFF) as i64;
                let offset = sign_extend((imm19 << 2) as u64, 21);
                let target = (address as i64 + offset) as u64;

                let mnemonic = if is_cbnz { "cbnz" } else { "cbz" };
                let reg = if sf { Self::xreg(rt) } else { Self::wreg(rt) };
                let condition = if is_cbnz { Condition::NotEqual } else { Condition::Equal };

                let inst = Instruction::new(address, 4, bytes, mnemonic)
                    .with_operation(Operation::ConditionalJump)
                    .with_operands(vec![Operand::reg(reg), Operand::pc_rel(offset, target)])
                    .with_control_flow(ControlFlow::ConditionalBranch {
                        target,
                        condition,
                        fallthrough: address + 4,
                    });

                Ok(DecodedInstruction { instruction: inst, size: 4 })
            }

            // Test and branch
            0b011 | 0b111 => {
                let is_tbnz = (insn >> 24) & 1 == 1;
                let b5 = (insn >> 31) & 1;
                let b40 = (insn >> 19) & 0x1F;
                let bit_pos = (b5 << 5) | b40;
                let rt = (insn & 0x1F) as u16;
                let imm14 = ((insn >> 5) & 0x3FFF) as i64;
                let offset = sign_extend((imm14 << 2) as u64, 16);
                let target = (address as i64 + offset) as u64;

                let mnemonic = if is_tbnz { "tbnz" } else { "tbz" };
                let is_64bit = b5 == 1;
                let reg = if is_64bit { Self::xreg(rt) } else { Self::wreg(rt) };
                let condition = if is_tbnz { Condition::NotEqual } else { Condition::Equal };

                let inst = Instruction::new(address, 4, bytes, mnemonic)
                    .with_operation(Operation::ConditionalJump)
                    .with_operands(vec![
                        Operand::reg(reg),
                        Operand::imm_unsigned(bit_pos as u64, 8),
                        Operand::pc_rel(offset, target),
                    ])
                    .with_control_flow(ControlFlow::ConditionalBranch {
                        target,
                        condition,
                        fallthrough: address + 4,
                    });

                Ok(DecodedInstruction { instruction: inst, size: 4 })
            }

            // Conditional branch
            0b010 => {
                let cond = (insn & 0xF) as u8;
                let imm19 = ((insn >> 5) & 0x7FFFF) as i64;
                let offset = sign_extend((imm19 << 2) as u64, 21);
                let target = (address as i64 + offset) as u64;

                let (cond_suffix, condition) = decode_condition(cond);
                let mnemonic = format!("b.{}", cond_suffix);

                let inst = Instruction::new(address, 4, bytes, mnemonic)
                    .with_operation(Operation::ConditionalJump)
                    .with_operand(Operand::pc_rel(offset, target))
                    .with_control_flow(ControlFlow::ConditionalBranch {
                        target,
                        condition,
                        fallthrough: address + 4,
                    });

                Ok(DecodedInstruction { instruction: inst, size: 4 })
            }

            // Misc branches / system instructions
            0b110 => {
                // Classify based on bits 25:21 and other fields
                // bits 24:21 help further distinguish system instructions:
                // - 0011: Hints (NOP, YIELD, WFE, WFI, SEV, SEVL)
                // - 0100: Barriers (DSB, DMB, ISB, CLREX)
                // - Unconditional branch (register): bit 25=1
                // - Exception generating: bit 25=0, bit 24=0

                let op1_24_21 = (insn >> 21) & 0xF; // bits 24:21
                let bit25 = (insn >> 25) & 1;
                let bit24 = (insn >> 24) & 1;

                if bit25 == 1 && bit24 == 0 {
                    // Unconditional branch (register): BR, BLR, RET
                    let opc = (insn >> 21) & 0x7;
                    let rn = ((insn >> 5) & 0x1F) as u16;

                    let (mnemonic, operation, cf) = match opc {
                        0b000 => ("br", Operation::Jump, ControlFlow::IndirectBranch { possible_targets: vec![] }),
                        0b001 => ("blr", Operation::Call, ControlFlow::IndirectCall { return_addr: address + 4 }),
                        0b010 => ("ret", Operation::Return, ControlFlow::Return),
                        _ => return self.decode_unknown(insn, address, bytes),
                    };

                    let operands = if opc == 0b010 && rn == 30 {
                        // RET with x30 (default) - no operand needed
                        vec![]
                    } else {
                        vec![Operand::reg(Self::xreg(rn))]
                    };

                    let inst = Instruction::new(address, 4, bytes, mnemonic)
                        .with_operation(operation)
                        .with_operands(operands)
                        .with_control_flow(cf);

                    Ok(DecodedInstruction { instruction: inst, size: 4 })
                } else if bit25 == 0 && bit24 == 0 {
                    // Exception generating: SVC, HVC, SMC, BRK, HLT (0xD4xxxxxx)
                    let opc = (insn >> 21) & 0x7;
                    let imm16 = ((insn >> 5) & 0xFFFF) as u64;

                    let (mnemonic, cf) = match opc {
                        0b000 => ("svc", ControlFlow::Syscall),
                        0b001 => ("hvc", ControlFlow::Halt),
                        0b010 => ("smc", ControlFlow::Halt),
                        0b011 => ("brk", ControlFlow::Halt),
                        0b100 => ("hlt", ControlFlow::Halt),
                        _ => return self.decode_unknown(insn, address, bytes),
                    };

                    let inst = Instruction::new(address, 4, bytes, mnemonic)
                        .with_operation(if opc == 0 { Operation::Syscall } else { Operation::Halt })
                        .with_operand(Operand::imm_unsigned(imm16, 16))
                        .with_control_flow(cf);

                    Ok(DecodedInstruction { instruction: inst, size: 4 })
                } else if bit25 == 0 && bit24 == 1 && op1_24_21 == 0b0011 {
                    // Hints: NOP, YIELD, WFE, WFI, SEV, SEVL (0xD503xxxx)
                    let crm = (insn >> 8) & 0xF;
                    let op2 = (insn >> 5) & 0x7;

                    let mnemonic = if crm == 0 {
                        match op2 {
                            0b000 => "nop",
                            0b001 => "yield",
                            0b010 => "wfe",
                            0b011 => "wfi",
                            0b100 => "sev",
                            0b101 => "sevl",
                            _ => "hint",
                        }
                    } else {
                        "hint"
                    };

                    let inst = Instruction::new(address, 4, bytes, mnemonic)
                        .with_operation(Operation::Nop);

                    Ok(DecodedInstruction { instruction: inst, size: 4 })
                } else if bit25 == 0 && bit24 == 1 && op1_24_21 == 0b0100 {
                    // Barriers: DSB, DMB, ISB, CLREX (0xD503xxxx)
                    let op2 = (insn >> 5) & 0x7;

                    let mnemonic = match op2 {
                        0b001 => "clrex",
                        0b100 => "dsb",
                        0b101 => "dmb",
                        0b110 => "isb",
                        _ => "barrier",
                    };

                    let inst = Instruction::new(address, 4, bytes, mnemonic)
                        .with_operation(Operation::Other(0));

                    Ok(DecodedInstruction { instruction: inst, size: 4 })
                } else {
                    // Other system instructions: MSR, MRS, SYS, SYSL
                    self.decode_system_insn(insn, address, bytes)
                }
            }

            _ => self.decode_unknown(insn, address, bytes),
        }
    }

    /// Decode system instructions (NOP, hints, MSR, MRS).
    fn decode_system_insn(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let l = (insn >> 21) & 1;
        let op0 = (insn >> 19) & 0x3;
        let op1 = (insn >> 16) & 0x7;
        let crn = (insn >> 12) & 0xF;
        let crm = (insn >> 8) & 0xF;
        let op2 = (insn >> 5) & 0x7;

        // Check for NOP and hints
        if l == 0 && op0 == 0 && op1 == 3 && crn == 2 && crm == 0 {
            let mnemonic = match op2 {
                0b000 => "nop",
                0b001 => "yield",
                0b010 => "wfe",
                0b011 => "wfi",
                0b100 => "sev",
                0b101 => "sevl",
                _ => return self.decode_unknown(insn, address, bytes),
            };

            let inst = Instruction::new(address, 4, bytes, mnemonic)
                .with_operation(Operation::Nop);

            return Ok(DecodedInstruction { instruction: inst, size: 4 });
        }

        // MRS (read system register)
        if l == 1 {
            let rt = (insn & 0x1F) as u16;
            let inst = Instruction::new(address, 4, bytes, "mrs")
                .with_operation(Operation::Move)
                .with_operand(Operand::reg(Self::xreg(rt)));
            return Ok(DecodedInstruction { instruction: inst, size: 4 });
        }

        // MSR (write system register)
        let rt = (insn & 0x1F) as u16;
        let inst = Instruction::new(address, 4, bytes, "msr")
            .with_operation(Operation::Move)
            .with_operand(Operand::reg(Self::xreg(rt)));
        Ok(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Decode load/store instructions.
    fn decode_load_store(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        // ARM64 load/store encoding (bits 29-27 determine major class)
        let op_29_27 = (insn >> 27) & 0x7;
        let v = (insn >> 26) & 1;  // SIMD/FP if set
        let op_25_23 = (insn >> 23) & 0x7;
        let op_21 = (insn >> 21) & 1;
        let op_11_10 = (insn >> 10) & 0x3;

        // Load/store pair (bits 29-27 = 101)
        if op_29_27 == 0b101 {
            return self.decode_ldst_pair(insn, address, bytes);
        }

        // Load/store register variants (bits 29-27 = 111)
        if op_29_27 == 0b111 {
            // Atomic memory operations (ARMv8.1): bits 25-24 = 00, bit 21 = 1, V=0
            // Must check BEFORE unscaled/pre/post-indexed as they have the same bits 25-24
            // Pattern: size[31:30]=xx, 111000, A, R, 1, Rs, o3, opc[2:0], 00, Rn, Rt
            // V=0 distinguishes from SIMD/FP register offset loads which have V=1
            if (op_25_23 >> 1) == 0b00 && op_21 == 1 && v == 0 {
                return self.decode_atomic_memory(insn, address, bytes);
            }

            // Unsigned offset: bits 25-24 = 01
            if (op_25_23 >> 1) == 0b01 {
                return self.decode_ldst_unsigned_imm(insn, address, bytes);
            }
            // Unscaled immediate, pre/post-indexed: bits 25-24 = 00
            if (op_25_23 >> 1) == 0b00 {
                // bits 11-10 determine type: 00=unscaled, 01=post-index, 11=pre-index, 10=register
                if op_11_10 == 0b10 {
                    return self.decode_ldst_reg_offset(insn, address, bytes);
                } else if op_11_10 == 0b01 || op_11_10 == 0b11 {
                    return self.decode_ldst_imm_indexed(insn, address, bytes);
                } else {
                    // Unscaled immediate (LDUR/STUR)
                    return self.decode_ldst_unscaled(insn, address, bytes);
                }
            }
        }

        // Load literal (bits 29-27 = 011)
        // Handles both GPR (v=0) and SIMD/FP (v=1) literal loads
        if op_29_27 == 0b011 {
            return self.decode_ldr_literal(insn, address, bytes);
        }

        // Load/store exclusive: bits 31-24 = xx001000
        // Pattern: size[31:30]=xx, 001000, o2, L, o1, Rs, o0, Rt2, Rn, Rt
        let bits_29_24 = (insn >> 24) & 0x3F;
        if bits_29_24 == 0b001000 {
            return self.decode_ldst_exclusive(insn, address, bytes);
        }

        // Atomic memory operations (ARMv8.1): bits 31-24 = xx111000, bit 21 = 1
        // Pattern: size[31:30]=xx, 111000, A, R, 1, Rs, o3, opc[2:0], 00, Rn, Rt
        if bits_29_24 == 0b111000 && (insn >> 21) & 1 == 1 {
            return self.decode_atomic_memory(insn, address, bytes);
        }

        // Load/store exclusive and atomic operations - fall through to unknown
        self.decode_unknown(insn, address, bytes)
    }

    /// Decode LDUR/STUR (unscaled immediate).
    fn decode_ldst_unscaled(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let size = (insn >> 30) & 0x3;
        let v = (insn >> 26) & 1;
        let opc = (insn >> 22) & 0x3;
        let imm9 = ((insn >> 12) & 0x1FF) as i64;
        let imm9 = if imm9 & 0x100 != 0 { imm9 | !0x1FF } else { imm9 }; // Sign extend
        let rn = ((insn >> 5) & 0x1F) as u16;
        let rt = (insn & 0x1F) as u16;

        let (mnemonic, is_load, data_size, simd_size) = if v == 0 {
            match (size, opc) {
                (0, 0) => ("sturb", false, 1, None),
                (0, 1) => ("ldurb", true, 1, None),
                (1, 0) => ("sturh", false, 2, None),
                (1, 1) => ("ldurh", true, 2, None),
                (2, 0) => ("stur", false, 4, None),
                (2, 1) => ("ldur", true, 4, None),
                (3, 0) => ("stur", false, 8, None),
                (3, 1) => ("ldur", true, 8, None),
                _ => return self.decode_unknown(insn, address, bytes),
            }
        } else {
            // SIMD/FP unscaled immediate
            // size:opc determines register size:
            // 00:00 = STUR Bt, 00:01 = LDUR Bt (8-bit)
            // 01:00 = STUR Ht, 01:01 = LDUR Ht (16-bit)
            // 10:00 = STUR St, 10:01 = LDUR St (32-bit)
            // 11:00 = STUR Dt, 11:01 = LDUR Dt (64-bit)
            // 00:10 = STUR Qt, 00:11 = LDUR Qt (128-bit)
            let is_load = opc & 1 != 0;
            match (size, opc) {
                (0, 0) | (0, 1) => (if is_load { "ldur" } else { "stur" }, is_load, 1, Some(0u32)),   // B
                (0, 2) | (0, 3) => (if is_load { "ldur" } else { "stur" }, is_load, 16, Some(4u32)), // Q
                (1, 0) | (1, 1) => (if is_load { "ldur" } else { "stur" }, is_load, 2, Some(1u32)),   // H
                (2, 0) | (2, 1) => (if is_load { "ldur" } else { "stur" }, is_load, 4, Some(2u32)),   // S
                (3, 0) | (3, 1) => (if is_load { "ldur" } else { "stur" }, is_load, 8, Some(3u32)),   // D
                _ => return self.decode_unknown(insn, address, bytes),
            }
        };

        let (reg_rt, reg_base) = if v == 0 {
            if data_size == 8 {
                (Self::xreg(rt), Self::xreg_sp(rn))
            } else {
                (Self::wreg(rt), Self::xreg_sp(rn))
            }
        } else {
            // SIMD/FP register
            (Self::simd_reg(rt, simd_size.unwrap()), Self::xreg_sp(rn))
        };

        let mem = MemoryRef::base_disp(reg_base.clone(), imm9, data_size as u8);
        // Use consistent operand order: [Register, Memory] for both loads and stores
        // This matches the STR/LDR unsigned immediate encoding
        let operands = vec![Operand::reg(reg_rt), Operand::Memory(mem)];

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(if is_load { Operation::Load } else { Operation::Store })
            .with_operands(operands);

        Ok(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Decode LDR/STR with unsigned immediate offset.
    fn decode_ldst_unsigned_imm(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let size = (insn >> 30) & 0x3;
        let v = (insn >> 26) & 1;
        let opc = (insn >> 22) & 0x3;
        let imm12 = ((insn >> 10) & 0xFFF) as u64;
        let rn = ((insn >> 5) & 0x1F) as u16;
        let rt = (insn & 0x1F) as u16;

        if v == 1 {
            // SIMD/FP load/store with unsigned immediate offset
            // size:opc determines the register size:
            // 00:00 = STR Bt, 00:01 = LDR Bt (8-bit)
            // 01:00 = STR Ht, 01:01 = LDR Ht (16-bit)
            // 10:00 = STR St, 10:01 = LDR St (32-bit)
            // 11:00 = STR Dt, 11:01 = LDR Dt (64-bit)
            // 00:10 = STR Qt, 00:11 = LDR Qt (128-bit)
            let is_load = opc & 0b01 != 0;
            let (mnemonic, simd_size) = match (size, opc) {
                (0, 0b00) | (0, 0b01) => (if is_load { "ldr" } else { "str" }, 0), // B
                (0, 0b10) | (0, 0b11) => (if is_load { "ldr" } else { "str" }, 4), // Q
                (1, _) => (if is_load { "ldr" } else { "str" }, 1), // H
                (2, _) => (if is_load { "ldr" } else { "str" }, 2), // S
                (3, _) => (if is_load { "ldr" } else { "str" }, 3), // D
                _ => return self.decode_unknown(insn, address, bytes),
            };

            let scale = if simd_size == 4 { 4 } else { simd_size }; // Q is 16 bytes = 2^4
            let offset = imm12 << scale;
            let access_size = 1u8 << scale;

            let reg = Self::simd_reg(rt, simd_size);
            let base = Self::xreg_sp(rn);
            let mem = if offset == 0 {
                MemoryRef::base(base, access_size)
            } else {
                MemoryRef::base_disp(base, offset as i64, access_size)
            };

            let operation = if is_load { Operation::Load } else { Operation::Store };
            let inst = Instruction::new(address, 4, bytes, mnemonic)
                .with_operation(operation)
                .with_operands(vec![Operand::reg(reg), Operand::Memory(mem)]);

            return Ok(DecodedInstruction { instruction: inst, size: 4 });
        }

        let scale = size;
        let offset = imm12 << scale;
        // opc encoding: 00=store, 01=load, 10=ldrsw/prfm, 11=signed loads
        // Only opc=00 is a store; all others are loads
        let is_load = opc != 0b00;
        let is_signed = opc & 0b10 != 0;

        let access_size = 1u8 << size;
        // Signed loads (ldrsb, ldrsh, ldrsw) always produce 64-bit results in X registers
        let is_64bit = size == 3 || is_signed;

        let (mnemonic, operation) = match (is_load, is_signed, size) {
            (true, false, 0) => ("ldrb", Operation::Load),
            (true, false, 1) => ("ldrh", Operation::Load),
            (true, false, 2) => ("ldr", Operation::Load),  // 32-bit
            (true, false, 3) => ("ldr", Operation::Load),  // 64-bit
            (true, true, 0) => ("ldrsb", Operation::Load),
            (true, true, 1) => ("ldrsh", Operation::Load),
            (true, true, 2) => ("ldrsw", Operation::Load),
            (false, _, 0) => ("strb", Operation::Store),
            (false, _, 1) => ("strh", Operation::Store),
            (false, _, 2) => ("str", Operation::Store),
            (false, _, 3) => ("str", Operation::Store),
            _ => return self.decode_unknown(insn, address, bytes),
        };

        let reg = if is_64bit || size == 3 { Self::xreg(rt) } else { Self::wreg(rt) };
        let base = Self::xreg_sp(rn);
        let mem = if offset == 0 {
            MemoryRef::base(base, access_size)
        } else {
            MemoryRef::base_disp(base, offset as i64, access_size)
        };

        let operands = vec![Operand::reg(reg), Operand::Memory(mem)];

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(operation)
            .with_operands(operands);

        Ok(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Decode load/store register pair (LDP, STP).
    fn decode_ldst_pair(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let opc = (insn >> 30) & 0x3;
        let v = (insn >> 26) & 1;
        let l = (insn >> 22) & 1;
        let imm7 = ((insn >> 15) & 0x7F) as i64;
        let rt2 = ((insn >> 10) & 0x1F) as u16;
        let rn = ((insn >> 5) & 0x1F) as u16;
        let rt = (insn & 0x1F) as u16;

        if v == 1 {
            // SIMD/FP pair load/store
            // opc determines register size: 00=S(32), 01=D(64), 10=Q(128)
            let is_load = l == 1;
            let (simd_size, scale) = match opc {
                0b00 => (2u32, 2u32), // S register, 4 bytes, scale=2
                0b01 => (3, 3),       // D register, 8 bytes, scale=3
                0b10 => (4, 4),       // Q register, 16 bytes, scale=4
                _ => return self.decode_unknown(insn, address, bytes),
            };

            let offset = sign_extend((imm7 << scale) as u64, 7 + scale as u8);
            let access_size = (1u8 << scale) * 2; // Pair access

            let mnemonic = if is_load { "ldp" } else { "stp" };
            let reg1 = Self::simd_reg(rt, simd_size);
            let reg2 = Self::simd_reg(rt2, simd_size);
            let base = Self::xreg_sp(rn);

            let mem = if offset == 0 {
                MemoryRef::base(base, access_size)
            } else {
                MemoryRef::base_disp(base, offset, access_size)
            };

            let operation = if is_load { Operation::Load } else { Operation::Store };
            let inst = Instruction::new(address, 4, bytes, mnemonic)
                .with_operation(operation)
                .with_operands(vec![Operand::reg(reg1), Operand::reg(reg2), Operand::Memory(mem)]);

            return Ok(DecodedInstruction { instruction: inst, size: 4 });
        }

        let is_load = l == 1;
        let is_64bit = opc & 0b10 != 0;
        let scale = if is_64bit { 3 } else { 2 };
        let offset = sign_extend((imm7 << scale) as u64, 7 + scale);

        let mnemonic = if is_load { "ldp" } else { "stp" };
        let reg1 = if is_64bit { Self::xreg(rt) } else { Self::wreg(rt) };
        let reg2 = if is_64bit { Self::xreg(rt2) } else { Self::wreg(rt2) };
        let base = Self::xreg_sp(rn);

        let mem = if offset == 0 {
            MemoryRef::base(base, if is_64bit { 16 } else { 8 })
        } else {
            MemoryRef::base_disp(base, offset, if is_64bit { 16 } else { 8 })
        };

        let operands = vec![Operand::reg(reg1), Operand::reg(reg2), Operand::Memory(mem)];

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(if is_load { Operation::Load } else { Operation::Store })
            .with_operands(operands);

        Ok(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Decode load/store with register offset.
    fn decode_ldst_reg_offset(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let size = (insn >> 30) & 0x3;
        let v = (insn >> 26) & 1;
        let opc = (insn >> 22) & 0x3;
        let rm = ((insn >> 16) & 0x1F) as u16;
        let option = (insn >> 13) & 0x7;
        let s = (insn >> 12) & 1;
        let rn = ((insn >> 5) & 0x1F) as u16;
        let rt = (insn & 0x1F) as u16;

        let is_load = opc & 1 == 1;

        if v == 1 {
            // SIMD/FP load/store with register offset
            // size:opc determines register size:
            // 00:00 = STR Bt, 00:01 = LDR Bt (8-bit)
            // 01:00 = STR Ht, 01:01 = LDR Ht (16-bit)
            // 10:00 = STR St, 10:01 = LDR St (32-bit)
            // 11:00 = STR Dt, 11:01 = LDR Dt (64-bit)
            // 00:10 = STR Qt, 00:11 = LDR Qt (128-bit)
            let (simd_size, scale) = match (size, opc) {
                (0, 0) | (0, 1) => (0u32, 0u32), // B register, 1 byte
                (0, 2) | (0, 3) => (4, 4),       // Q register, 16 bytes
                (1, 0) | (1, 1) => (1, 1),       // H register, 2 bytes
                (2, 0) | (2, 1) => (2, 2),       // S register, 4 bytes
                (3, 0) | (3, 1) => (3, 3),       // D register, 8 bytes
                _ => return self.decode_unknown(insn, address, bytes),
            };

            let access_size = 1u8 << scale;
            let shift_amount = if s == 1 { scale as u8 } else { 0 };

            let mnemonic = if is_load { "ldr" } else { "str" };
            let reg = Self::simd_reg(rt, simd_size);
            let base = Self::xreg_sp(rn);
            let index = if option & 0b011 == 0b011 {
                Self::xreg(rm)
            } else {
                Self::wreg(rm)
            };

            let mem = MemoryRef::sib(Some(base), Some(index), 1 << shift_amount, 0, access_size);
            let operands = vec![Operand::reg(reg), Operand::Memory(mem)];

            let inst = Instruction::new(address, 4, bytes, mnemonic)
                .with_operation(if is_load { Operation::Load } else { Operation::Store })
                .with_operands(operands);

            return Ok(DecodedInstruction { instruction: inst, size: 4 });
        }

        let access_size = 1u8 << size;
        let is_64bit = size == 3;

        let mnemonic = if is_load {
            match size {
                0 => "ldrb",
                1 => "ldrh",
                2 | 3 => "ldr",
                _ => unreachable!(),
            }
        } else {
            match size {
                0 => "strb",
                1 => "strh",
                2 | 3 => "str",
                _ => unreachable!(),
            }
        };

        let reg = if is_64bit { Self::xreg(rt) } else { Self::wreg(rt) };
        let base = Self::xreg_sp(rn);
        let index = if option & 0b011 == 0b011 {
            Self::xreg(rm)
        } else {
            Self::wreg(rm)
        };

        let scale = if s == 1 { size as u8 } else { 0 };
        let mem = MemoryRef::sib(Some(base), Some(index), 1 << scale, 0, access_size);

        let operands = vec![Operand::reg(reg), Operand::Memory(mem)];

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(if is_load { Operation::Load } else { Operation::Store })
            .with_operands(operands);

        Ok(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Decode load/store with immediate pre/post-indexed.
    fn decode_ldst_imm_indexed(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let size = (insn >> 30) & 0x3;
        let v = (insn >> 26) & 1;
        let opc = (insn >> 22) & 0x3;
        let imm9 = ((insn >> 12) & 0x1FF) as i64;
        let rn = ((insn >> 5) & 0x1F) as u16;
        let rt = (insn & 0x1F) as u16;
        let _is_pre = (insn >> 11) & 1 == 1;

        let is_load = opc & 1 == 1;
        let offset = sign_extend(imm9 as u64, 9);

        if v == 1 {
            // SIMD/FP load/store with pre/post-indexed immediate
            // size:opc determines register size:
            // 00:00 = STR Bt, 00:01 = LDR Bt (8-bit)
            // 01:00 = STR Ht, 01:01 = LDR Ht (16-bit)
            // 10:00 = STR St, 10:01 = LDR St (32-bit)
            // 11:00 = STR Dt, 11:01 = LDR Dt (64-bit)
            // 00:10 = STR Qt, 00:11 = LDR Qt (128-bit)
            let (simd_size, scale) = match (size, opc) {
                (0, 0) | (0, 1) => (0u32, 0u32), // B register, 1 byte
                (0, 2) | (0, 3) => (4, 4),       // Q register, 16 bytes
                (1, 0) | (1, 1) => (1, 1),       // H register, 2 bytes
                (2, 0) | (2, 1) => (2, 2),       // S register, 4 bytes
                (3, 0) | (3, 1) => (3, 3),       // D register, 8 bytes
                _ => return self.decode_unknown(insn, address, bytes),
            };

            let access_size = 1u8 << scale;
            let mnemonic = if is_load { "ldr" } else { "str" };
            let reg = Self::simd_reg(rt, simd_size);
            let base = Self::xreg_sp(rn);
            let mem = MemoryRef::base_disp(base, offset, access_size);

            let operands = vec![Operand::reg(reg), Operand::Memory(mem)];

            let inst = Instruction::new(address, 4, bytes, mnemonic)
                .with_operation(if is_load { Operation::Load } else { Operation::Store })
                .with_operands(operands);

            return Ok(DecodedInstruction { instruction: inst, size: 4 });
        }

        let access_size = 1u8 << size;
        let is_64bit = size == 3;

        let base_mnemonic = if is_load {
            match size {
                0 => "ldrb",
                1 => "ldrh",
                2 | 3 => "ldr",
                _ => unreachable!(),
            }
        } else {
            match size {
                0 => "strb",
                1 => "strh",
                2 | 3 => "str",
                _ => unreachable!(),
            }
        };

        // For display, we'd normally add ! for pre-indexed, but we'll just use the mnemonic
        let reg = if is_64bit { Self::xreg(rt) } else { Self::wreg(rt) };
        let base = Self::xreg_sp(rn);
        let mem = MemoryRef::base_disp(base, offset, access_size);

        let operands = vec![Operand::reg(reg), Operand::Memory(mem)];

        let inst = Instruction::new(address, 4, bytes, base_mnemonic)
            .with_operation(if is_load { Operation::Load } else { Operation::Store })
            .with_operands(operands);

        Ok(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Decode LDR (literal) - PC-relative load.
    fn decode_ldr_literal(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let opc = (insn >> 30) & 0x3;
        let v = (insn >> 26) & 1;
        let imm19 = ((insn >> 5) & 0x7FFFF) as i64;
        let rt = (insn & 0x1F) as u16;

        let offset = sign_extend((imm19 << 2) as u64, 21);
        let target = (address as i64 + offset) as u64;

        if v == 1 {
            // SIMD/FP literal load
            // opc: 00=S(32-bit), 01=D(64-bit), 10=Q(128-bit), 11=reserved
            let reg = match opc {
                0b00 => Self::sreg(rt),  // LDR S<t>, <label>
                0b01 => Self::dreg(rt),  // LDR D<t>, <label>
                0b10 => Self::qreg(rt),  // LDR Q<t>, <label>
                _ => return self.decode_unknown(insn, address, bytes),
            };

            let inst = Instruction::new(address, 4, bytes, "ldr")
                .with_operation(Operation::Load)
                .with_operands(vec![Operand::reg(reg), Operand::pc_rel(offset, target)]);

            return Ok(DecodedInstruction { instruction: inst, size: 4 });
        }

        let (mnemonic, is_64bit) = match opc {
            0b00 => ("ldr", false),
            0b01 => ("ldr", true),
            0b10 => ("ldrsw", true),
            _ => return self.decode_unknown(insn, address, bytes),
        };

        let reg = if is_64bit { Self::xreg(rt) } else { Self::wreg(rt) };

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(Operation::Load)
            .with_operands(vec![Operand::reg(reg), Operand::pc_rel(offset, target)]);

        Ok(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Decode load/store exclusive instructions (LDXR, STXR, LDXP, STXP, LDAXR, STLXR, etc.).
    fn decode_ldst_exclusive(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        // Encoding: size[31:30], 001000, o2, L, o1, Rs, o0, Rt2, Rn, Rt
        let size = (insn >> 30) & 0x3;
        let o2 = (insn >> 23) & 1;   // 0=exclusive, 1=ordered (LDAPR/STLR)
        let l = (insn >> 22) & 1;    // Load/store: 1=load, 0=store
        let o1 = (insn >> 21) & 1;   // Pair: 1=pair
        let rs = ((insn >> 16) & 0x1F) as u16;  // Status register (for store)
        let o0 = (insn >> 15) & 1;   // Acquire-release: 1=acquire/release
        let rt2 = ((insn >> 10) & 0x1F) as u16; // Second register (for pair)
        let rn = ((insn >> 5) & 0x1F) as u16;   // Base register
        let rt = (insn & 0x1F) as u16;          // Data register

        let is_pair = o1 == 1;
        let is_load = l == 1;
        let is_acquire_release = o0 == 1;
        let is_ordered = o2 == 1;

        // Determine register size from size field
        let is_64bit = size == 3 || (is_pair && size == 2);
        let access_size = match size {
            0 => 1u8,  // byte
            1 => 2,    // halfword
            2 => 4,    // word
            3 => 8,    // doubleword
            _ => 4,
        };

        // Build mnemonic based on instruction type
        let mnemonic = if is_ordered && !is_pair {
            // Load-acquire / Store-release (non-exclusive ordered access)
            match (is_load, size) {
                (true, 0) => if is_acquire_release { "ldarb" } else { "ldlarb" },
                (true, 1) => if is_acquire_release { "ldarh" } else { "ldlarh" },
                (true, 2) => if is_acquire_release { "ldar" } else { "ldlar" },
                (true, 3) => if is_acquire_release { "ldar" } else { "ldlar" },
                (false, 0) => if is_acquire_release { "stlrb" } else { "stllrb" },
                (false, 1) => if is_acquire_release { "stlrh" } else { "stllrh" },
                (false, 2) => if is_acquire_release { "stlr" } else { "stllr" },
                (false, 3) => if is_acquire_release { "stlr" } else { "stllr" },
                _ => "unknown",
            }
        } else if is_pair {
            // Exclusive pair
            match (is_load, is_acquire_release, size) {
                (true, false, 2) => "ldxp",
                (true, false, 3) => "ldxp",
                (true, true, 2) => "ldaxp",
                (true, true, 3) => "ldaxp",
                (false, false, 2) => "stxp",
                (false, false, 3) => "stxp",
                (false, true, 2) => "stlxp",
                (false, true, 3) => "stlxp",
                _ => "unknown",
            }
        } else {
            // Single exclusive
            match (is_load, is_acquire_release, size) {
                (true, false, 0) => "ldxrb",
                (true, false, 1) => "ldxrh",
                (true, false, 2) => "ldxr",
                (true, false, 3) => "ldxr",
                (true, true, 0) => "ldaxrb",
                (true, true, 1) => "ldaxrh",
                (true, true, 2) => "ldaxr",
                (true, true, 3) => "ldaxr",
                (false, false, 0) => "stxrb",
                (false, false, 1) => "stxrh",
                (false, false, 2) => "stxr",
                (false, false, 3) => "stxr",
                (false, true, 0) => "stlxrb",
                (false, true, 1) => "stlxrh",
                (false, true, 2) => "stlxr",
                (false, true, 3) => "stlxr",
                _ => "unknown",
            }
        };

        let base = Self::xreg_sp(rn);
        let mem = MemoryRef::base(base, access_size);

        let operands = if is_load {
            if is_pair {
                // LDXP/LDAXP: Rt, Rt2, [Xn|SP]
                let reg1 = if is_64bit { Self::xreg(rt) } else { Self::wreg(rt) };
                let reg2 = if is_64bit { Self::xreg(rt2) } else { Self::wreg(rt2) };
                vec![Operand::reg(reg1), Operand::reg(reg2), Operand::Memory(mem)]
            } else if is_ordered {
                // LDAR/LDLAR: Rt, [Xn|SP]
                let reg = if is_64bit { Self::xreg(rt) } else { Self::wreg(rt) };
                vec![Operand::reg(reg), Operand::Memory(mem)]
            } else {
                // LDXR/LDAXR: Rt, [Xn|SP]
                let reg = if is_64bit { Self::xreg(rt) } else { Self::wreg(rt) };
                vec![Operand::reg(reg), Operand::Memory(mem)]
            }
        } else if is_pair {
            // STXP/STLXP: Ws, Wt, Wt2, [Xn|SP]  (Ws is status)
            let status = Self::wreg(rs);
            let reg1 = if is_64bit { Self::xreg(rt) } else { Self::wreg(rt) };
            let reg2 = if is_64bit { Self::xreg(rt2) } else { Self::wreg(rt2) };
            vec![Operand::reg(status), Operand::reg(reg1), Operand::reg(reg2), Operand::Memory(mem)]
        } else if is_ordered && !is_acquire_release {
            // STLLR: Rt, [Xn|SP] (no status register)
            let reg = if is_64bit { Self::xreg(rt) } else { Self::wreg(rt) };
            vec![Operand::reg(reg), Operand::Memory(mem)]
        } else if is_ordered {
            // STLR: Rt, [Xn|SP]
            let reg = if is_64bit { Self::xreg(rt) } else { Self::wreg(rt) };
            vec![Operand::reg(reg), Operand::Memory(mem)]
        } else {
            // STXR/STLXR: Ws, Wt, [Xn|SP]  (Ws is status)
            let status = Self::wreg(rs);
            let reg = if is_64bit { Self::xreg(rt) } else { Self::wreg(rt) };
            vec![Operand::reg(status), Operand::reg(reg), Operand::Memory(mem)]
        };

        let operation = if is_load {
            Operation::LoadExclusive
        } else {
            Operation::StoreExclusive
        };

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(operation)
            .with_operands(operands);

        Ok(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Decode atomic memory operations (ARMv8.1 atomics: LDADD, LDCLR, LDEOR, LDSET, SWP, CAS, etc.).
    fn decode_atomic_memory(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        // Encoding: size[31:30], 111000, A, R, 1, Rs, o3, opc[2:0], 00, Rn, Rt
        let size = (insn >> 30) & 0x3;
        let a = (insn >> 23) & 1;    // Acquire
        let r = (insn >> 22) & 1;    // Release
        let rs = ((insn >> 16) & 0x1F) as u16;  // Source register
        let o3 = (insn >> 15) & 1;   // 0 for most atomics, 1 for SWP
        let opc = (insn >> 12) & 0x7; // Operation code
        let rn = ((insn >> 5) & 0x1F) as u16;   // Base register
        let rt = (insn & 0x1F) as u16;          // Destination register

        let is_64bit = size == 3;
        let access_size = 1u8 << size;

        // Build acquire-release suffix
        let ar_suffix = match (a, r) {
            (0, 0) => "",
            (1, 0) => "a",   // Acquire
            (0, 1) => "l",   // Release
            (1, 1) => "al",  // Acquire-release
            _ => "",
        };

        // Size suffix
        let size_suffix = match size {
            0 => "b",
            1 => "h",
            _ => "",
        };

        // Determine instruction and operation based on o3 and opc
        let (base_mnemonic, operation) = if o3 == 0 {
            match opc {
                0b000 => ("ldadd", Operation::AtomicAdd),
                0b001 => ("ldclr", Operation::AtomicClear),
                0b010 => ("ldeor", Operation::AtomicXor),
                0b011 => ("ldset", Operation::AtomicSet),
                0b100 => ("ldsmax", Operation::AtomicSignedMax),
                0b101 => ("ldsmin", Operation::AtomicSignedMin),
                0b110 => ("ldumax", Operation::AtomicUnsignedMax),
                0b111 => ("ldumin", Operation::AtomicUnsignedMin),
                _ => ("atomic", Operation::Other(0)),
            }
        } else {
            // o3 == 1: SWP or special variants
            match opc {
                0b000 => ("swp", Operation::AtomicSwap),
                _ => ("atomic", Operation::Other(0)),
            }
        };

        // Build full mnemonic
        let mnemonic = format!("{}{}{}", base_mnemonic, ar_suffix, size_suffix);

        let base = Self::xreg_sp(rn);
        let mem = MemoryRef::base(base, access_size);
        let src = if is_64bit { Self::xreg(rs) } else { Self::wreg(rs) };
        let dst = if is_64bit { Self::xreg(rt) } else { Self::wreg(rt) };

        // Operands: Rs (source/operand), Rt (destination/old value), [Xn|SP]
        let operands = vec![Operand::reg(src), Operand::reg(dst), Operand::Memory(mem)];

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(operation)
            .with_operands(operands);

        Ok(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Decode compare and swap instructions (CAS, CASP - ARMv8.1).
    #[allow(dead_code)]
    fn decode_compare_and_swap(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        // CAS encoding: size[31:30], 0010001, L, 1, Rs, o0, 11111, Rn, Rt
        // CASP encoding: 0, sz, 0010000, L, 1, Rs, o0, 11111, Rn, Rt
        let size = (insn >> 30) & 0x3;
        let l = (insn >> 22) & 1;    // 1=Acquire
        let rs = ((insn >> 16) & 0x1F) as u16;  // Compare value register
        let o0 = (insn >> 15) & 1;   // 1=Release
        let rn = ((insn >> 5) & 0x1F) as u16;   // Base register
        let rt = (insn & 0x1F) as u16;          // Destination/swap value register

        let is_64bit = size == 3;
        let access_size = 1u8 << size;

        // Build acquire-release suffix
        let ar_suffix = match (l, o0) {
            (0, 0) => "",
            (1, 0) => "a",   // Acquire
            (0, 1) => "l",   // Release
            (1, 1) => "al",  // Acquire-release
            _ => "",
        };

        // Size suffix
        let size_suffix = match size {
            0 => "b",
            1 => "h",
            _ => "",
        };

        let mnemonic = format!("cas{}{}", ar_suffix, size_suffix);

        let base = Self::xreg_sp(rn);
        let mem = MemoryRef::base(base, access_size);
        let compare_reg = if is_64bit { Self::xreg(rs) } else { Self::wreg(rs) };
        let swap_reg = if is_64bit { Self::xreg(rt) } else { Self::wreg(rt) };

        // Operands: Xs (compare), Xt (swap/result), [Xn|SP]
        let operands = vec![Operand::reg(compare_reg), Operand::reg(swap_reg), Operand::Memory(mem)];

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(Operation::CompareAndSwap)
            .with_operands(operands);

        Ok(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Decode data processing - register instructions.
    fn decode_dp_reg(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let op0 = (insn >> 30) & 1;
        let op1 = (insn >> 28) & 1;
        let op2 = (insn >> 21) & 0xF;

        // Logical (shifted register)
        if op1 == 0 && (op2 & 0b1000) == 0 {
            return self.decode_logical_shifted_reg(insn, address, bytes);
        }

        // Add/subtract (shifted register)
        if op1 == 0 && (op2 & 0b1001) == 0b1000 {
            return self.decode_add_sub_shifted_reg(insn, address, bytes);
        }

        // Add/subtract (extended register)
        if op1 == 0 && (op2 & 0b1001) == 0b1001 {
            return self.decode_add_sub_extended_reg(insn, address, bytes);
        }

        // Data processing (2 source)
        if op1 == 1 && op2 == 0b0110 {
            return self.decode_dp_2source(insn, address, bytes);
        }

        // Data processing (1 source)
        if op1 == 1 && op2 == 0b0000 {
            return self.decode_dp_1source(insn, address, bytes);
        }

        // Conditional select
        if op1 == 1 && (op2 & 0b1110) == 0b0100 {
            return self.decode_cond_select(insn, address, bytes);
        }

        // Data processing (3 source) - MUL, MADD, MSUB, etc.
        if op1 == 1 && (op2 & 0b1000) == 0b1000 {
            return self.decode_dp_3source(insn, address, bytes);
        }

        self.decode_unknown(insn, address, bytes)
    }

    /// Decode logical (shifted register).
    fn decode_logical_shifted_reg(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let sf = (insn >> 31) & 1 == 1;
        let opc = (insn >> 29) & 0x3;
        let shift = (insn >> 22) & 0x3;
        let n = (insn >> 21) & 1;
        let rm = ((insn >> 16) & 0x1F) as u16;
        let imm6 = ((insn >> 10) & 0x3F) as u8;
        let rn = ((insn >> 5) & 0x1F) as u16;
        let rd = (insn & 0x1F) as u16;

        let (base_mnemonic, operation, set_flags) = match (opc, n) {
            (0b00, 0) => ("and", Operation::And, false),
            (0b00, 1) => ("bic", Operation::And, false),  // AND NOT
            (0b01, 0) => ("orr", Operation::Or, false),
            (0b01, 1) => ("orn", Operation::Or, false),   // OR NOT
            (0b10, 0) => ("eor", Operation::Xor, false),
            (0b10, 1) => ("eon", Operation::Xor, false),  // XOR NOT
            (0b11, 0) => ("ands", Operation::And, true),
            (0b11, 1) => ("bics", Operation::And, true),
            _ => unreachable!(),
        };

        let dst = if sf { Self::xreg(rd) } else { Self::wreg(rd) };
        let src1 = if sf { Self::xreg(rn) } else { Self::wreg(rn) };
        let src2 = if sf { Self::xreg(rm) } else { Self::wreg(rm) };

        // Check for MOV alias (ORR with zero register)
        let (mnemonic, operands) = if opc == 0b01 && n == 0 && rn == 31 && imm6 == 0 {
            ("mov", vec![Operand::reg(dst), Operand::reg(src2)])
        } else if opc == 0b01 && n == 1 && rn == 31 && imm6 == 0 {
            ("mvn", vec![Operand::reg(dst), Operand::reg(src2)])
        } else if set_flags && rd == 31 {
            // TST alias
            ("tst", vec![Operand::reg(src1), Operand::reg(src2)])
        } else if imm6 == 0 {
            (base_mnemonic, vec![Operand::reg(dst), Operand::reg(src1), Operand::reg(src2)])
        } else {
            let shift_type = match shift {
                0 => "lsl",
                1 => "lsr",
                2 => "asr",
                3 => "ror",
                _ => unreachable!(),
            };
            // Include shift in mnemonic for now
            (base_mnemonic, vec![
                Operand::reg(dst),
                Operand::reg(src1),
                Operand::reg(src2),
                Operand::imm_unsigned(imm6 as u64, 8),
            ])
        };

        let final_operation = if mnemonic == "mov" || mnemonic == "mvn" {
            Operation::Move
        } else if mnemonic == "tst" {
            Operation::Test
        } else {
            operation
        };

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(final_operation)
            .with_operands(operands);

        Ok(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Decode add/subtract (shifted register).
    fn decode_add_sub_shifted_reg(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let sf = (insn >> 31) & 1 == 1;
        let op = (insn >> 30) & 1;
        let s = (insn >> 29) & 1;
        let shift = (insn >> 22) & 0x3;
        let rm = ((insn >> 16) & 0x1F) as u16;
        let imm6 = ((insn >> 10) & 0x3F) as u8;
        let rn = ((insn >> 5) & 0x1F) as u16;
        let rd = (insn & 0x1F) as u16;

        let is_sub = op == 1;
        let set_flags = s == 1;

        let dst = if sf { Self::xreg(rd) } else { Self::wreg(rd) };
        let src1 = if sf { Self::xreg(rn) } else { Self::wreg(rn) };
        let src2 = if sf { Self::xreg(rm) } else { Self::wreg(rm) };

        // Check for CMP/CMN aliases
        let (mnemonic, operands, operation) = if set_flags && rd == 31 {
            let mnem = if is_sub { "cmp" } else { "cmn" };
            if imm6 == 0 {
                (mnem, vec![Operand::reg(src1), Operand::reg(src2)], Operation::Compare)
            } else {
                (mnem, vec![Operand::reg(src1), Operand::reg(src2), Operand::imm_unsigned(imm6 as u64, 8)], Operation::Compare)
            }
        } else if !set_flags && is_sub && rn == 31 {
            // NEG alias
            ("neg", vec![Operand::reg(dst), Operand::reg(src2)], Operation::Neg)
        } else {
            let mnem = match (is_sub, set_flags) {
                (false, false) => "add",
                (false, true) => "adds",
                (true, false) => "sub",
                (true, true) => "subs",
            };
            let op = if is_sub { Operation::Sub } else { Operation::Add };
            if imm6 == 0 {
                (mnem, vec![Operand::reg(dst), Operand::reg(src1), Operand::reg(src2)], op)
            } else {
                (mnem, vec![Operand::reg(dst), Operand::reg(src1), Operand::reg(src2), Operand::imm_unsigned(imm6 as u64, 8)], op)
            }
        };

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(operation)
            .with_operands(operands);

        Ok(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Decode add/subtract (extended register).
    fn decode_add_sub_extended_reg(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let sf = (insn >> 31) & 1 == 1;
        let op = (insn >> 30) & 1;
        let s = (insn >> 29) & 1;
        let rm = ((insn >> 16) & 0x1F) as u16;
        let option = (insn >> 13) & 0x7;
        let imm3 = ((insn >> 10) & 0x7) as u8;
        let rn = ((insn >> 5) & 0x1F) as u16;
        let rd = (insn & 0x1F) as u16;

        let is_sub = op == 1;
        let set_flags = s == 1;

        let dst = if sf { Self::xreg(rd) } else { Self::wreg(rd) };
        let src1 = if sf { Self::xreg(rn) } else { Self::wreg(rn) };
        let src2 = if option & 0b011 == 0b011 && sf {
            Self::xreg(rm)
        } else {
            Self::wreg(rm)
        };

        let mnemonic = match (is_sub, set_flags) {
            (false, false) => "add",
            (false, true) => "adds",
            (true, false) => "sub",
            (true, true) => "subs",
        };

        let operands = vec![Operand::reg(dst), Operand::reg(src1), Operand::reg(src2)];

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(if is_sub { Operation::Sub } else { Operation::Add })
            .with_operands(operands);

        Ok(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Decode data processing (2 source) - UDIV, SDIV, LSLV, etc.
    fn decode_dp_2source(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let sf = (insn >> 31) & 1 == 1;
        let opcode = (insn >> 10) & 0x3F;
        let rm = ((insn >> 16) & 0x1F) as u16;
        let rn = ((insn >> 5) & 0x1F) as u16;
        let rd = (insn & 0x1F) as u16;

        let (mnemonic, operation) = match opcode {
            0b000010 => ("udiv", Operation::Div),
            0b000011 => ("sdiv", Operation::Div),
            0b001000 => ("lslv", Operation::Shl),
            0b001001 => ("lsrv", Operation::Shr),
            0b001010 => ("asrv", Operation::Sar),
            0b001011 => ("rorv", Operation::Ror),
            _ => return self.decode_unknown(insn, address, bytes),
        };

        let dst = if sf { Self::xreg(rd) } else { Self::wreg(rd) };
        let src1 = if sf { Self::xreg(rn) } else { Self::wreg(rn) };
        let src2 = if sf { Self::xreg(rm) } else { Self::wreg(rm) };

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(operation)
            .with_operands(vec![Operand::reg(dst), Operand::reg(src1), Operand::reg(src2)]);

        Ok(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Decode data processing (1 source) - REV, CLZ, etc.
    fn decode_dp_1source(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let sf = (insn >> 31) & 1 == 1;
        let opcode = (insn >> 10) & 0x3F;
        let rn = ((insn >> 5) & 0x1F) as u16;
        let rd = (insn & 0x1F) as u16;

        let mnemonic = match opcode {
            0b000000 => "rbit",
            0b000001 => "rev16",
            0b000010 => if sf { "rev32" } else { "rev" },
            0b000011 => "rev",
            0b000100 => "clz",
            0b000101 => "cls",
            _ => return self.decode_unknown(insn, address, bytes),
        };

        let dst = if sf { Self::xreg(rd) } else { Self::wreg(rd) };
        let src = if sf { Self::xreg(rn) } else { Self::wreg(rn) };

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(Operation::Other(0))
            .with_operands(vec![Operand::reg(dst), Operand::reg(src)]);

        Ok(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Decode conditional select (CSEL, CSINC, CSINV, CSNEG).
    fn decode_cond_select(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let sf = (insn >> 31) & 1 == 1;
        let op = (insn >> 30) & 1;
        let op2 = (insn >> 10) & 0x3;
        let rm = ((insn >> 16) & 0x1F) as u16;
        let cond = ((insn >> 12) & 0xF) as u8;
        let rn = ((insn >> 5) & 0x1F) as u16;
        let rd = (insn & 0x1F) as u16;

        let mnemonic = match (op, op2) {
            (0, 0b00) => "csel",
            (0, 0b01) => "csinc",
            (1, 0b00) => "csinv",
            (1, 0b01) => "csneg",
            _ => return self.decode_unknown(insn, address, bytes),
        };

        let dst = if sf { Self::xreg(rd) } else { Self::wreg(rd) };
        let src1 = if sf { Self::xreg(rn) } else { Self::wreg(rn) };
        let src2 = if sf { Self::xreg(rm) } else { Self::wreg(rm) };
        let (cond_str, _) = decode_condition(cond);

        // Check for aliases
        let (final_mnemonic, operands) = if op == 0 && op2 == 0b01 && rn == rm && cond & 0xE != 0xE {
            // CINC alias
            if rn == 31 {
                // CSET
                ("cset", vec![Operand::reg(dst)])
            } else {
                ("cinc", vec![Operand::reg(dst), Operand::reg(src1)])
            }
        } else if op == 1 && op2 == 0b00 && rn == rm && cond & 0xE != 0xE {
            // CINV alias
            if rn == 31 {
                ("csetm", vec![Operand::reg(dst)])
            } else {
                ("cinv", vec![Operand::reg(dst), Operand::reg(src1)])
            }
        } else if op == 1 && op2 == 0b01 && rn == rm && cond & 0xE != 0xE {
            // CNEG alias
            ("cneg", vec![Operand::reg(dst), Operand::reg(src1)])
        } else {
            (mnemonic, vec![Operand::reg(dst), Operand::reg(src1), Operand::reg(src2)])
        };

        let inst = Instruction::new(address, 4, bytes, final_mnemonic)
            .with_operation(Operation::Move)
            .with_operands(operands);

        Ok(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Decode data processing (3 source) - MADD, MSUB, MUL, etc.
    fn decode_dp_3source(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let sf = (insn >> 31) & 1 == 1;
        let op54 = (insn >> 29) & 0x3;
        let op31 = (insn >> 21) & 0x7;
        let o0 = (insn >> 15) & 1;
        let rm = ((insn >> 16) & 0x1F) as u16;
        let ra = ((insn >> 10) & 0x1F) as u16;
        let rn = ((insn >> 5) & 0x1F) as u16;
        let rd = (insn & 0x1F) as u16;

        let dst = if sf { Self::xreg(rd) } else { Self::wreg(rd) };
        let src1 = if sf { Self::xreg(rn) } else { Self::wreg(rn) };
        let src2 = if sf { Self::xreg(rm) } else { Self::wreg(rm) };
        let addend = if sf { Self::xreg(ra) } else { Self::wreg(ra) };

        let (mnemonic, operands) = match (op54, op31, o0) {
            (0b00, 0b000, 0) => {
                if ra == 31 {
                    ("mul", vec![Operand::reg(dst), Operand::reg(src1), Operand::reg(src2)])
                } else {
                    ("madd", vec![Operand::reg(dst), Operand::reg(src1), Operand::reg(src2), Operand::reg(addend)])
                }
            }
            (0b00, 0b000, 1) => {
                if ra == 31 {
                    ("mneg", vec![Operand::reg(dst), Operand::reg(src1), Operand::reg(src2)])
                } else {
                    ("msub", vec![Operand::reg(dst), Operand::reg(src1), Operand::reg(src2), Operand::reg(addend)])
                }
            }
            (0b00, 0b001, 0) if sf => ("smaddl", vec![Operand::reg(dst), Operand::reg(Self::wreg(rn)), Operand::reg(Self::wreg(rm)), Operand::reg(addend)]),
            (0b00, 0b010, 0) if sf => {
                if ra == 31 {
                    ("smulh", vec![Operand::reg(dst), Operand::reg(src1), Operand::reg(src2)])
                } else {
                    return self.decode_unknown(insn, address, bytes);
                }
            }
            (0b00, 0b101, 0) if sf => ("umaddl", vec![Operand::reg(dst), Operand::reg(Self::wreg(rn)), Operand::reg(Self::wreg(rm)), Operand::reg(addend)]),
            (0b00, 0b110, 0) if sf => {
                if ra == 31 {
                    ("umulh", vec![Operand::reg(dst), Operand::reg(src1), Operand::reg(src2)])
                } else {
                    return self.decode_unknown(insn, address, bytes);
                }
            }
            _ => return self.decode_unknown(insn, address, bytes),
        };

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(Operation::Mul)
            .with_operands(operands);

        Ok(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Decode SIMD/FP instructions.
    fn decode_simd_fp(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        // ARM64 SIMD/FP encoding classification
        // Bits 28-25 = 0111 or 1111 for SIMD/FP
        let op0 = (insn >> 28) & 0xF;
        let op1 = (insn >> 23) & 0x3;
        let op2 = (insn >> 19) & 0xF;
        let op3 = (insn >> 10) & 0x1FF;

        // Bit 31 = Q (vector size: 0=64-bit, 1=128-bit)
        let q = (insn >> 30) & 1;
        // Bit 29 = U (unsigned)
        let u = (insn >> 29) & 1;

        // Check for various SIMD instruction groups
        // SIMD three-same: op0=x111, op1=10
        // SIMD three-different: op0=x111, op1=01/11
        // SIMD two-reg misc: op0=x111, op1=00, bit 17=1
        // Crypto: specific patterns

        // First, try to identify crypto instructions (SHA, AES)
        if self.is_crypto_insn(insn) {
            return self.decode_crypto(insn, address, bytes);
        }

        // Scalar floating-point data processing: bits 28-24 = 11110
        // This must be checked BEFORE SIMD checks as the bit patterns overlap
        if (insn >> 24) & 0x1F == 0b11110 {
            return self.decode_scalar_fp(insn, address, bytes);
        }

        // SIMD across lanes: bits 21-17 = 0x18, bits 10-6 = 0
        if (insn >> 17) & 0x1F == 0x18 && (insn >> 10) & 0x1F == 0x0 {
            return self.decode_simd_across_lanes(insn, address, bytes);
        }

        // SIMD three-same register: bits 28-24 = x1110, bit 21 = 1, bit 10 = 1
        let bits_28_24 = (insn >> 24) & 0x1F;
        if bits_28_24 & 0xF == 0xE && (insn >> 21) & 0x1 == 1 && (insn >> 10) & 0x1 == 1 {
            return self.decode_simd_three_same(insn, address, bytes);
        }

        // SIMD two-reg misc: bits 21-17 = 0b10000
        if (insn >> 17) & 0x1F == 0b10000 {
            return self.decode_simd_two_reg_misc(insn, address, bytes);
        }

        // SIMD copy/duplicate
        if (insn >> 29) & 0x3 == 0x0 && (insn >> 21) & 0xF == 0x0 {
            return self.decode_simd_copy(insn, address, bytes);
        }

        // Fallback scalar FP (backup path)
        if op0 & 0x4 == 0 {
            return self.decode_scalar_fp(insn, address, bytes);
        }

        // Fallback: output generic SIMD/FP mnemonic
        let mnemonic = self.identify_simd_mnemonic(insn);
        let operands = self.decode_simd_operands(insn);

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(Operation::Other(0))
            .with_operands(operands);
        Ok(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Check if instruction is a crypto instruction.
    fn is_crypto_insn(&self, insn: u32) -> bool {
        // AES: bits 31-24 = 01001110 00, bit 21-17 for operation
        // SHA: bits 31-24 = 01011110 or similar patterns
        let top8 = (insn >> 24) & 0xFF;
        let op21_17 = (insn >> 17) & 0x1F;

        // AES instructions: 0x4E28xxxx pattern
        if top8 == 0x4E && (insn >> 12) & 0x3FF == 0b0010100001 {
            return true;
        }

        // SHA instructions: 0x5E28xxxx or 0x5E00xxxx patterns
        if (top8 == 0x5E || top8 == 0x0E) && ((insn >> 10) & 0x3F) < 8 {
            let op = (insn >> 12) & 0x1F;
            if op <= 7 {
                return true;
            }
        }

        false
    }

    /// Decode crypto instructions (AES, SHA).
    fn decode_crypto(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let op = (insn >> 12) & 0x1F;
        let rn = ((insn >> 5) & 0x1F) as u16;
        let rd = (insn & 0x1F) as u16;

        // AES two-register
        let (mnemonic, is_aes) = if (insn >> 24) & 0xFF == 0x4E {
            match op {
                0b00100 => ("aese", true),
                0b00101 => ("aesd", true),
                0b00110 => ("aesmc", true),
                0b00111 => ("aesimc", true),
                _ => ("aes_unknown", true),
            }
        } else {
            // SHA instructions
            match op {
                0b00000 => ("sha1c", false),
                0b00001 => ("sha1p", false),
                0b00010 => ("sha1m", false),
                0b00011 => ("sha1su0", false),
                0b00100 => ("sha256h", false),
                0b00101 => ("sha256h2", false),
                0b00110 => ("sha256su1", false),
                _ => ("sha_unknown", false),
            }
        };

        let vd = self.vreg(rd, 128);
        let vn = self.vreg(rn, 128);

        let operands = if is_aes && (op == 0b00110 || op == 0b00111) {
            // Single source for AESMC/AESIMC
            vec![Operand::reg(vd), Operand::reg(vn)]
        } else {
            vec![Operand::reg(vd), Operand::reg(vn)]
        };

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(Operation::Other(0x100)) // Crypto ops
            .with_operands(operands);

        Ok(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Decode SIMD three-same register instructions.
    fn decode_simd_three_same(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let q = (insn >> 30) & 1;
        let u = (insn >> 29) & 1;
        let size = (insn >> 22) & 0x3;
        let rm = ((insn >> 16) & 0x1F) as u16;
        let opcode = (insn >> 11) & 0x1F;
        let rn = ((insn >> 5) & 0x1F) as u16;
        let rd = (insn & 0x1F) as u16;

        let vec_bits = if q == 1 { 128 } else { 64 };
        let elem_size = match size {
            0 => "8b",
            1 => "16b",
            2 => if q == 1 { "4s" } else { "2s" },
            3 => if q == 1 { "2d" } else { "1d" },
            _ => "?",
        };

        let (mnemonic, operation) = match (u, opcode) {
            // Integer operations
            (0, 0b00000) => ("shadd", Operation::Add),
            (0, 0b00001) => ("sqadd", Operation::Add),
            (0, 0b00010) => ("srhadd", Operation::Add),
            (0, 0b00100) => ("shsub", Operation::Sub),
            (0, 0b00101) => ("sqsub", Operation::Sub),
            (0, 0b00110) => ("cmgt", Operation::Compare),
            (0, 0b00111) => ("cmge", Operation::Compare),
            (0, 0b01000) => ("sshl", Operation::Shl),
            (0, 0b01001) => ("sqshl", Operation::Shl),
            (0, 0b01010) => ("srshl", Operation::Shr),
            (0, 0b01011) => ("sqrshl", Operation::Shr),
            (0, 0b01100) => ("smax", Operation::Other(0)),
            (0, 0b01101) => ("smin", Operation::Other(0)),
            (0, 0b01110) => ("sabd", Operation::Sub),
            (0, 0b01111) => ("saba", Operation::Add),
            (0, 0b10000) => ("add", Operation::Add),
            (0, 0b10001) => ("cmtst", Operation::Test),
            (0, 0b10010) => ("mla", Operation::Add),
            (0, 0b10011) => ("mul", Operation::Mul),
            (0, 0b10100) => ("smaxp", Operation::Other(0)),
            (0, 0b10101) => ("sminp", Operation::Other(0)),
            (0, 0b10110) => ("sqdmulh", Operation::Mul),
            (0, 0b10111) => ("addp", Operation::Add),

            // Floating-point (size=0/1 for S/D)
            (0, 0b11000) if size >= 2 => ("fmaxnm", Operation::Other(0)),
            (0, 0b11001) if size >= 2 => ("fmla", Operation::Add),
            (0, 0b11010) if size >= 2 => ("fadd", Operation::Add),
            (0, 0b11011) if size >= 2 => ("fmulx", Operation::Mul),
            (0, 0b11100) if size >= 2 => ("fcmeq", Operation::Compare),
            (0, 0b11110) if size >= 2 => ("fmax", Operation::Other(0)),
            (0, 0b11111) if size >= 2 => ("frecps", Operation::Div),

            // Unsigned integer operations
            (1, 0b00000) => ("uhadd", Operation::Add),
            (1, 0b00001) => ("uqadd", Operation::Add),
            (1, 0b00010) => ("urhadd", Operation::Add),
            (1, 0b00100) => ("uhsub", Operation::Sub),
            (1, 0b00101) => ("uqsub", Operation::Sub),
            (1, 0b00110) => ("cmhi", Operation::Compare),
            (1, 0b00111) => ("cmhs", Operation::Compare),
            (1, 0b01000) => ("ushl", Operation::Shl),
            (1, 0b01001) => ("uqshl", Operation::Shl),
            (1, 0b01010) => ("urshl", Operation::Shr),
            (1, 0b01011) => ("uqrshl", Operation::Shr),
            (1, 0b01100) => ("umax", Operation::Other(0)),
            (1, 0b01101) => ("umin", Operation::Other(0)),
            (1, 0b01110) => ("uabd", Operation::Sub),
            (1, 0b01111) => ("uaba", Operation::Add),
            (1, 0b10000) => ("sub", Operation::Sub),
            (1, 0b10001) => ("cmeq", Operation::Compare),
            (1, 0b10010) => ("mls", Operation::Sub),
            (1, 0b10011) => ("pmul", Operation::Mul),
            (1, 0b10100) => ("umaxp", Operation::Other(0)),
            (1, 0b10101) => ("uminp", Operation::Other(0)),
            (1, 0b10110) => ("sqrdmulh", Operation::Mul),

            // Unsigned floating-point
            (1, 0b11000) if size >= 2 => ("fminnm", Operation::Other(0)),
            (1, 0b11001) if size >= 2 => ("fmls", Operation::Sub),
            (1, 0b11010) if size >= 2 => ("fsub", Operation::Sub),
            (1, 0b11100) if size >= 2 => ("fcmge", Operation::Compare),
            (1, 0b11101) if size >= 2 => ("facge", Operation::Compare),
            (1, 0b11110) if size >= 2 => ("fmin", Operation::Other(0)),
            (1, 0b11111) if size >= 2 => ("frsqrts", Operation::Div),

            // Bitwise
            (0, 0b00011) if size == 0 => ("and", Operation::And),
            (0, 0b00011) if size == 1 => ("bic", Operation::And),
            (0, 0b00011) if size == 2 => ("orr", Operation::Or),
            (0, 0b00011) if size == 3 => ("orn", Operation::Or),
            (1, 0b00011) if size == 0 => ("eor", Operation::Xor),
            (1, 0b00011) if size == 1 => ("bsl", Operation::Other(0)),
            (1, 0b00011) if size == 2 => ("bit", Operation::Other(0)),
            (1, 0b00011) if size == 3 => ("bif", Operation::Other(0)),

            _ => ("simd_3same", Operation::Other(0)),
        };

        let vd = self.vreg(rd, vec_bits);
        let vn = self.vreg(rn, vec_bits);
        let vm = self.vreg(rm, vec_bits);

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(operation)
            .with_operands(vec![Operand::reg(vd), Operand::reg(vn), Operand::reg(vm)]);

        Ok(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Decode SIMD two-register misc instructions.
    fn decode_simd_two_reg_misc(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let q = (insn >> 30) & 1;
        let u = (insn >> 29) & 1;
        let size = (insn >> 22) & 0x3;
        let opcode = (insn >> 12) & 0x1F;
        let rn = ((insn >> 5) & 0x1F) as u16;
        let rd = (insn & 0x1F) as u16;

        let vec_bits = if q == 1 { 128 } else { 64 };

        let mnemonic = match (u, opcode) {
            (0, 0b00000) => "rev64",
            (0, 0b00001) => "rev16",
            (0, 0b00010) => "saddlp",
            (0, 0b00011) => "suqadd",
            (0, 0b00100) => "cls",
            (0, 0b00101) => "cnt",
            (0, 0b00110) => "sadalp",
            (0, 0b00111) => "sqabs",
            (0, 0b01000) => "cmgt",  // compare vs zero
            (0, 0b01001) => "cmeq",
            (0, 0b01010) => "cmlt",
            (0, 0b01011) => "abs",
            (0, 0b10010) => "xtn",
            (0, 0b10100) => "sqxtn",
            (0, 0b10110) if size >= 2 => "fcvtn",
            (0, 0b10111) if size >= 2 => "fcvtl",
            (0, 0b11000) if size >= 2 => "frintn",
            (0, 0b11001) if size >= 2 => "frintm",
            (0, 0b11010) if size >= 2 => "fcvtns",
            (0, 0b11011) if size >= 2 => "fcvtms",
            (0, 0b11100) if size >= 2 => "fcvtas",
            (0, 0b11101) if size >= 2 => "scvtf",
            (0, 0b11110) if size >= 2 => "fcmgt",  // vs zero
            (0, 0b11111) if size >= 2 => "fcmeq",  // vs zero

            (1, 0b00000) => "rev32",
            (1, 0b00010) => "uaddlp",
            (1, 0b00011) => "usqadd",
            (1, 0b00100) => "clz",
            (1, 0b00101) => "not",
            (1, 0b00110) => "uadalp",
            (1, 0b00111) => "sqneg",
            (1, 0b01000) => "cmge",  // vs zero
            (1, 0b01001) => "cmle",  // vs zero
            (1, 0b01011) => "neg",
            (1, 0b10010) => "sqxtun",
            (1, 0b10011) => "shll",
            (1, 0b10100) => "uqxtn",
            (1, 0b10110) if size >= 2 => "fcvtxn",
            (1, 0b11000) if size >= 2 => "frinta",
            (1, 0b11001) if size >= 2 => "frintx",
            (1, 0b11010) if size >= 2 => "fcvtnu",
            (1, 0b11011) if size >= 2 => "fcvtmu",
            (1, 0b11100) if size >= 2 => "fcvtau",
            (1, 0b11101) if size >= 2 => "ucvtf",
            (1, 0b11110) if size >= 2 => "fcmlt",  // vs zero
            (1, 0b11111) if size >= 2 => "fcmle",  // vs zero

            _ => "simd_2reg",
        };

        let vd = self.vreg(rd, vec_bits);
        let vn = self.vreg(rn, vec_bits);

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(Operation::Other(0))
            .with_operands(vec![Operand::reg(vd), Operand::reg(vn)]);

        Ok(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Decode SIMD across lanes instructions.
    fn decode_simd_across_lanes(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let q = (insn >> 30) & 1;
        let u = (insn >> 29) & 1;
        let size = (insn >> 22) & 0x3;
        let opcode = (insn >> 12) & 0x1F;
        let rn = ((insn >> 5) & 0x1F) as u16;
        let rd = (insn & 0x1F) as u16;

        let mnemonic = match (u, opcode) {
            (0, 0b00011) => "saddlv",
            (0, 0b01010) => "smaxv",
            (0, 0b11010) => "sminv",
            (0, 0b11011) => "addv",
            (1, 0b00011) => "uaddlv",
            (1, 0b01010) => "umaxv",
            (1, 0b11010) => "uminv",
            (1, 0b01100) if size >= 2 => "fmaxnmv",
            (1, 0b01101) if size >= 2 => "fmaxv",
            (1, 0b01110) if size >= 2 => "fminnmv",
            (1, 0b01111) if size >= 2 => "fminv",
            _ => "simd_across",
        };

        let vec_bits = if q == 1 { 128 } else { 64 };
        let scalar_bits = 8 << size;

        let vd = self.vreg(rd, scalar_bits as u16);
        let vn = self.vreg(rn, vec_bits);

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(Operation::Other(0))
            .with_operands(vec![Operand::reg(vd), Operand::reg(vn)]);

        Ok(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Decode SIMD copy/duplicate instructions.
    fn decode_simd_copy(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let q = (insn >> 30) & 1;
        let op = (insn >> 29) & 1;
        let imm5 = (insn >> 16) & 0x1F;
        let imm4 = (insn >> 11) & 0xF;
        let rn = ((insn >> 5) & 0x1F) as u16;
        let rd = (insn & 0x1F) as u16;

        let vec_bits = if q == 1 { 128 } else { 64 };

        let (mnemonic, operands) = if op == 0 {
            // DUP, SMOV, UMOV
            if imm4 == 0 {
                // DUP (element)
                let vd = self.vreg(rd, vec_bits);
                let vn = self.vreg(rn, 128);
                ("dup", vec![Operand::reg(vd), Operand::reg(vn)])
            } else if imm4 == 1 {
                // DUP (general)
                let vd = self.vreg(rd, vec_bits);
                let gpr = Self::xreg(rn);
                ("dup", vec![Operand::reg(vd), Operand::reg(gpr)])
            } else if imm4 == 5 {
                // SMOV
                let gpr = if q == 1 { Self::xreg(rd) } else { Self::wreg(rd) };
                let vn = self.vreg(rn, 128);
                ("smov", vec![Operand::reg(gpr), Operand::reg(vn)])
            } else if imm4 == 7 {
                // UMOV
                let gpr = if q == 1 { Self::xreg(rd) } else { Self::wreg(rd) };
                let vn = self.vreg(rn, 128);
                ("umov", vec![Operand::reg(gpr), Operand::reg(vn)])
            } else {
                let vd = self.vreg(rd, vec_bits);
                ("simd_copy", vec![Operand::reg(vd)])
            }
        } else {
            // INS (element from element or general)
            let vd = self.vreg(rd, 128);
            let vn = self.vreg(rn, 128);
            ("ins", vec![Operand::reg(vd), Operand::reg(vn)])
        };

        let inst = Instruction::new(address, 4, bytes, mnemonic)
            .with_operation(Operation::Move)
            .with_operands(operands);

        Ok(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Decode scalar floating-point instructions.
    fn decode_scalar_fp(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        let m = (insn >> 31) & 1;
        let s = (insn >> 29) & 1;
        let ptype = (insn >> 22) & 0x3;
        let opcode = (insn >> 15) & 0x3F;
        let rn = ((insn >> 5) & 0x1F) as u16;
        let rd = (insn & 0x1F) as u16;

        let fp_size = match ptype {
            0 => 32,  // Single
            1 => 64,  // Double
            3 => 16,  // Half
            _ => 32,
        };

        // Scalar FP data-processing (2-source): bit 21=1, bits 11-10=10
        if (insn >> 21) & 0x1 == 1 && (insn >> 10) & 0x3 == 0b10 {
            let rm = ((insn >> 16) & 0x1F) as u16;
            let op = (insn >> 12) & 0xF;

            let mnemonic = match op {
                0b0000 => "fmul",
                0b0001 => "fdiv",
                0b0010 => "fadd",
                0b0011 => "fsub",
                0b0100 => "fmax",
                0b0101 => "fmin",
                0b0110 => "fmaxnm",
                0b0111 => "fminnm",
                0b1000 => "fnmul",
                _ => "fp_2src",
            };

            let fd = self.fpreg(rd, fp_size);
            let fn_ = self.fpreg(rn, fp_size);
            let fm = self.fpreg(rm, fp_size);

            let operation = match op {
                0b0000 | 0b1000 => Operation::Mul,
                0b0001 => Operation::Div,
                0b0010 => Operation::Add,
                0b0011 => Operation::Sub,
                _ => Operation::Other(0),
            };

            let inst = Instruction::new(address, 4, bytes, mnemonic)
                .with_operation(operation)
                .with_operands(vec![Operand::reg(fd), Operand::reg(fn_), Operand::reg(fm)]);

            return Ok(DecodedInstruction { instruction: inst, size: 4 });
        }

        // Scalar FP data-processing (1-source): bit 21=1, bits 15-10=010000
        if (insn >> 21) & 0x1 == 1 && (insn >> 10) & 0x3F == 0b010000 {
            let op = (insn >> 15) & 0x3F;

            let mnemonic = match op {
                0b000000 => "fmov",
                0b000001 => "fabs",
                0b000010 => "fneg",
                0b000011 => "fsqrt",
                0b000101 => "fcvt",  // to double
                0b000100 => "fcvt",  // to single
                0b001000 => "frintn",
                0b001001 => "frintp",
                0b001010 => "frintm",
                0b001011 => "frintz",
                0b001100 => "frinta",
                0b001110 => "frintx",
                0b001111 => "frinti",
                _ => "fp_1src",
            };

            let fd = self.fpreg(rd, fp_size);
            let fn_ = self.fpreg(rn, fp_size);

            let operation = match op {
                0b000000 => Operation::Move,
                0b000010 => Operation::Neg,
                _ => Operation::Other(0),
            };

            let inst = Instruction::new(address, 4, bytes, mnemonic)
                .with_operation(operation)
                .with_operands(vec![Operand::reg(fd), Operand::reg(fn_)]);

            return Ok(DecodedInstruction { instruction: inst, size: 4 });
        }

        // Scalar FP compare
        if (insn >> 21) & 0xF == 0x0 && (insn >> 14) & 0x3 == 0x2 {
            let rm = ((insn >> 16) & 0x1F) as u16;
            let op = (insn >> 3) & 0x3;

            let mnemonic = match op {
                0b00 => "fcmp",
                0b01 => "fcmpe",
                0b10 => "fcmp",  // vs zero
                0b11 => "fcmpe", // vs zero
                _ => "fcmp",
            };

            let fn_ = self.fpreg(rn, fp_size);
            let operands = if op >= 2 {
                vec![Operand::reg(fn_), Operand::imm(0, 8)]
            } else {
                let fm = self.fpreg(rm, fp_size);
                vec![Operand::reg(fn_), Operand::reg(fm)]
            };

            let inst = Instruction::new(address, 4, bytes, mnemonic)
                .with_operation(Operation::Compare)
                .with_operands(operands);

            return Ok(DecodedInstruction { instruction: inst, size: 4 });
        }

        // Fallback
        let fd = self.fpreg(rd, fp_size);
        let inst = Instruction::new(address, 4, bytes, "fp_scalar")
            .with_operation(Operation::Other(0))
            .with_operands(vec![Operand::reg(fd)]);

        Ok(DecodedInstruction { instruction: inst, size: 4 })
    }

    /// Create a NEON vector register.
    fn vreg(&self, id: u16, bits: u16) -> Register {
        Register::new(
            Architecture::Arm64,
            RegisterClass::Vector,
            arm64::V0 + id,
            bits,
        )
    }

    /// Create a floating-point register.
    fn fpreg(&self, id: u16, bits: u16) -> Register {
        Register::new(
            Architecture::Arm64,
            RegisterClass::FloatingPoint,
            arm64::V0 + id,
            bits,
        )
    }

    /// Try to identify SIMD mnemonic from instruction bits.
    fn identify_simd_mnemonic(&self, insn: u32) -> &'static str {
        let u = (insn >> 29) & 1;
        let opcode = (insn >> 11) & 0x1F;

        // Very simplified fallback
        match (u, opcode & 0xF) {
            (0, 0) => "simd_add",
            (1, 0) => "simd_sub",
            (_, 3) => "simd_mul",
            _ => "simd",
        }
    }

    /// Decode basic SIMD operands.
    fn decode_simd_operands(&self, insn: u32) -> Vec<Operand> {
        let q = (insn >> 30) & 1;
        let rn = ((insn >> 5) & 0x1F) as u16;
        let rd = (insn & 0x1F) as u16;

        let vec_bits = if q == 1 { 128 } else { 64 };
        let vd = self.vreg(rd, vec_bits);
        let vn = self.vreg(rn, vec_bits);

        vec![Operand::reg(vd), Operand::reg(vn)]
    }

    /// Decode unknown instruction.
    fn decode_unknown(
        &self,
        insn: u32,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<DecodedInstruction, DecodeError> {
        Err(DecodeError::unknown_opcode(address, &bytes))
    }
}

impl Default for Arm64Disassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Disassembler for Arm64Disassembler {
    fn decode_instruction(&self, bytes: &[u8], address: u64) -> Result<DecodedInstruction, DecodeError> {
        self.decode(bytes, address)
    }

    fn min_instruction_size(&self) -> usize {
        4
    }

    fn max_instruction_size(&self) -> usize {
        4
    }

    fn is_fixed_width(&self) -> bool {
        true
    }

    fn architecture(&self) -> Architecture {
        Architecture::Arm64
    }
}

/// Sign-extend a value from a given bit width.
fn sign_extend(value: u64, bits: u8) -> i64 {
    let shift = 64 - bits;
    ((value as i64) << shift) >> shift
}

/// Decode ARM64 condition code.
fn decode_condition(cond: u8) -> (&'static str, Condition) {
    match cond {
        0b0000 => ("eq", Condition::Equal),
        0b0001 => ("ne", Condition::NotEqual),
        0b0010 => ("cs", Condition::AboveOrEqual), // HS (unsigned >=)
        0b0011 => ("cc", Condition::Below),        // LO (unsigned <)
        0b0100 => ("mi", Condition::Sign),         // Negative
        0b0101 => ("pl", Condition::NotSign),      // Positive or zero
        0b0110 => ("vs", Condition::Overflow),     // Overflow
        0b0111 => ("vc", Condition::NotOverflow),  // No overflow
        0b1000 => ("hi", Condition::Above),        // Unsigned >
        0b1001 => ("ls", Condition::BelowOrEqual), // Unsigned <=
        0b1010 => ("ge", Condition::GreaterOrEqual), // Signed >=
        0b1011 => ("lt", Condition::Less),         // Signed <
        0b1100 => ("gt", Condition::Greater),      // Signed >
        0b1101 => ("le", Condition::LessOrEqual),  // Signed <=
        0b1110 => ("al", Condition::Equal),        // Always (placeholder)
        0b1111 => ("nv", Condition::Equal),        // Never (placeholder)
        _ => ("??", Condition::Equal),
    }
}

/// Decode bitmask immediate (complex ARM64 encoding).
/// This is a simplified version - full implementation is complex.
fn decode_bitmask_imm(n: u8, imms: u8, immr: u8, is_64bit: bool) -> u64 {
    let len = if n == 1 {
        6
    } else {
        // Find highest set bit in ~imms
        let mut len = 5u8;
        while len > 0 && (imms & (1 << len)) != 0 {
            len -= 1;
        }
        len
    };

    if len == 0 {
        return 0; // Invalid encoding
    }

    // Element size: when len=6, size=64 (not 128); element size is capped at 64
    let size = if len >= 6 { 64u64 } else { 1u64 << (len + 1) };
    let mask = if len >= 6 { 0x3Fu64 } else { (1u64 << (len + 1)) - 1 };
    let s = (imms as u64) & mask;
    let r = (immr as u64) & mask;

    // Create base pattern: s+1 ones
    let ones = if s + 1 >= 64 { !0u64 } else { (1u64 << (s + 1)) - 1 };

    // Rotate right by r within element size
    let rotated = if r == 0 {
        ones
    } else if size == 64 {
        // Use built-in rotate for 64-bit elements to avoid overflow
        ones.rotate_right(r as u32)
    } else {
        // For smaller elements, rotate within element size
        let r = r % size;
        ((ones >> r) | (ones << (size - r))) & ((1u64 << size) - 1)
    };

    // Mask to element size
    let pattern = if size >= 64 { rotated } else { rotated & ((1u64 << size) - 1) };

    // Replicate pattern across register
    let mut result = 0u64;
    let mut pos = 0u64;
    let reg_size = if is_64bit { 64u64 } else { 32u64 };
    while pos < reg_size {
        result |= pattern << pos;
        pos += size;
    }

    if !is_64bit {
        result &= 0xFFFFFFFF;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nop() {
        let disasm = Arm64Disassembler::new();
        // NOP: 0xD503201F
        let bytes = [0x1F, 0x20, 0x03, 0xD5];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "nop");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_ret() {
        let disasm = Arm64Disassembler::new();
        // RET: 0xD65F03C0
        let bytes = [0xC0, 0x03, 0x5F, 0xD6];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ret");
        assert!(result.instruction.is_return());
    }

    #[test]
    fn test_mov_immediate() {
        let disasm = Arm64Disassembler::new();
        // MOV X0, #0x1234 (MOVZ): 0xD2824680
        let bytes = [0x80, 0x46, 0x82, 0xD2];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "mov");
    }

    #[test]
    fn test_bl() {
        let disasm = Arm64Disassembler::new();
        // BL +0x100: 0x94000040
        let bytes = [0x40, 0x00, 0x00, 0x94];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "bl");
        assert!(result.instruction.is_call());
    }

    #[test]
    fn test_fadd_scalar() {
        let disasm = Arm64Disassembler::new();
        // FADD D0, D1, D2: 0x1E622820
        let bytes = [0x20, 0x28, 0x62, 0x1E];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "fadd");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_fmul_scalar() {
        let disasm = Arm64Disassembler::new();
        // FMUL D0, D1, D2: 0x1E620820
        let bytes = [0x20, 0x08, 0x62, 0x1E];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "fmul");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_add_simd_vector() {
        let disasm = Arm64Disassembler::new();
        // ADD V0.4S, V1.4S, V2.4S: 0x4EA28420
        let bytes = [0x20, 0x84, 0xA2, 0x4E];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "add");
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_fmov_scalar() {
        let disasm = Arm64Disassembler::new();
        // FMOV D0, D1: 0x1E604020
        let bytes = [0x20, 0x40, 0x60, 0x1E];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "fmov");
        assert_eq!(result.size, 4);
    }

    // SIMD/FP load/store tests

    #[test]
    fn test_ldr_simd_s_unsigned_imm() {
        let disasm = Arm64Disassembler::new();
        // LDR S0, [X1, #4]: 0xBD400420
        // Encoding: size=10, V=1, opc=01, imm12=1, Rn=1, Rt=0
        let bytes = [0x20, 0x04, 0x40, 0xBD];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ldr");
        assert_eq!(result.instruction.operation, Operation::Load);
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_str_simd_d_unsigned_imm() {
        let disasm = Arm64Disassembler::new();
        // STR D0, [X1, #8]: 0xFD000420
        // Encoding: size=11, V=1, opc=00, imm12=1, Rn=1, Rt=0
        let bytes = [0x20, 0x04, 0x00, 0xFD];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "str");
        assert_eq!(result.instruction.operation, Operation::Store);
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_ldr_simd_q_unsigned_imm() {
        let disasm = Arm64Disassembler::new();
        // LDR Q0, [X1, #16]: 0x3DC00420
        // Encoding: size=00, V=1, opc=11, imm12=1, Rn=1, Rt=0
        let bytes = [0x20, 0x04, 0xC0, 0x3D];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ldr");
        assert_eq!(result.instruction.operation, Operation::Load);
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_ldp_simd_d() {
        let disasm = Arm64Disassembler::new();
        // LDP D0, D1, [X2]: 0x6D400440
        // Encoding: opc=01, V=1, L=1, imm7=0, Rt2=1, Rn=2, Rt=0
        let bytes = [0x40, 0x04, 0x40, 0x6D];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ldp");
        assert_eq!(result.instruction.operation, Operation::Load);
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_stp_simd_q() {
        let disasm = Arm64Disassembler::new();
        // STP Q0, Q1, [X2]: 0xAD000440
        // Encoding: opc=10, V=1, L=0, imm7=0, Rt2=1, Rn=2, Rt=0
        let bytes = [0x40, 0x04, 0x00, 0xAD];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "stp");
        assert_eq!(result.instruction.operation, Operation::Store);
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_ldr_simd_d_register() {
        let disasm = Arm64Disassembler::new();
        // LDR D0, [X1, X2]: 0xFC626820
        // Encoding: size=11, V=1, opc=01, Rm=2, option=011, S=0, Rn=1, Rt=0
        let bytes = [0x20, 0x68, 0x62, 0xFC];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ldr");
        assert_eq!(result.instruction.operation, Operation::Load);
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_str_simd_s_pre_index() {
        let disasm = Arm64Disassembler::new();
        // STR S0, [X1, #-4]!: 0xBC1FC020
        // Encoding: size=10, V=1, opc=00, imm9=-4, pre=1, Rn=1, Rt=0
        let bytes = [0x20, 0xCC, 0x1F, 0xBC];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "str");
        assert_eq!(result.instruction.operation, Operation::Store);
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_ldur_simd_d() {
        let disasm = Arm64Disassembler::new();
        // LDUR D0, [X1, #-8]: 0xFC5F8020
        // Encoding: size=11, V=1, opc=01, imm9=-8, Rn=1, Rt=0
        let bytes = [0x20, 0x80, 0x5F, 0xFC];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ldur");
        assert_eq!(result.instruction.operation, Operation::Load);
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_ldr_simd_literal() {
        let disasm = Arm64Disassembler::new();
        // LDR S0, label (offset +8): 0x1C000040
        // Encoding: opc=00, V=1, imm19=2, Rt=0
        let bytes = [0x40, 0x00, 0x00, 0x1C];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ldr");
        assert_eq!(result.instruction.operation, Operation::Load);
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_ldr_simd_b_unsigned_imm() {
        let disasm = Arm64Disassembler::new();
        // LDR B0, [X1, #1]: 0x3D400420
        // Encoding: size=00, V=1, opc=01, imm12=1, Rn=1, Rt=0
        let bytes = [0x20, 0x04, 0x40, 0x3D];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ldr");
        assert_eq!(result.instruction.operation, Operation::Load);
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_str_simd_h_unsigned_imm() {
        let disasm = Arm64Disassembler::new();
        // STR H0, [X1, #2]: 0x7D000420
        // Encoding: size=01, V=1, opc=00, imm12=1, Rn=1, Rt=0
        let bytes = [0x20, 0x04, 0x00, 0x7D];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "str");
        assert_eq!(result.instruction.operation, Operation::Store);
        assert_eq!(result.size, 4);
    }

    // Load/Store Exclusive tests

    #[test]
    fn test_ldxr() {
        let disasm = Arm64Disassembler::new();
        // LDXR X0, [X1]: 0xC85F7C20
        // Encoding: size=11, 001000, o2=0, L=1, o1=0, Rs=11111, o0=0, Rt2=11111, Rn=1, Rt=0
        let bytes = [0x20, 0x7C, 0x5F, 0xC8];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ldxr");
        assert_eq!(result.instruction.operation, Operation::LoadExclusive);
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_ldxr_32bit() {
        let disasm = Arm64Disassembler::new();
        // LDXR W0, [X1]: 0x885F7C20
        // Encoding: size=10, 001000, o2=0, L=1, o1=0, Rs=11111, o0=0, Rt2=11111, Rn=1, Rt=0
        let bytes = [0x20, 0x7C, 0x5F, 0x88];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ldxr");
        assert_eq!(result.instruction.operation, Operation::LoadExclusive);
    }

    #[test]
    fn test_stxr() {
        let disasm = Arm64Disassembler::new();
        // STXR W2, X0, [X1]: 0xC8027C20
        // Encoding: size=11, 001000, o2=0, L=0, o1=0, Rs=2, o0=0, Rt2=11111, Rn=1, Rt=0
        let bytes = [0x20, 0x7C, 0x02, 0xC8];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "stxr");
        assert_eq!(result.instruction.operation, Operation::StoreExclusive);
    }

    #[test]
    fn test_ldaxr() {
        let disasm = Arm64Disassembler::new();
        // LDAXR X0, [X1]: 0xC85FFC20
        // Encoding: size=11, 001000, o2=0, L=1, o1=0, Rs=11111, o0=1, Rt2=11111, Rn=1, Rt=0
        let bytes = [0x20, 0xFC, 0x5F, 0xC8];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ldaxr");
        assert_eq!(result.instruction.operation, Operation::LoadExclusive);
    }

    #[test]
    fn test_stlxr() {
        let disasm = Arm64Disassembler::new();
        // STLXR W2, X0, [X1]: 0xC802FC20
        // Encoding: size=11, 001000, o2=0, L=0, o1=0, Rs=2, o0=1, Rt2=11111, Rn=1, Rt=0
        let bytes = [0x20, 0xFC, 0x02, 0xC8];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "stlxr");
        assert_eq!(result.instruction.operation, Operation::StoreExclusive);
    }

    #[test]
    fn test_ldxp() {
        let disasm = Arm64Disassembler::new();
        // LDXP X0, X3, [X1]: 0xC8600C20
        // Encoding: size=11, 001000, o2=0, L=1, o1=1, Rs=00000, o0=0, Rt2=3, Rn=1, Rt=0
        let bytes = [0x20, 0x0C, 0x60, 0xC8];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ldxp");
        assert_eq!(result.instruction.operation, Operation::LoadExclusive);
        assert_eq!(result.instruction.operands.len(), 3); // X0, X3, [X1]
    }

    #[test]
    fn test_stxp() {
        let disasm = Arm64Disassembler::new();
        // STXP W2, X0, X3, [X1]: 0xC8220C20
        // Encoding: size=11, 001000, o2=0, L=0, o1=1, Rs=2, o0=0, Rt2=3, Rn=1, Rt=0
        let bytes = [0x20, 0x0C, 0x22, 0xC8];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "stxp");
        assert_eq!(result.instruction.operation, Operation::StoreExclusive);
        assert_eq!(result.instruction.operands.len(), 4); // W2, X0, X3, [X1]
    }

    #[test]
    fn test_ldar() {
        let disasm = Arm64Disassembler::new();
        // LDAR X0, [X1]: 0xC8DFFC20
        // Encoding: size=11, 001000, o2=1, L=1, o1=0, Rs=11111, o0=1, Rt2=11111, Rn=1, Rt=0
        let bytes = [0x20, 0xFC, 0xDF, 0xC8];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ldar");
        assert_eq!(result.instruction.operation, Operation::LoadExclusive);
    }

    #[test]
    fn test_stlr() {
        let disasm = Arm64Disassembler::new();
        // STLR X0, [X1]: 0xC89FFC20
        // Encoding: size=11, 001000, o2=1, L=0, o1=0, Rs=11111, o0=1, Rt2=11111, Rn=1, Rt=0
        let bytes = [0x20, 0xFC, 0x9F, 0xC8];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "stlr");
        assert_eq!(result.instruction.operation, Operation::StoreExclusive);
    }

    // Atomic memory operation tests (ARMv8.1)

    #[test]
    fn test_ldadd() {
        let disasm = Arm64Disassembler::new();
        // LDADD X2, X0, [X1]: 0xF8220020
        // Encoding: size=11, 111000, A=0, R=0, 1, Rs=2, o3=0, opc=000, 00, Rn=1, Rt=0
        let bytes = [0x20, 0x00, 0x22, 0xF8];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ldadd");
        assert_eq!(result.instruction.operation, Operation::AtomicAdd);
    }

    #[test]
    fn test_ldadda() {
        let disasm = Arm64Disassembler::new();
        // LDADDA X2, X0, [X1]: 0xF8A20020
        // Encoding: size=11, 111000, A=1, R=0, 1, Rs=2, o3=0, opc=000, 00, Rn=1, Rt=0
        let bytes = [0x20, 0x00, 0xA2, 0xF8];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ldadda");
        assert_eq!(result.instruction.operation, Operation::AtomicAdd);
    }

    #[test]
    fn test_ldaddal() {
        let disasm = Arm64Disassembler::new();
        // LDADDAL X2, X0, [X1]: 0xF8E20020
        // Encoding: size=11, 111000, A=1, R=1, 1, Rs=2, o3=0, opc=000, 00, Rn=1, Rt=0
        let bytes = [0x20, 0x00, 0xE2, 0xF8];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ldaddal");
        assert_eq!(result.instruction.operation, Operation::AtomicAdd);
    }

    #[test]
    fn test_ldclr() {
        let disasm = Arm64Disassembler::new();
        // LDCLR X2, X0, [X1]: 0xF8221020
        // Encoding: size=11, 111000, A=0, R=0, 1, Rs=2, o3=0, opc=001, 00, Rn=1, Rt=0
        let bytes = [0x20, 0x10, 0x22, 0xF8];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ldclr");
        assert_eq!(result.instruction.operation, Operation::AtomicClear);
    }

    #[test]
    fn test_ldeor() {
        let disasm = Arm64Disassembler::new();
        // LDEOR X2, X0, [X1]: 0xF8222020
        // Encoding: size=11, 111000, A=0, R=0, 1, Rs=2, o3=0, opc=010, 00, Rn=1, Rt=0
        let bytes = [0x20, 0x20, 0x22, 0xF8];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ldeor");
        assert_eq!(result.instruction.operation, Operation::AtomicXor);
    }

    #[test]
    fn test_ldset() {
        let disasm = Arm64Disassembler::new();
        // LDSET X2, X0, [X1]: 0xF8223020
        // Encoding: size=11, 111000, A=0, R=0, 1, Rs=2, o3=0, opc=011, 00, Rn=1, Rt=0
        let bytes = [0x20, 0x30, 0x22, 0xF8];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ldset");
        assert_eq!(result.instruction.operation, Operation::AtomicSet);
    }

    #[test]
    fn test_ldsmax() {
        let disasm = Arm64Disassembler::new();
        // LDSMAX X2, X0, [X1]: 0xF8224020
        // Encoding: size=11, 111000, A=0, R=0, 1, Rs=2, o3=0, opc=100, 00, Rn=1, Rt=0
        let bytes = [0x20, 0x40, 0x22, 0xF8];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ldsmax");
        assert_eq!(result.instruction.operation, Operation::AtomicSignedMax);
    }

    #[test]
    fn test_ldsmin() {
        let disasm = Arm64Disassembler::new();
        // LDSMIN X2, X0, [X1]: 0xF8225020
        // Encoding: size=11, 111000, A=0, R=0, 1, Rs=2, o3=0, opc=101, 00, Rn=1, Rt=0
        let bytes = [0x20, 0x50, 0x22, 0xF8];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ldsmin");
        assert_eq!(result.instruction.operation, Operation::AtomicSignedMin);
    }

    #[test]
    fn test_ldumax() {
        let disasm = Arm64Disassembler::new();
        // LDUMAX X2, X0, [X1]: 0xF8226020
        // Encoding: size=11, 111000, A=0, R=0, 1, Rs=2, o3=0, opc=110, 00, Rn=1, Rt=0
        let bytes = [0x20, 0x60, 0x22, 0xF8];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ldumax");
        assert_eq!(result.instruction.operation, Operation::AtomicUnsignedMax);
    }

    #[test]
    fn test_ldumin() {
        let disasm = Arm64Disassembler::new();
        // LDUMIN X2, X0, [X1]: 0xF8227020
        // Encoding: size=11, 111000, A=0, R=0, 1, Rs=2, o3=0, opc=111, 00, Rn=1, Rt=0
        let bytes = [0x20, 0x70, 0x22, 0xF8];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ldumin");
        assert_eq!(result.instruction.operation, Operation::AtomicUnsignedMin);
    }

    #[test]
    fn test_swp() {
        let disasm = Arm64Disassembler::new();
        // SWP X2, X0, [X1]: 0xF8228020
        // Encoding: size=11, 111000, A=0, R=0, 1, Rs=2, o3=1, opc=000, 00, Rn=1, Rt=0
        let bytes = [0x20, 0x80, 0x22, 0xF8];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "swp");
        assert_eq!(result.instruction.operation, Operation::AtomicSwap);
    }

    #[test]
    fn test_swpal() {
        let disasm = Arm64Disassembler::new();
        // SWPAL X2, X0, [X1]: 0xF8E28020
        // Encoding: size=11, 111000, A=1, R=1, 1, Rs=2, o3=1, opc=000, 00, Rn=1, Rt=0
        let bytes = [0x20, 0x80, 0xE2, 0xF8];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "swpal");
        assert_eq!(result.instruction.operation, Operation::AtomicSwap);
    }

    #[test]
    fn test_ldaddb() {
        let disasm = Arm64Disassembler::new();
        // LDADDB W2, W0, [X1]: 0x38220020
        // Encoding: size=00, 111000, A=0, R=0, 1, Rs=2, o3=0, opc=000, 00, Rn=1, Rt=0
        let bytes = [0x20, 0x00, 0x22, 0x38];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ldaddb");
        assert_eq!(result.instruction.operation, Operation::AtomicAdd);
    }

    #[test]
    fn test_ldaddh() {
        let disasm = Arm64Disassembler::new();
        // LDADDH W2, W0, [X1]: 0x78220020
        // Encoding: size=01, 111000, A=0, R=0, 1, Rs=2, o3=0, opc=000, 00, Rn=1, Rt=0
        let bytes = [0x20, 0x00, 0x22, 0x78];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "ldaddh");
        assert_eq!(result.instruction.operation, Operation::AtomicAdd);
    }

    // SVE (Scalable Vector Extension) tests

    #[test]
    fn test_sve_cntd() {
        let disasm = Arm64Disassembler::new();
        // CNTD X0: 0x04EE0FE0
        // Encoding: 0000_0100_11_10_1110_0000_11_11111_00000
        let bytes = [0xE0, 0x0F, 0xEE, 0x04];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "cntd");
        assert_eq!(result.instruction.operation, Operation::SveCount);
        assert_eq!(result.size, 4);
    }

    #[test]
    fn test_sve_cntb() {
        let disasm = Arm64Disassembler::new();
        // CNTB X0: 0x042E0FE0
        // Encoding: 0000_0100_00_10_1110_0000_11_11111_00000
        let bytes = [0xE0, 0x0F, 0x2E, 0x04];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "cntb");
        assert_eq!(result.instruction.operation, Operation::SveCount);
    }

    #[test]
    fn test_sve_cnth() {
        let disasm = Arm64Disassembler::new();
        // CNTH X1: 0x046E0FE1
        // Encoding: 0000_0100_01_10_1110_0000_11_11111_00001
        let bytes = [0xE1, 0x0F, 0x6E, 0x04];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "cnth");
        assert_eq!(result.instruction.operation, Operation::SveCount);
    }

    #[test]
    fn test_sve_cntw() {
        let disasm = Arm64Disassembler::new();
        // CNTW X2: 0x04AE0FE2
        // Encoding: 0000_0100_10_10_1110_0000_11_11111_00010
        let bytes = [0xE2, 0x0F, 0xAE, 0x04];
        let result = disasm.decode_instruction(&bytes, 0x1000).unwrap();
        assert_eq!(result.instruction.mnemonic, "cntw");
        assert_eq!(result.instruction.operation, Operation::SveCount);
    }
}
