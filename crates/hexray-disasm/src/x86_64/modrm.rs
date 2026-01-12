//! ModR/M and SIB byte decoding.

use super::prefix::{Prefixes, Rex};
use hexray_core::{
    register::{x86, RegisterClass},
    Architecture, MemoryRef, Operand, Register,
};

/// Decoded ModR/M byte.
#[derive(Debug, Clone, Copy)]
pub struct ModRM {
    /// Mod field (2 bits)
    pub mod_: u8,
    /// Reg field (3 bits, extended by REX.R)
    pub reg: u8,
    /// R/M field (3 bits, extended by REX.B)
    pub rm: u8,
}

impl ModRM {
    /// Parse a ModR/M byte with REX extension.
    pub fn parse(byte: u8, rex: Option<Rex>) -> Self {
        let rex = rex.unwrap_or_default();
        Self {
            mod_: (byte >> 6) & 0x3,
            reg: ((byte >> 3) & 0x7) | ((rex.r as u8) << 3),
            rm: (byte & 0x7) | ((rex.b as u8) << 3),
        }
    }

    /// Returns true if this ModR/M encodes a register operand (mod=11).
    pub fn is_register(&self) -> bool {
        self.mod_ == 0b11
    }

    /// Returns true if this ModR/M requires a SIB byte.
    pub fn needs_sib(&self) -> bool {
        self.mod_ != 0b11 && (self.rm & 0x7) == 0x4
    }

    /// Returns true if this ModR/M has a 32-bit displacement.
    pub fn has_disp32(&self) -> bool {
        self.mod_ == 0b10 || (self.mod_ == 0b00 && (self.rm & 0x7) == 0x5)
    }

    /// Returns true if this ModR/M has an 8-bit displacement.
    pub fn has_disp8(&self) -> bool {
        self.mod_ == 0b01
    }
}

/// Decoded SIB byte.
#[derive(Debug, Clone, Copy)]
pub struct Sib {
    /// Scale (2 bits) - actual scale is 1 << scale
    pub scale: u8,
    /// Index register (3 bits, extended by REX.X)
    pub index: u8,
    /// Base register (3 bits, extended by REX.B)
    pub base: u8,
}

impl Sib {
    /// Parse a SIB byte with REX extension.
    pub fn parse(byte: u8, rex: Option<Rex>) -> Self {
        let rex = rex.unwrap_or_default();
        Self {
            scale: (byte >> 6) & 0x3,
            index: ((byte >> 3) & 0x7) | ((rex.x as u8) << 3),
            base: (byte & 0x7) | ((rex.b as u8) << 3),
        }
    }

    /// Returns the actual scale factor (1, 2, 4, or 8).
    pub fn scale_factor(&self) -> u8 {
        1 << self.scale
    }
}

/// Decode a register operand from a register number.
pub fn decode_gpr(reg: u8, size: u16) -> Register {
    Register::new(
        Architecture::X86_64,
        RegisterClass::General,
        reg as u16,
        size,
    )
}

/// Decode an XMM/YMM register from a register number.
/// The size parameter should be 128 for XMM or 256 for YMM.
pub fn decode_xmm(reg: u8, size: u16) -> Register {
    Register::new(
        Architecture::X86_64,
        if size == 256 { RegisterClass::Vector } else { RegisterClass::FloatingPoint },
        x86::XMM0 + reg as u16,
        size,
    )
}

/// Decode the reg field of ModR/M as a register operand.
pub fn decode_modrm_reg(modrm: ModRM, size: u16) -> Operand {
    Operand::Register(decode_gpr(modrm.reg, size))
}

/// Decode the reg field of ModR/M as an XMM/YMM register operand.
pub fn decode_modrm_reg_xmm(modrm: ModRM, size: u16) -> Operand {
    Operand::Register(decode_xmm(modrm.reg, size))
}

/// Decode the r/m field of ModR/M.
/// Returns (operand, bytes_consumed).
pub fn decode_modrm_rm(
    bytes: &[u8],
    modrm: ModRM,
    prefixes: &Prefixes,
    operand_size: u16,
) -> Option<(Operand, usize)> {
    let mut offset = 0;

    // Register operand
    if modrm.is_register() {
        return Some((
            Operand::Register(decode_gpr(modrm.rm, operand_size)),
            0,
        ));
    }

    // Memory operand
    let mut base: Option<Register> = None;
    let mut index: Option<Register> = None;
    let mut scale: u8 = 1;
    let mut displacement: i64 = 0;

    // Handle SIB byte if needed
    if modrm.needs_sib() {
        if bytes.is_empty() {
            return None;
        }
        let sib = Sib::parse(bytes[0], prefixes.rex);
        offset += 1;

        // Index register (RSP encoding means no index)
        if (sib.index & 0x7) != 0x4 {
            index = Some(decode_gpr(sib.index, 64));
            scale = sib.scale_factor();
        }

        // Base register
        if (sib.base & 0x7) == 0x5 && modrm.mod_ == 0b00 {
            // No base, just displacement
        } else {
            base = Some(decode_gpr(sib.base, 64));
        }
    } else if (modrm.rm & 0x7) == 0x5 && modrm.mod_ == 0b00 {
        // RIP-relative addressing
        if bytes.len() < offset + 4 {
            return None;
        }
        let disp = i32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        offset += 4;
        // RIP-relative - we'll handle this specially
        base = Some(Register::new(
            Architecture::X86_64,
            RegisterClass::ProgramCounter,
            x86::RIP,
            64,
        ));
        displacement = disp as i64;

        return Some((
            Operand::Memory(MemoryRef {
                base,
                index: None,
                scale: 1,
                displacement,
                size: (operand_size / 8) as u8,
                segment: None,
            }),
            offset,
        ));
    } else {
        // Simple register addressing
        base = Some(decode_gpr(modrm.rm, 64));
    }

    // Read displacement
    if modrm.has_disp32() || ((modrm.rm & 0x7) == 0x5 && modrm.mod_ == 0b00) {
        if bytes.len() < offset + 4 {
            return None;
        }
        let disp = i32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        displacement = disp as i64;
        offset += 4;
    } else if modrm.has_disp8() {
        if bytes.len() < offset + 1 {
            return None;
        }
        displacement = bytes[offset] as i8 as i64;
        offset += 1;
    }

    Some((
        Operand::Memory(MemoryRef {
            base,
            index,
            scale,
            displacement,
            size: (operand_size / 8) as u8,
            segment: None,
        }),
        offset,
    ))
}

/// Decode the r/m field of ModR/M for XMM/YMM operands.
/// Returns (operand, bytes_consumed).
pub fn decode_modrm_rm_xmm(
    bytes: &[u8],
    modrm: ModRM,
    prefixes: &Prefixes,
    vector_size: u16,
) -> Option<(Operand, usize)> {
    // If it's a register operand, decode as XMM/YMM
    if modrm.is_register() {
        return Some((
            Operand::Register(decode_xmm(modrm.rm, vector_size)),
            0,
        ));
    }

    // Otherwise, it's a memory operand - use the same decoding but with vector size
    // Memory operand size is the vector size / 8
    decode_modrm_rm(bytes, modrm, prefixes, vector_size)
}
