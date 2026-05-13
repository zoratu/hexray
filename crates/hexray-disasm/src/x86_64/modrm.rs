//! ModR/M and SIB byte decoding.

use super::prefix::{Evex, Prefixes, Rex, Segment};
use hexray_core::{
    register::{x86, RegisterClass},
    Architecture, IndexMode, MemoryRef, Operand, Register,
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

    /// Parse a ModR/M byte with EVEX extension.
    /// EVEX provides R', R, X, B bits for 5-bit register encoding.
    pub fn parse_evex(byte: u8, evex: &Evex) -> Self {
        // EVEX provides:
        // - R and R' for reg field (5 bits total)
        // - B and X for rm field with SIB (5 bits total)
        Self {
            mod_: (byte >> 6) & 0x3,
            // reg = modrm.reg[2:0] | EVEX.R << 3 | EVEX.R' << 4
            reg: ((byte >> 3) & 0x7) | ((evex.r as u8) << 3) | ((evex.r_prime as u8) << 4),
            // rm = modrm.rm[2:0] | EVEX.B << 3 | EVEX.X << 4 (X used when SIB present)
            rm: (byte & 0x7) | ((evex.b as u8) << 3),
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

fn decode_gpr_id(reg: u8, size: u16, rex_present: bool) -> u16 {
    if size == 8 && !rex_present {
        match reg {
            4 => x86::AH,
            5 => x86::CH,
            6 => x86::DH,
            7 => x86::BH,
            _ => reg as u16,
        }
    } else {
        reg as u16
    }
}

/// Decode a register operand from a register number.
pub fn decode_gpr(reg: u8, size: u16, rex_present: bool) -> Register {
    Register::new(
        Architecture::X86_64,
        RegisterClass::General,
        decode_gpr_id(reg, size, rex_present),
        size,
    )
}

/// Decode an XMM/YMM/ZMM register from a register number.
/// The size parameter should be 128 for XMM, 256 for YMM, or 512 for ZMM.
/// reg can be 0-31 for EVEX-encoded instructions.
pub fn decode_xmm(reg: u8, size: u16) -> Register {
    // For extended registers (16-31), use the XMM16 base
    let reg_id = if reg >= 16 {
        x86::XMM16.wrapping_add(reg.wrapping_sub(16) as u16)
    } else {
        x86::XMM0.wrapping_add(reg as u16)
    };

    let class = match size {
        512 | 256 => RegisterClass::Vector,
        _ => RegisterClass::FloatingPoint,
    };

    Register::new(Architecture::X86_64, class, reg_id, size)
}

/// Decode an opmask register (k0-k7) from a register number.
#[allow(dead_code)]
pub fn decode_opmask(reg: u8) -> Register {
    Register::new(
        Architecture::X86_64,
        RegisterClass::Other,
        x86::K0.wrapping_add((reg & 0x7) as u16),
        64, // opmask registers are 64-bit
    )
}

/// Decode an AMX tile register (tmm0-tmm7) from a register number.
pub fn decode_tmm(reg: u8) -> Register {
    Register::new(
        Architecture::X86_64,
        RegisterClass::Tile,
        x86::TMM0.wrapping_add((reg & 0x7) as u16),
        0, // tile size is configuration-dependent
    )
}

fn decode_segment(segment: Segment) -> Register {
    let id = match segment {
        Segment::CS => x86::CS,
        Segment::SS => x86::SS,
        Segment::DS => x86::DS,
        Segment::ES => x86::ES,
        Segment::FS => x86::FS,
        Segment::GS => x86::GS,
    };
    Register::new(Architecture::X86_64, RegisterClass::Segment, id, 16)
}

/// Decode the reg field of ModR/M as a register operand.
pub fn decode_modrm_reg(modrm: ModRM, size: u16, rex_present: bool) -> Operand {
    Operand::Register(decode_gpr(modrm.reg, size, rex_present))
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
    let mut offset: usize = 0;

    // Register operand
    if modrm.is_register() {
        return Some((
            Operand::Register(decode_gpr(modrm.rm, operand_size, prefixes.rex.is_some())),
            0,
        ));
    }

    // Memory operand
    let mut base: Option<Register> = None;
    let mut index: Option<Register> = None;
    let mut scale: u8 = 1;
    let mut displacement: i64 = 0;
    let mut sib_disp32 = false; // Track SIB with base=5, mod=00 case

    // Handle SIB byte if needed
    if modrm.needs_sib() {
        if bytes.is_empty() {
            return None;
        }
        let sib_byte = *bytes.first()?;
        let sib = Sib::parse(sib_byte, prefixes.rex);
        offset = offset.saturating_add(1);

        // Index register.
        //
        // In 64-bit mode the SIB "no index" sentinel only applies to the raw
        // 3-bit encoding 100 when REX.X is clear. With REX.X set, the same raw
        // encoding names r12 and must be preserved.
        let raw_index = (sib_byte >> 3) & 0x7;
        if raw_index != 0x4 || prefixes.rex.is_some_and(|rex| rex.x) {
            index = Some(decode_gpr(sib.index, 64, false));
            scale = sib.scale_factor();
        }

        // Base register
        // When SIB base=5 and mod=00, there's no base register but there IS a 32-bit displacement
        if (sib.base & 0x7) == 0x5 && modrm.mod_ == 0b00 {
            // No base, just displacement (disp32)
            sib_disp32 = true;
        } else {
            base = Some(decode_gpr(sib.base, 64, false));
        }
    } else if (modrm.rm & 0x7) == 0x5 && modrm.mod_ == 0b00 {
        // RIP-relative addressing
        let end = offset.checked_add(4)?;
        let chunk = bytes.get(offset..end)?;
        let disp = i32::from_le_bytes(chunk.try_into().unwrap_or_default());
        offset = end;
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
                segment: prefixes.segment.map(decode_segment),
                broadcast: false,
                index_mode: IndexMode::None,
                space: hexray_core::MemorySpace::Generic,
            }),
            offset,
        ));
    } else {
        // Simple register addressing
        base = Some(decode_gpr(modrm.rm, 64, false));
    }

    // Read displacement
    // disp32 is needed for: mod=10, or mod=00 with rm=5 (RIP-relative), or SIB with base=5 and mod=00
    if modrm.has_disp32() || sib_disp32 {
        let end = offset.checked_add(4)?;
        let chunk = bytes.get(offset..end)?;
        let disp = i32::from_le_bytes(chunk.try_into().unwrap_or_default());
        displacement = disp as i64;
        offset = end;
    } else if modrm.has_disp8() {
        let &b = bytes.get(offset)?;
        displacement = b as i8 as i64;
        offset = offset.saturating_add(1);
    }

    Some((
        Operand::Memory(MemoryRef {
            base,
            index,
            scale,
            displacement,
            size: (operand_size / 8) as u8,
            segment: prefixes.segment.map(decode_segment),
            broadcast: false,
            index_mode: IndexMode::None,
            space: hexray_core::MemorySpace::Generic,
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
        return Some((Operand::Register(decode_xmm(modrm.rm, vector_size)), 0));
    }

    // Otherwise, it's a memory operand - use the same decoding but with vector size
    // Memory operand size is the vector size / 8
    decode_modrm_rm(bytes, modrm, prefixes, vector_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_modrm_rm_preserves_segment_override() {
        let prefixes = Prefixes {
            segment: Some(Segment::FS),
            ..Default::default()
        };
        let modrm = ModRM {
            mod_: 0b00,
            reg: 0,
            rm: 0b100,
        };
        let bytes = [0x25, 0xb0, 0xff, 0xff, 0xff];

        let (operand, consumed) = decode_modrm_rm(&bytes, modrm, &prefixes, 32).unwrap();

        assert_eq!(consumed, 5);
        let Operand::Memory(mem) = operand else {
            panic!("expected memory operand");
        };
        assert_eq!(mem.displacement, -0x50);
        assert_eq!(
            mem.segment.as_ref().map(|segment| segment.id),
            Some(x86::FS)
        );
    }

    #[test]
    fn decode_modrm_rm_preserves_extended_sib_index_register() {
        let prefixes = Prefixes {
            rex: Some(Rex {
                x: true,
                b: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let modrm = ModRM {
            mod_: 0b00,
            reg: 0,
            rm: 0b100,
        };
        let bytes = [0x24];

        let (operand, consumed) = decode_modrm_rm(&bytes, modrm, &prefixes, 32).unwrap();

        assert_eq!(consumed, 1);
        let Operand::Memory(mem) = operand else {
            panic!("expected memory operand");
        };
        assert_eq!(mem.base.as_ref().map(|reg| reg.name()), Some("r12"));
        assert_eq!(mem.index.as_ref().map(|reg| reg.name()), Some("r12"));
        assert_eq!(mem.scale, 1);
    }
}
