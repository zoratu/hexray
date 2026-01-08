//! x86 prefix parsing.

#![allow(dead_code)]

/// Legacy prefixes that can appear before an instruction.
#[derive(Debug, Clone, Default)]
pub struct Prefixes {
    /// LOCK prefix (0xF0)
    pub lock: bool,
    /// REPNE/REPNZ prefix (0xF2)
    pub repne: bool,
    /// REP/REPE/REPZ prefix (0xF3)
    pub rep: bool,
    /// Segment override
    pub segment: Option<Segment>,
    /// Operand size override (0x66)
    pub operand_size: bool,
    /// Address size override (0x67)
    pub address_size: bool,
    /// REX prefix
    pub rex: Option<Rex>,
}

/// Segment override prefixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Segment {
    CS,
    SS,
    DS,
    ES,
    FS,
    GS,
}

/// REX prefix fields.
#[derive(Debug, Clone, Copy, Default)]
pub struct Rex {
    /// REX.W - 64-bit operand size
    pub w: bool,
    /// REX.R - extends ModR/M reg field
    pub r: bool,
    /// REX.X - extends SIB index field
    pub x: bool,
    /// REX.B - extends ModR/M r/m, SIB base, or opcode reg
    pub b: bool,
}

impl Rex {
    /// Parse a REX byte.
    pub fn from_byte(byte: u8) -> Self {
        Self {
            w: byte & 0x08 != 0,
            r: byte & 0x04 != 0,
            x: byte & 0x02 != 0,
            b: byte & 0x01 != 0,
        }
    }

    /// Returns true if this REX prefix is "empty" (0x40).
    pub fn is_empty(&self) -> bool {
        !self.w && !self.r && !self.x && !self.b
    }
}

impl Prefixes {
    /// Parse prefixes from the start of an instruction.
    /// Returns the prefixes and the number of bytes consumed.
    pub fn parse(bytes: &[u8]) -> (Self, usize) {
        let mut prefixes = Self::default();
        let mut offset = 0;

        while offset < bytes.len() {
            let byte = bytes[offset];

            match byte {
                // Group 1: LOCK and repeat
                0xF0 => prefixes.lock = true,
                0xF2 => prefixes.repne = true,
                0xF3 => prefixes.rep = true,

                // Group 2: Segment overrides
                0x26 => prefixes.segment = Some(Segment::ES),
                0x2E => prefixes.segment = Some(Segment::CS),
                0x36 => prefixes.segment = Some(Segment::SS),
                0x3E => prefixes.segment = Some(Segment::DS),
                0x64 => prefixes.segment = Some(Segment::FS),
                0x65 => prefixes.segment = Some(Segment::GS),

                // Group 3: Operand size override
                0x66 => prefixes.operand_size = true,

                // Group 4: Address size override
                0x67 => prefixes.address_size = true,

                // REX prefix (0x40-0x4F in 64-bit mode)
                0x40..=0x4F => {
                    prefixes.rex = Some(Rex::from_byte(byte));
                    offset += 1;
                    // REX must be the last prefix
                    break;
                }

                // Not a prefix
                _ => break,
            }

            offset += 1;
        }

        (prefixes, offset)
    }

    /// Returns the effective operand size in bits.
    pub fn operand_size(&self, default_64: bool) -> u16 {
        if self.rex.map(|r| r.w).unwrap_or(false) {
            64
        } else if self.operand_size {
            16
        } else if default_64 {
            64
        } else {
            32
        }
    }

    /// Returns the effective address size in bits.
    pub fn address_size(&self) -> u16 {
        if self.address_size {
            32
        } else {
            64
        }
    }
}
