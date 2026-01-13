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
    /// VEX prefix (2-byte or 3-byte)
    pub vex: Option<Vex>,
    /// EVEX prefix (4-byte, AVX-512)
    pub evex: Option<Evex>,
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

/// VEX prefix (used for AVX instructions).
/// Can be 2-byte (0xC5) or 3-byte (0xC4).
#[derive(Debug, Clone, Copy, Default)]
pub struct Vex {
    /// VEX.R (~REX.R) - extends ModR/M reg field
    pub r: bool,
    /// VEX.X (~REX.X) - extends SIB index field (only in 3-byte VEX)
    pub x: bool,
    /// VEX.B (~REX.B) - extends ModR/M r/m field (only in 3-byte VEX)
    pub b: bool,
    /// VEX.W - 64-bit operand size / opcode extension
    pub w: bool,
    /// VEX.vvvv - additional operand (inverted, 4 bits)
    pub vvvv: u8,
    /// VEX.L - vector length (0 = 128-bit/XMM, 1 = 256-bit/YMM)
    pub l: bool,
    /// VEX.pp - implied prefix (00=none, 01=0x66, 10=0xF3, 11=0xF2)
    pub pp: u8,
    /// VEX.mmmmm - implied escape bytes (1=0x0F, 2=0x0F38, 3=0x0F3A)
    pub mmmmm: u8,
}

impl Vex {
    /// Parse a 2-byte VEX prefix (0xC5 pp).
    pub fn from_2byte(byte1: u8) -> Self {
        // C5 RvvvvLpp
        Self {
            r: (byte1 & 0x80) == 0, // Inverted
            x: true,                 // Not encoded in 2-byte, default to 1 (no extension)
            b: true,                 // Not encoded in 2-byte, default to 1 (no extension)
            w: false,                // Not encoded in 2-byte, default to 0
            vvvv: (!byte1 >> 3) & 0x0F,
            l: (byte1 & 0x04) != 0,
            pp: byte1 & 0x03,
            mmmmm: 1,                // 2-byte VEX implies 0x0F escape
        }
    }

    /// Parse a 3-byte VEX prefix (0xC4 mmmmm WvvvvLpp).
    pub fn from_3byte(byte1: u8, byte2: u8) -> Self {
        // C4 RXBmmmmm WvvvvLpp
        Self {
            r: (byte1 & 0x80) == 0, // Inverted
            x: (byte1 & 0x40) == 0, // Inverted
            b: (byte1 & 0x20) == 0, // Inverted
            w: (byte2 & 0x80) != 0,
            vvvv: (!byte2 >> 3) & 0x0F,
            l: (byte2 & 0x04) != 0,
            pp: byte2 & 0x03,
            mmmmm: byte1 & 0x1F,
        }
    }

    /// Returns the vector length in bits (128 or 256).
    pub fn vector_size(&self) -> u16 {
        if self.l { 256 } else { 128 }
    }

    /// Returns the implied legacy prefix byte (0x66, 0xF3, 0xF2, or None).
    pub fn implied_prefix(&self) -> Option<u8> {
        match self.pp {
            0 => None,
            1 => Some(0x66),
            2 => Some(0xF3),
            3 => Some(0xF2),
            _ => None,
        }
    }

    /// Converts VEX fields to an equivalent REX struct.
    pub fn to_rex(&self) -> Rex {
        Rex {
            w: self.w,
            r: self.r,
            x: self.x,
            b: self.b,
        }
    }
}

/// EVEX prefix (4-byte, used for AVX-512 instructions).
/// Format: 62 P0 P1 P2
#[derive(Debug, Clone, Copy, Default)]
pub struct Evex {
    // P0 byte: RXBR'00mm
    /// EVEX.R (~REX.R) - extends ModR/M reg field
    pub r: bool,
    /// EVEX.X (~REX.X) - extends SIB index field
    pub x: bool,
    /// EVEX.B (~REX.B) - extends ModR/M r/m field
    pub b: bool,
    /// EVEX.R' - high bit of register encoding
    pub r_prime: bool,
    /// EVEX.mm - opcode map (1=0x0F, 2=0x0F38, 3=0x0F3A)
    pub mm: u8,

    // P1 byte: WvvvvUpp
    /// EVEX.W - 64-bit operand size / opcode extension
    pub w: bool,
    /// EVEX.vvvv - additional operand (inverted, 4 bits)
    pub vvvv: u8,
    /// EVEX.pp - implied prefix (00=none, 01=0x66, 10=0xF3, 11=0xF2)
    pub pp: u8,

    // P2 byte: zL'Lbv'aaa
    /// EVEX.z - zeroing/merging (0=merge, 1=zero)
    pub z: bool,
    /// EVEX.L'L - vector length (00=128, 01=256, 10=512)
    pub ll: u8,
    /// EVEX.b - broadcast/rounding/SAE
    pub broadcast: bool,
    /// EVEX.V' - extends vvvv to 5 bits
    pub v_prime: bool,
    /// EVEX.aaa - opmask register k0-k7
    pub aaa: u8,
}

impl Evex {
    /// Parse a 4-byte EVEX prefix (0x62 P0 P1 P2).
    pub fn from_bytes(p0: u8, p1: u8, p2: u8) -> Self {
        // P0: RXBR'00mm
        // Bit 7: ~R, Bit 6: ~X, Bit 5: ~B, Bit 4: ~R'
        // Bits 3-2: must be 00 (distinguishes from BOUND in 32-bit mode)
        // Bits 1-0: mm (opcode map)
        let r = (p0 & 0x80) == 0;       // Inverted
        let x = (p0 & 0x40) == 0;       // Inverted
        let b = (p0 & 0x20) == 0;       // Inverted
        let r_prime = (p0 & 0x10) == 0; // Inverted
        let mm = p0 & 0x03;

        // P1: WvvvvUpp
        // Bit 7: W
        // Bits 6-3: ~vvvv (inverted)
        // Bit 2: U (must be 1 for EVEX, 0 reserved)
        // Bits 1-0: pp
        let w = (p1 & 0x80) != 0;
        let vvvv = (!p1 >> 3) & 0x0F;
        let pp = p1 & 0x03;

        // P2: zL'Lb~v'aaa
        // Bit 7: z (zeroing)
        // Bits 6-5: L'L (vector length)
        // Bit 4: b (broadcast/rounding/SAE)
        // Bit 3: ~V' (inverted, extends vvvv)
        // Bits 2-0: aaa (opmask register)
        let z = (p2 & 0x80) != 0;
        let ll = (p2 >> 5) & 0x03;
        let broadcast = (p2 & 0x10) != 0;
        let v_prime = (p2 & 0x08) == 0; // Inverted
        let aaa = p2 & 0x07;

        Self {
            r, x, b, r_prime, mm,
            w, vvvv, pp,
            z, ll, broadcast, v_prime, aaa,
        }
    }

    /// Returns the vector length in bits (128, 256, or 512).
    pub fn vector_size(&self) -> u16 {
        match self.ll {
            0 => 128,
            1 => 256,
            2 => 512,
            _ => 512, // L'L=11 is reserved but assume 512
        }
    }

    /// Returns the implied legacy prefix byte (0x66, 0xF3, 0xF2, or None).
    pub fn implied_prefix(&self) -> Option<u8> {
        match self.pp {
            0 => None,
            1 => Some(0x66),
            2 => Some(0xF3),
            3 => Some(0xF2),
            _ => None,
        }
    }

    /// Returns the full 5-bit vvvv register encoding.
    pub fn vvvvv(&self) -> u8 {
        if self.v_prime {
            self.vvvv | 0x10
        } else {
            self.vvvv
        }
    }

    /// Returns the opmask register number (k0-k7).
    pub fn opmask(&self) -> u8 {
        self.aaa
    }

    /// Returns true if zeroing mode is enabled.
    pub fn is_zeroing(&self) -> bool {
        self.z
    }

    /// Returns true if broadcast is enabled.
    pub fn is_broadcast(&self) -> bool {
        self.broadcast
    }

    /// Converts EVEX fields to an equivalent REX struct.
    pub fn to_rex(&self) -> Rex {
        Rex {
            w: self.w,
            r: self.r,
            x: self.x,
            b: self.b,
        }
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

                // 2-byte VEX prefix (0xC5)
                0xC5 => {
                    if offset + 1 < bytes.len() {
                        // In 64-bit mode, 0xC5 is always VEX
                        // In 32-bit mode, check ModR/M (bits 7:6 != 11)
                        prefixes.vex = Some(Vex::from_2byte(bytes[offset + 1]));
                        offset += 2;
                        break;
                    } else {
                        break; // Not enough bytes for VEX
                    }
                }

                // 3-byte VEX prefix (0xC4)
                0xC4 => {
                    if offset + 2 < bytes.len() {
                        // In 64-bit mode, 0xC4 is always VEX
                        prefixes.vex = Some(Vex::from_3byte(bytes[offset + 1], bytes[offset + 2]));
                        offset += 3;
                        break;
                    } else {
                        break; // Not enough bytes for VEX
                    }
                }

                // 4-byte EVEX prefix (0x62)
                0x62 => {
                    if offset + 3 < bytes.len() {
                        // Check if this is a valid EVEX prefix
                        // In 64-bit mode, 0x62 is always EVEX
                        // In 32-bit mode, EVEX.P0 bits 3-2 must be 0 (not BOUND)
                        let p0 = bytes[offset + 1];
                        let p1 = bytes[offset + 2];
                        let p2 = bytes[offset + 3];

                        // Validate EVEX format: P0 bits 3-2 must be 00
                        // and P1 bit 2 (U) must be 1
                        if (p0 & 0x0C) == 0 && (p1 & 0x04) != 0 {
                            prefixes.evex = Some(Evex::from_bytes(p0, p1, p2));
                            offset += 4;
                            break;
                        }
                    }
                    break; // Not enough bytes or invalid EVEX
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

    /// Returns an effective REX-like prefix from either REX, VEX, or EVEX.
    pub fn effective_rex(&self) -> Option<Rex> {
        if let Some(evex) = self.evex {
            Some(evex.to_rex())
        } else if let Some(vex) = self.vex {
            Some(vex.to_rex())
        } else {
            self.rex
        }
    }

    /// Returns true if this is a VEX-encoded instruction.
    pub fn is_vex(&self) -> bool {
        self.vex.is_some()
    }

    /// Returns true if this is an EVEX-encoded instruction.
    pub fn is_evex(&self) -> bool {
        self.evex.is_some()
    }

    /// Returns true if this uses any vector encoding (VEX or EVEX).
    pub fn is_vector_encoded(&self) -> bool {
        self.vex.is_some() || self.evex.is_some()
    }

    /// Returns the vector size in bits (128 for XMM, 256 for YMM, 512 for ZMM).
    pub fn vector_size(&self) -> u16 {
        if let Some(evex) = self.evex {
            evex.vector_size()
        } else if let Some(vex) = self.vex {
            vex.vector_size()
        } else {
            128
        }
    }

    /// Returns the opcode map for VEX/EVEX instructions.
    pub fn opcode_map(&self) -> u8 {
        if let Some(evex) = self.evex {
            evex.mm
        } else if let Some(vex) = self.vex {
            vex.mmmmm
        } else {
            0
        }
    }

    /// Returns the opmask register for EVEX instructions (k0-k7).
    pub fn opmask(&self) -> Option<u8> {
        self.evex.map(|e| e.opmask())
    }

    /// Returns true if EVEX zeroing mode is enabled.
    pub fn is_zeroing(&self) -> bool {
        self.evex.map(|e| e.is_zeroing()).unwrap_or(false)
    }

    /// Returns true if EVEX broadcast is enabled.
    pub fn is_broadcast(&self) -> bool {
        self.evex.map(|e| e.is_broadcast()).unwrap_or(false)
    }
}
