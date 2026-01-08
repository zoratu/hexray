//! Mach-O segment and section parsing.

use crate::ParseError;

// Section flags
pub const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x80000000;
pub const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x00000400;

// VM protection flags
pub const VM_PROT_READ: u32 = 0x01;
pub const VM_PROT_WRITE: u32 = 0x02;
pub const VM_PROT_EXECUTE: u32 = 0x04;

/// A Mach-O segment.
#[derive(Debug, Clone)]
pub struct Segment {
    /// Segment name (up to 16 characters).
    pub segname: String,
    /// Virtual memory address.
    pub vmaddr: u64,
    /// Virtual memory size.
    pub vmsize: u64,
    /// File offset.
    pub fileoff: u64,
    /// File size.
    pub filesize: u64,
    /// Maximum VM protection.
    pub maxprot: u32,
    /// Initial VM protection.
    pub initprot: u32,
    /// Flags.
    pub flags: u32,
    /// Sections in this segment.
    pub sections: Vec<Section>,
}

impl Segment {
    /// Parse a 32-bit segment command.
    pub fn parse_32(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 56 {
            return Err(ParseError::too_short(56, data.len()));
        }

        let segname = parse_name(&data[8..24]);
        let vmaddr = u32::from_le_bytes([data[24], data[25], data[26], data[27]]) as u64;
        let vmsize = u32::from_le_bytes([data[28], data[29], data[30], data[31]]) as u64;
        let fileoff = u32::from_le_bytes([data[32], data[33], data[34], data[35]]) as u64;
        let filesize = u32::from_le_bytes([data[36], data[37], data[38], data[39]]) as u64;
        let maxprot = u32::from_le_bytes([data[40], data[41], data[42], data[43]]);
        let initprot = u32::from_le_bytes([data[44], data[45], data[46], data[47]]);
        let nsects = u32::from_le_bytes([data[48], data[49], data[50], data[51]]);
        let flags = u32::from_le_bytes([data[52], data[53], data[54], data[55]]);

        // Parse sections
        let mut sections = Vec::with_capacity(nsects as usize);
        let mut offset = 56;
        for _ in 0..nsects {
            if offset + 68 > data.len() {
                break;
            }
            sections.push(Section::parse_32(&data[offset..])?);
            offset += 68;
        }

        Ok(Self {
            segname,
            vmaddr,
            vmsize,
            fileoff,
            filesize,
            maxprot,
            initprot,
            flags,
            sections,
        })
    }

    /// Parse a 64-bit segment command.
    pub fn parse_64(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 72 {
            return Err(ParseError::too_short(72, data.len()));
        }

        let segname = parse_name(&data[8..24]);
        let vmaddr = u64::from_le_bytes([
            data[24], data[25], data[26], data[27],
            data[28], data[29], data[30], data[31],
        ]);
        let vmsize = u64::from_le_bytes([
            data[32], data[33], data[34], data[35],
            data[36], data[37], data[38], data[39],
        ]);
        let fileoff = u64::from_le_bytes([
            data[40], data[41], data[42], data[43],
            data[44], data[45], data[46], data[47],
        ]);
        let filesize = u64::from_le_bytes([
            data[48], data[49], data[50], data[51],
            data[52], data[53], data[54], data[55],
        ]);
        let maxprot = u32::from_le_bytes([data[56], data[57], data[58], data[59]]);
        let initprot = u32::from_le_bytes([data[60], data[61], data[62], data[63]]);
        let nsects = u32::from_le_bytes([data[64], data[65], data[66], data[67]]);
        let flags = u32::from_le_bytes([data[68], data[69], data[70], data[71]]);

        // Parse sections
        let mut sections = Vec::with_capacity(nsects as usize);
        let mut offset = 72;
        for _ in 0..nsects {
            if offset + 80 > data.len() {
                break;
            }
            sections.push(Section::parse_64(&data[offset..])?);
            offset += 80;
        }

        Ok(Self {
            segname,
            vmaddr,
            vmsize,
            fileoff,
            filesize,
            maxprot,
            initprot,
            flags,
            sections,
        })
    }

    /// Returns true if this segment is executable.
    pub fn is_executable(&self) -> bool {
        self.initprot & VM_PROT_EXECUTE != 0
    }

    /// Returns true if this segment is writable.
    pub fn is_writable(&self) -> bool {
        self.initprot & VM_PROT_WRITE != 0
    }

    /// Returns true if this segment is readable.
    pub fn is_readable(&self) -> bool {
        self.initprot & VM_PROT_READ != 0
    }
}

/// A Mach-O section.
#[derive(Debug, Clone)]
pub struct Section {
    /// Section name (up to 16 characters).
    pub sectname: String,
    /// Segment name this section belongs to.
    pub segname: String,
    /// Virtual memory address.
    pub addr: u64,
    /// Size in bytes.
    pub size: u64,
    /// File offset.
    pub offset: u32,
    /// Alignment (power of 2).
    pub align: u32,
    /// File offset of relocations.
    pub reloff: u32,
    /// Number of relocations.
    pub nreloc: u32,
    /// Flags.
    pub flags: u32,
    /// Reserved fields.
    pub reserved1: u32,
    pub reserved2: u32,
    pub reserved3: u32,
    /// Cached section data.
    data_cache: Vec<u8>,
}

impl Section {
    /// Parse a 32-bit section.
    pub fn parse_32(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 68 {
            return Err(ParseError::too_short(68, data.len()));
        }

        Ok(Self {
            sectname: parse_name(&data[0..16]),
            segname: parse_name(&data[16..32]),
            addr: u32::from_le_bytes([data[32], data[33], data[34], data[35]]) as u64,
            size: u32::from_le_bytes([data[36], data[37], data[38], data[39]]) as u64,
            offset: u32::from_le_bytes([data[40], data[41], data[42], data[43]]),
            align: u32::from_le_bytes([data[44], data[45], data[46], data[47]]),
            reloff: u32::from_le_bytes([data[48], data[49], data[50], data[51]]),
            nreloc: u32::from_le_bytes([data[52], data[53], data[54], data[55]]),
            flags: u32::from_le_bytes([data[56], data[57], data[58], data[59]]),
            reserved1: u32::from_le_bytes([data[60], data[61], data[62], data[63]]),
            reserved2: u32::from_le_bytes([data[64], data[65], data[66], data[67]]),
            reserved3: 0,
            data_cache: Vec::new(),
        })
    }

    /// Parse a 64-bit section.
    pub fn parse_64(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 80 {
            return Err(ParseError::too_short(80, data.len()));
        }

        Ok(Self {
            sectname: parse_name(&data[0..16]),
            segname: parse_name(&data[16..32]),
            addr: u64::from_le_bytes([
                data[32], data[33], data[34], data[35],
                data[36], data[37], data[38], data[39],
            ]),
            size: u64::from_le_bytes([
                data[40], data[41], data[42], data[43],
                data[44], data[45], data[46], data[47],
            ]),
            offset: u32::from_le_bytes([data[48], data[49], data[50], data[51]]),
            align: u32::from_le_bytes([data[52], data[53], data[54], data[55]]),
            reloff: u32::from_le_bytes([data[56], data[57], data[58], data[59]]),
            nreloc: u32::from_le_bytes([data[60], data[61], data[62], data[63]]),
            flags: u32::from_le_bytes([data[64], data[65], data[66], data[67]]),
            reserved1: u32::from_le_bytes([data[68], data[69], data[70], data[71]]),
            reserved2: u32::from_le_bytes([data[72], data[73], data[74], data[75]]),
            reserved3: u32::from_le_bytes([data[76], data[77], data[78], data[79]]),
            data_cache: Vec::new(),
        })
    }

    /// Returns the full section name (segment.section).
    pub fn full_name(&self) -> String {
        format!("{}.{}", self.segname, self.sectname)
    }

    /// Populates the section data cache from the file data.
    pub fn populate_data(&mut self, file_data: &[u8]) {
        let start = self.offset as usize;
        let end = start + self.size as usize;
        if end <= file_data.len() {
            self.data_cache = file_data[start..end].to_vec();
        }
    }
}

impl crate::Section for Section {
    fn name(&self) -> &str {
        &self.sectname
    }

    fn virtual_address(&self) -> u64 {
        self.addr
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn data(&self) -> &[u8] {
        &self.data_cache
    }

    fn is_executable(&self) -> bool {
        self.flags & S_ATTR_PURE_INSTRUCTIONS != 0
            || self.flags & S_ATTR_SOME_INSTRUCTIONS != 0
    }

    fn is_writable(&self) -> bool {
        // Sections don't have their own write flag; check segment
        false
    }

    fn is_allocated(&self) -> bool {
        self.size > 0
    }
}

/// Parse a null-terminated name from a fixed-size buffer.
fn parse_name(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).to_string()
}
