use crate::ParseError;

// Section flags
pub const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x80000000;
pub const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x00000400;

// VM protection flags
pub const VM_PROT_READ: u32 = 0x01;
pub const VM_PROT_WRITE: u32 = 0x02;
pub const VM_PROT_EXECUTE: u32 = 0x04;

// Bounds-checked little-endian readers (caller has already verified
// the buffer length at function entry).
#[inline]
fn read_u32(data: &[u8], at: usize) -> u32 {
    let end = at.saturating_add(4);
    let arr: [u8; 4] = data
        .get(at..end)
        .unwrap_or(&[0; 4])
        .try_into()
        .unwrap_or_default();
    u32::from_le_bytes(arr)
}

#[inline]
fn read_u64(data: &[u8], at: usize) -> u64 {
    let end = at.saturating_add(8);
    let arr: [u8; 8] = data
        .get(at..end)
        .unwrap_or(&[0; 8])
        .try_into()
        .unwrap_or_default();
    u64::from_le_bytes(arr)
}

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

        let segname = parse_name(data.get(8..24).unwrap_or(&[]));
        let vmaddr = read_u32(data, 24) as u64;
        let vmsize = read_u32(data, 28) as u64;
        let fileoff = read_u32(data, 32) as u64;
        let filesize = read_u32(data, 36) as u64;
        let maxprot = read_u32(data, 40);
        let initprot = read_u32(data, 44);
        let nsects = read_u32(data, 48);
        let flags = read_u32(data, 52);

        // Parse sections
        let mut sections = Vec::with_capacity(nsects.min(1000) as usize);
        let mut offset: usize = 56;
        for _ in 0..nsects {
            let next = offset.saturating_add(68);
            let Some(slice) = data.get(offset..next) else {
                break;
            };
            sections.push(Section::parse_32(slice)?);
            offset = next;
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

        let segname = parse_name(data.get(8..24).unwrap_or(&[]));
        let vmaddr = read_u64(data, 24);
        let vmsize = read_u64(data, 32);
        let fileoff = read_u64(data, 40);
        let filesize = read_u64(data, 48);
        let maxprot = read_u32(data, 56);
        let initprot = read_u32(data, 60);
        let nsects = read_u32(data, 64);
        let flags = read_u32(data, 68);

        // Parse sections
        let mut sections = Vec::with_capacity(nsects.min(1000) as usize);
        let mut offset: usize = 72;
        for _ in 0..nsects {
            let next = offset.saturating_add(80);
            let Some(slice) = data.get(offset..next) else {
                break;
            };
            sections.push(Section::parse_64(slice)?);
            offset = next;
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
            sectname: parse_name(data.get(0..16).unwrap_or(&[])),
            segname: parse_name(data.get(16..32).unwrap_or(&[])),
            addr: read_u32(data, 32) as u64,
            size: read_u32(data, 36) as u64,
            offset: read_u32(data, 40),
            align: read_u32(data, 44),
            reloff: read_u32(data, 48),
            nreloc: read_u32(data, 52),
            flags: read_u32(data, 56),
            reserved1: read_u32(data, 60),
            reserved2: read_u32(data, 64),
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
            sectname: parse_name(data.get(0..16).unwrap_or(&[])),
            segname: parse_name(data.get(16..32).unwrap_or(&[])),
            addr: read_u64(data, 32),
            size: read_u64(data, 40),
            offset: read_u32(data, 48),
            align: read_u32(data, 52),
            reloff: read_u32(data, 56),
            nreloc: read_u32(data, 60),
            flags: read_u32(data, 64),
            reserved1: read_u32(data, 68),
            reserved2: read_u32(data, 72),
            reserved3: read_u32(data, 76),
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
        let end = start.saturating_add(self.size as usize);
        if end > start {
            if let Some(slice) = file_data.get(start..end) {
                self.data_cache = slice.to_vec();
            }
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
        self.flags & S_ATTR_PURE_INSTRUCTIONS != 0 || self.flags & S_ATTR_SOME_INSTRUCTIONS != 0
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
    crate::name_from_bytes(data.get(..end).unwrap_or(&[]))
}
