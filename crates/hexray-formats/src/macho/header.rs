//! Mach-O header parsing.

use crate::ParseError;
use hexray_core::Architecture;

// Magic numbers
pub const MH_MAGIC: u32 = 0xFEEDFACE;    // 32-bit
pub const MH_CIGAM: u32 = 0xCEFAEDFE;    // 32-bit, byte-swapped
pub const MH_MAGIC_64: u32 = 0xFEEDFACF; // 64-bit
pub const MH_CIGAM_64: u32 = 0xCFFAEDFE; // 64-bit, byte-swapped
pub const FAT_MAGIC: u32 = 0xCAFEBABE;   // Fat binary
pub const FAT_CIGAM: u32 = 0xBEBAFECA;   // Fat binary, byte-swapped

// CPU types
pub const CPU_TYPE_X86: u32 = 7;
pub const CPU_TYPE_X86_64: u32 = CPU_TYPE_X86 | 0x01000000;
pub const CPU_TYPE_ARM: u32 = 12;
pub const CPU_TYPE_ARM64: u32 = CPU_TYPE_ARM | 0x01000000;
pub const CPU_TYPE_ARM64_32: u32 = CPU_TYPE_ARM | 0x02000000;

// File types
pub const MH_OBJECT: u32 = 0x1;
pub const MH_EXECUTE: u32 = 0x2;
pub const MH_FVMLIB: u32 = 0x3;
pub const MH_CORE: u32 = 0x4;
pub const MH_PRELOAD: u32 = 0x5;
pub const MH_DYLIB: u32 = 0x6;
pub const MH_DYLINKER: u32 = 0x7;
pub const MH_BUNDLE: u32 = 0x8;
pub const MH_DSYM: u32 = 0xA;
pub const MH_KEXT_BUNDLE: u32 = 0xB;

/// CPU type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuType {
    X86,
    X86_64,
    Arm,
    Arm64,
    Arm64_32,
    Other(u32),
}

impl CpuType {
    pub fn from_u32(value: u32) -> Self {
        match value {
            CPU_TYPE_X86 => Self::X86,
            CPU_TYPE_X86_64 => Self::X86_64,
            CPU_TYPE_ARM => Self::Arm,
            CPU_TYPE_ARM64 => Self::Arm64,
            CPU_TYPE_ARM64_32 => Self::Arm64_32,
            other => Self::Other(other),
        }
    }
}

/// File type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Object,
    Execute,
    Dylib,
    Dylinker,
    Bundle,
    Dsym,
    KextBundle,
    Other(u32),
}

impl FileType {
    pub fn from_u32(value: u32) -> Self {
        match value {
            MH_OBJECT => Self::Object,
            MH_EXECUTE => Self::Execute,
            MH_DYLIB => Self::Dylib,
            MH_DYLINKER => Self::Dylinker,
            MH_BUNDLE => Self::Bundle,
            MH_DSYM => Self::Dsym,
            MH_KEXT_BUNDLE => Self::KextBundle,
            other => Self::Other(other),
        }
    }
}

/// Mach-O header.
#[derive(Debug, Clone)]
pub struct MachHeader {
    /// Magic number.
    pub magic: u32,
    /// CPU type.
    pub cputype: CpuType,
    /// CPU subtype.
    pub cpusubtype: u32,
    /// File type.
    pub filetype: FileType,
    /// Number of load commands.
    pub ncmds: u32,
    /// Size of all load commands.
    pub sizeofcmds: u32,
    /// Flags.
    pub flags: u32,
    /// Reserved (64-bit only).
    pub reserved: u32,
}

impl MachHeader {
    /// Parse a Mach-O header from bytes.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 28 {
            return Err(ParseError::too_short(28, data.len()));
        }

        let magic = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);

        let (is_64, needs_swap) = match magic {
            MH_MAGIC => (false, false),
            MH_CIGAM => (false, true),
            MH_MAGIC_64 => (true, false),
            MH_CIGAM_64 => (true, true),
            _ => {
                return Err(ParseError::invalid_magic(
                    "Mach-O",
                    &data[0..4],
                ));
            }
        };

        let min_size = if is_64 { 32 } else { 28 };
        if data.len() < min_size {
            return Err(ParseError::too_short(min_size, data.len()));
        }

        let read_u32 = |offset: usize| -> u32 {
            let val = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            if needs_swap { val.swap_bytes() } else { val }
        };

        let cputype = read_u32(4);
        let cpusubtype = read_u32(8);
        let filetype = read_u32(12);
        let ncmds = read_u32(16);
        let sizeofcmds = read_u32(20);
        let flags = read_u32(24);
        let reserved = if is_64 { read_u32(28) } else { 0 };

        Ok(Self {
            magic,
            cputype: CpuType::from_u32(cputype),
            cpusubtype,
            filetype: FileType::from_u32(filetype),
            ncmds,
            sizeofcmds,
            flags,
            reserved,
        })
    }

    /// Returns true if this is a 64-bit Mach-O.
    pub fn is_64bit(&self) -> bool {
        self.magic == MH_MAGIC_64 || self.magic == MH_CIGAM_64
    }

    /// Returns the size of the header in bytes.
    pub fn header_size(&self) -> usize {
        if self.is_64bit() { 32 } else { 28 }
    }

    /// Returns the architecture.
    pub fn architecture(&self) -> Architecture {
        match self.cputype {
            CpuType::X86_64 => Architecture::X86_64,
            CpuType::X86 => Architecture::X86,
            CpuType::Arm64 | CpuType::Arm64_32 => Architecture::Arm64,
            CpuType::Arm => Architecture::Arm,
            CpuType::Other(v) => Architecture::Unknown(v as u16),
        }
    }
}

/// Fat binary header.
#[derive(Debug)]
pub struct FatHeader {
    /// Architectures in the fat binary.
    pub architectures: Vec<FatArch>,
}

/// Architecture entry in a fat binary.
#[derive(Debug, Clone)]
pub struct FatArch {
    /// CPU type.
    pub cputype: u32,
    /// CPU subtype.
    pub cpusubtype: u32,
    /// File offset to this architecture.
    pub offset: u32,
    /// Size of this architecture.
    pub size: u32,
    /// Alignment (power of 2).
    pub align: u32,
}

impl FatHeader {
    /// Parse a fat binary header.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 8 {
            return Err(ParseError::too_short(8, data.len()));
        }

        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let needs_swap = magic == FAT_CIGAM;

        if magic != FAT_MAGIC && magic != FAT_CIGAM {
            return Err(ParseError::invalid_magic("fat Mach-O", &data[0..4]));
        }

        let nfat_arch = if needs_swap {
            u32::from_be_bytes([data[4], data[5], data[6], data[7]]).swap_bytes()
        } else {
            u32::from_be_bytes([data[4], data[5], data[6], data[7]])
        };

        let mut architectures = Vec::with_capacity(nfat_arch as usize);
        let mut offset = 8;

        for _ in 0..nfat_arch {
            if offset + 20 > data.len() {
                break;
            }

            let read_u32 = |o: usize| -> u32 {
                let val = u32::from_be_bytes([
                    data[o],
                    data[o + 1],
                    data[o + 2],
                    data[o + 3],
                ]);
                if needs_swap { val.swap_bytes() } else { val }
            };

            architectures.push(FatArch {
                cputype: read_u32(offset),
                cpusubtype: read_u32(offset + 4),
                offset: read_u32(offset + 8),
                size: read_u32(offset + 12),
                align: read_u32(offset + 16),
            });

            offset += 20;
        }

        Ok(Self { architectures })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mach64_header() {
        // Minimal valid Mach-O 64-bit header
        let mut data = vec![0u8; 32];
        // Magic: MH_MAGIC_64
        data[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        // CPU type: x86_64
        data[4..8].copy_from_slice(&CPU_TYPE_X86_64.to_le_bytes());
        // File type: execute
        data[12..16].copy_from_slice(&MH_EXECUTE.to_le_bytes());

        let header = MachHeader::parse(&data).unwrap();
        assert!(header.is_64bit());
        assert_eq!(header.cputype, CpuType::X86_64);
        assert_eq!(header.filetype, FileType::Execute);
        assert_eq!(header.architecture(), Architecture::X86_64);
    }

    #[test]
    fn test_parse_fat_magic() {
        let mut data = vec![0u8; 28];
        // Fat magic
        data[0..4].copy_from_slice(&FAT_MAGIC.to_be_bytes());
        // 1 architecture
        data[4..8].copy_from_slice(&1u32.to_be_bytes());
        // CPU type: x86_64
        data[8..12].copy_from_slice(&CPU_TYPE_X86_64.to_be_bytes());
        // CPU subtype
        data[12..16].copy_from_slice(&0u32.to_be_bytes());
        // Offset
        data[16..20].copy_from_slice(&4096u32.to_be_bytes());
        // Size
        data[20..24].copy_from_slice(&1000u32.to_be_bytes());
        // Align
        data[24..28].copy_from_slice(&12u32.to_be_bytes());

        let fat = FatHeader::parse(&data).unwrap();
        assert_eq!(fat.architectures.len(), 1);
        assert_eq!(fat.architectures[0].cputype, CPU_TYPE_X86_64);
        assert_eq!(fat.architectures[0].offset, 4096);
    }
}
