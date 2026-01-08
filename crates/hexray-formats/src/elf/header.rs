//! ELF header parsing.

use crate::ParseError;
use hexray_core::{Architecture, Endianness};

/// ELF magic bytes.
pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// ELF class (32-bit or 64-bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfClass {
    Elf32,
    Elf64,
}

/// ELF file type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfType {
    /// No file type.
    None,
    /// Relocatable file.
    Relocatable,
    /// Executable file.
    Executable,
    /// Shared object file.
    SharedObject,
    /// Core file.
    Core,
    /// Other type.
    Other(u16),
}

impl From<u16> for ElfType {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Relocatable,
            2 => Self::Executable,
            3 => Self::SharedObject,
            4 => Self::Core,
            other => Self::Other(other),
        }
    }
}

/// Machine architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Machine {
    None,
    X86,
    X86_64,
    Arm,
    Arm64,
    RiscV,
    Other(u16),
}

impl Machine {
    pub fn from_u16(value: u16) -> Self {
        match value {
            0 => Self::None,
            3 => Self::X86,
            40 => Self::Arm,
            62 => Self::X86_64,
            183 => Self::Arm64,
            243 => Self::RiscV,
            other => Self::Other(other),
        }
    }
}

/// Parsed ELF header.
#[derive(Debug)]
pub struct ElfHeader {
    /// ELF class (32 or 64 bit).
    pub class: ElfClass,
    /// Endianness.
    pub endianness: Endianness,
    /// ELF version (should be 1).
    pub version: u8,
    /// OS/ABI identification.
    pub osabi: u8,
    /// ABI version.
    pub abi_version: u8,
    /// File type.
    pub file_type: ElfType,
    /// Machine architecture.
    pub machine: Machine,
    /// Entry point virtual address.
    pub e_entry: u64,
    /// Program header table file offset.
    pub e_phoff: u64,
    /// Section header table file offset.
    pub e_shoff: u64,
    /// Processor-specific flags.
    pub e_flags: u32,
    /// ELF header size.
    pub e_ehsize: u16,
    /// Program header table entry size.
    pub e_phentsize: u16,
    /// Program header table entry count.
    pub e_phnum: u16,
    /// Section header table entry size.
    pub e_shentsize: u16,
    /// Section header table entry count.
    pub e_shnum: u16,
    /// Section name string table index.
    pub e_shstrndx: u16,
}

impl ElfHeader {
    /// Minimum size of the ELF identification bytes.
    const EI_NIDENT: usize = 16;

    /// Parse an ELF header from bytes.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        // Check minimum size for ident bytes
        if data.len() < Self::EI_NIDENT {
            return Err(ParseError::too_short(Self::EI_NIDENT, data.len()));
        }

        // Check magic
        if data[0..4] != ELF_MAGIC {
            return Err(ParseError::invalid_magic("ELF", &data[0..4]));
        }

        // Parse ELF class
        let class = match data[4] {
            1 => ElfClass::Elf32,
            2 => ElfClass::Elf64,
            _ => {
                return Err(ParseError::invalid_structure(
                    "ELF header",
                    4,
                    format!("invalid ELF class: {}", data[4]),
                ))
            }
        };

        // Parse endianness
        let endianness = match data[5] {
            1 => Endianness::Little,
            2 => Endianness::Big,
            _ => {
                return Err(ParseError::invalid_structure(
                    "ELF header",
                    5,
                    format!("invalid endianness: {}", data[5]),
                ))
            }
        };

        let version = data[6];
        let osabi = data[7];
        let abi_version = data[8];

        // Parse the rest based on class
        match class {
            ElfClass::Elf32 => Self::parse_elf32(data, endianness, version, osabi, abi_version),
            ElfClass::Elf64 => Self::parse_elf64(data, endianness, version, osabi, abi_version),
        }
    }

    fn parse_elf32(
        data: &[u8],
        endianness: Endianness,
        version: u8,
        osabi: u8,
        abi_version: u8,
    ) -> Result<Self, ParseError> {
        const ELF32_HEADER_SIZE: usize = 52;

        if data.len() < ELF32_HEADER_SIZE {
            return Err(ParseError::too_short(ELF32_HEADER_SIZE, data.len()));
        }

        let read_u16 = |offset: usize| -> u16 {
            let bytes = [data[offset], data[offset + 1]];
            match endianness {
                Endianness::Little => u16::from_le_bytes(bytes),
                Endianness::Big => u16::from_be_bytes(bytes),
            }
        };

        let read_u32 = |offset: usize| -> u32 {
            let bytes = [
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ];
            match endianness {
                Endianness::Little => u32::from_le_bytes(bytes),
                Endianness::Big => u32::from_be_bytes(bytes),
            }
        };

        Ok(Self {
            class: ElfClass::Elf32,
            endianness,
            version,
            osabi,
            abi_version,
            file_type: ElfType::from(read_u16(16)),
            machine: Machine::from_u16(read_u16(18)),
            e_entry: read_u32(24) as u64,
            e_phoff: read_u32(28) as u64,
            e_shoff: read_u32(32) as u64,
            e_flags: read_u32(36),
            e_ehsize: read_u16(40),
            e_phentsize: read_u16(42),
            e_phnum: read_u16(44),
            e_shentsize: read_u16(46),
            e_shnum: read_u16(48),
            e_shstrndx: read_u16(50),
        })
    }

    fn parse_elf64(
        data: &[u8],
        endianness: Endianness,
        version: u8,
        osabi: u8,
        abi_version: u8,
    ) -> Result<Self, ParseError> {
        const ELF64_HEADER_SIZE: usize = 64;

        if data.len() < ELF64_HEADER_SIZE {
            return Err(ParseError::too_short(ELF64_HEADER_SIZE, data.len()));
        }

        let read_u16 = |offset: usize| -> u16 {
            let bytes = [data[offset], data[offset + 1]];
            match endianness {
                Endianness::Little => u16::from_le_bytes(bytes),
                Endianness::Big => u16::from_be_bytes(bytes),
            }
        };

        let read_u32 = |offset: usize| -> u32 {
            let bytes = [
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ];
            match endianness {
                Endianness::Little => u32::from_le_bytes(bytes),
                Endianness::Big => u32::from_be_bytes(bytes),
            }
        };

        let read_u64 = |offset: usize| -> u64 {
            let bytes = [
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ];
            match endianness {
                Endianness::Little => u64::from_le_bytes(bytes),
                Endianness::Big => u64::from_be_bytes(bytes),
            }
        };

        Ok(Self {
            class: ElfClass::Elf64,
            endianness,
            version,
            osabi,
            abi_version,
            file_type: ElfType::from(read_u16(16)),
            machine: Machine::from_u16(read_u16(18)),
            e_entry: read_u64(24),
            e_phoff: read_u64(32),
            e_shoff: read_u64(40),
            e_flags: read_u32(48),
            e_ehsize: read_u16(52),
            e_phentsize: read_u16(54),
            e_phnum: read_u16(56),
            e_shentsize: read_u16(58),
            e_shnum: read_u16(60),
            e_shstrndx: read_u16(62),
        })
    }

    /// Returns the architecture for this ELF.
    pub fn architecture(&self) -> Architecture {
        match (self.machine, self.class) {
            (Machine::X86_64, _) => Architecture::X86_64,
            (Machine::X86, _) => Architecture::X86,
            (Machine::Arm64, _) => Architecture::Arm64,
            (Machine::Arm, _) => Architecture::Arm,
            (Machine::RiscV, ElfClass::Elf64) => Architecture::RiscV64,
            (Machine::RiscV, ElfClass::Elf32) => Architecture::RiscV32,
            (Machine::Other(m), _) => Architecture::Unknown(m),
            (Machine::None, _) => Architecture::Unknown(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_elf64_header() {
        // Minimal valid ELF64 header (little-endian, x86_64, executable)
        let mut data = vec![0u8; 64];
        // Magic
        data[0..4].copy_from_slice(&ELF_MAGIC);
        // Class: ELF64
        data[4] = 2;
        // Endianness: little
        data[5] = 1;
        // Version
        data[6] = 1;
        // Type: executable (2)
        data[16] = 2;
        data[17] = 0;
        // Machine: x86_64 (62)
        data[18] = 62;
        data[19] = 0;
        // Entry point
        data[24..32].copy_from_slice(&0x401000u64.to_le_bytes());

        let header = ElfHeader::parse(&data).unwrap();
        assert_eq!(header.class, ElfClass::Elf64);
        assert_eq!(header.endianness, Endianness::Little);
        assert_eq!(header.machine, Machine::X86_64);
        assert_eq!(header.e_entry, 0x401000);
        assert_eq!(header.architecture(), Architecture::X86_64);
    }

    #[test]
    fn test_reject_invalid_magic() {
        let data = b"NOT_AN_ELF_FILE!";
        let result = ElfHeader::parse(data);
        assert!(matches!(result, Err(ParseError::InvalidMagic { .. })));
    }

    #[test]
    fn test_reject_too_short() {
        let data = b"\x7fELF";
        let result = ElfHeader::parse(data);
        assert!(matches!(result, Err(ParseError::TooShort { .. })));
    }
}
