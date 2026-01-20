//! PE header parsing.

#![allow(dead_code)]

use crate::ParseError;

/// DOS header magic number ("MZ")
pub const DOS_MAGIC: u16 = 0x5A4D;

/// PE signature ("PE\0\0")
pub const PE_SIGNATURE: u32 = 0x00004550;

/// Machine types
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;
pub const IMAGE_FILE_MACHINE_ARM: u16 = 0x01c0;
pub const IMAGE_FILE_MACHINE_RISCV32: u16 = 0x5032;
pub const IMAGE_FILE_MACHINE_RISCV64: u16 = 0x5064;

/// PE32 magic
pub const PE32_MAGIC: u16 = 0x10b;
/// PE32+ (64-bit) magic
pub const PE32PLUS_MAGIC: u16 = 0x20b;

/// Characteristics flags
pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
pub const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
pub const IMAGE_FILE_DLL: u16 = 0x2000;

/// Section characteristics
pub const IMAGE_SCN_CNT_CODE: u32 = 0x00000020;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

/// DOS Header (64 bytes)
#[derive(Debug, Clone)]
pub struct DosHeader {
    /// Magic number (MZ)
    pub e_magic: u16,
    /// Offset to PE header
    pub e_lfanew: u32,
}

impl DosHeader {
    /// Parse DOS header from bytes.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 64 {
            return Err(ParseError::too_short(64, data.len()));
        }

        let e_magic = u16::from_le_bytes([data[0], data[1]]);
        if e_magic != DOS_MAGIC {
            return Err(ParseError::invalid_magic("MZ", &data[0..2]));
        }

        let e_lfanew = u32::from_le_bytes([data[60], data[61], data[62], data[63]]);

        Ok(Self { e_magic, e_lfanew })
    }
}

/// COFF File Header (20 bytes)
#[derive(Debug, Clone)]
pub struct CoffHeader {
    /// Machine type
    pub machine: u16,
    /// Number of sections
    pub number_of_sections: u16,
    /// Time stamp
    pub time_date_stamp: u32,
    /// Pointer to symbol table
    pub pointer_to_symbol_table: u32,
    /// Number of symbols
    pub number_of_symbols: u32,
    /// Size of optional header
    pub size_of_optional_header: u16,
    /// Characteristics
    pub characteristics: u16,
}

impl CoffHeader {
    /// Parse COFF header from bytes.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 20 {
            return Err(ParseError::too_short(20, data.len()));
        }

        Ok(Self {
            machine: u16::from_le_bytes([data[0], data[1]]),
            number_of_sections: u16::from_le_bytes([data[2], data[3]]),
            time_date_stamp: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            pointer_to_symbol_table: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            number_of_symbols: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            size_of_optional_header: u16::from_le_bytes([data[16], data[17]]),
            characteristics: u16::from_le_bytes([data[18], data[19]]),
        })
    }

    /// Returns true if this is a 64-bit PE.
    pub fn is_64bit(&self) -> bool {
        self.machine == IMAGE_FILE_MACHINE_AMD64 || self.machine == IMAGE_FILE_MACHINE_ARM64
    }

    /// Returns true if this is an executable.
    pub fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_FILE_EXECUTABLE_IMAGE != 0
    }

    /// Returns true if this is a DLL.
    pub fn is_dll(&self) -> bool {
        self.characteristics & IMAGE_FILE_DLL != 0
    }
}

/// Data directory entry
#[derive(Debug, Clone, Copy, Default)]
pub struct DataDirectory {
    /// Virtual address
    pub virtual_address: u32,
    /// Size
    pub size: u32,
}

impl DataDirectory {
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 8 {
            return Err(ParseError::too_short(8, data.len()));
        }
        Ok(Self {
            virtual_address: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            size: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
        })
    }
}

/// Data directory indices
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
pub const IMAGE_DIRECTORY_ENTRY_CLR: usize = 14;

/// Optional Header (PE32: 96 bytes standard + 128 bytes data dirs = 224 bytes)
/// (PE32+: 112 bytes standard + 128 bytes data dirs = 240 bytes)
#[derive(Debug, Clone)]
pub struct OptionalHeader {
    /// Magic (PE32 or PE32+)
    pub magic: u16,
    /// Major linker version
    pub major_linker_version: u8,
    /// Minor linker version
    pub minor_linker_version: u8,
    /// Size of code section
    pub size_of_code: u32,
    /// Size of initialized data
    pub size_of_initialized_data: u32,
    /// Size of uninitialized data
    pub size_of_uninitialized_data: u32,
    /// Entry point RVA
    pub address_of_entry_point: u32,
    /// Base of code
    pub base_of_code: u32,
    /// Image base address
    pub image_base: u64,
    /// Section alignment
    pub section_alignment: u32,
    /// File alignment
    pub file_alignment: u32,
    /// Major OS version
    pub major_operating_system_version: u16,
    /// Minor OS version
    pub minor_operating_system_version: u16,
    /// Major image version
    pub major_image_version: u16,
    /// Minor image version
    pub minor_image_version: u16,
    /// Major subsystem version
    pub major_subsystem_version: u16,
    /// Minor subsystem version
    pub minor_subsystem_version: u16,
    /// Size of image
    pub size_of_image: u32,
    /// Size of headers
    pub size_of_headers: u32,
    /// Checksum
    pub checksum: u32,
    /// Subsystem
    pub subsystem: u16,
    /// DLL characteristics
    pub dll_characteristics: u16,
    /// Size of stack reserve
    pub size_of_stack_reserve: u64,
    /// Size of stack commit
    pub size_of_stack_commit: u64,
    /// Size of heap reserve
    pub size_of_heap_reserve: u64,
    /// Size of heap commit
    pub size_of_heap_commit: u64,
    /// Number of data directories
    pub number_of_rva_and_sizes: u32,
    /// Data directories
    pub data_directories: Vec<DataDirectory>,
}

impl OptionalHeader {
    /// Parse PE32 optional header.
    pub fn parse_pe32(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 96 {
            return Err(ParseError::too_short(96, data.len()));
        }

        let magic = u16::from_le_bytes([data[0], data[1]]);
        if magic != PE32_MAGIC {
            return Err(ParseError::invalid_magic("PE32 (0x10b)", &data[0..2]));
        }

        let number_of_rva_and_sizes = u32::from_le_bytes([data[92], data[93], data[94], data[95]]);
        let num_dirs = number_of_rva_and_sizes.min(16) as usize;

        let mut data_directories = Vec::with_capacity(num_dirs);
        let dir_offset = 96;
        for i in 0..num_dirs {
            let offset = dir_offset + i * 8;
            if offset + 8 <= data.len() {
                data_directories.push(DataDirectory::parse(&data[offset..])?);
            }
        }

        Ok(Self {
            magic,
            major_linker_version: data[2],
            minor_linker_version: data[3],
            size_of_code: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            size_of_initialized_data: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            size_of_uninitialized_data: u32::from_le_bytes([
                data[12], data[13], data[14], data[15],
            ]),
            address_of_entry_point: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            base_of_code: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
            image_base: u32::from_le_bytes([data[28], data[29], data[30], data[31]]) as u64,
            section_alignment: u32::from_le_bytes([data[32], data[33], data[34], data[35]]),
            file_alignment: u32::from_le_bytes([data[36], data[37], data[38], data[39]]),
            major_operating_system_version: u16::from_le_bytes([data[40], data[41]]),
            minor_operating_system_version: u16::from_le_bytes([data[42], data[43]]),
            major_image_version: u16::from_le_bytes([data[44], data[45]]),
            minor_image_version: u16::from_le_bytes([data[46], data[47]]),
            major_subsystem_version: u16::from_le_bytes([data[48], data[49]]),
            minor_subsystem_version: u16::from_le_bytes([data[50], data[51]]),
            size_of_image: u32::from_le_bytes([data[56], data[57], data[58], data[59]]),
            size_of_headers: u32::from_le_bytes([data[60], data[61], data[62], data[63]]),
            checksum: u32::from_le_bytes([data[64], data[65], data[66], data[67]]),
            subsystem: u16::from_le_bytes([data[68], data[69]]),
            dll_characteristics: u16::from_le_bytes([data[70], data[71]]),
            size_of_stack_reserve: u32::from_le_bytes([data[72], data[73], data[74], data[75]])
                as u64,
            size_of_stack_commit: u32::from_le_bytes([data[76], data[77], data[78], data[79]])
                as u64,
            size_of_heap_reserve: u32::from_le_bytes([data[80], data[81], data[82], data[83]])
                as u64,
            size_of_heap_commit: u32::from_le_bytes([data[84], data[85], data[86], data[87]])
                as u64,
            number_of_rva_and_sizes,
            data_directories,
        })
    }

    /// Parse PE32+ (64-bit) optional header.
    pub fn parse_pe32plus(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < 112 {
            return Err(ParseError::too_short(112, data.len()));
        }

        let magic = u16::from_le_bytes([data[0], data[1]]);
        if magic != PE32PLUS_MAGIC {
            return Err(ParseError::invalid_magic("PE32+ (0x20b)", &data[0..2]));
        }

        let number_of_rva_and_sizes =
            u32::from_le_bytes([data[108], data[109], data[110], data[111]]);
        let num_dirs = number_of_rva_and_sizes.min(16) as usize;

        let mut data_directories = Vec::with_capacity(num_dirs);
        let dir_offset = 112;
        for i in 0..num_dirs {
            let offset = dir_offset + i * 8;
            if offset + 8 <= data.len() {
                data_directories.push(DataDirectory::parse(&data[offset..])?);
            }
        }

        Ok(Self {
            magic,
            major_linker_version: data[2],
            minor_linker_version: data[3],
            size_of_code: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            size_of_initialized_data: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            size_of_uninitialized_data: u32::from_le_bytes([
                data[12], data[13], data[14], data[15],
            ]),
            address_of_entry_point: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            base_of_code: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
            image_base: u64::from_le_bytes([
                data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
            ]),
            section_alignment: u32::from_le_bytes([data[32], data[33], data[34], data[35]]),
            file_alignment: u32::from_le_bytes([data[36], data[37], data[38], data[39]]),
            major_operating_system_version: u16::from_le_bytes([data[40], data[41]]),
            minor_operating_system_version: u16::from_le_bytes([data[42], data[43]]),
            major_image_version: u16::from_le_bytes([data[44], data[45]]),
            minor_image_version: u16::from_le_bytes([data[46], data[47]]),
            major_subsystem_version: u16::from_le_bytes([data[48], data[49]]),
            minor_subsystem_version: u16::from_le_bytes([data[50], data[51]]),
            size_of_image: u32::from_le_bytes([data[56], data[57], data[58], data[59]]),
            size_of_headers: u32::from_le_bytes([data[60], data[61], data[62], data[63]]),
            checksum: u32::from_le_bytes([data[64], data[65], data[66], data[67]]),
            subsystem: u16::from_le_bytes([data[68], data[69]]),
            dll_characteristics: u16::from_le_bytes([data[70], data[71]]),
            size_of_stack_reserve: u64::from_le_bytes([
                data[72], data[73], data[74], data[75], data[76], data[77], data[78], data[79],
            ]),
            size_of_stack_commit: u64::from_le_bytes([
                data[80], data[81], data[82], data[83], data[84], data[85], data[86], data[87],
            ]),
            size_of_heap_reserve: u64::from_le_bytes([
                data[88], data[89], data[90], data[91], data[92], data[93], data[94], data[95],
            ]),
            size_of_heap_commit: u64::from_le_bytes([
                data[96], data[97], data[98], data[99], data[100], data[101], data[102], data[103],
            ]),
            number_of_rva_and_sizes,
            data_directories,
        })
    }

    /// Returns true if this is PE32+.
    pub fn is_64bit(&self) -> bool {
        self.magic == PE32PLUS_MAGIC
    }

    /// Get a data directory by index.
    pub fn data_directory(&self, index: usize) -> Option<&DataDirectory> {
        self.data_directories.get(index)
    }
}
