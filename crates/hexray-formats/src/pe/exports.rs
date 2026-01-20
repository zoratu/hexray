//! PE export table parsing.

use crate::ParseError;

/// Export directory size
pub const EXPORT_DIRECTORY_SIZE: usize = 40;

/// Export directory table
#[derive(Debug, Clone)]
pub struct ExportDirectory {
    /// Export flags (reserved, must be 0)
    pub characteristics: u32,
    /// Time/date stamp
    pub time_date_stamp: u32,
    /// Major version
    pub major_version: u16,
    /// Minor version
    pub minor_version: u16,
    /// RVA of DLL name
    pub name_rva: u32,
    /// Ordinal base
    pub base: u32,
    /// Number of functions
    pub number_of_functions: u32,
    /// Number of names
    pub number_of_names: u32,
    /// RVA of Export Address Table
    pub address_of_functions: u32,
    /// RVA of Export Name Pointer Table
    pub address_of_names: u32,
    /// RVA of Ordinal Table
    pub address_of_name_ordinals: u32,
}

impl ExportDirectory {
    /// Parse export directory from bytes.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < EXPORT_DIRECTORY_SIZE {
            return Err(ParseError::too_short(EXPORT_DIRECTORY_SIZE, data.len()));
        }

        Ok(Self {
            characteristics: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            time_date_stamp: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            major_version: u16::from_le_bytes([data[8], data[9]]),
            minor_version: u16::from_le_bytes([data[10], data[11]]),
            name_rva: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            base: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            number_of_functions: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
            number_of_names: u32::from_le_bytes([data[24], data[25], data[26], data[27]]),
            address_of_functions: u32::from_le_bytes([data[28], data[29], data[30], data[31]]),
            address_of_names: u32::from_le_bytes([data[32], data[33], data[34], data[35]]),
            address_of_name_ordinals: u32::from_le_bytes([data[36], data[37], data[38], data[39]]),
        })
    }
}

/// A parsed export entry
#[derive(Debug, Clone)]
pub struct Export {
    /// Export name (may be empty for ordinal-only exports)
    pub name: String,
    /// Ordinal number
    pub ordinal: u32,
    /// RVA of the exported function
    pub rva: u32,
    /// Forwarder string (if this is a forwarded export)
    pub forwarder: Option<String>,
}

/// Parse all exports from the export directory.
pub fn parse_exports(
    data: &[u8],
    export_dir_rva: u32,
    export_dir_size: u32,
    sections: &[super::section::SectionHeader],
) -> Vec<Export> {
    let mut exports = Vec::new();

    let Some(export_offset) = rva_to_offset(export_dir_rva, sections) else {
        return exports;
    };

    let Ok(export_dir) = ExportDirectory::parse(&data[export_offset..]) else {
        return exports;
    };

    // Get the addresses table
    let Some(addr_offset) = rva_to_offset(export_dir.address_of_functions, sections) else {
        return exports;
    };

    // Get the names table (optional)
    let names_offset = rva_to_offset(export_dir.address_of_names, sections);
    let ordinals_offset = rva_to_offset(export_dir.address_of_name_ordinals, sections);

    // Build a map of ordinal -> name
    let mut ordinal_to_name: std::collections::HashMap<u16, String> =
        std::collections::HashMap::new();

    if let (Some(names_off), Some(ords_off)) = (names_offset, ordinals_offset) {
        for i in 0..export_dir.number_of_names as usize {
            let name_rva_offset = names_off + i * 4;
            let ordinal_offset = ords_off + i * 2;

            if name_rva_offset + 4 > data.len() || ordinal_offset + 2 > data.len() {
                break;
            }

            let name_rva = u32::from_le_bytes([
                data[name_rva_offset],
                data[name_rva_offset + 1],
                data[name_rva_offset + 2],
                data[name_rva_offset + 3],
            ]);
            let ordinal = u16::from_le_bytes([data[ordinal_offset], data[ordinal_offset + 1]]);

            if let Some(name_off) = rva_to_offset(name_rva, sections) {
                let name = read_cstring(data, name_off);
                ordinal_to_name.insert(ordinal, name);
            }
        }
    }

    // Parse all exported functions
    let export_section_start = export_dir_rva;
    let export_section_end = export_dir_rva + export_dir_size;

    for i in 0..export_dir.number_of_functions as usize {
        let func_rva_offset = addr_offset + i * 4;
        if func_rva_offset + 4 > data.len() {
            break;
        }

        let func_rva = u32::from_le_bytes([
            data[func_rva_offset],
            data[func_rva_offset + 1],
            data[func_rva_offset + 2],
            data[func_rva_offset + 3],
        ]);

        // Skip empty entries
        if func_rva == 0 {
            continue;
        }

        let ordinal = export_dir.base + i as u32;
        let name = ordinal_to_name
            .get(&(i as u16))
            .cloned()
            .unwrap_or_default();

        // Check if this is a forwarder (RVA points inside export section)
        let forwarder = if func_rva >= export_section_start && func_rva < export_section_end {
            rva_to_offset(func_rva, sections).map(|off| read_cstring(data, off))
        } else {
            None
        };

        exports.push(Export {
            name,
            ordinal,
            rva: func_rva,
            forwarder,
        });
    }

    exports
}

/// Convert RVA to file offset using section table.
fn rva_to_offset(rva: u32, sections: &[super::section::SectionHeader]) -> Option<usize> {
    for section in sections {
        let section_start = section.virtual_address;
        let section_end = section_start + section.virtual_size.max(section.size_of_raw_data);
        if rva >= section_start && rva < section_end {
            let offset_in_section = rva - section_start;
            return Some((section.pointer_to_raw_data + offset_in_section) as usize);
        }
    }
    None
}

/// Read a null-terminated C string from data.
fn read_cstring(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }
    let bytes = &data[offset..];
    let end = bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(bytes.len().min(256));
    String::from_utf8_lossy(&bytes[..end]).to_string()
}
