use crate::ParseError;

/// Export directory size
pub const EXPORT_DIRECTORY_SIZE: usize = 40;

// Bounds-checked little-endian readers (caller has already verified
// the buffer length at function entry).
#[inline]
fn read_u16(data: &[u8], at: usize) -> u16 {
    let end = at.saturating_add(2);
    let arr: [u8; 2] = data
        .get(at..end)
        .unwrap_or(&[0; 2])
        .try_into()
        .unwrap_or_default();
    u16::from_le_bytes(arr)
}

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
            characteristics: read_u32(data, 0),
            time_date_stamp: read_u32(data, 4),
            major_version: read_u16(data, 8),
            minor_version: read_u16(data, 10),
            name_rva: read_u32(data, 12),
            base: read_u32(data, 16),
            number_of_functions: read_u32(data, 20),
            number_of_names: read_u32(data, 24),
            address_of_functions: read_u32(data, 28),
            address_of_names: read_u32(data, 32),
            address_of_name_ordinals: read_u32(data, 36),
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

    let Some(export_slice) = data.get(export_offset..) else {
        return exports;
    };

    let Ok(export_dir) = ExportDirectory::parse(export_slice) else {
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
            let Some(name_rva_offset) = names_off.checked_add(i.saturating_mul(4)) else {
                break;
            };
            let Some(ordinal_offset) = ords_off.checked_add(i.saturating_mul(2)) else {
                break;
            };
            let Some(name_end) = name_rva_offset.checked_add(4) else {
                break;
            };
            let Some(ord_end) = ordinal_offset.checked_add(2) else {
                break;
            };
            if name_end > data.len() || ord_end > data.len() {
                break;
            }

            let name_rva = read_u32(data, name_rva_offset);
            let ordinal = read_u16(data, ordinal_offset);

            if let Some(name_off) = rva_to_offset(name_rva, sections) {
                let name = read_cstring(data, name_off);
                ordinal_to_name.insert(ordinal, name);
            }
        }
    }

    // Parse all exported functions
    let export_section_start = export_dir_rva;
    let export_section_end = export_dir_rva.saturating_add(export_dir_size);

    for i in 0..export_dir.number_of_functions as usize {
        let Some(func_rva_offset) = addr_offset.checked_add(i.saturating_mul(4)) else {
            break;
        };
        let Some(func_end) = func_rva_offset.checked_add(4) else {
            break;
        };
        if func_end > data.len() {
            break;
        }

        let func_rva = read_u32(data, func_rva_offset);

        // Skip empty entries
        if func_rva == 0 {
            continue;
        }

        let ordinal = export_dir.base.saturating_add(i as u32);
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
        let section_end =
            section_start.saturating_add(section.virtual_size.max(section.size_of_raw_data));
        if rva >= section_start && rva < section_end {
            let offset_in_section = rva.saturating_sub(section_start);
            return Some(
                section
                    .pointer_to_raw_data
                    .saturating_add(offset_in_section) as usize,
            );
        }
    }
    None
}

/// Read a null-terminated C string from data.
fn read_cstring(data: &[u8], offset: usize) -> String {
    let Some(bytes) = data.get(offset..) else {
        return String::new();
    };
    let end = bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(bytes.len().min(256));
    crate::name_from_bytes(bytes.get(..end).unwrap_or(&[]))
}
