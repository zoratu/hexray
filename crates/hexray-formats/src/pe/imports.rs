//! PE import table parsing.

use crate::ParseError;

/// Import directory entry size
pub const IMPORT_DESCRIPTOR_SIZE: usize = 20;

/// Import directory entry
#[derive(Debug, Clone)]
pub struct ImportDescriptor {
    /// RVA of Import Lookup Table (or Import Name Table)
    pub original_first_thunk: u32,
    /// Time/date stamp
    pub time_date_stamp: u32,
    /// Forwarder chain
    pub forwarder_chain: u32,
    /// RVA of DLL name
    pub name_rva: u32,
    /// RVA of Import Address Table
    pub first_thunk: u32,
}

impl ImportDescriptor {
    /// Parse an import descriptor from bytes.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < IMPORT_DESCRIPTOR_SIZE {
            return Err(ParseError::too_short(IMPORT_DESCRIPTOR_SIZE, data.len()));
        }

        Ok(Self {
            original_first_thunk: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            time_date_stamp: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            forwarder_chain: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            name_rva: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            first_thunk: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
        })
    }

    /// Returns true if this is a null terminator entry.
    pub fn is_null(&self) -> bool {
        self.original_first_thunk == 0 && self.name_rva == 0 && self.first_thunk == 0
    }
}

/// A parsed import entry
#[derive(Debug, Clone)]
pub struct Import {
    /// DLL name
    pub dll_name: String,
    /// Function name (or ordinal if by ordinal)
    pub name: String,
    /// Ordinal number (if imported by ordinal)
    pub ordinal: Option<u16>,
    /// Hint value
    pub hint: u16,
    /// IAT RVA (where the import address is stored)
    pub iat_rva: u32,
}

/// Parse all imports from the import directory.
pub fn parse_imports(
    data: &[u8],
    import_dir_rva: u32,
    _import_dir_size: u32,
    sections: &[super::section::SectionHeader],
    is_64bit: bool,
) -> Vec<Import> {
    let mut imports = Vec::new();

    // Find the section containing the import directory
    let Some(import_offset) = rva_to_offset(import_dir_rva, sections) else {
        return imports;
    };

    // Parse import descriptors
    let mut desc_offset = import_offset;
    loop {
        if desc_offset + IMPORT_DESCRIPTOR_SIZE > data.len() {
            break;
        }

        let Ok(desc) = ImportDescriptor::parse(&data[desc_offset..]) else {
            break;
        };

        if desc.is_null() {
            break;
        }

        // Get DLL name
        let dll_name = if let Some(name_offset) = rva_to_offset(desc.name_rva, sections) {
            read_cstring(data, name_offset)
        } else {
            String::new()
        };

        // Parse Import Lookup Table (or IAT if ILT is zero)
        let ilt_rva = if desc.original_first_thunk != 0 {
            desc.original_first_thunk
        } else {
            desc.first_thunk
        };

        if let Some(ilt_offset) = rva_to_offset(ilt_rva, sections) {
            let entry_size = if is_64bit { 8 } else { 4 };
            let mut entry_offset = ilt_offset;
            let mut iat_rva = desc.first_thunk;

            loop {
                if entry_offset + entry_size > data.len() {
                    break;
                }

                let entry = if is_64bit {
                    u64::from_le_bytes([
                        data[entry_offset],
                        data[entry_offset + 1],
                        data[entry_offset + 2],
                        data[entry_offset + 3],
                        data[entry_offset + 4],
                        data[entry_offset + 5],
                        data[entry_offset + 6],
                        data[entry_offset + 7],
                    ])
                } else {
                    u32::from_le_bytes([
                        data[entry_offset],
                        data[entry_offset + 1],
                        data[entry_offset + 2],
                        data[entry_offset + 3],
                    ]) as u64
                };

                if entry == 0 {
                    break;
                }

                // Check if imported by ordinal (high bit set)
                let ordinal_flag = if is_64bit { 1u64 << 63 } else { 1u64 << 31 };
                let (name, ordinal, hint) = if entry & ordinal_flag != 0 {
                    let ord = (entry & 0xFFFF) as u16;
                    (format!("Ordinal_{}", ord), Some(ord), 0)
                } else {
                    // Import by name - entry is RVA to hint/name
                    let hint_name_rva = entry as u32;
                    if let Some(hn_offset) = rva_to_offset(hint_name_rva, sections) {
                        if hn_offset + 2 < data.len() {
                            let hint = u16::from_le_bytes([data[hn_offset], data[hn_offset + 1]]);
                            let name = read_cstring(data, hn_offset + 2);
                            (name, None, hint)
                        } else {
                            (String::new(), None, 0)
                        }
                    } else {
                        (String::new(), None, 0)
                    }
                };

                imports.push(Import {
                    dll_name: dll_name.clone(),
                    name,
                    ordinal,
                    hint,
                    iat_rva,
                });

                entry_offset += entry_size;
                iat_rva += entry_size as u32;
            }
        }

        desc_offset += IMPORT_DESCRIPTOR_SIZE;
    }

    imports
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
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len().min(256));
    String::from_utf8_lossy(&bytes[..end]).to_string()
}
