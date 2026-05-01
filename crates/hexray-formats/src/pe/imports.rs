use crate::ParseError;

/// Import directory entry size
pub const IMPORT_DESCRIPTOR_SIZE: usize = 20;

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
            original_first_thunk: read_u32(data, 0),
            time_date_stamp: read_u32(data, 4),
            forwarder_chain: read_u32(data, 8),
            name_rva: read_u32(data, 12),
            first_thunk: read_u32(data, 16),
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
    while let Some(desc_end) = desc_offset.checked_add(IMPORT_DESCRIPTOR_SIZE) {
        let Some(desc_slice) = data.get(desc_offset..desc_end) else {
            break;
        };

        let Ok(desc) = ImportDescriptor::parse(desc_slice) else {
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
            let entry_size: usize = if is_64bit { 8 } else { 4 };
            let mut entry_offset = ilt_offset;
            let mut iat_rva = desc.first_thunk;

            while let Some(entry_end) = entry_offset.checked_add(entry_size) {
                if entry_end > data.len() {
                    break;
                }

                let entry = if is_64bit {
                    read_u64(data, entry_offset)
                } else {
                    read_u32(data, entry_offset) as u64
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
                    rva_to_offset(hint_name_rva, sections)
                        .and_then(|hn_offset| {
                            let hn_after_hint = hn_offset.checked_add(2)?;
                            if hn_after_hint <= data.len() {
                                let hint = read_u16(data, hn_offset);
                                let name = read_cstring(data, hn_after_hint);
                                Some((name, None, hint))
                            } else {
                                None
                            }
                        })
                        .unwrap_or((String::new(), None, 0))
                };

                imports.push(Import {
                    dll_name: dll_name.clone(),
                    name,
                    ordinal,
                    hint,
                    iat_rva,
                });

                entry_offset = entry_end;
                iat_rva = iat_rva.saturating_add(entry_size as u32);
            }
        }

        desc_offset = desc_end;
    }

    imports
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
