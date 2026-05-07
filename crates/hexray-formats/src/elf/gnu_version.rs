//! GNU ELF symbol-version parsing.

use super::section::SectionHeader;
use crate::Section;
use hexray_core::Endianness;
use std::collections::HashMap;

const VERSYM_HIDDEN: u16 = 0x8000;

#[derive(Debug, Default, Clone)]
pub(crate) struct GnuVersionTable {
    symbol_versions: HashMap<usize, Vec<u16>>,
    definitions: HashMap<u16, String>,
    requirements: HashMap<u16, String>,
}

impl GnuVersionTable {
    pub(crate) fn parse(data: &[u8], sections: &[SectionHeader], endianness: Endianness) -> Self {
        let mut table = Self::default();

        for section in sections {
            match section.name() {
                ".gnu.version" => {
                    if let Some(entries) = parse_versym_entries(data, section, endianness) {
                        table
                            .symbol_versions
                            .insert(section.sh_link as usize, entries);
                    }
                }
                ".gnu.version_d" => {
                    table.definitions.extend(parse_version_definitions(
                        data, sections, section, endianness,
                    ));
                }
                ".gnu.version_r" => {
                    table.requirements.extend(parse_version_requirements(
                        data, sections, section, endianness,
                    ));
                }
                _ => {}
            }
        }

        table
    }

    pub(crate) fn decorate_symbol_name(
        &self,
        symbol_section_index: usize,
        symbol_index: usize,
        base_name: &str,
        is_defined: bool,
    ) -> String {
        let Some(raw_version) = self
            .symbol_versions
            .get(&symbol_section_index)
            .and_then(|versions| versions.get(symbol_index))
            .copied()
        else {
            return base_name.to_string();
        };

        let version_index = raw_version & !VERSYM_HIDDEN;
        if version_index <= 1 {
            return base_name.to_string();
        }

        let version_name = if is_defined {
            self.definitions
                .get(&version_index)
                .or_else(|| self.requirements.get(&version_index))
        } else {
            self.requirements
                .get(&version_index)
                .or_else(|| self.definitions.get(&version_index))
        };

        let Some(version_name) = version_name else {
            return base_name.to_string();
        };

        if is_defined {
            let separator = if raw_version & VERSYM_HIDDEN != 0 {
                "@"
            } else {
                "@@"
            };
            format!("{base_name}{separator}{version_name}")
        } else {
            format!("{base_name}@{version_name}")
        }
    }
}

fn parse_versym_entries(
    data: &[u8],
    section: &SectionHeader,
    endianness: Endianness,
) -> Option<Vec<u16>> {
    let bytes = section_bytes(data, section)?;
    if bytes.len() < 2 {
        return Some(Vec::new());
    }

    let mut entries = Vec::with_capacity(bytes.len() / 2);
    let mut offset = 0usize;
    while offset.saturating_add(2) <= bytes.len() {
        entries.push(read_u16(bytes, offset, endianness));
        offset = offset.saturating_add(2);
    }

    Some(entries)
}

fn parse_version_definitions(
    data: &[u8],
    sections: &[SectionHeader],
    section: &SectionHeader,
    endianness: Endianness,
) -> HashMap<u16, String> {
    let mut definitions = HashMap::new();
    let Some(bytes) = section_bytes(data, section) else {
        return definitions;
    };
    let Some(strtab) = section_string_table(data, sections, section.sh_link as usize) else {
        return definitions;
    };

    let mut offset = 0usize;
    while offset.saturating_add(20) <= bytes.len() {
        let version_index = read_u16(bytes, offset.saturating_add(4), endianness);
        let aux_offset = read_u32(bytes, offset.saturating_add(12), endianness) as usize;
        let next = read_u32(bytes, offset.saturating_add(16), endianness) as usize;

        if let Some(aux) = offset.checked_add(aux_offset) {
            if aux.saturating_add(8) <= bytes.len() {
                let name_offset = read_u32(bytes, aux, endianness) as usize;
                if let Some(name) = strtab.get(name_offset) {
                    definitions.insert(version_index, name.to_string());
                }
            }
        }

        if next == 0 {
            break;
        }
        offset = offset.saturating_add(next);
    }

    definitions
}

fn parse_version_requirements(
    data: &[u8],
    sections: &[SectionHeader],
    section: &SectionHeader,
    endianness: Endianness,
) -> HashMap<u16, String> {
    let mut requirements = HashMap::new();
    let Some(bytes) = section_bytes(data, section) else {
        return requirements;
    };
    let Some(strtab) = section_string_table(data, sections, section.sh_link as usize) else {
        return requirements;
    };

    let mut offset = 0usize;
    while offset.saturating_add(16) <= bytes.len() {
        let aux_offset = read_u32(bytes, offset.saturating_add(8), endianness) as usize;
        let next = read_u32(bytes, offset.saturating_add(12), endianness) as usize;

        let mut current_aux = match offset.checked_add(aux_offset) {
            Some(aux) => aux,
            None => break,
        };

        while current_aux.saturating_add(16) <= bytes.len() {
            let version_index = read_u16(bytes, current_aux.saturating_add(6), endianness);
            let name_offset = read_u32(bytes, current_aux.saturating_add(8), endianness) as usize;
            let aux_next = read_u32(bytes, current_aux.saturating_add(12), endianness) as usize;

            if let Some(name) = strtab.get(name_offset) {
                requirements.insert(version_index & !VERSYM_HIDDEN, name.to_string());
            }

            if aux_next == 0 {
                break;
            }
            current_aux = current_aux.saturating_add(aux_next);
        }

        if next == 0 {
            break;
        }
        offset = offset.saturating_add(next);
    }

    requirements
}

fn section_bytes<'a>(data: &'a [u8], section: &SectionHeader) -> Option<&'a [u8]> {
    let start = section.sh_offset as usize;
    let end = start.checked_add(section.sh_size as usize)?;
    data.get(start..end)
}

fn section_string_table<'a>(
    data: &'a [u8],
    sections: &[SectionHeader],
    section_index: usize,
) -> Option<ByteStringTable<'a>> {
    let section = sections.get(section_index)?;
    Some(ByteStringTable::new(section_bytes(data, section)?))
}

#[derive(Debug, Clone, Copy)]
struct ByteStringTable<'a> {
    data: &'a [u8],
}

impl<'a> ByteStringTable<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn get(&self, offset: usize) -> Option<&'a str> {
        let remaining = self.data.get(offset..)?;
        let end = remaining.iter().position(|&byte| byte == 0)?;
        std::str::from_utf8(remaining.get(..end)?).ok()
    }
}

fn read_u16(data: &[u8], offset: usize, endianness: Endianness) -> u16 {
    let end = offset.saturating_add(2);
    let bytes: [u8; 2] = data
        .get(offset..end)
        .unwrap_or(&[0; 2])
        .try_into()
        .unwrap_or_default();
    match endianness {
        Endianness::Little => u16::from_le_bytes(bytes),
        Endianness::Big => u16::from_be_bytes(bytes),
    }
}

fn read_u32(data: &[u8], offset: usize, endianness: Endianness) -> u32 {
    let end = offset.saturating_add(4);
    let bytes: [u8; 4] = data
        .get(offset..end)
        .unwrap_or(&[0; 4])
        .try_into()
        .unwrap_or_default();
    match endianness {
        Endianness::Little => u32::from_le_bytes(bytes),
        Endianness::Big => u32::from_be_bytes(bytes),
    }
}
