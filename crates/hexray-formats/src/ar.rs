//! ar archive parsing.

use crate::{name_from_bytes, ParseError};

const GLOBAL_HEADER: &[u8; 8] = b"!<arch>\n";
const MEMBER_HEADER_LEN: usize = 60;

/// A parsed `ar` archive.
#[derive(Debug, Clone)]
pub struct ArArchive<'a> {
    members: Vec<ArMember<'a>>,
}

impl<'a> ArArchive<'a> {
    /// Parse an `ar` archive from raw bytes.
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        if data.len() < GLOBAL_HEADER.len() {
            return Err(ParseError::too_short(GLOBAL_HEADER.len(), data.len()));
        }
        if data.get(..GLOBAL_HEADER.len()) != Some(GLOBAL_HEADER.as_slice()) {
            let actual = data.get(..GLOBAL_HEADER.len()).unwrap_or_default();
            return Err(ParseError::invalid_magic("ar archive", actual));
        }

        let mut offset = GLOBAL_HEADER.len();
        let mut gnu_name_table: Option<&'a [u8]> = None;
        let mut members = Vec::new();

        while offset < data.len() {
            let header_end = offset
                .checked_add(MEMBER_HEADER_LEN)
                .ok_or(ParseError::Overflow {
                    context: "ar member header",
                })?;
            let header = data
                .get(offset..header_end)
                .ok_or_else(|| ParseError::too_short(header_end, data.len()))?;

            if header.get(58..60) != Some(b"`\n".as_slice()) {
                return Err(ParseError::invalid_structure(
                    "ar member header",
                    offset as u64,
                    "missing trailing `\\n` marker",
                ));
            }

            let member_size = parse_decimal_field(
                header.get(48..58).ok_or_else(|| {
                    ParseError::invalid_structure(
                        "ar member header",
                        offset as u64,
                        "missing size field",
                    )
                })?,
                offset,
                "size",
            )?;
            let data_start = header_end;
            let data_end = data_start
                .checked_add(member_size)
                .ok_or(ParseError::Overflow {
                    context: "ar member data",
                })?;
            let member_bytes = data
                .get(data_start..data_end)
                .ok_or_else(|| ParseError::too_short(data_end, data.len()))?;

            let raw_name = parse_name_field(header.get(..16).ok_or_else(|| {
                ParseError::invalid_structure(
                    "ar member header",
                    offset as u64,
                    "missing name field",
                )
            })?);
            let (kind, name, payload) =
                resolve_member_name(raw_name, member_bytes, gnu_name_table, offset)?;
            if matches!(kind, ArMemberKind::GnuNameTable) {
                gnu_name_table = Some(payload);
            }

            members.push(ArMember {
                name,
                kind,
                header_offset: offset,
                data_offset: data_start,
                data: payload,
            });

            offset = data_end;
            if member_size % 2 == 1 {
                offset = offset.checked_add(1).ok_or(ParseError::Overflow {
                    context: "ar member padding",
                })?;
            }
        }

        Ok(Self { members })
    }

    /// Returns every member, including archive metadata entries.
    pub fn members(&self) -> &[ArMember<'a>] {
        &self.members
    }

    /// Returns only regular file members.
    pub fn regular_members(&self) -> impl Iterator<Item = &ArMember<'a>> {
        self.members
            .iter()
            .filter(|member| member.kind == ArMemberKind::Regular)
    }
}

/// Parsed archive member metadata.
#[derive(Debug, Clone)]
pub struct ArMember<'a> {
    name: String,
    kind: ArMemberKind,
    header_offset: usize,
    data_offset: usize,
    data: &'a [u8],
}

impl<'a> ArMember<'a> {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn kind(&self) -> ArMemberKind {
        self.kind
    }

    pub fn header_offset(&self) -> usize {
        self.header_offset
    }

    pub fn data_offset(&self) -> usize {
        self.data_offset
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }

    pub fn data(&self) -> &'a [u8] {
        self.data
    }
}

/// Distinguishes real archive members from metadata entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArMemberKind {
    Regular,
    SymbolTable,
    GnuNameTable,
}

fn parse_decimal_field(
    field: &[u8],
    offset: usize,
    name: &'static str,
) -> Result<usize, ParseError> {
    let text = std::str::from_utf8(field).map_err(|_| {
        ParseError::invalid_structure("ar member header", offset as u64, "non-utf8 number field")
    })?;
    text.trim().parse::<usize>().map_err(|_| {
        ParseError::invalid_structure(
            "ar member header",
            offset as u64,
            format!("invalid {name} field"),
        )
    })
}

fn parse_name_field(field: &[u8]) -> &str {
    let text = std::str::from_utf8(field).unwrap_or_default();
    text.trim_end_matches(' ')
}

fn resolve_member_name<'a>(
    raw_name: &str,
    member_bytes: &'a [u8],
    gnu_name_table: Option<&'a [u8]>,
    offset: usize,
) -> Result<(ArMemberKind, String, &'a [u8]), ParseError> {
    if raw_name == "/" {
        return Ok((ArMemberKind::SymbolTable, "/".to_string(), member_bytes));
    }
    if raw_name == "//" {
        return Ok((ArMemberKind::GnuNameTable, "//".to_string(), member_bytes));
    }

    if let Some(len_text) = raw_name.strip_prefix("#1/") {
        let name_len = len_text.parse::<usize>().map_err(|_| {
            ParseError::invalid_structure(
                "ar member header",
                offset as u64,
                "invalid BSD extended name length",
            )
        })?;
        let name_bytes = member_bytes.get(..name_len).ok_or_else(|| {
            ParseError::invalid_structure(
                "ar member data",
                offset as u64,
                "BSD extended name exceeds member size",
            )
        })?;
        let payload = member_bytes.get(name_len..).ok_or_else(|| {
            ParseError::invalid_structure(
                "ar member data",
                offset as u64,
                "missing BSD extended member payload",
            )
        })?;
        return Ok((ArMemberKind::Regular, name_from_bytes(name_bytes), payload));
    }

    if let Some(name_offset_text) = raw_name.strip_prefix('/') {
        let name_offset_text = name_offset_text.trim_end_matches('/');
        if !name_offset_text.is_empty() && name_offset_text.bytes().all(|b| b.is_ascii_digit()) {
            let name_offset = name_offset_text.parse::<usize>().map_err(|_| {
                ParseError::invalid_structure(
                    "ar member header",
                    offset as u64,
                    "invalid GNU name-table offset",
                )
            })?;
            let name_table = gnu_name_table.ok_or_else(|| {
                ParseError::invalid_structure(
                    "ar member header",
                    offset as u64,
                    "GNU long name used before // name table",
                )
            })?;
            let name = read_gnu_name(name_table, name_offset).ok_or_else(|| {
                ParseError::invalid_structure(
                    "ar member header",
                    offset as u64,
                    "GNU long name offset outside // name table",
                )
            })?;
            return Ok((ArMemberKind::Regular, name, member_bytes));
        }
    }

    Ok((
        ArMemberKind::Regular,
        raw_name.trim_end_matches('/').to_string(),
        member_bytes,
    ))
}

fn read_gnu_name(name_table: &[u8], offset: usize) -> Option<String> {
    let rest = name_table.get(offset..)?;
    let end = rest
        .windows(2)
        .position(|window| window == b"/\n")
        .or_else(|| rest.iter().position(|&b| b == b'/'))?;
    let name = rest.get(..end)?;
    Some(name_from_bytes(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn archive_member(name: &str, data: &[u8]) -> Vec<u8> {
        let display_name = if name == "/" || name == "//" {
            name.to_string()
        } else {
            format!("{name}/")
        };
        let mut bytes = format!(
            "{display_name:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            0,
            0,
            0,
            0o644,
            data.len()
        )
        .into_bytes();
        bytes.extend_from_slice(data);
        if data.len() % 2 == 1 {
            bytes.push(b'\n');
        }
        bytes
    }

    fn make_archive() -> Vec<u8> {
        let mut archive = GLOBAL_HEADER.to_vec();
        archive.extend_from_slice(&archive_member("/", &[0, 0, 0, 0]));
        archive.extend_from_slice(&archive_member("alpha.o", b"AAAA"));
        archive.extend_from_slice(&archive_member("beta.o", b"BBBBB"));
        archive
    }

    #[test]
    fn parses_regular_members_and_skips_symbol_table() {
        let bytes = make_archive();
        let archive = ArArchive::parse(&bytes).expect("archive parses");
        let members: Vec<_> = archive
            .regular_members()
            .map(|member| (member.name().to_string(), member.size()))
            .collect();
        assert_eq!(
            members,
            vec![("alpha.o".to_string(), 4), ("beta.o".to_string(), 5)]
        );
    }

    #[test]
    fn parses_gnu_long_names() {
        let name_table = b"really_long_member_name.o/\n";
        let mut archive = GLOBAL_HEADER.to_vec();
        archive.extend_from_slice(&archive_member("//", name_table));
        archive.extend_from_slice(&archive_member("/0", b"DATA"));

        let archive = ArArchive::parse(&archive).expect("archive parses");
        let member = archive.regular_members().next().expect("member exists");
        assert_eq!(member.name(), "really_long_member_name.o");
        assert_eq!(member.data(), b"DATA");
    }
}
