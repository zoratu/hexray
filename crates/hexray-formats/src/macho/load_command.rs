//! Mach-O load command parsing.

#![allow(dead_code)]

use super::segment::Segment;
use crate::ParseError;

// Load command types
pub const LC_SEGMENT: u32 = 0x1;
pub const LC_SYMTAB: u32 = 0x2;
pub const LC_UNIXTHREAD: u32 = 0x5;
pub const LC_DYSYMTAB: u32 = 0xB;
pub const LC_LOAD_DYLIB: u32 = 0xC;
pub const LC_ID_DYLIB: u32 = 0xD;
pub const LC_LOAD_DYLINKER: u32 = 0xE;
pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_UUID: u32 = 0x1B;
pub const LC_CODE_SIGNATURE: u32 = 0x1D;
pub const LC_ENCRYPTION_INFO: u32 = 0x21;
pub const LC_DYLD_INFO: u32 = 0x22;
pub const LC_DYLD_INFO_ONLY: u32 = 0x80000022;
pub const LC_VERSION_MIN_MACOSX: u32 = 0x24;
pub const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
pub const LC_FUNCTION_STARTS: u32 = 0x26;
pub const LC_MAIN: u32 = 0x80000028;
pub const LC_DATA_IN_CODE: u32 = 0x29;
pub const LC_SOURCE_VERSION: u32 = 0x2A;
pub const LC_BUILD_VERSION: u32 = 0x32;

/// A parsed load command.
#[derive(Debug, Clone)]
pub enum LoadCommand {
    /// LC_SEGMENT (32-bit)
    Segment(Segment),
    /// LC_SEGMENT_64
    Segment64(Segment),
    /// LC_SYMTAB
    Symtab {
        symoff: u32,
        nsyms: u32,
        stroff: u32,
        strsize: u32,
    },
    /// LC_DYSYMTAB
    Dysymtab {
        ilocalsym: u32,
        nlocalsym: u32,
        iextdefsym: u32,
        nextdefsym: u32,
        iundefsym: u32,
        nundefsym: u32,
    },
    /// LC_MAIN
    Main {
        entryoff: u64,
        stacksize: u64,
    },
    /// LC_UNIXTHREAD (legacy entry point)
    UnixThread {
        entry_point: u64,
    },
    /// LC_UUID
    Uuid {
        uuid: [u8; 16],
    },
    /// LC_LOAD_DYLIB
    LoadDylib {
        name: String,
    },
    /// LC_BUILD_VERSION
    BuildVersion {
        platform: u32,
        minos: u32,
        sdk: u32,
    },
    /// LC_FUNCTION_STARTS
    FunctionStarts {
        dataoff: u32,
        datasize: u32,
    },
    /// Other/unknown load command
    Other {
        cmd: u32,
        cmdsize: u32,
    },
}

impl LoadCommand {
    /// Parse a load command from bytes.
    pub fn parse(cmd: u32, data: &[u8], is_64: bool) -> Result<Option<Self>, ParseError> {
        if data.len() < 8 {
            return Err(ParseError::too_short(8, data.len()));
        }

        let cmdsize = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        let result = match cmd {
            LC_SEGMENT => {
                let seg = Segment::parse_32(data)?;
                Some(Self::Segment(seg))
            }
            LC_SEGMENT_64 => {
                let seg = Segment::parse_64(data)?;
                Some(Self::Segment64(seg))
            }
            LC_SYMTAB => {
                if data.len() < 24 {
                    return Err(ParseError::too_short(24, data.len()));
                }
                Some(Self::Symtab {
                    symoff: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
                    nsyms: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
                    stroff: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
                    strsize: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
                })
            }
            LC_DYSYMTAB => {
                if data.len() < 80 {
                    return Ok(Some(Self::Other { cmd, cmdsize }));
                }
                Some(Self::Dysymtab {
                    ilocalsym: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
                    nlocalsym: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
                    iextdefsym: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
                    nextdefsym: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
                    iundefsym: u32::from_le_bytes([data[24], data[25], data[26], data[27]]),
                    nundefsym: u32::from_le_bytes([data[28], data[29], data[30], data[31]]),
                })
            }
            LC_MAIN => {
                if data.len() < 24 {
                    return Err(ParseError::too_short(24, data.len()));
                }
                Some(Self::Main {
                    entryoff: u64::from_le_bytes([
                        data[8], data[9], data[10], data[11],
                        data[12], data[13], data[14], data[15],
                    ]),
                    stacksize: u64::from_le_bytes([
                        data[16], data[17], data[18], data[19],
                        data[20], data[21], data[22], data[23],
                    ]),
                })
            }
            LC_UNIXTHREAD => {
                // Thread state is architecture-specific
                // For x86_64, RIP is at offset 16*8 + 8 = 136 from thread state start
                // Thread state starts at offset 16 (after cmd, cmdsize, flavor, count)
                let entry_point = if is_64 && data.len() >= 16 + 136 + 8 {
                    u64::from_le_bytes([
                        data[16 + 136], data[16 + 137], data[16 + 138], data[16 + 139],
                        data[16 + 140], data[16 + 141], data[16 + 142], data[16 + 143],
                    ])
                } else if !is_64 && data.len() >= 16 + 40 + 4 {
                    // For i386, EIP is at offset 10*4 = 40
                    u32::from_le_bytes([
                        data[16 + 40], data[16 + 41], data[16 + 42], data[16 + 43],
                    ]) as u64
                } else {
                    0
                };
                Some(Self::UnixThread { entry_point })
            }
            LC_UUID => {
                if data.len() < 24 {
                    return Err(ParseError::too_short(24, data.len()));
                }
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(&data[8..24]);
                Some(Self::Uuid { uuid })
            }
            LC_LOAD_DYLIB | LC_ID_DYLIB => {
                if data.len() < 24 {
                    return Ok(Some(Self::Other { cmd, cmdsize }));
                }
                let name_offset = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
                let name = if name_offset < data.len() {
                    let name_bytes = &data[name_offset..];
                    let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
                    String::from_utf8_lossy(&name_bytes[..end]).to_string()
                } else {
                    String::new()
                };
                Some(Self::LoadDylib { name })
            }
            LC_BUILD_VERSION => {
                if data.len() < 20 {
                    return Ok(Some(Self::Other { cmd, cmdsize }));
                }
                Some(Self::BuildVersion {
                    platform: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
                    minos: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
                    sdk: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
                })
            }
            LC_FUNCTION_STARTS => {
                if data.len() < 16 {
                    return Ok(Some(Self::Other { cmd, cmdsize }));
                }
                Some(Self::FunctionStarts {
                    dataoff: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
                    datasize: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
                })
            }
            _ => Some(Self::Other { cmd, cmdsize }),
        };

        Ok(result)
    }

    /// Returns the command type.
    pub fn cmd_type(&self) -> u32 {
        match self {
            Self::Segment(_) => LC_SEGMENT,
            Self::Segment64(_) => LC_SEGMENT_64,
            Self::Symtab { .. } => LC_SYMTAB,
            Self::Dysymtab { .. } => LC_DYSYMTAB,
            Self::Main { .. } => LC_MAIN,
            Self::UnixThread { .. } => LC_UNIXTHREAD,
            Self::Uuid { .. } => LC_UUID,
            Self::LoadDylib { .. } => LC_LOAD_DYLIB,
            Self::BuildVersion { .. } => LC_BUILD_VERSION,
            Self::FunctionStarts { .. } => LC_FUNCTION_STARTS,
            Self::Other { cmd, .. } => *cmd,
        }
    }

    /// Returns a human-readable name for this command type.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Segment(_) => "LC_SEGMENT",
            Self::Segment64(_) => "LC_SEGMENT_64",
            Self::Symtab { .. } => "LC_SYMTAB",
            Self::Dysymtab { .. } => "LC_DYSYMTAB",
            Self::Main { .. } => "LC_MAIN",
            Self::UnixThread { .. } => "LC_UNIXTHREAD",
            Self::Uuid { .. } => "LC_UUID",
            Self::LoadDylib { .. } => "LC_LOAD_DYLIB",
            Self::BuildVersion { .. } => "LC_BUILD_VERSION",
            Self::FunctionStarts { .. } => "LC_FUNCTION_STARTS",
            Self::Other { .. } => "LC_OTHER",
        }
    }
}
