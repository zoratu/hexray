#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use hexray_formats::macho::MachO;
use hexray_formats::{BinaryFormat, Section};

/// Mach-O magic values
const MH_MAGIC: u32 = 0xfeedface;
const MH_MAGIC_64: u32 = 0xfeedfacf;
const MH_CIGAM: u32 = 0xcefaedfe;
const MH_CIGAM_64: u32 = 0xcffaedfe;
const FAT_MAGIC: u32 = 0xcafebabe;
const FAT_CIGAM: u32 = 0xbebafeca;

/// Load command types
const LC_SEGMENT: u32 = 0x1;
const LC_SYMTAB: u32 = 0x2;
const LC_THREAD: u32 = 0x4;
const LC_UNIXTHREAD: u32 = 0x5;
const LC_DYSYMTAB: u32 = 0xb;
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_SEGMENT_64: u32 = 0x19;
const LC_UUID: u32 = 0x1b;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const LC_MAIN: u32 = 0x80000028;

#[derive(Debug, Arbitrary)]
struct FuzzedMachO {
    // Header fields
    is_64bit: bool,
    is_big_endian: bool,
    cputype: u32,
    cpusubtype: u32,
    filetype: u32,
    flags: u32,

    // Load commands
    segments: Vec<FuzzedSegment>,
    symtab: Option<FuzzedSymtab>,
    has_main: bool,
    main_entryoff: u64,
    has_unixthread: bool,
    unixthread_entry: u64,

    // Extra data for reaching various offsets
    extra_data: Vec<u8>,
}

#[derive(Debug, Arbitrary)]
struct FuzzedSegment {
    segname: [u8; 16],
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    maxprot: u32,
    initprot: u32,
    flags: u32,
    sections: Vec<FuzzedMachOSection>,
}

#[derive(Debug, Arbitrary)]
struct FuzzedMachOSection {
    sectname: [u8; 16],
    segname: [u8; 16],
    addr: u64,
    size: u64,
    offset: u32,
    align: u32,
    reloff: u32,
    nreloc: u32,
    flags: u32,
}

#[derive(Debug, Arbitrary)]
struct FuzzedSymtab {
    symoff: u32,
    nsyms: u32,
    stroff: u32,
    strsize: u32,
}

impl FuzzedMachO {
    fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        let is_le = !self.is_big_endian;

        let write_u32 = |d: &mut Vec<u8>, v: u32| {
            if is_le { d.extend_from_slice(&v.to_le_bytes()); }
            else { d.extend_from_slice(&v.to_be_bytes()); }
        };
        let write_u64 = |d: &mut Vec<u8>, v: u64| {
            if is_le { d.extend_from_slice(&v.to_le_bytes()); }
            else { d.extend_from_slice(&v.to_be_bytes()); }
        };

        // Mach-O header magic
        let magic = if self.is_64bit {
            if is_le { MH_MAGIC_64 } else { MH_CIGAM_64 }
        } else {
            if is_le { MH_MAGIC } else { MH_CIGAM }
        };
        write_u32(&mut data, magic);

        // CPU type and subtype
        write_u32(&mut data, self.cputype);
        write_u32(&mut data, self.cpusubtype);

        // File type
        write_u32(&mut data, self.filetype);

        // Count load commands
        let mut ncmds = self.segments.len();
        if self.symtab.is_some() { ncmds += 1; }
        if self.has_main { ncmds += 1; }
        if self.has_unixthread { ncmds += 1; }
        write_u32(&mut data, ncmds as u32);

        // Placeholder for sizeofcmds (we'll update later)
        let sizeofcmds_offset = data.len();
        write_u32(&mut data, 0);

        // Flags
        write_u32(&mut data, self.flags);

        // Reserved (64-bit only)
        if self.is_64bit {
            write_u32(&mut data, 0);
        }

        let cmds_start = data.len();

        // Write segment load commands
        for seg in &self.segments {
            let cmd = if self.is_64bit { LC_SEGMENT_64 } else { LC_SEGMENT };
            write_u32(&mut data, cmd);

            let cmdsize = if self.is_64bit {
                72 + seg.sections.len() * 80
            } else {
                56 + seg.sections.len() * 68
            };
            write_u32(&mut data, cmdsize as u32);

            data.extend_from_slice(&seg.segname);

            if self.is_64bit {
                write_u64(&mut data, seg.vmaddr);
                write_u64(&mut data, seg.vmsize);
                write_u64(&mut data, seg.fileoff);
                write_u64(&mut data, seg.filesize);
            } else {
                write_u32(&mut data, seg.vmaddr as u32);
                write_u32(&mut data, seg.vmsize as u32);
                write_u32(&mut data, seg.fileoff as u32);
                write_u32(&mut data, seg.filesize as u32);
            }

            write_u32(&mut data, seg.maxprot);
            write_u32(&mut data, seg.initprot);
            write_u32(&mut data, seg.sections.len() as u32);
            write_u32(&mut data, seg.flags);

            // Write sections
            for sect in &seg.sections {
                data.extend_from_slice(&sect.sectname);
                data.extend_from_slice(&sect.segname);

                if self.is_64bit {
                    write_u64(&mut data, sect.addr);
                    write_u64(&mut data, sect.size);
                } else {
                    write_u32(&mut data, sect.addr as u32);
                    write_u32(&mut data, sect.size as u32);
                }

                write_u32(&mut data, sect.offset);
                write_u32(&mut data, sect.align);
                write_u32(&mut data, sect.reloff);
                write_u32(&mut data, sect.nreloc);
                write_u32(&mut data, sect.flags);
                write_u32(&mut data, 0); // reserved1
                write_u32(&mut data, 0); // reserved2

                if self.is_64bit {
                    write_u32(&mut data, 0); // reserved3
                }
            }
        }

        // Write symtab if present
        if let Some(ref symtab) = self.symtab {
            write_u32(&mut data, LC_SYMTAB);
            write_u32(&mut data, 24); // cmdsize
            write_u32(&mut data, symtab.symoff);
            write_u32(&mut data, symtab.nsyms);
            write_u32(&mut data, symtab.stroff);
            write_u32(&mut data, symtab.strsize);
        }

        // Write LC_MAIN if present
        if self.has_main {
            write_u32(&mut data, LC_MAIN);
            write_u32(&mut data, 24); // cmdsize
            write_u64(&mut data, self.main_entryoff);
            write_u64(&mut data, 0); // stacksize
        }

        // Write LC_UNIXTHREAD if present
        if self.has_unixthread {
            write_u32(&mut data, LC_UNIXTHREAD);
            write_u32(&mut data, 184); // cmdsize for x86_64
            write_u32(&mut data, 4); // flavor (x86_THREAD_STATE64)
            write_u32(&mut data, 42); // count
            // Thread state (simplified - just entry point at offset)
            for _ in 0..16 {
                write_u64(&mut data, self.unixthread_entry);
            }
        }

        // Update sizeofcmds
        let sizeofcmds = data.len() - cmds_start;
        let sizeofcmds_bytes = if is_le {
            (sizeofcmds as u32).to_le_bytes()
        } else {
            (sizeofcmds as u32).to_be_bytes()
        };
        data[sizeofcmds_offset..sizeofcmds_offset + 4].copy_from_slice(&sizeofcmds_bytes);

        // Add extra data
        data.extend_from_slice(&self.extra_data);

        data
    }
}

fuzz_target!(|data: &[u8]| {
    // Try structured generation
    if let Ok(fuzzed) = FuzzedMachO::arbitrary(&mut Unstructured::new(data)) {
        let macho_bytes = fuzzed.to_bytes();
        test_macho_parsing(&macho_bytes);
    }

    // Also test raw input
    test_macho_parsing(data);
});

fn test_macho_parsing(data: &[u8]) {
    match MachO::parse(data) {
        Ok(macho) => {
            let _ = macho.architecture();
            let _ = macho.entry_point();

            for symbol in macho.symbols() {
                let _ = symbol.name.len();
                let _ = symbol.address;
                let _ = symbol.size;
            }

            for section in macho.sections() {
                let _ = section.name().len();
                let _ = section.virtual_address();
                let _ = section.data().len();
            }

            for section in macho.executable_sections() {
                let _ = section.name().len();
                let _ = section.virtual_address();
                let _ = section.data().len();
            }

            let _ = macho.segment_by_name("__TEXT");
            let _ = macho.segment_by_name("__DATA");
            let _ = macho.segment_by_name("__LINKEDIT");
            let _ = macho.segment_by_name("__PAGEZERO");

            // Test all sections iteration
            for seg in &macho.segments {
                for sect in &seg.sections {
                    let _ = sect.name().len();
                    let _ = sect.addr;
                    let _ = sect.size;
                }
            }
        }
        Err(_) => {}
    }
}
