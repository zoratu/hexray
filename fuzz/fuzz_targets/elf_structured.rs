#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use hexray_formats::elf::Elf;
use hexray_formats::{BinaryFormat, Section};

/// Structured ELF header for targeted fuzzing
#[derive(Debug, Arbitrary)]
struct FuzzedElf {
    // ELF identification
    ei_class: u8,      // 1 = 32-bit, 2 = 64-bit
    ei_data: u8,       // 1 = little endian, 2 = big endian
    ei_osabi: u8,

    // ELF header fields
    e_type: u16,       // Object file type
    e_machine: u16,    // Architecture
    e_entry: u64,      // Entry point
    e_phoff: u64,      // Program header offset
    e_shoff: u64,      // Section header offset
    e_flags: u32,
    e_phnum: u16,      // Number of program headers
    e_shnum: u16,      // Number of section headers
    e_shstrndx: u16,   // Section name string table index

    // Variable sections
    sections: Vec<FuzzedSection>,
    program_headers: Vec<FuzzedProgramHeader>,
    extra_data: Vec<u8>,
}

#[derive(Debug, Arbitrary)]
struct FuzzedSection {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
    data: Vec<u8>,
}

#[derive(Debug, Arbitrary)]
struct FuzzedProgramHeader {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

impl FuzzedElf {
    fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        let is_64bit = self.ei_class == 2;
        let is_le = self.ei_data != 2;

        // ELF magic
        data.extend_from_slice(&[0x7f, b'E', b'L', b'F']);

        // ELF identification
        data.push(self.ei_class.clamp(1, 2));
        data.push(self.ei_data.clamp(1, 2));
        data.push(1); // EI_VERSION
        data.push(self.ei_osabi);
        data.extend_from_slice(&[0u8; 8]); // padding

        let write_u16 = |d: &mut Vec<u8>, v: u16| {
            if is_le { d.extend_from_slice(&v.to_le_bytes()); }
            else { d.extend_from_slice(&v.to_be_bytes()); }
        };
        let write_u32 = |d: &mut Vec<u8>, v: u32| {
            if is_le { d.extend_from_slice(&v.to_le_bytes()); }
            else { d.extend_from_slice(&v.to_be_bytes()); }
        };
        let write_u64 = |d: &mut Vec<u8>, v: u64| {
            if is_le { d.extend_from_slice(&v.to_le_bytes()); }
            else { d.extend_from_slice(&v.to_be_bytes()); }
        };

        // ELF header
        write_u16(&mut data, self.e_type);
        write_u16(&mut data, self.e_machine);
        write_u32(&mut data, 1); // e_version

        if is_64bit {
            write_u64(&mut data, self.e_entry);
            write_u64(&mut data, self.e_phoff);
            write_u64(&mut data, self.e_shoff);
        } else {
            write_u32(&mut data, self.e_entry as u32);
            write_u32(&mut data, self.e_phoff as u32);
            write_u32(&mut data, self.e_shoff as u32);
        }

        write_u32(&mut data, self.e_flags);
        write_u16(&mut data, if is_64bit { 64 } else { 52 }); // e_ehsize
        write_u16(&mut data, if is_64bit { 56 } else { 32 }); // e_phentsize
        write_u16(&mut data, self.e_phnum);
        write_u16(&mut data, if is_64bit { 64 } else { 40 }); // e_shentsize
        write_u16(&mut data, self.e_shnum);
        write_u16(&mut data, self.e_shstrndx);

        // Add extra data to reach various offsets
        data.extend_from_slice(&self.extra_data);

        data
    }
}

fuzz_target!(|data: &[u8]| {
    // Try structured generation
    if let Ok(fuzzed) = FuzzedElf::arbitrary(&mut Unstructured::new(data)) {
        let elf_bytes = fuzzed.to_bytes();
        test_elf_parsing(&elf_bytes);
    }

    // Also test raw input
    test_elf_parsing(data);
});

fn test_elf_parsing(data: &[u8]) {
    match Elf::parse(data) {
        Ok(elf) => {
            let _ = elf.architecture();
            let _ = elf.entry_point();
            let _ = elf.is_relocatable();

            for symbol in elf.symbols() {
                let _ = symbol.name.len();
                let _ = symbol.address;
                let _ = symbol.size;
            }

            for section in elf.sections() {
                let _ = section.name().len();
                let _ = section.virtual_address();
                let _ = section.data().len();
            }

            for section in elf.executable_sections() {
                let _ = section.name().len();
                let _ = section.virtual_address();
                let _ = section.data().len();
            }

            let _ = elf.section_by_name(".text");
            let _ = elf.section_by_name(".data");
            let _ = elf.section_by_name(".rodata");
            let _ = elf.section_by_name(".bss");
            let _ = elf.section_by_name(".symtab");
            let _ = elf.section_by_name(".strtab");
            let _ = elf.section_by_name(".dynsym");
            let _ = elf.section_by_name(".dynstr");
            let _ = elf.section_by_name(".plt");
            let _ = elf.section_by_name(".got");

            if elf.is_relocatable() {
                for reloc in &elf.relocations {
                    let _ = reloc.offset;
                    let _ = reloc.symbol_index;
                    let _ = reloc.r_type;
                    let _ = reloc.addend;
                }
            }
        }
        Err(_) => {}
    }
}
