#![no_main]

use libfuzzer_sys::fuzz_target;
use hexray_formats::elf::ElfFile;
use hexray_formats::BinaryFormat;

fuzz_target!(|data: &[u8]| {
    // Try to parse as ELF - should never panic
    match ElfFile::parse(data) {
        Ok(elf) => {
            // If parsing succeeds, try to use the parsed data
            let _ = elf.architecture();
            let _ = elf.entry_point();
            let _ = elf.is_relocatable();

            // Iterate symbols
            for symbol in elf.symbols() {
                let _ = symbol.name.len();
                let _ = symbol.address;
                let _ = symbol.size;
            }

            // Iterate sections
            for section in elf.executable_sections() {
                let _ = section.name.len();
                let _ = section.address;
                let _ = section.data.len();
            }

            // Try to get specific sections
            let _ = elf.section_by_name(".text");
            let _ = elf.section_by_name(".data");
            let _ = elf.section_by_name(".rodata");

            // Try relocations if applicable
            if elf.is_relocatable() {
                for reloc in elf.relocations() {
                    let _ = reloc.offset;
                    let _ = reloc.symbol_name.len();
                }
            }
        }
        Err(_) => {
            // Parse errors are expected for malformed input
        }
    }
});
