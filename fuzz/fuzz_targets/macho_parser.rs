#![no_main]

use libfuzzer_sys::fuzz_target;
use hexray_formats::macho::MachOFile;
use hexray_formats::BinaryFormat;

fuzz_target!(|data: &[u8]| {
    // Try to parse as Mach-O - should never panic
    match MachOFile::parse(data) {
        Ok(macho) => {
            // If parsing succeeds, try to use the parsed data
            let _ = macho.architecture();
            let _ = macho.entry_point();
            let _ = macho.is_relocatable();

            // Iterate symbols
            for symbol in macho.symbols() {
                let _ = symbol.name.len();
                let _ = symbol.address;
                let _ = symbol.size;
            }

            // Iterate sections
            for section in macho.executable_sections() {
                let _ = section.name.len();
                let _ = section.address;
                let _ = section.data.len();
            }

            // Try to get specific sections
            let _ = macho.section_by_name("__text");
            let _ = macho.section_by_name("__data");

            // Try relocations
            for reloc in macho.relocations() {
                let _ = reloc.offset;
                let _ = reloc.symbol_name.len();
            }
        }
        Err(_) => {
            // Parse errors are expected for malformed input
        }
    }
});
