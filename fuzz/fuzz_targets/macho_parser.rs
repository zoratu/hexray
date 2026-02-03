#![no_main]

use libfuzzer_sys::fuzz_target;
use hexray_formats::macho::MachO;
use hexray_formats::{BinaryFormat, Section};

fuzz_target!(|data: &[u8]| {
    // Try to parse as Mach-O - should never panic
    match MachO::parse(data) {
        Ok(macho) => {
            // If parsing succeeds, try to use the parsed data
            let _ = macho.architecture();
            let _ = macho.entry_point();

            // Iterate symbols
            for symbol in macho.symbols() {
                let _ = symbol.name.len();
                let _ = symbol.address;
                let _ = symbol.size;
            }

            // Iterate sections
            for section in macho.executable_sections() {
                let _ = section.name().len();
                let _ = section.virtual_address();
                let _ = section.data().len();
            }

            // Try segments
            let _ = macho.segment_by_name("__TEXT");
            let _ = macho.segment_by_name("__DATA");
        }
        Err(_) => {
            // Parse errors are expected for malformed input
        }
    }
});
