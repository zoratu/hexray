#![no_main]

use hexray_formats::pe::Pe;
use hexray_formats::BinaryFormat;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match Pe::parse(data) {
        Ok(pe) => {
            let _ = pe.architecture();
            let _ = pe.entry_point();
            let _ = pe.is_64bit();
            let _ = pe.is_dll();
            let _ = pe.image_base();

            for symbol in pe.symbols() {
                let _ = symbol.name.len();
                let _ = symbol.address;
                let _ = symbol.size;
            }

            for section in pe.sections() {
                let _ = section.name().len();
                let _ = section.virtual_address();
                let _ = section.data().len();
            }

            for section in pe.executable_sections() {
                let _ = section.name().len();
                let _ = section.virtual_address();
                let _ = section.data().len();
            }

            if let Some(entry) = pe.entry_point() {
                let _ = pe.va_to_offset(entry);
                let _ = pe.bytes_at(entry, 16);
            }

            if let Some(first_section) = pe.sections.first() {
                let _ = pe.rva_to_offset(first_section.virtual_address);
            }
        }
        Err(_) => {}
    }
});
