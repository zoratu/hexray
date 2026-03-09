#![no_main]

use hexray_formats::dwarf::{parse_eh_frame, DebugInfo, DebugInfoParser};
use libfuzzer_sys::fuzz_target;

fn split_debug_sections(data: &[u8]) -> (&[u8], &[u8], &[u8]) {
    let first = data.len() / 3;
    let second = first + (data.len() - first) / 2;
    (&data[..first], &data[first..second], &data[second..])
}

fn section_base(data: &[u8], big_endian: bool) -> u64 {
    let mut bytes = [0u8; 8];
    for (idx, byte) in data.iter().take(8).enumerate() {
        bytes[idx] = *byte;
    }
    if big_endian {
        u64::from_be_bytes(bytes)
    } else {
        u64::from_le_bytes(bytes)
    }
}

fuzz_target!(|data: &[u8]| {
    let (debug_info, debug_abbrev, debug_str) = split_debug_sections(data);
    let parser = DebugInfoParser::new(debug_info, debug_abbrev, Some(debug_str));

    if let Ok(units) = parser.parse_all() {
        let debug = DebugInfo::new(units, Vec::new());
        let _ = debug.find_location(0);
        let _ = debug.find_function(0);
        let _ = debug.functions().count();
    }

    let big_endian = data.get(1).map(|byte| byte & 1 == 1).unwrap_or(false);
    let address_size = if data.first().map(|byte| byte & 1 == 1).unwrap_or(false) {
        8
    } else {
        4
    };
    let _ = parse_eh_frame(data, address_size, big_endian, section_base(data, big_endian));
});
