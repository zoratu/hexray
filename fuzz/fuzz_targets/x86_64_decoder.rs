#![no_main]

use libfuzzer_sys::fuzz_target;
use hexray_disasm::x86_64::X86_64Disassembler;
use hexray_disasm::traits::Disassembler;

fuzz_target!(|data: &[u8]| {
    // Create disassembler
    let disasm = X86_64Disassembler::new();

    // Try to decode instruction - should never panic
    // May return error for invalid sequences, that's fine
    let _ = disasm.decode_instruction(data, 0x1000);

    // Also test disassembling a block of instructions
    if data.len() >= 16 {
        let mut offset = 0;
        let mut count = 0;
        while offset < data.len() && count < 100 {
            match disasm.decode_instruction(&data[offset..], 0x1000 + offset as u64) {
                Ok(decoded) => {
                    if decoded.size == 0 {
                        break; // Avoid infinite loop
                    }
                    offset += decoded.size;
                    count += 1;
                }
                Err(_) => {
                    offset += 1; // Skip byte on error
                    count += 1;
                }
            }
        }
    }
});
