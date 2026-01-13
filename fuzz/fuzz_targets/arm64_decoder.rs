#![no_main]

use libfuzzer_sys::fuzz_target;
use hexray_disasm::arm64::Arm64Disassembler;
use hexray_disasm::traits::Disassembler;

fuzz_target!(|data: &[u8]| {
    // ARM64 instructions are fixed 32-bit
    if data.len() < 4 {
        return;
    }

    let disasm = Arm64Disassembler::new();

    // Decode single instruction
    let _ = disasm.decode_instruction(data, 0x1000);

    // Decode multiple instructions from the buffer
    let mut offset = 0;
    let mut count = 0;
    while offset + 4 <= data.len() && count < 100 {
        match disasm.decode_instruction(&data[offset..], 0x1000 + offset as u64) {
            Ok(decoded) => {
                // ARM64 instructions are always 4 bytes
                assert!(decoded.size == 4 || decoded.size == 0);
                if decoded.size == 0 {
                    break;
                }
                offset += decoded.size;
                count += 1;
            }
            Err(_) => {
                offset += 4; // Skip instruction on error
                count += 1;
            }
        }
    }
});
