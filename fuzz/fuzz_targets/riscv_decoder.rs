#![no_main]

use libfuzzer_sys::fuzz_target;
use hexray_disasm::riscv::RiscVDisassembler;
use hexray_disasm::traits::Disassembler;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    // Test both RV64 and RV32 variants
    let disasm_rv64 = RiscVDisassembler::new();
    let disasm_rv32 = RiscVDisassembler::new_rv32();

    // Decode single instruction with RV64
    let _ = disasm_rv64.decode_instruction(data, 0x1000);

    // Decode single instruction with RV32
    let _ = disasm_rv32.decode_instruction(data, 0x1000);

    // Decode multiple instructions (RV64 with compressed)
    let mut offset = 0;
    let mut count = 0;
    while offset < data.len() && count < 100 {
        // Check for compressed instruction (2 bytes) vs standard (4 bytes)
        let min_size = if data.len() - offset >= 2 && (data[offset] & 0x03) != 0x03 {
            2 // Compressed instruction
        } else {
            4 // Standard instruction
        };

        if data.len() - offset < min_size {
            break;
        }

        match disasm_rv64.decode_instruction(&data[offset..], 0x1000 + offset as u64) {
            Ok(decoded) => {
                if decoded.size == 0 {
                    break;
                }
                // RISC-V instructions are 2 or 4 bytes
                assert!(decoded.size == 2 || decoded.size == 4);
                offset += decoded.size;
                count += 1;
            }
            Err(_) => {
                offset += min_size;
                count += 1;
            }
        }
    }
});
