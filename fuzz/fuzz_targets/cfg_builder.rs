#![no_main]

use libfuzzer_sys::fuzz_target;
use hexray_analysis::CfgBuilder;
use hexray_core::Instruction;
use hexray_disasm::x86_64::X86_64Disassembler;
use hexray_disasm::traits::Disassembler;

/// Disassemble bytes into instructions for CFG building.
fn disassemble_bytes(data: &[u8], start_addr: u64) -> Vec<Instruction> {
    let disasm = X86_64Disassembler::new();
    let mut instructions = Vec::new();
    let mut offset = 0;

    // Limit to prevent excessive processing
    while offset < data.len() && instructions.len() < 200 {
        match disasm.decode_instruction(&data[offset..], start_addr + offset as u64) {
            Ok(decoded) => {
                if decoded.size == 0 {
                    break;
                }
                let is_ret = decoded.instruction.is_return();
                instructions.push(decoded.instruction);
                offset += decoded.size;

                // Stop at return for function-like behavior
                if is_ret {
                    break;
                }
            }
            Err(_) => {
                offset += 1;
            }
        }
    }

    instructions
}

fuzz_target!(|data: &[u8]| {
    // Skip very small inputs
    if data.len() < 4 {
        return;
    }

    // Disassemble the bytes
    let instructions = disassemble_bytes(data, 0x1000);

    if instructions.is_empty() {
        return;
    }

    // Build CFG - should never panic
    let cfg = CfgBuilder::build(&instructions, 0x1000);

    // Verify basic CFG properties (should not panic)
    let block_count = cfg.blocks().count();
    let _has_entry = cfg.entry_block().is_some();

    // Iterate through blocks and edges (should not panic)
    for block in cfg.blocks() {
        let _id = block.id;
        let _start = block.start;
        let _end = block.end;
        let _instr_count = block.instructions.len();
    }

    // Test with various start addresses to check robustness
    if !instructions.is_empty() && data.len() >= 8 {
        let alt_addr = u64::from_le_bytes([
            data[0], data[1], data[2], data[3],
            data[4], data[5], data[6], data[7],
        ]) & 0xFFFFFFFF; // Limit to 32-bit address

        if alt_addr > 0 {
            let _ = CfgBuilder::build(&instructions, alt_addr);
        }
    }

    // Also test with subset of instructions
    if instructions.len() > 5 {
        let subset = &instructions[..instructions.len() / 2];
        let _ = CfgBuilder::build(subset, 0x1000);
    }

    // Ensure we can handle degenerate cases
    if block_count > 0 {
        // Single instruction CFG
        if !instructions.is_empty() {
            let _ = CfgBuilder::build(&instructions[..1], 0x1000);
        }
    }
});
