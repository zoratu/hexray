#![no_main]

use libfuzzer_sys::fuzz_target;
use hexray_analysis::{CfgBuilder, Decompiler, StringTable, SymbolTable};
use hexray_core::Instruction;
use hexray_disasm::x86_64::X86_64Disassembler;
use hexray_disasm::traits::Disassembler;

/// Disassemble bytes into instructions for decompilation.
fn disassemble_bytes(data: &[u8], start_addr: u64) -> Vec<Instruction> {
    let disasm = X86_64Disassembler::new();
    let mut instructions = Vec::new();
    let mut offset = 0;

    // Limit to prevent excessive processing during fuzzing
    while offset < data.len() && instructions.len() < 150 {
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

    // Build CFG
    let cfg = CfgBuilder::build(&instructions, 0x1000);

    // Skip if CFG is too large (would be slow to decompile)
    if cfg.blocks().count() > 50 {
        return;
    }

    // Test basic decompiler - should never panic
    let decompiler = Decompiler::new();
    let _output = decompiler.decompile(&cfg, "fuzz_func");

    // Test with addresses enabled
    let decompiler_with_addr = Decompiler::new().with_addresses(true);
    let _output = decompiler_with_addr.decompile(&cfg, "fuzz_func_addr");

    // Test with symbol table
    let mut symbols = SymbolTable::new();
    if data.len() >= 16 {
        // Use some input bytes to generate fake symbols
        let sym_addr = 0x1000 + (data[8] as u64) * 4;
        symbols.insert(sym_addr, "test_symbol".to_string());
    }
    let decompiler_with_syms = Decompiler::new().with_symbol_table(symbols);
    let _output = decompiler_with_syms.decompile(&cfg, "fuzz_func_syms");

    // Test with string table
    let mut strings = StringTable::new();
    if data.len() >= 20 {
        let str_addr = 0x2000 + (data[12] as u64) * 8;
        strings.insert(str_addr, "test string".to_string());
    }
    let decompiler_with_strs = Decompiler::new().with_string_table(strings);
    let _output = decompiler_with_strs.decompile(&cfg, "fuzz_func_strs");

    // Test with struct inference enabled/disabled
    let decompiler_struct = Decompiler::new().with_struct_inference(true);
    let _output = decompiler_struct.decompile(&cfg, "fuzz_func_struct");

    let decompiler_no_struct = Decompiler::new().with_struct_inference(false);
    let _output = decompiler_no_struct.decompile(&cfg, "fuzz_func_no_struct");

    // Test with a function name from input data (edge case testing)
    if data.len() >= 24 {
        // Generate a function name from input (may contain unusual characters)
        let name_len = (data[20] as usize % 32).max(1);
        let name_bytes: Vec<u8> = data[21..data.len().min(21 + name_len)]
            .iter()
            .map(|&b| {
                // Convert to valid identifier characters
                if b.is_ascii_alphanumeric() || b == b'_' {
                    b
                } else {
                    b'_'
                }
            })
            .collect();
        if let Ok(name) = String::from_utf8(name_bytes) {
            if !name.is_empty() {
                let _ = decompiler.decompile(&cfg, &name);
            }
        }
    }
});
