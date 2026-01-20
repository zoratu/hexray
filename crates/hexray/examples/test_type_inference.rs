//! Example demonstrating type inference integration with decompiler.
//!
//! This example loads a binary, runs type inference on a function,
//! and shows the decompiled output with inferred types.

use hexray_analysis::decompiler::Decompiler;
use hexray_analysis::ssa::SsaBuilder;
use hexray_analysis::types::TypeInference;
use hexray_analysis::CfgBuilder;
use hexray_core::Architecture;
use hexray_disasm::arm64::Arm64Disassembler;
use hexray_disasm::x86_64::X86_64Disassembler;
use hexray_disasm::Disassembler;
use hexray_formats::macho::MachO;
use hexray_formats::BinaryFormat;
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load test binary (use x86_64 for better type inference demo)
    let binary_path = "tests/fixtures/test_x86_64_macho";
    let data = std::fs::read(binary_path)?;

    println!("=== Type Inference + Decompiler Demo ===\n");

    // Parse Mach-O
    let macho = MachO::parse(&data)?;
    println!("Loaded: {} ({:?})", binary_path, macho.architecture());

    // Find main function (more interesting for type inference)
    let target_sym = macho
        .symbols()
        .find(|s| s.name.contains("main") || s.name.contains("factorial"))
        .ok_or("main/factorial not found")?;

    println!(
        "\nFunction: {} at {:#x}",
        target_sym.name, target_sym.address
    );

    // Get function bytes
    let func_bytes = macho
        .bytes_at(target_sym.address, 200)
        .ok_or("Cannot read bytes")?;

    // Disassemble using the correct architecture
    let arch = macho.architecture();
    let instructions = match arch {
        Architecture::Arm64 => {
            let disasm = Arm64Disassembler::new();
            disassemble_function(&disasm, func_bytes, target_sym.address)
        }
        Architecture::X86_64 | Architecture::X86 => {
            let disasm = X86_64Disassembler::new();
            disassemble_function(&disasm, func_bytes, target_sym.address)
        }
        _ => return Err(format!("Unsupported architecture: {:?}", arch).into()),
    };

    println!("\nDisassembled {} instructions", instructions.len());

    // Build CFG
    let cfg = CfgBuilder::build(&instructions, target_sym.address);
    println!("Built CFG with {} blocks", cfg.blocks().count());

    // Build SSA
    let ssa = SsaBuilder::new(&cfg).build("factorial");
    println!("Built SSA with {} blocks", ssa.blocks.len());

    // Run type inference
    let mut type_inference = TypeInference::with_libc();
    type_inference.infer(&ssa);

    // Export types for decompiler
    let type_info = type_inference.export_for_decompiler();
    println!("\nInferred types:");
    for (var, ty) in &type_info {
        println!("  {} : {}", var, ty);
    }

    // Decompile without type info
    println!("\n--- Decompiled (without type inference) ---");
    let decompiler = Decompiler::new().with_addresses(false);
    let output = decompiler.decompile(&cfg, "factorial");
    println!("{}", output);

    // Decompile with type info
    println!("--- Decompiled (with type inference) ---");
    let decompiler_with_types = Decompiler::new()
        .with_addresses(false)
        .with_type_info(type_info);
    let output_with_types = decompiler_with_types.decompile(&cfg, "factorial");
    println!("{}", output_with_types);

    // Also test with manually set types to show the feature works
    println!("--- Decompiled (with manual type annotations) ---");
    let mut manual_types = HashMap::new();
    manual_types.insert("var_4".to_string(), "int".to_string());
    manual_types.insert("var_8".to_string(), "size_t".to_string());
    manual_types.insert("local_4".to_string(), "int".to_string());
    manual_types.insert("local_8".to_string(), "int64_t".to_string());
    manual_types.insert("local_c".to_string(), "unsigned int".to_string());

    let decompiler_manual = Decompiler::new()
        .with_addresses(false)
        .with_type_info(manual_types);
    let output_manual = decompiler_manual.decompile(&cfg, "factorial");
    println!("{}", output_manual);

    // Demonstrate DWARF variable names (simulated)
    println!("--- Decompiled (with DWARF variable names) ---");
    let mut dwarf_names: HashMap<i128, String> = HashMap::new();
    // Simulate DWARF names for stack offsets (frame-relative)
    // For x86_64: locals at negative offsets from rbp
    // local_4 -> i, local_8 -> result, local_c -> n (parameter)
    dwarf_names.insert(-4, "i".to_string());
    dwarf_names.insert(-8, "result".to_string());
    dwarf_names.insert(-12, "n".to_string());

    let decompiler_dwarf = Decompiler::new()
        .with_addresses(false)
        .with_dwarf_names(dwarf_names);
    let output_dwarf = decompiler_dwarf.decompile(&cfg, "factorial");
    println!("{}", output_dwarf);

    Ok(())
}

/// Disassemble a function until we hit a return instruction.
fn disassemble_function<D: Disassembler>(
    disasm: &D,
    bytes: &[u8],
    start_addr: u64,
) -> Vec<hexray_core::Instruction> {
    let mut instructions = Vec::new();
    let mut offset = 0;

    while offset < bytes.len() && instructions.len() < 500 {
        let remaining = &bytes[offset..];
        let addr = start_addr + offset as u64;

        match disasm.decode_instruction(remaining, addr) {
            Ok(decoded) => {
                let is_ret = decoded.instruction.is_return();
                instructions.push(decoded.instruction);
                offset += decoded.size;

                if is_ret {
                    break;
                }
            }
            Err(_) => {
                offset += disasm.min_instruction_size().max(1);
            }
        }
    }

    instructions
}
