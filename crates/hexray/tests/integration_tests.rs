//! Cross-crate integration tests for hexray.
//!
//! These tests exercise the full decompilation pipeline from binary parsing
//! through disassembly, CFG construction, and decompilation. They verify
//! that all crates work together correctly.

use std::fs;
use std::path::Path;

use hexray_analysis::{CallGraph, CfgBuilder, Decompiler};
use hexray_core::{Architecture, Bitness, Instruction};
use hexray_disasm::{Arm64Disassembler, Disassembler, X86_64Disassembler};
use hexray_formats::{detect_format, BinaryFormat, BinaryType, Elf, MachO, Pe};

/// Get the path to a test fixture.
fn fixture_path(name: &str) -> String {
    format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name)
}

/// Check if a fixture exists.
fn fixture_exists(name: &str) -> bool {
    Path::new(&fixture_path(name)).exists()
}

/// Helper macro to skip tests if fixture is missing.
macro_rules! skip_if_missing {
    ($fixture:expr) => {
        if !fixture_exists($fixture) {
            eprintln!("Skipping test: fixture {} not found", $fixture);
            return;
        }
    };
}

/// Helper to disassemble code using architecture-specific disassembler.
fn disassemble_block(arch: Architecture, data: &[u8], address: u64) -> Vec<Instruction> {
    match arch {
        Architecture::X86_64 => {
            let disasm = X86_64Disassembler::new();
            disasm
                .disassemble_block(data, address)
                .into_iter()
                .filter_map(|r| r.ok())
                .collect()
        }
        Architecture::Arm64 => {
            let disasm = Arm64Disassembler::new();
            disasm
                .disassemble_block(data, address)
                .into_iter()
                .filter_map(|r| r.ok())
                .collect()
        }
        _ => vec![],
    }
}

// =============================================================================
// Binary Format Detection Tests
// =============================================================================

#[test]
fn test_detect_elf_format() {
    skip_if_missing!("elf/simple_x86_64");

    let data = fs::read(fixture_path("elf/simple_x86_64")).expect("Failed to read fixture");
    let format = detect_format(&data);
    assert_eq!(format, BinaryType::Elf, "Should detect ELF format");
}

#[test]
fn test_detect_macho_format() {
    skip_if_missing!("test_x86_64_macho");

    let data = fs::read(fixture_path("test_x86_64_macho")).expect("Failed to read fixture");
    let format = detect_format(&data);
    assert_eq!(format, BinaryType::MachO, "Should detect Mach-O format");
}

#[test]
fn test_detect_pe_format() {
    skip_if_missing!("pe/simple_x64.exe");

    let data = fs::read(fixture_path("pe/simple_x64.exe")).expect("Failed to read fixture");
    let format = detect_format(&data);
    assert_eq!(format, BinaryType::Pe, "Should detect PE format");
}

#[test]
fn test_detect_arm64_macho() {
    skip_if_missing!("test_arm64_macho");

    let data = fs::read(fixture_path("test_arm64_macho")).expect("Failed to read fixture");
    let format = detect_format(&data);
    assert_eq!(
        format,
        BinaryType::MachO,
        "Should detect ARM64 Mach-O format"
    );
}

// =============================================================================
// ELF Parsing and Disassembly Tests
// =============================================================================

#[test]
fn test_elf_parsing_x86_64() {
    skip_if_missing!("elf/simple_x86_64");

    let data = fs::read(fixture_path("elf/simple_x86_64")).expect("Failed to read fixture");
    let elf = Elf::parse(&data).expect("Failed to parse ELF");

    assert_eq!(elf.bitness(), Bitness::Bits64, "Should be 64-bit ELF");
    assert_eq!(elf.architecture(), Architecture::X86_64);
}

#[test]
fn test_elf_with_symbols_parsing() {
    skip_if_missing!("elf/test_with_symbols");

    let data = fs::read(fixture_path("elf/test_with_symbols")).expect("Failed to read fixture");
    let elf = Elf::parse(&data).expect("Failed to parse ELF");

    let symbols: Vec<_> = elf.symbols().collect();
    assert!(!symbols.is_empty(), "Should have symbols");
}

#[test]
fn test_elf_disassembly() {
    skip_if_missing!("elf/simple_x86_64");

    let data = fs::read(fixture_path("elf/simple_x86_64")).expect("Failed to read fixture");
    let elf = Elf::parse(&data).expect("Failed to parse ELF");

    let text_section = elf
        .sections()
        .find(|s| s.name() == ".text" || s.name() == "text");
    if let Some(section) = text_section {
        let instructions = disassemble_block(
            Architecture::X86_64,
            section.data(),
            section.virtual_address(),
        );
        assert!(!instructions.is_empty(), "Should decode some instructions");
    }
}

// =============================================================================
// Mach-O Parsing and Disassembly Tests
// =============================================================================

#[test]
fn test_macho_parsing_x86_64() {
    skip_if_missing!("test_x86_64_macho");

    let data = fs::read(fixture_path("test_x86_64_macho")).expect("Failed to read fixture");
    let macho = MachO::parse(&data).expect("Failed to parse Mach-O");

    assert_eq!(macho.bitness(), Bitness::Bits64, "Should be 64-bit Mach-O");
    assert_eq!(macho.architecture(), Architecture::X86_64);
}

#[test]
fn test_macho_parsing_arm64() {
    skip_if_missing!("test_arm64_macho");

    let data = fs::read(fixture_path("test_arm64_macho")).expect("Failed to read fixture");
    let macho = MachO::parse(&data).expect("Failed to parse Mach-O");

    assert_eq!(macho.bitness(), Bitness::Bits64, "Should be 64-bit Mach-O");
    assert_eq!(macho.architecture(), Architecture::Arm64);
}

#[test]
fn test_macho_disassembly_x86_64() {
    skip_if_missing!("test_x86_64_macho");

    let data = fs::read(fixture_path("test_x86_64_macho")).expect("Failed to read fixture");
    let macho = MachO::parse(&data).expect("Failed to parse Mach-O");

    let text_section = macho
        .sections()
        .find(|s| s.name() == "__text" || s.name().contains("__text"));
    if let Some(section) = text_section {
        let instructions = disassemble_block(
            Architecture::X86_64,
            section.data(),
            section.virtual_address(),
        );
        assert!(!instructions.is_empty(), "Should decode some instructions");
    }
}

#[test]
fn test_macho_disassembly_arm64() {
    skip_if_missing!("test_arm64_macho");

    let data = fs::read(fixture_path("test_arm64_macho")).expect("Failed to read fixture");
    let macho = MachO::parse(&data).expect("Failed to parse Mach-O");

    let text_section = macho
        .sections()
        .find(|s| s.name() == "__text" || s.name().contains("__text"));
    if let Some(section) = text_section {
        let instructions = disassemble_block(
            Architecture::Arm64,
            section.data(),
            section.virtual_address(),
        );
        assert!(!instructions.is_empty(), "Should decode ARM64 instructions");
    }
}

// =============================================================================
// PE Parsing Tests
// =============================================================================

#[test]
fn test_pe_parsing_x64() {
    skip_if_missing!("pe/simple_x64.exe");

    let data = fs::read(fixture_path("pe/simple_x64.exe")).expect("Failed to read fixture");
    let pe = Pe::parse(&data).expect("Failed to parse PE");

    assert_eq!(pe.bitness(), Bitness::Bits64, "Should be 64-bit PE");
    assert_eq!(pe.architecture(), Architecture::X86_64);
}

#[test]
fn test_pe_sections() {
    skip_if_missing!("pe/simple_x64.exe");

    let data = fs::read(fixture_path("pe/simple_x64.exe")).expect("Failed to read fixture");
    let pe = Pe::parse(&data).expect("Failed to parse PE");

    let sections: Vec<_> = pe.sections().collect();
    assert!(!sections.is_empty(), "PE should have sections");

    // PE files typically have .text section
    let has_text = sections
        .iter()
        .any(|s| s.name().contains("text") || s.name().contains("TEXT"));
    assert!(has_text, "PE should have text section");
}

// =============================================================================
// CFG Construction Tests
// =============================================================================

#[test]
fn test_cfg_construction_elf() {
    skip_if_missing!("elf/test_with_symbols");

    let data = fs::read(fixture_path("elf/test_with_symbols")).expect("Failed to read fixture");
    let elf = Elf::parse(&data).expect("Failed to parse ELF");

    // Find a function to build CFG for
    let functions: Vec<_> = elf.symbols().filter(|s| s.is_function()).collect();
    if let Some(func) = functions.first() {
        let text_section = elf.sections().find(|s| {
            s.virtual_address() <= func.address
                && func.address < s.virtual_address() + s.data().len() as u64
        });

        if let Some(section) = text_section {
            let offset = (func.address - section.virtual_address()) as usize;
            let end_offset = if func.size > 0 {
                offset + func.size as usize
            } else {
                section.data().len().min(offset + 256)
            };
            let func_data = &section.data()[offset..end_offset.min(section.data().len())];

            let instructions = disassemble_block(Architecture::X86_64, func_data, func.address);

            if !instructions.is_empty() {
                let cfg = CfgBuilder::build(&instructions, func.address);
                assert!(cfg.num_blocks() > 0, "CFG should have at least one block");
            }
        }
    }
}

#[test]
fn test_cfg_construction_macho() {
    skip_if_missing!("test_decompile");

    let data = fs::read(fixture_path("test_decompile")).expect("Failed to read fixture");
    let macho = MachO::parse(&data).expect("Failed to parse Mach-O");

    // Find main function
    let main_sym = macho
        .symbols()
        .find(|s| s.name == "_main" || s.name == "main");
    if let Some(func) = main_sym {
        let text_section = macho.sections().find(|s| {
            s.virtual_address() <= func.address
                && func.address < s.virtual_address() + s.data().len() as u64
        });

        if let Some(section) = text_section {
            let arch = macho.architecture();
            let offset = (func.address - section.virtual_address()) as usize;
            let end_offset = if func.size > 0 {
                offset + func.size as usize
            } else {
                section.data().len().min(offset + 1024)
            };
            let func_data = &section.data()[offset..end_offset.min(section.data().len())];

            let instructions = disassemble_block(arch, func_data, func.address);

            if !instructions.is_empty() {
                let cfg = CfgBuilder::build(&instructions, func.address);
                assert!(cfg.num_blocks() > 0, "CFG should have at least one block");
            }
        }
    }
}

// =============================================================================
// Call Graph Construction Tests
// =============================================================================

#[test]
fn test_callgraph_construction() {
    skip_if_missing!("test_decompile");

    let data = fs::read(fixture_path("test_decompile")).expect("Failed to read fixture");
    let macho = MachO::parse(&data).expect("Failed to parse Mach-O");

    let functions: Vec<_> = macho.symbols().filter(|s| s.is_function()).collect();
    if !functions.is_empty() {
        let mut callgraph = CallGraph::new();

        for func in &functions {
            callgraph.add_node(func.address, Some(func.name.clone()), false);
        }

        assert!(callgraph.node_count() > 0, "Call graph should have nodes");
    }
}

// =============================================================================
// End-to-End Decompilation Tests
// =============================================================================

#[test]
fn test_decompile_simple_function() {
    skip_if_missing!("test_decompile");

    let data = fs::read(fixture_path("test_decompile")).expect("Failed to read fixture");
    let macho = MachO::parse(&data).expect("Failed to parse Mach-O");

    // Find main function
    let main_sym = macho
        .symbols()
        .find(|s| s.name == "_main" || s.name == "main");
    if let Some(func) = main_sym {
        let text_section = macho.sections().find(|s| {
            s.virtual_address() <= func.address
                && func.address < s.virtual_address() + s.data().len() as u64
        });

        if let Some(section) = text_section {
            let arch = macho.architecture();
            let offset = (func.address - section.virtual_address()) as usize;
            let end_offset = if func.size > 0 {
                offset + func.size as usize
            } else {
                section.data().len().min(offset + 2048)
            };
            let func_data = &section.data()[offset..end_offset.min(section.data().len())];

            let instructions = disassemble_block(arch, func_data, func.address);

            if !instructions.is_empty() {
                let cfg = CfgBuilder::build(&instructions, func.address);

                if cfg.num_blocks() > 0 {
                    let decompiler = Decompiler::new();
                    let result = decompiler.decompile(&cfg, &func.name);

                    // Verify output contains function syntax
                    assert!(
                        result.contains("("),
                        "Decompiled output should contain function call syntax"
                    );
                    assert!(
                        result.contains(")"),
                        "Decompiled output should contain closing paren"
                    );
                }
            }
        }
    }
}

#[test]
fn test_decompile_produces_valid_c_syntax() {
    skip_if_missing!("test_decompile");

    let data = fs::read(fixture_path("test_decompile")).expect("Failed to read fixture");
    let macho = MachO::parse(&data).expect("Failed to parse Mach-O");

    let main_sym = macho
        .symbols()
        .find(|s| s.name == "_main" || s.name == "main");
    if let Some(func) = main_sym {
        let text_section = macho.sections().find(|s| {
            s.virtual_address() <= func.address
                && func.address < s.virtual_address() + s.data().len() as u64
        });

        if let Some(section) = text_section {
            let arch = macho.architecture();
            let offset = (func.address - section.virtual_address()) as usize;
            let end_offset = if func.size > 0 {
                offset + func.size as usize
            } else {
                section.data().len().min(offset + 2048)
            };
            let func_data = &section.data()[offset..end_offset.min(section.data().len())];

            let instructions = disassemble_block(arch, func_data, func.address);

            if !instructions.is_empty() {
                let cfg = CfgBuilder::build(&instructions, func.address);

                if cfg.num_blocks() > 0 {
                    let decompiler = Decompiler::new();
                    let result = decompiler.decompile(&cfg, &func.name);

                    // Basic C syntax validation
                    // Should have balanced braces
                    let open_braces = result.matches('{').count();
                    let close_braces = result.matches('}').count();
                    assert_eq!(
                        open_braces, close_braces,
                        "Braces should be balanced in output"
                    );

                    // Should have balanced parentheses
                    let open_parens = result.matches('(').count();
                    let close_parens = result.matches(')').count();
                    assert_eq!(
                        open_parens, close_parens,
                        "Parentheses should be balanced in output"
                    );
                }
            }
        }
    }
}

// =============================================================================
// Debug Information Tests
// =============================================================================

#[test]
fn test_binary_with_dwarf_debug_info() {
    skip_if_missing!("test_with_debug");

    let data = fs::read(fixture_path("test_with_debug")).expect("Failed to read fixture");
    let macho = MachO::parse(&data).expect("Failed to parse Mach-O");

    // Binary should parse successfully even with debug info
    assert_eq!(macho.bitness(), Bitness::Bits64);

    // Should have symbols from debug info
    let symbols: Vec<_> = macho.symbols().collect();
    assert!(!symbols.is_empty(), "Debug binary should have symbols");
}

// =============================================================================
// Stripped Binary Tests
// =============================================================================

#[test]
fn test_stripped_binary_analysis() {
    skip_if_missing!("elf/simple_x86_64");

    let data = fs::read(fixture_path("elf/simple_x86_64")).expect("Failed to read fixture");
    let elf = Elf::parse(&data).expect("Failed to parse ELF");

    // This binary might be stripped - verify we can still analyze it
    let text_section = elf
        .sections()
        .find(|s| s.name() == ".text" || s.name() == "text");

    if let Some(section) = text_section {
        // Even without symbols, we should be able to disassemble
        let instructions = disassemble_block(
            Architecture::X86_64,
            section.data(),
            section.virtual_address(),
        );

        // Should be able to decode some instructions
        assert!(
            !instructions.is_empty() || section.data().is_empty(),
            "Should decode instructions from stripped binary"
        );
    }
}

// =============================================================================
// Relocatable Object Tests
// =============================================================================

#[test]
fn test_relocatable_object_parsing() {
    skip_if_missing!("test_relocatable.o");

    let data = fs::read(fixture_path("test_relocatable.o")).expect("Failed to read fixture");
    let elf = Elf::parse(&data).expect("Failed to parse relocatable ELF");

    // Relocatable objects have different characteristics
    assert_eq!(elf.bitness(), Bitness::Bits64);
    assert_eq!(elf.architecture(), Architecture::X86_64);

    // Should have sections
    let sections: Vec<_> = elf.sections().collect();
    assert!(
        !sections.is_empty(),
        "Relocatable object should have sections"
    );
}

// =============================================================================
// Architecture-Specific Tests
// =============================================================================

#[test]
fn test_x86_64_instruction_decoding() {
    skip_if_missing!("elf/simple_x86_64");

    let data = fs::read(fixture_path("elf/simple_x86_64")).expect("Failed to read fixture");
    let elf = Elf::parse(&data).expect("Failed to parse ELF");

    let text_section = elf
        .sections()
        .find(|s| s.name() == ".text" || s.name() == "text");
    if let Some(section) = text_section {
        let instructions = disassemble_block(
            Architecture::X86_64,
            section.data(),
            section.virtual_address(),
        );

        for inst in &instructions {
            // All instructions should have valid mnemonics
            assert!(
                !inst.mnemonic.is_empty(),
                "Instruction should have mnemonic"
            );
            // All instructions should have size > 0
            assert!(inst.size > 0, "Instruction should have positive size");
        }
    }
}

#[test]
fn test_arm64_instruction_decoding() {
    skip_if_missing!("test_arm64_macho");

    let data = fs::read(fixture_path("test_arm64_macho")).expect("Failed to read fixture");
    let macho = MachO::parse(&data).expect("Failed to parse Mach-O");

    let text_section = macho
        .sections()
        .find(|s| s.name() == "__text" || s.name().contains("__text"));

    if let Some(section) = text_section {
        let instructions = disassemble_block(
            Architecture::Arm64,
            section.data(),
            section.virtual_address(),
        );

        for inst in &instructions {
            // All ARM64 instructions are 4 bytes
            assert_eq!(inst.size, 4, "ARM64 instructions should be 4 bytes");
            // All instructions should have valid mnemonics
            assert!(
                !inst.mnemonic.is_empty(),
                "Instruction should have mnemonic"
            );
        }
    }
}

// =============================================================================
// Signature Recovery Tests
// =============================================================================

#[test]
fn test_signature_recovery() {
    skip_if_missing!("test_decompile");

    let data = fs::read(fixture_path("test_decompile")).expect("Failed to read fixture");
    let macho = MachO::parse(&data).expect("Failed to parse Mach-O");

    let main_sym = macho
        .symbols()
        .find(|s| s.name == "_main" || s.name == "main");
    if let Some(func) = main_sym {
        let text_section = macho.sections().find(|s| {
            s.virtual_address() <= func.address
                && func.address < s.virtual_address() + s.data().len() as u64
        });

        if let Some(section) = text_section {
            let arch = macho.architecture();
            let offset = (func.address - section.virtual_address()) as usize;
            let end_offset = if func.size > 0 {
                offset + func.size as usize
            } else {
                section.data().len().min(offset + 2048)
            };
            let func_data = &section.data()[offset..end_offset.min(section.data().len())];

            let instructions = disassemble_block(arch, func_data, func.address);

            if !instructions.is_empty() {
                let cfg = CfgBuilder::build(&instructions, func.address);

                if cfg.num_blocks() > 0 {
                    let decompiler = Decompiler::new();
                    let signature = decompiler.recover_signature(&cfg);

                    // Signature recovery should produce some result
                    // (even if empty, it shouldn't panic)
                    let _ = signature;
                }
            }
        }
    }
}

// =============================================================================
// Output Format Integration Tests
// =============================================================================

#[test]
fn test_cfg_to_dot_export() {
    skip_if_missing!("test_decompile");

    let data = fs::read(fixture_path("test_decompile")).expect("Failed to read fixture");
    let macho = MachO::parse(&data).expect("Failed to parse Mach-O");

    let main_sym = macho
        .symbols()
        .find(|s| s.name == "_main" || s.name == "main");
    if let Some(func) = main_sym {
        let text_section = macho.sections().find(|s| {
            s.virtual_address() <= func.address
                && func.address < s.virtual_address() + s.data().len() as u64
        });

        if let Some(section) = text_section {
            let arch = macho.architecture();
            let offset = (func.address - section.virtual_address()) as usize;
            let end_offset = if func.size > 0 {
                offset + func.size as usize
            } else {
                section.data().len().min(offset + 2048)
            };
            let func_data = &section.data()[offset..end_offset.min(section.data().len())];

            let instructions = disassemble_block(arch, func_data, func.address);

            if !instructions.is_empty() {
                let cfg = CfgBuilder::build(&instructions, func.address);

                if cfg.num_blocks() > 0 {
                    use hexray_analysis::CfgDotExporter;
                    let exporter = CfgDotExporter::new();
                    let dot = exporter.export_to_string(&cfg, &func.name);

                    assert!(dot.contains("digraph"), "DOT output should be a digraph");
                    assert!(
                        dot.contains("->") || cfg.num_blocks() == 1,
                        "DOT should have edges or single block"
                    );
                }
            }
        }
    }
}

#[test]
fn test_cfg_to_json_export() {
    skip_if_missing!("test_decompile");

    let data = fs::read(fixture_path("test_decompile")).expect("Failed to read fixture");
    let macho = MachO::parse(&data).expect("Failed to parse Mach-O");

    let main_sym = macho
        .symbols()
        .find(|s| s.name == "_main" || s.name == "main");
    if let Some(func) = main_sym {
        let text_section = macho.sections().find(|s| {
            s.virtual_address() <= func.address
                && func.address < s.virtual_address() + s.data().len() as u64
        });

        if let Some(section) = text_section {
            let arch = macho.architecture();
            let offset = (func.address - section.virtual_address()) as usize;
            let end_offset = if func.size > 0 {
                offset + func.size as usize
            } else {
                section.data().len().min(offset + 2048)
            };
            let func_data = &section.data()[offset..end_offset.min(section.data().len())];

            let instructions = disassemble_block(arch, func_data, func.address);

            if !instructions.is_empty() {
                let cfg = CfgBuilder::build(&instructions, func.address);

                if cfg.num_blocks() > 0 {
                    use hexray_analysis::CfgJsonExporter;
                    let exporter = CfgJsonExporter::new();
                    let json = exporter.export_to_string(&cfg, &func.name);

                    // Verify it's valid JSON
                    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&json);
                    assert!(parsed.is_ok(), "JSON output should be valid JSON");
                }
            }
        }
    }
}

// =============================================================================
// Error Handling Tests
// =============================================================================

#[test]
fn test_invalid_binary_handling() {
    // Create invalid binary data
    let invalid_data = vec![0x00, 0x01, 0x02, 0x03];

    // Should detect as unknown format
    let format = detect_format(&invalid_data);
    assert_eq!(format, BinaryType::Unknown);

    // ELF parser should fail gracefully
    let elf_result = Elf::parse(&invalid_data);
    assert!(elf_result.is_err(), "Invalid data should fail ELF parsing");

    // Mach-O parser should fail gracefully
    let macho_result = MachO::parse(&invalid_data);
    assert!(
        macho_result.is_err(),
        "Invalid data should fail Mach-O parsing"
    );

    // PE parser should fail gracefully
    let pe_result = Pe::parse(&invalid_data);
    assert!(pe_result.is_err(), "Invalid data should fail PE parsing");
}

#[test]
fn test_truncated_binary_handling() {
    skip_if_missing!("elf/simple_x86_64");

    let data = fs::read(fixture_path("elf/simple_x86_64")).expect("Failed to read fixture");

    // Truncate to just headers
    let truncated = &data[..data.len().min(64)];

    // Should still detect format
    let format = detect_format(truncated);
    assert_eq!(
        format,
        BinaryType::Elf,
        "Should still detect ELF from magic"
    );

    // Parsing may fail or succeed with partial data - should not panic
    let _result = Elf::parse(truncated);
}

#[test]
fn test_empty_data_handling() {
    let empty_data: Vec<u8> = vec![];

    // Should detect as unknown
    let format = detect_format(&empty_data);
    assert_eq!(format, BinaryType::Unknown);

    // Parsers should fail gracefully
    assert!(Elf::parse(&empty_data).is_err());
    assert!(MachO::parse(&empty_data).is_err());
    assert!(Pe::parse(&empty_data).is_err());
}

// =============================================================================
// Cross-Format Consistency Tests
// =============================================================================

#[test]
fn test_architecture_consistency() {
    // Verify that detected architecture is consistent across parsing steps
    skip_if_missing!("test_x86_64_macho");

    let data = fs::read(fixture_path("test_x86_64_macho")).expect("Failed to read fixture");
    let macho = MachO::parse(&data).expect("Failed to parse Mach-O");

    let arch_from_parser = macho.architecture();

    let text_section = macho
        .sections()
        .find(|s| s.name() == "__text" || s.name().contains("__text"));

    if let Some(section) = text_section {
        let instructions =
            disassemble_block(arch_from_parser, section.data(), section.virtual_address());

        // All decoded instructions should be valid for this architecture
        for inst in &instructions {
            assert!(inst.size > 0, "Instruction size should be positive");
        }
    }
}

// =============================================================================
// Multi-Architecture Pipeline Tests
// =============================================================================

#[test]
fn test_full_pipeline_x86_64_elf() {
    skip_if_missing!("elf/test_with_symbols");

    let data = fs::read(fixture_path("elf/test_with_symbols")).expect("Failed to read fixture");

    // Step 1: Parse
    let elf = Elf::parse(&data).expect("Failed to parse ELF");
    assert_eq!(elf.architecture(), Architecture::X86_64);

    // Step 2: Find functions
    let functions: Vec<_> = elf.symbols().filter(|s| s.is_function()).collect();
    assert!(!functions.is_empty(), "Should find function symbols");

    // Step 3: Disassemble and build CFG for each function
    for func in functions.iter().take(3) {
        // Limit to first 3 for speed
        let text_section = elf.sections().find(|s| {
            s.virtual_address() <= func.address
                && func.address < s.virtual_address() + s.data().len() as u64
        });

        if let Some(section) = text_section {
            let offset = (func.address - section.virtual_address()) as usize;
            let end_offset = if func.size > 0 {
                offset + func.size as usize
            } else {
                section.data().len().min(offset + 256)
            };
            let func_data = &section.data()[offset..end_offset.min(section.data().len())];

            let instructions = disassemble_block(Architecture::X86_64, func_data, func.address);

            if !instructions.is_empty() {
                // Step 4: Build CFG
                let cfg = CfgBuilder::build(&instructions, func.address);
                assert!(cfg.num_blocks() > 0);

                // Step 5: Decompile
                if cfg.num_blocks() > 0 {
                    let decompiler = Decompiler::new();
                    let output = decompiler.decompile(&cfg, &func.name);
                    assert!(!output.is_empty(), "Decompilation should produce output");
                }
            }
        }
    }
}

#[test]
fn test_full_pipeline_x86_64_macho() {
    skip_if_missing!("test_x86_64_macho");

    let data = fs::read(fixture_path("test_x86_64_macho")).expect("Failed to read fixture");

    // Step 1: Parse
    let macho = MachO::parse(&data).expect("Failed to parse Mach-O");
    assert_eq!(macho.architecture(), Architecture::X86_64);

    // Step 2: Find main
    let main_sym = macho
        .symbols()
        .find(|s| s.name == "_main" || s.name == "main");

    if let Some(func) = main_sym {
        let text_section = macho.sections().find(|s| {
            s.virtual_address() <= func.address
                && func.address < s.virtual_address() + s.data().len() as u64
        });

        if let Some(section) = text_section {
            let offset = (func.address - section.virtual_address()) as usize;
            let end_offset = section.data().len().min(offset + 2048);
            let func_data = &section.data()[offset..end_offset];

            // Step 3: Disassemble
            let instructions = disassemble_block(Architecture::X86_64, func_data, func.address);

            if !instructions.is_empty() {
                // Step 4: Build CFG
                let cfg = CfgBuilder::build(&instructions, func.address);

                // Step 5: Decompile
                if cfg.num_blocks() > 0 {
                    let decompiler = Decompiler::new();
                    let output = decompiler.decompile(&cfg, &func.name);
                    assert!(!output.is_empty());

                    // Step 6: Export to DOT
                    use hexray_analysis::CfgDotExporter;
                    let dot_exporter = CfgDotExporter::new();
                    let dot = dot_exporter.export_to_string(&cfg, &func.name);
                    assert!(dot.contains("digraph"));

                    // Step 7: Export to JSON
                    use hexray_analysis::CfgJsonExporter;
                    let json_exporter = CfgJsonExporter::new();
                    let json = json_exporter.export_to_string(&cfg, &func.name);
                    let _: serde_json::Value =
                        serde_json::from_str(&json).expect("JSON should be valid");
                }
            }
        }
    }
}

#[test]
fn test_full_pipeline_arm64_macho() {
    skip_if_missing!("test_arm64_macho");

    let data = fs::read(fixture_path("test_arm64_macho")).expect("Failed to read fixture");

    // Step 1: Parse
    let macho = MachO::parse(&data).expect("Failed to parse Mach-O");
    assert_eq!(macho.architecture(), Architecture::Arm64);

    // Step 2: Find main
    let main_sym = macho
        .symbols()
        .find(|s| s.name == "_main" || s.name == "main");

    if let Some(func) = main_sym {
        let text_section = macho.sections().find(|s| {
            s.virtual_address() <= func.address
                && func.address < s.virtual_address() + s.data().len() as u64
        });

        if let Some(section) = text_section {
            let offset = (func.address - section.virtual_address()) as usize;
            let end_offset = section.data().len().min(offset + 2048);
            let func_data = &section.data()[offset..end_offset];

            // Step 3: Disassemble
            let instructions = disassemble_block(Architecture::Arm64, func_data, func.address);

            if !instructions.is_empty() {
                // Step 4: Build CFG
                let cfg = CfgBuilder::build(&instructions, func.address);

                // Step 5: Decompile
                if cfg.num_blocks() > 0 {
                    let decompiler = Decompiler::new();
                    let output = decompiler.decompile(&cfg, &func.name);
                    assert!(!output.is_empty());
                }
            }
        }
    }
}
