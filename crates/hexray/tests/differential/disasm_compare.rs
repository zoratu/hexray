//! Disassembly comparison tests.
//!
//! These tests compare hexray's disassembly output against objdump/llvm-objdump
//! to verify instruction decoding accuracy.

use super::{
    compare_instructions, fixture_path, normalize_mnemonic, parse_objdump_simple, run_objdump,
    DisasmDiffResult,
};
use hexray_disasm::{Disassembler, X86_64Disassembler};
use hexray_formats::{BinaryFormat, Elf, MachO};
use std::fs;

/// Minimum match rate threshold for disassembly tests.
const DISASM_MATCH_THRESHOLD: f64 = 0.95;

/// Disassemble an ELF binary using hexray.
pub fn disassemble_elf_with_hexray(binary_path: &str) -> Vec<(u64, String)> {
    let data = match fs::read(binary_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to read {}: {}", binary_path, e);
            return Vec::new();
        }
    };

    let elf: Elf = match Elf::parse(&data) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Failed to parse ELF {}: {:?}", binary_path, e);
            return Vec::new();
        }
    };

    let disasm = X86_64Disassembler::new();
    let mut instructions = Vec::new();

    // Disassemble all executable sections
    for section in elf.executable_sections() {
        let section_data = section.data();
        let base_addr = section.virtual_address();

        let mut offset = 0;
        while offset < section_data.len() {
            let addr = base_addr + offset as u64;
            match disasm.decode_instruction(&section_data[offset..], addr) {
                Ok(decoded) => {
                    if decoded.size == 0 {
                        offset += 1;
                        continue;
                    }
                    instructions.push((addr, decoded.instruction.mnemonic.to_lowercase()));
                    offset += decoded.size;
                }
                Err(_) => {
                    offset += 1;
                }
            }
        }
    }

    instructions
}

/// Disassemble a Mach-O binary using hexray.
pub fn disassemble_macho_with_hexray(binary_path: &str) -> Vec<(u64, String)> {
    let data = match fs::read(binary_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to read {}: {}", binary_path, e);
            return Vec::new();
        }
    };

    let macho: MachO = match MachO::parse(&data) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Failed to parse Mach-O {}: {:?}", binary_path, e);
            return Vec::new();
        }
    };

    let disasm = X86_64Disassembler::new();
    let mut instructions = Vec::new();

    // Disassemble all executable sections
    for section in macho.executable_sections() {
        let section_data = section.data();
        let base_addr = section.virtual_address();

        let mut offset = 0;
        while offset < section_data.len() {
            let addr = base_addr + offset as u64;
            match disasm.decode_instruction(&section_data[offset..], addr) {
                Ok(decoded) => {
                    if decoded.size == 0 {
                        offset += 1;
                        continue;
                    }
                    instructions.push((addr, decoded.instruction.mnemonic.to_lowercase()));
                    offset += decoded.size;
                }
                Err(_) => {
                    offset += 1;
                }
            }
        }
    }

    instructions
}

/// Compare disassembly for an ELF binary.
pub fn compare_elf_disassembly(binary_path: &str) -> DisasmDiffResult {
    let hexray_instrs = disassemble_elf_with_hexray(binary_path);

    let objdump_output = match run_objdump(binary_path, false) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Failed to run objdump on {}: {}", binary_path, e);
            return DisasmDiffResult::new();
        }
    };

    let reference_instrs = parse_objdump_simple(&objdump_output);
    compare_instructions(&hexray_instrs, &reference_instrs)
}

/// Compare disassembly for a Mach-O binary.
pub fn compare_macho_disassembly(binary_path: &str) -> DisasmDiffResult {
    let hexray_instrs = disassemble_macho_with_hexray(binary_path);

    let objdump_output = match run_objdump(binary_path, false) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Failed to run objdump on {}: {}", binary_path, e);
            return DisasmDiffResult::new();
        }
    };

    let reference_instrs = parse_objdump_simple(&objdump_output);
    compare_instructions(&hexray_instrs, &reference_instrs)
}

/// Detailed disassembly comparison with verbose output.
pub fn compare_disassembly_verbose(binary_path: &str) -> DisasmDiffResult {
    println!("\n=== Disassembly Comparison: {} ===", binary_path);

    let result = if binary_path.ends_with(".exe") {
        // PE format - not fully supported for differential testing yet
        println!("PE format differential testing not yet implemented");
        DisasmDiffResult::new()
    } else if binary_path.contains("macho") || !binary_path.contains('.') {
        // Try Mach-O first, then ELF
        let macho_result = compare_macho_disassembly(binary_path);
        if macho_result.total_instructions > 0 {
            macho_result
        } else {
            compare_elf_disassembly(binary_path)
        }
    } else {
        compare_elf_disassembly(binary_path)
    };

    println!("{}", result.summary());
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::differential::{check_prerequisites, find_objdump, fixture_exists};

    /// Helper to skip test if prerequisites are not met.
    macro_rules! skip_if_missing {
        ($fixture:expr, $tool:expr) => {
            if let Err(reason) = check_prerequisites($fixture, $tool) {
                eprintln!("Skipping test: {}", reason);
                return;
            }
        };
    }

    #[test]
    fn test_disasm_elf_simple_x86_64() {
        skip_if_missing!("elf/simple_x86_64", "objdump");

        let path = fixture_path("elf/simple_x86_64");
        let result = compare_elf_disassembly(&path);

        println!("{}", result.summary());

        assert!(
            result.total_instructions > 0,
            "No instructions found in binary"
        );
        assert!(
            result.meets_threshold(DISASM_MATCH_THRESHOLD),
            "Match rate {:.2}% below threshold {:.2}%",
            result.match_rate * 100.0,
            DISASM_MATCH_THRESHOLD * 100.0
        );
    }

    #[test]
    fn test_disasm_elf_with_symbols() {
        skip_if_missing!("elf/test_with_symbols", "objdump");

        let path = fixture_path("elf/test_with_symbols");
        let result = compare_elf_disassembly(&path);

        println!("{}", result.summary());

        assert!(
            result.total_instructions > 0,
            "No instructions found in binary"
        );
        assert!(
            result.meets_threshold(0.90), // Allow lower threshold for complex binaries
            "Match rate {:.2}% below threshold 90%",
            result.match_rate * 100.0
        );
    }

    #[test]
    fn test_disasm_macho_x86_64() {
        skip_if_missing!("test_x86_64_macho", "objdump");

        let path = fixture_path("test_x86_64_macho");
        let result = compare_macho_disassembly(&path);

        println!("{}", result.summary());

        assert!(
            result.total_instructions > 0,
            "No instructions found in binary"
        );
        assert!(
            result.meets_threshold(DISASM_MATCH_THRESHOLD),
            "Match rate {:.2}% below threshold {:.2}%",
            result.match_rate * 100.0,
            DISASM_MATCH_THRESHOLD * 100.0
        );
    }

    #[test]
    fn test_disasm_test_decompile() {
        skip_if_missing!("test_decompile", "objdump");

        let path = fixture_path("test_decompile");
        let result = compare_disassembly_verbose(&path);

        assert!(
            result.total_instructions > 0,
            "No instructions found in binary"
        );
        assert!(
            result.meets_threshold(DISASM_MATCH_THRESHOLD),
            "Match rate {:.2}% below threshold {:.2}%",
            result.match_rate * 100.0,
            DISASM_MATCH_THRESHOLD * 100.0
        );
    }

    #[test]
    fn test_disasm_test_strings() {
        skip_if_missing!("test_strings", "objdump");

        let path = fixture_path("test_strings");
        let result = compare_disassembly_verbose(&path);

        assert!(
            result.total_instructions > 0,
            "No instructions found in binary"
        );
        // Allow lower threshold for larger binaries
        assert!(
            result.meets_threshold(0.90),
            "Match rate {:.2}% below threshold 90%",
            result.match_rate * 100.0
        );
    }

    #[test]
    fn test_disasm_all_fixtures() {
        // Run disassembly comparison on all available fixtures
        let fixtures = [
            "elf/simple_x86_64",
            "elf/test_with_symbols",
            "test_x86_64_macho",
            "test_decompile",
            "test_strings",
            "test_strings2",
        ];

        if find_objdump().is_none() {
            eprintln!("Skipping test: objdump not available");
            return;
        }

        let mut total_tests = 0;
        let mut passed_tests = 0;

        for fixture in fixtures {
            if !fixture_exists(fixture) {
                eprintln!("Fixture not found: {}", fixture);
                continue;
            }

            total_tests += 1;
            let path = fixture_path(fixture);
            let result = compare_disassembly_verbose(&path);

            if result.total_instructions > 0 && result.meets_threshold(0.90) {
                passed_tests += 1;
            }
        }

        println!(
            "\n=== Summary: {}/{} fixtures passed ===",
            passed_tests, total_tests
        );

        assert!(
            passed_tests > 0 || total_tests == 0,
            "At least some fixtures should pass"
        );
    }

    #[test]
    fn test_mnemonic_normalization_for_comparison() {
        // Test that our normalization handles common variations
        let test_cases = [
            ("push", "pushq", true),
            ("mov", "movq", true),
            ("ret", "retq", true),
            ("je", "jz", true),
            ("jne", "jnz", true),
            ("nop", "nopl", true),
            ("mov", "push", false),
            ("call", "jmp", false),
        ];

        for (a, b, should_match) in test_cases {
            let result = normalize_mnemonic(a) == normalize_mnemonic(b);
            assert_eq!(
                result,
                should_match,
                "Expected normalize('{}') {} normalize('{}'), but got {}",
                a,
                if should_match { "==" } else { "!=" },
                b,
                if result { "==" } else { "!=" }
            );
        }
    }
}
