//! Differential tests comparing hexray output against reference tools.
//!
//! This test suite compares hexray's output against standard binary analysis tools
//! to ensure correctness and compatibility.
//!
//! # Test Categories
//!
//! - **Disassembly** (`disasm_compare`): Compare instruction decoding against objdump/llvm-objdump
//! - **Symbols** (`symbols_compare`): Compare symbol extraction against nm
//! - **Strings** (`strings_compare`): Compare string detection against the strings command
//!
//! # Running Tests
//!
//! Run all differential tests:
//! ```bash
//! cargo test --test differential_tests
//! ```
//!
//! Run specific category:
//! ```bash
//! cargo test --test differential_tests disasm
//! cargo test --test differential_tests symbols
//! cargo test --test differential_tests strings
//! ```
//!
//! Run tests that require external tools (ignored by default):
//! ```bash
//! cargo test --test differential_tests -- --ignored
//! ```
//!
//! Run all tests including ignored ones:
//! ```bash
//! cargo test --test differential_tests -- --include-ignored
//! ```
//!
//! # Test Thresholds
//!
//! - Disassembly: Target >95% mnemonic match rate
//! - Symbols: Target >99% symbol match rate
//! - Strings: Target >80% string match rate (string algorithms differ more)

mod differential;

// Include submodules from the differential directory
#[path = "differential/disasm_compare.rs"]
pub mod disasm_compare;
#[path = "differential/symbols_compare.rs"]
pub mod symbols_compare;
#[path = "differential/strings_compare.rs"]
pub mod strings_compare;

// Re-export utilities for use in test modules
pub use differential::*;

use std::path::Path;

// =============================================================================
// Integration Tests
// =============================================================================

/// Run all differential tests on a single binary.
fn run_all_comparisons(binary_path: &str) {
    println!("\n============================================================");
    println!("Running all differential tests on: {}", binary_path);
    println!("============================================================");

    // Disassembly comparison
    let disasm_result = disasm_compare::compare_disassembly_verbose(binary_path);

    // Symbol comparison
    let symbol_result = symbols_compare::compare_symbols_verbose(binary_path);

    // String comparison
    let string_result = strings_compare::compare_strings_verbose(binary_path, 4);

    // Summary
    println!("\n=== Overall Summary for {} ===", binary_path);
    println!(
        "Disassembly: {:.1}% match ({}/{})",
        disasm_result.match_rate * 100.0,
        disasm_result.matching_instructions,
        disasm_result.total_instructions
    );
    println!(
        "Symbols: {:.1}% match ({}/{})",
        symbol_result.match_rate * 100.0,
        symbol_result.matching_symbols,
        symbol_result.total_symbols
    );
    println!(
        "Strings: {:.1}% match ({}/{})",
        string_result.match_rate * 100.0,
        string_result.matching_strings,
        string_result.total_strings
    );
}

#[test]
#[ignore] // Requires external tools and test fixtures
fn integration_test_decompile() {
    let path = fixture_path("test_decompile");
    if !Path::new(&path).exists() {
        eprintln!("Skipping: fixture not found");
        return;
    }
    run_all_comparisons(&path);
}

#[test]
#[ignore] // Requires external tools and test fixtures
fn integration_test_strings() {
    let path = fixture_path("test_strings");
    if !Path::new(&path).exists() {
        eprintln!("Skipping: fixture not found");
        return;
    }
    run_all_comparisons(&path);
}

#[test]
#[ignore] // Requires external tools and test fixtures
fn integration_test_x86_64_macho() {
    let path = fixture_path("test_x86_64_macho");
    if !Path::new(&path).exists() {
        eprintln!("Skipping: fixture not found");
        return;
    }
    run_all_comparisons(&path);
}

// =============================================================================
// Quick Sanity Tests (no external tools required)
// =============================================================================

#[test]
fn sanity_test_objdump_parser() {
    let sample_output = br#"
test:     file format elf64-x86-64

Disassembly of section .text:

0000000000401000 <_start>:
  401000:	55                   	push   %rbp
  401001:	48 89 e5             	mov    %rsp,%rbp
  401004:	b8 3c 00 00 00       	mov    $0x3c,%eax
  401009:	5d                   	pop    %rbp
  40100a:	c3                   	ret
"#;

    let instructions = parse_objdump_output(sample_output);
    assert_eq!(instructions.len(), 5, "Should parse 5 instructions");
    assert_eq!(instructions[0].address, 0x401000);
    assert_eq!(instructions[0].mnemonic, "push");
    assert_eq!(instructions[4].mnemonic, "ret");
}

#[test]
fn sanity_test_nm_parser() {
    let sample_output = b"0000000000401000 T _start
0000000000401010 T main
0000000000402000 D global_data
                 U printf
";

    let symbols = parse_nm_output(sample_output);
    assert_eq!(symbols.len(), 4, "Should parse 4 symbols");
    assert_eq!(symbols[0].name, "_start");
    assert_eq!(symbols[0].address, 0x401000);
    assert_eq!(symbols[3].name, "printf");
    assert_eq!(symbols[3].address, 0); // Undefined symbol
}

#[test]
fn sanity_test_strings_parser() {
    let sample_output = b"Hello, World!
This is a test
Another string
";

    let strings = parse_strings_output(sample_output);
    assert_eq!(strings.len(), 3, "Should parse 3 strings");
    assert!(strings.contains("Hello, World!"));
    assert!(strings.contains("This is a test"));
}

#[test]
fn sanity_test_mnemonic_normalization() {
    // These pairs should all normalize to the same value
    let equivalent_pairs = [
        ("push", "pushq"),
        ("mov", "movq"),
        ("ret", "retq"),
        ("je", "jz"),
        ("jne", "jnz"),
        ("nop", "nopl"),
    ];

    for (a, b) in equivalent_pairs {
        assert!(
            mnemonics_equivalent(a, b),
            "{} and {} should be equivalent",
            a,
            b
        );
    }

    // These should NOT be equivalent
    let different_pairs = [("mov", "push"), ("call", "jmp"), ("add", "sub")];

    for (a, b) in different_pairs {
        assert!(
            !mnemonics_equivalent(a, b),
            "{} and {} should NOT be equivalent",
            a,
            b
        );
    }
}

#[test]
fn sanity_test_comparison_functions() {
    // Test instruction comparison
    let hexray_instrs = vec![
        (0x1000u64, "push".to_string()),
        (0x1001, "mov".to_string()),
        (0x1004, "ret".to_string()),
    ];
    let ref_instrs = vec![
        (0x1000u64, "pushq".to_string()),
        (0x1001, "movq".to_string()),
        (0x1004, "retq".to_string()),
    ];

    let disasm_result = compare_instructions(&hexray_instrs, &ref_instrs);
    assert_eq!(disasm_result.matching_instructions, 3);
    assert!(disasm_result.match_rate > 0.99);

    // Test symbol comparison
    let hexray_syms = vec![
        (0x1000u64, "main".to_string()),
        (0x2000, "helper".to_string()),
    ];
    let ref_syms = vec![
        (0x1000u64, "main".to_string()),
        (0x2000, "helper".to_string()),
        (0x3000, "missing".to_string()),
    ];

    let sym_result = compare_symbols(&hexray_syms, &ref_syms);
    assert_eq!(sym_result.matching_symbols, 2);
    assert_eq!(sym_result.reference_only.len(), 1);

    // Test string comparison
    let hexray_strings: std::collections::HashSet<String> =
        ["Hello".to_string(), "World".to_string()].into_iter().collect();
    let ref_strings: std::collections::HashSet<String> =
        ["Hello".to_string(), "World".to_string(), "Extra".to_string()]
            .into_iter()
            .collect();

    let str_result = compare_strings(&hexray_strings, &ref_strings);
    assert_eq!(str_result.matching_strings, 2);
    assert_eq!(str_result.reference_only.len(), 1);
}

#[test]
fn sanity_test_tool_detection() {
    // These functions shouldn't panic even if tools aren't available
    let _objdump = find_objdump();
    let _nm = find_nm();
    let _strings_available = command_available("strings");

    // Print what's available for debugging
    println!("objdump: {:?}", find_objdump());
    println!("nm: {:?}", find_nm());
    println!("strings: {}", command_available("strings"));
}

// =============================================================================
// Benchmark-style tests
// =============================================================================

#[test]
#[ignore]
fn benchmark_disassembly_comparison() {
    let fixtures = [
        "elf/simple_x86_64",
        "test_decompile",
        "test_strings",
        "test_x86_64_macho",
    ];

    println!("\n=== Disassembly Comparison Benchmark ===\n");

    for fixture in fixtures {
        let path = fixture_path(fixture);
        if !Path::new(&path).exists() {
            continue;
        }

        let start = std::time::Instant::now();
        let result = disasm_compare::compare_disassembly_verbose(&path);
        let elapsed = start.elapsed();

        println!(
            "{}: {} instrs in {:?} ({:.1}% match)",
            fixture,
            result.total_instructions,
            elapsed,
            result.match_rate * 100.0
        );
    }
}

#[test]
#[ignore]
fn benchmark_symbol_comparison() {
    let fixtures = [
        "elf/test_with_symbols",
        "test_decompile",
        "test_x86_64_macho",
    ];

    println!("\n=== Symbol Comparison Benchmark ===\n");

    for fixture in fixtures {
        let path = fixture_path(fixture);
        if !Path::new(&path).exists() {
            continue;
        }

        let start = std::time::Instant::now();
        let result = symbols_compare::compare_symbols_verbose(&path);
        let elapsed = start.elapsed();

        println!(
            "{}: {} symbols in {:?} ({:.1}% match)",
            fixture,
            result.total_symbols,
            elapsed,
            result.match_rate * 100.0
        );
    }
}

#[test]
#[ignore]
fn benchmark_string_comparison() {
    let fixtures = ["test_strings", "test_strings2", "test_decompile"];

    println!("\n=== String Comparison Benchmark ===\n");

    for fixture in fixtures {
        let path = fixture_path(fixture);
        if !Path::new(&path).exists() {
            continue;
        }

        let start = std::time::Instant::now();
        let result = strings_compare::compare_strings_verbose(&path, 4);
        let elapsed = start.elapsed();

        println!(
            "{}: {} strings in {:?} ({:.1}% match)",
            fixture,
            result.total_strings,
            elapsed,
            result.match_rate * 100.0
        );
    }
}
