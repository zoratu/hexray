//! Symbol extraction comparison tests.
//!
//! These tests compare hexray's symbol extraction against nm
//! to verify symbol table parsing accuracy.

use super::{
    compare_symbols, fixture_path, parse_nm_output, parse_nm_simple, run_nm,
    run_nm_with_options, SymbolDiffResult, SymbolInfo,
};
use hexray_formats::elf::Elf;
use hexray_formats::macho::MachO;
use hexray_formats::BinaryFormat;
use std::collections::HashSet;
use std::fs;

/// Minimum match rate threshold for symbol tests.
const SYMBOL_MATCH_THRESHOLD: f64 = 0.99;

/// Extract symbols from an ELF binary using hexray.
pub fn extract_elf_symbols_hexray(binary_path: &str) -> Vec<(u64, String)> {
    let data = match fs::read(binary_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to read {}: {}", binary_path, e);
            return Vec::new();
        }
    };

    let elf = match Elf::parse(&data) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Failed to parse ELF {}: {:?}", binary_path, e);
            return Vec::new();
        }
    };

    elf.symbols()
        .filter(|s| !s.name.is_empty() && s.address != 0)
        .map(|s| (s.address, s.name.to_string()))
        .collect()
}

/// Extract symbols from a Mach-O binary using hexray.
pub fn extract_macho_symbols_hexray(binary_path: &str) -> Vec<(u64, String)> {
    let data = match fs::read(binary_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to read {}: {}", binary_path, e);
            return Vec::new();
        }
    };

    let macho = match MachO::parse(&data) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Failed to parse Mach-O {}: {:?}", binary_path, e);
            return Vec::new();
        }
    };

    macho
        .symbols()
        .filter(|s| !s.name.is_empty() && s.address != 0)
        .map(|s| (s.address, s.name.to_string()))
        .collect()
}

/// Extract reference symbols using nm.
pub fn extract_nm_symbols(binary_path: &str) -> Vec<(u64, String)> {
    let output = match run_nm(binary_path) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Failed to run nm on {}: {}", binary_path, e);
            return Vec::new();
        }
    };

    parse_nm_simple(&output)
}

/// Extract reference symbols with detailed info using nm.
pub fn extract_nm_symbols_detailed(binary_path: &str) -> Vec<SymbolInfo> {
    let output = match run_nm(binary_path) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Failed to run nm on {}: {}", binary_path, e);
            return Vec::new();
        }
    };

    parse_nm_output(&output)
}

/// Compare symbol extraction for an ELF binary.
pub fn compare_elf_symbols(binary_path: &str) -> SymbolDiffResult {
    let hexray_symbols = extract_elf_symbols_hexray(binary_path);
    let nm_symbols = extract_nm_symbols(binary_path);

    compare_symbols(&hexray_symbols, &nm_symbols)
}

/// Compare symbol extraction for a Mach-O binary.
pub fn compare_macho_symbols(binary_path: &str) -> SymbolDiffResult {
    let hexray_symbols = extract_macho_symbols_hexray(binary_path);
    let nm_symbols = extract_nm_symbols(binary_path);

    compare_symbols(&hexray_symbols, &nm_symbols)
}

/// Detailed symbol comparison with verbose output.
pub fn compare_symbols_verbose(binary_path: &str) -> SymbolDiffResult {
    println!("\n=== Symbol Comparison: {} ===", binary_path);

    // Get hexray symbols
    let hexray_symbols = if binary_path.contains("macho") {
        extract_macho_symbols_hexray(binary_path)
    } else {
        extract_elf_symbols_hexray(binary_path)
    };

    // Get nm symbols
    let nm_symbols = extract_nm_symbols(binary_path);

    println!("Hexray found {} symbols", hexray_symbols.len());
    println!("nm found {} symbols", nm_symbols.len());

    let result = compare_symbols(&hexray_symbols, &nm_symbols);
    println!("{}", result.summary());

    result
}

/// Compare function symbols only.
pub fn compare_function_symbols(binary_path: &str) -> SymbolDiffResult {
    let hexray_symbols: Vec<(u64, String)> = {
        let data = match fs::read(binary_path) {
            Ok(d) => d,
            Err(_) => return SymbolDiffResult::new(),
        };

        if let Ok(elf) = Elf::parse(&data) {
            elf.symbols()
                .filter(|s| s.is_function() && !s.name.is_empty() && s.address != 0)
                .map(|s| (s.address, s.name.to_string()))
                .collect()
        } else if let Ok(macho) = MachO::parse(&data) {
            macho
                .symbols()
                .filter(|s| s.is_function() && !s.name.is_empty() && s.address != 0)
                .map(|s| (s.address, s.name.to_string()))
                .collect()
        } else {
            return SymbolDiffResult::new();
        }
    };

    // Get function symbols from nm (type T, t, W, w)
    let nm_output = match run_nm(binary_path) {
        Ok(o) => o,
        Err(_) => return SymbolDiffResult::new(),
    };

    let nm_symbols: Vec<(u64, String)> = parse_nm_output(&nm_output)
        .into_iter()
        .filter(|s| {
            matches!(
                s.symbol_type,
                Some('T') | Some('t') | Some('W') | Some('w')
            )
        })
        .filter(|s| s.address != 0)
        .map(|s| (s.address, s.name))
        .collect();

    compare_symbols(&hexray_symbols, &nm_symbols)
}

/// Compare global symbols only.
pub fn compare_global_symbols(binary_path: &str) -> SymbolDiffResult {
    let hexray_symbols: Vec<(u64, String)> = {
        let data = match fs::read(binary_path) {
            Ok(d) => d,
            Err(_) => return SymbolDiffResult::new(),
        };

        if let Ok(elf) = Elf::parse(&data) {
            elf.symbols()
                .filter(|s| s.is_global() && !s.name.is_empty() && s.address != 0)
                .map(|s| (s.address, s.name.to_string()))
                .collect()
        } else if let Ok(macho) = MachO::parse(&data) {
            macho
                .symbols()
                .filter(|s| s.is_global() && !s.name.is_empty() && s.address != 0)
                .map(|s| (s.address, s.name.to_string()))
                .collect()
        } else {
            return SymbolDiffResult::new();
        }
    };

    // Get global symbols from nm (uppercase type letters)
    let nm_output = match run_nm(binary_path) {
        Ok(o) => o,
        Err(_) => return SymbolDiffResult::new(),
    };

    let nm_symbols: Vec<(u64, String)> = parse_nm_output(&nm_output)
        .into_iter()
        .filter(|s| s.symbol_type.map(|c| c.is_uppercase()).unwrap_or(false))
        .filter(|s| s.address != 0)
        .map(|s| (s.address, s.name))
        .collect();

    compare_symbols(&hexray_symbols, &nm_symbols)
}

/// Compare symbol names only (ignoring addresses).
pub fn compare_symbol_names(binary_path: &str) -> (usize, usize, f64) {
    let hexray_names: HashSet<String> = {
        let data = match fs::read(binary_path) {
            Ok(d) => d,
            Err(_) => return (0, 0, 0.0),
        };

        if let Ok(elf) = Elf::parse(&data) {
            elf.symbols()
                .filter(|s| !s.name.is_empty())
                .map(|s| s.name.to_string())
                .collect()
        } else if let Ok(macho) = MachO::parse(&data) {
            macho
                .symbols()
                .filter(|s| !s.name.is_empty())
                .map(|s| s.name.to_string())
                .collect()
        } else {
            return (0, 0, 0.0);
        }
    };

    let nm_output = match run_nm(binary_path) {
        Ok(o) => o,
        Err(_) => return (0, 0, 0.0),
    };

    let nm_names: HashSet<String> = parse_nm_output(&nm_output)
        .into_iter()
        .map(|s| s.name)
        .collect();

    let matching = hexray_names.intersection(&nm_names).count();
    let total = nm_names.len();
    let rate = if total > 0 {
        matching as f64 / total as f64
    } else {
        1.0
    };

    (matching, total, rate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::differential::{check_prerequisites, find_nm, fixture_exists};

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
    #[ignore] // Requires nm and test fixtures
    fn test_symbols_elf_with_symbols() {
        skip_if_missing!("elf/test_with_symbols", "nm");

        let path = fixture_path("elf/test_with_symbols");
        let result = compare_elf_symbols(&path);

        println!("{}", result.summary());

        assert!(result.total_symbols > 0, "No symbols found in binary");
        assert!(
            result.meets_threshold(SYMBOL_MATCH_THRESHOLD),
            "Match rate {:.2}% below threshold {:.2}%",
            result.match_rate * 100.0,
            SYMBOL_MATCH_THRESHOLD * 100.0
        );
    }

    #[test]
    #[ignore] // Requires nm and test fixtures
    fn test_symbols_elf_simple() {
        skip_if_missing!("elf/simple_x86_64", "nm");

        let path = fixture_path("elf/simple_x86_64");
        let result = compare_elf_symbols(&path);

        println!("{}", result.summary());

        // Simple binaries might have few symbols
        if result.total_symbols > 0 {
            assert!(
                result.meets_threshold(SYMBOL_MATCH_THRESHOLD),
                "Match rate {:.2}% below threshold {:.2}%",
                result.match_rate * 100.0,
                SYMBOL_MATCH_THRESHOLD * 100.0
            );
        }
    }

    #[test]
    #[ignore] // Requires nm and test fixtures
    fn test_symbols_macho_x86_64() {
        skip_if_missing!("test_x86_64_macho", "nm");

        let path = fixture_path("test_x86_64_macho");
        let result = compare_macho_symbols(&path);

        println!("{}", result.summary());

        assert!(result.total_symbols > 0, "No symbols found in binary");
        // Allow lower threshold for Mach-O due to potential differences
        assert!(
            result.meets_threshold(0.95),
            "Match rate {:.2}% below threshold 95%",
            result.match_rate * 100.0
        );
    }

    #[test]
    #[ignore] // Requires nm and test fixtures
    fn test_symbols_test_decompile() {
        skip_if_missing!("test_decompile", "nm");

        let path = fixture_path("test_decompile");
        let result = compare_symbols_verbose(&path);

        assert!(result.total_symbols > 0, "No symbols found in binary");
        assert!(
            result.meets_threshold(0.95),
            "Match rate {:.2}% below threshold 95%",
            result.match_rate * 100.0
        );
    }

    #[test]
    #[ignore] // Requires nm and test fixtures
    fn test_function_symbols_only() {
        skip_if_missing!("test_decompile", "nm");

        let path = fixture_path("test_decompile");
        let result = compare_function_symbols(&path);

        println!("\nFunction symbols comparison:");
        println!("{}", result.summary());

        if result.total_symbols > 0 {
            assert!(
                result.meets_threshold(0.90),
                "Function symbol match rate {:.2}% below threshold 90%",
                result.match_rate * 100.0
            );
        }
    }

    #[test]
    #[ignore] // Requires nm and test fixtures
    fn test_global_symbols_only() {
        skip_if_missing!("test_decompile", "nm");

        let path = fixture_path("test_decompile");
        let result = compare_global_symbols(&path);

        println!("\nGlobal symbols comparison:");
        println!("{}", result.summary());

        if result.total_symbols > 0 {
            assert!(
                result.meets_threshold(0.90),
                "Global symbol match rate {:.2}% below threshold 90%",
                result.match_rate * 100.0
            );
        }
    }

    #[test]
    #[ignore] // Requires nm and test fixtures
    fn test_symbol_names_coverage() {
        skip_if_missing!("test_decompile", "nm");

        let path = fixture_path("test_decompile");
        let (matching, total, rate) = compare_symbol_names(&path);

        println!(
            "\nSymbol name coverage: {}/{} ({:.2}%)",
            matching,
            total,
            rate * 100.0
        );

        assert!(total > 0, "No symbols found");
        assert!(
            rate >= 0.95,
            "Symbol name coverage {:.2}% below threshold 95%",
            rate * 100.0
        );
    }

    #[test]
    #[ignore]
    fn test_symbols_all_fixtures() {
        // Run symbol comparison on all available fixtures
        let fixtures = [
            "elf/test_with_symbols",
            "test_x86_64_macho",
            "test_decompile",
            "test_strings",
        ];

        if find_nm().is_none() {
            eprintln!("Skipping test: nm not available");
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
            let result = compare_symbols_verbose(&path);

            if result.total_symbols > 0 && result.meets_threshold(0.90) {
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
    fn test_nm_output_parsing() {
        // Test that nm output parsing handles various formats
        let test_output = b"0000000000401000 T main
0000000000401050 T helper
0000000000402000 D global_var
                 U external_func
0000000000401100 t local_func
";
        let symbols = parse_nm_output(test_output);

        assert_eq!(symbols.len(), 5);

        // Check main
        assert_eq!(symbols[0].name, "main");
        assert_eq!(symbols[0].address, 0x401000);
        assert_eq!(symbols[0].symbol_type, Some('T'));

        // Check undefined symbol
        assert_eq!(symbols[3].name, "external_func");
        assert_eq!(symbols[3].address, 0);
        assert_eq!(symbols[3].symbol_type, Some('U'));
    }

    #[test]
    fn test_symbol_type_filtering() {
        let test_output = b"0000000000401000 T text_func
0000000000402000 D data_obj
0000000000403000 B bss_obj
0000000000401100 t local_func
                 U undefined
";
        let symbols = parse_nm_output(test_output);

        // Filter for function symbols (T, t, W, w)
        let functions: Vec<_> = symbols
            .iter()
            .filter(|s| {
                matches!(
                    s.symbol_type,
                    Some('T') | Some('t') | Some('W') | Some('w')
                )
            })
            .collect();

        assert_eq!(functions.len(), 2);
        assert!(functions.iter().any(|s| s.name == "text_func"));
        assert!(functions.iter().any(|s| s.name == "local_func"));

        // Filter for global symbols (uppercase)
        let globals: Vec<_> = symbols
            .iter()
            .filter(|s| s.symbol_type.map(|c| c.is_uppercase()).unwrap_or(false))
            .collect();

        assert_eq!(globals.len(), 4); // T, D, B, U
    }
}
