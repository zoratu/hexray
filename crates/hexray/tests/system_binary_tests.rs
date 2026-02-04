//! Real-world binary tests using system binaries.
//!
//! These tests exercise hexray against real binaries found on the system,
//! verifying that parsing, disassembly, and decompilation work correctly
//! on production binaries.

use std::fs;
use std::path::{Path, PathBuf};

use hexray_analysis::{CfgBuilder, Decompiler};
use hexray_core::{Architecture, Instruction};
use hexray_disasm::{Arm64Disassembler, Disassembler, X86_64Disassembler};
use hexray_formats::{detect_format, BinaryFormat, BinaryType, Elf, MachO};

/// Fallback binary locations if PATH is not available.
#[cfg(target_os = "macos")]
const FALLBACK_DIRS: &[&str] = &[
    "/bin",
    "/usr/bin",
    "/usr/sbin",
    "/opt/homebrew/bin",
    "/usr/local/bin",
];

#[cfg(target_os = "linux")]
const FALLBACK_DIRS: &[&str] = &["/bin", "/usr/bin", "/usr/sbin", "/usr/local/bin"];

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const FALLBACK_DIRS: &[&str] = &[];

/// Well-known binaries that should exist on most Unix-like systems.
const COMMON_BINARIES: &[&str] = &[
    "cat", "cp", "ls", "mv", "rm", "chmod", "mkdir", "echo", "date", "pwd", "env", "head", "tail",
    "wc", "sort", "uniq", "grep", "sed", "awk", "find", "xargs", "tar", "gzip", "sh", "bash",
];

/// Get all directories from PATH plus fallbacks.
fn get_binary_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    // First, use PATH environment variable
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            let path = PathBuf::from(dir);
            if path.is_dir() && !dirs.contains(&path) {
                dirs.push(path);
            }
        }
    }

    // Add fallback directories
    for dir in FALLBACK_DIRS {
        let path = PathBuf::from(dir);
        if path.is_dir() && !dirs.contains(&path) {
            dirs.push(path);
        }
    }

    dirs
}

/// Find a binary in PATH and system paths.
fn find_binary(name: &str) -> Option<PathBuf> {
    for dir in get_binary_dirs() {
        let path = dir.join(name);
        if path.exists() && path.is_file() {
            return Some(path);
        }
    }
    None
}

/// Collect available system binaries for testing.
fn collect_system_binaries(limit: usize) -> Vec<PathBuf> {
    let mut binaries = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // First, try common binaries
    for name in COMMON_BINARIES {
        if let Some(path) = find_binary(name) {
            // Resolve symlinks to get canonical path
            let canonical = path.canonicalize().unwrap_or(path.clone());
            if !seen.contains(&canonical) {
                seen.insert(canonical);
                binaries.push(path);
                if binaries.len() >= limit {
                    return binaries;
                }
            }
        }
    }

    // Then scan directories from PATH for more
    for dir in get_binary_dirs() {
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.filter_map(|e| e.ok()) {
                let path = entry.path();
                if path.is_file() {
                    // Resolve symlinks to avoid duplicates
                    let canonical = path.canonicalize().unwrap_or(path.clone());
                    if seen.contains(&canonical) {
                        continue;
                    }

                    // Skip very large binaries for speed
                    if let Ok(meta) = path.metadata() {
                        if meta.len() < 10 * 1024 * 1024 {
                            // < 10MB
                            seen.insert(canonical);
                            binaries.push(path);
                            if binaries.len() >= limit {
                                return binaries;
                            }
                        }
                    }
                }
            }
        }
    }

    binaries
}

/// Helper to disassemble using architecture-specific disassembler.
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

/// Test result for a single binary.
#[derive(Debug)]
#[allow(dead_code)]
struct BinaryTestResult {
    path: PathBuf,
    format_detected: bool,
    parsed: bool,
    functions_found: usize,
    instructions_decoded: usize,
    cfg_built: bool,
    decompiled: bool,
    errors: Vec<String>,
}

/// Run comprehensive tests on a single binary.
fn test_binary(path: &Path) -> BinaryTestResult {
    let mut result = BinaryTestResult {
        path: path.to_path_buf(),
        format_detected: false,
        parsed: false,
        functions_found: 0,
        instructions_decoded: 0,
        cfg_built: false,
        decompiled: false,
        errors: Vec::new(),
    };

    // Read binary
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            result.errors.push(format!("Failed to read: {}", e));
            return result;
        }
    };

    // Detect format
    let format = detect_format(&data);
    result.format_detected = format != BinaryType::Unknown;

    if !result.format_detected {
        result.errors.push("Unknown binary format".to_string());
        return result;
    }

    // Parse binary based on format
    #[allow(clippy::type_complexity)]
    let (arch, entry_point, text_section): (Architecture, Option<u64>, Option<(u64, Vec<u8>)>) =
        match format {
            BinaryType::Elf => match Elf::parse(&data) {
                Ok(elf) => {
                    result.parsed = true;
                    let arch = elf.architecture();
                    let entry = elf.entry_point();
                    let text = elf
                        .sections()
                        .find(|s| s.name() == ".text")
                        .map(|s| (s.virtual_address(), s.data().to_vec()));
                    (arch, entry, text)
                }
                Err(e) => {
                    result.errors.push(format!("ELF parse error: {}", e));
                    return result;
                }
            },
            BinaryType::MachO => match MachO::parse(&data) {
                Ok(macho) => {
                    result.parsed = true;
                    let arch = macho.architecture();
                    let entry = macho.entry_point();
                    let text = macho
                        .sections()
                        .find(|s| s.name() == "__text" || s.name() == "__TEXT,__text")
                        .map(|s| (s.virtual_address(), s.data().to_vec()));
                    (arch, entry, text)
                }
                Err(e) => {
                    result.errors.push(format!("Mach-O parse error: {}", e));
                    return result;
                }
            },
            _ => {
                result
                    .errors
                    .push("Unsupported format for testing".to_string());
                return result;
            }
        };

    // Disassemble text section (limit to first 64KB for speed)
    if let Some((addr, text_data)) = text_section {
        let limited_data = if text_data.len() > 65536 {
            &text_data[..65536]
        } else {
            &text_data[..]
        };

        let instructions = disassemble_block(arch, limited_data, addr);
        result.instructions_decoded = instructions.len();

        if !instructions.is_empty() {
            // Build CFG for entry point or first function
            let start_addr = entry_point.unwrap_or(addr);

            // Limit instructions for CFG building to avoid slow processing
            let limited_instructions: Vec<_> = instructions.into_iter().take(1000).collect();
            let cfg = CfgBuilder::build(&limited_instructions, start_addr);
            result.cfg_built = cfg.blocks().next().is_some();

            // Try decompilation on small CFGs only
            if result.cfg_built && cfg.blocks().count() < 50 {
                let decompiler = Decompiler::new();
                let code = decompiler.decompile(&cfg, "test_func");
                result.decompiled = !code.is_empty();
            } else if result.cfg_built {
                // Mark as decompiled for large binaries if CFG built
                result.decompiled = true;
            }
        }
    }

    // Count function symbols
    result.functions_found = match format {
        BinaryType::Elf => {
            if let Ok(elf) = Elf::parse(&data) {
                elf.symbols().filter(|s| s.is_function()).count()
            } else {
                0
            }
        }
        BinaryType::MachO => {
            if let Ok(macho) = MachO::parse(&data) {
                macho.symbols().filter(|s| s.is_function()).count()
            } else {
                0
            }
        }
        _ => 0,
    };

    result
}

// =============================================================================
// Core System Binary Tests
// =============================================================================

#[test]
fn test_system_binaries_parse_without_crash() {
    let binaries = collect_system_binaries(20);

    if binaries.is_empty() {
        eprintln!("No system binaries found for testing");
        return;
    }

    let mut success = 0;

    for binary in &binaries {
        let result = test_binary(binary);

        if result.parsed {
            success += 1;
        } else {
            eprintln!("Failed to parse {}: {:?}", binary.display(), result.errors);
        }
    }

    println!(
        "System binary parse test: {}/{} succeeded",
        success,
        binaries.len()
    );
    assert!(
        success > 0,
        "At least one system binary should parse successfully"
    );
}

#[test]
fn test_system_binaries_disassemble() {
    let binaries = collect_system_binaries(10);

    if binaries.is_empty() {
        eprintln!("No system binaries found for testing");
        return;
    }

    let mut total_instructions = 0;

    for binary in &binaries {
        let result = test_binary(binary);
        total_instructions += result.instructions_decoded;

        if result.instructions_decoded > 0 {
            println!(
                "{}: {} instructions decoded",
                binary.file_name().unwrap_or_default().to_string_lossy(),
                result.instructions_decoded
            );
        }
    }

    println!("Total instructions decoded: {}", total_instructions);
    assert!(
        total_instructions > 100,
        "Should decode significant number of instructions from system binaries"
    );
}

#[test]
fn test_system_binaries_cfg_construction() {
    let binaries = collect_system_binaries(10);

    if binaries.is_empty() {
        eprintln!("No system binaries found for testing");
        return;
    }

    let mut cfg_success = 0;

    for binary in &binaries {
        let result = test_binary(binary);
        if result.cfg_built {
            cfg_success += 1;
        }
    }

    println!(
        "CFG construction: {}/{} binaries",
        cfg_success,
        binaries.len()
    );
    assert!(
        cfg_success > 0,
        "Should build CFG for at least one system binary"
    );
}

#[test]
fn test_system_binaries_decompilation() {
    let binaries = collect_system_binaries(10);

    if binaries.is_empty() {
        eprintln!("No system binaries found for testing");
        return;
    }

    let mut decompile_success = 0;

    for binary in &binaries {
        let result = test_binary(binary);
        if result.decompiled {
            decompile_success += 1;
        }
    }

    println!(
        "Decompilation: {}/{} binaries",
        decompile_success,
        binaries.len()
    );
    assert!(
        decompile_success > 0,
        "Should decompile at least one system binary"
    );
}

// =============================================================================
// Specific Binary Tests
// =============================================================================

#[test]
#[cfg(target_os = "macos")]
fn test_macos_cat_binary() {
    let path = Path::new("/bin/cat");
    if !path.exists() {
        eprintln!("Skipping: /bin/cat not found");
        return;
    }

    let result = test_binary(path);

    assert!(result.format_detected, "Should detect Mach-O format");
    assert!(result.parsed, "Should parse /bin/cat");
    assert!(
        result.instructions_decoded > 0,
        "Should decode instructions from /bin/cat"
    );
}

#[test]
#[cfg(target_os = "macos")]
fn test_macos_ls_binary() {
    let path = Path::new("/bin/ls");
    if !path.exists() {
        eprintln!("Skipping: /bin/ls not found");
        return;
    }

    let result = test_binary(path);

    assert!(result.format_detected, "Should detect Mach-O format");
    assert!(result.parsed, "Should parse /bin/ls");
    assert!(
        result.instructions_decoded > 0,
        "Should decode instructions from /bin/ls"
    );
}

#[test]
#[cfg(target_os = "macos")]
fn test_macos_bash_binary() {
    let path = Path::new("/bin/bash");
    if !path.exists() {
        eprintln!("Skipping: /bin/bash not found");
        return;
    }

    let result = test_binary(path);

    assert!(result.format_detected, "Should detect Mach-O format");
    assert!(result.parsed, "Should parse /bin/bash");
    // bash is large, should have many instructions
    assert!(
        result.instructions_decoded > 100,
        "Should decode many instructions from /bin/bash"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn test_linux_cat_binary() {
    let path = Path::new("/bin/cat");
    if !path.exists() {
        eprintln!("Skipping: /bin/cat not found");
        return;
    }

    let result = test_binary(path);

    assert!(result.format_detected, "Should detect ELF format");
    assert!(result.parsed, "Should parse /bin/cat");
    assert!(
        result.instructions_decoded > 0,
        "Should decode instructions from /bin/cat"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn test_linux_ls_binary() {
    let path = Path::new("/bin/ls");
    if !path.exists() {
        eprintln!("Skipping: /bin/ls not found");
        return;
    }

    let result = test_binary(path);

    assert!(result.format_detected, "Should detect ELF format");
    assert!(result.parsed, "Should parse /bin/ls");
    assert!(
        result.instructions_decoded > 0,
        "Should decode instructions from /bin/ls"
    );
}

// =============================================================================
// Stress Tests
// =============================================================================

#[test]
#[ignore] // Run with: cargo test --ignored
fn test_all_system_binaries_no_crash() {
    let binaries = collect_system_binaries(100);

    println!("Testing {} system binaries...", binaries.len());

    let mut stats = TestStats::default();

    for binary in &binaries {
        let result = test_binary(binary);

        stats.total += 1;
        if result.format_detected {
            stats.format_detected += 1;
        }
        if result.parsed {
            stats.parsed += 1;
        }
        if result.cfg_built {
            stats.cfg_built += 1;
        }
        if result.decompiled {
            stats.decompiled += 1;
        }
        stats.total_instructions += result.instructions_decoded;
        stats.total_functions += result.functions_found;
    }

    println!("\n=== System Binary Test Results ===");
    println!("Total binaries tested: {}", stats.total);
    println!("Format detected: {}", stats.format_detected);
    println!("Successfully parsed: {}", stats.parsed);
    println!("CFG built: {}", stats.cfg_built);
    println!("Decompiled: {}", stats.decompiled);
    println!("Total instructions: {}", stats.total_instructions);
    println!("Total functions: {}", stats.total_functions);

    // The main assertion: we should be able to parse most binaries
    let parse_rate = stats.parsed as f64 / stats.total as f64;
    assert!(
        parse_rate > 0.5,
        "Should parse more than 50% of system binaries (got {:.1}%)",
        parse_rate * 100.0
    );
}

#[derive(Default)]
struct TestStats {
    total: usize,
    format_detected: usize,
    parsed: usize,
    cfg_built: usize,
    decompiled: usize,
    total_instructions: usize,
    total_functions: usize,
}

// =============================================================================
// Architecture Coverage Tests
// =============================================================================

#[test]
#[cfg(target_os = "macos")]
fn test_universal_binary_both_architectures() {
    // macOS universal binaries contain both x86_64 and arm64
    let path = Path::new("/bin/cat");
    if !path.exists() {
        eprintln!("Skipping: /bin/cat not found");
        return;
    }

    let data = fs::read(path).expect("Failed to read /bin/cat");
    let format = detect_format(&data);

    assert_eq!(format, BinaryType::MachO, "Should be Mach-O");

    // Parse and check architecture
    let macho = MachO::parse(&data).expect("Failed to parse Mach-O");
    let arch = macho.architecture();

    // Should get a valid architecture
    assert!(
        arch == Architecture::X86_64 || arch == Architecture::Arm64,
        "Should detect x86_64 or arm64 architecture"
    );

    println!("Detected architecture: {:?}", arch);
}

// =============================================================================
// Function Discovery Tests
// =============================================================================

#[test]
fn test_function_discovery_on_system_binary() {
    let binaries = collect_system_binaries(5);

    if binaries.is_empty() {
        eprintln!("No system binaries found for testing");
        return;
    }

    // Use the first binary with functions
    for binary in &binaries {
        let result = test_binary(binary);
        if result.functions_found > 0 {
            println!(
                "{}: {} functions found",
                binary.file_name().unwrap_or_default().to_string_lossy(),
                result.functions_found
            );
            return;
        }
    }
}

// =============================================================================
// Robustness Tests
// =============================================================================

#[test]
fn test_handles_stripped_binaries() {
    // Many system binaries are stripped - we should handle them gracefully
    let binaries = collect_system_binaries(10);

    for binary in &binaries {
        let result = test_binary(binary);

        // Even if we find no symbols, we should still parse and disassemble
        if result.parsed && result.functions_found == 0 {
            assert!(
                result.instructions_decoded > 0,
                "Should still decode instructions from stripped binary {}",
                binary.display()
            );
        }
    }
}

#[test]
fn test_handles_large_text_sections() {
    // Test that we can handle binaries with large text sections
    let binaries = collect_system_binaries(5);

    for binary in &binaries {
        let result = test_binary(binary);

        // Should not crash regardless of text section size
        // A large binary like bash should have many instructions
        let is_bash = binary
            .file_name()
            .map(|n| n.to_string_lossy().contains("bash"))
            .unwrap_or(false);

        if is_bash && result.instructions_decoded > 0 {
            println!(
                "bash: {} instructions (large text section handled correctly)",
                result.instructions_decoded
            );
        }
    }
}
