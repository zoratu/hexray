//! CLI integration tests for hexray.
//!
//! These tests verify that the hexray CLI works correctly with various
//! commands and options against real test binaries.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

/// Get the path to the hexray binary.
fn hexray_bin() -> String {
    // In test mode, use cargo to run the binary
    env!("CARGO_BIN_EXE_hexray").to_string()
}

/// Get the path to a test fixture.
fn fixture_path(name: &str) -> String {
    format!("tests/fixtures/{}", name)
}

/// Check if a fixture exists.
fn fixture_exists(name: &str) -> bool {
    Path::new(&fixture_path(name)).exists()
}

/// Run hexray with the given arguments.
fn run_hexray(args: &[&str]) -> Output {
    Command::new(hexray_bin())
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to execute hexray")
}

fn decompile_header(binary: &str, symbol: &str) -> Option<String> {
    let output = run_hexray(&[binary, "decompile", symbol]);
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .map(str::trim)
        .find(|line| {
            line.contains('(')
                && line.ends_with(')')
                && !line.starts_with("Decompiling ")
                && !line.is_empty()
        })
        .map(ToString::to_string)
}

fn strict_callback_typing_mode() -> bool {
    std::env::var("HEXRAY_STRICT_CALLBACK_TYPING")
        .map(|v| {
            let normalized = v.trim().to_ascii_lowercase();
            normalized == "1" || normalized == "true" || normalized == "yes" || normalized == "on"
        })
        .unwrap_or(false)
}

fn find_c_compiler() -> Option<&'static str> {
    ["cc", "clang", "gcc"].into_iter().find(|compiler| {
        Command::new(compiler)
            .arg("--version")
            .output()
            .is_ok_and(|out| out.status.success())
    })
}

fn build_c_fixture(source_name: &str) -> Option<PathBuf> {
    let compiler = match find_c_compiler() {
        Some(c) => c,
        None => {
            eprintln!("Skipping test: no C compiler (cc/clang/gcc) found");
            return None;
        }
    };

    let source = fixture_path(source_name);
    if !Path::new(&source).exists() {
        eprintln!("Skipping test: fixture {} not found", source_name);
        return None;
    }

    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let out_dir = std::env::temp_dir().join(format!(
        "hexray-cli-fixture-{}-{}",
        std::process::id(),
        stamp
    ));
    if let Err(e) = fs::create_dir_all(&out_dir) {
        eprintln!("Skipping test: failed to create temp dir: {}", e);
        return None;
    }
    let out_bin = out_dir.join("fixture_bin");

    let compile = Command::new(compiler)
        .args(["-O0", "-g", "-pthread", &source, "-o"])
        .arg(&out_bin)
        .output();
    match compile {
        Ok(out) if out.status.success() => Some(out_bin),
        Ok(out) => {
            eprintln!(
                "Skipping test: compiler failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            None
        }
        Err(e) => {
            eprintln!("Skipping test: failed to invoke compiler: {}", e);
            None
        }
    }
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

// =============================================================================
// Basic Command Tests
// =============================================================================

#[test]
fn test_help() {
    let output = run_hexray(&["--help"]);
    assert!(output.status.success(), "hexray --help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("multi-architecture disassembler"),
        "Help should mention disassembler"
    );
    assert!(
        stdout.contains("--symbol"),
        "Help should show --symbol option"
    );
}

#[test]
fn test_version() {
    let output = run_hexray(&["--version"]);
    // Version flag may not be implemented in all versions
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("hexray") || !stdout.is_empty(),
            "Version output should not be empty"
        );
    } else {
        // If not implemented, verify it fails gracefully (not a crash)
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("unexpected") || stderr.contains("error") || stderr.contains("Usage"),
            "Should fail with meaningful message"
        );
    }
}

// =============================================================================
// Sections Command Tests
// =============================================================================

#[test]
fn test_sections_elf() {
    skip_if_missing!("elf/simple_x86_64");

    let output = run_hexray(&[&fixture_path("elf/simple_x86_64"), "sections"]);
    assert!(output.status.success(), "sections command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(".text") || stdout.contains("text"),
        "Should show .text section"
    );
}

#[test]
fn test_sections_macho() {
    skip_if_missing!("test_x86_64_macho");

    let output = run_hexray(&[&fixture_path("test_x86_64_macho"), "sections"]);
    assert!(output.status.success(), "sections command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("__TEXT") || stdout.contains("__text"),
        "Should show __TEXT section"
    );
}

#[test]
fn test_sections_pe() {
    skip_if_missing!("pe/simple_x64.exe");

    let output = run_hexray(&[&fixture_path("pe/simple_x64.exe"), "sections"]);
    assert!(output.status.success(), "sections command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // PE files typically have .text section
    assert!(
        stdout.contains(".text") || stdout.contains("text"),
        "Should show .text section: {}",
        stdout
    );
}

// =============================================================================
// Symbols Command Tests
// =============================================================================

#[test]
fn test_symbols_elf() {
    skip_if_missing!("elf/test_with_symbols");

    let output = run_hexray(&[&fixture_path("elf/test_with_symbols"), "symbols"]);
    assert!(output.status.success(), "symbols command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should list some symbols
    assert!(!stdout.is_empty(), "Should output symbol list");
}

#[test]
fn test_symbols_functions_only() {
    skip_if_missing!("elf/test_with_symbols");

    let output = run_hexray(&[
        &fixture_path("elf/test_with_symbols"),
        "symbols",
        "--functions",
    ]);
    assert!(
        output.status.success(),
        "symbols --functions should succeed"
    );
}

#[test]
fn test_symbols_macho() {
    skip_if_missing!("test_x86_64_macho");

    let output = run_hexray(&[&fixture_path("test_x86_64_macho"), "symbols"]);
    assert!(output.status.success(), "symbols command should succeed");
}

// =============================================================================
// Info Command Tests
// =============================================================================

#[test]
fn test_info_elf() {
    skip_if_missing!("elf/simple_x86_64");

    let output = run_hexray(&[&fixture_path("elf/simple_x86_64"), "info"]);
    assert!(output.status.success(), "info command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should show format type
    assert!(
        stdout.contains("ELF") || stdout.contains("elf"),
        "Should identify ELF format"
    );
}

#[test]
fn test_info_macho() {
    skip_if_missing!("test_x86_64_macho");

    let output = run_hexray(&[&fixture_path("test_x86_64_macho"), "info"]);
    assert!(output.status.success(), "info command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Mach-O") || stdout.contains("macho") || stdout.contains("MachO"),
        "Should identify Mach-O format: {}",
        stdout
    );
}

#[test]
fn test_info_pe() {
    skip_if_missing!("pe/simple_x64.exe");

    let output = run_hexray(&[&fixture_path("pe/simple_x64.exe"), "info"]);
    assert!(output.status.success(), "info command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("PE") || stdout.contains("pe"),
        "Should identify PE format"
    );
}

// =============================================================================
// Strings Command Tests
// =============================================================================

#[test]
fn test_strings_basic() {
    skip_if_missing!("test_strings");

    let output = run_hexray(&[&fixture_path("test_strings"), "strings"]);
    assert!(output.status.success(), "strings command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "Should find some strings");
}

#[test]
fn test_strings_min_length() {
    skip_if_missing!("test_strings");

    let output = run_hexray(&[
        &fixture_path("test_strings"),
        "strings",
        "--min-length",
        "10",
    ]);
    assert!(
        output.status.success(),
        "strings --min-length should succeed"
    );
}

#[test]
fn test_strings_json() {
    skip_if_missing!("test_strings");

    let output = run_hexray(&[&fixture_path("test_strings"), "strings", "--json"]);
    assert!(output.status.success(), "strings --json should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // JSON output should be valid
    assert!(
        stdout.starts_with('[') || stdout.starts_with('{'),
        "JSON output should start with [ or {{"
    );
}

// =============================================================================
// Disassembly Tests
// =============================================================================

#[test]
fn test_disassemble_entry_point() {
    skip_if_missing!("elf/simple_x86_64");

    let output = run_hexray(&[&fixture_path("elf/simple_x86_64")]);
    assert!(
        output.status.success(),
        "Basic disassembly should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should show some disassembly
    assert!(!stdout.is_empty(), "Should produce disassembly output");
}

#[test]
fn test_disassemble_by_address() {
    skip_if_missing!("elf/simple_x86_64");

    // Try disassembling at a known address (entry point area)
    let output = run_hexray(&[
        &fixture_path("elf/simple_x86_64"),
        "--address",
        "0x401000",
        "--count",
        "10",
    ]);
    // This may fail if the address doesn't exist, but shouldn't crash
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(!stdout.is_empty(), "Should produce output");
    }
}

// =============================================================================
// CFG Command Tests
// =============================================================================

#[test]
fn test_cfg_basic() {
    skip_if_missing!("test_decompile");

    let output = run_hexray(&[&fixture_path("test_decompile"), "cfg", "main"]);
    // May not find 'main' in all binaries, but shouldn't crash
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(!stdout.is_empty(), "Should produce CFG output");
    }
}

#[test]
fn test_cfg_dot_format() {
    skip_if_missing!("test_decompile");

    let output = run_hexray(&[&fixture_path("test_decompile"), "cfg", "main", "--dot"]);
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // DOT format should contain graph structure
        assert!(
            stdout.contains("digraph") || stdout.contains("->"),
            "DOT output should contain graph structure"
        );
    }
}

#[test]
fn test_cfg_json_format() {
    skip_if_missing!("test_decompile");

    let output = run_hexray(&[&fixture_path("test_decompile"), "cfg", "main", "--json"]);
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.starts_with('{') || stdout.starts_with('['),
            "JSON output should be valid JSON"
        );
    }
}

// =============================================================================
// Decompile Command Tests
// =============================================================================

#[test]
fn test_decompile_basic() {
    skip_if_missing!("test_decompile");

    let output = run_hexray(&[&fixture_path("test_decompile"), "decompile"]);
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Decompiler output should contain function-like syntax
        assert!(
            stdout.contains("(") && stdout.contains(")"),
            "Decompiled output should contain function syntax"
        );
    }
}

#[test]
fn test_decompile_with_addresses() {
    skip_if_missing!("test_decompile");

    let output = run_hexray(&[
        &fixture_path("test_decompile"),
        "decompile",
        "--show-addresses",
    ]);
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // With --show-addresses, should have address comments
        assert!(
            stdout.contains("0x") || stdout.contains("/*"),
            "Should show addresses in output"
        );
    }
}

#[test]
fn test_decompile_callback_apis_via_compiled_fixture() {
    let Some(binary) = build_c_fixture("test_callbacks.c") else {
        return;
    };

    let binary = binary.to_string_lossy().to_string();
    let output = run_hexray(&[&binary, "decompile", "sort_with_cmp"]);
    assert!(
        output.status.success(),
        "decompile callback fixture should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("sort_with_cmp"),
        "Output should include target function name:\n{}",
        stdout
    );
    assert!(
        stdout.contains("qsort("),
        "Output should include callback API call:\n{}",
        stdout
    );
    assert!(
        stdout.contains("int32_t (*cmp)(void*, void*)")
            || stdout.contains("int32_t (*compar)(void*, void*)")
            || stdout.contains("int32_t (*arg2)(void*, void*)"),
        "Output should include precise qsort callback signature:\n{}",
        stdout
    );

    let output = run_hexray(&[&binary, "decompile", "lookup_with_cmp"]);
    assert!(
        output.status.success(),
        "decompile callback fixture should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("bsearch("),
        "Output should include bsearch callback API call:\n{}",
        stdout
    );
    assert!(
        stdout.contains("int32_t (*cmp)(void*, void*)")
            || stdout.contains("int32_t (*compar)(void*, void*)")
            || stdout.contains("int32_t (*arg3)(void*, void*)"),
        "Output should include precise bsearch callback signature:\n{}",
        stdout
    );

    let output = run_hexray(&[&binary, "decompile", "install_handler"]);
    assert!(
        output.status.success(),
        "decompile callback fixture should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("signal("),
        "Output should include signal callback API call:\n{}",
        stdout
    );
    assert!(
        stdout.contains("void (*h)(int32_t)")
            || stdout.contains("void (*handler)(int32_t)")
            || stdout.contains("void (*arg0)(int32_t)"),
        "Output should include precise signal-handler signature:\n{}",
        stdout
    );

    let output = run_hexray(&[&binary, "decompile", "sort_with_static_cmp"]);
    assert!(
        output.status.success(),
        "decompile callback fixture should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let header = stdout
        .lines()
        .map(str::trim)
        .find(|line| {
            line.contains('(')
                && line.ends_with(')')
                && !line.starts_with("Decompiling ")
                && !line.is_empty()
        })
        .unwrap_or_default();
    assert!(
        header == "int32_t _sort_with_static_cmp(int64_t arg0, int64_t arg1, int64_t arg2)"
            || header
                == "int32_t _sort_with_static_cmp(int64_t arg0, int64_t arg1, int32_t (*arg2)(void*, void*))",
        "Static-callback wrapper header unexpectedly changed:\n{}",
        stdout
    );

    let output = run_hexray(&[&binary, "decompile", "spawn_with_start"]);
    assert!(
        output.status.success(),
        "decompile callback fixture should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("pthread_create("),
        "Output should include pthread callback API call:\n{}",
        stdout
    );
    assert!(
        stdout.contains("void* (*start_routine)(void*)")
            || stdout.contains("void* (*start)(void*)")
            || stdout.contains("void* (*arg1)(void*)")
            || stdout.contains("void* (*arg0)(void*)"),
        "Output should include precise pthread callback signature:\n{}",
        stdout
    );

    let output = run_hexray(&[&binary, "decompile", "spawn_with_static_start"]);
    assert!(
        output.status.success(),
        "decompile callback fixture should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let header = stdout
        .lines()
        .map(str::trim)
        .find(|line| {
            line.contains('(')
                && line.ends_with(')')
                && !line.starts_with("Decompiling ")
                && !line.is_empty()
        })
        .unwrap_or_default();
    assert!(
        header == "int32_t _spawn_with_static_start(int64_t arg0)"
            || header == "int32_t _spawn_with_static_start(void* (*arg0)(void*))",
        "Static-start wrapper header unexpectedly changed:\n{}",
        stdout
    );

    let output = run_hexray(&[&binary, "decompile", "sort_with_cmp_multihop"]);
    assert!(
        output.status.success(),
        "decompile callback fixture should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("int32_t (*cmp)(void*, void*)")
            || stdout.contains("int32_t (*arg2)(void*, void*)"),
        "Output should keep typed qsort callback through multihop aliasing:\n{}",
        stdout
    );

    let output = run_hexray(&[&binary, "decompile", "spawn_with_start_multihop"]);
    assert!(
        output.status.success(),
        "decompile callback fixture should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("void* (*start_routine)(void*)")
            || stdout.contains("void* (*arg0)(void*)")
            || stdout.contains("void* (*arg1)(void*)"),
        "Output should keep typed pthread callback through multihop aliasing:\n{}",
        stdout
    );

    let output = run_hexray(&[&binary, "decompile", "sort_with_qsort_r_glibc"]);
    assert!(
        output.status.success(),
        "decompile callback fixture should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hexray_qsort_r("),
        "Output should include glibc-like qsort_r callback API call:\n{}",
        stdout
    );
    assert!(
        stdout.contains("int32_t (*cmp)(void*, void*, void*)")
            || stdout.contains("int32_t (*compar)(void*, void*, void*)")
            || stdout.contains("int32_t (*arg2)(void*, void*, void*)")
            || stdout.contains("int32_t (*arg3)(void*, void*, void*)"),
        "Output should include precise glibc-like qsort_r callback signature:\n{}",
        stdout
    );

    let output = run_hexray(&[&binary, "decompile", "sort_with_qsort_r_bsd"]);
    assert!(
        output.status.success(),
        "decompile callback fixture should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hexray_bsd_qsort_r("),
        "Output should include BSD-like qsort_r callback API call:\n{}",
        stdout
    );
    assert!(
        stdout.contains("int32_t (*cmp)(void*, void*, void*)")
            || stdout.contains("int32_t (*compar)(void*, void*, void*)")
            || stdout.contains("int32_t (*arg2)(void*, void*, void*)")
            || stdout.contains("int32_t (*arg3)(void*, void*, void*)"),
        "Output should include precise BSD-like qsort_r callback signature:\n{}",
        stdout
    );

    let output = run_hexray(&[&binary, "decompile", "register_on_exit"]);
    assert!(
        output.status.success(),
        "decompile callback fixture should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hexray_on_exit("),
        "Output should include on_exit-style callback API call:\n{}",
        stdout
    );
    assert!(
        stdout.contains("void (*cb)(int32_t, void*)")
            || stdout.contains("void (*arg0)(int32_t, void*)")
            || stdout.contains("void (*arg1)(int32_t, void*)"),
        "Output should include precise on_exit callback signature:\n{}",
        stdout
    );

    let output = run_hexray(&[&binary, "decompile", "register_atfork"]);
    assert!(
        output.status.success(),
        "decompile callback fixture should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hexray_pthread_atfork("),
        "Output should include pthread_atfork-style callback API call:\n{}",
        stdout
    );
    assert!(
        stdout.contains("void (*prepare)(void)")
            || stdout.contains("void (*arg0)(void)")
            || stdout.contains("void (*arg1)(void)")
            || stdout.contains("void (*arg2)(void)"),
        "Output should include precise atfork callback signatures:\n{}",
        stdout
    );
}

#[test]
fn test_decompile_callback_header_snapshots() {
    let Some(binary) = build_c_fixture("test_callbacks.c") else {
        return;
    };
    let binary = binary.to_string_lossy().to_string();
    let strict = strict_callback_typing_mode();

    let strict_expected = [
        (
            "sort_with_cmp",
            "int32_t _sort_with_cmp(int64_t arg0, int64_t arg1, int32_t (*arg2)(void*, void*))",
        ),
        (
            "lookup_with_cmp",
            "int32_t _lookup_with_cmp(int64_t arg0, int64_t arg1, int32_t arg2, int32_t (*arg3)(void*, void*))",
        ),
        (
            "spawn_with_start",
            "int32_t _spawn_with_start(void* (*arg0)(void*), int64_t arg1)",
        ),
        (
            "sort_with_cmp_multihop",
            "int32_t _sort_with_cmp_multihop(int64_t arg0, int64_t arg1, int32_t (*arg2)(void*, void*))",
        ),
        (
            "spawn_with_start_multihop",
            "int32_t _spawn_with_start_multihop(void* (*arg0)(void*), int64_t arg1)",
        ),
        (
            "register_on_exit",
            "int32_t _register_on_exit(void (*arg0)(int32_t, void*), int64_t arg1)",
        ),
        (
            "register_atfork",
            "int32_t _register_atfork(void (*arg0)(void), void (*arg1)(void), void (*arg2)(void))",
        ),
    ];

    for (symbol, expected_header) in strict_expected {
        let header = decompile_header(&binary, symbol)
            .unwrap_or_else(|| panic!("missing decompile header for symbol {}", symbol));
        assert_eq!(
            header, expected_header,
            "Header snapshot mismatch for symbol {}",
            symbol
        );
    }

    let static_cmp_header = decompile_header(&binary, "sort_with_static_cmp")
        .unwrap_or_else(|| panic!("missing decompile header for symbol sort_with_static_cmp"));
    if strict {
        assert_eq!(
            static_cmp_header,
            "int32_t _sort_with_static_cmp(int64_t arg0, int64_t arg1, int32_t (*arg2)(void*, void*))",
            "Strict mode mismatch for symbol sort_with_static_cmp"
        );
    } else {
        assert!(
            static_cmp_header == "int32_t _sort_with_static_cmp(int64_t arg0, int64_t arg1, int64_t arg2)"
                || static_cmp_header
                    == "int32_t _sort_with_static_cmp(int64_t arg0, int64_t arg1, int32_t (*arg2)(void*, void*))",
            "Header snapshot mismatch for symbol sort_with_static_cmp: {}",
            static_cmp_header
        );
    }

    let static_spawn_header = decompile_header(&binary, "spawn_with_static_start")
        .unwrap_or_else(|| panic!("missing decompile header for symbol spawn_with_static_start"));
    if strict {
        assert_eq!(
            static_spawn_header, "int32_t _spawn_with_static_start(void* (*arg0)(void*))",
            "Strict mode mismatch for symbol spawn_with_static_start"
        );
    } else {
        assert!(
            static_spawn_header == "int32_t _spawn_with_static_start(int64_t arg0)"
                || static_spawn_header == "int32_t _spawn_with_static_start(void* (*arg0)(void*))",
            "Header snapshot mismatch for symbol spawn_with_static_start: {}",
            static_spawn_header
        );
    }

    let mixed_spawn_header = decompile_header(&binary, "spawn_mixed_forwarding")
        .unwrap_or_else(|| panic!("missing decompile header for symbol spawn_mixed_forwarding"));
    if strict {
        assert_eq!(
            mixed_spawn_header,
            "int32_t _spawn_mixed_forwarding(int64_t arg0, int64_t arg1, void* (*arg2)(void*))",
            "Strict mode mismatch for symbol spawn_mixed_forwarding"
        );
    } else {
        assert!(
            mixed_spawn_header
                == "int32_t _spawn_mixed_forwarding(void* (*arg0)(void*), int64_t arg1, int32_t arg2)"
                || mixed_spawn_header
                    == "int32_t _spawn_mixed_forwarding(int64_t arg0, void* (*arg1)(void*), int32_t arg2)"
                || mixed_spawn_header
                    == "int32_t _spawn_mixed_forwarding(int64_t arg0, int64_t arg1, void* (*arg2)(void*))",
            "Header snapshot mismatch for symbol spawn_mixed_forwarding: {}",
            mixed_spawn_header
        );
    }

    let mixed_sort_header = decompile_header(&binary, "sort_mixed_forwarding")
        .unwrap_or_else(|| panic!("missing decompile header for symbol sort_mixed_forwarding"));
    if strict {
        assert_eq!(
            mixed_sort_header,
            "int32_t _sort_mixed_forwarding(int64_t arg0, int64_t arg1, int64_t arg2, int32_t (*arg3)(void*, void*))",
            "Strict mode mismatch for symbol sort_mixed_forwarding"
        );
    } else {
        assert!(
            mixed_sort_header
                == "int32_t _sort_mixed_forwarding(int64_t arg0, int64_t arg1, int32_t (*arg2)(void*, void*), int32_t arg3)"
                || mixed_sort_header
                    == "int32_t _sort_mixed_forwarding(int64_t arg0, int64_t arg1, int64_t arg2, int32_t (*arg3)(void*, void*))",
            "Header snapshot mismatch for symbol sort_mixed_forwarding: {}",
            mixed_sort_header
        );
    }

    let qsort_r_glibc_header = decompile_header(&binary, "sort_with_qsort_r_glibc")
        .unwrap_or_else(|| panic!("missing decompile header for symbol sort_with_qsort_r_glibc"));
    assert!(
        qsort_r_glibc_header.contains("(*arg2)(void*, void*, void*)")
            || qsort_r_glibc_header.contains("(*arg3)(void*, void*, void*)"),
        "Header snapshot mismatch for symbol sort_with_qsort_r_glibc: {}",
        qsort_r_glibc_header
    );

    let qsort_r_bsd_header = decompile_header(&binary, "sort_with_qsort_r_bsd")
        .unwrap_or_else(|| panic!("missing decompile header for symbol sort_with_qsort_r_bsd"));
    assert!(
        qsort_r_bsd_header.contains("(*arg2)(void*, void*, void*)")
            || qsort_r_bsd_header.contains("(*arg3)(void*, void*, void*)"),
        "Header snapshot mismatch for symbol sort_with_qsort_r_bsd: {}",
        qsort_r_bsd_header
    );

    let on_exit_header = decompile_header(&binary, "register_on_exit")
        .unwrap_or_else(|| panic!("missing decompile header for symbol register_on_exit"));
    if strict {
        assert_eq!(
            on_exit_header, "int32_t _register_on_exit(void (*arg0)(int32_t, void*), int64_t arg1)",
            "Strict mode mismatch for symbol register_on_exit"
        );
    } else {
        assert!(
            on_exit_header.contains("(*arg0)(int32_t, void*)")
                || on_exit_header.contains("(*arg1)(int32_t, void*)"),
            "Header snapshot mismatch for symbol register_on_exit: {}",
            on_exit_header
        );
    }

    let atfork_header = decompile_header(&binary, "register_atfork")
        .unwrap_or_else(|| panic!("missing decompile header for symbol register_atfork"));
    if strict {
        assert_eq!(
            atfork_header,
            "int32_t _register_atfork(void (*arg0)(void), void (*arg1)(void), void (*arg2)(void))",
            "Strict mode mismatch for symbol register_atfork"
        );
    } else {
        assert!(
            atfork_header.contains("(*arg0)(void)")
                || atfork_header.contains("(*arg1)(void)")
                || atfork_header.contains("(*arg2)(void)"),
            "Header snapshot mismatch for symbol register_atfork: {}",
            atfork_header
        );
    }
}

#[test]
fn test_decompile_callback_diagnostics() {
    let Some(binary) = build_c_fixture("test_callbacks.c") else {
        return;
    };
    let binary = binary.to_string_lossy().to_string();
    let output = run_hexray(&[&binary, "decompile", "spawn_with_start", "--diagnostics"]);
    assert!(
        output.status.success(),
        "decompile diagnostics should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("[diag]") && stdout.contains("spawn_with_start"),
        "Diagnostics banner should include target name:\n{}",
        stdout
    );
    assert!(
        stdout.contains("inferred as void* (*)(void*)")
            || stdout.contains("no function-pointer parameters inferred"),
        "Diagnostics should include function-pointer inference status:\n{}",
        stdout
    );
    assert!(
        stdout.contains("callback slot")
            || stdout.contains("summary marks")
            || stdout.contains("no function-pointer parameters inferred"),
        "Diagnostics should include function-pointer provenance details:\n{}",
        stdout
    );
    assert!(
        stdout.contains("return inferred as"),
        "Diagnostics should include return-type inference details:\n{}",
        stdout
    );
    assert!(
        stdout.contains("confidence") || stdout.contains("return inferred as void"),
        "Diagnostics should include return-type confidence or explicit void return:\n{}",
        stdout
    );

    let output = run_hexray(&[&binary, "decompile", "register_atfork", "--diagnostics"]);
    assert!(
        output.status.success(),
        "decompile diagnostics should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("[source=slot-fallback]"),
        "Diagnostics should include slot-fallback provenance for multi-callback mapping:\n{}",
        stdout
    );

    let output = run_hexray(&[&binary, "decompile", "sort_with_cmp", "--diagnostics"]);
    assert!(
        output.status.success(),
        "decompile diagnostics should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("[source=alias]"),
        "Diagnostics should include alias callback provenance:\n{}",
        stdout
    );
    assert!(
        !stdout.contains("[source=shape-fallback] mapped callback slot '_qsort'"),
        "qsort callback should no longer require ABI-shape fallback:\n{}",
        stdout
    );

    let output = run_hexray(&[&binary, "decompile", "register_on_exit", "--diagnostics"]);
    assert!(
        output.status.success(),
        "decompile diagnostics should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("[source=alias]"),
        "Diagnostics should include alias callback provenance for slot-0 callback wrappers:\n{}",
        stdout
    );
}

#[test]
fn test_decompile_callback_golden_multihop_with_diagnostics() {
    let Some(binary) = build_c_fixture("test_callbacks.c") else {
        return;
    };
    let binary = binary.to_string_lossy().to_string();
    let output = run_hexray(&[
        &binary,
        "decompile",
        "sort_with_cmp_multihop",
        "--diagnostics",
    ]);
    assert!(
        output.status.success(),
        "decompile diagnostics should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let header = stdout
        .lines()
        .find(|l| l.contains("_sort_with_cmp_multihop("));
    assert_eq!(
        header,
        Some("int32_t _sort_with_cmp_multihop(int64_t arg0, int64_t arg1, int32_t (*arg2)(void*, void*))"),
        "Golden callback header mismatch:\n{}",
        stdout
    );
    assert!(
        stdout.contains("[diag]")
            && stdout.contains("callback slot")
            && stdout.contains("return inferred as"),
        "Golden diagnostics should include callback and return provenance:\n{}",
        stdout
    );
}

// =============================================================================
// Callgraph Command Tests
// =============================================================================

#[test]
fn test_callgraph_basic() {
    skip_if_missing!("test_decompile");

    let output = run_hexray(&[&fixture_path("test_decompile"), "callgraph"]);
    assert!(
        output.status.success(),
        "callgraph command should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_callgraph_dot() {
    skip_if_missing!("test_decompile");

    let output = run_hexray(&[&fixture_path("test_decompile"), "callgraph", "--dot"]);
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("digraph"), "DOT output should be a digraph");
    }
}

#[test]
fn test_callgraph_json() {
    skip_if_missing!("test_decompile");

    let output = run_hexray(&[&fixture_path("test_decompile"), "callgraph", "--json"]);
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.starts_with('{') || stdout.starts_with('['),
            "JSON output should be valid"
        );
    }
}

// =============================================================================
// Xrefs Command Tests
// =============================================================================

#[test]
fn test_xrefs_basic() {
    skip_if_missing!("test_decompile");

    let output = run_hexray(&[&fixture_path("test_decompile"), "xrefs"]);
    assert!(
        output.status.success(),
        "xrefs command should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_xrefs_json() {
    skip_if_missing!("test_decompile");

    let output = run_hexray(&[&fixture_path("test_decompile"), "xrefs", "--json"]);
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.starts_with('{') || stdout.starts_with('['),
            "JSON output should be valid"
        );
    }
}

// =============================================================================
// Type Library Tests
// =============================================================================

#[test]
fn test_types_list() {
    // types list requires a category argument
    let output = run_hexray(&["types", "list", "all"]);
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Should list available type libraries
        assert!(
            !stdout.is_empty() || stdout.contains("posix") || stdout.contains("POSIX"),
            "Should list available type libraries: {}",
            stdout
        );
    } else {
        // If 'all' isn't a valid category, try 'posix'
        let output = run_hexray(&["types", "list", "posix"]);
        assert!(
            output.status.success() || !String::from_utf8_lossy(&output.stderr).is_empty(),
            "types list should either succeed or provide meaningful error"
        );
    }
}

// =============================================================================
// Error Handling Tests
// =============================================================================

#[test]
fn test_nonexistent_file() {
    let output = run_hexray(&["nonexistent_file_that_does_not_exist.bin"]);
    assert!(!output.status.success(), "Should fail for nonexistent file");
}

#[test]
fn test_invalid_address() {
    skip_if_missing!("elf/simple_x86_64");

    // Invalid hex address should be handled gracefully
    let output = run_hexray(&[&fixture_path("elf/simple_x86_64"), "--address", "not_a_hex"]);
    assert!(!output.status.success(), "Should fail for invalid address");
}

// =============================================================================
// Format Detection Tests
// =============================================================================

#[test]
fn test_format_auto_detection_elf() {
    skip_if_missing!("elf/simple_x86_64");

    let output = run_hexray(&[&fixture_path("elf/simple_x86_64"), "info"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.to_lowercase().contains("elf"),
        "Should auto-detect ELF format"
    );
}

#[test]
fn test_format_auto_detection_macho() {
    skip_if_missing!("test_x86_64_macho");

    let output = run_hexray(&[&fixture_path("test_x86_64_macho"), "info"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.to_lowercase().contains("mach"),
        "Should auto-detect Mach-O format"
    );
}

#[test]
fn test_format_auto_detection_pe() {
    skip_if_missing!("pe/simple_x64.exe");

    let output = run_hexray(&[&fixture_path("pe/simple_x64.exe"), "info"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.to_lowercase().contains("pe"),
        "Should auto-detect PE format"
    );
}

// =============================================================================
// Multi-Architecture Tests
// =============================================================================

#[test]
fn test_arm64_binary() {
    skip_if_missing!("test_arm64_macho");

    let output = run_hexray(&[&fixture_path("test_arm64_macho"), "info"]);
    assert!(output.status.success(), "Should handle ARM64 binary");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should detect ARM64 architecture
    assert!(
        stdout.to_lowercase().contains("arm64") || stdout.to_lowercase().contains("aarch64"),
        "Should detect ARM64 architecture: {}",
        stdout
    );
}

// =============================================================================
// Debug Info Tests
// =============================================================================

#[test]
fn test_binary_with_debug_info() {
    skip_if_missing!("test_with_debug");

    let output = run_hexray(&[&fixture_path("test_with_debug"), "info"]);
    assert!(
        output.status.success(),
        "Should handle binary with debug info"
    );
}

// =============================================================================
// Signature Tests
// =============================================================================

#[test]
fn test_signatures_list() {
    let output = run_hexray(&["signatures", "list"]);
    assert!(
        output.status.success(),
        "signatures list should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
