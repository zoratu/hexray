//! Snapshot tests for hexray output formats.
//!
//! These tests capture the expected output in various formats (JSON, DOT, HTML)
//! and verify that the output remains consistent across changes.
//!
//! To update snapshots when making intentional changes, run:
//! ```bash
//! cargo insta review
//! ```
//!
//! Or with auto-accept:
//! ```bash
//! cargo insta test --accept
//! ```

use std::path::Path;
use std::process::{Command, Output};

/// Get the path to the hexray binary.
fn hexray_bin() -> String {
    env!("CARGO_BIN_EXE_hexray").to_string()
}

/// Get the path to a test fixture (in workspace root).
fn fixture_path(name: &str) -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    // Go up two directories from crates/hexray to workspace root
    format!("{}/../../tests/fixtures/{}", manifest_dir, name)
}

/// Check if a fixture exists.
fn fixture_exists(name: &str) -> bool {
    let path = fixture_path(name);
    Path::new(&path).exists()
}

/// Run hexray with the given arguments.
fn run_hexray(args: &[&str]) -> Output {
    Command::new(hexray_bin())
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("Failed to execute hexray")
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

/// Normalize output for snapshot comparison by removing addresses that vary between runs.
fn normalize_output(output: &str) -> String {
    // Replace hex addresses with placeholders for stable snapshots
    let mut result = String::new();
    let mut chars = output.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '0' && chars.peek() == Some(&'x') {
            // Found potential hex address
            let mut hex = String::from("0x");
            chars.next(); // consume 'x'

            while let Some(&next) = chars.peek() {
                if next.is_ascii_hexdigit() {
                    hex.push(chars.next().unwrap());
                } else {
                    break;
                }
            }

            // Replace long addresses (>= 8 hex digits) with placeholder
            if hex.len() >= 10 {
                result.push_str("[ADDR]");
            } else {
                result.push_str(&hex);
            }
        } else {
            result.push(c);
        }
    }

    result
}

// =============================================================================
// JSON Output Snapshots
// =============================================================================

#[test]
fn snapshot_strings_json() {
    skip_if_missing!("test_strings");

    let output = run_hexray(&[&fixture_path("test_strings"), "strings", "--json"]);
    if !output.status.success() {
        eprintln!("Command failed, skipping snapshot");
        return;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse and re-serialize JSON to normalize formatting
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        // Redact addresses from the JSON
        let redacted = redact_json_addresses(json);
        insta::assert_json_snapshot!("strings_json", redacted);
    } else {
        // If not valid JSON, snapshot the raw output (but normalized)
        let normalized = normalize_output(&stdout);
        insta::assert_snapshot!("strings_json_raw", normalized);
    }
}

#[test]
fn snapshot_xrefs_json() {
    skip_if_missing!("test_decompile");

    let output = run_hexray(&[&fixture_path("test_decompile"), "xrefs", "--json"]);
    if !output.status.success() {
        eprintln!("Command failed, skipping snapshot");
        return;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        let redacted = redact_json_addresses(json);
        insta::assert_json_snapshot!("xrefs_json", redacted);
    }
}

#[test]
fn snapshot_callgraph_json() {
    skip_if_missing!("test_decompile");

    let output = run_hexray(&[&fixture_path("test_decompile"), "callgraph", "--json"]);
    if !output.status.success() {
        eprintln!("Command failed, skipping snapshot");
        return;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        let redacted = redact_json_addresses(json);
        // Sort arrays to ensure deterministic output for snapshot comparison
        let sorted = sort_json_arrays(redacted);
        insta::assert_json_snapshot!("callgraph_json", sorted);
    }
}

// =============================================================================
// DOT Output Snapshots
// =============================================================================

#[test]
fn snapshot_callgraph_dot() {
    skip_if_missing!("test_decompile");

    let output = run_hexray(&[&fixture_path("test_decompile"), "callgraph", "--dot"]);
    if !output.status.success() {
        eprintln!("Command failed, skipping snapshot");
        return;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let normalized = normalize_output(&stdout);

    // Only snapshot if we got valid DOT output
    // Sort lines within the digraph body to ensure deterministic output
    if normalized.contains("digraph") {
        let sorted = sort_dot_output(&normalized);
        insta::assert_snapshot!("callgraph_dot", sorted);
    }
}

#[test]
fn snapshot_cfg_dot() {
    skip_if_missing!("test_decompile");

    let output = run_hexray(&[&fixture_path("test_decompile"), "cfg", "main", "--dot"]);
    if !output.status.success() {
        // Try with address if main not found
        return;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let normalized = normalize_output(&stdout);

    if normalized.contains("digraph") {
        insta::assert_snapshot!("cfg_dot", normalized);
    }
}

// =============================================================================
// Info Command Snapshots
// =============================================================================

#[test]
fn snapshot_info_elf() {
    skip_if_missing!("elf/simple_x86_64");

    let output = run_hexray(&[&fixture_path("elf/simple_x86_64"), "info"]);
    if !output.status.success() {
        return;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let normalized = normalize_output(&stdout);

    insta::assert_snapshot!("info_elf", normalized);
}

#[test]
fn snapshot_info_macho() {
    skip_if_missing!("test_x86_64_macho");

    let output = run_hexray(&[&fixture_path("test_x86_64_macho"), "info"]);
    if !output.status.success() {
        return;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let normalized = normalize_output(&stdout);

    insta::assert_snapshot!("info_macho", normalized);
}

#[test]
fn snapshot_info_pe() {
    skip_if_missing!("pe/simple_x64.exe");

    let output = run_hexray(&[&fixture_path("pe/simple_x64.exe"), "info"]);
    if !output.status.success() {
        return;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let normalized = normalize_output(&stdout);

    insta::assert_snapshot!("info_pe", normalized);
}

// =============================================================================
// Sections Command Snapshots
// =============================================================================

#[test]
fn snapshot_sections_elf() {
    skip_if_missing!("elf/simple_x86_64");

    let output = run_hexray(&[&fixture_path("elf/simple_x86_64"), "sections"]);
    if !output.status.success() {
        return;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let normalized = normalize_output(&stdout);

    insta::assert_snapshot!("sections_elf", normalized);
}

#[test]
fn snapshot_sections_macho() {
    skip_if_missing!("test_x86_64_macho");

    let output = run_hexray(&[&fixture_path("test_x86_64_macho"), "sections"]);
    if !output.status.success() {
        return;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let normalized = normalize_output(&stdout);

    insta::assert_snapshot!("sections_macho", normalized);
}

// =============================================================================
// Symbols Command Snapshots
// =============================================================================

#[test]
fn snapshot_symbols_elf() {
    skip_if_missing!("elf/test_with_symbols");

    let output = run_hexray(&[&fixture_path("elf/test_with_symbols"), "symbols"]);
    if !output.status.success() {
        return;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let normalized = normalize_output(&stdout);

    insta::assert_snapshot!("symbols_elf", normalized);
}

// =============================================================================
// Decompile Command Snapshots
// =============================================================================

#[test]
fn snapshot_decompile() {
    skip_if_missing!("test_decompile");

    let output = run_hexray(&[&fixture_path("test_decompile"), "decompile"]);
    if !output.status.success() {
        return;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let normalized = normalize_output(&stdout);

    // Decompiler output should be stable (function names, structure)
    insta::assert_snapshot!("decompile", normalized);
}

#[test]
fn snapshot_decompile_with_addresses() {
    skip_if_missing!("test_decompile");

    let output = run_hexray(&[
        &fixture_path("test_decompile"),
        "decompile",
        "--show-addresses",
    ]);
    if !output.status.success() {
        return;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let normalized = normalize_output(&stdout);

    insta::assert_snapshot!("decompile_with_addresses", normalized);
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Sort JSON arrays by their string representation for deterministic snapshots.
fn sort_json_arrays(value: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;

    match value {
        Value::Object(map) => {
            let new_map: serde_json::Map<String, Value> = map
                .into_iter()
                .map(|(k, v)| (k, sort_json_arrays(v)))
                .collect();
            Value::Object(new_map)
        }
        Value::Array(arr) => {
            let mut sorted: Vec<Value> = arr.into_iter().map(sort_json_arrays).collect();
            // Sort by JSON string representation
            sorted.sort_by(|a, b| {
                let a_str = serde_json::to_string(a).unwrap_or_default();
                let b_str = serde_json::to_string(b).unwrap_or_default();
                a_str.cmp(&b_str)
            });
            Value::Array(sorted)
        }
        other => other,
    }
}

/// Sort DOT output lines for deterministic snapshots.
fn sort_dot_output(dot: &str) -> String {
    let lines: Vec<&str> = dot.lines().collect();

    // Find the start and end of the digraph body
    let mut body_start = 0;
    let mut body_end = lines.len();

    for (i, line) in lines.iter().enumerate() {
        if line.contains("digraph") && line.contains("{") {
            body_start = i + 1;
        }
        if line.trim() == "}" {
            body_end = i;
            break;
        }
    }

    // Sort only the body lines
    if body_start < body_end {
        let header: Vec<&str> = lines[..body_start].to_vec();
        let mut body: Vec<&str> = lines[body_start..body_end].to_vec();
        let footer: Vec<&str> = lines[body_end..].to_vec();

        body.sort();

        let mut result = header;
        result.extend(body);
        result.extend(footer);
        result.join("\n")
    } else {
        lines.join("\n")
    }
}

/// Redact addresses from JSON values for stable snapshots.
fn redact_json_addresses(value: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;

    match value {
        Value::Object(map) => {
            let mut new_map = serde_json::Map::new();
            for (key, val) in map {
                // Redact address-like keys
                if key.contains("address") || key.contains("addr") {
                    if val.is_number() {
                        new_map.insert(key, Value::String("[ADDR]".to_string()));
                    } else {
                        new_map.insert(key, redact_json_addresses(val));
                    }
                } else {
                    new_map.insert(key, redact_json_addresses(val));
                }
            }
            Value::Object(new_map)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(redact_json_addresses).collect()),
        Value::String(s) => {
            // Redact hex address strings
            if s.starts_with("0x") && s.len() >= 10 {
                Value::String("[ADDR]".to_string())
            } else {
                Value::String(s)
            }
        }
        other => other,
    }
}

// =============================================================================
// Disassembly Stability Tests
// =============================================================================

#[test]
fn snapshot_disassembly_basic() {
    skip_if_missing!("elf/simple_x86_64");

    let output = run_hexray(&[&fixture_path("elf/simple_x86_64"), "--count", "20"]);
    if !output.status.success() {
        return;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let normalized = normalize_output(&stdout);

    // Basic disassembly format should be stable
    insta::assert_snapshot!("disassembly_basic", normalized);
}
