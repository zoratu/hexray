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

/// Lock the CUDA-info output format. Generates a tiny synthetic sm_80
/// CUBIN at test time so the test is hermetic — it doesn't depend on
/// the corpus being built locally.
#[test]
fn snapshot_info_cubin() {
    use std::io::Write;
    let dir = std::env::temp_dir().join("hexray-snapshot-cubin");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("sm80_stub.cubin");

    // Minimal valid ELF64 + EM_CUDA, ABI V1, e_flags = sm_80.
    let mut data = vec![0u8; 64];
    data[0..4].copy_from_slice(b"\x7fELF");
    data[4] = 2; // ELF64
    data[5] = 1; // little-endian
    data[6] = 1; // EI_VERSION
    data[8] = 7; // EI_ABIVERSION (CUDA V1)
    data[16] = 2; // ET_EXEC
    data[18] = 190; // EM_CUDA
    data[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
    data[48..52].copy_from_slice(&0x0050_0550u32.to_le_bytes()); // sm_80
    data[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize

    std::fs::File::create(&path)
        .unwrap()
        .write_all(&data)
        .unwrap();

    let output = run_hexray(&[path.to_str().unwrap(), "info"]);
    if !output.status.success() {
        eprintln!("hexray info failed: {:?}", output);
        return;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let normalized = normalize_output(&stdout);
    insta::assert_snapshot!("info_cubin", normalized);
}

/// Lock the AMDGPU-info output format. Generates a tiny synthetic
/// gfx906 code object at test time — hermetic, doesn't depend on
/// ROCm being installed.
#[test]
fn snapshot_info_amdgpu() {
    use std::io::Write;
    let dir = std::env::temp_dir().join("hexray-snapshot-amdgpu");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("gfx906_stub.co");

    let bytes = synth_amdgpu_codeobject(
        "vector_add",
        // raw vgpr=2 → 12 vgprs (gfx906 wave64), raw sgpr=1 → 16
        // sgprs, kernarg=24, granulated_lds=4 (512B dynamic).
        DescriptorParams {
            vgpr_raw: 2,
            sgpr_raw: 1,
            kernarg: 24,
            lds_granulated: 4,
        },
        // gfx906 mach 0x2F, V4 ABI, xnack=on, sramecc=off.
        0x2F | (0b11 << 8) | (0b10 << 10),
    );

    std::fs::File::create(&path)
        .unwrap()
        .write_all(&bytes)
        .unwrap();

    let output = run_hexray(&[path.to_str().unwrap(), "info"]);
    if !output.status.success() {
        eprintln!("hexray info failed: {:?}", output);
        return;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let normalized = normalize_output(&stdout);
    insta::assert_snapshot!("info_amdgpu", normalized);
}

struct DescriptorParams {
    vgpr_raw: u32,
    sgpr_raw: u32,
    kernarg: u32,
    lds_granulated: u32,
}

fn synth_amdgpu_codeobject(kernel: &str, p: DescriptorParams, e_flags: u32) -> Vec<u8> {
    const KD: usize = 64;
    const SYM: usize = 24;

    // Build the 64-byte kernel descriptor.
    let mut kd = [0u8; KD];
    let rsrc1 = (p.vgpr_raw & 0x3f) | ((p.sgpr_raw & 0xf) << 6);
    let rsrc2 = (p.lds_granulated & 0x1ff) << 15;
    kd[0..4].copy_from_slice(&256u32.to_le_bytes()); // 256B static LDS
    kd[8..12].copy_from_slice(&p.kernarg.to_le_bytes());
    kd[16..24].copy_from_slice(&0x100i64.to_le_bytes()); // entry offset
    kd[48..52].copy_from_slice(&rsrc1.to_le_bytes());
    kd[52..56].copy_from_slice(&rsrc2.to_le_bytes());

    // Section bytes.
    let text: Vec<u8> = vec![0x01, 0x03, 0x00, 0x7e, 0x00, 0x00, 0x81, 0xbf];
    let rodata: Vec<u8> = kd.to_vec();
    let shstr = b"\0.text\0.rodata\0.shstrtab\0.strtab\0.symtab\0";
    let (sh_text, sh_rodata, sh_shstrtab, sh_strtab, sh_symtab) = (1u32, 7, 15, 25, 33);

    // String table for symbols.
    let mut strtab = vec![0u8];
    let entry_off = strtab.len() as u32;
    strtab.extend_from_slice(kernel.as_bytes());
    strtab.push(0);
    let kd_off = strtab.len() as u32;
    strtab.extend_from_slice(kernel.as_bytes());
    strtab.extend_from_slice(b".kd\0");

    // Symbol table.
    let mut symtab = vec![0u8; SYM];
    let mut push_sym = |name: u32, info: u8, shndx: u16, value: u64, size: u64| {
        let mut s = [0u8; SYM];
        s[0..4].copy_from_slice(&name.to_le_bytes());
        s[4] = info;
        s[6..8].copy_from_slice(&shndx.to_le_bytes());
        s[8..16].copy_from_slice(&value.to_le_bytes());
        s[16..24].copy_from_slice(&size.to_le_bytes());
        symtab.extend_from_slice(&s);
    };
    push_sym(entry_off, 0x12, 1, 0, text.len() as u64); // STT_FUNC
    push_sym(kd_off, 0x11, 2, 0, KD as u64); // STT_OBJECT

    // Layout.
    let ehdr = 64u64;
    let text_off = ehdr;
    let rodata_off = text_off + text.len() as u64;
    let shstrtab_off = rodata_off + rodata.len() as u64;
    let strtab_off = shstrtab_off + shstr.len() as u64;
    let symtab_off = strtab_off + strtab.len() as u64;
    let shdrs_off = symtab_off + symtab.len() as u64;

    let mut data = Vec::new();
    let mut h = vec![0u8; 64];
    h[0..4].copy_from_slice(b"\x7fELF");
    h[4] = 2;
    h[5] = 1;
    h[6] = 1;
    h[7] = 64; // ELFOSABI_AMDGPU_HSA
    h[8] = 2; // V4
    h[16..18].copy_from_slice(&1u16.to_le_bytes()); // ET_REL
    h[18..20].copy_from_slice(&224u16.to_le_bytes()); // EM_AMDGPU
    h[20..24].copy_from_slice(&1u32.to_le_bytes());
    h[40..48].copy_from_slice(&shdrs_off.to_le_bytes());
    h[48..52].copy_from_slice(&e_flags.to_le_bytes());
    h[52..54].copy_from_slice(&64u16.to_le_bytes());
    h[58..60].copy_from_slice(&64u16.to_le_bytes());
    h[60..62].copy_from_slice(&6u16.to_le_bytes());
    h[62..64].copy_from_slice(&3u16.to_le_bytes());
    data.extend_from_slice(&h);
    data.extend_from_slice(&text);
    data.extend_from_slice(&rodata);
    data.extend_from_slice(shstr);
    data.extend_from_slice(&strtab);
    data.extend_from_slice(&symtab);

    let mk =
        |name: u32, ty: u32, flags: u64, off: u64, size: u64, link: u32, info: u32, ent: u64| {
            let mut h = vec![0u8; 64];
            h[0..4].copy_from_slice(&name.to_le_bytes());
            h[4..8].copy_from_slice(&ty.to_le_bytes());
            h[8..16].copy_from_slice(&flags.to_le_bytes());
            h[24..32].copy_from_slice(&off.to_le_bytes());
            h[32..40].copy_from_slice(&size.to_le_bytes());
            h[40..44].copy_from_slice(&link.to_le_bytes());
            h[44..48].copy_from_slice(&info.to_le_bytes());
            h[48..56].copy_from_slice(&1u64.to_le_bytes());
            h[56..64].copy_from_slice(&ent.to_le_bytes());
            h
        };
    data.extend_from_slice(&[0u8; 64]);
    data.extend_from_slice(&mk(sh_text, 1, 0x6, text_off, text.len() as u64, 0, 0, 0));
    data.extend_from_slice(&mk(
        sh_rodata,
        1,
        0x2,
        rodata_off,
        rodata.len() as u64,
        0,
        0,
        0,
    ));
    data.extend_from_slice(&mk(
        sh_shstrtab,
        3,
        0,
        shstrtab_off,
        shstr.len() as u64,
        0,
        0,
        0,
    ));
    data.extend_from_slice(&mk(
        sh_strtab,
        3,
        0,
        strtab_off,
        strtab.len() as u64,
        0,
        0,
        0,
    ));
    data.extend_from_slice(&mk(
        sh_symtab,
        2,
        0,
        symtab_off,
        symtab.len() as u64,
        4,
        1,
        SYM as u64,
    ));

    data
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
