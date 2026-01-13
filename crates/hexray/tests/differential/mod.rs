//! Differential testing utilities for comparing hexray output against reference tools.
//!
//! This module provides utilities for comparing hexray's output against standard
//! binary analysis tools (objdump, nm, strings) to ensure correctness.
//!
//! # Test Categories
//!
//! - **Disassembly**: Compare instruction decoding against objdump/llvm-objdump
//! - **Symbols**: Compare symbol extraction against nm
//! - **Strings**: Compare string detection against the strings command

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::Command;

/// Result of comparing two disassembly outputs.
#[derive(Debug)]
pub struct DisasmDiffResult {
    /// Total number of instructions compared.
    pub total_instructions: usize,
    /// Number of instructions that matched.
    pub matching_instructions: usize,
    /// Match rate (0.0 to 1.0).
    pub match_rate: f64,
    /// List of mismatches (address, hexray_mnemonic, reference_mnemonic).
    pub mismatches: Vec<DisasmMismatch>,
    /// Instructions only found in hexray output.
    pub hexray_only: Vec<(u64, String)>,
    /// Instructions only found in reference output.
    pub reference_only: Vec<(u64, String)>,
}

/// A single disassembly mismatch.
#[derive(Debug, Clone)]
pub struct DisasmMismatch {
    /// Address of the instruction.
    pub address: u64,
    /// Hexray's mnemonic.
    pub hexray_mnemonic: String,
    /// Reference tool's mnemonic.
    pub reference_mnemonic: String,
    /// Optional: full hexray instruction text.
    pub hexray_full: Option<String>,
    /// Optional: full reference instruction text.
    pub reference_full: Option<String>,
}

impl DisasmDiffResult {
    /// Create a new empty result.
    pub fn new() -> Self {
        Self {
            total_instructions: 0,
            matching_instructions: 0,
            match_rate: 0.0,
            mismatches: Vec::new(),
            hexray_only: Vec::new(),
            reference_only: Vec::new(),
        }
    }

    /// Compute the match rate from the totals.
    pub fn compute_rate(&mut self) {
        if self.total_instructions > 0 {
            self.match_rate = self.matching_instructions as f64 / self.total_instructions as f64;
        }
    }

    /// Returns true if the match rate meets the threshold.
    pub fn meets_threshold(&self, threshold: f64) -> bool {
        self.match_rate >= threshold
    }

    /// Generate a summary report.
    pub fn summary(&self) -> String {
        let mut report = String::new();
        report.push_str(&format!(
            "Disassembly Comparison Results:\n\
             ================================\n\
             Total instructions: {}\n\
             Matching: {} ({:.2}%)\n\
             Mismatches: {}\n\
             Hexray-only: {}\n\
             Reference-only: {}\n",
            self.total_instructions,
            self.matching_instructions,
            self.match_rate * 100.0,
            self.mismatches.len(),
            self.hexray_only.len(),
            self.reference_only.len(),
        ));

        if !self.mismatches.is_empty() {
            report.push_str("\nFirst 10 mismatches:\n");
            for mismatch in self.mismatches.iter().take(10) {
                report.push_str(&format!(
                    "  0x{:08x}: hexray='{}' reference='{}'\n",
                    mismatch.address, mismatch.hexray_mnemonic, mismatch.reference_mnemonic
                ));
            }
        }

        report
    }
}

impl Default for DisasmDiffResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of comparing symbol tables.
#[derive(Debug)]
pub struct SymbolDiffResult {
    /// Total symbols in reference.
    pub total_symbols: usize,
    /// Number of matching symbols.
    pub matching_symbols: usize,
    /// Match rate (0.0 to 1.0).
    pub match_rate: f64,
    /// Symbols only in hexray.
    pub hexray_only: Vec<SymbolInfo>,
    /// Symbols only in reference.
    pub reference_only: Vec<SymbolInfo>,
    /// Symbols with address mismatches.
    pub address_mismatches: Vec<SymbolAddressMismatch>,
}

/// Basic symbol information.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SymbolInfo {
    /// Symbol name.
    pub name: String,
    /// Symbol address.
    pub address: u64,
    /// Symbol type character (from nm).
    pub symbol_type: Option<char>,
}

/// A symbol with mismatched addresses.
#[derive(Debug, Clone)]
pub struct SymbolAddressMismatch {
    /// Symbol name.
    pub name: String,
    /// Address from hexray.
    pub hexray_address: u64,
    /// Address from reference.
    pub reference_address: u64,
}

impl SymbolDiffResult {
    /// Create a new empty result.
    pub fn new() -> Self {
        Self {
            total_symbols: 0,
            matching_symbols: 0,
            match_rate: 0.0,
            hexray_only: Vec::new(),
            reference_only: Vec::new(),
            address_mismatches: Vec::new(),
        }
    }

    /// Compute the match rate.
    pub fn compute_rate(&mut self) {
        if self.total_symbols > 0 {
            self.match_rate = self.matching_symbols as f64 / self.total_symbols as f64;
        }
    }

    /// Returns true if the match rate meets the threshold.
    pub fn meets_threshold(&self, threshold: f64) -> bool {
        self.match_rate >= threshold
    }

    /// Generate a summary report.
    pub fn summary(&self) -> String {
        let mut report = String::new();
        report.push_str(&format!(
            "Symbol Comparison Results:\n\
             ==========================\n\
             Total symbols: {}\n\
             Matching: {} ({:.2}%)\n\
             Hexray-only: {}\n\
             Reference-only: {}\n\
             Address mismatches: {}\n",
            self.total_symbols,
            self.matching_symbols,
            self.match_rate * 100.0,
            self.hexray_only.len(),
            self.reference_only.len(),
            self.address_mismatches.len(),
        ));

        if !self.reference_only.is_empty() {
            report.push_str("\nFirst 10 reference-only symbols:\n");
            for sym in self.reference_only.iter().take(10) {
                report.push_str(&format!("  0x{:08x}: {}\n", sym.address, sym.name));
            }
        }

        report
    }
}

impl Default for SymbolDiffResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of comparing string detection.
#[derive(Debug)]
pub struct StringDiffResult {
    /// Total strings in reference.
    pub total_strings: usize,
    /// Number of matching strings.
    pub matching_strings: usize,
    /// Match rate (0.0 to 1.0).
    pub match_rate: f64,
    /// Strings only in hexray.
    pub hexray_only: Vec<String>,
    /// Strings only in reference.
    pub reference_only: Vec<String>,
    /// Partial matches (hexray string is substring of reference or vice versa).
    pub partial_matches: Vec<(String, String)>,
}

impl StringDiffResult {
    /// Create a new empty result.
    pub fn new() -> Self {
        Self {
            total_strings: 0,
            matching_strings: 0,
            match_rate: 0.0,
            hexray_only: Vec::new(),
            reference_only: Vec::new(),
            partial_matches: Vec::new(),
        }
    }

    /// Compute the match rate.
    pub fn compute_rate(&mut self) {
        if self.total_strings > 0 {
            self.match_rate = self.matching_strings as f64 / self.total_strings as f64;
        }
    }

    /// Returns true if the match rate meets the threshold.
    pub fn meets_threshold(&self, threshold: f64) -> bool {
        self.match_rate >= threshold
    }

    /// Generate a summary report.
    pub fn summary(&self) -> String {
        let mut report = String::new();
        report.push_str(&format!(
            "String Comparison Results:\n\
             ==========================\n\
             Total strings (reference): {}\n\
             Matching: {} ({:.2}%)\n\
             Hexray-only: {}\n\
             Reference-only: {}\n\
             Partial matches: {}\n",
            self.total_strings,
            self.matching_strings,
            self.match_rate * 100.0,
            self.hexray_only.len(),
            self.reference_only.len(),
            self.partial_matches.len(),
        ));

        if !self.reference_only.is_empty() {
            report.push_str("\nFirst 10 reference-only strings:\n");
            for s in self.reference_only.iter().take(10) {
                let display = if s.len() > 60 {
                    format!("{}...", &s[..60])
                } else {
                    s.clone()
                };
                report.push_str(&format!("  '{}'\n", display));
            }
        }

        report
    }
}

impl Default for StringDiffResult {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Reference Tool Runners
// =============================================================================

/// Check if a command is available on the system.
pub fn command_available(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Determine the best objdump command to use.
pub fn find_objdump() -> Option<String> {
    // Prefer llvm-objdump for consistent output
    for cmd in ["llvm-objdump", "objdump", "gobjdump"] {
        if command_available(cmd) {
            return Some(cmd.to_string());
        }
    }
    None
}

/// Determine the best nm command to use.
pub fn find_nm() -> Option<String> {
    for cmd in ["nm", "llvm-nm", "gnm"] {
        if command_available(cmd) {
            return Some(cmd.to_string());
        }
    }
    None
}

/// Run objdump on a binary file.
pub fn run_objdump(binary_path: &str, intel_syntax: bool) -> Result<Vec<u8>, std::io::Error> {
    let objdump_cmd = find_objdump().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "objdump not found")
    })?;

    let mut cmd = Command::new(&objdump_cmd);
    cmd.arg("-d");

    // Handle different objdump flavors
    if objdump_cmd.contains("llvm") {
        if intel_syntax {
            cmd.arg("--x86-asm-syntax=intel");
        }
    } else if intel_syntax {
        cmd.arg("-M").arg("intel");
    }

    cmd.arg(binary_path);

    let output = cmd.output()?;
    Ok(output.stdout)
}

/// Run nm on a binary file.
pub fn run_nm(binary_path: &str) -> Result<Vec<u8>, std::io::Error> {
    let nm_cmd = find_nm().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "nm not found")
    })?;

    let output = Command::new(nm_cmd).arg(binary_path).output()?;
    Ok(output.stdout)
}

/// Run nm with specific options.
pub fn run_nm_with_options(binary_path: &str, options: &[&str]) -> Result<Vec<u8>, std::io::Error> {
    let nm_cmd = find_nm().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "nm not found")
    })?;

    let mut cmd = Command::new(nm_cmd);
    for opt in options {
        cmd.arg(opt);
    }
    cmd.arg(binary_path);

    let output = cmd.output()?;
    Ok(output.stdout)
}

/// Run the strings command on a binary file.
pub fn run_strings(binary_path: &str, min_len: usize) -> Result<Vec<u8>, std::io::Error> {
    let output = Command::new("strings")
        .arg("-a") // Scan the whole file
        .arg("-n")
        .arg(min_len.to_string())
        .arg(binary_path)
        .output()?;
    Ok(output.stdout)
}

/// Run strings with encoding option.
pub fn run_strings_with_encoding(
    binary_path: &str,
    min_len: usize,
    encoding: &str, // "s" for single-byte, "S" for single-byte including ISO-8859, "b" for big-endian 16-bit, "l" for little-endian 16-bit
) -> Result<Vec<u8>, std::io::Error> {
    let output = Command::new("strings")
        .arg("-a")
        .arg("-n")
        .arg(min_len.to_string())
        .arg("-e")
        .arg(encoding)
        .arg(binary_path)
        .output()?;
    Ok(output.stdout)
}

// =============================================================================
// Output Parsers
// =============================================================================

/// Parsed instruction from objdump output.
#[derive(Debug, Clone)]
pub struct ParsedInstruction {
    /// Instruction address.
    pub address: u64,
    /// Mnemonic (lowercase).
    pub mnemonic: String,
    /// Full instruction text.
    pub full_text: String,
    /// Raw bytes (hex string).
    pub bytes: String,
}

/// Parse objdump -d output into instructions.
pub fn parse_objdump_output(output: &[u8]) -> Vec<ParsedInstruction> {
    let text = String::from_utf8_lossy(output);
    let mut instructions = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || !line.contains(':') {
            continue;
        }

        // Skip section headers and labels (lines ending with ':')
        if line.ends_with(':') || line.starts_with("Disassembly") {
            continue;
        }

        // Parse objdump format: "  401000:	55                   	push   %rbp"
        // or llvm-objdump: "  401000: 55                           pushq   %rbp"
        if let Some(colon_pos) = line.find(':') {
            let addr_str = line[..colon_pos].trim();
            if let Ok(addr) = u64::from_str_radix(addr_str, 16) {
                let rest = &line[colon_pos + 1..];

                // Find the instruction mnemonic after hex bytes
                // Look for either tab-separated or space-separated format
                let parts: Vec<&str> = rest.split_whitespace().collect();

                // Skip the hex bytes to find the mnemonic
                let mut mnemonic_idx = 0;
                for (i, part) in parts.iter().enumerate() {
                    // Check if this looks like a hex byte sequence
                    if !part.chars().all(|c| c.is_ascii_hexdigit()) {
                        mnemonic_idx = i;
                        break;
                    }
                }

                if mnemonic_idx < parts.len() {
                    let mnemonic = parts[mnemonic_idx].to_lowercase();
                    // Remove any suffix like 'q', 'l', etc. for normalization
                    let bytes = parts[..mnemonic_idx].join(" ");
                    let full_text = parts[mnemonic_idx..].join(" ");

                    if !mnemonic.is_empty() {
                        instructions.push(ParsedInstruction {
                            address: addr,
                            mnemonic,
                            full_text,
                            bytes,
                        });
                    }
                }
            }
        }
    }

    instructions
}

/// Parse objdump output into simple (address, mnemonic) pairs for compatibility.
pub fn parse_objdump_simple(output: &[u8]) -> Vec<(u64, String)> {
    parse_objdump_output(output)
        .into_iter()
        .map(|i| (i.address, i.mnemonic))
        .collect()
}

/// Parse nm output into symbol information.
pub fn parse_nm_output(output: &[u8]) -> Vec<SymbolInfo> {
    let text = String::from_utf8_lossy(output);
    let mut symbols = Vec::new();

    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();

        // nm format: "0000000000401000 T main" or "                 U external_func"
        if parts.len() >= 3 {
            if let Ok(addr) = u64::from_str_radix(parts[0], 16) {
                let sym_type = parts[1].chars().next();
                let name = parts[2].to_string();
                symbols.push(SymbolInfo {
                    name,
                    address: addr,
                    symbol_type: sym_type,
                });
            }
        } else if parts.len() == 2 {
            // Undefined symbol (no address)
            let sym_type = parts[0].chars().next();
            let name = parts[1].to_string();
            symbols.push(SymbolInfo {
                name,
                address: 0,
                symbol_type: sym_type,
            });
        }
    }

    symbols
}

/// Parse nm output into simple (address, name) pairs for compatibility.
pub fn parse_nm_simple(output: &[u8]) -> Vec<(u64, String)> {
    parse_nm_output(output)
        .into_iter()
        .filter(|s| s.address != 0)
        .map(|s| (s.address, s.name))
        .collect()
}

/// Parse strings command output.
pub fn parse_strings_output(output: &[u8]) -> HashSet<String> {
    let text = String::from_utf8_lossy(output);
    text.lines().map(|s| s.to_string()).collect()
}

/// Parse strings command output preserving order.
pub fn parse_strings_ordered(output: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(output);
    text.lines().map(|s| s.to_string()).collect()
}

// =============================================================================
// Mnemonic Normalization
// =============================================================================

/// Normalize a mnemonic for comparison.
///
/// This handles:
/// - Case normalization
/// - Common aliases (je/jz, jne/jnz, etc.)
/// - Suffix variations (movq/mov, retq/ret, etc.)
pub fn normalize_mnemonic(mnemonic: &str) -> String {
    let m = mnemonic.to_lowercase();

    // Remove common suffixes that indicate operand size
    let base = m
        .strip_suffix('q')
        .or_else(|| m.strip_suffix('l'))
        .or_else(|| m.strip_suffix('w'))
        .or_else(|| m.strip_suffix('b'))
        .unwrap_or(&m);

    // Handle common aliases
    match base {
        // Jump aliases
        "je" => "jz".to_string(),
        "jne" => "jnz".to_string(),
        "jc" => "jb".to_string(),
        "jnc" => "jnb".to_string(),
        "jnae" => "jb".to_string(),
        "jae" => "jnb".to_string(),
        "jna" => "jbe".to_string(),
        "ja" => "jnbe".to_string(),
        "jpe" => "jp".to_string(),
        "jpo" => "jnp".to_string(),
        "jnge" => "jl".to_string(),
        "jge" => "jnl".to_string(),
        "jng" => "jle".to_string(),
        "jg" => "jnle".to_string(),

        // Set aliases
        "sete" => "setz".to_string(),
        "setne" => "setnz".to_string(),
        "setc" => "setb".to_string(),
        "setnc" => "setnb".to_string(),

        // Conditional move aliases
        "cmove" => "cmovz".to_string(),
        "cmovne" => "cmovnz".to_string(),

        // NOP variants
        "nopl" | "nopw" | "nopq" => "nop".to_string(),
        "data16" => "nop".to_string(), // Sometimes used as NOP padding

        // Return variants (already handled by suffix stripping)
        "ret" => "ret".to_string(),

        // rep prefixes - normalize
        "rep" | "repe" | "repz" => "rep".to_string(),
        "repne" | "repnz" => "repne".to_string(),

        // Default: return as-is
        _ => base.to_string(),
    }
}

/// Check if two mnemonics are equivalent after normalization.
pub fn mnemonics_equivalent(a: &str, b: &str) -> bool {
    normalize_mnemonic(a) == normalize_mnemonic(b)
}

// =============================================================================
// Comparison Functions
// =============================================================================

/// Compare two sets of instructions.
pub fn compare_instructions(
    hexray: &[(u64, String)],
    reference: &[(u64, String)],
) -> DisasmDiffResult {
    let mut result = DisasmDiffResult::new();

    let hexray_map: HashMap<u64, &String> = hexray.iter().map(|(a, m)| (*a, m)).collect();
    let reference_map: HashMap<u64, &String> = reference.iter().map(|(a, m)| (*a, m)).collect();

    // Check all reference instructions
    for (addr, ref_mnemonic) in reference {
        result.total_instructions += 1;

        if let Some(hexray_mnemonic) = hexray_map.get(addr) {
            if mnemonics_equivalent(hexray_mnemonic, ref_mnemonic) {
                result.matching_instructions += 1;
            } else {
                result.mismatches.push(DisasmMismatch {
                    address: *addr,
                    hexray_mnemonic: (*hexray_mnemonic).clone(),
                    reference_mnemonic: ref_mnemonic.clone(),
                    hexray_full: None,
                    reference_full: None,
                });
            }
        } else {
            result.reference_only.push((*addr, ref_mnemonic.clone()));
        }
    }

    // Find hexray-only instructions
    for (addr, hexray_mnemonic) in hexray {
        if !reference_map.contains_key(addr) {
            result.hexray_only.push((*addr, hexray_mnemonic.clone()));
        }
    }

    result.compute_rate();
    result
}

/// Compare two sets of symbols.
pub fn compare_symbols(
    hexray: &[(u64, String)],
    reference: &[(u64, String)],
) -> SymbolDiffResult {
    let mut result = SymbolDiffResult::new();

    // Build lookup maps
    let hexray_by_name: HashMap<&str, u64> =
        hexray.iter().map(|(a, n)| (n.as_str(), *a)).collect();
    let reference_by_name: HashMap<&str, u64> =
        reference.iter().map(|(a, n)| (n.as_str(), *a)).collect();

    result.total_symbols = reference.len();

    // Compare by name
    for (ref_addr, ref_name) in reference {
        if let Some(&hexray_addr) = hexray_by_name.get(ref_name.as_str()) {
            if hexray_addr == *ref_addr {
                result.matching_symbols += 1;
            } else {
                result.address_mismatches.push(SymbolAddressMismatch {
                    name: ref_name.clone(),
                    hexray_address: hexray_addr,
                    reference_address: *ref_addr,
                });
            }
        } else {
            result.reference_only.push(SymbolInfo {
                name: ref_name.clone(),
                address: *ref_addr,
                symbol_type: None,
            });
        }
    }

    // Find hexray-only symbols
    for (hexray_addr, hexray_name) in hexray {
        if !reference_by_name.contains_key(hexray_name.as_str()) {
            result.hexray_only.push(SymbolInfo {
                name: hexray_name.clone(),
                address: *hexray_addr,
                symbol_type: None,
            });
        }
    }

    result.compute_rate();
    result
}

/// Compare two sets of strings.
pub fn compare_strings(hexray: &HashSet<String>, reference: &HashSet<String>) -> StringDiffResult {
    let mut result = StringDiffResult::new();

    result.total_strings = reference.len();
    result.matching_strings = hexray.intersection(reference).count();

    // Find reference-only strings
    for s in reference {
        if !hexray.contains(s) {
            // Check for partial matches
            let partial = hexray.iter().find(|h| h.contains(s.as_str()) || s.contains(h.as_str()));
            if let Some(partial_match) = partial {
                result.partial_matches.push((partial_match.clone(), s.clone()));
            } else {
                result.reference_only.push(s.clone());
            }
        }
    }

    // Find hexray-only strings
    for s in hexray {
        if !reference.contains(s) {
            let has_partial = reference
                .iter()
                .any(|r| r.contains(s.as_str()) || s.contains(r.as_str()));
            if !has_partial {
                result.hexray_only.push(s.clone());
            }
        }
    }

    result.compute_rate();
    result
}

// =============================================================================
// Test Helpers
// =============================================================================

/// Get the path to a test fixture.
pub fn fixture_path(name: &str) -> String {
    format!("tests/fixtures/{}", name)
}

/// Check if a test fixture exists.
pub fn fixture_exists(name: &str) -> bool {
    Path::new(&fixture_path(name)).exists()
}

/// Skip reason for tests.
pub enum SkipReason {
    /// Test fixture not found.
    FixtureNotFound(String),
    /// Required tool not available.
    ToolNotAvailable(String),
    /// Other reason.
    Other(String),
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SkipReason::FixtureNotFound(path) => write!(f, "Fixture not found: {}", path),
            SkipReason::ToolNotAvailable(tool) => write!(f, "Tool not available: {}", tool),
            SkipReason::Other(msg) => write!(f, "{}", msg),
        }
    }
}

/// Check prerequisites for differential tests.
pub fn check_prerequisites(fixture: &str, tool: &str) -> Result<(), SkipReason> {
    if !fixture_exists(fixture) {
        return Err(SkipReason::FixtureNotFound(fixture.to_string()));
    }

    let tool_available = match tool {
        "objdump" => find_objdump().is_some(),
        "nm" => find_nm().is_some(),
        "strings" => command_available("strings"),
        _ => command_available(tool),
    };

    if !tool_available {
        return Err(SkipReason::ToolNotAvailable(tool.to_string()));
    }

    Ok(())
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_objdump_output() {
        let output = br#"
test:     file format elf64-x86-64


Disassembly of section .text:

0000000000401000 <_start>:
  401000:	55                   	push   %rbp
  401001:	48 89 e5             	mov    %rsp,%rbp
  401004:	b8 00 00 00 00       	mov    $0x0,%eax
  401009:	5d                   	pop    %rbp
  40100a:	c3                   	ret
"#;

        let instructions = parse_objdump_output(output);
        assert_eq!(instructions.len(), 5);
        assert_eq!(instructions[0].address, 0x401000);
        assert_eq!(instructions[0].mnemonic, "push");
        assert_eq!(instructions[4].address, 0x40100a);
        assert_eq!(instructions[4].mnemonic, "ret");
    }

    #[test]
    fn test_parse_nm_output() {
        let output = b"0000000000401000 T main\n0000000000401050 T helper\n                 U printf\n";
        let symbols = parse_nm_output(output);
        assert_eq!(symbols.len(), 3);
        assert_eq!(symbols[0].name, "main");
        assert_eq!(symbols[0].address, 0x401000);
        assert_eq!(symbols[0].symbol_type, Some('T'));
        assert_eq!(symbols[2].name, "printf");
        assert_eq!(symbols[2].address, 0);
        assert_eq!(symbols[2].symbol_type, Some('U'));
    }

    #[test]
    fn test_normalize_mnemonic() {
        assert_eq!(normalize_mnemonic("je"), "jz");
        assert_eq!(normalize_mnemonic("JNE"), "jnz");
        assert_eq!(normalize_mnemonic("retq"), "ret");
        assert_eq!(normalize_mnemonic("movq"), "mov");
        assert_eq!(normalize_mnemonic("mov"), "mov");
        assert_eq!(normalize_mnemonic("pushq"), "push");
        assert_eq!(normalize_mnemonic("nopl"), "nop");
    }

    #[test]
    fn test_mnemonics_equivalent() {
        assert!(mnemonics_equivalent("je", "jz"));
        assert!(mnemonics_equivalent("JNE", "jnz"));
        assert!(mnemonics_equivalent("retq", "ret"));
        assert!(mnemonics_equivalent("movq", "mov"));
        assert!(!mnemonics_equivalent("mov", "push"));
    }

    #[test]
    fn test_compare_instructions() {
        let hexray = vec![
            (0x1000, "push".to_string()),
            (0x1001, "mov".to_string()),
            (0x1004, "ret".to_string()),
        ];
        let reference = vec![
            (0x1000, "pushq".to_string()),
            (0x1001, "movq".to_string()),
            (0x1004, "retq".to_string()),
        ];

        let result = compare_instructions(&hexray, &reference);
        assert_eq!(result.total_instructions, 3);
        assert_eq!(result.matching_instructions, 3);
        assert!(result.match_rate > 0.99);
    }

    #[test]
    fn test_compare_symbols() {
        let hexray = vec![
            (0x1000, "main".to_string()),
            (0x1050, "helper".to_string()),
        ];
        let reference = vec![
            (0x1000, "main".to_string()),
            (0x1050, "helper".to_string()),
            (0x2000, "extra".to_string()),
        ];

        let result = compare_symbols(&hexray, &reference);
        assert_eq!(result.total_symbols, 3);
        assert_eq!(result.matching_symbols, 2);
        assert_eq!(result.reference_only.len(), 1);
    }

    #[test]
    fn test_compare_strings() {
        let hexray: HashSet<String> = ["Hello".to_string(), "World".to_string()]
            .into_iter()
            .collect();
        let reference: HashSet<String> = ["Hello".to_string(), "World".to_string(), "Extra".to_string()]
            .into_iter()
            .collect();

        let result = compare_strings(&hexray, &reference);
        assert_eq!(result.total_strings, 3);
        assert_eq!(result.matching_strings, 2);
        assert_eq!(result.reference_only.len(), 1);
    }
}
