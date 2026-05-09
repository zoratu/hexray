//! Function signature recognition commands.
//!
//! Commands for identifying library functions using signature matching
//! (FLIRT-like functionality).

use anyhow::{bail, Result};
use clap::Subcommand;
use hexray_core::Architecture;
use hexray_formats::BinaryFormat;
use hexray_signatures::{builtin as sig_builtin, SignatureMatcher};

#[cfg(test)]
use hexray_core::Symbol;

/// Signature management actions.
#[derive(Subcommand)]
pub enum SignaturesAction {
    /// Scan binary for known library functions
    Scan {
        /// Minimum confidence threshold (0.0-1.0)
        #[arg(short, long, default_value = "0.5", value_parser = parse_confidence)]
        confidence: f32,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// List builtin signature databases
    Builtin,
    /// Show signature database statistics
    Stats {
        /// Architecture: x86_64 or aarch64 (arm64/arm64e aliases accepted)
        #[arg(short, long, default_value = "x86_64", value_parser = parse_signature_arch)]
        arch: String,
    },
    /// List all signatures in a database
    List {
        /// Architecture: x86_64 or aarch64 (arm64/arm64e aliases accepted)
        #[arg(short, long, default_value = "x86_64", value_parser = parse_signature_arch)]
        arch: String,
        /// Filter by library name
        #[arg(short, long)]
        library: Option<String>,
    },
    /// Show details of a specific signature
    Show {
        /// Signature name (e.g., "strlen", "malloc")
        name: String,
        /// Architecture: x86_64 or aarch64 (arm64/arm64e aliases accepted)
        #[arg(short, long, default_value = "x86_64", value_parser = parse_signature_arch)]
        arch: String,
    },
}

/// Handle signature commands that don't require a binary file.
pub fn handle_signatures_command_no_binary(action: &SignaturesAction) -> Result<()> {
    match action {
        SignaturesAction::Builtin => {
            println!("Available builtin signature databases:");
            println!("{}", "=".repeat(50));
            println!("  x86_64   - x86_64 libc signatures (glibc/musl patterns)");
            println!("  aarch64  - ARM64 libc signatures (glibc/musl patterns)");
            println!();
            println!("Use 'signatures stats -a <arch>' to see database statistics.");
            println!("Use 'signatures list -a <arch>' to list all signatures.");
        }

        SignaturesAction::Stats { arch } => {
            let db = sig_builtin::load_for_architecture(arch);
            let stats = db.stats();

            println!("Signature Database Statistics ({})", arch);
            println!("{}", "=".repeat(50));
            println!("{}", stats);
        }

        SignaturesAction::List { arch, library } => {
            let db = sig_builtin::load_for_architecture(arch);

            println!("Signatures for {} ({} total)", arch, db.len());
            println!("{}", "=".repeat(60));
            println!();

            let signatures: Vec<_> = if let Some(lib) = library {
                db.filter_by_library(lib)
            } else {
                db.signatures().iter().collect()
            };

            println!(
                "{:<24} {:<12} {:<8} {:<12}",
                "Name", "Library", "Conf", "Pattern Len"
            );
            println!("{}", "-".repeat(60));

            for sig in signatures {
                println!(
                    "{:<24} {:<12} {:<8.2} {:>4} bytes",
                    sig.name,
                    &sig.library,
                    sig.confidence,
                    sig.pattern.len()
                );
            }
        }

        SignaturesAction::Show { name, arch } => {
            let db = sig_builtin::load_for_architecture(arch);

            if let Some(sig) = db.get(name) {
                println!("Signature: {}", sig.name);
                println!("{}", "=".repeat(50));
                println!("Library:      {}", sig.library);
                println!("Confidence:   {:.2}", sig.confidence);
                println!("Pattern:      {}", sig.pattern);
                println!("Pattern len:  {} bytes", sig.pattern.len());

                if let Some(doc) = &sig.doc {
                    println!("Description:  {}", doc);
                }

                if !sig.aliases.is_empty() {
                    println!("Aliases:      {}", sig.aliases.join(", "));
                }

                println!("Convention:   {:?}", sig.calling_convention);

                println!("Returns:      {:?}", sig.return_type);

                if !sig.parameters.is_empty() {
                    println!("Parameters:");
                    for param in &sig.parameters {
                        println!("  - {} : {:?}", param.name, param.param_type);
                    }
                }

                println!();
                println!("C Prototype:  {}", sig.to_c_prototype());
            } else {
                bail!("Signature '{}' not found in {} database", name, arch);
            }
        }

        SignaturesAction::Scan { .. } => {
            // This should not be called - scan requires a binary
            bail!("Internal error: Scan requires a binary file");
        }
    }

    Ok(())
}

/// Handle signature commands that require a binary file.
pub fn handle_signatures_command(fmt: &dyn BinaryFormat, action: SignaturesAction) -> Result<()> {
    match action {
        SignaturesAction::Scan { confidence, json } => {
            let arch = fmt.architecture();

            // Load appropriate signature database based on architecture
            let arch_str = match arch {
                Architecture::X86_64 | Architecture::X86 => "x86_64",
                Architecture::Arm64 => "aarch64",
                Architecture::RiscV64 | Architecture::RiscV32 => {
                    bail!("No builtin signatures for RISC-V yet");
                }
                _ => bail!("Unsupported architecture: {:?}", arch),
            };

            let db = sig_builtin::load_for_architecture(arch_str);
            let matcher = SignatureMatcher::new(&db).with_min_confidence(confidence);
            let mut matches = scan_function_symbols(fmt, &matcher);

            // Sort by address
            matches.sort_by_key(|m| m.offset);

            // Remove duplicates at same address (keep highest confidence)
            matches.dedup_by(|a, b| {
                if a.offset == b.offset {
                    // Keep the one with higher confidence
                    a.confidence <= b.confidence
                } else {
                    false
                }
            });

            if json {
                print_scan_result_json(arch_str, confidence, &matches);
            } else {
                print_scan_result(arch_str, confidence, &matches);
            }
        }

        // These are handled before binary loading
        SignaturesAction::Builtin
        | SignaturesAction::Stats { .. }
        | SignaturesAction::List { .. }
        | SignaturesAction::Show { .. } => {
            unreachable!("These subcommands should have been handled earlier");
        }
    }

    Ok(())
}

fn scan_function_symbols<'a>(
    fmt: &dyn BinaryFormat,
    matcher: &SignatureMatcher<'a>,
) -> Vec<hexray_signatures::MatchResult<'a>> {
    let mut matches = Vec::new();
    let symbols: Vec<_> = fmt.symbols().cloned().collect();
    let mut seen = std::collections::HashSet::new();

    for (address, size, heuristic_bounds) in
        crate::discover_function_starts(fmt, fmt.architecture(), &symbols)
    {
        if !seen.insert(address) {
            continue;
        }
        let Some(bytes) = crate::function_start_bytes(fmt, address, size, heuristic_bounds) else {
            continue;
        };

        if let Some(mut m) = matcher.match_bytes(bytes) {
            m.offset += address as usize;
            matches.push(m);
        }
    }

    matches
}

fn parse_signature_arch(input: &str) -> std::result::Result<String, String> {
    match input.to_ascii_lowercase().as_str() {
        "x86_64" | "x64" | "amd64" => Ok("x86_64".to_string()),
        "aarch64" | "arm64" | "arm64e" => Ok("aarch64".to_string()),
        _ => Err(format!(
            "unsupported architecture '{input}'; supported values: x86_64, aarch64 (aliases: x64, amd64, arm64, arm64e)"
        )),
    }
}

fn parse_confidence(input: &str) -> std::result::Result<f32, String> {
    let confidence: f32 = input.parse().map_err(|_| {
        format!("invalid confidence '{input}': expected a number between 0.0 and 1.0")
    })?;

    if !(0.0..=1.0).contains(&confidence) {
        return Err(format!(
            "confidence must be between 0.0 and 1.0, got {confidence}"
        ));
    }

    Ok(confidence)
}

fn print_scan_result_json(
    arch_str: &str,
    confidence: f32,
    matches: &[hexray_signatures::MatchResult],
) {
    println!("{{");
    println!("  \"architecture\": \"{}\",", arch_str);
    println!("  \"min_confidence\": {},", confidence);
    println!("  \"matches\": [");
    for (i, m) in matches.iter().enumerate() {
        let comma = if i < matches.len() - 1 { "," } else { "" };
        println!("    {{");
        println!("      \"address\": \"{:#x}\",", m.offset);
        println!("      \"name\": \"{}\",", m.signature.preferred_name());
        println!("      \"library\": \"{}\",", m.signature.library);
        println!("      \"confidence\": {:.3},", m.confidence);
        if let Some(doc) = &m.signature.doc {
            println!("      \"description\": \"{}\"", doc);
        }
        println!("    }}{}", comma);
    }
    println!("  ],");
    println!("  \"total\": {}", matches.len());
    println!("}}");
}

fn print_scan_result(arch_str: &str, confidence: f32, matches: &[hexray_signatures::MatchResult]) {
    println!("Function Signature Scan ({})", arch_str);
    println!("{}", "=".repeat(60));
    println!("Min confidence: {:.2}", confidence);
    println!();

    if matches.is_empty() {
        println!("No matching signatures found.");
        println!();
        println!("Tips:");
        println!("  - Try lowering the confidence threshold (-c 0.3)");
        println!("  - The binary may use different library versions");
        println!("  - Functions may be inlined or optimized differently");
    } else {
        println!(
            "{:<16} {:<24} {:<12} {:<8}",
            "Address", "Function", "Library", "Conf"
        );
        println!("{}", "-".repeat(60));

        for m in matches {
            println!(
                "{:#016x} {:<24} {:<12} {:.2}",
                m.offset,
                m.signature.preferred_name(),
                &m.signature.library,
                m.confidence
            );
        }

        println!();
        println!("Found {} potential library function(s)", matches.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexray_core::{Bitness, Endianness, SymbolBinding, SymbolKind};
    use hexray_formats::Section;

    struct TestBinary {
        sections: Vec<TestSection>,
        symbols: Vec<Symbol>,
    }

    struct TestSection {
        name: &'static str,
        address: u64,
        data: Vec<u8>,
        executable: bool,
    }

    impl BinaryFormat for TestBinary {
        fn architecture(&self) -> Architecture {
            Architecture::X86_64
        }

        fn endianness(&self) -> Endianness {
            Endianness::Little
        }

        fn bitness(&self) -> Bitness {
            Bitness::Bits64
        }

        fn entry_point(&self) -> Option<u64> {
            None
        }

        fn executable_sections(&self) -> Box<dyn Iterator<Item = &dyn Section> + '_> {
            Box::new(
                self.sections
                    .iter()
                    .filter(|section| section.executable)
                    .map(|section| section as &dyn Section),
            )
        }

        fn sections(&self) -> Box<dyn Iterator<Item = &dyn Section> + '_> {
            Box::new(self.sections.iter().map(|section| section as &dyn Section))
        }

        fn symbols(&self) -> Box<dyn Iterator<Item = &Symbol> + '_> {
            Box::new(self.symbols.iter())
        }

        fn symbol_at(&self, addr: u64) -> Option<&Symbol> {
            self.symbols.iter().find(|symbol| symbol.address == addr)
        }

        fn bytes_at(&self, addr: u64, len: usize) -> Option<&[u8]> {
            let section = self.section_containing(addr)?;
            let start = usize::try_from(addr.checked_sub(section.virtual_address())?).ok()?;
            section.data().get(start..start.checked_add(len)?)
        }

        fn section_containing(&self, addr: u64) -> Option<&dyn Section> {
            self.sections
                .iter()
                .find(|section| {
                    let start = section.address;
                    let end = start.saturating_add(section.data.len() as u64);
                    addr >= start && addr < end
                })
                .map(|section| section as &dyn Section)
        }
    }

    impl Section for TestSection {
        fn name(&self) -> &str {
            self.name
        }

        fn virtual_address(&self) -> u64 {
            self.address
        }

        fn size(&self) -> u64 {
            self.data.len() as u64
        }

        fn data(&self) -> &[u8] {
            &self.data
        }

        fn is_executable(&self) -> bool {
            self.executable
        }

        fn is_writable(&self) -> bool {
            false
        }

        fn is_allocated(&self) -> bool {
            true
        }
    }

    #[test]
    fn scan_is_anchored_to_function_symbol_starts() {
        let mut false_positive = vec![0x90; 4];
        false_positive.extend_from_slice(&[
            0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x08, 0x48, 0x85, 0xFF, 0x74,
        ]);

        let binary = TestBinary {
            sections: vec![
                TestSection {
                    name: ".text.false_positive",
                    address: 0x1000,
                    data: false_positive,
                    executable: true,
                },
                TestSection {
                    name: ".text.real_match",
                    address: 0x2000,
                    data: vec![
                        0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x08, 0x48, 0x85, 0xFF,
                        0x74,
                    ],
                    executable: true,
                },
            ],
            symbols: vec![
                Symbol {
                    name: "not_free".to_string(),
                    address: 0x1000,
                    size: 17,
                    kind: SymbolKind::Function,
                    binding: SymbolBinding::Global,
                    section_index: Some(1),
                },
                Symbol {
                    name: "real_free".to_string(),
                    address: 0x2000,
                    size: 13,
                    kind: SymbolKind::Function,
                    binding: SymbolBinding::Global,
                    section_index: Some(2),
                },
            ],
        };

        let db = sig_builtin::load_x86_64();
        let matcher = SignatureMatcher::new(&db).with_min_confidence(0.5);
        let matches = scan_function_symbols(&binary, &matcher);

        assert!(!matches.iter().any(|m| m.offset == 0x1004));
        assert!(matches
            .iter()
            .any(|m| m.offset == 0x2000 && m.signature.name == "free"));
    }

    #[test]
    fn scan_recovers_matches_from_stripped_endbr_starts() {
        let binary = TestBinary {
            sections: vec![TestSection {
                name: ".text",
                address: 0x2000,
                data: vec![
                    0xF3, 0x0F, 0x1E, 0xFA, 0x8B, 0x15, 0x10, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x05,
                    0x20, 0x00, 0x00, 0x00, 0x89, 0xD1, 0xF7, 0xD1, 0x81, 0xE1, 0x28, 0x01, 0x00,
                    0x00, 0x74, 0x03, 0xC3, 0x90, 0x90,
                ],
                executable: true,
            }],
            symbols: vec![],
        };

        let db = sig_builtin::load_x86_64();
        let matcher = SignatureMatcher::new(&db).with_min_confidence(0.5);
        let matches = scan_function_symbols(&binary, &matcher);

        assert!(matches
            .iter()
            .any(|m| m.offset == 0x2000 && m.signature.preferred_name() == "strlen"));
    }

    #[test]
    fn parse_confidence_accepts_bounds() {
        assert_eq!(parse_confidence("0.0").unwrap(), 0.0);
        assert_eq!(parse_confidence("0.5").unwrap(), 0.5);
        assert_eq!(parse_confidence("1.0").unwrap(), 1.0);
    }

    #[test]
    fn parse_confidence_rejects_out_of_range_values() {
        assert!(parse_confidence("-0.1").is_err());
        assert!(parse_confidence("1.5").is_err());
    }

    #[test]
    fn parse_signature_arch_accepts_aliases() {
        assert_eq!(parse_signature_arch("x86_64").unwrap(), "x86_64");
        assert_eq!(parse_signature_arch("amd64").unwrap(), "x86_64");
        assert_eq!(parse_signature_arch("arm64").unwrap(), "aarch64");
        assert_eq!(parse_signature_arch("arm64e").unwrap(), "aarch64");
    }

    #[test]
    fn parse_signature_arch_rejects_unknown_values() {
        assert!(parse_signature_arch("riscv64").is_err());
        assert!(parse_signature_arch("not-a-real-arch").is_err());
    }
}
