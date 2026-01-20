//! Function signature recognition commands.
//!
//! Commands for identifying library functions using signature matching
//! (FLIRT-like functionality).

use anyhow::{bail, Result};
use clap::Subcommand;
use hexray_core::Architecture;
use hexray_formats::BinaryFormat;
use hexray_signatures::{builtin as sig_builtin, SignatureMatcher};

/// Signature management actions.
#[derive(Subcommand)]
pub enum SignaturesAction {
    /// Scan binary for known library functions
    Scan {
        /// Minimum confidence threshold (0.0-1.0)
        #[arg(short, long, default_value = "0.5")]
        confidence: f32,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// List builtin signature databases
    Builtin,
    /// Show signature database statistics
    Stats {
        /// Architecture: x86_64 or aarch64
        #[arg(short, long, default_value = "x86_64")]
        arch: String,
    },
    /// List all signatures in a database
    List {
        /// Architecture: x86_64 or aarch64
        #[arg(short, long, default_value = "x86_64")]
        arch: String,
        /// Filter by library name
        #[arg(short, long)]
        library: Option<String>,
    },
    /// Show details of a specific signature
    Show {
        /// Signature name (e.g., "strlen", "malloc")
        name: String,
        /// Architecture: x86_64 or aarch64
        #[arg(short, long, default_value = "x86_64")]
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

            // Scan all executable sections for function signatures
            let mut matches = Vec::new();

            for section in fmt.sections() {
                if !section.is_executable() {
                    continue;
                }

                let section_data = section.data();
                let section_addr = section.virtual_address();

                if section_data.is_empty() {
                    continue;
                }

                // Scan the section for all matching signatures
                // scan() returns byte offsets, convert to virtual addresses
                for mut m in matcher.scan(section_data) {
                    m.offset += section_addr as usize;
                    matches.push(m);
                }
            }

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
        println!("      \"name\": \"{}\",", m.signature.name);
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
                m.offset, &m.signature.name, &m.signature.library, m.confidence
            );
        }

        println!();
        println!("Found {} potential library function(s)", matches.len());
    }
}
