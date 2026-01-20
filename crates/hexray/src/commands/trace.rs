//! Data flow trace commands.
//!
//! Commands for tracing values through the program to understand
//! where values come from and where they go.

use anyhow::{bail, Result};
use clap::Subcommand;
use hexray_analysis::{CfgBuilder, DataFlowQuery, DataFlowQueryEngine};
use hexray_core::Architecture;
use hexray_disasm::{Arm64Disassembler, Disassembler, RiscVDisassembler, X86_64Disassembler};
use hexray_formats::BinaryFormat;

/// Data flow trace actions.
#[derive(Subcommand)]
pub enum TraceAction {
    /// Trace value backwards: where did it come from?
    Backward {
        /// Function to analyze (symbol name or address)
        function: String,
        /// Address where value is used (hex)
        #[arg(short, long, value_parser = crate::parse_hex)]
        address: u64,
        /// Register ID to trace
        #[arg(short, long)]
        register: u16,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Trace value forwards: where does it go?
    Forward {
        /// Function to analyze (symbol name or address)
        function: String,
        /// Address where value is defined (hex)
        #[arg(short, long, value_parser = crate::parse_hex)]
        address: u64,
        /// Register ID to trace
        #[arg(short, long)]
        register: u16,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Find all uses of a value defined at an address
    Uses {
        /// Function to analyze (symbol name or address)
        function: String,
        /// Address where value is defined (hex)
        #[arg(short, long, value_parser = crate::parse_hex)]
        address: u64,
        /// Register ID
        #[arg(short, long)]
        register: u16,
    },
    /// Find all definitions reaching a use
    Defs {
        /// Function to analyze (symbol name or address)
        function: String,
        /// Address where value is used (hex)
        #[arg(short, long, value_parser = crate::parse_hex)]
        address: u64,
        /// Register ID
        #[arg(short, long)]
        register: u16,
    },
}

/// Handle data flow trace commands.
pub fn handle_trace_command(fmt: &dyn BinaryFormat, action: TraceAction) -> Result<()> {
    let arch = fmt.architecture();

    // Create architecture-specific disassembler
    let disassembler: Box<dyn Disassembler> = match arch {
        Architecture::X86_64 | Architecture::X86 => Box::new(X86_64Disassembler::new()),
        Architecture::Arm64 => Box::new(Arm64Disassembler::new()),
        Architecture::RiscV64 | Architecture::RiscV32 => Box::new(RiscVDisassembler::new()),
        _ => bail!("Unsupported architecture for trace: {:?}", arch),
    };

    // Helper to resolve function target
    let resolve_function = |target: &str| -> Result<(u64, usize)> {
        // Try parsing as hex address
        if let Ok(addr) = u64::from_str_radix(target.strip_prefix("0x").unwrap_or(target), 16) {
            // Find section containing this address
            for section in fmt.sections() {
                let start = section.virtual_address();
                let end = start + section.data().len() as u64;
                if addr >= start && addr < end {
                    // Estimate function size (simple heuristic: until next symbol or 4KB)
                    return Ok((addr, 4096));
                }
            }
            bail!("Address {:#x} not found in any section", addr);
        }

        // Try as symbol name
        for sym in fmt.symbols() {
            if sym.name == target {
                let size = if sym.size > 0 {
                    sym.size as usize
                } else {
                    4096
                };
                return Ok((sym.address, size));
            }
        }

        bail!("Symbol '{}' not found", target);
    };

    // Helper to build CFG for a function
    let build_cfg = |start_addr: u64, size: usize| -> Result<hexray_core::ControlFlowGraph> {
        // Find section containing the function
        for section in fmt.sections() {
            let section_start = section.virtual_address();
            let section_data = section.data();
            let section_end = section_start + section_data.len() as u64;

            if start_addr >= section_start && start_addr < section_end {
                let offset = (start_addr - section_start) as usize;
                let available = section_data.len() - offset;
                let func_size = size.min(available);
                let func_data = &section_data[offset..offset + func_size];

                // Disassemble the function bytes
                let results = disassembler.disassemble_block(func_data, start_addr);
                let instructions: Vec<_> = results.into_iter().filter_map(|r| r.ok()).collect();

                if instructions.is_empty() {
                    bail!("Failed to disassemble function at {:#x}", start_addr);
                }

                // Build CFG from instructions
                let cfg = CfgBuilder::build(&instructions, start_addr);
                return Ok(cfg);
            }
        }

        bail!(
            "Function at {:#x} not found in executable sections",
            start_addr
        );
    };

    match action {
        TraceAction::Backward {
            function,
            address,
            register,
            json,
        } => {
            let (func_addr, func_size) = resolve_function(&function)?;
            let cfg = build_cfg(func_addr, func_size)?;

            let engine = DataFlowQueryEngine::new(&cfg);
            let query = DataFlowQuery::TraceBackward {
                address,
                register_id: register,
            };
            let result = engine.query(&query);

            if json {
                print_trace_result_json(&result);
            } else {
                println!("{}", result);
            }
        }

        TraceAction::Forward {
            function,
            address,
            register,
            json,
        } => {
            let (func_addr, func_size) = resolve_function(&function)?;
            let cfg = build_cfg(func_addr, func_size)?;

            let engine = DataFlowQueryEngine::new(&cfg);
            let query = DataFlowQuery::TraceForward {
                address,
                register_id: register,
            };
            let result = engine.query(&query);

            if json {
                print_trace_result_json(&result);
            } else {
                println!("{}", result);
            }
        }

        TraceAction::Uses {
            function,
            address,
            register,
        } => {
            let (func_addr, func_size) = resolve_function(&function)?;
            let cfg = build_cfg(func_addr, func_size)?;

            let engine = DataFlowQueryEngine::new(&cfg);
            let query = DataFlowQuery::FindUses {
                def_address: address,
                register_id: register,
            };
            let result = engine.query(&query);

            println!("{}", result);
        }

        TraceAction::Defs {
            function,
            address,
            register,
        } => {
            let (func_addr, func_size) = resolve_function(&function)?;
            let cfg = build_cfg(func_addr, func_size)?;

            let engine = DataFlowQueryEngine::new(&cfg);
            let query = DataFlowQuery::FindDefs {
                use_address: address,
                register_id: register,
            };
            let result = engine.query(&query);

            println!("{}", result);
        }
    }

    Ok(())
}

fn print_trace_result_json(result: &hexray_analysis::DataFlowResult) {
    println!("{{");
    println!("  \"complete\": {},", result.complete);
    println!("  \"steps\": [");
    for (i, step) in result.steps.iter().enumerate() {
        let comma = if i < result.steps.len() - 1 { "," } else { "" };
        println!("    {{");
        println!("      \"address\": \"{:#x}\",", step.address);
        println!(
            "      \"instruction\": \"{}\",",
            step.instruction.replace('\"', "\\\"")
        );
        println!("      \"role\": \"{}\",", step.role);
        if let Some(desc) = &step.description {
            println!("      \"description\": \"{}\"", desc.replace('\"', "\\\""));
        }
        println!("    }}{}", comma);
    }
    println!("  ],");
    if let Some(reason) = &result.truncation_reason {
        println!("  \"truncation_reason\": \"{}\",", reason);
    }
    println!("  \"total_steps\": {}", result.steps.len());
    println!("}}")
}
