//! Data flow trace commands.
//!
//! Commands for tracing values through the program to understand
//! where values come from and where they go.

use anyhow::{bail, Result};
use clap::Subcommand;
use hexray_analysis::{collect_noreturn_targets, CfgBuilder, DataFlowQuery, DataFlowQueryEngine};
use hexray_core::Architecture;
use hexray_disasm::{Arm64Disassembler, Disassembler, RiscVDisassembler, X86_64Disassembler};
use hexray_formats::BinaryFormat;

fn parse_register_id(arch: Architecture, value: &str) -> Result<u16> {
    if let Ok(register_id) = value.parse::<u16>() {
        return Ok(register_id);
    }

    let normalized = value.trim().to_ascii_lowercase();
    let register_id = match arch {
        Architecture::X86_64 | Architecture::X86 => match normalized.as_str() {
            "rax" => 0,
            "rcx" => 1,
            "rdx" => 2,
            "rbx" => 3,
            "rsp" => 4,
            "rbp" => 5,
            "rsi" => 6,
            "rdi" => 7,
            "r8" => 8,
            "r9" => 9,
            "r10" => 10,
            "r11" => 11,
            "r12" => 12,
            "r13" => 13,
            "r14" => 14,
            "r15" => 15,
            _ => bail!("Unknown x86_64 register '{}'", value),
        },
        Architecture::Arm64 => {
            if normalized == "sp" {
                31
            } else if let Some(index) = normalized.strip_prefix('x') {
                index
                    .parse::<u16>()
                    .ok()
                    .filter(|idx| *idx <= 30)
                    .ok_or_else(|| anyhow::anyhow!("Unknown AArch64 register '{}'", value))?
            } else {
                bail!("Unknown AArch64 register '{}'", value);
            }
        }
        _ => bail!(
            "Register names are not supported for architecture {:?}; pass a numeric register id",
            arch
        ),
    };

    Ok(register_id)
}

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
        register: String,
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
        register: String,
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
        register: String,
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
        register: String,
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
    let resolve_function = |target: &str| -> Result<(u64, usize, bool)> {
        // Try parsing as hex address
        if let Ok(addr) = u64::from_str_radix(target.strip_prefix("0x").unwrap_or(target), 16) {
            // Find section containing this address
            for section in fmt.sections() {
                let start = section.virtual_address();
                let end = start + section.data().len() as u64;
                if addr >= start && addr < end {
                    // Estimate function size (simple heuristic: until next symbol or 4KB)
                    return Ok((addr, 4096, true));
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
                return Ok((sym.address, size, sym.size == 0));
            }
        }

        bail!("Symbol '{}' not found", target);
    };

    // Helper to build CFG for a function
    let build_cfg = |start_addr: u64,
                     size: usize,
                     heuristic_bounds: bool|
     -> Result<hexray_core::ControlFlowGraph> {
        // Find section containing the function
        let noreturn_targets = collect_noreturn_targets(fmt.symbols());

        for section in fmt.sections() {
            let section_start = section.virtual_address();
            let section_data = section.data();
            let section_end = section_start + section_data.len() as u64;

            if start_addr >= section_start && start_addr < section_end {
                let offset = (start_addr - section_start) as usize;
                let available = section_data.len() - offset;
                let func_size = size.min(available);
                let func_data = &section_data[offset..offset + func_size];

                // Heuristic windows must stop at a return or known noreturn call
                // to avoid decoding into the next function.
                let mut instructions = Vec::new();
                let mut inst_offset = 0usize;
                while inst_offset < func_data.len() && instructions.len() < 2000 {
                    let remaining = &func_data[inst_offset..];
                    let addr = start_addr + inst_offset as u64;

                    match disassembler.decode_instruction(remaining, addr) {
                        Ok(decoded) => {
                            let is_ret = decoded.instruction.is_return();
                            let is_noreturn_call = matches!(
                                decoded.instruction.control_flow,
                                hexray_core::ControlFlow::Call { target, .. }
                                    if noreturn_targets.contains(&target)
                            );

                            instructions.push(decoded.instruction);
                            inst_offset += decoded.size;

                            if heuristic_bounds && (is_ret || is_noreturn_call) {
                                break;
                            }
                            if !heuristic_bounds && is_ret && inst_offset >= func_data.len() / 2 {
                                break;
                            }
                        }
                        Err(_) => {
                            inst_offset += disassembler.min_instruction_size().max(1);
                        }
                    }
                }

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
            let register = parse_register_id(arch, &register)?;
            let (func_addr, func_size, heuristic_bounds) = resolve_function(&function)?;
            let cfg = build_cfg(func_addr, func_size, heuristic_bounds)?;

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
            let register = parse_register_id(arch, &register)?;
            let (func_addr, func_size, heuristic_bounds) = resolve_function(&function)?;
            let cfg = build_cfg(func_addr, func_size, heuristic_bounds)?;

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
            let register = parse_register_id(arch, &register)?;
            let (func_addr, func_size, heuristic_bounds) = resolve_function(&function)?;
            let cfg = build_cfg(func_addr, func_size, heuristic_bounds)?;

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
            let register = parse_register_id(arch, &register)?;
            let (func_addr, func_size, heuristic_bounds) = resolve_function(&function)?;
            let cfg = build_cfg(func_addr, func_size, heuristic_bounds)?;

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

#[cfg(test)]
mod tests {
    use super::parse_register_id;
    use hexray_core::Architecture;

    #[test]
    fn test_parse_trace_register_accepts_numeric_ids() {
        assert_eq!(parse_register_id(Architecture::X86_64, "7").unwrap(), 7);
    }

    #[test]
    fn test_parse_trace_register_accepts_x86_register_names() {
        assert_eq!(parse_register_id(Architecture::X86_64, "rdi").unwrap(), 7);
        assert_eq!(parse_register_id(Architecture::X86_64, "RAX").unwrap(), 0);
    }

    #[test]
    fn test_parse_trace_register_accepts_aarch64_register_names() {
        assert_eq!(parse_register_id(Architecture::Arm64, "x30").unwrap(), 30);
        assert_eq!(parse_register_id(Architecture::Arm64, "sp").unwrap(), 31);
    }
}
