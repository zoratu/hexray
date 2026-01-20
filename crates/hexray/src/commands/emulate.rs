//! Static emulation commands.
//!
//! Commands for static emulation to resolve indirect branches
//! and trace execution paths.

use anyhow::{bail, Context, Result};
use clap::Subcommand;
use hexray_core::Architecture;
use hexray_disasm::{Disassembler, X86_64Disassembler};
use hexray_emulate::{state::x86_regs, Emulator, EmulatorConfig, Value};
use hexray_formats::BinaryFormat;

/// Static emulation actions.
#[derive(Subcommand)]
pub enum EmulateAction {
    /// Execute from a start address and trace execution path
    Run {
        /// Function or start address
        target: String,
        /// Stop at this address (optional)
        #[arg(long, value_parser = crate::parse_hex)]
        stop_at: Option<u64>,
        /// Maximum number of instructions to execute
        #[arg(short, long, default_value = "1000")]
        max_instructions: usize,
        /// Stop at call instructions
        #[arg(long)]
        stop_at_calls: bool,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Set initial register value (format: rax=0x1234)
        #[arg(short, long)]
        reg: Vec<String>,
    },
    /// Resolve an indirect jump/call by trying multiple input values
    Resolve {
        /// Function containing the indirect branch
        function: String,
        /// Address of the indirect branch instruction
        #[arg(short, long, value_parser = crate::parse_hex)]
        address: u64,
        /// Register containing the index value
        #[arg(short, long)]
        index_register: u16,
        /// Minimum index value to try
        #[arg(long, default_value = "0")]
        min_index: u64,
        /// Maximum index value to try
        #[arg(long, default_value = "32")]
        max_index: u64,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Show the state after execution
    State {
        /// Function or start address
        target: String,
        /// Stop at this address
        #[arg(long, value_parser = crate::parse_hex)]
        stop_at: Option<u64>,
        /// Maximum number of instructions
        #[arg(short, long, default_value = "100")]
        max_instructions: usize,
        /// Set initial register value (format: rax=0x1234)
        #[arg(short, long)]
        reg: Vec<String>,
    },
}

/// Handle emulation commands.
pub fn handle_emulate_command(fmt: &dyn BinaryFormat, action: EmulateAction) -> Result<()> {
    let arch = fmt.architecture();

    // Only support x86_64 for now
    if !matches!(arch, Architecture::X86_64 | Architecture::X86) {
        bail!("Emulation currently only supports x86_64 architecture");
    }

    // Create architecture-specific disassembler
    let disassembler: Box<dyn Disassembler> = match arch {
        Architecture::X86_64 | Architecture::X86 => Box::new(X86_64Disassembler::new()),
        _ => bail!("Unsupported architecture for emulation: {:?}", arch),
    };

    // Helper to resolve function target
    let resolve_function = |target: &str| -> Result<(u64, usize)> {
        // Try parsing as hex address
        if let Ok(addr) = u64::from_str_radix(target.strip_prefix("0x").unwrap_or(target), 16) {
            for section in fmt.sections() {
                let start = section.virtual_address();
                let end = start + section.data().len() as u64;
                if addr >= start && addr < end {
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

    // Helper to get instructions for a function
    let get_instructions =
        |start_addr: u64, size: usize| -> Result<Vec<hexray_core::Instruction>> {
            for section in fmt.sections() {
                let section_start = section.virtual_address();
                let section_data = section.data();
                let section_end = section_start + section_data.len() as u64;

                if start_addr >= section_start && start_addr < section_end {
                    let offset = (start_addr - section_start) as usize;
                    let available = section_data.len() - offset;
                    let func_size = size.min(available);
                    let func_data = &section_data[offset..offset + func_size];

                    let results = disassembler.disassemble_block(func_data, start_addr);
                    let instructions: Vec<_> = results.into_iter().filter_map(|r| r.ok()).collect();

                    if instructions.is_empty() {
                        bail!("Failed to disassemble function at {:#x}", start_addr);
                    }

                    return Ok(instructions);
                }
            }

            bail!(
                "Function at {:#x} not found in executable sections",
                start_addr
            );
        };

    // Helper to parse register assignment (e.g., "rax=0x1234")
    let parse_reg_assignment = |s: &str| -> Result<(u16, u64)> {
        let parts: Vec<&str> = s.split('=').collect();
        if parts.len() != 2 {
            bail!("Invalid register assignment: {}. Use format: rax=0x1234", s);
        }
        let reg_name = parts[0].to_lowercase();
        let reg_id = match reg_name.as_str() {
            "rax" | "eax" => x86_regs::RAX,
            "rcx" | "ecx" => x86_regs::RCX,
            "rdx" | "edx" => x86_regs::RDX,
            "rbx" | "ebx" => x86_regs::RBX,
            "rsp" | "esp" => x86_regs::RSP,
            "rbp" | "ebp" => x86_regs::RBP,
            "rsi" | "esi" => x86_regs::RSI,
            "rdi" | "edi" => x86_regs::RDI,
            "r8" => x86_regs::R8,
            "r9" => x86_regs::R9,
            "r10" => x86_regs::R10,
            "r11" => x86_regs::R11,
            "r12" => x86_regs::R12,
            "r13" => x86_regs::R13,
            "r14" => x86_regs::R14,
            "r15" => x86_regs::R15,
            _ => bail!("Unknown register: {}", reg_name),
        };
        let value = u64::from_str_radix(parts[1].strip_prefix("0x").unwrap_or(parts[1]), 16)
            .with_context(|| format!("Invalid hex value: {}", parts[1]))?;
        Ok((reg_id, value))
    };

    match action {
        EmulateAction::Run {
            target,
            stop_at,
            max_instructions,
            stop_at_calls,
            json,
            reg,
        } => {
            let (func_addr, func_size) = resolve_function(&target)?;
            let instructions = get_instructions(func_addr, func_size)?;

            // Create emulator with config
            let config = EmulatorConfig {
                max_instructions,
                stop_at_calls,
                stop_at_returns: true,
                stop_addresses: stop_at.into_iter().collect(),
                detect_loops: true,
                max_loop_iterations: 100,
            };
            let mut emu = Emulator::new(config);

            // Load code section into emulator memory
            for section in fmt.sections() {
                if section.is_executable() {
                    emu.load_memory(section.virtual_address(), section.data());
                }
            }

            // Set initial register values
            for reg_str in &reg {
                let (reg_id, value) = parse_reg_assignment(reg_str)?;
                emu.set_register(reg_id, value);
            }

            // Execute
            let result = emu.execute(&instructions)?;

            if json {
                print_run_result_json(&result, &instructions);
            } else {
                print_run_result(&result, &instructions);
            }
        }

        EmulateAction::Resolve {
            function,
            address,
            index_register,
            min_index,
            max_index,
            json,
        } => {
            let (func_addr, func_size) = resolve_function(&function)?;
            let instructions = get_instructions(func_addr, func_size)?;

            // Create emulator
            let config = EmulatorConfig {
                max_instructions: 1000,
                stop_at_calls: true,
                stop_at_returns: true,
                stop_addresses: Default::default(),
                detect_loops: true,
                max_loop_iterations: 100,
            };
            let mut emu = Emulator::new(config);

            // Load code section
            for section in fmt.sections() {
                if section.is_executable() {
                    emu.load_memory(section.virtual_address(), section.data());
                }
            }

            // Resolve the indirect branch
            let targets =
                emu.resolve_indirect(&instructions, address, index_register, min_index, max_index);

            if json {
                print_resolve_result_json(address, index_register, min_index, max_index, &targets);
            } else {
                print_resolve_result(fmt, address, index_register, min_index, max_index, &targets);
            }
        }

        EmulateAction::State {
            target,
            stop_at,
            max_instructions,
            reg,
        } => {
            let (func_addr, func_size) = resolve_function(&target)?;
            let instructions = get_instructions(func_addr, func_size)?;

            // Create emulator
            let config = EmulatorConfig {
                max_instructions,
                stop_at_calls: true,
                stop_at_returns: true,
                stop_addresses: stop_at.into_iter().collect(),
                detect_loops: true,
                max_loop_iterations: 100,
            };
            let mut emu = Emulator::new(config);

            // Load code section
            for section in fmt.sections() {
                if section.is_executable() {
                    emu.load_memory(section.virtual_address(), section.data());
                }
            }

            // Set initial register values
            for reg_str in &reg {
                let (reg_id, value) = parse_reg_assignment(reg_str)?;
                emu.set_register(reg_id, value);
            }

            // Execute
            let result = emu.execute(&instructions)?;

            print_state_result(&result);
        }
    }

    Ok(())
}

fn print_run_result_json(
    result: &hexray_emulate::ExecutionResult,
    _instructions: &[hexray_core::Instruction],
) {
    println!("{{");
    println!("  \"instruction_count\": {},", result.instruction_count);
    println!("  \"stop_reason\": \"{:?}\",", result.stop_reason);
    println!("  \"path\": [");
    for (i, addr) in result.path.iter().enumerate() {
        let comma = if i < result.path.len() - 1 { "," } else { "" };
        println!("    \"{:#x}\"{}", addr, comma);
    }
    println!("  ],");
    println!("  \"indirect_targets\": [");
    for (i, target) in result.indirect_targets.iter().enumerate() {
        let comma = if i < result.indirect_targets.len() - 1 {
            ","
        } else {
            ""
        };
        println!(
            "    {{ \"address\": \"{:#x}\", \"targets\": {:?} }}{}",
            target.instruction_address, target.targets, comma
        );
    }
    println!("  ]");
    println!("}}");
}

fn print_run_result(
    result: &hexray_emulate::ExecutionResult,
    instructions: &[hexray_core::Instruction],
) {
    println!("Emulation Results");
    println!("=================");
    println!("Instructions executed: {}", result.instruction_count);
    println!("Stop reason: {:?}", result.stop_reason);
    println!("\nExecution path ({} addresses):", result.path.len());
    for (i, addr) in result.path.iter().enumerate().take(50) {
        // Find instruction at this address
        if let Some(inst) = instructions.iter().find(|i| i.address == *addr) {
            println!("  {}: {:#x}  {}", i, addr, inst.mnemonic);
        } else {
            println!("  {}: {:#x}", i, addr);
        }
    }
    if result.path.len() > 50 {
        println!("  ... ({} more)", result.path.len() - 50);
    }
    if !result.indirect_targets.is_empty() {
        println!("\nResolved indirect targets:");
        for target in &result.indirect_targets {
            println!(
                "  {:#x} -> {:?}",
                target.instruction_address, target.targets
            );
        }
    }
}

fn print_resolve_result_json(
    address: u64,
    index_register: u16,
    min_index: u64,
    max_index: u64,
    targets: &[u64],
) {
    println!("{{");
    println!("  \"address\": \"{:#x}\",", address);
    println!("  \"index_register\": {},", index_register);
    println!("  \"min_index\": {},", min_index);
    println!("  \"max_index\": {},", max_index);
    println!("  \"targets\": [");
    for (i, t) in targets.iter().enumerate() {
        let comma = if i < targets.len() - 1 { "," } else { "" };
        println!("    \"{:#x}\"{}", t, comma);
    }
    println!("  ]");
    println!("}}");
}

fn print_resolve_result(
    fmt: &dyn BinaryFormat,
    address: u64,
    index_register: u16,
    min_index: u64,
    max_index: u64,
    targets: &[u64],
) {
    println!("Indirect Branch Resolution");
    println!("==========================");
    println!("Address:        {:#x}", address);
    println!("Index register: {}", x86_regs::name(index_register));
    println!("Index range:    {} - {}", min_index, max_index);
    println!("\nResolved targets ({}):", targets.len());
    for (i, t) in targets.iter().enumerate() {
        // Try to find symbol for target
        let sym_name = fmt
            .symbols()
            .find(|s| s.address == *t)
            .map(|s| s.name.clone())
            .unwrap_or_default();
        if !sym_name.is_empty() {
            println!("  {}: {:#x} ({})", i, t, sym_name);
        } else {
            println!("  {}: {:#x}", i, t);
        }
    }
}

fn print_state_result(result: &hexray_emulate::ExecutionResult) {
    println!("Machine State After Emulation");
    println!("=============================");
    println!("Instructions executed: {}", result.instruction_count);
    println!("Stop reason: {:?}", result.stop_reason);
    println!("\nRegister state:");
    for (name, id) in [
        ("rax", x86_regs::RAX),
        ("rcx", x86_regs::RCX),
        ("rdx", x86_regs::RDX),
        ("rbx", x86_regs::RBX),
        ("rsp", x86_regs::RSP),
        ("rbp", x86_regs::RBP),
        ("rsi", x86_regs::RSI),
        ("rdi", x86_regs::RDI),
        ("r8", x86_regs::R8),
        ("r9", x86_regs::R9),
        ("r10", x86_regs::R10),
        ("r11", x86_regs::R11),
        ("r12", x86_regs::R12),
        ("r13", x86_regs::R13),
        ("r14", x86_regs::R14),
        ("r15", x86_regs::R15),
    ] {
        let value = result.state.get_register(id);
        match value {
            Value::Concrete(v) => println!("  {:4}: {:#018x}", name, v),
            Value::Unknown => println!("  {:4}: <unknown>", name),
            Value::Symbolic(sym) => println!("  {:4}: <symbolic:{}>", name, sym.0),
        }
    }
    println!("\nFlags:");
    let flags = &result.state.flags;
    println!(
        "  CF: {:?}  ZF: {:?}  SF: {:?}",
        flags.cf, flags.zf, flags.sf
    );
    println!(
        "  OF: {:?}  PF: {:?}  AF: {:?}",
        flags.of, flags.pf, flags.af
    );
}
