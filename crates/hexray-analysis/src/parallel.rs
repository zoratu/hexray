//! Parallel processing utilities for analysis.
//!
//! This module provides utilities for parallel disassembly and analysis
//! of multiple functions using rayon.

use std::collections::HashSet;

use rayon::prelude::*;

use hexray_core::Instruction;
use hexray_disasm::Disassembler;

/// Result of disassembling a single function.
#[derive(Debug)]
pub struct DisassembledFunction {
    /// Entry address of the function.
    pub entry: u64,
    /// Disassembled instructions.
    pub instructions: Vec<Instruction>,
}

/// Information about a function to disassemble.
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    /// Entry address.
    pub address: u64,
    /// Function size in bytes.
    pub size: usize,
    /// Raw bytes to disassemble.
    pub bytes: Vec<u8>,
    /// Whether the byte range is a heuristic fallback rather than known bounds.
    pub heuristic_bounds: bool,
}

/// Disassemble multiple functions in parallel.
///
/// Takes a list of function information and a disassembler, and returns
/// the disassembled instructions for each function.
///
/// # Example
/// ```ignore
/// use hexray_analysis::parallel::{disassemble_functions_parallel, FunctionInfo};
/// use hexray_disasm::X86_64Disassembler;
///
/// let functions = vec![
///     FunctionInfo { address: 0x1000, size: 100, bytes: vec![...], heuristic_bounds: false },
///     FunctionInfo { address: 0x2000, size: 200, bytes: vec![...], heuristic_bounds: false },
/// ];
///
/// let disasm = X86_64Disassembler::new();
/// let results = disassemble_functions_parallel(&functions, &disasm, &HashSet::new());
/// ```
pub fn disassemble_functions_parallel<D>(
    functions: &[FunctionInfo],
    disasm: &D,
    noreturn_targets: &HashSet<u64>,
) -> Vec<DisassembledFunction>
where
    D: Disassembler + Sync,
{
    functions
        .par_iter()
        .map(|func| {
            let instructions = disassemble_function(
                disasm,
                &func.bytes,
                func.address,
                func.heuristic_bounds,
                noreturn_targets,
            );
            DisassembledFunction {
                entry: func.address,
                instructions,
            }
        })
        .collect()
}

/// Disassemble a single function.
fn disassemble_function<D: Disassembler>(
    disasm: &D,
    bytes: &[u8],
    start_addr: u64,
    heuristic_bounds: bool,
    noreturn_targets: &HashSet<u64>,
) -> Vec<Instruction> {
    let mut instructions = Vec::new();
    let mut offset = 0;

    // Limit to 500 instructions to prevent runaway disassembly
    while offset < bytes.len() && instructions.len() < 500 {
        let remaining = &bytes[offset..];
        let addr = start_addr + offset as u64;

        match disasm.decode_instruction(remaining, addr) {
            Ok(decoded) => {
                let is_ret = decoded.instruction.is_return();
                let is_halt = matches!(
                    decoded.instruction.control_flow,
                    hexray_core::ControlFlow::Halt
                );
                let is_heuristic_tail_jump = heuristic_bounds
                    && matches!(
                        decoded.instruction.control_flow,
                        hexray_core::ControlFlow::UnconditionalBranch { .. }
                    );
                let is_noreturn_call = heuristic_bounds
                    && matches!(
                        decoded.instruction.control_flow,
                        hexray_core::ControlFlow::Call { target, .. }
                            if noreturn_targets.contains(&target)
                    );
                instructions.push(decoded.instruction);
                offset += decoded.size;

                if is_halt || is_noreturn_call || is_heuristic_tail_jump {
                    break;
                }

                // Exact symbol bounds should keep scanning across early returns
                // so later cold/error blocks still contribute call edges.
                if heuristic_bounds && is_ret {
                    break;
                }
            }
            Err(_) => {
                offset += disasm.min_instruction_size().max(1);
            }
        }
    }

    instructions
}

/// Parallel call graph builder that processes functions in parallel.
pub struct ParallelCallGraphBuilder;

impl ParallelCallGraphBuilder {
    /// Build a call graph from functions, disassembling in parallel.
    pub fn build<D>(
        functions: &[FunctionInfo],
        disasm: &D,
        symbols: &[hexray_core::Symbol],
    ) -> crate::CallGraph
    where
        D: Disassembler + Sync,
    {
        let noreturn_targets: HashSet<u64> = symbols
            .iter()
            .filter(|symbol| crate::is_noreturn_function_name(&symbol.name))
            .map(|symbol| symbol.address)
            .collect();

        // Disassemble all functions in parallel
        let disassembled = disassemble_functions_parallel(functions, disasm, &noreturn_targets);

        // Build the call graph sequentially (shared state)
        let mut builder = crate::CallGraphBuilder::new();
        builder.add_symbols(symbols);

        for func in disassembled {
            builder.add_function(func.entry, func.instructions);
        }

        builder.build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexray_core::ControlFlow;
    use hexray_disasm::X86_64Disassembler;
    use std::collections::HashSet;

    #[test]
    fn test_function_info() {
        let info = FunctionInfo {
            address: 0x1000,
            size: 100,
            bytes: vec![0x90; 100], // NOP sled
            heuristic_bounds: false,
        };
        assert_eq!(info.address, 0x1000);
        assert_eq!(info.size, 100);
        assert!(!info.heuristic_bounds);
    }

    #[test]
    fn test_disassembled_function() {
        let func = DisassembledFunction {
            entry: 0x1000,
            instructions: vec![],
        };
        assert_eq!(func.entry, 0x1000);
        assert!(func.instructions.is_empty());
    }

    #[test]
    fn exact_sized_parallel_disassembly_keeps_scanning_past_return() {
        let bytes = vec![
            0xf3, 0x0f, 0x1e, 0xfa, // endbr64
            0xc3, // ret
            0xe8, 0x00, 0x00, 0x00, 0x00, // call 0x100a
            0xc3, // ret
        ];
        let disasm = X86_64Disassembler::new();

        let instructions = disassemble_function(&disasm, &bytes, 0x1000, false, &HashSet::new());

        assert_eq!(instructions.len(), 4);
        assert_eq!(instructions[0].mnemonic, "endbr64");
        assert_eq!(instructions[1].mnemonic, "ret");
        assert_eq!(instructions[2].mnemonic, "call");
        assert_eq!(instructions[3].mnemonic, "ret");
        assert!(matches!(
            instructions[2].control_flow,
            ControlFlow::Call { target: 0x100a, .. }
        ));
    }
}
