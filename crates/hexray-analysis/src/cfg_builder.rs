//! Control flow graph construction.

use hexray_core::{BasicBlock, BasicBlockId, BlockTerminator, ControlFlow, ControlFlowGraph, Instruction};
use std::collections::BTreeSet;

/// Builds control flow graphs from disassembled instructions.
pub struct CfgBuilder;

impl CfgBuilder {
    /// Build a CFG from a sequence of instructions.
    ///
    /// The instructions should be from a single function or code region.
    pub fn build(instructions: &[Instruction], entry: u64) -> ControlFlowGraph {
        if instructions.is_empty() {
            let mut cfg = ControlFlowGraph::new(BasicBlockId::ENTRY);
            cfg.add_block(BasicBlock::new(BasicBlockId::ENTRY, entry));
            return cfg;
        }

        // Step 1: Find all leaders (block start addresses)
        let mut leaders = BTreeSet::new();
        leaders.insert(entry);

        for inst in instructions {
            match &inst.control_flow {
                ControlFlow::UnconditionalBranch { target } => {
                    leaders.insert(*target);
                }
                ControlFlow::ConditionalBranch {
                    target,
                    fallthrough,
                    ..
                } => {
                    leaders.insert(*target);
                    leaders.insert(*fallthrough);
                }
                ControlFlow::Call { return_addr, .. } => {
                    leaders.insert(*return_addr);
                }
                ControlFlow::IndirectCall { return_addr } => {
                    leaders.insert(*return_addr);
                }
                ControlFlow::Return | ControlFlow::Halt | ControlFlow::Syscall => {
                    // Next instruction (if any) is a leader
                    if let Some(next) = instructions.iter().find(|i| i.address > inst.address) {
                        leaders.insert(next.address);
                    }
                }
                _ => {}
            }
        }

        // Step 2: Create basic blocks
        let leaders_vec: Vec<_> = leaders.iter().copied().collect();
        let mut address_to_block: std::collections::HashMap<u64, BasicBlockId> =
            std::collections::HashMap::new();
        let mut blocks = Vec::new();

        for (i, &leader) in leaders_vec.iter().enumerate() {
            let block_id = BasicBlockId::new(i as u32);
            address_to_block.insert(leader, block_id);

            let next_leader = leaders_vec.get(i + 1).copied();

            let block_insts: Vec<_> = instructions
                .iter()
                .filter(|inst| {
                    inst.address >= leader && next_leader.map_or(true, |nl| inst.address < nl)
                })
                .cloned()
                .collect();

            let mut block = BasicBlock::new(block_id, leader);
            for inst in block_insts {
                block.push_instruction(inst);
            }
            blocks.push(block);
        }

        // Step 3: Build CFG with edges
        let entry_id = address_to_block.get(&entry).copied().unwrap_or(BasicBlockId::ENTRY);
        let mut cfg = ControlFlowGraph::new(entry_id);

        for mut block in blocks {
            let block_id = block.id;

            // Determine terminator and add edges
            if let Some(last_inst) = block.last_instruction() {
                let terminator = match &last_inst.control_flow {
                    ControlFlow::Sequential => {
                        // Falls through to next block
                        let fallthrough_addr = last_inst.end_address();
                        if let Some(&target_id) = address_to_block.get(&fallthrough_addr) {
                            cfg.add_edge(block_id, target_id);
                            BlockTerminator::Fallthrough { target: target_id }
                        } else {
                            BlockTerminator::Unknown
                        }
                    }
                    ControlFlow::UnconditionalBranch { target } => {
                        if let Some(&target_id) = address_to_block.get(target) {
                            cfg.add_edge(block_id, target_id);
                            BlockTerminator::Jump { target: target_id }
                        } else {
                            BlockTerminator::Unknown
                        }
                    }
                    ControlFlow::ConditionalBranch {
                        target,
                        condition,
                        fallthrough,
                    } => {
                        let true_target = address_to_block.get(target).copied();
                        let false_target = address_to_block.get(fallthrough).copied();

                        if let (Some(true_id), Some(false_id)) = (true_target, false_target) {
                            cfg.add_edge(block_id, true_id);
                            cfg.add_edge(block_id, false_id);
                            BlockTerminator::ConditionalBranch {
                                condition: *condition,
                                true_target: true_id,
                                false_target: false_id,
                            }
                        } else {
                            BlockTerminator::Unknown
                        }
                    }
                    ControlFlow::IndirectBranch { .. } => BlockTerminator::IndirectJump {
                        target: last_inst.operands.first().cloned().unwrap_or(
                            hexray_core::Operand::imm(0, 64),
                        ),
                        possible_targets: vec![],
                    },
                    ControlFlow::Call { return_addr, target } => {
                        if let Some(&return_id) = address_to_block.get(return_addr) {
                            cfg.add_edge(block_id, return_id);
                            BlockTerminator::Call {
                                target: hexray_core::basic_block::CallTarget::Direct(*target),
                                return_block: return_id,
                            }
                        } else {
                            BlockTerminator::Unknown
                        }
                    }
                    ControlFlow::IndirectCall { return_addr } => {
                        if let Some(&return_id) = address_to_block.get(return_addr) {
                            cfg.add_edge(block_id, return_id);
                            BlockTerminator::Call {
                                target: hexray_core::basic_block::CallTarget::Indirect(
                                    last_inst.operands.first().cloned().unwrap_or(
                                        hexray_core::Operand::imm(0, 64),
                                    ),
                                ),
                                return_block: return_id,
                            }
                        } else {
                            BlockTerminator::Unknown
                        }
                    }
                    ControlFlow::Return => BlockTerminator::Return,
                    ControlFlow::Syscall => {
                        // Syscall typically returns
                        let fallthrough_addr = last_inst.end_address();
                        if let Some(&target_id) = address_to_block.get(&fallthrough_addr) {
                            cfg.add_edge(block_id, target_id);
                            BlockTerminator::Fallthrough { target: target_id }
                        } else {
                            BlockTerminator::Unknown
                        }
                    }
                    ControlFlow::Halt => BlockTerminator::Unreachable,
                };
                block.terminator = terminator;
            }

            cfg.add_block(block);
        }

        cfg
    }
}
