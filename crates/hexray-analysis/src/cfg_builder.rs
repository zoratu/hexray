//! Control flow graph construction.

use crate::decompiler::BinaryDataContext;
use hexray_core::{
    BasicBlock, BasicBlockId, BlockTerminator, ControlFlow, ControlFlowGraph, Instruction, Operand,
    Operation,
};
use std::collections::{BTreeSet, HashMap, HashSet};

/// Builds control flow graphs from disassembled instructions.
pub struct CfgBuilder;

impl CfgBuilder {
    /// Build a CFG from a sequence of instructions, using binary data when
    /// available to recover computed-dispatch tables.
    pub fn build_with_binary_context(
        instructions: &[Instruction],
        entry: u64,
        binary_ctx: &BinaryDataContext,
    ) -> ControlFlowGraph {
        let mut annotated = instructions.to_vec();
        let function_end = annotated
            .iter()
            .map(Instruction::end_address)
            .max()
            .unwrap_or(entry);
        annotate_computed_dispatch_targets(&mut annotated, binary_ctx, entry, function_end);
        Self::build(&annotated, entry)
    }

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
        // Build sorted index once for efficient lookups - O(n log n)
        let mut sorted_indices: Vec<usize> = (0..instructions.len()).collect();
        sorted_indices.sort_by_key(|&i| instructions[i].address);

        let mut leaders = BTreeSet::new();
        leaders.insert(entry);

        for (pos, &idx) in sorted_indices.iter().enumerate() {
            let inst = &instructions[idx];
            match &inst.control_flow {
                ControlFlow::UnconditionalBranch { target } => {
                    leaders.insert(*target);
                    // The instruction after an unconditional branch may be reachable via
                    // another path (e.g., jump table entries), so mark it as a leader too
                    if let Some(&next_idx) = sorted_indices.get(pos + 1) {
                        leaders.insert(instructions[next_idx].address);
                    }
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
                    if let Some(&next_idx) = sorted_indices.get(pos + 1) {
                        if instructions[next_idx].address == *return_addr {
                            leaders.insert(*return_addr);
                        }
                    }
                }
                ControlFlow::IndirectCall { return_addr } => {
                    if let Some(&next_idx) = sorted_indices.get(pos + 1) {
                        if instructions[next_idx].address == *return_addr {
                            leaders.insert(*return_addr);
                        }
                    }
                }
                ControlFlow::IndirectBranch { .. } => {
                    // The instruction after an indirect jump can still be reachable via a
                    // different handler or jump-table entry, so keep it as a leader too.
                    if let Some(&next_idx) = sorted_indices.get(pos + 1) {
                        leaders.insert(instructions[next_idx].address);
                    }
                }
                ControlFlow::Return | ControlFlow::Halt | ControlFlow::Syscall => {
                    // Next instruction (if any) is a leader - O(1) lookup via sorted index
                    if let Some(&next_idx) = sorted_indices.get(pos + 1) {
                        leaders.insert(instructions[next_idx].address);
                    }
                }
                _ => {}
            }
        }

        // Step 2: Create basic blocks (reuses sorted_indices from Step 1)
        let leaders_vec: Vec<_> = leaders.iter().copied().collect();
        let mut address_to_block: HashMap<u64, BasicBlockId> = HashMap::new();
        let mut blocks = Vec::new();

        for (i, &leader) in leaders_vec.iter().enumerate() {
            let block_id = BasicBlockId::new(i as u32);
            address_to_block.insert(leader, block_id);

            let next_leader = leaders_vec.get(i + 1).copied();

            // Use binary search to find instruction range for this block - O(log n) instead of O(n)
            let start_idx =
                sorted_indices.partition_point(|&idx| instructions[idx].address < leader);
            let end_idx = if let Some(nl) = next_leader {
                sorted_indices.partition_point(|&idx| instructions[idx].address < nl)
            } else {
                sorted_indices.len()
            };

            let mut block = BasicBlock::new(block_id, leader);
            for &idx in &sorted_indices[start_idx..end_idx] {
                block.push_instruction(instructions[idx].clone());
            }
            blocks.push(block);
        }

        let instruction_addresses: HashSet<u64> =
            instructions.iter().map(|inst| inst.address).collect();

        // Preserve out-of-range conditional targets as synthetic external blocks
        // so split hot/cold bodies stay visible in the structured output.
        for &idx in &sorted_indices {
            let inst = &instructions[idx];
            let ControlFlow::ConditionalBranch {
                target,
                fallthrough,
                ..
            } = &inst.control_flow
            else {
                continue;
            };

            for branch_target in [*target, *fallthrough] {
                materialize_external_target(
                    branch_target,
                    &instruction_addresses,
                    &mut address_to_block,
                    &mut blocks,
                );
            }
        }

        // Preserve out-of-range indirect dispatch targets as synthetic external blocks.
        for &idx in &sorted_indices {
            let inst = &instructions[idx];
            let ControlFlow::IndirectBranch { possible_targets } = &inst.control_flow else {
                continue;
            };

            for &target in possible_targets {
                materialize_external_target(
                    target,
                    &instruction_addresses,
                    &mut address_to_block,
                    &mut blocks,
                );
            }
        }

        // Step 3: Build CFG with edges
        let entry_id = address_to_block
            .get(&entry)
            .copied()
            .unwrap_or(BasicBlockId::ENTRY);
        let mut indirect_target_blocks = HashMap::new();
        for inst in instructions {
            let ControlFlow::IndirectBranch { possible_targets } = &inst.control_flow else {
                continue;
            };
            for &target in possible_targets {
                if indirect_target_blocks.contains_key(&target) {
                    continue;
                }
                if let Some(target_id) =
                    find_block_id_for_target(target, &blocks, &address_to_block)
                {
                    indirect_target_blocks.insert(target, target_id);
                }
            }
        }
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
                        // Check if this is an unresolved relocation (jump to next instruction)
                        // In kernel modules, `jmp` with 0 offset (e9 00 00 00 00) is typically
                        // a relocation placeholder for __x86_return_thunk
                        let is_unresolved_reloc = *target == last_inst.end_address()
                            && last_inst.bytes.len() >= 5
                            && last_inst.bytes[0] == 0xe9
                            && last_inst.bytes[1..5] == [0, 0, 0, 0];

                        if is_unresolved_reloc {
                            // Treat as a return (likely __x86_return_thunk)
                            BlockTerminator::Return
                        } else if let Some(&target_id) = address_to_block.get(target) {
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
                    ControlFlow::IndirectBranch { possible_targets } => {
                        let mut resolved_targets = Vec::new();
                        let mut seen = HashSet::new();

                        for target in possible_targets {
                            if let Some(&target_id) = indirect_target_blocks.get(target) {
                                cfg.add_edge(block_id, target_id);
                                if seen.insert(target_id) {
                                    resolved_targets.push(target_id);
                                }
                            }
                        }

                        BlockTerminator::IndirectJump {
                            target: last_inst
                                .operands
                                .first()
                                .cloned()
                                .unwrap_or(hexray_core::Operand::imm(0, 64)),
                            possible_targets: resolved_targets,
                        }
                    }
                    ControlFlow::Call {
                        return_addr,
                        target,
                    } => {
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
                                    last_inst
                                        .operands
                                        .first()
                                        .cloned()
                                        .unwrap_or(hexray_core::Operand::imm(0, 64)),
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

const MAX_COMPUTED_DISPATCH_ENTRIES: usize = 256;

#[derive(Debug, Clone, Copy)]
struct DispatchTableAccess {
    table_base: u64,
    entry_size: usize,
}

fn materialize_external_target(
    target: u64,
    instruction_addresses: &HashSet<u64>,
    address_to_block: &mut HashMap<u64, BasicBlockId>,
    blocks: &mut Vec<BasicBlock>,
) {
    if instruction_addresses.contains(&target) {
        return;
    }

    if let Some(block_id) = address_to_block.get(&target).copied() {
        if let Some(block) = blocks.iter_mut().find(|block| block.id == block_id) {
            if block.instructions.is_empty() {
                block.terminator = BlockTerminator::ExternalJump { target };
            }
        }
        return;
    }

    let block_id = BasicBlockId::new(blocks.len() as u32);
    address_to_block.insert(target, block_id);

    let mut block = BasicBlock::new(block_id, target);
    block.terminator = BlockTerminator::ExternalJump { target };
    blocks.push(block);
}

fn find_block_id_for_target(
    target: u64,
    blocks: &[BasicBlock],
    address_to_block: &HashMap<u64, BasicBlockId>,
) -> Option<BasicBlockId> {
    address_to_block.get(&target).copied().or_else(|| {
        blocks
            .iter()
            .find(|block| block.start <= target && target < block.end)
            .map(|block| block.id)
    })
}

/// Recover computed-goto / threaded-VM dispatch targets from pointer tables and
/// store them in each indirect branch's `possible_targets`.
pub fn annotate_computed_dispatch_targets(
    instructions: &mut [Instruction],
    binary_ctx: &BinaryDataContext,
    function_start: u64,
    function_end: u64,
) {
    for branch_index in 0..instructions.len() {
        if !matches!(
            instructions[branch_index].control_flow,
            ControlFlow::IndirectBranch { .. }
        ) {
            continue;
        }

        let targets = resolve_computed_dispatch_targets(
            instructions,
            branch_index,
            binary_ctx,
            function_start,
            function_end,
        );
        if targets.is_empty() {
            continue;
        }

        if let ControlFlow::IndirectBranch { possible_targets } =
            &mut instructions[branch_index].control_flow
        {
            *possible_targets = targets;
        }
    }
}

/// Resolve the target set of an indirect branch whose destination comes from a
/// dispatch table in binary data.
pub fn resolve_computed_dispatch_targets(
    instructions: &[Instruction],
    branch_index: usize,
    binary_ctx: &BinaryDataContext,
    function_start: u64,
    function_end: u64,
) -> Vec<u64> {
    let Some(access) = extract_dispatch_table_access(instructions, branch_index) else {
        return Vec::new();
    };

    read_dispatch_table_targets(binary_ctx, access, function_start, function_end)
}

fn extract_dispatch_table_access(
    instructions: &[Instruction],
    branch_index: usize,
) -> Option<DispatchTableAccess> {
    let branch = instructions.get(branch_index)?;
    let branch_operand = branch.operands.first()?;

    match branch_operand {
        Operand::Memory(mem) => {
            let register_values = track_register_values(instructions, branch_index);
            dispatch_table_access_from_memory(mem, &register_values)
        }
        Operand::Register(target_reg) => {
            for def_index in (0..branch_index).rev() {
                let inst = &instructions[def_index];
                let Some(Operand::Register(dst_reg)) = inst.operands.first() else {
                    continue;
                };
                if dst_reg.id != target_reg.id {
                    continue;
                }
                if !matches!(inst.operation, Operation::Load | Operation::Move) {
                    continue;
                }
                let Some(Operand::Memory(mem)) = inst.operands.get(1) else {
                    continue;
                };
                let register_values = track_register_values(instructions, def_index);
                if let Some(access) = dispatch_table_access_from_memory(mem, &register_values) {
                    return Some(access);
                }
            }
            None
        }
        _ => None,
    }
}

fn dispatch_table_access_from_memory(
    mem: &hexray_core::MemoryRef,
    register_values: &HashMap<u16, u64>,
) -> Option<DispatchTableAccess> {
    let _ = mem.index.as_ref()?;

    let entry_size = usize::from(mem.scale.max(1));
    if !matches!(entry_size, 4 | 8) {
        return None;
    }

    let table_base = resolve_table_base(mem, register_values)?;
    Some(DispatchTableAccess {
        table_base,
        entry_size,
    })
}

fn resolve_table_base(
    mem: &hexray_core::MemoryRef,
    register_values: &HashMap<u16, u64>,
) -> Option<u64> {
    if let Some(base_reg) = &mem.base {
        let base = register_values.get(&base_reg.id).copied()?;
        base.checked_add_signed(mem.displacement)
    } else if mem.displacement >= 0 {
        Some(mem.displacement as u64)
    } else {
        None
    }
}

fn track_register_values(instructions: &[Instruction], end_exclusive: usize) -> HashMap<u16, u64> {
    let mut register_values = HashMap::new();

    for inst in &instructions[..end_exclusive.min(instructions.len())] {
        let tracked_assignment = tracked_register_assignment(inst, &register_values);
        for reg in &inst.writes {
            register_values.remove(&reg.id);
        }
        if let Some((dest_reg, value)) = tracked_assignment {
            register_values.insert(dest_reg, value);
        }
    }

    register_values
}

fn tracked_register_assignment(
    instr: &Instruction,
    register_values: &HashMap<u16, u64>,
) -> Option<(u16, u64)> {
    let dest_reg = match instr.operands.first() {
        Some(Operand::Register(reg)) => reg.id,
        _ => return None,
    };

    match instr.operation {
        Operation::Move | Operation::LoadEffectiveAddress => {
            let source = instr.operands.get(1)?;
            materialized_source_address(instr, register_values, source)
                .map(|value| (dest_reg, value))
        }
        Operation::Add => {
            let imm = match instr.operands.get(1) {
                Some(Operand::Immediate(imm)) => imm.value,
                _ => return None,
            };
            register_values
                .get(&dest_reg)
                .copied()
                .and_then(|value| value.checked_add_signed(imm as i64))
                .map(|value| (dest_reg, value))
        }
        Operation::Sub => {
            let imm = match instr.operands.get(1) {
                Some(Operand::Immediate(imm)) => imm.value,
                _ => return None,
            };
            register_values
                .get(&dest_reg)
                .copied()
                .and_then(|value| value.checked_add_signed(-(imm as i64)))
                .map(|value| (dest_reg, value))
        }
        _ => None,
    }
}

fn materialized_source_address(
    instr: &Instruction,
    register_values: &HashMap<u16, u64>,
    source: &Operand,
) -> Option<u64> {
    match source {
        Operand::Immediate(imm) => Some(imm.value as u64),
        Operand::PcRelative { target, .. } => Some(*target),
        Operand::Register(reg) => register_values.get(&reg.id).copied(),
        Operand::Memory(mem) if matches!(instr.operation, Operation::LoadEffectiveAddress) => {
            if mem.index.is_some() {
                return None;
            }

            if mem.base.as_ref().is_some_and(|reg| reg.name() == "rip") {
                let inst_end = instr.address + instr.size as u64;
                return inst_end.checked_add_signed(mem.displacement);
            }

            let base = mem
                .base
                .as_ref()
                .and_then(|reg| register_values.get(&reg.id).copied())?;
            base.checked_add_signed(mem.displacement)
        }
        _ => None,
    }
}

fn read_dispatch_table_targets(
    binary_ctx: &BinaryDataContext,
    access: DispatchTableAccess,
    function_start: u64,
    function_end: u64,
) -> Vec<u64> {
    let Some((data, section_base)) = binary_ctx.section_containing(access.table_base) else {
        return Vec::new();
    };
    if access.table_base < section_base {
        return Vec::new();
    }

    let mut targets = Vec::new();
    let mut seen = HashSet::new();
    let offset = (access.table_base - section_base) as usize;

    for entry_index in 0..MAX_COMPUTED_DISPATCH_ENTRIES {
        let entry_offset = offset + entry_index * access.entry_size;
        if entry_offset + access.entry_size > data.len() {
            break;
        }

        let target = match access.entry_size {
            4 => {
                let bytes: [u8; 4] = data[entry_offset..entry_offset + 4]
                    .try_into()
                    .expect("slice length checked above");
                u32::from_le_bytes(bytes) as u64
            }
            8 => {
                let bytes: [u8; 8] = data[entry_offset..entry_offset + 8]
                    .try_into()
                    .expect("slice length checked above");
                u64::from_le_bytes(bytes)
            }
            _ => break,
        };

        if target == 0 {
            break;
        }
        if target < function_start || target >= function_end {
            if targets.is_empty() {
                return Vec::new();
            }
            break;
        }
        if seen.insert(target) {
            targets.push(target);
        }
    }

    if targets.len() >= 2 {
        targets
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{annotate_computed_dispatch_targets, CfgBuilder};
    use crate::decompiler::BinaryDataContext;
    use hexray_core::{
        register::x86, Architecture, BlockTerminator, ControlFlow, IndexMode, Instruction,
        MemoryRef, Operand, Operation, Register, RegisterClass,
    };

    fn x86_reg(id: u16, size: u16) -> Register {
        Register::new(Architecture::X86_64, RegisterClass::General, id, size)
    }

    #[test]
    fn terminal_call_without_fallthrough_does_not_create_empty_block() {
        let instructions = vec![
            Instruction::new(0x1000, 1, vec![0x90], "nop"),
            Instruction::new(0x1001, 5, vec![0xe8, 0, 0, 0, 0], "call")
                .with_operation(Operation::Call)
                .with_control_flow(ControlFlow::Call {
                    target: 0x2000,
                    return_addr: 0x1006,
                }),
        ];

        let cfg = CfgBuilder::build(&instructions, 0x1000);

        assert_eq!(cfg.num_blocks(), 1);
        let block = cfg.entry_block().unwrap();
        assert!(cfg.successors(block.id).is_empty());
        assert!(matches!(block.terminator, BlockTerminator::Unknown));
    }

    #[test]
    fn conditional_branch_to_out_of_range_target_gets_external_block() {
        let instructions = vec![Instruction::new(0x1000, 2, vec![0x75, 0x0e], "jne")
            .with_operation(Operation::Jump)
            .with_control_flow(ControlFlow::ConditionalBranch {
                target: 0x2000,
                condition: hexray_core::Condition::NotEqual,
                fallthrough: 0x1002,
            })];

        let cfg = CfgBuilder::build(&instructions, 0x1000);

        let entry = cfg.entry_block().unwrap();
        let (true_target, false_target) = match &entry.terminator {
            BlockTerminator::ConditionalBranch {
                true_target,
                false_target,
                ..
            } => (*true_target, *false_target),
            other => panic!("expected conditional branch, got {other:?}"),
        };

        let true_block = cfg.block(true_target).unwrap();
        assert!(matches!(
            true_block.terminator,
            BlockTerminator::ExternalJump { target: 0x2000 }
        ));

        let false_block = cfg.block(false_target).unwrap();
        assert_eq!(false_block.start, 0x1002);
    }

    #[test]
    fn computed_dispatch_targets_populate_cfg_edges() {
        let mut rodata = vec![0u8; 0x40];
        for (index, value) in [0x1010u64, 0x1020, 0x1030].into_iter().enumerate() {
            let start = index * 8;
            rodata[start..start + 8].copy_from_slice(&value.to_le_bytes());
        }
        let mut binary_ctx = BinaryDataContext::new();
        binary_ctx.add_section(0x2000, rodata);

        let mut instructions = vec![
            Instruction {
                address: 0x1000,
                size: 7,
                bytes: vec![],
                mnemonic: "jmp".to_string(),
                operation: Operation::Jump,
                operands: vec![Operand::Memory(MemoryRef {
                    base: None,
                    index: Some(x86_reg(x86::RDI, 64)),
                    scale: 8,
                    displacement: 0x2000,
                    size: 8,
                    segment: None,
                    broadcast: false,
                    index_mode: IndexMode::None,
                    space: hexray_core::MemorySpace::Generic,
                })],
                control_flow: ControlFlow::IndirectBranch {
                    possible_targets: vec![],
                },
                reads: vec![],
                writes: vec![],
                guard: None,
            },
            Instruction::new(0x1010, 1, vec![0x90], "nop"),
            Instruction::new(0x1011, 1, vec![0xc3], "ret")
                .with_operation(Operation::Return)
                .with_control_flow(ControlFlow::Return),
            Instruction::new(0x1020, 1, vec![0x90], "nop"),
            Instruction::new(0x1021, 1, vec![0xc3], "ret")
                .with_operation(Operation::Return)
                .with_control_flow(ControlFlow::Return),
            Instruction::new(0x1030, 1, vec![0x90], "nop"),
            Instruction::new(0x1031, 1, vec![0xc3], "ret")
                .with_operation(Operation::Return)
                .with_control_flow(ControlFlow::Return),
        ];

        annotate_computed_dispatch_targets(&mut instructions, &binary_ctx, 0x1000, 0x1040);
        let cfg = CfgBuilder::build(&instructions, 0x1000);

        let entry = cfg.entry_block().unwrap();
        let possible_targets = match &entry.terminator {
            BlockTerminator::IndirectJump {
                possible_targets, ..
            } => possible_targets.clone(),
            other => panic!("expected indirect jump, got {other:?}"),
        };
        assert_eq!(possible_targets.len(), 3);
        assert_eq!(cfg.successors(entry.id).len(), 3);
    }

    #[test]
    fn build_with_binary_context_recovers_dispatch_targets_loaded_through_register() {
        let mut rodata = vec![0u8; 0x40];
        for (index, value) in [0x1010u64, 0x1020, 0x1030].into_iter().enumerate() {
            let start = index * 8;
            rodata[start..start + 8].copy_from_slice(&value.to_le_bytes());
        }
        let mut binary_ctx = BinaryDataContext::new();
        binary_ctx.add_section(0x2000, rodata);

        let instructions = vec![
            Instruction {
                address: 0x1000,
                size: 8,
                bytes: vec![],
                mnemonic: "mov".to_string(),
                operation: Operation::Move,
                operands: vec![
                    Operand::Register(x86_reg(x86::RDI, 64)),
                    Operand::Memory(MemoryRef {
                        base: None,
                        index: Some(x86_reg(x86::RDI, 64)),
                        scale: 8,
                        displacement: 0x2000,
                        size: 8,
                        segment: None,
                        broadcast: false,
                        index_mode: IndexMode::None,
                        space: hexray_core::MemorySpace::Generic,
                    }),
                ],
                control_flow: ControlFlow::Sequential,
                reads: vec![],
                writes: vec![x86_reg(x86::RDI, 64)],
                guard: None,
            },
            Instruction {
                address: 0x1008,
                size: 2,
                bytes: vec![],
                mnemonic: "jmp".to_string(),
                operation: Operation::Jump,
                operands: vec![Operand::Register(x86_reg(x86::RDI, 64))],
                control_flow: ControlFlow::IndirectBranch {
                    possible_targets: vec![],
                },
                reads: vec![x86_reg(x86::RDI, 64)],
                writes: vec![],
                guard: None,
            },
            Instruction::new(0x1010, 1, vec![0x90], "nop"),
            Instruction::new(0x1011, 1, vec![0xc3], "ret")
                .with_operation(Operation::Return)
                .with_control_flow(ControlFlow::Return),
            Instruction::new(0x1020, 1, vec![0x90], "nop"),
            Instruction::new(0x1021, 1, vec![0xc3], "ret")
                .with_operation(Operation::Return)
                .with_control_flow(ControlFlow::Return),
            Instruction::new(0x1030, 1, vec![0x90], "nop"),
            Instruction::new(0x1031, 1, vec![0xc3], "ret")
                .with_operation(Operation::Return)
                .with_control_flow(ControlFlow::Return),
        ];

        let cfg = CfgBuilder::build_with_binary_context(&instructions, 0x1000, &binary_ctx);
        let entry = cfg.entry_block().unwrap();
        let possible_targets = match &entry.terminator {
            BlockTerminator::IndirectJump {
                possible_targets, ..
            } => possible_targets.clone(),
            _ => Vec::new(),
        };
        assert_eq!(possible_targets.len(), 3);
        assert_eq!(cfg.successors(entry.id).len(), 3);
    }

    #[test]
    fn computed_dispatch_targets_out_of_range_become_external_blocks() {
        let mut rodata = vec![0u8; 0x20];
        rodata[..8].copy_from_slice(&0x2000u64.to_le_bytes());
        rodata[8..16].copy_from_slice(&0x2010u64.to_le_bytes());
        let mut binary_ctx = BinaryDataContext::new();
        binary_ctx.add_section(0x3000, rodata);

        let instructions = vec![Instruction {
            address: 0x1000,
            size: 7,
            bytes: vec![],
            mnemonic: "jmp".to_string(),
            operation: Operation::Jump,
            operands: vec![Operand::Memory(MemoryRef {
                base: None,
                index: Some(x86_reg(x86::RDI, 64)),
                scale: 8,
                displacement: 0x3000,
                size: 8,
                segment: None,
                broadcast: false,
                index_mode: IndexMode::None,
                space: hexray_core::MemorySpace::Generic,
            })],
            control_flow: ControlFlow::IndirectBranch {
                possible_targets: vec![0x2000, 0x2010],
            },
            reads: vec![],
            writes: vec![],
            guard: None,
        }];

        let cfg = CfgBuilder::build_with_binary_context(&instructions, 0x1000, &binary_ctx);
        let entry = cfg.entry_block().unwrap();
        let succs = cfg.successors(entry.id);
        assert_eq!(succs.len(), 2);
        for succ in succs {
            let block = cfg.block(*succ).unwrap();
            assert!(matches!(
                block.terminator,
                BlockTerminator::ExternalJump { .. }
            ));
        }
    }
}
