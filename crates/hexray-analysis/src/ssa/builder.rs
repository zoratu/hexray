//! SSA form builder.
//!
//! Converts a CFG to SSA form using the standard algorithm:
//! 1. Insert phi nodes using dominance frontiers
//! 2. Rename variables using dominator tree walk

use super::types::*;
use super::{collect_definitions, compute_dominance_frontiers, find_phi_placements};
use crate::dataflow::{InstructionEffects, Location};
use hexray_core::{BasicBlockId, ControlFlowGraph, Operand};
use std::collections::{HashMap, HashSet};

/// Builds SSA form from a CFG.
pub struct SsaBuilder<'a> {
    cfg: &'a ControlFlowGraph,
    /// Dominance frontiers for phi placement.
    frontiers: HashMap<BasicBlockId, HashSet<BasicBlockId>>,
    /// Current version counters.
    version_counters: HashMap<Location, Version>,
    /// Current reaching definition for each location (stack of versions).
    reaching_def: HashMap<Location, Vec<Version>>,
    /// Where phi nodes are needed.
    phi_locations: HashMap<BasicBlockId, HashSet<Location>>,
}

impl<'a> SsaBuilder<'a> {
    /// Creates a new SSA builder.
    pub fn new(cfg: &'a ControlFlowGraph) -> Self {
        let frontiers = compute_dominance_frontiers(cfg);
        Self {
            cfg,
            frontiers,
            version_counters: HashMap::new(),
            reaching_def: HashMap::new(),
            phi_locations: HashMap::new(),
        }
    }

    /// Builds SSA form for the CFG.
    pub fn build(&mut self, name: &str) -> SsaFunction {
        // Step 1: Find where phi nodes are needed
        self.find_phi_locations();

        // Step 2: Create SSA function and initialize all blocks with their phi nodes
        let mut func = SsaFunction::new(name, self.cfg.entry);

        // First pass: create all blocks with phi node placeholders
        for block in self.cfg.blocks() {
            let mut ssa_block = SsaBlock::new(block.id, block.start);

            // Create phi nodes for this block (with placeholder values)
            if let Some(phi_locs) = self.phi_locations.get(&block.id).cloned() {
                for loc in phi_locs {
                    let version = self.new_version(&loc);
                    let result = SsaValue::new(loc.clone(), version);
                    let phi = PhiNode::new(result);
                    ssa_block.add_phi(phi);
                    // Don't push_def here yet - we'll do that during renaming
                }
            }

            func.add_block(ssa_block);
        }

        // Reset version counters for the actual renaming pass
        self.version_counters.clear();

        // Step 3: Walk dominator tree to rename
        let dom_tree = self.cfg.compute_dominators();
        self.rename_block_pass2(self.cfg.entry, &mut func, &dom_tree);

        func.version_counters = self.version_counters.clone();
        func
    }

    /// Finds all locations where phi nodes are needed.
    fn find_phi_locations(&mut self) {
        let defs_by_loc = collect_definitions(self.cfg);

        for (loc, def_blocks) in defs_by_loc {
            let phi_blocks = find_phi_placements(self.cfg, &self.frontiers, &def_blocks);

            for block_id in phi_blocks {
                self.phi_locations
                    .entry(block_id)
                    .or_default()
                    .insert(loc.clone());
            }
        }
    }

    /// Gets a new version number for a location.
    fn new_version(&mut self, loc: &Location) -> Version {
        let counter = self.version_counters.entry(loc.clone()).or_insert(0);
        let version = *counter;
        *counter += 1;
        version
    }

    /// Gets the current reaching definition for a location.
    fn current_def(&self, loc: &Location) -> Version {
        self.reaching_def
            .get(loc)
            .and_then(|stack| stack.last().copied())
            .unwrap_or(0) // Version 0 is undefined/parameter
    }

    /// Pushes a new definition.
    fn push_def(&mut self, loc: &Location, version: Version) {
        self.reaching_def
            .entry(loc.clone())
            .or_default()
            .push(version);
    }

    /// Pops a definition (when leaving a block's scope).
    fn pop_def(&mut self, loc: &Location) {
        if let Some(stack) = self.reaching_def.get_mut(loc) {
            stack.pop();
        }
    }

    /// Renames variables in a block and its dominated blocks (second pass).
    fn rename_block_pass2(
        &mut self,
        block_id: BasicBlockId,
        func: &mut SsaFunction,
        dom_tree: &hexray_core::cfg::DominatorTree,
    ) {
        let block = match self.cfg.block(block_id) {
            Some(b) => b,
            None => return,
        };

        let mut defs_in_block: Vec<Location> = Vec::new();

        // Process phi nodes in this block - push their definitions
        if let Some(ssa_block) = func.block(block_id) {
            for phi in &ssa_block.phis {
                let loc = phi.result.location.clone();
                let version = self.new_version(&loc);
                self.push_def(&loc, version);
                defs_in_block.push(loc);
            }
        }

        // Process instructions and add them to the block
        let mut ssa_instructions = Vec::new();
        for inst in &block.instructions {
            let effects = InstructionEffects::from_instruction(inst);

            // Build SSA uses (look up current versions)
            let uses: Vec<SsaOperand> = inst
                .operands
                .iter()
                .skip(1) // First operand is often the destination
                .map(|op| self.operand_to_ssa(op))
                .collect();

            // Build SSA defs (create new versions)
            let mut defs = Vec::new();
            for loc in effects.defs {
                let version = self.new_version(&loc);
                defs.push(SsaValue::new(loc.clone(), version));
                self.push_def(&loc, version);
                defs_in_block.push(loc);
            }

            let ssa_inst = SsaInstruction {
                address: inst.address,
                operation: inst.operation,
                defs,
                uses,
                mnemonic: inst.mnemonic.clone(),
            };
            ssa_instructions.push(ssa_inst);
        }

        // Update the block with instructions
        if let Some(ssa_block) = func.block_mut(block_id) {
            ssa_block.instructions = ssa_instructions;
        }

        // Fill in phi operands for successors
        for &succ_id in self.cfg.successors(block_id) {
            self.fill_phi_operands(block_id, succ_id, func);
        }

        // Recurse into dominated blocks
        for child_id in self.cfg.block_ids() {
            if dom_tree.immediate_dominator(child_id) == Some(block_id) && child_id != block_id {
                self.rename_block_pass2(child_id, func, dom_tree);
            }
        }

        // Pop definitions when leaving this block's scope
        for loc in defs_in_block.into_iter().rev() {
            self.pop_def(&loc);
        }
    }

    /// Fills in phi node operands for a successor block.
    fn fill_phi_operands(
        &self,
        from_block: BasicBlockId,
        to_block: BasicBlockId,
        func: &mut SsaFunction,
    ) {
        let block = match func.block_mut(to_block) {
            Some(b) => b,
            None => return,
        };

        for phi in &mut block.phis {
            let loc = &phi.result.location;
            let version = self.current_def(loc);
            let value = SsaValue::new(loc.clone(), version);
            phi.add_incoming(from_block, value);
        }
    }

    /// Converts an operand to SSA form.
    fn operand_to_ssa(&self, op: &Operand) -> SsaOperand {
        match op {
            Operand::Register(reg) => {
                let loc = Location::from_register(reg);
                let version = self.current_def(&loc);
                SsaOperand::Value(SsaValue::new(loc, version))
            }
            Operand::Immediate(imm) => SsaOperand::Immediate(imm.value),
            Operand::Memory(mem) => {
                let base = mem.base.as_ref().map(|r| {
                    let loc = Location::from_register(r);
                    SsaValue::new(loc.clone(), self.current_def(&loc))
                });
                let index = mem.index.as_ref().map(|r| {
                    let loc = Location::from_register(r);
                    SsaValue::new(loc.clone(), self.current_def(&loc))
                });
                SsaOperand::Memory {
                    base,
                    index,
                    scale: mem.scale,
                    displacement: mem.displacement,
                    size: mem.size,
                }
            }
            Operand::PcRelative { target, .. } => SsaOperand::Immediate(*target as i128),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexray_core::{
        Architecture, BasicBlock, BlockTerminator, Condition, Immediate, Instruction, MemoryRef,
        Operation, Register, RegisterClass,
    };

    fn make_register(id: u16, _name: &str) -> Register {
        Register::new(Architecture::X86_64, RegisterClass::General, id, 64)
    }

    fn make_mov_imm(addr: u64, reg_id: u16, reg_name: &str, value: i128) -> Instruction {
        let mut inst = Instruction::new(addr, 3, vec![0; 3], "mov");
        inst.operation = Operation::Move;
        inst.operands = vec![
            Operand::Register(make_register(reg_id, reg_name)),
            Operand::Immediate(Immediate {
                value,
                size: 8,
                signed: false,
            }),
        ];
        inst
    }

    fn make_mov_reg(addr: u64, dst_id: u16, src_id: u16) -> Instruction {
        let mut inst = Instruction::new(addr, 3, vec![0; 3], "mov");
        inst.operation = Operation::Move;
        inst.operands = vec![
            Operand::Register(make_register(dst_id, "dst")),
            Operand::Register(make_register(src_id, "src")),
        ];
        inst
    }

    fn make_add_reg(addr: u64, dst_id: u16, src_id: u16) -> Instruction {
        let mut inst = Instruction::new(addr, 3, vec![0; 3], "add");
        inst.operation = Operation::Add;
        inst.operands = vec![
            Operand::Register(make_register(dst_id, "dst")),
            Operand::Register(make_register(src_id, "src")),
        ];
        inst
    }

    fn make_load(addr: u64, dst_id: u16, base_id: u16, disp: i64) -> Instruction {
        let mut inst = Instruction::new(addr, 4, vec![0; 4], "mov");
        inst.operation = Operation::Load;
        inst.operands = vec![
            Operand::Register(make_register(dst_id, "dst")),
            Operand::Memory(MemoryRef::base_disp(
                make_register(base_id, "base"),
                disp,
                8,
            )),
        ];
        inst
    }

    #[test]
    fn test_ssa_simple() {
        // Linear:
        // mov rax, 1
        // mov rax, 2
        // Should create rax_0 = 1, rax_1 = 2
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut bb = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb.push_instruction(make_mov_imm(0x1000, 0, "rax", 1));
        bb.push_instruction(make_mov_imm(0x1003, 0, "rax", 2));
        bb.terminator = BlockTerminator::Return;
        cfg.add_block(bb);

        let mut builder = SsaBuilder::new(&cfg);
        let ssa = builder.build("test");

        let block = ssa.block(BasicBlockId::new(0)).unwrap();

        // Should have two instructions defining rax_0 and rax_1
        assert_eq!(block.instructions.len(), 2);

        let def0 = &block.instructions[0].defs;
        let def1 = &block.instructions[1].defs;

        // Should have different versions
        assert!(!def0.is_empty());
        assert!(!def1.is_empty());
        assert_ne!(def0[0].version, def1[0].version);
    }

    #[test]
    fn test_ssa_phi_nodes() {
        // Diamond:
        //   bb0: br cond, bb1, bb2
        //   bb1: rax = 1 -> bb3
        //   bb2: rax = 2 -> bb3
        //   bb3: (needs phi for rax)
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(1),
            false_target: BasicBlockId::new(2),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        bb1.push_instruction(make_mov_imm(0x1010, 0, "rax", 1));
        bb1.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(3),
        };
        cfg.add_block(bb1);

        let mut bb2 = BasicBlock::new(BasicBlockId::new(2), 0x1020);
        bb2.push_instruction(make_mov_imm(0x1020, 0, "rax", 2));
        bb2.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(3),
        };
        cfg.add_block(bb2);

        let mut bb3 = BasicBlock::new(BasicBlockId::new(3), 0x1030);
        bb3.terminator = BlockTerminator::Return;
        cfg.add_block(bb3);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(3));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(3));

        let mut builder = SsaBuilder::new(&cfg);
        let ssa = builder.build("test");

        // bb3 should have a phi node for rax
        let block3 = ssa.block(BasicBlockId::new(3)).unwrap();
        assert!(!block3.phis.is_empty(), "bb3 should have phi nodes");

        let phi = &block3.phis[0];
        assert_eq!(phi.incoming.len(), 2, "phi should have 2 incoming edges");
    }

    #[test]
    fn test_ssa_empty_function() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut bb = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb.terminator = BlockTerminator::Return;
        cfg.add_block(bb);

        let mut builder = SsaBuilder::new(&cfg);
        let ssa = builder.build("empty");

        assert_eq!(ssa.name, "empty");
        assert_eq!(ssa.blocks.len(), 1);

        let block = ssa.block(BasicBlockId::new(0)).unwrap();
        assert!(block.phis.is_empty());
        assert!(block.instructions.is_empty());
    }

    #[test]
    fn test_ssa_multiple_registers() {
        // mov rax, 1
        // mov rbx, 2
        // mov rcx, 3
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut bb = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb.push_instruction(make_mov_imm(0x1000, 0, "rax", 1));
        bb.push_instruction(make_mov_imm(0x1003, 3, "rbx", 2));
        bb.push_instruction(make_mov_imm(0x1006, 1, "rcx", 3));
        bb.terminator = BlockTerminator::Return;
        cfg.add_block(bb);

        let mut builder = SsaBuilder::new(&cfg);
        let ssa = builder.build("multi_reg");

        let block = ssa.block(BasicBlockId::new(0)).unwrap();
        assert_eq!(block.instructions.len(), 3);

        // Each should define a different register
        let def0 = &block.instructions[0].defs[0];
        let def1 = &block.instructions[1].defs[0];
        let def2 = &block.instructions[2].defs[0];

        assert_ne!(def0.location, def1.location);
        assert_ne!(def1.location, def2.location);
    }

    #[test]
    fn test_ssa_loop_phi() {
        // Proper loop structure with separate body block:
        // bb0: rax = 0 -> bb1 (header)
        // bb1: check condition -> bb2 (body) or bb3 (exit)
        // bb2: rax = rax + 1 -> bb1 (back edge)
        // bb3: return
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        // Entry: initialize rax
        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.push_instruction(make_mov_imm(0x1000, 0, "rax", 0));
        bb0.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(bb0);

        // Loop header: check condition
        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        bb1.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::NotEqual,
            true_target: BasicBlockId::new(2),  // continue loop
            false_target: BasicBlockId::new(3), // exit
        };
        cfg.add_block(bb1);

        // Loop body: increment rax
        let mut bb2 = BasicBlock::new(BasicBlockId::new(2), 0x1020);
        bb2.push_instruction(make_add_reg(0x1020, 0, 0)); // rax = rax + 1
        bb2.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(1), // back to header
        };
        cfg.add_block(bb2);

        // Exit
        let mut bb3 = BasicBlock::new(BasicBlockId::new(3), 0x1030);
        bb3.terminator = BlockTerminator::Return;
        cfg.add_block(bb3);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(3));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(1)); // back edge

        let mut builder = SsaBuilder::new(&cfg);
        let ssa = builder.build("loop");

        // bb1 should have a phi node for rax
        // (rax comes from bb0 on first iteration, from bb2 on subsequent iterations)
        let block1 = ssa.block(BasicBlockId::new(1)).unwrap();
        assert!(!block1.phis.is_empty(), "Loop header should have phi nodes");
    }

    #[test]
    fn test_ssa_use_def_chain() {
        // rax = 1
        // rbx = rax (use of rax_0)
        // rax = 2
        // rcx = rax (use of rax_1)
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut bb = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb.push_instruction(make_mov_imm(0x1000, 0, "rax", 1));
        bb.push_instruction(make_mov_reg(0x1003, 3, 0)); // rbx = rax
        bb.push_instruction(make_mov_imm(0x1006, 0, "rax", 2));
        bb.push_instruction(make_mov_reg(0x1009, 1, 0)); // rcx = rax
        bb.terminator = BlockTerminator::Return;
        cfg.add_block(bb);

        let mut builder = SsaBuilder::new(&cfg);
        let ssa = builder.build("use_def");

        let block = ssa.block(BasicBlockId::new(0)).unwrap();
        assert_eq!(block.instructions.len(), 4);

        // First mov rax, 1 defines rax_0
        // Second mov rbx, rax uses rax_0
        // Third mov rax, 2 defines rax_1
        // Fourth mov rcx, rax uses rax_1

        let rax_v0 = &block.instructions[0].defs[0];
        let rax_v1 = &block.instructions[2].defs[0];

        assert_eq!(rax_v0.version, 0);
        assert_eq!(rax_v1.version, 1);
    }

    #[test]
    fn test_ssa_memory_operand() {
        // mov rax, [rbx + 8]
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut bb = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb.push_instruction(make_load(0x1000, 0, 3, 8));
        bb.terminator = BlockTerminator::Return;
        cfg.add_block(bb);

        let mut builder = SsaBuilder::new(&cfg);
        let ssa = builder.build("memory");

        let block = ssa.block(BasicBlockId::new(0)).unwrap();
        assert_eq!(block.instructions.len(), 1);

        // The load should have a memory operand with an SSA value for base
        let uses = &block.instructions[0].uses;
        assert!(!uses.is_empty());

        // Check that one of the uses is a memory operand
        let has_memory = uses.iter().any(|u| matches!(u, SsaOperand::Memory { .. }));
        assert!(has_memory, "Should have a memory operand");
    }

    #[test]
    fn test_ssa_phi_incoming_blocks() {
        // Diamond pattern - verify phi incoming blocks are correct
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(1),
            false_target: BasicBlockId::new(2),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        bb1.push_instruction(make_mov_imm(0x1010, 0, "rax", 10));
        bb1.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(3),
        };
        cfg.add_block(bb1);

        let mut bb2 = BasicBlock::new(BasicBlockId::new(2), 0x1020);
        bb2.push_instruction(make_mov_imm(0x1020, 0, "rax", 20));
        bb2.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(3),
        };
        cfg.add_block(bb2);

        let mut bb3 = BasicBlock::new(BasicBlockId::new(3), 0x1030);
        bb3.terminator = BlockTerminator::Return;
        cfg.add_block(bb3);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(3));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(3));

        let mut builder = SsaBuilder::new(&cfg);
        let ssa = builder.build("phi_blocks");

        let block3 = ssa.block(BasicBlockId::new(3)).unwrap();
        assert!(!block3.phis.is_empty());

        let phi = &block3.phis[0];

        // Verify incoming blocks are bb1 and bb2
        let incoming_blocks: HashSet<_> = phi.incoming.iter().map(|(b, _)| *b).collect();
        assert!(incoming_blocks.contains(&BasicBlockId::new(1)));
        assert!(incoming_blocks.contains(&BasicBlockId::new(2)));
    }

    #[test]
    fn test_ssa_version_counter() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut bb = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb.push_instruction(make_mov_imm(0x1000, 0, "rax", 1));
        bb.push_instruction(make_mov_imm(0x1003, 0, "rax", 2));
        bb.push_instruction(make_mov_imm(0x1006, 0, "rax", 3));
        bb.terminator = BlockTerminator::Return;
        cfg.add_block(bb);

        let mut builder = SsaBuilder::new(&cfg);
        let ssa = builder.build("versions");

        // Version counter for register 0 should be 3 (0, 1, 2)
        let loc = Location::Register(0);
        assert!(ssa.version_counters.contains_key(&loc));
        assert_eq!(ssa.version_counters[&loc], 3);
    }

    #[test]
    fn test_ssa_function_display() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut bb = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb.push_instruction(make_mov_imm(0x1000, 0, "rax", 42));
        bb.terminator = BlockTerminator::Return;
        cfg.add_block(bb);

        let mut builder = SsaBuilder::new(&cfg);
        let ssa = builder.build("display_test");

        let output = ssa.display();

        assert!(output.contains("function display_test:"));
        assert!(output.contains("bb0:"));
        assert!(output.contains("mov"));
    }

    #[test]
    fn test_ssa_nested_diamond() {
        // More complex control flow: nested diamonds
        //       bb0
        //      /   \
        //    bb1   bb2
        //   / \   / \
        // bb3 bb4 bb5 bb6
        //   \ /   \ /
        //   bb7   bb8
        //     \   /
        //      bb9
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        // Entry block
        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(1),
            false_target: BasicBlockId::new(2),
        };
        cfg.add_block(bb0);

        // Second level
        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        bb1.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Less,
            true_target: BasicBlockId::new(3),
            false_target: BasicBlockId::new(4),
        };
        cfg.add_block(bb1);

        let mut bb2 = BasicBlock::new(BasicBlockId::new(2), 0x1020);
        bb2.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Less,
            true_target: BasicBlockId::new(5),
            false_target: BasicBlockId::new(6),
        };
        cfg.add_block(bb2);

        // Third level - leaves with definitions
        for (i, addr) in [(3, 0x1030), (4, 0x1040), (5, 0x1050), (6, 0x1060)] {
            let mut bb = BasicBlock::new(BasicBlockId::new(i), addr);
            bb.push_instruction(make_mov_imm(addr, 0, "rax", i as i128));
            let target = if i <= 4 { 7 } else { 8 };
            bb.terminator = BlockTerminator::Jump {
                target: BasicBlockId::new(target),
            };
            cfg.add_block(bb);
        }

        // Fourth level - joins
        let mut bb7 = BasicBlock::new(BasicBlockId::new(7), 0x1070);
        bb7.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(9),
        };
        cfg.add_block(bb7);

        let mut bb8 = BasicBlock::new(BasicBlockId::new(8), 0x1080);
        bb8.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(9),
        };
        cfg.add_block(bb8);

        // Exit
        let mut bb9 = BasicBlock::new(BasicBlockId::new(9), 0x1090);
        bb9.terminator = BlockTerminator::Return;
        cfg.add_block(bb9);

        // Add edges
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(3));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(4));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(5));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(6));
        cfg.add_edge(BasicBlockId::new(3), BasicBlockId::new(7));
        cfg.add_edge(BasicBlockId::new(4), BasicBlockId::new(7));
        cfg.add_edge(BasicBlockId::new(5), BasicBlockId::new(8));
        cfg.add_edge(BasicBlockId::new(6), BasicBlockId::new(8));
        cfg.add_edge(BasicBlockId::new(7), BasicBlockId::new(9));
        cfg.add_edge(BasicBlockId::new(8), BasicBlockId::new(9));

        let mut builder = SsaBuilder::new(&cfg);
        let ssa = builder.build("nested");

        // bb7 and bb8 should have phi nodes
        assert!(
            !ssa.block(BasicBlockId::new(7)).unwrap().phis.is_empty(),
            "bb7 should have phi"
        );
        assert!(
            !ssa.block(BasicBlockId::new(8)).unwrap().phis.is_empty(),
            "bb8 should have phi"
        );

        // bb9 should also have a phi node
        assert!(
            !ssa.block(BasicBlockId::new(9)).unwrap().phis.is_empty(),
            "bb9 should have phi"
        );
    }

    #[test]
    fn test_ssa_builder_deterministic() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut bb = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb.push_instruction(make_mov_imm(0x1000, 0, "rax", 1));
        bb.push_instruction(make_mov_imm(0x1003, 0, "rax", 2));
        bb.terminator = BlockTerminator::Return;
        cfg.add_block(bb);

        // Build twice and compare
        let mut builder1 = SsaBuilder::new(&cfg);
        let ssa1 = builder1.build("test");

        let mut builder2 = SsaBuilder::new(&cfg);
        let ssa2 = builder2.build("test");

        // Should produce identical results
        assert_eq!(ssa1.display(), ssa2.display());
    }
}
