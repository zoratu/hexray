//! SSA-based optimizations.
//!
//! This module provides optimization passes that operate on SSA form:
//! - Dead code elimination (remove unused definitions)
//! - Copy propagation (replace copies with their source)
//! - Constant folding (evaluate constant expressions)
//! - Phi node simplification (remove trivial phi nodes)

use super::types::{PhiNode, SsaFunction, SsaInstruction, SsaOperand, SsaValue};
use hexray_core::{BasicBlockId, Operation};
use std::collections::{HashMap, HashSet};

/// SSA optimizer that runs multiple optimization passes.
pub struct SsaOptimizer {
    /// Values that are used (for dead code elimination).
    used_values: HashSet<SsaValue>,
    /// Copy propagation mapping: value -> replacement.
    copy_map: HashMap<SsaValue, SsaValue>,
    /// Constant values.
    constants: HashMap<SsaValue, i128>,
}

impl SsaOptimizer {
    /// Creates a new SSA optimizer.
    pub fn new() -> Self {
        Self {
            used_values: HashSet::new(),
            copy_map: HashMap::new(),
            constants: HashMap::new(),
        }
    }

    /// Runs all optimization passes on an SSA function.
    pub fn optimize(&mut self, func: &mut SsaFunction) {
        // Run passes until no changes
        let mut changed = true;
        let max_iterations = 5;
        let mut iteration = 0;

        while changed && iteration < max_iterations {
            changed = false;
            iteration += 1;

            // 1. Simplify phi nodes
            changed |= self.simplify_phis(func);

            // 2. Copy propagation
            changed |= self.propagate_copies(func);

            // 3. Constant folding
            changed |= self.fold_constants(func);

            // 4. Dead code elimination (must be last)
            changed |= self.eliminate_dead_code(func);
        }
    }

    /// Simplifies trivial phi nodes.
    ///
    /// A phi node is trivial if:
    /// - All incoming values are the same
    /// - All incoming values except one are the phi result itself
    fn simplify_phis(&mut self, func: &mut SsaFunction) -> bool {
        let mut changed = false;
        let mut replacements: Vec<(BasicBlockId, usize, SsaValue)> = Vec::new();

        for (block_id, block) in &func.blocks {
            for (phi_idx, phi) in block.phis.iter().enumerate() {
                if let Some(replacement) = self.get_trivial_phi_value(phi) {
                    replacements.push((*block_id, phi_idx, replacement));
                }
            }
        }

        for (block_id, phi_idx, replacement) in replacements {
            if let Some(block) = func.blocks.get_mut(&block_id) {
                let phi = &block.phis[phi_idx];
                // Record the replacement for copy propagation
                self.copy_map.insert(phi.result.clone(), replacement);
                changed = true;
            }
        }

        changed
    }

    /// Gets the value a trivial phi node can be replaced with.
    fn get_trivial_phi_value(&self, phi: &PhiNode) -> Option<SsaValue> {
        if phi.incoming.is_empty() {
            return None;
        }

        // Filter out self-references
        let non_self: Vec<_> = phi
            .incoming
            .iter()
            .filter(|(_, v)| v != &phi.result)
            .collect();

        if non_self.is_empty() {
            // All values are self-references - undefined
            return None;
        }

        // Check if all non-self values are the same
        let first = &non_self[0].1;
        if non_self.iter().all(|(_, v)| v == first) {
            // Apply copy propagation to get the canonical value
            Some(self.resolve_copy(first))
        } else {
            None
        }
    }

    /// Resolves a value through the copy chain.
    fn resolve_copy(&self, value: &SsaValue) -> SsaValue {
        let mut current = value.clone();
        let mut visited = HashSet::new();

        while let Some(replacement) = self.copy_map.get(&current) {
            if !visited.insert(current.clone()) {
                // Cycle detected
                break;
            }
            current = replacement.clone();
        }

        current
    }

    /// Propagates copies through the function.
    fn propagate_copies(&mut self, func: &mut SsaFunction) -> bool {
        let mut changed = false;

        // Find copy instructions (move with value operand)
        for block in func.blocks.values() {
            for inst in &block.instructions {
                if inst.operation == Operation::Move {
                    if let (Some(def), Some(SsaOperand::Value(src))) =
                        (inst.defs.first(), inst.uses.first())
                    {
                        let resolved_src = self.resolve_copy(src);
                        if !self.copy_map.contains_key(def) {
                            self.copy_map.insert(def.clone(), resolved_src);
                            changed = true;
                        }
                    }
                }
            }
        }

        // Apply copy propagation to all uses
        for block in func.blocks.values_mut() {
            // Update phi incoming values
            for phi in &mut block.phis {
                for (_, value) in &mut phi.incoming {
                    let resolved = self.resolve_copy(value);
                    if resolved != *value {
                        *value = resolved;
                        changed = true;
                    }
                }
            }

            // Update instruction uses
            for inst in &mut block.instructions {
                for op in &mut inst.uses {
                    if let SsaOperand::Value(v) = op {
                        let resolved = self.resolve_copy(v);
                        if resolved != *v {
                            *v = resolved;
                            changed = true;
                        }
                    }
                }
            }
        }

        changed
    }

    /// Folds constant expressions.
    fn fold_constants(&mut self, func: &mut SsaFunction) -> bool {
        let mut changed = false;

        // First, identify constant values from immediate assignments
        for block in func.blocks.values() {
            for inst in &block.instructions {
                if inst.operation == Operation::Move {
                    if let (Some(def), Some(SsaOperand::Immediate(imm))) =
                        (inst.defs.first(), inst.uses.first())
                    {
                        self.constants.insert(def.clone(), *imm);
                    }
                }
            }
        }

        // Fold binary operations with constant operands
        for block in func.blocks.values_mut() {
            for inst in &mut block.instructions {
                if let Some(folded) = self.try_fold_instruction(inst) {
                    if let Some(def) = inst.defs.first() {
                        self.constants.insert(def.clone(), folded);
                        // Replace uses with immediate
                        inst.uses = vec![SsaOperand::Immediate(folded)];
                        inst.operation = Operation::Move;
                        changed = true;
                    }
                }
            }
        }

        changed
    }

    /// Tries to fold an instruction to a constant.
    fn try_fold_instruction(&self, inst: &SsaInstruction) -> Option<i128> {
        // Need exactly 2 operands for binary ops
        if inst.uses.len() != 2 {
            return None;
        }

        let left = self.get_constant_value(&inst.uses[0])?;
        let right = self.get_constant_value(&inst.uses[1])?;

        match inst.operation {
            Operation::Add => Some(left.wrapping_add(right)),
            Operation::Sub => Some(left.wrapping_sub(right)),
            Operation::Mul => Some(left.wrapping_mul(right)),
            Operation::And => Some(left & right),
            Operation::Or => Some(left | right),
            Operation::Xor => Some(left ^ right),
            Operation::Shl => Some(left << (right & 63)),
            Operation::Shr => Some(((left as u128) >> (right & 63)) as i128),
            _ => None,
        }
    }

    /// Gets the constant value of an operand, if known.
    fn get_constant_value(&self, op: &SsaOperand) -> Option<i128> {
        match op {
            SsaOperand::Immediate(imm) => Some(*imm),
            SsaOperand::Value(v) => {
                let resolved = self.resolve_copy(v);
                self.constants.get(&resolved).copied()
            }
            _ => None,
        }
    }

    /// Eliminates dead code (unused definitions).
    fn eliminate_dead_code(&mut self, func: &mut SsaFunction) -> bool {
        // Collect all used values
        self.used_values.clear();
        self.collect_uses(func);

        let mut changed = false;

        // Remove unused instructions
        for block in func.blocks.values_mut() {
            // Keep instructions that define used values or have side effects
            let original_len = block.instructions.len();
            block.instructions.retain(|inst| {
                self.has_side_effects(inst)
                    || inst.defs.iter().any(|d| self.used_values.contains(d))
            });
            if block.instructions.len() != original_len {
                changed = true;
            }

            // Remove unused phi nodes
            let original_phi_len = block.phis.len();
            block
                .phis
                .retain(|phi| self.used_values.contains(&phi.result));
            if block.phis.len() != original_phi_len {
                changed = true;
            }
        }

        changed
    }

    /// Collects all used values.
    fn collect_uses(&mut self, func: &SsaFunction) {
        for block in func.blocks.values() {
            // Uses in phi nodes
            for phi in &block.phis {
                for (_, value) in &phi.incoming {
                    self.used_values.insert(value.clone());
                }
            }

            // Uses in instructions
            for inst in &block.instructions {
                for op in &inst.uses {
                    match op {
                        SsaOperand::Value(v) => {
                            self.used_values.insert(v.clone());
                        }
                        SsaOperand::Memory { base, index, .. } => {
                            if let Some(b) = base {
                                self.used_values.insert(b.clone());
                            }
                            if let Some(i) = index {
                                self.used_values.insert(i.clone());
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Returns true if an instruction has side effects and shouldn't be removed.
    fn has_side_effects(&self, inst: &SsaInstruction) -> bool {
        matches!(
            inst.operation,
            Operation::Store
                | Operation::Call
                | Operation::Return
                | Operation::Jump
                | Operation::ConditionalJump
        )
    }

    /// Returns statistics about optimizations performed.
    pub fn stats(&self) -> OptimizationStats {
        OptimizationStats {
            copies_propagated: self.copy_map.len(),
            constants_folded: self.constants.len(),
        }
    }
}

impl Default for SsaOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about optimizations performed.
#[derive(Debug, Clone)]
pub struct OptimizationStats {
    /// Number of copy propagations.
    pub copies_propagated: usize,
    /// Number of constants folded.
    pub constants_folded: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dataflow::Location;
    use crate::ssa::types::SsaBlock;

    // --- Copy Propagation Tests ---

    #[test]
    fn test_copy_propagation() {
        let mut optimizer = SsaOptimizer::new();

        // r0_0 = 5
        // r1_0 = r0_0  (copy)
        // r2_0 = r1_0  (copy)
        // After propagation: r2_0 should resolve to r0_0

        let r0 = SsaValue::new(Location::Register(0), 0);
        let r1 = SsaValue::new(Location::Register(1), 0);
        let r2 = SsaValue::new(Location::Register(2), 0);

        optimizer.copy_map.insert(r1.clone(), r0.clone());
        optimizer.copy_map.insert(r2.clone(), r1.clone());

        let resolved = optimizer.resolve_copy(&r2);
        assert_eq!(resolved, r0);
    }

    #[test]
    fn test_copy_propagation_no_copies() {
        let optimizer = SsaOptimizer::new();

        let r0 = SsaValue::new(Location::Register(0), 0);
        let resolved = optimizer.resolve_copy(&r0);
        assert_eq!(resolved, r0);
    }

    #[test]
    fn test_copy_propagation_cycle_detection() {
        let mut optimizer = SsaOptimizer::new();

        // Create a cycle: r0 -> r1 -> r2 -> r0
        let r0 = SsaValue::new(Location::Register(0), 0);
        let r1 = SsaValue::new(Location::Register(1), 0);
        let r2 = SsaValue::new(Location::Register(2), 0);

        optimizer.copy_map.insert(r0.clone(), r1.clone());
        optimizer.copy_map.insert(r1.clone(), r2.clone());
        optimizer.copy_map.insert(r2.clone(), r0.clone());

        // Should not infinite loop
        let resolved = optimizer.resolve_copy(&r0);
        // Result should be one of the values in the cycle
        assert!(resolved == r0 || resolved == r1 || resolved == r2);
    }

    #[test]
    fn test_copy_propagation_single_step() {
        let mut optimizer = SsaOptimizer::new();

        let r0 = SsaValue::new(Location::Register(0), 0);
        let r1 = SsaValue::new(Location::Register(1), 0);

        optimizer.copy_map.insert(r1.clone(), r0.clone());

        let resolved = optimizer.resolve_copy(&r1);
        assert_eq!(resolved, r0);
    }

    // --- Constant Folding Tests ---

    #[test]
    fn test_constant_folding() {
        let optimizer = SsaOptimizer::new();

        // Test ADD folding
        let inst = SsaInstruction {
            address: 0,
            operation: Operation::Add,
            defs: vec![SsaValue::new(Location::Register(0), 0)],
            uses: vec![SsaOperand::Immediate(5), SsaOperand::Immediate(3)],
            mnemonic: "add".to_string(),
        };

        let result = optimizer.try_fold_instruction(&inst);
        assert_eq!(result, Some(8));
    }

    #[test]
    fn test_constant_folding_sub() {
        let optimizer = SsaOptimizer::new();

        let inst = SsaInstruction {
            address: 0,
            operation: Operation::Sub,
            defs: vec![SsaValue::new(Location::Register(0), 0)],
            uses: vec![SsaOperand::Immediate(10), SsaOperand::Immediate(3)],
            mnemonic: "sub".to_string(),
        };

        let result = optimizer.try_fold_instruction(&inst);
        assert_eq!(result, Some(7));
    }

    #[test]
    fn test_constant_folding_mul() {
        let optimizer = SsaOptimizer::new();

        let inst = SsaInstruction {
            address: 0,
            operation: Operation::Mul,
            defs: vec![SsaValue::new(Location::Register(0), 0)],
            uses: vec![SsaOperand::Immediate(6), SsaOperand::Immediate(7)],
            mnemonic: "imul".to_string(),
        };

        let result = optimizer.try_fold_instruction(&inst);
        assert_eq!(result, Some(42));
    }

    #[test]
    fn test_constant_folding_and() {
        let optimizer = SsaOptimizer::new();

        let inst = SsaInstruction {
            address: 0,
            operation: Operation::And,
            defs: vec![SsaValue::new(Location::Register(0), 0)],
            uses: vec![SsaOperand::Immediate(0xFF), SsaOperand::Immediate(0x0F)],
            mnemonic: "and".to_string(),
        };

        let result = optimizer.try_fold_instruction(&inst);
        assert_eq!(result, Some(0x0F));
    }

    #[test]
    fn test_constant_folding_or() {
        let optimizer = SsaOptimizer::new();

        let inst = SsaInstruction {
            address: 0,
            operation: Operation::Or,
            defs: vec![SsaValue::new(Location::Register(0), 0)],
            uses: vec![SsaOperand::Immediate(0xF0), SsaOperand::Immediate(0x0F)],
            mnemonic: "or".to_string(),
        };

        let result = optimizer.try_fold_instruction(&inst);
        assert_eq!(result, Some(0xFF));
    }

    #[test]
    fn test_constant_folding_xor() {
        let optimizer = SsaOptimizer::new();

        let inst = SsaInstruction {
            address: 0,
            operation: Operation::Xor,
            defs: vec![SsaValue::new(Location::Register(0), 0)],
            uses: vec![SsaOperand::Immediate(0xFF), SsaOperand::Immediate(0xFF)],
            mnemonic: "xor".to_string(),
        };

        let result = optimizer.try_fold_instruction(&inst);
        assert_eq!(result, Some(0));
    }

    #[test]
    fn test_constant_folding_shl() {
        let optimizer = SsaOptimizer::new();

        let inst = SsaInstruction {
            address: 0,
            operation: Operation::Shl,
            defs: vec![SsaValue::new(Location::Register(0), 0)],
            uses: vec![SsaOperand::Immediate(1), SsaOperand::Immediate(4)],
            mnemonic: "shl".to_string(),
        };

        let result = optimizer.try_fold_instruction(&inst);
        assert_eq!(result, Some(16)); // 1 << 4 = 16
    }

    #[test]
    fn test_constant_folding_shr() {
        let optimizer = SsaOptimizer::new();

        let inst = SsaInstruction {
            address: 0,
            operation: Operation::Shr,
            defs: vec![SsaValue::new(Location::Register(0), 0)],
            uses: vec![SsaOperand::Immediate(64), SsaOperand::Immediate(2)],
            mnemonic: "shr".to_string(),
        };

        let result = optimizer.try_fold_instruction(&inst);
        assert_eq!(result, Some(16)); // 64 >> 2 = 16
    }

    #[test]
    fn test_constant_folding_non_binary() {
        let optimizer = SsaOptimizer::new();

        // Only 1 operand - should not fold
        let inst = SsaInstruction {
            address: 0,
            operation: Operation::Add,
            defs: vec![SsaValue::new(Location::Register(0), 0)],
            uses: vec![SsaOperand::Immediate(5)],
            mnemonic: "inc".to_string(),
        };

        let result = optimizer.try_fold_instruction(&inst);
        assert_eq!(result, None);
    }

    #[test]
    fn test_constant_folding_non_constant() {
        let optimizer = SsaOptimizer::new();

        // One operand is a non-constant value
        let inst = SsaInstruction {
            address: 0,
            operation: Operation::Add,
            defs: vec![SsaValue::new(Location::Register(0), 0)],
            uses: vec![
                SsaOperand::Value(SsaValue::new(Location::Register(1), 0)),
                SsaOperand::Immediate(5),
            ],
            mnemonic: "add".to_string(),
        };

        let result = optimizer.try_fold_instruction(&inst);
        assert_eq!(result, None);
    }

    #[test]
    fn test_constant_folding_with_known_value() {
        let mut optimizer = SsaOptimizer::new();

        // r1_0 is known to be 10
        let r1 = SsaValue::new(Location::Register(1), 0);
        optimizer.constants.insert(r1.clone(), 10);

        let inst = SsaInstruction {
            address: 0,
            operation: Operation::Add,
            defs: vec![SsaValue::new(Location::Register(0), 0)],
            uses: vec![SsaOperand::Value(r1), SsaOperand::Immediate(5)],
            mnemonic: "add".to_string(),
        };

        let result = optimizer.try_fold_instruction(&inst);
        assert_eq!(result, Some(15));
    }

    // --- Trivial Phi Tests ---

    #[test]
    fn test_trivial_phi_detection() {
        let optimizer = SsaOptimizer::new();

        // Phi where all incoming values are the same
        let r0_v0 = SsaValue::new(Location::Register(0), 0);
        let r0_v1 = SsaValue::new(Location::Register(0), 1);

        let mut phi = PhiNode::new(r0_v1.clone());
        phi.add_incoming(BasicBlockId::new(0), r0_v0.clone());
        phi.add_incoming(BasicBlockId::new(1), r0_v0.clone());

        let result = optimizer.get_trivial_phi_value(&phi);
        assert_eq!(result, Some(r0_v0));
    }

    #[test]
    fn test_trivial_phi_with_self_reference() {
        let optimizer = SsaOptimizer::new();

        // Phi: r0_1 = phi(r0_0, r0_1)
        // Should simplify to r0_0
        let r0_v0 = SsaValue::new(Location::Register(0), 0);
        let r0_v1 = SsaValue::new(Location::Register(0), 1);

        let mut phi = PhiNode::new(r0_v1.clone());
        phi.add_incoming(BasicBlockId::new(0), r0_v0.clone());
        phi.add_incoming(BasicBlockId::new(1), r0_v1.clone()); // self-reference

        let result = optimizer.get_trivial_phi_value(&phi);
        assert_eq!(result, Some(r0_v0));
    }

    #[test]
    fn test_non_trivial_phi() {
        let optimizer = SsaOptimizer::new();

        // Phi with different incoming values
        let r0_v0 = SsaValue::new(Location::Register(0), 0);
        let r0_v1 = SsaValue::new(Location::Register(0), 1);
        let r0_v2 = SsaValue::new(Location::Register(0), 2);

        let mut phi = PhiNode::new(r0_v2.clone());
        phi.add_incoming(BasicBlockId::new(0), r0_v0.clone());
        phi.add_incoming(BasicBlockId::new(1), r0_v1.clone());

        let result = optimizer.get_trivial_phi_value(&phi);
        assert_eq!(result, None);
    }

    #[test]
    fn test_trivial_phi_empty() {
        let optimizer = SsaOptimizer::new();

        let r0_v0 = SsaValue::new(Location::Register(0), 0);
        let phi = PhiNode::new(r0_v0);

        let result = optimizer.get_trivial_phi_value(&phi);
        assert_eq!(result, None);
    }

    #[test]
    fn test_trivial_phi_all_self_reference() {
        let optimizer = SsaOptimizer::new();

        // Phi that only references itself - undefined
        let r0_v0 = SsaValue::new(Location::Register(0), 0);

        let mut phi = PhiNode::new(r0_v0.clone());
        phi.add_incoming(BasicBlockId::new(0), r0_v0.clone());
        phi.add_incoming(BasicBlockId::new(1), r0_v0.clone());

        let result = optimizer.get_trivial_phi_value(&phi);
        assert_eq!(result, None);
    }

    // --- Side Effects Tests ---

    #[test]
    fn test_has_side_effects_store() {
        let optimizer = SsaOptimizer::new();

        let inst = SsaInstruction {
            address: 0,
            operation: Operation::Store,
            defs: vec![],
            uses: vec![],
            mnemonic: "mov".to_string(),
        };

        assert!(optimizer.has_side_effects(&inst));
    }

    #[test]
    fn test_has_side_effects_call() {
        let optimizer = SsaOptimizer::new();

        let inst = SsaInstruction {
            address: 0,
            operation: Operation::Call,
            defs: vec![],
            uses: vec![],
            mnemonic: "call".to_string(),
        };

        assert!(optimizer.has_side_effects(&inst));
    }

    #[test]
    fn test_has_side_effects_return() {
        let optimizer = SsaOptimizer::new();

        let inst = SsaInstruction {
            address: 0,
            operation: Operation::Return,
            defs: vec![],
            uses: vec![],
            mnemonic: "ret".to_string(),
        };

        assert!(optimizer.has_side_effects(&inst));
    }

    #[test]
    fn test_has_no_side_effects_add() {
        let optimizer = SsaOptimizer::new();

        let inst = SsaInstruction {
            address: 0,
            operation: Operation::Add,
            defs: vec![SsaValue::new(Location::Register(0), 0)],
            uses: vec![SsaOperand::Immediate(1), SsaOperand::Immediate(2)],
            mnemonic: "add".to_string(),
        };

        assert!(!optimizer.has_side_effects(&inst));
    }

    // --- Dead Code Elimination Tests ---

    #[test]
    fn test_dead_code_elimination() {
        let mut optimizer = SsaOptimizer::new();

        let mut func = SsaFunction::new("test", BasicBlockId::new(0));
        let mut block = SsaBlock::new(BasicBlockId::new(0), 0x1000);

        // r0_0 = 5 (dead - not used)
        block.add_instruction(SsaInstruction {
            address: 0x1000,
            operation: Operation::Move,
            defs: vec![SsaValue::new(Location::Register(0), 0)],
            uses: vec![SsaOperand::Immediate(5)],
            mnemonic: "mov".to_string(),
        });

        // r1_0 = 10 (used in next instruction)
        let r1_v0 = SsaValue::new(Location::Register(1), 0);
        block.add_instruction(SsaInstruction {
            address: 0x1004,
            operation: Operation::Move,
            defs: vec![r1_v0.clone()],
            uses: vec![SsaOperand::Immediate(10)],
            mnemonic: "mov".to_string(),
        });

        // store r1_0 (side effect - uses r1_0)
        block.add_instruction(SsaInstruction {
            address: 0x1008,
            operation: Operation::Store,
            defs: vec![],
            uses: vec![SsaOperand::Value(r1_v0)],
            mnemonic: "mov".to_string(),
        });

        func.add_block(block);

        let changed = optimizer.eliminate_dead_code(&mut func);

        // r0_0 = 5 should be removed (dead)
        // r1_0 = 10 should remain (used)
        // store should remain (side effect)
        let block = func.block(BasicBlockId::new(0)).unwrap();
        assert_eq!(block.instructions.len(), 2);
        assert!(changed);
    }

    // --- Stats Tests ---

    #[test]
    fn test_optimizer_stats() {
        let mut optimizer = SsaOptimizer::new();

        let r0 = SsaValue::new(Location::Register(0), 0);
        let r1 = SsaValue::new(Location::Register(1), 0);

        optimizer.copy_map.insert(r1.clone(), r0.clone());
        optimizer.constants.insert(r0, 42);

        let stats = optimizer.stats();
        assert_eq!(stats.copies_propagated, 1);
        assert_eq!(stats.constants_folded, 1);
    }

    #[test]
    fn test_optimizer_default() {
        let optimizer = SsaOptimizer::default();
        assert!(optimizer.copy_map.is_empty());
        assert!(optimizer.constants.is_empty());
        assert!(optimizer.used_values.is_empty());
    }

    // --- Integration Tests ---

    #[test]
    fn test_optimize_empty_function() {
        let mut optimizer = SsaOptimizer::new();
        let mut func = SsaFunction::new("empty", BasicBlockId::new(0));
        func.add_block(SsaBlock::new(BasicBlockId::new(0), 0x1000));

        // Should not panic
        optimizer.optimize(&mut func);

        assert_eq!(func.blocks.len(), 1);
    }

    #[test]
    fn test_optimize_preserves_side_effects() {
        let mut optimizer = SsaOptimizer::new();

        let mut func = SsaFunction::new("test", BasicBlockId::new(0));
        let mut block = SsaBlock::new(BasicBlockId::new(0), 0x1000);

        // call (side effect - must be preserved)
        block.add_instruction(SsaInstruction {
            address: 0x1000,
            operation: Operation::Call,
            defs: vec![],
            uses: vec![],
            mnemonic: "call".to_string(),
        });

        func.add_block(block);
        optimizer.optimize(&mut func);

        let block = func.block(BasicBlockId::new(0)).unwrap();
        assert_eq!(block.instructions.len(), 1);
    }

    #[test]
    fn test_optimization_iteration_limit() {
        let mut optimizer = SsaOptimizer::new();

        // Create a function that might trigger multiple optimization rounds
        let mut func = SsaFunction::new("test", BasicBlockId::new(0));
        let mut block = SsaBlock::new(BasicBlockId::new(0), 0x1000);

        // Add several constant moves
        for i in 0..10u32 {
            block.add_instruction(SsaInstruction {
                address: 0x1000 + i as u64 * 4,
                operation: Operation::Move,
                defs: vec![SsaValue::new(Location::Register(i as u16), 0)],
                uses: vec![SsaOperand::Immediate(i as i128)],
                mnemonic: "mov".to_string(),
            });
        }

        // Add a store to keep something alive
        block.add_instruction(SsaInstruction {
            address: 0x1100,
            operation: Operation::Store,
            defs: vec![],
            uses: vec![SsaOperand::Value(SsaValue::new(Location::Register(0), 0))],
            mnemonic: "mov".to_string(),
        });

        func.add_block(block);

        // Should complete without infinite loop
        optimizer.optimize(&mut func);
    }

    #[test]
    fn test_collect_uses_memory_operand() {
        let mut optimizer = SsaOptimizer::new();

        let mut func = SsaFunction::new("test", BasicBlockId::new(0));
        let mut block = SsaBlock::new(BasicBlockId::new(0), 0x1000);

        let base = SsaValue::new(Location::Register(0), 0);
        let index = SsaValue::new(Location::Register(1), 0);

        block.add_instruction(SsaInstruction {
            address: 0x1000,
            operation: Operation::Load,
            defs: vec![SsaValue::new(Location::Register(2), 0)],
            uses: vec![SsaOperand::Memory {
                base: Some(base.clone()),
                index: Some(index.clone()),
                scale: 4,
                displacement: 0,
                size: 8,
            }],
            mnemonic: "mov".to_string(),
        });

        func.add_block(block);

        optimizer.collect_uses(&func);

        // Both base and index should be marked as used
        assert!(optimizer.used_values.contains(&base));
        assert!(optimizer.used_values.contains(&index));
    }
}
