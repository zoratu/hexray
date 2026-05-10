//! Lifting per-architecture branch / `setcc` / `cmovcc` patterns into
//! structured `Expr` conditions.
//!
//! This module is the bridge between raw `BlockTerminator::Conditional`
//! (which only carries a `Condition`-flag-name and a register) and the
//! Boolean-expression form the structurer's if/while/loop reduction
//! consumes.
//!
//! Several of the helpers here look "backwards" through a basic block
//! (or even backwards from a particular address inside one) so they
//! can substitute the most recent flag-setting operands into the
//! condition expression — without that, a `je` rendered after a `cmp`
//! would lose the comparison entirely.

use std::collections::HashMap;

use hexray_core::{BasicBlock, Condition, IndexMode, Instruction, Operand, Operation};

use super::super::abi::is_callee_saved_register;
use super::super::expression::{BinOpKind, Expr};

/// Try to extract condition from ARM64 CBZ/CBNZ/TBZ/TBNZ instructions.
///
/// These instructions have the comparison built into the branch:
/// - CBZ reg, target: branch if reg == 0
/// - CBNZ reg, target: branch if reg != 0
/// - TBZ reg, #bit, target: branch if bit is clear
/// - TBNZ reg, #bit, target: branch if bit is set
pub(super) fn try_extract_arm64_branch_condition(
    block: &BasicBlock,
    op: BinOpKind,
    reg_values: &HashMap<String, Expr>,
) -> Option<Expr> {
    // Find the last ConditionalJump instruction (CBZ/CBNZ/TBZ/TBNZ)
    let branch_inst = block
        .instructions
        .iter()
        .rev()
        .find(|inst| matches!(inst.operation, Operation::ConditionalJump))?;

    let mnemonic = branch_inst.mnemonic.to_lowercase();

    // Check for CBZ/CBNZ (Compare and Branch if Zero/Not Zero)
    if mnemonic == "cbz" || mnemonic == "cbnz" {
        // Operands: [reg, pc_rel_target]
        if !branch_inst.operands.is_empty() {
            let reg_expr = substitute_register_in_expr(
                Expr::from_operand_with_inst(&branch_inst.operands[0], branch_inst),
                reg_values,
            );
            // CBZ: reg == 0, CBNZ: reg != 0
            // The condition (Equal/NotEqual) is already encoded, so just use op
            return Some(Expr::binop(op, reg_expr, Expr::int(0)));
        }
    }

    // Check for TBZ/TBNZ (Test and Branch if Zero/Not Zero)
    if mnemonic == "tbz" || mnemonic == "tbnz" {
        // Operands: [reg, bit_pos, pc_rel_target]
        if branch_inst.operands.len() >= 2 {
            // Extract bit position
            if let hexray_core::Operand::Immediate(imm) = &branch_inst.operands[1] {
                let bit_pos = imm.value;
                let reg_expr = substitute_register_in_expr(
                    Expr::from_operand_with_inst(&branch_inst.operands[0], branch_inst),
                    reg_values,
                );

                // Common signed-compare lowering:
                // tbz wN,#31 => wN >= 0, tbnz wN,#31 => wN < 0
                // tbz xN,#63 => xN >= 0, tbnz xN,#63 => xN < 0
                if let Operand::Register(reg) = &branch_inst.operands[0] {
                    let sign_bit = (reg.size as i128).saturating_sub(1);
                    if bit_pos == sign_bit {
                        let cmp_op = if mnemonic == "tbz" {
                            BinOpKind::Ge
                        } else {
                            BinOpKind::Lt
                        };
                        return Some(Expr::binop(cmp_op, reg_expr, Expr::int(0)));
                    }
                }

                // Create bit test expression: (reg >> bit_pos) & 1
                let shifted = Expr::binop(BinOpKind::Shr, reg_expr, Expr::int(bit_pos));
                let masked = Expr::binop(BinOpKind::And, shifted, Expr::int(1));
                // TBZ: bit == 0, TBNZ: bit != 0
                return Some(Expr::binop(op, masked, Expr::int(0)));
            }
        }
    }

    None
}

/// Checks if an instruction sets CPU flags that can be used for conditional branches.
/// Returns true for comparison instructions (CMP, TEST), arithmetic operations (ADD, SUB, INC, DEC),
/// and logical operations (AND, OR, XOR) that affect condition codes.
fn is_flag_setting_instruction(inst: &Instruction) -> bool {
    match inst.operation {
        // Explicit comparison instructions
        Operation::Compare | Operation::Test => true,

        // Arithmetic operations that set flags
        Operation::Add | Operation::Sub | Operation::Inc | Operation::Dec | Operation::Neg => true,

        // Logical operations - on ARM64 only set flags with 's' suffix, on x86 always set flags
        Operation::And | Operation::Or | Operation::Xor => {
            // Check if this is ARM instruction with 's' suffix (ANDS, ORRS, EORS)
            // or x86 instruction (and, or, xor)
            inst.mnemonic.ends_with('s')
                || inst.mnemonic == "and"
                || inst.mnemonic == "or"
                || inst.mnemonic == "xor"
        }

        // Shift operations that set flags
        Operation::Shl | Operation::Shr | Operation::Sar => true,

        _ => false,
    }
}

fn x86_float_compare_binop(cond: Condition, inst: &Instruction) -> Option<BinOpKind> {
    let mnemonic = inst.mnemonic.to_ascii_lowercase();
    if !matches!(
        mnemonic.as_str(),
        "comiss"
            | "ucomiss"
            | "comisd"
            | "ucomisd"
            | "vcomiss"
            | "vucomiss"
            | "vcomisd"
            | "vucomisd"
    ) {
        return None;
    }

    Some(match cond {
        Condition::Equal => BinOpKind::Eq,
        Condition::NotEqual => BinOpKind::Ne,
        Condition::Above => BinOpKind::Gt,
        Condition::AboveOrEqual => BinOpKind::Ge,
        Condition::Below => BinOpKind::Lt,
        Condition::BelowOrEqual => BinOpKind::Le,
        Condition::Greater => BinOpKind::Gt,
        Condition::GreaterOrEqual => BinOpKind::Ge,
        Condition::Less => BinOpKind::Lt,
        Condition::LessOrEqual => BinOpKind::Le,
        _ => return None,
    })
}

fn expr_requires_single_evaluation(expr: &Expr) -> bool {
    use super::super::expression::ExprKind;

    match &expr.kind {
        ExprKind::Call { .. } | ExprKind::Assign { .. } | ExprKind::CompoundAssign { .. } => true,
        ExprKind::Deref { .. } | ExprKind::ArrayAccess { .. } | ExprKind::FieldAccess { .. } => {
            true
        }
        ExprKind::GotRef { is_deref, .. } => *is_deref,
        ExprKind::BinOp { left, right, .. } => {
            expr_requires_single_evaluation(left) || expr_requires_single_evaluation(right)
        }
        ExprKind::UnaryOp { operand, .. }
        | ExprKind::Cast { expr: operand, .. }
        | ExprKind::BitField { expr: operand, .. } => expr_requires_single_evaluation(operand),
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            expr_requires_single_evaluation(cond)
                || expr_requires_single_evaluation(then_expr)
                || expr_requires_single_evaluation(else_expr)
        }
        ExprKind::Phi(args) => args.iter().any(expr_requires_single_evaluation),
        ExprKind::AddressOf(_) | ExprKind::IntLit(_) | ExprKind::Unknown(_) | ExprKind::Var(_) => {
            false
        }
    }
}

fn expr_is_boolean_wrapper(expr: &Expr) -> bool {
    use super::super::expression::{ExprKind, UnaryOpKind};

    match &expr.kind {
        ExprKind::BinOp { op, .. } => {
            op.is_comparison() || matches!(op, BinOpKind::LogicalAnd | BinOpKind::LogicalOr)
        }
        ExprKind::UnaryOp {
            op: UnaryOpKind::LogicalNot,
            ..
        }
        | ExprKind::Conditional { .. } => true,
        ExprKind::Cast { expr, .. } => expr_is_boolean_wrapper(expr),
        _ => false,
    }
}

/// Converts a Condition to an Expr, extracting operands from the block's compare instruction.
/// Also substitutes register names with their values from preceding MOV instructions.
pub(super) fn condition_to_expr_with_block(cond: Condition, block: &BasicBlock) -> Expr {
    // Find the last compare in the block (no address limit)
    condition_to_expr_before_address_with_options(cond, block, None, true)
}

/// Converts a Condition to an Expr, falling back to a predecessor block when the current
/// block only contains the consuming branch and the flags were set earlier.
pub(super) fn condition_to_expr_with_block_and_fallback(
    cond: Condition,
    block: &BasicBlock,
    fallback_block: Option<&BasicBlock>,
) -> Expr {
    condition_to_expr_before_address_with_fallback(cond, block, None, true, fallback_block)
}

/// Converts a condition to an Expr without folding same-block ALU updates into register values.
/// This is useful for bottom-tested self-loops where the arithmetic update is already emitted
/// in the loop body and should not be duplicated in the condition.
pub(super) fn condition_to_expr_with_block_no_alu_updates(
    cond: Condition,
    block: &BasicBlock,
) -> Expr {
    condition_to_expr_before_address_with_options(cond, block, None, false)
}

/// Like `condition_to_expr_with_block_no_alu_updates`, but allows a predecessor fallback when
/// the condition consumes flags set in a different block.
pub(super) fn condition_to_expr_with_block_no_alu_updates_and_fallback(
    cond: Condition,
    block: &BasicBlock,
    fallback_block: Option<&BasicBlock>,
) -> Expr {
    condition_to_expr_before_address_with_fallback(cond, block, None, false, fallback_block)
}

/// Converts a Condition to an Expr, finding the compare instruction before the given address.
/// This is needed for ARM64 CMP+CSEL chains where each CSEL uses a different preceding CMP.
pub(super) fn condition_to_expr_before_address(
    cond: Condition,
    block: &BasicBlock,
    before_addr: Option<u64>,
) -> Expr {
    condition_to_expr_before_address_with_options(cond, block, before_addr, true)
}

fn condition_to_expr_before_address_with_options(
    cond: Condition,
    block: &BasicBlock,
    before_addr: Option<u64>,
    track_alu_updates: bool,
) -> Expr {
    condition_to_expr_before_address_with_fallback(
        cond,
        block,
        before_addr,
        track_alu_updates,
        None,
    )
}

fn condition_to_expr_before_address_with_fallback(
    cond: Condition,
    block: &BasicBlock,
    before_addr: Option<u64>,
    track_alu_updates: bool,
    fallback_block: Option<&BasicBlock>,
) -> Expr {
    let op = match cond {
        Condition::Equal => BinOpKind::Eq,
        Condition::NotEqual => BinOpKind::Ne,
        Condition::Less => BinOpKind::Lt,
        Condition::LessOrEqual => BinOpKind::Le,
        Condition::Greater => BinOpKind::Gt,
        Condition::GreaterOrEqual => BinOpKind::Ge,
        Condition::Below => BinOpKind::ULt,
        Condition::BelowOrEqual => BinOpKind::ULe,
        Condition::Above => BinOpKind::UGt,
        Condition::AboveOrEqual => BinOpKind::UGe,
        Condition::Sign => BinOpKind::Lt,
        Condition::NotSign => BinOpKind::Ge,
        _ => BinOpKind::Ne,
    };

    let branch_reg_values =
        build_register_value_map_with_options(block, before_addr, track_alu_updates);

    if let Some(cond_expr) = try_extract_arm64_branch_condition(block, op, &branch_reg_values) {
        return cond_expr;
    }

    let lift_condition_from_inst = |inst: &Instruction, reg_values: &HashMap<String, Expr>| {
        let cmp_op = x86_float_compare_binop(cond, inst).unwrap_or(op);

        if matches!(inst.operation, Operation::Neg) && !inst.operands.is_empty() {
            let operand = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[0], inst),
                reg_values,
            );
            let neg_op = match cond {
                Condition::Sign => BinOpKind::Gt,
                Condition::NotSign => BinOpKind::Le,
                _ => op,
            };
            return Some(Expr::binop(neg_op, operand, Expr::int(0)));
        }

        if matches!(inst.operation, Operation::Inc | Operation::Dec) && !inst.operands.is_empty() {
            let operand = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[0], inst),
                reg_values,
            );
            let adjustment = if matches!(inst.operation, Operation::Inc) {
                1
            } else {
                -1
            };
            let result = Expr::binop(BinOpKind::Add, operand, Expr::int(adjustment));
            return Some(Expr::binop(op, result, Expr::int(0)));
        }

        if inst.operands.len() >= 3 && matches!(inst.operation, Operation::Add) {
            let src1 = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[1], inst),
                reg_values,
            );
            let src2 = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[2], inst),
                reg_values,
            );
            let result = Expr::binop(BinOpKind::Add, src1, src2);
            return Some(Expr::binop(op, result, Expr::int(0)));
        }

        if inst.operands.len() == 2 && matches!(inst.operation, Operation::Add) {
            let dst = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[0], inst),
                reg_values,
            );
            let src = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[1], inst),
                reg_values,
            );
            let result = Expr::binop(BinOpKind::Add, dst, src);
            return Some(Expr::binop(op, result, Expr::int(0)));
        }

        if inst.operands.len() >= 3 && matches!(inst.operation, Operation::Sub) {
            let left = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[1], inst),
                reg_values,
            );
            let right = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[2], inst),
                reg_values,
            );
            return Some(Expr::binop(op, left, right));
        } else if inst.operands.len() >= 3
            && matches!(
                inst.operation,
                Operation::And | Operation::Or | Operation::Xor
            )
        {
            let src1 = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[1], inst),
                reg_values,
            );
            let src2 = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[2], inst),
                reg_values,
            );
            let binop_kind = match inst.operation {
                Operation::And => BinOpKind::And,
                Operation::Or => BinOpKind::Or,
                Operation::Xor => BinOpKind::Xor,
                _ => unreachable!(),
            };
            let result = Expr::binop(binop_kind, src1, src2);
            return Some(Expr::binop(op, result, Expr::int(0)));
        } else if inst.operands.len() == 2
            && matches!(
                inst.operation,
                Operation::And | Operation::Or | Operation::Xor
            )
        {
            let dst = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[0], inst),
                reg_values,
            );
            let src = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[1], inst),
                reg_values,
            );

            if matches!(inst.operation, Operation::Xor) && inst.operands[0] == inst.operands[1] {
                return Some(Expr::binop(op, Expr::int(0), Expr::int(0)));
            }

            let binop_kind = match inst.operation {
                Operation::And => BinOpKind::And,
                Operation::Or => BinOpKind::Or,
                Operation::Xor => BinOpKind::Xor,
                _ => unreachable!(),
            };
            let result = Expr::binop(binop_kind, dst, src);
            return Some(Expr::binop(op, result, Expr::int(0)));
        } else if inst.operands.len() >= 2 {
            let raw_left = Expr::from_operand_with_inst(&inst.operands[0], inst);
            let raw_right = Expr::from_operand_with_inst(&inst.operands[1], inst);
            let mut left = substitute_register_in_expr(raw_left.clone(), reg_values);
            let mut right = substitute_register_in_expr(raw_right.clone(), reg_values);

            if matches!(inst.operation, Operation::Test) {
                if matches!(inst.operands[0], Operand::Register(_))
                    && expr_requires_single_evaluation(&left)
                    && !expr_is_boolean_wrapper(&left)
                {
                    left = raw_left;
                }
                if matches!(inst.operands[1], Operand::Register(_))
                    && expr_requires_single_evaluation(&right)
                    && !expr_is_boolean_wrapper(&right)
                {
                    right = raw_right;
                }

                if inst.operands[0] == inst.operands[1] {
                    return Some(Expr::binop(cmp_op, left, Expr::int(0)));
                }

                let tested = Expr::binop(BinOpKind::And, left, right).simplify();
                return Some(Expr::binop(cmp_op, tested, Expr::int(0)));
            }

            return Some(Expr::binop(cmp_op, left, right));
        } else if inst.operands.len() == 1 {
            let left = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[0], inst),
                reg_values,
            );
            return Some(Expr::binop(cmp_op, left, Expr::int(0)));
        }

        None
    };

    if let Some(inst) = find_flag_setting_instruction(block, before_addr) {
        let reg_values =
            build_register_value_map_with_options(block, Some(inst.address), track_alu_updates);
        if let Some(expr) = lift_condition_from_inst(inst, &reg_values) {
            return expr;
        }
    } else if let Some(fallback_block) = fallback_block {
        if let Some(inst) = find_flag_setting_instruction(fallback_block, None) {
            let fallback_reg_values = build_register_value_map_with_options(
                fallback_block,
                Some(inst.address),
                track_alu_updates,
            );
            if let Some(expr) = lift_condition_from_inst(inst, &fallback_reg_values) {
                return expr;
            }
        }
    }

    let cond_name = match cond {
        Condition::Equal => "/* equal */",
        Condition::NotEqual => "/* not_equal */",
        Condition::Less => "/* signed_lt */",
        Condition::LessOrEqual => "/* signed_le */",
        Condition::Greater => "/* signed_gt */",
        Condition::GreaterOrEqual => "/* signed_ge */",
        Condition::Below => "/* unsigned_lt */",
        Condition::BelowOrEqual => "/* unsigned_le */",
        Condition::Above => "/* unsigned_gt */",
        Condition::AboveOrEqual => "/* unsigned_ge */",
        Condition::Sign => "/* negative */",
        Condition::NotSign => "/* non_negative */",
        Condition::Overflow => "/* overflow */",
        Condition::NotOverflow => "/* no_overflow */",
        Condition::Parity => "/* parity_even */",
        Condition::NotParity => "/* parity_odd */",
        _ => "/* condition */",
    };
    Expr::unknown(cond_name)
}

/// Builds a map of register names to their values from MOV/LDR instructions in a block.
/// This is used to substitute register names in conditions with meaningful variable names.
///
/// Special handling for return value captures: when the block starts with `mov dest, ret_reg`,
/// we map the return register (eax/rax/x0) to the destination register. This ensures
/// that conditions like `test eax, eax` display as `if (ebx == 0)` when we've merged
/// the call into `ebx = func()`.
pub(super) fn build_register_value_map(block: &BasicBlock) -> HashMap<String, Expr> {
    build_register_value_map_with_options(block, None, true)
}

fn build_register_value_map_with_options(
    block: &BasicBlock,
    before_addr: Option<u64>,
    track_alu_updates: bool,
) -> HashMap<String, Expr> {
    use super::super::expression::{ExprKind, VarKind, Variable};
    use hexray_core::Operand;

    let mut reg_values: HashMap<String, Expr> = HashMap::new();
    let mut at_block_start = true;
    let mut saw_call = false;
    let mut ret_capture_counter: u32 = 0;

    for inst in &block.instructions {
        if before_addr.is_some_and(|addr| inst.address >= addr) {
            break;
        }

        // Track if we've seen a call instruction
        if inst.is_call() {
            saw_call = true;
            // Model call return register as a unique temporary to avoid reusing arg names.
            let temp_name = format!("ret_{}", ret_capture_counter);
            ret_capture_counter += 1;
            let ret_var64 = Expr::var(Variable {
                name: temp_name.clone(),
                kind: VarKind::Temp(ret_capture_counter),
                size: 8,
            });
            let ret_var32 = Expr::var(Variable {
                name: temp_name.clone(),
                kind: VarKind::Temp(ret_capture_counter),
                size: 4,
            });
            reg_values.insert("rax".to_string(), ret_var64.clone());
            reg_values.insert("eax".to_string(), ret_var32.clone());
            reg_values.insert("x0".to_string(), ret_var64);
            reg_values.insert("w0".to_string(), ret_var32.clone());
            reg_values.insert("a0".to_string(), ret_var32);
            reg_values.insert(
                "arg0".to_string(),
                Expr::var(Variable {
                    name: temp_name,
                    kind: VarKind::Temp(ret_capture_counter),
                    size: 8,
                }),
            );
            at_block_start = false;
            continue;
        }

        // Look for MOV instructions (x86-64)
        if matches!(inst.operation, Operation::Move) && inst.operands.len() >= 2 {
            // First operand is destination (register), second is source
            if let Operand::Register(dst_reg) = &inst.operands[0] {
                let dst_name = dst_reg.name().to_lowercase();
                let substituted_src = substitute_register_in_expr(
                    Expr::from_operand_with_inst(&inst.operands[1], inst),
                    &reg_values,
                );
                let simplified_src = substituted_src.clone().simplify();

                // Check if source is a memory operand (stack variable or global)
                if let Operand::Memory { .. } = &inst.operands[1] {
                    insert_register_value_aliases(&mut reg_values, &dst_name, substituted_src);
                    at_block_start = false;
                }
                // Check for return value capture: mov dest, ret_reg at block start or after call
                // At block start, the previous block likely ended with a call
                // Only substitute if destination is a callee-saved register (indicating
                // the value is being preserved across calls, not just temporarily stored)
                else if at_block_start || saw_call {
                    let mut handled_return_capture = false;
                    if let Operand::Register(src_reg) = &inst.operands[1] {
                        let src_name = src_reg.name().to_lowercase();
                        // Return registers: eax/rax (x86-64), x0/w0 (ARM64)
                        if matches!(src_name.as_str(), "eax" | "rax" | "x0" | "w0") {
                            // Only substitute if destination is callee-saved
                            // x86-64: rbx, rbp, r12-r15 (and their 32-bit variants)
                            // ARM64: x19-x28
                            if is_callee_saved_register(&dst_name) {
                                // Map the return register to the destination variable
                                // So `eax` in conditions becomes `ebx` when we have `mov ebx, eax`
                                let dest_var = Variable {
                                    name: dst_name.clone(),
                                    kind: VarKind::Register(dst_reg.id),
                                    size: (dst_reg.size / 8) as u8,
                                };
                                insert_register_value_aliases(
                                    &mut reg_values,
                                    &src_name,
                                    Expr::var(dest_var),
                                );
                            }
                            at_block_start = false;
                            saw_call = false;
                            handled_return_capture = true;
                        }
                    }
                    if !handled_return_capture {
                        insert_register_value_aliases(&mut reg_values, &dst_name, simplified_src);
                        at_block_start = false;
                    }
                } else {
                    insert_register_value_aliases(&mut reg_values, &dst_name, simplified_src);
                    at_block_start = false;
                }
            }
        }

        if matches!(inst.operation, Operation::ConditionalMove) && inst.operands.len() >= 2 {
            if let Operand::Register(dst_reg) = &inst.operands[0] {
                let dst_name = dst_reg.name().to_lowercase();
                let current = reg_values
                    .get(&dst_name)
                    .cloned()
                    .unwrap_or_else(|| Expr::from_operand_with_inst(&inst.operands[0], inst));
                let src = substitute_register_in_expr(
                    Expr::from_operand_with_inst(&inst.operands[1], inst),
                    &reg_values,
                )
                .simplify();

                if let Some(cond) = parse_condition_from_mnemonic(&inst.mnemonic) {
                    let cond_expr =
                        condition_to_expr_before_address(cond, block, Some(inst.address));
                    let value = Expr {
                        kind: ExprKind::Conditional {
                            cond: Box::new(cond_expr),
                            then_expr: Box::new(src),
                            else_expr: Box::new(current),
                        },
                    }
                    .simplify();
                    insert_register_value_aliases(&mut reg_values, &dst_name, value);
                }
            }
            at_block_start = false;
            saw_call = false;
        }

        if matches!(inst.operation, Operation::SetConditional) && !inst.operands.is_empty() {
            if let Operand::Register(dst_reg) = &inst.operands[0] {
                let dst_name = dst_reg.name().to_lowercase();
                let lowered = lift_setcc_with_context(inst, block);
                if let super::super::expression::ExprKind::Assign { rhs, .. } = lowered.kind {
                    insert_register_value_aliases(&mut reg_values, &dst_name, *rhs);
                }
            }
            at_block_start = false;
            continue;
        }

        // Look for LDR instructions (ARM64): ldr reg, [sp, #offset]
        if matches!(inst.operation, Operation::Load) && inst.operands.len() >= 2 {
            // First operand is destination (register), second is source (memory)
            if let Operand::Register(reg) = &inst.operands[0] {
                let reg_name = reg.name().to_lowercase();
                // Track if source is a memory operand (stack variable or global)
                if let Operand::Memory { .. } = &inst.operands[1] {
                    let value = Expr::from_operand_with_inst(&inst.operands[1], inst);
                    insert_register_value_aliases(&mut reg_values, &reg_name, value);
                }
            }
            at_block_start = false;
        }

        // Track simple ALU updates so later TEST/CMP instructions see the computed value,
        // not just the register's last load.
        if track_alu_updates && inst.operands.len() >= 2 {
            if let Operand::Register(dst_reg) = &inst.operands[0] {
                let dst_name = dst_reg.name().to_lowercase();
                if let Some(binop) = binop_for_register_update(inst.operation) {
                    let current = reg_values
                        .get(&dst_name)
                        .cloned()
                        .unwrap_or_else(|| Expr::from_operand_with_inst(&inst.operands[0], inst));
                    let rhs = substitute_register_in_expr(
                        Expr::from_operand_with_inst(&inst.operands[1], inst),
                        &reg_values,
                    );
                    insert_register_value_aliases(
                        &mut reg_values,
                        &dst_name,
                        Expr::binop(binop, current, rhs).simplify(),
                    );
                }
            }
        }

        // Reset saw_call after any non-move instruction (except test/cmp which follow immediately)
        if !matches!(
            inst.operation,
            Operation::Move | Operation::Compare | Operation::Test
        ) {
            saw_call = false;
            at_block_start = false;
        }
    }

    reg_values
}

fn find_flag_setting_instruction(
    block: &BasicBlock,
    before_addr: Option<u64>,
) -> Option<&Instruction> {
    block
        .instructions
        .iter()
        .rev()
        .filter(|inst| before_addr.map_or(true, |addr| inst.address < addr))
        .find(|inst| is_flag_setting_instruction(inst))
}

fn binop_for_register_update(operation: Operation) -> Option<BinOpKind> {
    match operation {
        Operation::Add => Some(BinOpKind::Add),
        Operation::Sub => Some(BinOpKind::Sub),
        Operation::And => Some(BinOpKind::And),
        Operation::Or => Some(BinOpKind::Or),
        Operation::Xor => Some(BinOpKind::Xor),
        _ => None,
    }
}

fn insert_register_value_aliases(
    reg_values: &mut HashMap<String, Expr>,
    reg_name: &str,
    value: Expr,
) {
    for alias in register_aliases(reg_name) {
        reg_values.insert(alias, value.clone());
    }
}

fn register_aliases(name: &str) -> Vec<String> {
    match name {
        "al" | "ax" | "eax" | "rax" => vec![
            "al".to_string(),
            "ax".to_string(),
            "eax".to_string(),
            "rax".to_string(),
        ],
        "bl" | "bx" | "ebx" | "rbx" => vec![
            "bl".to_string(),
            "bx".to_string(),
            "ebx".to_string(),
            "rbx".to_string(),
        ],
        "cl" | "cx" | "ecx" | "rcx" => vec![
            "cl".to_string(),
            "cx".to_string(),
            "ecx".to_string(),
            "rcx".to_string(),
        ],
        "dl" | "dx" | "edx" | "rdx" => vec![
            "dl".to_string(),
            "dx".to_string(),
            "edx".to_string(),
            "rdx".to_string(),
        ],
        "sil" | "si" | "esi" | "rsi" => vec![
            "sil".to_string(),
            "si".to_string(),
            "esi".to_string(),
            "rsi".to_string(),
        ],
        "dil" | "di" | "edi" | "rdi" => vec![
            "dil".to_string(),
            "di".to_string(),
            "edi".to_string(),
            "rdi".to_string(),
        ],
        "r8d" | "r8" => vec!["r8d".to_string(), "r8".to_string()],
        "r9d" | "r9" => vec!["r9d".to_string(), "r9".to_string()],
        "r10d" | "r10" => vec!["r10d".to_string(), "r10".to_string()],
        "r11d" | "r11" => vec!["r11d".to_string(), "r11".to_string()],
        _ => {
            if let Some(rest) = name.strip_prefix('w') {
                if rest.chars().all(|ch| ch.is_ascii_digit()) {
                    return vec![name.to_string(), format!("x{}", rest)];
                }
            }
            if let Some(rest) = name.strip_prefix('x') {
                if rest.chars().all(|ch| ch.is_ascii_digit()) {
                    return vec![format!("w{}", rest), name.to_string()];
                }
            }
            vec![name.to_string()]
        }
    }
}

/// Substitutes register references in an expression with their known values.
fn substitute_register_in_expr(expr: Expr, reg_values: &HashMap<String, Expr>) -> Expr {
    use super::super::expression::ExprKind;

    match &expr.kind {
        ExprKind::Var(v) => {
            // Check if this variable name is a register we have a value for
            let lower_name = v.name.to_lowercase();
            if let Some(value) = reg_values.get(&lower_name) {
                value.clone()
            } else {
                expr
            }
        }
        ExprKind::BinOp { op, left, right } => Expr::binop(
            *op,
            substitute_register_in_expr((**left).clone(), reg_values),
            substitute_register_in_expr((**right).clone(), reg_values),
        ),
        ExprKind::UnaryOp { op, operand } => Expr::unary(
            *op,
            substitute_register_in_expr((**operand).clone(), reg_values),
        ),
        ExprKind::Deref { addr, size } => Expr::deref(
            substitute_register_in_expr((**addr).clone(), reg_values),
            *size,
        ),
        _ => expr,
    }
}

/// Simple condition conversion without block context (fallback).
pub(super) fn condition_to_expr(cond: Condition) -> Expr {
    // Use readable condition names instead of raw flag expressions
    let cond_name = match cond {
        Condition::Equal => "/* equal */",
        Condition::NotEqual => "/* not_equal */",
        Condition::Less => "/* signed_lt */",
        Condition::LessOrEqual => "/* signed_le */",
        Condition::Greater => "/* signed_gt */",
        Condition::GreaterOrEqual => "/* signed_ge */",
        Condition::Below => "/* unsigned_lt */",
        Condition::BelowOrEqual => "/* unsigned_le */",
        Condition::Above => "/* unsigned_gt */",
        Condition::AboveOrEqual => "/* unsigned_ge */",
        Condition::Sign => "/* negative */",
        Condition::NotSign => "/* non_negative */",
        Condition::Overflow => "/* overflow */",
        Condition::NotOverflow => "/* no_overflow */",
        Condition::Parity => "/* parity_even */",
        Condition::NotParity => "/* parity_odd */",
        _ => "/* condition */",
    };
    Expr::unknown(cond_name)
}

/// Negates a condition expression.
pub(super) fn negate_condition(expr: Expr) -> Expr {
    match &expr.kind {
        super::super::expression::ExprKind::BinOp { op, left, right } => {
            let negated_op = match op {
                BinOpKind::Eq => Some(BinOpKind::Ne),
                BinOpKind::Ne => Some(BinOpKind::Eq),
                BinOpKind::Lt => Some(BinOpKind::Ge),
                BinOpKind::Le => Some(BinOpKind::Gt),
                BinOpKind::Gt => Some(BinOpKind::Le),
                BinOpKind::Ge => Some(BinOpKind::Lt),
                BinOpKind::ULt => Some(BinOpKind::UGe),
                BinOpKind::ULe => Some(BinOpKind::UGt),
                BinOpKind::UGt => Some(BinOpKind::ULe),
                BinOpKind::UGe => Some(BinOpKind::ULt),
                _ => None,
            };
            if let Some(negated) = negated_op {
                Expr::binop(negated, (**left).clone(), (**right).clone())
            } else {
                Expr::unary(super::super::expression::UnaryOpKind::LogicalNot, expr)
            }
        }
        // Handle negation of condition comment placeholders
        super::super::expression::ExprKind::Unknown(s) => {
            let negated = match s.as_str() {
                "/* equal */" => "/* not_equal */",
                "/* not_equal */" => "/* equal */",
                "/* signed_lt */" => "/* signed_ge */",
                "/* signed_le */" => "/* signed_gt */",
                "/* signed_gt */" => "/* signed_le */",
                "/* signed_ge */" => "/* signed_lt */",
                "/* unsigned_lt */" => "/* unsigned_ge */",
                "/* unsigned_le */" => "/* unsigned_gt */",
                "/* unsigned_gt */" => "/* unsigned_le */",
                "/* unsigned_ge */" => "/* unsigned_lt */",
                "/* negative */" => "/* non_negative */",
                "/* non_negative */" => "/* negative */",
                "/* overflow */" => "/* no_overflow */",
                "/* no_overflow */" => "/* overflow */",
                "/* parity_even */" => "/* parity_odd */",
                "/* parity_odd */" => "/* parity_even */",
                _ => return Expr::unary(super::super::expression::UnaryOpKind::LogicalNot, expr),
            };
            Expr::unknown(negated)
        }
        _ => Expr::unary(super::super::expression::UnaryOpKind::LogicalNot, expr),
    }
}

/// Parses the condition suffix from a SETcc or CMOVcc mnemonic.
/// Returns None if the mnemonic doesn't have a recognized condition suffix.
pub(super) fn parse_condition_from_mnemonic(mnemonic: &str) -> Option<Condition> {
    // Handle ARM64 style: cset.eq, cinc.ne, csetm.mi, etc.
    if let Some(dot_pos) = mnemonic.find('.') {
        let prefix = &mnemonic[..dot_pos];
        let suffix = &mnemonic[dot_pos + 1..];
        // Check for ARM64 conditional instructions
        if matches!(
            prefix,
            "cset" | "csetm" | "cinc" | "cinv" | "cneg" | "csel" | "csinc" | "csinv" | "csneg"
        ) {
            return parse_arm64_condition(suffix);
        }
    }

    // Handle x86 style: sete, cmovne, etc.
    let suffix = if let Some(s) = mnemonic.strip_prefix("set") {
        s
    } else {
        mnemonic.strip_prefix("cmov")?
    };

    // Map x86 suffix to Condition
    match suffix {
        "e" | "z" => Some(Condition::Equal),
        "ne" | "nz" => Some(Condition::NotEqual),
        "l" | "nge" => Some(Condition::Less),
        "le" | "ng" => Some(Condition::LessOrEqual),
        "g" | "nle" => Some(Condition::Greater),
        "ge" | "nl" => Some(Condition::GreaterOrEqual),
        "b" | "c" | "nae" => Some(Condition::Below),
        "be" | "na" => Some(Condition::BelowOrEqual),
        "a" | "nbe" => Some(Condition::Above),
        "ae" | "nc" | "nb" => Some(Condition::AboveOrEqual),
        "s" => Some(Condition::Sign),
        "ns" => Some(Condition::NotSign),
        "o" => Some(Condition::Overflow),
        "no" => Some(Condition::NotOverflow),
        "p" | "pe" => Some(Condition::Parity),
        "np" | "po" => Some(Condition::NotParity),
        _ => None,
    }
}

/// Parse ARM64 condition code suffixes
pub(super) fn parse_arm64_condition(suffix: &str) -> Option<Condition> {
    match suffix {
        "eq" => Some(Condition::Equal),
        "ne" => Some(Condition::NotEqual),
        "lt" => Some(Condition::Less),
        "le" => Some(Condition::LessOrEqual),
        "gt" => Some(Condition::Greater),
        "ge" => Some(Condition::GreaterOrEqual),
        // Unsigned comparisons
        "lo" | "cc" => Some(Condition::Below), // Carry Clear = Below
        "ls" => Some(Condition::BelowOrEqual), // Lower or Same
        "hi" => Some(Condition::Above),        // Higher
        "hs" | "cs" => Some(Condition::AboveOrEqual), // Carry Set = Above or Equal
        // Sign/overflow
        "mi" => Some(Condition::Sign),        // Negative (minus)
        "pl" => Some(Condition::NotSign),     // Positive or zero (plus)
        "vs" => Some(Condition::Overflow),    // Overflow set
        "vc" => Some(Condition::NotOverflow), // Overflow clear
        // "al" (always) shouldn't appear in cset - just ignore it
        _ => None,
    }
}

/// Generates a writeback expression for post-indexed load/store instructions.
///
/// For ARM64 post-indexed addressing like `ldrb w9, [x8], #1`:
/// - The main load is: w9 = *x8
/// - The writeback is: x8 = x8 + 1
///
/// Returns None if no writeback is needed.
pub(super) fn generate_writeback_expr(inst: &hexray_core::Instruction) -> Option<Expr> {
    use super::super::expression::{ExprKind, VarKind, Variable};

    // Check if this is a load or store operation
    if !matches!(inst.operation, Operation::Load | Operation::Store) {
        return None;
    }

    // Find the memory operand with pre/post-indexed mode
    for operand in &inst.operands {
        if let Operand::Memory(mem) = operand {
            if mem.index_mode == IndexMode::Post || mem.index_mode == IndexMode::Pre {
                // Both pre and post-indexed have writeback: base = base + displacement
                if let Some(base_reg) = &mem.base {
                    let base_name = base_reg.name().to_lowercase();
                    let base_var = Expr {
                        kind: ExprKind::Var(Variable {
                            name: base_name.clone(),
                            kind: VarKind::Register(base_reg.id),
                            size: (base_reg.size / 8) as u8,
                        }),
                    };

                    // Create: base = base + displacement
                    let offset_expr = Expr::int(mem.displacement as i128);
                    let add_expr = Expr::binop(BinOpKind::Add, base_var.clone(), offset_expr);
                    return Some(Expr::assign(base_var, add_expr));
                }
            }
        }
    }

    None
}

/// Lifts a SETcc instruction with block context to get the actual comparison.
/// Returns an expression like: dest = (left op right)
/// For ARM64 CSEL: dest = cond ? src1 : src2
pub(super) fn lift_setcc_with_context(inst: &hexray_core::Instruction, block: &BasicBlock) -> Expr {
    let dest = if !inst.operands.is_empty() {
        Expr::from_operand_with_inst(&inst.operands[0], inst)
    } else {
        Expr::unknown(&inst.mnemonic)
    };

    // Check for ARM64 conditional instructions
    let mnem_lower = inst.mnemonic.to_lowercase();
    if let Some(dot_pos) = mnem_lower.find('.') {
        let prefix = &mnem_lower[..dot_pos];

        // CSEL/CSINC/CSINV/CSNEG have 3 operands: rd, rn, rm
        // rd = cond ? rn : rm (or variant)
        if matches!(prefix, "csel" | "csinc" | "csinv" | "csneg") && inst.operands.len() >= 3 {
            if let Some(cond) = parse_condition_from_mnemonic(&inst.mnemonic) {
                let cond_expr = condition_to_expr_before_address(cond, block, Some(inst.address));
                let then_expr = Expr::from_operand_with_inst(&inst.operands[1], inst);
                let else_expr = Expr::from_operand_with_inst(&inst.operands[2], inst);

                return Expr::assign(
                    dest,
                    Expr {
                        kind: super::super::expression::ExprKind::Conditional {
                            cond: Box::new(cond_expr),
                            then_expr: Box::new(then_expr),
                            else_expr: Box::new(else_expr),
                        },
                    },
                );
            }
        }

        // CINC/CINV/CNEG have 2 operands: rd, rn
        // cinc: rd = cond ? rn+1 : rn
        // cinv: rd = cond ? ~rn : rn
        // cneg: rd = cond ? -rn : rn
        if matches!(prefix, "cinc" | "cinv" | "cneg") && inst.operands.len() >= 2 {
            if let Some(cond) = parse_condition_from_mnemonic(&inst.mnemonic) {
                let cond_expr = condition_to_expr_before_address(cond, block, Some(inst.address));
                let src_expr = Expr::from_operand_with_inst(&inst.operands[1], inst);

                let then_expr = match prefix {
                    "cinc" => Expr::binop(
                        super::super::expression::BinOpKind::Add,
                        src_expr.clone(),
                        Expr::int(1),
                    ),
                    "cinv" => {
                        Expr::unary(super::super::expression::UnaryOpKind::Not, src_expr.clone())
                    }
                    "cneg" => {
                        Expr::unary(super::super::expression::UnaryOpKind::Neg, src_expr.clone())
                    }
                    _ => src_expr.clone(),
                };

                return Expr::assign(
                    dest,
                    Expr {
                        kind: super::super::expression::ExprKind::Conditional {
                            cond: Box::new(cond_expr),
                            then_expr: Box::new(then_expr),
                            else_expr: Box::new(src_expr),
                        },
                    },
                );
            }
        }

        // CSET/CSETM have 1 operand: rd
        // cset: rd = cond ? 1 : 0
        // csetm: rd = cond ? -1 : 0
        if matches!(prefix, "cset" | "csetm") && !inst.operands.is_empty() {
            if let Some(cond) = parse_condition_from_mnemonic(&inst.mnemonic) {
                let cond_expr = condition_to_expr_before_address(cond, block, Some(inst.address));

                let (then_val, else_val) = if prefix == "csetm" {
                    (Expr::int(-1), Expr::int(0))
                } else {
                    (Expr::int(1), Expr::int(0))
                };

                return Expr::assign(
                    dest,
                    Expr {
                        kind: super::super::expression::ExprKind::Conditional {
                            cond: Box::new(cond_expr),
                            then_expr: Box::new(then_val),
                            else_expr: Box::new(else_val),
                        },
                    },
                );
            }
        }
    }

    // Try to parse condition from mnemonic (for CSET, SETcc, etc.)
    if let Some(cond) = parse_condition_from_mnemonic(&inst.mnemonic) {
        // SETcc reads the flags as they existed at this instruction, not after later ALU ops.
        let cond_expr = condition_to_expr_before_address(cond, block, Some(inst.address));
        // Assign the boolean result to the destination
        Expr::assign(dest, cond_expr)
    } else {
        // Fallback: emit as function call if we can't parse the condition
        Expr::assign(
            dest,
            Expr::call(
                super::super::expression::CallTarget::Named(inst.mnemonic.clone()),
                vec![],
            ),
        )
    }
}

/// Lifts a CMOVcc instruction with block context.
/// Returns an expression like: dest = condition ? src : dest
/// For simplicity, we emit: if (condition) dest = src
pub(super) fn lift_cmovcc_with_context(
    inst: &hexray_core::Instruction,
    block: &BasicBlock,
) -> Expr {
    if inst.operands.len() < 2 {
        return Expr::unknown(&inst.mnemonic);
    }

    let dest = Expr::from_operand_with_inst(&inst.operands[0], inst);
    let src = Expr::from_operand_with_inst(&inst.operands[1], inst);

    // Try to parse condition from mnemonic
    if let Some(cond) = parse_condition_from_mnemonic(&inst.mnemonic) {
        let cond_expr = condition_to_expr_before_address(cond, block, Some(inst.address));
        // Emit as conditional: dest = (cond) ? src : dest
        Expr::assign(
            dest.clone(),
            Expr {
                kind: super::super::expression::ExprKind::Conditional {
                    cond: Box::new(cond_expr),
                    then_expr: Box::new(src),
                    else_expr: Box::new(dest),
                },
            },
        )
    } else {
        // Fallback: emit as function call
        Expr::assign(
            dest,
            Expr::call(
                super::super::expression::CallTarget::Named(inst.mnemonic.clone()),
                vec![src],
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexray_core::{
        Architecture, BasicBlock, BasicBlockId, ControlFlow, Instruction, MemoryRef, Operand,
        Register, RegisterClass,
    };

    #[test]
    fn test_condition_uses_loaded_stack_value_for_32bit_register_alias() {
        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);
        let rbp = Register::new(Architecture::X86_64, RegisterClass::General, 5, 64);

        let mut block = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        block.instructions.push(
            Instruction::new(0x1000, 3, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![
                    Operand::Register(eax),
                    Operand::Memory(MemoryRef::base_disp(rbp, -8, 4)),
                ]),
        );
        block.instructions.push(
            Instruction::new(0x1003, 3, vec![], "cmp")
                .with_operation(Operation::Compare)
                .with_operands(vec![
                    Operand::Register(eax),
                    Operand::Memory(MemoryRef::base_disp(rbp, -0x14, 4)),
                ]),
        );

        let expr = condition_to_expr_with_block(Condition::Less, &block);
        let rendered = format!("{expr}");
        assert!(
            !rendered.contains("ret"),
            "expected condition alias resolution to avoid return placeholder, got {rendered}"
        );
        assert!(
            rendered.contains("rbp + -0x8"),
            "expected cmp lhs to resolve through the loaded stack slot, got {rendered}"
        );
    }

    #[test]
    fn test_condition_preserves_simple_alu_chain_before_test() {
        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);
        let rbp = Register::new(Architecture::X86_64, RegisterClass::General, 5, 64);

        let mut block = BasicBlock::new(BasicBlockId::new(0), 0x2000);
        block.instructions.push(
            Instruction::new(0x2000, 3, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![
                    Operand::Register(eax),
                    Operand::Memory(MemoryRef::base_disp(rbp, -8, 4)),
                ]),
        );
        block.instructions.push(
            Instruction::new(0x2003, 2, vec![], "and")
                .with_operation(Operation::And)
                .with_operands(vec![Operand::Register(eax), Operand::imm_unsigned(1, 32)]),
        );
        block.instructions.push(
            Instruction::new(0x2005, 2, vec![], "test")
                .with_operation(Operation::Test)
                .with_operands(vec![Operand::Register(eax), Operand::Register(eax)]),
        );

        let expr = condition_to_expr_with_block(Condition::NotEqual, &block);
        let rendered = format!("{expr}");
        assert!(
            (rendered.contains("rax") || rendered.contains("eax"))
                && !rendered.contains("rbp + -0x8")
                && !rendered.contains("[rbp"),
            "expected TEST lowering to reuse the loaded register without re-reading memory, got {rendered}"
        );
    }

    #[test]
    fn test_condition_lifts_test_mask_as_and_zero_compare() {
        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);
        let ecx = Register::new(Architecture::X86_64, RegisterClass::General, 1, 32);

        let mut block = BasicBlock::new(BasicBlockId::new(0), 0x2200);
        block.instructions.push(
            Instruction::new(0x2200, 2, vec![], "test")
                .with_operation(Operation::Test)
                .with_operands(vec![Operand::Register(eax), Operand::Register(ecx)]),
        );

        let equal = format!("{}", condition_to_expr_with_block(Condition::Equal, &block));
        assert!(
            equal.contains('&') && (equal.contains("== 0") || equal.contains("== '\\0'")),
            "expected TEST/JE to lower as an AND-against-zero predicate, got {equal}"
        );

        let not_equal = format!(
            "{}",
            condition_to_expr_with_block(Condition::NotEqual, &block)
        );
        assert!(
            not_equal.contains('&')
                && (not_equal.contains("!= 0") || not_equal.contains("!= '\\0'")),
            "expected TEST/JNE to lower as an AND-against-zero predicate, got {not_equal}"
        );
    }

    #[test]
    fn test_condition_can_skip_same_block_alu_substitution() {
        let edi = Register::new(Architecture::X86_64, RegisterClass::General, 7, 32);

        let mut block = BasicBlock::new(BasicBlockId::new(0), 0x2400);
        block.instructions.push(
            Instruction::new(0x2400, 3, vec![], "sub")
                .with_operation(Operation::Sub)
                .with_operands(vec![Operand::Register(edi), Operand::imm_unsigned(1, 32)]),
        );
        block.instructions.push(
            Instruction::new(0x2403, 3, vec![], "cmp")
                .with_operation(Operation::Compare)
                .with_operands(vec![Operand::Register(edi), Operand::imm_unsigned(1, 32)]),
        );

        let expr = condition_to_expr_with_block_no_alu_updates(Condition::NotEqual, &block);
        assert_eq!(format!("{expr}"), "rdi != 1");
    }

    #[test]
    fn test_condition_uses_call_return_temp_for_low_byte_alias() {
        let al = Register::new(Architecture::X86_64, RegisterClass::General, 0, 8);

        let mut block = BasicBlock::new(BasicBlockId::new(0), 0x3000);
        block.instructions.push(
            Instruction::new(0x3000, 5, vec![], "call").with_control_flow(ControlFlow::Call {
                target: 0x4000,
                return_addr: 0x3005,
            }),
        );
        block.instructions.push(
            Instruction::new(0x3005, 2, vec![], "test")
                .with_operation(Operation::Test)
                .with_operands(vec![Operand::Register(al), Operand::Register(al)]),
        );

        let expr = condition_to_expr_with_block(Condition::NotEqual, &block);
        let rendered = format!("{expr}");
        assert!(
            rendered.contains("ret_0"),
            "expected TEST on al to resolve through call return temp, got {rendered}"
        );
    }

    #[test]
    fn test_condition_ignores_post_test_clobbers_in_same_block() {
        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);
        let rax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 64);
        let rbp = Register::new(Architecture::X86_64, RegisterClass::General, 5, 64);

        let mut block = BasicBlock::new(BasicBlockId::new(0), 0x3200);
        block.instructions.push(
            Instruction::new(0x3200, 5, vec![], "call").with_control_flow(ControlFlow::Call {
                target: 0x4000,
                return_addr: 0x3205,
            }),
        );
        block.instructions.push(
            Instruction::new(0x3205, 2, vec![], "test")
                .with_operation(Operation::Test)
                .with_operands(vec![Operand::Register(eax), Operand::Register(eax)]),
        );
        block.instructions.push(
            Instruction::new(0x3207, 4, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![
                    Operand::Register(rax),
                    Operand::Memory(MemoryRef::base_disp(rbp, -8, 8)),
                ]),
        );

        let expr = condition_to_expr_with_block(Condition::NotEqual, &block);
        let rendered = format!("{expr}");
        assert!(
            rendered.contains("ret_0"),
            "expected condition to use the call result before later clobbers, got {rendered}"
        );
        assert!(
            !rendered.contains("rbp + -0x8"),
            "expected later register writes to be ignored for the TEST predicate, got {rendered}"
        );
    }

    #[test]
    fn test_condition_can_fall_back_to_predecessor_compare() {
        let edi = Register::new(Architecture::X86_64, RegisterClass::General, 7, 32);

        let mut pred = BasicBlock::new(BasicBlockId::new(0), 0x4000);
        pred.instructions.push(
            Instruction::new(0x4000, 3, vec![], "cmp")
                .with_operation(Operation::Compare)
                .with_operands(vec![Operand::Register(edi), Operand::imm_unsigned(100, 32)]),
        );

        let mut block = BasicBlock::new(BasicBlockId::new(1), 0x4003);
        block.instructions.push(
            Instruction::new(0x4003, 2, vec![], "jg")
                .with_operation(Operation::ConditionalJump)
                .with_operands(vec![Operand::pc_rel(0x4005, 0x4010)]),
        );

        let expr =
            condition_to_expr_with_block_and_fallback(Condition::Greater, &block, Some(&pred));
        let rendered = format!("{expr}");
        assert!(
            rendered.contains("rdi >") || rendered.contains("edi >"),
            "expected predecessor compare operands to be recovered, got {rendered}"
        );
        assert!(
            !rendered.contains("signed_gt"),
            "expected real comparison instead of placeholder, got {rendered}"
        );
    }

    #[test]
    fn test_condition_tracks_cmove_boolean_wrapper_through_test() {
        let rax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 64);
        let rcx = Register::new(Architecture::X86_64, RegisterClass::General, 1, 64);
        let rdx = Register::new(Architecture::X86_64, RegisterClass::General, 2, 64);
        let rsp = Register::new(Architecture::X86_64, RegisterClass::General, 4, 64);

        let mut block = BasicBlock::new(BasicBlockId::new(0), 0x5000);
        block.instructions.push(
            Instruction::new(0x5000, 10, vec![], "movabs")
                .with_operation(Operation::Move)
                .with_operands(vec![
                    Operand::Register(rdx),
                    Operand::imm(i64::MIN as i128, 64),
                ]),
        );
        block.instructions.push(
            Instruction::new(0x500a, 5, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(rax), Operand::imm_unsigned(1, 32)]),
        );
        block.instructions.push(
            Instruction::new(0x500f, 2, vec![], "xor")
                .with_operation(Operation::Xor)
                .with_operands(vec![Operand::Register(rcx), Operand::Register(rcx)]),
        );
        block.instructions.push(
            Instruction::new(0x5011, 7, vec![], "cmp")
                .with_operation(Operation::Compare)
                .with_operands(vec![
                    Operand::Memory(MemoryRef::base_disp(rsp, 0x100, 8)),
                    Operand::Register(rdx),
                ]),
        );
        block.instructions.push(
            Instruction::new(0x5018, 4, vec![], "cmove")
                .with_operation(Operation::ConditionalMove)
                .with_operands(vec![Operand::Register(rax), Operand::Register(rcx)]),
        );
        block.instructions.push(
            Instruction::new(0x501c, 4, vec![], "test")
                .with_operation(Operation::Test)
                .with_operands(vec![Operand::Register(rax), Operand::imm_unsigned(1, 32)]),
        );

        let reg_values = build_register_value_map_with_options(&block, Some(0x501c), true);
        let Some(rax_value) = reg_values.get("rax") else {
            panic!("expected rax value to be tracked through cmove");
        };
        assert_eq!(
            format!("{rax_value}"),
            "rsp[0x20] == -0x8000000000000000 ? 0 : 1"
        );

        let expr = condition_to_expr_with_block(Condition::NotEqual, &block).simplify();
        let rendered = format!("{expr}");
        assert!(
            rendered.contains("== -0x8000000000000000")
                || rendered.contains("!= -0x8000000000000000"),
            "expected cmove/test wrapper to collapse back to a direct compare, got {rendered}"
        );
        assert!(
            !rendered.contains("== 1"),
            "expected no boolean-compare chain after cmove/test lowering, got {rendered}"
        );
    }

    #[test]
    fn test_lift_setcc_uses_flags_before_later_alu_updates() {
        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);
        let esi = Register::new(Architecture::X86_64, RegisterClass::General, 6, 32);
        let al = Register::new(Architecture::X86_64, RegisterClass::General, 0, 8);

        let mut block = BasicBlock::new(BasicBlockId::new(0), 0x5000);
        block.instructions.push(
            Instruction::new(0x5000, 3, vec![], "cmp")
                .with_operation(Operation::Compare)
                .with_operands(vec![Operand::Register(esi), Operand::imm_unsigned(1, 32)]),
        );
        let setne = Instruction::new(0x5003, 3, vec![], "setne")
            .with_operation(Operation::SetConditional)
            .with_operands(vec![Operand::Register(al)]);
        block.instructions.push(setne.clone());
        block.instructions.push(
            Instruction::new(0x5006, 3, vec![], "add")
                .with_operation(Operation::Add)
                .with_operands(vec![Operand::Register(eax), Operand::imm_unsigned(2, 32)]),
        );

        let rendered = format!("{}", lift_setcc_with_context(&setne, &block));
        assert!(
            rendered.contains("!= 1"),
            "expected SETcc to use the preceding CMP operands, got {rendered}"
        );
        assert!(
            !rendered.contains("+ 2"),
            "expected SETcc lowering to ignore later flag clobbers, got {rendered}"
        );
    }

    #[test]
    fn test_condition_lifts_setcc_test_chain_as_negated_predicate() {
        let edi = Register::new(Architecture::X86_64, RegisterClass::General, 7, 32);
        let al = Register::new(Architecture::X86_64, RegisterClass::General, 0, 8);

        let mut block = BasicBlock::new(BasicBlockId::new(0), 0x7000);
        block.instructions.push(
            Instruction::new(0x7000, 3, vec![], "cmp")
                .with_operation(Operation::Compare)
                .with_operands(vec![Operand::Register(edi), Operand::imm(-1, 32)]),
        );
        block.instructions.push(
            Instruction::new(0x7003, 3, vec![], "sete")
                .with_operation(Operation::SetConditional)
                .with_operands(vec![Operand::Register(al)]),
        );
        block.instructions.push(
            Instruction::new(0x7006, 2, vec![], "test")
                .with_operation(Operation::Test)
                .with_operands(vec![Operand::Register(al), Operand::Register(al)]),
        );

        let rendered = format!(
            "{}",
            condition_to_expr_with_block(Condition::Equal, &block).simplify()
        );
        assert!(
            rendered.contains("!="),
            "expected setcc/test/je chain to render as a negated compare, got {rendered}"
        );
        assert!(
            !rendered.contains("== 0"),
            "expected no trailing boolean compare wrapper, got {rendered}"
        );
    }

    #[test]
    fn test_float_compare_maps_ja_to_gt_after_vcomiss() {
        use hexray_core::register::x86;

        let xmm0 = Register::new(
            Architecture::X86_64,
            RegisterClass::FloatingPoint,
            x86::XMM0,
            128,
        );
        let xmm1 = Register::new(
            Architecture::X86_64,
            RegisterClass::FloatingPoint,
            x86::XMM1,
            128,
        );

        let mut block = BasicBlock::new(BasicBlockId::new(0), 0x6000);
        block.instructions.push(
            Instruction::new(0x6000, 4, vec![], "vcomiss")
                .with_operation(Operation::Compare)
                .with_operands(vec![Operand::Register(xmm1), Operand::Register(xmm0)]),
        );

        let rendered = format!("{}", condition_to_expr_with_block(Condition::Above, &block));
        assert_eq!(rendered, "xmm1 > xmm0");
    }
}
