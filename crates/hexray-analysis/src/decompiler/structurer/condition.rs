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

/// Converts a Condition to an Expr, extracting operands from the block's compare instruction.
/// Also substitutes register names with their values from preceding MOV instructions.
pub(super) fn condition_to_expr_with_block(cond: Condition, block: &BasicBlock) -> Expr {
    // Find the last compare in the block (no address limit)
    condition_to_expr_before_address(cond, block, None)
}

/// Converts a Condition to an Expr, finding the compare instruction before the given address.
/// This is needed for ARM64 CMP+CSEL chains where each CSEL uses a different preceding CMP.
pub(super) fn condition_to_expr_before_address(
    cond: Condition,
    block: &BasicBlock,
    before_addr: Option<u64>,
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
        // Sign/NotSign: after CMP x, y, MI is set when x - y < 0 (signed)
        Condition::Sign => BinOpKind::Lt,
        Condition::NotSign => BinOpKind::Ge,
        _ => BinOpKind::Ne, // Default for flag-based conditions
    };

    // Build a map of register values from MOV instructions before the compare
    let reg_values = build_register_value_map(block);

    // Check for ARM64 CBZ/CBNZ/TBZ/TBNZ instructions first
    // These have the comparison built into the branch instruction itself
    if let Some(cond_expr) = try_extract_arm64_branch_condition(block, op, &reg_values) {
        return cond_expr;
    }

    // Find the last flag-setting instruction in the block (before the given address if specified)
    // This includes CMP, TEST, SUB, NEG, ADD, INC, DEC, AND, OR, XOR, and shift operations
    let compare_inst = block
        .instructions
        .iter()
        .rev()
        .filter(|inst| {
            // If before_addr is specified, only consider instructions before that address
            before_addr.map_or(true, |addr| inst.address < addr)
        })
        .find(|inst| is_flag_setting_instruction(inst));

    if let Some(inst) = compare_inst {
        // For NEG instructions, flags reflect the negated result
        // neg eax: SF set if (-eax) < 0, i.e., eax > 0
        // For Sign condition after NEG, we need "operand > 0" (or < 0 for inverted)
        if matches!(inst.operation, Operation::Neg) && !inst.operands.is_empty() {
            let operand = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[0], inst),
                &reg_values,
            );
            // NEG sets SF if result is negative, meaning original was positive
            // So Sign (SF) after NEG means original > 0
            let neg_op = match cond {
                Condition::Sign => BinOpKind::Gt,    // SF set means orig > 0
                Condition::NotSign => BinOpKind::Le, // SF clear means orig <= 0
                _ => op,                             // Use default mapping for other conditions
            };
            return Expr::binop(neg_op, operand, Expr::int(0));
        }

        // INC/DEC: compare result against 0
        if matches!(inst.operation, Operation::Inc | Operation::Dec) && !inst.operands.is_empty() {
            let operand = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[0], inst),
                &reg_values,
            );
            let adjustment = if matches!(inst.operation, Operation::Inc) {
                1
            } else {
                -1
            };
            let result = Expr::binop(BinOpKind::Add, operand, Expr::int(adjustment));
            return Expr::binop(op, result, Expr::int(0));
        }

        // ADD (3 operands): ARM64 ADDS
        if inst.operands.len() >= 3 && matches!(inst.operation, Operation::Add) {
            let src1 = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[1], inst),
                &reg_values,
            );
            let src2 = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[2], inst),
                &reg_values,
            );
            let result = Expr::binop(BinOpKind::Add, src1, src2);
            return Expr::binop(op, result, Expr::int(0));
        }

        // ADD (2 operands): x86 ADD
        if inst.operands.len() == 2 && matches!(inst.operation, Operation::Add) {
            let dst = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[0], inst),
                &reg_values,
            );
            let src = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[1], inst),
                &reg_values,
            );
            let result = Expr::binop(BinOpKind::Add, dst, src);
            return Expr::binop(op, result, Expr::int(0));
        }

        // For SUB/SUBS instructions (ARM64), operands are [dst, src1, src2]
        // The comparison is between src1 and src2
        if inst.operands.len() >= 3 && matches!(inst.operation, Operation::Sub) {
            let left = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[1], inst),
                &reg_values,
            );
            let right = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[2], inst),
                &reg_values,
            );
            return Expr::binop(op, left, right);
        } else if inst.operands.len() >= 3
            && matches!(
                inst.operation,
                Operation::And | Operation::Or | Operation::Xor
            )
        {
            // ARM64: ANDS/ORRS/EORS dst, src1, src2
            let src1 = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[1], inst),
                &reg_values,
            );
            let src2 = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[2], inst),
                &reg_values,
            );
            let binop_kind = match inst.operation {
                Operation::And => BinOpKind::And,
                Operation::Or => BinOpKind::Or,
                Operation::Xor => BinOpKind::Xor,
                _ => unreachable!(),
            };
            let result = Expr::binop(binop_kind, src1, src2);
            return Expr::binop(op, result, Expr::int(0));
        } else if inst.operands.len() == 2
            && matches!(
                inst.operation,
                Operation::And | Operation::Or | Operation::Xor
            )
        {
            // x86: AND/OR/XOR dst, src
            let dst = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[0], inst),
                &reg_values,
            );
            let src = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[1], inst),
                &reg_values,
            );

            // Special case: XOR reg, reg clears to 0
            if matches!(inst.operation, Operation::Xor) && inst.operands[0] == inst.operands[1] {
                return Expr::binop(op, Expr::int(0), Expr::int(0));
            }

            let binop_kind = match inst.operation {
                Operation::And => BinOpKind::And,
                Operation::Or => BinOpKind::Or,
                Operation::Xor => BinOpKind::Xor,
                _ => unreachable!(),
            };
            let result = Expr::binop(binop_kind, dst, src);
            return Expr::binop(op, result, Expr::int(0));
        } else if inst.operands.len() >= 2 {
            // For CMP/TEST instructions, operands are [src1, src2]
            let left = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[0], inst),
                &reg_values,
            );
            let right = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[1], inst),
                &reg_values,
            );

            // Special case: TEST reg, reg (same register) is a zero check
            // test eax, eax; je → jump if eax == 0
            // test eax, eax; jne → jump if eax != 0
            if matches!(inst.operation, Operation::Test) && inst.operands[0] == inst.operands[1] {
                return Expr::binop(op, left, Expr::int(0));
            }

            return Expr::binop(op, left, right);
        } else if inst.operands.len() == 1 {
            // Compare against zero (common for test/cmp with single operand)
            let left = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[0], inst),
                &reg_values,
            );
            return Expr::binop(op, left, Expr::int(0));
        }
    }

    // Fallback: show a descriptive condition name when compare not found
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
    // Return just the condition name as an unknown expression
    // The operator and 0 comparison are implicit
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
    use super::super::expression::{VarKind, Variable};
    use hexray_core::Operand;

    let mut reg_values: HashMap<String, Expr> = HashMap::new();
    let mut at_block_start = true;
    let mut saw_call = false;
    let mut ret_capture_counter: u32 = 0;

    for inst in &block.instructions {
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

                // Check if source is a memory operand (stack variable or global)
                if let Operand::Memory { .. } = &inst.operands[1] {
                    let value = Expr::from_operand_with_inst(&inst.operands[1], inst);
                    reg_values.insert(dst_name, value);
                    at_block_start = false;
                }
                // Check for return value capture: mov dest, ret_reg at block start or after call
                // At block start, the previous block likely ended with a call
                // Only substitute if destination is a callee-saved register (indicating
                // the value is being preserved across calls, not just temporarily stored)
                else if at_block_start || saw_call {
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
                                let dest_var = super::super::expression::Variable {
                                    name: dst_name.clone(),
                                    kind: super::super::expression::VarKind::Register(dst_reg.id),
                                    size: (dst_reg.size / 8) as u8,
                                };
                                reg_values.insert(src_name, Expr::var(dest_var));
                            }
                            at_block_start = false;
                            saw_call = false;
                        }
                    }
                }
            }
        }

        // Look for LDR instructions (ARM64): ldr reg, [sp, #offset]
        if matches!(inst.operation, Operation::Load) && inst.operands.len() >= 2 {
            // First operand is destination (register), second is source (memory)
            if let Operand::Register(reg) = &inst.operands[0] {
                let reg_name = reg.name().to_lowercase();
                // Track if source is a memory operand (stack variable or global)
                if let Operand::Memory { .. } = &inst.operands[1] {
                    let value = Expr::from_operand_with_inst(&inst.operands[1], inst);
                    reg_values.insert(reg_name, value);
                }
            }
            at_block_start = false;
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
        // Get the comparison expression using the block context
        let cond_expr = condition_to_expr_with_block(cond, block);
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
        // Get the comparison expression
        let cond_expr = condition_to_expr_with_block(cond, block);
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
