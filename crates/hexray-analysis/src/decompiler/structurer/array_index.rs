//! Reconstruct array-index dereferences that survive copy propagation.
//!
//! At `-O0` an `arr[i]` access lowers to a chain of register temporaries that
//! copy propagation leaves intact, because the chain crosses a memory load (the
//! index) and an opaque sign-extension (`cdqe`):
//!
//! ```text
//! eax = i; cdqe; rdx = eax * 4; rax = base + rdx; ... *(rax) ...
//! ```
//!
//! General copy propagation deliberately does not duplicate the memory load, so
//! the address never folds and the dereference reads `*(rax)` with `rax` an
//! opaque temporary (often displayed by ABI role, e.g. `arr[arg2]`).
//!
//! This block-local pass forward-resolves register values *specifically to
//! rewrite dereference addresses*: it propagates the index memory load and
//! treats `cdqe`/`cltq` as transparent, so `*(rax)` resolves to
//! `*(base + i*scale)`, which [`try_detect_array_in_deref`] turns into
//! `base[i]`. It only rewrites a dereference when the resolved address is a
//! genuine `base + index*scale` array pattern — every other expression is left
//! untouched — and the now-dead index temporaries are removed by the existing
//! dead-assignment passes.

use super::super::expression::{try_detect_array_in_deref, CallTarget, Expr, ExprKind, VarKind};
use super::StructuredNode;
use std::collections::HashMap;

/// Resolved register values within the current block, used only to rewrite
/// dereference addresses.
type ValueMap = HashMap<String, Expr>;

pub(super) fn reconstruct_array_index_derefs(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    nodes.into_iter().map(reconstruct_node).collect()
}

fn reconstruct_node(node: StructuredNode) -> StructuredNode {
    match node {
        StructuredNode::Block {
            id,
            statements,
            address_range,
        } => StructuredNode::Block {
            id,
            statements: process_block(statements),
            address_range,
        },
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition,
            then_body: reconstruct_array_index_derefs(then_body),
            else_body: else_body.map(reconstruct_array_index_derefs),
        },
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition,
            body: reconstruct_array_index_derefs(body),
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: reconstruct_array_index_derefs(body),
            condition,
            header,
            exit_block,
        },
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => StructuredNode::For {
            init,
            condition,
            update,
            body: reconstruct_array_index_derefs(body),
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: reconstruct_array_index_derefs(body),
            header,
            exit_block,
        },
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value,
            cases: cases
                .into_iter()
                .map(|(vals, body)| (vals, reconstruct_array_index_derefs(body)))
                .collect(),
            default: default.map(reconstruct_array_index_derefs),
        },
        StructuredNode::Sequence(body) => {
            StructuredNode::Sequence(reconstruct_array_index_derefs(body))
        }
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => StructuredNode::TryCatch {
            try_body: reconstruct_array_index_derefs(try_body),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|mut h| {
                    h.body = reconstruct_array_index_derefs(h.body);
                    h
                })
                .collect(),
        },
        other => other,
    }
}

fn process_block(statements: Vec<Expr>) -> Vec<Expr> {
    let mut values: ValueMap = HashMap::new();
    let mut out = Vec::with_capacity(statements.len());

    for stmt in statements {
        // `cdqe`/`cltq` widen the accumulator in place; for index arithmetic the
        // sign-extension is transparent, so keep the tracked value and emit the
        // instruction unchanged.
        if is_accumulator_sign_extend(&stmt) {
            out.push(stmt);
            continue;
        }

        // Rewrite dereference addresses that resolve to an array access.
        let stmt = rewrite_array_derefs(stmt, &values);

        // Update the value map from this statement.
        if let ExprKind::Assign { lhs, rhs } = &stmt.kind {
            if let ExprKind::Var(v) = &lhs.kind {
                if matches!(v.kind, VarKind::Register(_)) {
                    let resolved = resolve(rhs, &values);
                    values.insert(v.name.to_lowercase(), resolved);
                }
            }
        }

        // A real call clobbers registers; a memory write may alias a tracked
        // index load. Both invalidate the relevant tracked values.
        if statement_is_real_call(&stmt) {
            values.clear();
        } else if statement_writes_memory(&stmt) {
            values.retain(|_, e| !expr_reads_memory(e));
        }

        out.push(stmt);
    }

    out
}

/// Substitute tracked register values into an expression (one level deep — the
/// map already holds fully resolved values).
fn resolve(expr: &Expr, values: &ValueMap) -> Expr {
    match &expr.kind {
        ExprKind::Var(v) => values
            .get(&v.name.to_lowercase())
            .cloned()
            .unwrap_or_else(|| expr.clone()),
        ExprKind::BinOp { op, left, right } => Expr::binop(
            *op,
            resolve(left, values),
            resolve(right, values),
        ),
        ExprKind::UnaryOp { op, operand } => Expr::unary(*op, resolve(operand, values)),
        ExprKind::Cast {
            expr: inner,
            to_size,
            signed,
        } => Expr {
            kind: ExprKind::Cast {
                expr: Box::new(resolve(inner, values)),
                to_size: *to_size,
                signed: *signed,
            },
        },
        // Do not resolve through dereferences/other shapes — only the flat
        // address arithmetic of an index chain matters here.
        _ => expr.clone(),
    }
}

/// Rewrite every dereference whose resolved address is an array pattern into the
/// corresponding `ArrayAccess`. Non-array dereferences are left untouched.
fn rewrite_array_derefs(expr: Expr, values: &ValueMap) -> Expr {
    match expr.kind {
        ExprKind::Deref { addr, size } => {
            let addr = rewrite_array_derefs(*addr, values);
            let resolved = resolve(&addr, values);
            // Only reconstruct genuine variable-index array accesses. A constant
            // index means a fixed offset — a stack slot or struct field, not an
            // array — and resolving it here would turn a plain local store into a
            // noisy `(sp - 32 + 16)[-1]` form. Leave those for the normal passes.
            match try_detect_array_in_deref(&resolved, size) {
                Some(array) if !array_access_has_constant_index(&array) => array,
                _ => Expr::deref(addr, size),
            }
        }
        ExprKind::Assign { lhs, rhs } => Expr::assign(
            rewrite_array_derefs(*lhs, values),
            rewrite_array_derefs(*rhs, values),
        ),
        ExprKind::CompoundAssign { op, lhs, rhs } => Expr {
            kind: ExprKind::CompoundAssign {
                op,
                lhs: Box::new(rewrite_array_derefs(*lhs, values)),
                rhs: Box::new(rewrite_array_derefs(*rhs, values)),
            },
        },
        ExprKind::BinOp { op, left, right } => Expr::binop(
            op,
            rewrite_array_derefs(*left, values),
            rewrite_array_derefs(*right, values),
        ),
        ExprKind::UnaryOp { op, operand } => Expr::unary(op, rewrite_array_derefs(*operand, values)),
        ExprKind::AddressOf(inner) => Expr::address_of(rewrite_array_derefs(*inner, values)),
        ExprKind::Cast {
            expr: inner,
            to_size,
            signed,
        } => Expr {
            kind: ExprKind::Cast {
                expr: Box::new(rewrite_array_derefs(*inner, values)),
                to_size,
                signed,
            },
        },
        ExprKind::Call { target, args } => Expr::call(
            target,
            args.into_iter()
                .map(|a| rewrite_array_derefs(a, values))
                .collect(),
        ),
        _ => expr,
    }
}

/// Whether a recovered array access has a constant (literal) index — i.e. a
/// fixed offset that is really a stack slot or struct field, not an array index.
fn array_access_has_constant_index(expr: &Expr) -> bool {
    matches!(&expr.kind, ExprKind::ArrayAccess { index, .. } if matches!(index.kind, ExprKind::IntLit(_)))
}

/// `cdqe`/`cltq`/`cwde`/`cwtl`/`cbw`/`cbtw`: accumulator sign-extension with no
/// explicit operands, lifted as an argument-less call.
fn is_accumulator_sign_extend(stmt: &Expr) -> bool {
    matches!(&stmt.kind, ExprKind::Call { target: CallTarget::Named(name), args }
        if args.is_empty()
            && matches!(name.as_str(), "cdqe" | "cltq" | "cwde" | "cwtl" | "cbw" | "cbtw"))
}

fn statement_is_real_call(stmt: &Expr) -> bool {
    match &stmt.kind {
        ExprKind::Call { target, .. } => !is_pseudo_call(target),
        ExprKind::Assign { rhs, .. } => {
            matches!(&rhs.kind, ExprKind::Call { target, .. } if !is_pseudo_call(target))
        }
        _ => false,
    }
}

fn is_pseudo_call(target: &CallTarget) -> bool {
    matches!(target, CallTarget::Named(name)
        if matches!(name.as_str(),
            "push" | "pop" | "cdqe" | "cltq" | "cwde" | "cwtl" | "cbw" | "cbtw"))
}

/// True if the statement writes to memory (a store through a pointer or a frame
/// slot), which may alias a tracked index load.
fn statement_writes_memory(stmt: &Expr) -> bool {
    let lhs = match &stmt.kind {
        ExprKind::Assign { lhs, .. } | ExprKind::CompoundAssign { lhs, .. } => lhs,
        _ => return false,
    };
    matches!(
        &lhs.kind,
        ExprKind::Deref { .. }
            | ExprKind::ArrayAccess { .. }
            | ExprKind::FieldAccess { .. }
    ) || matches!(&lhs.kind, ExprKind::Var(v) if matches!(v.kind, VarKind::Stack(_)))
}

/// True if the expression reads memory (contains a dereference / array / field
/// access), so its tracked value can be invalidated by a memory write.
fn expr_reads_memory(expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::Deref { .. } | ExprKind::ArrayAccess { .. } | ExprKind::FieldAccess { .. } => {
            true
        }
        ExprKind::BinOp { left, right, .. } => expr_reads_memory(left) || expr_reads_memory(right),
        ExprKind::UnaryOp { operand, .. } => expr_reads_memory(operand),
        ExprKind::Cast { expr, .. } => expr_reads_memory(expr),
        ExprKind::AddressOf(inner) => expr_reads_memory(inner),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::expression::{BinOpKind, Variable};
    use hexray_core::BasicBlockId;

    fn block(stmts: Vec<Expr>) -> StructuredNode {
        StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: stmts,
            address_range: (0, 0),
        }
    }

    fn reg(name: &str, size: u8) -> Expr {
        Expr::var(Variable::reg(name, size))
    }

    /// `eax = i; cdqe; rdx = eax*4; rax = base + rdx; dst = *(rax)`
    /// should recover `dst = base[i]`.
    #[test]
    fn reconstructs_scaled_array_index_load() {
        let stmts = vec![
            Expr::assign(reg("rax", 4), Expr::unknown("i")),
            Expr::call(CallTarget::Named("cdqe".to_string()), vec![]),
            Expr::assign(
                reg("rdx", 8),
                Expr::binop(BinOpKind::Mul, reg("rax", 8), Expr::int(4)),
            ),
            Expr::assign(
                reg("rax", 8),
                Expr::binop(BinOpKind::Add, Expr::unknown("arg0"), reg("rdx", 8)),
            ),
            Expr::assign(reg("rsi", 4), Expr::deref(reg("rax", 8), 4)),
        ];
        let out = reconstruct_array_index_derefs(vec![block(stmts)]);
        let StructuredNode::Block { statements, .. } = &out[0] else {
            panic!("expected block");
        };
        let ExprKind::Assign { rhs, .. } = &statements[4].kind else {
            panic!("expected assignment");
        };
        match &rhs.kind {
            ExprKind::ArrayAccess {
                base,
                index,
                element_size,
            } => {
                assert_eq!(*element_size, 4);
                assert!(matches!(&base.kind, ExprKind::Unknown(n) if n == "arg0"));
                assert!(matches!(&index.kind, ExprKind::Unknown(n) if n == "i"));
            }
            other => panic!("expected ArrayAccess(arg0, i, 4), got {other:?}"),
        }
    }

    /// A store through the reconstructed address: `*(rax) = val` -> `base[i] = val`.
    #[test]
    fn reconstructs_scaled_array_index_store() {
        let stmts = vec![
            Expr::assign(reg("rax", 4), Expr::unknown("i")),
            Expr::call(CallTarget::Named("cdqe".to_string()), vec![]),
            Expr::assign(
                reg("rdx", 8),
                Expr::binop(BinOpKind::Mul, reg("rax", 8), Expr::int(8)),
            ),
            Expr::assign(
                reg("rax", 8),
                Expr::binop(BinOpKind::Add, Expr::unknown("arg0"), reg("rdx", 8)),
            ),
            Expr::assign(Expr::deref(reg("rax", 8), 8), Expr::int(0)),
        ];
        let out = reconstruct_array_index_derefs(vec![block(stmts)]);
        let StructuredNode::Block { statements, .. } = &out[0] else {
            panic!("expected block");
        };
        let ExprKind::Assign { lhs, .. } = &statements[4].kind else {
            panic!("expected assignment");
        };
        assert!(
            matches!(&lhs.kind, ExprKind::ArrayAccess { element_size: 8, .. }),
            "store target should be an 8-byte ArrayAccess, got {lhs:?}"
        );
    }

    /// A plain pointer dereference (no scaled index) must stay a `Deref`.
    #[test]
    fn leaves_plain_deref_untouched() {
        let stmts = vec![Expr::assign(
            reg("rax", 8),
            Expr::deref(Expr::unknown("arg0"), 8),
        )];
        let out = reconstruct_array_index_derefs(vec![block(stmts)]);
        let StructuredNode::Block { statements, .. } = &out[0] else {
            panic!("expected block");
        };
        let ExprKind::Assign { rhs, .. } = &statements[0].kind else {
            panic!("expected assignment");
        };
        assert!(matches!(&rhs.kind, ExprKind::Deref { .. }), "plain deref preserved");
    }
}
