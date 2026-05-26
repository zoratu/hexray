//! Recovery of the System V AMD64 `va_arg` register/overflow state machine.
//!
//! A `va_arg(ap, T)` access on x86-64 SysV is lowered by the compiler into a
//! branch on the relevant save-area offset (`gp_offset` for integer/pointer
//! arguments, `fp_offset` for floating point), choosing between the register
//! save area and the stack overflow area, then loading the value:
//!
//! ```text
//! if (gp_offset > 47) {                 // no register slots left
//!     addr = overflow_arg_area;         // take from the stack
//!     overflow_arg_area += 8;
//! } else {
//!     addr = reg_save_area + gp_offset; // take from the saved registers
//!     gp_offset += 8;
//! }
//! value = *(T*)addr;
//! ```
//!
//! After copy propagation the slot reads in the branches fold to concrete frame
//! offsets, but the comparison against the SysV threshold (47/48 for GPRs,
//! 175/176 for the XMM save area) and the increment of the tested offset slot
//! remain reliable anchors. This pass matches that shape and collapses it back
//! into a single `value = va_arg(ap, T)` assignment, which is both far more
//! readable and a faithful rendering of the original source.
//!
//! The matcher is deliberately conservative: it only fires on the full diamond
//! (threshold compare on a frame slot + the same destination address assigned
//! in both branches + the tested slot incremented in one branch + an
//! immediately following dereference of that destination), so it cannot
//! misfire on ordinary `if` statements. The `va_start` slot initialization is
//! left in place: signature recovery keys variadic (`...`) detection off it.

use super::super::expression::{BinOpKind, CallTarget, Expr, ExprKind, VarKind, Variable};
use super::StructuredNode;

/// Name used for the synthesized `va_list` cursor. SysV variadic functions
/// almost always thread a single `va_list`, so a shared name renders correctly
/// for the common case.
const VA_LIST_NAME: &str = "ap";

/// Collapse SysV `va_arg` state machines into `va_arg(ap, T)` assignments, then
/// rewrite the now-dead `va_start` slot setup into a `va_start(ap, last)` call.
pub(super) fn recover_va_arg(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    let mut nodes = collapse_tree(nodes);
    if tree_contains_va_arg(&nodes) {
        rewrite_va_start_init(&mut nodes);
    }
    nodes
}

/// Recursively collapse every `va_arg` diamond in the tree (bottom-up).
fn collapse_tree(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    let mut nodes: Vec<_> = nodes.into_iter().map(recurse_node).collect();
    collapse_in_list(&mut nodes);
    nodes
}

fn recurse_node(node: StructuredNode) -> StructuredNode {
    match node {
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition,
            then_body: collapse_tree(then_body),
            else_body: else_body.map(collapse_tree),
        },
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition,
            body: collapse_tree(body),
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: collapse_tree(body),
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
            body: collapse_tree(body),
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: collapse_tree(body),
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
                .map(|(vals, body)| (vals, collapse_tree(body)))
                .collect(),
            default: default.map(collapse_tree),
        },
        StructuredNode::Sequence(body) => StructuredNode::Sequence(collapse_tree(body)),
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => StructuredNode::TryCatch {
            try_body: collapse_tree(try_body),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|mut h| {
                    h.body = collapse_tree(h.body);
                    h
                })
                .collect(),
        },
        other => other,
    }
}

/// Scan a single node list for `If`-diamond + following-load pairs and collapse
/// each into a `va_arg(ap, T)` assignment.
fn collapse_in_list(nodes: &mut Vec<StructuredNode>) {
    let mut i = 0;
    while i + 1 < nodes.len() {
        if let Some(m) = match_va_arg_diamond(&nodes[i]) {
            if let Some(ty) = following_load_type(&nodes[i + 1], &m.dest) {
                // Replace the load's right-hand side with `va_arg(ap, T)`,
                // preserving the value receiver, and drop the diamond `If`.
                if let StructuredNode::Block { statements, .. } = &mut nodes[i + 1] {
                    if let ExprKind::Assign { rhs, .. } = &mut statements[0].kind {
                        **rhs = make_va_arg_call(ty);
                    }
                }
                nodes.remove(i);
                continue;
            }
        }
        i += 1;
    }
}

/// Rewrite the `va_start` slot initialization left over after collapsing the
/// `va_arg` diamonds. The setup is four stores into the 24-byte `va_list`
/// (`gp_offset`, `fp_offset`, `overflow_arg_area`, `reg_save_area`); once every
/// `va_arg` that read them has been collapsed they are dead. The `gp_offset`
/// store becomes a `va_start(ap, last)` call (its constant encodes the named
/// integer parameter count) and the other three are dropped.
///
/// A store is only touched when its target slot is otherwise unreferenced in the
/// whole function, so a partially recovered function (some diamond left intact)
/// never loses setup that is still live.
fn rewrite_va_start_init(nodes: &mut [StructuredNode]) {
    // Phase 1: classify candidate stores in the top-level blocks, recording
    // dead ones. Reference counts are taken over the (not-yet-mutated) tree.
    let mut to_va_start: Vec<(usize, usize, usize)> = Vec::new(); // (block, stmt, named_count)
    let mut to_remove: Vec<(usize, usize)> = Vec::new();
    for (bi, node) in nodes.iter().enumerate() {
        let StructuredNode::Block { statements, .. } = node else {
            continue;
        };
        for (si, stmt) in statements.iter().enumerate() {
            let Some((slot, kind)) = classify_va_start_store(stmt) else {
                continue;
            };
            if count_slot_in_nodes(nodes, slot) != 1 {
                continue; // still live — leave it alone
            }
            match kind {
                VaStartStore::GpOffset(named_count) => to_va_start.push((bi, si, named_count)),
                VaStartStore::Other => to_remove.push((bi, si)),
            }
        }
    }

    // Phase 2: apply. Replace the gp_offset store with the `va_start` call.
    for (bi, si, named_count) in &to_va_start {
        if let StructuredNode::Block { statements, .. } = &mut nodes[*bi] {
            statements[*si] = make_va_start_call(*named_count);
        }
    }
    // Drop the dead sibling stores, highest index first so earlier ones stay
    // valid.
    to_remove.sort_unstable();
    for (bi, si) in to_remove.into_iter().rev() {
        if let StructuredNode::Block { statements, .. } = &mut nodes[bi] {
            statements.remove(si);
        }
    }
}

/// Classification of a `va_list` setup store.
enum VaStartStore {
    /// `gp_offset = 8 * named_int_params` — carries the fixed-parameter count.
    GpOffset(usize),
    /// `fp_offset = 48`, `overflow_arg_area = frame+k`, or `reg_save_area =
    /// frame-k` — dropped once dead.
    Other,
}

/// If `stmt` is a `va_list` slot initialization store, return its slot lvalue
/// and classification.
fn classify_va_start_store(stmt: &Expr) -> Option<(&Expr, VaStartStore)> {
    let ExprKind::Assign { lhs, rhs } = &stmt.kind else {
        return None;
    };
    if !is_frame_slot(lhs) {
        return None;
    }
    match &strip_casts(rhs).kind {
        // gp_offset starts at 8 * (named integer params), 1..=5 of them.
        ExprKind::IntLit(v @ (8 | 16 | 24 | 32 | 40)) => {
            let named_count = (*v / 8) as usize;
            Some((lhs, VaStartStore::GpOffset(named_count)))
        }
        // fp_offset always starts at 48.
        ExprKind::IntLit(48) => Some((lhs, VaStartStore::Other)),
        // overflow_arg_area / reg_save_area are frame-pointer ± constant.
        ExprKind::BinOp {
            op: BinOpKind::Add | BinOpKind::Sub,
            left,
            right,
        } if references_frame_pointer(strip_casts(left))
            && matches!(strip_casts(right).kind, ExprKind::IntLit(_)) =>
        {
            Some((lhs, VaStartStore::Other))
        }
        _ => None,
    }
}

/// `va_start(ap, arg{named_count - 1})` — names the last fixed parameter.
fn make_va_start_call(named_count: usize) -> Expr {
    let last_param = format!("arg{}", named_count.saturating_sub(1));
    Expr::call(
        CallTarget::Named("va_start".to_string()),
        vec![token_expr(VA_LIST_NAME), token_expr(&last_param)],
    )
}

/// Total number of structural occurrences of `slot` as a (sub)expression across
/// the whole node tree.
fn count_slot_in_nodes(nodes: &[StructuredNode], slot: &Expr) -> usize {
    let mut count = 0;
    walk_exprs_in_nodes(nodes, &mut |e| count += count_slot_in_expr(e, slot));
    count
}

fn count_slot_in_expr(expr: &Expr, slot: &Expr) -> usize {
    let mut count = usize::from(lvalue_eq(expr, slot));
    let mut visit = |e: &Expr| count += count_slot_in_expr(e, slot);
    match &expr.kind {
        ExprKind::BinOp { left, right, .. } => {
            visit(left);
            visit(right);
        }
        ExprKind::UnaryOp { operand, .. } => visit(operand),
        ExprKind::Deref { addr, .. } => visit(addr),
        ExprKind::AddressOf(inner) => visit(inner),
        ExprKind::Cast { expr, .. } => visit(expr),
        ExprKind::BitField { expr, .. } => visit(expr),
        ExprKind::ArrayAccess { base, index, .. } => {
            visit(base);
            visit(index);
        }
        ExprKind::FieldAccess { base, .. } => visit(base),
        ExprKind::Assign { lhs, rhs } => {
            visit(lhs);
            visit(rhs);
        }
        ExprKind::CompoundAssign { lhs, rhs, .. } => {
            visit(lhs);
            visit(rhs);
        }
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            visit(cond);
            visit(then_expr);
            visit(else_expr);
        }
        ExprKind::Call { args, .. } => args.iter().for_each(visit),
        ExprKind::Phi(exprs) => exprs.iter().for_each(visit),
        _ => {}
    }
    count
}

/// Visit every statement/condition expression in the node tree.
fn walk_exprs_in_nodes(nodes: &[StructuredNode], f: &mut impl FnMut(&Expr)) {
    for node in nodes {
        match node {
            StructuredNode::Block { statements, .. } => {
                for e in statements {
                    f(e);
                }
            }
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                f(condition);
                walk_exprs_in_nodes(then_body, f);
                if let Some(eb) = else_body {
                    walk_exprs_in_nodes(eb, f);
                }
            }
            StructuredNode::While {
                condition, body, ..
            }
            | StructuredNode::DoWhile {
                condition, body, ..
            } => {
                f(condition);
                walk_exprs_in_nodes(body, f);
            }
            StructuredNode::For {
                init,
                condition,
                update,
                body,
                ..
            } => {
                if let Some(i) = init {
                    f(i);
                }
                f(condition);
                if let Some(u) = update {
                    f(u);
                }
                walk_exprs_in_nodes(body, f);
            }
            StructuredNode::Loop { body, .. } => walk_exprs_in_nodes(body, f),
            StructuredNode::Switch {
                value,
                cases,
                default,
            } => {
                f(value);
                for (_, body) in cases {
                    walk_exprs_in_nodes(body, f);
                }
                if let Some(d) = default {
                    walk_exprs_in_nodes(d, f);
                }
            }
            StructuredNode::Sequence(body) => walk_exprs_in_nodes(body, f),
            StructuredNode::Return(Some(e)) | StructuredNode::Expr(e) => f(e),
            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                walk_exprs_in_nodes(try_body, f);
                for h in catch_handlers {
                    walk_exprs_in_nodes(&h.body, f);
                }
            }
            StructuredNode::Return(None)
            | StructuredNode::Break
            | StructuredNode::Continue
            | StructuredNode::Goto(_)
            | StructuredNode::Label(_) => {}
        }
    }
}

/// Whether any `va_arg(...)` call appears in the node tree.
fn tree_contains_va_arg(nodes: &[StructuredNode]) -> bool {
    let mut found = false;
    walk_exprs_in_nodes(nodes, &mut |e| found |= expr_contains_va_arg(e));
    found
}

fn expr_contains_va_arg(expr: &Expr) -> bool {
    if let ExprKind::Call {
        target: CallTarget::Named(name),
        ..
    } = &expr.kind
    {
        if name == "va_arg" {
            return true;
        }
    }
    let mut found = false;
    let mut visit = |e: &Expr| found |= expr_contains_va_arg(e);
    match &expr.kind {
        ExprKind::BinOp { left, right, .. } => {
            visit(left);
            visit(right);
        }
        ExprKind::UnaryOp { operand, .. } => visit(operand),
        ExprKind::Deref { addr, .. } => visit(addr),
        ExprKind::AddressOf(inner) => visit(inner),
        ExprKind::Cast { expr, .. } => visit(expr),
        ExprKind::BitField { expr, .. } => visit(expr),
        ExprKind::ArrayAccess { base, index, .. } => {
            visit(base);
            visit(index);
        }
        ExprKind::FieldAccess { base, .. } => visit(base),
        ExprKind::Assign { lhs, rhs } | ExprKind::CompoundAssign { lhs, rhs, .. } => {
            visit(lhs);
            visit(rhs);
        }
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            visit(cond);
            visit(then_expr);
            visit(else_expr);
        }
        ExprKind::Call { args, .. } => args.iter().for_each(visit),
        ExprKind::Phi(exprs) => exprs.iter().for_each(visit),
        _ => {}
    }
    found
}

/// A matched `va_arg` diamond.
struct VaArgMatch {
    /// Register/temp variable holding the loaded value's address in both
    /// branches.
    dest: Variable,
}

/// Match the `If` node against the SysV `va_arg` diamond shape.
fn match_va_arg_diamond(node: &StructuredNode) -> Option<VaArgMatch> {
    let StructuredNode::If {
        condition,
        then_body,
        else_body,
    } = node
    else {
        return None;
    };
    let else_body = else_body.as_ref()?;

    // Condition must compare a frame offset slot against a SysV threshold.
    let (offset_slot, register_is_else) = match_threshold_condition(condition)?;

    let then_ops = flatten_branch(then_body)?;
    let else_ops = flatten_branch(else_body)?;

    // The register branch increments the tested offset slot; the overflow
    // branch bumps a different slot. `register_is_else` says which is which
    // based on the comparison direction.
    let (reg_ops, overflow_ops) = if register_is_else {
        (&else_ops, &then_ops)
    } else {
        (&then_ops, &else_ops)
    };

    // Both branches must assign the same destination address register.
    let reg_dest = branch_dest_var(reg_ops)?;
    let overflow_dest = branch_dest_var(overflow_ops)?;
    if reg_dest.name != overflow_dest.name {
        return None;
    }

    // The register branch must reassign the tested offset slot (the `+= 8`,
    // folded to a constant store after propagation).
    if !branch_assigns_lvalue(reg_ops, &offset_slot) {
        return None;
    }

    // The overflow branch must bump a *different* frame slot (the overflow
    // area), confirming the diamond shape.
    if !branch_bumps_other_frame_slot(overflow_ops, &offset_slot) {
        return None;
    }

    Some(VaArgMatch {
        dest: reg_dest.clone(),
    })
}

/// Recognize `slot <cmp> threshold`, returning the slot lvalue and whether the
/// register-save branch is the `else` branch.
///
/// gcc/clang emit `cmp gp_offset, 48; jae overflow`, which lowers to a
/// `gp_offset > 47` (or `>= 48`) test whose *taken* (then) branch is the
/// overflow path — so the register path is the `else` branch. The inverse
/// comparison (`<`/`<=`) swaps that.
fn match_threshold_condition(condition: &Expr) -> Option<(Expr, bool)> {
    let cond = strip_casts(condition);
    let ExprKind::BinOp { op, left, right } = &cond.kind else {
        return None;
    };

    let slot = strip_casts(left);
    if !is_frame_slot(slot) {
        return None;
    }
    let ExprKind::IntLit(threshold) = strip_casts(right).kind else {
        return None;
    };
    if !is_sysv_offset_threshold(threshold) {
        return None;
    }

    match op {
        // slot > / >= threshold: overflow path is taken (then), register is else.
        BinOpKind::Gt | BinOpKind::Ge | BinOpKind::UGt | BinOpKind::UGe => Some((slot.clone(), true)),
        // slot < / <= threshold: register path is taken (then), overflow is else.
        BinOpKind::Lt | BinOpKind::Le | BinOpKind::ULt | BinOpKind::ULe => {
            Some((slot.clone(), false))
        }
        _ => None,
    }
}

/// SysV thresholds: 47/48 mark the last 8-byte GPR save slot; 175/176 mark the
/// last 16-byte XMM save slot.
fn is_sysv_offset_threshold(t: i128) -> bool {
    matches!(t, 47 | 48 | 175 | 176)
}

/// A branch body that is purely straight-line statements, flattened to a list
/// of `Expr`. Returns `None` if the branch contains nested control flow.
fn flatten_branch(body: &[StructuredNode]) -> Option<Vec<Expr>> {
    let mut out = Vec::new();
    for node in body {
        match node {
            StructuredNode::Block { statements, .. } => out.extend(statements.iter().cloned()),
            StructuredNode::Expr(e) => out.push(e.clone()),
            StructuredNode::Sequence(inner) => out.extend(flatten_branch(inner)?),
            _ => return None,
        }
    }
    Some(out)
}

/// The single register/temp destination assigned by a branch (the result
/// address), distinguished from the frame offset slots it also writes.
fn branch_dest_var(ops: &[Expr]) -> Option<&Variable> {
    for e in ops {
        if let ExprKind::Assign { lhs, .. } = &e.kind {
            if let ExprKind::Var(v) = &lhs.kind {
                if matches!(v.kind, VarKind::Register(_) | VarKind::Temp(_)) {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// True if the branch assigns the given lvalue (its `+= 8` increment).
fn branch_assigns_lvalue(ops: &[Expr], slot: &Expr) -> bool {
    ops.iter()
        .any(|e| matches!(&e.kind, ExprKind::Assign { lhs, .. } if lvalue_eq(lhs, slot)))
}

/// True if the overflow branch bumps a frame slot other than the tested offset
/// slot (the `overflow_arg_area += 8`).
fn branch_bumps_other_frame_slot(ops: &[Expr], offset_slot: &Expr) -> bool {
    ops.iter().any(|e| {
        matches!(&e.kind, ExprKind::Assign { lhs, .. }
            if is_frame_slot(lhs) && !lvalue_eq(lhs, offset_slot))
    })
}

/// If the block following the diamond begins with `value = *(T*)(... dest ...)`,
/// the load type. The first statement must dereference the diamond's result
/// address register.
fn following_load_type(node: &StructuredNode, dest: &Variable) -> Option<&'static str> {
    let StructuredNode::Block { statements, .. } = node else {
        return None;
    };
    let first = statements.first()?;
    let ExprKind::Assign { lhs, rhs } = &first.kind else {
        return None;
    };
    if !matches!(&lhs.kind, ExprKind::Var(_)) {
        return None;
    }
    if !deref_targets_var(rhs, &dest.name) {
        return None;
    }
    Some(c_type_for_size(deref_size(rhs)))
}

/// True if `expr` is `*(T*)(... dest ...)`, i.e. a dereference whose address
/// expression references the named variable.
fn deref_targets_var(expr: &Expr, dest: &str) -> bool {
    if let ExprKind::Deref { addr, .. } = &expr.kind {
        return expr_references_var(addr, dest);
    }
    if let ExprKind::Cast { expr: inner, .. } = &expr.kind {
        return deref_targets_var(inner, dest);
    }
    false
}

fn expr_references_var(expr: &Expr, name: &str) -> bool {
    match &expr.kind {
        ExprKind::Var(v) => v.name == name,
        ExprKind::BinOp { left, right, .. } => {
            expr_references_var(left, name) || expr_references_var(right, name)
        }
        ExprKind::UnaryOp { operand, .. } => expr_references_var(operand, name),
        ExprKind::Cast { expr, .. } => expr_references_var(expr, name),
        ExprKind::Deref { addr, .. } => expr_references_var(addr, name),
        _ => false,
    }
}

/// Build the `va_arg(ap, T)` call expression.
///
/// Both operands are rendered as verbatim tokens (`Unknown`) rather than real
/// variables, so the synthesized `ap` cursor and the type name are not picked
/// up as declarable locals by the emitter.
fn make_va_arg_call(ty: &str) -> Expr {
    Expr::call(
        CallTarget::Named("va_arg".to_string()),
        vec![token_expr(VA_LIST_NAME), token_expr(ty)],
    )
}

fn token_expr(text: &str) -> Expr {
    Expr {
        kind: ExprKind::Unknown(text.to_string()),
    }
}

/// Map a load size to the C type name used in the `va_arg` type operand.
fn c_type_for_size(size: Option<u8>) -> &'static str {
    match size {
        Some(1) => "char",
        Some(2) => "short",
        Some(4) => "int",
        Some(8) => "long",
        _ => "int",
    }
}

/// Strip surrounding `Cast` wrappers from an expression.
fn strip_casts(expr: &Expr) -> &Expr {
    let mut cur = expr;
    while let ExprKind::Cast { expr, .. } = &cur.kind {
        cur = expr;
    }
    cur
}

/// True if the expression is a frame-relative storage slot: a stack variable,
/// or a memory access (`ArrayAccess` / `Deref` / `FieldAccess`) based off the
/// frame or stack pointer.
fn is_frame_slot(expr: &Expr) -> bool {
    match &strip_casts(expr).kind {
        ExprKind::Var(v) => matches!(v.kind, VarKind::Stack(_)),
        ExprKind::ArrayAccess { base, .. } => references_frame_pointer(base),
        ExprKind::Deref { addr, .. } => references_frame_pointer(addr),
        ExprKind::FieldAccess { base, .. } => references_frame_pointer(base),
        _ => false,
    }
}

/// True if the expression references the frame or stack pointer register.
fn references_frame_pointer(expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::Var(v) => v.name == "rbp" || v.name == "rsp",
        ExprKind::BinOp { left, right, .. } => {
            references_frame_pointer(left) || references_frame_pointer(right)
        }
        ExprKind::Cast { expr, .. } => references_frame_pointer(expr),
        ExprKind::UnaryOp { operand, .. } => references_frame_pointer(operand),
        _ => false,
    }
}

/// Structural equality over the lvalue expression shapes the matcher compares.
fn lvalue_eq(a: &Expr, b: &Expr) -> bool {
    match (&a.kind, &b.kind) {
        (ExprKind::Var(v1), ExprKind::Var(v2)) => v1 == v2,
        (ExprKind::IntLit(n1), ExprKind::IntLit(n2)) => n1 == n2,
        (
            ExprKind::BinOp {
                op: o1,
                left: l1,
                right: r1,
            },
            ExprKind::BinOp {
                op: o2,
                left: l2,
                right: r2,
            },
        ) => o1 == o2 && lvalue_eq(l1, l2) && lvalue_eq(r1, r2),
        (
            ExprKind::ArrayAccess {
                base: b1,
                index: i1,
                element_size: s1,
            },
            ExprKind::ArrayAccess {
                base: b2,
                index: i2,
                element_size: s2,
            },
        ) => s1 == s2 && lvalue_eq(b1, b2) && lvalue_eq(i1, i2),
        (
            ExprKind::Deref {
                addr: a1,
                size: s1,
            },
            ExprKind::Deref {
                addr: a2,
                size: s2,
            },
        ) => s1 == s2 && lvalue_eq(a1, a2),
        (
            ExprKind::FieldAccess {
                base: b1,
                offset: o1,
                ..
            },
            ExprKind::FieldAccess {
                base: b2,
                offset: o2,
                ..
            },
        ) => o1 == o2 && lvalue_eq(b1, b2),
        (
            ExprKind::UnaryOp {
                op: o1,
                operand: x1,
            },
            ExprKind::UnaryOp {
                op: o2,
                operand: x2,
            },
        ) => o1 == o2 && lvalue_eq(x1, x2),
        (ExprKind::Cast { expr: e1, .. }, _) => lvalue_eq(e1, b),
        (_, ExprKind::Cast { expr: e2, .. }) => lvalue_eq(a, e2),
        _ => false,
    }
}

fn deref_size(expr: &Expr) -> Option<u8> {
    match &expr.kind {
        ExprKind::Deref { size, .. } => Some(*size),
        ExprKind::Cast { expr, to_size, .. } => deref_size(expr).or(Some(*to_size)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexray_core::BasicBlockId;

    fn block(id: u32, statements: Vec<Expr>) -> StructuredNode {
        StructuredNode::Block {
            id: BasicBlockId::new(id),
            statements,
            address_range: (0x1000, 0x1008),
        }
    }

    fn rbp() -> Expr {
        Expr::var(Variable::reg("rbp", 8))
    }

    /// `gp_offset` slot at `rbp[-52]` (the canonical `local_d0` location).
    fn gp_slot() -> Expr {
        Expr::array_access(rbp(), Expr::int(-52), 4)
    }

    /// `overflow_arg_area` slot at `rbp[-25]`.
    fn overflow_slot() -> Expr {
        Expr::array_access(rbp(), Expr::int(-25), 8)
    }

    fn rax(size: u8) -> Expr {
        Expr::var(Variable::reg("rax", size))
    }

    /// Build the canonical SysV integer `va_arg` diamond followed by the load
    /// block, as produced after copy propagation.
    fn va_arg_diamond(load_size: u8) -> Vec<StructuredNode> {
        let then_overflow = vec![block(
            1,
            vec![
                Expr::assign(rax(8), Expr::binop(BinOpKind::Add, rbp(), Expr::int(16))),
                Expr::assign(
                    overflow_slot(),
                    Expr::binop(
                        BinOpKind::Add,
                        Expr::binop(BinOpKind::Add, rbp(), Expr::int(16)),
                        Expr::int(8),
                    ),
                ),
            ],
        )];
        let else_register = vec![block(
            2,
            vec![
                Expr::assign(
                    rax(8),
                    Expr::binop(
                        BinOpKind::Add,
                        Expr::binop(BinOpKind::Add, rbp(), Expr::int(-176)),
                        Expr::int(8),
                    ),
                ),
                Expr::assign(gp_slot(), Expr::int(16)),
            ],
        )];
        vec![
            StructuredNode::If {
                condition: Expr::binop(BinOpKind::UGt, gp_slot(), Expr::int(47)),
                then_body: then_overflow,
                else_body: Some(else_register),
            },
            block(
                3,
                vec![Expr::assign(rax(load_size), Expr::deref(rax(8), load_size))],
            ),
        ]
    }

    fn first_rhs_is_va_arg(node: &StructuredNode) -> Option<String> {
        let StructuredNode::Block { statements, .. } = node else {
            return None;
        };
        let ExprKind::Assign { rhs, .. } = &statements[0].kind else {
            return None;
        };
        let ExprKind::Call { target, args } = &rhs.kind else {
            return None;
        };
        let CallTarget::Named(name) = target else {
            return None;
        };
        if name != "va_arg" {
            return None;
        }
        // Return the rendered type operand for assertion.
        match &args[1].kind {
            ExprKind::Unknown(t) => Some(t.clone()),
            _ => None,
        }
    }

    #[test]
    fn collapses_integer_va_arg_diamond() {
        let out = recover_va_arg(va_arg_diamond(4));
        // The `If` diamond is removed, leaving just the (rewritten) load block.
        assert_eq!(out.len(), 1);
        assert_eq!(first_rhs_is_va_arg(&out[0]).as_deref(), Some("int"));
    }

    #[test]
    fn picks_c_type_from_load_size() {
        assert_eq!(
            first_rhs_is_va_arg(&recover_va_arg(va_arg_diamond(8))[0]).as_deref(),
            Some("long")
        );
        assert_eq!(
            first_rhs_is_va_arg(&recover_va_arg(va_arg_diamond(2))[0]).as_deref(),
            Some("short")
        );
    }

    #[test]
    fn recovers_va_arg_inside_loop_body() {
        let body = va_arg_diamond(4);
        let nodes = vec![StructuredNode::While {
            condition: Expr::binop(
                BinOpKind::Lt,
                Expr::var(Variable::reg("i", 4)),
                Expr::var(Variable::reg("n", 4)),
            ),
            body,
            header: None,
            exit_block: None,
        }];
        let out = recover_va_arg(nodes);
        let StructuredNode::While { body, .. } = &out[0] else {
            panic!("expected while");
        };
        assert_eq!(body.len(), 1);
        assert_eq!(first_rhs_is_va_arg(&body[0]).as_deref(), Some("int"));
    }

    #[test]
    fn leaves_ordinary_if_untouched() {
        // Same shape but the condition compares against a non-SysV threshold,
        // so it must not be mistaken for a va_arg diamond.
        let mut nodes = va_arg_diamond(4);
        if let StructuredNode::If { condition, .. } = &mut nodes[0] {
            *condition = Expr::binop(BinOpKind::UGt, gp_slot(), Expr::int(10));
        }
        let out = recover_va_arg(nodes);
        // Nothing collapsed: the `If` and the load block both remain.
        assert_eq!(out.len(), 2);
        assert!(matches!(out[0], StructuredNode::If { .. }));
        assert!(first_rhs_is_va_arg(&out[1]).is_none());
    }

    /// `fp_offset` slot at `rbp[-48]`.
    fn fp_slot() -> Expr {
        Expr::array_access(rbp(), Expr::int(-48), 4)
    }

    /// `reg_save_area` slot at `rbp[-24]`.
    fn reg_save_slot() -> Expr {
        Expr::array_access(rbp(), Expr::int(-24), 8)
    }

    /// A full variadic function: `va_start` slot setup, the `va_arg` diamond,
    /// the load, and a return.
    fn va_arg_function() -> Vec<StructuredNode> {
        let init = block(
            0,
            vec![
                Expr::assign(gp_slot(), Expr::int(8)),
                Expr::assign(fp_slot(), Expr::int(48)),
                Expr::assign(overflow_slot(), Expr::binop(BinOpKind::Add, rbp(), Expr::int(16))),
                Expr::assign(reg_save_slot(), Expr::binop(BinOpKind::Add, rbp(), Expr::int(-176))),
            ],
        );
        let mut nodes = vec![init];
        nodes.extend(va_arg_diamond(4));
        nodes.push(StructuredNode::Return(Some(rax(4))));
        nodes
    }

    fn va_start_last_param(node: &StructuredNode) -> Option<String> {
        let StructuredNode::Block { statements, .. } = node else {
            return None;
        };
        statements.iter().find_map(|stmt| {
            let ExprKind::Call { target, args } = &stmt.kind else {
                return None;
            };
            let CallTarget::Named(name) = target else {
                return None;
            };
            if name != "va_start" {
                return None;
            }
            match &args[1].kind {
                ExprKind::Unknown(p) => Some(p.clone()),
                _ => None,
            }
        })
    }

    #[test]
    fn rewrites_va_start_init_cluster() {
        let out = recover_va_arg(va_arg_function());
        // Setup block now holds only the va_start call (4 slot stores -> 1).
        let StructuredNode::Block { statements, .. } = &out[0] else {
            panic!("expected setup block");
        };
        assert_eq!(statements.len(), 1);
        assert_eq!(va_start_last_param(&out[0]).as_deref(), Some("arg0"));
        // The va_arg load survived the collapse.
        assert!(first_rhs_is_va_arg(&out[1]).is_some());
    }

    #[test]
    fn keeps_va_start_setup_when_slot_still_live() {
        // An extra read of the gp_offset slot keeps it live, so the setup must
        // not be rewritten away (guards against partial collapse).
        let mut nodes = va_arg_function();
        nodes.push(StructuredNode::Expr(Expr::assign(rax(4), gp_slot())));
        let out = recover_va_arg(nodes);
        // No va_start emitted; the raw gp_offset store is retained.
        assert!(va_start_last_param(&out[0]).is_none());
        let StructuredNode::Block { statements, .. } = &out[0] else {
            panic!("expected setup block");
        };
        assert!(statements
            .iter()
            .any(|s| matches!(&s.kind, ExprKind::Assign { lhs, .. } if lvalue_eq(lhs, &gp_slot()))));
    }

    #[test]
    fn leaves_diamond_without_following_load_untouched() {
        // The threshold diamond is present but the next block does not
        // dereference the result address, so it is not a va_arg access.
        let mut nodes = va_arg_diamond(4);
        nodes[1] = block(3, vec![Expr::assign(rax(4), Expr::int(0))]);
        let out = recover_va_arg(nodes);
        assert_eq!(out.len(), 2);
        assert!(matches!(out[0], StructuredNode::If { .. }));
    }
}
