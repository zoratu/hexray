//! C++ coroutine resume-dispatch recovery.
//!
//! A coroutine `.actor` (gcc) / `.resume` (clang) clone steps the state machine:
//! it loads the suspend index from the heap-allocated frame and dispatches to
//! the matching resume point. Compilers lower this dispatch as a binary-search
//! if-tree (gcc `-O0`) or a cmp-chain over `frame->__resume_index`, which the
//! generic switch detector doesn't collapse because the field is reloaded into
//! several temporaries (and the frame pointer is spilled and re-copied) and the
//! tree carries `<=` / `!=` bound checks.
//!
//! This pass identifies the resume-index field and flattens a dispatch if-tree
//! whose conditions are all comparisons against that field into a single
//! `switch (frame->__resume_index) { case N: ... }`. It is deliberately
//! conservative: a tree is only rewritten when ≥2 distinct equality cases are
//! recovered and every condition on the path is a state comparison, so ordinary
//! control flow (and non-coroutine functions) is never mangled.

use super::expression::{BinOpKind, Expr, ExprKind, VarKind};
use std::collections::{HashMap, HashSet};

/// Synthesized name for the coroutine frame's suspend/resume index field.
pub const RESUME_FIELD_NAME: &str = "__resume_index";

/// True if `name` is a coroutine resume-stepper clone: gcc emits `[clone .actor]`,
/// clang emits `[clone .resume]`. The `.destroy`/`.cleanup` partitions also
/// dispatch on the state but only for teardown, so they are left alone here.
pub fn is_coroutine_resume_clone(name: &str) -> bool {
    name.contains("[clone .actor]") || name.contains("[clone .resume]")
}

use super::structurer::StructuredNode;

/// The coroutine frame pointer and everything that stably aliases it. The first
/// parameter holds the frame; `-O0` spills it to a stack home, so a dispatch
/// `(rbp[-5])[18]` is the same `frame[18]`. `aliases` are normalized keys
/// ([`alias_key`]) of every expression known to hold the frame pointer (the arg
/// plus stack-memory copies — scratch registers are deliberately excluded
/// because they get reused); `base_expr` is a representative base used when
/// emitting the recovered `frame->__resume_index`.
#[derive(Clone)]
struct Frame {
    aliases: HashSet<String>,
    base_expr: Expr,
}

/// The recovered resume-index field, identified by its byte offset in the frame.
#[derive(Clone, Copy)]
struct StateField {
    offset: i64,
}

/// Recover the resume dispatch in a coroutine clone body. Returns the body
/// unchanged when no frame or confident dispatch is found.
pub fn recover_resume_dispatch(body: Vec<StructuredNode>) -> Vec<StructuredNode> {
    let Some(frame) = build_frame(&body) else {
        return body;
    };
    let Some(state) = find_state_field(&body, &frame) else {
        return body;
    };
    let mut env = BindingEnv::default();
    let rewritten = rewrite_nodes(body.clone(), &frame, &state, &mut env, &Domain::default());
    // The rewrite also renames the state field to `frame->__resume_index`; only
    // commit it when a dispatch actually flattened into a switch, so a field that
    // merely happened to be the most-compared one is never renamed in isolation.
    if contains_resume_switch(&rewritten) {
        rewritten
    } else {
        body
    }
}

/// True if the body contains a `switch` whose value is the recovered
/// `frame->__resume_index` field (i.e. this pass flattened a dispatch).
fn contains_resume_switch(nodes: &[StructuredNode]) -> bool {
    nodes.iter().any(|n| match n {
        StructuredNode::Switch {
            value, cases, default, ..
        } => {
            matches!(&value.kind, ExprKind::FieldAccess { field_name, .. } if field_name == RESUME_FIELD_NAME)
                || cases.iter().any(|(_, b)| contains_resume_switch(b))
                || default.as_ref().is_some_and(|b| contains_resume_switch(b))
        }
        StructuredNode::If { then_body, else_body, .. } => {
            contains_resume_switch(then_body)
                || else_body.as_ref().is_some_and(|b| contains_resume_switch(b))
        }
        StructuredNode::While { body, .. }
        | StructuredNode::DoWhile { body, .. }
        | StructuredNode::For { body, .. }
        | StructuredNode::Loop { body, .. } => contains_resume_switch(body),
        StructuredNode::Sequence(nodes) => contains_resume_switch(nodes),
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => {
            contains_resume_switch(try_body)
                || catch_handlers.iter().any(|h| contains_resume_switch(&h.body))
        }
        _ => false,
    })
}

/// Identify the frame pointer (the first parameter) and its stable aliases.
fn build_frame(body: &[StructuredNode]) -> Option<Frame> {
    // The frame is the first parameter, represented as `Unknown("arg0")` (or a
    // `Var` named `arg0`). Find a representative base expression.
    let base_expr = find_frame_param(body)?;
    let base_key = alias_key(&base_expr)?;

    // Collect, per stable home (memory location / stack-slot var — scratch
    // registers excluded since they get reused), the alias key of every value
    // ever assigned to it (`None` for a non-aliasable RHS such as a call result).
    let mut assigns: HashMap<String, Vec<Option<String>>> = HashMap::new();
    visit_assignments(body, &mut |lhs, rhs| {
        if !is_stable_frame_home(lhs) {
            return;
        }
        if let Some(lk) = alias_key(lhs) {
            assigns.entry(lk).or_default().push(alias_key(rhs));
        }
    });

    // A home is a frame alias only if EVERY assignment to it copies a frame
    // alias — so a slot reused for a non-frame value after the prologue spill is
    // never trusted. Fixpoint from the parameter (which the body never reassigns).
    let mut aliases: HashSet<String> = HashSet::from([base_key]);
    loop {
        let mut changed = false;
        for (home, rhss) in &assigns {
            if aliases.contains(home) {
                continue;
            }
            if !rhss.is_empty()
                && rhss
                    .iter()
                    .all(|r| r.as_ref().is_some_and(|rk| aliases.contains(rk)))
            {
                aliases.insert(home.clone());
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    Some(Frame { aliases, base_expr })
}

/// Find a representative frame-parameter base expression (the first
/// `Unknown("arg0")` / `arg0` variable referenced anywhere in the body).
fn find_frame_param(body: &[StructuredNode]) -> Option<Expr> {
    let mut found: Option<Expr> = None;
    visit_exprs(body, &mut |e| {
        if found.is_some() {
            return;
        }
        if is_frame_param_expr(e) {
            found = Some(e.clone());
        }
    });
    found
}

fn is_frame_param_expr(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Unknown(s) => s == "arg0",
        ExprKind::Var(v) => v.name == "arg0",
        _ => false,
    }
}

/// A frame-pointer spill destination that stably holds the frame for the rest
/// of the function: a memory location (`*(rbp-N)`) or a named stack-slot local
/// (`local_N`, a `VarKind::Stack` variable). Scratch registers are excluded —
/// they get reused, so trusting them as frame aliases would be unsound.
fn is_stable_frame_home(e: &Expr) -> bool {
    matches!(
        e.kind,
        ExprKind::ArrayAccess { .. }
            | ExprKind::Deref { .. }
            | ExprKind::FieldAccess { .. }
            | ExprKind::Var(super::expression::Variable {
                kind: VarKind::Stack(_),
                ..
            })
    )
}

/// A normalized key identifying an lvalue location (a register/arg, or a
/// memory location off one), so frame copies and re-reads can be matched.
fn alias_key(e: &Expr) -> Option<String> {
    match &e.kind {
        ExprKind::Unknown(s) => Some(format!("U:{s}")),
        ExprKind::Var(v) => Some(format!("V:{}", v.name)),
        ExprKind::Cast { expr, .. } => alias_key(expr),
        ExprKind::ArrayAccess {
            base,
            index,
            element_size,
        } => {
            let ExprKind::IntLit(i) = &index.kind else {
                return None;
            };
            let b = alias_key(base)?;
            Some(format!("{b}[{}]", *i as i64 * *element_size as i64))
        }
        ExprKind::Deref { addr, .. } => match &addr.kind {
            ExprKind::BinOp {
                op: BinOpKind::Add,
                left,
                right,
            } => {
                let ExprKind::IntLit(off) = &right.kind else {
                    return None;
                };
                let b = alias_key(left)?;
                Some(format!("{b}+{off}"))
            }
            _ => {
                let b = alias_key(addr)?;
                Some(format!("{b}+0"))
            }
        },
        _ => None,
    }
}

/// If `e` is a field access off a frame alias (`frame[idx]` / `*(frame + off)` /
/// `frame->field`), return the byte offset.
fn frame_offset(e: &Expr, frame: &Frame) -> Option<i64> {
    match &e.kind {
        ExprKind::Cast { expr, .. } => frame_offset(expr, frame),
        ExprKind::ArrayAccess {
            base,
            index,
            element_size,
        } => {
            if frame.aliases.contains(&alias_key(base)?) {
                if let ExprKind::IntLit(i) = &index.kind {
                    return Some(*i as i64 * *element_size as i64);
                }
            }
            None
        }
        ExprKind::FieldAccess { base, offset, .. } => {
            frame.aliases.contains(&alias_key(base)?).then_some(*offset as i64)
        }
        ExprKind::Deref { addr, .. } => match &addr.kind {
            ExprKind::BinOp {
                op: BinOpKind::Add,
                left,
                right,
            } => {
                if frame.aliases.contains(&alias_key(left)?) {
                    if let ExprKind::IntLit(off) = &right.kind {
                        return Some(*off as i64);
                    }
                }
                None
            }
            _ => frame.aliases.contains(&alias_key(addr)?).then_some(0),
        },
        _ => None,
    }
}

/// Two branch bodies are equivalent if they structure-print identically.
fn bodies_equivalent(a: &[StructuredNode], b: &[StructuredNode]) -> bool {
    format!("{a:?}") == format!("{b:?}")
}

/// Locate the resume-index field offset: the frame field compared (directly or
/// through a `tmp = frame[off]` reload) against the most distinct small
/// non-negative constants. The `tmp -> offset` map is maintained in execution
/// order and scoped per branch, so a temporary later reused for a different
/// frame field doesn't retroactively re-attribute earlier comparisons.
fn find_state_field(body: &[StructuredNode], frame: &Frame) -> Option<StateField> {
    let mut counts: HashMap<i64, HashSet<i128>> = HashMap::new();
    scan_state_compares(body, frame, &mut HashMap::new(), &mut counts);
    counts
        .into_iter()
        .filter(|(_, vals)| vals.len() >= 2)
        .max_by_key(|(_, vals)| vals.len())
        .map(|(offset, _)| StateField { offset })
}

/// Ordered walk maintaining `temp -> frame offset` bindings; counts each
/// comparison's `(offset, const)` against the binding live at that point.
fn scan_state_compares(
    nodes: &[StructuredNode],
    frame: &Frame,
    temp_offset: &mut HashMap<String, i64>,
    counts: &mut HashMap<i64, HashSet<i128>>,
) {
    for node in nodes {
        match node {
            StructuredNode::Block { statements, .. } => {
                for stmt in statements {
                    if let ExprKind::Assign { lhs, rhs } = &stmt.kind {
                        if let ExprKind::Var(v) = &lhs.kind {
                            match frame_offset(rhs, frame) {
                                Some(off) => {
                                    temp_offset.insert(v.name.clone(), off);
                                }
                                None => {
                                    temp_offset.remove(&v.name);
                                }
                            }
                        }
                    }
                }
            }
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                note_state_compare(condition, frame, temp_offset, counts);
                scan_state_compares(then_body, frame, &mut temp_offset.clone(), counts);
                if let Some(b) = else_body {
                    scan_state_compares(b, frame, &mut temp_offset.clone(), counts);
                }
            }
            StructuredNode::While { condition, body, .. }
            | StructuredNode::DoWhile { condition, body, .. } => {
                note_state_compare(condition, frame, temp_offset, counts);
                scan_state_compares(body, frame, &mut temp_offset.clone(), counts);
            }
            StructuredNode::For { body, .. } | StructuredNode::Loop { body, .. } => {
                scan_state_compares(body, frame, &mut temp_offset.clone(), counts);
            }
            StructuredNode::Switch { cases, default, .. } => {
                for (_, b) in cases {
                    scan_state_compares(b, frame, &mut temp_offset.clone(), counts);
                }
                if let Some(b) = default {
                    scan_state_compares(b, frame, &mut temp_offset.clone(), counts);
                }
            }
            StructuredNode::Sequence(nodes) => scan_state_compares(nodes, frame, temp_offset, counts),
            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                scan_state_compares(try_body, frame, &mut temp_offset.clone(), counts);
                for handler in catch_handlers {
                    scan_state_compares(&handler.body, frame, &mut temp_offset.clone(), counts);
                }
            }
            _ => {}
        }
    }
}

fn note_state_compare(
    cond: &Expr,
    frame: &Frame,
    temp_offset: &HashMap<String, i64>,
    counts: &mut HashMap<i64, HashSet<i128>>,
) {
    if let Some((off, value, op)) = compare_to_frame_offset(cond, frame, temp_offset) {
        // Only equality comparisons name an actual case; `<`/`<=` etc. are
        // binary-search navigation, so a frame field range-checked but never
        // switched on must not be mistaken for the resume index.
        if matches!(op, BinOpKind::Eq | BinOpKind::Ne) && (0..256).contains(&value) {
            counts.entry(off).or_default().insert(value);
        }
    }
}

/// If `cond` is `<frame field or its temp> <cmp> <const>`, return
/// (offset, const, op) with `op` oriented so the field is the left operand.
fn compare_to_frame_offset(
    cond: &Expr,
    frame: &Frame,
    temp_offset: &HashMap<String, i64>,
) -> Option<(i64, i128, BinOpKind)> {
    let ExprKind::BinOp { op, left, right } = &cond.kind else {
        return None;
    };
    if !is_comparison(*op) {
        return None;
    }
    let resolve = |e: &Expr| -> Option<i64> {
        frame_offset(e, frame).or_else(|| match peel_cast(e).kind {
            ExprKind::Var(ref v) => temp_offset.get(&v.name).copied(),
            _ => None,
        })
    };
    if let (Some(off), Some(v)) = (resolve(left), int_lit(right)) {
        return Some((off, v, *op));
    }
    if let (Some(off), Some(v)) = (resolve(right), int_lit(left)) {
        return Some((off, v, flip_op(*op)));
    }
    None
}

fn peel_cast(e: &Expr) -> &Expr {
    match &e.kind {
        ExprKind::Cast { expr, .. } => peel_cast(expr),
        _ => e,
    }
}

fn is_comparison(op: BinOpKind) -> bool {
    matches!(
        op,
        BinOpKind::Eq
            | BinOpKind::Ne
            | BinOpKind::Lt
            | BinOpKind::Le
            | BinOpKind::Gt
            | BinOpKind::Ge
            | BinOpKind::ULt
            | BinOpKind::ULe
            | BinOpKind::UGt
            | BinOpKind::UGe
    )
}

fn int_lit(e: &Expr) -> Option<i128> {
    match &e.kind {
        ExprKind::IntLit(v) => Some(*v),
        ExprKind::Cast { expr, .. } => int_lit(expr),
        _ => None,
    }
}

/// The set of state values that can reach a point, narrowed by the enclosing
/// state conditions (parity from an even/odd `BITS(state,0,1)` split, and range
/// bounds). Used to enumerate only the states that actually reach a dispatch so
/// per-value fate evaluation never invents cases for impossible values.
#[derive(Clone, Default)]
struct Domain {
    constraints: Vec<DomainConstraint>,
}

#[derive(Clone, Copy)]
enum DomainConstraint {
    /// `state <op> k`.
    Cmp(BinOpKind, i128),
    /// `BITS(state, start, width) == value` (e.g. the even/odd split is
    /// `start = 0, width = 1`).
    Slice { start: u8, width: u8, value: i128 },
}

impl Domain {
    fn allows(&self, v: i128) -> bool {
        self.constraints.iter().all(|c| match c {
            DomainConstraint::Cmp(op, k) => apply_cmp(*op, v, *k),
            DomainConstraint::Slice {
                start,
                width,
                value,
            } => (v >> start) & ((1i128 << width) - 1) == *value,
        })
    }

    fn with(&self, c: DomainConstraint) -> Domain {
        let mut constraints = self.constraints.clone();
        constraints.push(c);
        Domain { constraints }
    }
}

fn apply_cmp(op: BinOpKind, a: i128, b: i128) -> bool {
    match op {
        BinOpKind::Eq => a == b,
        BinOpKind::Ne => a != b,
        BinOpKind::Lt | BinOpKind::ULt => a < b,
        BinOpKind::Le | BinOpKind::ULe => a <= b,
        BinOpKind::Gt | BinOpKind::UGt => a > b,
        BinOpKind::Ge | BinOpKind::UGe => a >= b,
        _ => false,
    }
}

/// If `cond` constrains the state field, return the (then, else) domain
/// constraints it imposes — a whole-state comparison or a bit-slice equality
/// (e.g. the even/odd `state & 1 == k` split). Either side is `None` when that
/// branch's constraint isn't expressible (e.g. `!=` on a multi-bit slice).
fn cond_constraints(
    cond: &Expr,
    frame: &Frame,
    state: &StateField,
    env: &BindingEnv,
) -> Option<(Option<DomainConstraint>, Option<DomainConstraint>)> {
    let ExprKind::BinOp { op, left, right } = &cond.kind else {
        return None;
    };
    if !is_comparison(*op) {
        return None;
    }
    // Bit-slice equality: `BITS(state, s, w) <eq> k` (parity is s=0, w=1).
    for (a, b, op) in [(left, right, *op), (right, left, flip_op(*op))] {
        if let Some((start, width)) = env.state_slice(a, frame, state) {
            let Some(k) = int_lit(b) else { continue };
            let mask = (1i128 << width) - 1;
            let value = k & mask;
            return Some(match op {
                BinOpKind::Eq => (
                    Some(DomainConstraint::Slice { start, width, value }),
                    // The complement is a single slice value only for width 1.
                    (width == 1).then_some(DomainConstraint::Slice {
                        start,
                        width,
                        value: value ^ 1,
                    }),
                ),
                BinOpKind::Ne => (
                    (width == 1).then_some(DomainConstraint::Slice {
                        start,
                        width,
                        value: value ^ 1,
                    }),
                    Some(DomainConstraint::Slice { start, width, value }),
                ),
                _ => (None, None),
            });
        }
    }
    // Plain `state <op> k`.
    if let Some((_, k, op)) = as_state_compare_expr(cond, frame, state, env) {
        return Some((
            Some(DomainConstraint::Cmp(op, k)),
            Some(DomainConstraint::Cmp(negate_cmp(op), k)),
        ));
    }
    None
}

/// `as_state_compare` returning the constant and field-left-oriented op.
fn as_state_compare_expr(
    cond: &Expr,
    frame: &Frame,
    state: &StateField,
    env: &BindingEnv,
) -> Option<((), i128, BinOpKind)> {
    let ExprKind::BinOp { op, left, right } = &cond.kind else {
        return None;
    };
    if !is_comparison(*op) {
        return None;
    }
    if env.is_state(left, frame, state) {
        return int_lit(right).map(|k| ((), k, *op));
    }
    if env.is_state(right, frame, state) {
        return int_lit(left).map(|k| ((), k, flip_op(*op)));
    }
    None
}

fn negate_cmp(op: BinOpKind) -> BinOpKind {
    match op {
        BinOpKind::Eq => BinOpKind::Ne,
        BinOpKind::Ne => BinOpKind::Eq,
        BinOpKind::Lt => BinOpKind::Ge,
        BinOpKind::Le => BinOpKind::Gt,
        BinOpKind::Gt => BinOpKind::Le,
        BinOpKind::Ge => BinOpKind::Lt,
        BinOpKind::ULt => BinOpKind::UGe,
        BinOpKind::ULe => BinOpKind::UGt,
        BinOpKind::UGt => BinOpKind::ULe,
        BinOpKind::UGe => BinOpKind::ULt,
        other => other,
    }
}

/// The outcome a single (unmatched) state value `v` executes when it flows
/// through a dispatch If-tree: the trailing nodes it runs after navigating the
/// bounds/equality checks — `[]` for a clean fall-through past the dispatch,
/// `[trap]` for a noreturn leaf, or a live default body. Used to compute the
/// switch's default/extra cases exactly per value, never conflating ranges.
fn eval_outcome(
    nodes: &[StructuredNode],
    v: i128,
    frame: &Frame,
    state: &StateField,
    env: &BindingEnv,
) -> Vec<StructuredNode> {
    let mut env = env.clone();
    for (i, node) in nodes.iter().enumerate() {
        match node {
            StructuredNode::Block { statements, .. } => {
                if is_state_reload_block(statements, frame, state, &env) {
                    env.note_block(statements, frame, state);
                    continue;
                }
                // A real (or trap) block: v runs it and the rest of this sibling
                // list as its outcome.
                return nodes[i..].to_vec();
            }
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                let branch = match eval_state_cond(condition, v, frame, state, &env) {
                    Some(true) => Some(then_body.as_slice()),
                    Some(false) => else_body.as_deref(),
                    // Non-state condition: v has reached ordinary code; its outcome
                    // is this node onward (the whole region).
                    None => return nodes[i..].to_vec(),
                };
                // v executes the taken branch; if that branch falls through (no
                // trap/return), it then continues with the siblings after this If.
                let mut outcome = branch
                    .map(|b| eval_outcome(b, v, frame, state, &env))
                    .unwrap_or_default();
                if !ends_noreturn(&outcome) {
                    outcome.extend(eval_outcome(&nodes[i + 1..], v, frame, state, &env));
                }
                return outcome;
            }
            _ => return nodes[i..].to_vec(),
        }
    }
    Vec::new()
}

/// Whether the outcome's final statement halts control flow (trap / unreachable
/// / return / break / continue), so following siblings don't run.
fn ends_noreturn(nodes: &[StructuredNode]) -> bool {
    match nodes.last() {
        Some(StructuredNode::Return(_) | StructuredNode::Break | StructuredNode::Continue) => true,
        Some(StructuredNode::Block { statements, .. }) => statements.iter().any(is_noreturn_call),
        Some(StructuredNode::Expr(e)) => is_noreturn_call(e),
        _ => false,
    }
}

fn is_noreturn_call(e: &Expr) -> bool {
    use super::expression::CallTarget;
    match &e.kind {
        ExprKind::Call { target, .. } => matches!(
            target,
            CallTarget::Named(n)
                if matches!(
                    n.as_str(),
                    "__builtin_trap" | "__builtin_unreachable" | "abort" | "std::terminate"
                )
        ),
        ExprKind::Unknown(s) => s.contains("__builtin_trap") || s.contains("__builtin_unreachable"),
        _ => false,
    }
}

/// Evaluate a state condition for a concrete value `v`. Handles `state <op> k`
/// and the parity `BITS(state,0,1) <eq> k`. `None` if not a state condition.
fn eval_state_cond(
    cond: &Expr,
    v: i128,
    frame: &Frame,
    state: &StateField,
    env: &BindingEnv,
) -> Option<bool> {
    let ExprKind::BinOp { op, left, right } = &cond.kind else {
        return None;
    };
    if !is_comparison(*op) {
        return None;
    }
    if let Some(lv) = eval_state_operand(left, v, frame, state, env) {
        if let Some(k) = int_lit(right) {
            return Some(apply_cmp(*op, lv, k));
        }
    }
    if let Some(rv) = eval_state_operand(right, v, frame, state, env) {
        if let Some(k) = int_lit(left) {
            return Some(apply_cmp(flip_op(*op), rv, k));
        }
    }
    None
}

/// The integer value of a state-derived operand (the state itself, or a bitfield
/// slice of it) for `state == v`.
fn eval_state_operand(
    e: &Expr,
    v: i128,
    frame: &Frame,
    state: &StateField,
    env: &BindingEnv,
) -> Option<i128> {
    if env.is_state(e, frame, state) {
        return Some(v);
    }
    // A bit-slice of the state (directly `BITS(state,s,w)` or via a temp).
    if let Some((start, width)) = env.state_slice(e, frame, state) {
        return Some((v >> start) & ((1i128 << width) - 1));
    }
    None
}

/// The largest state constant compared anywhere in a dispatch tree (case labels
/// and bound constants), so per-value enumeration covers every distinct range.
fn max_state_constant(
    nodes: &[StructuredNode],
    frame: &Frame,
    state: &StateField,
    env: &BindingEnv,
) -> i128 {
    let mut max = 0;
    let mut env = env.clone();
    for node in nodes {
        match node {
            StructuredNode::Block { statements, .. } => env.note_block(statements, frame, state),
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                if let Some((_, k, _)) = as_state_compare_expr(condition, frame, state, &env) {
                    max = max.max(k);
                }
                max = max.max(max_state_constant(then_body, frame, state, &env));
                if let Some(b) = else_body {
                    max = max.max(max_state_constant(b, frame, state, &env));
                }
            }
            StructuredNode::Sequence(nodes) => {
                max = max.max(max_state_constant(nodes, frame, state, &env));
            }
            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                max = max.max(max_state_constant(try_body, frame, state, &env));
                for handler in catch_handlers {
                    max = max.max(max_state_constant(&handler.body, frame, state, &env));
                }
            }
            _ => {}
        }
    }
    max
}

/// Scoped binding environment: temporaries currently holding the state value
/// (`tmp = frame->state`, kept across zero-extending `tmp = (u16)tmp` copies) and
/// bit-slice temporaries (`tmp = BITS(state, start, width)` — the even/odd
/// resume/destroy split is `tmp = state & 1`).
#[derive(Default, Clone)]
struct BindingEnv {
    state_temps: HashSet<String>,
    /// temp name -> (start, width) of the state bit-slice it holds.
    slice_temps: HashMap<String, (u8, u8)>,
}

impl BindingEnv {
    fn note_block(&mut self, statements: &[Expr], frame: &Frame, state: &StateField) {
        for stmt in statements {
            if let ExprKind::Assign { lhs, rhs } = &stmt.kind {
                if let ExprKind::Var(v) = &lhs.kind {
                    if self.is_state(rhs, frame, state) {
                        self.state_temps.insert(v.name.clone());
                        self.slice_temps.remove(&v.name);
                    } else if let Some(slice) = self.state_slice(rhs, frame, state) {
                        self.slice_temps.insert(v.name.clone(), slice);
                        self.state_temps.remove(&v.name);
                    } else {
                        self.state_temps.remove(&v.name);
                        self.slice_temps.remove(&v.name);
                    }
                }
            }
        }
    }

    fn is_state(&self, expr: &Expr, frame: &Frame, state: &StateField) -> bool {
        if frame_offset(expr, frame) == Some(state.offset) {
            return true;
        }
        match &peel_cast(expr).kind {
            ExprKind::Var(v) => self.state_temps.contains(&v.name),
            _ => false,
        }
    }

    /// If `expr` is a bit-slice of the state (`BITS(state, s, w)` directly, or a
    /// temp holding one), return `(start, width)`.
    fn state_slice(&self, expr: &Expr, frame: &Frame, state: &StateField) -> Option<(u8, u8)> {
        match &peel_cast(expr).kind {
            ExprKind::BitField { expr, start, width } if self.is_state(expr, frame, state) => {
                Some((*start, *width))
            }
            ExprKind::Var(v) => self.slice_temps.get(&v.name).copied(),
            _ => None,
        }
    }
}

/// Walk the body, updating the binding environment over `Block`s and attempting
/// to flatten any state-dispatch `If` into a `Switch`.
fn rewrite_nodes(
    nodes: Vec<StructuredNode>,
    frame: &Frame,
    state: &StateField,
    env: &mut BindingEnv,
    domain: &Domain,
) -> Vec<StructuredNode> {
    let mut out = Vec::with_capacity(nodes.len());
    for node in nodes {
        match node {
            StructuredNode::Block {
                id,
                statements,
                address_range,
            } => {
                env.note_block(&statements, frame, state);
                let statements = statements
                    .into_iter()
                    .map(|s| rename_state_in_expr(s, frame, state))
                    .collect();
                out.push(StructuredNode::Block {
                    id,
                    statements,
                    address_range,
                });
            }
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                if let Some(switch_nodes) =
                    try_flatten_switch(&condition, &then_body, &else_body, frame, state, env, domain)
                {
                    out.extend(switch_nodes);
                    continue;
                }
                // Narrow the domain for each branch by the (state) condition, so a
                // dispatch nested under an even/odd or range guard enumerates only
                // the states that can reach it.
                let narrow = |c: Option<DomainConstraint>| match c {
                    Some(c) => domain.with(c),
                    None => domain.clone(),
                };
                let (then_dom, else_dom) = match cond_constraints(&condition, frame, state, env) {
                    Some((t, e)) => (narrow(t), narrow(e)),
                    None => (domain.clone(), domain.clone()),
                };
                let condition = rename_state_in_expr(condition, frame, state);
                let then_body = rewrite_nodes(then_body, frame, state, &mut env.clone(), &then_dom);
                let else_body =
                    else_body.map(|b| rewrite_nodes(b, frame, state, &mut env.clone(), &else_dom));
                out.push(StructuredNode::If {
                    condition,
                    then_body,
                    else_body,
                });
            }
            other => out.push(rewrite_structural(other, frame, state, env, domain)),
        }
    }
    out
}

/// Recurse into the structural children of loops/switch/etc. with a fresh env
/// clone (these don't extend the linear binding scope meaningfully). The domain
/// isn't narrowed across these (a loop/switch body re-enters with the same
/// reachable state set), which is conservative for fate evaluation.
fn rewrite_structural(
    node: StructuredNode,
    frame: &Frame,
    state: &StateField,
    env: &BindingEnv,
    domain: &Domain,
) -> StructuredNode {
    let recur = |b: Vec<StructuredNode>| rewrite_nodes(b, frame, state, &mut env.clone(), domain);
    match node {
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition: rename_state_in_expr(condition, frame, state),
            body: recur(body),
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: recur(body),
            condition: rename_state_in_expr(condition, frame, state),
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
            body: recur(body),
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: recur(body),
            header,
            exit_block,
        },
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value: rename_state_in_expr(value, frame, state),
            cases: cases.into_iter().map(|(vals, body)| (vals, recur(body))).collect(),
            default: default.map(recur),
        },
        StructuredNode::Sequence(nodes) => StructuredNode::Sequence(recur(nodes)),
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => StructuredNode::TryCatch {
            try_body: recur(try_body),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|h| super::structurer::CatchHandler {
                    body: rewrite_nodes(h.body, frame, state, &mut env.clone(), domain),
                    ..h
                })
                .collect(),
        },
        other => other,
    }
}

/// Attempt to flatten an `If` rooted state dispatch into a `Switch`. Returns
/// `None` (leaving the if-tree untouched) unless ≥2 distinct equality cases are
/// confidently recovered. The unmatched-state behavior (default and any explicit
/// trap cases) is computed by evaluating each reachable state value through the
/// original tree, so trapping and fall-through states are emitted exactly.
fn try_flatten_switch(
    condition: &Expr,
    then_body: &[StructuredNode],
    else_body: &Option<Vec<StructuredNode>>,
    frame: &Frame,
    state: &StateField,
    env: &BindingEnv,
    domain: &Domain,
) -> Option<Vec<StructuredNode>> {
    as_state_compare(condition, frame, state, env)?;

    // 1. Collect the equality cases and their bodies.
    let mut cases: Vec<(i128, Vec<StructuredNode>)> = Vec::new();
    collect_cases(condition, then_body, else_body, frame, state, env, &mut cases)?;

    let mut labels = HashSet::new();
    for (label, _) in &cases {
        if !labels.insert(*label) {
            return None; // duplicate case label — not a clean dispatch
        }
    }
    if labels.len() < 2 {
        return None;
    }

    // 2. Determine the fate of every *unmatched* reachable state value by
    //    evaluating the original tree per value. The tree is the root `If`.
    let tree = vec![StructuredNode::If {
        condition: condition.clone(),
        then_body: then_body.to_vec(),
        else_body: else_body.clone(),
    }];
    let max_const = max_state_constant(&tree, frame, state, env).max(*labels.iter().max().unwrap());
    // A value beyond every compared constant (of an allowed parity) stands in for
    // all larger states; its outcome is the switch default.
    let beyond = (max_const + 1..=max_const + 3).find(|v| domain.allows(*v));
    let beyond_outcome = beyond
        .map(|v| eval_outcome(&tree, v, frame, state, env))
        .unwrap_or_default();

    // In-range unmatched values whose outcome differs from the default become
    // explicit cases (grouped by identical outcome), so e.g. a single invalid
    // index traps while the rest fall through.
    let mut extra: Vec<(i128, Vec<StructuredNode>)> = Vec::new();
    for v in 0..=max_const {
        if !domain.allows(v) || labels.contains(&v) {
            continue;
        }
        let outcome = eval_outcome(&tree, v, frame, state, env);
        if !bodies_equivalent(&outcome, &beyond_outcome) {
            extra.push((v, outcome));
        }
    }

    // 3. Safety: a free `break` in any emitted body would be recaptured by the
    //    synthesized switch.
    if cases.iter().chain(extra.iter()).any(|(_, b)| contains_free_break(b))
        || contains_free_break(&beyond_outcome)
    {
        return None;
    }

    // 4. Build the switch: real cases + explicit minority-outcome cases, with the
    //    beyond outcome as the default (empty outcome => no default, fall through).
    cases.extend(extra);
    cases.sort_by_key(|(label, _)| *label);
    let switch_cases: Vec<(Vec<i128>, Vec<StructuredNode>)> = cases
        .into_iter()
        .map(|(label, body)| (vec![label], rewrite_nodes(body, frame, state, &mut env.clone(), domain)))
        .collect();
    let default = if beyond_outcome.is_empty() {
        None
    } else {
        Some(rewrite_nodes(beyond_outcome, frame, state, &mut env.clone(), domain))
    };

    Some(vec![StructuredNode::Switch {
        value: named_state_expr(frame, state),
        cases: switch_cases,
        default,
    }])
}

/// True if `nodes` contain a `break` that is not already enclosed by a nested
/// loop/switch (and so would bind to a freshly-synthesized switch). `continue`
/// only ever targets a loop, which our switch can't capture, so it's ignored.
fn contains_free_break(nodes: &[StructuredNode]) -> bool {
    nodes.iter().any(|n| match n {
        StructuredNode::Break => true,
        StructuredNode::If { then_body, else_body, .. } => {
            contains_free_break(then_body)
                || else_body.as_ref().is_some_and(|b| contains_free_break(b))
        }
        StructuredNode::Sequence(ns) => contains_free_break(ns),
        // try/catch does not capture `break`, so recurse into its bodies.
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => {
            contains_free_break(try_body)
                || catch_handlers.iter().any(|h| contains_free_break(&h.body))
        }
        // Loops and switches capture `break`, so one inside them isn't free.
        _ => false,
    })
}

/// Recursively gather `(label, body)` equality cases from a state-dispatch
/// if-tree. `Eq`/`Ne` produce a case; inequality bound checks partition the
/// state space so we recurse into both branches. Unmatched-state behavior
/// (default / traps) is NOT tracked here — it's computed exactly per value by
/// [`eval_outcome`] in `try_flatten_switch`.
fn collect_cases(
    condition: &Expr,
    then_body: &[StructuredNode],
    else_body: &Option<Vec<StructuredNode>>,
    frame: &Frame,
    state: &StateField,
    env: &BindingEnv,
    cases: &mut Vec<(i128, Vec<StructuredNode>)>,
) -> Option<()> {
    let (op, value) = as_state_compare(condition, frame, state, env)?;
    match op {
        BinOpKind::Eq => {
            cases.push((value, then_body.to_vec()));
            collect_branch_opt(else_body, frame, state, env, cases)
        }
        BinOpKind::Ne => {
            // `state != N` guards the rest in `then`; the excluded value N takes
            // the `else` (an empty body when there's no else).
            cases.push((value, else_body.clone().unwrap_or_default()));
            collect_branch(then_body, frame, state, env, cases)
        }
        BinOpKind::Lt
        | BinOpKind::Le
        | BinOpKind::Gt
        | BinOpKind::Ge
        | BinOpKind::ULt
        | BinOpKind::ULe
        | BinOpKind::UGt
        | BinOpKind::UGe => {
            collect_branch(then_body, frame, state, env, cases)?;
            collect_branch_opt(else_body, frame, state, env, cases)
        }
        _ => None,
    }
}

fn collect_branch_opt(
    else_body: &Option<Vec<StructuredNode>>,
    frame: &Frame,
    state: &StateField,
    env: &BindingEnv,
    cases: &mut Vec<(i128, Vec<StructuredNode>)>,
) -> Option<()> {
    match else_body {
        None => Some(()),
        Some(nodes) => collect_branch(nodes, frame, state, env, cases),
    }
}

/// Process a continuation branch and collect any equality cases it introduces.
/// A leading pure state-reload block (`tmp = frame->__resume_index`) is peeled as
/// a shared prefix and prepended to each recovered case; sibling code after the
/// nested dispatch is the fall-through suffix appended to each case. A terminal
/// (non-dispatch) branch introduces no cases — its per-value fate is handled by
/// `eval_outcome`.
fn collect_branch(
    nodes: &[StructuredNode],
    frame: &Frame,
    state: &StateField,
    env: &BindingEnv,
    cases: &mut Vec<(i128, Vec<StructuredNode>)>,
) -> Option<()> {
    let mut local_env = env.clone();
    let mut prefix: Vec<StructuredNode> = Vec::new();
    let mut tail = nodes;
    while let [block @ StructuredNode::Block { statements, .. }, more @ ..] = tail {
        if !is_state_reload_block(statements, frame, state, &local_env) {
            break;
        }
        local_env.note_block(statements, frame, state);
        prefix.push(block.clone());
        tail = more;
    }

    if let [StructuredNode::If {
        condition,
        then_body,
        else_body,
    }, rest @ ..] = tail
    {
        if as_state_compare(condition, frame, state, &local_env).is_some() {
            let mut sub: Vec<(i128, Vec<StructuredNode>)> = Vec::new();
            collect_cases(condition, then_body, else_body, frame, state, &local_env, &mut sub)?;
            // Each selected case runs: prefix (reload) ++ case body ++ suffix
            // (sibling code that follows the nested dispatch for fall-through).
            for (_, body) in &mut sub {
                if !rest.is_empty() {
                    body.extend(rest.iter().cloned());
                }
                if !prefix.is_empty() {
                    let mut combined = prefix.clone();
                    combined.append(body);
                    *body = combined;
                }
            }
            cases.extend(sub);
        }
    }
    Some(())
}

/// True if every statement in a block is a state-reload assignment
/// (`tmp = <state field or state temp>`) — pure dispatch plumbing with no other
/// effect, which is dead once the dispatch becomes a switch on the named field.
/// An empty block qualifies. `env` is the binding state on entry to the block.
fn is_state_reload_block(
    statements: &[Expr],
    frame: &Frame,
    state: &StateField,
    env: &BindingEnv,
) -> bool {
    let mut local = env.clone();
    for stmt in statements {
        match &stmt.kind {
            ExprKind::Assign { lhs, rhs }
                if matches!(lhs.kind, ExprKind::Var(_)) && local.is_state(rhs, frame, state) =>
            {
                local.note_block(std::slice::from_ref(stmt), frame, state);
            }
            _ => return false,
        }
    }
    true
}

/// If `cond` is `state <op> const`, return the op (oriented so `state` is the
/// left operand) and the constant.
fn as_state_compare(
    cond: &Expr,
    frame: &Frame,
    state: &StateField,
    env: &BindingEnv,
) -> Option<(BinOpKind, i128)> {
    let ExprKind::BinOp { op, left, right } = &cond.kind else {
        return None;
    };
    if !is_comparison(*op) {
        return None;
    }
    if env.is_state(left, frame, state) {
        if let Some(v) = int_lit(right) {
            return Some((*op, v));
        }
    }
    if env.is_state(right, frame, state) {
        if let Some(v) = int_lit(left) {
            return Some((flip_op(*op), v));
        }
    }
    None
}

fn flip_op(op: BinOpKind) -> BinOpKind {
    match op {
        BinOpKind::Lt => BinOpKind::Gt,
        BinOpKind::Le => BinOpKind::Ge,
        BinOpKind::Gt => BinOpKind::Lt,
        BinOpKind::Ge => BinOpKind::Le,
        BinOpKind::ULt => BinOpKind::UGt,
        BinOpKind::ULe => BinOpKind::UGe,
        BinOpKind::UGt => BinOpKind::ULt,
        BinOpKind::UGe => BinOpKind::ULe,
        other => other,
    }
}

/// The named field expression used as the recovered switch value and in renamed
/// state accesses: `frame->__resume_index`.
fn named_state_expr(frame: &Frame, state: &StateField) -> Expr {
    Expr::field_access(
        frame.base_expr.clone(),
        RESUME_FIELD_NAME,
        state.offset as usize,
    )
}

/// Rename a direct state-field access inside an expression to the named
/// `frame->__resume_index` field (recursively).
fn rename_state_in_expr(expr: Expr, frame: &Frame, state: &StateField) -> Expr {
    if frame_offset(&expr, frame) == Some(state.offset) {
        return named_state_expr(frame, state);
    }
    let kind = match expr.kind {
        ExprKind::BinOp { op, left, right } => ExprKind::BinOp {
            op,
            left: Box::new(rename_state_in_expr(*left, frame, state)),
            right: Box::new(rename_state_in_expr(*right, frame, state)),
        },
        ExprKind::UnaryOp { op, operand } => ExprKind::UnaryOp {
            op,
            operand: Box::new(rename_state_in_expr(*operand, frame, state)),
        },
        ExprKind::Assign { lhs, rhs } => ExprKind::Assign {
            lhs: Box::new(rename_state_in_expr(*lhs, frame, state)),
            rhs: Box::new(rename_state_in_expr(*rhs, frame, state)),
        },
        ExprKind::CompoundAssign { op, lhs, rhs } => ExprKind::CompoundAssign {
            op,
            lhs: Box::new(rename_state_in_expr(*lhs, frame, state)),
            rhs: Box::new(rename_state_in_expr(*rhs, frame, state)),
        },
        ExprKind::Cast {
            expr,
            to_size,
            signed,
        } => ExprKind::Cast {
            expr: Box::new(rename_state_in_expr(*expr, frame, state)),
            to_size,
            signed,
        },
        ExprKind::Call { target, args } => ExprKind::Call {
            target,
            args: args
                .into_iter()
                .map(|a| rename_state_in_expr(a, frame, state))
                .collect(),
        },
        other => Expr { kind: other }.kind,
    };
    Expr { kind }
}

// ---- Generic structured-node visitors --------------------------------------

fn visit_assignments(nodes: &[StructuredNode], f: &mut impl FnMut(&Expr, &Expr)) {
    visit_exprs(nodes, &mut |e| {
        if let ExprKind::Assign { lhs, rhs } = &e.kind {
            f(lhs, rhs);
        }
    });
}

/// Walk every expression (and sub-expression) appearing in the body.
fn visit_exprs(nodes: &[StructuredNode], f: &mut impl FnMut(&Expr)) {
    fn walk_expr(e: &Expr, f: &mut impl FnMut(&Expr)) {
        f(e);
        match &e.kind {
            ExprKind::BinOp { left, right, .. } => {
                walk_expr(left, f);
                walk_expr(right, f);
            }
            ExprKind::UnaryOp { operand, .. } => walk_expr(operand, f),
            ExprKind::Deref { addr, .. } => walk_expr(addr, f),
            ExprKind::AddressOf(e) => walk_expr(e, f),
            ExprKind::ArrayAccess { base, index, .. } => {
                walk_expr(base, f);
                walk_expr(index, f);
            }
            ExprKind::FieldAccess { base, .. } => walk_expr(base, f),
            ExprKind::Call { args, .. } => {
                for a in args {
                    walk_expr(a, f);
                }
            }
            ExprKind::Assign { lhs, rhs } | ExprKind::CompoundAssign { lhs, rhs, .. } => {
                walk_expr(lhs, f);
                walk_expr(rhs, f);
            }
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                walk_expr(cond, f);
                walk_expr(then_expr, f);
                walk_expr(else_expr, f);
            }
            ExprKind::Cast { expr, .. } | ExprKind::BitField { expr, .. } => walk_expr(expr, f),
            ExprKind::Phi(exprs) => {
                for e in exprs {
                    walk_expr(e, f);
                }
            }
            _ => {}
        }
    }

    for node in nodes {
        match node {
            StructuredNode::Block { statements, .. } => {
                for s in statements {
                    walk_expr(s, f);
                }
            }
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                walk_expr(condition, f);
                visit_exprs(then_body, f);
                if let Some(b) = else_body {
                    visit_exprs(b, f);
                }
            }
            StructuredNode::While { condition, body, .. }
            | StructuredNode::DoWhile { condition, body, .. } => {
                walk_expr(condition, f);
                visit_exprs(body, f);
            }
            StructuredNode::For { body, .. } | StructuredNode::Loop { body, .. } => {
                visit_exprs(body, f)
            }
            StructuredNode::Switch {
                value,
                cases,
                default,
            } => {
                walk_expr(value, f);
                for (_, b) in cases {
                    visit_exprs(b, f);
                }
                if let Some(b) = default {
                    visit_exprs(b, f);
                }
            }
            StructuredNode::Return(Some(e)) | StructuredNode::Expr(e) => walk_expr(e, f),
            StructuredNode::Sequence(nodes) => visit_exprs(nodes, f),
            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                visit_exprs(try_body, f);
                for handler in catch_handlers {
                    visit_exprs(&handler.body, f);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::expression::Variable;
    use hexray_core::BasicBlockId;

    fn frame() -> Expr {
        Expr::unknown("arg0")
    }

    /// `arg0[18]` (byte offset 36) — the resume-index field.
    fn state_access() -> Expr {
        Expr::array_access(frame(), Expr::int(18), 2)
    }

    fn block(stmts: Vec<Expr>) -> StructuredNode {
        StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: stmts,
            address_range: (0, 0),
        }
    }

    fn iff(cond: Expr, then: Vec<StructuredNode>, els: Vec<StructuredNode>) -> StructuredNode {
        StructuredNode::If {
            condition: cond,
            then_body: then,
            else_body: if els.is_empty() { None } else { Some(els) },
        }
    }

    fn cmp(op: BinOpKind, lhs: Expr, n: i128) -> Expr {
        Expr::binop(op, lhs, Expr::int(n))
    }

    /// Extract a `Switch` node's case labels (sorted) from a body, if present.
    fn switch_labels(body: &[StructuredNode]) -> Option<Vec<i128>> {
        for n in body {
            match n {
                StructuredNode::Switch { cases, .. } => {
                    return Some(cases.iter().flat_map(|(v, _)| v.clone()).collect());
                }
                StructuredNode::If { then_body, else_body, .. } => {
                    if let Some(l) = switch_labels(then_body) {
                        return Some(l);
                    }
                    if let Some(l) = else_body.as_ref().and_then(|b| switch_labels(b)) {
                        return Some(l);
                    }
                }
                StructuredNode::TryCatch { try_body, catch_handlers } => {
                    if let Some(l) = switch_labels(try_body) {
                        return Some(l);
                    }
                    for h in catch_handlers {
                        if let Some(l) = switch_labels(&h.body) {
                            return Some(l);
                        }
                    }
                }
                _ => {}
            }
        }
        None
    }

    #[test]
    fn flattens_equality_chain_into_switch() {
        // if (arg0[18] == 0) A else if (arg0[18] == 1) B else trap
        let body = vec![iff(
            cmp(BinOpKind::Eq, state_access(), 0),
            vec![block(vec![Expr::int(100)])],
            vec![iff(
                cmp(BinOpKind::Eq, state_access(), 1),
                vec![block(vec![Expr::int(200)])],
                vec![block(vec![Expr::unknown("__builtin_trap()")])],
            )],
        )];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
    }

    fn bits0(e: Expr) -> Expr {
        Expr {
            kind: ExprKind::BitField {
                expr: Box::new(e),
                start: 0,
                width: 1,
            },
        }
    }

    #[test]
    fn parity_split_excludes_other_residue_from_cases() {
        // tmp = state & 1;
        // if (tmp == 0) { if (state <= 2) { if (state==0) A else if (state==2) B
        //                                   else trap } }
        // Only even states reach the even branch, so the `<= 2` gap value 1 (odd)
        // must NOT be emitted as a trap case — parity restricts the domain.
        let parity = || Expr::var(Variable::reg("rcx", 4));
        let body = vec![
            block(vec![Expr::assign(parity(), bits0(state_access()))]),
            iff(
                cmp(BinOpKind::Eq, parity(), 0),
                vec![iff(
                    cmp(BinOpKind::Le, state_access(), 2),
                    vec![iff(
                        cmp(BinOpKind::Eq, state_access(), 0),
                        vec![block(vec![Expr::unknown("body_a")])],
                        vec![iff(
                            cmp(BinOpKind::Eq, state_access(), 2),
                            vec![block(vec![Expr::unknown("body_b")])],
                            vec![block(vec![Expr::call(
                                crate::decompiler::expression::CallTarget::Named(
                                    "__builtin_trap".to_string(),
                                ),
                                vec![],
                            )])],
                        )],
                    )],
                    vec![],
                )],
                vec![],
            ),
        ];
        let out = recover_resume_dispatch(body);
        // Even branch: only {0, 2}; the odd value 1 is not a case.
        assert_eq!(switch_labels(&out), Some(vec![0, 2]));
    }

    #[test]
    fn range_limited_trap_becomes_explicit_case_not_global_default() {
        // if (state <= 1) { if (state == 0) A else trap } else { if (state == 2) B }
        // state 1 traps; states > 2 fall through. The trap must be an explicit
        // `case 1:` rather than a default that captures the fall-through states.
        let body = vec![iff(
            cmp(BinOpKind::Le, state_access(), 1),
            vec![iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![Expr::unknown("body_a")])],
                vec![block(vec![Expr::call(
                    crate::decompiler::expression::CallTarget::Named("__builtin_trap".to_string()),
                    vec![],
                )])],
            )],
            vec![iff(
                cmp(BinOpKind::Eq, state_access(), 2),
                vec![block(vec![Expr::unknown("body_b")])],
                vec![],
            )],
        )];
        let out = recover_resume_dispatch(body);
        // 0, 1 (trap), 2 are cases; no default (state > 2 falls through).
        assert_eq!(switch_labels(&out), Some(vec![0, 1, 2]));
        assert!(find_default_dump(&out).is_none());
        assert!(format!("{out:?}").contains("__builtin_trap"));
    }

    #[test]
    fn recovers_dispatch_nested_in_try_catch() {
        // The resume dispatch can be wrapped in a try/catch for an EH coroutine;
        // the scan and rewrite must descend into the try body.
        let inner = vec![iff(
            cmp(BinOpKind::Eq, state_access(), 0),
            vec![block(vec![Expr::unknown("body_a")])],
            vec![iff(
                cmp(BinOpKind::Eq, state_access(), 1),
                vec![block(vec![Expr::unknown("body_b")])],
                vec![],
            )],
        )];
        let body = vec![StructuredNode::TryCatch {
            try_body: inner,
            catch_handlers: vec![],
        }];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
    }

    #[test]
    fn flattens_binary_search_dispatch_with_reloaded_temp() {
        // tmp = arg0[18];
        // if (tmp <= 1) { if (tmp == 0) A else if (tmp == 1) B }
        // else            { if (tmp == 2) C else trap }
        // Mirrors gcc -O0: every case is an explicit `== N`, the bound check only
        // navigates, and there is a single terminal trap default.
        let tmp = || Expr::var(Variable::reg("rax", 4));
        let body = vec![
            block(vec![Expr::assign(tmp(), state_access())]),
            iff(
                cmp(BinOpKind::Le, tmp(), 1),
                vec![iff(
                    cmp(BinOpKind::Eq, tmp(), 0),
                    vec![block(vec![Expr::int(1)])],
                    vec![iff(
                        cmp(BinOpKind::Eq, tmp(), 1),
                        vec![block(vec![Expr::int(2)])],
                        vec![],
                    )],
                )],
                vec![iff(
                    cmp(BinOpKind::Eq, tmp(), 2),
                    vec![block(vec![Expr::int(3)])],
                    vec![block(vec![Expr::unknown("__builtin_trap()")])],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        // `tmp == 0/1/2` resolve through the reload; bound check `<= 1` navigates.
        assert_eq!(switch_labels(&out), Some(vec![0, 1, 2]));
    }

    #[test]
    fn moves_shared_epilogue_after_switch() {
        // if (arg0[18] == 0) {} else if (arg0[18] == 1) {} ; epilogue
        // where the dispatch If is followed by a shared epilogue block.
        let body = vec![iff(
            cmp(BinOpKind::Le, state_access(), 1),
            vec![
                iff(
                    cmp(BinOpKind::Eq, state_access(), 0),
                    vec![block(vec![Expr::int(1)])],
                    vec![iff(
                        cmp(BinOpKind::Eq, state_access(), 1),
                        vec![block(vec![Expr::int(2)])],
                        vec![],
                    )],
                ),
                block(vec![Expr::unknown("epilogue")]),
            ],
            vec![],
        )];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        // The epilogue block survives as a sibling after the switch.
        let has_epilogue = format!("{out:?}").contains("epilogue");
        assert!(has_epilogue);
    }

    #[test]
    fn declines_when_a_case_body_has_a_free_break() {
        // A `break` in a case body would have targeted an enclosing loop/switch;
        // synthesizing a switch around it would recapture it, so decline.
        let body = vec![iff(
            cmp(BinOpKind::Eq, state_access(), 0),
            vec![StructuredNode::Break],
            vec![iff(
                cmp(BinOpKind::Eq, state_access(), 1),
                vec![block(vec![Expr::int(1)])],
                vec![],
            )],
        )];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), None);
    }

    #[test]
    fn declines_when_a_free_break_is_inside_try_catch() {
        // A `break` inside a case body's try/catch (which doesn't capture break)
        // would still be recaptured by the synthesized switch -> decline.
        let body = vec![iff(
            cmp(BinOpKind::Eq, state_access(), 0),
            vec![StructuredNode::TryCatch {
                try_body: vec![StructuredNode::Break],
                catch_handlers: vec![],
            }],
            vec![iff(
                cmp(BinOpKind::Eq, state_access(), 1),
                vec![block(vec![Expr::int(1)])],
                vec![],
            )],
        )];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), None);
    }

    #[test]
    fn leaves_non_dispatch_body_untouched() {
        // A single equality compare (only one case) is not a dispatch.
        let body = vec![iff(
            cmp(BinOpKind::Eq, state_access(), 0),
            vec![block(vec![Expr::int(1)])],
            vec![],
        )];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), None);
    }

    #[test]
    fn ignores_body_without_a_frame_field_dispatch() {
        // Comparisons against a plain register (no frame field) -> no state field.
        let r = || Expr::var(Variable::reg("eax", 4));
        let body = vec![iff(
            cmp(BinOpKind::Eq, r(), 0),
            vec![block(vec![Expr::int(1)])],
            vec![iff(
                cmp(BinOpKind::Eq, r(), 1),
                vec![block(vec![Expr::int(2)])],
                vec![],
            )],
        )];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), None);
    }

    #[test]
    fn appends_suffix_to_nested_real_default_fallthrough() {
        // if (state == 9) X else { if (state==0) A else if (state==1) B else REAL ; suffix }
        // The non-trap REAL default (genuine catch-all for all unmatched states)
        // also falls through to `suffix`, so the suffix is appended to it.
        let body = vec![iff(
            cmp(BinOpKind::Eq, state_access(), 9),
            vec![block(vec![Expr::unknown("body_x")])],
            vec![
                iff(
                    cmp(BinOpKind::Eq, state_access(), 0),
                    vec![block(vec![Expr::unknown("body_a")])],
                    vec![iff(
                        cmp(BinOpKind::Eq, state_access(), 1),
                        vec![block(vec![Expr::unknown("body_b")])],
                        vec![block(vec![Expr::unknown("real_default")])],
                    )],
                ),
                block(vec![Expr::unknown("suffix")]),
            ],
        )];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1, 9]));
        // The real default must carry the suffix; a trap default would not.
        let default_dump = find_default_dump(&out).expect("switch default present");
        assert!(default_dump.contains("real_default"));
        assert!(default_dump.contains("suffix"));
    }

    #[test]
    fn noreturn_trap_default_does_not_get_dead_suffix() {
        let body = vec![iff(
            cmp(BinOpKind::Eq, state_access(), 9),
            vec![block(vec![Expr::unknown("body_x")])],
            vec![
                iff(
                    cmp(BinOpKind::Eq, state_access(), 0),
                    vec![block(vec![Expr::unknown("body_a")])],
                    vec![iff(
                        cmp(BinOpKind::Eq, state_access(), 1),
                        vec![block(vec![Expr::unknown("body_b")])],
                        vec![block(vec![Expr::call(
                            crate::decompiler::expression::CallTarget::Named(
                                "__builtin_trap".to_string(),
                            ),
                            vec![],
                        )])],
                    )],
                ),
                block(vec![Expr::unknown("suffix")]),
            ],
        )];
        let out = recover_resume_dispatch(body);
        let default_dump = find_default_dump(&out).expect("switch default present");
        assert!(default_dump.contains("__builtin_trap"));
        assert!(!default_dump.contains("suffix"));
    }

    #[test]
    fn bound_without_else_does_not_trap_fallthrough_states() {
        // if (state <= 1) { if (state==0) A else if (state==1) B else trap }
        // No else on the bound: states > 1 fall through, so the dead taken-range
        // trap must NOT become the switch default that captures them.
        let body = vec![iff(
            cmp(BinOpKind::Le, state_access(), 1),
            vec![iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![Expr::unknown("body_a")])],
                vec![iff(
                    cmp(BinOpKind::Eq, state_access(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![block(vec![Expr::call(
                        crate::decompiler::expression::CallTarget::Named(
                            "__builtin_trap".to_string(),
                        ),
                        vec![],
                    )])],
                )],
            )],
            vec![],
        )];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        // The dead taken-range trap is dropped; no default captures state > 1.
        assert!(find_default_dump(&out).is_none());
    }

    fn find_default_dump(body: &[StructuredNode]) -> Option<String> {
        for n in body {
            match n {
                StructuredNode::Switch { default, .. } => {
                    return default.as_ref().map(|d| format!("{d:?}"));
                }
                StructuredNode::If { then_body, else_body, .. } => {
                    if let Some(d) = find_default_dump(then_body) {
                        return Some(d);
                    }
                    if let Some(d) = else_body.as_ref().and_then(|b| find_default_dump(b)) {
                        return Some(d);
                    }
                }
                _ => {}
            }
        }
        None
    }

    #[test]
    fn flattens_dispatch_with_leading_reload_block_in_branch() {
        // if (arg0[18] <= 1) { tmp = arg0[18]; if (tmp==0) A else if (tmp==1) B }
        // else                { if (arg0[18] == 2) C else trap }
        // The reload block before the nested dispatch is peeled and re-prepended
        // to the recovered cases.
        let tmp = || Expr::var(Variable::reg("rax", 4));
        let body = vec![iff(
            cmp(BinOpKind::Le, state_access(), 1),
            vec![
                block(vec![Expr::assign(tmp(), state_access())]),
                iff(
                    cmp(BinOpKind::Eq, tmp(), 0),
                    vec![block(vec![Expr::unknown("body_a")])],
                    vec![iff(
                        cmp(BinOpKind::Eq, tmp(), 1),
                        vec![block(vec![Expr::unknown("body_b")])],
                        vec![],
                    )],
                ),
            ],
            vec![iff(
                cmp(BinOpKind::Eq, state_access(), 2),
                vec![block(vec![Expr::unknown("body_c")])],
                vec![block(vec![Expr::call(
                    crate::decompiler::expression::CallTarget::Named("__builtin_trap".to_string()),
                    vec![],
                )])],
            )],
        )];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1, 2]));
    }

    #[test]
    fn reused_stack_slot_is_not_treated_as_frame_alias() {
        // local_8 = arg0; local_8 = <non-frame>; if (local_8[18]==0/1) ...
        // Because local_8 is later overwritten with a non-frame value, it must NOT
        // be trusted as the frame, so its `[18]` compares aren't a resume dispatch.
        let local = || Expr::var(Variable::stack(-8, 8));
        let local_state = || Expr::array_access(local(), Expr::int(18), 2);
        let body = vec![
            block(vec![
                Expr::assign(local(), frame()),
                Expr::assign(local(), Expr::var(Variable::reg("rcx", 8))), // non-frame reuse
            ]),
            iff(
                cmp(BinOpKind::Eq, local_state(), 0),
                vec![block(vec![Expr::int(1)])],
                vec![iff(
                    cmp(BinOpKind::Eq, local_state(), 1),
                    vec![block(vec![Expr::int(2)])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), None);
        assert!(!format!("{out:?}").contains(RESUME_FIELD_NAME));
    }

    #[test]
    fn recognizes_named_stack_local_frame_spill() {
        // local_8 = arg0;  (a VarKind::Stack home, not a memory expr)
        // if (local_8[18] == 0) .. else if (local_8[18] == 1) ..
        let local = || Expr::var(Variable::stack(-8, 8));
        let local_state = || Expr::array_access(local(), Expr::int(18), 2);
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            iff(
                cmp(BinOpKind::Eq, local_state(), 0),
                vec![block(vec![Expr::int(1)])],
                vec![iff(
                    cmp(BinOpKind::Eq, local_state(), 1),
                    vec![block(vec![Expr::int(2)])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
    }

    #[test]
    fn temp_reused_for_another_field_does_not_misidentify_state() {
        // tmp = arg0[18]; if (tmp==0) .. else if (tmp==1) ..   (real dispatch @36)
        // tmp = arg0[50]; if (tmp==9) ..                       (reuse, offset 100)
        // The ordered scan attributes 0/1 to offset 36, not the later 100.
        let tmp = || Expr::var(Variable::reg("rax", 4));
        let other = Expr::array_access(frame(), Expr::int(50), 2); // offset 100
        let body = vec![
            block(vec![Expr::assign(tmp(), state_access())]),
            iff(
                cmp(BinOpKind::Eq, tmp(), 0),
                vec![block(vec![Expr::int(1)])],
                vec![iff(
                    cmp(BinOpKind::Eq, tmp(), 1),
                    vec![block(vec![Expr::int(2)])],
                    vec![],
                )],
            ),
            block(vec![Expr::assign(tmp(), other)]),
            iff(cmp(BinOpKind::Eq, tmp(), 9), vec![block(vec![Expr::int(3)])], vec![]),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
    }

    #[test]
    fn ne_without_else_makes_excluded_value_fall_through_not_trap() {
        // if (state != 0) { if (state==1) A else if (state==2) B else trap }
        // state == 0 must NOT hit the trap default; it falls through (empty case).
        let body = vec![iff(
            cmp(BinOpKind::Ne, state_access(), 0),
            vec![iff(
                cmp(BinOpKind::Eq, state_access(), 1),
                vec![block(vec![Expr::unknown("body_a")])],
                vec![iff(
                    cmp(BinOpKind::Eq, state_access(), 2),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![block(vec![Expr::call(
                        crate::decompiler::expression::CallTarget::Named(
                            "__builtin_trap".to_string(),
                        ),
                        vec![],
                    )])],
                )],
            )],
            vec![],
        )];
        let out = recover_resume_dispatch(body);
        // Case 0 exists (empty fall-through), 1 and 2 carry bodies, trap is default.
        assert_eq!(switch_labels(&out), Some(vec![0, 1, 2]));
        let default_dump = find_default_dump(&out).expect("trap default");
        assert!(default_dump.contains("__builtin_trap"));
    }

    #[test]
    fn implicit_fallthrough_suffix_becomes_default() {
        // if (state != 0) { if (state == 1) A ; suffix } else B
        // Unmatched states (not 0, not 1) fall through the inner if to `suffix`,
        // so the synthesized switch default must run `suffix`.
        let body = vec![iff(
            cmp(BinOpKind::Ne, state_access(), 0),
            vec![
                iff(
                    cmp(BinOpKind::Eq, state_access(), 1),
                    vec![block(vec![Expr::unknown("body_a")])],
                    vec![],
                ),
                block(vec![Expr::unknown("suffix")]),
            ],
            vec![block(vec![Expr::unknown("body_b")])],
        )];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let default_dump = find_default_dump(&out).expect("synthesized default");
        assert!(default_dump.contains("suffix"));
    }

    #[test]
    fn range_checked_field_is_not_mistaken_for_resume_index() {
        // A frame field compared only with inequalities (range checks) has no
        // equality labels, so it must not be picked as the resume index, and with
        // no switch recovered the body is returned unchanged (no rename).
        let body = vec![iff(
            cmp(BinOpKind::Lt, state_access(), 2),
            vec![block(vec![Expr::int(1)])],
            vec![iff(
                cmp(BinOpKind::Lt, state_access(), 4),
                vec![block(vec![Expr::int(2)])],
                vec![],
            )],
        )];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), None);
        assert!(!format!("{out:?}").contains(RESUME_FIELD_NAME));
    }

    #[test]
    fn does_not_rename_when_no_switch_recovered() {
        // Two equality compares on the field but they never form a flattenable
        // dispatch shape the pass recognizes... here a single case only.
        let body = vec![iff(
            cmp(BinOpKind::Eq, state_access(), 0),
            vec![block(vec![Expr::assign(state_access(), Expr::int(9))])],
            vec![],
        )];
        let out = recover_resume_dispatch(body);
        // One case -> no switch -> field left as-is (no `__resume_index`).
        assert!(!format!("{out:?}").contains(RESUME_FIELD_NAME));
    }

    #[test]
    fn renames_state_field_accesses() {
        let body = vec![iff(
            cmp(BinOpKind::Eq, state_access(), 0),
            vec![block(vec![Expr::int(1)])],
            vec![iff(
                cmp(BinOpKind::Eq, state_access(), 1),
                vec![block(vec![Expr::assign(state_access(), Expr::int(2))])],
                vec![],
            )],
        )];
        let out = recover_resume_dispatch(body);
        let dump = format!("{out:?}");
        assert!(dump.contains(RESUME_FIELD_NAME));
    }
}
