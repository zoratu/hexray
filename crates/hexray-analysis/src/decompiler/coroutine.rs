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

use super::expression::{BinOpKind, Expr, ExprKind};
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
    rewrite_nodes(body, &frame, &state, &mut env)
}

/// Identify the frame pointer (the first parameter) and its stable aliases.
fn build_frame(body: &[StructuredNode]) -> Option<Frame> {
    // The frame is the first parameter, represented as `Unknown("arg0")` (or a
    // `Var` named `arg0`). Find a representative base expression.
    let base_expr = find_frame_param(body)?;
    let mut aliases = HashSet::new();
    aliases.insert(alias_key(&base_expr)?);

    // Fixpoint: a `mem = <frame alias>` copy (the prologue spill) makes that
    // stack home another alias. Restricted to memory destinations so reused
    // scratch registers don't pollute the set.
    loop {
        let mut changed = false;
        visit_assignments(body, &mut |lhs, rhs| {
            if !is_memory(lhs) {
                return;
            }
            if let (Some(rk), Some(lk)) = (alias_key(rhs), alias_key(lhs)) {
                if aliases.contains(&rk) && !aliases.contains(&lk) {
                    aliases.insert(lk);
                    changed = true;
                }
            }
        });
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

fn is_memory(e: &Expr) -> bool {
    matches!(
        e.kind,
        ExprKind::ArrayAccess { .. } | ExprKind::Deref { .. } | ExprKind::FieldAccess { .. }
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
    if let Some((off, value)) = compare_to_frame_offset(cond, frame, temp_offset) {
        if (0..256).contains(&value) {
            counts.entry(off).or_default().insert(value);
        }
    }
}

/// If `cond` is `<frame field or its temp> <cmp> <const>`, return (offset, const).
fn compare_to_frame_offset(
    cond: &Expr,
    frame: &Frame,
    temp_offset: &HashMap<String, i64>,
) -> Option<(i64, i128)> {
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
        return Some((off, v));
    }
    if let (Some(off), Some(v)) = (resolve(right), int_lit(left)) {
        return Some((off, v));
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

/// Scoped binding environment: temporaries currently holding the state value
/// (`tmp = frame->state`, kept across zero-extending `tmp = (u16)tmp` copies).
#[derive(Default, Clone)]
struct BindingEnv {
    state_temps: HashSet<String>,
}

impl BindingEnv {
    fn note_block(&mut self, statements: &[Expr], frame: &Frame, state: &StateField) {
        for stmt in statements {
            if let ExprKind::Assign { lhs, rhs } = &stmt.kind {
                if let ExprKind::Var(v) = &lhs.kind {
                    if self.is_state(rhs, frame, state) {
                        self.state_temps.insert(v.name.clone());
                    } else {
                        self.state_temps.remove(&v.name);
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
}

/// Walk the body, updating the binding environment over `Block`s and attempting
/// to flatten any state-dispatch `If` into a `Switch`.
fn rewrite_nodes(
    nodes: Vec<StructuredNode>,
    frame: &Frame,
    state: &StateField,
    env: &mut BindingEnv,
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
                    try_flatten_switch(&condition, &then_body, &else_body, frame, state, env)
                {
                    out.extend(switch_nodes);
                    continue;
                }
                let condition = rename_state_in_expr(condition, frame, state);
                let then_body = rewrite_nodes(then_body, frame, state, &mut env.clone());
                let else_body = else_body.map(|b| rewrite_nodes(b, frame, state, &mut env.clone()));
                out.push(StructuredNode::If {
                    condition,
                    then_body,
                    else_body,
                });
            }
            other => out.push(rewrite_structural(other, frame, state, env)),
        }
    }
    out
}

/// Recurse into the structural children of loops/switch/etc. with a fresh env
/// clone (these don't extend the linear binding scope meaningfully).
fn rewrite_structural(
    node: StructuredNode,
    frame: &Frame,
    state: &StateField,
    env: &BindingEnv,
) -> StructuredNode {
    let recur = |b: Vec<StructuredNode>| rewrite_nodes(b, frame, state, &mut env.clone());
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
        other => other,
    }
}

/// Attempt to flatten an `If` rooted state dispatch into a `Switch`. Returns
/// `None` (leaving the if-tree untouched) unless ≥2 distinct equality cases are
/// confidently recovered.
fn try_flatten_switch(
    condition: &Expr,
    then_body: &[StructuredNode],
    else_body: &Option<Vec<StructuredNode>>,
    frame: &Frame,
    state: &StateField,
    env: &BindingEnv,
) -> Option<Vec<StructuredNode>> {
    as_state_compare(condition, frame, state, env)?;

    let mut acc = Dispatch::default();
    collect_cases(condition, then_body, else_body, frame, state, env, &mut acc)?;

    let mut seen = HashSet::new();
    for (label, _) in &acc.cases {
        if !seen.insert(*label) {
            return None;
        }
    }
    if seen.len() < 2 {
        return None;
    }

    acc.cases.sort_by_key(|(label, _)| *label);
    let switch_cases: Vec<(Vec<i128>, Vec<StructuredNode>)> = acc
        .cases
        .into_iter()
        .map(|(label, body)| (vec![label], rewrite_nodes(body, frame, state, &mut env.clone())))
        .collect();
    let default = acc
        .default
        .map(|b| rewrite_nodes(b, frame, state, &mut env.clone()));

    // Any code that follows this dispatch at the SAME sibling level (shared by
    // every case) stays after the switch — `rewrite_nodes` keeps those siblings
    // in place. Code local to one branch is appended to that branch's cases in
    // `collect_branch`, never hoisted, so semantics are preserved.
    Some(vec![StructuredNode::Switch {
        value: named_state_expr(frame, state),
        cases: switch_cases,
        default,
    }])
}

/// Accumulator for a flattened dispatch: equality cases and the terminal default
/// (a trap / unreachable / empty leaf).
#[derive(Default)]
struct Dispatch {
    cases: Vec<(i128, Vec<StructuredNode>)>,
    default: Option<Vec<StructuredNode>>,
}

/// Recursively gather `(label, body)` cases from a state-dispatch if-tree.
/// `Eq`/`Ne` produce a case; inequality bound checks partition the state space
/// so we recurse into both branches; a non-state terminal body becomes the
/// default (a second one aborts the flatten — mixed control flow).
fn collect_cases(
    condition: &Expr,
    then_body: &[StructuredNode],
    else_body: &Option<Vec<StructuredNode>>,
    frame: &Frame,
    state: &StateField,
    env: &BindingEnv,
    acc: &mut Dispatch,
) -> Option<()> {
    let (op, value) = as_state_compare(condition, frame, state, env)?;
    match op {
        BinOpKind::Eq => {
            acc.cases.push((value, then_body.to_vec()));
            collect_branch_opt(else_body, frame, state, env, acc)
        }
        BinOpKind::Ne => {
            if let Some(else_nodes) = else_body {
                acc.cases.push((value, else_nodes.clone()));
            }
            collect_branch(then_body, frame, state, env, acc)
        }
        BinOpKind::Lt
        | BinOpKind::Le
        | BinOpKind::Gt
        | BinOpKind::Ge
        | BinOpKind::ULt
        | BinOpKind::ULe
        | BinOpKind::UGt
        | BinOpKind::UGe => {
            collect_branch(then_body, frame, state, env, acc)?;
            collect_branch_opt(else_body, frame, state, env, acc)
        }
        _ => None,
    }
}

fn collect_branch_opt(
    else_body: &Option<Vec<StructuredNode>>,
    frame: &Frame,
    state: &StateField,
    env: &BindingEnv,
    acc: &mut Dispatch,
) -> Option<()> {
    match else_body {
        None => Some(()),
        Some(nodes) => collect_branch(nodes, frame, state, env, acc),
    }
}

/// Process a continuation branch: if its first node is a nested state dispatch,
/// recurse, and treat any sibling nodes after it as the shared fall-through
/// epilogue (post-switch code). A pure terminal body (a trap / unreachable /
/// empty leaf) is the switch default; a second distinct default aborts.
fn collect_branch(
    nodes: &[StructuredNode],
    frame: &Frame,
    state: &StateField,
    env: &BindingEnv,
    acc: &mut Dispatch,
) -> Option<()> {
    if let [StructuredNode::If {
        condition,
        then_body,
        else_body,
    }, rest @ ..] = nodes
    {
        if as_state_compare(condition, frame, state, env).is_some() {
            // Flatten the nested dispatch into a private accumulator first.
            let mut sub = Dispatch::default();
            collect_cases(condition, then_body, else_body, frame, state, env, &mut sub)?;
            // Sibling code after the nested dispatch is the fall-through for the
            // states IT covered only — append it to those case bodies (and the
            // nested default, which also falls through) rather than hoisting it,
            // so it never runs for states handled elsewhere. (When the nested
            // default is the usual unreachable trap the appended copy is dead but
            // harmless.)
            if !rest.is_empty() {
                for (_, body) in &mut sub.cases {
                    body.extend(rest.iter().cloned());
                }
                if let Some(default_body) = &mut sub.default {
                    if !body_is_noreturn(default_body) {
                        default_body.extend(rest.iter().cloned());
                    }
                }
            }
            acc.cases.extend(sub.cases);
            // Merge defaults. Two nested branches usually share the same
            // unreachable trap leaf; keep one. But two *distinct, live* defaults
            // mean states would reach different code than the original — abort the
            // flatten rather than silently pick one.
            match (acc.default.take(), sub.default) {
                (None, d) | (d, None) => acc.default = d,
                (Some(a), Some(b)) => {
                    if bodies_equivalent(&a, &b)
                        || (body_is_noreturn(&a) && body_is_noreturn(&b))
                    {
                        acc.default = Some(a);
                    } else {
                        return None;
                    }
                }
            }
            return Some(());
        }
    }
    if nodes.is_empty() {
        return Some(());
    }
    if acc.default.is_some() {
        return None;
    }
    acc.default = Some(nodes.to_vec());
    Some(())
}

/// True if a branch body cannot fall through to following code — its last
/// statement is a `return`/`break`/`continue`, or a call to a noreturn builtin
/// (`__builtin_trap`/`__builtin_unreachable`, `abort`). Used so a post-dispatch
/// suffix is not appended (as dead code) after such a body.
fn body_is_noreturn(nodes: &[StructuredNode]) -> bool {
    match nodes.last() {
        Some(StructuredNode::Return(_) | StructuredNode::Break | StructuredNode::Continue) => true,
        Some(StructuredNode::Block { statements, .. }) => {
            statements.iter().any(is_noreturn_call)
        }
        Some(StructuredNode::Expr(e)) => is_noreturn_call(e),
        _ => false,
    }
}

fn is_noreturn_call(e: &Expr) -> bool {
    use super::expression::CallTarget;
    if let ExprKind::Call { target, .. } = &e.kind {
        let name = match target {
            CallTarget::Named(n) => Some(n.as_str()),
            _ => None,
        };
        return matches!(
            name,
            Some("__builtin_trap" | "__builtin_unreachable" | "abort" | "std::terminate")
        );
    }
    false
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
        // if (state <= 1) { if (state==0) A else if (state==1) B else REAL ; suffix }
        // The non-trap REAL default also falls through to `suffix`, so the suffix
        // must be appended to it (not just the cases).
        let body = vec![iff(
            cmp(BinOpKind::Le, state_access(), 1),
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
            vec![],
        )];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        // The real default must carry the suffix; a trap default would not.
        let default_dump = find_default_dump(&out).expect("switch default present");
        assert!(default_dump.contains("real_default"));
        assert!(default_dump.contains("suffix"));
    }

    #[test]
    fn noreturn_trap_default_does_not_get_dead_suffix() {
        let body = vec![iff(
            cmp(BinOpKind::Le, state_access(), 1),
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
            vec![],
        )];
        let out = recover_resume_dispatch(body);
        let default_dump = find_default_dump(&out).expect("switch default present");
        assert!(default_dump.contains("__builtin_trap"));
        assert!(!default_dump.contains("suffix"));
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
