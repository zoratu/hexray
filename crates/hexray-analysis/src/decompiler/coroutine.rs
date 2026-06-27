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
    let rewritten = rewrite_nodes(body.clone(), &frame, &state, &mut env);
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

    // A `break` in a recovered body that targeted an enclosing loop/switch would
    // be captured by the switch we're about to synthesize, changing its target.
    // Decline the flatten if any case or the default has such a free break.
    if acc
        .cases
        .iter()
        .any(|(_, body)| contains_free_break(body))
        || acc.default.as_deref().is_some_and(contains_free_break)
    {
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
            // `state != N` guards the rest in `then`; the excluded value N takes
            // the `else`. Always materialize case N — with the else body, or an
            // empty body when there's no else (so state == N breaks to the shared
            // post-dispatch flow instead of hitting the default).
            acc.cases.push((value, else_body.clone().unwrap_or_default()));
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
            // Each side of the bound covers only its own sub-range, so any default
            // recovered from a branch is range-limited. A flat switch has a single
            // default for ALL unmatched states, so a *live* (non-noreturn)
            // range-limited default can't be represented — decline. A noreturn
            // trap is uniform-enough (invalid states abort) and is merged.
            let mut then_d = Dispatch::default();
            collect_branch(then_body, frame, state, env, &mut then_d)?;
            if matches!(&then_d.default, Some(d) if !body_is_noreturn(d)) {
                return None;
            }
            acc.cases.extend(then_d.cases);

            match else_body {
                Some(else_nodes) => {
                    // Both ranges are dispatched explicitly.
                    let mut else_d = Dispatch::default();
                    collect_branch(else_nodes, frame, state, env, &mut else_d)?;
                    if matches!(&else_d.default, Some(d) if !body_is_noreturn(d)) {
                        return None;
                    }
                    acc.cases.extend(else_d.cases);
                    for d in [then_d.default, else_d.default].into_iter().flatten() {
                        if acc.default.is_none() {
                            acc.default = Some(d);
                        }
                    }
                    Some(())
                }
                None => {
                    // No else: states not satisfying the bound fall through past the
                    // dispatch, so the taken range's noreturn trap (covering only
                    // taken-range gaps, dead for a dense dispatch) must be dropped —
                    // not promoted to a default that would trap those fall-through
                    // states.
                    Some(())
                }
            }
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
    // A nested dispatch may be preceded by leading `Block`s — typically a reload
    // `tmp = frame->__resume_index` that feeds the comparisons. Peel them as a
    // shared prefix (advancing the binding env so the reloaded temp resolves) and
    // prepend them to each selected case below, so the reload still runs exactly
    // once for the chosen state.
    let mut local_env = env.clone();
    let mut prefix: Vec<StructuredNode> = Vec::new();
    let mut tail = nodes;
    while let [block @ StructuredNode::Block { statements, .. }, more @ ..] = tail {
        // Only peel a block that is purely state-reload plumbing
        // (`tmp = frame->__resume_index`). Such a block is dead once the dispatch
        // is a switch, so it's safe to skip on unmatched states; a block with any
        // other effect must stay put (it becomes the terminal default body), so
        // stop peeling.
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
            // Flatten the nested dispatch into a private accumulator first.
            let mut sub = Dispatch::default();
            collect_cases(condition, then_body, else_body, frame, state, &local_env, &mut sub)?;
            // Sibling code after the nested dispatch is the fall-through suffix for
            // the states IT covered. It runs for each matched case AND for the
            // states that fell through unmatched — so append it to the case bodies
            // and to the default. When there is no explicit default, the unmatched
            // states implicitly fall through to the suffix, so synthesize one from
            // it; a noreturn (trap) default never falls through, so it is left as
            // is. (Done before the prefix so the prefix wraps the synthesized
            // default too.)
            if !rest.is_empty() {
                for (_, body) in &mut sub.cases {
                    body.extend(rest.iter().cloned());
                }
                match &mut sub.default {
                    None => sub.default = Some(rest.to_vec()),
                    Some(default_body) if !body_is_noreturn(default_body) => {
                        default_body.extend(rest.iter().cloned());
                    }
                    Some(_) => {}
                }
            }
            // The peeled prefix is a pure state reload (see the peel loop), which
            // becomes dead once the dispatch is a switch on the named field —
            // prepend it to each matched case body (harmless, keeps any temp use
            // defined) and to an existing default. Unmatched states skip it, which
            // is safe precisely because it has no effect beyond feeding the
            // dispatch we just replaced.
            if !prefix.is_empty() {
                for (_, body) in &mut sub.cases {
                    let mut combined = prefix.clone();
                    combined.append(body);
                    *body = combined;
                }
                if let Some(default_body) = &mut sub.default {
                    let mut combined = prefix.clone();
                    combined.append(default_body);
                    *default_body = combined;
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
    match &e.kind {
        ExprKind::Call { target, .. } => {
            let name = match target {
                CallTarget::Named(n) => Some(n.as_str()),
                _ => None,
            };
            matches!(
                name,
                Some("__builtin_trap" | "__builtin_unreachable" | "abort" | "std::terminate")
            )
        }
        // Some lifters surface a trap/unreachable as an opaque marker rather than
        // a call (e.g. x86 `ud2`).
        ExprKind::Unknown(s) => s.contains("__builtin_trap") || s.contains("__builtin_unreachable"),
        _ => false,
    }
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
