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
    /// Target pointer width in bytes, derived from a frame-pointer home's width
    /// (a slot holding the whole frame pointer is exactly pointer-sized). Used to
    /// tell a full-width register copy (`reg = frame`, establishes an alias) from a
    /// partial one (`eax = frame` on a 64-bit target). Defaults to 8 when no
    /// sized home is found.
    pointer_size: u8,
}

impl Frame {
    /// A copy of this frame with extra register names (flow-sensitively found to
    /// currently hold a frame-pointer copy) added to the alias set, so a store
    /// through such a register — `ret[18] = N` after `ret = frame_copy` — is
    /// recognized as a frame field access. See [`BindingEnv::frame_ptr_regs`].
    fn with_frame_ptr_regs(&self, reg_names: &HashSet<String>) -> Frame {
        if reg_names.is_empty() {
            return self.clone();
        }
        let mut aliases = self.aliases.clone();
        aliases.extend(reg_names.iter().map(|n| format!("V:{n}")));
        Frame {
            aliases,
            base_expr: self.base_expr.clone(),
            pointer_size: self.pointer_size,
        }
    }
}

/// The recovered resume-index field, identified by its byte offset in the frame.
#[derive(Clone, Copy)]
struct StateField {
    offset: i64,
}

/// Recover the resume dispatch in a coroutine clone body. Returns the body
/// unchanged when no frame or confident dispatch is found.
pub fn recover_resume_dispatch(body: Vec<StructuredNode>) -> Vec<StructuredNode> {
    // Normalize the dispatch spine by splicing transparent `Sequence` wrappers
    // inline (constant propagation etc. can wrap fall-through code, or an `else if`
    // continuation, as `Sequence([...])`). Analysis and the rewrite then run on a
    // Sequence-free spine, so field detection, guard canonicalization, and the
    // flattener all see the dispatch directly. On no recovery the ORIGINAL body is
    // returned unchanged, so a non-coroutine or unrecovered clone is never restructured.
    let normalized = flatten_spine_sequences(body.clone());
    let Some(frame) = build_frame(&normalized) else {
        return body;
    };
    let Some(state) = find_state_field(&normalized, &frame) else {
        return body;
    };
    let mut env = BindingEnv::default();
    let rewritten = rewrite_nodes(normalized, &frame, &state, &mut env, &Domain::default());
    // The rewrite also renames the state field to `frame->__resume_index`; only
    // commit it when a dispatch actually flattened into a switch, so a field that
    // merely happened to be the most-compared one is never renamed in isolation.
    if contains_resume_switch(&rewritten) {
        rewritten
    } else {
        body
    }
}

/// Splice transparent `Sequence` wrappers inline throughout the dispatch spine
/// (the top-level node list and every `If` branch, recursively), so downstream
/// detection/rewrite/flatten never see a `Sequence` between a frame copy and its
/// dispatch or wrapping an `else if` continuation. Loop/switch/try-catch bodies are
/// left as-is — the resume dispatch is the outermost branching, never inside them.
fn flatten_spine_sequences(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    let mut out = Vec::with_capacity(nodes.len());
    for node in nodes {
        match node {
            StructuredNode::Sequence(inner) => out.extend(flatten_spine_sequences(inner)),
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => out.push(StructuredNode::If {
                condition,
                then_body: flatten_spine_sequences(then_body),
                else_body: else_body.map(flatten_spine_sequences),
            }),
            other => out.push(other),
        }
    }
    out
}

/// Whether a (recovered) body contains the resume-index `switch` — i.e. the
/// dispatch reconstruction actually fired. Used to keep the coroutine header from
/// claiming a recovered switch on steppers where the pass declined.
pub fn body_has_resume_switch(nodes: &[StructuredNode]) -> bool {
    contains_resume_switch(nodes)
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
    // Widths of sized (stack-slot `Var`) frame homes, keyed like `aliases`. A slot
    // that stably holds the frame pointer is exactly pointer-wide, so once the
    // fixpoint below confirms a home is a frame alias, its width gives the target
    // pointer size (see `Frame::pointer_size`).
    let mut home_sizes: HashMap<String, u8> = HashMap::new();
    visit_assignments(body, &mut |lhs, rhs| {
        if !is_stable_frame_home(lhs) {
            return;
        }
        if let Some(lk) = alias_key(lhs) {
            if let Some(w) = frame_home_width(lhs) {
                home_sizes.insert(lk.clone(), w);
            }
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
    // Derive the target pointer width from a confirmed frame-alias home's slot
    // width (all hold the whole pointer, so they agree), falling back to the frame
    // parameter's own width when it is a sized `Var` — so an optimized 32-bit
    // coroutine that keeps the frame in a register with no stack spill is still
    // recognized. Default to 8 only when nothing sized is available.
    let base_width = match &base_expr.kind {
        ExprKind::Var(v) if v.size > 0 => Some(v.size),
        _ => None,
    };
    let pointer_size = aliases
        .iter()
        .filter_map(|k| home_sizes.get(k).copied())
        .chain(base_width)
        .max()
        .unwrap_or(8);
    Some(Frame {
        aliases,
        base_expr,
        pointer_size,
    })
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

/// The store width (bytes) of a frame-pointer home, when it directly encodes the
/// pointer size: a stack-slot `Var`'s size, or a memory `Deref`'s access size —
/// both equal the target pointer width for a slot that holds the whole frame
/// pointer. Returns `None` for homes whose width is not a reliable pointer size
/// (`ArrayAccess` element size / `FieldAccess`), so `pointer_size` only ever
/// tightens the full-copy gate on evidence we trust.
fn frame_home_width(e: &Expr) -> Option<u8> {
    match &e.kind {
        ExprKind::Var(v) if v.size > 0 => Some(v.size),
        ExprKind::Deref { size, .. } if *size > 0 => Some(*size),
        _ => None,
    }
}

/// Update the block-local set of registers currently holding a frame-pointer
/// copy for one straight-line statement: `reg = <frame value>` marks `reg`; any
/// other assignment (or compound assignment) to `reg` clears it; and a call
/// clobbers every caller-saved register (a callee-saved one survives). Tracked
/// only within a single `Block`'s straight-line statements, so no stale alias can
/// ever leak across a branch/loop/call boundary.
fn note_frame_ptr_reg(regs: &mut HashSet<String>, stmt: &Expr, frame: &Frame) {
    // (The call clobber is applied by the caller BEFORE this statement's rename,
    // so it covers a call in the statement itself; here we only handle the
    // statement's effect on the tracked registers.)
    //
    // First invalidate the alias of every register written ANYWHERE in the
    // statement — not just a top-level assignment, but nested mutations such as
    // `foo(++rbx)` or a conditional containing `rbx += 8` — since after such a
    // write the register no longer holds the frame.
    clear_mutated_regs(regs, stmt);
    // Then, a top-level FULL-WIDTH `reg = <frame value>` (re)establishes the alias.
    // A partial write only defines part of the pointer, so it can't be trusted as
    // the frame (and was already invalidated above). Width is checked by size
    // because a sub-register may be lifted under its 64-bit name (e.g. `eax` as
    // name `rax`, size 4); `pointer_size` is the target pointer width (4 on 32-bit,
    // 8 on 64-bit), so a full copy is recognized on every architecture.
    if let ExprKind::Assign { lhs, rhs } = &stmt.kind {
        if let ExprKind::Var(v) = &lhs.kind {
            if holds_frame_ptr(regs, rhs, frame) && v.size >= frame.pointer_size {
                regs.insert(canon_reg(&v.name));
            }
        }
    }
}

/// Like [`clear_mutated_regs`], but for computing the effective frame of a single
/// statement: a top-level assignment/compound-assignment writes its target only
/// AFTER the RHS (and LHS address) are evaluated, so the target still holds the
/// frame while those are inspected — `eax = rax[18]` must keep `rax`. Only NESTED
/// mutations (whose evaluation order relative to sibling subexpressions is
/// unspecified) are cleared. The top-level target's clobber for the FOLLOWING
/// statements is applied separately by `note_frame_ptr_reg`.
fn clear_intra_stmt_mutated_regs(regs: &mut HashSet<String>, stmt: &Expr) {
    match &stmt.kind {
        ExprKind::Assign { lhs, rhs } | ExprKind::CompoundAssign { lhs, rhs, .. } => {
            // Skip the top-level target itself; still clear nested mutations in the
            // LHS (e.g. `arr[++i] = ...`) and anywhere in the RHS.
            clear_mutated_regs(regs, lhs);
            clear_mutated_regs(regs, rhs);
        }
        _ => clear_mutated_regs(regs, stmt),
    }
}

/// Remove from `regs` the alias of every register that is written (assigned,
/// compound-assigned, or inc/dec'd) anywhere in `e`, recursing through the whole
/// expression tree so a mutation nested inside a call argument, binary operand,
/// or conditional is not missed.
fn clear_mutated_regs(regs: &mut HashSet<String>, e: &Expr) {
    use super::expression::UnaryOpKind;
    let clear_target = |regs: &mut HashSet<String>, t: &Expr| {
        if let ExprKind::Var(v) = &t.kind {
            regs.remove(&canon_reg(&v.name));
        }
    };
    match &e.kind {
        ExprKind::Assign { lhs, rhs } | ExprKind::CompoundAssign { lhs, rhs, .. } => {
            clear_target(regs, lhs);
            clear_mutated_regs(regs, lhs);
            clear_mutated_regs(regs, rhs);
        }
        ExprKind::UnaryOp { op, operand } => {
            if matches!(op, UnaryOpKind::Inc | UnaryOpKind::Dec) {
                clear_target(regs, operand);
            }
            clear_mutated_regs(regs, operand);
        }
        ExprKind::BinOp { left, right, .. } => {
            clear_mutated_regs(regs, left);
            clear_mutated_regs(regs, right);
        }
        ExprKind::Deref { addr, .. } => clear_mutated_regs(regs, addr),
        ExprKind::AddressOf(o)
        | ExprKind::Cast { expr: o, .. }
        | ExprKind::BitField { expr: o, .. } => clear_mutated_regs(regs, o),
        ExprKind::ArrayAccess { base, index, .. } => {
            clear_mutated_regs(regs, base);
            clear_mutated_regs(regs, index);
        }
        ExprKind::FieldAccess { base, .. } => clear_mutated_regs(regs, base),
        ExprKind::Call { target, args } => {
            match target {
                super::expression::CallTarget::Indirect(t)
                | super::expression::CallTarget::IndirectGot { expr: t, .. } => {
                    clear_mutated_regs(regs, t)
                }
                _ => {}
            }
            for a in args {
                clear_mutated_regs(regs, a);
            }
        }
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            clear_mutated_regs(regs, cond);
            clear_mutated_regs(regs, then_expr);
            clear_mutated_regs(regs, else_expr);
        }
        ExprKind::Phi(exprs) => {
            for x in exprs {
                clear_mutated_regs(regs, x);
            }
        }
        _ => {}
    }
}

/// Tracker of which scratch registers currently hold a frame-pointer copy, stepped
/// statement-by-statement over straight-line code. Every consumer of a block's
/// statements (field detection, state binding, the final rename) drives it
/// identically through [`Self::effective_frame`], so they all agree on which
/// register-aliased memory accesses are frame fields.
///
/// The tracker follows straight-line control flow: within a `Block`, and across a
/// run of fall-through sibling nodes (a `Block` into the next `Block`, or into an
/// `If`'s CONDITION — which runs before the branch splits). It is reset at any join
/// point (a `Label`, the only way a node is reached other than by fall-through,
/// since the structurer materializes every goto target as a `Label`) and at
/// anything that isn't straight-line (loops, switch, after an `If`), and it never
/// flows into a branch BODY. So a stale alias can never leak into code reachable by
/// another path.
///
/// Carrying the alias into an `If` condition is why `try_flatten_switch` takes a
/// separate condition-frame (register-aliased, for the guard chain) and body-frame
/// (plain, for emitting/rewriting the case bodies): the alias must drive dispatch
/// detection without rewriting register accesses inside case bodies, where the copy
/// may have been clobbered on the branch path.
#[derive(Default, Clone)]
struct FramePtrTracker {
    regs: HashSet<String>,
}

impl FramePtrTracker {
    /// The effective frame to use for `stmt` (the base frame plus the registers
    /// known to hold a frame copy *before* this statement), then advance the
    /// tracker past `stmt`. A statement that calls out first drops caller-saved
    /// register aliases (see the block rewrite loop for why this is conservative
    /// for the whole statement); the copy/clobber effects of the statement itself
    /// are applied after the effective frame is captured, matching evaluation
    /// order for the following statements.
    fn effective_frame(&mut self, stmt: &Expr, frame: &Frame) -> Frame {
        if expr_contains_call(stmt) {
            self.regs.retain(|reg| reg_survives_call(reg));
        }
        // A register mutated by a NESTED side effect can't be trusted for this
        // statement's own frame accesses: expression evaluation order within a
        // statement is not recoverable, so `foo(++rbx, rbx[18])` must not rename
        // `rbx[18]`. But a top-level assignment's own target is written only AFTER
        // its RHS is evaluated, so the RHS still sees the old (frame) value —
        // `eax = rax[18]` (a `movzx eax,[rax+off]` state reload) must keep the `rax`
        // alias while inspecting the RHS. So exclude nested mutations only, not the
        // top-level target (whose clobber `note_frame_ptr_reg` applies to the
        // following statements).
        let mut eff_regs = self.regs.clone();
        clear_intra_stmt_mutated_regs(&mut eff_regs, stmt);
        let eff = frame.with_frame_ptr_regs(&eff_regs);
        note_frame_ptr_reg(&mut self.regs, stmt, frame);
        eff
    }

    /// The effective frame for a terminator/condition expression WITHOUT advancing
    /// the tracker — used for an `If`'s condition, which executes on straight-line
    /// fall-through from the preceding block before the branch splits. Applies the
    /// same call-clobber and same-expression mutation exclusions as
    /// [`Self::effective_frame`].
    fn effective_frame_peek(&self, expr: &Expr, frame: &Frame) -> Frame {
        let mut eff_regs = self.regs.clone();
        if expr_contains_call(expr) {
            eff_regs.retain(|reg| reg_survives_call(reg));
        }
        clear_intra_stmt_mutated_regs(&mut eff_regs, expr);
        frame.with_frame_ptr_regs(&eff_regs)
    }
}

/// Canonical (widest) name of a register, so a write to a sub-register clears the
/// alias for the full register it overlaps: x86-64 sub-registers fold to their
/// 64-bit name, and AArch64 `w<N>` folds to `x<N>` (a 32-bit write zero-extends
/// into the whole register).
fn canon_reg(name: &str) -> String {
    if let Some((canon, _)) = super::abi::normalize_x86_64_register(name, 8) {
        return canon.to_string();
    }
    if let Some(num) = name.strip_prefix('w') {
        if !num.is_empty() && num.bytes().all(|b| b.is_ascii_digit()) {
            return format!("x{num}");
        }
    }
    name.to_string()
}

/// Whether a register's value is preserved across a function call, so a frame
/// pointer held in it survives the call. Callee-saved registers qualify — EXCEPT
/// the AArch64 link register (`x30`/`lr`), which a `bl` overwrites with the
/// return address even though it is otherwise callee-saved.
fn reg_survives_call(reg: &str) -> bool {
    super::abi::is_callee_saved_register(reg) && !matches!(reg, "x30" | "w30" | "lr")
}

/// Whether `e` evaluates to a frame-pointer copy: a known (flow-insensitive)
/// frame alias, or a register currently in the block-local `regs` set.
fn holds_frame_ptr(regs: &HashSet<String>, e: &Expr, frame: &Frame) -> bool {
    // Peel casts, but reject any that NARROWS below the pointer width: a value cast
    // through e.g. `(uint32_t)` truncates the pointer, so `rax = (uint32_t)local`
    // does not leave `rax` holding a usable frame pointer even though `local` is a
    // frame alias. (Widening / same-width casts are transparent.)
    let mut cur = e;
    while let ExprKind::Cast { expr, to_size, .. } = &cur.kind {
        if *to_size < frame.pointer_size {
            return false;
        }
        cur = expr;
    }
    // Also reject a NARROW read of a frame location — a sub-register read like
    // `eax` (lifted as `Var{name:"rax", size:4}`) or a sub-pointer-width memory
    // load holds only the low bits, so even though the location is a frame alias
    // its value is not a usable frame pointer (`rbx = (uint64_t)eax` after
    // `rax = frame`). An unsized/opaque form (the `arg0` base param) is full.
    if !frame_read_is_full_width(cur, frame.pointer_size) {
        return false;
    }
    if let Some(k) = alias_key(cur) {
        if frame.aliases.contains(&k) {
            return true;
        }
    }
    matches!(&cur.kind, ExprKind::Var(v) if regs.contains(&canon_reg(&v.name)))
}

/// Whether reading `e` yields the whole pointer (not a truncated low-bits slice):
/// a sized value form (`Var` / memory `Deref` / `ArrayAccess`) must be at least
/// `pointer_size` wide; an unsized form (e.g. the `arg0` base param, a
/// `FieldAccess`) carries no truncation signal and is treated as full-width.
fn frame_read_is_full_width(e: &Expr, pointer_size: u8) -> bool {
    match &e.kind {
        ExprKind::Var(v) => v.size == 0 || v.size >= pointer_size,
        ExprKind::Deref { size, .. } => *size == 0 || *size >= pointer_size,
        ExprKind::ArrayAccess { element_size, .. } => {
            *element_size == 0 || *element_size >= pointer_size as usize
        }
        _ => true,
    }
}

/// Whether `e` contains a function call anywhere in its subtree (used to detect
/// caller-saved-register clobbers).
fn expr_contains_call(e: &Expr) -> bool {
    match &e.kind {
        ExprKind::Call { .. } => true,
        ExprKind::BinOp { left, right, .. }
        | ExprKind::Assign { lhs: left, rhs: right }
        | ExprKind::CompoundAssign {
            lhs: left,
            rhs: right,
            ..
        } => expr_contains_call(left) || expr_contains_call(right),
        ExprKind::UnaryOp { operand, .. }
        | ExprKind::Deref { addr: operand, .. }
        | ExprKind::AddressOf(operand)
        | ExprKind::Cast { expr: operand, .. }
        | ExprKind::BitField { expr: operand, .. } => expr_contains_call(operand),
        ExprKind::ArrayAccess { base, index, .. } => {
            expr_contains_call(base) || expr_contains_call(index)
        }
        ExprKind::FieldAccess { base, .. } => expr_contains_call(base),
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            expr_contains_call(cond)
                || expr_contains_call(then_expr)
                || expr_contains_call(else_expr)
        }
        ExprKind::Phi(exprs) => exprs.iter().any(expr_contains_call),
        _ => false,
    }
}

/// A normalized key identifying an lvalue location (a register/arg, or a
/// memory location off one), so frame copies and re-reads can be matched.
fn alias_key(e: &Expr) -> Option<String> {
    match &e.kind {
        ExprKind::Unknown(s) => Some(format!("U:{s}")),
        // Canonicalize register names (`eax`->`rax`, `w19`->`x19`) so a full-width
        // copy recorded under its canonical name (see `with_frame_ptr_regs`, which
        // keys block-local reg aliases by `canon_reg`) matches a later access
        // spelled with the same or a narrower sub-register. Non-register vars
        // (stack/arg/temp) never collide with register names, so `canon_reg` is a
        // no-op for them; registers never enter the flow-insensitive alias set.
        ExprKind::Var(v) => {
            let name = if matches!(v.kind, VarKind::Register(_)) {
                canon_reg(&v.name)
            } else {
                v.name.clone()
            };
            Some(format!("V:{name}"))
        }
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

/// Whether `base` is a usable frame pointer: a frame alias read at FULL pointer
/// width. Routed through [`holds_frame_ptr`] (the block-local register aliases are
/// already folded into `frame.aliases`), so the cast-narrowing and sub-register
/// width checks apply here too — `eax[18]`/`(uint32_t)rax` after `rax = frame`
/// must NOT resolve as a frame field, since the base is a truncated pointer.
fn base_is_frame(base: &Expr, frame: &Frame) -> bool {
    holds_frame_ptr(&HashSet::new(), base, frame)
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
            if base_is_frame(base, frame) {
                if let ExprKind::IntLit(i) = &index.kind {
                    return Some(*i as i64 * *element_size as i64);
                }
            }
            None
        }
        ExprKind::FieldAccess { base, offset, .. } => {
            base_is_frame(base, frame).then_some(*offset as i64)
        }
        ExprKind::Deref { addr, .. } => match &addr.kind {
            ExprKind::BinOp {
                op: BinOpKind::Add,
                left,
                right,
            } => {
                if base_is_frame(left, frame) {
                    if let ExprKind::IntLit(off) = &right.kind {
                        return Some(*off as i64);
                    }
                }
                None
            }
            _ => base_is_frame(addr, frame).then_some(0),
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
    // Per offset: the set of equality constants it is compared against, and the
    // shallowest nesting depth at which it is compared.
    let mut stats: HashMap<i64, OffsetStat> = HashMap::new();
    scan_state_compares(
        body,
        frame,
        &mut HashMap::new(),
        &mut stats,
        0,
        &FramePtrTracker::default(),
    );
    // The resume dispatch is the actor/resume clone's OUTERMOST branching, so its
    // index field is compared at the shallowest depth; an unrelated frame field
    // (e.g. a user enum switched on in resumed code) is nested inside a resume
    // case body and therefore deeper. Prefer the shallowest field, breaking ties
    // by the larger number of distinct case constants.
    stats
        .into_iter()
        .filter(|(_, s)| s.values.len() >= 2)
        .min_by(|(_, a), (_, b)| {
            a.min_depth
                .cmp(&b.min_depth)
                .then_with(|| b.values.len().cmp(&a.values.len()))
        })
        .map(|(offset, _)| StateField { offset })
}

#[derive(Default)]
struct OffsetStat {
    values: HashSet<i128>,
    min_depth: usize,
}

/// Ordered walk maintaining `temp -> frame offset` bindings; records each
/// comparison's `(offset, const)` and the nesting depth against the binding live
/// at that point.
///
/// Advance `carry`/`temp_offset` over one straight-line statement (a `Block`'s
/// statement or a raw `Expr` node): a `tmp = <frame field>` load binds `tmp` to the
/// offset; any other write clears the binding.
fn scan_stmt_bindings(
    stmt: &Expr,
    frame: &Frame,
    carry: &mut FramePtrTracker,
    temp_offset: &mut HashMap<String, i64>,
) {
    let frame = &carry.effective_frame(stmt, frame);
    match &stmt.kind {
        ExprKind::Assign { lhs, rhs } => {
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
        // A compound assignment mutates the temp — clear its binding.
        ExprKind::CompoundAssign { lhs, .. } => {
            if let ExprKind::Var(v) = &lhs.kind {
                temp_offset.remove(&v.name);
            }
        }
        _ => {}
    }
}

/// Splice transparent `Sequence` wrappers inline so the alias carry flows across
/// them (constant propagation can emit `Sequence([...])` between a frame copy and
/// its dispatch); other nodes pass through unchanged.
fn flatten_transparent_seq<'a>(nodes: &'a [StructuredNode], out: &mut Vec<&'a StructuredNode>) {
    for n in nodes {
        match n {
            StructuredNode::Sequence(inner) => flatten_transparent_seq(inner, out),
            other => out.push(other),
        }
    }
}

fn scan_state_compares(
    nodes: &[StructuredNode],
    frame: &Frame,
    temp_offset: &mut HashMap<String, i64>,
    stats: &mut HashMap<i64, OffsetStat>,
    depth: usize,
    entry_carry: &FramePtrTracker,
) {
    // Frame-pointer register aliases carried from the preceding straight-line
    // sibling (see `FramePtrTracker`), seeded with those live on entry to this node
    // list; reset wherever fall-through is not guaranteed so a `temp = ret[18]` load
    // or `if (ret[18] == N)` compare through a register copied in an earlier
    // fall-through block is attributed to the right offset. This pass only COUNTS
    // candidate offsets (no code transform), so it may also flow the aliases into a
    // branch body's leading guard — an `else if (ret[18] == 1)` chain keeps `ret` as
    // the frame along the guard chain — without any soundness risk.
    let mut carry = entry_carry.clone();
    // Splice transparent `Sequence` wrappers inline so the carry flows across them.
    let mut flat: Vec<&StructuredNode> = Vec::with_capacity(nodes.len());
    flatten_transparent_seq(nodes, &mut flat);
    for node in flat {
        match node {
            StructuredNode::Block { statements, .. } => {
                for stmt in statements {
                    scan_stmt_bindings(stmt, frame, &mut carry, temp_offset);
                }
            }
            // A raw `Expr` node is a single straight-line statement — advance through
            // it (it may be the `ret = local` / `tmp = ret[18]` itself).
            StructuredNode::Expr(e) => {
                scan_stmt_bindings(e, frame, &mut carry, temp_offset);
            }
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                // The condition runs on fall-through from the preceding block, so it
                // may use the carried aliases. A branch keeps those aliases only if
                // it is a TRUE dispatch continuation: a single nested `If` whose guard
                // navigates the SAME frame offset, AND whose arm can still hold OTHER
                // state values. An `==` guard's true arm is a concrete case (state is
                // fixed there), `!=`'s false arm likewise; a range guard leaves both
                // arms open. So a case BODY — even one that is a single `If` on the
                // same field (`if (ret[18]==0){ if (ret[18]==1) }`) or a different
                // field (`if (ret[50]==0)`) — is never counted against the resume
                // field.
                let cond_frame = carry.effective_frame_peek(condition, frame);
                note_state_compare(condition, &cond_frame, temp_offset, stats, depth);
                let parent = compare_to_frame_offset(condition, &cond_frame, temp_offset);
                let parent_off = parent.map(|(o, _, _)| o);
                let then_open = parent.is_some_and(|(_, _, op)| op != BinOpKind::Eq);
                let else_open = parent.is_some_and(|(_, _, op)| op != BinOpKind::Ne);
                let branch_carry = carry.clone();
                carry = FramePtrTracker::default();
                let empty = FramePtrTracker::default();
                let seed = |b: &[StructuredNode], arm_open: bool| -> &FramePtrTracker {
                    if arm_open {
                        if let [StructuredNode::If { condition: inner, .. }] = b {
                            let inner_frame = branch_carry.effective_frame_peek(inner, frame);
                            let inner_off = compare_to_frame_offset(inner, &inner_frame, temp_offset)
                                .map(|(o, _, _)| o);
                            if parent_off.is_some() && inner_off == parent_off {
                                return &branch_carry;
                            }
                        }
                    }
                    &empty
                };
                // In a CLOSED arm (== true / != false) the state equals the matched
                // value, so a temp holding the parent offset is a known constant, not a
                // dispatch variable — drop those bindings so a dead nested `tmp == K`
                // there isn't counted as another value for the resume field (mirrors
                // the register-carry suppression above).
                let branch_temps = |arm_open: bool| -> HashMap<String, i64> {
                    let mut t = temp_offset.clone();
                    if !arm_open {
                        if let Some(off) = parent_off {
                            t.retain(|_, v| *v != off);
                        }
                    }
                    t
                };
                scan_state_compares(
                    then_body,
                    frame,
                    &mut branch_temps(then_open),
                    stats,
                    depth + 1,
                    seed(then_body, then_open),
                );
                if let Some(b) = else_body {
                    scan_state_compares(
                        b,
                        frame,
                        &mut branch_temps(else_open),
                        stats,
                        depth + 1,
                        seed(b, else_open),
                    );
                }
            }
            StructuredNode::While { condition, body, .. }
            | StructuredNode::DoWhile { condition, body, .. } => {
                carry = FramePtrTracker::default();
                note_state_compare(condition, frame, temp_offset, stats, depth);
                scan_state_compares(
                    body,
                    frame,
                    &mut temp_offset.clone(),
                    stats,
                    depth + 1,
                    &FramePtrTracker::default(),
                );
            }
            StructuredNode::For { body, .. } | StructuredNode::Loop { body, .. } => {
                carry = FramePtrTracker::default();
                scan_state_compares(
                    body,
                    frame,
                    &mut temp_offset.clone(),
                    stats,
                    depth + 1,
                    &FramePtrTracker::default(),
                );
            }
            StructuredNode::Switch { cases, default, .. } => {
                carry = FramePtrTracker::default();
                for (_, b) in cases {
                    scan_state_compares(
                        b,
                        frame,
                        &mut temp_offset.clone(),
                        stats,
                        depth + 1,
                        &FramePtrTracker::default(),
                    );
                }
                if let Some(b) = default {
                    scan_state_compares(
                        b,
                        frame,
                        &mut temp_offset.clone(),
                        stats,
                        depth + 1,
                        &FramePtrTracker::default(),
                    );
                }
            }
            // `Sequence` nodes were spliced inline by `flatten_transparent_seq`.
            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                carry = FramePtrTracker::default();
                scan_state_compares(
                    try_body,
                    frame,
                    &mut temp_offset.clone(),
                    stats,
                    depth + 1,
                    &FramePtrTracker::default(),
                );
                for handler in catch_handlers {
                    scan_state_compares(
                        &handler.body,
                        frame,
                        &mut temp_offset.clone(),
                        stats,
                        depth + 1,
                        &FramePtrTracker::default(),
                    );
                }
            }
            _ => {
                // Labels/goto/break/continue/return break straight-line flow.
                carry = FramePtrTracker::default();
            }
        }
    }
}

fn note_state_compare(
    cond: &Expr,
    frame: &Frame,
    temp_offset: &HashMap<String, i64>,
    stats: &mut HashMap<i64, OffsetStat>,
    depth: usize,
) {
    if let Some((off, value, op)) = compare_to_frame_offset(cond, frame, temp_offset) {
        // Only equality comparisons name an actual case; `<`/`<=` etc. are
        // binary-search navigation, so a frame field range-checked but never
        // switched on must not be mistaken for the resume index.
        if matches!(op, BinOpKind::Eq | BinOpKind::Ne) && (0..256).contains(&value) {
            let entry = stats.entry(off).or_insert_with(|| OffsetStat {
                values: HashSet::new(),
                min_depth: depth,
            });
            entry.values.insert(value);
            entry.min_depth = entry.min_depth.min(depth);
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

    /// The repeat period of the bit-slice constraints (e.g. an even/odd parity
    /// slice repeats every 2). A value satisfying the domain past some point
    /// recurs within one period, so a "beyond" representative can always be found
    /// within `period` steps. Capped to bound the search.
    fn period(&self) -> i128 {
        let mut period: i128 = 1;
        for c in &self.constraints {
            if let DomainConstraint::Slice { start, width, .. } = c {
                period = period.saturating_mul(1i128 << (*start as u32 + *width as u32));
                if period >= 4096 {
                    return 4096;
                }
            }
        }
        period.max(1)
    }
}

fn apply_cmp(op: BinOpKind, a: i128, b: i128) -> bool {
    // Unsigned guards must compare as unsigned: a `cmp ..., -1; jbe` lowers to
    // `ULe` against a sign-extended `IntLit(-1)`, and signed `a <= -1` would send
    // every non-negative resume index down the wrong branch. Reinterpret both
    // operands' bits as unsigned for the U* comparisons.
    match op {
        BinOpKind::Eq => a == b,
        BinOpKind::Ne => a != b,
        BinOpKind::Lt => a < b,
        BinOpKind::Le => a <= b,
        BinOpKind::Gt => a > b,
        BinOpKind::Ge => a >= b,
        BinOpKind::ULt => (a as u128) < (b as u128),
        BinOpKind::ULe => (a as u128) <= (b as u128),
        BinOpKind::UGt => (a as u128) > (b as u128),
        BinOpKind::UGe => (a as u128) >= (b as u128),
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
    // Reload blocks (`tmp = frame->state`) are skipped for dispatch navigation,
    // but a later case/default body may reuse that temp for ordinary code. Keep
    // the skipped reloads and re-prepend any whose temp is referenced by the
    // outcome we ultimately emit, so the switch body never drops their assignment.
    let mut reloads: Vec<StructuredNode> = Vec::new();
    for (i, node) in nodes.iter().enumerate() {
        match node {
            StructuredNode::Block { statements, .. } => {
                if is_state_reload_block(statements, frame, state, &env) {
                    env.note_block(statements, frame, state);
                    reloads.push(node.clone());
                    continue;
                }
                // A real (or trap) block: v runs it and the rest of this sibling
                // list as its outcome.
                return prepend_used_reloads(reloads, nodes[i..].to_vec());
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
                    None => return prepend_used_reloads(reloads, nodes[i..].to_vec()),
                };
                // v executes the taken branch; if that branch falls through (no
                // trap/return), it then continues with the siblings after this If.
                let mut outcome = branch
                    .map(|b| eval_outcome(b, v, frame, state, &env))
                    .unwrap_or_default();
                if !ends_noreturn(&outcome) {
                    // The taken branch may have reassigned a temp that held the
                    // resume index; the fall-through siblings must not keep treating
                    // it as the state value. Invalidate every temp the branch
                    // assigned before evaluating the continuation.
                    let mut sibling_env = env.clone();
                    if let Some(b) = branch {
                        for name in assigned_vars(b) {
                            sibling_env.state_temps.remove(&name);
                            sibling_env.slice_temps.remove(&name);
                        }
                    }
                    outcome.extend(eval_outcome(&nodes[i + 1..], v, frame, state, &sibling_env));
                }
                return prepend_used_reloads(reloads, outcome);
            }
            _ => return prepend_used_reloads(reloads, nodes[i..].to_vec()),
        }
    }
    Vec::new()
}

/// Re-prepend the skipped reload blocks whose assigned temp is actually
/// referenced by `outcome`, so a case/default body that reuses the reload value
/// keeps its defining assignment (the reload is otherwise dropped, since the
/// whole if-tree is replaced by the synthesized switch). Reloads whose temp is
/// unused stay dropped — they were pure dispatch scaffolding.
fn prepend_used_reloads(
    reloads: Vec<StructuredNode>,
    outcome: Vec<StructuredNode>,
) -> Vec<StructuredNode> {
    if reloads.is_empty() {
        return outcome;
    }
    let used: Vec<StructuredNode> = reloads
        .into_iter()
        .filter(|r| reload_temps(r).iter().any(|k| outcome_uses_key(&outcome, k)))
        .collect();
    if used.is_empty() {
        return outcome;
    }
    let mut combined = used;
    combined.extend(outcome);
    combined
}

/// The lvalue keys assigned by a reload block's statements.
fn reload_temps(node: &StructuredNode) -> Vec<String> {
    let mut keys = Vec::new();
    if let StructuredNode::Block { statements, .. } = node {
        for s in statements {
            if let ExprKind::Assign { lhs, .. } = &s.kind {
                if let Some(k) = alias_key(lhs) {
                    keys.push(k);
                }
            }
        }
    }
    keys
}

/// Whether any expression in `outcome` references the lvalue `key`.
fn outcome_uses_key(outcome: &[StructuredNode], key: &str) -> bool {
    let mut found = false;
    visit_exprs(outcome, &mut |e| {
        if alias_key(e).as_deref() == Some(key) {
            found = true;
        }
    });
    found
}

/// Whether the outcome's final statement halts control flow (trap / unreachable
/// / return / break / continue), so following siblings don't run.
fn ends_noreturn(nodes: &[StructuredNode]) -> bool {
    match nodes.last() {
        Some(
            StructuredNode::Return(_)
            | StructuredNode::Break
            | StructuredNode::Continue
            | StructuredNode::Goto(_),
        ) => true,
        Some(StructuredNode::Block { statements, .. }) => statements.iter().any(is_noreturn_call),
        Some(StructuredNode::Expr(e)) => is_noreturn_call(e),
        // An `if` whose every branch halts (including the implicit empty else,
        // which falls through) is itself terminating only when both arms exist and
        // both halt.
        Some(StructuredNode::If {
            then_body,
            else_body: Some(else_body),
            ..
        }) => ends_noreturn(then_body) && ends_noreturn(else_body),
        Some(StructuredNode::Sequence(nodes)) => ends_noreturn(nodes),
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

/// Every state constant compared in a dispatch tree (case labels and bound
/// constants) — the boundaries between distinct outcome ranges, used to sample
/// large ranges without enumerating them.
fn collect_state_constants(
    nodes: &[StructuredNode],
    frame: &Frame,
    state: &StateField,
    env: &BindingEnv,
) -> Vec<i128> {
    let mut out = Vec::new();
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
                    out.push(k);
                }
                out.extend(collect_state_constants(then_body, frame, state, &env));
                if let Some(b) = else_body {
                    out.extend(collect_state_constants(b, frame, state, &env));
                }
            }
            StructuredNode::Sequence(nodes) => {
                out.extend(collect_state_constants(nodes, frame, state, &env))
            }
            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                out.extend(collect_state_constants(try_body, frame, state, &env));
                for handler in catch_handlers {
                    out.extend(collect_state_constants(&handler.body, frame, state, &env));
                }
            }
            _ => {}
        }
    }
    out
}

/// The state-value period induced by any bit-slice (parity) condition anywhere
/// in the tree: outcomes can repeat every `period` steps, so the tail-uniformity
/// check must sample a full period. 1 when no slice condition appears.
fn tree_slice_period(
    nodes: &[StructuredNode],
    frame: &Frame,
    state: &StateField,
    env: &BindingEnv,
) -> i128 {
    let mut env = env.clone();
    let mut period: i128 = 1;
    for node in nodes {
        match node {
            StructuredNode::Block { statements, .. } => env.note_block(statements, frame, state),
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                period = period.max(cond_slice_period(condition, frame, state, &env));
                period = period.max(tree_slice_period(then_body, frame, state, &env));
                if let Some(b) = else_body {
                    period = period.max(tree_slice_period(b, frame, state, &env));
                }
            }
            StructuredNode::While { condition, body, .. }
            | StructuredNode::DoWhile { condition, body, .. } => {
                period = period.max(cond_slice_period(condition, frame, state, &env));
                period = period.max(tree_slice_period(body, frame, state, &env));
            }
            StructuredNode::For { body, .. } | StructuredNode::Loop { body, .. } => {
                period = period.max(tree_slice_period(body, frame, state, &env));
            }
            StructuredNode::Switch { cases, default, .. } => {
                for (_, b) in cases {
                    period = period.max(tree_slice_period(b, frame, state, &env));
                }
                if let Some(b) = default {
                    period = period.max(tree_slice_period(b, frame, state, &env));
                }
            }
            StructuredNode::Sequence(nodes) => {
                period = period.max(tree_slice_period(nodes, frame, state, &env))
            }
            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                period = period.max(tree_slice_period(try_body, frame, state, &env));
                for handler in catch_handlers {
                    period = period.max(tree_slice_period(&handler.body, frame, state, &env));
                }
            }
            _ => {}
        }
        period = period.min(4096);
    }
    period.min(4096)
}

/// The period contributed by a single condition: 2^(start+width) for a bit-slice
/// constraint (parity etc.), else 1.
fn cond_slice_period(cond: &Expr, frame: &Frame, state: &StateField, env: &BindingEnv) -> i128 {
    let mut p: i128 = 1;
    if let Some((a, b)) = cond_constraints(cond, frame, state, env) {
        for c in [a, b].into_iter().flatten() {
            if let DomainConstraint::Slice { start, width, .. } = c {
                p = p.max(1i128 << (start as u32 + width as u32));
            }
        }
    }
    p
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
        self.note_block_seeded(statements, frame, state, &FramePtrTracker::default());
    }

    /// Like [`Self::note_block`], but the register tracker starts from `seed` (the
    /// aliases live at block entry from the preceding straight-line sibling) and its
    /// end state is returned, so callers can carry it into the following sibling.
    fn note_block_seeded(
        &mut self,
        statements: &[Expr],
        frame: &Frame,
        state: &StateField,
        seed: &FramePtrTracker,
    ) -> FramePtrTracker {
        // Drive the same frame-pointer register tracker the rewrite loop uses, so a
        // state reload through a just-copied frame register (`rax = local;
        // tmp = rax[18];`) is recognized as a state temp.
        let mut tracker = seed.clone();
        for stmt in statements {
            let frame = &tracker.effective_frame(stmt, frame);
            match &stmt.kind {
                ExprKind::Assign { lhs, rhs } => {
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
                // A compound assignment (`tmp += 1`, etc.) mutates the temp, so it
                // no longer holds the resume index / slice — drop the binding.
                ExprKind::CompoundAssign { lhs, .. } => {
                    if let ExprKind::Var(v) = &lhs.kind {
                        self.state_temps.remove(&v.name);
                        self.slice_temps.remove(&v.name);
                    }
                }
                _ => {}
            }
        }
        tracker
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
    rewrite_nodes_seeded(nodes, frame, state, env, domain, &FramePtrTracker::default()).0
}

/// [`rewrite_nodes`] whose frame-pointer register carry starts from `entry_carry`
/// (the aliases live on entry to this node list — non-empty only for a transparent
/// `Sequence` wrapping fall-through code from a preceding block). Returns the
/// rewritten nodes and the carry left at the END of the list, so a caller can thread
/// it across a transparent wrapper.
fn rewrite_nodes_seeded(
    nodes: Vec<StructuredNode>,
    frame: &Frame,
    state: &StateField,
    env: &mut BindingEnv,
    domain: &Domain,
    entry_carry: &FramePtrTracker,
) -> (Vec<StructuredNode>, FramePtrTracker) {
    let mut out = Vec::with_capacity(nodes.len());
    // Frame-pointer register aliases live at the start of the current sibling,
    // carried from the preceding straight-line node (see `FramePtrTracker`). Reset
    // wherever fall-through is not guaranteed.
    let mut carry = entry_carry.clone();
    for node in nodes {
        match node {
            StructuredNode::Block {
                id,
                statements,
                address_range,
            } => {
                // Seed both the binding pass and the rename tracker with the aliases
                // carried in from the preceding sibling, so a store/reload through a
                // register copied in an earlier fall-through block is recognized too.
                env.note_block_seeded(&statements, frame, state, &carry);
                let mut tracker = carry.clone();
                let mut renamed = Vec::with_capacity(statements.len());
                for s in statements {
                    let eff = tracker.effective_frame(&s, frame);
                    renamed.push(rename_state_in_expr(s, &eff, state));
                }
                // The block's end aliases carry to the next fall-through sibling.
                carry = tracker;
                out.push(StructuredNode::Block {
                    id,
                    statements: renamed,
                    address_range,
                });
            }
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                // The condition runs on straight-line fall-through from the preceding
                // block (before the branch splits), so a dispatch guard made through
                // a carried frame-pointer register — `ret = local; if (ret[18] == 0)`
                // — is valid here. Canonicalize the guard SPINE to the named field
                // using those aliases, then run every downstream step on the PLAIN
                // frame: the register alias never reaches case-body analysis, so a
                // register access inside a body (possibly a clobbered copy on the
                // branch path) is never mis-renamed. After the `if` the branches
                // merge, so no register state carries past it.
                let had_aliases = !carry.regs.is_empty();
                let cond_frame = carry.effective_frame_peek(&condition, frame);
                carry = FramePtrTracker::default();
                let (condition, then_body, else_body) = if had_aliases {
                    match rewrite_dispatch_guards(
                        StructuredNode::If {
                            condition,
                            then_body,
                            else_body,
                        },
                        &cond_frame,
                        state,
                        env,
                    ) {
                        StructuredNode::If {
                            condition,
                            then_body,
                            else_body,
                        } => (condition, then_body, else_body),
                        _ => unreachable!("rewrite_dispatch_guards preserves the If"),
                    }
                } else {
                    (condition, then_body, else_body)
                };

                // A temp the branches reassign no longer holds the state after the
                // `if`, so invalidate those bindings for the following siblings.
                let mut reassigned = assigned_vars(&then_body);
                if let Some(b) = &else_body {
                    reassigned.extend(assigned_vars(b));
                }
                let kill = |env: &mut BindingEnv| {
                    for n in &reassigned {
                        env.state_temps.remove(n);
                        env.slice_temps.remove(n);
                    }
                };

                if let Some(switch_nodes) =
                    try_flatten_switch(&condition, &then_body, &else_body, frame, state, env, domain)
                {
                    out.extend(switch_nodes);
                    kill(env);
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
                kill(env);
            }
            StructuredNode::Sequence(seq) => {
                // A `Sequence` is a transparent inline run of fall-through nodes, so
                // the carried aliases flow into it AND its end state threads back to
                // the following sibling — a dispatch wrapped as
                // `Sequence([if (ret[18] == 0) ...])`, or an empty `Sequence([])`
                // between the frame copy and the dispatch, no longer breaks recovery.
                // Env is cloned like `rewrite_structural`, and temps the sequence
                // reassigns are killed for the following siblings, matching the old
                // path.
                let reassigned = assigned_vars(&seq);
                let (inner, end) =
                    rewrite_nodes_seeded(seq, frame, state, &mut env.clone(), domain, &carry);
                carry = end;
                out.push(StructuredNode::Sequence(inner));
                for n in &reassigned {
                    env.state_temps.remove(n);
                    env.slice_temps.remove(n);
                }
            }
            StructuredNode::Expr(e) => {
                // A raw `Expr` node is a single straight-line statement — advance the
                // carry through it (it may be `ret = local` / a state store) and bind
                // any `tmp = <state>` into env, mirroring a one-statement block.
                env.note_block_seeded(std::slice::from_ref(&e), frame, state, &carry);
                let eff = carry.effective_frame(&e, frame);
                out.push(StructuredNode::Expr(rename_state_in_expr(e, &eff, state)));
            }
            other => {
                // Loops/switch/try-catch/labels/goto break straight-line flow (a
                // `Label` is a join point reachable from elsewhere), so reset the
                // carried register aliases — nothing survives to the next sibling.
                carry = FramePtrTracker::default();
                let reassigned = assigned_vars(std::slice::from_ref(&other));
                out.push(rewrite_structural(other, frame, state, env, domain));
                for n in &reassigned {
                    env.state_temps.remove(n);
                    env.slice_temps.remove(n);
                }
            }
        }
    }
    (out, carry)
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
            init: init.map(|e| rename_state_in_expr(e, frame, state)),
            condition: rename_state_in_expr(condition, frame, state),
            update: update.map(|e| rename_state_in_expr(e, frame, state)),
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
        StructuredNode::Expr(e) => StructuredNode::Expr(rename_state_in_expr(e, frame, state)),
        StructuredNode::Return(Some(e)) => {
            StructuredNode::Return(Some(rename_state_in_expr(e, frame, state)))
        }
        other => other,
    }
}

/// Canonicalize the comparisons on a dispatch if-tree's guard SPINE from a carried
/// frame-pointer register to the named field: `if (ret[18] == K)` (after
/// `ret = local`) becomes `if (frame->__resume_index == K)`. `cond_frame` carries
/// the register alias, valid at every guard on the spine (the comparisons don't
/// clobber the register). Only pure-navigation guards are rewritten — recursion
/// stops at any branch that isn't itself a single state-compare `If`, so a leaf
/// case BODY (a `Block`, where the register may be clobbered) is never touched.
/// After this the whole tree references the frame directly and the flattener runs
/// on the plain frame, so no register alias reaches body analysis.
fn rewrite_dispatch_guards(
    node: StructuredNode,
    cond_frame: &Frame,
    state: &StateField,
    env: &BindingEnv,
) -> StructuredNode {
    let StructuredNode::If {
        condition,
        then_body,
        else_body,
    } = node
    else {
        return node;
    };
    // Only a state comparison is a guard we recurse through — but recognized against
    // the LIVE env, so a mixed tree whose root guard is a state TEMP
    // (`tmp = ret[18]; if (tmp <= 1) { if (ret[18] == 0) ... }`) still descends to
    // canonicalize the nested register-aliased guards. rename_state_in_expr only
    // rewrites a direct register-aliased frame access, so a temp-based condition is
    // left untouched for the env-based paths. `as_state_compare` matches only the
    // resume field, so recursion never enters an unrelated-offset sub-dispatch.
    let Some((parent_op, _)) = as_state_compare(&condition, cond_frame, state, env) else {
        return StructuredNode::If {
            condition,
            then_body,
            else_body,
        };
    };
    let recur = |b: Vec<StructuredNode>, arm_open: bool| -> Vec<StructuredNode> {
        // Recurse only into an arm that can still hold OTHER state values (== -> else,
        // != -> then, ranges -> both), and only when it is exactly one `If`. An `==`
        // guard's true arm is a concrete case BODY — descending would rewrite its
        // `ret[..]` accesses even though the register may be clobbered there, so it is
        // left untouched (matches `scan_state_compares`).
        if arm_open && b.len() == 1 && matches!(b[0], StructuredNode::If { .. }) {
            b.into_iter()
                .map(|n| rewrite_dispatch_guards(n, cond_frame, state, env))
                .collect()
        } else {
            b
        }
    };
    StructuredNode::If {
        condition: rename_state_in_expr(condition, cond_frame, state),
        then_body: recur(then_body, parent_op != BinOpKind::Eq),
        else_body: else_body.map(|b| recur(b, parent_op != BinOpKind::Ne)),
    }
}

/// Attempt to flatten an `If` rooted state dispatch into a `Switch`. Returns
/// `None` (leaving the if-tree untouched) unless ≥2 distinct equality cases are
/// confidently recovered. The unmatched-state behavior (default and any explicit
/// trap cases) is computed by evaluating each reachable state value through the
/// original tree, so trapping and fall-through states are emitted exactly.
///
/// The tree is expected to reference the frame directly (any dispatch guard made
/// through a carried frame-pointer register is canonicalized to the named field by
/// `rewrite_dispatch_guards` before this runs), so a single plain `frame` is used
/// throughout — no register alias reaches case-body analysis.
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

    // 1. Discover the candidate equality case labels (the constants compared with
    //    `==` anywhere in the tree). Their *bodies* are NOT taken from this raw
    //    recursion — an equality test nested under an incompatible range guard
    //    (e.g. `if (state==0)` inside the `state > 0` else-branch) would otherwise
    //    contribute a body for a state that can never reach it. Bodies are instead
    //    computed per value by `eval_outcome`, which honours the path constraints.
    let mut label_cases: Vec<(i128, Vec<StructuredNode>)> = Vec::new();
    collect_cases(condition, then_body, else_body, frame, state, env, &mut label_cases)?;

    let mut labels = HashSet::new();
    for (label, _) in &label_cases {
        labels.insert(*label);
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
    // Resume indices are small. Cap the dense enumeration at the largest *bound*
    // constant only up to ENUM_CAP — a bound may be huge (e.g. an unsigned
    // `state <= 0xffffffff` guard) and enumerating to it would hang. An equality
    // label larger than the cap isn't a resume index — decline.
    const ENUM_CAP: i128 = 4096;
    let max_label = *labels.iter().max().unwrap();
    // Resume indices are small non-negatives. A negative sentinel label (e.g.
    // `state == -1`) isn't enumerated by the `0..=dense_limit` case loop, so it
    // would silently fall into the default — decline rather than change behavior.
    // A label above the cap isn't a resume index either.
    if max_label > ENUM_CAP || labels.iter().any(|&l| l < 0) {
        return None;
    }
    let max_const = max_state_constant(&tree, frame, state, env);
    // The reachable state values are periodic when a bit-slice (parity) condition
    // appears anywhere in the tree — the outcome can repeat every `period` steps.
    let period = domain.period().max(tree_slice_period(&tree, frame, state, env));

    // The "tail" is every reachable state above the densely-enumerated range. It
    // becomes the single switch default, so it must be UNIFORM: a tail split by a
    // range bound (e.g. `state <= N`) or a bit-slice/parity condition can't be one
    // default and can't be enumerated as explicit cases (it's unbounded), so we
    // decline. Sample one full slice period past the largest constant (catches
    // parity splits) plus every range-bound boundary above the dense range.
    let dense_limit = max_const.min(ENUM_CAP);
    let mut tail_reps: Vec<i128> = ((max_const + 1)..=(max_const + period)).collect();
    for c in collect_state_constants(&tree, frame, state, env) {
        tail_reps.push(c);
        tail_reps.push(c + 1);
    }
    tail_reps.retain(|v| *v > dense_limit && domain.allows(*v));
    tail_reps.sort_unstable();
    tail_reps.dedup();
    let beyond_outcome = match tail_reps.first() {
        Some(v) => eval_outcome(&tree, *v, frame, state, env),
        None => Vec::new(),
    };
    for v in &tail_reps {
        if !bodies_equivalent(&eval_outcome(&tree, *v, frame, state, env), &beyond_outcome) {
            return None; // non-uniform tail — not representable as a single default
        }
    }

    // Build every case body by evaluating the tree per value (path-constraint
    // aware) over the dense range. A candidate equality label always gets an
    // explicit case; any other in-range value whose outcome differs from the
    // default becomes an explicit case too (e.g. a single invalid index traps
    // while the rest fall through).
    let mut cases: Vec<(i128, Vec<StructuredNode>)> = Vec::new();
    for v in 0..=dense_limit {
        if !domain.allows(v) {
            continue;
        }
        let outcome = eval_outcome(&tree, v, frame, state, env);
        if labels.contains(&v) || !bodies_equivalent(&outcome, &beyond_outcome) {
            cases.push((v, outcome));
        }
    }
    // A candidate label that survived to here only via an unreachable branch (its
    // path-aware outcome matched nothing distinct and the domain excluded it) can
    // drop the effective case count below two — decline rather than emit a
    // degenerate switch.
    if cases.iter().filter(|(v, _)| labels.contains(v)).count() < 2 {
        return None;
    }

    // 3. Safety: a free `break` in any emitted body would be recaptured by the
    //    synthesized switch.
    if cases.iter().any(|(_, b)| contains_free_break(b)) || contains_free_break(&beyond_outcome) {
        return None;
    }

    // 4. Build the switch: every case (real + explicit minority-outcome) with the
    //    beyond outcome as the default (empty outcome => no default, fall through).
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
            // (sibling code that follows the nested dispatch). The suffix is only
            // appended to a case that actually falls through — a case ending in a
            // return/goto/trap never reaches it.
            for (_, body) in &mut sub {
                if !rest.is_empty() && !ends_noreturn(body) {
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
///
/// NOTE: a leading frame-pointer COPY (`rax = local`) is intentionally NOT accepted
/// here. Unlike a state reload into a scratch temp (dead after the dispatch), a
/// register holding a frame-pointer copy can be live anywhere — a later indirect
/// call target, or a sibling AFTER the flattened switch — and the reload-peeling
/// machinery (`prepend_used_reloads`) only re-prepends a dropped reload when the
/// case body itself uses it, so peeling a frame copy could drop a still-live
/// register. The block-local register-alias tracking still recovers this reload
/// shape at the top level (via `note_block`/`rewrite_nodes`); extending the
/// bounded-branch prefix peeler to it soundly needs post-region liveness analysis
/// and is a dedicated follow-up.
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
                if is_scratch_dest(lhs) && local.is_state(rhs, frame, state) =>
            {
                local.note_block(std::slice::from_ref(stmt), frame, state);
            }
            _ => return false,
        }
    }
    true
}

/// Whether an lvalue is a scratch destination — a register or a compiler temp.
/// A reload into one of these is pure dispatch plumbing, droppable once the
/// dispatch becomes a switch. A stack/global/arg destination might be read
/// elsewhere (including after the switch), so a `local = frame->state` spill to
/// one of those must NOT be treated as droppable plumbing.
fn is_scratch_dest(lhs: &Expr) -> bool {
    matches!(
        &lhs.kind,
        ExprKind::Var(v) if matches!(v.kind, VarKind::Register(_) | VarKind::Temp(_))
    )
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
        ExprKind::Deref { addr, size } => ExprKind::Deref {
            addr: Box::new(rename_state_in_expr(*addr, frame, state)),
            size,
        },
        ExprKind::AddressOf(inner) => {
            ExprKind::AddressOf(Box::new(rename_state_in_expr(*inner, frame, state)))
        }
        ExprKind::ArrayAccess {
            base,
            index,
            element_size,
        } => ExprKind::ArrayAccess {
            base: Box::new(rename_state_in_expr(*base, frame, state)),
            index: Box::new(rename_state_in_expr(*index, frame, state)),
            element_size,
        },
        ExprKind::FieldAccess {
            base,
            field_name,
            offset,
        } => ExprKind::FieldAccess {
            base: Box::new(rename_state_in_expr(*base, frame, state)),
            field_name,
            offset,
        },
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => ExprKind::Conditional {
            cond: Box::new(rename_state_in_expr(*cond, frame, state)),
            then_expr: Box::new(rename_state_in_expr(*then_expr, frame, state)),
            else_expr: Box::new(rename_state_in_expr(*else_expr, frame, state)),
        },
        ExprKind::BitField { expr, start, width } => ExprKind::BitField {
            expr: Box::new(rename_state_in_expr(*expr, frame, state)),
            start,
            width,
        },
        ExprKind::Phi(exprs) => ExprKind::Phi(
            exprs
                .into_iter()
                .map(|e| rename_state_in_expr(e, frame, state))
                .collect(),
        ),
        other => other,
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

/// Every variable/temp name assigned anywhere within `nodes` — the lhs of a
/// plain OR compound assignment. Used to invalidate state/slice/frame-pointer
/// bindings that a conditional branch may have overwritten (including via
/// `tmp += 1` / `ret += 8`) before continuing with the following siblings.
fn assigned_vars(nodes: &[StructuredNode]) -> HashSet<String> {
    let mut names = HashSet::new();
    visit_exprs(nodes, &mut |e| {
        let lhs = match &e.kind {
            ExprKind::Assign { lhs, .. } | ExprKind::CompoundAssign { lhs, .. } => lhs,
            _ => return,
        };
        if let ExprKind::Var(v) = &lhs.kind {
            names.insert(v.name.clone());
        }
    });
    names
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
            ExprKind::Call { target, args } => {
                // Visit the indirect-call target too, so a value used ONLY as
                // `(*reg)()` counts as a use (e.g. a frame copy feeding an indirect
                // call must not be dropped as dead reload plumbing).
                match target {
                    super::expression::CallTarget::Indirect(t)
                    | super::expression::CallTarget::IndirectGot { expr: t, .. } => walk_expr(t, f),
                    _ => {}
                }
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
            StructuredNode::For {
                init,
                condition,
                update,
                body,
                ..
            } => {
                if let Some(e) = init {
                    walk_expr(e, f);
                }
                walk_expr(condition, f);
                if let Some(e) = update {
                    walk_expr(e, f);
                }
                visit_exprs(body, f);
            }
            StructuredNode::Loop { body, .. } => visit_exprs(body, f),
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
    fn huge_bound_constant_does_not_hang() {
        // if (state <= 0xffffffff) { if (state==0) A else if (state==1) B else trap }
        // The dense enumeration must be capped at the small case labels, not the
        // 4-billion bound; the huge trap range can't be explicit cases, so the
        // pass declines (and returns promptly).
        let body = vec![iff(
            cmp(BinOpKind::ULe, state_access(), 0xffff_ffff),
            vec![iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![Expr::unknown("body_a")])],
                vec![iff(
                    cmp(BinOpKind::Eq, state_access(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![block(vec![Expr::call(
                        crate::decompiler::expression::CallTarget::Named("__builtin_trap".to_string()),
                        vec![],
                    )])],
                )],
            )],
            vec![],
        )];
        let out = recover_resume_dispatch(body);
        // The outer 4-billion bound declines fast (sampled, not enumerated); the
        // inner small dispatch flattens to `switch { case 0; case 1; default trap }`
        // inside the `if (state <= 0xffffffff)`. The test completing proves no hang.
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
    }

    #[test]
    fn multi_bit_slice_guard_finds_beyond_for_default() {
        // if (BITS(state,0,3) == 7) { if (state==7) A else if (state==15) B
        //                             else trap }
        // Reachable states are ≡ 7 (mod 8): 7, 15, 23, ... The next reachable
        // value past the cases (23) is 8 steps beyond 15, so the default-search
        // must span a full slice period to keep the trap default.
        let bits = |start: u8, width: u8| Expr {
            kind: ExprKind::BitField {
                expr: Box::new(state_access()),
                start,
                width,
            },
        };
        let body = vec![iff(
            cmp(BinOpKind::Eq, bits(0, 3), 7),
            vec![iff(
                cmp(BinOpKind::Eq, state_access(), 7),
                vec![block(vec![Expr::unknown("body_a")])],
                vec![iff(
                    cmp(BinOpKind::Eq, state_access(), 15),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![block(vec![Expr::call(
                        crate::decompiler::expression::CallTarget::Named("__builtin_trap".to_string()),
                        vec![],
                    )])],
                )],
            )],
            vec![],
        )];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![7, 15]));
        let default_dump = find_default_dump(&out).expect("trap default for state 23+");
        assert!(default_dump.contains("__builtin_trap"));
    }

    #[test]
    fn returning_case_does_not_get_unreachable_suffix() {
        // if (state <= 1) { if (state == 0) return; else if (state == 1) body ;
        //                   suffix }
        // case 0 returns before the suffix, so the suffix must not be appended to
        // it; case 1 falls through and does get it.
        let body = vec![iff(
            cmp(BinOpKind::Le, state_access(), 1),
            vec![
                iff(
                    cmp(BinOpKind::Eq, state_access(), 0),
                    vec![StructuredNode::Return(None)],
                    vec![iff(
                        cmp(BinOpKind::Eq, state_access(), 1),
                        vec![block(vec![Expr::unknown("body_b")])],
                        vec![],
                    )],
                ),
                block(vec![Expr::unknown("suffix")]),
            ],
            vec![],
        )];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        // Locate case 0's body and verify it has no suffix after the return.
        let case0 = case_body(&out, 0).expect("case 0");
        assert!(!format!("{case0:?}").contains("suffix"));
        let case1 = case_body(&out, 1).expect("case 1");
        assert!(format!("{case1:?}").contains("suffix"));
    }

    #[test]
    fn exhaustive_terminating_if_does_not_append_suffix() {
        // if (state <= 1) {
        //     if (state == 0) { if (extern) return; else return; }   // exhaustive
        //     suffix;                                                 // unreachable for 0
        // } else if (state == 2) { body_c }
        // For state 0 the inner if halts on every branch, so the sibling `suffix`
        // must not be appended to case 0.
        let body = vec![iff(
            cmp(BinOpKind::Le, state_access(), 1),
            vec![
                iff(
                    cmp(BinOpKind::Eq, state_access(), 0),
                    vec![iff(
                        Expr::unknown("extern_cond"),
                        vec![StructuredNode::Return(None)],
                        vec![StructuredNode::Return(None)],
                    )],
                    vec![],
                ),
                block(vec![Expr::unknown("suffix")]),
            ],
            vec![iff(
                cmp(BinOpKind::Eq, state_access(), 2),
                vec![block(vec![Expr::unknown("body_c")])],
                vec![],
            )],
        )];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1, 2]));
        let case0 = case_body(&out, 0).expect("case 0");
        assert!(
            !format!("{case0:?}").contains("suffix"),
            "case0 should not include the unreachable suffix: {case0:?}"
        );
        // The fall-through state 1 legitimately reaches the suffix.
        let case1 = case_body(&out, 1).expect("case 1");
        assert!(format!("{case1:?}").contains("suffix"), "case1={case1:?}");
    }

    #[test]
    fn negative_sentinel_label_declines() {
        // if (state == -1) cleanup else if (state == 0) A else if (state == 1) B
        // The negative sentinel can't be a small resume index and wouldn't be
        // enumerated as a case — decline rather than route -1 into the default.
        let body = vec![iff(
            cmp(BinOpKind::Eq, state_access(), -1),
            vec![block(vec![Expr::unknown("cleanup")])],
            vec![iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![Expr::unknown("body_a")])],
                vec![iff(
                    cmp(BinOpKind::Eq, state_access(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![],
                )],
            )],
        )];
        let out = recover_resume_dispatch(body);
        // The outer `state == -1` sentinel declines (negative), so it stays as an
        // `if` and its cleanup body is preserved; the inner non-negative dispatch
        // still flattens. The -1 state is never silently routed into a default.
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let dump = format!("{out:?}");
        assert!(dump.contains("cleanup"), "negative sentinel body dropped: {dump}");
    }

    #[test]
    fn branch_reassigned_temp_not_treated_as_state_in_fallthrough() {
        // tmp = state;
        // if (state == 0) A
        // else {
        //     if (state == 1) { tmp = 7; }       // case 1 reassigns tmp, falls through
        //     if (tmp == 5) shared_b else shared_c   // compares the *reused* tmp
        // }
        // For state 1, tmp is 7 by the time the second if runs, so it must NOT be
        // routed as `state == 5`; case 1 keeps the whole tmp-compare (both arms).
        let tmp = || Expr::var(Variable::reg("rcx", 8));
        let body = vec![
            block(vec![Expr::assign(tmp(), state_access())]),
            iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![Expr::unknown("body_a")])],
                vec![
                    iff(
                        cmp(BinOpKind::Eq, state_access(), 1),
                        vec![block(vec![Expr::assign(tmp(), Expr::int(7))])],
                        vec![],
                    ),
                    iff(
                        cmp(BinOpKind::Eq, tmp(), 5),
                        vec![block(vec![Expr::unknown("shared_b")])],
                        vec![block(vec![Expr::unknown("shared_c")])],
                    ),
                ],
            ),
        ];
        let out = recover_resume_dispatch(body);
        let case1 = case_body(&out, 1).expect("case 1");
        let c1 = format!("{case1:?}");
        assert!(c1.contains("shared_b"), "fall-through tmp-compare mis-routed: {c1}");
        assert!(c1.contains("shared_c"), "{c1}");
    }

    #[test]
    fn compound_assign_to_state_temp_clears_binding() {
        // tmp = state; tmp += 1;
        // if (tmp == 1) A else if (tmp == 2) B
        // After `tmp += 1` the temp no longer holds the resume index, so the
        // comparisons must NOT be flattened into a switch on __resume_index.
        let tmp = || Expr::var(Variable::reg("rcx", 8));
        let compound = Expr {
            kind: ExprKind::CompoundAssign {
                op: BinOpKind::Add,
                lhs: Box::new(tmp()),
                rhs: Box::new(Expr::int(1)),
            },
        };
        let body = vec![
            block(vec![Expr::assign(tmp(), state_access()), compound]),
            iff(
                cmp(BinOpKind::Eq, tmp(), 1),
                vec![block(vec![Expr::unknown("body_a")])],
                vec![iff(
                    cmp(BinOpKind::Eq, tmp(), 2),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), None);
    }

    #[test]
    fn expr_and_return_nodes_in_case_bodies_are_renamed() {
        // case 0 is a standalone Expr node then a Return node, both referencing the
        // state field; both must be renamed to frame->__resume_index (no raw
        // arg0[18] ArrayAccess left behind).
        let body = vec![iff(
            cmp(BinOpKind::Eq, state_access(), 0),
            vec![
                StructuredNode::Expr(Expr::assign(Expr::var(Variable::reg("rax", 8)), state_access())),
                StructuredNode::Return(Some(state_access())),
            ],
            vec![iff(
                cmp(BinOpKind::Eq, state_access(), 1),
                vec![block(vec![Expr::unknown("body_b")])],
                vec![],
            )],
        )];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let case0 = case_body(&out, 0).expect("case 0");
        let c0 = format!("{case0:?}");
        assert!(c0.contains("__resume_index"), "{c0}");
        assert!(!c0.contains("ArrayAccess"), "raw state access in case0: {c0}");
    }

    #[test]
    fn stack_local_state_spill_is_not_dropped() {
        // if (state == 0) { local_8 = state;   // spill to a named stack local
        //                   body_a }           // (separate real block)
        // else if (state == 1) { body_b }
        // The spill targets a stack local (potentially read after the switch), so
        // it is NOT droppable plumbing — case 0 must keep the assignment.
        let local = || Expr::var(Variable::stack(-8, 8));
        let body = vec![iff(
            cmp(BinOpKind::Eq, state_access(), 0),
            vec![
                block(vec![Expr::assign(local(), state_access())]),
                block(vec![Expr::unknown("body_a")]),
            ],
            vec![iff(
                cmp(BinOpKind::Eq, state_access(), 1),
                vec![block(vec![Expr::unknown("body_b")])],
                vec![],
            )],
        )];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let case0 = case_body(&out, 0).expect("case 0");
        let c0 = format!("{case0:?}");
        assert!(
            c0.contains("__resume_index"),
            "stack-local spill dropped from case0: {c0}"
        );
        assert!(c0.contains("body_a"), "{c0}");
    }

    #[test]
    fn parity_split_tail_is_not_collapsed_to_a_single_default() {
        // if (state == 0) A
        // else if (state == 1) B
        // else if (BITS(state,0,1) == 0) trap   // even tail traps, odd falls through
        // The tail above the cases is split by parity, so it can't be one switch
        // default — the pass declines rather than trap odd states too.
        let body = vec![iff(
            cmp(BinOpKind::Eq, state_access(), 0),
            vec![block(vec![Expr::unknown("body_a")])],
            vec![iff(
                cmp(BinOpKind::Eq, state_access(), 1),
                vec![block(vec![Expr::unknown("body_b")])],
                vec![iff(
                    cmp(BinOpKind::Eq, bits0(state_access()), 0),
                    vec![block(vec![Expr::call(
                        crate::decompiler::expression::CallTarget::Named("__builtin_trap".to_string()),
                        vec![],
                    )])],
                    vec![],
                )],
            )],
        )];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), None);
    }

    #[test]
    fn unrelated_deeper_frame_field_is_not_picked_as_state() {
        // `arg0[10]` (offset 20) is a user enum compared against MORE constants
        // than the resume index, but only inside a resume case body (deeper). The
        // shallow resume index `arg0[18]` (compared at top level) must win.
        let enum_field = || Expr::array_access(frame(), Expr::int(10), 2);
        let body = vec![iff(
            cmp(BinOpKind::Eq, state_access(), 0),
            // case 0 body contains the user enum if-chain (3 constants, depth >= 1)
            vec![iff(
                cmp(BinOpKind::Eq, enum_field(), 5),
                vec![block(vec![Expr::unknown("enum_x")])],
                vec![iff(
                    cmp(BinOpKind::Eq, enum_field(), 6),
                    vec![block(vec![Expr::unknown("enum_y")])],
                    vec![iff(
                        cmp(BinOpKind::Eq, enum_field(), 7),
                        vec![block(vec![Expr::unknown("enum_z")])],
                        vec![],
                    )],
                )],
            )],
            vec![iff(
                cmp(BinOpKind::Eq, state_access(), 1),
                vec![block(vec![Expr::unknown("body_b")])],
                vec![],
            )],
        )];
        let out = recover_resume_dispatch(body);
        // The recovered switch is on the resume index (labels 0/1), not the enum.
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
    }

    #[test]
    fn reload_reused_by_case_body_is_preserved() {
        // if (state <= 3) {
        //     tmp = state;                       // branch-local reload
        //     if (tmp == 0) { rdx = tmp; A }     // case 0 reuses tmp
        //     else if (tmp == 1) { B }           // case 1 doesn't
        // }
        // case 0 must keep the reload assignment (renamed); case 1, which never
        // references tmp, must not carry it.
        let tmp = || Expr::var(Variable::reg("rcx", 8));
        let body = vec![iff(
            cmp(BinOpKind::Le, state_access(), 3),
            vec![
                block(vec![Expr::assign(tmp(), state_access())]),
                iff(
                    cmp(BinOpKind::Eq, tmp(), 0),
                    vec![block(vec![
                        Expr::assign(Expr::var(Variable::reg("rdx", 8)), tmp()),
                        Expr::unknown("body_a"),
                    ])],
                    vec![iff(
                        cmp(BinOpKind::Eq, tmp(), 1),
                        vec![block(vec![Expr::unknown("body_b")])],
                        vec![],
                    )],
                ),
            ],
            vec![],
        )];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let case0 = case_body(&out, 0).expect("case 0");
        let c0 = format!("{case0:?}");
        assert!(c0.contains("__resume_index"), "reload dropped from case0: {c0}");
        assert!(c0.contains("body_a"), "{c0}");
        let case1 = case_body(&out, 1).expect("case 1");
        let c1 = format!("{case1:?}");
        assert!(
            !c1.contains("__resume_index"),
            "unused reload carried into case1: {c1}"
        );
    }

    #[test]
    fn for_loop_header_state_reference_is_renamed() {
        // A dispatch that flattens plus a `for` whose condition references the
        // state field: once the switch is recovered the for-header must be renamed
        // to frame->__resume_index too (no leftover raw arg0[18] ArrayAccess).
        let body = vec![
            iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![Expr::unknown("body_a")])],
                vec![iff(
                    cmp(BinOpKind::Eq, state_access(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![],
                )],
            ),
            StructuredNode::For {
                init: None,
                condition: cmp(BinOpKind::Lt, state_access(), 10),
                update: None,
                body: vec![block(vec![Expr::unknown("loop_body")])],
                header: None,
                exit_block: None,
            },
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let dump = format!("{out:?}");
        assert!(dump.contains("__resume_index"), "{dump}");
        assert!(
            !dump.contains("ArrayAccess"),
            "for-header left a raw state access: {dump}"
        );
    }

    #[test]
    fn for_loop_header_reassignment_kills_stale_state_temp() {
        // tmp = state; for (...; ...; tmp = 0) { ... }
        // if (tmp == 0) A else if (tmp == 1) B
        // The for-update reassigns tmp, so after the loop it is no longer the
        // resume index and the following if must NOT be flattened to a switch.
        let tmp = || Expr::var(Variable::reg("rcx", 8));
        let body = vec![
            block(vec![Expr::assign(tmp(), state_access())]),
            StructuredNode::For {
                init: None,
                condition: Expr::unknown("i < n"),
                update: Some(Expr::assign(tmp(), Expr::int(0))),
                body: vec![block(vec![Expr::unknown("loop_body")])],
                header: None,
                exit_block: None,
            },
            iff(
                cmp(BinOpKind::Eq, tmp(), 0),
                vec![block(vec![Expr::unknown("body_a")])],
                vec![iff(
                    cmp(BinOpKind::Eq, tmp(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), None);
    }

    #[test]
    fn unsigned_guard_against_sign_extended_immediate() {
        // `cmp state, -1; jbe` lowers to `ULe` against a sign-extended -1, which
        // is always true for unsigned (every non-negative index <= 0xffff...). The
        // inner equality dispatch must still resolve correctly: case 0 -> A,
        // case 1 -> B (not swallowed by a signed `state <= -1` misread).
        let body = vec![iff(
            cmp(BinOpKind::ULe, state_access(), -1),
            vec![iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![Expr::unknown("body_a")])],
                vec![iff(
                    cmp(BinOpKind::Eq, state_access(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![],
                )],
            )],
            vec![],
        )];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let case0 = case_body(&out, 0).expect("case 0");
        assert!(format!("{case0:?}").contains("body_a"), "case0={case0:?}");
        let case1 = case_body(&out, 1).expect("case 1");
        assert!(format!("{case1:?}").contains("body_b"), "case1={case1:?}");
    }

    #[test]
    fn nested_state_wrapper_in_case_body_is_renamed() {
        // A case body that references the state field wrapped in an expression the
        // renamer must recurse through (here `&state`) must not leave a raw
        // `arg0[18]` once the switch renames the dispatch to __resume_index.
        let addr_of_state = Expr {
            kind: ExprKind::AddressOf(Box::new(state_access())),
        };
        let body = vec![iff(
            cmp(BinOpKind::Eq, state_access(), 0),
            vec![block(vec![Expr::assign(
                Expr::var(Variable::reg("rax", 8)),
                addr_of_state,
            )])],
            vec![iff(
                cmp(BinOpKind::Eq, state_access(), 1),
                vec![block(vec![Expr::unknown("body_b")])],
                vec![],
            )],
        )];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let dump = format!("{out:?}");
        assert!(dump.contains("__resume_index"), "{dump}");
        // The raw state access is `arg0[18]` (an ArrayAccess); after renaming the
        // AddressOf body it must become a FieldAccess, leaving no ArrayAccess. The
        // `arg0` base of `frame->__resume_index` itself is expected.
        assert!(!dump.contains("ArrayAccess"), "leftover raw state access: {dump}");
    }

    #[test]
    fn equality_under_incompatible_range_guard_uses_reachable_body() {
        // if (state <= 0) { if (state == 0) A }
        // else            { if (state == 0) B; else if (state == 1) C }
        // The else-branch's `state == 0` is unreachable (state > 0 there), so
        // case 0 must be A (the reachable body), never B.
        let body = vec![iff(
            cmp(BinOpKind::Le, state_access(), 0),
            vec![iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![Expr::unknown("body_a")])],
                vec![],
            )],
            vec![iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![Expr::unknown("body_b")])],
                vec![iff(
                    cmp(BinOpKind::Eq, state_access(), 1),
                    vec![block(vec![Expr::unknown("body_c")])],
                    vec![],
                )],
            )],
        )];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let case0 = case_body(&out, 0).expect("case 0");
        assert!(format!("{case0:?}").contains("body_a"), "case0={case0:?}");
        assert!(!format!("{case0:?}").contains("body_b"), "case0={case0:?}");
        let case1 = case_body(&out, 1).expect("case 1");
        assert!(format!("{case1:?}").contains("body_c"), "case1={case1:?}");
    }

    fn case_body(body: &[StructuredNode], label: i128) -> Option<Vec<StructuredNode>> {
        for n in body {
            match n {
                StructuredNode::Switch { cases, .. } => {
                    for (vals, b) in cases {
                        if vals.contains(&label) {
                            return Some(b.clone());
                        }
                    }
                }
                StructuredNode::If { then_body, else_body, .. } => {
                    if let Some(b) = case_body(then_body, label) {
                        return Some(b);
                    }
                    if let Some(b) = else_body.as_ref().and_then(|e| case_body(e, label)) {
                        return Some(b);
                    }
                }
                _ => {}
            }
        }
        None
    }

    #[test]
    fn goto_terminated_outcome_does_not_append_suffix() {
        // if (state == 9) X else { if (state==0)A else if (state==1)B else goto L
        //                          ; suffix }
        // An unmatched state hits `goto L`, which jumps away — the trailing
        // `suffix` must NOT be appended after the goto in the default outcome.
        use hexray_core::BasicBlockId;
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
                        vec![StructuredNode::Goto(BasicBlockId::new(7))],
                    )],
                ),
                block(vec![Expr::unknown("suffix")]),
            ],
        )];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1, 9]));
        let default_dump = find_default_dump(&out).expect("goto default");
        assert!(!default_dump.contains("suffix"));
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
    fn stale_temp_reassigned_in_branch_is_not_a_dispatch() {
        // tmp = state;
        // if (flag == 0) { tmp = 99; }     // tmp no longer holds the state
        // if (tmp == 0) A else if (tmp == 1) B   // must NOT become a switch
        let tmp = || Expr::var(Variable::reg("rax", 4));
        let flag = || Expr::var(Variable::reg("rbx", 4));
        let body = vec![
            block(vec![Expr::assign(tmp(), state_access())]),
            iff(
                cmp(BinOpKind::Eq, flag(), 0),
                vec![block(vec![Expr::assign(tmp(), Expr::int(99))])],
                vec![],
            ),
            iff(
                cmp(BinOpKind::Eq, tmp(), 0),
                vec![block(vec![Expr::unknown("body_a")])],
                vec![iff(
                    cmp(BinOpKind::Eq, tmp(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), None);
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
    fn truncated_register_base_is_not_a_frame_field() {
        // local = arg0; rax = local; tmp = eax[18]; if (tmp==0/1) ...
        // `eax` is the low 32 bits of the frame-holding rax; `eax[18]` reads through
        // a truncated pointer, so frame_offset must NOT accept it as the resume
        // field and the dispatch must not flatten.
        let local = || Expr::var(Variable::stack(-8, 8));
        let rax = || Expr::var(Variable::reg("rax", 8));
        let eax = || Expr::var(Variable::reg("eax", 4));
        let tmp = || Expr::var(Variable::reg("edx", 4));
        let body = vec![
            block(vec![
                Expr::assign(local(), frame()),
                Expr::assign(rax(), local()),
                Expr::assign(tmp(), Expr::array_access(eax(), Expr::int(18), 2)),
            ]),
            iff(
                cmp(BinOpKind::Eq, tmp(), 0),
                vec![block(vec![Expr::int(1)])],
                vec![iff(
                    cmp(BinOpKind::Eq, tmp(), 1),
                    vec![block(vec![Expr::int(2)])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_ne!(switch_labels(&out), Some(vec![0, 1]));
    }

    #[test]
    fn flattens_dispatch_with_same_register_reload() {
        // rax = local;            (rax holds the frame)
        // eax = rax[18];          (state reload writing BACK into rax's low half —
        //                          `movzx eax,[rax+off]`; RHS reads old rax = frame)
        // if (eax == 0) A else if (eax == 1) B
        // The RHS load must still see rax as the frame even though the assignment's
        // target (canonical rax) is clobbered afterwards, so eax binds as a state
        // temp and the dispatch flattens.
        let local = || Expr::var(Variable::stack(-8, 8));
        let rax = || Expr::var(Variable::reg("rax", 8));
        let eax = || Expr::var(Variable::reg("eax", 4));
        let body = vec![
            block(vec![
                Expr::assign(rax(), local()),
                Expr::assign(eax(), Expr::array_access(rax(), Expr::int(18), 2)),
            ]),
            iff(
                cmp(BinOpKind::Eq, eax(), 0),
                vec![block(vec![Expr::int(1)])],
                vec![iff(
                    cmp(BinOpKind::Eq, eax(), 1),
                    vec![block(vec![Expr::int(2)])],
                    vec![],
                )],
            ),
        ];
        // Establish `local = arg0` so `rax = local` is a frame copy.
        let mut full = vec![block(vec![Expr::assign(local(), frame())])];
        full.extend(body);
        let out = recover_resume_dispatch(full);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
    }

    #[test]
    fn flattens_cross_sibling_inline_compare_through_register_alias() {
        // local = arg0;              (block A)
        // ret = local;               (block B: ret is a frame copy)
        // if (ret[18] == 0) A else if (ret[18] == 1) B
        // The resume index is compared INLINE in the following sibling `if`, through
        // the register copied in block B. The alias carries across the fall-through
        // into the condition, so the dispatch flattens.
        let local = || Expr::var(Variable::stack(-8, 8));
        let ret = || Expr::var(Variable::reg("rax", 8));
        let ret_state = || Expr::array_access(ret(), Expr::int(18), 2);
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            block(vec![Expr::assign(ret(), local())]),
            iff(
                cmp(BinOpKind::Eq, ret_state(), 0),
                vec![block(vec![Expr::int(1)])],
                vec![iff(
                    cmp(BinOpKind::Eq, ret_state(), 1),
                    vec![block(vec![Expr::int(2)])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
    }

    #[test]
    fn cross_sibling_alias_does_not_rename_case_body_access() {
        // local = arg0; ret = local;
        // if (ret[18] == 0) { ret[18] = 5; } else if (ret[18] == 1) B
        // The guard `ret[18]` flattens via the carried alias, but the case body's
        // `ret[18] = 5` must NOT be renamed: on the branch path the copy in `ret`
        // may have been clobbered, so bodies are rewritten with the plain frame.
        let local = || Expr::var(Variable::stack(-8, 8));
        let ret = || Expr::var(Variable::reg("rax", 8));
        let ret_state = || Expr::array_access(ret(), Expr::int(18), 2);
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            block(vec![Expr::assign(ret(), local())]),
            iff(
                cmp(BinOpKind::Eq, ret_state(), 0),
                vec![block(vec![Expr::assign(ret_state(), Expr::int(5))])],
                vec![iff(
                    cmp(BinOpKind::Eq, ret_state(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let case0 = case_body(&out, 0).expect("case 0");
        let c0 = format!("{case0:?}");
        assert!(
            c0.contains("ArrayAccess") && !c0.contains("__resume_index"),
            "case-body register access was wrongly renamed: {c0}"
        );
    }

    #[test]
    fn cross_sibling_case_body_field_does_not_outrank_resume_field() {
        // local = arg0; ret = local;
        // if (ret[18] == 0) { if (ret[50]==0) A else if (ret[50]==1) B else C }
        // else if (ret[18] == 1) D
        // The case-0 body compares a DIFFERENT frame field (offset 50*2) more times
        // than the real resume field (offset 18*2). The carried alias must not be
        // counted through the case body, so the shallow resume field still wins and
        // the outer dispatch flattens on offset 36 (index 18), not 100 (index 50).
        let local = || Expr::var(Variable::stack(-8, 8));
        let ret = || Expr::var(Variable::reg("rax", 8));
        let idx = |n| Expr::array_access(ret(), Expr::int(n), 2);
        let inner = iff(
            cmp(BinOpKind::Eq, idx(50), 0),
            vec![block(vec![Expr::unknown("a")])],
            vec![iff(
                cmp(BinOpKind::Eq, idx(50), 1),
                vec![block(vec![Expr::unknown("b")])],
                vec![block(vec![Expr::unknown("c")])],
            )],
        );
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            block(vec![Expr::assign(ret(), local())]),
            iff(
                cmp(BinOpKind::Eq, idx(18), 0),
                vec![inner],
                vec![iff(
                    cmp(BinOpKind::Eq, idx(18), 1),
                    vec![block(vec![Expr::unknown("d")])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        // The recovered switch is on the resume field (index 18 = offset 36), with
        // the two outer cases — not on the inner branch-body field.
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
    }

    #[test]
    fn eq_case_body_temp_nested_compare_is_not_counted() {
        // local = arg0; ret = local; tmp = ret[18];
        // if (tmp == 5) { if (tmp == 6) A else B }        [dead nested temp compare]
        // else { if (local[50]==0) X else if (==1) Y else if (==2) Z }
        // `tmp` is bound to offset 36 from the register-aliased reload. In the `==`
        // true arm the state is fixed at 5, so the dead `tmp == 6` must NOT be counted
        // (the temp binding is scoped out of the closed arm), otherwise offset 36 gets
        // two shallow values and outranks the genuine offset-50 dispatch in the else.
        let local = || Expr::var(Variable::stack(-8, 8));
        let ret = || Expr::var(Variable::reg("rax", 8));
        let tmp = || Expr::var(Variable::reg("edx", 4));
        let lidx = |n| Expr::array_access(local(), Expr::int(n), 2);
        let dead = iff(
            cmp(BinOpKind::Eq, tmp(), 6),
            vec![block(vec![Expr::unknown("a")])],
            vec![block(vec![Expr::unknown("b")])],
        );
        let real = iff(
            cmp(BinOpKind::Eq, lidx(50), 0),
            vec![block(vec![Expr::unknown("x")])],
            vec![iff(
                cmp(BinOpKind::Eq, lidx(50), 1),
                vec![block(vec![Expr::unknown("y")])],
                vec![iff(
                    cmp(BinOpKind::Eq, lidx(50), 2),
                    vec![block(vec![Expr::unknown("z")])],
                    vec![],
                )],
            )],
        );
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            block(vec![Expr::assign(ret(), local())]),
            block(vec![Expr::assign(tmp(), Expr::array_access(ret(), Expr::int(18), 2))]),
            iff(cmp(BinOpKind::Eq, tmp(), 5), vec![dead], vec![real]),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1, 2]));
    }

    #[test]
    fn eq_case_body_same_field_nested_if_is_not_counted() {
        // local = arg0; ret = local;
        // if (ret[18] == 5) { if (ret[18] == 6) A else B }   [a dead nested compare]
        // else { if (local[50]==0) X else if (local[50]==1) Y else if (local[50]==2) Z }
        // The `==` true arm is a concrete case (state fixed to 5 there), so its nested
        // register-aliased `ret[18] == 6` must NOT be counted — otherwise offset 18
        // gets two shallow values and outranks the genuine offset-50 dispatch in the
        // else (accessed directly off the stack frame alias, so found without the
        // register carry). The real dispatch must still be recovered on offset 50.
        let local = || Expr::var(Variable::stack(-8, 8));
        let ret = || Expr::var(Variable::reg("rax", 8));
        let ridx = |n| Expr::array_access(ret(), Expr::int(n), 2);
        let lidx = |n| Expr::array_access(local(), Expr::int(n), 2);
        let dead = iff(
            cmp(BinOpKind::Eq, ridx(18), 6),
            vec![block(vec![Expr::unknown("a")])],
            vec![block(vec![Expr::unknown("b")])],
        );
        let real = iff(
            cmp(BinOpKind::Eq, lidx(50), 0),
            vec![block(vec![Expr::unknown("x")])],
            vec![iff(
                cmp(BinOpKind::Eq, lidx(50), 1),
                vec![block(vec![Expr::unknown("y")])],
                vec![iff(
                    cmp(BinOpKind::Eq, lidx(50), 2),
                    vec![block(vec![Expr::unknown("z")])],
                    vec![],
                )],
            )],
        );
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            block(vec![Expr::assign(ret(), local())]),
            iff(cmp(BinOpKind::Eq, ridx(18), 5), vec![dead], vec![real]),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1, 2]));
    }

    #[test]
    fn single_if_body_on_other_field_does_not_win_field_selection() {
        // local = arg0; ret = local;
        // if (ret[18] <= 1) { if (ret[18]==0) A else if (ret[18]==1) B }
        // else              { if (ret[50]==0) X else if (ret[50]==1) Y else if (ret[50]==2) Z }
        // The else default body is a single `If` on a DIFFERENT field (offset 100)
        // with MORE distinct constants than the resume field (offset 36), at the same
        // depth. The alias must not carry into it, so the resume field still wins and
        // the dispatch flattens on offset 36 (index 18).
        let local = || Expr::var(Variable::stack(-8, 8));
        let ret = || Expr::var(Variable::reg("rax", 8));
        let idx = |n| Expr::array_access(ret(), Expr::int(n), 2);
        let resume = iff(
            cmp(BinOpKind::Eq, idx(18), 0),
            vec![block(vec![Expr::unknown("a")])],
            vec![iff(
                cmp(BinOpKind::Eq, idx(18), 1),
                vec![block(vec![Expr::unknown("b")])],
                vec![],
            )],
        );
        let other = iff(
            cmp(BinOpKind::Eq, idx(50), 0),
            vec![block(vec![Expr::unknown("x")])],
            vec![iff(
                cmp(BinOpKind::Eq, idx(50), 1),
                vec![block(vec![Expr::unknown("y")])],
                vec![iff(
                    cmp(BinOpKind::Eq, idx(50), 2),
                    vec![block(vec![Expr::unknown("z")])],
                    vec![],
                )],
            )],
        );
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            block(vec![Expr::assign(ret(), local())]),
            iff(cmp(BinOpKind::Le, idx(18), 1), vec![resume], vec![other]),
        ];
        let out = recover_resume_dispatch(body);
        // Recovered on the resume field (index 18), not the deeper other-field body.
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
    }

    #[test]
    fn flattens_mixed_temp_root_register_nested_dispatch() {
        // local = arg0; ret = local; tmp = ret[18];
        // if (tmp <= 1) { if (ret[18]==0) A else if (ret[18]==1) B }
        // The ROOT guard is a state TEMP (bound from the register-aliased reload);
        // the nested guards use the register alias directly. Guard canonicalization
        // must recognize the temp root (via the live env) and still descend to
        // rewrite the nested `ret[18]` guards, so the mixed tree flattens.
        let local = || Expr::var(Variable::stack(-8, 8));
        let ret = || Expr::var(Variable::reg("rax", 8));
        let tmp = || Expr::var(Variable::reg("edx", 4));
        let ret_state = || Expr::array_access(ret(), Expr::int(18), 2);
        let inner = iff(
            cmp(BinOpKind::Eq, ret_state(), 0),
            vec![block(vec![Expr::unknown("a")])],
            vec![iff(
                cmp(BinOpKind::Eq, ret_state(), 1),
                vec![block(vec![Expr::unknown("b")])],
                vec![],
            )],
        );
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            block(vec![Expr::assign(ret(), local())]),
            block(vec![Expr::assign(tmp(), ret_state())]),
            iff(cmp(BinOpKind::Le, tmp(), 1), vec![inner], vec![]),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
    }

    #[test]
    fn flattens_cross_sibling_with_sequence_wrapped_continuation() {
        // local = arg0; ret = local;
        // if (ret[18]==0) A else Sequence([ if (ret[18]==1) B ])
        // The `else if` continuation is wrapped in a transparent Sequence; spine
        // normalization must splice it so both values are recovered.
        let local = || Expr::var(Variable::stack(-8, 8));
        let ret = || Expr::var(Variable::reg("rax", 8));
        let ret_state = || Expr::array_access(ret(), Expr::int(18), 2);
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            block(vec![Expr::assign(ret(), local())]),
            iff(
                cmp(BinOpKind::Eq, ret_state(), 0),
                vec![block(vec![Expr::int(1)])],
                vec![StructuredNode::Sequence(vec![iff(
                    cmp(BinOpKind::Eq, ret_state(), 1),
                    vec![block(vec![Expr::int(2)])],
                    vec![],
                )])],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
    }

    #[test]
    fn empty_sequence_barrier_does_not_break_cross_sibling_recovery() {
        // local = arg0; ret = local; Sequence([]); if (ret[18]==0) A else if (==1) B
        // An empty transparent Sequence between the frame copy and the dispatch must
        // not reset the carried alias (const-prop can emit one).
        let local = || Expr::var(Variable::stack(-8, 8));
        let ret = || Expr::var(Variable::reg("rax", 8));
        let ret_state = || Expr::array_access(ret(), Expr::int(18), 2);
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            block(vec![Expr::assign(ret(), local())]),
            StructuredNode::Sequence(vec![]),
            iff(
                cmp(BinOpKind::Eq, ret_state(), 0),
                vec![block(vec![Expr::int(1)])],
                vec![iff(
                    cmp(BinOpKind::Eq, ret_state(), 1),
                    vec![block(vec![Expr::int(2)])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
    }

    #[test]
    fn raw_expr_node_establishes_frame_ptr_alias() {
        // local = arg0; Expr(ret = local); if (ret[18]==0) A else if (==1) B
        // The frame copy is a raw `Expr` node (not a Block); it must advance the
        // carry as straight-line so the following register-aliased dispatch flattens.
        let local = || Expr::var(Variable::stack(-8, 8));
        let ret = || Expr::var(Variable::reg("rax", 8));
        let ret_state = || Expr::array_access(ret(), Expr::int(18), 2);
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            StructuredNode::Expr(Expr::assign(ret(), local())),
            iff(
                cmp(BinOpKind::Eq, ret_state(), 0),
                vec![block(vec![Expr::int(1)])],
                vec![iff(
                    cmp(BinOpKind::Eq, ret_state(), 1),
                    vec![block(vec![Expr::int(2)])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
    }

    #[test]
    fn flattens_cross_sibling_dispatch_wrapped_in_sequence() {
        // local = arg0; ret = local;
        // Sequence([ if (ret[18]==0) A else if (ret[18]==1) B ])
        // A transparent Sequence wrapper must not stop the carried alias, so the
        // wrapped dispatch is still found and flattened.
        let local = || Expr::var(Variable::stack(-8, 8));
        let ret = || Expr::var(Variable::reg("rax", 8));
        let ret_state = || Expr::array_access(ret(), Expr::int(18), 2);
        let dispatch = iff(
            cmp(BinOpKind::Eq, ret_state(), 0),
            vec![block(vec![Expr::int(1)])],
            vec![iff(
                cmp(BinOpKind::Eq, ret_state(), 1),
                vec![block(vec![Expr::int(2)])],
                vec![],
            )],
        );
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            block(vec![Expr::assign(ret(), local())]),
            StructuredNode::Sequence(vec![dispatch]),
        ];
        let out = recover_resume_dispatch(body);
        assert!(
            body_has_resume_switch(&out),
            "sequence-wrapped cross-sibling dispatch was not flattened: {out:?}"
        );
    }

    #[test]
    fn eq_case_body_single_if_on_register_is_not_rewritten() {
        // local = arg0; ret = local;
        // if (ret[18] == 0) { if (ret[18] == 6) A else B } else if (ret[18] == 1) C
        // case 0's body is itself a single `If` on the same register. The guard
        // canonicalization must NOT descend into it (the `==` true arm is a concrete
        // case), so the body's `ret[18] == 6` stays a raw access, not dispatch logic.
        let local = || Expr::var(Variable::stack(-8, 8));
        let ret = || Expr::var(Variable::reg("rax", 8));
        let ret_state = |k| Expr::array_access(ret(), Expr::int(k), 2);
        let case0 = iff(
            cmp(BinOpKind::Eq, ret_state(6), 0),
            vec![block(vec![Expr::unknown("a")])],
            vec![block(vec![Expr::unknown("b")])],
        );
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            block(vec![Expr::assign(ret(), local())]),
            iff(
                cmp(BinOpKind::Eq, ret_state(18), 0),
                vec![case0],
                vec![iff(
                    cmp(BinOpKind::Eq, ret_state(18), 1),
                    vec![block(vec![Expr::unknown("c")])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let c0 = format!("{:?}", case_body(&out, 0).expect("case 0"));
        // The case body's inner compare stays a raw register access (ArrayAccess),
        // not a second __resume_index dispatch. (The outer switch value is the only
        // __resume_index; the body keeps ret[6].)
        assert!(
            c0.contains("ArrayAccess") && !c0.contains("__resume_index"),
            "concrete == case body was wrongly rewritten as dispatch: {c0}"
        );
    }

    #[test]
    fn cross_sibling_case_body_reusing_register_is_preserved() {
        // local = arg0; ret = local;
        // if (ret[18] == 0) { rax = rax[18]; body_a } else if (ret[18] == 1) body_b
        // The case-0 body overwrites `rax` and re-reads `rax[18]`; because the
        // flattener runs on the plain frame (the guard spine was canonicalized to
        // the named field first), that body block is NOT misread as droppable
        // dispatch plumbing — the real body code survives.
        let local = || Expr::var(Variable::stack(-8, 8));
        let ret = || Expr::var(Variable::reg("rax", 8));
        let ret_state = || Expr::array_access(ret(), Expr::int(18), 2);
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            block(vec![Expr::assign(ret(), local())]),
            iff(
                cmp(BinOpKind::Eq, ret_state(), 0),
                vec![
                    block(vec![Expr::assign(ret(), ret_state())]),
                    block(vec![Expr::unknown("body_a")]),
                ],
                vec![iff(
                    cmp(BinOpKind::Eq, ret_state(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let case0 = case_body(&out, 0).expect("case 0");
        let c0 = format!("{case0:?}");
        assert!(
            c0.contains("body_a"),
            "case body reusing the register was wrongly dropped as plumbing: {c0}"
        );
    }

    #[test]
    fn flattens_dispatch_with_state_loaded_through_register_alias() {
        // local = arg0;            (frame spill -> stack alias)
        // ret = local;             (scratch-register frame copy)
        // tmp = ret[18];           (resume index loaded THROUGH the register alias)
        // if (tmp == 0) A else if (tmp == 1) B
        // The load reaches the state field only via the block-local register alias
        // `ret`; field detection and state binding must both honor it so the
        // dispatch still flattens.
        let local = || Expr::var(Variable::stack(-8, 8));
        let ret = || Expr::var(Variable::reg("rax", 8));
        let tmp = || Expr::var(Variable::reg("edx", 4));
        let body = vec![
            block(vec![
                Expr::assign(local(), frame()),
                Expr::assign(ret(), local()),
                Expr::assign(tmp(), Expr::array_access(ret(), Expr::int(18), 2)),
            ]),
            iff(
                cmp(BinOpKind::Eq, tmp(), 0),
                vec![block(vec![Expr::int(1)])],
                vec![iff(
                    cmp(BinOpKind::Eq, tmp(), 1),
                    vec![block(vec![Expr::int(2)])],
                    vec![],
                )],
            ),
        ];
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
    fn reload_used_only_as_indirect_call_target_is_preserved() {
        // A `rax = local` reload feeding an indirect call `(*rax)()` must NOT be
        // dropped as dead plumbing — the use is the call TARGET, which the expr
        // visitor must descend into.
        use super::super::expression::CallTarget;
        let rax = || Expr::var(Variable::reg("rax", 8));
        let local = || Expr::var(Variable::stack(-8, 8));
        let reloads = vec![block(vec![Expr::assign(rax(), local())])];
        let outcome = vec![block(vec![Expr::call(
            CallTarget::Indirect(Box::new(rax())),
            vec![],
        )])];
        let combined = prepend_used_reloads(reloads, outcome);
        assert_eq!(
            combined.len(),
            2,
            "reload feeding an indirect call target was wrongly dropped: {combined:?}"
        );
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
    fn aliased_frame_pointer_register_store_is_renamed() {
        // local = arg0;                     (frame spill -> stack alias)
        // if (state == 0) { ret = local; ret[18] = 5; }   (store through a reg copy)
        // else if (state == 1) { body_b }
        // `ret` is a scratch register (excluded from the flow-insensitive alias
        // set), but flow-sensitively it holds the frame after `ret = local`, so
        // `ret[18] = 5` renames to `frame->__resume_index = 5`.
        let local = || Expr::var(Variable::stack(-8, 8));
        let ret = || Expr::var(Variable::reg("rax", 8));
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![
                    Expr::assign(ret(), local()),
                    Expr::assign(Expr::array_access(ret(), Expr::int(18), 2), Expr::int(5)),
                ])],
                vec![iff(
                    cmp(BinOpKind::Eq, state_access(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let case0 = case_body(&out, 0).expect("case 0");
        let c0 = format!("{case0:?}");
        assert!(c0.contains("__resume_index"), "aliased store not renamed: {c0}");
        // The renamed store leaves no raw `ret[18]` ArrayAccess behind.
        assert!(!c0.contains("ArrayAccess"), "aliased store not fully renamed: {c0}");
    }

    #[test]
    fn aliased_frame_pointer_register_store_is_renamed_on_32bit() {
        // Same shape as the 64-bit case, but every frame-pointer home/copy is
        // 4-wide (a 32-bit target). `pointer_size` is derived from the frame
        // home's slot width (4 here), so a 4-byte `ret = local` is recognized as a
        // FULL copy and `ret[18] = 5` still renames — the width check is not
        // hard-coded to 8. (`state_access` reads a 2-byte field either way.)
        let local = || Expr::var(Variable::stack(-8, 4));
        let ret = || Expr::var(Variable::reg("eax", 4));
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![
                    Expr::assign(ret(), local()),
                    Expr::assign(Expr::array_access(ret(), Expr::int(18), 2), Expr::int(5)),
                ])],
                vec![iff(
                    cmp(BinOpKind::Eq, state_access(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let case0 = case_body(&out, 0).expect("case 0");
        let c0 = format!("{case0:?}");
        assert!(
            c0.contains("__resume_index"),
            "32-bit aliased store not renamed: {c0}"
        );
        assert!(
            !c0.contains("ArrayAccess"),
            "32-bit aliased store not fully renamed: {c0}"
        );
    }

    #[test]
    fn pointer_width_derived_from_deref_frame_home_on_32bit() {
        // 32-bit target whose frame spill is a memory Deref home rather than a
        // named stack slot: *(ebp-4) = arg0; then eax = *(ebp-4); eax[18] = 5.
        // `pointer_size` must come from the 4-byte Deref store width, so the
        // 4-byte `eax` copy is recognized as a full copy and the store renames.
        // `*(ebp + -4)` — the normalized (Add-with-negative-offset) form the lifter
        // produces and `alias_key` recognizes.
        let mem = || {
            Expr::deref(
                Expr::binop(
                    BinOpKind::Add,
                    Expr::var(Variable::reg("ebp", 4)),
                    Expr::int(-4),
                ),
                4,
            )
        };
        let ret = || Expr::var(Variable::reg("eax", 4));
        let body = vec![
            block(vec![Expr::assign(mem(), frame())]),
            iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![
                    Expr::assign(ret(), mem()),
                    Expr::assign(Expr::array_access(ret(), Expr::int(18), 2), Expr::int(5)),
                ])],
                vec![iff(
                    cmp(BinOpKind::Eq, state_access(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let case0 = case_body(&out, 0).expect("case 0");
        let c0 = format!("{case0:?}");
        assert!(
            c0.contains("__resume_index"),
            "deref-home 32-bit store not renamed: {c0}"
        );
    }

    #[test]
    fn same_statement_register_mutation_is_not_trusted_for_that_statement() {
        // rbx = local; foo(++rbx, rbx[18]);
        // The statement both mutates rbx (++rbx) and accesses rbx[18]; evaluation
        // order within the statement is not recoverable, so rbx[18] must NOT be
        // renamed. rbx is callee-saved so the call clobber alone leaves it — only
        // the same-statement mutation exclusion catches this.
        use super::super::expression::{CallTarget, UnaryOpKind};
        let local = || Expr::var(Variable::stack(-8, 8));
        let rbx = || Expr::var(Variable::reg("rbx", 8));
        let call = Expr::call(
            CallTarget::Named("foo".to_string()),
            vec![
                Expr::unary(UnaryOpKind::Inc, rbx()),
                Expr::array_access(rbx(), Expr::int(18), 2),
            ],
        );
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![Expr::assign(rbx(), local()), call])],
                vec![iff(
                    cmp(BinOpKind::Eq, state_access(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let case0 = case_body(&out, 0).expect("case 0");
        let c0 = format!("{case0:?}");
        assert!(
            !c0.contains("__resume_index"),
            "access through a same-statement-mutated register was renamed: {c0}"
        );
    }

    #[test]
    fn pointer_width_from_frame_param_when_no_spill_home_32bit() {
        // Optimized 32-bit coroutine: the frame arg (a sized 4-byte Var) is kept in
        // a register with NO stack/Deref spill home, so pointer_size must come from
        // the frame parameter's own width. Then `eax = arg0` is a full 4-byte copy
        // and `eax[18] = 5` renames.
        let arg0v = || {
            Expr::var(Variable {
                kind: VarKind::Arg(0),
                name: "arg0".to_string(),
                size: 4,
            })
        };
        let eax = || Expr::var(Variable::reg("eax", 4));
        let state = || Expr::array_access(arg0v(), Expr::int(18), 2);
        let body = vec![iff(
            cmp(BinOpKind::Eq, state(), 0),
            vec![block(vec![
                Expr::assign(eax(), arg0v()),
                Expr::assign(Expr::array_access(eax(), Expr::int(18), 2), Expr::int(5)),
            ])],
            vec![iff(
                cmp(BinOpKind::Eq, state(), 1),
                vec![block(vec![Expr::unknown("body_b")])],
                vec![],
            )],
        )];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let case0 = case_body(&out, 0).expect("case 0");
        let c0 = format!("{case0:?}");
        assert!(
            c0.contains("__resume_index"),
            "32-bit no-spill register copy store was not renamed: {c0}"
        );
    }

    #[test]
    fn narrowing_cast_copy_does_not_establish_frame_ptr_alias() {
        // local = arg0; rax = (uint32_t)local; rax[18] = 5;
        // The cast truncates the 64-bit pointer to 32 bits, so `rax` does NOT hold
        // a usable frame pointer and the store must stay raw. (`rax` is otherwise a
        // full-width 8-byte register, so only the cast width can catch this.)
        let local = || Expr::var(Variable::stack(-8, 8));
        let rax = || Expr::var(Variable::reg("rax", 8));
        let narrowed = Expr {
            kind: ExprKind::Cast {
                expr: Box::new(local()),
                to_size: 4,
                signed: false,
            },
        };
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![
                    Expr::assign(rax(), narrowed),
                    Expr::assign(Expr::array_access(rax(), Expr::int(18), 2), Expr::int(5)),
                ])],
                vec![iff(
                    cmp(BinOpKind::Eq, state_access(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let case0 = case_body(&out, 0).expect("case 0");
        let c0 = format!("{case0:?}");
        assert!(
            !c0.contains("__resume_index"),
            "store through a truncated frame pointer was wrongly renamed: {c0}"
        );
    }

    #[test]
    fn widened_subregister_read_does_not_establish_frame_ptr_alias() {
        // local = arg0; rax = local; rbx = (uint64_t)eax; rbx[18] = 5;
        // `eax` is the low 32 bits of the frame-holding `rax` (lifted as
        // Var{name:"rax", size:4}); widening it back to 64 bits does not restore the
        // pointer, so `rbx` must NOT be treated as a frame alias.
        let local = || Expr::var(Variable::stack(-8, 8));
        let rax = || Expr::var(Variable::reg("rax", 8));
        let eax = || Expr::var(Variable::reg("eax", 4));
        let rbx = || Expr::var(Variable::reg("rbx", 8));
        let widened = Expr {
            kind: ExprKind::Cast {
                expr: Box::new(eax()),
                to_size: 8,
                signed: false,
            },
        };
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![
                    Expr::assign(rax(), local()),
                    Expr::assign(rbx(), widened),
                    Expr::assign(Expr::array_access(rbx(), Expr::int(18), 2), Expr::int(5)),
                ])],
                vec![iff(
                    cmp(BinOpKind::Eq, state_access(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let case0 = case_body(&out, 0).expect("case 0");
        let c0 = format!("{case0:?}");
        // Only the raw `rbx[18]` store remains; it must not become __resume_index.
        // (`rax = local` may render, but the truncated-copy store stays raw.)
        assert!(
            c0.matches("__resume_index").count() == 0,
            "store through a widened sub-register was wrongly renamed: {c0}"
        );
    }

    #[test]
    fn nested_register_mutation_clears_frame_ptr_alias() {
        // rbx = local;            (rbx is a callee-saved frame copy)
        // rcx[++rbx] = 0;         (rbx mutated INSIDE an array index — no call)
        // rbx[18] = 5;            (rbx no longer holds the frame -> stays raw)
        // Uses rbx (callee-saved) with no call in the block, so this exercises the
        // nested-mutation clear specifically, not the caller-saved call clobber.
        use super::super::expression::UnaryOpKind;
        let local = || Expr::var(Variable::stack(-8, 8));
        let rbx = || Expr::var(Variable::reg("rbx", 8));
        let inc_rbx = Expr::unary(UnaryOpKind::Inc, rbx());
        let nested = Expr::assign(
            Expr::array_access(Expr::var(Variable::reg("rcx", 8)), inc_rbx, 1),
            Expr::int(0),
        );
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![
                    Expr::assign(rbx(), local()),
                    nested,
                    Expr::assign(Expr::array_access(rbx(), Expr::int(18), 2), Expr::int(5)),
                ])],
                vec![iff(
                    cmp(BinOpKind::Eq, state_access(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let case0 = case_body(&out, 0).expect("case 0");
        let c0 = format!("{case0:?}");
        // The store through the mutated register must NOT be renamed.
        assert!(
            !c0.contains("__resume_index"),
            "store through nested-mutated register was wrongly renamed: {c0}"
        );
    }

    #[test]
    fn frame_ptr_reg_alias_does_not_cross_block_boundary() {
        // ret = local;   (block A: ret is a frame copy)
        // if (state == 0) { ret[18] = 5; }   (block B, a different block/node)
        // Frame-pointer register tracking is BLOCK-LOCAL, so the alias does not
        // carry from block A into block B — the store is conservatively left raw
        // rather than risk a stale-alias rename across the control-flow boundary.
        let local = || Expr::var(Variable::stack(-8, 8));
        let ret = || Expr::var(Variable::reg("rax", 8));
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            block(vec![Expr::assign(ret(), local())]),
            iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![Expr::assign(
                    Expr::array_access(ret(), Expr::int(18), 2),
                    Expr::int(5),
                )])],
                vec![iff(
                    cmp(BinOpKind::Eq, state_access(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let case0 = case_body(&out, 0).expect("case 0");
        let c0 = format!("{case0:?}");
        assert!(
            c0.contains("ArrayAccess"),
            "block-local alias should not rename a store in a separate block: {c0}"
        );
    }

    #[test]
    fn call_clobbers_caller_saved_frame_ptr_reg() {
        // local = arg0;
        // if (state == 0) { rax = local; foo(); rax[18] = 5; } else if (state==1) B
        // `rax` is caller-saved — `foo()` clobbers it, so `rax[18]` must stay raw.
        let local = || Expr::var(Variable::stack(-8, 8));
        let rax = || Expr::var(Variable::reg("rax", 8));
        let foo = || {
            Expr::call(
                crate::decompiler::expression::CallTarget::Named("foo".to_string()),
                vec![],
            )
        };
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![
                    Expr::assign(rax(), local()),
                    foo(),
                    Expr::assign(Expr::array_access(rax(), Expr::int(18), 2), Expr::int(5)),
                ])],
                vec![iff(
                    cmp(BinOpKind::Eq, state_access(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let case0 = case_body(&out, 0).expect("case 0");
        let c0 = format!("{case0:?}");
        assert!(
            c0.contains("ArrayAccess"),
            "caller-saved frame reg not cleared on call: {c0}"
        );
    }

    #[test]
    fn switch_arm_within_block_copy_and_store_is_renamed_independently() {
        // A pre-existing switch where case 0 does its own within-block frame copy +
        // store and case 1 calls out. Block-local tracking makes each arm
        // independent, so case 0's `rax[18]` renames regardless of case 1's call.
        // local = arg0;
        // switch (sel) { case 0: { rax = local; rax[18] = 5; }  case 1: foo(); }
        // if (state == 0) A else if (state == 1) B    (triggers recovery)
        let local = || Expr::var(Variable::stack(-8, 8));
        let rax = || Expr::var(Variable::reg("rax", 8));
        let pre_switch = StructuredNode::Switch {
            value: Expr::unknown("sel"),
            cases: vec![
                (
                    vec![0],
                    vec![block(vec![
                        Expr::assign(rax(), local()),
                        Expr::assign(
                            Expr::array_access(rax(), Expr::int(18), 2),
                            Expr::int(5),
                        ),
                    ])],
                ),
                (
                    vec![1],
                    vec![block(vec![Expr::call(
                        crate::decompiler::expression::CallTarget::Named("foo".to_string()),
                        vec![],
                    )])],
                ),
            ],
            default: None,
        };
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            pre_switch,
            iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![Expr::unknown("body_a")])],
                vec![iff(
                    cmp(BinOpKind::Eq, state_access(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        let dump = format!("{out:?}");
        assert!(dump.contains("__resume_index"), "{dump}");
        assert!(
            !dump.contains("ArrayAccess"),
            "case 0's within-block store was not renamed: {dump}"
        );
    }

    #[test]
    fn same_statement_call_clobbers_frame_ptr_reg() {
        // if (state == 0) { rax = local; rax[18] = foo(); } else if (state==1) B
        // The call on the rhs clobbers rax before the store, so `rax[18]` (through
        // the now-clobbered rax) must stay raw even in the same statement.
        let local = || Expr::var(Variable::stack(-8, 8));
        let rax = || Expr::var(Variable::reg("rax", 8));
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![
                    Expr::assign(rax(), local()),
                    Expr::assign(
                        Expr::array_access(rax(), Expr::int(18), 2),
                        Expr::call(
                            crate::decompiler::expression::CallTarget::Named("foo".to_string()),
                            vec![],
                        ),
                    ),
                ])],
                vec![iff(
                    cmp(BinOpKind::Eq, state_access(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let case0 = case_body(&out, 0).expect("case 0");
        let c0 = format!("{case0:?}");
        assert!(
            c0.contains("ArrayAccess"),
            "same-statement call did not clobber the frame alias: {c0}"
        );
    }

    #[test]
    fn caller_saved_reg_not_renamed_in_call_statement() {
        // if (state == 0) { rax = local; foo(rax[18]); } else if (state==1) B
        // The statement calls out; after call-result folding the order of the
        // access relative to the call is unrecoverable, so caller-saved register
        // aliases are conservatively dropped for the whole statement — rax[18]
        // stays raw. (A stack alias would still be renamed; calls don't clobber
        // memory.)
        let local = || Expr::var(Variable::stack(-8, 8));
        let rax = || Expr::var(Variable::reg("rax", 8));
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![
                    Expr::assign(rax(), local()),
                    Expr::call(
                        crate::decompiler::expression::CallTarget::Named("foo".to_string()),
                        vec![Expr::array_access(rax(), Expr::int(18), 2)],
                    ),
                ])],
                vec![iff(
                    cmp(BinOpKind::Eq, state_access(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let case0 = case_body(&out, 0).expect("case 0");
        let c0 = format!("{case0:?}");
        assert!(
            c0.contains("ArrayAccess"),
            "caller-saved access in a call statement was renamed: {c0}"
        );
    }

    #[test]
    fn compound_store_with_call_value_clobbers_frame_ptr_reg() {
        // if (state == 0) { rax = local; rax[18] += foo(); } else if (state==1) B
        // A compound memory store whose rhs calls out clobbers rax before the
        // write, just like a plain `= foo()` store, so it must stay raw.
        let local = || Expr::var(Variable::stack(-8, 8));
        let rax = || Expr::var(Variable::reg("rax", 8));
        let compound_store = Expr {
            kind: ExprKind::CompoundAssign {
                op: BinOpKind::Add,
                lhs: Box::new(Expr::array_access(rax(), Expr::int(18), 2)),
                rhs: Box::new(Expr::call(
                    crate::decompiler::expression::CallTarget::Named("foo".to_string()),
                    vec![],
                )),
            },
        };
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![Expr::assign(rax(), local()), compound_store])],
                vec![iff(
                    cmp(BinOpKind::Eq, state_access(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let case0 = case_body(&out, 0).expect("case 0");
        let c0 = format!("{case0:?}");
        assert!(
            c0.contains("ArrayAccess"),
            "compound call-valued store did not clobber the frame alias: {c0}"
        );
    }

    #[test]
    fn unary_inc_clears_frame_ptr_reg_alias() {
        // if (state == 0) { rax = local; ++rax; rax[18] = 5; } else if (state==1) B
        // ++rax mutates rax, so the later store must stay raw.
        let local = || Expr::var(Variable::stack(-8, 8));
        let rax = || Expr::var(Variable::reg("rax", 8));
        let inc = Expr {
            kind: ExprKind::UnaryOp {
                op: super::super::expression::UnaryOpKind::Inc,
                operand: Box::new(rax()),
            },
        };
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![
                    Expr::assign(rax(), local()),
                    inc,
                    Expr::assign(Expr::array_access(rax(), Expr::int(18), 2), Expr::int(5)),
                ])],
                vec![iff(
                    cmp(BinOpKind::Eq, state_access(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let case0 = case_body(&out, 0).expect("case 0");
        let c0 = format!("{case0:?}");
        assert!(
            c0.contains("ArrayAccess"),
            "++reg did not clear the frame alias: {c0}"
        );
    }

    #[test]
    fn partial_register_frame_copy_does_not_establish_alias() {
        // if (state == 0) { eax = local; rax[18] = 5; } else if (state==1) B
        // `eax = local` only writes the low 32 bits, so the full rax is NOT the
        // frame — the later rax[18] store must stay raw.
        let local = || Expr::var(Variable::stack(-8, 8));
        let eax = || Expr::var(Variable::reg("eax", 4));
        let rax = || Expr::var(Variable::reg("rax", 8));
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![
                    Expr::assign(eax(), local()),
                    Expr::assign(Expr::array_access(rax(), Expr::int(18), 2), Expr::int(5)),
                ])],
                vec![iff(
                    cmp(BinOpKind::Eq, state_access(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let case0 = case_body(&out, 0).expect("case 0");
        let c0 = format!("{case0:?}");
        assert!(
            c0.contains("ArrayAccess"),
            "partial-register copy was wrongly promoted to a frame alias: {c0}"
        );
    }

    #[test]
    fn narrow_width_copy_under_full_name_does_not_establish_alias() {
        // A sub-register lifted under its 64-bit NAME but narrow SIZE (`eax` as
        // name `rax`, size 4) must not establish a full frame alias.
        // if (state == 0) { rax:4 = local; rax:8[18] = 5; } else if (state==1) B
        let local = || Expr::var(Variable::stack(-8, 8));
        let rax32 = || Expr::var(Variable::reg("rax", 4));
        let rax64 = || Expr::var(Variable::reg("rax", 8));
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![
                    Expr::assign(rax32(), local()),
                    Expr::assign(Expr::array_access(rax64(), Expr::int(18), 2), Expr::int(5)),
                ])],
                vec![iff(
                    cmp(BinOpKind::Eq, state_access(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let case0 = case_body(&out, 0).expect("case 0");
        let c0 = format!("{case0:?}");
        assert!(
            c0.contains("ArrayAccess"),
            "narrow-width copy wrongly established a frame alias: {c0}"
        );
    }

    #[test]
    fn subregister_write_clears_overlapping_frame_ptr_alias() {
        // if (state == 0) { x19 = local; w19 = 0; x19[18] = 5; } else if (state==1) B
        // Writing w19 zero-extends into x19, clobbering the frame copy, so the
        // later x19[18] store must stay raw.
        let local = || Expr::var(Variable::stack(-8, 8));
        let x19 = || Expr::var(Variable::reg("x19", 8));
        let w19 = || Expr::var(Variable::reg("w19", 4));
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![
                    Expr::assign(x19(), local()),
                    Expr::assign(w19(), Expr::int(0)),
                    Expr::assign(Expr::array_access(x19(), Expr::int(18), 2), Expr::int(5)),
                ])],
                vec![iff(
                    cmp(BinOpKind::Eq, state_access(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let case0 = case_body(&out, 0).expect("case 0");
        let c0 = format!("{case0:?}");
        assert!(
            c0.contains("ArrayAccess"),
            "sub-register write did not clear the overlapping alias: {c0}"
        );
    }

    #[test]
    fn link_register_frame_alias_does_not_survive_call() {
        // local = arg0;
        // if (state == 0) { x30 = local; foo(); x30[18] = 5; } else if (state==1) B
        // x30 is the AArch64 link register — `bl` (foo) overwrites it even though
        // it is otherwise callee-saved, so the store stays raw.
        let local = || Expr::var(Variable::stack(-8, 8));
        let x30 = || Expr::var(Variable::reg("x30", 8));
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![
                    Expr::assign(x30(), local()),
                    Expr::call(
                        crate::decompiler::expression::CallTarget::Named("foo".to_string()),
                        vec![],
                    ),
                    Expr::assign(Expr::array_access(x30(), Expr::int(18), 2), Expr::int(5)),
                ])],
                vec![iff(
                    cmp(BinOpKind::Eq, state_access(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let case0 = case_body(&out, 0).expect("case 0");
        let c0 = format!("{case0:?}");
        assert!(
            c0.contains("ArrayAccess"),
            "link-register frame alias survived a call: {c0}"
        );
    }

    #[test]
    fn callee_saved_frame_ptr_reg_survives_call() {
        // Same shape but `rbx` (callee-saved) keeps the frame across `foo()`, so
        // `rbx[18] = 5` is still renamed.
        let local = || Expr::var(Variable::stack(-8, 8));
        let rbx = || Expr::var(Variable::reg("rbx", 8));
        let foo = || {
            Expr::call(
                crate::decompiler::expression::CallTarget::Named("foo".to_string()),
                vec![],
            )
        };
        let body = vec![
            block(vec![Expr::assign(local(), frame())]),
            iff(
                cmp(BinOpKind::Eq, state_access(), 0),
                vec![block(vec![
                    Expr::assign(rbx(), local()),
                    foo(),
                    Expr::assign(Expr::array_access(rbx(), Expr::int(18), 2), Expr::int(5)),
                ])],
                vec![iff(
                    cmp(BinOpKind::Eq, state_access(), 1),
                    vec![block(vec![Expr::unknown("body_b")])],
                    vec![],
                )],
            ),
        ];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let case0 = case_body(&out, 0).expect("case 0");
        let c0 = format!("{case0:?}");
        assert!(
            c0.contains("__resume_index"),
            "callee-saved frame reg wrongly cleared on call: {c0}"
        );
    }

    #[test]
    fn non_frame_register_store_is_not_renamed() {
        // if (state == 0) { ret = extern(); ret[18] = 5; }  else if (state == 1) B
        // `ret` holds a call result, NOT a frame copy, so `ret[18]` must NOT be
        // renamed to the resume-index field.
        let ret = || Expr::var(Variable::reg("rax", 8));
        let body = vec![iff(
            cmp(BinOpKind::Eq, state_access(), 0),
            vec![block(vec![
                Expr::assign(
                    ret(),
                    Expr::call(
                        crate::decompiler::expression::CallTarget::Named("extern".to_string()),
                        vec![],
                    ),
                ),
                Expr::assign(Expr::array_access(ret(), Expr::int(18), 2), Expr::int(5)),
            ])],
            vec![iff(
                cmp(BinOpKind::Eq, state_access(), 1),
                vec![block(vec![Expr::unknown("body_b")])],
                vec![],
            )],
        )];
        let out = recover_resume_dispatch(body);
        assert_eq!(switch_labels(&out), Some(vec![0, 1]));
        let case0 = case_body(&out, 0).expect("case 0");
        let c0 = format!("{case0:?}");
        // The switch value renames to __resume_index, but the case-0 body's
        // `ret[18]` store (through a non-frame register) must stay a raw
        // ArrayAccess — not renamed.
        assert!(c0.contains("ArrayAccess"), "non-frame store wrongly renamed: {c0}");
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
