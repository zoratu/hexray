//! Stack-local struct reconstruction via known function prototypes (deferral #3).
//!
//! When a call argument is the address of a stack region (e.g. `rbp + -20`) and
//! the resolved prototype declares the matching parameter as `T*` for a known
//! struct `T`, the stack region [rbp+K, rbp+K+sizeof(T)) is actually a local of
//! type `T`. This module collects those `(stack_offset, struct_type)` bindings
//! from the structured body so a later pass can:
//!   - render the call argument as `&<local>` instead of the raw stack
//!     address,
//!   - rewrite the bare-offset field stores into `<local>.field = …` form,
//!   - declare `struct T <local>;` at the top of the function.
//!
//! The existing [`super::struct_inference`] pass fires on *pointer-relative*
//! accesses (`[rbx+8]`) producing anonymous `struct_0`/`field_8` names. This
//! pass is the complementary path: **stack-local + bound to a named library
//! type** via the call-site prototype.
//!
//! # Status
//!
//! Scaffolding. [`StackStructBindings::analyze`] is functional and exercised by
//! the unit tests below; the rewrite pass that uses the bindings (call-arg
//! `&local`, store-side field rewrite, local declaration) lands in a follow-up
//! commit.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use hexray_types::builtin::libc::load_libc_functions;
use hexray_types::builtin::linux::load_linux_types;
use hexray_types::builtin::posix::load_posix_types;
use hexray_types::database::TypeDatabase;
use hexray_types::types::CType;

use super::expression::{BinOpKind, CallTarget, Expr, ExprKind, VarKind, Variable};
use super::structurer::{CatchHandler, StructuredNode};
use super::BinaryDataContext;

/// A stack region recognised as a typed struct via a known call prototype.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackStructBinding {
    /// Stack offset relative to the frame register (negative for `rbp - K`).
    pub stack_offset: i64,
    /// Total size of the bound struct in bytes (from the type database).
    pub size: usize,
    /// Fully-qualified C type name, e.g. `"struct epoll_event"`.
    pub type_name: String,
    /// Suggested local variable name for the rewritten output, e.g.
    /// `"epoll_event_14"` (struct name + abs(offset) in hex).
    pub local_name: String,
}

/// `stack_offset -> binding` map collected by [`Self::analyze`].
#[derive(Debug, Default, Clone)]
pub struct StackStructBindings {
    by_offset: BTreeMap<i64, StackStructBinding>,
}

impl StackStructBindings {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.by_offset.is_empty()
    }

    #[allow(dead_code)] // kept for API symmetry with `is_empty`
    pub fn len(&self) -> usize {
        self.by_offset.len()
    }

    /// Look up the binding whose base equals this stack offset, if any.
    pub fn get(&self, stack_offset: i64) -> Option<&StackStructBinding> {
        self.by_offset.get(&stack_offset)
    }

    /// Look up the binding whose region `[stack_offset, stack_offset + size)`
    /// contains the given stack offset.
    pub fn containing(&self, stack_offset: i64) -> Option<&StackStructBinding> {
        self.by_offset.values().find(|b| {
            stack_offset >= b.stack_offset && stack_offset < b.stack_offset + b.size as i64
        })
    }

    /// Iterate the collected bindings in offset order.
    pub fn iter(&self) -> impl Iterator<Item = &StackStructBinding> {
        self.by_offset.values()
    }

    /// Walk `nodes`, look up each `Call`'s prototype in `db`, and bind any
    /// stack-address argument whose matching prototype parameter is `T*` for a
    /// known struct `T` in `db`. `binary_data` (if provided) resolves
    /// `CallTarget::Direct` addresses to names via the symbol/PLT table —
    /// without it, only already-named call sites are considered.
    pub fn analyze(
        &mut self,
        nodes: &[StructuredNode],
        db: &TypeDatabase,
        binary_data: Option<&BinaryDataContext>,
    ) {
        for n in nodes {
            visit_node(n, db, binary_data, self);
        }
    }
}

/// Run [`StackStructBindings::analyze`] against the built-in posix/linux/libc
/// type database (cached after first use). The pipeline call site uses this.
pub fn analyze_with_builtin_db(
    nodes: &[StructuredNode],
    binary_data: Option<&BinaryDataContext>,
) -> StackStructBindings {
    let mut bindings = StackStructBindings::new();
    bindings.analyze(nodes, builtin_db(), binary_data);
    bindings
}

fn builtin_db() -> &'static TypeDatabase {
    static DB: OnceLock<TypeDatabase> = OnceLock::new();
    DB.get_or_init(|| {
        let mut db = TypeDatabase::new();
        load_posix_types(&mut db);
        load_linux_types(&mut db);
        load_libc_functions(&mut db);
        db
    })
}

fn visit_node(
    node: &StructuredNode,
    db: &TypeDatabase,
    binary_data: Option<&BinaryDataContext>,
    out: &mut StackStructBindings,
) {
    use StructuredNode as N;
    match node {
        N::Block { statements, .. } => {
            for s in statements {
                visit_expr(s, db, binary_data, out);
            }
        }
        N::If {
            condition,
            then_body,
            else_body,
        } => {
            visit_expr(condition, db, binary_data, out);
            for n in then_body {
                visit_node(n, db, binary_data, out);
            }
            if let Some(eb) = else_body {
                for n in eb {
                    visit_node(n, db, binary_data, out);
                }
            }
        }
        N::While {
            condition, body, ..
        }
        | N::DoWhile {
            condition, body, ..
        } => {
            visit_expr(condition, db, binary_data, out);
            for n in body {
                visit_node(n, db, binary_data, out);
            }
        }
        N::For {
            init,
            condition,
            update,
            body,
            ..
        } => {
            if let Some(e) = init {
                visit_expr(e, db, binary_data, out);
            }
            visit_expr(condition, db, binary_data, out);
            if let Some(e) = update {
                visit_expr(e, db, binary_data, out);
            }
            for n in body {
                visit_node(n, db, binary_data, out);
            }
        }
        N::Loop { body, .. } => {
            for n in body {
                visit_node(n, db, binary_data, out);
            }
        }
        N::Switch {
            value,
            cases,
            default,
        } => {
            visit_expr(value, db, binary_data, out);
            for (_, body) in cases {
                for n in body {
                    visit_node(n, db, binary_data, out);
                }
            }
            if let Some(d) = default {
                for n in d {
                    visit_node(n, db, binary_data, out);
                }
            }
        }
        N::Sequence(body) => {
            for n in body {
                visit_node(n, db, binary_data, out);
            }
        }
        N::TryCatch {
            try_body,
            catch_handlers,
        } => {
            for n in try_body {
                visit_node(n, db, binary_data, out);
            }
            for h in catch_handlers {
                for n in &h.body {
                    visit_node(n, db, binary_data, out);
                }
            }
        }
        N::Expr(e) | N::Return(Some(e)) => visit_expr(e, db, binary_data, out),
        _ => {}
    }
}

fn visit_expr(
    expr: &Expr,
    db: &TypeDatabase,
    binary_data: Option<&BinaryDataContext>,
    out: &mut StackStructBindings,
) {
    if let ExprKind::Call { target, args } = &expr.kind {
        try_bind_call(target, args, db, binary_data, out);
    }
    walk_children(expr, db, binary_data, out);
}

fn walk_children(
    expr: &Expr,
    db: &TypeDatabase,
    binary_data: Option<&BinaryDataContext>,
    out: &mut StackStructBindings,
) {
    use ExprKind as K;
    match &expr.kind {
        K::Call { args, .. } | K::Phi(args) => {
            for a in args {
                visit_expr(a, db, binary_data, out);
            }
        }
        K::Assign { lhs, rhs } | K::CompoundAssign { lhs, rhs, .. } => {
            visit_expr(lhs, db, binary_data, out);
            visit_expr(rhs, db, binary_data, out);
        }
        K::BinOp { left, right, .. } => {
            visit_expr(left, db, binary_data, out);
            visit_expr(right, db, binary_data, out);
        }
        K::UnaryOp { operand, .. }
        | K::Deref { addr: operand, .. }
        | K::AddressOf(operand)
        | K::Cast { expr: operand, .. }
        | K::BitField { expr: operand, .. } => visit_expr(operand, db, binary_data, out),
        K::ArrayAccess { base, index, .. } => {
            visit_expr(base, db, binary_data, out);
            visit_expr(index, db, binary_data, out);
        }
        K::FieldAccess { base, .. } => visit_expr(base, db, binary_data, out),
        K::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            visit_expr(cond, db, binary_data, out);
            visit_expr(then_expr, db, binary_data, out);
            visit_expr(else_expr, db, binary_data, out);
        }
        _ => {}
    }
}

fn try_bind_call(
    target: &CallTarget,
    args: &[Expr],
    db: &TypeDatabase,
    binary_data: Option<&BinaryDataContext>,
    out: &mut StackStructBindings,
) {
    let Some(name) = resolve_call_name(target, binary_data) else {
        return;
    };
    let normalized = normalize_call_name(&name);
    let Some(proto) = db.get_function(normalized) else {
        return;
    };
    for (i, arg) in args.iter().enumerate() {
        let Some((_, param_type)) = proto.parameters.get(i) else {
            break;
        };
        let Some(type_name) = pointed_struct_type_name(param_type) else {
            continue;
        };
        let Some(stack_offset) = stack_offset_of_address(arg) else {
            continue;
        };
        let Some(size) = struct_size_in_db(db, &type_name) else {
            continue;
        };
        let local_name = synthesize_local_name(&type_name, stack_offset);
        out.by_offset
            .entry(stack_offset)
            .or_insert(StackStructBinding {
                stack_offset,
                size,
                type_name,
                local_name,
            });
    }
}

/// Resolve a `CallTarget` to a textual function name. `Named` is trivial;
/// `Direct { target, call_site }` consults the binary's symbol/PLT table via
/// `binary_data` (so e.g. `epoll_ctl@GLIBC_2.3.2` resolves correctly).
/// `Indirect` / `IndirectGot` are not bound (no static name).
fn resolve_call_name(
    target: &CallTarget,
    binary_data: Option<&BinaryDataContext>,
) -> Option<String> {
    match target {
        CallTarget::Named(n) => Some(n.clone()),
        CallTarget::Direct { target, call_site } => binary_data.and_then(|ctx| {
            ctx.call_target_name_by_call_site(*call_site)
                .or_else(|| ctx.call_target_name_by_address(*target))
                .map(str::to_string)
        }),
        CallTarget::Indirect(_) | CallTarget::IndirectGot { .. } => None,
    }
}

/// Strip leading underscores and any `@version` suffix.
fn normalize_call_name(name: &str) -> &str {
    let trimmed = name.trim_start_matches('_');
    trimmed.split('@').next().unwrap_or(trimmed)
}

/// If `ty` is `Ptr(Named("struct X"))` or `Ptr(Struct(X))`, return `"struct X"`.
fn pointed_struct_type_name(ty: &CType) -> Option<String> {
    let CType::Pointer(inner) = ty else {
        return None;
    };
    match inner.as_ref() {
        CType::Named(n) if n.starts_with("struct ") => Some(n.clone()),
        CType::Struct(s) => s.name.as_ref().map(|n| format!("struct {n}")),
        CType::Typedef(t) => pointed_struct_type_name(&CType::Pointer(Box::new((*t.target).clone()))),
        _ => None,
    }
}

/// Look up a struct's total size in the database.
fn struct_size_in_db(db: &TypeDatabase, type_name: &str) -> Option<usize> {
    let ty = db.get_type(type_name)?;
    match ty {
        CType::Struct(s) => Some(s.size),
        CType::Typedef(t) => match t.target.as_ref() {
            CType::Struct(s) => Some(s.size),
            _ => None,
        },
        _ => None,
    }
}

/// Match a stack-address expression `frame_reg + K` (or `K + frame_reg`) and
/// return `K`.
fn stack_offset_of_address(expr: &Expr) -> Option<i64> {
    let ExprKind::BinOp {
        op: BinOpKind::Add,
        left,
        right,
    } = &expr.kind
    else {
        return None;
    };
    use ExprKind as K;
    match (&left.kind, &right.kind) {
        (K::Var(v), K::IntLit(k)) if is_frame_register(&v.name) => i64::try_from(*k).ok(),
        (K::IntLit(k), K::Var(v)) if is_frame_register(&v.name) => i64::try_from(*k).ok(),
        _ => None,
    }
}

fn is_frame_register(name: &str) -> bool {
    matches!(
        name,
        "rbp" | "ebp" | "bp" | "rsp" | "esp" | "sp" | "x29" | "fp"
    )
}

/// Build a deterministic local name from the struct type and stack offset.
/// `"struct epoll_event"` at offset `-20` → `"epoll_event_14"`.
fn synthesize_local_name(type_name: &str, offset: i64) -> String {
    let short = type_name
        .strip_prefix("struct ")
        .or_else(|| type_name.strip_prefix("union "))
        .unwrap_or(type_name);
    format!("{}_{:x}", short, offset.unsigned_abs())
}

// ----- Rewrite -----------------------------------------------------------
//
// `apply_bindings` consumes a structured body together with the
// `StackStructBindings` collected by `analyze` and rewrites:
//   - `Add(frame_reg, K)` for bound `K`         → `AddressOf(Var(<local>))`
//   - `Var(local_<hex>)` whose decoded offset
//     lands at a top-level struct field offset → `<local>.<field>`
//
// Stack stores at offsets that don't match an exact top-level field
// (interior union/array bytes, padding) are intentionally left alone for
// now — a follow-up commit can refine those once the basic shape works.

/// Apply the collected bindings to the structured body.
pub fn apply_bindings(
    nodes: Vec<StructuredNode>,
    bindings: &StackStructBindings,
) -> Vec<StructuredNode> {
    if bindings.is_empty() {
        return nodes;
    }
    let db = builtin_db();
    nodes
        .iter()
        .map(|n| transform_node(n, bindings, db))
        .collect()
}

fn transform_node(
    node: &StructuredNode,
    bindings: &StackStructBindings,
    db: &TypeDatabase,
) -> StructuredNode {
    use StructuredNode as N;
    match node {
        N::Block {
            id,
            statements,
            address_range,
        } => N::Block {
            id: *id,
            statements: statements
                .iter()
                .map(|e| transform_expr(e, bindings, db))
                .collect(),
            address_range: *address_range,
        },
        N::If {
            condition,
            then_body,
            else_body,
        } => N::If {
            condition: transform_expr(condition, bindings, db),
            then_body: then_body
                .iter()
                .map(|n| transform_node(n, bindings, db))
                .collect(),
            else_body: else_body
                .as_ref()
                .map(|b| b.iter().map(|n| transform_node(n, bindings, db)).collect()),
        },
        N::While {
            condition,
            body,
            header,
            exit_block,
        } => N::While {
            condition: transform_expr(condition, bindings, db),
            body: body
                .iter()
                .map(|n| transform_node(n, bindings, db))
                .collect(),
            header: *header,
            exit_block: *exit_block,
        },
        N::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => N::DoWhile {
            body: body
                .iter()
                .map(|n| transform_node(n, bindings, db))
                .collect(),
            condition: transform_expr(condition, bindings, db),
            header: *header,
            exit_block: *exit_block,
        },
        N::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => N::For {
            init: init.as_ref().map(|e| transform_expr(e, bindings, db)),
            condition: transform_expr(condition, bindings, db),
            update: update.as_ref().map(|e| transform_expr(e, bindings, db)),
            body: body
                .iter()
                .map(|n| transform_node(n, bindings, db))
                .collect(),
            header: *header,
            exit_block: *exit_block,
        },
        N::Loop {
            body,
            header,
            exit_block,
        } => N::Loop {
            body: body
                .iter()
                .map(|n| transform_node(n, bindings, db))
                .collect(),
            header: *header,
            exit_block: *exit_block,
        },
        N::Switch {
            value,
            cases,
            default,
        } => N::Switch {
            value: transform_expr(value, bindings, db),
            cases: cases
                .iter()
                .map(|(vals, body)| {
                    (
                        vals.clone(),
                        body.iter()
                            .map(|n| transform_node(n, bindings, db))
                            .collect(),
                    )
                })
                .collect(),
            default: default
                .as_ref()
                .map(|b| b.iter().map(|n| transform_node(n, bindings, db)).collect()),
        },
        N::Sequence(body) => N::Sequence(
            body.iter()
                .map(|n| transform_node(n, bindings, db))
                .collect(),
        ),
        N::TryCatch {
            try_body,
            catch_handlers,
        } => N::TryCatch {
            try_body: try_body
                .iter()
                .map(|n| transform_node(n, bindings, db))
                .collect(),
            catch_handlers: catch_handlers
                .iter()
                .map(|h| CatchHandler {
                    exception_type: h.exception_type.clone(),
                    variable_name: h.variable_name.clone(),
                    body: h
                        .body
                        .iter()
                        .map(|n| transform_node(n, bindings, db))
                        .collect(),
                    landing_pad: h.landing_pad,
                })
                .collect(),
        },
        N::Expr(e) => N::Expr(transform_expr(e, bindings, db)),
        N::Return(opt) => {
            N::Return(opt.as_ref().map(|e| transform_expr(e, bindings, db)))
        }
        other => other.clone(),
    }
}

fn transform_expr(
    expr: &Expr,
    bindings: &StackStructBindings,
    db: &TypeDatabase,
) -> Expr {
    use ExprKind as K;

    // Case A: `Deref(Add(frame, K), size)` whose `K` lands inside a bound
    // region and whose `size` matches an exact top-level field there →
    // `<local>.<field>`. Covers `mov [rbp-K], …` lifts that came through as
    // a Deref.
    if let K::Deref { addr, size } = &expr.kind {
        if let Some(addr_off) = stack_offset_of_address(addr) {
            if let Some(binding) = bindings.containing(addr_off) {
                let rel = (addr_off - binding.stack_offset) as usize;
                if let Some(field_expr) =
                    field_access_for_struct_offset(binding, rel, *size as usize, db)
                {
                    return field_expr;
                }
            }
        }
    }

    // Case A2: `ArrayAccess(Var(frame), IntLit(index), element_size)` whose
    // byte offset `index * element_size` lands at a bound field — the
    // production shape for plain `mov [rbp-N], reg` lifts. Same field-match
    // rule as Case A.
    if let K::ArrayAccess {
        base,
        index,
        element_size,
    } = &expr.kind
    {
        if let (K::Var(v), K::IntLit(k)) = (&base.kind, &index.kind) {
            if is_frame_register(&v.name) {
                if let Some(byte_off) = (*k)
                    .checked_mul(*element_size as i128)
                    .and_then(|p| i64::try_from(p).ok())
                {
                    if let Some(binding) = bindings.containing(byte_off) {
                        let rel = (byte_off - binding.stack_offset) as usize;
                        if let Some(field_expr) =
                            field_access_for_struct_offset(binding, rel, *element_size, db)
                        {
                            return field_expr;
                        }
                    }
                }
            }
        }
    }

    // Case B: Bare bound stack address (call-arg form).
    if let Some(off) = stack_offset_of_address(expr) {
        if let Some(binding) = bindings.get(off) {
            return Expr::address_of(struct_local_expr(binding));
        }
    }

    // Case C: Bare `Var(local_<hex>)` that lands at an exact field offset.
    // (Some pipelines hand us already-named stack slots — handle them too.)
    if let K::Var(v) = &expr.kind {
        if let Some(field_expr) = field_access_for_local_var(v, bindings, db) {
            return field_expr;
        }
    }

    // Case D: Recurse, transforming each subexpression.
    let kind = match &expr.kind {
        K::Var(_) | K::Unknown(_) | K::IntLit(_) => return expr.clone(),
        K::BinOp { op, left, right } => K::BinOp {
            op: *op,
            left: Box::new(transform_expr(left, bindings, db)),
            right: Box::new(transform_expr(right, bindings, db)),
        },
        K::UnaryOp { op, operand } => K::UnaryOp {
            op: *op,
            operand: Box::new(transform_expr(operand, bindings, db)),
        },
        K::Assign { lhs, rhs } => K::Assign {
            lhs: Box::new(transform_expr(lhs, bindings, db)),
            rhs: Box::new(transform_expr(rhs, bindings, db)),
        },
        K::CompoundAssign { op, lhs, rhs } => K::CompoundAssign {
            op: *op,
            lhs: Box::new(transform_expr(lhs, bindings, db)),
            rhs: Box::new(transform_expr(rhs, bindings, db)),
        },
        K::Deref { addr, size } => K::Deref {
            addr: Box::new(transform_expr(addr, bindings, db)),
            size: *size,
        },
        K::AddressOf(inner) => K::AddressOf(Box::new(transform_expr(inner, bindings, db))),
        K::Cast {
            expr: inner,
            to_size,
            signed,
        } => K::Cast {
            expr: Box::new(transform_expr(inner, bindings, db)),
            to_size: *to_size,
            signed: *signed,
        },
        K::BitField {
            expr: inner,
            start,
            width,
        } => K::BitField {
            expr: Box::new(transform_expr(inner, bindings, db)),
            start: *start,
            width: *width,
        },
        K::ArrayAccess {
            base,
            index,
            element_size,
        } => K::ArrayAccess {
            base: Box::new(transform_expr(base, bindings, db)),
            index: Box::new(transform_expr(index, bindings, db)),
            element_size: *element_size,
        },
        K::FieldAccess {
            base,
            field_name,
            offset,
        } => K::FieldAccess {
            base: Box::new(transform_expr(base, bindings, db)),
            field_name: field_name.clone(),
            offset: *offset,
        },
        K::Call { target, args } => K::Call {
            target: target.clone(),
            args: args
                .iter()
                .map(|a| transform_expr(a, bindings, db))
                .collect(),
        },
        K::Conditional {
            cond,
            then_expr,
            else_expr,
        } => K::Conditional {
            cond: Box::new(transform_expr(cond, bindings, db)),
            then_expr: Box::new(transform_expr(then_expr, bindings, db)),
            else_expr: Box::new(transform_expr(else_expr, bindings, db)),
        },
        K::Phi(args) => K::Phi(
            args.iter()
                .map(|a| transform_expr(a, bindings, db))
                .collect(),
        ),
        _ => return expr.clone(),
    };
    Expr { kind }
}

/// Build the `<base>.<field>[.<member>…]` expression for an access at
/// `rel_offset` with `access_size` bytes within `ty`. Recurses through
/// nested struct/union fields (and peels typedefs) so e.g.
/// `epoll_event.data.fd` (union member at union-offset 0, size 4) is found
/// even though `data` itself is an 8-byte union. Returns None when no exact
/// `(offset, size)` match can be built — interior offsets inside a union
/// (sub-offset > 0), partial-overlap accesses, padding bytes, etc. all fall
/// through and are left as raw locals by the rewrite.
fn field_access_at_offset(
    base: Expr,
    ty: &CType,
    rel_offset: usize,
    access_size: usize,
) -> Option<Expr> {
    match peel_typedef(ty) {
        CType::Struct(s) => {
            for field in &s.fields {
                let field_size = field.field_type.size().unwrap_or(0);
                if field_size == 0 {
                    continue;
                }
                if rel_offset < field.offset || rel_offset >= field.offset + field_size {
                    continue;
                }
                let sub_offset = rel_offset - field.offset;
                // Exact direct match at this nesting level.
                if sub_offset == 0 && field_size == access_size {
                    return Some(Expr::field_access(
                        base,
                        field.name.clone(),
                        field.offset,
                    ));
                }
                // The access falls inside this field — recurse into nested
                // struct/union (peeled through typedef).
                let inner_base = Expr::field_access(base, field.name.clone(), field.offset);
                return field_access_at_offset(
                    inner_base,
                    &field.field_type,
                    sub_offset,
                    access_size,
                );
            }
            None
        }
        CType::Union(u) => {
            // Members all share offset 0; accessing past offset 0 means
            // reading into the *interior* of some union member (e.g. upper
            // bytes of a `u64`) which doesn't map to a single named member.
            if rel_offset != 0 {
                return None;
            }
            // Prefer the first member whose declared size matches the access
            // — mirrors typical source order (e.g. `epoll_data.fd` comes
            // before `epoll_data.u32`, both at offset 0 size 4).
            for member in &u.members {
                let member_size = member.member_type.size().unwrap_or(0);
                if member_size == access_size {
                    return Some(Expr::field_access(base, member.name.clone(), 0));
                }
            }
            // Otherwise try to recurse into nested struct/union members.
            for member in &u.members {
                if matches!(
                    peel_typedef(&member.member_type),
                    CType::Struct(_) | CType::Union(_)
                ) {
                    let inner_base =
                        Expr::field_access(base.clone(), member.name.clone(), 0);
                    if let Some(e) =
                        field_access_at_offset(inner_base, &member.member_type, 0, access_size)
                    {
                        return Some(e);
                    }
                }
            }
            None
        }
        _ => None,
    }
}

fn peel_typedef(ty: &CType) -> &CType {
    let mut cur = ty;
    while let CType::Typedef(t) = cur {
        cur = &t.target;
    }
    cur
}

/// Look up `binding`'s struct in the database and build a field-access
/// expression at the given relative offset and access size. Thin wrapper
/// around [`field_access_at_offset`].
fn field_access_for_struct_offset(
    binding: &StackStructBinding,
    rel_offset: usize,
    access_size: usize,
    db: &TypeDatabase,
) -> Option<Expr> {
    let ty = db.get_type(&binding.type_name)?;
    field_access_at_offset(struct_local_expr(binding), ty, rel_offset, access_size)
}

/// If `var` is named `local_<hex>` and its decoded stack offset lands at a
/// nested field of a bound struct/union of the right size, return the
/// corresponding `<local>.<field>[.<member>…]` expression. A size-zero var
/// (recovery hasn't pinned the access width) is skipped — without it the
/// match would be ambiguous, especially inside unions.
fn field_access_for_local_var(
    var: &Variable,
    bindings: &StackStructBindings,
    db: &TypeDatabase,
) -> Option<Expr> {
    if var.size == 0 {
        return None;
    }
    let local_offset = parse_local_name_offset(&var.name)?;
    let binding = bindings.containing(local_offset)?;
    let rel = (local_offset - binding.stack_offset) as usize;
    field_access_for_struct_offset(binding, rel, var.size as usize, db)
}

/// Construct the `Var(<binding.local_name>)` expression for a binding.
fn struct_local_expr(binding: &StackStructBinding) -> Expr {
    let size = binding.size.min(u8::MAX as usize) as u8;
    Expr::var(Variable {
        kind: VarKind::Stack(binding.stack_offset),
        name: binding.local_name.clone(),
        size,
    })
}

/// Decode the `local_<hex>` stack-slot naming convention back to a signed
/// frame offset. `local_14` → `-0x14`. Names that don't match return None.
fn parse_local_name_offset(name: &str) -> Option<i64> {
    let hex = name.strip_prefix("local_")?;
    let abs = i64::from_str_radix(hex, 16).ok()?;
    Some(-abs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexray_core::BasicBlockId;
    use hexray_types::builtin::linux::load_linux_types;
    use hexray_types::builtin::libc::load_libc_functions;
    use hexray_types::builtin::posix::load_posix_types;

    use super::super::expression::{Expr, Variable};

    fn full_db() -> TypeDatabase {
        let mut db = TypeDatabase::new();
        load_posix_types(&mut db);
        load_linux_types(&mut db);
        load_libc_functions(&mut db);
        db
    }

    fn block(statements: Vec<Expr>) -> StructuredNode {
        StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements,
            address_range: (0x1000, 0x1020),
        }
    }

    fn rbp_plus(off: i64) -> Expr {
        Expr::binop(
            BinOpKind::Add,
            Expr::var(Variable::reg("rbp", 8)),
            Expr::int(off as i128),
        )
    }

    #[test]
    fn binds_stack_address_arg_to_known_struct_pointer_param() {
        // epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &<stack@-20>) — the 4th arg is a
        // stack address and epoll_ctl's prototype says param 3 is
        // `struct epoll_event *event`, so this is the canonical binding case.
        let call = Expr::call(
            CallTarget::Named("epoll_ctl".to_string()),
            vec![Expr::int(3), Expr::int(1), Expr::int(0), rbp_plus(-20)],
        );

        let mut bindings = StackStructBindings::new();
        bindings.analyze(&[block(vec![call])], &full_db(), None);

        assert_eq!(bindings.len(), 1, "expected exactly one binding");
        let b = bindings.get(-20).expect("binding at -20");
        assert_eq!(b.type_name, "struct epoll_event");
        assert_eq!(b.size, 12, "packed epoll_event = 4-byte events + 8-byte data");
        assert_eq!(b.local_name, "epoll_event_14");
    }

    #[test]
    fn ignores_non_stack_address_arg() {
        // 4th arg is a plain Var, not a frame+offset — must not bind.
        let call = Expr::call(
            CallTarget::Named("epoll_ctl".to_string()),
            vec![
                Expr::int(3),
                Expr::int(1),
                Expr::int(0),
                Expr::var(Variable::reg("rdi", 8)),
            ],
        );
        let mut bindings = StackStructBindings::new();
        bindings.analyze(&[block(vec![call])], &full_db(), None);
        assert!(bindings.is_empty());
    }

    #[test]
    fn ignores_unknown_callee() {
        // An unknown function has no prototype → no binding even on a stack arg.
        let call = Expr::call(
            CallTarget::Named("definitely_not_a_libc_function".to_string()),
            vec![rbp_plus(-20)],
        );
        let mut bindings = StackStructBindings::new();
        bindings.analyze(&[block(vec![call])], &full_db(), None);
        assert!(bindings.is_empty());
    }

    #[test]
    fn ignores_non_struct_pointer_param() {
        // memset(s, c, n): the first param is `void *`, not a struct pointer —
        // so even with a stack address there, nothing should bind.
        let call = Expr::call(
            CallTarget::Named("memset".to_string()),
            vec![rbp_plus(-20), Expr::int(0), Expr::int(12)],
        );
        let mut bindings = StackStructBindings::new();
        bindings.analyze(&[block(vec![call])], &full_db(), None);
        assert!(bindings.is_empty());
    }

    #[test]
    fn normalize_call_name_strips_underscore_and_version() {
        assert_eq!(normalize_call_name("_epoll_ctl"), "epoll_ctl");
        assert_eq!(normalize_call_name("epoll_ctl@GLIBC_2.3.2"), "epoll_ctl");
        assert_eq!(normalize_call_name("__libc_epoll_ctl"), "libc_epoll_ctl");
    }

    #[test]
    fn synthesizes_short_local_name() {
        assert_eq!(synthesize_local_name("struct epoll_event", -20), "epoll_event_14");
        assert_eq!(synthesize_local_name("struct clone_args", -0x90), "clone_args_90");
        assert_eq!(synthesize_local_name("union epoll_data", -16), "epoll_data_10");
    }

    fn epoll_ctl_with_stack_arg() -> Expr {
        Expr::call(
            CallTarget::Named("epoll_ctl".to_string()),
            vec![Expr::int(3), Expr::int(1), Expr::int(0), rbp_plus(-20)],
        )
    }

    fn run_apply(body: Vec<StructuredNode>) -> Vec<StructuredNode> {
        let mut bindings = StackStructBindings::new();
        bindings.analyze(&body, &full_db(), None);
        apply_bindings(body, &bindings)
    }

    #[test]
    fn apply_bindings_rewrites_stack_address_arg_to_address_of_struct_local() {
        let body = vec![block(vec![epoll_ctl_with_stack_arg()])];
        let out = run_apply(body);
        let StructuredNode::Block { statements, .. } = &out[0] else {
            panic!("expected block")
        };
        let ExprKind::Call { args, .. } = &statements[0].kind else {
            panic!("expected call, got {:?}", statements[0].kind)
        };
        let ExprKind::AddressOf(inner) = &args.last().unwrap().kind else {
            panic!("expected AddressOf, got {:?}", args.last().unwrap().kind)
        };
        let ExprKind::Var(v) = &inner.kind else {
            panic!("expected Var inside AddressOf, got {:?}", inner.kind)
        };
        assert_eq!(v.name, "epoll_event_14");
        assert!(matches!(v.kind, VarKind::Stack(-0x14)));
    }

    #[test]
    fn apply_bindings_rewrites_field_offset_assignment_to_struct_field_access() {
        // local_14 (stack offset -0x14, size 4) lands exactly at
        // `epoll_event_14.events` (offset 0, u32).
        let lhs = Expr::var(Variable {
            kind: VarKind::Stack(-0x14),
            name: "local_14".to_string(),
            size: 4,
        });
        let store = Expr::assign(lhs, Expr::int(8193));
        let body = vec![block(vec![store, epoll_ctl_with_stack_arg()])];
        let out = run_apply(body);
        let StructuredNode::Block { statements, .. } = &out[0] else {
            panic!("expected block")
        };
        let ExprKind::Assign { lhs, .. } = &statements[0].kind else {
            panic!("expected Assign, got {:?}", statements[0].kind)
        };
        let ExprKind::FieldAccess {
            base, field_name, ..
        } = &lhs.kind
        else {
            panic!("expected FieldAccess LHS, got {:?}", lhs.kind)
        };
        assert_eq!(field_name, "events");
        let ExprKind::Var(v) = &base.kind else {
            panic!("expected Var base, got {:?}", base.kind)
        };
        assert_eq!(v.name, "epoll_event_14");
    }

    #[test]
    fn apply_bindings_leaves_interior_offset_store_untouched() {
        // local_c (stack offset -0xc = struct offset 8) lands INSIDE the
        // `data` union, not at any top-level field offset. Must stay as-is.
        let lhs = Expr::var(Variable {
            kind: VarKind::Stack(-0xc),
            name: "local_c".to_string(),
            size: 4,
        });
        let store = Expr::assign(lhs, Expr::int(0));
        let body = vec![block(vec![store, epoll_ctl_with_stack_arg()])];
        let out = run_apply(body);
        let StructuredNode::Block { statements, .. } = &out[0] else {
            panic!("expected block")
        };
        let ExprKind::Assign { lhs, .. } = &statements[0].kind else {
            panic!("expected Assign")
        };
        let ExprKind::Var(v) = &lhs.kind else {
            panic!("expected Var LHS (no rewrite), got {:?}", lhs.kind)
        };
        assert_eq!(v.name, "local_c");
    }

    #[test]
    fn apply_bindings_leaves_unrelated_local_untouched() {
        // local_1c is outside the bound region [-0x14, -0x14+12) = [-0x14, -0x8).
        let lhs = Expr::var(Variable {
            kind: VarKind::Stack(-0x1c),
            name: "local_1c".to_string(),
            size: 4,
        });
        let store = Expr::assign(lhs, Expr::int(7));
        let body = vec![block(vec![store, epoll_ctl_with_stack_arg()])];
        let out = run_apply(body);
        let StructuredNode::Block { statements, .. } = &out[0] else {
            panic!("expected block")
        };
        let ExprKind::Assign { lhs, .. } = &statements[0].kind else {
            panic!("expected Assign")
        };
        let ExprKind::Var(v) = &lhs.kind else {
            panic!("expected Var LHS (no rewrite)")
        };
        assert_eq!(v.name, "local_1c");
    }

    #[test]
    fn apply_bindings_rewrites_deref_field_store() {
        // The production shape `*(int*)(rbp - 20) = 8193` lifts as
        // Deref(Add(rbp, -20), 4) = 8193 — Case A.
        let lhs = Expr::deref(rbp_plus(-20), 4);
        let store = Expr::assign(lhs, Expr::int(8193));
        let body = vec![block(vec![store, epoll_ctl_with_stack_arg()])];
        let out = run_apply(body);
        let StructuredNode::Block { statements, .. } = &out[0] else {
            panic!("expected block")
        };
        let ExprKind::Assign { lhs, .. } = &statements[0].kind else {
            panic!("expected Assign")
        };
        let ExprKind::FieldAccess { field_name, .. } = &lhs.kind else {
            panic!("expected FieldAccess LHS, got {:?}", lhs.kind)
        };
        assert_eq!(field_name, "events");
    }

    #[test]
    fn apply_bindings_rewrites_array_access_field_store() {
        // The production shape `mov [rbp - 20], imm32` lifts as
        // ArrayAccess(rbp, IntLit(-5), 4) — Case A2. Byte offset = -5 * 4 = -20.
        let lhs = Expr {
            kind: ExprKind::ArrayAccess {
                base: Box::new(Expr::var(Variable::reg("rbp", 8))),
                index: Box::new(Expr::int(-5)),
                element_size: 4,
            },
        };
        let store = Expr::assign(lhs, Expr::int(8193));
        let body = vec![block(vec![store, epoll_ctl_with_stack_arg()])];
        let out = run_apply(body);
        let StructuredNode::Block { statements, .. } = &out[0] else {
            panic!("expected block")
        };
        let ExprKind::Assign { lhs, .. } = &statements[0].kind else {
            panic!("expected Assign")
        };
        let ExprKind::FieldAccess { field_name, .. } = &lhs.kind else {
            panic!("expected FieldAccess LHS, got {:?}", lhs.kind)
        };
        assert_eq!(field_name, "events");
    }

    #[test]
    fn apply_bindings_walks_into_union_member_for_data_fd_store() {
        // ev.data.fd = fd at -O0 → `mov [rbp - 16], reg32`, lifted as
        // ArrayAccess(rbp, IntLit(-4), 4). Byte offset = -16, struct offset 4
        // (where the `data` union starts). Sub-offset 0 inside an 8-byte union
        // → recurse and pick the size-4 member `fd`.
        let lhs = Expr {
            kind: ExprKind::ArrayAccess {
                base: Box::new(Expr::var(Variable::reg("rbp", 8))),
                index: Box::new(Expr::int(-4)),
                element_size: 4,
            },
        };
        let store = Expr::assign(lhs, Expr::unknown("fd"));
        let body = vec![block(vec![store, epoll_ctl_with_stack_arg()])];
        let out = run_apply(body);
        let StructuredNode::Block { statements, .. } = &out[0] else {
            panic!("expected block")
        };
        let ExprKind::Assign { lhs, .. } = &statements[0].kind else {
            panic!("expected Assign")
        };
        // LHS shape: FieldAccess(FieldAccess(<local>, "data", 4), "fd", 0).
        let ExprKind::FieldAccess {
            base, field_name, ..
        } = &lhs.kind
        else {
            panic!("expected FieldAccess LHS, got {:?}", lhs.kind)
        };
        assert_eq!(field_name, "fd", "outer field should be the union member");
        let ExprKind::FieldAccess {
            field_name: outer, ..
        } = &base.kind
        else {
            panic!("expected nested FieldAccess base, got {:?}", base.kind)
        };
        assert_eq!(outer, "data", "inner field should be the union itself");
    }

    #[test]
    fn apply_bindings_leaves_interior_union_byte_store_untouched() {
        // `mov dword [rbp - 12], 0` at struct offset 8 → inside the data union
        // at union sub-offset 4. No top-level member starts at offset 4 in the
        // union, so the rewrite intentionally bails (an upper-half-of-u64
        // access has no clean C member name).
        let lhs = Expr {
            kind: ExprKind::ArrayAccess {
                base: Box::new(Expr::var(Variable::reg("rbp", 8))),
                index: Box::new(Expr::int(-3)),
                element_size: 4,
            },
        };
        let store = Expr::assign(lhs, Expr::int(0));
        let body = vec![block(vec![store, epoll_ctl_with_stack_arg()])];
        let out = run_apply(body);
        let StructuredNode::Block { statements, .. } = &out[0] else {
            panic!("expected block")
        };
        let ExprKind::Assign { lhs, .. } = &statements[0].kind else {
            panic!("expected Assign")
        };
        // Must remain an ArrayAccess — no FieldAccess rewrite for this offset.
        assert!(
            matches!(lhs.kind, ExprKind::ArrayAccess { .. }),
            "expected ArrayAccess (no rewrite), got {:?}",
            lhs.kind
        );
    }

    #[test]
    fn parse_local_name_offset_handles_hex_widths() {
        assert_eq!(parse_local_name_offset("local_14"), Some(-0x14));
        assert_eq!(parse_local_name_offset("local_8"), Some(-0x8));
        assert_eq!(parse_local_name_offset("local_90"), Some(-0x90));
        assert_eq!(parse_local_name_offset("local_deadbeef"), Some(-0xdeadbeef));
        assert_eq!(parse_local_name_offset("ret"), None);
        assert_eq!(parse_local_name_offset("local_xyz"), None);
    }
}
