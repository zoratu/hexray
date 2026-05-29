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

use super::expression::{BinOpKind, CallTarget, Expr, ExprKind};
use super::structurer::StructuredNode;

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

// `is_empty`/`len`/`get`/`iter` are the API the follow-up rewrite pass will
// consume; tests already exercise them. Suppress the dead-code warning until
// the transform commit lands.
#[allow(dead_code)]
impl StackStructBindings {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.by_offset.is_empty()
    }

    pub fn len(&self) -> usize {
        self.by_offset.len()
    }

    /// Look up the binding for a stack offset, if any.
    pub fn get(&self, stack_offset: i64) -> Option<&StackStructBinding> {
        self.by_offset.get(&stack_offset)
    }

    /// Iterate the collected bindings in offset order.
    pub fn iter(&self) -> impl Iterator<Item = &StackStructBinding> {
        self.by_offset.values()
    }

    /// Walk `nodes`, look up each `Call`'s prototype in `db`, and bind any
    /// stack-address argument whose matching prototype parameter is `T*` for a
    /// known struct `T` in `db`.
    pub fn analyze(&mut self, nodes: &[StructuredNode], db: &TypeDatabase) {
        for n in nodes {
            visit_node(n, db, self);
        }
    }
}

/// Run [`StackStructBindings::analyze`] against the built-in posix/linux/libc
/// type database (cached after first use). The pipeline call site uses this.
pub fn analyze_with_builtin_db(nodes: &[StructuredNode]) -> StackStructBindings {
    let mut bindings = StackStructBindings::new();
    bindings.analyze(nodes, builtin_db());
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

fn visit_node(node: &StructuredNode, db: &TypeDatabase, out: &mut StackStructBindings) {
    use StructuredNode as N;
    match node {
        N::Block { statements, .. } => {
            for s in statements {
                visit_expr(s, db, out);
            }
        }
        N::If {
            condition,
            then_body,
            else_body,
        } => {
            visit_expr(condition, db, out);
            for n in then_body {
                visit_node(n, db, out);
            }
            if let Some(eb) = else_body {
                for n in eb {
                    visit_node(n, db, out);
                }
            }
        }
        N::While {
            condition, body, ..
        }
        | N::DoWhile {
            condition, body, ..
        } => {
            visit_expr(condition, db, out);
            for n in body {
                visit_node(n, db, out);
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
                visit_expr(e, db, out);
            }
            visit_expr(condition, db, out);
            if let Some(e) = update {
                visit_expr(e, db, out);
            }
            for n in body {
                visit_node(n, db, out);
            }
        }
        N::Loop { body, .. } => {
            for n in body {
                visit_node(n, db, out);
            }
        }
        N::Switch {
            value,
            cases,
            default,
        } => {
            visit_expr(value, db, out);
            for (_, body) in cases {
                for n in body {
                    visit_node(n, db, out);
                }
            }
            if let Some(d) = default {
                for n in d {
                    visit_node(n, db, out);
                }
            }
        }
        N::Sequence(body) => {
            for n in body {
                visit_node(n, db, out);
            }
        }
        N::TryCatch {
            try_body,
            catch_handlers,
        } => {
            for n in try_body {
                visit_node(n, db, out);
            }
            for h in catch_handlers {
                for n in &h.body {
                    visit_node(n, db, out);
                }
            }
        }
        N::Expr(e) | N::Return(Some(e)) => visit_expr(e, db, out),
        _ => {}
    }
}

fn visit_expr(expr: &Expr, db: &TypeDatabase, out: &mut StackStructBindings) {
    if let ExprKind::Call { target, args } = &expr.kind {
        try_bind_call(target, args, db, out);
    }
    walk_children(expr, db, out);
}

fn walk_children(expr: &Expr, db: &TypeDatabase, out: &mut StackStructBindings) {
    use ExprKind as K;
    match &expr.kind {
        K::Call { args, .. } | K::Phi(args) => {
            for a in args {
                visit_expr(a, db, out);
            }
        }
        K::Assign { lhs, rhs } | K::CompoundAssign { lhs, rhs, .. } => {
            visit_expr(lhs, db, out);
            visit_expr(rhs, db, out);
        }
        K::BinOp { left, right, .. } => {
            visit_expr(left, db, out);
            visit_expr(right, db, out);
        }
        K::UnaryOp { operand, .. }
        | K::Deref { addr: operand, .. }
        | K::AddressOf(operand)
        | K::Cast { expr: operand, .. }
        | K::BitField { expr: operand, .. } => visit_expr(operand, db, out),
        K::ArrayAccess { base, index, .. } => {
            visit_expr(base, db, out);
            visit_expr(index, db, out);
        }
        K::FieldAccess { base, .. } => visit_expr(base, db, out),
        K::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            visit_expr(cond, db, out);
            visit_expr(then_expr, db, out);
            visit_expr(else_expr, db, out);
        }
        _ => {}
    }
}

fn try_bind_call(
    target: &CallTarget,
    args: &[Expr],
    db: &TypeDatabase,
    out: &mut StackStructBindings,
) {
    let CallTarget::Named(name) = target else {
        return;
    };
    let normalized = normalize_call_name(name);
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
        bindings.analyze(&[block(vec![call])], &full_db());

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
        bindings.analyze(&[block(vec![call])], &full_db());
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
        bindings.analyze(&[block(vec![call])], &full_db());
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
        bindings.analyze(&[block(vec![call])], &full_db());
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
}
