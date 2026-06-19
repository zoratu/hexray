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
    /// `true` when this binding represents a C++ class object whose
    /// lifecycle is constructor / destructor driven (smart pointers
    /// today; future C++ stack-locals later) rather than a plain C
    /// struct. The struct-rewrite path treats them differently: a
    /// zero-store into a C-struct local is a `memset` aggregate
    /// initialisation, but a zero-store into a class object is the
    /// in-place default constructor / move-from-nullptr — emitting
    /// `memset(&shared_ptr, 0, 16)` would corrupt the meaning.
    pub class_object: bool,
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
///
/// `pointer_size` overrides the cached DB's pointer width (which defaults to
/// LP64) so smart-pointer bindings size their stack regions correctly on
/// 32-bit targets. Pass `db.arch().pointer_size` if you have a custom DB;
/// at the decompiler's call site this comes from
/// [`CallingConvention::pointer_size`].
pub fn analyze_with_builtin_db(
    nodes: &[StructuredNode],
    binary_data: Option<&BinaryDataContext>,
    pointer_size: usize,
) -> StackStructBindings {
    use hexray_types::database::ArchInfo;
    // Clone the cached posix/linux/libc DB and override its arch with
    // the caller's pointer width. The clone is cheap relative to
    // re-building the type library and is the simplest way to keep
    // the smart-pointer size derivation (which reads
    // `db.arch().pointer_size`) in sync with the binary's actual
    // word size on 32-bit targets.
    let mut db = builtin_db().clone();
    db.set_arch(ArchInfo {
        pointer_size,
        long_size: pointer_size,
        big_endian: false,
    });
    let mut bindings = StackStructBindings::new();
    bindings.analyze(nodes, &db, binary_data);
    bindings
}

/// Shared posix + linux + libc type DB, initialised once. Sibling modules
/// (notably the emitter) consult it to resolve field types of stack-bound
/// structs that were never registered in any user-supplied `TypeDatabase`.
pub(crate) fn builtin_db() -> &'static TypeDatabase {
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
        // Run alongside `try_bind_call`: smart-pointer method calls
        // aren't in the TypeDatabase (their type comes from the C++
        // class template, not a libc/POSIX prototype), so they need a
        // separate name-pattern detection path.
        try_bind_smart_pointer_method_call(target, args, db, binary_data, out);
        // `std::optional<T>` / `std::variant<...>` are class templates
        // too, recognised the same way (qualified-method name pattern +
        // stack `this`), but with template-arg-derived layout sizes.
        try_bind_optional_variant_method_call(target, args, db, binary_data, out);
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
                class_object: false,
            });
    }
}

/// Recognise a C++ smart-pointer method call (`std::shared_ptr<T>::reset(...)`,
/// `std::unique_ptr<Widget>::get(...)`, etc.) whose `this` argument is the
/// address of a stack region, and bind that region as `std::shared_ptr<T>` /
/// `std::unique_ptr<T>` / `std::weak_ptr<T>` so the downstream rewriter can
/// surface a typed local instead of a bare `rbp - K` argument.
///
/// We match the demangled-name pattern rather than going through the
/// `TypeDatabase` because smart pointers are class templates that resolve
/// per-instantiation; libstdc++ also emits an internal `std::__shared_ptr` /
/// `std::__weak_ptr` base class which the matcher accepts too. The first
/// comma-separated template argument is taken as the inner type `T`
/// (`unique_ptr<T, Deleter>` and `__shared_ptr<T, std::allocator<…>>` both
/// land on the right `T` this way).
///
/// Conservatively only the common ABI sizes are bound:
/// * `unique_ptr<T>` → 8 (single pointer; stateless / default-deleter form).
/// * `shared_ptr<T>` / `weak_ptr<T>` → 16 (data pointer + control block).
///
/// `unique_ptr<T, StatefulDeleter>` instances can be larger; the matcher
/// still emits the 8-byte binding for them because the more common case is
/// the stateless one. A stateful-deleter follow-up can refine the size from
/// `_M_t`'s tuple layout once we have that recognised.
fn try_bind_smart_pointer_method_call(
    target: &CallTarget,
    args: &[Expr],
    db: &TypeDatabase,
    binary_data: Option<&BinaryDataContext>,
    out: &mut StackStructBindings,
) {
    let Some(raw_name) = resolve_call_name(target, binary_data) else {
        return;
    };
    // Relocation-table lookups can hand us a raw Itanium-ABI mangled
    // symbol (e.g. `_ZNSt10shared_ptrI6WidgetE5resetEv`); the symbol
    // table pre-demangles, but the relocation map bypasses that path.
    // The parser only recognises demangled `std::...` patterns, so
    // demangle on entry and fall back to the raw form for already-
    // demangled or non-mangled names. Codex review on PR #24: without
    // this, smart-pointer bindings are silently missed on relocated
    // C++ calls in `.o` files.
    let demangled = hexray_demangle::demangle(&raw_name);
    let name: &str = demangled.as_deref().unwrap_or(&raw_name);
    // Methods that return a non-trivial object by value pass a hidden
    // return-buffer pointer as the first call argument under the
    // SysV / Itanium ABI. Treating `args[0]` as `this` for those would
    // bind the destination's stack slot as the wrong type. Canonical
    // case: `weak_ptr<T>::lock()` returns `shared_ptr<T>` by value.
    if smart_pointer_method_returns_by_value(name) {
        return;
    }
    let Some((kind, inner)) = parse_smart_pointer_kind_and_inner(name) else {
        return;
    };
    // Instance methods receive `this` as the first argument in the lifted
    // call. Free functions like `std::make_shared<T>(...)` don't match the
    // `::method` suffix so they never reach this point.
    let Some(this_arg) = args.first() else {
        return;
    };
    let Some(stack_offset) = stack_offset_of_address(this_arg) else {
        return;
    };
    // Size depends on the target pointer width (4 on 32-bit, 8 on
    // 64-bit). unique_ptr<T> = 1 * ptr_size (the data pointer);
    // shared_ptr<T> / weak_ptr<T> = 2 * ptr_size (data + control
    // block).
    let ptr = db.arch().pointer_size;
    let (short, size) = match kind {
        SmartPointerKind::Unique => ("unique_ptr", ptr),
        SmartPointerKind::Shared => ("shared_ptr", ptr.saturating_mul(2)),
        SmartPointerKind::Weak => ("weak_ptr", ptr.saturating_mul(2)),
    };
    let type_name = format!("std::{short}<{inner}>");
    let local_name = synthesize_smart_pointer_local_name(short, &inner, stack_offset);
    out.by_offset
        .entry(stack_offset)
        .or_insert(StackStructBinding {
            stack_offset,
            size,
            type_name,
            local_name,
            class_object: true,
        });
}

/// Recognise the smart-pointer methods that return a non-trivial object
/// by value (so the SysV / Itanium ABI uses `sret`, putting the
/// destination's address in `args[0]` and the receiver in `args[1]`).
/// Keep the list tight — only methods verified against libstdc++.
/// Everything else falls through and the binder treats `args[0]` as
/// `this` normally.
fn smart_pointer_method_returns_by_value(name: &str) -> bool {
    let method = match name.rsplit_once("::") {
        Some((_, tail)) => tail
            .split(|c: char| c == '(' || c.is_whitespace())
            .next()
            .unwrap_or(""),
        None => return false,
    };
    matches!(method, "lock")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SmartPointerKind {
    Unique,
    Shared,
    Weak,
}

/// Parse a demangled name and, if it looks like
/// `std::<smart_ptr_name><...>::<method>(...)`, return the kind and the first
/// template argument (the inner pointee type). Both the public class names
/// (`shared_ptr`, `unique_ptr`, `weak_ptr`) and the libstdc++ internal base
/// classes (`__shared_ptr`, `__weak_ptr`) are accepted. Returns `None` for
/// anything else so the caller can decline the bind.
fn parse_smart_pointer_kind_and_inner(name: &str) -> Option<(SmartPointerKind, String)> {
    // Order matters: try the longer/more-specific names first so
    // `__shared_ptr` doesn't get parsed as `shared_ptr` with a stray
    // `__` prefix.
    let candidates = [
        ("std::__shared_ptr", SmartPointerKind::Shared),
        ("std::shared_ptr", SmartPointerKind::Shared),
        ("std::__weak_ptr", SmartPointerKind::Weak),
        ("std::weak_ptr", SmartPointerKind::Weak),
        ("std::unique_ptr", SmartPointerKind::Unique),
    ];
    // The prefix must start the name's class qualifier AND be in the
    // called-method position (before the method's argument list).
    // Two distinct codex P2 findings on PR #24 are addressed here:
    //
    //   1. Anchored-identifier: a user type like
    //      `mystd::shared_ptr<Widget>` would otherwise match at offset
    //      2 because `find` is unconstrained. Require the match
    //      position to be 0 or immediately preceded by a non-
    //      identifier byte.
    //
    //   2. Pre-argument-list: in a name like
    //      `foo(std::shared_ptr<Widget>::element_type*)`, the prefix
    //      occurs INSIDE the argument list of an unrelated function.
    //      Require the match to be before the first `(` so we only
    //      pick up the actual called method, not a smart-pointer
    //      type nested inside someone else's signature.
    let is_identifier_byte = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let arg_list_start = name.find('(').unwrap_or(name.len());
    let (kind, after_prefix) = candidates.iter().find_map(|(prefix, kind)| {
        let i = name.find(prefix)?;
        if i >= arg_list_start {
            return None;
        }
        let prev_ok = i == 0
            || name
                .as_bytes()
                .get(i.saturating_sub(1))
                .is_none_or(|b| !is_identifier_byte(*b));
        if !prev_ok {
            return None;
        }
        Some((*kind, &name[i + prefix.len()..]))
    })?;
    let after_lt = after_prefix.strip_prefix('<')?;
    // Walk to the matching `>` honouring nested template brackets so we
    // extract the WHOLE argument list, not the first segment.
    let mut depth = 1usize;
    let mut end = None;
    for (i, c) in after_lt.char_indices() {
        match c {
            '<' => depth = depth.saturating_add(1),
            '>' => {
                depth -= 1;
                if depth == 0 {
                    end = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let end = end?;
    let args = &after_lt[..end];
    let after_args = after_lt.get(end + 1..)?;
    // Must be a method call (`::method`), not a stray type mention.
    // Trim leading whitespace because the Itanium demangler emits a
    // space before the qualifier for nested template closings like
    // `unique_ptr<int, std::default_delete<int> >::get()`. Codex
    // review on PR #24.
    if !after_args.trim_start().starts_with("::") {
        return None;
    }
    // Take the first top-level comma-separated argument as the inner
    // type. For `unique_ptr<T, Deleter>` we also need to check the
    // second argument so a stateful deleter can decline the bind:
    // `std::unique_ptr<T, StatefulDeleter>` can be larger than one
    // pointer once the deleter has state, and an 8-byte binding
    // would absorb adjacent stack locals into the region.
    let segments = split_top_level_comma(args);
    let inner = segments.first()?.trim().to_string();
    if matches!(kind, SmartPointerKind::Unique) && segments.len() > 1 {
        let deleter = segments.get(1).map(|s| s.trim()).unwrap_or("");
        let default = format!("std::default_delete<{inner}>");
        if deleter != default {
            return None;
        }
    }
    Some((kind, inner))
}

/// Split a comma-separated list of template arguments at top level only,
/// skipping commas nested inside `<…>` or `(…)`. Returns the trimmed
/// segments in order.
fn split_top_level_comma(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut depth = 0i32;
    for (i, c) in s.char_indices() {
        match c {
            '<' | '(' => depth += 1,
            '>' | ')' => depth -= 1,
            ',' if depth == 0 => {
                if let Some(seg) = s.get(start..i) {
                    parts.push(seg.to_string());
                }
                start = i + 1;
            }
            _ => {}
        }
    }
    if let Some(rest) = s.get(start..) {
        parts.push(rest.to_string());
    }
    parts
}

/// Build a deterministic local name for a smart-pointer binding. The inner
/// type can contain `::`, `<>`, and spaces (`std::vector<int>` etc.); strip
/// them down to a single short slug so the rendered name reads as a real
/// identifier (`vector_int_8`, `widget_8`).
fn synthesize_smart_pointer_local_name(short: &str, inner: &str, offset: i64) -> String {
    let slug = inner
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' => c,
            _ => '_',
        })
        .collect::<String>();
    // Collapse runs of `_` and strip leading/trailing.
    let mut collapsed = String::with_capacity(slug.len());
    let mut prev_underscore = false;
    for c in slug.chars() {
        if c == '_' {
            if !prev_underscore {
                collapsed.push('_');
            }
            prev_underscore = true;
        } else {
            collapsed.push(c);
            prev_underscore = false;
        }
    }
    let trimmed = collapsed.trim_matches('_');
    if trimmed.is_empty() {
        format!("{short}_{:x}", offset.unsigned_abs())
    } else {
        format!("{trimmed}_{short}_{:x}", offset.unsigned_abs())
    }
}

// ----- std::optional / std::variant binding ----------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OptVarKind {
    Optional,
    Variant,
}

/// Recognise a `std::optional<T>::<method>(...)` or
/// `std::variant<T...>::<method>(...)` member call whose `this` argument is a
/// stack address, and bind that region as `std::optional<T>` /
/// `std::variant<T...>`.
///
/// Like [`try_bind_smart_pointer_method_call`], these are class templates that
/// resolve per-instantiation, so detection is by demangled-name pattern rather
/// than the `TypeDatabase`. The key difference is sizing: optional/variant
/// layout is derived from the template arguments' own sizes/alignments (see
/// [`optional_layout_size`] / [`variant_layout_size`]), and the bind is
/// *declined* whenever a template argument can't be sized confidently — an
/// over- or under-sized region would absorb adjacent stack locals or split the
/// object, the same hazard the smart-pointer stateful-deleter guard avoids.
///
/// First slice: type binding + named local only. The `has_value()` / `index()`
/// → engaged-flag / discriminator semantic sugar is a documented follow-up; the
/// free-function `std::get<...>` / `std::holds_alternative<...>` forms are
/// deliberately not matched here because their template shape is ambiguous with
/// `std::tuple` / `std::pair` access.
fn try_bind_optional_variant_method_call(
    target: &CallTarget,
    args: &[Expr],
    db: &TypeDatabase,
    binary_data: Option<&BinaryDataContext>,
    out: &mut StackStructBindings,
) {
    let Some(raw_name) = resolve_call_name(target, binary_data) else {
        return;
    };
    // Demangle on entry (relocation-map names arrive raw) and fall back to the
    // raw form — same rationale as the smart-pointer path.
    let demangled = hexray_demangle::demangle(&raw_name);
    let name: &str = demangled.as_deref().unwrap_or(&raw_name);
    let Some((kind, type_args, method)) = parse_optional_variant_kind_and_args(name) else {
        return;
    };
    // A member returning a non-trivial *object* by value takes a hidden sret
    // pointer as `args[0]` (receiver in `args[1]`); binding `args[0]` would
    // type the return buffer, not the optional. The only such method here is
    // `optional<T>::value_or(U&&)`, which returns `T` by value — but only an
    // object `T` uses sret. A register-returned scalar (`value_or` on
    // `int`/`double`/a pointer/…) still passes `this` in `args[0]`, so binding
    // is safe and declining would miss the optional entirely (codex P2 on this
    // PR). Decide using the parsed type, not the name alone.
    if method_returns_object_by_value(kind, &type_args, &method) {
        return;
    }
    // Instance methods receive `this` as the first argument in the lifted call.
    let Some(this_arg) = args.first() else {
        return;
    };
    let Some(stack_offset) = stack_offset_of_address(this_arg) else {
        return;
    };
    let (short, type_name, size) = match kind {
        OptVarKind::Optional => {
            let inner = &type_args[0];
            let Some(size) = optional_layout_size(db, inner) else {
                return;
            };
            ("optional", format!("std::optional<{inner}>"), size)
        }
        OptVarKind::Variant => {
            let Some(size) = variant_layout_size(db, &type_args) else {
                return;
            };
            let joined = type_args.join(", ");
            ("variant", format!("std::variant<{joined}>"), size)
        }
    };
    let slug_inner = type_args.join("_");
    let local_name = synthesize_smart_pointer_local_name(short, &slug_inner, stack_offset);
    out.by_offset
        .entry(stack_offset)
        .or_insert(StackStructBinding {
            stack_offset,
            size,
            type_name,
            local_name,
            // Like smart pointers, a zero-store into one of these slots is the
            // default constructor (disengaged optional / valueless variant),
            // not aggregate zero-init padding.
            class_object: true,
        });
}

/// Whether the called member returns a non-trivial *object* by value, so the
/// SysV / Itanium ABI passes a hidden sret pointer as `args[0]` (receiver in
/// `args[1]`). The only such method among the ones we match is
/// `optional<T>::value_or(U&&)` returning `T`; and only when `T` is an object
/// type — a register-returned scalar still passes `this` in `args[0]`.
///
/// `method` is the receiver-qualifier's method name extracted by the parser
/// (e.g. `"value_or"`), NOT a rsplit of the whole signature: a namespaced
/// parameter type like `value_or(ns::S&&)` would otherwise have its trailing
/// `::S` mistaken for the method (codex P2 on PR #43).
fn method_returns_object_by_value(kind: OptVarKind, type_args: &[String], method: &str) -> bool {
    match (kind, method) {
        // `value_or(U&&)` returns the value type `T` — register-safe when `T`
        // is a scalar, sret otherwise.
        (OptVarKind::Optional, "value_or") => type_args
            .first()
            .map(|t| !is_register_returned_scalar(t))
            // No parsed value type → can't prove it's register-safe; assume sret.
            .unwrap_or(true),
        // C++23 monadic ops return a `std::optional<U>` by value whose `U`
        // (and thus triviality / size, hence sret-or-not) isn't recoverable
        // from the member name. Conservatively assume sret and decline — a
        // miss is safe, mis-binding the return buffer is not. Other calls on
        // the same optional (`has_value`, `value`, `operator*`) still bind it.
        (OptVarKind::Optional, "transform" | "and_then" | "or_else") => true,
        _ => false,
    }
}

/// Whether a demangled type spelling is returned in registers under the SysV /
/// Itanium ABI (scalars, pointers, references) rather than via a hidden sret
/// pointer. Conservative: only primitive scalar spellings and pointer/reference
/// types count; objects and unknown user types are assumed to use sret.
///
/// Note this is a deliberately *different* axis from [`inner_type_size_align`]:
/// `long double` is register-returned (x87 `st0`) and so counts here, even
/// though the sizing table declines it (its 16-byte SysV alignment isn't
/// modelled). Both share [`primitive_scalar_size_align`] for the common cases.
fn is_register_returned_scalar(name: &str) -> bool {
    // Strip top-level cv like the sizing path does, so a `value_or` on
    // `int const` / `int* const` is still recognized as register-returned and
    // binds (codex P3 on PR #43).
    let n = strip_top_level_cv(name.trim());
    n.ends_with('*')
        || n.ends_with('&')
        || n == "long double"
        || primitive_scalar_size_align(n, 8).is_some()
}

/// Parse a demangled name and, if it is `std::optional<T>::method(...)` or
/// `std::variant<T...>::method(...)`, return the kind and the trimmed top-level
/// template arguments (one element for optional, the full alternative list for
/// variant). Returns `None` for anything else.
fn parse_optional_variant_kind_and_args(name: &str) -> Option<(OptVarKind, Vec<String>, String)> {
    if let Some((args, method)) = template_args_of_qualified_method(name, "std::optional") {
        let inner = split_top_level_comma(&args)
            .into_iter()
            .next()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())?;
        return Some((OptVarKind::Optional, vec![inner], method));
    }
    if let Some((args, method)) = template_args_of_qualified_method(name, "std::variant") {
        let segments: Vec<String> = split_top_level_comma(&args)
            .into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if segments.is_empty() {
            return None;
        }
        return Some((OptVarKind::Variant, segments, method));
    }
    None
}

/// If `name` contains a receiver qualifier `<prefix><...>::method(...)`, return
/// the `<...>` class-template argument string.
///
/// Each candidate occurrence of `prefix` must be:
///   1. anchored at an identifier boundary (so `mystd::optional<T>` and
///      `std::optionalish<…>` don't match),
///   2. at paren-depth 0 — *not* nested inside another function's argument
///      list (rejects `foo(std::optional<int>::value_type*)`),
///   3. immediately followed by a balanced `<...>` then `::`, with a `(` later
///      in the tail (so it's a called method, not a stray type mention).
///
/// Scanning *every* occurrence at paren-depth 0 (rather than the first match +
/// a global first-`(` cutoff) is what makes this robust to a demangled name
/// that leads with a return type containing the same template, e.g.
/// `std::enable_if<…, std::variant<int,double>&>::type std::variant<int,double>::operator=<int>(…)`
/// — the return-type occurrence is rejected (followed by `&`, not `::`) and the
/// real receiver qualifier is found. (hexray's own demangler is configured
/// `no_return_type`, so it emits the short form, but names can arrive
/// pre-demangled from other sources; this hardens against codex P2 on PR #43.)
fn template_args_of_qualified_method(name: &str, prefix: &str) -> Option<(String, String)> {
    let is_identifier_byte = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let bytes = name.as_bytes();
    let mut search_from = 0;
    while let Some(rel) = name.get(search_from..)?.find(prefix) {
        let i = search_from + rel;
        // Advance past this occurrence for the next iteration regardless of
        // whether it matches.
        search_from = i + prefix.len();

        let prev_ok = i == 0 || bytes.get(i - 1).is_none_or(|b| !is_identifier_byte(*b));
        if !prev_ok {
            continue;
        }
        // Reject occurrences nested inside an earlier (...) argument list.
        if paren_depth_before(name, i) != 0 {
            continue;
        }
        let Some(after_lt) = name[i + prefix.len()..].strip_prefix('<') else {
            continue;
        };
        // Walk to the matching `>` honouring nested template brackets.
        let mut depth = 1usize;
        let mut end = None;
        for (j, c) in after_lt.char_indices() {
            match c {
                '<' => depth = depth.saturating_add(1),
                '>' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(j);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(end) = end else { continue };
        let Some(after_args) = after_lt.get(end + 1..) else {
            continue;
        };
        // Must be a method call: `::method` (trim the space the Itanium
        // demangler emits before a nested-template closer), with the method's
        // own argument list applied *directly* to the name after the qualifier.
        let tail = after_args.trim_start();
        let Some(after_colons) = tail.strip_prefix("::") else {
            continue;
        };
        let Some(method) = method_call_head(after_colons) else {
            continue;
        };
        return Some((after_lt[..end].to_string(), method));
    }
    None
}

/// If the text right after a `Qualifier::` is a method name applied directly to
/// its argument list — `name(`, `name<...>(`, `operator…(` — return the bare
/// method name. Returns `None` for `<return-type> <function-name>(`, the shape
/// an unrelated function takes when its return type merely *spells* this
/// template (e.g. `std::optional<int>::value_type make_value(int*)`); without
/// this the binder would treat that free function's first stack argument as a
/// bogus `this` (codex P2 on PR #43).
fn method_call_head(after_colons: &str) -> Option<String> {
    let trimmed = after_colons.trim_start();
    // Operator functions first: their names legitimately contain `<`, `>`,
    // `-`, and spaces (`operator->`, `operator<<`, `operator<=`,
    // `operator bool`, `operator new[]`, `operator()`), which would otherwise
    // throw off the angle-bracket / identifier scan below — e.g. the `>` in
    // `operator->` reads as a template close and the method `(` is never found
    // (codex P2 on PR #43). A name starting with `operator` after the qualifier
    // is always a member function; require its argument list to be present.
    // None of these operators are sret-returning members we special-case, so
    // the bare `"operator"` tag is enough for the caller.
    if trimmed.starts_with("operator") {
        return trimmed.contains('(').then(|| "operator".to_string());
    }
    // Locate the method's own `(` at angle-bracket depth 0 (so an explicit
    // template-args clause like `value_or<int>` isn't mistaken for the args).
    let mut angle_depth = 0i32;
    let mut paren = None;
    for (k, c) in after_colons.char_indices() {
        match c {
            '<' => angle_depth += 1,
            '>' => angle_depth -= 1,
            '(' if angle_depth == 0 => {
                paren = Some(k);
                break;
            }
            _ => {}
        }
    }
    let head = after_colons[..paren?].trim();
    if head.is_empty() {
        return None;
    }
    // The name is a single identifier (or `~dtor`), optionally followed by an
    // explicit template-args clause `<...>`. A space-separated second
    // identifier means `<return-type> <function-name>` → not a direct method
    // call on this qualifier.
    let ident_end = head
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '~'))
        .unwrap_or(head.len());
    if ident_end == 0 {
        return None;
    }
    let rest = head[ident_end..].trim_start();
    if rest.is_empty() || rest.starts_with('<') {
        Some(head[..ident_end].to_string())
    } else {
        None
    }
}

/// Count of unbalanced `(` before byte index `i` (each `)` cancels a `(`,
/// floored at 0). Used to tell a receiver qualifier at top level from a
/// template mentioned inside another call's argument list.
fn paren_depth_before(name: &str, i: usize) -> i32 {
    let mut depth = 0i32;
    for &b in &name.as_bytes()[..i] {
        match b {
            b'(' => depth += 1,
            b')' => depth = (depth - 1).max(0),
            _ => {}
        }
    }
    depth
}

/// Round `n` up to a multiple of `align` (treating `align == 0` as 1).
fn align_up(n: usize, align: usize) -> usize {
    let align = align.max(1);
    n.div_ceil(align).saturating_mul(align)
}

/// libstdc++ `std::optional<T>` layout: the `T` payload, a one-byte engaged
/// flag at offset `sizeof(T)`, padded to `alignof(T)`. Empirically verified
/// against g++ 13 (`optional<char>`=2, `<int>`=8, `<double>`=16, `<int*>`=16).
/// Returns `None` if `T` can't be sized (caller declines the bind).
fn optional_layout_size(db: &TypeDatabase, inner: &str) -> Option<usize> {
    let (size, align) = inner_type_size_align(db, inner)?;
    Some(align_up(size.saturating_add(1), align))
}

/// libstdc++ `std::variant<T...>` layout: a union of the alternatives, itself
/// padded to the max alternative alignment, followed by a one-byte
/// discriminator, with the whole object padded to that same alignment.
/// Crucially the union is padded to its alignment *before* the discriminator is
/// placed — when the largest alternative isn't the most-aligned one (e.g.
/// `variant<S, double>` with `S` 12 bytes/4-aligned and `double` 8/8-aligned)
/// the union is `align_up(12, 8) = 16` and the variant is `align_up(16+1, 8) =
/// 24`, not `align_up(12+1, 8) = 16` (codex P2 on PR #43). Empirically verified
/// against g++ 13 (`variant<char,char>`=2, `<int,char>`=8, `<int,double>`=16,
/// `<int,int,double>`=16). Declines if any alternative can't be sized, or for
/// the (unrealistic) >255-alternative case where libstdc++ widens the
/// discriminator past one byte.
fn variant_layout_size(db: &TypeDatabase, alternatives: &[String]) -> Option<usize> {
    if alternatives.is_empty() || alternatives.len() > 255 {
        return None;
    }
    let mut payload = 0usize;
    let mut payload_align = 1usize;
    for t in alternatives {
        let (size, align) = inner_type_size_align(db, t)?;
        payload = payload.max(size);
        payload_align = payload_align.max(align);
    }
    let union_size = align_up(payload, payload_align);
    Some(align_up(union_size.saturating_add(1), payload_align))
}

/// Size and alignment (in bytes) of a demangled type spelling. Handles the
/// data-model-fixed scalar spellings (see [`primitive_scalar_size_align`]),
/// pointer/reference types (any trailing `*`/`&`, one machine word), and named
/// struct/union/enum/typedef types resolved through `db`. Returns `None` for
/// anything it can't size confidently — including the data-model-dependent
/// scalars (`long`, `wchar_t`, `long double`) — so the caller declines rather
/// than emit a wrong-sized binding.
fn inner_type_size_align(db: &TypeDatabase, name: &str) -> Option<(usize, usize)> {
    // Strip top-level cv-qualifiers first: a `const`/`volatile` payload has the
    // same size/alignment as the unqualified type, but the demangler spells it
    // `int const` / `int* const`, which would otherwise miss both the scalar
    // table and the DB (codex P2 on PR #43). Done before the pointer check so
    // `int* const` (const pointer) still sizes as a pointer.
    let n = strip_top_level_cv(name.trim());
    // Pointer / reference to anything is one machine word.
    if n.ends_with('*') || n.ends_with('&') {
        let p = db.arch().pointer_size;
        return Some((p, p));
    }
    primitive_scalar_size_align(n, db.arch().pointer_size)
        .or_else(|| named_type_size_align(db, n))
}

/// Strip leading/trailing top-level `const` / `volatile` qualifiers (as
/// whole tokens, so `constant` / `Volatile_t` aren't touched). Leaves
/// qualifiers nested inside template arguments alone.
fn strip_top_level_cv(s: &str) -> &str {
    let mut s = s.trim();
    loop {
        let start = s;
        for kw in ["const", "volatile"] {
            // Leading `<kw> ...`
            if let Some(rest) = s.strip_prefix(kw) {
                if rest.starts_with(char::is_whitespace) {
                    s = rest.trim_start();
                }
            }
            // Trailing `... <kw>`
            if let Some(rest) = s.strip_suffix(kw) {
                if rest.ends_with(char::is_whitespace) {
                    s = rest.trim_end();
                }
            }
        }
        if s == start {
            return s;
        }
    }
}

/// Size and alignment of a primitive scalar type spelling (no pointers, no DB
/// lookup), for a target with the given `pointer_size`.
///
/// The 8-byte scalars (`double`, `long long`) are the tricky case: their
/// alignment is ABI-specific and *not* derivable from data-model sizes alone.
/// On every 64-bit ABI they are 8-aligned (LP64 *and* LLP64/Win64, so
/// `optional<double>` is 16). On 32-bit it splits — i386 System V aligns them
/// to 4 (`optional<double>` = 12) but ARM32 AAPCS aligns to 8 (= 16) — and
/// `ArchInfo` can't tell those apart. So: 8-align on 64-bit (`pointer_size >=
/// 8`), and **decline** the 8-byte scalars on 32-bit rather than guess and
/// risk an over/under-sized region (codex P2s on this PR).
///
/// Other spellings **declined** (→ `None`):
///
/// - `long` / `unsigned long`: 8 on LP64 but 4 on LLP64, and `ArchInfo` can't
///   distinguish the two — data-model-dependent.
/// - `wchar_t`: 4 on SysV, 2 on Windows — likewise.
/// - `long double`: alignment (16 on x86-64, 4 on i386) isn't modelled.
///
/// `char8_t`/`char16_t`/`char32_t` are standard-fixed (1/2/4) and kept. Shared
/// by the sizing and ABI-return-class paths so the spelling list lives in one
/// place. Threading the real ABI to recover `long`/`wchar_t`/32-bit-`double`
/// precisely is a documented follow-up.
fn primitive_scalar_size_align(name: &str, pointer_size: usize) -> Option<(usize, usize)> {
    // 8-byte scalars: 8-aligned on all 64-bit ABIs; ambiguous on 32-bit.
    let wide = (pointer_size >= 8).then_some((8usize, 8usize));
    match name {
        "bool" => Some((1, 1)),
        "char" | "signed char" | "unsigned char" | "char8_t" => Some((1, 1)),
        "short" | "short int" | "unsigned short" | "unsigned short int" | "char16_t" => {
            Some((2, 2))
        }
        "int" | "unsigned int" | "unsigned" => Some((4, 4)),
        "char32_t" | "float" => Some((4, 4)),
        "long long" | "long long int" | "unsigned long long" | "unsigned long long int"
        | "double" => wide,
        _ => None,
    }
}

/// Resolve a named (non-scalar) type's size and alignment through the type
/// database, trying the bare name plus the `struct`/`union`/`enum` spellings
/// the DB keys aggregates under.
fn named_type_size_align(db: &TypeDatabase, name: &str) -> Option<(usize, usize)> {
    [
        name.to_string(),
        format!("struct {name}"),
        format!("union {name}"),
        format!("enum {name}"),
    ]
    .into_iter()
    .find_map(|key| resolve_named_size_align(db, &key))
}

/// Resolve a DB type key to its concrete size/alignment, following both
/// `Typedef` wrappers (peeled in place) and `CType::Named` references (looked
/// back up by name) — the same two hops `struct_size_in_db` walks. Without the
/// `Named` hop, a typedef whose target is stored as `CType::Named` (e.g.
/// `epoll_data_t -> Named("union epoll_data")`) leaves a `Named` node whose
/// `size()`/`alignment()` are `None`, so the binder would decline a type the
/// DB can actually size (codex P2 on PR #43). Bounded loop guards against
/// self-referential aliases.
fn resolve_named_size_align(db: &TypeDatabase, key: &str) -> Option<(usize, usize)> {
    let mut current = key.to_string();
    for _ in 0..16 {
        let ty = db.get_type(&current)?;
        match peel_typedef(ty) {
            CType::Named(next) => current = next.clone(),
            // `CType::Pointer::size()/alignment()` are hardcoded to 8, so a
            // typedef/named alias to a pointer (e.g. `using P = int*`) would
            // size as 8 even on ILP32 — the direct `int*` spelling avoids this
            // via the `ends_with('*')` fast path, but a named alias reaches
            // here (codex P2 on PR #43). Use the target pointer width.
            CType::Pointer(_) => {
                let p = db.arch().pointer_size;
                return Some((p, p));
            }
            concrete => return concrete.size().zip(concrete.alignment()),
        }
    }
    None
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
        CType::Typedef(t) => {
            pointed_struct_type_name(&CType::Pointer(Box::new((*t.target).clone())))
        }
        _ => None,
    }
}

/// Look up a struct or union's total size in the database. Walks both kinds
/// of indirection the DB uses to spell aliases: `CType::Typedef` wrappers
/// (peeled in place) and `CType::Named` references (looked back up by name).
/// A typical chain like `epoll_data_t → CType::Typedef(target =
/// CType::Named("union epoll_data")) → CType::Union { size: 8 }` needs both
/// hops to resolve. Recognises unions in addition to structs. Bounded loop
/// guards against pathological self-referential aliases.
fn struct_size_in_db(db: &TypeDatabase, type_name: &str) -> Option<usize> {
    let mut current = type_name.to_string();
    for _ in 0..16 {
        let ty = db.get_type(&current)?;
        match peel_typedef(ty) {
            CType::Struct(s) => return Some(s.size),
            CType::Union(u) => return Some(u.size),
            CType::Named(next) => current = next.clone(),
            _ => return None,
        }
    }
    None
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
                .filter(|s| !is_droppable_interior_zero_store(s, bindings))
                .map(|e| {
                    if let Some(memset) = try_rewrite_base_zero_to_memset(e, bindings, db) {
                        return memset;
                    }
                    transform_expr(e, bindings, db)
                })
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
        N::Return(opt) => N::Return(opt.as_ref().map(|e| transform_expr(e, bindings, db))),
        other => other.clone(),
    }
}

fn transform_expr(expr: &Expr, bindings: &StackStructBindings, db: &TypeDatabase) -> Expr {
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

    // Case B: Bare bound stack address (call-arg form). Rewrites
    // `Add(frame, K)` to `&<local>` so a method call site like
    // `epoll_ctl(epfd, ADD, fd, &event)` or
    // `std::shared_ptr<Widget>::reset(&sp)` reads as a typed
    // reference. The local's emitted name comes from `binding.local_name`
    // — the typed-local declaration only renders when at least one
    // expression references it, so keeping this rewrite is what makes
    // the smart-pointer binding observable in the output (codex
    // review on PR #24).
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
        K::Deref { addr, size } => {
            // For a Deref into a class-object region (typically the
            // default-constructor byte-zero stores at function entry,
            // `*(rbp - 16) = 0`), recursing into the `addr` would let
            // Case B rewrite it to `&<local>`, and the emitter would
            // render the whole thing as the visually-confusing
            // `qword(&sp) = 0`. Leaving the inner address raw keeps
            // the readable byte view. The typed local declaration is
            // still emitted because Case B fires elsewhere — call-arg
            // sites like `reset(&sp)` reference it. Codex review on
            // PR #24.
            if let Some(off) = stack_offset_of_address(addr) {
                if let Some(binding) = bindings.containing(off) {
                    if binding.class_object {
                        return expr.clone();
                    }
                }
            }
            K::Deref {
                addr: Box::new(transform_expr(addr, bindings, db)),
                size: *size,
            }
        }
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
        } => {
            // Same class-object protection as the Deref case: a
            // `frame[idx]` access landing inside a class-object
            // binding stays raw so the byte view survives. Codex
            // review on PR #24.
            if let (K::Var(v), K::IntLit(k)) = (&base.kind, &index.kind) {
                if is_frame_register(&v.name) {
                    if let Some(byte_off) = (*k)
                        .checked_mul(*element_size as i128)
                        .and_then(|p| i64::try_from(p).ok())
                    {
                        if let Some(binding) = bindings.containing(byte_off) {
                            if binding.class_object {
                                return expr.clone();
                            }
                        }
                    }
                }
            }
            K::ArrayAccess {
                base: Box::new(transform_expr(base, bindings, db)),
                index: Box::new(transform_expr(index, bindings, db)),
                element_size: *element_size,
            }
        }
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
                // Exact direct match at this nesting level. For an aggregate
                // field we still need to descend — a bare `s.data = value`
                // where `data` is a union (or sub-struct) isn't valid C, the
                // store has to name a writable sub-member like `s.data.u64`.
                // The recursion at offset 0 reuses the union member-by-size
                // matching to pick that sub-member.
                if sub_offset == 0 && field_size == access_size {
                    let peeled_field = peel_typedef(&field.field_type);
                    if !matches!(peeled_field, CType::Struct(_) | CType::Union(_)) {
                        return Some(Expr::field_access(base, field.name.clone(), field.offset));
                    }
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
                    let inner_base = Expr::field_access(base.clone(), member.name.clone(), 0);
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

/// Recognize the "base-of-region wide zero" — a zero store at the very start
/// of a bound stack region whose access size doesn't line up with any single
/// top-level field (so the regular rewrite can't produce `local.field = 0`).
/// This is the leading part of an `-O0` zero-init for the whole struct, often
/// emitted as `*(uint64_t*)&ev = 0` for the first 8 bytes of a 12-byte
/// `epoll_event` (with the trailing 4 bytes coming through as the interior
/// zeros that [`is_droppable_interior_zero_store`] silences).
///
/// Returns `Some(memset_call_expr)` for `memset(&<local>, 0, sizeof(<local>))`
/// when the statement matches, otherwise `None`. The size we emit is the full
/// struct size — representing the source-level intent of `T x = {0};` — rather
/// than the partial access size, since the contiguous interior zeros are
/// dropped before this runs and we know the full region was zero-initialised.
fn try_rewrite_base_zero_to_memset(
    stmt: &Expr,
    bindings: &StackStructBindings,
    db: &TypeDatabase,
) -> Option<Expr> {
    let ExprKind::Assign { lhs, rhs } = &stmt.kind else {
        return None;
    };
    if !matches!(&rhs.kind, ExprKind::IntLit(0)) {
        return None;
    }
    let (byte_off, access_size) = match &lhs.kind {
        ExprKind::Deref { addr, size } => {
            let off = stack_offset_of_address(addr)?;
            (off, *size as usize)
        }
        ExprKind::ArrayAccess {
            base,
            index,
            element_size,
        } => {
            let (ExprKind::Var(v), ExprKind::IntLit(k)) = (&base.kind, &index.kind) else {
                return None;
            };
            if !is_frame_register(&v.name) {
                return None;
            }
            let off = (*k)
                .checked_mul(*element_size as i128)
                .and_then(|p| i64::try_from(p).ok())?;
            (off, *element_size)
        }
        _ => return None,
    };
    let binding = bindings.containing(byte_off)?;
    // C++ class objects (smart pointers today, more to come) don't
    // memset-init: a zero store into a `std::shared_ptr<T>` slot is the
    // default constructor / move-from-nullptr, not an aggregate
    // initialisation. Rewriting it as `memset(&sp, 0, 16)` would
    // misrepresent the object's lifecycle and surface bytes-level
    // semantics for what is a class operation. Codex review on PR #24.
    if binding.class_object {
        return None;
    }
    // Must be the base of the bound region (rel == 0).
    if byte_off != binding.stack_offset {
        return None;
    }
    // If a top-level field at offset 0 cleanly matches the access size, the
    // regular rewrite already produces `local.field = 0` — don't replace.
    if field_access_for_struct_offset(binding, 0, access_size, db).is_some() {
        return None;
    }
    Some(Expr::call(
        CallTarget::Named("memset".to_string()),
        vec![
            Expr::address_of(struct_local_expr(binding)),
            Expr::int(0),
            Expr::int(binding.size as i128),
        ],
    ))
}

/// Recognize an "interior zero-init" store that doesn't line up with any
/// recognized field — i.e. the kind of `local_<hex> = 0` that the byte-by-byte
/// `-O0` lift of `struct T x = {0}` leaves behind inside the bound region.
/// Returning `true` drops the statement so the emitter doesn't see a `local_X`
/// reference there and therefore doesn't declare an `int local_X;` overlapping
/// the struct.
///
/// Gated narrowly:
///   - LHS is a stack access (`Deref(Add(frame, K), size)` or
///     `ArrayAccess(Var(frame), IntLit(idx), element_size)`).
///   - The byte offset lands **inside** a bound region at a relative offset
///     **> 0** (the base-of-region wide zero is preserved as a zero-init
///     marker — refinement #2 will fold a contiguous run into a struct literal
///     or `memset`).
///   - RHS is the integer literal `0`.
///   - No exact top-level field matches the access (otherwise the regular
///     rewrite is already producing `local.field = 0`).
fn is_droppable_interior_zero_store(stmt: &Expr, bindings: &StackStructBindings) -> bool {
    let ExprKind::Assign { lhs, rhs } = &stmt.kind else {
        return false;
    };
    if !matches!(&rhs.kind, ExprKind::IntLit(0)) {
        return false;
    }
    let (byte_off, access_size) = match &lhs.kind {
        ExprKind::Deref { addr, size } => {
            let Some(off) = stack_offset_of_address(addr) else {
                return false;
            };
            (off, *size as usize)
        }
        ExprKind::ArrayAccess {
            base,
            index,
            element_size,
        } => {
            let (ExprKind::Var(v), ExprKind::IntLit(k)) = (&base.kind, &index.kind) else {
                return false;
            };
            if !is_frame_register(&v.name) {
                return false;
            }
            let Some(off) = (*k)
                .checked_mul(*element_size as i128)
                .and_then(|p| i64::try_from(p).ok())
            else {
                return false;
            };
            (off, *element_size)
        }
        _ => return false,
    };
    let Some(binding) = bindings.containing(byte_off) else {
        return false;
    };
    // C++ class objects (smart pointers and friends): an interior
    // zero store inside the bound region is part of a real
    // constructor / move-assignment sequence, not aggregate
    // zero-init padding to be silenced. Dropping it would hide
    // semantically-meaningful writes. Codex review on PR #24.
    if binding.class_object {
        return false;
    }
    let rel = byte_off - binding.stack_offset;
    if rel <= 0 {
        // Offset-0 base-of-region zero is the zero-init marker; keep it.
        return false;
    }
    // If a top-level field exactly matches, the regular rewrite handles it
    // cleanly as `local.field = 0`; don't drop the assignment.
    let db = builtin_db();
    field_access_for_struct_offset(binding, rel as usize, access_size, db).is_none()
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
    use hexray_types::builtin::libc::load_libc_functions;
    use hexray_types::builtin::linux::load_linux_types;
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
        assert_eq!(
            b.size, 12,
            "packed epoll_event = 4-byte events + 8-byte data"
        );
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
        assert_eq!(
            synthesize_local_name("struct epoll_event", -20),
            "epoll_event_14"
        );
        assert_eq!(
            synthesize_local_name("struct clone_args", -0x90),
            "clone_args_90"
        );
        assert_eq!(
            synthesize_local_name("union epoll_data", -16),
            "epoll_data_10"
        );
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
    fn apply_bindings_rewrites_wide_union_store_to_member_not_aggregate() {
        // A whole 8-byte store to the `data` union of `struct epoll_event`
        // (struct offset 4, access size 8) used to emit
        // `epoll_event_14.data = value` — but `data` is a union, so naming
        // the union by itself is not a valid C lvalue assignment from a
        // scalar. The recogniser now descends into the union and picks the
        // first member matching the access size; for the size-8 case that's
        // the `u64` member.
        let lhs = Expr {
            kind: ExprKind::ArrayAccess {
                base: Box::new(Expr::var(Variable::reg("rbp", 8))),
                index: Box::new(Expr::int(-2)), // -2 * 8 = -16 → struct offset 4
                element_size: 8,
            },
        };
        let store = Expr::assign(lhs, Expr::unknown("data_u64"));
        let body = vec![block(vec![store, epoll_ctl_with_stack_arg()])];
        let out = run_apply(body);
        let StructuredNode::Block { statements, .. } = &out[0] else {
            panic!("expected block")
        };
        let ExprKind::Assign { lhs, .. } = &statements[0].kind else {
            panic!("expected Assign")
        };
        // LHS shape must be FieldAccess(FieldAccess(<local>, "data", 4), "u64", 0)
        // — never the bare FieldAccess(<local>, "data", 4) that previously
        // surfaced as `.data = …`.
        let ExprKind::FieldAccess {
            base, field_name, ..
        } = &lhs.kind
        else {
            panic!("expected nested FieldAccess LHS, got {:?}", lhs.kind)
        };
        // The union has `ptr` (8) / `fd` (4) / `u32` (4) / `u64` (8) in that
        // declaration order; the recogniser picks the FIRST member matching
        // access_size, so the canonical 8-byte rewrite resolves to `.data.ptr`
        // (not `.data.u64`). Either is valid C — `ptr` mirrors source order.
        assert_eq!(
            field_name, "ptr",
            "wide store must select the first size-matching union member"
        );
        let ExprKind::FieldAccess {
            field_name: outer, ..
        } = &base.kind
        else {
            panic!("expected union FieldAccess as base, got {:?}", base.kind)
        };
        assert_eq!(outer, "data", "outer hop should be the union container");
    }

    #[test]
    fn struct_size_in_db_handles_unions_and_chained_typedefs() {
        // `union epoll_data` is registered directly + via the typedef
        // `epoll_data_t` → `CType::Named("union epoll_data")` → `Typedef`
        // chain. The fixed helper recursively peels typedefs and accepts
        // unions, so both names resolve to the underlying 8-byte size.
        let db = full_db();
        let direct =
            struct_size_in_db(&db, "union epoll_data").expect("union epoll_data must resolve");
        let via_typedef =
            struct_size_in_db(&db, "epoll_data_t").expect("epoll_data_t typedef must resolve");
        assert_eq!(
            direct, 8,
            "union epoll_data is 8 bytes (largest member u64)"
        );
        assert_eq!(
            via_typedef, direct,
            "typedef must resolve to underlying size"
        );
    }

    #[test]
    fn apply_bindings_leaves_interior_union_byte_store_untouched() {
        // `mov dword [rbp - 12], 0x5a5a5a5a` at struct offset 8 → inside the
        // data union at union sub-offset 4. No top-level member starts at
        // offset 4 in the union, so the FieldAccess rewrite intentionally
        // bails (an upper-half-of-u64 access has no clean C member name).
        // A non-zero RHS is used here because zero stores at interior
        // offsets get filtered out by the shadow-zero-init suppression
        // (the `apply_bindings_drops_interior_shadow_zero_store` test
        // covers that path); this test exercises the orthogonal "no field
        // match at this offset, no rewrite" path.
        let lhs = Expr {
            kind: ExprKind::ArrayAccess {
                base: Box::new(Expr::var(Variable::reg("rbp", 8))),
                index: Box::new(Expr::int(-3)),
                element_size: 4,
            },
        };
        let store = Expr::assign(lhs, Expr::int(0x5a5a5a5a));
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
    fn apply_bindings_drops_interior_shadow_zero_store() {
        // `local_c = 0` lifts as ArrayAccess(rbp, -3, 4) = 0 at struct offset 8
        // inside the data union (sub-offset 4) — no clean field match. The
        // statement is dropped so the emitter doesn't declare `int local_c;`.
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
        // Only the call should remain (the interior zero was dropped).
        assert_eq!(
            statements.len(),
            1,
            "expected only the call, got {statements:#?}"
        );
        assert!(matches!(statements[0].kind, ExprKind::Call { .. }));
    }

    #[test]
    fn apply_bindings_keeps_interior_nonzero_store_untouched() {
        // A NON-zero store at an interior offset is meaningful and must be
        // preserved (only zero-init noise is dropped).
        let lhs = Expr {
            kind: ExprKind::ArrayAccess {
                base: Box::new(Expr::var(Variable::reg("rbp", 8))),
                index: Box::new(Expr::int(-3)),
                element_size: 4,
            },
        };
        let store = Expr::assign(lhs, Expr::int(7));
        let body = vec![block(vec![store, epoll_ctl_with_stack_arg()])];
        let out = run_apply(body);
        let StructuredNode::Block { statements, .. } = &out[0] else {
            panic!("expected block")
        };
        assert_eq!(statements.len(), 2, "non-zero interior store must be kept");
    }

    #[test]
    fn apply_bindings_rewrites_wide_base_zero_to_memset() {
        // `*(uint64_t*)(rbp - 20) = 0` lifts as Deref(Add(rbp,-20), 8) = 0 at
        // the base of the bound epoll_event_14 region (size 12). Size 8 ≠
        // events field size (4), so no clean field rewrite → memset.
        let lhs = Expr::deref(rbp_plus(-20), 8);
        let store = Expr::assign(lhs, Expr::int(0));
        let body = vec![block(vec![store, epoll_ctl_with_stack_arg()])];
        let out = run_apply(body);
        let StructuredNode::Block { statements, .. } = &out[0] else {
            panic!("expected block")
        };
        let ExprKind::Call { target, args } = &statements[0].kind else {
            panic!("expected Call (memset), got {:?}", statements[0].kind)
        };
        let CallTarget::Named(name) = target else {
            panic!("expected Named target")
        };
        assert_eq!(name, "memset");
        assert_eq!(args.len(), 3);
        let ExprKind::AddressOf(inner) = &args[0].kind else {
            panic!("first memset arg should be AddressOf")
        };
        let ExprKind::Var(v) = &inner.kind else {
            panic!("AddressOf inner should be Var")
        };
        assert_eq!(v.name, "epoll_event_14");
        assert!(matches!(args[1].kind, ExprKind::IntLit(0)));
        assert!(matches!(args[2].kind, ExprKind::IntLit(12)));
    }

    #[test]
    fn apply_bindings_keeps_base_zero_with_exact_field_size_as_field_assign() {
        // A 4-byte zero store at the base of the region lines up exactly with
        // the `events` field (offset 0, size 4) → MUST become
        // `epoll_event_14.events = 0`, NOT a memset.
        let lhs = Expr {
            kind: ExprKind::ArrayAccess {
                base: Box::new(Expr::var(Variable::reg("rbp", 8))),
                index: Box::new(Expr::int(-5)),
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
            panic!("expected Assign, got {:?}", statements[0].kind)
        };
        let ExprKind::FieldAccess { field_name, .. } = &lhs.kind else {
            panic!("expected FieldAccess LHS, got {:?}", lhs.kind)
        };
        assert_eq!(field_name, "events");
    }

    #[test]
    fn apply_bindings_leaves_wide_base_nonzero_store_untouched() {
        // A non-zero wide store at the base must NOT be rewritten — it's a
        // legitimate write to that prefix of the struct, not a zero-init.
        let lhs = Expr::deref(rbp_plus(-20), 8);
        let store = Expr::assign(lhs, Expr::int(0xdeadbeef));
        let body = vec![block(vec![store, epoll_ctl_with_stack_arg()])];
        let out = run_apply(body);
        let StructuredNode::Block { statements, .. } = &out[0] else {
            panic!("expected block")
        };
        // First stmt should still be the wide-store Assign (with the address
        // rewritten through Case B from `rbp + -20` to `&epoll_event_14`).
        let ExprKind::Assign { lhs, .. } = &statements[0].kind else {
            panic!("expected Assign, got {:?}", statements[0].kind)
        };
        assert!(matches!(lhs.kind, ExprKind::Deref { .. }));
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

    // ----- Smart-pointer binding tests ---------------------------------

    #[test]
    fn smart_pointer_parser_recognises_shared_unique_weak() {
        for (name, expected_kind, expected_inner) in [
            (
                "std::shared_ptr<Widget>::reset()",
                SmartPointerKind::Shared,
                "Widget",
            ),
            (
                "std::unique_ptr<int>::get() const",
                SmartPointerKind::Unique,
                "int",
            ),
            (
                "std::weak_ptr<Widget>::lock() const",
                SmartPointerKind::Weak,
                "Widget",
            ),
            // libstdc++ internal base class
            (
                "std::__shared_ptr<Widget, std::allocator<Widget>(int)>::reset()",
                SmartPointerKind::Shared,
                "Widget",
            ),
            (
                "std::__weak_ptr<int, std::__atomic>::lock() const",
                SmartPointerKind::Weak,
                "int",
            ),
            // Stateful deleter on unique_ptr — still extract the first template
            // argument as the inner type.
            (
                "std::unique_ptr<Widget, std::default_delete<Widget>>::operator->()",
                SmartPointerKind::Unique,
                "Widget",
            ),
            // Nested template type as the inner argument.
            (
                "std::shared_ptr<std::vector<int>>::operator*() const",
                SmartPointerKind::Shared,
                "std::vector<int>",
            ),
        ] {
            let parsed = parse_smart_pointer_kind_and_inner(name)
                .unwrap_or_else(|| panic!("parser declined valid smart-pointer name: {name}"));
            assert_eq!(parsed.0, expected_kind, "kind mismatch on {name}");
            assert_eq!(parsed.1, expected_inner, "inner mismatch on {name}");
        }
    }

    #[test]
    fn smart_pointer_parser_declines_unrelated_names() {
        for name in [
            "memcpy",
            "std::vector<int>::push_back(int const&)",
            "std::shared_ptr<Widget>", // type ref, not a ::method call
            "std::make_shared<Widget>(int, int)", // free function
            "MyClass::shared_ptr_helper", // unrelated suffix
        ] {
            assert!(
                parse_smart_pointer_kind_and_inner(name).is_none(),
                "parser accepted non-smart-pointer name: {name}"
            );
        }
    }

    #[test]
    fn binds_stack_this_arg_for_shared_ptr_method_call() {
        // `std::shared_ptr<Widget>::reset(this, …)` where `this` is a stack
        // address binds [rbp-32, rbp-32+16) as `std::shared_ptr<Widget>`.
        let call = Expr::call(
            CallTarget::Named("std::shared_ptr<Widget>::reset()".to_string()),
            vec![rbp_plus(-32)],
        );

        let mut bindings = StackStructBindings::new();
        bindings.analyze(&[block(vec![call])], &full_db(), None);

        assert_eq!(bindings.len(), 1, "expected one binding");
        let b = bindings.get(-32).expect("binding at -32");
        assert_eq!(b.type_name, "std::shared_ptr<Widget>");
        assert_eq!(b.size, 16, "shared_ptr = ptr + control_block");
        assert_eq!(b.local_name, "Widget_shared_ptr_20");
    }

    #[test]
    fn binds_stack_this_arg_for_unique_ptr_method_call() {
        let call = Expr::call(
            CallTarget::Named("std::unique_ptr<int>::get() const".to_string()),
            vec![rbp_plus(-8)],
        );

        let mut bindings = StackStructBindings::new();
        bindings.analyze(&[block(vec![call])], &full_db(), None);

        let b = bindings.get(-8).expect("binding at -8");
        assert_eq!(b.type_name, "std::unique_ptr<int>");
        assert_eq!(b.size, 8, "unique_ptr = bare data pointer");
    }

    #[test]
    fn does_not_bind_smart_pointer_when_this_arg_is_not_stack_address() {
        // First arg is a plain Var (a register-held pointer), not `rbp + K`.
        let call = Expr::call(
            CallTarget::Named("std::shared_ptr<Widget>::reset()".to_string()),
            vec![Expr::var(Variable::reg("rdi", 8))],
        );
        let mut bindings = StackStructBindings::new();
        bindings.analyze(&[block(vec![call])], &full_db(), None);
        assert_eq!(
            bindings.len(),
            0,
            "must not bind when this is not a stack address"
        );
    }

    /// Codex review on PR #24: a smart-pointer binding sitting at the same
    /// offset as a zero store must NOT trigger the C-struct memset/drop
    /// rewrite — a zero into a `std::shared_ptr<T>` slot is the default
    /// constructor or move-from-nullptr, not aggregate zero-init padding.
    #[test]
    fn class_object_binding_skips_struct_memset_rewrite() {
        let binding = StackStructBinding {
            stack_offset: -16,
            size: 16,
            type_name: "std::shared_ptr<Widget>".to_string(),
            local_name: "Widget_shared_ptr_10".to_string(),
            class_object: true,
        };
        let mut bindings = StackStructBindings::new();
        bindings.by_offset.insert(binding.stack_offset, binding);

        // A wide zero store at the base of the bound region — would be
        // rewritten to memset for a regular struct, must be left alone here.
        let stmt = Expr::assign(Expr::deref(rbp_plus(-16), 8), Expr::int(0));
        assert!(
            try_rewrite_base_zero_to_memset(&stmt, &bindings, &full_db()).is_none(),
            "class_object binding must not trigger memset rewrite"
        );

        // An interior zero store inside the region — would be dropped for a
        // regular struct, must be kept here.
        let interior = Expr::assign(Expr::deref(rbp_plus(-8), 4), Expr::int(0));
        assert!(
            !is_droppable_interior_zero_store(&interior, &bindings),
            "class_object binding must not silence interior zero stores"
        );
    }

    /// `weak_ptr<T>::lock()` returns `shared_ptr<T>` by value, so the
    /// SysV / Itanium ABI passes the destination's address as `args[0]`
    /// and the receiver as `args[1]`. The binder must decline rather
    /// than bind the destination's stack region as the receiver type.
    #[test]
    fn does_not_bind_sret_returning_smart_pointer_method_call() {
        let call = Expr::call(
            CallTarget::Named("std::weak_ptr<Widget>::lock() const".to_string()),
            vec![rbp_plus(-16), rbp_plus(-32)],
        );
        let mut bindings = StackStructBindings::new();
        bindings.analyze(&[block(vec![call])], &full_db(), None);
        assert_eq!(
            bindings.len(),
            0,
            "must not bind for sret-returning methods: {:#?}",
            bindings.iter().collect::<Vec<_>>()
        );
    }

    /// `std::unique_ptr<T, StatefulDeleter>` can be larger than one
    /// pointer when the deleter has state. A flat 8-byte binding
    /// would absorb adjacent stack locals. Decline non-default
    /// deleters; the canonical default (`std::default_delete<T>`,
    /// EBO'd to 0 bytes) still binds normally.
    #[test]
    fn smart_pointer_parser_declines_stateful_unique_ptr_deleter() {
        assert!(parse_smart_pointer_kind_and_inner(
            "std::unique_ptr<Widget, MyStatefulDeleter>::reset()"
        )
        .is_none());
        assert_eq!(
            parse_smart_pointer_kind_and_inner(
                "std::unique_ptr<Widget, std::default_delete<Widget>>::reset()"
            ),
            Some((SmartPointerKind::Unique, "Widget".to_string()))
        );
    }

    /// Codex review on PR #24: relocation-table lookups can hand the
    /// binder a raw Itanium-ABI mangled symbol like
    /// `_ZNSt10shared_ptrI6WidgetE5resetEv` (the symbol table
    /// pre-demangles, but the relocation map doesn't), and the
    /// parser only recognises demangled `std::...` shapes. Demangle
    /// on entry so a relocated C++ call in a `.o` file still binds.
    #[test]
    fn binds_when_resolved_name_is_raw_mangled_itanium_symbol() {
        // _ZNSt10shared_ptrI6WidgetE5resetEv ≡ std::shared_ptr<Widget>::reset()
        let call = Expr::call(
            CallTarget::Named("_ZNSt10shared_ptrI6WidgetE5resetEv".to_string()),
            vec![rbp_plus(-16)],
        );
        let mut bindings = StackStructBindings::new();
        bindings.analyze(&[block(vec![call])], &full_db(), None);
        let b = bindings.get(-16).expect("binding at -16");
        assert_eq!(b.type_name, "std::shared_ptr<Widget>");
        assert_eq!(b.size, 16);
    }

    /// Codex review on PR #24: the Itanium demangler emits a space
    /// before the qualifier for nested template closings
    /// (`unique_ptr<int, std::default_delete<int> >::get()`,
    /// `shared_ptr<std::vector<int> >::reset()`), so my
    /// `starts_with("::")` check rejected the most common
    /// default-deleter `unique_ptr` and nested-template shapes.
    /// Trim leading whitespace before the qualifier check.
    #[test]
    fn smart_pointer_parser_handles_demangler_space_before_qualifier() {
        // Default-deleter unique_ptr in the Itanium demangler form.
        assert_eq!(
            parse_smart_pointer_kind_and_inner(
                "std::unique_ptr<int, std::default_delete<int> >::get()"
            ),
            Some((SmartPointerKind::Unique, "int".to_string())),
        );
        // shared_ptr of a nested template type.
        assert_eq!(
            parse_smart_pointer_kind_and_inner("std::shared_ptr<std::vector<int> >::reset()"),
            Some((SmartPointerKind::Shared, "std::vector<int>".to_string())),
        );
    }

    /// Codex review on PR #24: a non-member function whose demangled
    /// parameter list contains a smart-pointer type as a nested
    /// qualifier (e.g. `foo(std::shared_ptr<Widget>::element_type*)`)
    /// would match — the parser only required `::` after the
    /// template, which is satisfied by the `::element_type` suffix.
    /// Require the match to be before the first `(` so we only pick
    /// up the actually-called method.
    #[test]
    fn smart_pointer_parser_declines_match_inside_argument_list() {
        assert!(
            parse_smart_pointer_kind_and_inner("foo(std::shared_ptr<Widget>::element_type*)")
                .is_none(),
            "match inside an argument list must not bind: {:?}",
            parse_smart_pointer_kind_and_inner("foo(std::shared_ptr<Widget>::element_type*)")
        );
        // Real method call still matches.
        assert_eq!(
            parse_smart_pointer_kind_and_inner("std::shared_ptr<Widget>::reset()"),
            Some((SmartPointerKind::Shared, "Widget".to_string()))
        );
    }

    /// Codex review on PR #24: a Deref of a class-object stack address
    /// (`*(rbp - 16) = 0`, byte-level ctor zero) must NOT be rewritten
    /// through `AddressOf(local)`, because the emitter would render it
    /// as the visually-confusing `qword(&sp) = 0`. Stay-raw so the
    /// byte view survives. Bare addresses outside a Deref context
    /// (call-arg form like `reset(rbp + -16)`) DO rewrite to
    /// `&<local>` so the typed local is actually referenced and the
    /// emitter declaration pass keeps it.
    #[test]
    fn transform_expr_leaves_class_object_deref_lvalues_raw() {
        let binding = StackStructBinding {
            stack_offset: -16,
            size: 16,
            type_name: "std::shared_ptr<Widget>".to_string(),
            local_name: "Widget_shared_ptr_10".to_string(),
            class_object: true,
        };
        let mut bindings = StackStructBindings::new();
        bindings.by_offset.insert(binding.stack_offset, binding);

        // 1. A bare address `Add(rbp, -16)` (call-arg form) DOES
        //    rewrite — the typed local needs at least one reference
        //    for the emitter to keep its declaration.
        let bare = rbp_plus(-16);
        let bare_out = transform_expr(&bare, &bindings, &full_db());
        assert!(
            matches!(&bare_out.kind, ExprKind::AddressOf(_)),
            "bare class-object address (call-arg form) should rewrite to &<local>: {bare_out:?}"
        );

        // 2. A Deref of that address (`*(rbp - 16)`) stays raw so the
        //    byte view doesn't show as `qword(&sp)`.
        let deref = Expr::deref(rbp_plus(-16), 8);
        let deref_out = transform_expr(&deref, &bindings, &full_db());
        match &deref_out.kind {
            ExprKind::Deref { addr, .. } => {
                assert!(
                    matches!(&addr.kind, ExprKind::BinOp { .. }),
                    "Deref's address should stay raw, got {addr:?}"
                );
            }
            other => panic!("expected Deref to survive: got {other:?}"),
        }
    }

    /// Codex review on PR #24: the parser used an unconstrained
    /// `name.find(prefix)`, so a user type like
    /// `mystd::shared_ptr<Widget>` would match the embedded
    /// `std::shared_ptr` substring at offset 2 and bind the stack slot
    /// as a real `std::shared_ptr<Widget>`. The match must be anchored
    /// at a class-qualifier boundary (position 0 or after a
    /// non-identifier byte).
    #[test]
    fn smart_pointer_parser_does_not_match_substring_in_user_type() {
        assert!(
            parse_smart_pointer_kind_and_inner("mystd::shared_ptr<Widget>::reset()").is_none(),
            "user type containing std::shared_ptr substring must not match"
        );
        // Sanity: the real std qualifier still matches.
        assert_eq!(
            parse_smart_pointer_kind_and_inner("std::shared_ptr<Widget>::reset()"),
            Some((SmartPointerKind::Shared, "Widget".to_string()))
        );
    }

    /// Binding size derives from the target's pointer width
    /// (`db.arch().pointer_size`), not a hardcoded constant. On 32-bit
    /// builds `unique_ptr<T>` is 4 bytes, `shared_ptr<T>` / `weak_ptr<T>`
    /// are 8 — using the 64-bit value would absorb adjacent stack
    /// locals.
    #[test]
    fn smart_pointer_binding_size_tracks_db_pointer_width() {
        use hexray_types::database::ArchInfo;
        let db32 = TypeDatabase::with_arch(ArchInfo::ilp32());
        let call_shared = Expr::call(
            CallTarget::Named("std::shared_ptr<Widget>::reset()".to_string()),
            vec![rbp_plus(-16)],
        );
        let mut bindings = StackStructBindings::new();
        bindings.analyze(&[block(vec![call_shared])], &db32, None);
        assert_eq!(
            bindings.get(-16).expect("binding").size,
            8,
            "shared_ptr on 32-bit = 2 * 4 bytes"
        );

        let call_unique = Expr::call(
            CallTarget::Named("std::unique_ptr<int>::get() const".to_string()),
            vec![rbp_plus(-8)],
        );
        let mut bindings = StackStructBindings::new();
        bindings.analyze(&[block(vec![call_unique])], &db32, None);
        assert_eq!(
            bindings.get(-8).expect("binding").size,
            4,
            "unique_ptr on 32-bit = 1 * 4 bytes"
        );
    }

    // ----- std::optional / std::variant binding tests ------------------

    #[test]
    fn optional_variant_parser_recognises_member_calls() {
        // optional: single template arg, various method shapes incl. the
        // constructor's own method-template clause and a `const` suffix.
        for (name, expect) in [
            ("std::optional<int>::has_value() const", vec!["int"]),
            ("std::optional<int>::optional<int, true>()", vec!["int"]),
            ("std::optional<double>::operator*()", vec!["double"]),
            (
                "std::optional<std::vector<int> >::value()",
                vec!["std::vector<int>"],
            ),
        ] {
            let (kind, args, _method) = parse_optional_variant_kind_and_args(name)
                .unwrap_or_else(|| panic!("parser declined valid optional name: {name}"));
            assert_eq!(kind, OptVarKind::Optional, "kind mismatch on {name}");
            assert_eq!(args, expect, "args mismatch on {name}");
        }
        // variant: full alternative list preserved, nested commas honoured.
        for (name, expect) in [
            (
                "std::variant<int, double>::index() const",
                vec!["int", "double"],
            ),
            (
                "std::variant<int, double>::operator=<int>()",
                vec!["int", "double"],
            ),
            (
                "std::variant<int, std::pair<int, double> >::index() const",
                vec!["int", "std::pair<int, double>"],
            ),
        ] {
            let (kind, args, _method) = parse_optional_variant_kind_and_args(name)
                .unwrap_or_else(|| panic!("parser declined valid variant name: {name}"));
            assert_eq!(kind, OptVarKind::Variant, "kind mismatch on {name}");
            assert_eq!(args, expect, "args mismatch on {name}");
        }
    }

    /// Codex P2 on PR #43: `rsplit_once("::")` on the whole signature splits
    /// inside a namespaced parameter type (`ns::S`), so `value_or` went
    /// undetected and the sret return buffer (`args[0]`) was bound as the
    /// optional. The method name must come from the receiver qualifier.
    #[test]
    fn parses_method_name_past_namespaced_param_type() {
        let (kind, args, method) =
            parse_optional_variant_kind_and_args("std::optional<ns::S>::value_or(ns::S&&) const")
                .expect("must parse");
        assert_eq!(kind, OptVarKind::Optional);
        assert_eq!(args, vec!["ns::S"]);
        assert_eq!(method, "value_or");
    }

    #[test]
    fn declines_object_value_or_with_namespaced_param() {
        // value_or returning a non-scalar object → assume sret → args[0] is the
        // return buffer, not `this`. Must decline (even with the namespaced
        // parameter type that previously masked the value_or detection).
        let call = Expr::call(
            CallTarget::Named("std::optional<ns::S>::value_or(ns::S&&) const".to_string()),
            vec![rbp_plus(-16), rbp_plus(-32)],
        );
        let mut bindings = StackStructBindings::new();
        bindings.analyze(&[block(vec![call])], &full_db(), None);
        assert_eq!(bindings.len(), 0, "object value_or must decline");
    }

    /// Codex P2 on PR #43: a demangled member name may lead with a return
    /// type that itself mentions the same template (the receiver qualifier
    /// follows it). The parser must skip the return-type occurrence — which is
    /// followed by `&`/`>`, not `::` — and the parens inside the return type,
    /// and bind from the real receiver qualifier.
    #[test]
    fn optional_variant_parser_finds_receiver_past_return_type() {
        let name = "std::enable_if<(true), std::variant<int, double>&>::type \
                    std::variant<int, double>::operator=<int>(int&&)";
        let (kind, args, method) = parse_optional_variant_kind_and_args(name)
            .expect("must find the receiver qualifier past the return type");
        assert_eq!(kind, OptVarKind::Variant);
        assert_eq!(args, vec!["int", "double"]);
        assert_eq!(method, "operator");
    }

    #[test]
    fn optional_variant_parser_declines_unrelated_names() {
        for name in [
            "memcpy",
            "std::optional<int>",                        // type ref, not ::method
            "std::variant<int, double>",                 // type ref, not ::method
            "mystd::optional<int>::has_value()",         // not anchored at boundary
            "foo(std::optional<int>::value_type*)",      // nested in an arg list
            "std::vector<int>::push_back(int const&)",   // unrelated template
            // Free function whose RETURN TYPE spells the template, with a
            // space-separated function name — the `(` belongs to `make_value`,
            // not to a method on the qualifier (codex P2 on PR #43).
            "std::optional<int>::value_type make_value(int*)",
            "std::variant<int, double>::type build(int*, double*)",
        ] {
            assert!(
                parse_optional_variant_kind_and_args(name).is_none(),
                "parser accepted unrelated name: {name}"
            );
        }
    }

    #[test]
    fn binds_stack_this_arg_for_optional_method_call() {
        // sizeof(optional<int>) == 8 (4 payload + engaged@4 + pad).
        let call = Expr::call(
            CallTarget::Named("std::optional<int>::has_value() const".to_string()),
            vec![rbp_plus(-24)],
        );
        let mut bindings = StackStructBindings::new();
        bindings.analyze(&[block(vec![call])], &full_db(), None);

        let b = bindings.get(-24).expect("binding at -24");
        assert_eq!(b.type_name, "std::optional<int>");
        assert_eq!(b.size, 8, "optional<int> = align_up(4 + 1, 4)");
        assert!(b.class_object, "optional is a class object");
        assert_eq!(b.local_name, "int_optional_18");
    }

    /// Codex P2 on PR #43: `operator->` (and `operator<`, `operator<<`, …)
    /// contain `>`/`<`, which the angle-depth scan mistook for template
    /// brackets, so the method `(` was never found and the binding was missed.
    /// `optional<int>::operator->()` is a common `-O0` access path.
    #[test]
    fn binds_optional_accessed_via_arrow_and_angle_operators() {
        for name in [
            "std::optional<int>::operator->()",
            "std::optional<int>::operator*() const",
            "std::optional<int>::operator bool() const",
        ] {
            let call =
                Expr::call(CallTarget::Named(name.to_string()), vec![rbp_plus(-24)]);
            let mut bindings = StackStructBindings::new();
            bindings.analyze(&[block(vec![call])], &full_db(), None);
            let b = bindings
                .get(-24)
                .unwrap_or_else(|| panic!("must bind via operator: {name}"));
            assert_eq!(b.type_name, "std::optional<int>");
            assert_eq!(b.size, 8);
        }
    }

    #[test]
    fn binds_stack_this_arg_for_optional_double_method_call() {
        // sizeof(optional<double>) == 16 (8 payload + engaged@8 + pad).
        let call = Expr::call(
            CallTarget::Named("std::optional<double>::value()".to_string()),
            vec![rbp_plus(-32)],
        );
        let mut bindings = StackStructBindings::new();
        bindings.analyze(&[block(vec![call])], &full_db(), None);
        let b = bindings.get(-32).expect("binding at -32");
        assert_eq!(b.type_name, "std::optional<double>");
        assert_eq!(b.size, 16, "optional<double> = align_up(8 + 1, 8)");
    }

    #[test]
    fn binds_stack_this_arg_for_variant_method_call() {
        // sizeof(variant<int, double>) == 16 (8 union payload + index@8).
        let call = Expr::call(
            CallTarget::Named("std::variant<int, double>::index() const".to_string()),
            vec![rbp_plus(-24)],
        );
        let mut bindings = StackStructBindings::new();
        bindings.analyze(&[block(vec![call])], &full_db(), None);

        let b = bindings.get(-24).expect("binding at -24");
        assert_eq!(b.type_name, "std::variant<int, double>");
        assert_eq!(b.size, 16, "variant<int, double> = align_up(8 + 1, 8)");
        assert!(b.class_object, "variant is a class object");
    }

    /// Codex P2 on PR #43: when the largest-sized alternative is not the
    /// most-aligned one, the union is padded to its alignment *before* the
    /// discriminator. `variant<S, double>` with `S` = 12 bytes / 4-aligned and
    /// `double` = 8 / 8-aligned: union = align_up(12, 8) = 16, variant =
    /// align_up(16 + 1, 8) = 24 — not align_up(12 + 1, 8) = 16.
    #[test]
    fn variant_layout_pads_union_before_discriminator() {
        use hexray_types::types::StructType;
        let mut db = full_db();
        let s = StructType {
            name: Some("S".to_string()),
            fields: vec![],
            size: 12,
            alignment: 4,
            packed: false,
        };
        db.add_type("S", CType::Struct(s));
        // sanity: the DB sizes S as 12/4.
        assert_eq!(inner_type_size_align(&db, "S"), Some((12, 4)));
        assert_eq!(
            variant_layout_size(&db, &["S".into(), "double".into()]),
            Some(24)
        );
    }

    /// Codex P2 on PR #43: a template argument that is a typedef whose target
    /// is stored as `CType::Named` (e.g. `epoll_data_t -> union epoll_data`)
    /// must follow the `Named` reference back through the DB, like
    /// `struct_size_in_db` does — otherwise the binder declines a type the DB
    /// can size. `union epoll_data` is 8 bytes / 8-aligned, so
    /// `optional<epoll_data_t>` = align_up(8 + 1, 8) = 16.
    #[test]
    fn sizes_optional_of_typedef_alias_to_named_type() {
        let db = full_db();
        assert_eq!(inner_type_size_align(&db, "epoll_data_t"), Some((8, 8)));
        assert_eq!(optional_layout_size(&db, "epoll_data_t"), Some(16));
    }

    /// Codex P2 on PR #43: `CType::Pointer::size()` is hardcoded to 8, so a
    /// *named* alias to a pointer (`using P = int*`) resolved via the DB sized
    /// as 8 even on ILP32 — unlike the direct `int*` spelling, which uses the
    /// arch pointer width. `resolve_named_size_align` must use the target
    /// pointer size for resolved pointer types.
    #[test]
    fn sizes_named_pointer_alias_by_target_pointer_width() {
        use hexray_types::database::ArchInfo;
        let mut db64 = full_db();
        db64.add_type("IntPtrAlias", CType::ptr(CType::int()));
        assert_eq!(inner_type_size_align(&db64, "IntPtrAlias"), Some((8, 8)));
        assert_eq!(optional_layout_size(&db64, "IntPtrAlias"), Some(16));

        let mut db32 = TypeDatabase::with_arch(ArchInfo::ilp32());
        db32.add_type("IntPtrAlias", CType::ptr(CType::int()));
        // 4-byte pointer: align_up(4 + 1, 4) == 8, not 16.
        assert_eq!(inner_type_size_align(&db32, "IntPtrAlias"), Some((4, 4)));
        assert_eq!(optional_layout_size(&db32, "IntPtrAlias"), Some(8));
    }

    #[test]
    fn variant_layout_picks_largest_alternative() {
        // variant<char, char> == 2; variant<int, char> == 8.
        assert_eq!(
            variant_layout_size(&full_db(), &["char".into(), "char".into()]),
            Some(2)
        );
        assert_eq!(
            variant_layout_size(&full_db(), &["int".into(), "char".into()]),
            Some(8)
        );
        assert_eq!(
            variant_layout_size(
                &full_db(),
                &["int".into(), "int".into(), "double".into()]
            ),
            Some(16)
        );
    }

    /// Codex P2 on PR #43: the demangler spells a cv-qualified payload as
    /// `int const` / `int* const`, which misses both the scalar table and the
    /// DB. Top-level `const`/`volatile` must be stripped before sizing (a
    /// qualified type has the same layout as its unqualified form).
    #[test]
    fn sizes_cv_qualified_payloads() {
        let db = full_db();
        assert_eq!(optional_layout_size(&db, "int const"), Some(8));
        assert_eq!(optional_layout_size(&db, "const int"), Some(8));
        assert_eq!(optional_layout_size(&db, "int volatile"), Some(8));
        // const pointer → still a pointer (8 on LP64): align_up(8 + 1, 8) = 16.
        assert_eq!(optional_layout_size(&db, "int* const"), Some(16));
        // cv nested in a template arg is left alone (declines, unknown type).
        assert_eq!(optional_layout_size(&db, "std::vector<const int>"), None);
        // Token-boundary safety: `constant` is not a qualifier.
        assert_eq!(strip_top_level_cv("constant"), "constant");
        assert_eq!(strip_top_level_cv("int const"), "int");
        assert_eq!(strip_top_level_cv("const volatile int"), "int");
    }

    #[test]
    fn optional_layout_handles_pointer_and_char() {
        // optional<char> == 2, optional<int*> == 16 (ptr payload + flag + pad).
        assert_eq!(optional_layout_size(&full_db(), "char"), Some(2));
        assert_eq!(optional_layout_size(&full_db(), "int*"), Some(16));
    }

    /// Codex P2s on this PR: the 8-byte scalars' alignment is ABI-specific and
    /// not derivable from data-model sizes. On 32-bit it's ambiguous (i386 = 4,
    /// ARM32 = 8) so `double`/`long long` must DECLINE there rather than guess;
    /// pointers still size by the target width. On 64-bit (LP64 *and* LLP64)
    /// they are 8-aligned, so `optional<double>` = 16.
    #[test]
    fn scalar_layout_respects_target_abi() {
        use hexray_types::database::ArchInfo;

        // 32-bit: 8-byte scalars decline (ambiguous alignment), pointers size.
        let db32 = TypeDatabase::with_arch(ArchInfo::ilp32());
        assert_eq!(optional_layout_size(&db32, "double"), None);
        assert_eq!(optional_layout_size(&db32, "long long"), None);
        assert_eq!(
            variant_layout_size(&db32, &["int".into(), "double".into()]),
            None
        );
        // 4-byte pointer payload still binds: align_up(4 + 1, 4) == 8.
        assert_eq!(optional_layout_size(&db32, "int*"), Some(8));

        // LP64 and LLP64 both 8-align the 8-byte scalars → 16.
        for arch in [ArchInfo::lp64(), ArchInfo::llp64()] {
            let db = TypeDatabase::with_arch(arch);
            assert_eq!(optional_layout_size(&db, "double"), Some(16));
            assert_eq!(optional_layout_size(&db, "long long"), Some(16));
            assert_eq!(
                variant_layout_size(&db, &["int".into(), "double".into()]),
                Some(16)
            );
        }
    }

    /// Codex P2 (confirmatory pass) on PR #43: `long` is 8 on LP64 but 4 on
    /// LLP64 (Win64), and `wchar_t` is 4 on SysV but 2 on Windows. The binder's
    /// arch info can't distinguish the data models (the pipeline forces
    /// `long_size == pointer_size`), so these must decline rather than risk an
    /// oversized region. Standard-fixed widths (`int`, `long long`, `char32_t`)
    /// still size.
    #[test]
    fn declines_data_model_dependent_scalars() {
        let db = full_db();
        assert_eq!(optional_layout_size(&db, "long"), None);
        assert_eq!(optional_layout_size(&db, "unsigned long"), None);
        assert_eq!(optional_layout_size(&db, "wchar_t"), None);
        // Fixed-width scalars are unaffected.
        assert_eq!(optional_layout_size(&db, "int"), Some(8));
        assert_eq!(optional_layout_size(&db, "long long"), Some(16));
        assert_eq!(optional_layout_size(&db, "char32_t"), Some(8));
        // A variant whose alternative is data-model-dependent also declines.
        assert_eq!(
            variant_layout_size(&db, &["int".into(), "long".into()]),
            None
        );
    }

    #[test]
    fn declines_optional_when_inner_type_unsizable() {
        // `long double` is intentionally not in the scalar table (16-byte
        // alignment on x86-64 SysV is not modelled), and an unknown user
        // type can't be sized — both must decline rather than mis-size.
        assert_eq!(optional_layout_size(&full_db(), "long double"), None);
        assert_eq!(optional_layout_size(&full_db(), "CompletelyUnknownType"), None);

        let call = Expr::call(
            CallTarget::Named("std::optional<long double>::has_value() const".to_string()),
            vec![rbp_plus(-32)],
        );
        let mut bindings = StackStructBindings::new();
        bindings.analyze(&[block(vec![call])], &full_db(), None);
        assert_eq!(bindings.len(), 0, "must not bind an unsizable optional");
    }

    #[test]
    fn does_not_bind_optional_when_this_arg_is_not_stack_address() {
        let call = Expr::call(
            CallTarget::Named("std::optional<int>::has_value() const".to_string()),
            vec![Expr::var(Variable::reg("rdi", 8))],
        );
        let mut bindings = StackStructBindings::new();
        bindings.analyze(&[block(vec![call])], &full_db(), None);
        assert_eq!(bindings.len(), 0, "must not bind a register this");
    }

    /// `optional<Obj>::value_or(U&&)` returning a non-trivial *object* by value
    /// uses sret: `args[0]` is the return buffer, the receiver is `args[1]`.
    /// The binder must decline rather than type the return buffer's stack
    /// region as the optional. (`Obj` is unknown to the DB → object-by-value.)
    #[test]
    fn does_not_bind_sret_returning_object_value_or() {
        let call = Expr::call(
            CallTarget::Named("std::optional<Obj>::value_or(Obj&&) const".to_string()),
            vec![rbp_plus(-16), rbp_plus(-32)],
        );
        let mut bindings = StackStructBindings::new();
        bindings.analyze(&[block(vec![call])], &full_db(), None);
        assert_eq!(
            bindings.len(),
            0,
            "must not bind for sret-returning object value_or: {:#?}",
            bindings.iter().collect::<Vec<_>>()
        );
    }

    /// Codex P2 on this PR: `optional<int>::value_or(int)` returns a *scalar*
    /// in registers — no hidden sret — so `args[0]` is still the stack `this`.
    /// Binding it is safe and declining would miss the optional entirely. The
    /// receiver region must bind as `std::optional<int>`.
    #[test]
    fn binds_scalar_value_or_optional() {
        let call = Expr::call(
            CallTarget::Named("std::optional<int>::value_or(int&&) const".to_string()),
            vec![rbp_plus(-24)],
        );
        let mut bindings = StackStructBindings::new();
        bindings.analyze(&[block(vec![call])], &full_db(), None);
        let b = bindings.get(-24).expect("scalar value_or must bind");
        assert_eq!(b.type_name, "std::optional<int>");
        assert_eq!(b.size, 8);
    }

    /// Codex P3 on PR #43: a cv-qualified scalar/pointer payload is still
    /// register-returned, so `value_or` on `int const` keeps `this` in
    /// `args[0]` and must bind (the sret guard strips cv like the sizing path).
    #[test]
    fn binds_cv_qualified_scalar_value_or() {
        assert!(is_register_returned_scalar("int const"));
        assert!(is_register_returned_scalar("int* const"));
        let call = Expr::call(
            CallTarget::Named("std::optional<int const>::value_or(int const&&) const".to_string()),
            vec![rbp_plus(-24)],
        );
        let mut bindings = StackStructBindings::new();
        bindings.analyze(&[block(vec![call])], &full_db(), None);
        let b = bindings.get(-24).expect("cv scalar value_or must bind");
        assert_eq!(b.type_name, "std::optional<int const>");
        assert_eq!(b.size, 8);
    }

    /// Codex P2 on PR #43: C++23 `optional<T>::transform/and_then/or_else`
    /// return a `std::optional<U>` by value (sret in `args[0]` for non-trivial
    /// `U`), and `U` isn't recoverable from the member name. The binder must
    /// decline these — even though `T` itself is a sizeable scalar — rather
    /// than type the sret return buffer as the optional.
    #[test]
    fn declines_optional_monadic_by_value_returns() {
        for method in ["transform", "and_then", "or_else"] {
            let name = format!("std::optional<int>::{method}<F>(F&&) const");
            let call = Expr::call(
                CallTarget::Named(name.clone()),
                // args[0] = hidden sret return buffer, args[1] = receiver.
                vec![rbp_plus(-16), rbp_plus(-32)],
            );
            let mut bindings = StackStructBindings::new();
            bindings.analyze(&[block(vec![call])], &full_db(), None);
            assert_eq!(bindings.len(), 0, "monadic {method} must decline");
        }
    }

    #[test]
    fn binds_optional_from_raw_mangled_itanium_symbol() {
        // _ZNSt8optionalIiE9has_valueEv ≡ std::optional<int>::has_value() const
        let call = Expr::call(
            CallTarget::Named("_ZNKSt8optionalIiE9has_valueEv".to_string()),
            vec![rbp_plus(-24)],
        );
        let mut bindings = StackStructBindings::new();
        bindings.analyze(&[block(vec![call])], &full_db(), None);
        let b = bindings.get(-24).expect("binding at -24");
        assert_eq!(b.type_name, "std::optional<int>");
        assert_eq!(b.size, 8);
    }
}
