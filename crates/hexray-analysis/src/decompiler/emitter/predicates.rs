//! Pure predicate / pattern-extraction helpers used by the
//! pseudo-code emitter.
//!
//! These functions classify expressions or names — recognizing
//! function-prologue/epilogue boilerplate, stack-canary patterns,
//! `_chk` failure call sites, ARM64 temp registers, and identifiers
//! the emitter chooses to declare. They take only `&Expr` / `&str`
//! and return `bool` / `Option<…>`, so they're trivially testable in
//! isolation.

use std::collections::HashSet;

use super::super::expression::{BinOpKind, CallTarget, Expr, ExprKind};
use super::super::structurer::StructuredNode;
use super::super::SymbolTable;

pub(super) fn format_condition(cond: &Expr) -> String {
    cond.to_string()
}

/// Extracts the stack variable name from an expression.
/// Handles both Var("var_4") and Deref patterns like [rbp - 0x4] → "var_4".
pub(super) fn get_stack_var_name(expr: &Expr) -> Option<String> {
    use super::super::expression::BinOpKind;

    match &expr.kind {
        ExprKind::Var(v) => {
            if v.name.starts_with("var_")
                || v.name.starts_with("arg_")
                || v.name.starts_with("local_")
            {
                Some(v.name.clone())
            } else {
                None
            }
        }
        ExprKind::Deref { addr, .. } => {
            // Check for base-only pattern (offset 0): just "sp" or "rsp"
            if let ExprKind::Var(base) = &addr.kind {
                if base.name == "sp" || base.name == "rsp" {
                    return Some("var_0".to_string());
                }
            }

            // Check for base + offset pattern
            if let ExprKind::BinOp { op, left, right } = &addr.kind {
                if let ExprKind::Var(base) = &left.kind {
                    // Frame pointers: rbp (x86-64), x29 (ARM64)
                    let is_frame_pointer = base.name == "rbp" || base.name == "x29";
                    // Stack pointer: sp (ARM64), rsp (x86-64)
                    let is_stack_pointer = base.name == "sp" || base.name == "rsp";

                    if is_frame_pointer || is_stack_pointer {
                        if let ExprKind::IntLit(offset) = &right.kind {
                            let actual_offset = match op {
                                BinOpKind::Add => *offset,
                                BinOpKind::Sub => -*offset,
                                _ => return None,
                            };

                            if is_frame_pointer {
                                // Frame pointer: locals at negative offsets, args at positive
                                if actual_offset < 0 {
                                    return Some(format!("local_{:x}", -actual_offset));
                                } else if actual_offset > 0 {
                                    return Some(format!("arg_{:x}", actual_offset));
                                }
                            } else {
                                // Stack pointer: locals at positive offsets
                                if actual_offset >= 0 {
                                    return Some(format!("var_{:x}", actual_offset));
                                }
                            }
                        }
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// Checks if a statement is a prologue pattern (push rbp, rbp = rsp, sp = sp - N, etc.)
pub(super) fn is_prologue_statement(expr: &Expr) -> bool {
    match &expr.kind {
        // push(rbp) - x86-64 prologue
        ExprKind::Call { target, args } => {
            if let CallTarget::Named(name) = target {
                if name == "push" {
                    if let Some(arg) = args.first() {
                        if let ExprKind::Var(v) = &arg.kind {
                            return v.name == "rbp";
                        }
                    }
                }
                // ARM64: stp (store pair) for x29, x30
                if name == "stp" {
                    return true;
                }
            }
            false
        }
        // Frame setup patterns for x86-64 and ARM64
        ExprKind::Assign { lhs, rhs } => {
            // ARM64: stur wzr, [x29 - N] - implicit return value initialization
            // This stores 0 (zero register) to a frame-relative location
            if let ExprKind::Deref { addr, .. } = &lhs.kind {
                if let ExprKind::BinOp {
                    op: super::super::expression::BinOpKind::Add,
                    left,
                    right,
                } = &addr.kind
                {
                    if let ExprKind::Var(base) = &left.kind {
                        if base.name == "x29" || base.name == "rbp" {
                            if let ExprKind::IntLit(offset) = &right.kind {
                                // Negative offset (frame-relative local) assigned 0 or zero register
                                if *offset < 0 {
                                    // Check for IntLit(0) or zero register (wzr/xzr)
                                    let is_zero = match &rhs.kind {
                                        ExprKind::IntLit(0) => true,
                                        ExprKind::Var(v) => v.name == "wzr" || v.name == "xzr",
                                        _ => false,
                                    };
                                    if is_zero {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ARM64: x29[-N] = 0 (ArrayAccess form of frame-relative zero initialization)
            if let ExprKind::ArrayAccess {
                base,
                index,
                element_size: _,
            } = &lhs.kind
            {
                if let ExprKind::Var(base_var) = &base.kind {
                    if base_var.name == "x29" || base_var.name == "rbp" {
                        if let ExprKind::IntLit(idx) = &index.kind {
                            // Negative index (or negative offset)
                            if *idx < 0 {
                                // Check for IntLit(0) or zero register
                                let is_zero = match &rhs.kind {
                                    ExprKind::IntLit(0) => true,
                                    ExprKind::Var(v) => v.name == "wzr" || v.name == "xzr",
                                    _ => false,
                                };
                                if is_zero {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }

            if let ExprKind::Var(lhs_var) = &lhs.kind {
                // x86-64: rbp = rsp (frame pointer setup)
                if lhs_var.name == "rbp" {
                    if let ExprKind::Var(rhs_var) = &rhs.kind {
                        return rhs_var.name == "rsp";
                    }
                }
                // x86-64: rsp = rsp - N (stack allocation)
                // ARM64: sp = sp - N or sp = N (stack allocation)
                if lhs_var.name == "rsp" || lhs_var.name == "sp" {
                    // sp = 0 or sp = constant (ARM64 sub sp, sp, #N becomes sp = 0 after structuring)
                    if let ExprKind::IntLit(_) = &rhs.kind {
                        return true;
                    }
                    if let ExprKind::BinOp { left, .. } = &rhs.kind {
                        if let ExprKind::Var(inner_var) = &left.kind {
                            if inner_var.name == "rsp" || inner_var.name == "sp" {
                                return true;
                            }
                        }
                    }
                }
                // ARM64: x29 = sp + N (frame pointer setup)
                if lhs_var.name == "x29" {
                    return true;
                }
                // ARM64: x30 = x29 (link register save pattern)
                if lhs_var.name == "x30" {
                    if let ExprKind::Var(rhs_var) = &rhs.kind {
                        if rhs_var.name == "x29" {
                            return true;
                        }
                    }
                }
            }
            false
        }
        // Compound assignment: rsp -= N or sp -= N (stack allocation)
        ExprKind::CompoundAssign { op, lhs, rhs } => {
            if let ExprKind::Var(lhs_var) = &lhs.kind {
                if lhs_var.name == "rsp" || lhs_var.name == "sp" {
                    // rsp -= N (stack allocation)
                    if matches!(op, super::super::expression::BinOpKind::Sub)
                        && matches!(rhs.kind, ExprKind::IntLit(_))
                    {
                        return true;
                    }
                }
            }
            false
        }
        _ => false,
    }
}

/// Checks if a statement is an epilogue pattern (pop rbp, rsp = rsp + N, ldp, etc.)
pub(super) fn is_epilogue_statement(expr: &Expr) -> bool {
    match &expr.kind {
        // pop(rbp) - x86-64 epilogue
        // ldp - ARM64 epilogue (load pair, restores x29/x30)
        ExprKind::Call { target, args } => {
            if let CallTarget::Named(name) = target {
                if name == "pop" {
                    if let Some(arg) = args.first() {
                        if let ExprKind::Var(v) = &arg.kind {
                            return v.name == "rbp";
                        }
                    }
                }
                // ARM64: ldp (load pair) for x29, x30
                if name == "ldp" {
                    return true;
                }
            }
            false
        }
        // Stack deallocation patterns
        ExprKind::Assign { lhs, rhs } => {
            if let ExprKind::Var(lhs_var) = &lhs.kind {
                // x86-64: rsp = rsp + N
                // ARM64: sp = sp + N
                if lhs_var.name == "rsp" || lhs_var.name == "sp" {
                    if let ExprKind::BinOp { left, .. } = &rhs.kind {
                        if let ExprKind::Var(inner_var) = &left.kind {
                            if inner_var.name == "rsp" || inner_var.name == "sp" {
                                return true;
                            }
                        }
                    }
                }
                // ARM64: x29 = x30 (restore frame pointer from link register)
                if lhs_var.name == "x29" {
                    if let ExprKind::Var(rhs_var) = &rhs.kind {
                        if rhs_var.name == "x30" {
                            return true;
                        }
                    }
                }
            }
            false
        }
        // Compound assignment: rsp += N or sp += N (stack deallocation)
        ExprKind::CompoundAssign { op, lhs, rhs } => {
            if let ExprKind::Var(lhs_var) = &lhs.kind {
                if lhs_var.name == "rsp" || lhs_var.name == "sp" {
                    // rsp += N (stack deallocation)
                    if matches!(op, super::super::expression::BinOpKind::Add)
                        && matches!(rhs.kind, ExprKind::IntLit(_))
                    {
                        return true;
                    }
                }
            }
            false
        }
        _ => false,
    }
}

/// Renames registers to more meaningful variable names.
/// Callee-saved registers used for return values/error codes get renamed.
/// Low-byte registers used as boolean temporaries get renamed to temp_N.
pub(super) fn rename_register(name: &str) -> String {
    let name_lower = name.to_lowercase();
    match name_lower.as_str() {
        // x86-64 return value register
        "eax" | "rax" => "ret".to_string(),
        // x86-64 callee-saved registers commonly used for error/result
        "ebx" | "rbx" => "err".to_string(),
        "r12" | "r12d" | "r12w" | "r12b" => "result".to_string(),
        "r13" | "r13d" | "r13w" | "r13b" => "saved1".to_string(),
        "r14" | "r14d" | "r14w" | "r14b" => "saved2".to_string(),
        "r15" | "r15d" | "r15w" | "r15b" => "saved3".to_string(),
        // x86-64 argument registers (64-bit only for function args)
        "rdi" => "arg0".to_string(),
        "rsi" => "arg1".to_string(),
        "rdx" => "arg2".to_string(),
        "rcx" => "arg3".to_string(),
        "r8" => "arg4".to_string(),
        "r9" => "arg5".to_string(),
        // ARM64 callee-saved registers (x19-x28)
        "x19" | "w19" => "err".to_string(),
        "x20" | "w20" => "result".to_string(),
        "x21" | "w21" => "saved1".to_string(),
        "x22" | "w22" => "saved2".to_string(),
        "x23" | "w23" => "saved3".to_string(),
        "x24" | "w24" => "saved4".to_string(),
        "x25" | "w25" => "saved5".to_string(),
        "x26" | "w26" => "saved6".to_string(),
        "x27" | "w27" => "saved7".to_string(),
        "x28" | "w28" => "saved8".to_string(),
        // ARM64 floating-point/SIMD callee-saved registers (d8-d15)
        "d8" => "fp_saved0".to_string(),
        "d9" => "fp_saved1".to_string(),
        "d10" => "fp_saved2".to_string(),
        "d11" => "fp_saved3".to_string(),
        "d12" => "fp_saved4".to_string(),
        "d13" => "fp_saved5".to_string(),
        "d14" => "fp_saved6".to_string(),
        "d15" => "fp_saved7".to_string(),
        // ARM64 frame pointer and link register (not user-visible but may leak through)
        "x29" | "w29" => "fp".to_string(),
        "x30" | "w30" => "lr".to_string(),
        // ARM64 temporary/scratch registers (x8-x17) - used for intermediate computations
        "x8" | "w8" => "tmp0".to_string(),
        "x9" | "w9" => "tmp1".to_string(),
        "x10" | "w10" => "tmp2".to_string(),
        "x11" | "w11" => "tmp3".to_string(),
        "x12" | "w12" => "tmp4".to_string(),
        "x13" | "w13" => "tmp5".to_string(),
        "x14" | "w14" => "tmp6".to_string(),
        "x15" | "w15" => "tmp7".to_string(),
        "x16" | "w16" => "tmp8".to_string(),
        "x17" | "w17" => "tmp9".to_string(),
        // x18 is the platform register (reserved on some OSes)
        "x18" | "w18" => "platform_reg".to_string(),
        // ARM64 argument registers (x0 is both arg0 and return value - treat as arg0 here,
        // return value handling is done separately by the return statement)
        "x0" | "w0" => "arg0".to_string(),
        "x1" | "w1" => "arg1".to_string(),
        "x2" | "w2" => "arg2".to_string(),
        "x3" | "w3" => "arg3".to_string(),
        "x4" | "w4" => "arg4".to_string(),
        "x5" | "w5" => "arg5".to_string(),
        "x6" | "w6" => "arg6".to_string(),
        "x7" | "w7" => "arg7".to_string(),
        // x86-64 low-byte and partial registers used as temporaries
        // These are often used for boolean conditions (setcc results)
        "al" | "ah" => "tmp_a".to_string(),
        "bl" | "bh" => "tmp_b".to_string(),
        "cl" | "ch" => "tmp_c".to_string(),
        "dl" | "dh" => "tmp_d".to_string(),
        "sil" => "tmp_si".to_string(),
        "dil" => "tmp_di".to_string(),
        "spl" => "tmp_sp".to_string(),
        "bpl" => "tmp_bp".to_string(),
        "r8b" | "r8w" => "tmp_r8".to_string(),
        "r9b" | "r9w" => "tmp_r9".to_string(),
        "r10b" | "r10w" => "tmp_r10".to_string(),
        "r11b" | "r11w" => "tmp_r11".to_string(),
        // 32-bit subregister forms of the first argument registers.
        // These appear frequently in parameter setup and should keep arg naming.
        "edi" => "arg0".to_string(),
        "esi" => "arg1".to_string(),
        "edx" => "arg2".to_string(),
        "ecx" => "arg3".to_string(),
        "r8d" => "tmp_r8".to_string(),
        "r9d" => "tmp_r9".to_string(),
        "r10d" => "tmp_r10".to_string(),
        "r11d" => "tmp_r11".to_string(),
        // Keep other registers as-is (rsp, rbp, rip, etc.)
        _ => name.to_string(),
    }
}

pub(super) fn normalize_variable_name(name: &str) -> String {
    if let Some(rest) = name.strip_prefix("arg_") {
        if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_hexdigit()) {
            return format!("local_{}", rest.to_lowercase());
        }
    }
    name.to_string()
}

/// Checks if two expressions are structurally equal.
pub(super) fn exprs_equal(a: &Expr, b: &Expr) -> bool {
    match (&a.kind, &b.kind) {
        (ExprKind::Var(va), ExprKind::Var(vb)) => va.name == vb.name,
        (ExprKind::IntLit(na), ExprKind::IntLit(nb)) => na == nb,
        (
            ExprKind::BinOp {
                op: opa,
                left: la,
                right: ra,
            },
            ExprKind::BinOp {
                op: opb,
                left: lb,
                right: rb,
            },
        ) => opa == opb && exprs_equal(la, lb) && exprs_equal(ra, rb),
        (
            ExprKind::UnaryOp {
                op: opa,
                operand: oa,
            },
            ExprKind::UnaryOp {
                op: opb,
                operand: ob,
            },
        ) => opa == opb && exprs_equal(oa, ob),
        (ExprKind::Deref { addr: aa, size: sa }, ExprKind::Deref { addr: ab, size: sb }) => {
            sa == sb && exprs_equal(aa, ab)
        }
        (
            ExprKind::ArrayAccess {
                base: ba,
                index: ia,
                element_size: ea,
            },
            ExprKind::ArrayAccess {
                base: bb,
                index: ib,
                element_size: eb,
            },
        ) => ea == eb && exprs_equal(ba, bb) && exprs_equal(ia, ib),
        (
            ExprKind::FieldAccess {
                base: ba,
                field_name: fa,
                offset: oa,
            },
            ExprKind::FieldAccess {
                base: bb,
                field_name: fb,
                offset: ob,
            },
        ) => oa == ob && fa == fb && exprs_equal(ba, bb),
        _ => false,
    }
}

/// Checks if a body contains only a call to __stack_chk_fail.
pub(super) fn is_stack_canary_check_body(
    nodes: &[StructuredNode],
    symbol_table: Option<&SymbolTable>,
) -> bool {
    // Look for a single statement that calls __stack_chk_fail
    for node in nodes {
        match node {
            StructuredNode::Block { statements, .. } => {
                for stmt in statements {
                    if is_stack_chk_fail_call(stmt, symbol_table) {
                        return true;
                    }
                }
            }
            StructuredNode::Expr(expr) => {
                if is_stack_chk_fail_call(expr, symbol_table) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// Checks if an expression is a call to __stack_chk_fail.
pub(super) fn is_stack_chk_fail_call(expr: &Expr, symbol_table: Option<&SymbolTable>) -> bool {
    if let ExprKind::Call { target, .. } = &expr.kind {
        match target {
            CallTarget::Named(name) => {
                if name.contains("stack_chk_fail") {
                    return true;
                }
            }
            CallTarget::Direct { target: addr, .. } => {
                // Check if this address resolves to stack_chk_fail
                if let Some(sym_table) = symbol_table {
                    if let Some(name) = sym_table.get(*addr) {
                        if name.contains("stack_chk_fail") {
                            return true;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    false
}

/// Checks if an expression is a stack canary load.
/// Pattern: local_X = *(*(GOT_address))
pub(super) fn is_stack_canary_load(expr: &Expr) -> bool {
    if let ExprKind::Assign { rhs, .. } = &expr.kind {
        // Check for double dereference: *(*(something))
        if let ExprKind::Deref { addr: inner, .. } = &rhs.kind {
            if let ExprKind::Deref { .. } = &inner.kind {
                // Double dereference - likely GOT access to __stack_chk_guard
                return true;
            }
        }
    }
    false
}

/// Checks if a register name is an ARM64 temporary/scratch register (x8-x17 or w8-w17).
/// These are used for intermediate values during argument setup and don't need to appear
/// in the output.
pub(super) fn is_arm64_temp_register(name: &str) -> bool {
    matches!(
        name,
        "x8" | "x9"
            | "x10"
            | "x11"
            | "x12"
            | "x13"
            | "x14"
            | "x15"
            | "x16"
            | "x17"
            | "w8"
            | "w9"
            | "w10"
            | "w11"
            | "w12"
            | "w13"
            | "w14"
            | "w15"
            | "w16"
            | "w17"
    )
}

/// Checks if an expression is an ARM64 temporary register variable.
pub(super) fn is_arm64_temp_register_expr(expr: &Expr) -> bool {
    if let ExprKind::Var(v) = &expr.kind {
        return is_arm64_temp_register(&v.name);
    }
    false
}

/// Determines if a variable name represents a local variable that needs declaration.
/// This includes both original names (var_N, local_N, arg_N) and semantically renamed
/// variables (iter, idx, tmp0, saved1, result, err, etc.).
///
/// Also handles the case where register names will be renamed during formatting:
/// e.g., x8 → tmp0, x19 → err, etc. These need declarations too.
///
/// Returns false for:
/// - Argument registers (x0-x7, rdi, rsi, etc.) - these become function parameters
/// - Numeric literals and addresses (0x...)
/// - Empty names
pub(super) fn is_declarable_variable(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }

    // Original variable patterns that always need declaration
    if name.starts_with("var_")
        || name.starts_with("local_")
        || name.starts_with("arg_")
        || name.starts_with("tmp")
    {
        return true;
    }

    // Semantically renamed variables that need declaration
    // These are the names assigned by variable_naming.rs
    if matches!(
        name,
        "iter"
            | "idx"
            | "idx2"
            | "idx3"
            | "result"
            | "err"
            | "size"
            | "flag"
            | "str"
            | "ptr"
            | "len"
            | "buf"
            | "count"
            | "offset"
            | "pos"
            | "ret"
            | "status"
            | "rc"
            | "fd"
            | "handle"
            | "stream"
            | "file"
            | "path"
            | "name"
            | "data"
            | "addr"
            | "base"
            | "end"
            | "start"
            | "limit"
            | "cmp_result"
            | "thread_result"
            | "err_msg"
            | "err_result"
            | "addr_result"
    ) {
        return true;
    }

    // Callee-saved register renames (saved1, saved2, ..., saved8)
    if name.starts_with("saved") {
        if let Some(suffix) = name.strip_prefix("saved") {
            if suffix.parse::<u32>().is_ok() {
                return true;
            }
        }
    }

    // Loop index variables (i, j, k, etc.)
    if matches!(name, "i" | "j" | "k" | "l" | "m" | "n" | "ii" | "jj" | "kk") {
        return true;
    }

    // Check if this is a register that will be renamed to something declarable.
    // We need to get the renamed name and check if that needs declaration.
    let renamed = rename_register(name);
    if renamed != name {
        // The register was renamed - check if the renamed name needs declaration
        // Exclude argument registers (arg0-arg7) and return value (ret)
        if renamed.starts_with("tmp")
            || renamed.starts_with("saved")
            || renamed.starts_with("fp_saved")
            || matches!(renamed.as_str(), "err" | "result")
        {
            return true;
        }
        // arg0-arg7, ret, etc. don't need declaration here (handled as params)
        return false;
    }

    // ARM64/x86-64 register names that aren't renamed - don't declare
    // Frame pointer, stack pointer, link register, etc.
    if matches!(
        name,
        "sp" | "fp" | "lr" | "pc" | "xzr" | "wzr" | "rbp" | "rsp"
    ) {
        return false;
    }

    // Numeric literals and addresses - don't declare
    if name.starts_with("0x") || name.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }

    // Default: if not a register and not a literal, likely a local variable
    // This catches any other semantic names we might have missed
    true
}

pub(super) fn is_assignable_unknown_name(name: &str) -> bool {
    if is_declarable_variable(name) {
        return true;
    }

    // Avoid treating linker/compiler helper symbols as locals.
    if name.starts_with("__") {
        return false;
    }

    // Accept generic identifier-shaped names on assignment LHS (e.g., sum, total, value).
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    if !chars.all(|c| c == '_' || c.is_ascii_alphanumeric()) {
        return false;
    }

    true
}

pub(super) fn is_likely_global_identifier(name: &str) -> bool {
    name.starts_with("g_")
        || name.starts_with("data_")
        || name.starts_with("__")
        || matches!(name, "stdin" | "stdout" | "stderr" | "errno")
}

pub(super) fn contains_identifier_token(text: &str, ident: &str) -> bool {
    if ident.is_empty() {
        return false;
    }

    let bytes = text.as_bytes();
    let mut start = 0;
    while let Some(found) = text[start..].find(ident) {
        let pos = start + found;
        let end = pos + ident.len();

        let before_is_ident = pos > 0 && is_identifier_char(bytes[pos - 1] as char);
        let after_is_ident = end < bytes.len() && is_identifier_char(bytes[end] as char);
        if !before_is_ident && !after_is_ident {
            return true;
        }

        start = end;
    }

    false
}

fn is_identifier_char(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphanumeric()
}

pub(super) fn collect_decl_identifiers_from_emitted_body(body: &str) -> HashSet<String> {
    let mut vars = HashSet::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }
        if trimmed.starts_with("if ")
            || trimmed.starts_with("if(")
            || trimmed.starts_with("while ")
            || trimmed.starts_with("while(")
            || trimmed.starts_with("for ")
            || trimmed.starts_with("for(")
            || trimmed.starts_with("switch ")
            || trimmed.starts_with("switch(")
            || trimmed.starts_with("return")
        {
            continue;
        }

        if let Some(lhs) = extract_assignment_lhs(trimmed) {
            if let Some(name) = canonical_decl_var_name(lhs) {
                if !is_likely_global_identifier(&name) && !looks_like_parameter_name(&name) {
                    vars.insert(name);
                }
            }
        }
    }
    vars
}

pub(super) fn extract_assignment_lhs(line: &str) -> Option<&str> {
    const OPS: [&str; 10] = ["<<=", ">>=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "="];

    let mut best: Option<(usize, &str)> = None;
    for op in OPS {
        if let Some(pos) = line.find(op) {
            if op == "=" {
                let bytes = line.as_bytes();
                let prev = pos.checked_sub(1).map(|i| bytes[i] as char);
                let next = bytes.get(pos + 1).copied().map(char::from);
                if matches!(prev, Some('=' | '!' | '<' | '>')) || next == Some('=') {
                    continue;
                }
            }

            if best.map_or(true, |(best_pos, _)| pos < best_pos) {
                best = Some((pos, op));
            }
        }
    }

    best.map(|(pos, _)| line[..pos].trim().trim_end_matches(';').trim())
}

pub(super) fn looks_like_parameter_name(name: &str) -> bool {
    if let Some(rest) = name.strip_prefix("arg") {
        if !rest.is_empty() {
            return rest.chars().all(|c| c.is_ascii_digit());
        }
    }
    if let Some(rest) = name.strip_prefix("arg_") {
        if !rest.is_empty() {
            return rest.chars().all(|c| c.is_ascii_hexdigit());
        }
    }
    false
}

pub(super) fn canonical_decl_var_name(name: &str) -> Option<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return None;
    }

    let base = trimmed.split('[').next().unwrap_or(trimmed).trim();
    if is_assignable_unknown_name(base) {
        Some(base.to_string())
    } else {
        None
    }
}

pub(super) fn is_loop_counter_like_name(name: &str) -> bool {
    matches!(
        name,
        "i" | "j"
            | "k"
            | "l"
            | "m"
            | "n"
            | "ii"
            | "jj"
            | "kk"
            | "iter"
            | "idx"
            | "idx2"
            | "idx3"
            | "count"
            | "pos"
            | "offset"
    ) || name.ends_with("_idx")
        || name.ends_with("_iter")
}

/// Attempts to extract array access components from an address expression.
/// Matches patterns like `base + index * element_size` where `element_size == size`.
/// Returns `Some((base, index))` if the pattern matches, `None` otherwise.
pub(super) fn try_extract_array_access(addr: &Expr, size: u8) -> Option<(Expr, Expr)> {
    // Pattern: base + (index * element_size) or (index * element_size) + base
    if let ExprKind::BinOp {
        op: BinOpKind::Add,
        left,
        right,
    } = &addr.kind
    {
        // Try left as base, right as index * size
        if let Some((index, element_size)) = extract_mul_by_constant(right) {
            if element_size == size as i128 {
                return Some(((**left).clone(), index));
            }
        }
        // Try right as base, left as index * size (commutative)
        if let Some((index, element_size)) = extract_mul_by_constant(left) {
            if element_size == size as i128 {
                return Some(((**right).clone(), index));
            }
        }
        // Also try shift patterns: base + (index << shift) where 1 << shift == size
        if let Some((index, shift_amount)) = extract_shift_left_by_constant(right) {
            if (1i128 << shift_amount) == size as i128 {
                return Some(((**left).clone(), index));
            }
        }
        if let Some((index, shift_amount)) = extract_shift_left_by_constant(left) {
            if (1i128 << shift_amount) == size as i128 {
                return Some(((**right).clone(), index));
            }
        }
    }
    None
}

/// Extracts (operand, constant) from expressions like `operand * constant` or `constant * operand`.
pub(super) fn extract_mul_by_constant(expr: &Expr) -> Option<(Expr, i128)> {
    if let ExprKind::BinOp {
        op: BinOpKind::Mul,
        left,
        right,
    } = &expr.kind
    {
        // Try left * constant
        if let ExprKind::IntLit(n) = right.kind {
            return Some(((**left).clone(), n));
        }
        // Try constant * right
        if let ExprKind::IntLit(n) = left.kind {
            return Some(((**right).clone(), n));
        }
    }
    None
}

/// Extracts (operand, shift_amount) from expressions like `operand << constant`.
pub(super) fn extract_shift_left_by_constant(expr: &Expr) -> Option<(Expr, i128)> {
    if let ExprKind::BinOp {
        op: BinOpKind::Shl,
        left,
        right,
    } = &expr.kind
    {
        if let ExprKind::IntLit(n) = right.kind {
            return Some(((**left).clone(), n));
        }
    }
    None
}

/// Extracts the byte offset from a RIP/EIP-relative address expression.
/// Matches patterns like `rip + offset` or `eip + offset` where `offset` is an integer literal.
/// Returns `Some(offset)` if the pattern matches, `None` otherwise.
pub(super) fn try_extract_rip_relative_offset(addr: &Expr) -> Option<u64> {
    if let ExprKind::BinOp {
        op: BinOpKind::Add,
        left,
        right,
    } = &addr.kind
    {
        // Check if left is rip/eip and right is an integer offset
        if let ExprKind::Var(v) = &left.kind {
            if v.name == "rip" || v.name == "eip" {
                if let ExprKind::IntLit(offset) = &right.kind {
                    if *offset >= 0 {
                        return Some(*offset as u64);
                    }
                }
            }
        }
        // Check if right is rip/eip and left is an integer offset (commutative)
        if let ExprKind::Var(v) = &right.kind {
            if v.name == "rip" || v.name == "eip" {
                if let ExprKind::IntLit(offset) = &left.kind {
                    if *offset >= 0 {
                        return Some(*offset as u64);
                    }
                }
            }
        }
    }
    None
}
