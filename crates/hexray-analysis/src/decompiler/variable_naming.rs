//! Variable naming inference.
//!
//! Infers better variable names based on how variables are used in the code.
//! This improves readability by giving meaningful names to temporary variables.

use std::collections::HashMap;

use super::expression::{BinOpKind, CallTarget, Expr, ExprKind};
use super::structurer::StructuredNode;

/// Naming hints collected from code analysis.
#[derive(Debug, Clone, Default)]
pub struct NamingHints {
    /// Suggested names for variables.
    pub suggestions: HashMap<String, String>,
    /// Usage patterns for variables.
    pub usage_patterns: HashMap<String, Vec<UsagePattern>>,
}

/// How a variable is used.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Some variants reserved for future use
pub enum UsagePattern {
    /// Used as loop counter.
    LoopCounter,
    /// Used as pointer/iterator.
    Iterator,
    /// Used as index into array.
    ArrayIndex,
    /// Used as function argument.
    FunctionArg { func_name: String, arg_index: usize },
    /// Result of function call.
    FunctionResult { func_name: String },
    /// Used in string operation.
    StringOp,
    /// Used as size/count.
    SizeOrCount,
    /// Used as boolean/flag.
    Boolean,
    /// Used in comparison against specific value.
    ComparedTo(i128),
}

/// Analyze nodes and collect naming hints.
pub fn collect_naming_hints(nodes: &[StructuredNode]) -> NamingHints {
    let mut hints = NamingHints::default();

    for node in nodes {
        collect_hints_from_node(node, &mut hints);
    }

    // Generate suggestions based on collected patterns
    generate_suggestions(&mut hints);

    hints
}

/// Collect hints from a single node.
fn collect_hints_from_node(node: &StructuredNode, hints: &mut NamingHints) {
    match node {
        StructuredNode::Block { statements, .. } => {
            for stmt in statements {
                collect_hints_from_expr(stmt, hints);
            }
        }

        StructuredNode::Expr(expr) => {
            collect_hints_from_expr(expr, hints);
        }

        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_hints_from_expr(condition, hints);
            for node in then_body {
                collect_hints_from_node(node, hints);
            }
            if let Some(else_body) = else_body {
                for node in else_body {
                    collect_hints_from_node(node, hints);
                }
            }
        }

        StructuredNode::While {
            condition, body, ..
        } => {
            // Variables in while condition might be iterators
            if let Some(var) = extract_iterator_var(condition) {
                add_usage_pattern(hints, &var, UsagePattern::Iterator);
            }
            collect_hints_from_expr(condition, hints);
            for node in body {
                collect_hints_from_node(node, hints);
            }
        }

        StructuredNode::For {
            init,
            condition,
            update,
            body,
            ..
        } => {
            // For loop init variable is likely a counter
            if let Some(init) = init {
                if let Some(var) = extract_assigned_var(init) {
                    add_usage_pattern(hints, &var, UsagePattern::LoopCounter);
                }
                collect_hints_from_expr(init, hints);
            }
            collect_hints_from_expr(condition, hints);
            if let Some(update) = update {
                collect_hints_from_expr(update, hints);
            }
            for node in body {
                collect_hints_from_node(node, hints);
            }
        }

        StructuredNode::DoWhile {
            body, condition, ..
        } => {
            for node in body {
                collect_hints_from_node(node, hints);
            }
            collect_hints_from_expr(condition, hints);
        }

        StructuredNode::Loop { body, .. } => {
            for node in body {
                collect_hints_from_node(node, hints);
            }
        }

        StructuredNode::Switch {
            value,
            cases,
            default,
        } => {
            collect_hints_from_expr(value, hints);
            for (_, case_body) in cases {
                for node in case_body {
                    collect_hints_from_node(node, hints);
                }
            }
            if let Some(default) = default {
                for node in default {
                    collect_hints_from_node(node, hints);
                }
            }
        }

        StructuredNode::Return(Some(expr)) => {
            collect_hints_from_expr(expr, hints);
        }

        StructuredNode::Sequence(nodes) => {
            for node in nodes {
                collect_hints_from_node(node, hints);
            }
        }

        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => {
            for node in try_body {
                collect_hints_from_node(node, hints);
            }
            for handler in catch_handlers {
                for node in &handler.body {
                    collect_hints_from_node(node, hints);
                }
            }
        }

        _ => {}
    }
}

/// Collect hints from an expression.
fn collect_hints_from_expr(expr: &Expr, hints: &mut NamingHints) {
    match &expr.kind {
        ExprKind::Assign { lhs, rhs } => {
            // Check if rhs is a function call
            if let ExprKind::Call { target, .. } = &rhs.kind {
                if let Some(var) = extract_var_name(lhs) {
                    if let Some(func_name) = get_call_target_name(target) {
                        add_usage_pattern(
                            hints,
                            &var,
                            UsagePattern::FunctionResult {
                                func_name: func_name.to_string(),
                            },
                        );
                    }
                }
            }
            collect_hints_from_expr(lhs, hints);
            collect_hints_from_expr(rhs, hints);
        }

        ExprKind::Call { target, args } => {
            // Track function arguments
            if let Some(func_name) = get_call_target_name(target) {
                for (i, arg) in args.iter().enumerate() {
                    if let Some(var) = extract_var_name(arg) {
                        add_usage_pattern(
                            hints,
                            &var,
                            UsagePattern::FunctionArg {
                                func_name: func_name.to_string(),
                                arg_index: i,
                            },
                        );
                    }
                }

                // Detect string operations
                if is_string_function(func_name) {
                    for arg in args {
                        if let Some(var) = extract_var_name(arg) {
                            add_usage_pattern(hints, &var, UsagePattern::StringOp);
                        }
                    }
                }
            }
        }

        ExprKind::BinOp { op, left, right } => {
            // Check for comparison patterns
            if is_comparison_op(op) {
                if let Some(var) = extract_var_name(left) {
                    if let ExprKind::IntLit(n) = &right.kind {
                        add_usage_pattern(hints, &var, UsagePattern::ComparedTo(*n));
                    }
                }
                if let Some(var) = extract_var_name(right) {
                    if let ExprKind::IntLit(n) = &left.kind {
                        add_usage_pattern(hints, &var, UsagePattern::ComparedTo(*n));
                    }
                }
            }
            collect_hints_from_expr(left, hints);
            collect_hints_from_expr(right, hints);
        }

        ExprKind::ArrayAccess { index, .. } => {
            // Index variable is likely an array index
            if let Some(var) = extract_var_name(index) {
                add_usage_pattern(hints, &var, UsagePattern::ArrayIndex);
            }
        }

        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            collect_hints_from_expr(cond, hints);
            collect_hints_from_expr(then_expr, hints);
            collect_hints_from_expr(else_expr, hints);
        }

        ExprKind::UnaryOp { operand, .. } => {
            collect_hints_from_expr(operand, hints);
        }

        ExprKind::Deref { addr, .. } => {
            collect_hints_from_expr(addr, hints);
        }

        ExprKind::Cast { expr: inner, .. } => {
            collect_hints_from_expr(inner, hints);
        }

        _ => {}
    }
}

/// Extract variable name from expression.
fn extract_var_name(expr: &Expr) -> Option<String> {
    if let ExprKind::Var(v) = &expr.kind {
        return Some(v.name.clone());
    }
    None
}

/// Extract assigned variable from assignment expression.
fn extract_assigned_var(expr: &Expr) -> Option<String> {
    if let ExprKind::Assign { lhs, .. } = &expr.kind {
        return extract_var_name(lhs);
    }
    None
}

/// Extract iterator variable from condition.
fn extract_iterator_var(condition: &Expr) -> Option<String> {
    match &condition.kind {
        ExprKind::BinOp {
            op: BinOpKind::Ne,
            left,
            right,
        }
        | ExprKind::BinOp {
            op: BinOpKind::Lt,
            left,
            right,
        }
        | ExprKind::BinOp {
            op: BinOpKind::Le,
            left,
            right,
        } => {
            // Check for != 0 (NULL check) or < n
            if matches!(right.kind, ExprKind::IntLit(_)) {
                return extract_var_name(left);
            }
            if matches!(left.kind, ExprKind::IntLit(_)) {
                return extract_var_name(right);
            }
            None
        }
        ExprKind::Var(v) => Some(v.name.clone()),
        _ => None,
    }
}

/// Get call target name.
fn get_call_target_name(target: &CallTarget) -> Option<&str> {
    match target {
        CallTarget::Named(name) => Some(name.as_str()),
        _ => None,
    }
}

/// Check if a function is a string operation.
fn is_string_function(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "strlen"
            | "strcmp"
            | "strncmp"
            | "strcpy"
            | "strncpy"
            | "strcat"
            | "strncat"
            | "strchr"
            | "strrchr"
            | "strstr"
            | "memcpy"
            | "memmove"
            | "memset"
            | "memcmp"
    )
}

/// Check if operator is a comparison.
fn is_comparison_op(op: &BinOpKind) -> bool {
    matches!(
        op,
        BinOpKind::Eq
            | BinOpKind::Ne
            | BinOpKind::Lt
            | BinOpKind::Le
            | BinOpKind::Gt
            | BinOpKind::Ge
    )
}

/// Add a usage pattern for a variable.
fn add_usage_pattern(hints: &mut NamingHints, var: &str, pattern: UsagePattern) {
    hints
        .usage_patterns
        .entry(var.to_string())
        .or_default()
        .push(pattern);
}

/// Generate name suggestions based on collected patterns.
fn generate_suggestions(hints: &mut NamingHints) {
    for (var, patterns) in &hints.usage_patterns {
        // Skip already well-named variables
        if !should_rename(var) {
            continue;
        }

        if let Some(suggestion) = suggest_name_from_patterns(var, patterns) {
            hints.suggestions.insert(var.clone(), suggestion);
        }
    }
}

/// Check if a variable should be considered for renaming.
fn should_rename(var: &str) -> bool {
    // Rename temporaries and generic register names
    var.starts_with("temp")
        || var.starts_with("tmp")
        || var.starts_with("t_")
        || var.starts_with("v_")
        || var.starts_with("var_")
        || is_generic_register(var)
}

/// Check if name is a generic register name.
fn is_generic_register(var: &str) -> bool {
    let lower = var.to_lowercase();
    // x86 registers
    if matches!(
        lower.as_str(),
        "eax"
            | "ebx"
            | "ecx"
            | "edx"
            | "esi"
            | "edi"
            | "rax"
            | "rbx"
            | "rcx"
            | "rdx"
            | "rsi"
            | "rdi"
            | "r8"
            | "r9"
            | "r10"
            | "r11"
            | "r12"
            | "r13"
            | "r14"
            | "r15"
    ) {
        return true;
    }
    // ARM registers
    if lower.starts_with('x') || lower.starts_with('w') {
        if let Some(num_str) = lower.get(1..) {
            if num_str.parse::<u32>().is_ok() {
                return true;
            }
        }
    }
    false
}

/// Suggest a name based on usage patterns.
fn suggest_name_from_patterns(original: &str, patterns: &[UsagePattern]) -> Option<String> {
    // Prioritize certain patterns
    for pattern in patterns {
        match pattern {
            UsagePattern::LoopCounter => return Some("i".to_string()),
            UsagePattern::ArrayIndex => return Some("idx".to_string()),
            UsagePattern::Iterator => return Some("iter".to_string()),
            UsagePattern::StringOp => return Some("str".to_string()),
            UsagePattern::SizeOrCount => return Some("size".to_string()),
            UsagePattern::Boolean => return Some("flag".to_string()),
            UsagePattern::FunctionResult { func_name } => {
                return suggest_from_function_result(func_name);
            }
            UsagePattern::FunctionArg {
                func_name,
                arg_index,
            } => {
                if let Some(name) = suggest_from_function_arg(func_name, *arg_index) {
                    return Some(name);
                }
            }
            UsagePattern::ComparedTo(0) => {
                // Compared to 0 might be a pointer or boolean
                if original.starts_with('p') || original.contains("ptr") {
                    return Some("ptr".to_string());
                }
            }
            _ => {}
        }
    }

    None
}

/// Suggest a name based on function result.
fn suggest_from_function_result(func_name: &str) -> Option<String> {
    match func_name.to_lowercase().as_str() {
        "strlen" => Some("len".to_string()),
        "malloc" | "calloc" | "realloc" => Some("ptr".to_string()),
        "open" | "fopen" => Some("fd".to_string()),
        "socket" => Some("sock".to_string()),
        "read" | "write" | "recv" | "send" => Some("bytes".to_string()),
        "getchar" | "fgetc" => Some("ch".to_string()),
        "strcmp" | "strncmp" | "memcmp" => Some("cmp".to_string()),
        "strchr" | "strrchr" | "strstr" => Some("found".to_string()),
        "atoi" | "atol" | "strtol" | "strtoul" => Some("num".to_string()),
        _ => None,
    }
}

/// Suggest a name based on function argument position.
fn suggest_from_function_arg(func_name: &str, arg_index: usize) -> Option<String> {
    match (func_name.to_lowercase().as_str(), arg_index) {
        ("strcpy" | "strncpy" | "memcpy" | "memmove", 0) => Some("dst".to_string()),
        ("strcpy" | "strncpy" | "memcpy" | "memmove", 1) => Some("src".to_string()),
        ("memcpy" | "memmove" | "memset" | "strncpy", 2) => Some("n".to_string()),
        ("strcmp" | "strncmp" | "memcmp", 0 | 1) => Some("str".to_string()),
        ("strlen" | "strchr" | "strrchr", 0) => Some("str".to_string()),
        ("printf" | "sprintf" | "fprintf", 0) => Some("fmt".to_string()),
        ("malloc" | "calloc", 0) => Some("size".to_string()),
        _ => None,
    }
}

/// Analyzes nodes and applies suggested variable names.
///
/// This is the main entry point for the variable naming pass.
pub fn suggest_variable_names(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    let hints = collect_naming_hints(&nodes);
    apply_naming_hints(nodes, &hints)
}

/// Apply naming suggestions to nodes.
pub fn apply_naming_hints(nodes: Vec<StructuredNode>, hints: &NamingHints) -> Vec<StructuredNode> {
    if hints.suggestions.is_empty() {
        return nodes;
    }

    nodes
        .into_iter()
        .map(|node| apply_hints_to_node(node, hints))
        .collect()
}

fn apply_hints_to_node(node: StructuredNode, hints: &NamingHints) -> StructuredNode {
    match node {
        StructuredNode::Block {
            id,
            statements,
            address_range,
        } => StructuredNode::Block {
            id,
            statements: statements
                .into_iter()
                .map(|e| apply_hints_to_expr(e, hints))
                .collect(),
            address_range,
        },

        StructuredNode::Expr(expr) => StructuredNode::Expr(apply_hints_to_expr(expr, hints)),

        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition: apply_hints_to_expr(condition, hints),
            then_body: apply_naming_hints(then_body, hints),
            else_body: else_body.map(|e| apply_naming_hints(e, hints)),
        },

        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition: apply_hints_to_expr(condition, hints),
            body: apply_naming_hints(body, hints),
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
            init: init.map(|e| apply_hints_to_expr(e, hints)),
            condition: apply_hints_to_expr(condition, hints),
            update: update.map(|e| apply_hints_to_expr(e, hints)),
            body: apply_naming_hints(body, hints),
            header,
            exit_block,
        },

        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: apply_naming_hints(body, hints),
            condition: apply_hints_to_expr(condition, hints),
            header,
            exit_block,
        },

        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: apply_naming_hints(body, hints),
            header,
            exit_block,
        },

        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value: apply_hints_to_expr(value, hints),
            cases: cases
                .into_iter()
                .map(|(vals, body)| (vals, apply_naming_hints(body, hints)))
                .collect(),
            default: default.map(|d| apply_naming_hints(d, hints)),
        },

        StructuredNode::Return(Some(expr)) => {
            StructuredNode::Return(Some(apply_hints_to_expr(expr, hints)))
        }

        StructuredNode::Sequence(nodes) => {
            StructuredNode::Sequence(apply_naming_hints(nodes, hints))
        }

        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => StructuredNode::TryCatch {
            try_body: apply_naming_hints(try_body, hints),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|h| super::structurer::CatchHandler {
                    body: apply_naming_hints(h.body, hints),
                    ..h
                })
                .collect(),
        },

        other => other,
    }
}

fn apply_hints_to_expr(expr: Expr, hints: &NamingHints) -> Expr {
    match expr.kind {
        ExprKind::Var(mut v) => {
            if let Some(new_name) = hints.suggestions.get(&v.name) {
                v.name = new_name.clone();
            }
            Expr::var(v)
        }

        ExprKind::Assign { lhs, rhs } => Expr::assign(
            apply_hints_to_expr(*lhs, hints),
            apply_hints_to_expr(*rhs, hints),
        ),

        ExprKind::BinOp { op, left, right } => Expr::binop(
            op,
            apply_hints_to_expr(*left, hints),
            apply_hints_to_expr(*right, hints),
        ),

        ExprKind::UnaryOp { op, operand } => Expr::unary(op, apply_hints_to_expr(*operand, hints)),

        ExprKind::Call { target, args } => Expr::call(
            target,
            args.into_iter()
                .map(|a| apply_hints_to_expr(a, hints))
                .collect(),
        ),

        ExprKind::Deref { addr, size } => Expr::deref(apply_hints_to_expr(*addr, hints), size),

        ExprKind::ArrayAccess {
            base,
            index,
            element_size,
        } => Expr::array_access(
            apply_hints_to_expr(*base, hints),
            apply_hints_to_expr(*index, hints),
            element_size,
        ),

        ExprKind::FieldAccess {
            base,
            field_name,
            offset,
        } => Expr::field_access(apply_hints_to_expr(*base, hints), field_name, offset),

        ExprKind::Cast {
            expr,
            to_size,
            signed,
        } => Expr {
            kind: ExprKind::Cast {
                expr: Box::new(apply_hints_to_expr(*expr, hints)),
                to_size,
                signed,
            },
        },

        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => Expr {
            kind: ExprKind::Conditional {
                cond: Box::new(apply_hints_to_expr(*cond, hints)),
                then_expr: Box::new(apply_hints_to_expr(*then_expr, hints)),
                else_expr: Box::new(apply_hints_to_expr(*else_expr, hints)),
            },
        },

        _ => expr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::expression::{VarKind, Variable};

    fn make_var(name: &str) -> Expr {
        Expr::var(Variable {
            name: name.to_string(),
            kind: VarKind::Register(0),
            size: 8,
        })
    }

    #[test]
    fn test_should_rename() {
        assert!(should_rename("temp0"));
        assert!(should_rename("tmp_val"));
        assert!(should_rename("var_8"));
        assert!(should_rename("eax"));
        assert!(should_rename("x0"));

        assert!(!should_rename("size"));
        assert!(!should_rename("count"));
        assert!(!should_rename("ptr"));
    }

    #[test]
    fn test_suggest_from_function_result() {
        assert_eq!(
            suggest_from_function_result("strlen"),
            Some("len".to_string())
        );
        assert_eq!(
            suggest_from_function_result("malloc"),
            Some("ptr".to_string())
        );
        assert_eq!(suggest_from_function_result("open"), Some("fd".to_string()));
    }

    #[test]
    fn test_suggest_from_function_arg() {
        assert_eq!(
            suggest_from_function_arg("strcpy", 0),
            Some("dst".to_string())
        );
        assert_eq!(
            suggest_from_function_arg("strcpy", 1),
            Some("src".to_string())
        );
        assert_eq!(
            suggest_from_function_arg("memcpy", 2),
            Some("n".to_string())
        );
    }

    #[test]
    fn test_collect_hints_from_loop() {
        let init = Expr::assign(make_var("temp0"), Expr::int(0));
        let condition = Expr::binop(BinOpKind::Lt, make_var("temp0"), make_var("n"));
        let update = Expr::assign(
            make_var("temp0"),
            Expr::binop(BinOpKind::Add, make_var("temp0"), Expr::int(1)),
        );

        let for_loop = StructuredNode::For {
            init: Some(init),
            condition,
            update: Some(update),
            body: vec![],
            header: Some(hexray_core::BasicBlockId::new(0)),
            exit_block: None,
        };

        let hints = collect_naming_hints(&[for_loop]);

        assert!(hints.usage_patterns.contains_key("temp0"));
        let patterns = &hints.usage_patterns["temp0"];
        assert!(patterns
            .iter()
            .any(|p| matches!(p, UsagePattern::LoopCounter)));
    }
}
