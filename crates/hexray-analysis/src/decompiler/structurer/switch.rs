//! Switch-statement detection and `strcmp`-chain canonicalization.
//!
//! Two entry points consumed by the structurer driver:
//!
//! * [`detect_switch_statements`] — collapses chains of `if (x == 0) ... else if (x == 1) ...`
//!   into a single `switch (x)`.
//! * [`simplify_strcmp_switch_patterns`] — rewrites `result = strcmp(s, "lit"); if (result == 0)`
//!   chains into a string-keyed switch.
//!
//! Both run as post-processing passes after the basic CFG-to-tree reduction
//! has produced an unstructured `Vec<StructuredNode>`. They're idempotent:
//! running them twice is the same as running them once.

use super::super::expression::{BinOpKind, Expr};
use super::super::for_loop_detection::get_expr_var_key;
use super::{CatchHandler, StructuredNode};

/// Post-processes nodes to detect switch statements from chains of if-else.
pub(super) fn detect_switch_statements(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    let mut result = Vec::new();

    for node in nodes {
        let node = detect_switch_in_node(node);
        result.push(node);
    }

    result
}

/// Rewrites common option-parsing pattern:
///   `tmp = strcmp(x, "..."); switch (tmp) { case 0: ... default: ... }`
/// into:
///   `if (strcmp(x, "...") == 0) { ... } else { ... }`
pub(super) fn simplify_strcmp_switch_patterns(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    // First recurse into children.
    let recursed: Vec<StructuredNode> = nodes
        .into_iter()
        .map(simplify_strcmp_switch_in_node)
        .collect();

    // Then rewrite adjacent node pairs at this level.
    let mut out = Vec::with_capacity(recursed.len());
    let mut i = 0usize;
    while i < recursed.len() {
        if i + 1 < recursed.len() {
            if let Some(mut rewritten) =
                rewrite_strcmp_switch_pair(recursed[i].clone(), recursed[i + 1].clone())
            {
                out.append(&mut rewritten);
                i += 2;
                continue;
            }
        }
        out.push(recursed[i].clone());
        i += 1;
    }

    out
}

fn simplify_strcmp_switch_in_node(node: StructuredNode) -> StructuredNode {
    match node {
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition,
            then_body: simplify_strcmp_switch_patterns(then_body),
            else_body: else_body.map(simplify_strcmp_switch_patterns),
        },
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition,
            body: simplify_strcmp_switch_patterns(body),
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: simplify_strcmp_switch_patterns(body),
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
            body: simplify_strcmp_switch_patterns(body),
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: simplify_strcmp_switch_patterns(body),
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
                .map(|(vals, body)| (vals, simplify_strcmp_switch_patterns(body)))
                .collect(),
            default: default.map(simplify_strcmp_switch_patterns),
        },
        StructuredNode::Sequence(nodes) => {
            StructuredNode::Sequence(simplify_strcmp_switch_patterns(nodes))
        }
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => StructuredNode::TryCatch {
            try_body: simplify_strcmp_switch_patterns(try_body),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|h| CatchHandler {
                    body: simplify_strcmp_switch_patterns(h.body),
                    ..h
                })
                .collect(),
        },
        other => other,
    }
}

fn rewrite_strcmp_switch_pair(
    first: StructuredNode,
    second: StructuredNode,
) -> Option<Vec<StructuredNode>> {
    // Extract `tmp = strcmp(...);` from first node.
    let (remaining_first, cmp_var, cmp_call) = extract_strcmp_assignment(first)?;

    // Extract `switch(tmp)` with only `case 0` (+ optional default) from second.
    let (then_body, else_body) = extract_zero_case_switch(&second, &cmp_var)?;

    let condition = Expr::binop(BinOpKind::Eq, cmp_call, Expr::int(0));
    let if_node = StructuredNode::If {
        condition,
        then_body,
        else_body,
    };

    let mut out = Vec::new();
    if let Some(node) = remaining_first {
        out.push(node);
    }
    out.push(if_node);
    Some(out)
}

fn extract_strcmp_assignment(
    node: StructuredNode,
) -> Option<(Option<StructuredNode>, String, Expr)> {
    // Support either:
    //   Expr(tmp = strcmp(...))
    // or
    //   Block { ..., tmp = strcmp(...) } (assignment must be last stmt)
    match node {
        StructuredNode::Expr(expr) => {
            let (var, call) = match_strcmp_assign(&expr)?;
            Some((None, var, call))
        }
        StructuredNode::Block {
            id,
            mut statements,
            address_range,
        } => {
            let last = statements.last()?.clone();
            let (var, call) = match_strcmp_assign(&last)?;
            statements.pop();
            let remaining = if statements.is_empty() {
                None
            } else {
                Some(StructuredNode::Block {
                    id,
                    statements,
                    address_range,
                })
            };
            Some((remaining, var, call))
        }
        _ => None,
    }
}

fn match_strcmp_assign(expr: &Expr) -> Option<(String, Expr)> {
    if let super::super::expression::ExprKind::Assign { lhs, rhs } = &expr.kind {
        if let super::super::expression::ExprKind::Var(v) = &lhs.kind {
            if let super::super::expression::ExprKind::Call {
                target: super::super::expression::CallTarget::Named(name),
                ..
            } = &rhs.kind
            {
                let lower = name.to_lowercase();
                if matches!(
                    lower.as_str(),
                    "strcmp" | "strncmp" | "strcasecmp" | "strncasecmp"
                ) {
                    return Some((v.name.clone(), (**rhs).clone()));
                }
            }
        }
    }
    None
}

fn extract_zero_case_switch(
    node: &StructuredNode,
    expected_var: &str,
) -> Option<(Vec<StructuredNode>, Option<Vec<StructuredNode>>)> {
    let StructuredNode::Switch {
        value,
        cases,
        default,
    } = node
    else {
        return None;
    };

    let super::super::expression::ExprKind::Var(v) = &value.kind else {
        return None;
    };
    if v.name != expected_var {
        return None;
    }

    // Only handle single-case switches where the case is exactly value 0.
    if cases.len() != 1 {
        return None;
    }
    let (vals, body) = &cases[0];
    if vals.len() != 1 || vals[0] != 0 {
        return None;
    }

    Some((body.clone(), default.clone()))
}

/// Detect switch patterns in a single node and its children.
fn detect_switch_in_node(node: StructuredNode) -> StructuredNode {
    match node {
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => {
            // Try to extract a switch from this if-else chain
            if let Some(switch_node) = try_extract_switch(&condition, &then_body, &else_body) {
                return switch_node;
            }

            // Otherwise, recursively process children
            StructuredNode::If {
                condition,
                then_body: detect_switch_statements(then_body),
                else_body: else_body.map(detect_switch_statements),
            }
        }
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition,
            body: detect_switch_statements(body),
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: detect_switch_statements(body),
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
            body: detect_switch_statements(body),
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: detect_switch_statements(body),
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
                .map(|(vals, body)| (vals, detect_switch_statements(body)))
                .collect(),
            default: default.map(detect_switch_statements),
        },
        StructuredNode::Sequence(nodes) => {
            StructuredNode::Sequence(detect_switch_statements(nodes))
        }
        other => other,
    }
}

/// Try to extract a switch statement from an if-else chain.
/// Returns Some(Switch) if successful, None if the pattern doesn't match.
///
/// Handles two patterns:
/// 1. `if (x == A) { caseA } else if (x == B) { caseB } ...` (== pattern)
/// 2. `if (x != A) { if (x != B) { ... } else { caseB } } else { caseA }` (!= pattern)
fn try_extract_switch(
    condition: &Expr,
    then_body: &[StructuredNode],
    else_body: &Option<Vec<StructuredNode>>,
) -> Option<StructuredNode> {
    // First, try to extract range condition (x >= min && x <= max)
    if let Some(range_info) = extract_switch_range_info(condition) {
        let values: Vec<i128> = (range_info.start..=range_info.end).collect();
        // For range conditions, we start with that case and continue checking else chain
        let mut cases: Vec<(Vec<i128>, Vec<StructuredNode>)> = vec![(values, then_body.to_vec())];
        let mut current_else = else_body.clone();
        let switch_var_key = range_info.var_key.clone();
        let switch_var_expr = range_info.var_expr.clone();

        // Walk down the else chain looking for more cases (range or equality)
        while let Some(ref else_nodes) = current_else {
            let mut found_if = false;
            for node in else_nodes {
                if let StructuredNode::If {
                    condition: else_cond,
                    then_body: else_then,
                    else_body: nested_else,
                } = node
                {
                    if let Some((var_key, _, values)) = extract_switch_case_or_range(else_cond) {
                        if var_key == switch_var_key {
                            cases.push((values, else_then.to_vec()));
                            current_else = nested_else.clone();
                            found_if = true;
                            break;
                        }
                    }
                }
            }
            if !found_if {
                break;
            }
        }

        // Need at least 2 cases for range-based switches (the range might cover many values)
        if cases.len() >= 2 || cases.iter().map(|(v, _)| v.len()).sum::<usize>() >= 3 {
            // Reject switches where case values are duplicated.
            let mut has_duplicates = false;
            {
                let mut seen_values = std::collections::HashSet::new();
                for (vals, _) in &cases {
                    for val in vals {
                        if !seen_values.insert(*val) {
                            has_duplicates = true;
                            break;
                        }
                    }
                    if has_duplicates {
                        break;
                    }
                }
            }
            if has_duplicates {
                return None;
            }

            let default = current_else.map(detect_switch_statements);
            let final_cases = cases
                .into_iter()
                .map(|(vals, body)| (vals, detect_switch_statements(body)))
                .collect();
            return Some(StructuredNode::Switch {
                value: switch_var_expr,
                cases: final_cases,
                default,
            });
        }
    }

    // Check if condition is a comparison against a literal (== or != pattern)
    let first_info = extract_switch_case_info(condition)?;

    // Determine if we're dealing with == or != patterns
    if first_info.negated {
        // != pattern: case body is in else, rest of chain is in then
        return try_extract_switch_negated(&first_info, then_body, else_body);
    }

    // == pattern: case body is in then, rest of chain is in else
    // Start collecting cases
    let mut cases: Vec<(Vec<i128>, Vec<StructuredNode>)> =
        vec![(vec![first_info.value], then_body.to_vec())];
    let mut current_else = else_body.clone();
    let mut switch_var_key = first_info.var_key.clone();
    let mut switch_var_expr = first_info.var_expr.clone();
    let first_var_expr = first_info.var_expr.clone(); // Save original for mismatch case
    let mut first_var_mismatch = false;

    // Walk down the else chain
    while let Some(ref else_nodes) = current_else {
        // Find an If node in the else body (may be preceded by Block nodes)
        let mut found_if = false;
        for node in else_nodes {
            if let StructuredNode::If {
                condition: else_cond,
                then_body: else_then,
                else_body: nested_else,
            } = node
            {
                // Check if this condition matches our switch variable
                // Try both equality and range patterns
                if let Some((var_key, var_expr, values)) = extract_switch_case_or_range(else_cond) {
                    // If this is the second case and variable differs, switch to the new variable
                    // This handles cases where the first condition uses the original parameter
                    // but subsequent conditions use a copy
                    if cases.len() == 1 && var_key != switch_var_key {
                        // Change to the new variable for subsequent checks
                        switch_var_key = var_key.clone();
                        switch_var_expr = var_expr.clone();
                        first_var_mismatch = true;
                    }

                    if var_key == switch_var_key {
                        cases.push((values, else_then.to_vec()));
                        current_else = nested_else.clone();
                        found_if = true;
                        break;
                    }
                }
            }
        }

        if !found_if {
            // This else doesn't contain a matching If - it becomes the default case
            break;
        }
    }

    // Need at least 3 cases to be worth converting to switch
    // If first var mismatched, we need at least 4 cases (first case won't be included)
    let min_cases = if first_var_mismatch { 4 } else { 3 };
    if cases.len() < min_cases {
        return None;
    }

    // If first var mismatched, exclude the first case from the switch
    let (final_cases, first_case) = if first_var_mismatch {
        let mut iter = cases.into_iter();
        let first = iter.next();
        (iter.collect::<Vec<_>>(), first)
    } else {
        (cases, None)
    };

    // Reject switches where case values are duplicated.
    // This catches false positives like: if (x == 0) ... else if (y = foo(); y == 0) ...
    // where the same value appears multiple times due to variable reassignment.
    {
        let mut seen_values = std::collections::HashSet::new();
        for (vals, _) in &final_cases {
            for val in vals {
                if !seen_values.insert(*val) {
                    // Duplicate value found - this isn't a valid switch
                    return None;
                }
            }
        }
    }

    // Process the default case
    let default = current_else.map(detect_switch_statements);

    // Recursively process case bodies
    let final_cases = final_cases
        .into_iter()
        .map(|(vals, body)| (vals, detect_switch_statements(body)))
        .collect();

    let switch_node = StructuredNode::Switch {
        value: switch_var_expr.clone(),
        cases: final_cases,
        default,
    };

    // If we had a first case mismatch, wrap the switch in an if-else
    if let Some((first_vals, first_body)) = first_case {
        use super::super::expression::BinOpKind;
        let first_condition = Expr::binop(
            BinOpKind::Eq,
            first_var_expr.clone(),
            Expr::int(first_vals[0]),
        );
        Some(StructuredNode::If {
            condition: first_condition,
            then_body: detect_switch_statements(first_body),
            else_body: Some(vec![switch_node]),
        })
    } else {
        Some(switch_node)
    }
}

/// Try to extract a switch statement from a != pattern if-else chain.
///
/// Pattern: `if (x != A) { if (x != B) { default } else { caseB } } else { caseA }`
/// This is the inverted form where case bodies are in the else branches.
fn try_extract_switch_negated(
    first_info: &SwitchCaseInfo,
    then_body: &[StructuredNode],
    else_body: &Option<Vec<StructuredNode>>,
) -> Option<StructuredNode> {
    // For != pattern, the case body is in the else branch
    let first_case_body = else_body.as_ref()?.clone();

    let mut cases: Vec<(Vec<i128>, Vec<StructuredNode>)> =
        vec![(vec![first_info.value], first_case_body)];
    let switch_var_key = first_info.var_key.clone();
    let switch_var_expr = first_info.var_expr.clone();

    // The then_body contains the rest of the chain
    let mut current_then = then_body.to_vec();

    // Walk down the then chain (which is nested != comparisons)
    loop {
        // Find an If node in the then body
        let mut found_if = false;

        // Look for a single If node (possibly with some preceding statements)
        for node in &current_then {
            if let StructuredNode::If {
                condition: inner_cond,
                then_body: inner_then,
                else_body: inner_else,
            } = node
            {
                // Check if this condition is a != comparison on our switch variable
                if let Some(info) = extract_switch_case_info(inner_cond) {
                    if info.negated && info.var_key == switch_var_key {
                        // Case body is in else
                        if let Some(case_body) = inner_else {
                            cases.push((vec![info.value], case_body.clone()));
                            current_then = inner_then.clone();
                            found_if = true;
                            break;
                        }
                    }
                }
            }
        }

        if !found_if {
            // No more matching != patterns - current_then becomes the default
            break;
        }
    }

    // Need at least 3 cases to be worth converting to switch
    if cases.len() < 3 {
        return None;
    }

    // Reject switches where case values are duplicated.
    {
        let mut seen_values = std::collections::HashSet::new();
        for (vals, _) in &cases {
            for val in vals {
                if !seen_values.insert(*val) {
                    // Duplicate value found - this isn't a valid switch
                    return None;
                }
            }
        }
    }

    // The remaining then_body is the default case (when none of the values matched)
    let default = if current_then.is_empty() {
        None
    } else {
        Some(detect_switch_statements(current_then))
    };

    // Recursively process case bodies
    let final_cases: Vec<(Vec<i128>, Vec<StructuredNode>)> = cases
        .into_iter()
        .map(|(vals, body)| (vals, detect_switch_statements(body)))
        .collect();

    Some(StructuredNode::Switch {
        value: switch_var_expr,
        cases: final_cases,
        default,
    })
}

/// Result of extracting a switch case condition.
/// Contains the variable key, variable expression, comparison value, and whether it's negated.
struct SwitchCaseInfo {
    var_key: String,
    var_expr: Expr,
    value: i128,
    /// If true, condition is `var != N`, case body is in else branch.
    negated: bool,
}

/// Result of extracting a range-based switch case condition.
/// Contains the variable key, variable expression, and the range bounds.
pub(super) struct SwitchRangeInfo {
    pub(super) var_key: String,
    pub(super) var_expr: Expr,
    /// Inclusive start of the range.
    pub(super) start: i128,
    /// Inclusive end of the range.
    pub(super) end: i128,
}

/// Maximum size for a range to be expanded into individual case values.
/// Ranges larger than this will not be converted to switch cases to avoid
/// creating massive switch statements.
const MAX_SWITCH_RANGE_SIZE: i128 = 256;

/// Try to extract a range condition from an expression.
///
/// Detects patterns like:
/// - `x >= min && x <= max`
/// - `x > min - 1 && x < max + 1`
/// - `min <= x && x <= max`
///
/// Returns (var_key, var_expr, start, end) for the inclusive range [start, end].
pub(super) fn extract_switch_range_info(condition: &Expr) -> Option<SwitchRangeInfo> {
    use super::super::expression::BinOpKind;
    use super::super::expression::ExprKind;

    // Look for logical AND of two comparisons
    if let ExprKind::BinOp {
        op: BinOpKind::LogicalAnd,
        left,
        right,
    } = &condition.kind
    {
        // Try to extract bounds from both sides
        let left_bound = extract_range_bound(left);
        let right_bound = extract_range_bound(right);

        if let (Some(lb), Some(rb)) = (left_bound, right_bound) {
            // Both must reference the same variable
            if lb.var_key != rb.var_key {
                return None;
            }

            // Determine which is the lower and which is the upper bound
            let (start, end) = match (lb.is_lower, rb.is_lower) {
                (true, false) => (lb.value, rb.value), // x >= start && x <= end
                (false, true) => (rb.value, lb.value), // x <= end && x >= start
                _ => return None,                      // Both are same type - not a valid range
            };

            // Sanity check: start should be <= end and range should be reasonable
            if start > end {
                return None;
            }

            let range_size = end.saturating_sub(start).saturating_add(1);
            if range_size > MAX_SWITCH_RANGE_SIZE {
                return None;
            }

            return Some(SwitchRangeInfo {
                var_key: lb.var_key,
                var_expr: lb.var_expr,
                start,
                end,
            });
        }
    }

    None
}

/// Information about a single bound in a range condition.
struct RangeBoundInfo {
    var_key: String,
    var_expr: Expr,
    value: i128,
    /// True if this is a lower bound (x >= N or x > N)
    is_lower: bool,
}

/// Extract a range bound from a comparison expression.
/// Handles: x >= N, x > N, x <= N, x < N, N <= x, N < x, N >= x, N > x
fn extract_range_bound(expr: &Expr) -> Option<RangeBoundInfo> {
    use super::super::expression::BinOpKind;
    use super::super::expression::ExprKind;

    if let ExprKind::BinOp { op, left, right } = &expr.kind {
        // x op N
        if let Some(key) = get_expr_var_key(left) {
            if let ExprKind::IntLit(n) = right.kind {
                let (value, is_lower) = match op {
                    BinOpKind::Ge => (n, true),      // x >= n: lower bound, inclusive
                    BinOpKind::Gt => (n + 1, true),  // x > n: lower bound is n+1
                    BinOpKind::Le => (n, false),     // x <= n: upper bound, inclusive
                    BinOpKind::Lt => (n - 1, false), // x < n: upper bound is n-1
                    _ => return None,
                };
                return Some(RangeBoundInfo {
                    var_key: key,
                    var_expr: (**left).clone(),
                    value,
                    is_lower,
                });
            }
        }
        // N op x (reversed)
        if let Some(key) = get_expr_var_key(right) {
            if let ExprKind::IntLit(n) = left.kind {
                let (value, is_lower) = match op {
                    BinOpKind::Le => (n, true),      // n <= x: lower bound, inclusive
                    BinOpKind::Lt => (n + 1, true),  // n < x: lower bound is n+1
                    BinOpKind::Ge => (n, false),     // n >= x: upper bound, inclusive
                    BinOpKind::Gt => (n - 1, false), // n > x: upper bound is n-1
                    _ => return None,
                };
                return Some(RangeBoundInfo {
                    var_key: key,
                    var_expr: (**right).clone(),
                    value,
                    is_lower,
                });
            }
        }
    }

    None
}

/// Try to extract a switch case or range from a condition.
/// First tries exact match (var == N), then range match (x >= min && x <= max).
/// Returns (var_key, var_expr, values) where values is a Vec of all case values.
pub(super) fn extract_switch_case_or_range(condition: &Expr) -> Option<(String, Expr, Vec<i128>)> {
    // First try exact equality
    if let Some((key, expr, value)) = extract_switch_case(condition) {
        return Some((key, expr, vec![value]));
    }

    // Then try range
    if let Some(range_info) = extract_switch_range_info(condition) {
        let values: Vec<i128> = (range_info.start..=range_info.end).collect();
        return Some((range_info.var_key, range_info.var_expr, values));
    }

    None
}

/// Extract switch case from a condition: var == N or var != N
/// Returns the case info if it matches the pattern.
fn extract_switch_case_info(condition: &Expr) -> Option<SwitchCaseInfo> {
    use super::super::expression::BinOpKind;
    use super::super::expression::ExprKind;

    if let ExprKind::BinOp { op, left, right } = &condition.kind {
        let negated = match op {
            BinOpKind::Eq => false,
            BinOpKind::Ne => true,
            _ => return None,
        };

        // var == N or var != N
        if let Some(key) = get_expr_var_key(left) {
            if let ExprKind::IntLit(n) = right.kind {
                return Some(SwitchCaseInfo {
                    var_key: key,
                    var_expr: (**left).clone(),
                    value: n,
                    negated,
                });
            }
        }
        // N == var or N != var (reversed)
        if let Some(key) = get_expr_var_key(right) {
            if let ExprKind::IntLit(n) = left.kind {
                return Some(SwitchCaseInfo {
                    var_key: key,
                    var_expr: (**right).clone(),
                    value: n,
                    negated,
                });
            }
        }
    }

    None
}

/// Extract switch case from a condition: var == N (legacy wrapper)
/// Returns (variable_key, variable_expr, value) if it matches the pattern.
fn extract_switch_case(condition: &Expr) -> Option<(String, Expr, i128)> {
    let info = extract_switch_case_info(condition)?;
    // Only return for == patterns (legacy behavior)
    if !info.negated {
        Some((info.var_key, info.var_expr, info.value))
    } else {
        None
    }
}

/// Create a switch value expression from a variable key.
/// The key is the variable name returned by get_expr_var_key.
fn create_switch_value(var_key: &str) -> Expr {
    use super::super::expression::{Expr as E, VarKind, Variable};

    // The key is typically a variable name like "var_0", "stack_4", etc.
    // Create a simple variable expression with that name
    E::var(Variable {
        kind: VarKind::Temp(0),
        name: var_key.to_string(),
        size: 4,
    })
}

/// Create a comparison expression: var == value
fn create_comparison(var_key: &str, value: i128) -> Expr {
    use super::super::expression::{BinOpKind, Expr as E};

    let var_expr = create_switch_value(var_key);
    let val_expr = E::int(value);
    E::binop(BinOpKind::Eq, var_expr, val_expr)
}
