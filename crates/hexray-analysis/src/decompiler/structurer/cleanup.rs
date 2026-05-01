//! Goto-reduction passes that run after the basic CFG-to-tree
//! reduction has completed.
//!
//! Each entry point is idempotent and works at the
//! `Vec<StructuredNode>` level. Composed in order by the structurer
//! driver in [`super::Structurer::structurize`]:
//!
//! 1. [`convert_cleanup_gotos`] — `if (err) goto cleanup;` +
//!    trailing label-and-cleanup-block becomes the cleanup body
//!    inlined into the if-true branch.
//! 2. [`convert_gotos_to_early_returns`] — `goto ret_label;` where
//!    `ret_label` is a setup-and-return chunk becomes a direct
//!    `return <value>;` at the goto site.
//! 3. [`remove_orphan_labels`] — labels nobody jumps to anymore.
//! 4. [`convert_multilevel_breaks`] — gotos that escape an
//!    enclosing loop / switch into multilevel `break` (or just
//!    `break` when one level out is the closest scope).
//! 5. [`structure_shared_exits`] — collapses identical
//!    return/cleanup tails reached through multiple gotos.
//! 6. [`remove_orphan_gotos`] — `goto X;` where `X:` no longer
//!    exists in the tree (left behind by earlier passes).

use std::collections::{HashMap, HashSet};

use hexray_core::BasicBlockId;

use super::super::expression::Expr;
use super::{body_terminates, is_noreturn_call, CatchHandler, StructuredNode};

// ============================================================================
// Advanced Goto Reduction Passes
// ============================================================================

/// Converts gotos to labeled cleanup blocks into structured cleanup patterns.
///
/// This handles patterns like:
/// ```text
///     if (error) goto cleanup;
///     // normal code
///   cleanup:
///     close(fd);
///     return -1;
/// ```
///
/// Converting to:
/// ```text
///     if (error) {
///         close(fd);
///         return -1;
///     }
///     // normal code
/// ```
pub fn convert_cleanup_gotos(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    // Step 1: Identify labeled cleanup blocks (labels followed by cleanup code then return/break)
    let cleanup_blocks = identify_cleanup_blocks(&nodes);

    if cleanup_blocks.is_empty() {
        return nodes;
    }

    // Step 2: Inline cleanup blocks at goto sites and remove original labels
    inline_cleanup_blocks(nodes, &cleanup_blocks)
}

/// Identifies labeled blocks that are cleanup patterns.
/// A cleanup block is a label followed by code ending in return/break.
fn identify_cleanup_blocks(nodes: &[StructuredNode]) -> HashMap<BasicBlockId, Vec<StructuredNode>> {
    let mut cleanup_blocks = HashMap::new();

    let mut i = 0;
    while i < nodes.len() {
        // Look for Label followed by cleanup code
        if let StructuredNode::Label(label_id) = &nodes[i] {
            // Collect the cleanup body until we hit another label or end
            let mut cleanup_body = Vec::new();
            let mut j = i + 1;
            let mut ends_with_terminator = false;

            while j < nodes.len() {
                match &nodes[j] {
                    StructuredNode::Label(_) => break,
                    node => {
                        let terminates = node_terminates(node);
                        cleanup_body.push(nodes[j].clone());
                        if terminates {
                            ends_with_terminator = true;
                            break;
                        }
                    }
                }
                j += 1;
            }

            // Only treat as cleanup if it terminates and is reasonably short
            if ends_with_terminator && cleanup_body.len() <= 5 {
                cleanup_blocks.insert(*label_id, cleanup_body);
            }
        }
        i += 1;
    }

    cleanup_blocks
}

/// Checks if a single node terminates control flow.
fn node_terminates(node: &StructuredNode) -> bool {
    match node {
        StructuredNode::Return(_) => true,
        StructuredNode::Break => true,
        StructuredNode::Continue => true,
        StructuredNode::Goto(_) => true,
        StructuredNode::If {
            then_body,
            else_body,
            ..
        } => body_terminates(then_body) && else_body.as_ref().is_some_and(|e| body_terminates(e)),
        StructuredNode::Block { statements, .. } => statements.last().is_some_and(is_noreturn_call),
        _ => false,
    }
}

/// Inlines cleanup blocks at goto sites and removes original labels.
fn inline_cleanup_blocks(
    nodes: Vec<StructuredNode>,
    cleanup_blocks: &HashMap<BasicBlockId, Vec<StructuredNode>>,
) -> Vec<StructuredNode> {
    let mut result = Vec::new();

    for node in nodes {
        match node {
            // Replace goto to cleanup with inlined cleanup code
            StructuredNode::Goto(target) if cleanup_blocks.contains_key(&target) => {
                let cleanup = cleanup_blocks.get(&target).unwrap();
                result.extend(cleanup.clone());
            }

            // Remove labels that have been inlined (keep if there are non-inlined gotos)
            StructuredNode::Label(label_id) if cleanup_blocks.contains_key(&label_id) => {
                // Skip the label - it's being inlined
            }

            // Recurse into compound structures
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                result.push(StructuredNode::If {
                    condition,
                    then_body: inline_cleanup_blocks(then_body, cleanup_blocks),
                    else_body: else_body.map(|e| inline_cleanup_blocks(e, cleanup_blocks)),
                });
            }

            StructuredNode::While {
                condition,
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::While {
                    condition,
                    body: inline_cleanup_blocks(body, cleanup_blocks),
                    header,
                    exit_block,
                });
            }

            StructuredNode::DoWhile {
                body,
                condition,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::DoWhile {
                    body: inline_cleanup_blocks(body, cleanup_blocks),
                    condition,
                    header,
                    exit_block,
                });
            }

            StructuredNode::For {
                init,
                condition,
                update,
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::For {
                    init,
                    condition,
                    update,
                    body: inline_cleanup_blocks(body, cleanup_blocks),
                    header,
                    exit_block,
                });
            }

            StructuredNode::Loop {
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::Loop {
                    body: inline_cleanup_blocks(body, cleanup_blocks),
                    header,
                    exit_block,
                });
            }

            StructuredNode::Switch {
                value,
                cases,
                default,
            } => {
                result.push(StructuredNode::Switch {
                    value,
                    cases: cases
                        .into_iter()
                        .map(|(vals, body)| (vals, inline_cleanup_blocks(body, cleanup_blocks)))
                        .collect(),
                    default: default.map(|d| inline_cleanup_blocks(d, cleanup_blocks)),
                });
            }

            StructuredNode::Sequence(seq) => {
                let converted = inline_cleanup_blocks(seq, cleanup_blocks);
                // Flatten sequences
                result.extend(converted);
            }

            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                result.push(StructuredNode::TryCatch {
                    try_body: inline_cleanup_blocks(try_body, cleanup_blocks),
                    catch_handlers: catch_handlers
                        .into_iter()
                        .map(|h| CatchHandler {
                            body: inline_cleanup_blocks(h.body, cleanup_blocks),
                            ..h
                        })
                        .collect(),
                });
            }

            other => result.push(other),
        }
    }

    result
}

/// Converts gotos that target blocks containing only a return into direct returns.
///
/// This handles patterns like:
/// ```text
///     if (cond) goto ret_label;
///     ...
///   ret_label:
///     return x;
/// ```
///
/// Converting to:
/// ```text
///     if (cond) return x;
///     ...
/// ```
pub fn convert_gotos_to_early_returns(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    // Step 1: Identify labels that just contain a return
    let return_labels = identify_return_labels(&nodes);

    if return_labels.is_empty() {
        return nodes;
    }

    // Step 2: Replace gotos with returns and remove the original labels
    convert_gotos_to_returns_impl(nodes, &return_labels)
}

/// Identifies labels that are followed only by a return statement.
fn identify_return_labels(nodes: &[StructuredNode]) -> HashMap<BasicBlockId, Option<Expr>> {
    let mut return_labels = HashMap::new();

    let mut i = 0;
    while i < nodes.len() {
        if let StructuredNode::Label(label_id) = &nodes[i] {
            // Check what follows the label
            if i + 1 < nodes.len() {
                match &nodes[i + 1] {
                    StructuredNode::Return(expr) => {
                        return_labels.insert(*label_id, expr.clone());
                    }
                    StructuredNode::Block { statements, .. } => {
                        // Check if block just contains return value setup
                        if statements.is_empty() && i + 2 < nodes.len() {
                            if let StructuredNode::Return(expr) = &nodes[i + 2] {
                                return_labels.insert(*label_id, expr.clone());
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        i += 1;
    }

    return_labels
}

/// Converts gotos to return labels into direct returns.
fn convert_gotos_to_returns_impl(
    nodes: Vec<StructuredNode>,
    return_labels: &HashMap<BasicBlockId, Option<Expr>>,
) -> Vec<StructuredNode> {
    let mut result = Vec::new();
    let mut skip_next_return = false;

    for node in nodes {
        if skip_next_return {
            if matches!(node, StructuredNode::Return(_)) {
                skip_next_return = false;
                continue;
            }
            skip_next_return = false;
        }

        match node {
            // Replace goto to return label with direct return
            StructuredNode::Goto(target) if return_labels.contains_key(&target) => {
                let ret_expr = return_labels.get(&target).unwrap();
                result.push(StructuredNode::Return(ret_expr.clone()));
            }

            // Remove labels that have been converted (but keep if referenced elsewhere)
            StructuredNode::Label(label_id) if return_labels.contains_key(&label_id) => {
                skip_next_return = true;
                // Skip label and following return
            }

            // Recurse into compound structures
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                result.push(StructuredNode::If {
                    condition,
                    then_body: convert_gotos_to_returns_impl(then_body, return_labels),
                    else_body: else_body.map(|e| convert_gotos_to_returns_impl(e, return_labels)),
                });
            }

            StructuredNode::While {
                condition,
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::While {
                    condition,
                    body: convert_gotos_to_returns_impl(body, return_labels),
                    header,
                    exit_block,
                });
            }

            StructuredNode::DoWhile {
                body,
                condition,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::DoWhile {
                    body: convert_gotos_to_returns_impl(body, return_labels),
                    condition,
                    header,
                    exit_block,
                });
            }

            StructuredNode::For {
                init,
                condition,
                update,
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::For {
                    init,
                    condition,
                    update,
                    body: convert_gotos_to_returns_impl(body, return_labels),
                    header,
                    exit_block,
                });
            }

            StructuredNode::Loop {
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::Loop {
                    body: convert_gotos_to_returns_impl(body, return_labels),
                    header,
                    exit_block,
                });
            }

            StructuredNode::Switch {
                value,
                cases,
                default,
            } => {
                result.push(StructuredNode::Switch {
                    value,
                    cases: cases
                        .into_iter()
                        .map(|(vals, body)| {
                            (vals, convert_gotos_to_returns_impl(body, return_labels))
                        })
                        .collect(),
                    default: default.map(|d| convert_gotos_to_returns_impl(d, return_labels)),
                });
            }

            StructuredNode::Sequence(seq) => {
                result.push(StructuredNode::Sequence(convert_gotos_to_returns_impl(
                    seq,
                    return_labels,
                )));
            }

            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                result.push(StructuredNode::TryCatch {
                    try_body: convert_gotos_to_returns_impl(try_body, return_labels),
                    catch_handlers: catch_handlers
                        .into_iter()
                        .map(|h| CatchHandler {
                            body: convert_gotos_to_returns_impl(h.body, return_labels),
                            ..h
                        })
                        .collect(),
                });
            }

            other => result.push(other),
        }
    }

    result
}

/// Removes orphan labels that have no gotos targeting them.
///
/// After other goto reduction passes, some labels may no longer be needed.
/// This pass removes them and integrates their code into the normal flow.
pub fn remove_orphan_labels(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    // Step 1: Collect all goto targets
    let goto_targets = collect_goto_targets(&nodes);

    // Step 2: Remove labels not in the target set
    remove_unused_labels(nodes, &goto_targets)
}

/// Collects all goto targets from the structured nodes.
fn collect_goto_targets(nodes: &[StructuredNode]) -> HashSet<BasicBlockId> {
    let mut targets = HashSet::new();

    for node in nodes {
        collect_goto_targets_in_node(node, &mut targets);
    }

    targets
}

fn collect_goto_targets_in_node(node: &StructuredNode, targets: &mut HashSet<BasicBlockId>) {
    match node {
        StructuredNode::Goto(target) => {
            targets.insert(*target);
        }
        StructuredNode::If {
            then_body,
            else_body,
            ..
        } => {
            for n in then_body {
                collect_goto_targets_in_node(n, targets);
            }
            if let Some(eb) = else_body {
                for n in eb {
                    collect_goto_targets_in_node(n, targets);
                }
            }
        }
        StructuredNode::While { body, .. }
        | StructuredNode::DoWhile { body, .. }
        | StructuredNode::Loop { body, .. }
        | StructuredNode::For { body, .. } => {
            for n in body {
                collect_goto_targets_in_node(n, targets);
            }
        }
        StructuredNode::Switch { cases, default, .. } => {
            for (_, body) in cases {
                for n in body {
                    collect_goto_targets_in_node(n, targets);
                }
            }
            if let Some(d) = default {
                for n in d {
                    collect_goto_targets_in_node(n, targets);
                }
            }
        }
        StructuredNode::Sequence(seq) => {
            for n in seq {
                collect_goto_targets_in_node(n, targets);
            }
        }
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => {
            for n in try_body {
                collect_goto_targets_in_node(n, targets);
            }
            for h in catch_handlers {
                for n in &h.body {
                    collect_goto_targets_in_node(n, targets);
                }
            }
        }
        _ => {}
    }
}

/// Removes labels not targeted by any goto.
fn remove_unused_labels(
    nodes: Vec<StructuredNode>,
    goto_targets: &HashSet<BasicBlockId>,
) -> Vec<StructuredNode> {
    let mut result = Vec::new();

    for node in nodes {
        match node {
            StructuredNode::Label(label_id) if !goto_targets.contains(&label_id) => {
                // Skip orphan label
            }

            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                result.push(StructuredNode::If {
                    condition,
                    then_body: remove_unused_labels(then_body, goto_targets),
                    else_body: else_body.map(|e| remove_unused_labels(e, goto_targets)),
                });
            }

            StructuredNode::While {
                condition,
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::While {
                    condition,
                    body: remove_unused_labels(body, goto_targets),
                    header,
                    exit_block,
                });
            }

            StructuredNode::DoWhile {
                body,
                condition,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::DoWhile {
                    body: remove_unused_labels(body, goto_targets),
                    condition,
                    header,
                    exit_block,
                });
            }

            StructuredNode::For {
                init,
                condition,
                update,
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::For {
                    init,
                    condition,
                    update,
                    body: remove_unused_labels(body, goto_targets),
                    header,
                    exit_block,
                });
            }

            StructuredNode::Loop {
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::Loop {
                    body: remove_unused_labels(body, goto_targets),
                    header,
                    exit_block,
                });
            }

            StructuredNode::Switch {
                value,
                cases,
                default,
            } => {
                result.push(StructuredNode::Switch {
                    value,
                    cases: cases
                        .into_iter()
                        .map(|(vals, body)| (vals, remove_unused_labels(body, goto_targets)))
                        .collect(),
                    default: default.map(|d| remove_unused_labels(d, goto_targets)),
                });
            }

            StructuredNode::Sequence(seq) => {
                let cleaned = remove_unused_labels(seq, goto_targets);
                result.extend(cleaned);
            }

            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                result.push(StructuredNode::TryCatch {
                    try_body: remove_unused_labels(try_body, goto_targets),
                    catch_handlers: catch_handlers
                        .into_iter()
                        .map(|h| CatchHandler {
                            body: remove_unused_labels(h.body, goto_targets),
                            ..h
                        })
                        .collect(),
                });
            }

            other => result.push(other),
        }
    }

    result
}

/// Converts multi-level break patterns (gotos that escape nested loops)
/// into flag variables or early returns where possible.
///
/// This handles patterns like:
/// ```text
///   while (cond1) {
///     while (cond2) {
///       if (error) goto outer_exit;
///     }
///   }
/// outer_exit:
///   // code
/// ```
///
/// Converting to:
/// ```text
///   bool break_outer = false;
///   while (cond1 && !break_outer) {
///     while (cond2) {
///       if (error) { break_outer = true; break; }
///     }
///     if (break_outer) break;
///   }
///   // code
/// ```
pub fn convert_multilevel_breaks(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    // Identify gotos that escape multiple loop levels
    let multilevel_gotos = find_multilevel_escape_gotos(&nodes);

    if multilevel_gotos.is_empty() {
        return nodes;
    }

    // For simple cases where the goto target is just after the outer loop,
    // convert to break instead of flag variable
    convert_multilevel_to_break(nodes, &multilevel_gotos)
}

/// Finds gotos that escape multiple nesting levels.
fn find_multilevel_escape_gotos(nodes: &[StructuredNode]) -> HashSet<BasicBlockId> {
    let mut escaping = HashSet::new();

    // Find labels that appear after loops at top level
    let mut label_positions: HashMap<BasicBlockId, usize> = HashMap::new();
    for (i, node) in nodes.iter().enumerate() {
        if let StructuredNode::Label(id) = node {
            label_positions.insert(*id, i);
        }
    }

    // Find gotos inside nested loops that target these labels
    for (i, node) in nodes.iter().enumerate() {
        match node {
            StructuredNode::While { body, .. }
            | StructuredNode::DoWhile { body, .. }
            | StructuredNode::Loop { body, .. }
            | StructuredNode::For { body, .. } => {
                // Check for gotos inside the loop that escape to labels after this loop
                find_escaping_gotos_in_loop(body, &label_positions, i, &mut escaping);
            }
            _ => {}
        }
    }

    escaping
}

/// Finds gotos in a loop body that escape to labels defined outside.
fn find_escaping_gotos_in_loop(
    body: &[StructuredNode],
    label_positions: &HashMap<BasicBlockId, usize>,
    loop_pos: usize,
    escaping: &mut HashSet<BasicBlockId>,
) {
    for node in body {
        match node {
            StructuredNode::Goto(target) => {
                // If this goto targets a label after the loop, it's an escape
                if let Some(&label_pos) = label_positions.get(target) {
                    if label_pos > loop_pos {
                        escaping.insert(*target);
                    }
                }
            }
            StructuredNode::If {
                then_body,
                else_body,
                ..
            } => {
                find_escaping_gotos_in_loop(then_body, label_positions, loop_pos, escaping);
                if let Some(eb) = else_body {
                    find_escaping_gotos_in_loop(eb, label_positions, loop_pos, escaping);
                }
            }
            StructuredNode::While { body: inner, .. }
            | StructuredNode::DoWhile { body: inner, .. }
            | StructuredNode::Loop { body: inner, .. }
            | StructuredNode::For { body: inner, .. } => {
                // Nested loop - these gotos escape multiple levels
                find_escaping_gotos_in_loop(inner, label_positions, loop_pos, escaping);
            }
            StructuredNode::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    find_escaping_gotos_in_loop(case_body, label_positions, loop_pos, escaping);
                }
                if let Some(d) = default {
                    find_escaping_gotos_in_loop(d, label_positions, loop_pos, escaping);
                }
            }
            StructuredNode::Sequence(seq) => {
                find_escaping_gotos_in_loop(seq, label_positions, loop_pos, escaping);
            }
            _ => {}
        }
    }
}

/// Converts multilevel escape gotos to break statements.
fn convert_multilevel_to_break(
    nodes: Vec<StructuredNode>,
    targets: &HashSet<BasicBlockId>,
) -> Vec<StructuredNode> {
    let mut result = Vec::new();

    for node in nodes {
        match node {
            StructuredNode::While {
                condition,
                body,
                header,
                exit_block,
            } => {
                // Convert gotos to targets in the body to breaks
                let new_body = convert_escaping_gotos_to_break(body, targets);
                result.push(StructuredNode::While {
                    condition,
                    body: new_body,
                    header,
                    exit_block,
                });
            }

            StructuredNode::DoWhile {
                body,
                condition,
                header,
                exit_block,
            } => {
                let new_body = convert_escaping_gotos_to_break(body, targets);
                result.push(StructuredNode::DoWhile {
                    body: new_body,
                    condition,
                    header,
                    exit_block,
                });
            }

            StructuredNode::For {
                init,
                condition,
                update,
                body,
                header,
                exit_block,
            } => {
                let new_body = convert_escaping_gotos_to_break(body, targets);
                result.push(StructuredNode::For {
                    init,
                    condition,
                    update,
                    body: new_body,
                    header,
                    exit_block,
                });
            }

            StructuredNode::Loop {
                body,
                header,
                exit_block,
            } => {
                let new_body = convert_escaping_gotos_to_break(body, targets);
                result.push(StructuredNode::Loop {
                    body: new_body,
                    header,
                    exit_block,
                });
            }

            // Remove labels that are now break targets
            StructuredNode::Label(id) if targets.contains(&id) => {
                // Keep the label for now - remove_orphan_labels will clean it up
                // if no gotos remain
                result.push(StructuredNode::Label(id));
            }

            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                result.push(StructuredNode::If {
                    condition,
                    then_body: convert_multilevel_to_break(then_body, targets),
                    else_body: else_body.map(|e| convert_multilevel_to_break(e, targets)),
                });
            }

            StructuredNode::Switch {
                value,
                cases,
                default,
            } => {
                result.push(StructuredNode::Switch {
                    value,
                    cases: cases
                        .into_iter()
                        .map(|(vals, body)| (vals, convert_multilevel_to_break(body, targets)))
                        .collect(),
                    default: default.map(|d| convert_multilevel_to_break(d, targets)),
                });
            }

            StructuredNode::Sequence(seq) => {
                result.extend(convert_multilevel_to_break(seq, targets));
            }

            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                result.push(StructuredNode::TryCatch {
                    try_body: convert_multilevel_to_break(try_body, targets),
                    catch_handlers: catch_handlers
                        .into_iter()
                        .map(|h| CatchHandler {
                            body: convert_multilevel_to_break(h.body, targets),
                            ..h
                        })
                        .collect(),
                });
            }

            other => result.push(other),
        }
    }

    result
}

/// Converts gotos to escape targets into breaks.
fn convert_escaping_gotos_to_break(
    nodes: Vec<StructuredNode>,
    targets: &HashSet<BasicBlockId>,
) -> Vec<StructuredNode> {
    nodes
        .into_iter()
        .map(|node| match node {
            StructuredNode::Goto(target) if targets.contains(&target) => StructuredNode::Break,

            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => StructuredNode::If {
                condition,
                then_body: convert_escaping_gotos_to_break(then_body, targets),
                else_body: else_body.map(|e| convert_escaping_gotos_to_break(e, targets)),
            },

            // Don't recurse into nested loops - those need their own exit handling
            StructuredNode::While {
                condition,
                body,
                header,
                exit_block,
            } => StructuredNode::While {
                condition,
                body: convert_escaping_gotos_to_break(body, targets),
                header,
                exit_block,
            },

            StructuredNode::DoWhile {
                body,
                condition,
                header,
                exit_block,
            } => StructuredNode::DoWhile {
                body: convert_escaping_gotos_to_break(body, targets),
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
                body: convert_escaping_gotos_to_break(body, targets),
                header,
                exit_block,
            },

            StructuredNode::Loop {
                body,
                header,
                exit_block,
            } => StructuredNode::Loop {
                body: convert_escaping_gotos_to_break(body, targets),
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
                    .map(|(vals, body)| (vals, convert_escaping_gotos_to_break(body, targets)))
                    .collect(),
                default: default.map(|d| convert_escaping_gotos_to_break(d, targets)),
            },

            StructuredNode::Sequence(seq) => {
                StructuredNode::Sequence(convert_escaping_gotos_to_break(seq, targets))
            }

            other => other,
        })
        .collect()
}

/// Structures shared exit paths by detecting when multiple gotos target the same block.
///
/// This identifies patterns where different code paths converge and restructures
/// them to avoid gotos where possible.
pub fn structure_shared_exits(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    // Count how many gotos target each label
    let mut goto_counts: HashMap<BasicBlockId, usize> = HashMap::new();
    count_goto_targets(&nodes, &mut goto_counts);

    // For labels with multiple gotos, keep them
    // For labels with single gotos, try to inline
    let single_target_labels: HashSet<BasicBlockId> = goto_counts
        .iter()
        .filter(|(_, &count)| count == 1)
        .map(|(&id, _)| id)
        .collect();

    if single_target_labels.is_empty() {
        return nodes;
    }

    // Find the content of single-target labels and inline them
    let label_contents = extract_label_contents(&nodes, &single_target_labels);
    inline_single_target_labels(nodes, &label_contents)
}

/// Counts gotos to each target.
fn count_goto_targets(nodes: &[StructuredNode], counts: &mut HashMap<BasicBlockId, usize>) {
    for node in nodes {
        match node {
            StructuredNode::Goto(target) => {
                *counts.entry(*target).or_insert(0) += 1;
            }
            StructuredNode::If {
                then_body,
                else_body,
                ..
            } => {
                count_goto_targets(then_body, counts);
                if let Some(eb) = else_body {
                    count_goto_targets(eb, counts);
                }
            }
            StructuredNode::While { body, .. }
            | StructuredNode::DoWhile { body, .. }
            | StructuredNode::Loop { body, .. }
            | StructuredNode::For { body, .. } => {
                count_goto_targets(body, counts);
            }
            StructuredNode::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    count_goto_targets(body, counts);
                }
                if let Some(d) = default {
                    count_goto_targets(d, counts);
                }
            }
            StructuredNode::Sequence(seq) => {
                count_goto_targets(seq, counts);
            }
            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                count_goto_targets(try_body, counts);
                for h in catch_handlers {
                    count_goto_targets(&h.body, counts);
                }
            }
            _ => {}
        }
    }
}

/// Extracts the content following single-target labels.
fn extract_label_contents(
    nodes: &[StructuredNode],
    targets: &HashSet<BasicBlockId>,
) -> HashMap<BasicBlockId, Vec<StructuredNode>> {
    let mut contents = HashMap::new();

    let mut i = 0;
    while i < nodes.len() {
        if let StructuredNode::Label(label_id) = &nodes[i] {
            if targets.contains(label_id) {
                // Collect everything after this label until the next label or end
                let mut content = Vec::new();
                let mut j = i + 1;
                while j < nodes.len() {
                    if matches!(nodes[j], StructuredNode::Label(_)) {
                        break;
                    }
                    content.push(nodes[j].clone());
                    j += 1;
                }
                if !content.is_empty() {
                    contents.insert(*label_id, content);
                }
            }
        }
        i += 1;
    }

    contents
}

/// Inlines single-target labels.
fn inline_single_target_labels(
    nodes: Vec<StructuredNode>,
    contents: &HashMap<BasicBlockId, Vec<StructuredNode>>,
) -> Vec<StructuredNode> {
    let mut result = Vec::new();

    for node in nodes {
        match node {
            StructuredNode::Goto(target) if contents.contains_key(&target) => {
                // Replace goto with inlined content
                result.extend(contents.get(&target).unwrap().clone());
            }

            // Skip single-target labels and their content (already inlined)
            StructuredNode::Label(id) if contents.contains_key(&id) => {
                // Skip - content is inlined at goto site
            }

            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                result.push(StructuredNode::If {
                    condition,
                    then_body: inline_single_target_labels(then_body, contents),
                    else_body: else_body.map(|e| inline_single_target_labels(e, contents)),
                });
            }

            StructuredNode::While {
                condition,
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::While {
                    condition,
                    body: inline_single_target_labels(body, contents),
                    header,
                    exit_block,
                });
            }

            StructuredNode::DoWhile {
                body,
                condition,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::DoWhile {
                    body: inline_single_target_labels(body, contents),
                    condition,
                    header,
                    exit_block,
                });
            }

            StructuredNode::For {
                init,
                condition,
                update,
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::For {
                    init,
                    condition,
                    update,
                    body: inline_single_target_labels(body, contents),
                    header,
                    exit_block,
                });
            }

            StructuredNode::Loop {
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::Loop {
                    body: inline_single_target_labels(body, contents),
                    header,
                    exit_block,
                });
            }

            StructuredNode::Switch {
                value,
                cases,
                default,
            } => {
                result.push(StructuredNode::Switch {
                    value,
                    cases: cases
                        .into_iter()
                        .map(|(vals, body)| (vals, inline_single_target_labels(body, contents)))
                        .collect(),
                    default: default.map(|d| inline_single_target_labels(d, contents)),
                });
            }

            StructuredNode::Sequence(seq) => {
                result.extend(inline_single_target_labels(seq, contents));
            }

            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                result.push(StructuredNode::TryCatch {
                    try_body: inline_single_target_labels(try_body, contents),
                    catch_handlers: catch_handlers
                        .into_iter()
                        .map(|h| CatchHandler {
                            body: inline_single_target_labels(h.body, contents),
                            ..h
                        })
                        .collect(),
                });
            }

            other => result.push(other),
        }
    }

    result
}

/// Removes orphan gotos - gotos that target blocks with no corresponding labels.
///
/// These gotos are effectively unreachable or targets blocks that were inlined
/// elsewhere. The goto statements are removed if:
/// 1. The goto appears as the last statement in a sequence (dead code after loop exit)
/// 2. The goto appears right before code that will execute anyway (fallthrough)
///
/// For gotos that can't be removed, we leave them with a comment indicating
/// they're unresolved.
pub fn remove_orphan_gotos(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    // First, collect all labels that exist
    let existing_labels = collect_all_labels(&nodes);

    // Then, remove gotos to non-existent labels
    remove_gotos_without_labels(nodes, &existing_labels)
}

/// Collects all Label node targets from the structure.
fn collect_all_labels(nodes: &[StructuredNode]) -> HashSet<BasicBlockId> {
    let mut labels = HashSet::new();

    for node in nodes {
        match node {
            StructuredNode::Label(id) => {
                labels.insert(*id);
            }
            StructuredNode::If {
                then_body,
                else_body,
                ..
            } => {
                labels.extend(collect_all_labels(then_body));
                if let Some(eb) = else_body {
                    labels.extend(collect_all_labels(eb));
                }
            }
            StructuredNode::While { body, .. }
            | StructuredNode::DoWhile { body, .. }
            | StructuredNode::Loop { body, .. }
            | StructuredNode::For { body, .. } => {
                labels.extend(collect_all_labels(body));
            }
            StructuredNode::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    labels.extend(collect_all_labels(body));
                }
                if let Some(d) = default {
                    labels.extend(collect_all_labels(d));
                }
            }
            StructuredNode::Sequence(seq) => {
                labels.extend(collect_all_labels(seq));
            }
            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                labels.extend(collect_all_labels(try_body));
                for h in catch_handlers {
                    labels.extend(collect_all_labels(&h.body));
                }
            }
            _ => {}
        }
    }

    labels
}

/// Removes gotos that don't have corresponding labels.
fn remove_gotos_without_labels(
    nodes: Vec<StructuredNode>,
    existing_labels: &HashSet<BasicBlockId>,
) -> Vec<StructuredNode> {
    let mut result = Vec::new();

    for node in nodes {
        match node {
            // Skip gotos to non-existent labels
            StructuredNode::Goto(target) if !existing_labels.contains(&target) => {
                // Skip this goto - it targets a non-existent label
                // This likely means the target was inlined elsewhere
            }

            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                let new_then = remove_gotos_without_labels(then_body, existing_labels);
                let new_else = else_body.map(|e| remove_gotos_without_labels(e, existing_labels));

                // Always emit the If structure - even with empty bodies, the condition may have side effects
                // and we want to preserve the control flow structure
                result.push(StructuredNode::If {
                    condition,
                    then_body: new_then,
                    else_body: new_else,
                });
            }

            StructuredNode::While {
                condition,
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::While {
                    condition,
                    body: remove_gotos_without_labels(body, existing_labels),
                    header,
                    exit_block,
                });
            }

            StructuredNode::DoWhile {
                body,
                condition,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::DoWhile {
                    body: remove_gotos_without_labels(body, existing_labels),
                    condition,
                    header,
                    exit_block,
                });
            }

            StructuredNode::For {
                init,
                condition,
                update,
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::For {
                    init,
                    condition,
                    update,
                    body: remove_gotos_without_labels(body, existing_labels),
                    header,
                    exit_block,
                });
            }

            StructuredNode::Loop {
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::Loop {
                    body: remove_gotos_without_labels(body, existing_labels),
                    header,
                    exit_block,
                });
            }

            StructuredNode::Switch {
                value,
                cases,
                default,
            } => {
                result.push(StructuredNode::Switch {
                    value,
                    cases: cases
                        .into_iter()
                        .map(|(vals, body)| {
                            (vals, remove_gotos_without_labels(body, existing_labels))
                        })
                        .collect(),
                    default: default.map(|d| remove_gotos_without_labels(d, existing_labels)),
                });
            }

            StructuredNode::Sequence(seq) => {
                let cleaned = remove_gotos_without_labels(seq, existing_labels);
                result.extend(cleaned);
            }

            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                result.push(StructuredNode::TryCatch {
                    try_body: remove_gotos_without_labels(try_body, existing_labels),
                    catch_handlers: catch_handlers
                        .into_iter()
                        .map(|h| CatchHandler {
                            body: remove_gotos_without_labels(h.body, existing_labels),
                            ..h
                        })
                        .collect(),
                });
            }

            other => result.push(other),
        }
    }

    result
}

// ============================================================================
// End of Goto Reduction Passes
