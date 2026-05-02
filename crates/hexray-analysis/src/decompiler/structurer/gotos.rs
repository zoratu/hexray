//! Goto → break/continue conversion.
//!
//! Runs after the main CFG-to-tree reduction (see
//! [`super::Structurer`]) and before the broader cleanup-goto passes
//! ([`super::cleanup`]). Each entry point is idempotent on its
//! `Vec<StructuredNode>` input.
//!
//! Pass order from the structurer driver:
//!
//! 1. `convert_gotos_to_break_continue` — `goto loop_header` ⟶
//!    `continue`, `goto loop_exit` ⟶ `break`. Walks the tree
//!    carrying the surrounding `LoopContext`.
//! 2. `convert_global_gotos_to_continue` — global gotos that target
//!    *any* known loop header become `continue` even when not
//!    nested directly inside that loop.
//! 3. `convert_switch_gotos_to_break` — gotos inside switch arms
//!    that all target the same fall-through label collapse to
//!    `break;` (with the trailing label dropped at the switch
//!    boundary).

use std::collections::{HashMap, HashSet};

use hexray_core::BasicBlockId;

use super::{CatchHandler, StructuredNode};

/// Context for tracking the current loop during goto-to-break/continue conversion.
#[derive(Clone)]
pub(super) struct LoopContext {
    /// Block ID of the loop header (for continue detection).
    pub(super) header: BasicBlockId,
    /// Block ID of the loop exit (for break detection).
    pub(super) exit_block: Option<BasicBlockId>,
}

/// Converts goto statements to break/continue where applicable.
///
/// This pass runs after the main structuring and converts:
/// - `goto loop_header` inside a loop body → `continue`
/// - Gotos that exit a loop are handled specially (could become break in some cases)
pub(super) fn convert_gotos_to_break_continue(
    nodes: Vec<StructuredNode>,
    current_loop: Option<&LoopContext>,
) -> Vec<StructuredNode> {
    nodes
        .into_iter()
        .map(|node| convert_gotos_in_node(node, current_loop))
        .collect()
}

/// Converts gotos in a single node.
fn convert_gotos_in_node(
    node: StructuredNode,
    current_loop: Option<&LoopContext>,
) -> StructuredNode {
    match node {
        // For loops, create a new loop context for the body using the stored header
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => {
            // Create a loop context from the stored header and exit block
            let loop_ctx = header.map(|h| LoopContext {
                header: h,
                exit_block,
            });
            let ctx = loop_ctx.as_ref().or(current_loop);
            StructuredNode::While {
                condition,
                body: convert_gotos_in_loop_body(body, ctx),
                header,
                exit_block,
            }
        }
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => {
            let loop_ctx = header.map(|h| LoopContext {
                header: h,
                exit_block,
            });
            let ctx = loop_ctx.as_ref().or(current_loop);
            StructuredNode::DoWhile {
                body: convert_gotos_in_loop_body(body, ctx),
                condition,
                header,
                exit_block,
            }
        }
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => {
            let loop_ctx = header.map(|h| LoopContext {
                header: h,
                exit_block,
            });
            let ctx = loop_ctx.as_ref().or(current_loop);
            StructuredNode::Loop {
                body: convert_gotos_in_loop_body(body, ctx),
                header,
                exit_block,
            }
        }
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => {
            let loop_ctx = header.map(|h| LoopContext {
                header: h,
                exit_block,
            });
            let ctx = loop_ctx.as_ref().or(current_loop);
            StructuredNode::For {
                init,
                condition,
                update,
                body: convert_gotos_in_loop_body(body, ctx),
                header,
                exit_block,
            }
        }
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition,
            then_body: convert_gotos_to_break_continue(then_body, current_loop),
            else_body: else_body.map(|e| convert_gotos_to_break_continue(e, current_loop)),
        },
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value,
            cases: cases
                .into_iter()
                .map(|(vals, body)| (vals, convert_gotos_to_break_continue(body, current_loop)))
                .collect(),
            default: default.map(|d| convert_gotos_to_break_continue(d, current_loop)),
        },
        StructuredNode::Sequence(nodes) => {
            StructuredNode::Sequence(convert_gotos_to_break_continue(nodes, current_loop))
        }
        // Check if this goto should become break or continue
        StructuredNode::Goto(target) => {
            if let Some(ctx) = current_loop {
                if target == ctx.header {
                    // Goto to loop header = continue
                    return StructuredNode::Continue;
                }
                // Check if goto targets the loop exit block = break
                if let Some(exit) = ctx.exit_block {
                    if target == exit {
                        return StructuredNode::Break;
                    }
                }
            }
            StructuredNode::Goto(target)
        }
        // Other nodes pass through unchanged
        other => other,
    }
}

/// Converts gotos in a loop body, using the provided loop context.
fn convert_gotos_in_loop_body(
    body: Vec<StructuredNode>,
    loop_ctx: Option<&LoopContext>,
) -> Vec<StructuredNode> {
    // Use the provided loop context to detect break/continue opportunities.
    convert_gotos_to_break_continue(body, loop_ctx)
}

/// Collects all loop headers from the structured nodes.
/// This is used for the global goto-to-continue conversion pass.
pub(super) fn collect_loop_headers(nodes: &[StructuredNode]) -> HashSet<BasicBlockId> {
    let mut headers = HashSet::new();
    for node in nodes {
        collect_loop_headers_in_node(node, &mut headers);
    }
    headers
}

fn collect_loop_headers_in_node(node: &StructuredNode, headers: &mut HashSet<BasicBlockId>) {
    match node {
        StructuredNode::While { body, header, .. } => {
            if let Some(h) = header {
                headers.insert(*h);
            }
            for n in body {
                collect_loop_headers_in_node(n, headers);
            }
        }
        StructuredNode::DoWhile { body, header, .. } => {
            if let Some(h) = header {
                headers.insert(*h);
            }
            for n in body {
                collect_loop_headers_in_node(n, headers);
            }
        }
        StructuredNode::Loop { body, header, .. } => {
            if let Some(h) = header {
                headers.insert(*h);
            }
            for n in body {
                collect_loop_headers_in_node(n, headers);
            }
        }
        StructuredNode::For { body, header, .. } => {
            if let Some(h) = header {
                headers.insert(*h);
            }
            for n in body {
                collect_loop_headers_in_node(n, headers);
            }
        }
        StructuredNode::If {
            then_body,
            else_body,
            ..
        } => {
            for n in then_body {
                collect_loop_headers_in_node(n, headers);
            }
            if let Some(eb) = else_body {
                for n in eb {
                    collect_loop_headers_in_node(n, headers);
                }
            }
        }
        StructuredNode::Switch { cases, default, .. } => {
            for (_, body) in cases {
                for n in body {
                    collect_loop_headers_in_node(n, headers);
                }
            }
            if let Some(d) = default {
                for n in d {
                    collect_loop_headers_in_node(n, headers);
                }
            }
        }
        StructuredNode::Sequence(nodes) => {
            for n in nodes {
                collect_loop_headers_in_node(n, headers);
            }
        }
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => {
            for n in try_body {
                collect_loop_headers_in_node(n, headers);
            }
            for handler in catch_handlers {
                for n in &handler.body {
                    collect_loop_headers_in_node(n, headers);
                }
            }
        }
        _ => {}
    }
}

/// Converts gotos at the global level (orphan labeled blocks) to continue
/// when they target loop headers.
/// This handles patterns like getopt switch cases that goto back to the loop start.
pub(super) fn convert_global_gotos_to_continue(
    nodes: Vec<StructuredNode>,
    loop_headers: &HashSet<BasicBlockId>,
) -> Vec<StructuredNode> {
    nodes
        .into_iter()
        .map(|node| convert_global_goto_in_node(node, loop_headers))
        .collect()
}

fn convert_global_goto_in_node(
    node: StructuredNode,
    loop_headers: &HashSet<BasicBlockId>,
) -> StructuredNode {
    match node {
        // Convert goto to continue if it targets a loop header
        StructuredNode::Goto(target) => {
            if loop_headers.contains(&target) {
                StructuredNode::Continue
            } else {
                StructuredNode::Goto(target)
            }
        }
        // Recursively process labeled blocks (these are the orphan switch cases)
        StructuredNode::Block {
            id,
            statements,
            address_range,
        } => StructuredNode::Block {
            id,
            statements,
            address_range,
        },
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition,
            then_body: convert_global_gotos_to_continue(then_body, loop_headers),
            else_body: else_body.map(|e| convert_global_gotos_to_continue(e, loop_headers)),
        },
        StructuredNode::Sequence(nodes) => {
            StructuredNode::Sequence(convert_global_gotos_to_continue(nodes, loop_headers))
        }
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value,
            cases: cases
                .into_iter()
                .map(|(vals, body)| (vals, convert_global_gotos_to_continue(body, loop_headers)))
                .collect(),
            default: default.map(|d| convert_global_gotos_to_continue(d, loop_headers)),
        },
        // Other nodes pass through (loops are already handled by the normal pass)
        other => other,
    }
}

/// Converts gotos in switch cases to break statements when they target
/// a block that comes after the switch.
/// This handles patterns where switch cases use goto to exit to a common point.
pub(super) fn convert_switch_gotos_to_break(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    // First pass: identify switches followed by labels
    // Those labels are switch exit points and gotos to them should be breaks
    let mut switch_exits = HashSet::new();
    let mut i = 0;
    while i < nodes.len() {
        if let StructuredNode::Switch { .. } = &nodes[i] {
            // Check if there's a label after the switch
            if i + 1 < nodes.len() {
                if let StructuredNode::Label(label_id) = &nodes[i + 1] {
                    switch_exits.insert(*label_id);
                }
            }
        }
        i += 1;
    }

    // Also find common goto targets within switches
    for node in &nodes {
        if let StructuredNode::Switch { cases, default, .. } = node {
            let common_target = find_common_goto_target(cases, default);
            if let Some(target) = common_target {
                switch_exits.insert(target);
            }
        }
    }

    // Second pass: convert gotos in switches
    nodes
        .into_iter()
        .map(|node| convert_switch_gotos_in_node(node, &switch_exits))
        .collect()
}

/// Finds a common goto target used by multiple switch cases.
fn find_common_goto_target(
    cases: &[(Vec<i128>, Vec<StructuredNode>)],
    default: &Option<Vec<StructuredNode>>,
) -> Option<BasicBlockId> {
    let mut target_counts: HashMap<BasicBlockId, usize> = HashMap::new();

    for (_, body) in cases {
        if let Some(target) = get_trailing_goto(body) {
            *target_counts.entry(target).or_insert(0) += 1;
        }
    }

    if let Some(body) = default {
        if let Some(target) = get_trailing_goto(body) {
            *target_counts.entry(target).or_insert(0) += 1;
        }
    }

    // Return the most common target if it appears in at least 2 cases
    target_counts
        .into_iter()
        .filter(|(_, count)| *count >= 2)
        .max_by_key(|(_, count)| *count)
        .map(|(target, _)| target)
}

/// Gets the trailing goto target from a node sequence.
fn get_trailing_goto(nodes: &[StructuredNode]) -> Option<BasicBlockId> {
    if let Some(last) = nodes.last() {
        match last {
            StructuredNode::Goto(target) => Some(*target),
            StructuredNode::If {
                then_body,
                else_body,
                ..
            } => {
                // Check if both branches end with the same goto
                let then_target = get_trailing_goto(then_body);
                let else_target = else_body.as_ref().and_then(|e| get_trailing_goto(e));
                if then_target == else_target {
                    then_target
                } else {
                    None
                }
            }
            _ => None,
        }
    } else {
        None
    }
}

fn convert_switch_gotos_in_node(
    node: StructuredNode,
    switch_exits: &HashSet<BasicBlockId>,
) -> StructuredNode {
    match node {
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => {
            // For each case, convert gotos to the switch exit into breaks
            let converted_cases = cases
                .into_iter()
                .map(|(vals, body)| {
                    let new_body = convert_gotos_to_break_in_body(body, switch_exits);
                    (vals, new_body)
                })
                .collect();

            let converted_default =
                default.map(|d| convert_gotos_to_break_in_body(d, switch_exits));

            StructuredNode::Switch {
                value,
                cases: converted_cases,
                default: converted_default,
            }
        }
        // Recurse into other structures
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition,
            then_body: convert_switch_gotos_to_break(then_body),
            else_body: else_body.map(convert_switch_gotos_to_break),
        },
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition,
            body: convert_switch_gotos_to_break(body),
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: convert_switch_gotos_to_break(body),
            condition,
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: convert_switch_gotos_to_break(body),
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
            body: convert_switch_gotos_to_break(body),
            header,
            exit_block,
        },
        StructuredNode::Sequence(nodes) => {
            StructuredNode::Sequence(convert_switch_gotos_to_break(nodes))
        }
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => StructuredNode::TryCatch {
            try_body: convert_switch_gotos_to_break(try_body),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|h| CatchHandler {
                    body: convert_switch_gotos_to_break(h.body),
                    ..h
                })
                .collect(),
        },
        other => other,
    }
}

fn convert_gotos_to_break_in_body(
    nodes: Vec<StructuredNode>,
    switch_exits: &HashSet<BasicBlockId>,
) -> Vec<StructuredNode> {
    nodes
        .into_iter()
        .map(|node| match node {
            StructuredNode::Goto(target) if switch_exits.contains(&target) => StructuredNode::Break,
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => StructuredNode::If {
                condition,
                then_body: convert_gotos_to_break_in_body(then_body, switch_exits),
                else_body: else_body.map(|e| convert_gotos_to_break_in_body(e, switch_exits)),
            },
            StructuredNode::Sequence(nodes) => {
                StructuredNode::Sequence(convert_gotos_to_break_in_body(nodes, switch_exits))
            }
            other => other,
        })
        .collect()
}

// ============================================================================
