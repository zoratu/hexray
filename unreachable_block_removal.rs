// Unreachable block removal functions for structurer.rs
// These should be added to structurer.rs before the #[cfg(test)] line

use std::collections::HashSet;
use hexray_core::BasicBlockId;

// Add these imports at the top of structurer.rs if not already present:
// use std::collections::{HashMap, HashSet};

/// Removes unreachable labeled blocks from the structured output.
///
/// This function performs three cleanup operations:
/// 1. Removes labels that have no gotos targeting them (truly unreachable)
/// 2. Removes any blocks after a return/break/continue in a sequence (dead code)
/// 3. Eliminates labels that are immediately followed by a goto to themselves
fn remove_unreachable_blocks(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    // First pass: collect all goto targets
    let mut goto_targets = HashSet::new();
    collect_goto_targets(&nodes, &mut goto_targets);

    // Second pass: remove unreachable blocks and clean up
    let mut result = Vec::new();
    let mut i = 0;

    while i < nodes.len() {
        let node = &nodes[i];

        match node {
            // If we see a label, check if it's actually used
            StructuredNode::Label(target) => {
                if goto_targets.contains(target) {
                    // Label is used, but check if it's immediately followed by a goto to itself
                    // (which would make it unreachable after the goto)
                    if i + 1 < nodes.len() {
                        if let StructuredNode::Goto(goto_target) = &nodes[i + 1] {
                            if goto_target == target {
                                // Skip both the label and the self-goto
                                i += 2;
                                continue;
                            }
                        }
                    }
                    result.push(remove_unreachable_in_node(node.clone(), &goto_targets));
                }
                // If label is not in goto_targets, skip it entirely (unreachable)
            }

            // For other nodes, recursively clean them up
            _ => {
                result.push(remove_unreachable_in_node(node.clone(), &goto_targets));
            }
        }

        i += 1;
    }

    // Third pass: remove code after terminating statements
    filter_dead_code_after_terminators(result)
}

/// Collects all basic block IDs that are targets of goto statements.
fn collect_goto_targets(nodes: &[StructuredNode], targets: &mut HashSet<BasicBlockId>) {
    for node in nodes {
        match node {
            StructuredNode::Goto(target) => {
                targets.insert(*target);
            }
            StructuredNode::If {
                then_body,
                else_body,
                ..
            } => {
                collect_goto_targets(then_body, targets);
                if let Some(else_nodes) = else_body {
                    collect_goto_targets(else_nodes, targets);
                }
            }
            StructuredNode::While { body, .. }
            | StructuredNode::DoWhile { body, .. }
            | StructuredNode::Loop { body, .. } => {
                collect_goto_targets(body, targets);
            }
            StructuredNode::For { body, .. } => {
                collect_goto_targets(body, targets);
            }
            StructuredNode::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    collect_goto_targets(case_body, targets);
                }
                if let Some(default_body) = default {
                    collect_goto_targets(default_body, targets);
                }
            }
            StructuredNode::Sequence(inner_nodes) => {
                collect_goto_targets(inner_nodes, targets);
            }
            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                collect_goto_targets(try_body, targets);
                for handler in catch_handlers {
                    collect_goto_targets(&handler.body, targets);
                }
            }
            // Other node types don't contain gotos or nested structures
            _ => {}
        }
    }
}

/// Recursively removes unreachable blocks within a node.
fn remove_unreachable_in_node(
    node: StructuredNode,
    goto_targets: &HashSet<BasicBlockId>,
) -> StructuredNode {
    match node {
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition,
            then_body: remove_unreachable_blocks(then_body),
            else_body: else_body.map(remove_unreachable_blocks),
        },
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition,
            body: remove_unreachable_blocks(body),
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: remove_unreachable_blocks(body),
            condition,
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: remove_unreachable_blocks(body),
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
            body: remove_unreachable_blocks(body),
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
                .map(|(vals, body)| (vals, remove_unreachable_blocks(body)))
                .collect(),
            default: default.map(remove_unreachable_blocks),
        },
        StructuredNode::Sequence(nodes) => {
            StructuredNode::Sequence(remove_unreachable_blocks(nodes))
        }
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => StructuredNode::TryCatch {
            try_body: remove_unreachable_blocks(try_body),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|h| CatchHandler {
                    body: remove_unreachable_blocks(h.body),
                    ..h
                })
                .collect(),
        },
        // Other nodes pass through unchanged
        other => other,
    }
}

/// Removes any statements/blocks that appear after terminating statements.
/// For example, after a return statement in a sequence, nothing else should be emitted.
fn filter_dead_code_after_terminators(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    let mut result = Vec::new();

    for node in nodes {
        let node = filter_dead_code_in_node(node);
        let terminates = is_terminating_node(&node);
        result.push(node);

        // If this node terminates execution, stop processing further nodes
        if terminates {
            break;
        }
    }

    result
}

/// Checks if a single node terminates execution (return, break, continue, goto, noreturn call).
fn is_terminating_node(node: &StructuredNode) -> bool {
    match node {
        StructuredNode::Return(_)
        | StructuredNode::Break
        | StructuredNode::Continue
        | StructuredNode::Goto(_) => true,
        StructuredNode::If {
            then_body,
            else_body: Some(else_body),
            ..
        } => {
            // If terminates only if BOTH branches terminate
            body_terminates(then_body) && body_terminates(else_body)
        }
        StructuredNode::Sequence(nodes) => {
            // Sequence terminates if any of its nodes terminate
            nodes.iter().any(is_terminating_node)
        }
        StructuredNode::Expr(expr) => is_noreturn_call(expr),
        StructuredNode::Block { statements, .. } => {
            statements.last().is_some_and(is_noreturn_call)
        }
        _ => false,
    }
}

/// Recursively filters dead code within a node structure.
fn filter_dead_code_in_node(node: StructuredNode) -> StructuredNode {
    match node {
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition,
            then_body: filter_dead_code_after_terminators(then_body),
            else_body: else_body.map(filter_dead_code_after_terminators),
        },
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition,
            body: filter_dead_code_after_terminators(body),
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: filter_dead_code_after_terminators(body),
            condition,
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: filter_dead_code_after_terminators(body),
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
            body: filter_dead_code_after_terminators(body),
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
                .map(|(vals, body)| (vals, filter_dead_code_after_terminators(body)))
                .collect(),
            default: default.map(filter_dead_code_after_terminators),
        },
        StructuredNode::Sequence(nodes) => {
            StructuredNode::Sequence(filter_dead_code_after_terminators(nodes))
        }
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => StructuredNode::TryCatch {
            try_body: filter_dead_code_after_terminators(try_body),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|h| CatchHandler {
                    body: filter_dead_code_after_terminators(h.body),
                    ..h
                })
                .collect(),
        },
        // Other nodes pass through unchanged
        other => other,
    }
}

// ==================== INTEGRATION INSTRUCTIONS ====================
//
// 1. Add these functions to structurer.rs before the #[cfg(test)] line (around line 5200)
//
// 2. In the from_cfg_with_config function (around line 178), add this line after structurer.structure():
//
//    let mut structurer = Structurer::new(cfg);
//    let mut body = structurer.structure();
//
//    // Add this line:
//    body = remove_unreachable_blocks(body);
//
//    // Rest of the optimization passes...
//
// 3. The existing functions body_terminates() and is_noreturn_call() are already in the file and are used by these new functions.
