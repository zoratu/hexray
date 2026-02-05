//! Decompilation quality metrics.
//!
//! This module provides metrics for evaluating the quality of decompiled code output.
//! These metrics can be used for:
//! - Benchmarking decompiler improvements
//! - Comparing output across optimization levels
//! - Detecting quality regressions
//!
//! ## Quality Indicators
//!
//! | Metric | Better When | Description |
//! |--------|-------------|-------------|
//! | Statement count | Lower | Fewer statements = more concise |
//! | Nesting depth | Lower | Shallower nesting = more readable |
//! | Goto count | Zero | No gotos = fully structured |
//! | Named variable ratio | Higher | Better variable naming |
//! | Control structure ratio | Higher | More high-level constructs |

use super::expression::{Expr, ExprKind};
use super::structurer::StructuredNode;

/// Quality metrics for decompiled code.
#[derive(Debug, Clone, Default)]
pub struct QualityMetrics {
    /// Total number of statements.
    pub statement_count: usize,
    /// Maximum nesting depth (if/while/for/switch).
    pub max_nesting_depth: usize,
    /// Number of goto statements.
    pub goto_count: usize,
    /// Number of break statements.
    pub break_count: usize,
    /// Number of continue statements.
    pub continue_count: usize,
    /// Number of return statements.
    pub return_count: usize,
    /// Number of for loops detected.
    pub for_loop_count: usize,
    /// Number of while loops detected.
    pub while_loop_count: usize,
    /// Number of do-while loops detected.
    pub do_while_count: usize,
    /// Number of infinite loops.
    pub infinite_loop_count: usize,
    /// Number of switch statements.
    pub switch_count: usize,
    /// Number of if statements.
    pub if_count: usize,
    /// Number of variables with meaningful names.
    pub named_variable_count: usize,
    /// Number of variables with temporary names (temp_*, var_*, etc.).
    pub temp_variable_count: usize,
    /// Number of function calls.
    pub call_count: usize,
    /// Total number of expressions.
    pub expression_count: usize,
    /// Number of complex expressions (nested operations).
    pub complex_expression_count: usize,
    /// Number of assignments.
    pub assignment_count: usize,
    /// Number of compound assignments (+=, -=, etc.).
    pub compound_assignment_count: usize,
    /// Number of array accesses detected.
    pub array_access_count: usize,
    /// Number of field accesses detected.
    pub field_access_count: usize,
}

impl QualityMetrics {
    /// Computes a quality score (0.0 - 1.0, higher is better).
    ///
    /// This is a weighted combination of various quality indicators.
    pub fn quality_score(&self) -> f64 {
        // Weights for different factors
        const GOTO_PENALTY: f64 = 0.2; // Each goto reduces score
        const NESTING_PENALTY: f64 = 0.05; // Per level of nesting beyond 3
        const NAMED_VAR_BONUS: f64 = 0.1; // Bonus for well-named variables
        const CONTROL_STRUCT_BONUS: f64 = 0.1; // Bonus for structured control flow

        let mut score = 1.0;

        // Penalize gotos heavily (they indicate unstructured code)
        score -= self.goto_count as f64 * GOTO_PENALTY;

        // Penalize deep nesting (beyond 3 levels)
        if self.max_nesting_depth > 3 {
            score -= (self.max_nesting_depth - 3) as f64 * NESTING_PENALTY;
        }

        // Bonus for named variables
        let total_vars = self.named_variable_count + self.temp_variable_count;
        if total_vars > 0 {
            let named_ratio = self.named_variable_count as f64 / total_vars as f64;
            score += named_ratio * NAMED_VAR_BONUS;
        }

        // Bonus for structured control flow (for/while/switch vs raw ifs)
        let structured = self.for_loop_count + self.while_loop_count + self.switch_count;
        let total_control = structured + self.if_count;
        if total_control > 0 {
            let struct_ratio = structured as f64 / total_control as f64;
            score += struct_ratio * CONTROL_STRUCT_BONUS;
        }

        // Clamp score to [0, 1]
        score.clamp(0.0, 1.0)
    }

    /// Returns the control flow complexity (McCabe-like metric).
    ///
    /// This counts decision points: branches, loops, and switches.
    pub fn control_flow_complexity(&self) -> usize {
        1 + // Base complexity
        self.if_count +
        self.for_loop_count +
        self.while_loop_count +
        self.do_while_count +
        self.switch_count
    }

    /// Returns the ratio of structured control flow to total control statements.
    ///
    /// Higher is better (1.0 means no raw if-gotos).
    pub fn structured_ratio(&self) -> f64 {
        let structured = self.for_loop_count + self.while_loop_count + self.switch_count;
        let total = structured + self.if_count;

        if total == 0 {
            1.0 // No control flow is fully "structured"
        } else {
            structured as f64 / total as f64
        }
    }

    /// Returns the ratio of named variables to total variables.
    ///
    /// Higher is better (1.0 means all variables have meaningful names).
    pub fn naming_quality(&self) -> f64 {
        let total = self.named_variable_count + self.temp_variable_count;
        if total == 0 {
            1.0
        } else {
            self.named_variable_count as f64 / total as f64
        }
    }

    /// Returns conciseness score (lower statement count per control structure).
    pub fn conciseness(&self) -> f64 {
        let control_points = self.control_flow_complexity() as f64;
        if control_points > 0.0 {
            // Ideal: ~3-5 statements per control point
            let ratio = self.statement_count as f64 / control_points;
            // Score from 0 to 1, with 4 statements per control point being ideal
            let ideal = 4.0;
            1.0 - ((ratio - ideal).abs() / (ideal + ratio.max(1.0))).min(1.0)
        } else {
            1.0
        }
    }

    /// Merges another metrics instance into this one.
    pub fn merge(&mut self, other: &QualityMetrics) {
        self.statement_count += other.statement_count;
        self.max_nesting_depth = self.max_nesting_depth.max(other.max_nesting_depth);
        self.goto_count += other.goto_count;
        self.break_count += other.break_count;
        self.continue_count += other.continue_count;
        self.return_count += other.return_count;
        self.for_loop_count += other.for_loop_count;
        self.while_loop_count += other.while_loop_count;
        self.do_while_count += other.do_while_count;
        self.infinite_loop_count += other.infinite_loop_count;
        self.switch_count += other.switch_count;
        self.if_count += other.if_count;
        self.named_variable_count += other.named_variable_count;
        self.temp_variable_count += other.temp_variable_count;
        self.call_count += other.call_count;
        self.expression_count += other.expression_count;
        self.complex_expression_count += other.complex_expression_count;
        self.assignment_count += other.assignment_count;
        self.compound_assignment_count += other.compound_assignment_count;
        self.array_access_count += other.array_access_count;
        self.field_access_count += other.field_access_count;
    }
}

impl std::fmt::Display for QualityMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== Decompilation Quality Metrics ===")?;
        writeln!(f, "Quality Score: {:.2}", self.quality_score())?;
        writeln!(f)?;
        writeln!(f, "Structure:")?;
        writeln!(f, "  Statements: {}", self.statement_count)?;
        writeln!(f, "  Max nesting: {}", self.max_nesting_depth)?;
        writeln!(f, "  Complexity: {}", self.control_flow_complexity())?;
        writeln!(f)?;
        writeln!(f, "Control Flow:")?;
        writeln!(f, "  For loops: {}", self.for_loop_count)?;
        writeln!(f, "  While loops: {}", self.while_loop_count)?;
        writeln!(f, "  Do-while loops: {}", self.do_while_count)?;
        writeln!(f, "  Switches: {}", self.switch_count)?;
        writeln!(f, "  If statements: {}", self.if_count)?;
        writeln!(f, "  Gotos: {}", self.goto_count)?;
        writeln!(f)?;
        writeln!(f, "Variables:")?;
        writeln!(f, "  Named: {}", self.named_variable_count)?;
        writeln!(f, "  Temporary: {}", self.temp_variable_count)?;
        writeln!(f, "  Naming quality: {:.1}%", self.naming_quality() * 100.0)?;
        writeln!(f)?;
        writeln!(f, "Expressions:")?;
        writeln!(f, "  Total: {}", self.expression_count)?;
        writeln!(f, "  Complex: {}", self.complex_expression_count)?;
        writeln!(f, "  Calls: {}", self.call_count)?;
        writeln!(f, "  Array accesses: {}", self.array_access_count)?;
        writeln!(f, "  Field accesses: {}", self.field_access_count)?;
        Ok(())
    }
}

/// Analyzes structured code and computes quality metrics.
pub fn compute_metrics(nodes: &[StructuredNode]) -> QualityMetrics {
    let mut metrics = QualityMetrics::default();
    for node in nodes {
        collect_node_metrics(node, 0, &mut metrics);
    }
    metrics
}

/// Recursively collects metrics from a structured node.
fn collect_node_metrics(node: &StructuredNode, depth: usize, metrics: &mut QualityMetrics) {
    metrics.max_nesting_depth = metrics.max_nesting_depth.max(depth);

    match node {
        StructuredNode::Block { statements, .. } => {
            for stmt in statements {
                collect_expr_metrics(stmt, metrics);
            }
            metrics.statement_count += statements.len();
        }

        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => {
            metrics.if_count += 1;
            collect_expr_metrics(condition, metrics);
            for child in then_body {
                collect_node_metrics(child, depth + 1, metrics);
            }
            if let Some(else_nodes) = else_body {
                for child in else_nodes {
                    collect_node_metrics(child, depth + 1, metrics);
                }
            }
        }

        StructuredNode::While {
            condition, body, ..
        } => {
            metrics.while_loop_count += 1;
            collect_expr_metrics(condition, metrics);
            for child in body {
                collect_node_metrics(child, depth + 1, metrics);
            }
        }

        StructuredNode::DoWhile {
            body, condition, ..
        } => {
            metrics.do_while_count += 1;
            collect_expr_metrics(condition, metrics);
            for child in body {
                collect_node_metrics(child, depth + 1, metrics);
            }
        }

        StructuredNode::For {
            init,
            condition,
            update,
            body,
            ..
        } => {
            metrics.for_loop_count += 1;
            if let Some(e) = init {
                collect_expr_metrics(e, metrics);
            }
            collect_expr_metrics(condition, metrics);
            if let Some(e) = update {
                collect_expr_metrics(e, metrics);
            }
            for child in body {
                collect_node_metrics(child, depth + 1, metrics);
            }
        }

        StructuredNode::Loop { body, .. } => {
            metrics.infinite_loop_count += 1;
            for child in body {
                collect_node_metrics(child, depth + 1, metrics);
            }
        }

        StructuredNode::Switch {
            value,
            cases,
            default,
        } => {
            metrics.switch_count += 1;
            collect_expr_metrics(value, metrics);
            for (_, case_body) in cases {
                for child in case_body {
                    collect_node_metrics(child, depth + 1, metrics);
                }
            }
            if let Some(def) = default {
                for child in def {
                    collect_node_metrics(child, depth + 1, metrics);
                }
            }
        }

        StructuredNode::Sequence(nodes) => {
            for child in nodes {
                collect_node_metrics(child, depth, metrics);
            }
        }

        StructuredNode::Return(expr) => {
            metrics.return_count += 1;
            if let Some(e) = expr {
                collect_expr_metrics(e, metrics);
            }
        }

        StructuredNode::Expr(e) => {
            metrics.statement_count += 1;
            collect_expr_metrics(e, metrics);
        }

        StructuredNode::Goto(_) => {
            metrics.goto_count += 1;
            metrics.statement_count += 1;
        }

        StructuredNode::Break => {
            metrics.break_count += 1;
            metrics.statement_count += 1;
        }

        StructuredNode::Continue => {
            metrics.continue_count += 1;
            metrics.statement_count += 1;
        }

        StructuredNode::Label(_) => {
            // Label is just a marker, no body
        }

        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => {
            for child in try_body {
                collect_node_metrics(child, depth + 1, metrics);
            }
            for handler in catch_handlers {
                for child in &handler.body {
                    collect_node_metrics(child, depth + 1, metrics);
                }
            }
        }
    }
}

/// Collects metrics from an expression.
fn collect_expr_metrics(expr: &Expr, metrics: &mut QualityMetrics) {
    metrics.expression_count += 1;

    match &expr.kind {
        ExprKind::Var(var) => {
            if is_meaningful_name(&var.name) {
                metrics.named_variable_count += 1;
            } else {
                metrics.temp_variable_count += 1;
            }
        }

        ExprKind::Assign { lhs, rhs } => {
            metrics.assignment_count += 1;
            collect_expr_metrics(lhs, metrics);
            collect_expr_metrics(rhs, metrics);
        }

        ExprKind::CompoundAssign { lhs, rhs, .. } => {
            metrics.compound_assignment_count += 1;
            collect_expr_metrics(lhs, metrics);
            collect_expr_metrics(rhs, metrics);
        }

        ExprKind::BinOp { left, right, .. } => {
            metrics.complex_expression_count += 1;
            collect_expr_metrics(left, metrics);
            collect_expr_metrics(right, metrics);
        }

        ExprKind::UnaryOp { operand, .. } => {
            collect_expr_metrics(operand, metrics);
        }

        ExprKind::Call { args, .. } => {
            metrics.call_count += 1;
            for arg in args {
                collect_expr_metrics(arg, metrics);
            }
        }

        ExprKind::ArrayAccess { base, index, .. } => {
            metrics.array_access_count += 1;
            collect_expr_metrics(base, metrics);
            collect_expr_metrics(index, metrics);
        }

        ExprKind::FieldAccess { base, .. } => {
            metrics.field_access_count += 1;
            collect_expr_metrics(base, metrics);
        }

        ExprKind::Deref { addr, .. } => {
            collect_expr_metrics(addr, metrics);
        }

        ExprKind::AddressOf(inner) => {
            collect_expr_metrics(inner, metrics);
        }

        ExprKind::Cast { expr: inner, .. } => {
            collect_expr_metrics(inner, metrics);
        }

        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            metrics.complex_expression_count += 1;
            collect_expr_metrics(cond, metrics);
            collect_expr_metrics(then_expr, metrics);
            collect_expr_metrics(else_expr, metrics);
        }

        // Leaf expressions
        ExprKind::IntLit(_) | ExprKind::GotRef { .. } | ExprKind::Unknown(_) => {}

        // Bitfield access - count as complex
        ExprKind::BitField { expr, .. } => {
            metrics.complex_expression_count += 1;
            collect_expr_metrics(expr, metrics);
        }

        // Phi nodes - shouldn't appear in final output ideally
        ExprKind::Phi(exprs) => {
            for e in exprs {
                collect_expr_metrics(e, metrics);
            }
        }
    }
}

/// Checks if a variable name is meaningful (not a temp/generated name).
fn is_meaningful_name(name: &str) -> bool {
    // Temporary/generated name patterns
    let temp_patterns = ["temp", "tmp", "var_", "arg_", "local_", "t_", "v_", "r_"];

    // Register names
    let register_patterns = [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15", "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "ax", "bx",
        "cx", "dx", "al", "ah", "bl", "bh", "cl", "ch", "dl", "dh", "x0", "x1", "x2", "x3", "x4",
        "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
        "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30",
        "sp", "fp", "lr", "pc", "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8", "w9", "w10",
        "w11", "w12", "w13", "w14", "w15",
    ];

    let lower_name = name.to_lowercase();

    // Check if it matches temp patterns
    for pattern in &temp_patterns {
        if lower_name.starts_with(pattern) {
            return false;
        }
    }

    // Check if it's a register name
    for reg in &register_patterns {
        if lower_name == *reg {
            return false;
        }
    }

    // Check for single letter names (except common conventions)
    if name.len() == 1 && !matches!(name, "i" | "j" | "k" | "n" | "x" | "y" | "c" | "s" | "p") {
        return false;
    }

    // Check for names that are just numbers/hex
    if name.chars().all(|c| c.is_ascii_hexdigit() || c == '_') && !name.is_empty() {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::expression::{BinOpKind, VarKind, Variable};
    use hexray_core::BasicBlockId;

    fn make_var(name: &str) -> Expr {
        Expr::var(Variable {
            kind: VarKind::Register(0),
            name: name.to_string(),
            size: 8,
        })
    }

    #[test]
    fn test_is_meaningful_name() {
        // Meaningful names
        assert!(is_meaningful_name("size"));
        assert!(is_meaningful_name("count"));
        assert!(is_meaningful_name("buffer"));
        assert!(is_meaningful_name("result"));
        assert!(is_meaningful_name("i")); // Common loop variable
        assert!(is_meaningful_name("j")); // Common loop variable
        assert!(is_meaningful_name("ptr"));

        // Not meaningful
        assert!(!is_meaningful_name("temp0"));
        assert!(!is_meaningful_name("tmp_value"));
        assert!(!is_meaningful_name("var_8"));
        assert!(!is_meaningful_name("rax"));
        assert!(!is_meaningful_name("x0"));
        assert!(!is_meaningful_name("arg_0"));
        assert!(!is_meaningful_name("local_10"));
    }

    #[test]
    fn test_metrics_for_simple_block() {
        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![
                Expr::assign(make_var("result"), Expr::int(0)),
                Expr::assign(make_var("temp0"), Expr::int(1)),
            ],
            address_range: (0x1000, 0x1010),
        };

        let metrics = compute_metrics(&[block]);

        assert_eq!(metrics.statement_count, 2);
        assert_eq!(metrics.assignment_count, 2);
        assert_eq!(metrics.named_variable_count, 1); // "result"
        assert_eq!(metrics.temp_variable_count, 1); // "temp0"
    }

    #[test]
    fn test_metrics_for_loop() {
        let for_loop = StructuredNode::For {
            init: Some(Expr::assign(make_var("i"), Expr::int(0))),
            condition: Expr::binop(BinOpKind::Lt, make_var("i"), make_var("n")),
            update: Some(Expr::assign(
                make_var("i"),
                Expr::binop(BinOpKind::Add, make_var("i"), Expr::int(1)),
            )),
            body: vec![StructuredNode::Expr(Expr::call(
                crate::decompiler::expression::CallTarget::Named("printf".to_string()),
                vec![make_var("i")],
            ))],
            header: None,
            exit_block: None,
        };

        let metrics = compute_metrics(&[for_loop]);

        assert_eq!(metrics.for_loop_count, 1);
        assert_eq!(metrics.call_count, 1);
        assert!(metrics.max_nesting_depth >= 1);
    }

    #[test]
    fn test_metrics_for_nested_if() {
        let nested_if = StructuredNode::If {
            condition: Expr::binop(BinOpKind::Gt, make_var("x"), Expr::int(0)),
            then_body: vec![StructuredNode::If {
                condition: Expr::binop(BinOpKind::Lt, make_var("x"), Expr::int(100)),
                then_body: vec![StructuredNode::Expr(make_var("y"))],
                else_body: None,
            }],
            else_body: None,
        };

        let metrics = compute_metrics(&[nested_if]);

        assert_eq!(metrics.if_count, 2);
        assert_eq!(metrics.max_nesting_depth, 2);
    }

    #[test]
    fn test_metrics_with_goto() {
        let nodes = vec![
            StructuredNode::Goto(BasicBlockId::new(1)),
            StructuredNode::Expr(make_var("x")),
        ];

        let metrics = compute_metrics(&nodes);

        assert_eq!(metrics.goto_count, 1);
        // Gotos should hurt quality score
        assert!(metrics.quality_score() < 1.0);
    }

    #[test]
    fn test_quality_score() {
        // High quality: structured, named variables
        let high_quality = StructuredNode::For {
            init: Some(Expr::assign(make_var("index"), Expr::int(0))),
            condition: Expr::binop(BinOpKind::Lt, make_var("index"), make_var("size")),
            update: Some(Expr::assign(
                make_var("index"),
                Expr::binop(BinOpKind::Add, make_var("index"), Expr::int(1)),
            )),
            body: vec![],
            header: None,
            exit_block: None,
        };

        let high_metrics = compute_metrics(&[high_quality]);

        // Low quality: gotos, temp variables
        let low_quality = vec![
            StructuredNode::Expr(Expr::assign(make_var("temp0"), make_var("temp1"))),
            StructuredNode::Goto(BasicBlockId::new(1)),
            StructuredNode::Goto(BasicBlockId::new(2)),
        ];

        let low_metrics = compute_metrics(&low_quality);

        assert!(high_metrics.quality_score() > low_metrics.quality_score());
    }

    #[test]
    fn test_structured_ratio() {
        // All structured: for + while
        let structured = vec![
            StructuredNode::For {
                init: None,
                condition: Expr::int(1),
                update: None,
                body: vec![],
                header: None,
                exit_block: None,
            },
            StructuredNode::While {
                condition: Expr::int(1),
                body: vec![],
                header: None,
                exit_block: None,
            },
        ];

        let metrics = compute_metrics(&structured);
        assert_eq!(metrics.structured_ratio(), 1.0);

        // Half structured: for + if
        let half = vec![
            StructuredNode::For {
                init: None,
                condition: Expr::int(1),
                update: None,
                body: vec![],
                header: None,
                exit_block: None,
            },
            StructuredNode::If {
                condition: Expr::int(1),
                then_body: vec![],
                else_body: None,
            },
        ];

        let half_metrics = compute_metrics(&half);
        assert_eq!(half_metrics.structured_ratio(), 0.5);
    }

    #[test]
    fn test_metrics_display() {
        let metrics = QualityMetrics {
            statement_count: 10,
            for_loop_count: 2,
            if_count: 3,
            named_variable_count: 5,
            temp_variable_count: 2,
            ..Default::default()
        };

        let display = format!("{}", metrics);
        assert!(display.contains("Quality Score"));
        assert!(display.contains("For loops: 2"));
        assert!(display.contains("Named: 5"));
    }

    #[test]
    fn test_metrics_merge() {
        let mut m1 = QualityMetrics {
            statement_count: 10,
            for_loop_count: 2,
            max_nesting_depth: 3,
            ..Default::default()
        };

        let m2 = QualityMetrics {
            statement_count: 5,
            for_loop_count: 1,
            max_nesting_depth: 5,
            ..Default::default()
        };

        m1.merge(&m2);

        assert_eq!(m1.statement_count, 15);
        assert_eq!(m1.for_loop_count, 3);
        assert_eq!(m1.max_nesting_depth, 5); // Max
    }
}
