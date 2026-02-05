//! Comparison testing against external decompilers (Ghidra, IDA).
//!
//! This module provides utilities for comparing hexray decompiler output
//! against Ghidra and IDA Pro to measure quality and identify improvements.
//!
//! # Usage
//!
//! ```ignore
//! use hexray_analysis::decompiler::comparison::{ComparisonTester, DecompilerOutput};
//!
//! let tester = ComparisonTester::new();
//! let result = tester.compare_function(
//!     "main",
//!     &hexray_output,
//!     &ghidra_output,
//! );
//! println!("Similarity: {:.1}%", result.similarity_score * 100.0);
//! ```

use std::collections::{HashMap, HashSet};

/// Output from a decompiler.
#[derive(Debug, Clone)]
pub struct DecompilerOutput {
    /// Source decompiler name.
    pub source: DecompilerSource,
    /// Function name.
    pub function_name: String,
    /// The decompiled code.
    pub code: String,
    /// Detected constructs.
    pub constructs: DetectedConstructs,
    /// Variable names used.
    pub variables: Vec<String>,
    /// Function calls made.
    pub function_calls: Vec<String>,
    /// Number of lines.
    pub line_count: usize,
}

/// Source decompiler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecompilerSource {
    /// hexray decompiler.
    Hexray,
    /// Ghidra's decompiler.
    Ghidra,
    /// IDA Pro's Hex-Rays decompiler.
    IdaPro,
    /// Binary Ninja.
    BinaryNinja,
    /// RetDec.
    RetDec,
    /// Other/unknown.
    Other,
}

impl DecompilerSource {
    /// Returns the display name.
    pub fn name(&self) -> &'static str {
        match self {
            DecompilerSource::Hexray => "hexray",
            DecompilerSource::Ghidra => "Ghidra",
            DecompilerSource::IdaPro => "IDA Pro",
            DecompilerSource::BinaryNinja => "Binary Ninja",
            DecompilerSource::RetDec => "RetDec",
            DecompilerSource::Other => "Other",
        }
    }
}

/// Detected high-level constructs.
#[derive(Debug, Clone, Default)]
pub struct DetectedConstructs {
    /// Number of for loops.
    pub for_loops: usize,
    /// Number of while loops.
    pub while_loops: usize,
    /// Number of do-while loops.
    pub do_while_loops: usize,
    /// Number of if statements.
    pub if_statements: usize,
    /// Number of switch statements.
    pub switch_statements: usize,
    /// Number of goto statements.
    pub gotos: usize,
    /// Number of labels.
    pub labels: usize,
    /// Number of return statements.
    pub returns: usize,
    /// Number of ternary expressions.
    pub ternary_exprs: usize,
    /// Maximum nesting depth.
    pub max_nesting: usize,
}

/// Result of comparing two decompiler outputs.
#[derive(Debug, Clone)]
pub struct ComparisonResult {
    /// Function being compared.
    pub function_name: String,
    /// First decompiler source.
    pub source_a: DecompilerSource,
    /// Second decompiler source.
    pub source_b: DecompilerSource,
    /// Overall similarity score (0.0 - 1.0).
    pub similarity_score: f64,
    /// Structural similarity score.
    pub structural_similarity: f64,
    /// Variable naming similarity.
    pub variable_similarity: f64,
    /// Control flow similarity.
    pub control_flow_similarity: f64,
    /// Detailed metrics.
    pub metrics: ComparisonMetrics,
    /// Detected differences.
    pub differences: Vec<ComparisonDifference>,
}

/// Detailed comparison metrics.
#[derive(Debug, Clone, Default)]
pub struct ComparisonMetrics {
    /// Line count difference (abs).
    pub line_count_diff: i32,
    /// Character count difference (abs).
    pub char_count_diff: i32,
    /// Goto count difference.
    pub goto_diff: i32,
    /// Shared variables.
    pub shared_variables: usize,
    /// Variables only in A.
    pub variables_only_a: usize,
    /// Variables only in B.
    pub variables_only_b: usize,
    /// Shared function calls.
    pub shared_calls: usize,
    /// Function calls only in A.
    pub calls_only_a: usize,
    /// Function calls only in B.
    pub calls_only_b: usize,
}

/// A specific difference between outputs.
#[derive(Debug, Clone)]
pub struct ComparisonDifference {
    /// Type of difference.
    pub kind: DifferenceKind,
    /// Description.
    pub description: String,
    /// Severity (1-5, 5 being most severe).
    pub severity: u8,
}

/// Kind of difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DifferenceKind {
    /// Different control flow structure.
    ControlFlow,
    /// Different loop type.
    LoopType,
    /// One uses goto, other doesn't.
    GotoUsage,
    /// Different variable names.
    VariableNaming,
    /// Different function calls.
    FunctionCalls,
    /// Different expression structure.
    Expression,
    /// Different types.
    TypeAnnotation,
    /// Different nesting depth.
    NestingDepth,
    /// Other difference.
    Other,
}

/// Tester for comparing decompiler outputs.
#[derive(Debug, Default)]
pub struct ComparisonTester {
    /// Weight for structural similarity.
    pub structural_weight: f64,
    /// Weight for variable similarity.
    pub variable_weight: f64,
    /// Weight for control flow similarity.
    pub control_flow_weight: f64,
}

impl ComparisonTester {
    /// Creates a new comparison tester with default weights.
    pub fn new() -> Self {
        Self {
            structural_weight: 0.4,
            variable_weight: 0.2,
            control_flow_weight: 0.4,
        }
    }

    /// Sets custom weights for similarity calculation.
    pub fn with_weights(mut self, structural: f64, variable: f64, control_flow: f64) -> Self {
        let total = structural + variable + control_flow;
        self.structural_weight = structural / total;
        self.variable_weight = variable / total;
        self.control_flow_weight = control_flow / total;
        self
    }

    /// Compares two decompiler outputs.
    pub fn compare(
        &self,
        output_a: &DecompilerOutput,
        output_b: &DecompilerOutput,
    ) -> ComparisonResult {
        // Calculate structural similarity
        let structural_similarity = self.calculate_structural_similarity(output_a, output_b);

        // Calculate variable similarity
        let variable_similarity = self.calculate_variable_similarity(output_a, output_b);

        // Calculate control flow similarity
        let control_flow_similarity = self.calculate_control_flow_similarity(output_a, output_b);

        // Calculate overall similarity
        let similarity_score = structural_similarity * self.structural_weight
            + variable_similarity * self.variable_weight
            + control_flow_similarity * self.control_flow_weight;

        // Calculate metrics
        let metrics = self.calculate_metrics(output_a, output_b);

        // Detect differences
        let differences = self.detect_differences(output_a, output_b);

        ComparisonResult {
            function_name: output_a.function_name.clone(),
            source_a: output_a.source,
            source_b: output_b.source,
            similarity_score,
            structural_similarity,
            variable_similarity,
            control_flow_similarity,
            metrics,
            differences,
        }
    }

    /// Compares raw code strings.
    pub fn compare_code(
        &self,
        func_name: &str,
        source_a: DecompilerSource,
        code_a: &str,
        source_b: DecompilerSource,
        code_b: &str,
    ) -> ComparisonResult {
        let output_a = Self::parse_output(source_a, func_name, code_a);
        let output_b = Self::parse_output(source_b, func_name, code_b);
        self.compare(&output_a, &output_b)
    }

    /// Parses decompiler output from a code string.
    pub fn parse_output(source: DecompilerSource, func_name: &str, code: &str) -> DecompilerOutput {
        let constructs = detect_constructs(code);
        let variables = extract_variables(code);
        let function_calls = extract_function_calls(code);
        let line_count = code.lines().count();

        DecompilerOutput {
            source,
            function_name: func_name.to_string(),
            code: code.to_string(),
            constructs,
            variables,
            function_calls,
            line_count,
        }
    }

    fn calculate_structural_similarity(
        &self,
        output_a: &DecompilerOutput,
        output_b: &DecompilerOutput,
    ) -> f64 {
        // Compare line counts
        let max_lines = output_a.line_count.max(output_b.line_count) as f64;
        let line_diff = (output_a.line_count as i32 - output_b.line_count as i32).abs() as f64;
        let line_similarity = if max_lines > 0.0 {
            1.0 - (line_diff / max_lines).min(1.0)
        } else {
            1.0
        };

        // Compare character counts
        let len_a = output_a.code.len();
        let len_b = output_b.code.len();
        let max_chars = len_a.max(len_b) as f64;
        let char_diff = (len_a as i32 - len_b as i32).abs() as f64;
        let char_similarity = if max_chars > 0.0 {
            1.0 - (char_diff / max_chars).min(1.0)
        } else {
            1.0
        };

        // Compare nesting depth
        let max_nesting = output_a
            .constructs
            .max_nesting
            .max(output_b.constructs.max_nesting) as f64;
        let nesting_diff = (output_a.constructs.max_nesting as i32
            - output_b.constructs.max_nesting as i32)
            .abs() as f64;
        let nesting_similarity = if max_nesting > 0.0 {
            1.0 - (nesting_diff / max_nesting).min(1.0)
        } else {
            1.0
        };

        (line_similarity + char_similarity + nesting_similarity) / 3.0
    }

    fn calculate_variable_similarity(
        &self,
        output_a: &DecompilerOutput,
        output_b: &DecompilerOutput,
    ) -> f64 {
        let vars_a: HashSet<_> = output_a.variables.iter().collect();
        let vars_b: HashSet<_> = output_b.variables.iter().collect();

        let shared = vars_a.intersection(&vars_b).count();
        let total = vars_a.union(&vars_b).count();

        if total > 0 {
            shared as f64 / total as f64
        } else {
            1.0
        }
    }

    fn calculate_control_flow_similarity(
        &self,
        output_a: &DecompilerOutput,
        output_b: &DecompilerOutput,
    ) -> f64 {
        let ca = &output_a.constructs;
        let cb = &output_b.constructs;

        // Calculate similarity for each construct type
        let mut scores = Vec::new();

        // For loops
        if ca.for_loops > 0 || cb.for_loops > 0 {
            let max = ca.for_loops.max(cb.for_loops) as f64;
            let diff = (ca.for_loops as i32 - cb.for_loops as i32).abs() as f64;
            scores.push(1.0 - (diff / max).min(1.0));
        }

        // While loops
        if ca.while_loops > 0 || cb.while_loops > 0 {
            let max = ca.while_loops.max(cb.while_loops) as f64;
            let diff = (ca.while_loops as i32 - cb.while_loops as i32).abs() as f64;
            scores.push(1.0 - (diff / max).min(1.0));
        }

        // If statements
        if ca.if_statements > 0 || cb.if_statements > 0 {
            let max = ca.if_statements.max(cb.if_statements) as f64;
            let diff = (ca.if_statements as i32 - cb.if_statements as i32).abs() as f64;
            scores.push(1.0 - (diff / max).min(1.0));
        }

        // Switch statements
        if ca.switch_statements > 0 || cb.switch_statements > 0 {
            let max = ca.switch_statements.max(cb.switch_statements) as f64;
            let diff = (ca.switch_statements as i32 - cb.switch_statements as i32).abs() as f64;
            scores.push(1.0 - (diff / max).min(1.0));
        }

        // Gotos (penalize both having gotos)
        let goto_penalty = match (ca.gotos, cb.gotos) {
            (0, 0) => 1.0,           // Both no gotos - perfect
            (0, _) => 0.8,           // One has gotos
            (_, 0) => 0.8,           // One has gotos
            (a, b) if a == b => 0.7, // Same number of gotos
            _ => 0.5,                // Different number of gotos
        };
        scores.push(goto_penalty);

        if scores.is_empty() {
            1.0
        } else {
            scores.iter().sum::<f64>() / scores.len() as f64
        }
    }

    fn calculate_metrics(
        &self,
        output_a: &DecompilerOutput,
        output_b: &DecompilerOutput,
    ) -> ComparisonMetrics {
        let vars_a: HashSet<_> = output_a.variables.iter().collect();
        let vars_b: HashSet<_> = output_b.variables.iter().collect();
        let calls_a: HashSet<_> = output_a.function_calls.iter().collect();
        let calls_b: HashSet<_> = output_b.function_calls.iter().collect();

        ComparisonMetrics {
            line_count_diff: (output_a.line_count as i32 - output_b.line_count as i32).abs(),
            char_count_diff: (output_a.code.len() as i32 - output_b.code.len() as i32).abs(),
            goto_diff: (output_a.constructs.gotos as i32 - output_b.constructs.gotos as i32).abs(),
            shared_variables: vars_a.intersection(&vars_b).count(),
            variables_only_a: vars_a.difference(&vars_b).count(),
            variables_only_b: vars_b.difference(&vars_a).count(),
            shared_calls: calls_a.intersection(&calls_b).count(),
            calls_only_a: calls_a.difference(&calls_b).count(),
            calls_only_b: calls_b.difference(&calls_a).count(),
        }
    }

    fn detect_differences(
        &self,
        output_a: &DecompilerOutput,
        output_b: &DecompilerOutput,
    ) -> Vec<ComparisonDifference> {
        let mut differences = Vec::new();
        let ca = &output_a.constructs;
        let cb = &output_b.constructs;

        // Check for goto usage difference
        if (ca.gotos > 0) != (cb.gotos > 0) {
            let desc = if ca.gotos > 0 {
                format!(
                    "{} uses {} gotos, {} uses none",
                    output_a.source.name(),
                    ca.gotos,
                    output_b.source.name()
                )
            } else {
                format!(
                    "{} uses {} gotos, {} uses none",
                    output_b.source.name(),
                    cb.gotos,
                    output_a.source.name()
                )
            };
            differences.push(ComparisonDifference {
                kind: DifferenceKind::GotoUsage,
                description: desc,
                severity: 4,
            });
        }

        // Check for loop type differences
        let total_loops_a = ca.for_loops + ca.while_loops + ca.do_while_loops;
        let total_loops_b = cb.for_loops + cb.while_loops + cb.do_while_loops;
        if total_loops_a != total_loops_b {
            differences.push(ComparisonDifference {
                kind: DifferenceKind::LoopType,
                description: format!(
                    "Loop count differs: {} has {}, {} has {}",
                    output_a.source.name(),
                    total_loops_a,
                    output_b.source.name(),
                    total_loops_b
                ),
                severity: 3,
            });
        }

        // Check for switch vs if-else ladder
        if (ca.switch_statements > 0) != (cb.switch_statements > 0) {
            let desc = if ca.switch_statements > 0 {
                format!(
                    "{} uses switch, {} uses if-else",
                    output_a.source.name(),
                    output_b.source.name()
                )
            } else {
                format!(
                    "{} uses switch, {} uses if-else",
                    output_b.source.name(),
                    output_a.source.name()
                )
            };
            differences.push(ComparisonDifference {
                kind: DifferenceKind::ControlFlow,
                description: desc,
                severity: 2,
            });
        }

        // Check for nesting depth differences
        if (ca.max_nesting as i32 - cb.max_nesting as i32).abs() > 2 {
            differences.push(ComparisonDifference {
                kind: DifferenceKind::NestingDepth,
                description: format!(
                    "Nesting depth differs significantly: {} has {}, {} has {}",
                    output_a.source.name(),
                    ca.max_nesting,
                    output_b.source.name(),
                    cb.max_nesting
                ),
                severity: 2,
            });
        }

        differences
    }
}

/// Detect constructs in code.
fn detect_constructs(code: &str) -> DetectedConstructs {
    // Count labels (lines ending with ':' that aren't case/default)
    let labels = code
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            trimmed.ends_with(':')
                && !trimmed.contains(' ')
                && !trimmed.starts_with("case ")
                && !trimmed.starts_with("default")
        })
        .count();

    // Count ternary expressions
    let ternary_count = code.matches(" ? ").count();
    let colon_count = code.matches(" : ").count();

    DetectedConstructs {
        for_loops: code.matches("for (").count() + code.matches("for(").count(),
        while_loops: code.matches("while (").count() + code.matches("while(").count(),
        do_while_loops: code.matches("do {").count(),
        if_statements: code.matches("if (").count() + code.matches("if(").count(),
        switch_statements: code.matches("switch (").count() + code.matches("switch(").count(),
        gotos: code.matches("goto ").count(),
        labels,
        returns: code.matches("return ").count() + code.matches("return;").count(),
        ternary_exprs: ternary_count.min(colon_count),
        max_nesting: calculate_max_nesting(code),
    }
}

/// Calculate maximum nesting depth.
fn calculate_max_nesting(code: &str) -> usize {
    let mut max_depth: usize = 0;
    let mut current_depth: usize = 0;

    for c in code.chars() {
        match c {
            '{' => {
                current_depth += 1;
                max_depth = max_depth.max(current_depth);
            }
            '}' => {
                current_depth = current_depth.saturating_sub(1);
            }
            _ => {}
        }
    }

    max_depth
}

/// Extract variable names from code.
fn extract_variables(code: &str) -> Vec<String> {
    let mut variables = Vec::new();

    // Look for variable declarations and assignments
    // This is a simplified heuristic
    for line in code.lines() {
        // Type declarations: "type name"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            // Check for common types
            let types = [
                "int", "char", "long", "short", "float", "double", "void", "unsigned", "signed",
                "uint8_t", "uint16_t", "uint32_t", "uint64_t", "int8_t", "int16_t", "int32_t",
                "int64_t", "size_t", "bool",
            ];
            if types.iter().any(|t| parts[0].starts_with(t)) {
                // Extract variable name (handle pointers, arrays)
                let name = parts[1]
                    .trim_start_matches('*')
                    .split('[')
                    .next()
                    .unwrap_or("")
                    .split('=')
                    .next()
                    .unwrap_or("")
                    .trim_end_matches(';')
                    .trim_end_matches(',');
                if !name.is_empty() && is_valid_identifier(name) {
                    variables.push(name.to_string());
                }
            }
        }
    }

    variables.sort();
    variables.dedup();
    variables
}

/// Extract function calls from code.
fn extract_function_calls(code: &str) -> Vec<String> {
    let mut calls = Vec::new();

    // Look for function call patterns: name(
    let mut current_name = String::new();
    let mut in_identifier = false;

    for c in code.chars() {
        if c.is_alphanumeric() || c == '_' {
            in_identifier = true;
            current_name.push(c);
        } else if c == '(' && in_identifier && !current_name.is_empty() {
            // Found a potential function call
            let keywords = ["if", "while", "for", "switch", "return", "sizeof", "typeof"];
            if !keywords.contains(&current_name.as_str()) && is_valid_identifier(&current_name) {
                calls.push(current_name.clone());
            }
            current_name.clear();
            in_identifier = false;
        } else {
            current_name.clear();
            in_identifier = false;
        }
    }

    calls.sort();
    calls.dedup();
    calls
}

/// Check if a string is a valid C identifier.
fn is_valid_identifier(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let first = s.chars().next().unwrap();
    if !first.is_alphabetic() && first != '_' {
        return false;
    }
    s.chars().all(|c| c.is_alphanumeric() || c == '_')
}

/// Results from comparing against multiple decompilers.
#[derive(Debug, Clone, Default)]
pub struct MultiComparisonResults {
    /// Results for each pair comparison.
    pub pairwise_results: HashMap<(DecompilerSource, DecompilerSource), ComparisonResult>,
    /// Ranking of decompilers by quality metrics.
    pub rankings: Vec<(DecompilerSource, f64)>,
    /// Summary statistics.
    pub summary: MultiComparisonSummary,
}

/// Summary of multi-decompiler comparison.
#[derive(Debug, Clone, Default)]
pub struct MultiComparisonSummary {
    /// Decompiler with fewest gotos.
    pub fewest_gotos: Option<DecompilerSource>,
    /// Decompiler with best structure (loops, switches).
    pub best_structure: Option<DecompilerSource>,
    /// Decompiler with most meaningful variable names.
    pub best_naming: Option<DecompilerSource>,
    /// Average similarity between all pairs.
    pub average_similarity: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_constructs() {
        let code = r#"
            int main() {
                for (int i = 0; i < 10; i++) {
                    if (i > 5) {
                        break;
                    }
                }
                return 0;
            }
        "#;

        let constructs = detect_constructs(code);
        assert_eq!(constructs.for_loops, 1);
        assert_eq!(constructs.if_statements, 1);
        assert_eq!(constructs.returns, 1);
        assert!(constructs.max_nesting >= 3);
    }

    #[test]
    fn test_extract_function_calls() {
        let code = r#"
            void foo() {
                printf("hello");
                bar(1, 2);
                if (condition) {
                    baz();
                }
            }
        "#;

        let calls = extract_function_calls(code);
        assert!(calls.contains(&"printf".to_string()));
        assert!(calls.contains(&"bar".to_string()));
        assert!(calls.contains(&"baz".to_string()));
        assert!(!calls.contains(&"if".to_string()));
    }

    #[test]
    fn test_extract_variables() {
        let code = r#"
            void foo() {
                int x = 5;
                char *buffer;
                uint32_t count = 0;
            }
        "#;

        let vars = extract_variables(code);
        assert!(vars.contains(&"x".to_string()));
        assert!(vars.contains(&"buffer".to_string()));
        assert!(vars.contains(&"count".to_string()));
    }

    #[test]
    fn test_comparison() {
        let code_a = r#"
            void func() {
                for (int i = 0; i < n; i++) {
                    sum += arr[i];
                }
            }
        "#;

        let code_b = r#"
            void func() {
                int i = 0;
                while (i < n) {
                    sum = sum + arr[i];
                    i++;
                }
            }
        "#;

        let tester = ComparisonTester::new();
        let result = tester.compare_code(
            "func",
            DecompilerSource::Hexray,
            code_a,
            DecompilerSource::Ghidra,
            code_b,
        );

        // Should have some similarity but not perfect
        assert!(result.similarity_score > 0.3);
        assert!(result.similarity_score < 1.0);
    }

    #[test]
    fn test_goto_detection() {
        let code_with_goto = r#"
            void func() {
                if (x) goto label;
                y = 1;
            label:
                return;
            }
        "#;

        let code_without_goto = r#"
            void func() {
                if (!x) {
                    y = 1;
                }
                return;
            }
        "#;

        let tester = ComparisonTester::new();
        let result = tester.compare_code(
            "func",
            DecompilerSource::Hexray,
            code_without_goto,
            DecompilerSource::Ghidra,
            code_with_goto,
        );

        // Should detect goto difference
        assert!(result
            .differences
            .iter()
            .any(|d| d.kind == DifferenceKind::GotoUsage));
    }

    #[test]
    fn test_valid_identifier() {
        assert!(is_valid_identifier("foo"));
        assert!(is_valid_identifier("_bar"));
        assert!(is_valid_identifier("var123"));
        assert!(!is_valid_identifier("123var"));
        assert!(!is_valid_identifier(""));
        assert!(!is_valid_identifier("foo bar"));
    }

    #[test]
    fn test_decompiler_source_name() {
        assert_eq!(DecompilerSource::Hexray.name(), "hexray");
        assert_eq!(DecompilerSource::Ghidra.name(), "Ghidra");
        assert_eq!(DecompilerSource::IdaPro.name(), "IDA Pro");
    }
}
