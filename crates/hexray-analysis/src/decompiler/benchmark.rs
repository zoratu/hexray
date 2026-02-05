//! Decompiler benchmark suite with ground truth comparison.
//!
//! This module provides a framework for benchmarking decompiler output quality
//! by comparing against known source code patterns.
//!
//! # Features
//!
//! - Ground truth test cases with source code
//! - Pattern matching against expected constructs
//! - Quality metrics computation
//! - Automated scoring and reporting
//!
//! # Example
//!
//! ```ignore
//! use hexray_analysis::decompiler::benchmark::{BenchmarkSuite, BenchmarkCase};
//!
//! let mut suite = BenchmarkSuite::new();
//! suite.add_case(BenchmarkCase::new("simple_loop")
//!     .with_source(r#"for (int i = 0; i < n; i++) { sum += arr[i]; }"#)
//!     .expect_pattern(Pattern::ForLoop));
//!
//! let results = suite.run_all();
//! println!("Score: {:.1}%", results.overall_score * 100.0);
//! ```

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A benchmark test case.
#[derive(Debug, Clone)]
pub struct BenchmarkCase {
    /// Unique identifier for this case.
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// Original source code (if available).
    pub source_code: Option<String>,
    /// Expected patterns in the decompiled output.
    pub expected_patterns: Vec<ExpectedPattern>,
    /// Patterns that should NOT appear.
    pub forbidden_patterns: Vec<ForbiddenPattern>,
    /// Minimum acceptable quality score (0.0 - 1.0).
    pub min_quality: f64,
    /// Category of the test (e.g., "loops", "conditionals", "arithmetic").
    pub category: String,
    /// Difficulty level (1-5).
    pub difficulty: u8,
}

impl BenchmarkCase {
    /// Creates a new benchmark case.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            description: String::new(),
            source_code: None,
            expected_patterns: Vec::new(),
            forbidden_patterns: Vec::new(),
            min_quality: 0.5,
            category: "general".to_string(),
            difficulty: 1,
        }
    }

    /// Sets the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Sets the source code.
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source_code = Some(source.into());
        self
    }

    /// Adds an expected pattern.
    pub fn expect_pattern(mut self, pattern: ExpectedPattern) -> Self {
        self.expected_patterns.push(pattern);
        self
    }

    /// Adds a forbidden pattern.
    pub fn forbid_pattern(mut self, pattern: ForbiddenPattern) -> Self {
        self.forbidden_patterns.push(pattern);
        self
    }

    /// Sets the minimum quality threshold.
    pub fn with_min_quality(mut self, quality: f64) -> Self {
        self.min_quality = quality;
        self
    }

    /// Sets the category.
    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.category = category.into();
        self
    }

    /// Sets the difficulty level.
    pub fn with_difficulty(mut self, level: u8) -> Self {
        self.difficulty = level.clamp(1, 5);
        self
    }
}

/// An expected pattern in decompiled output.
#[derive(Debug, Clone)]
pub enum ExpectedPattern {
    /// A for loop construct.
    ForLoop,
    /// A while loop construct.
    WhileLoop,
    /// A do-while loop construct.
    DoWhileLoop,
    /// An if-else construct.
    IfElse,
    /// A switch statement with minimum cases.
    Switch { min_cases: usize },
    /// A function call.
    FunctionCall { name: String },
    /// Array access pattern.
    ArrayAccess,
    /// Struct field access (. or ->).
    StructAccess,
    /// A literal string should appear.
    Contains(String),
    /// Variable assignment.
    Assignment,
    /// Return statement.
    Return,
    /// Ternary/conditional expression.
    TernaryExpr,
    /// A math function call (abs, min, max, etc.).
    MathFunction(String),
    /// An operator pattern (++, --, +=, etc.).
    Operator(String),
}

/// A pattern that should NOT appear in decompiled output.
#[derive(Debug, Clone)]
pub enum ForbiddenPattern {
    /// Goto statements (indicates failure to structure).
    Goto,
    /// Raw assembly/machine code.
    RawAsm,
    /// Generic variable names (var1, var2, etc.).
    GenericVarNames,
    /// Excessive nesting depth.
    ExcessiveNesting(usize),
    /// A specific pattern that shouldn't appear.
    Contains(String),
    /// Label that indicates unstructured code.
    Label,
    /// Dead code that shouldn't be present.
    DeadCode,
}

/// Result of running a single benchmark case.
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    /// The case ID.
    pub case_id: String,
    /// Whether the case passed.
    pub passed: bool,
    /// Quality score (0.0 - 1.0).
    pub score: f64,
    /// Number of expected patterns found.
    pub patterns_found: usize,
    /// Total expected patterns.
    pub patterns_expected: usize,
    /// Number of forbidden patterns found (should be 0).
    pub violations_found: usize,
    /// Execution time.
    pub duration: Duration,
    /// The decompiled output.
    pub output: String,
    /// Detailed pattern match results.
    pub pattern_results: Vec<PatternMatchResult>,
    /// Error message if failed.
    pub error: Option<String>,
}

/// Result of matching a single pattern.
#[derive(Debug, Clone)]
pub struct PatternMatchResult {
    /// Pattern description.
    pub pattern: String,
    /// Whether it matched.
    pub matched: bool,
    /// Match location (line number).
    pub location: Option<usize>,
    /// Additional details.
    pub details: Option<String>,
}

/// Aggregate results for the entire benchmark suite.
#[derive(Debug, Clone)]
pub struct BenchmarkSuiteResults {
    /// Results for each case.
    pub case_results: Vec<BenchmarkResult>,
    /// Number of cases passed.
    pub passed: usize,
    /// Number of cases failed.
    pub failed: usize,
    /// Overall quality score.
    pub overall_score: f64,
    /// Total execution time.
    pub total_duration: Duration,
    /// Results grouped by category.
    pub by_category: HashMap<String, CategoryResults>,
}

/// Results for a specific category.
#[derive(Debug, Clone, Default)]
pub struct CategoryResults {
    /// Category name.
    pub name: String,
    /// Number of cases in this category.
    pub total: usize,
    /// Number passed.
    pub passed: usize,
    /// Average score.
    pub avg_score: f64,
}

/// A benchmark suite containing multiple test cases.
#[derive(Debug, Default)]
pub struct BenchmarkSuite {
    /// All test cases.
    cases: Vec<BenchmarkCase>,
    /// Configuration.
    config: BenchmarkConfig,
}

/// Configuration for benchmark runs.
#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    /// Whether to run in verbose mode.
    pub verbose: bool,
    /// Timeout for each case.
    pub timeout: Duration,
    /// Whether to continue on failure.
    pub continue_on_failure: bool,
    /// Categories to run (empty = all).
    pub categories: Vec<String>,
    /// Minimum difficulty to run.
    pub min_difficulty: u8,
    /// Maximum difficulty to run.
    pub max_difficulty: u8,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            verbose: false,
            timeout: Duration::from_secs(30),
            continue_on_failure: true,
            categories: Vec::new(),
            min_difficulty: 1,
            max_difficulty: 5,
        }
    }
}

impl BenchmarkSuite {
    /// Creates a new benchmark suite.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the configuration.
    pub fn with_config(mut self, config: BenchmarkConfig) -> Self {
        self.config = config;
        self
    }

    /// Adds a test case.
    pub fn add_case(&mut self, case: BenchmarkCase) {
        self.cases.push(case);
    }

    /// Returns the number of cases.
    pub fn len(&self) -> usize {
        self.cases.len()
    }

    /// Returns true if there are no cases.
    pub fn is_empty(&self) -> bool {
        self.cases.is_empty()
    }

    /// Runs all benchmarks with the given evaluator function.
    ///
    /// The evaluator takes a case ID and returns the decompiled output.
    pub fn run_all<F>(&self, evaluator: F) -> BenchmarkSuiteResults
    where
        F: Fn(&str) -> Result<String, String>,
    {
        let start = Instant::now();
        let mut case_results = Vec::with_capacity(self.cases.len());
        let mut passed = 0;
        let mut failed = 0;
        let mut total_score = 0.0;

        for case in &self.cases {
            // Check if case should be run
            if !self.should_run_case(case) {
                continue;
            }

            let result = self.run_case(case, &evaluator);

            if result.passed {
                passed += 1;
            } else {
                failed += 1;
            }
            total_score += result.score;

            case_results.push(result);

            if !self.config.continue_on_failure && failed > 0 {
                break;
            }
        }

        let total_duration = start.elapsed();
        let overall_score = if !case_results.is_empty() {
            total_score / case_results.len() as f64
        } else {
            0.0
        };

        // Compute category results
        let by_category = self.compute_category_results(&case_results);

        BenchmarkSuiteResults {
            case_results,
            passed,
            failed,
            overall_score,
            total_duration,
            by_category,
        }
    }

    fn should_run_case(&self, case: &BenchmarkCase) -> bool {
        // Check difficulty
        if case.difficulty < self.config.min_difficulty
            || case.difficulty > self.config.max_difficulty
        {
            return false;
        }

        // Check category filter
        if !self.config.categories.is_empty() && !self.config.categories.contains(&case.category) {
            return false;
        }

        true
    }

    fn run_case<F>(&self, case: &BenchmarkCase, evaluator: &F) -> BenchmarkResult
    where
        F: Fn(&str) -> Result<String, String>,
    {
        let start = Instant::now();

        // Run the evaluator
        let output = match evaluator(&case.id) {
            Ok(out) => out,
            Err(e) => {
                return BenchmarkResult {
                    case_id: case.id.clone(),
                    passed: false,
                    score: 0.0,
                    patterns_found: 0,
                    patterns_expected: case.expected_patterns.len(),
                    violations_found: 0,
                    duration: start.elapsed(),
                    output: String::new(),
                    pattern_results: Vec::new(),
                    error: Some(e),
                };
            }
        };

        // Match patterns
        let pattern_results = self.match_patterns(case, &output);
        let patterns_found = pattern_results.iter().filter(|r| r.matched).count();

        // Check for forbidden patterns
        let violations_found = self.count_violations(case, &output);

        // Calculate score
        let pattern_score = if !case.expected_patterns.is_empty() {
            patterns_found as f64 / case.expected_patterns.len() as f64
        } else {
            1.0
        };

        // Penalize violations
        let violation_penalty = violations_found as f64 * 0.1;
        let score = (pattern_score - violation_penalty).clamp(0.0, 1.0);

        let passed = score >= case.min_quality && violations_found == 0;

        BenchmarkResult {
            case_id: case.id.clone(),
            passed,
            score,
            patterns_found,
            patterns_expected: case.expected_patterns.len(),
            violations_found,
            duration: start.elapsed(),
            output,
            pattern_results,
            error: None,
        }
    }

    fn match_patterns(&self, case: &BenchmarkCase, output: &str) -> Vec<PatternMatchResult> {
        let mut results = Vec::new();

        for pattern in &case.expected_patterns {
            let (matched, location, details) = self.check_pattern(pattern, output);
            results.push(PatternMatchResult {
                pattern: format!("{:?}", pattern),
                matched,
                location,
                details,
            });
        }

        results
    }

    fn check_pattern(
        &self,
        pattern: &ExpectedPattern,
        output: &str,
    ) -> (bool, Option<usize>, Option<String>) {
        match pattern {
            ExpectedPattern::ForLoop => {
                let matched = output.contains("for (") || output.contains("for(");
                let location = output
                    .lines()
                    .position(|l| l.contains("for (") || l.contains("for("));
                (matched, location, None)
            }

            ExpectedPattern::WhileLoop => {
                let matched = output.contains("while (") || output.contains("while(");
                let location = output
                    .lines()
                    .position(|l| l.contains("while (") || l.contains("while("));
                (matched, location, None)
            }

            ExpectedPattern::DoWhileLoop => {
                let matched = output.contains("do {") && output.contains("} while");
                let location = output.lines().position(|l| l.contains("do {"));
                (matched, location, None)
            }

            ExpectedPattern::IfElse => {
                let has_if = output.contains("if (") || output.contains("if(");
                let has_else = output.contains("else");
                let matched = has_if && has_else;
                (matched, None, None)
            }

            ExpectedPattern::Switch { min_cases } => {
                let has_switch = output.contains("switch (") || output.contains("switch(");
                let case_count = output.matches("case ").count();
                let matched = has_switch && case_count >= *min_cases;
                (matched, None, Some(format!("found {} cases", case_count)))
            }

            ExpectedPattern::FunctionCall { name } => {
                let call_pattern = format!("{}(", name);
                let matched = output.contains(&call_pattern);
                let location = output.lines().position(|l| l.contains(&call_pattern));
                (matched, location, None)
            }

            ExpectedPattern::ArrayAccess => {
                let matched = output.contains('[') && output.contains(']');
                (matched, None, None)
            }

            ExpectedPattern::StructAccess => {
                let has_dot = output.contains('.');
                let has_arrow = output.contains("->");
                let matched = has_dot || has_arrow;
                (matched, None, None)
            }

            ExpectedPattern::Contains(text) => {
                let matched = output.contains(text);
                let location = output.lines().position(|l| l.contains(text));
                (matched, location, None)
            }

            ExpectedPattern::Assignment => {
                let has_assign = output.contains(" = ");
                (has_assign, None, None)
            }

            ExpectedPattern::Return => {
                let matched = output.contains("return ");
                let location = output.lines().position(|l| l.contains("return "));
                (matched, location, None)
            }

            ExpectedPattern::TernaryExpr => {
                let matched = output.contains(" ? ") && output.contains(" : ");
                (matched, None, None)
            }

            ExpectedPattern::MathFunction(name) => {
                let matched = output.contains(&format!("{}(", name));
                (matched, None, None)
            }

            ExpectedPattern::Operator(op) => {
                let matched = output.contains(op);
                (matched, None, None)
            }
        }
    }

    fn count_violations(&self, case: &BenchmarkCase, output: &str) -> usize {
        let mut count = 0;

        for pattern in &case.forbidden_patterns {
            match pattern {
                ForbiddenPattern::Goto => {
                    if output.contains("goto ") {
                        count += 1;
                    }
                }
                ForbiddenPattern::RawAsm => {
                    if output.contains("__asm") || output.contains("asm volatile") {
                        count += 1;
                    }
                }
                ForbiddenPattern::GenericVarNames => {
                    // Check for var1, var2, temp1, etc.
                    if contains_generic_var_name(output) {
                        count += 1;
                    }
                }
                ForbiddenPattern::ExcessiveNesting(max_depth) => {
                    let max_found = count_max_nesting(output);
                    if max_found > *max_depth {
                        count += 1;
                    }
                }
                ForbiddenPattern::Contains(text) => {
                    if output.contains(text) {
                        count += 1;
                    }
                }
                ForbiddenPattern::Label => {
                    // Check for labels like "label_123:" or "L1:"
                    if contains_label_pattern(output) {
                        count += 1;
                    }
                }
                ForbiddenPattern::DeadCode => {
                    // Check for obvious dead code patterns
                    if output.contains("/* unreachable */") || output.contains("// dead code") {
                        count += 1;
                    }
                }
            }
        }

        count
    }

    fn compute_category_results(
        &self,
        results: &[BenchmarkResult],
    ) -> HashMap<String, CategoryResults> {
        let mut by_category: HashMap<String, CategoryResults> = HashMap::new();

        for case in &self.cases {
            let entry =
                by_category
                    .entry(case.category.clone())
                    .or_insert_with(|| CategoryResults {
                        name: case.category.clone(),
                        total: 0,
                        passed: 0,
                        avg_score: 0.0,
                    });
            entry.total += 1;
        }

        for result in results {
            if let Some(case) = self.cases.iter().find(|c| c.id == result.case_id) {
                if let Some(cat) = by_category.get_mut(&case.category) {
                    if result.passed {
                        cat.passed += 1;
                    }
                    cat.avg_score += result.score;
                }
            }
        }

        // Compute averages
        for cat in by_category.values_mut() {
            if cat.total > 0 {
                cat.avg_score /= cat.total as f64;
            }
        }

        by_category
    }
}

/// Count maximum nesting depth in code.
fn count_max_nesting(code: &str) -> usize {
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

/// Check if output contains generic variable names like var1, temp2, etc.
fn contains_generic_var_name(output: &str) -> bool {
    // Simple heuristic: look for common patterns
    let patterns = [
        "var1", "var2", "var3", "temp1", "temp2", "tmp1", "tmp2", "local_", "v1_", "v2_",
    ];
    patterns.iter().any(|p| output.contains(p))
}

/// Check if output contains label patterns like "label_123:" or "L1:"
fn contains_label_pattern(output: &str) -> bool {
    for line in output.lines() {
        let trimmed = line.trim();
        // Check for label patterns ending with ':'
        if trimmed.ends_with(':') && !trimmed.contains(' ') {
            // Exclude switch case labels
            if !trimmed.starts_with("case ") && !trimmed.starts_with("default") {
                return true;
            }
        }
    }
    false
}

/// Create the standard benchmark suite with common test cases.
pub fn create_standard_suite() -> BenchmarkSuite {
    let mut suite = BenchmarkSuite::new();

    // Loop patterns
    suite.add_case(
        BenchmarkCase::new("simple_for_loop")
            .with_description("Simple counting for loop")
            .with_category("loops")
            .with_difficulty(1)
            .with_source("for (int i = 0; i < n; i++) { sum += arr[i]; }")
            .expect_pattern(ExpectedPattern::ForLoop)
            .expect_pattern(ExpectedPattern::ArrayAccess)
            .forbid_pattern(ForbiddenPattern::Goto),
    );

    suite.add_case(
        BenchmarkCase::new("while_loop")
            .with_description("While loop with condition")
            .with_category("loops")
            .with_difficulty(1)
            .with_source("while (ptr != NULL) { ptr = ptr->next; count++; }")
            .expect_pattern(ExpectedPattern::WhileLoop)
            .expect_pattern(ExpectedPattern::StructAccess)
            .forbid_pattern(ForbiddenPattern::Goto),
    );

    suite.add_case(
        BenchmarkCase::new("do_while_loop")
            .with_description("Do-while loop")
            .with_category("loops")
            .with_difficulty(2)
            .with_source("do { x = process(x); } while (x > 0);")
            .expect_pattern(ExpectedPattern::DoWhileLoop)
            .forbid_pattern(ForbiddenPattern::Goto),
    );

    suite.add_case(
        BenchmarkCase::new("nested_loops")
            .with_description("Nested for loops (matrix iteration)")
            .with_category("loops")
            .with_difficulty(3)
            .with_source("for (int i = 0; i < n; i++) for (int j = 0; j < m; j++) result[i][j] = a[i][j] + b[i][j];")
            .expect_pattern(ExpectedPattern::ForLoop)
            .expect_pattern(ExpectedPattern::ArrayAccess)
            .forbid_pattern(ForbiddenPattern::Goto)
            .forbid_pattern(ForbiddenPattern::ExcessiveNesting(5)),
    );

    // Conditional patterns
    suite.add_case(
        BenchmarkCase::new("simple_if_else")
            .with_description("Simple if-else")
            .with_category("conditionals")
            .with_difficulty(1)
            .with_source("if (x > 0) return 1; else return -1;")
            .expect_pattern(ExpectedPattern::IfElse)
            .expect_pattern(ExpectedPattern::Return),
    );

    suite.add_case(
        BenchmarkCase::new("switch_statement")
            .with_description("Switch with multiple cases")
            .with_category("conditionals")
            .with_difficulty(2)
            .with_source("switch (op) { case '+': return a + b; case '-': return a - b; default: return 0; }")
            .expect_pattern(ExpectedPattern::Switch { min_cases: 2 })
            .expect_pattern(ExpectedPattern::Return),
    );

    suite.add_case(
        BenchmarkCase::new("ternary_expression")
            .with_description("Ternary conditional expression")
            .with_category("conditionals")
            .with_difficulty(2)
            .with_source("return x > 0 ? x : -x;")
            .expect_pattern(ExpectedPattern::TernaryExpr)
            .expect_pattern(ExpectedPattern::Return),
    );

    // Arithmetic patterns
    suite.add_case(
        BenchmarkCase::new("abs_pattern")
            .with_description("Absolute value pattern")
            .with_category("arithmetic")
            .with_difficulty(2)
            .with_source("return x < 0 ? -x : x;")
            .expect_pattern(ExpectedPattern::MathFunction("abs".to_string())),
    );

    suite.add_case(
        BenchmarkCase::new("min_max_pattern")
            .with_description("Min/max pattern")
            .with_category("arithmetic")
            .with_difficulty(2)
            .with_source("return a < b ? a : b;")
            .expect_pattern(ExpectedPattern::MathFunction("min".to_string())),
    );

    // Function calls
    suite.add_case(
        BenchmarkCase::new("function_call")
            .with_description("Standard library call")
            .with_category("functions")
            .with_difficulty(1)
            .with_source("memcpy(dst, src, len);")
            .expect_pattern(ExpectedPattern::FunctionCall {
                name: "memcpy".to_string(),
            }),
    );

    // Struct patterns
    suite.add_case(
        BenchmarkCase::new("struct_access")
            .with_description("Struct field access")
            .with_category("structs")
            .with_difficulty(2)
            .with_source("return obj->field1 + obj->field2;")
            .expect_pattern(ExpectedPattern::StructAccess)
            .expect_pattern(ExpectedPattern::Return),
    );

    // Complex patterns
    suite.add_case(
        BenchmarkCase::new("binary_search")
            .with_description("Binary search algorithm")
            .with_category("algorithms")
            .with_difficulty(4)
            .with_source(
                r#"
                while (low <= high) {
                    int mid = (low + high) / 2;
                    if (arr[mid] == target) return mid;
                    else if (arr[mid] < target) low = mid + 1;
                    else high = mid - 1;
                }
                return -1;
            "#,
            )
            .expect_pattern(ExpectedPattern::WhileLoop)
            .expect_pattern(ExpectedPattern::ArrayAccess)
            .expect_pattern(ExpectedPattern::IfElse)
            .expect_pattern(ExpectedPattern::Return)
            .forbid_pattern(ForbiddenPattern::Goto)
            .with_min_quality(0.7),
    );

    suite.add_case(
        BenchmarkCase::new("linked_list_traversal")
            .with_description("Linked list traversal")
            .with_category("data_structures")
            .with_difficulty(3)
            .with_source("while (node != NULL) { process(node->data); node = node->next; }")
            .expect_pattern(ExpectedPattern::WhileLoop)
            .expect_pattern(ExpectedPattern::StructAccess)
            .expect_pattern(ExpectedPattern::FunctionCall {
                name: "process".to_string(),
            })
            .forbid_pattern(ForbiddenPattern::Goto),
    );

    suite
}

impl BenchmarkSuiteResults {
    /// Generates a report string.
    pub fn report(&self) -> String {
        let mut report = String::new();

        report.push_str("=== Decompiler Benchmark Results ===\n\n");
        report.push_str(&format!(
            "Overall: {}/{} passed ({:.1}% score)\n",
            self.passed,
            self.passed + self.failed,
            self.overall_score * 100.0
        ));
        report.push_str(&format!("Duration: {:?}\n\n", self.total_duration));

        // Category breakdown
        report.push_str("By Category:\n");
        for (name, cat) in &self.by_category {
            report.push_str(&format!(
                "  {}: {}/{} passed ({:.1}%)\n",
                name,
                cat.passed,
                cat.total,
                cat.avg_score * 100.0
            ));
        }
        report.push('\n');

        // Individual results
        report.push_str("Individual Results:\n");
        for result in &self.case_results {
            let status = if result.passed { "PASS" } else { "FAIL" };
            report.push_str(&format!(
                "  [{}] {} - {:.1}% ({}/{} patterns, {} violations)\n",
                status,
                result.case_id,
                result.score * 100.0,
                result.patterns_found,
                result.patterns_expected,
                result.violations_found
            ));
            if let Some(ref err) = result.error {
                report.push_str(&format!("       Error: {}\n", err));
            }
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_case_builder() {
        let case = BenchmarkCase::new("test")
            .with_description("Test case")
            .with_category("test")
            .with_difficulty(3)
            .expect_pattern(ExpectedPattern::ForLoop)
            .forbid_pattern(ForbiddenPattern::Goto);

        assert_eq!(case.id, "test");
        assert_eq!(case.category, "test");
        assert_eq!(case.difficulty, 3);
        assert_eq!(case.expected_patterns.len(), 1);
        assert_eq!(case.forbidden_patterns.len(), 1);
    }

    #[test]
    fn test_pattern_matching() {
        let suite = BenchmarkSuite::new();

        // Test for loop detection
        let output = "for (int i = 0; i < n; i++) { x += i; }";
        let (matched, _, _) = suite.check_pattern(&ExpectedPattern::ForLoop, output);
        assert!(matched);

        // Test while loop detection
        let output = "while (ptr != NULL) { ptr = ptr->next; }";
        let (matched, _, _) = suite.check_pattern(&ExpectedPattern::WhileLoop, output);
        assert!(matched);

        // Test function call detection
        let output = "memcpy(dst, src, len);";
        let (matched, _, _) = suite.check_pattern(
            &ExpectedPattern::FunctionCall {
                name: "memcpy".to_string(),
            },
            output,
        );
        assert!(matched);
    }

    #[test]
    fn test_violation_counting() {
        let suite = BenchmarkSuite::new();

        let case = BenchmarkCase::new("test")
            .forbid_pattern(ForbiddenPattern::Goto)
            .forbid_pattern(ForbiddenPattern::Label);

        // Output with goto
        let output_with_goto = "goto label_123;";
        let violations = suite.count_violations(&case, output_with_goto);
        assert!(violations > 0);

        // Clean output
        let clean_output = "if (x > 0) return 1; else return -1;";
        let violations = suite.count_violations(&case, clean_output);
        assert_eq!(violations, 0);
    }

    #[test]
    fn test_nesting_count() {
        assert_eq!(count_max_nesting("{}"), 1);
        assert_eq!(count_max_nesting("{ { } }"), 2);
        assert_eq!(count_max_nesting("{ { { } } }"), 3);
        assert_eq!(count_max_nesting("{ } { }"), 1);
    }

    #[test]
    fn test_benchmark_run() {
        let mut suite = BenchmarkSuite::new();
        suite.add_case(
            BenchmarkCase::new("test")
                .expect_pattern(ExpectedPattern::ForLoop)
                .with_min_quality(0.5),
        );

        let results = suite.run_all(|_id| Ok("for (int i = 0; i < 10; i++) {}".to_string()));

        assert_eq!(results.passed, 1);
        assert_eq!(results.failed, 0);
        assert!(results.overall_score > 0.5);
    }

    #[test]
    fn test_standard_suite_creation() {
        let suite = create_standard_suite();
        assert!(!suite.is_empty());
        assert!(suite.len() >= 10);
    }

    #[test]
    fn test_generic_var_detection() {
        assert!(contains_generic_var_name("int var1 = 5;"));
        assert!(contains_generic_var_name("temp1 = x;"));
        assert!(!contains_generic_var_name("int count = 5;"));
    }

    #[test]
    fn test_label_detection() {
        assert!(contains_label_pattern("label_123:"));
        assert!(contains_label_pattern("  L1:"));
        assert!(!contains_label_pattern("case 1:"));
        assert!(!contains_label_pattern("default:"));
        assert!(!contains_label_pattern("int x = 5;"));
    }
}
