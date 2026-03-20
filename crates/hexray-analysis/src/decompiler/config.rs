//! Decompiler configuration and optimization passes.
//!
//! This module provides configuration options for controlling which
//! optimization passes are enabled during decompilation.

use std::collections::HashSet;

/// Optimization level presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OptimizationLevel {
    /// No optimizations - raw structured output.
    None,
    /// Basic optimizations only (expression simplification, copy propagation).
    Basic,
    /// Standard optimizations (default level).
    #[default]
    Standard,
    /// Aggressive optimizations (may be slower, more transformations).
    Aggressive,
}

impl OptimizationLevel {
    /// Parses an optimization level from a string.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "none" | "0" | "o0" => Some(Self::None),
            "basic" | "1" | "o1" => Some(Self::Basic),
            "standard" | "2" | "o2" | "default" => Some(Self::Standard),
            "aggressive" | "3" | "o3" | "max" => Some(Self::Aggressive),
            _ => None,
        }
    }

    /// Returns the numeric level (0-3).
    pub fn level(&self) -> u8 {
        match self {
            Self::None => 0,
            Self::Basic => 1,
            Self::Standard => 2,
            Self::Aggressive => 3,
        }
    }
}

/// Individual optimization passes that can be enabled or disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OptimizationPass {
    /// Propagate function arguments into call expressions.
    CallArgPropagation,
    /// Merge return value captures across block boundaries.
    ReturnValueMerge,
    /// Simplify temporary register patterns.
    TempSimplification,
    /// Detect for loops from while loops with init/update.
    ForLoopDetection,
    /// Hoist loop-invariant computations.
    LoopInvariantHoisting,
    /// Detect memcpy/memset patterns in loops.
    LoopPatternDetection,
    /// Detect switch statements from if-else chains.
    SwitchDetection,
    /// Detect short-circuit boolean patterns (a && b, a || b).
    ShortCircuitDetection,
    /// Convert gotos to break/continue where applicable.
    GotoConversion,
    /// Flatten nested if-else into guard clauses.
    GuardClauseFlattening,
    /// Simplify expressions (constant folding, algebraic).
    ExpressionSimplification,
    /// Detect string function patterns (strlen, strcpy, etc.).
    StringPatternDetection,
    /// Simplify architecture-specific patterns (CSEL, min/max, abs).
    ArchPatternSimplification,
    /// Eliminate dead stores (assignments to unused variables).
    DeadStoreElimination,
    /// Filter inline assembly and profiling infrastructure (stack pointer ops, __fentry__).
    InlineAsmFilter,
    /// Detect linked list traversal patterns.
    LinkedListDetection,
    /// Infer better variable names from usage context.
    VariableNaming,
    /// Loop canonicalization (do-while → while where applicable).
    LoopCanonicalization,
    /// Detect memset/array initialization idioms.
    MemsetIdiomDetection,
    /// Constant folding and propagation.
    ConstantPropagation,
    /// Type inference improvements.
    TypeInference,
    /// Improved switch statement recovery.
    SwitchRecovery,
    /// Handle irreducible CFG regions (gotos, state machines).
    IrreducibleHandling,
    /// Common subexpression elimination (replace duplicate expressions with references).
    CommonSubexpressionElimination,
}

impl OptimizationPass {
    /// Returns all available passes.
    pub fn all() -> &'static [OptimizationPass] {
        use OptimizationPass::*;
        &[
            CallArgPropagation,
            ReturnValueMerge,
            TempSimplification,
            ForLoopDetection,
            LoopInvariantHoisting,
            LoopPatternDetection,
            SwitchDetection,
            ShortCircuitDetection,
            GotoConversion,
            GuardClauseFlattening,
            ExpressionSimplification,
            StringPatternDetection,
            ArchPatternSimplification,
            DeadStoreElimination,
            InlineAsmFilter,
            LinkedListDetection,
            VariableNaming,
            LoopCanonicalization,
            MemsetIdiomDetection,
            ConstantPropagation,
            TypeInference,
            SwitchRecovery,
            IrreducibleHandling,
            CommonSubexpressionElimination,
        ]
    }

    /// Returns the name of the pass.
    pub fn name(&self) -> &'static str {
        use OptimizationPass::*;
        match self {
            CallArgPropagation => "call-arg-propagation",
            ReturnValueMerge => "return-value-merge",
            TempSimplification => "temp-simplification",
            ForLoopDetection => "for-loop-detection",
            LoopInvariantHoisting => "loop-invariant-hoisting",
            LoopPatternDetection => "loop-pattern-detection",
            SwitchDetection => "switch-detection",
            ShortCircuitDetection => "short-circuit-detection",
            GotoConversion => "goto-conversion",
            GuardClauseFlattening => "guard-clause-flattening",
            ExpressionSimplification => "expression-simplification",
            StringPatternDetection => "string-pattern-detection",
            ArchPatternSimplification => "arch-pattern-simplification",
            DeadStoreElimination => "dead-store-elimination",
            InlineAsmFilter => "inline-asm-filter",
            LinkedListDetection => "linked-list-detection",
            VariableNaming => "variable-naming",
            LoopCanonicalization => "loop-canonicalization",
            MemsetIdiomDetection => "memset-idiom-detection",
            ConstantPropagation => "constant-propagation",
            TypeInference => "type-inference",
            SwitchRecovery => "switch-recovery",
            IrreducibleHandling => "irreducible-handling",
            CommonSubexpressionElimination => "cse",
        }
    }

    /// Returns a description of the pass.
    pub fn description(&self) -> &'static str {
        use OptimizationPass::*;
        match self {
            CallArgPropagation => "Propagate function arguments into call expressions",
            ReturnValueMerge => "Merge return value captures across block boundaries",
            TempSimplification => "Simplify temporary register patterns",
            ForLoopDetection => "Detect for loops from while loops with init/update",
            LoopInvariantHoisting => "Hoist loop-invariant computations",
            LoopPatternDetection => "Detect memcpy/memset patterns in loops",
            SwitchDetection => "Detect switch statements from if-else chains",
            ShortCircuitDetection => "Detect short-circuit boolean patterns",
            GotoConversion => "Convert gotos to break/continue",
            GuardClauseFlattening => "Flatten nested if-else into guard clauses",
            ExpressionSimplification => "Simplify expressions (constant folding)",
            StringPatternDetection => "Detect string function patterns",
            ArchPatternSimplification => "Simplify architecture-specific patterns",
            DeadStoreElimination => "Eliminate dead stores",
            InlineAsmFilter => "Filter inline assembly and profiling infrastructure",
            LinkedListDetection => "Detect linked list traversal patterns",
            VariableNaming => "Infer better variable names from usage",
            LoopCanonicalization => "Canonicalize loop forms",
            MemsetIdiomDetection => "Detect memset/array initialization idioms",
            ConstantPropagation => "Constant folding and propagation",
            TypeInference => "Type inference improvements",
            SwitchRecovery => "Improved switch statement recovery",
            IrreducibleHandling => "Handle irreducible CFG regions",
            CommonSubexpressionElimination => "Eliminate duplicate expressions",
        }
    }

    /// Parses a pass name.
    pub fn from_name(name: &str) -> Option<Self> {
        use OptimizationPass::*;
        match name.to_lowercase().replace('_', "-").as_str() {
            "call-arg-propagation" => Some(CallArgPropagation),
            "return-value-merge" => Some(ReturnValueMerge),
            "temp-simplification" => Some(TempSimplification),
            "for-loop-detection" => Some(ForLoopDetection),
            "loop-invariant-hoisting" => Some(LoopInvariantHoisting),
            "loop-pattern-detection" => Some(LoopPatternDetection),
            "switch-detection" => Some(SwitchDetection),
            "short-circuit-detection" => Some(ShortCircuitDetection),
            "goto-conversion" => Some(GotoConversion),
            "guard-clause-flattening" => Some(GuardClauseFlattening),
            "expression-simplification" => Some(ExpressionSimplification),
            "string-pattern-detection" => Some(StringPatternDetection),
            "arch-pattern-simplification" => Some(ArchPatternSimplification),
            "dead-store-elimination" => Some(DeadStoreElimination),
            "inline-asm-filter" => Some(InlineAsmFilter),
            "linked-list-detection" => Some(LinkedListDetection),
            "variable-naming" => Some(VariableNaming),
            "loop-canonicalization" => Some(LoopCanonicalization),
            "memset-idiom-detection" => Some(MemsetIdiomDetection),
            "constant-propagation" => Some(ConstantPropagation),
            "type-inference" => Some(TypeInference),
            "switch-recovery" => Some(SwitchRecovery),
            "irreducible-handling" => Some(IrreducibleHandling),
            "cse" | "common-subexpression-elimination" => Some(CommonSubexpressionElimination),
            _ => None,
        }
    }
}

/// Configuration for the decompiler optimization passes.
#[derive(Debug, Clone)]
pub struct DecompilerConfig {
    /// The base optimization level.
    pub level: OptimizationLevel,
    /// Explicitly enabled passes (override level).
    pub enabled_passes: HashSet<OptimizationPass>,
    /// Explicitly disabled passes (override level).
    pub disabled_passes: HashSet<OptimizationPass>,
}

impl Default for DecompilerConfig {
    fn default() -> Self {
        Self {
            level: OptimizationLevel::Standard,
            enabled_passes: HashSet::new(),
            disabled_passes: HashSet::new(),
        }
    }
}

impl DecompilerConfig {
    /// Creates a new configuration with the specified optimization level.
    pub fn new(level: OptimizationLevel) -> Self {
        Self {
            level,
            enabled_passes: HashSet::new(),
            disabled_passes: HashSet::new(),
        }
    }

    /// Creates a configuration with no optimizations.
    pub fn none() -> Self {
        Self::new(OptimizationLevel::None)
    }

    /// Creates a configuration with basic optimizations.
    pub fn basic() -> Self {
        Self::new(OptimizationLevel::Basic)
    }

    /// Creates a configuration with standard optimizations.
    pub fn standard() -> Self {
        Self::new(OptimizationLevel::Standard)
    }

    /// Creates a configuration with aggressive optimizations.
    pub fn aggressive() -> Self {
        Self::new(OptimizationLevel::Aggressive)
    }

    /// Explicitly enables a pass.
    pub fn enable_pass(mut self, pass: OptimizationPass) -> Self {
        self.enabled_passes.insert(pass);
        self.disabled_passes.remove(&pass);
        self
    }

    /// Explicitly disables a pass.
    pub fn disable_pass(mut self, pass: OptimizationPass) -> Self {
        self.disabled_passes.insert(pass);
        self.enabled_passes.remove(&pass);
        self
    }

    /// Checks if a pass is enabled.
    pub fn is_pass_enabled(&self, pass: OptimizationPass) -> bool {
        // Explicit enable/disable takes precedence
        if self.enabled_passes.contains(&pass) {
            return true;
        }
        if self.disabled_passes.contains(&pass) {
            return false;
        }

        // Otherwise, check the optimization level
        self.pass_enabled_at_level(pass)
    }

    /// Checks if a pass is enabled at the current optimization level.
    fn pass_enabled_at_level(&self, pass: OptimizationPass) -> bool {
        use OptimizationLevel::*;
        use OptimizationPass::*;

        match self.level {
            None => false,
            Basic => matches!(
                pass,
                CallArgPropagation
                    | ReturnValueMerge
                    | TempSimplification
                    | ExpressionSimplification
            ),
            Standard => matches!(
                pass,
                CallArgPropagation
                    | ReturnValueMerge
                    | TempSimplification
                    | ForLoopDetection
                    | LoopInvariantHoisting
                    | LoopPatternDetection
                    | SwitchDetection
                    | SwitchRecovery
                    | ShortCircuitDetection
                    | GotoConversion
                    | GuardClauseFlattening
                    | ExpressionSimplification
                    | StringPatternDetection
                    | ArchPatternSimplification
                    | DeadStoreElimination
                    | VariableNaming
                    | ConstantPropagation
                    | LoopCanonicalization
                    | IrreducibleHandling
                    | CommonSubexpressionElimination
            ),
            Aggressive => {
                // All passes enabled at aggressive level
                true
            }
        }
    }

    /// Returns all enabled passes in the order they should be applied.
    pub fn enabled_passes(&self) -> Vec<OptimizationPass> {
        OptimizationPass::all()
            .iter()
            .copied()
            .filter(|&p| self.is_pass_enabled(p))
            .collect()
    }

    /// Lists all available passes with their enabled status.
    pub fn list_passes(&self) -> Vec<(OptimizationPass, bool, &'static str)> {
        OptimizationPass::all()
            .iter()
            .map(|&p| (p, self.is_pass_enabled(p), p.description()))
            .collect()
    }

    /// Creates a swarm configuration from a bitmask.
    ///
    /// Each bit in `bits` determines whether the corresponding pass from
    /// [`OptimizationPass::all()`] is enabled. This is the core primitive for
    /// *swarm testing* (Groce et al., ISSTA 2012): instead of running with a
    /// single "default" configuration that enables every pass, generate a
    /// diverse set of configurations that each *omit* a random subset of
    /// passes. Feature-omission diversity leads to better coverage and fault
    /// detection because some passes actively suppress behaviors that would
    /// otherwise expose bugs, and passes compete for "space" in each test,
    /// limiting exploration depth.
    ///
    /// Use with proptest to generate random `u32` values:
    ///
    /// ```ignore
    /// proptest! {
    ///     #[test]
    ///     fn swarm(bits in proptest::bits::u32::ANY) {
    ///         let config = DecompilerConfig::from_swarm_bits(bits);
    ///         // ...run decompilation with config...
    ///     }
    /// }
    /// ```
    pub fn from_swarm_bits(bits: u32) -> Self {
        let all = OptimizationPass::all();
        debug_assert!(
            all.len() <= 32,
            "more than 32 passes; from_swarm_bits needs a wider type"
        );
        let mut config = Self::new(OptimizationLevel::None);
        for (i, &pass) in all.iter().enumerate() {
            if bits & (1 << i) != 0 {
                config.enabled_passes.insert(pass);
            }
        }
        config
    }

    /// Returns the bitmask representation of the currently-enabled passes.
    ///
    /// Inverse of [`from_swarm_bits`](Self::from_swarm_bits).
    pub fn to_swarm_bits(&self) -> u32 {
        let all = OptimizationPass::all();
        let mut bits = 0u32;
        for (i, &pass) in all.iter().enumerate() {
            if self.is_pass_enabled(pass) {
                bits |= 1 << i;
            }
        }
        bits
    }

    /// Returns a human-readable summary of the enabled passes.
    pub fn describe(&self) -> String {
        let enabled = self.enabled_passes();
        let names: Vec<&str> = enabled.iter().map(|p| p.name()).collect();
        format!(
            "{}/{} passes enabled: [{}]",
            enabled.len(),
            OptimizationPass::all().len(),
            names.join(", ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optimization_level_parse() {
        assert_eq!(
            OptimizationLevel::parse("none"),
            Some(OptimizationLevel::None)
        );
        assert_eq!(OptimizationLevel::parse("0"), Some(OptimizationLevel::None));
        assert_eq!(
            OptimizationLevel::parse("basic"),
            Some(OptimizationLevel::Basic)
        );
        assert_eq!(
            OptimizationLevel::parse("standard"),
            Some(OptimizationLevel::Standard)
        );
        assert_eq!(
            OptimizationLevel::parse("aggressive"),
            Some(OptimizationLevel::Aggressive)
        );
        assert_eq!(OptimizationLevel::parse("invalid"), None);
    }

    #[test]
    fn test_config_default() {
        let config = DecompilerConfig::default();
        assert_eq!(config.level, OptimizationLevel::Standard);
        assert!(config.is_pass_enabled(OptimizationPass::ExpressionSimplification));
        assert!(config.is_pass_enabled(OptimizationPass::VariableNaming));
    }

    #[test]
    fn test_config_none() {
        let config = DecompilerConfig::none();
        assert!(!config.is_pass_enabled(OptimizationPass::ExpressionSimplification));
        assert!(!config.is_pass_enabled(OptimizationPass::DeadStoreElimination));
    }

    #[test]
    fn test_config_explicit_enable() {
        let config = DecompilerConfig::none().enable_pass(OptimizationPass::DeadStoreElimination);
        assert!(config.is_pass_enabled(OptimizationPass::DeadStoreElimination));
        assert!(!config.is_pass_enabled(OptimizationPass::ExpressionSimplification));
    }

    #[test]
    fn test_config_explicit_disable() {
        let config =
            DecompilerConfig::standard().disable_pass(OptimizationPass::DeadStoreElimination);
        assert!(!config.is_pass_enabled(OptimizationPass::DeadStoreElimination));
        assert!(config.is_pass_enabled(OptimizationPass::ExpressionSimplification));
    }

    #[test]
    fn test_aggressive_enables_all() {
        let config = DecompilerConfig::aggressive();
        for pass in OptimizationPass::all() {
            assert!(
                config.is_pass_enabled(*pass),
                "Pass {:?} should be enabled at aggressive level",
                pass
            );
        }
    }

    #[test]
    fn test_swarm_bits_roundtrip() {
        // All bits set → all passes enabled
        let config = DecompilerConfig::from_swarm_bits(0x00FF_FFFF);
        assert_eq!(config.enabled_passes().len(), OptimizationPass::all().len());

        // Zero bits → no passes enabled
        let config = DecompilerConfig::from_swarm_bits(0);
        assert!(config.enabled_passes().is_empty());

        // Roundtrip: bits → config → bits
        let bits: u32 = 0b1010_1010_1010_1010_1010_1010;
        let config = DecompilerConfig::from_swarm_bits(bits);
        let mask = (1u32 << OptimizationPass::all().len()) - 1;
        assert_eq!(config.to_swarm_bits(), bits & mask);
    }

    #[test]
    fn test_swarm_bits_individual_passes() {
        // Bit 0 → first pass (CallArgPropagation)
        let config = DecompilerConfig::from_swarm_bits(1);
        assert!(config.is_pass_enabled(OptimizationPass::CallArgPropagation));
        assert!(!config.is_pass_enabled(OptimizationPass::ReturnValueMerge));
    }

    #[test]
    fn test_swarm_describe() {
        let config = DecompilerConfig::from_swarm_bits(0);
        assert!(config.describe().starts_with("0/"));

        let config = DecompilerConfig::from_swarm_bits(0x00FF_FFFF);
        assert!(config.describe().starts_with("24/"));
    }
}
