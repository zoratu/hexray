//! # hexray-analysis
//!
//! Analysis passes for hexray disassembler.
//!
//! This crate provides:
//! - Basic block detection
//! - CFG construction
//! - Function boundary detection
//! - Call graph construction
//! - Control flow structuring and decompilation
//! - Data flow analysis (def-use chains, liveness, reaching definitions)
//! - SSA form construction
//! - Type inference

pub mod callgraph;
pub mod cfg_builder;
pub mod dataflow;
pub mod decompiler;
pub mod function_finder;
pub mod output;
pub mod parallel;
pub mod ssa;
pub mod strings;
pub mod types;
pub mod xrefs;

pub use strings::{DetectedString, DetectedStringTable, StringConfig, StringDetector, StringEncoding};
pub use xrefs::{Xref, XrefBuilder, XrefDatabase, XrefType};

pub use callgraph::{CallGraph, CallGraphBuilder, CallGraphNode, CallSite, CallType};
pub use cfg_builder::CfgBuilder;
pub use dataflow::{ConstValue, ConstState, ConstantPropagation, DefUseChain, LivenessAnalysis, ReachingDefinitions, Location};
pub use decompiler::{Decompiler, StringTable, SymbolTable, RelocationTable};
pub use function_finder::FunctionFinder;
pub use output::{
    CallGraphDotExporter, CallGraphHtmlExporter, CallGraphJsonExporter,
    CfgDotExporter, CfgHtmlExporter, CfgJsonExporter,
};
pub use parallel::{
    disassemble_functions_parallel, DisassembledFunction, FunctionInfo,
    ParallelCallGraphBuilder,
};
pub use ssa::{SsaBuilder, SsaFunction, SsaValue, PhiNode, SsaOptimizer, OptimizationStats};
pub use types::{Type, TypeInference, FunctionSignatures, Constraint};
