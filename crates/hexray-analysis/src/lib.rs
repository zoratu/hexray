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
//! - Indirect call resolution
//! - Virtual function table (vtable) detection
//! - Stack canary (stack protector) detection

pub mod callgraph;
pub mod cfg_builder;
pub mod dataflow;
pub mod decompiler;
pub mod function_finder;
pub mod indirect_calls;
pub mod output;
pub mod parallel;
pub mod project;
pub mod ssa;
pub mod stack_canary;
pub mod strings;
pub mod types;
pub mod vtable;
pub mod xrefs;

pub use strings::{DetectedString, DetectedStringTable, StringConfig, StringDetector, StringEncoding};
pub use xrefs::{Xref, XrefBuilder, XrefDatabase, XrefType};
pub use indirect_calls::{
    CallTarget, Confidence, GotEntry, GotEntryBuilder, IndirectCallInfo,
    IndirectCallResolver, ResolutionMethod, ResolutionStats,
};

pub use callgraph::{CallGraph, CallGraphBuilder, CallGraphNode, CallSite, CallType};
pub use cfg_builder::CfgBuilder;
pub use dataflow::{
    ConstValue, ConstState, ConstantPropagation, DefUseChain, LivenessAnalysis,
    ReachingDefinitions, Location, DataFlowQuery, DataFlowQueryEngine, DataFlowResult,
    DataFlowStep, DataFlowRole,
};
pub use decompiler::{
    Decompiler, StringTable, SymbolTable, RelocationTable,
    CallingConvention, FunctionSignature, Parameter, ParameterLocation, ParamType, SignatureRecovery,
};
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
pub use vtable::{
    Vtable, VtableConfig, VtableDatabase, VtableDetector, VtableEntry, VirtualCallSite,
};
pub use stack_canary::{
    CanarySource, SegmentRegister, StackCanaryAnalysis, StackCanaryDetector, StackCanaryInfo,
};
pub use project::{
    AnalysisProject, Annotation, AnnotationKind, Bookmark, FunctionOverride,
    ProjectError, ProjectResult, ProjectStats, SignatureOverride, TypeOverride,
};
