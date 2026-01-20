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
pub mod cpp_special;
pub mod dataflow;
pub mod decompiler;
pub mod function_finder;
pub mod indirect_calls;
pub mod output;
pub mod parallel;
pub mod project;
pub mod rtti;
pub mod ssa;
pub mod stack_canary;
pub mod strings;
pub mod types;
pub mod vtable;
pub mod xrefs;

pub use indirect_calls::{
    CallTarget, Confidence, GotEntry, GotEntryBuilder, IndirectCallInfo, IndirectCallResolver,
    ResolutionMethod, ResolutionStats,
};
pub use strings::{
    DetectedString, DetectedStringTable, StringConfig, StringDetector, StringEncoding,
};
pub use xrefs::{Xref, XrefBuilder, XrefDatabase, XrefType};

pub use callgraph::{CallGraph, CallGraphBuilder, CallGraphNode, CallSite, CallType};
pub use cfg_builder::CfgBuilder;
pub use cpp_special::{
    BaseCall, CppSpecialDatabase, CppSpecialDetector, SpecialMemberAnalysis, SpecialMemberKind,
    VtableAssignment,
};
pub use dataflow::{
    ConstState, ConstValue, ConstantPropagation, DataFlowQuery, DataFlowQueryEngine,
    DataFlowResult, DataFlowRole, DataFlowStep, DefUseChain, LivenessAnalysis, Location,
    ReachingDefinitions,
};
pub use decompiler::{
    CallingConvention, CatchInfo, CleanupInfo, Decompiler, ExceptionInfo, FunctionSignature,
    ParamType, Parameter, ParameterLocation, RelocationTable, SignatureRecovery, StringTable,
    SymbolTable, TryBlockInfo,
};
pub use function_finder::FunctionFinder;
pub use output::{
    CallGraphDotExporter, CallGraphHtmlExporter, CallGraphJsonExporter, CfgDotExporter,
    CfgHtmlExporter, CfgJsonExporter,
};
pub use parallel::{
    disassemble_functions_parallel, DisassembledFunction, FunctionInfo, ParallelCallGraphBuilder,
};
pub use project::{
    AnalysisProject, Annotation, AnnotationKind, Bookmark, FunctionOverride, ProjectError,
    ProjectResult, ProjectStats, SignatureOverride, TypeOverride,
};
pub use rtti::{
    BaseClassFlags, BaseClassInfo, ClassHierarchy, RttiDatabase, RttiParser, TypeInfo,
    TypeInfoKind, TypeInfoVtableKind, VmiFlags,
};
pub use ssa::{OptimizationStats, PhiNode, SsaBuilder, SsaFunction, SsaOptimizer, SsaValue};
pub use stack_canary::{
    CanarySource, SegmentRegister, StackCanaryAnalysis, StackCanaryDetector, StackCanaryInfo,
};
pub use types::{Constraint, FunctionSignatures, Type, TypeInference};
pub use vtable::{
    VirtualCallSite, Vtable, VtableConfig, VtableDatabase, VtableDetector, VtableEntry,
};
