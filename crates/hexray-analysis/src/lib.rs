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

pub mod cfg_builder;
pub mod dataflow;
pub mod decompiler;
pub mod function_finder;
pub mod ssa;
pub mod types;

pub use cfg_builder::CfgBuilder;
pub use dataflow::{DefUseChain, LivenessAnalysis, ReachingDefinitions, Location};
pub use decompiler::{Decompiler, StringTable, SymbolTable, RelocationTable};
pub use function_finder::FunctionFinder;
pub use ssa::{SsaBuilder, SsaFunction, SsaValue, PhiNode};
pub use types::{Type, TypeInference, FunctionSignatures};
