//! # hexray-core
//!
//! Core abstractions for the hexray disassembler. This crate defines
//! architecture-agnostic types for instructions, operands, registers,
//! basic blocks, and control flow graphs.

pub mod arch;
pub mod basic_block;
pub mod cfg;
pub mod error;
pub mod instruction;
pub mod operand;
pub mod output;
pub mod register;
pub mod symbol;

pub use arch::{Architecture, Bitness, Endianness};
pub use basic_block::{BasicBlock, BasicBlockId, BlockTerminator};
pub use cfg::ControlFlowGraph;
pub use error::Error;
pub use instruction::{Condition, ControlFlow, Instruction, Operation};
pub use operand::{Immediate, IndexMode, MemoryRef, Operand};
pub use output::{escape_dot_string, DotConfig};
pub use register::{Register, RegisterClass};
pub use symbol::{Symbol, SymbolBinding, SymbolKind};
