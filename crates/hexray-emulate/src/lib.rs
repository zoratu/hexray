//! # hexray-emulate
//!
//! Static emulation and symbolic execution for hexray disassembler.
//!
//! This crate provides:
//! - Concrete execution of instructions without running the binary
//! - Symbolic execution for constraint solving
//! - Indirect call/jump resolution (jump tables, vtables)
//! - Value tracking through execution paths
//!
//! # Example
//!
//! ```ignore
//! use hexray_emulate::{Emulator, EmulatorConfig};
//! use hexray_core::Instruction;
//!
//! // Create an emulator
//! let mut emu = Emulator::new(EmulatorConfig::default());
//!
//! // Set initial state
//! emu.set_register(0, 0x1000);  // rax = 0x1000
//!
//! // Execute instructions
//! for inst in instructions {
//!     emu.execute(&inst)?;
//! }
//!
//! // Get final state
//! let rax = emu.get_register(0);
//! ```

pub mod value;
pub mod memory;
pub mod flags;
pub mod state;
pub mod executor;
pub mod x86_64;
pub mod simulation;

pub use value::{Value, SymbolicId};
pub use memory::SparseMemory;
pub use flags::Flags;
pub use state::MachineState;
pub use executor::{Emulator, EmulatorConfig, ExecutionResult, StopReason};
pub use simulation::{
    ExecutionTrace, FaultKind, Simulation, SimulationComparison, SimulationConfig,
    SimulationSnapshot, TraceStep, compare_simulations,
};

use thiserror::Error;

/// Errors that can occur during emulation.
#[derive(Debug, Error)]
pub enum EmulationError {
    #[error("Unsupported instruction: {0}")]
    UnsupportedInstruction(String),

    #[error("Invalid memory access at {address:#x}")]
    InvalidMemoryAccess { address: u64 },

    #[error("Division by zero")]
    DivisionByZero,

    #[error("Stack overflow")]
    StackOverflow,

    #[error("Stack underflow")]
    StackUnderflow,

    #[error("Maximum instruction count exceeded: {0}")]
    MaxInstructionsExceeded(usize),

    #[error("Unresolved symbolic value")]
    UnresolvedSymbolic,

    #[error("Invalid operand: {0}")]
    InvalidOperand(String),
}

/// Result type for emulation operations.
pub type EmulationResult<T> = Result<T, EmulationError>;

/// Information about a resolved indirect target.
#[derive(Debug, Clone)]
pub struct IndirectTarget {
    /// Address of the indirect call/jump instruction.
    pub instruction_address: u64,
    /// Resolved target addresses.
    pub targets: Vec<u64>,
    /// Confidence level (0.0 - 1.0).
    pub confidence: f64,
    /// How the target was resolved.
    pub resolution_method: ResolutionMethod,
}

/// Method used to resolve an indirect target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionMethod {
    /// Direct concrete execution.
    ConcreteExecution,
    /// Jump table detection.
    JumpTable,
    /// Virtual function table.
    VTable,
    /// Symbolic execution with constraint solving.
    SymbolicExecution,
}
