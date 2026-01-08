//! RISC-V instruction decoder.
//!
//! Supports the RV64I/RV32I base integer instruction sets with extensions:
//! - RV64I: Base 64-bit integer instructions
//! - RV32I: Base 32-bit integer instructions
//! - M extension: Multiply/Divide
//! - A extension: Atomics (LR/SC, AMO operations)
//! - C extension: Compressed 16-bit instructions
//!
//! RISC-V uses a clean, regular encoding with 32-bit standard instructions
//! and 16-bit compressed instructions (C extension).

mod decoder;

pub use decoder::RiscVDisassembler;
