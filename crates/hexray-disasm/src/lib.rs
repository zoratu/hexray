//! # hexray-disasm
//!
//! Architecture-specific instruction decoders for hexray.
//!
//! This crate provides disassembly backends for:
//! - x86_64 (AMD64)
//! - ARM64 (AArch64)
//! - RISC-V (RV64I/RV32I)
//! - CUDA SASS (Volta+, feature-gated, in-progress)

#![forbid(unsafe_code)]

pub mod error;
pub mod traits;

#[cfg(feature = "x86_64")]
pub mod x86_64;

#[cfg(feature = "arm64")]
pub mod arm64;

#[cfg(feature = "riscv")]
pub mod riscv;

#[cfg(feature = "cuda")]
pub mod cuda;

pub use error::DecodeError;
pub use traits::{DecodedInstruction, Disassembler};

#[cfg(feature = "x86_64")]
pub use x86_64::X86_64Disassembler;

#[cfg(feature = "arm64")]
pub use arm64::Arm64Disassembler;

#[cfg(feature = "riscv")]
pub use riscv::RiscVDisassembler;

#[cfg(feature = "cuda")]
pub use cuda::SassDisassembler;
