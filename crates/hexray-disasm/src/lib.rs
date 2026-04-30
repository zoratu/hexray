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
// Adversarial-input hardening — see `hexray-formats/src/lib.rs` for
// the full rationale. Decoders walk attacker-shaped instruction
// streams; panic / index-out-of-bounds / overflow on attacker
// input is a DoS surface even with Rust's memory safety.
//
// `unwrap_used` and `expect_used` are enforced (no remaining call
// sites). New code must propagate errors.
#![deny(clippy::unwrap_used, clippy::expect_used)]
// `indexing_slicing` and `arithmetic_side_effects` are denied at
// the crate root. Files with bounds-checked-at-entry decoders
// carry a file-level `#![allow]` with the `// File-level allow:`
// audit comment. New files must either use `.get()` + `checked_*`
// from the start, or copy that file-level allow + audit pattern.
// `panic` stays allowed (Vec::push etc. are not adversarial vectors).
#![deny(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
// Test code is the conventional place for `unwrap()` / `expect()`
// and direct indexing of fixed-size buffers.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
    )
)]
#![allow(clippy::panic)]

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

#[cfg(feature = "amdgpu")]
pub mod amdgpu;

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

#[cfg(feature = "amdgpu")]
pub use amdgpu::AmdgpuDisassembler;
