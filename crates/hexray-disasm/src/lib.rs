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
// Adversarial-input hardening — DOCUMENTED, NOT YET ENFORCED.
// See `hexray-formats/src/lib.rs` for the full rationale. Decoders
// walk attacker-shaped instruction streams; panics here are DoS
// surface. The bulk-refactor migration is pending; until then PR
// review and `scripts/run-fuzz-corpus` are the enforcement layer.
// `unwrap_used` and `expect_used` are now ENFORCED — no remaining
// call sites in this crate. New code must propagate errors.
#![deny(clippy::unwrap_used, clippy::expect_used)]
// Test code is the conventional place for `unwrap()` / `expect()` —
// the lints would fire at every assertion-style helper otherwise.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
// `indexing_slicing`, `arithmetic_side_effects`, `panic` still
// allowed: thousands of pre-existing call sites in instruction
// decoders / format-header parsers do bit math and direct slice
// indexing where bounds are checked once at the top of the parse.
// Refactoring all of them is its own multi-day project; the
// runtime fuzz gate (`scripts/run-fuzz-corpus`) catches regressions
// in the interim, and reviewers should still steer new parsing
// paths toward `.get()` / `checked_*`.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

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
