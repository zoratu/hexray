//! ARM64 (AArch64) instruction decoder.
//!
//! ARM64 uses fixed 32-bit instructions with a regular encoding scheme.
//! This module decodes common instructions including:
//! - Data processing (ADD, SUB, AND, ORR, etc.)
//! - Branches (B, BL, B.cond, CBZ, CBNZ, TBZ, TBNZ, RET)
//! - Load/Store (LDR, STR, LDP, STP)
//! - Move instructions (MOV, MOVZ, MOVK, MOVN)
//! - Compare (CMP, CMN, TST)
//! - System instructions (NOP, SVC, BRK)
//! - SVE (Scalable Vector Extension) instructions
//! - SVE2 (SVE version 2) instructions including crypto extensions
//! - SME (Scalable Matrix Extension) instructions

mod decoder;
mod sme;
mod sve;

pub use decoder::Arm64Disassembler;
pub use sme::SmeDecoder;
pub use sve::SveDecoder;
