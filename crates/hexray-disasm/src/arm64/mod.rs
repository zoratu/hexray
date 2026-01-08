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

mod decoder;

pub use decoder::Arm64Disassembler;
