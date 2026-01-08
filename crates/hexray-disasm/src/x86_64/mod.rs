//! x86_64 instruction decoder.
//!
//! This module implements a from-scratch x86_64 disassembler for educational purposes.
//! It handles:
//! - Legacy prefixes (REP, LOCK, segment overrides, operand/address size)
//! - REX prefix for 64-bit operands and extended registers
//! - ModR/M and SIB byte decoding
//! - Common instruction families

mod decoder;
mod modrm;
mod opcodes;
mod prefix;

pub use decoder::X86_64Disassembler;
