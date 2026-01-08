//! Disassembly error types.

use thiserror::Error;

/// Error type for instruction decoding.
#[derive(Error, Debug)]
pub enum DecodeError {
    /// Unknown opcode encountered.
    #[error("unknown opcode at {address:#x}: {bytes:02x?}")]
    UnknownOpcode { address: u64, bytes: Vec<u8> },

    /// Instruction was truncated (not enough bytes).
    #[error("truncated instruction at {address:#x}: need {needed} bytes, have {available}")]
    Truncated {
        address: u64,
        needed: usize,
        available: usize,
    },

    /// Invalid instruction encoding.
    #[error("invalid encoding at {address:#x}: {reason}")]
    InvalidEncoding { address: u64, reason: String },

    /// Unsupported instruction or feature.
    #[error("unsupported instruction at {address:#x}: {reason}")]
    Unsupported { address: u64, reason: String },
}

impl DecodeError {
    /// Creates a new UnknownOpcode error.
    pub fn unknown_opcode(address: u64, bytes: &[u8]) -> Self {
        Self::UnknownOpcode {
            address,
            bytes: bytes.to_vec(),
        }
    }

    /// Creates a new Truncated error.
    pub fn truncated(address: u64, needed: usize, available: usize) -> Self {
        Self::Truncated {
            address,
            needed,
            available,
        }
    }

    /// Creates a new InvalidEncoding error.
    pub fn invalid_encoding(address: u64, reason: impl Into<String>) -> Self {
        Self::InvalidEncoding {
            address,
            reason: reason.into(),
        }
    }

    /// Creates a new Unsupported error.
    pub fn unsupported(address: u64, reason: impl Into<String>) -> Self {
        Self::Unsupported {
            address,
            reason: reason.into(),
        }
    }
}
