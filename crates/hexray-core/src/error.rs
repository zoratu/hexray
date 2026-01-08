//! Error types for hexray-core.

use thiserror::Error;

/// Core error type.
#[derive(Error, Debug)]
pub enum Error {
    /// Invalid basic block reference.
    #[error("invalid basic block id: {0:?}")]
    InvalidBlockId(crate::BasicBlockId),

    /// Address not found in any block.
    #[error("address {0:#x} not found in CFG")]
    AddressNotFound(u64),
}
