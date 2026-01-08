//! Disassembler traits.

use crate::DecodeError;
use hexray_core::{Architecture, Instruction};

/// Result of decoding an instruction.
#[derive(Debug, Clone)]
pub struct DecodedInstruction {
    /// The decoded instruction.
    pub instruction: Instruction,
    /// Number of bytes consumed.
    pub size: usize,
}

/// Trait for architecture-specific instruction decoders.
pub trait Disassembler {
    /// Decode a single instruction starting at the given address.
    ///
    /// # Arguments
    /// * `bytes` - The raw bytes to decode
    /// * `address` - The virtual address of the first byte
    ///
    /// # Returns
    /// The decoded instruction and the number of bytes consumed.
    fn decode_instruction(&self, bytes: &[u8], address: u64) -> Result<DecodedInstruction, DecodeError>;

    /// Returns the minimum instruction size for this architecture.
    fn min_instruction_size(&self) -> usize;

    /// Returns the maximum instruction size for this architecture.
    fn max_instruction_size(&self) -> usize;

    /// Returns whether instructions are fixed-width.
    fn is_fixed_width(&self) -> bool;

    /// Returns the target architecture.
    fn architecture(&self) -> Architecture;

    /// Disassemble a block of code into instructions.
    fn disassemble_block(&self, bytes: &[u8], start_address: u64) -> Vec<Result<Instruction, DecodeError>> {
        let mut instructions = Vec::new();
        let mut offset = 0;

        while offset < bytes.len() {
            let remaining = &bytes[offset..];
            let address = start_address + offset as u64;

            match self.decode_instruction(remaining, address) {
                Ok(decoded) => {
                    offset += decoded.size;
                    instructions.push(Ok(decoded.instruction));
                }
                Err(e) => {
                    // On error, skip one byte and continue
                    offset += 1;
                    instructions.push(Err(e));
                }
            }
        }

        instructions
    }
}
