//! NVIDIA SASS disassembler for Volta and newer (16-byte fixed width).
//!
//! M3 ships the *skeleton* only: a [`Disassembler`] impl that walks
//! code in lockstep 16-byte strides (never desyncing into a misaligned
//! state, which the default trait `disassemble_block` would do), plus the
//! control-field extractor and a single canonical opcode — `NOP` — that
//! proves the plumbing end-to-end. Core arithmetic / memory opcodes land
//! in M4.
//!
//! The decoder is band-scoped: one instance targets exactly one SM, and
//! refuses to decode for another via [`DecodeError::Unsupported`]. This
//! keeps the opcode-table strategy honest — each SM generation gets its
//! own decoder state rather than a Frankenstein table.

pub mod bits;
pub mod control;
pub mod registers;

pub use bits::SassWord;
pub use control::ControlBits;

use crate::{DecodeError, DecodedInstruction, Disassembler};
use hexray_core::{
    Architecture, ControlFlow, CudaArchitecture, Instruction, Operation, SmArchitecture, SmFamily,
};

/// Instruction width on Volta and newer. Fixed, always 16 bytes.
pub const SASS_INSTRUCTION_SIZE: usize = 16;

/// NVIDIA SASS disassembler (Volta+).
///
/// Construct with [`SassDisassembler::for_sm`] to target a specific
/// compute capability, or [`SassDisassembler::ampere`] / [`::ada`] /
/// [`::hopper`] for the common modern bands.
#[derive(Debug, Clone, Copy)]
pub struct SassDisassembler {
    sm: SmArchitecture,
}

impl SassDisassembler {
    /// Build a decoder targeting `sm`. The SM's family must be
    /// Volta-or-newer; older SMs use a different (8-byte) encoding not
    /// covered by this decoder.
    pub fn for_sm(sm: SmArchitecture) -> Self {
        Self { sm }
    }

    /// Convenience: `sm_80` Ampere.
    pub fn ampere() -> Self {
        Self::for_sm(SmArchitecture::new(8, 0, hexray_core::SmVariant::Base))
    }

    /// Convenience: `sm_89` Ada Lovelace.
    pub fn ada() -> Self {
        Self::for_sm(SmArchitecture::new(8, 9, hexray_core::SmVariant::Base))
    }

    /// Convenience: `sm_90` Hopper (base target, no `a` accelerator
    /// features).
    pub fn hopper() -> Self {
        Self::for_sm(SmArchitecture::new(9, 0, hexray_core::SmVariant::Base))
    }

    /// Target SM this decoder was built for.
    pub fn sm(&self) -> SmArchitecture {
        self.sm
    }

    /// True if the target SM uses the 128-bit encoding this decoder
    /// understands. Volta and newer do; Maxwell/Pascal use the older
    /// 64-bit encoding and will be a separate decoder if we ever add
    /// support.
    pub fn is_volta_or_newer(&self) -> bool {
        matches!(
            self.sm.family,
            SmFamily::Volta
                | SmFamily::Turing
                | SmFamily::Ampere
                | SmFamily::Ada
                | SmFamily::Hopper
                | SmFamily::Blackwell
        )
    }

    /// Low-level decode entry point that takes an already-assembled
    /// [`SassWord`]. Exposed for tests that want to build synthetic
    /// encodings without round-tripping through bytes.
    pub fn decode_word(
        &self,
        word: SassWord,
        address: u64,
    ) -> Result<DecodedInstruction, DecodeError> {
        if !self.is_volta_or_newer() {
            return Err(DecodeError::unsupported(
                address,
                format!(
                    "SASS decoder for {} not implemented (pre-Volta 64-bit encoding)",
                    self.sm.canonical_name()
                ),
            ));
        }

        let control = ControlBits::from_word(&word);
        let opcode = word.bit_range(0, 15);

        let (mnemonic, operation) = classify_opcode(opcode)
            .ok_or_else(|| DecodeError::unknown_opcode(address, &word.to_bytes()))?;

        let mut instr = Instruction::new(
            address,
            SASS_INSTRUCTION_SIZE,
            word.to_bytes().to_vec(),
            mnemonic,
        );
        instr.operation = operation;
        instr.control_flow = match operation {
            Operation::Return => ControlFlow::Return,
            _ => ControlFlow::Sequential,
        };

        // Stash the control bits in the encoded instruction bytes — M4 /
        // M7 will add a typed arch-specific metadata slot. For now the
        // raw bytes preserve everything losslessly.
        let _ = control;

        Ok(DecodedInstruction {
            instruction: instr,
            size: SASS_INSTRUCTION_SIZE,
        })
    }
}

impl Disassembler for SassDisassembler {
    fn decode_instruction(
        &self,
        bytes: &[u8],
        address: u64,
    ) -> Result<DecodedInstruction, DecodeError> {
        if bytes.len() < SASS_INSTRUCTION_SIZE {
            return Err(DecodeError::truncated(
                address,
                SASS_INSTRUCTION_SIZE,
                bytes.len(),
            ));
        }
        let word = SassWord::from_bytes(&bytes[..SASS_INSTRUCTION_SIZE]);
        self.decode_word(word, address)
    }

    fn min_instruction_size(&self) -> usize {
        SASS_INSTRUCTION_SIZE
    }

    fn max_instruction_size(&self) -> usize {
        SASS_INSTRUCTION_SIZE
    }

    fn is_fixed_width(&self) -> bool {
        true
    }

    fn architecture(&self) -> Architecture {
        Architecture::Cuda(CudaArchitecture::Sass(self.sm))
    }

    /// Override the default walker so a decode failure never desyncs a
    /// fixed-width stream. The default advances one byte on error, which
    /// is catastrophic for SASS (16-byte aligned); we step 16 bytes no
    /// matter what happens to any single instruction.
    fn disassemble_block(
        &self,
        bytes: &[u8],
        start_address: u64,
    ) -> Vec<Result<Instruction, DecodeError>> {
        let mut out =
            Vec::with_capacity((bytes.len() + SASS_INSTRUCTION_SIZE - 1) / SASS_INSTRUCTION_SIZE);
        let mut offset = 0usize;
        while offset < bytes.len() {
            let address = start_address + offset as u64;
            let remaining = &bytes[offset..];
            if remaining.len() < SASS_INSTRUCTION_SIZE {
                out.push(Err(DecodeError::truncated(
                    address,
                    SASS_INSTRUCTION_SIZE,
                    remaining.len(),
                )));
                break;
            }
            let slot = &remaining[..SASS_INSTRUCTION_SIZE];
            out.push(
                self.decode_instruction(slot, address)
                    .map(|d| d.instruction),
            );
            offset += SASS_INSTRUCTION_SIZE;
        }
        out
    }
}

/// Maps the low 16 opcode bits to a (mnemonic, core [`Operation`])
/// pair. M3 covers only `NOP`; everything else is `UnknownOpcode` so the
/// block walker can continue past decode failures instead of desyncing.
fn classify_opcode(opcode_low16: u64) -> Option<(&'static str, Operation)> {
    match opcode_low16 {
        // `NOP` on Volta+ is encoded as opcode 0x7918 in the low bits —
        // the same literal is embedded in every Ampere/Ada/Hopper NOP we
        // have seen in public corpora. This is the one golden M3 needs.
        0x7918 => Some(("NOP", Operation::Nop)),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
