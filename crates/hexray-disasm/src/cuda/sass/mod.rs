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

// File-level allow: bit-math + slice indexing in this parser/decoder
// is bounds-checked at function entry. Per-site annotations would be
// noise; the runtime fuzz gate (`scripts/run-fuzz-corpus`) catches
// actual crashes. New code should prefer `.get()` + `checked_*`.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

pub mod bits;
pub mod control;
pub mod opcode_table;
pub mod registers;

pub use bits::SassWord;
pub use control::ControlBits;
pub use opcode_table::{lookup as lookup_opcode, OpcodeEntry};

use crate::{DecodeError, DecodedInstruction, Disassembler};
use hexray_core::{
    Architecture, ControlFlow, CudaArchitecture, Instruction, Operand, Operation, PredicateGuard,
    SmArchitecture, SmFamily,
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

        let _control = ControlBits::from_word(&word);
        let op_class = word.bit_range(0, 8) as u16;

        let entry = lookup_opcode(op_class)
            .ok_or_else(|| DecodeError::unknown_opcode(address, &word.to_bytes()))?;

        let mnemonic = entry.render_mnemonic(&word);
        let mut instr = Instruction::new(
            address,
            SASS_INSTRUCTION_SIZE,
            word.to_bytes().to_vec(),
            mnemonic,
        );
        instr.operation = entry.operation;
        instr.guard = decode_predicate_guard(&word, self.sm);
        instr.control_flow = derive_control_flow(entry, &word, address);
        populate_basic_operands(&mut instr, &word, self.sm);

        Ok(DecodedInstruction {
            instruction: instr,
            size: SASS_INSTRUCTION_SIZE,
        })
    }
}

/// Decode the 4-bit predicate-guard field in bits `[12..=15]`.
///
/// The low 3 bits select `P0..P6` (or `P7 = PT`); the high bit inverts.
/// A value of `0b0111 = PT` means "no guard" — we return `None` so that
/// `nvdisasm`-style output doesn't print `@PT` noise everywhere.
fn decode_predicate_guard(word: &SassWord, sm: SmArchitecture) -> Option<PredicateGuard> {
    let field = word.bit_range(12, 15) as u8;
    let idx = field & 0x7;
    let invert = (field & 0x8) != 0;
    if idx == registers::id::PT as u8 && !invert {
        return None;
    }
    let reg = registers::p(sm, idx as u16);
    Some(if invert {
        PredicateGuard::negated(reg)
    } else {
        PredicateGuard::positive(reg)
    })
}

/// Emit a minimal operand list so CPU-style callers that just want
/// "does this instruction touch R6" get something useful. We surface:
///
/// - the destination register from bits `[16..=23]` (common slot),
/// - the first source register from bits `[24..=31]` where present.
///
/// Values equal to `255` render as `RZ` (the zero register) via the
/// register module's canonical name logic.
///
/// This is deliberately conservative for M4. M7 will replace this with
/// per-opcode field tables so memory references, const-bank references,
/// and immediate values land correctly.
fn populate_basic_operands(instr: &mut Instruction, word: &SassWord, sm: SmArchitecture) {
    let op_class = instr
        .bytes
        .first()
        .copied()
        .map(|b| (b as u16) & 0xFF)
        .unwrap_or(0)
        | ((instr.bytes.get(1).copied().unwrap_or(0) as u16) & 0x1) << 8;
    let _ = op_class;

    let rd = word.bit_range(16, 23) as u16;
    let ra = word.bit_range(24, 31) as u16;

    // Destination: applies to most ALU / load / MOV / S2R opcodes.
    if needs_destination(instr) {
        instr.operands.push(Operand::reg(registers::r(sm, rd)));
        instr.writes.push(registers::r(sm, rd));
    }
    // Source register A: applies whenever bits [24..=31] are meaningful.
    if needs_source_a(instr) {
        instr.operands.push(Operand::reg(registers::r(sm, ra)));
        instr.reads.push(registers::r(sm, ra));
    }
}

/// Does this opcode class write to the register nibble at bits 16..23?
fn needs_destination(instr: &Instruction) -> bool {
    matches!(
        instr.operation,
        Operation::Add | Operation::Mul | Operation::Move | Operation::Load | Operation::Compare
    )
}

/// Does this opcode class treat bits 24..31 as a source register?
fn needs_source_a(instr: &Instruction) -> bool {
    matches!(
        instr.operation,
        Operation::Add | Operation::Mul | Operation::Compare | Operation::Store | Operation::Load
    )
}

/// Derive a conservative [`ControlFlow`] label from the opcode entry.
///
/// Branch targets are in a signed PC-relative field for `BRA`; M4 emits
/// `UnconditionalBranch { target: address }` as a placeholder (no
/// resolve of the offset yet — M7 handles it) so the CFG builder at
/// least sees a non-sequential instruction.
fn derive_control_flow(entry: &OpcodeEntry, _word: &SassWord, address: u64) -> ControlFlow {
    match entry.mnemonic {
        "EXIT" => ControlFlow::Return,
        "BRA" => ControlFlow::UnconditionalBranch { target: address },
        "BSYNC" | "BSSY" => ControlFlow::Sequential,
        "BAR" => ControlFlow::Sequential,
        _ => ControlFlow::Sequential,
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

#[cfg(test)]
mod tests;
