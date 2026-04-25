//! AMDGPU disassembler (GCN, CDNA, RDNA — variable-length encoding).
//!
//! Unlike SASS's fixed 16-byte word, AMDGPU instructions are 32 bits
//! or 64 bits, distinguished by a few high bits of the first dword.
//! The decoder walks the buffer in lockstep dword strides, classifies
//! the first dword's encoding family, and either consumes a second
//! dword (VOP3, SMEM, MUBUF, etc.) or emits the single-dword form.
//!
//! M10.3 is the *skeleton*: instruction-class dispatch, the
//! variable-length walker, and a single VOP1 mnemonic (`v_mov_b32`)
//! to prove the plumbing end-to-end. M10.4 fills the opcode tables
//! out across the SOP*, VOP1/2/3, VOPC, SMEM, MUBUF, DS, FLAT,
//! EXP, and POP families.
//!
//! The decoder is family-aware: a [`AmdgpuDisassembler`] targets
//! either the GFX9 (GCN5/CDNA1/2/3) or GFX10+ (RDNA1+) prefix layout.
//! Encoding-class prefixes shift between the two — most notably
//! VOP3A/B (`110100` → `110101`), SMEM (`110000` → `111101`), and EXP
//! (`110001` → `111110`).

pub mod encoding;
pub mod opcodes;
pub mod registers;

#[cfg(test)]
mod tests;

pub use encoding::{decode_class, EncodingClass, EncodingFamily};
pub use opcodes::{lookup as lookup_opcode, OpcodeEntry, TableClass};

use crate::{DecodeError, DecodedInstruction, Disassembler};
use hexray_core::{Architecture, ControlFlow, GfxArchitecture, GfxFamily, Instruction, Operation};

/// AMDGPU disassembler targeting one GFX family band (GFX9 vs GFX10+).
///
/// Construct with [`AmdgpuDisassembler::for_target`] to bind a
/// specific GFX target, or [`AmdgpuDisassembler::gfx906`] /
/// [`::gfx1030`] / [`::gfx1100`] convenience constructors.
#[derive(Debug, Clone, Copy)]
pub struct AmdgpuDisassembler {
    target: GfxArchitecture,
    family_band: EncodingFamily,
}

impl AmdgpuDisassembler {
    /// Build a decoder for the given target.
    pub fn for_target(target: GfxArchitecture) -> Self {
        let family_band = encoding_family_for(target.family);
        Self {
            target,
            family_band,
        }
    }

    /// Convenience: gfx906 (GCN5 Vega20).
    pub fn gfx906() -> Self {
        Self::for_target(GfxArchitecture::new(9, 0, 6))
    }

    /// Convenience: gfx1030 (RDNA2 Navi 21).
    pub fn gfx1030() -> Self {
        Self::for_target(GfxArchitecture::new(10, 3, 0))
    }

    /// Convenience: gfx1100 (RDNA3 Navi 31).
    pub fn gfx1100() -> Self {
        Self::for_target(GfxArchitecture::new(11, 0, 0))
    }

    /// Target this decoder was built for.
    pub fn target(&self) -> GfxArchitecture {
        self.target
    }

    /// The encoding family band — picks GFX9 vs GFX10+ encoding class
    /// prefixes.
    pub fn encoding_family(&self) -> EncodingFamily {
        self.family_band
    }
}

/// Map a `GfxFamily` to the encoding-prefix family band it follows.
fn encoding_family_for(family: GfxFamily) -> EncodingFamily {
    match family {
        GfxFamily::Gcn3
        | GfxFamily::Gcn4
        | GfxFamily::Gcn5
        | GfxFamily::Cdna1
        | GfxFamily::Cdna2
        | GfxFamily::Cdna3 => EncodingFamily::Gfx9,
        GfxFamily::Rdna1 | GfxFamily::Rdna2 | GfxFamily::Rdna3 | GfxFamily::Rdna4 => {
            EncodingFamily::Gfx10Plus
        }
        // Default to Gfx9 for unknown — pre-RDNA hardware is the
        // older / more conservative target band.
        GfxFamily::Unknown => EncodingFamily::Gfx9,
    }
}

impl Disassembler for AmdgpuDisassembler {
    fn decode_instruction(
        &self,
        bytes: &[u8],
        address: u64,
    ) -> Result<DecodedInstruction, DecodeError> {
        if bytes.len() < 4 {
            return Err(DecodeError::truncated(address, 4, bytes.len()));
        }
        let dword0 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let class = decode_class(dword0, self.family_band);

        let size = class.encoding_size();
        if bytes.len() < size {
            return Err(DecodeError::truncated(address, size, bytes.len()));
        }
        let dword1 = if size == 8 {
            Some(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]))
        } else {
            None
        };

        let mnemonic = render_mnemonic(class, dword0, dword1, self.family_band);
        let operation = derive_operation(class, dword0, self.family_band);
        let control_flow = derive_control_flow(class, dword0);
        let raw = bytes[..size].to_vec();
        let mut instr = Instruction::new(address, size, raw, mnemonic);
        instr.operation = operation;
        instr.control_flow = control_flow;

        Ok(DecodedInstruction {
            instruction: instr,
            size,
        })
    }

    fn min_instruction_size(&self) -> usize {
        4
    }

    fn max_instruction_size(&self) -> usize {
        8
    }

    fn is_fixed_width(&self) -> bool {
        false
    }

    fn architecture(&self) -> Architecture {
        Architecture::Amdgpu(self.target)
    }

    /// Override the default walker to handle variable-length encoding
    /// without desyncing.
    ///
    /// The default `disassemble_block` advances one byte on a decode
    /// error. AMDGPU instructions are dword-aligned (4-byte boundary)
    /// and either 32 or 64 bits, so a one-byte step would walk into
    /// the middle of a valid encoding. We always advance by the
    /// classified size (4 or 8 bytes); on a hard decode failure we
    /// step a conservative 4 bytes to find the next aligned boundary.
    fn disassemble_block(
        &self,
        bytes: &[u8],
        start_address: u64,
    ) -> Vec<Result<Instruction, DecodeError>> {
        let mut out = Vec::with_capacity(bytes.len() / 4);
        let mut offset = 0usize;
        while offset + 4 <= bytes.len() {
            let address = start_address + offset as u64;
            let remaining = &bytes[offset..];
            match self.decode_instruction(remaining, address) {
                Ok(d) => {
                    let size = d.size;
                    out.push(Ok(d.instruction));
                    offset += size;
                }
                Err(e) => {
                    out.push(Err(e));
                    offset += 4;
                }
            }
        }
        if offset < bytes.len() {
            // A trailing fragment shorter than 4 bytes: surface a
            // truncation error so the caller knows the stream
            // didn't end on a dword boundary.
            out.push(Err(DecodeError::truncated(
                start_address + offset as u64,
                4,
                bytes.len() - offset,
            )));
        }
        out
    }
}

/// Render the mnemonic for a decoded instruction by consulting the
/// per-class, per-family opcode table. Falls back to
/// `<class>.op<id>` for OPs not yet in the table — the walker keeps
/// running and the differential gate (M10.5) can quantify the gap.
fn render_mnemonic(
    class: EncodingClass,
    dword0: u32,
    _dword1: Option<u32>,
    family: EncodingFamily,
) -> String {
    let (table_class, op) = match class {
        // VOP1 layout (per LLVM SIInstrFormats.td):
        //   [8:0]   SRC0
        //   [16:9]  OP
        //   [24:17] VDST
        //   [31:25] encoding (0b0111111)
        EncodingClass::Vop1 => (
            Some(opcodes::TableClass::Vop1),
            ((dword0 >> 9) & 0xff) as u16,
        ),
        // VOP2 layout: [30:25] OP (6 bits), [16:9] VDST, [8:0] SRC0,
        // [24:17] VSRC1.
        EncodingClass::Vop2 => (
            Some(opcodes::TableClass::Vop2),
            ((dword0 >> 25) & 0x3f) as u16,
        ),
        // VOPC layout: [24:17] OP, [16:9] VSRC1, [8:0] SRC0.
        EncodingClass::Vopc => (
            Some(opcodes::TableClass::Vopc),
            ((dword0 >> 17) & 0xff) as u16,
        ),
        // SOP1 layout: [22:16] is special (sub-encoding marker), OP
        // is at [15:8]. SDST at [22:16].
        EncodingClass::Sop1 => (
            Some(opcodes::TableClass::Sop1),
            ((dword0 >> 8) & 0xff) as u16,
        ),
        // SOP2 layout: [29:23] OP, [22:16] SDST, [15:8] SSRC1, [7:0]
        // SSRC0.
        EncodingClass::Sop2 => (
            Some(opcodes::TableClass::Sop2),
            ((dword0 >> 23) & 0x7f) as u16,
        ),
        // SOPP layout: [22:16] OP (7 bits), [15:0] SIMM16.
        EncodingClass::Sopp => (
            Some(opcodes::TableClass::Sopp),
            ((dword0 >> 16) & 0x7f) as u16,
        ),
        // SMEM layout: [25:18] OP (8 bits) on GFX10+; GFX9 has OP at
        // [25:18] as well (verified against codex llvm-mc samples).
        EncodingClass::Smem => (
            Some(opcodes::TableClass::Smem),
            ((dword0 >> 18) & 0xff) as u16,
        ),
        _ => (None, 0),
    };

    if let Some(tc) = table_class {
        if let Some(entry) = opcodes::lookup(tc, family, op) {
            return entry.mnemonic.to_string();
        }
        return format!("{}.op{op:#x}", class.short_name());
    }
    class.short_name().to_string()
}

/// Map an encoding class + opcode to a high-level operation. Consults
/// the opcode table for known OPs (so `s_endpgm` becomes `Return`,
/// `s_branch` becomes `Jump`, etc.); falls back to a class-level
/// default for OPs not in the table.
fn derive_operation(class: EncodingClass, dword0: u32, family: EncodingFamily) -> Operation {
    let (table_class, op) = match class {
        EncodingClass::Vop1 => (
            Some(opcodes::TableClass::Vop1),
            ((dword0 >> 9) & 0xff) as u16,
        ),
        EncodingClass::Vop2 => (
            Some(opcodes::TableClass::Vop2),
            ((dword0 >> 25) & 0x3f) as u16,
        ),
        EncodingClass::Vopc => (
            Some(opcodes::TableClass::Vopc),
            ((dword0 >> 17) & 0xff) as u16,
        ),
        EncodingClass::Sop1 => (
            Some(opcodes::TableClass::Sop1),
            ((dword0 >> 8) & 0xff) as u16,
        ),
        EncodingClass::Sop2 => (
            Some(opcodes::TableClass::Sop2),
            ((dword0 >> 23) & 0x7f) as u16,
        ),
        EncodingClass::Sopp => (
            Some(opcodes::TableClass::Sopp),
            ((dword0 >> 16) & 0x7f) as u16,
        ),
        EncodingClass::Smem => (
            Some(opcodes::TableClass::Smem),
            ((dword0 >> 18) & 0xff) as u16,
        ),
        _ => (None, 0),
    };
    if let Some(tc) = table_class {
        if let Some(entry) = opcodes::lookup(tc, family, op) {
            return entry.operation;
        }
    }
    // Class-level default for opcodes not yet in the table.
    match class {
        EncodingClass::Vop1 | EncodingClass::Vop2 => Operation::Move,
        EncodingClass::Vop3a | EncodingClass::Vop3b => Operation::Other(0),
        EncodingClass::Sop2 | EncodingClass::Sop1 => Operation::Other(0),
        EncodingClass::Sopk => Operation::Other(0),
        EncodingClass::Sopc | EncodingClass::Vopc => Operation::Compare,
        EncodingClass::Sopp => Operation::Other(0),
        EncodingClass::Smem
        | EncodingClass::Mubuf
        | EncodingClass::Mtbuf
        | EncodingClass::Mimg
        | EncodingClass::Ds
        | EncodingClass::Flat => Operation::Load,
        EncodingClass::Exp => Operation::Other(0),
        EncodingClass::Unknown => Operation::Other(0),
    }
}

/// Best-effort control-flow inference from the encoding class. SOPP
/// holds branches and `s_endpgm` (kernel exit); the rest are
/// straight-line.
fn derive_control_flow(class: EncodingClass, dword0: u32) -> ControlFlow {
    if !matches!(class, EncodingClass::Sopp) {
        return ControlFlow::Sequential;
    }
    // SOPP layout: bits [22:16] = OP. Several OPs are kernel
    // terminators / branches:
    //
    //   0x01 s_endpgm    — kernel exit
    //   0x02 s_branch    — unconditional 16-bit signed PC offset
    //   0x06 s_cbranch_* — conditional branches (multiple OPs)
    //
    // Without a per-OP table we can at least mark `s_endpgm` as a
    // return-equivalent.
    let op = (dword0 >> 16) & 0x7f;
    match op {
        0x01 => ControlFlow::Return,
        _ => ControlFlow::Sequential,
    }
}
