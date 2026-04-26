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
use hexray_core::{
    Architecture, ControlFlow, GfxArchitecture, GfxFamily, Instruction, Operand, Operation,
    Register, RegisterClass,
};

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
        populate_operands(&mut instr, class, dword0, self.target);

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

/// Populate `instr.operands` and the `reads`/`writes` register lists
/// for the encoding class. Pure best-effort — we render the operand
/// fields LLVM tablegen documents per class. Encodings with literal
/// dwords or extended-form follow-on bits aren't expanded here yet.
///
/// Bit layouts (from LLVM `SIInstrFormats.td`):
///
/// | Class | SRC0 / SSRC0 | VSRC1 / SSRC1 | VDST / SDST | Notes              |
/// |-------|--------------|----------------|--------------|--------------------|
/// | VOP1  | `[8:0]`      | —              | `[24:17]`    | OP at `[16:9]`     |
/// | VOP2  | `[8:0]`      | `[16:9]`       | `[24:17]`    | OP at `[30:25]`    |
/// | VOPC  | `[8:0]`      | `[16:9]`       | (vcc/vcc_lo) | OP at `[24:17]`    |
/// | SOP1  | `[7:0]`      | —              | `[22:16]`    | OP at `[15:8]`     |
/// | SOP2  | `[7:0]`      | `[15:8]`       | `[22:16]`    | OP at `[29:23]`    |
/// | SOPP  | —            | —              | —            | SIMM16 at `[15:0]` |
fn populate_operands(
    instr: &mut Instruction,
    class: EncodingClass,
    dword0: u32,
    target: GfxArchitecture,
) {
    let arch = Architecture::Amdgpu(target);
    match class {
        EncodingClass::Vop1 => {
            let src0 = (dword0 & 0x1ff) as u16; // 9 bits
            let vdst = ((dword0 >> 17) & 0xff) as u16; // 8 bits, VGPR id
            push_vgpr(instr, arch, vdst, /*write=*/ true);
            push_amdgpu_operand(instr, arch, src0, /*write=*/ false);
        }
        EncodingClass::Vop2 => {
            let src0 = (dword0 & 0x1ff) as u16;
            let vsrc1 = ((dword0 >> 9) & 0xff) as u16;
            let vdst = ((dword0 >> 17) & 0xff) as u16;
            push_vgpr(instr, arch, vdst, true);
            push_amdgpu_operand(instr, arch, src0, false);
            push_vgpr(instr, arch, vsrc1, false);
        }
        EncodingClass::Vopc => {
            // Vector compares write the result to vcc / vcc_lo —
            // model that as an implicit write, not a printed operand.
            let src0 = (dword0 & 0x1ff) as u16;
            let vsrc1 = ((dword0 >> 9) & 0xff) as u16;
            push_amdgpu_operand(instr, arch, src0, false);
            push_vgpr(instr, arch, vsrc1, false);
        }
        EncodingClass::Sop1 => {
            let ssrc0 = (dword0 & 0xff) as u16; // 8 bits
            let sdst = ((dword0 >> 16) & 0x7f) as u16; // 7 bits, SGPR id
            push_sgpr(instr, arch, sdst, true);
            push_amdgpu_operand(instr, arch, ssrc0, false);
        }
        EncodingClass::Sop2 => {
            let ssrc0 = (dword0 & 0xff) as u16;
            let ssrc1 = ((dword0 >> 8) & 0xff) as u16;
            let sdst = ((dword0 >> 16) & 0x7f) as u16;
            push_sgpr(instr, arch, sdst, true);
            push_amdgpu_operand(instr, arch, ssrc0, false);
            push_amdgpu_operand(instr, arch, ssrc1, false);
        }
        EncodingClass::Sopp => {
            // Most SOPP forms (s_endpgm, s_nop, s_barrier) take no
            // visible operands. s_branch / s_cbranch_* take a 16-bit
            // signed SIMM16 — render as PC-relative.
            let op = (dword0 >> 16) & 0x7f;
            let simm16 = (dword0 & 0xffff) as i16;
            if matches!(op, 0x02 | 0x04..=0x09) {
                let target_addr =
                    (instr.address as i64).wrapping_add(((simm16 as i32) * 4 + 4) as i64) as u64;
                instr
                    .operands
                    .push(Operand::pc_rel((simm16 as i64) * 4, target_addr));
            }
        }
        _ => {
            // Other classes (VOP3, SMEM, MUBUF, DS, FLAT, MIMG, EXP)
            // have richer operand layouts that the M10.4 + v1.3.1
            // tables don't cover yet. Leave operands empty for now —
            // M10.4 already renders the mnemonic, and the
            // class-dispatcher tells callers something useful.
        }
    }
}

fn push_vgpr(instr: &mut Instruction, arch: Architecture, id: u16, write: bool) {
    // VGPR IDs are stored without the +256 offset in the VDST/VSRC1
    // fields (which are 8-bit and reference VGPRs by absolute index
    // 0..255). The Register `id` we store needs the +256 offset to
    // match the operand-encoding scheme used in 9-bit SRC0 fields,
    // so the central `amdgpu_reg_name` table can be a single
    // dispatcher.
    let reg = Register::new(arch, RegisterClass::General, id + 256, 32);
    if write {
        instr.writes.push(reg);
    } else {
        instr.reads.push(reg);
    }
    instr.operands.push(Operand::reg(reg));
}

fn push_sgpr(instr: &mut Instruction, arch: Architecture, id: u16, write: bool) {
    let reg = Register::new(arch, RegisterClass::General, id, 32);
    if write {
        instr.writes.push(reg);
    } else {
        instr.reads.push(reg);
    }
    instr.operands.push(Operand::reg(reg));
}

/// Push a 9-bit operand id. Inline constants render as immediates
/// (the Register name table also handles them, but Operand::Immediate
/// is more semantically correct for downstream consumers — the CFG
/// builder, signature recovery — that distinguish reg vs imm).
fn push_amdgpu_operand(instr: &mut Instruction, arch: Architecture, id: u16, write: bool) {
    // Inline constants 128..=208 / 240..=248 surface as immediates
    // so downstream IR users see them as values, not registers.
    if let Some(value) = inline_constant_value(id) {
        instr.operands.push(Operand::imm(value, 32));
        return;
    }
    // Everything else — SGPRs (0..101), VCC/EXEC/M0 specials, VGPRs
    // (256..511) — renders as a Register through the unified
    // amdgpu_reg_name table.
    let reg = Register::new(arch, RegisterClass::General, id, 32);
    if write {
        instr.writes.push(reg);
    } else {
        instr.reads.push(reg);
    }
    instr.operands.push(Operand::reg(reg));
}

/// Return the integer value of an inline constant operand id, if
/// the id encodes one. Hex / float constants are deliberately *not*
/// included here — they're not integers and need to be rendered as
/// strings; they fall through to the register-name path which
/// handles them via `amdgpu_reg_name`.
fn inline_constant_value(id: u16) -> Option<i128> {
    match id {
        // Signed 0..=64.
        128..=192 => Some((id as i128) - 128),
        // Signed -1..=-16.
        193..=208 => Some(-((id as i128) - 192)),
        _ => None,
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
