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

/// Map a `GfxFamily` to the encoding/opcode-table band it follows.
///
/// RDNA1/RDNA2 (gfx10xx) get the `Gfx10Plus` band; RDNA3/RDNA4
/// (gfx11xx/gfx12xx) get `Gfx11Plus` because RDNA3 substantially
/// renumbered VOP2/VOP3/SOPP/SOP1/SMEM/FLAT opcode tables relative
/// to RDNA2.
fn encoding_family_for(family: GfxFamily) -> EncodingFamily {
    match family {
        GfxFamily::Gcn3
        | GfxFamily::Gcn4
        | GfxFamily::Gcn5
        | GfxFamily::Cdna1
        | GfxFamily::Cdna2
        | GfxFamily::Cdna3 => EncodingFamily::Gfx9,
        GfxFamily::Rdna1 | GfxFamily::Rdna2 => EncodingFamily::Gfx10Plus,
        GfxFamily::Rdna3 | GfxFamily::Rdna4 => EncodingFamily::Gfx11Plus,
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
        let control_flow = derive_control_flow(class, dword0, self.family_band);
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
    // FLAT is special: on GFX10 (RDNA1/RDNA2) the `seg` bit field at
    // [16:14] selects flat/scratch/global and we rewrite the rendered
    // prefix. On GFX11+ (RDNA3+) the FLAT/GLOBAL/SCRATCH variants
    // occupy distinct OP slots — the table entries already carry the
    // right `global_*`/`flat_*`/`scratch_*` mnemonic, so we skip the
    // seg rewrite.
    if matches!(class, EncodingClass::Flat) {
        let op = ((dword0 >> 18) & 0x7f) as u16;
        if let Some(entry) = opcodes::lookup(opcodes::TableClass::Flat, family, op) {
            if matches!(family, EncodingFamily::Gfx11Plus) {
                return entry.mnemonic.to_string();
            }
            let seg = ((dword0 >> 14) & 0x3) as u8;
            return opcodes::render_flat_mnemonic(entry.mnemonic, seg);
        }
        return format!("flat.op{op:#x}");
    }

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
        // VOP3A / VOP3B: 10-bit OP at [25:16].
        EncodingClass::Vop3a | EncodingClass::Vop3b => (
            Some(opcodes::TableClass::Vop3),
            ((dword0 >> 16) & 0x3ff) as u16,
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
        EncodingClass::Vop3a | EncodingClass::Vop3b => (
            Some(opcodes::TableClass::Vop3),
            ((dword0 >> 16) & 0x3ff) as u16,
        ),
        EncodingClass::Flat => (
            Some(opcodes::TableClass::Flat),
            ((dword0 >> 18) & 0x7f) as u16,
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
            // SOPP carries either branches (PC-relative SIMM16) or
            // bare opcodes whose SIMM16 has class-specific bitfield
            // semantics (s_waitcnt: vmcnt | lgkmcnt | expcnt;
            // s_delay_alu: instid0 | instskip | instid1; s_clause:
            // instruction count). Family-aware dispatch via the
            // opcode table.
            let op = ((dword0 >> 16) & 0x7f) as u16;
            let simm16_u = (dword0 & 0xffff) as u16;
            let simm16 = simm16_u as i16;
            let family = encoding_family_for(target.family);
            let entry = opcodes::lookup(opcodes::TableClass::Sopp, family, op);
            let is_branch = entry
                .map(|e| matches!(e.operation, Operation::Jump | Operation::ConditionalJump))
                .unwrap_or(false);
            if is_branch {
                let target_addr =
                    (instr.address as i64).wrapping_add(((simm16 as i32) * 4 + 4) as i64) as u64;
                instr
                    .operands
                    .push(Operand::pc_rel((simm16 as i64) * 4, target_addr));
                // PcRelative's Display renders the absolute target;
                // we don't append the SIMM16 here so the output stays
                // single-token (matching `llvm-objdump`'s decimal
                // label-offset form is a future cosmetic).
            } else if let Some(entry) = entry {
                if let Some(rendered) = render_sopp_simm16(entry.mnemonic, simm16_u, family) {
                    if !rendered.is_empty() {
                        instr.mnemonic = format!("{} {}", instr.mnemonic, rendered);
                    }
                }
            }
        }
        EncodingClass::Vop3a | EncodingClass::Vop3b => {
            populate_vop3_operands(instr, dword0, target);
        }
        EncodingClass::Smem => {
            populate_smem_operands(instr, dword0, target);
        }
        EncodingClass::Flat => {
            populate_flat_operands(instr, dword0, target);
        }
        EncodingClass::Mubuf => {
            populate_mubuf_operands(instr, dword0, target);
        }
        EncodingClass::Ds => {
            populate_ds_operands(instr, dword0, target);
        }
        _ => {
            // MTBUF / MIMG / EXP have richer operand layouts
            // (resource descriptors + addressing modes); the mnemonic
            // dispatcher renders the right name and the walker stays
            // in sync. Operand-field expansion lands in a follow-up.
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

// =============================================================================
// VOP3 / SMEM / FLAT operand rendering
// =============================================================================
//
// These classes have richer operand layouts than VOP1/2/C and the
// generic `Register::name()` path can't render multi-dword register
// pairs (`v[0:1]`, `s[2:3]`). For these classes we render the full
// operand string ourselves and append it to `instr.mnemonic`. The
// `instr.reads` / `writes` lists still carry per-register entries
// for downstream IR consumers; only the *display* path is custom.
//
// Bit layouts (per LLVM SIInstrFormats.td):
//
// | Class | Layout                                                              |
// |-------|---------------------------------------------------------------------|
// | VOP3  | dword0: `[7:0]` VDST, `[8]` ABS_SRC0, `[9]` ABS_SRC1, `[10]` ABS_SRC2, `[14:8]` SDST (VOP3B), `[15]` CLAMP, `[25:16]` OP, `[31:26]` 0b110101. dword1: `[8:0]` SRC0, `[17:9]` SRC1, `[26:18]` SRC2, `[27]` OPSEL_HI, `[29:28]` OMOD, `[30]` NEG_SRC0, `[31]` NEG_SRC1 (RDNA layout has variations). |
// | SMEM  | dword0: `[5:0]` SBASE>>1, `[12:6]` SDST, `[14]` DLC, `[16:15]` reserved, `[25:18]` OP, `[31:26]` 0b111101 (GFX10+). dword1: `[20:0]` OFFSET (signed). |
// | FLAT  | dword0: `[12:0]` OFFSET (signed), `[14]` DLC, `[16:15]` SEG (0=flat, 1=scratch, 2=global), `[17]` SLC, `[24:18]` OP, `[31:26]` 0b110111. dword1: `[7:0]` ADDR, `[15:8]` DATA, `[22:16]` SADDR, `[31:24]` VDST. |

fn populate_vop3_operands(instr: &mut Instruction, dword0: u32, target: GfxArchitecture) {
    let arch = Architecture::Amdgpu(target);
    let family = encoding_family_for(target.family);
    let op = ((dword0 >> 16) & 0x3ff) as u16;

    // VOP3 dword1 carries the SRC fields. We don't always have it
    // (decode_instruction passes Option<u32>), but VOP3 is by spec
    // 64-bit so dword1 should be present at this point in the call.
    // populate_operands receives only dword0 — we encode dword1
    // back from raw bytes if we need it. Look at the trailing 4
    // bytes of `instr.bytes`.
    let dword1 = if instr.bytes.len() >= 8 {
        u32::from_le_bytes([
            instr.bytes[4],
            instr.bytes[5],
            instr.bytes[6],
            instr.bytes[7],
        ])
    } else {
        0
    };

    // Sizes: hard-coded for the OPs we currently know. Default to
    // single-dword. The mnemonic suffix (`_b32` / `_b64` / `_u64_u32`
    // etc.) tells us widths for most ops.
    let (dst_dwords, src_dwords) = vop3_widths(&instr.mnemonic, family, op);
    let writes_vdst = vop3_writes_explicit_vdst(&instr.mnemonic);
    let is_vop3b = is_vop3b_form(&instr.mnemonic);
    let n_src = vop3_src_count(&instr.mnemonic);

    let vdst = (dword0 & 0xff) as u16;
    let sdst = ((dword0 >> 8) & 0x7f) as u16; // VOP3B SDST
    let src0 = (dword1 & 0x1ff) as u16;
    let src1 = ((dword1 >> 9) & 0x1ff) as u16;
    let src2 = ((dword1 >> 18) & 0x1ff) as u16;

    // Modifiers. VOP3A:
    //   - NEG bits at [31:29] of dword1 (one per source).
    //   - ABS bits at [10:8] of dword0 (one per source).
    // VOP3B reuses [14:8] of dword0 as SDST, so ABS is unavailable;
    // any bits set there are SDST data, not modifiers.
    let neg_src0 = (dword1 >> 29) & 1 != 0;
    let neg_src1 = (dword1 >> 30) & 1 != 0;
    let neg_src2 = (dword1 >> 31) & 1 != 0;
    let (abs_src0, abs_src1, abs_src2) = if is_vop3b {
        (false, false, false)
    } else {
        (
            (dword0 >> 8) & 1 != 0,
            (dword0 >> 9) & 1 != 0,
            (dword0 >> 10) & 1 != 0,
        )
    };

    let mut parts = Vec::new();
    if writes_vdst {
        parts.push(render_vgpr_range(vdst, dst_dwords));
    }
    if is_vop3b {
        parts.push(render_sgpr_range(sdst, 1));
    }
    if n_src >= 1 {
        parts.push(render_amdgpu_operand_string(
            src0,
            src_dwords[0],
            neg_src0,
            abs_src0,
        ));
    }
    if n_src >= 2 {
        parts.push(render_amdgpu_operand_string(
            src1,
            src_dwords[1],
            neg_src1,
            abs_src1,
        ));
    }
    if n_src >= 3 {
        parts.push(render_amdgpu_operand_string(
            src2,
            src_dwords[2],
            neg_src2,
            abs_src2,
        ));
    }

    instr.mnemonic = format!("{} {}", instr.mnemonic, parts.join(", "));

    // Track reads/writes for downstream consumers WITHOUT pushing
    // to `instr.operands` — the operand string is already in the
    // mnemonic, so a generic Display would otherwise duplicate
    // every register it appears.
    let _ = arch;
    if writes_vdst {
        track_vgpr_write(instr, target, vdst);
    }
    push_amdgpu_operand_no_print(instr, Architecture::Amdgpu(target), src0, false);
    if n_src >= 2 {
        push_amdgpu_operand_no_print(instr, Architecture::Amdgpu(target), src1, false);
    }
    if n_src >= 3 {
        push_amdgpu_operand_no_print(instr, Architecture::Amdgpu(target), src2, false);
    }
}

/// VOPC encoded as VOP3 (`v_cmp_*_e64`, `v_cmpx_*_e64`) writes the
/// result implicitly to EXEC; the VDST field carries the EXEC
/// reference and llvm-objdump doesn't render it. Same for any
/// instruction where the VDST is metadata, not an output register.
fn vop3_writes_explicit_vdst(mnemonic: &str) -> bool {
    !mnemonic.starts_with("v_cmp_") && !mnemonic.starts_with("v_cmpx_")
}

/// VOP3B forms — the carry-add / divide-scale family that uses
/// `[14:8]` SDST as a separate output (typically vcc / null).
fn is_vop3b_form(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "v_add_co_u32"
            | "v_sub_co_u32"
            | "v_subrev_co_u32"
            | "v_addc_u32"
            | "v_subb_u32"
            | "v_subbrev_u32"
            | "v_mad_u64_u32"
            | "v_mad_i64_i32"
            | "v_div_scale_f32"
            | "v_div_scale_f64"
    )
}

/// Number of source operands the VOP3 mnemonic actually uses (so we
/// don't print src2 for 2-source ops like `v_lshlrev_b64`).
fn vop3_src_count(mnemonic: &str) -> u8 {
    if mnemonic.starts_with("v_cmp_") || mnemonic.starts_with("v_cmpx_") {
        return 2;
    }
    if matches!(
        mnemonic,
        "v_lshlrev_b64"
            | "v_lshrrev_b64"
            | "v_ashrrev_i64"
            | "v_add_co_u32"
            | "v_sub_co_u32"
            | "v_subrev_co_u32"
    ) {
        return 2;
    }
    3
}

fn track_vgpr_write(instr: &mut Instruction, target: GfxArchitecture, id: u16) {
    // VDST in VOP3 is an 8-bit field referencing a VGPR by absolute
    // index 0..255. Add to writes only — no generic operand push.
    instr.writes.push(Register::new(
        Architecture::Amdgpu(target),
        RegisterClass::General,
        id + 256,
        32,
    ));
}

fn populate_smem_operands(instr: &mut Instruction, dword0: u32, target: GfxArchitecture) {
    let arch = Architecture::Amdgpu(target);
    let _ = arch;
    let dword1 = if instr.bytes.len() >= 8 {
        u32::from_le_bytes([
            instr.bytes[4],
            instr.bytes[5],
            instr.bytes[6],
            instr.bytes[7],
        ])
    } else {
        0
    };
    // SBASE is in `[5:0]` shifted left by 1 (always even SGPR pair).
    let sbase = ((dword0 & 0x3f) as u16) << 1;
    let sdst = ((dword0 >> 6) & 0x7f) as u16;
    let offset = dword1 & 0x1f_ffff; // 21-bit unsigned offset
    let dst_dwords = sdst_dwords_from_smem_mnemonic(&instr.mnemonic);

    let sbase_str = render_sgpr_range(sbase, 2); // SBASE is always pair (64-bit)
    let sdst_str = render_sgpr_range(sdst, dst_dwords);
    let offset_str = if offset == 0 {
        // llvm-objdump renders an absent SOFFSET as `null` rather
        // than `0` — match that for clean diff comparison.
        "null".to_string()
    } else {
        format!("0x{offset:x}")
    };

    instr.mnemonic = format!(
        "{} {}, {}, {}",
        instr.mnemonic, sdst_str, sbase_str, offset_str
    );

    // Mark reads/writes — sdst is written; sbase is read.
    for i in 0..dst_dwords {
        instr.writes.push(Register::new(
            arch,
            RegisterClass::General,
            sdst.wrapping_add(i as u16),
            32,
        ));
    }
    for i in 0..2 {
        instr.reads.push(Register::new(
            arch,
            RegisterClass::General,
            sbase.wrapping_add(i),
            32,
        ));
    }
}

fn populate_flat_operands(instr: &mut Instruction, dword0: u32, target: GfxArchitecture) {
    let arch = Architecture::Amdgpu(target);
    let dword1 = if instr.bytes.len() >= 8 {
        u32::from_le_bytes([
            instr.bytes[4],
            instr.bytes[5],
            instr.bytes[6],
            instr.bytes[7],
        ])
    } else {
        0
    };
    let offset = dword0 & 0x1fff; // 13-bit signed offset
    let seg = ((dword0 >> 14) & 0x3) as u8;
    let addr = (dword1 & 0xff) as u16;
    let data = ((dword1 >> 8) & 0xff) as u16;
    let saddr = ((dword1 >> 16) & 0x7f) as u16;
    let vdst = ((dword1 >> 24) & 0xff) as u16;

    let is_load = matches!(instr.operation, Operation::Load);
    let is_store = matches!(instr.operation, Operation::Store);
    let dst_dwords = data_dwords_from_flat_mnemonic(&instr.mnemonic);
    let addr_dwords = if seg == 1 { 1 } else { 2 }; // scratch=1, flat/global=2

    let addr_str = render_vgpr_range(addr, addr_dwords);
    let saddr_str = if saddr == 0x7c {
        "off".to_string()
    } else {
        render_sgpr_range(saddr, 2)
    };

    if is_load {
        let dst_str = render_vgpr_range(vdst, dst_dwords);
        instr.mnemonic = format!(
            "{} {}, {}, {}",
            instr.mnemonic, dst_str, addr_str, saddr_str
        );
        for i in 0..dst_dwords {
            instr.writes.push(Register::new(
                arch,
                RegisterClass::General,
                vdst.wrapping_add(i as u16) + 256,
                32,
            ));
        }
    } else if is_store {
        let data_str = render_vgpr_range(data, dst_dwords);
        instr.mnemonic = format!(
            "{} {}, {}, {}",
            instr.mnemonic, addr_str, data_str, saddr_str
        );
        for i in 0..dst_dwords {
            instr.reads.push(Register::new(
                arch,
                RegisterClass::General,
                data.wrapping_add(i as u16) + 256,
                32,
            ));
        }
    } else {
        // Atomics, etc. — render the address only for now.
        instr.mnemonic = format!("{} {}, {}", instr.mnemonic, addr_str, saddr_str);
    }
    if offset != 0 {
        // Sign-extend the 13-bit offset.
        let signed = ((offset << 19) as i32) >> 19;
        if signed != 0 {
            instr.mnemonic = format!("{} offset:{}", instr.mnemonic, signed);
        }
    }

    for i in 0..addr_dwords {
        instr.reads.push(Register::new(
            arch,
            RegisterClass::General,
            addr.wrapping_add(i as u16) + 256,
            32,
        ));
    }
}

/// MUBUF operand layout (64-bit instruction; bit indices below are
/// across both dwords combined, low dword = `dword0`, high = `dword1`).
///
/// `dword0`:
///   - `[11:0]`  OFFSET (12-bit unsigned immediate)
///   - `[12]`    OFFEN  (use VADDR.0 as offset)
///   - `[13]`    IDXEN  (use VADDR.0 as index)
///   - `[14]`    GLC
///   - `[16]`    LDS    (write straight to LDS)
///   - `[17]`    SLC
///
/// `dword1`:
///   - `[39:32]` VADDR  (in dword1 = `[7:0]`)
///   - `[47:40]` VDATA  (in dword1 = `[15:8]`)
///   - `[52:48]` SRSRC  (in dword1 = `[20:16]`, references s[N*4:N*4+3])
///   - `[55]`    TFE
///   - `[63:56]` SOFFSET (in dword1 = `[31:24]`, scalar offset)
///
/// llvm-objdump renders as
///   `<vdata>, <vaddr>, <srsrc>, <soffset> [offset:N] [idxen] [offen]`
fn populate_mubuf_operands(instr: &mut Instruction, dword0: u32, target: GfxArchitecture) {
    let arch = Architecture::Amdgpu(target);
    let dword1 = if instr.bytes.len() >= 8 {
        u32::from_le_bytes([
            instr.bytes[4],
            instr.bytes[5],
            instr.bytes[6],
            instr.bytes[7],
        ])
    } else {
        0
    };

    let offset = dword0 & 0xfff;
    let offen = (dword0 >> 12) & 1 != 0;
    let idxen = (dword0 >> 13) & 1 != 0;
    let glc = (dword0 >> 14) & 1 != 0;
    let slc = (dword0 >> 17) & 1 != 0;

    let vaddr = (dword1 & 0xff) as u16;
    let vdata = ((dword1 >> 8) & 0xff) as u16;
    let srsrc_quad = ((dword1 >> 16) & 0x1f) as u16; // SGPR pair-of-pairs index
    let soffset = ((dword1 >> 24) & 0xff) as u16;

    let dwords = data_dwords_from_mubuf_mnemonic(&instr.mnemonic);
    let is_load = matches!(instr.operation, Operation::Load);
    let is_store = matches!(instr.operation, Operation::Store);

    // SRSRC is encoded as a 5-bit field that names s[N*4:N*4+3] — one
    // resource descriptor (V#) is 4 SGPRs / 128 bits.
    let srsrc_base = srsrc_quad * 4;
    let srsrc_str = format!("s[{}:{}]", srsrc_base, srsrc_base + 3);
    let vdata_str = render_vgpr_range(vdata, dwords);
    let vaddr_str = if offen && idxen {
        format!("v[{}:{}]", vaddr, vaddr + 1)
    } else if offen || idxen {
        render_vgpr_range(vaddr, 1)
    } else {
        // Neither offen nor idxen → no per-lane addr; render `off`.
        "off".to_string()
    };
    let soffset_str = if soffset == 0x80 {
        // Imm-zero soffset — llvm renders as literal 0.
        "0".to_string()
    } else {
        render_sgpr_range(soffset, 1)
    };

    let leading_v = if is_load || is_store {
        vdata_str.clone()
    } else {
        // Atomics: VDATA is both read and written; render once.
        vdata_str.clone()
    };

    let mut s = format!(
        "{} {}, {}, {}, {}",
        instr.mnemonic, leading_v, vaddr_str, srsrc_str, soffset_str
    );
    if offset != 0 {
        s.push_str(&format!(" offset:{offset}"));
    }
    if idxen {
        s.push_str(" idxen");
    }
    if offen {
        s.push_str(" offen");
    }
    if glc {
        s.push_str(" glc");
    }
    if slc {
        s.push_str(" slc");
    }
    instr.mnemonic = s;

    // Track register access. SRSRC = 4 SGPRs read.
    for i in 0..4 {
        instr.reads.push(Register::new(
            arch,
            RegisterClass::General,
            srsrc_base + i,
            32,
        ));
    }
    if soffset != 0x80 && soffset < 124 {
        instr
            .reads
            .push(Register::new(arch, RegisterClass::General, soffset, 32));
    }
    if offen || idxen {
        let n = if offen && idxen { 2 } else { 1 };
        for i in 0..n {
            instr.reads.push(Register::new(
                arch,
                RegisterClass::General,
                vaddr.wrapping_add(i) + 256,
                32,
            ));
        }
    }
    if is_load {
        for i in 0..dwords as u16 {
            instr.writes.push(Register::new(
                arch,
                RegisterClass::General,
                vdata.wrapping_add(i) + 256,
                32,
            ));
        }
    } else if is_store {
        for i in 0..dwords as u16 {
            instr.reads.push(Register::new(
                arch,
                RegisterClass::General,
                vdata.wrapping_add(i) + 256,
                32,
            ));
        }
    }
}

/// DS (LDS / GDS) operand layout (64-bit instruction).
///
/// `dword0`:
///   - `[7:0]`   OFFSET0 (8-bit unsigned)
///   - `[15:8]`  OFFSET1 (8-bit unsigned)
///   - `[16]`    GDS
///
/// `dword1`:
///   - `[39:32]` ADDR    (`dword1[7:0]`)
///   - `[47:40]` DATA0   (`dword1[15:8]`)
///   - `[55:48]` DATA1   (`dword1[23:16]`)
///   - `[63:56]` VDST    (`dword1[31:24]`)
///
/// llvm-objdump renders as
///   `<vdst>, <addr>[, <data0>[, <data1>]] [offset0:N] [offset1:N] [gds]`
fn populate_ds_operands(instr: &mut Instruction, dword0: u32, target: GfxArchitecture) {
    let arch = Architecture::Amdgpu(target);
    let dword1 = if instr.bytes.len() >= 8 {
        u32::from_le_bytes([
            instr.bytes[4],
            instr.bytes[5],
            instr.bytes[6],
            instr.bytes[7],
        ])
    } else {
        0
    };

    let offset0 = dword0 & 0xff;
    let offset1 = (dword0 >> 8) & 0xff;
    let gds = (dword0 >> 16) & 1 != 0;

    let addr = (dword1 & 0xff) as u16;
    let data0 = ((dword1 >> 8) & 0xff) as u16;
    let data1 = ((dword1 >> 16) & 0xff) as u16;
    let vdst = ((dword1 >> 24) & 0xff) as u16;

    let writes_vdst = ds_writes_vdst(&instr.mnemonic);
    let n_data = ds_data_count(&instr.mnemonic);
    let dwords = ds_data_dwords(&instr.mnemonic);

    let mut parts: Vec<String> = Vec::new();
    if writes_vdst {
        parts.push(render_vgpr_range(vdst, dwords));
    }
    parts.push(render_vgpr_range(addr, 1));
    if n_data >= 1 {
        parts.push(render_vgpr_range(data0, dwords));
    }
    if n_data >= 2 {
        parts.push(render_vgpr_range(data1, dwords));
    }

    let mut s = format!("{} {}", instr.mnemonic, parts.join(", "));
    if offset0 != 0 {
        s.push_str(&format!(" offset0:{offset0}"));
    }
    if offset1 != 0 {
        s.push_str(&format!(" offset1:{offset1}"));
    }
    if gds {
        s.push_str(" gds");
    }
    instr.mnemonic = s;

    // Track reads/writes.
    instr
        .reads
        .push(Register::new(arch, RegisterClass::General, addr + 256, 32));
    if writes_vdst {
        for i in 0..dwords as u16 {
            instr.writes.push(Register::new(
                arch,
                RegisterClass::General,
                vdst.wrapping_add(i) + 256,
                32,
            ));
        }
    }
    if n_data >= 1 {
        for i in 0..dwords as u16 {
            instr.reads.push(Register::new(
                arch,
                RegisterClass::General,
                data0.wrapping_add(i) + 256,
                32,
            ));
        }
    }
    if n_data >= 2 {
        for i in 0..dwords as u16 {
            instr.reads.push(Register::new(
                arch,
                RegisterClass::General,
                data1.wrapping_add(i) + 256,
                32,
            ));
        }
    }
}

/// Width in dwords of MUBUF VDATA, derived from the mnemonic suffix.
fn data_dwords_from_mubuf_mnemonic(mnemonic: &str) -> u8 {
    if mnemonic.ends_with("dwordx4") || mnemonic.ends_with("b128") {
        4
    } else if mnemonic.ends_with("dwordx3") || mnemonic.ends_with("b96") {
        3
    } else if mnemonic.ends_with("dwordx2") || mnemonic.ends_with("b64") {
        2
    } else {
        1
    }
}

/// Width in dwords of DS VDATA / VDST, derived from the mnemonic
/// suffix (mirrors the same `_b32` / `_b64` / `_b128` convention).
fn ds_data_dwords(mnemonic: &str) -> u8 {
    if mnemonic.contains("b128") {
        4
    } else if mnemonic.contains("b96") {
        3
    } else if mnemonic.contains("b64") {
        2
    } else {
        1
    }
}

/// Whether a DS opcode writes the VDST field. Stores
/// (`ds_write_*`) and barriers don't; loads / atomics-with-return do.
fn ds_writes_vdst(mnemonic: &str) -> bool {
    mnemonic.contains("ds_load")
        || mnemonic.contains("ds_read")
        || mnemonic.starts_with("ds_") && mnemonic.contains("rtn")
}

/// Number of DATA operands a DS opcode consumes (0, 1, or 2).
fn ds_data_count(mnemonic: &str) -> usize {
    if mnemonic.contains("ds_load") || mnemonic.contains("ds_read") {
        0
    } else if mnemonic.contains("ds_store2")
        || mnemonic.contains("ds_write2")
        || mnemonic.contains("_2addr")
    {
        2
    } else {
        1
    }
}

// -- Helpers --

/// Render a VGPR range as `vN` (single) or `v[N:M]` (multi-dword).
fn render_vgpr_range(base: u16, dwords: u8) -> String {
    if base == 0x7c && dwords == 1 {
        // Some instructions encode `null` in the VDST slot.
        return "null".to_string();
    }
    if dwords <= 1 {
        format!("v{base}")
    } else {
        format!("v[{}:{}]", base, base.saturating_add(dwords as u16 - 1))
    }
}

/// Render an SGPR range as `sN` (single) or `s[N:M]` (multi-dword).
fn render_sgpr_range(base: u16, dwords: u8) -> String {
    if base == 0x7c && dwords == 1 {
        return "null".to_string();
    }
    // Specials.
    match base {
        106 if dwords == 2 => return "vcc".to_string(),
        106 => return "vcc_lo".to_string(),
        107 => return "vcc_hi".to_string(),
        124 => return "m0".to_string(),
        126 if dwords == 2 => return "exec".to_string(),
        126 => return "exec_lo".to_string(),
        127 => return "exec_hi".to_string(),
        _ => {}
    }
    if dwords <= 1 {
        format!("s{base}")
    } else {
        format!("s[{}:{}]", base, base.saturating_add(dwords as u16 - 1))
    }
}

/// Render a 9-bit operand id with optional negation modifier and
/// width awareness. Inline integer/float constants surface as the
/// literal value; SGPRs/VGPRs go through the range-aware path.
fn render_amdgpu_operand_string(id: u16, dwords: u8, negate: bool, abs: bool) -> String {
    // VOP3A modifiers: ABS wraps the operand in `|...|`; NEG prefixes
    // a `-`. When both are set the form is `-|x|` to match
    // llvm-objdump (NEG outside ABS).
    let neg = if negate { "-" } else { "" };
    let (open, close) = if abs { ("|", "|") } else { ("", "") };
    let inner: String = {
        // null sink (RDNA).
        if id == 0x7c {
            "null".into()
        } else if let Some(v) = inline_constant_value(id) {
            // Inline integer constants.
            format!("{v}")
        } else {
            // Float inline constants.
            let float = match id {
                240 => Some("0.5"),
                241 => Some("-0.5"),
                242 => Some("1.0"),
                243 => Some("-1.0"),
                244 => Some("2.0"),
                245 => Some("-2.0"),
                246 => Some("4.0"),
                247 => Some("-4.0"),
                248 => Some("0x3e22f983"), // 1/(2*PI)
                _ => None,
            };
            if let Some(f) = float {
                f.into()
            } else if (256..512).contains(&id) {
                // VGPRs (id 256..511 — strip the offset and render as range).
                render_vgpr_range(id - 256, dwords)
            } else {
                // SGPRs and specials.
                render_sgpr_range(id, dwords)
            }
        }
    };
    format!("{neg}{open}{inner}{close}")
}

/// Like `push_amdgpu_operand` but doesn't emit the operand into the
/// `Instruction::operands` list — used by the populator paths that
/// render the operand string directly into the mnemonic.
fn push_amdgpu_operand_no_print(instr: &mut Instruction, arch: Architecture, id: u16, write: bool) {
    if inline_constant_value(id).is_some() || (240..=248).contains(&id) {
        return; // immediate, no register to track
    }
    if id == 0x7c {
        return; // null sink, no register
    }
    let reg = Register::new(arch, RegisterClass::General, id, 32);
    if write {
        instr.writes.push(reg);
    } else {
        instr.reads.push(reg);
    }
}

/// Width inference for VOP3 dst / src fields based on the mnemonic
/// suffix. Returns `(dst_dwords, [src0_dwords, src1_dwords,
/// src2_dwords])`. Hand-encoded for the OPs in the v1.3.4 GFX10/11
/// tables; M10.5 corpus widening will grow it.
fn vop3_widths(mnemonic: &str, _family: EncodingFamily, _op: u16) -> (u8, [u8; 3]) {
    // Defaults: 32-bit on both sides.
    let mut dst = 1u8;
    let mut src = [1u8; 3];

    // Dest side: if mnemonic ends in `_b64` / `_u64_*` / `_i64_*` /
    // `_f64`, dest is 64-bit (2 dwords).
    if mnemonic.contains("_b64") || mnemonic.contains("_f64") {
        dst = 2;
    }
    // v_mad_u64_u32: dest is 64-bit, src0/src1 are 32-bit, src2 is
    // 64-bit (the carry-add accumulator).
    if mnemonic == "v_mad_u64_u32" || mnemonic == "v_mad_i64_i32" {
        dst = 2;
        src[2] = 2;
    }
    // v_lshlrev_b64 / v_lshrrev_b64 / v_ashrrev_i64: dst + src1 are
    // 64-bit, src0 (shift amount) is 32-bit.
    if matches!(
        mnemonic,
        "v_lshlrev_b64" | "v_lshrrev_b64" | "v_ashrrev_i64"
    ) {
        dst = 2;
        src[1] = 2;
    }

    (dst, src)
}

/// SMEM SDST width inference from `s_load_b{32,64,128,256,512}` etc.
fn sdst_dwords_from_smem_mnemonic(mnemonic: &str) -> u8 {
    let suffix = mnemonic
        .strip_prefix("s_load_b")
        .or_else(|| mnemonic.strip_prefix("s_buffer_load_b"))
        .or_else(|| mnemonic.strip_prefix("s_load_dword"));
    match suffix {
        Some("32") | Some("") => 1,
        Some("64") | Some("x2") => 2,
        Some("128") | Some("x4") => 4,
        Some("256") | Some("x8") => 8,
        Some("512") | Some("x16") => 16,
        Some("3") => 3, // x3
        _ => 1,
    }
}

/// FLAT data width inference from `flat_load_b{32,64,128}` /
/// `global_load_b{32,64}` / `flat_load_dword*` etc.
fn data_dwords_from_flat_mnemonic(mnemonic: &str) -> u8 {
    // Try standard `_b<N>` suffix.
    for prefix in [
        "flat_load_b",
        "flat_store_b",
        "global_load_b",
        "global_store_b",
        "scratch_load_b",
        "scratch_store_b",
    ] {
        if let Some(suffix) = mnemonic.strip_prefix(prefix) {
            return match suffix {
                "32" => 1,
                "64" => 2,
                "96" => 3,
                "128" => 4,
                _ => 1,
            };
        }
    }
    // Fallback: legacy `_dword[xN]` suffix used by RDNA2 mnemonics.
    if let Some(suffix) = mnemonic
        .strip_prefix("flat_load_dword")
        .or_else(|| mnemonic.strip_prefix("flat_store_dword"))
        .or_else(|| mnemonic.strip_prefix("global_load_dword"))
        .or_else(|| mnemonic.strip_prefix("global_store_dword"))
        .or_else(|| mnemonic.strip_prefix("scratch_load_dword"))
        .or_else(|| mnemonic.strip_prefix("scratch_store_dword"))
    {
        return match suffix {
            "" => 1,
            "x2" => 2,
            "x3" => 3,
            "x4" => 4,
            _ => 1,
        };
    }
    1
}

/// Best-effort control-flow inference from the encoding class.
///
/// SOPP carries branches and `s_endpgm` (kernel exit); the OP
/// Render the SOPP SIMM16 immediate as LLVM-style sub-fields for
/// the opcodes that carry meaningful bitfields (s_waitcnt /
/// s_delay_alu / s_clause / s_wait_*). Returns the rendered string
/// (without leading space) or `None` if the OP doesn't have a
/// known sub-field structure.
///
/// References:
/// - **s_waitcnt** (GFX9/10/11): `[3:0]` vmcnt[3:0], `[6:4]` expcnt,
///   `[15:8]` lgkmcnt[7:0], `[15:14] | [11:10]` vmcnt[5:4]/[5:4]
///   pieces — RDNA1+ widened vmcnt to 6 bits.
/// - **s_delay_alu** (GFX11+): `[3:0]` instid0, `[6:4]` instskip,
///   `[10:7]` instid1.
/// - **s_clause** (RDNA): SIMM16 is the count of clause-grouped
///   instructions (low bits).
/// - **s_wait_loadcnt / s_wait_kmcnt** (GFX11+): SIMM16 is the
///   per-counter wait value.
fn render_sopp_simm16(mnemonic: &str, simm16: u16, family: EncodingFamily) -> Option<String> {
    match mnemonic {
        "s_waitcnt" => Some(render_waitcnt(simm16, family)),
        "s_delay_alu" => Some(render_delay_alu(simm16)),
        "s_clause" => {
            // SIMM16 low 6 bits = count of next-clause instructions
            // (encoded as count - 1 on RDNA per LLVM SOPPInstructions.td).
            let count = (simm16 & 0x3f) as u32 + 1;
            Some(format!("{:#x}", count - 1))
        }
        "s_nop" => {
            // Encoded as count - 1 (s_nop 0 → no extra cycles).
            Some(format!("{}", simm16 & 0xf))
        }
        "s_wait_loadcnt" | "s_wait_kmcnt" | "s_wait_storecnt" | "s_wait_samplecnt"
        | "s_wait_bvhcnt" | "s_wait_dscnt" | "s_wait_expcnt" => {
            // GFX11+ separate-counter waits: SIMM16 carries the per-counter
            // immediate value directly.
            Some(format!("{:#x}", simm16))
        }
        _ => None,
    }
}

fn render_waitcnt(simm16: u16, family: EncodingFamily) -> String {
    // SIMM16 layout differs between bands:
    //
    // - GFX9: VMCNT[3:0]=[3:0], EXPCNT=[6:4], LGKMCNT[3:0]=[11:8],
    //   no high VMCNT bits (4-bit total).
    // - GFX10: VMCNT[3:0]=[3:0], EXPCNT=[6:4], LGKMCNT[5:0]=[13:8],
    //   VMCNT[5:4]=[15:14] (6-bit total).
    // - GFX11: completely reshuffled — VMCNT[5:0]=[15:10] split,
    //   LGKMCNT[5:0]=[9:4], EXPCNT[2:0]=[3:0]. Confirmed by reverse-
    //   engineering the SCALE gfx1100 fixture against `llvm-objdump`.
    //
    // For GFX11 we use the shuffled layout. For GFX9/GFX10 we use
    // the older one.
    let (vmcnt, expcnt, lgkmcnt, vmcnt_max, lgkmcnt_max, expcnt_max) = match family {
        EncodingFamily::Gfx9 => {
            let vmcnt = (simm16 & 0xf) as u32;
            let expcnt = ((simm16 >> 4) & 0x7) as u32;
            let lgkmcnt = ((simm16 >> 8) & 0xf) as u32;
            (vmcnt, expcnt, lgkmcnt, 0xf, 0xf, 0x7)
        }
        EncodingFamily::Gfx10Plus => {
            let vmcnt_lo = (simm16 & 0xf) as u32;
            let expcnt = ((simm16 >> 4) & 0x7) as u32;
            let lgkmcnt = ((simm16 >> 8) & 0x3f) as u32;
            let vmcnt_hi = ((simm16 >> 14) & 0x3) as u32;
            let vmcnt = (vmcnt_hi << 4) | vmcnt_lo;
            (vmcnt, expcnt, lgkmcnt, 0x3f, 0x3f, 0x7)
        }
        EncodingFamily::Gfx11Plus => {
            // GFX11 unified s_waitcnt layout (validated against
            // `llvm-objdump --mcpu=gfx1100` on the SCALE fixture):
            //   VMCNT  at [15:10]
            //   LGKMCNT at [9:4]
            //   EXPCNT  at [2:0]  (bit 3 reserved / no field)
            let vmcnt = ((simm16 >> 10) & 0x3f) as u32;
            let lgkmcnt = ((simm16 >> 4) & 0x3f) as u32;
            let expcnt = (simm16 & 0x7) as u32;
            (vmcnt, expcnt, lgkmcnt, 0x3f, 0x3f, 0x7)
        }
    };
    let mut parts = Vec::new();
    if vmcnt < vmcnt_max {
        parts.push(format!("vmcnt({vmcnt})"));
    }
    if expcnt < expcnt_max {
        parts.push(format!("expcnt({expcnt})"));
    }
    if lgkmcnt < lgkmcnt_max {
        parts.push(format!("lgkmcnt({lgkmcnt})"));
    }
    if parts.is_empty() {
        // All maxed out — `s_waitcnt 0xffff` "wait nothing" form.
        format!("{simm16:#x}")
    } else {
        parts.join(" & ")
    }
}

fn render_delay_alu(simm16: u16) -> String {
    let instid0 = simm16 & 0xf;
    let instskip = (simm16 >> 4) & 0x7;
    let instid1 = (simm16 >> 7) & 0xf;
    let mut parts = Vec::new();
    if instid0 != 0 {
        parts.push(format!("instid0({})", delay_alu_id_name(instid0)));
    }
    if instskip != 0 {
        parts.push(format!("instskip({})", delay_alu_skip_name(instskip)));
    }
    if instid1 != 0 {
        parts.push(format!("instid1({})", delay_alu_id_name(instid1)));
    }
    if parts.is_empty() {
        format!("{:#x}", simm16)
    } else {
        parts.join(" | ")
    }
}

/// `s_delay_alu` instid* field encoding.
fn delay_alu_id_name(id: u16) -> &'static str {
    match id {
        0 => "NO_DEP",
        1 => "VALU_DEP_1",
        2 => "VALU_DEP_2",
        3 => "VALU_DEP_3",
        4 => "VALU_DEP_4",
        5 => "TRANS32_DEP_1",
        6 => "TRANS32_DEP_2",
        7 => "TRANS32_DEP_3",
        8 => "FMA_ACCUM_CYCLE_1",
        9 => "SALU_CYCLE_1",
        10 => "SALU_CYCLE_2",
        11 => "SALU_CYCLE_3",
        _ => "?",
    }
}

/// `s_delay_alu` instskip field encoding.
fn delay_alu_skip_name(skip: u16) -> &'static str {
    match skip {
        0 => "SAME",
        1 => "NEXT",
        2 => "SKIP_1",
        3 => "SKIP_2",
        4 => "SKIP_3",
        5 => "SKIP_4",
        _ => "?",
    }
}

/// numbering shifted between bands so we read it through the
/// family-aware opcode table rather than hard-coding the GFX10
/// numbers.
fn derive_control_flow(class: EncodingClass, dword0: u32, family: EncodingFamily) -> ControlFlow {
    if !matches!(class, EncodingClass::Sopp) {
        return ControlFlow::Sequential;
    }
    let op = ((dword0 >> 16) & 0x7f) as u16;
    if let Some(entry) = opcodes::lookup(opcodes::TableClass::Sopp, family, op) {
        return match entry.operation {
            Operation::Return => ControlFlow::Return,
            // M10.4 left branch targets unrendered on `Operation::Jump` /
            // `Operation::ConditionalJump` — populate_operands handles
            // the PC-relative target. Here we just tag the high-level
            // class.
            _ => ControlFlow::Sequential,
        };
    }
    ControlFlow::Sequential
}
