//! Encoding-class dispatch for AMDGPU.
//!
//! AMDGPU instruction encodings are distinguished by the *high* bits
//! of the first 32-bit dword (read in the architecture's natural
//! little-endian order, so the relevant bits are in the high byte).
//! The table below uses the AMD ISA reference's notation: prefixes
//! are written MSB-first, where bit 31 of the dword is the leftmost
//! bit.
//!
//! ## GFX9 (Vega / CDNA1/2/3)
//!
//! ```text
//!   0_111111 ........ ........ ........   VOP1            (32-bit)
//!   0_111110 ........ ........ ........   VOPC            (32-bit)
//!   0_xxxxxx ........ ........ ........   VOP2            (32-bit, fallthrough)
//!   1011 .... ........ ........ ........   SOPK           (32-bit)
//!   10_1111101 ...... ........ ........   SOP1            (32-bit)
//!   10_1111110 ...... ........ ........   SOPC            (32-bit)
//!   10_1111111 ...... ........ ........   SOPP            (32-bit)
//!   10_xxxxxxx ...... ........ ........   SOP2            (32-bit, fallthrough)
//!   110000 ..  ........ ........ ........   SMEM          (64-bit)
//!   110001 ..  ........ ........ ........   EXP           (64-bit)
//!   110100 ..  ........ ........ ........   VOP3A/B       (64-bit)
//!   110110 ..  ........ ........ ........   DS            (64-bit)
//!   110111 ..  ........ ........ ........   FLAT          (64-bit)
//!   111000 ..  ........ ........ ........   MUBUF         (64-bit)
//!   111010 ..  ........ ........ ........   MTBUF         (64-bit)
//!   111100 ..  ........ ........ ........   MIMG          (64-bit)
//! ```
//!
//! ## GFX10+ (RDNA1/2/3/4)
//!
//! Same as GFX9 *except*:
//!
//! ```text
//!   110101 ..  ........ ........ ........   VOP3A/B       (was 110100)
//!   111101 ..  ........ ........ ........   SMEM          (was 110000)
//!   111110 ..  ........ ........ ........   EXP           (was 110001)
//! ```
//!
//! Source: AMD ISA reference manuals (Vega Shader ISA, RDNA Shader ISA),
//! cross-checked with codex spot-decodes against `llvm-mc -triple
//! amdgcn-amd-amdhsa --show-encoding` for gfx906, gfx1030, gfx1100,
//! gfx1200.

/// Encoding family bands the dispatcher knows about.
///
/// The encoding-*class* prefix layout is shared across GFX10 / GFX11
/// / GFX12 (only OP numbers within each class change). This enum
/// drives both prefix dispatch (`decode_class`) and the per-class
/// opcode-table lookup (`opcodes::table_for`). RDNA3 (GFX11)
/// renumbered VOP2 / VOP3 / SOPP / SOP1 / SMEM / FLAT *substantially*
/// from RDNA2 — most visibly `s_endpgm` shifted from SOPP OP=0x01 to
/// 0x30 and `v_mad_u64_u32` shifted from VOP3 OP=0x176 to 0x2fe — so
/// it gets its own band.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncodingFamily {
    /// GFX6-9 (GCN3/4/5, CDNA1/2/3) — uses the older VOP3/SMEM/EXP
    /// prefix layout and GFX9 OP numbering.
    Gfx9,
    /// GFX10 (RDNA1, RDNA2 — gfx10xx). Shares the GFX10+ prefix
    /// layout with GFX11/GFX12 but has RDNA2-specific OP numbering.
    Gfx10Plus,
    /// GFX11 (RDNA3 — gfx11xx) and GFX12 (RDNA4 — gfx12xx). Shares
    /// the GFX10+ prefix layout but uses RDNA3+ OP numbering.
    Gfx11Plus,
}

/// Top-level instruction class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncodingClass {
    /// Single-source vector ALU (32-bit).
    Vop1,
    /// Two-source vector ALU (32-bit).
    Vop2,
    /// Vector compare (32-bit).
    Vopc,
    /// Three-source / extended vector ALU (64-bit).
    Vop3a,
    /// VOP3 with a separate dst (64-bit).
    Vop3b,
    /// Two-source scalar ALU (32-bit).
    Sop2,
    /// Single-source scalar ALU (32-bit).
    Sop1,
    /// Scalar compare (32-bit).
    Sopc,
    /// Scalar with 16-bit immediate (32-bit).
    Sopk,
    /// Scalar program-flow / control (32-bit). `s_endpgm`, branches.
    Sopp,
    /// Scalar memory (64-bit).
    Smem,
    /// Untyped buffer (64-bit).
    Mubuf,
    /// Typed buffer (64-bit).
    Mtbuf,
    /// Image (64-bit).
    Mimg,
    /// LDS / GDS (64-bit).
    Ds,
    /// Flat / Global / Scratch (64-bit).
    Flat,
    /// Pixel-shader export (64-bit).
    Exp,
    /// Class could not be determined.
    Unknown,
}

impl EncodingClass {
    /// Encoding size in bytes (4 or 8). `Unknown` defaults to 4 so the
    /// walker advances rather than getting stuck.
    pub fn encoding_size(self) -> usize {
        match self {
            Self::Vop1
            | Self::Vop2
            | Self::Vopc
            | Self::Sop1
            | Self::Sop2
            | Self::Sopc
            | Self::Sopk
            | Self::Sopp
            | Self::Unknown => 4,
            Self::Vop3a
            | Self::Vop3b
            | Self::Smem
            | Self::Mubuf
            | Self::Mtbuf
            | Self::Mimg
            | Self::Ds
            | Self::Flat
            | Self::Exp => 8,
        }
    }

    /// Lowercase short name (used as a placeholder mnemonic until
    /// M10.4 fills in the real opcode table).
    pub fn short_name(self) -> &'static str {
        match self {
            Self::Vop1 => "vop1",
            Self::Vop2 => "vop2",
            Self::Vopc => "vopc",
            Self::Vop3a => "vop3",
            Self::Vop3b => "vop3b",
            Self::Sop1 => "sop1",
            Self::Sop2 => "sop2",
            Self::Sopc => "sopc",
            Self::Sopk => "sopk",
            Self::Sopp => "sopp",
            Self::Smem => "smem",
            Self::Mubuf => "mubuf",
            Self::Mtbuf => "mtbuf",
            Self::Mimg => "mimg",
            Self::Ds => "ds",
            Self::Flat => "flat",
            Self::Exp => "exp",
            Self::Unknown => "unknown",
        }
    }
}

/// Classify a single 32-bit dword using the family band's prefix
/// layout.
///
/// Reads bits [31:23] (top 9 bits) for the most precise distinction
/// between SOP1/SOPC/SOPP/SOP2 and VOP1/VOPC/VOP2; falls through to
/// the 6-bit prefix for the 64-bit families.
pub fn decode_class(dword: u32, family: EncodingFamily) -> EncodingClass {
    let top9 = (dword >> 23) & 0x1ff; // bits [31:23]
    let top6 = (dword >> 26) & 0x3f; // bits [31:26]
    let top4 = (dword >> 28) & 0xf; // bits [31:28]
    let top2 = (dword >> 30) & 0x3; // bits [31:30]

    // VOP family: bit [31] = 0.
    if (dword >> 31) == 0 {
        // VOP1: top 7 bits = 0_111111.
        if (dword >> 25) & 0x7f == 0b011_1111 {
            return EncodingClass::Vop1;
        }
        // VOPC: top 7 bits = 0_111110.
        if (dword >> 25) & 0x7f == 0b011_1110 {
            return EncodingClass::Vopc;
        }
        return EncodingClass::Vop2;
    }

    // SOP*: bits [31:30] = 10. SOP1 / SOPC / SOPP carry distinguishing
    // bits in [29:23] and *must be checked before* SOPK — their top4
    // is 1011 (same as SOPK), so a SOPK-first dispatch swallows
    // s_endpgm and friends.
    if top2 == 0b10 {
        match top9 {
            0b10_1111101 => return EncodingClass::Sop1,
            0b10_1111110 => return EncodingClass::Sopc,
            0b10_1111111 => return EncodingClass::Sopp,
            _ => {}
        }
    }

    // SOPK: bits [31:28] = 1011 (with the SOP1/C/P top9 patterns
    // above already excluded).
    if top4 == 0b1011 {
        return EncodingClass::Sopk;
    }

    // SOP2 is the fallthrough for bit pattern `10xxxxxx` once SOP1/C/P
    // and SOPK have been excluded.
    if top2 == 0b10 {
        return EncodingClass::Sop2;
    }

    // 64-bit families: bits [31:30] = 11.
    if top2 == 0b11 {
        match family {
            // VOP3A and VOP3B share the same top6 prefix; the
            // sub-format is selected by the OP code inside the
            // 64-bit instruction. M10.3 dispatches both to
            // `Vop3a` and the per-class decoder (M10.4) refines.
            EncodingFamily::Gfx9 => match top6 {
                0b110000 => return EncodingClass::Smem,
                0b110001 => return EncodingClass::Exp,
                0b110100 => return EncodingClass::Vop3a,
                0b110110 => return EncodingClass::Ds,
                0b110111 => return EncodingClass::Flat,
                0b111000 => return EncodingClass::Mubuf,
                0b111010 => return EncodingClass::Mtbuf,
                0b111100 => return EncodingClass::Mimg,
                _ => {}
            },
            EncodingFamily::Gfx10Plus | EncodingFamily::Gfx11Plus => match top6 {
                0b110101 => return EncodingClass::Vop3a,
                0b110110 => return EncodingClass::Ds,
                0b110111 => return EncodingClass::Flat,
                0b111000 => return EncodingClass::Mubuf,
                0b111010 => return EncodingClass::Mtbuf,
                0b111100 => return EncodingClass::Mimg,
                0b111101 => return EncodingClass::Smem,
                0b111110 => return EncodingClass::Exp,
                _ => {}
            },
        }
    }

    EncodingClass::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vop1_v_mov_b32_decodes_to_vop1() {
        // From llvm-mc:
        //   v_mov_b32_e32 v0, v1   ; encoding: [0x01,0x03,0x00,0x7e]
        let dword = u32::from_le_bytes([0x01, 0x03, 0x00, 0x7e]);
        assert_eq!(
            decode_class(dword, EncodingFamily::Gfx9),
            EncodingClass::Vop1
        );
        assert_eq!(
            decode_class(dword, EncodingFamily::Gfx10Plus),
            EncodingClass::Vop1
        );
    }

    #[test]
    fn sop2_s_add_u32_decodes_to_sop2() {
        // s_add_u32 s0, s1, s2 ; encoding: [0x01,0x02,0x00,0x80]
        let dword = u32::from_le_bytes([0x01, 0x02, 0x00, 0x80]);
        assert_eq!(
            decode_class(dword, EncodingFamily::Gfx9),
            EncodingClass::Sop2
        );
    }

    #[test]
    fn vopc_decodes_to_vopc() {
        // v_cmp_eq_u32_e32 vcc_lo, v1, v2 ; encoding: [0x01,0x05,0x94,0x7c]
        let dword = u32::from_le_bytes([0x01, 0x05, 0x94, 0x7c]);
        assert_eq!(
            decode_class(dword, EncodingFamily::Gfx10Plus),
            EncodingClass::Vopc
        );
    }

    #[test]
    fn vop3_prefix_shifts_between_gfx9_and_gfx10() {
        // GFX9 VOP3A: top6 = 110100. Top byte = 1101_00xx, so any
        // value in 0xD0..=0xD3 in the high byte. Use 0xD0_00_00_00.
        let dword_gfx9 = 0xd0_00_00_00u32;
        assert_eq!(
            decode_class(dword_gfx9, EncodingFamily::Gfx9),
            EncodingClass::Vop3a
        );
        // Same dword on GFX10+: top6 = 110100 not in that family's
        // table (GFX10+ moved VOP3 to 110101), falls through.
        assert_eq!(
            decode_class(dword_gfx9, EncodingFamily::Gfx10Plus),
            EncodingClass::Unknown
        );

        // GFX10+ VOP3A: top6 = 110101. Top byte = 1101_01xx ∈
        // 0xD4..=0xD7. Use 0xD4_00_00_00.
        let dword_gfx10 = 0xd4_00_00_00u32;
        assert_eq!(
            decode_class(dword_gfx10, EncodingFamily::Gfx10Plus),
            EncodingClass::Vop3a
        );
        // Same dword on GFX9: top6 = 110101 isn't in the GFX9 table
        // (GFX9 uses 110100), so Unknown.
        assert_eq!(
            decode_class(dword_gfx10, EncodingFamily::Gfx9),
            EncodingClass::Unknown
        );
    }

    #[test]
    fn smem_prefix_shifts_between_gfx9_and_gfx10() {
        // GFX9 SMEM: top6 = 110000 → top byte = 1100_00xx, so
        // 0xC0..=0xC3. Use 0xC0_00_00_00.
        let dword_gfx9 = 0xc0_00_00_00u32;
        assert_eq!(
            decode_class(dword_gfx9, EncodingFamily::Gfx9),
            EncodingClass::Smem
        );
        // GFX10+ SMEM: top6 = 111101 → top byte = 1111_01xx, so
        // 0xF4..=0xF7. Use 0xF4_00_00_00.
        let dword_gfx10 = 0xf4_00_00_00u32;
        assert_eq!(
            decode_class(dword_gfx10, EncodingFamily::Gfx10Plus),
            EncodingClass::Smem
        );
    }

    #[test]
    fn encoding_size_matches_class() {
        assert_eq!(EncodingClass::Vop1.encoding_size(), 4);
        assert_eq!(EncodingClass::Vop2.encoding_size(), 4);
        assert_eq!(EncodingClass::Vopc.encoding_size(), 4);
        assert_eq!(EncodingClass::Sop2.encoding_size(), 4);
        assert_eq!(EncodingClass::Sopp.encoding_size(), 4);
        assert_eq!(EncodingClass::Vop3a.encoding_size(), 8);
        assert_eq!(EncodingClass::Smem.encoding_size(), 8);
        assert_eq!(EncodingClass::Mubuf.encoding_size(), 8);
        assert_eq!(EncodingClass::Ds.encoding_size(), 8);
        assert_eq!(EncodingClass::Unknown.encoding_size(), 4);
    }

    /// Build a 32-bit dword with the given 9-bit top prefix in bits
    /// `[31:23]`. The remaining bits are zero.
    fn dword_with_top9(top9: u32) -> u32 {
        (top9 & 0x1ff) << 23
    }

    /// Build a 32-bit dword with the given 6-bit top prefix in bits
    /// `[31:26]`.
    fn dword_with_top6(top6: u32) -> u32 {
        (top6 & 0x3f) << 26
    }

    #[test]
    fn sop1_top9_distinguishes_from_sop2_and_sopk() {
        // SOP1: top9 = 1011_11101.
        let dword = dword_with_top9(0b1_0111_1101);
        assert_eq!(
            decode_class(dword, EncodingFamily::Gfx9),
            EncodingClass::Sop1
        );
        assert_eq!(
            decode_class(dword, EncodingFamily::Gfx10Plus),
            EncodingClass::Sop1
        );
    }

    #[test]
    fn sopc_top9_distinguishes_from_sop2_and_sopk() {
        // SOPC: top9 = 1011_11110.
        let dword = dword_with_top9(0b1_0111_1110);
        assert_eq!(
            decode_class(dword, EncodingFamily::Gfx9),
            EncodingClass::Sopc
        );
    }

    #[test]
    fn sopp_top9_classified_before_sopk() {
        // SOPP: top9 = 1011_11111. The literal `s_endpgm` from the
        // end-to-end test (`0xbf810000`) has the same prefix.
        let dword = dword_with_top9(0b1_0111_1111);
        assert_eq!(
            decode_class(dword, EncodingFamily::Gfx9),
            EncodingClass::Sopp
        );
    }

    #[test]
    fn sopk_top4_dispatches_when_no_sop1_or_sopc_prefix() {
        // SOPK: top4 = 1011, but with a top9 outside the SOP1/C/P
        // patterns (1111101 / 1111110 / 1111111). Use top9 =
        // 1011_00000 = 0x160 — top4 still 1011, top byte 0xB0.
        let dword = dword_with_top9(0b1_0110_0000);
        assert_eq!(
            decode_class(dword, EncodingFamily::Gfx9),
            EncodingClass::Sopk
        );
    }

    #[test]
    fn gfx9_exp_classified_at_top6_110001() {
        // EXP on GFX9: top6 = 110001 → top byte 1100_01xx.
        let dword = dword_with_top6(0b110001);
        assert_eq!(
            decode_class(dword, EncodingFamily::Gfx9),
            EncodingClass::Exp
        );
        // GFX10+ moved EXP to 111110, so the GFX9 prefix shouldn't
        // resolve to EXP there.
        assert_ne!(
            decode_class(dword, EncodingFamily::Gfx10Plus),
            EncodingClass::Exp
        );
    }

    #[test]
    fn ds_classified_at_top6_110110_on_both_bands() {
        // DS lives at the same prefix on GFX9 and GFX10+.
        let dword = dword_with_top6(0b110110);
        assert_eq!(decode_class(dword, EncodingFamily::Gfx9), EncodingClass::Ds);
        assert_eq!(
            decode_class(dword, EncodingFamily::Gfx10Plus),
            EncodingClass::Ds
        );
    }

    #[test]
    fn flat_classified_at_top6_110111_on_both_bands() {
        let dword = dword_with_top6(0b110111);
        assert_eq!(
            decode_class(dword, EncodingFamily::Gfx9),
            EncodingClass::Flat
        );
        assert_eq!(
            decode_class(dword, EncodingFamily::Gfx10Plus),
            EncodingClass::Flat
        );
    }

    #[test]
    fn mubuf_classified_at_top6_111000_on_both_bands() {
        let dword = dword_with_top6(0b111000);
        assert_eq!(
            decode_class(dword, EncodingFamily::Gfx9),
            EncodingClass::Mubuf
        );
        assert_eq!(
            decode_class(dword, EncodingFamily::Gfx10Plus),
            EncodingClass::Mubuf
        );
    }

    #[test]
    fn mtbuf_classified_at_top6_111010_on_both_bands() {
        let dword = dword_with_top6(0b111010);
        assert_eq!(
            decode_class(dword, EncodingFamily::Gfx9),
            EncodingClass::Mtbuf
        );
        assert_eq!(
            decode_class(dword, EncodingFamily::Gfx10Plus),
            EncodingClass::Mtbuf
        );
    }

    #[test]
    fn mimg_classified_at_top6_111100_on_both_bands() {
        let dword = dword_with_top6(0b111100);
        assert_eq!(
            decode_class(dword, EncodingFamily::Gfx9),
            EncodingClass::Mimg
        );
        assert_eq!(
            decode_class(dword, EncodingFamily::Gfx10Plus),
            EncodingClass::Mimg
        );
    }

    #[test]
    fn gfx10_exp_at_top6_111110_does_not_resolve_on_gfx9() {
        // GFX10+ moved EXP to 111110.
        let dword = dword_with_top6(0b111110);
        assert_eq!(
            decode_class(dword, EncodingFamily::Gfx10Plus),
            EncodingClass::Exp
        );
        // GFX9 doesn't have EXP at this prefix.
        assert_eq!(
            decode_class(dword, EncodingFamily::Gfx9),
            EncodingClass::Unknown
        );
    }
}
