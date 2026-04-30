//! AMDGPU `amdhsa_kernel_descriptor_t` decoding.
//!
//! Every AMDGPU kernel has a 64-byte descriptor block in the code
//! object's `.rodata` section, addressed by a symbol named
//! `<kernel>.kd`. The runtime reads this block to set up the wave's
//! register allocation, LDS, scratch, kernarg pointer, and entry
//! point before launching the kernel.
//!
//! Layout (`amdgpu_kernel_descriptor_t`):
//!
//! ```text
//!   u32 group_segment_fixed_size           // 0..4   — static LDS bytes
//!   u32 private_segment_fixed_size         // 4..8   — static scratch bytes
//!   u32 kernarg_size                       // 8..12  — kernel-arg buffer size
//!   u8  reserved0[4]                       // 12..16
//!   i64 kernel_code_entry_byte_offset      // 16..24 — entry offset from KD addr
//!   u8  reserved1[20]                      // 24..44
//!   u32 compute_pgm_rsrc3                  // 44..48 (GFX10+ wave32, MFMA on CDNA)
//!   u32 compute_pgm_rsrc1                  // 48..52 — vgpr/sgpr counts, fp modes
//!   u32 compute_pgm_rsrc2                  // 52..56 — LDS size, kernarg setup
//!   u16 kernel_code_properties             // 56..58 — enable_sgpr_*
//!   u16 kernarg_preload                    // 58..60
//!   u8  reserved3[4]                       // 60..64
//! ```
//!
//! Source: `llvm/include/llvm/Support/AMDHSAKernelDescriptor.h`,
//! cross-checked against `lld/test/ELF/amdgpu-*` golden outputs.

// File-level allow: bit-math + slice indexing in this parser/decoder
// is bounds-checked at function entry. Per-site annotations would be
// noise; the runtime fuzz gate (`scripts/run-fuzz-corpus`) catches
// actual crashes. New code should prefer `.get()` + `checked_*`.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use crate::ParseError;

/// The fixed size of an AMDGPU kernel descriptor.
pub const KERNEL_DESCRIPTOR_SIZE: usize = 64;

/// Parsed AMDGPU kernel descriptor.
///
/// All fields are exposed both as their raw 32-bit `compute_pgm_rsrc*`
/// values and as decoded counts where decoding is unambiguous. The raw
/// values are retained so callers (the `hexray cmp` subcommand,
/// signature recovery) can diff them directly without going through
/// the lossy decoded forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelDescriptor {
    /// Static LDS size in bytes (group segment).
    pub group_segment_fixed_size: u32,
    /// Static scratch size in bytes (private segment).
    pub private_segment_fixed_size: u32,
    /// Kernel-argument buffer size in bytes.
    pub kernarg_size: u32,
    /// Signed offset from the descriptor's load address to the entry
    /// instruction. Always positive on real binaries; the type is
    /// signed for symmetry with LLVM's `int64_t`.
    pub kernel_code_entry_byte_offset: i64,
    /// Raw COMPUTE_PGM_RSRC3 word (GFX10+ wave32 control, CDNA MFMA
    /// behavior).
    pub compute_pgm_rsrc3: u32,
    /// Raw COMPUTE_PGM_RSRC1 word (vgpr / sgpr counts, FP modes).
    pub compute_pgm_rsrc1: u32,
    /// Raw COMPUTE_PGM_RSRC2 word (LDS size, kernarg setup, exception
    /// flags).
    pub compute_pgm_rsrc2: u32,
    /// Raw `kernel_code_properties` word (enable_sgpr_*).
    pub kernel_code_properties: u16,
    /// Kernarg preload control (GFX9.4+ / CDNA3).
    pub kernarg_preload: u16,
}

impl KernelDescriptor {
    /// Parse a 64-byte descriptor.
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        if bytes.len() < KERNEL_DESCRIPTOR_SIZE {
            return Err(ParseError::too_short(KERNEL_DESCRIPTOR_SIZE, bytes.len()));
        }
        let read_u32 =
            |o: usize| u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]);
        let read_u16 = |o: usize| u16::from_le_bytes([bytes[o], bytes[o + 1]]);
        let read_i64 = |o: usize| {
            i64::from_le_bytes([
                bytes[o],
                bytes[o + 1],
                bytes[o + 2],
                bytes[o + 3],
                bytes[o + 4],
                bytes[o + 5],
                bytes[o + 6],
                bytes[o + 7],
            ])
        };

        Ok(Self {
            group_segment_fixed_size: read_u32(0),
            private_segment_fixed_size: read_u32(4),
            kernarg_size: read_u32(8),
            kernel_code_entry_byte_offset: read_i64(16),
            compute_pgm_rsrc3: read_u32(44),
            compute_pgm_rsrc1: read_u32(48),
            compute_pgm_rsrc2: read_u32(52),
            kernel_code_properties: read_u16(56),
            kernarg_preload: read_u16(58),
        })
    }

    /// Decoded VGPR count.
    ///
    /// Stored as `granulated_workitem_vgpr_count` in
    /// COMPUTE_PGM_RSRC1[5:0]. The runtime allocates registers in
    /// granules whose size depends on the family and wave size:
    ///
    /// - GFX6-9 wave64: granule = 4 → `vgprs = (raw + 1) * 4`
    /// - GFX10+ wave32: granule = 8 → `vgprs = (raw + 1) * 8`
    /// - GFX10+ wave64: granule = 4 (same as GFX6-9)
    ///
    /// The wave size lives in `kernel_code_properties[10]`
    /// (`ENABLE_WAVEFRONT_SIZE32`); pre-GFX10 hardware ignores it and
    /// runs wave64 unconditionally.
    pub fn vgpr_count(&self, family_major: u8) -> u16 {
        let raw = (self.compute_pgm_rsrc1 & 0x3f) as u16;
        let granule = if family_major >= 10 && self.is_wave32() {
            8
        } else {
            4
        };
        (raw + 1) * granule
    }

    /// Decoded SGPR count.
    ///
    /// `granulated_wavefront_sgpr_count` lives in
    /// COMPUTE_PGM_RSRC1[9:6]; granule is 8 across all families.
    pub fn sgpr_count(&self) -> u16 {
        let raw = ((self.compute_pgm_rsrc1 >> 6) & 0xf) as u16;
        (raw + 1) * 8
    }

    /// True when this kernel runs in wave32 mode (GFX10+ only).
    ///
    /// `ENABLE_WAVEFRONT_SIZE32` lives at `kernel_code_properties[10]`
    /// (per `AMDHSAKernelDescriptor.h`). Pre-GFX10 hardware ignores
    /// this bit and runs wave64 unconditionally.
    pub fn is_wave32(&self) -> bool {
        (self.kernel_code_properties >> 10) & 1 != 0
    }

    /// Decoded LDS size in bytes from
    /// `granulated_lds_size` (COMPUTE_PGM_RSRC2[23:15]).
    ///
    /// Granule is 128 bytes on every GFX target shipping today; the
    /// driver requires this even though older docs sometimes call it
    /// "4 dwords."
    pub fn dynamic_lds_bytes(&self) -> u32 {
        let granulated = (self.compute_pgm_rsrc2 >> 15) & 0x1ff;
        granulated * 128
    }

    /// `user_sgpr_count` from COMPUTE_PGM_RSRC2[5:1].
    pub fn user_sgpr_count(&self) -> u8 {
        ((self.compute_pgm_rsrc2 >> 1) & 0x1f) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a 64-byte descriptor with the given fields. Helper for
    /// tests that don't need a full ELF.
    fn make_descriptor(
        group: u32,
        priv_seg: u32,
        kernarg: u32,
        entry_offset: i64,
        rsrc1: u32,
        rsrc2: u32,
    ) -> [u8; KERNEL_DESCRIPTOR_SIZE] {
        make_descriptor_with_props(group, priv_seg, kernarg, entry_offset, rsrc1, rsrc2, 0)
    }

    fn make_descriptor_with_props(
        group: u32,
        priv_seg: u32,
        kernarg: u32,
        entry_offset: i64,
        rsrc1: u32,
        rsrc2: u32,
        properties: u16,
    ) -> [u8; KERNEL_DESCRIPTOR_SIZE] {
        let mut buf = [0u8; KERNEL_DESCRIPTOR_SIZE];
        buf[0..4].copy_from_slice(&group.to_le_bytes());
        buf[4..8].copy_from_slice(&priv_seg.to_le_bytes());
        buf[8..12].copy_from_slice(&kernarg.to_le_bytes());
        buf[16..24].copy_from_slice(&entry_offset.to_le_bytes());
        buf[48..52].copy_from_slice(&rsrc1.to_le_bytes());
        buf[52..56].copy_from_slice(&rsrc2.to_le_bytes());
        buf[56..58].copy_from_slice(&properties.to_le_bytes());
        buf
    }

    #[test]
    fn descriptor_round_trips_static_fields() {
        let buf = make_descriptor(256, 0, 24, 0x100, 0, 0);
        let d = KernelDescriptor::parse(&buf).unwrap();
        assert_eq!(d.group_segment_fixed_size, 256);
        assert_eq!(d.private_segment_fixed_size, 0);
        assert_eq!(d.kernarg_size, 24);
        assert_eq!(d.kernel_code_entry_byte_offset, 0x100);
    }

    #[test]
    fn vgpr_decode_respects_family_and_wave_size() {
        // raw=2 → (2+1)*4 = 12 vgprs on GFX9 (wave64).
        let buf = make_descriptor(0, 0, 0, 0, 0x02, 0);
        let d = KernelDescriptor::parse(&buf).unwrap();
        assert_eq!(d.vgpr_count(9), 12);

        // Same raw value on GFX10 wave64 (bit 28 = 0): also 12.
        assert_eq!(d.vgpr_count(10), 12);

        // GFX10 wave32 (kernel_code_properties bit 10 = 1):
        // raw=2 → (2+1)*8 = 24 vgprs.
        let buf = make_descriptor_with_props(0, 0, 0, 0, 0x02, 0, 1 << 10);
        let d = KernelDescriptor::parse(&buf).unwrap();
        assert!(d.is_wave32());
        assert_eq!(d.vgpr_count(10), 24);
    }

    #[test]
    fn sgpr_decode_uses_8_granule() {
        // raw=1 in bits [9:6] = 0x40 → (1+1)*8 = 16 sgprs.
        let buf = make_descriptor(0, 0, 0, 0, 0x40, 0);
        let d = KernelDescriptor::parse(&buf).unwrap();
        assert_eq!(d.sgpr_count(), 16);

        // raw=0 → 8 sgprs (the minimum allocation).
        let buf = make_descriptor(0, 0, 0, 0, 0, 0);
        let d = KernelDescriptor::parse(&buf).unwrap();
        assert_eq!(d.sgpr_count(), 8);
    }

    #[test]
    fn lds_decode_in_128_byte_granules() {
        // granulated_lds_size = 4 (in bits [23:15]) → 4 * 128 = 512 bytes.
        let rsrc2 = 4u32 << 15;
        let buf = make_descriptor(0, 0, 0, 0, 0, rsrc2);
        let d = KernelDescriptor::parse(&buf).unwrap();
        assert_eq!(d.dynamic_lds_bytes(), 512);
    }

    #[test]
    fn user_sgpr_count_extracted() {
        // user_sgpr_count = 6 in bits [5:1] = 6 << 1 = 0xC.
        let rsrc2 = 6u32 << 1;
        let buf = make_descriptor(0, 0, 0, 0, 0, rsrc2);
        let d = KernelDescriptor::parse(&buf).unwrap();
        assert_eq!(d.user_sgpr_count(), 6);
    }

    #[test]
    fn parse_rejects_short_buffer() {
        let buf = [0u8; 32];
        assert!(KernelDescriptor::parse(&buf).is_err());
    }

    #[test]
    fn entry_offset_decodes_all_eight_bytes() {
        // The previous round-trip test used 0x100, which only hits
        // the low byte. Use a value with non-zero bytes in every
        // position so each `bytes[o + N]` index has to read the
        // right slot — any off-by-one in the indices would be
        // visible as a wrong magnitude.
        let entry_offset: i64 = 0x1234_5678_9ABC_DEF0;
        let buf = make_descriptor(0, 0, 0, entry_offset, 0, 0);
        let d = KernelDescriptor::parse(&buf).unwrap();
        assert_eq!(d.kernel_code_entry_byte_offset, entry_offset);
    }

    #[test]
    fn entry_offset_negative_round_trips_signed() {
        // Negative i64 forces all eight bytes to be 0xFF — useful for
        // catching mutations that swap byte order or drop a byte.
        // (-1 still ends up all 0xff but we use a more interesting
        // value to also catch mid-byte mutations.)
        let entry_offset: i64 = -0x0102_0304_0506_0708;
        let buf = make_descriptor(0, 0, 0, entry_offset, 0, 0);
        let d = KernelDescriptor::parse(&buf).unwrap();
        assert_eq!(d.kernel_code_entry_byte_offset, entry_offset);
    }

    #[test]
    fn vgpr_decode_at_max_raw_value() {
        // raw = 63 (max value of bits [5:0]) on GFX9 wave64 →
        // (63 + 1) * 4 = 256 vgprs. Catches mutations that turn
        // `(raw + 1) * granule` into `raw * granule`.
        let buf = make_descriptor(0, 0, 0, 0, 0x3f, 0);
        let d = KernelDescriptor::parse(&buf).unwrap();
        assert_eq!(d.vgpr_count(9), 256);
    }

    #[test]
    fn sgpr_decode_at_max_raw_value() {
        // raw = 15 (max value of bits [9:6]) → (15 + 1) * 8 = 128
        // sgprs.
        let buf = make_descriptor(0, 0, 0, 0, 0xf << 6, 0);
        let d = KernelDescriptor::parse(&buf).unwrap();
        assert_eq!(d.sgpr_count(), 128);
    }

    #[test]
    fn lds_decode_zero_granulated_yields_zero_bytes() {
        // granulated_lds_size = 0 → 0 * 128 = 0. Pins the
        // multiplication and the 0x1ff mask.
        let buf = make_descriptor(0, 0, 0, 0, 0, 0);
        let d = KernelDescriptor::parse(&buf).unwrap();
        assert_eq!(d.dynamic_lds_bytes(), 0);
    }

    #[test]
    fn lds_decode_max_granulated_yields_correct_bytes() {
        // granulated_lds_size = 0x1ff (max in 9 bits) → 0x1ff * 128.
        let rsrc2 = 0x1ffu32 << 15;
        let buf = make_descriptor(0, 0, 0, 0, 0, rsrc2);
        let d = KernelDescriptor::parse(&buf).unwrap();
        assert_eq!(d.dynamic_lds_bytes(), 0x1ff * 128);
    }

    #[test]
    fn user_sgpr_count_extracts_max_value() {
        // user_sgpr_count = 31 (max of bits [5:1]) → 0x1f << 1 = 0x3E.
        let rsrc2 = 31u32 << 1;
        let buf = make_descriptor(0, 0, 0, 0, 0, rsrc2);
        let d = KernelDescriptor::parse(&buf).unwrap();
        assert_eq!(d.user_sgpr_count(), 31);
    }

    #[test]
    fn is_wave32_reads_bit_ten_only() {
        // Set every bit of `kernel_code_properties` *except* bit 10:
        // is_wave32 must still return false. This pins the shift to
        // `>> 10` rather than `>> 9` or `>> 11`.
        let props: u16 = !(1u16 << 10);
        let buf = make_descriptor_with_props(0, 0, 0, 0, 0, 0, props);
        let d = KernelDescriptor::parse(&buf).unwrap();
        assert!(
            !d.is_wave32(),
            "bit 10 was clear; is_wave32 should be false"
        );

        // Now flip just bit 10 — must read true.
        let buf = make_descriptor_with_props(0, 0, 0, 0, 0, 0, 1 << 10);
        let d = KernelDescriptor::parse(&buf).unwrap();
        assert!(d.is_wave32(), "bit 10 set should yield wave32 = true");
    }

    #[test]
    fn vgpr_count_pre_gfx10_ignores_wave32_bit() {
        // Pre-GFX10 hardware (family_major < 10) must always use the
        // wave64 granule (4) regardless of the wave32 property bit.
        let buf = make_descriptor_with_props(0, 0, 0, 0, 0x02, 0, 1 << 10);
        let d = KernelDescriptor::parse(&buf).unwrap();
        // family_major = 9 → still wave64 → (2 + 1) * 4 = 12.
        assert_eq!(d.vgpr_count(9), 12);
    }

    #[test]
    fn vgpr_count_gfx10_wave64_uses_4_granule() {
        // family_major = 10 with wave32 disabled → granule = 4.
        // raw = 1 → (1 + 1) * 4 = 8.
        let buf = make_descriptor(0, 0, 0, 0, 1, 0);
        let d = KernelDescriptor::parse(&buf).unwrap();
        assert_eq!(d.vgpr_count(10), 8);
    }

    #[test]
    fn descriptor_round_trips_all_kernarg_size_bytes() {
        // The previous round-trip test used 24 (only the low byte).
        // Use a 4-byte value to pin every byte of the read_u32 helper.
        let buf = make_descriptor(0xDEAD_BEEF, 0xCAFE_F00D, 0x1234_5678, 0, 0, 0);
        let d = KernelDescriptor::parse(&buf).unwrap();
        assert_eq!(d.group_segment_fixed_size, 0xDEAD_BEEF);
        assert_eq!(d.private_segment_fixed_size, 0xCAFE_F00D);
        assert_eq!(d.kernarg_size, 0x1234_5678);
    }

    #[test]
    fn rsrc1_rsrc2_round_trip_full_words() {
        // The decoded sub-fields can mask away byte-order mistakes, so
        // assert the raw words round-trip across all four bytes.
        let mut buf = [0u8; KERNEL_DESCRIPTOR_SIZE];
        buf[44..48].copy_from_slice(&0xAABBCCDDu32.to_le_bytes());
        buf[48..52].copy_from_slice(&0x11223344u32.to_le_bytes());
        buf[52..56].copy_from_slice(&0x55667788u32.to_le_bytes());
        buf[58..60].copy_from_slice(&0x99AAu16.to_le_bytes()); // kernarg_preload
        let d = KernelDescriptor::parse(&buf).unwrap();
        assert_eq!(d.compute_pgm_rsrc3, 0xAABBCCDD);
        assert_eq!(d.compute_pgm_rsrc1, 0x11223344);
        assert_eq!(d.compute_pgm_rsrc2, 0x55667788);
        assert_eq!(d.kernarg_preload, 0x99AA);
    }
}
