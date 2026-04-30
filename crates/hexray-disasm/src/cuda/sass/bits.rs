//! Low-level bit-field helpers for a 128-bit Volta+ SASS word.
//!
//! A SASS instruction on Volta through Blackwell is a fixed 128-bit word
//! stored little-endian. We carry it around as a [`SassWord`] that owns
//! the two halves; all bit-field extraction goes through [`bit_range`] so
//! no caller has to think about which u64 a given bit lives in.

// File-level allow: bit-math + slice indexing in this parser/decoder
// is bounds-checked at function entry. Per-site annotations would be
// noise; the runtime fuzz gate (`scripts/run-fuzz-corpus`) catches
// actual crashes. New code should prefer `.get()` + `checked_*`.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

/// A raw 128-bit SASS word, low 64 bits and high 64 bits.
///
/// Bit indexing is done as if the word were a single 128-bit value: bit
/// `0` is the LSB of [`Self::low`], bit `63` is the MSB of [`Self::low`],
/// bit `64` is the LSB of [`Self::high`], and bit `127` is the MSB of
/// [`Self::high`]. This matches every public RE source (CuAssembler,
/// Volta/Turing SASS papers, nvdisasm internals).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SassWord {
    pub low: u64,
    pub high: u64,
}

impl SassWord {
    /// Parse a 16-byte little-endian SASS instruction.
    ///
    /// Panics when `bytes.len() < 16`; callers must pre-check. The decoder
    /// never hands `decode_instruction` fewer than 16 bytes.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() >= 16, "SASS instructions are always 16 bytes");
        let low = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let high = u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        Self { low, high }
    }

    /// Returns the raw 128 bits back as a 16-byte little-endian array.
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..8].copy_from_slice(&self.low.to_le_bytes());
        out[8..16].copy_from_slice(&self.high.to_le_bytes());
        out
    }

    /// Extract bits `[high_bit:low_bit]` inclusive on both ends.
    ///
    /// `low_bit` and `high_bit` are 0-based positions in the 128-bit word
    /// using the same convention as the Volta+ public RE literature. Only
    /// ranges of width ≤ 64 are meaningful — the result is returned as a
    /// `u64`. Ranges may span the low/high boundary.
    ///
    /// # Panics
    ///
    /// Debug builds panic if `high_bit < low_bit`, either index is ≥ 128,
    /// or the range is wider than 64 bits.
    #[inline]
    pub fn bit_range(&self, low_bit: u32, high_bit: u32) -> u64 {
        debug_assert!(high_bit < 128, "bit index {high_bit} ≥ 128");
        debug_assert!(
            high_bit >= low_bit,
            "bit_range: high_bit {high_bit} < low_bit {low_bit}"
        );
        let width = high_bit - low_bit + 1;
        debug_assert!(width <= 64, "bit_range: width {width} > 64 bits");
        if width == 64 && low_bit == 0 {
            return self.low;
        }
        if width == 64 && low_bit == 64 {
            return self.high;
        }
        // Treat the pair as a 128-bit value, shift, mask. We do this
        // explicitly to avoid depending on u128 alignment quirks.
        let combined: u128 = (self.high as u128) << 64 | (self.low as u128);
        let mask: u128 = if width == 64 {
            u64::MAX as u128
        } else {
            (1u128 << width) - 1
        };
        ((combined >> low_bit) & mask) as u64
    }

    /// Extract a single bit.
    #[inline]
    pub fn bit(&self, idx: u32) -> bool {
        self.bit_range(idx, idx) != 0
    }

    /// Convenience: the portion of the encoding reserved for opcode /
    /// operand fields — bits `[0:104]` on Volta+. Returns the low 64 bits
    /// of the encoding proper; callers that need higher-order opcode
    /// fields should use [`Self::bit_range`] directly.
    #[inline]
    pub fn encoding_low64(&self) -> u64 {
        self.low
    }

    /// The top 23 bits of the 128-bit word make up the scheduling control
    /// section (reuse / wait / barriers / yield / stall). Returned as a
    /// `u32` right-aligned, exactly as [`super::control::ControlBits`]
    /// decodes it.
    #[inline]
    pub fn control_raw(&self) -> u32 {
        // Bits 105..=127: 23-bit field living in the top of the high half.
        (self.high >> 41) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_matches_little_endian() {
        let bytes = [
            0x18, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0,
            0x0F, 0x00,
        ];
        let w = SassWord::from_bytes(&bytes);
        assert_eq!(w.low, 0x0000_0000_0000_7918);
        assert_eq!(w.high, 0x000f_c000_0000_0000);
    }

    #[test]
    fn round_trip_to_bytes() {
        let w = SassWord {
            low: 0xdead_beef_0000_0001,
            high: 0xcafe_f00d_1234_5678,
        };
        let w2 = SassWord::from_bytes(&w.to_bytes());
        assert_eq!(w, w2);
    }

    #[test]
    fn bit_range_single_word() {
        let w = SassWord {
            low: 0xDEAD_BEEF_CAFE_F00D,
            high: 0,
        };
        assert_eq!(w.bit_range(0, 7), 0x0D);
        assert_eq!(w.bit_range(8, 15), 0xF0);
        assert_eq!(w.bit_range(48, 63), 0xDEAD);
    }

    #[test]
    fn bit_range_spanning_boundary() {
        // Bits 60..=67 straddle the low/high boundary.
        let w = SassWord {
            low: 0xF000_0000_0000_0000,
            high: 0x0000_0000_0000_000F,
        };
        assert_eq!(w.bit_range(60, 67), 0xFF);
    }

    #[test]
    fn bit_range_full_64_low_and_high() {
        let w = SassWord {
            low: 0x0123_4567_89AB_CDEF,
            high: 0xFEDC_BA98_7654_3210,
        };
        assert_eq!(w.bit_range(0, 63), w.low);
        assert_eq!(w.bit_range(64, 127), w.high);
    }

    #[test]
    fn single_bit_accessor() {
        let w = SassWord {
            low: 0b1010,
            high: 0,
        };
        assert!(!w.bit(0));
        assert!(w.bit(1));
        assert!(!w.bit(2));
        assert!(w.bit(3));
    }

    #[test]
    fn control_raw_is_top_23_bits() {
        // Set only the top 23 bits to a pattern.
        let control: u32 = 0x0055_AA55 & 0x007F_FFFF; // 23-bit pattern
        let high = (control as u64) << 41;
        let w = SassWord { low: 0, high };
        assert_eq!(w.control_raw(), control);
    }
}
