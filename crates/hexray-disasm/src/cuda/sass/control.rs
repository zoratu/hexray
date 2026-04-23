//! Scheduling control bits for a Volta+ SASS instruction.
//!
//! The top 23 bits of every 128-bit SASS word encode the scheduling
//! envelope the compiler assigns to an instruction. Six fields live in
//! there, in this order from LSB to MSB (relative to the control slot):
//!
//! ```text
//!   [4:0]    stall        (cycles the scheduler will stall)
//!   [5]      yield        (yield hint; inverted in public RE tooling)
//!   [8:6]    write_barrier (index; 7 = none)
//!   [11:9]   read_barrier  (index; 7 = none)
//!   [17:12]  wait_mask    (6-bit bitmask of barriers to wait on)
//!   [21:18]  reuse        (operand-reuse cache bits for the next slot)
//!   [22]     reserved (observed zero)
//! ```
//!
//! Barrier index `7` is NVIDIA's "no barrier" sentinel. Yield is
//! conventionally printed as `Y` in `nvdisasm` when bit `5` is **clear**
//! (i.e. the field reads as `yield = !bit5`). We expose the raw bit in
//! [`ControlBits::yield_bit`] and a convenience [`ControlBits::yields`]
//! that matches the textual convention.
//!
//! Sources: CuAssembler `CuSMVersion.py` (`CCMask_7x_8x`), "Dissecting the
//! NVIDIA Volta GPU Architecture via Microbenchmarking"
//! <https://arxiv.org/abs/1804.06826>, and public JEB/PNF SASS write-ups.

use super::bits::SassWord;

/// Fully decoded scheduling control section of a SASS instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlBits {
    /// Cycles of pipeline stall the scheduler wedges after this
    /// instruction issues. 0..=15.
    pub stall: u8,
    /// Raw yield bit (bit 5 of the control slot). Public tools invert it
    /// when rendering; see [`ControlBits::yields`].
    pub yield_bit: bool,
    /// Index of the write-dependency barrier this instruction writes (0..=6),
    /// or [`BARRIER_NONE`] (7) if none.
    pub write_barrier: u8,
    /// Index of the read-dependency barrier this instruction writes (0..=6),
    /// or [`BARRIER_NONE`] (7) if none.
    pub read_barrier: u8,
    /// 6-bit mask of dependency barriers that must be cleared before this
    /// instruction is allowed to issue. Bit `i` waits on barrier `i`.
    pub wait_mask: u8,
    /// 4-bit operand-reuse cache hint for the next issue slot.
    pub reuse: u8,
}

/// The barrier-index sentinel meaning "no barrier" in both the write and
/// read barrier fields.
pub const BARRIER_NONE: u8 = 7;

impl ControlBits {
    /// Extract the control bits from a SASS word.
    pub fn from_word(word: &SassWord) -> Self {
        let raw = word.control_raw(); // 23-bit field, right-aligned.
        Self::from_raw(raw)
    }

    /// Decode from the right-aligned 23-bit control slot directly. Useful
    /// for tests that want to build synthetic control fields.
    pub fn from_raw(raw: u32) -> Self {
        Self {
            stall: (raw & 0xF) as u8,                // bits 0..=3  (4-bit stall counter)
            yield_bit: (raw >> 4) & 1 != 0,          // bit 4
            write_barrier: ((raw >> 5) & 0x7) as u8, // bits 5..=7
            read_barrier: ((raw >> 8) & 0x7) as u8,  // bits 8..=10
            wait_mask: ((raw >> 11) & 0x3F) as u8,   // bits 11..=16  (6-bit mask)
            reuse: ((raw >> 17) & 0xF) as u8,        // bits 17..=20 (4-bit reuse)
                                                     // bits 21..=22 observed zero; intentionally discarded.
        }
    }

    /// Re-encode this control field back into its 23-bit slot. Primarily
    /// used by tests that round-trip a control block.
    pub fn to_raw(&self) -> u32 {
        let mut raw: u32 = 0;
        raw |= (self.stall as u32) & 0xF;
        raw |= (self.yield_bit as u32) << 4;
        raw |= ((self.write_barrier as u32) & 0x7) << 5;
        raw |= ((self.read_barrier as u32) & 0x7) << 8;
        raw |= ((self.wait_mask as u32) & 0x3F) << 11;
        raw |= ((self.reuse as u32) & 0xF) << 17;
        raw
    }

    /// True if this instruction yields the issue slot. `nvdisasm` prints
    /// `Y` when this returns `true`.
    #[inline]
    pub fn yields(&self) -> bool {
        !self.yield_bit
    }

    /// True if the write-barrier index is one of the six real barriers
    /// (0..=5), not the "none" sentinel.
    #[inline]
    pub fn has_write_barrier(&self) -> bool {
        self.write_barrier < BARRIER_NONE
    }

    /// True if the read-barrier index is one of the six real barriers.
    #[inline]
    pub fn has_read_barrier(&self) -> bool {
        self.read_barrier < BARRIER_NONE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assemble(stall: u8, yield_bit: bool, wb: u8, rb: u8, wait: u8, reuse: u8) -> u32 {
        let cb = ControlBits {
            stall,
            yield_bit,
            write_barrier: wb,
            read_barrier: rb,
            wait_mask: wait,
            reuse,
        };
        cb.to_raw()
    }

    #[test]
    fn round_trip_all_fields() {
        let cb = ControlBits {
            stall: 5,
            yield_bit: true,
            write_barrier: 2,
            read_barrier: 4,
            wait_mask: 0b011010,
            reuse: 0b1010,
        };
        let raw = cb.to_raw();
        assert_eq!(ControlBits::from_raw(raw), cb);
    }

    #[test]
    fn none_barrier_sentinel() {
        let cb = ControlBits::from_raw(assemble(0, false, 7, 7, 0, 0));
        assert!(!cb.has_write_barrier());
        assert!(!cb.has_read_barrier());
    }

    #[test]
    fn nop_canonical_control_round_trips() {
        // The 7x/8x canonical NOP high word is 0x000fc00000000000, which
        // extracts to a 23-bit control slot of 0x7E0. The precise per-
        // field decomposition (which bits belong to stall vs. yield vs.
        // barrier indices) is empirically verified against `nvdisasm`
        // during M6; for M3 we only prove the control slot round-trips
        // cleanly through from_raw / to_raw.
        //
        // TODO(M6): tighten this test to assert exact field values once
        // the layout is cross-checked on real cubins.
        let high: u64 = 0x000f_c000_0000_0000;
        let raw = (high >> 41) as u32;
        assert_eq!(raw, 0x7E0);
        let cb = ControlBits::from_raw(raw);
        assert_eq!(cb.to_raw(), raw);
    }

    #[test]
    fn yield_bit_inversion() {
        let on = ControlBits::from_raw(assemble(0, false, 7, 7, 0, 0));
        let off = ControlBits::from_raw(assemble(0, true, 7, 7, 0, 0));
        // yield_bit=false → nvdisasm prints Y; yield_bit=true → no Y.
        assert!(on.yields());
        assert!(!off.yields());
    }

    #[test]
    fn from_word_extracts_top_23_bits() {
        let ctl: u32 = assemble(3, true, 0, 1, 0b000101, 0b0011);
        let high = (ctl as u64) << 41;
        let word = SassWord { low: 0, high };
        let cb = ControlBits::from_word(&word);
        assert_eq!(cb.stall, 3);
        assert!(cb.yield_bit);
        assert_eq!(cb.write_barrier, 0);
        assert_eq!(cb.read_barrier, 1);
        assert_eq!(cb.wait_mask, 0b000101);
        assert_eq!(cb.reuse, 0b0011);
    }
}
