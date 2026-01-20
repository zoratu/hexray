//! CPU flags handling for emulation.
//!
//! Tracks the standard x86 flags: CF, ZF, SF, OF, PF, AF.

use crate::value::Value;
use serde::{Deserialize, Serialize};

/// CPU flags register state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Flags {
    /// Carry flag - set on unsigned overflow.
    pub cf: Option<bool>,
    /// Zero flag - set when result is zero.
    pub zf: Option<bool>,
    /// Sign flag - set when result is negative (high bit set).
    pub sf: Option<bool>,
    /// Overflow flag - set on signed overflow.
    pub of: Option<bool>,
    /// Parity flag - set when low byte has even parity.
    pub pf: Option<bool>,
    /// Auxiliary carry flag - set on carry from bit 3 to 4.
    pub af: Option<bool>,
}

impl Flags {
    /// Create new flags with all unknown.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create flags from a concrete value (for test/cmp results).
    pub fn from_result(result: u64, size_bits: u32) -> Self {
        let mask = if size_bits >= 64 {
            u64::MAX
        } else {
            (1u64 << size_bits) - 1
        };
        let sign_bit = 1u64 << (size_bits - 1);
        let masked = result & mask;

        Self {
            cf: None, // Carry depends on the operation
            zf: Some(masked == 0),
            sf: Some((masked & sign_bit) != 0),
            of: None, // Overflow depends on the operation
            pf: Some((masked as u8).count_ones() % 2 == 0),
            af: None, // Auxiliary carry depends on the operation
        }
    }

    /// Update flags for an addition operation.
    pub fn update_add(&mut self, a: u64, b: u64, result: u64, size_bits: u32) {
        let mask = if size_bits >= 64 {
            u64::MAX
        } else {
            (1u64 << size_bits) - 1
        };
        let sign_bit = 1u64 << (size_bits - 1);

        let a_masked = a & mask;
        let b_masked = b & mask;
        let r_masked = result & mask;

        // Zero flag
        self.zf = Some(r_masked == 0);

        // Sign flag
        self.sf = Some((r_masked & sign_bit) != 0);

        // Carry flag (unsigned overflow)
        self.cf = Some(r_masked < a_masked);

        // Overflow flag (signed overflow)
        // Overflow if: same sign operands produce different sign result
        let a_sign = (a_masked & sign_bit) != 0;
        let b_sign = (b_masked & sign_bit) != 0;
        let r_sign = (r_masked & sign_bit) != 0;
        self.of = Some((a_sign == b_sign) && (a_sign != r_sign));

        // Parity flag (low byte)
        self.pf = Some((r_masked as u8).count_ones() % 2 == 0);

        // Auxiliary carry (carry from bit 3 to 4)
        self.af = Some(((a & 0xF) + (b & 0xF)) > 0xF);
    }

    /// Update flags for a subtraction operation.
    pub fn update_sub(&mut self, a: u64, b: u64, result: u64, size_bits: u32) {
        let mask = if size_bits >= 64 {
            u64::MAX
        } else {
            (1u64 << size_bits) - 1
        };
        let sign_bit = 1u64 << (size_bits - 1);

        let a_masked = a & mask;
        let b_masked = b & mask;
        let r_masked = result & mask;

        // Zero flag
        self.zf = Some(r_masked == 0);

        // Sign flag
        self.sf = Some((r_masked & sign_bit) != 0);

        // Carry flag (borrow)
        self.cf = Some(a_masked < b_masked);

        // Overflow flag (signed overflow)
        // Overflow if: different sign operands and result sign differs from first operand
        let a_sign = (a_masked & sign_bit) != 0;
        let b_sign = (b_masked & sign_bit) != 0;
        let r_sign = (r_masked & sign_bit) != 0;
        self.of = Some((a_sign != b_sign) && (a_sign != r_sign));

        // Parity flag (low byte)
        self.pf = Some((r_masked as u8).count_ones() % 2 == 0);

        // Auxiliary carry (borrow from bit 4)
        self.af = Some((a & 0xF) < (b & 0xF));
    }

    /// Update flags for a logical operation (AND, OR, XOR).
    pub fn update_logic(&mut self, result: u64, size_bits: u32) {
        let mask = if size_bits >= 64 {
            u64::MAX
        } else {
            (1u64 << size_bits) - 1
        };
        let sign_bit = 1u64 << (size_bits - 1);
        let r_masked = result & mask;

        self.zf = Some(r_masked == 0);
        self.sf = Some((r_masked & sign_bit) != 0);
        self.cf = Some(false); // Logical ops clear CF
        self.of = Some(false); // Logical ops clear OF
        self.pf = Some((r_masked as u8).count_ones() % 2 == 0);
        self.af = None; // AF is undefined for logical ops
    }

    /// Update flags for an increment operation.
    pub fn update_inc(&mut self, value: u64, result: u64, size_bits: u32) {
        let mask = if size_bits >= 64 {
            u64::MAX
        } else {
            (1u64 << size_bits) - 1
        };
        let sign_bit = 1u64 << (size_bits - 1);

        let v_masked = value & mask;
        let r_masked = result & mask;

        self.zf = Some(r_masked == 0);
        self.sf = Some((r_masked & sign_bit) != 0);
        // CF is not affected by INC
        self.of = Some(v_masked == (sign_bit - 1)); // Overflow if was max positive
        self.pf = Some((r_masked as u8).count_ones() % 2 == 0);
        self.af = Some((v_masked & 0xF) == 0xF);
    }

    /// Update flags for a decrement operation.
    pub fn update_dec(&mut self, value: u64, result: u64, size_bits: u32) {
        let mask = if size_bits >= 64 {
            u64::MAX
        } else {
            (1u64 << size_bits) - 1
        };
        let sign_bit = 1u64 << (size_bits - 1);

        let v_masked = value & mask;
        let r_masked = result & mask;

        self.zf = Some(r_masked == 0);
        self.sf = Some((r_masked & sign_bit) != 0);
        // CF is not affected by DEC
        self.of = Some(v_masked == sign_bit); // Overflow if was min negative
        self.pf = Some((r_masked as u8).count_ones() % 2 == 0);
        self.af = Some((v_masked & 0xF) == 0);
    }

    /// Check a condition code.
    pub fn check_condition(&self, condition: ConditionCode) -> Option<bool> {
        match condition {
            ConditionCode::O => self.of,
            ConditionCode::NO => self.of.map(|f| !f),
            ConditionCode::B => self.cf,
            ConditionCode::AE => self.cf.map(|f| !f),
            ConditionCode::E => self.zf,
            ConditionCode::NE => self.zf.map(|f| !f),
            ConditionCode::BE => match (self.cf, self.zf) {
                (Some(cf), Some(zf)) => Some(cf || zf),
                _ => None,
            },
            ConditionCode::A => match (self.cf, self.zf) {
                (Some(cf), Some(zf)) => Some(!cf && !zf),
                _ => None,
            },
            ConditionCode::S => self.sf,
            ConditionCode::NS => self.sf.map(|f| !f),
            ConditionCode::P => self.pf,
            ConditionCode::NP => self.pf.map(|f| !f),
            ConditionCode::L => match (self.sf, self.of) {
                (Some(sf), Some(of)) => Some(sf != of),
                _ => None,
            },
            ConditionCode::GE => match (self.sf, self.of) {
                (Some(sf), Some(of)) => Some(sf == of),
                _ => None,
            },
            ConditionCode::LE => match (self.zf, self.sf, self.of) {
                (Some(zf), Some(sf), Some(of)) => Some(zf || (sf != of)),
                _ => None,
            },
            ConditionCode::G => match (self.zf, self.sf, self.of) {
                (Some(zf), Some(sf), Some(of)) => Some(!zf && (sf == of)),
                _ => None,
            },
        }
    }

    /// Clear all flags.
    pub fn clear(&mut self) {
        self.cf = None;
        self.zf = None;
        self.sf = None;
        self.of = None;
        self.pf = None;
        self.af = None;
    }

    /// Convert to a packed EFLAGS-style value.
    pub fn to_eflags(&self) -> Value {
        match (self.cf, self.pf, self.af, self.zf, self.sf, self.of) {
            (Some(cf), Some(pf), Some(af), Some(zf), Some(sf), Some(of)) => {
                let mut flags = 0u64;
                if cf {
                    flags |= 1 << 0;
                }
                if pf {
                    flags |= 1 << 2;
                }
                if af {
                    flags |= 1 << 4;
                }
                if zf {
                    flags |= 1 << 6;
                }
                if sf {
                    flags |= 1 << 7;
                }
                if of {
                    flags |= 1 << 11;
                }
                Value::Concrete(flags)
            }
            _ => Value::Unknown,
        }
    }
}

/// x86 condition codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionCode {
    /// Overflow (OF=1)
    O,
    /// No overflow (OF=0)
    NO,
    /// Below / Carry (CF=1)
    B,
    /// Above or equal / No carry (CF=0)
    AE,
    /// Equal / Zero (ZF=1)
    E,
    /// Not equal / Not zero (ZF=0)
    NE,
    /// Below or equal (CF=1 or ZF=1)
    BE,
    /// Above (CF=0 and ZF=0)
    A,
    /// Sign (SF=1)
    S,
    /// No sign (SF=0)
    NS,
    /// Parity (PF=1)
    P,
    /// No parity (PF=0)
    NP,
    /// Less (SF!=OF)
    L,
    /// Greater or equal (SF=OF)
    GE,
    /// Less or equal (ZF=1 or SF!=OF)
    LE,
    /// Greater (ZF=0 and SF=OF)
    G,
}

impl ConditionCode {
    /// Parse from a mnemonic suffix (e.g., "je" -> E, "jne" -> NE).
    pub fn from_suffix(suffix: &str) -> Option<Self> {
        match suffix.to_lowercase().as_str() {
            "o" => Some(Self::O),
            "no" => Some(Self::NO),
            "b" | "c" | "nae" => Some(Self::B),
            "ae" | "nc" | "nb" => Some(Self::AE),
            "e" | "z" => Some(Self::E),
            "ne" | "nz" => Some(Self::NE),
            "be" | "na" => Some(Self::BE),
            "a" | "nbe" => Some(Self::A),
            "s" => Some(Self::S),
            "ns" => Some(Self::NS),
            "p" | "pe" => Some(Self::P),
            "np" | "po" => Some(Self::NP),
            "l" | "nge" => Some(Self::L),
            "ge" | "nl" => Some(Self::GE),
            "le" | "ng" => Some(Self::LE),
            "g" | "nle" => Some(Self::G),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_flags() {
        let mut flags = Flags::new();

        // Simple addition
        flags.update_add(5, 3, 8, 32);
        assert_eq!(flags.zf, Some(false));
        assert_eq!(flags.sf, Some(false));
        assert_eq!(flags.cf, Some(false));

        // Zero result
        flags.update_add(0, 0, 0, 32);
        assert_eq!(flags.zf, Some(true));

        // Unsigned overflow (carry)
        flags.update_add(0xFFFFFFFF, 1, 0, 32);
        assert_eq!(flags.cf, Some(true));
        assert_eq!(flags.zf, Some(true));
    }

    #[test]
    fn test_sub_flags() {
        let mut flags = Flags::new();

        // Simple subtraction
        flags.update_sub(5, 3, 2, 32);
        assert_eq!(flags.zf, Some(false));
        assert_eq!(flags.cf, Some(false));

        // Equal (zero result)
        flags.update_sub(5, 5, 0, 32);
        assert_eq!(flags.zf, Some(true));

        // Borrow
        flags.update_sub(3, 5, 0xFFFFFFFE, 32);
        assert_eq!(flags.cf, Some(true));
    }

    #[test]
    fn test_condition_codes() {
        let mut flags = Flags::new();

        // Equal
        flags.zf = Some(true);
        assert_eq!(flags.check_condition(ConditionCode::E), Some(true));
        assert_eq!(flags.check_condition(ConditionCode::NE), Some(false));

        // Less than (signed)
        flags.sf = Some(true);
        flags.of = Some(false);
        assert_eq!(flags.check_condition(ConditionCode::L), Some(true));
        assert_eq!(flags.check_condition(ConditionCode::GE), Some(false));
    }
}
