//! Value representation for emulation.
//!
//! Values can be:
//! - Concrete: A known numeric value
//! - Symbolic: A placeholder for constraint solving
//! - Unknown: A value that cannot be determined

use serde::{Deserialize, Serialize};
use std::fmt;

/// A unique identifier for symbolic values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SymbolicId(pub u32);

impl SymbolicId {
    /// Create a new symbolic ID.
    pub fn new(id: u32) -> Self {
        Self(id)
    }
}

impl fmt::Display for SymbolicId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sym_{}", self.0)
    }
}

/// A value in the emulator.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Value {
    /// A concrete numeric value.
    Concrete(u64),
    /// A symbolic value (for constraint solving).
    Symbolic(SymbolicId),
    /// An unknown value that cannot be determined.
    Unknown,
}

impl Value {
    /// Create a concrete value.
    pub fn concrete(value: u64) -> Self {
        Value::Concrete(value)
    }

    /// Create a symbolic value.
    pub fn symbolic(id: SymbolicId) -> Self {
        Value::Symbolic(id)
    }

    /// Create an unknown value.
    pub fn unknown() -> Self {
        Value::Unknown
    }

    /// Check if this is a concrete value.
    pub fn is_concrete(&self) -> bool {
        matches!(self, Value::Concrete(_))
    }

    /// Check if this is a symbolic value.
    pub fn is_symbolic(&self) -> bool {
        matches!(self, Value::Symbolic(_))
    }

    /// Check if this is unknown.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Value::Unknown)
    }

    /// Get the concrete value if available.
    pub fn as_concrete(&self) -> Option<u64> {
        match self {
            Value::Concrete(v) => Some(*v),
            _ => None,
        }
    }

    /// Get the symbolic ID if this is symbolic.
    pub fn as_symbolic(&self) -> Option<SymbolicId> {
        match self {
            Value::Symbolic(id) => Some(*id),
            _ => None,
        }
    }

    /// Unwrap as concrete, panicking if not concrete.
    pub fn unwrap_concrete(&self) -> u64 {
        match self {
            Value::Concrete(v) => *v,
            _ => panic!("Expected concrete value, got {:?}", self),
        }
    }

    // ==================== Arithmetic Operations ====================

    /// Add two values.
    pub fn add(&self, other: &Value) -> Value {
        match (self, other) {
            (Value::Concrete(a), Value::Concrete(b)) => Value::Concrete(a.wrapping_add(*b)),
            (Value::Concrete(0), other) | (other, Value::Concrete(0)) => other.clone(),
            _ => Value::Unknown,
        }
    }

    /// Subtract two values.
    pub fn sub(&self, other: &Value) -> Value {
        match (self, other) {
            (other, Value::Concrete(0)) => other.clone(),
            (Value::Concrete(a), Value::Concrete(b)) if a == b => Value::Concrete(0),
            (Value::Concrete(a), Value::Concrete(b)) => Value::Concrete(a.wrapping_sub(*b)),
            _ => Value::Unknown,
        }
    }

    /// Multiply two values.
    pub fn mul(&self, other: &Value) -> Value {
        match (self, other) {
            (Value::Concrete(a), Value::Concrete(b)) => Value::Concrete(a.wrapping_mul(*b)),
            (Value::Concrete(0), _) | (_, Value::Concrete(0)) => Value::Concrete(0),
            (Value::Concrete(1), other) | (other, Value::Concrete(1)) => other.clone(),
            _ => Value::Unknown,
        }
    }

    /// Unsigned divide two values.
    pub fn div(&self, other: &Value) -> Option<Value> {
        match (self, other) {
            (_, Value::Concrete(0)) => None, // Division by zero
            (Value::Concrete(a), Value::Concrete(b)) => Some(Value::Concrete(a / b)),
            (Value::Concrete(0), _) => Some(Value::Concrete(0)),
            (other, Value::Concrete(1)) => Some(other.clone()),
            _ => Some(Value::Unknown),
        }
    }

    /// Unsigned modulo two values.
    pub fn modulo(&self, other: &Value) -> Option<Value> {
        match (self, other) {
            (_, Value::Concrete(0)) => None, // Division by zero
            (Value::Concrete(a), Value::Concrete(b)) => Some(Value::Concrete(a % b)),
            (Value::Concrete(0), _) => Some(Value::Concrete(0)),
            _ => Some(Value::Unknown),
        }
    }

    /// Negate a value.
    pub fn neg(&self) -> Value {
        match self {
            Value::Concrete(v) => Value::Concrete((!*v).wrapping_add(1)),
            _ => Value::Unknown,
        }
    }

    // ==================== Bitwise Operations ====================

    /// Bitwise AND.
    pub fn and(&self, other: &Value) -> Value {
        match (self, other) {
            (Value::Concrete(a), Value::Concrete(b)) => Value::Concrete(a & b),
            (Value::Concrete(0), _) | (_, Value::Concrete(0)) => Value::Concrete(0),
            (Value::Concrete(u64::MAX), other) | (other, Value::Concrete(u64::MAX)) => other.clone(),
            _ => Value::Unknown,
        }
    }

    /// Bitwise OR.
    pub fn or(&self, other: &Value) -> Value {
        match (self, other) {
            (Value::Concrete(a), Value::Concrete(b)) => Value::Concrete(a | b),
            (Value::Concrete(0), other) | (other, Value::Concrete(0)) => other.clone(),
            (Value::Concrete(u64::MAX), _) | (_, Value::Concrete(u64::MAX)) => Value::Concrete(u64::MAX),
            _ => Value::Unknown,
        }
    }

    /// Bitwise XOR.
    pub fn xor(&self, other: &Value) -> Value {
        match (self, other) {
            (Value::Concrete(0), other) | (other, Value::Concrete(0)) => other.clone(),
            // XOR with self is 0 (for concrete values)
            (Value::Concrete(a), Value::Concrete(b)) if a == b => Value::Concrete(0),
            (Value::Concrete(a), Value::Concrete(b)) => Value::Concrete(a ^ b),
            _ => Value::Unknown,
        }
    }

    /// Bitwise NOT.
    pub fn not(&self) -> Value {
        match self {
            Value::Concrete(v) => Value::Concrete(!*v),
            _ => Value::Unknown,
        }
    }

    /// Left shift.
    pub fn shl(&self, amount: &Value) -> Value {
        match (self, amount) {
            (Value::Concrete(v), Value::Concrete(amt)) => {
                if *amt >= 64 {
                    Value::Concrete(0)
                } else {
                    Value::Concrete(v << amt)
                }
            }
            (Value::Concrete(0), _) => Value::Concrete(0),
            (_, Value::Concrete(0)) => self.clone(),
            _ => Value::Unknown,
        }
    }

    /// Logical right shift.
    pub fn shr(&self, amount: &Value) -> Value {
        match (self, amount) {
            (Value::Concrete(v), Value::Concrete(amt)) => {
                if *amt >= 64 {
                    Value::Concrete(0)
                } else {
                    Value::Concrete(v >> amt)
                }
            }
            (Value::Concrete(0), _) => Value::Concrete(0),
            (_, Value::Concrete(0)) => self.clone(),
            _ => Value::Unknown,
        }
    }

    /// Arithmetic right shift (sign-extending).
    pub fn sar(&self, amount: &Value) -> Value {
        match (self, amount) {
            (Value::Concrete(v), Value::Concrete(amt)) => {
                let signed = *v as i64;
                if *amt >= 64 {
                    Value::Concrete(if signed < 0 { u64::MAX } else { 0 })
                } else {
                    Value::Concrete((signed >> amt) as u64)
                }
            }
            (Value::Concrete(0), _) => Value::Concrete(0),
            (_, Value::Concrete(0)) => self.clone(),
            _ => Value::Unknown,
        }
    }

    // ==================== Comparison Operations ====================

    /// Compare equal.
    pub fn eq(&self, other: &Value) -> Value {
        match (self, other) {
            (Value::Concrete(a), Value::Concrete(b)) => {
                Value::Concrete(if a == b { 1 } else { 0 })
            }
            _ => Value::Unknown,
        }
    }

    /// Compare not equal.
    pub fn ne(&self, other: &Value) -> Value {
        match (self, other) {
            (Value::Concrete(a), Value::Concrete(b)) => {
                Value::Concrete(if a != b { 1 } else { 0 })
            }
            _ => Value::Unknown,
        }
    }

    /// Unsigned less than.
    pub fn ult(&self, other: &Value) -> Value {
        match (self, other) {
            (Value::Concrete(a), Value::Concrete(b)) => {
                Value::Concrete(if a < b { 1 } else { 0 })
            }
            _ => Value::Unknown,
        }
    }

    /// Signed less than.
    pub fn slt(&self, other: &Value) -> Value {
        match (self, other) {
            (Value::Concrete(a), Value::Concrete(b)) => {
                Value::Concrete(if (*a as i64) < (*b as i64) { 1 } else { 0 })
            }
            _ => Value::Unknown,
        }
    }

    // ==================== Size Operations ====================

    /// Zero-extend to 64 bits from a smaller size.
    pub fn zext(&self, from_bits: u32) -> Value {
        match self {
            Value::Concrete(v) => {
                let mask = if from_bits >= 64 { u64::MAX } else { (1u64 << from_bits) - 1 };
                Value::Concrete(*v & mask)
            }
            _ => Value::Unknown,
        }
    }

    /// Sign-extend to 64 bits from a smaller size.
    pub fn sext(&self, from_bits: u32) -> Value {
        match self {
            Value::Concrete(v) => {
                if from_bits >= 64 {
                    return self.clone();
                }
                let mask = (1u64 << from_bits) - 1;
                let sign_bit = 1u64 << (from_bits - 1);
                let value = *v & mask;
                if value & sign_bit != 0 {
                    // Sign extend
                    Value::Concrete(value | !mask)
                } else {
                    Value::Concrete(value)
                }
            }
            _ => Value::Unknown,
        }
    }

    /// Truncate to a smaller size.
    pub fn trunc(&self, to_bits: u32) -> Value {
        match self {
            Value::Concrete(v) => {
                let mask = if to_bits >= 64 { u64::MAX } else { (1u64 << to_bits) - 1 };
                Value::Concrete(*v & mask)
            }
            _ => Value::Unknown,
        }
    }
}

impl Default for Value {
    fn default() -> Self {
        Value::Concrete(0)
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Concrete(v) => write!(f, "{:#x}", v),
            Value::Symbolic(id) => write!(f, "{}", id),
            Value::Unknown => write!(f, "?"),
        }
    }
}

impl From<u64> for Value {
    fn from(v: u64) -> Self {
        Value::Concrete(v)
    }
}

impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Value::Concrete(v as u64)
    }
}

impl From<u32> for Value {
    fn from(v: u32) -> Self {
        Value::Concrete(v as u64)
    }
}

impl From<i32> for Value {
    fn from(v: i32) -> Self {
        Value::Concrete(v as i64 as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_concrete_arithmetic() {
        let a = Value::concrete(10);
        let b = Value::concrete(3);

        assert_eq!(a.add(&b), Value::concrete(13));
        assert_eq!(a.sub(&b), Value::concrete(7));
        assert_eq!(a.mul(&b), Value::concrete(30));
        assert_eq!(a.div(&b), Some(Value::concrete(3)));
        assert_eq!(a.modulo(&b), Some(Value::concrete(1)));
    }

    #[test]
    fn test_division_by_zero() {
        let a = Value::concrete(10);
        let zero = Value::concrete(0);

        assert_eq!(a.div(&zero), None);
        assert_eq!(a.modulo(&zero), None);
    }

    #[test]
    fn test_bitwise_operations() {
        let a = Value::concrete(0b1100);
        let b = Value::concrete(0b1010);

        assert_eq!(a.and(&b), Value::concrete(0b1000));
        assert_eq!(a.or(&b), Value::concrete(0b1110));
        assert_eq!(a.xor(&b), Value::concrete(0b0110));
    }

    #[test]
    fn test_shifts() {
        let v = Value::concrete(0b1000);

        assert_eq!(v.shl(&Value::concrete(2)), Value::concrete(0b100000));
        assert_eq!(v.shr(&Value::concrete(2)), Value::concrete(0b10));
    }

    #[test]
    fn test_sign_extension() {
        // -1 as 8-bit = 0xFF
        let v = Value::concrete(0xFF);
        let extended = v.sext(8);
        assert_eq!(extended, Value::concrete(u64::MAX)); // -1 as 64-bit

        // 127 as 8-bit = 0x7F (positive, no sign extension)
        let v = Value::concrete(0x7F);
        let extended = v.sext(8);
        assert_eq!(extended, Value::concrete(0x7F));
    }

    #[test]
    fn test_zero_extension() {
        let v = Value::concrete(0xFF);
        let extended = v.zext(8);
        assert_eq!(extended, Value::concrete(0xFF));

        let v = Value::concrete(0x1FF);
        let extended = v.zext(8);
        assert_eq!(extended, Value::concrete(0xFF)); // Truncates to 8 bits
    }
}
