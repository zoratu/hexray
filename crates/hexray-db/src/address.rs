//! Address and file-offset newtypes with a stable fixed-width encoding.
//!
//! Both are stored as 8-byte big-endian BLOBs. A BLOB (rather than a SQL
//! `INTEGER`) keeps the full `u64` range addressable: SQLite integers are
//! signed 64-bit, so `u64::MAX` would alias `-1` and sort before 0. Big-endian
//! bytes compare bytewise in numeric order, so `ORDER BY` on the BLOB matches
//! numeric order for every value in `0..=u64::MAX`.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// An address in the analyzed image's virtual address space.
///
/// Serialized as a `0x`-prefixed hex string everywhere: JSON consumers must
/// never see an address as a number, because anything past 2^53 loses
/// precision in JavaScript and every reader would have to know which fields
/// are addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address(pub u64);

/// A byte offset in the *full* original input source. Serialized like
/// [`Address`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileOffset(pub u64);

/// A checked range failure. Ranges are half-open `[start, start + len)`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RangeError {
    #[error("range {start:#x}+{len:#x} overflows the address space")]
    Overflow { start: u64, len: u64 },
    #[error("address blob must be 8 bytes, got {0}")]
    BadBlobLength(usize),
    #[error("range length must be non-zero")]
    EmptyRange,
}

const BLOB_LEN: usize = 8;

impl Address {
    pub const ZERO: Self = Self(0);

    /// Fixed-width big-endian encoding used in every SQL column.
    pub fn to_blob(self) -> [u8; BLOB_LEN] {
        self.0.to_be_bytes()
    }

    pub fn from_blob(blob: &[u8]) -> Result<Self, RangeError> {
        if blob.len() != BLOB_LEN {
            return Err(RangeError::BadBlobLength(blob.len()));
        }
        let mut raw = [0u8; BLOB_LEN];
        raw.copy_from_slice(blob);
        Ok(Self(u64::from_be_bytes(raw)))
    }

    /// Exclusive end of `self + len`.
    pub fn checked_end(self, len: u64) -> Result<u64, RangeError> {
        self.0
            .checked_add(len)
            .ok_or(RangeError::Overflow { start: self.0, len })
    }

    /// Half-open range starting here.
    pub fn range(self, len: u64) -> Result<AddressRange, RangeError> {
        AddressRange::new(self, len)
    }

    /// `0x`-prefixed hex, the only textual form on the CLI/JSON surface.
    pub fn to_hex(self) -> String {
        format!("0x{:x}", self.0)
    }
}

impl FileOffset {
    pub const ZERO: Self = Self(0);

    pub fn to_blob(self) -> [u8; BLOB_LEN] {
        self.0.to_be_bytes()
    }

    pub fn from_blob(blob: &[u8]) -> Result<Self, RangeError> {
        if blob.len() != BLOB_LEN {
            return Err(RangeError::BadBlobLength(blob.len()));
        }
        let mut raw = [0u8; BLOB_LEN];
        raw.copy_from_slice(blob);
        Ok(Self(u64::from_be_bytes(raw)))
    }

    pub fn checked_end(self, len: u64) -> Result<u64, RangeError> {
        self.0
            .checked_add(len)
            .ok_or(RangeError::Overflow { start: self.0, len })
    }

    pub fn to_hex(self) -> String {
        format!("0x{:x}", self.0)
    }
}

/// Hex-string serde shared by [`Address`] and [`FileOffset`].
mod hex_u64 {
    use super::*;

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("0x{value:x}"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let text = String::deserialize(deserializer)?;
        let digits = text
            .strip_prefix("0x")
            .or_else(|| text.strip_prefix("0X"))
            .ok_or_else(|| {
                serde::de::Error::custom(format!("address '{text}' needs a 0x prefix"))
            })?;
        u64::from_str_radix(digits, 16)
            .map_err(|error| serde::de::Error::custom(format!("address '{text}': {error}")))
    }
}

macro_rules! impl_hex_serde {
    ($ty:ty) => {
        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                hex_u64::serialize(&self.0, serializer)
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                hex_u64::deserialize(deserializer).map(Self)
            }
        }
    };
}

impl_hex_serde!(Address);
impl_hex_serde!(FileOffset);

macro_rules! impl_common {
    ($ty:ty) => {
        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{:#x}", self.0)
            }
        }

        impl From<u64> for $ty {
            fn from(value: u64) -> Self {
                Self(value)
            }
        }

        impl From<$ty> for u64 {
            fn from(value: $ty) -> Self {
                value.0
            }
        }

        impl $ty {
            pub fn as_i64(self) -> i64 {
                // Only used for non-address metadata columns; addresses never
                // round-trip through i64.
                i64::try_from(self.0).unwrap_or(i64::MAX)
            }
        }
    };
}

impl_common!(Address);
impl_common!(FileOffset);

/// A non-empty half-open range in one address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressRange {
    pub start: Address,
    pub len: u64,
}

impl AddressRange {
    pub fn new(start: Address, len: u64) -> Result<Self, RangeError> {
        if len == 0 {
            return Err(RangeError::EmptyRange);
        }
        start.checked_end(len)?;
        Ok(Self { start, len })
    }

    /// Exclusive end. Only fails for ranges built without `new`.
    pub fn end(self) -> Result<u64, RangeError> {
        self.start.checked_end(self.len)
    }

    /// Inclusive-last address, `None` for an empty range.
    pub fn last(self) -> Result<Option<Address>, RangeError> {
        if self.len == 0 {
            return Ok(None);
        }
        Ok(Some(Address(self.end()? - 1)))
    }

    pub fn contains(self, address: Address) -> Result<bool, RangeError> {
        let end = self.end()?;
        Ok(address.0 >= self.start.0 && address.0 < end)
    }

    pub fn overlaps(self, other: AddressRange) -> Result<bool, RangeError> {
        let (a_end, b_end) = (self.end()?, other.end()?);
        Ok(self.start.0 < b_end && other.start.0 < a_end)
    }
}

/// Half-open range of source file offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileRange {
    pub start: FileOffset,
    pub len: u64,
}

impl FileRange {
    pub fn new(start: FileOffset, len: u64) -> Result<Self, RangeError> {
        if len == 0 {
            return Err(RangeError::EmptyRange);
        }
        start.checked_end(len)?;
        Ok(Self { start, len })
    }

    pub fn end(self) -> Result<u64, RangeError> {
        self.start.checked_end(self.len)
    }

    pub fn overlaps(self, other: FileRange) -> Result<bool, RangeError> {
        let (a_end, b_end) = (self.end()?, other.end()?);
        Ok(self.start.0 < b_end && other.start.0 < a_end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_roundtrip_high_bit_values() {
        for value in [
            0u64,
            1,
            (1 << 53) + 1,
            i64::MAX as u64,
            1u64 << 63,
            u64::MAX,
        ] {
            let blob = Address(value).to_blob();
            assert_eq!(Address::from_blob(&blob).unwrap(), Address(value));
            let blob = FileOffset(value).to_blob();
            assert_eq!(FileOffset::from_blob(&blob).unwrap(), FileOffset(value));
        }
    }

    #[test]
    fn blob_order_matches_numeric_order() {
        let mut values = vec![u64::MAX, 0, 1u64 << 63, i64::MAX as u64 + 1, 7];
        values.sort_unstable();
        let mut blobs: Vec<[u8; 8]> = values.iter().map(|v| Address(*v).to_blob()).collect();
        blobs.sort_unstable();
        let decoded: Vec<u64> = blobs
            .iter()
            .map(|b| Address::from_blob(b).unwrap().0)
            .collect();
        assert_eq!(decoded, values);
    }

    #[test]
    fn range_overflow_is_rejected() {
        assert!(Address(u64::MAX).range(1).is_err());
        assert!(FileRange::new(FileOffset(u64::MAX), 2).is_err());
        assert!(AddressRange::new(Address(0), 0).is_err());
        assert!(FileRange::new(FileOffset(0), 0).is_err());
    }

    #[test]
    fn bad_blob_length_is_rejected() {
        assert_eq!(
            Address::from_blob(&[0; 7]),
            Err(RangeError::BadBlobLength(7))
        );
        assert_eq!(
            FileOffset::from_blob(&[0; 9]),
            Err(RangeError::BadBlobLength(9))
        );
    }
}
