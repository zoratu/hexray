//! Byte pattern representation with wildcards.
//!
//! Patterns can contain:
//! - Concrete bytes: exact byte match
//! - Wildcards: match any byte
//! - Masked wildcards: match byte with specific bits

use crate::{Result, SignatureError};
use serde::{Deserialize, Serialize};

/// A single byte in a pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatternByte {
    /// Exact byte match.
    Concrete(u8),
    /// Match any byte (wildcard).
    Wildcard,
    /// Match byte with mask: (value, mask).
    /// Matches if (byte & mask) == (value & mask).
    Masked { value: u8, mask: u8 },
}

impl PatternByte {
    /// Check if this pattern byte matches a concrete byte.
    pub fn matches(&self, byte: u8) -> bool {
        match self {
            PatternByte::Concrete(b) => *b == byte,
            PatternByte::Wildcard => true,
            PatternByte::Masked { value, mask } => (byte & mask) == (value & mask),
        }
    }

    /// Returns true if this is a wildcard (any kind).
    pub fn is_wildcard(&self) -> bool {
        matches!(self, PatternByte::Wildcard | PatternByte::Masked { .. })
    }

    /// Returns true if this is a concrete byte.
    pub fn is_concrete(&self) -> bool {
        matches!(self, PatternByte::Concrete(_))
    }
}

/// A byte pattern for matching function prologues.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BytePattern {
    /// The pattern bytes.
    bytes: Vec<PatternByte>,
}

impl BytePattern {
    /// Create an empty pattern.
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Create a pattern from concrete bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.iter().map(|&b| PatternByte::Concrete(b)).collect(),
        }
    }

    /// Create a pattern from pattern bytes.
    pub fn from_pattern_bytes(bytes: Vec<PatternByte>) -> Self {
        Self { bytes }
    }

    /// Parse a pattern from a hex string with wildcards.
    ///
    /// Format: "55 48 89 E5 ?? ?? 48 8B"
    /// - Each byte is two hex digits
    /// - "??" represents a wildcard
    /// - Bytes are space-separated
    pub fn parse(s: &str) -> Result<Self> {
        let mut bytes = Vec::new();

        for part in s.split_whitespace() {
            let byte = if part == "??" || part == "**" {
                PatternByte::Wildcard
            } else if part.len() == 2 {
                let value = u8::from_str_radix(part, 16).map_err(|_| {
                    SignatureError::InvalidPattern(format!("Invalid hex byte: {}", part))
                })?;
                PatternByte::Concrete(value)
            } else if part.contains('&') {
                // Masked format: "XX&MM" where XX is value, MM is mask
                let parts: Vec<&str> = part.split('&').collect();
                if parts.len() != 2 || parts[0].len() != 2 || parts[1].len() != 2 {
                    return Err(SignatureError::InvalidPattern(format!(
                        "Invalid masked byte: {} (expected format: XX&MM)",
                        part
                    )));
                }
                let value = u8::from_str_radix(parts[0], 16).map_err(|_| {
                    SignatureError::InvalidPattern(format!("Invalid masked value: {}", part))
                })?;
                let mask = u8::from_str_radix(parts[1], 16).map_err(|_| {
                    SignatureError::InvalidPattern(format!("Invalid mask: {}", part))
                })?;
                PatternByte::Masked { value, mask }
            } else {
                return Err(SignatureError::InvalidPattern(format!(
                    "Invalid pattern part: {}",
                    part
                )));
            };
            bytes.push(byte);
        }

        Ok(Self { bytes })
    }

    /// Get the pattern length.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if the pattern is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Get the pattern bytes.
    pub fn bytes(&self) -> &[PatternByte] {
        &self.bytes
    }

    /// Check if this pattern matches the given bytes.
    pub fn matches(&self, data: &[u8]) -> bool {
        if data.len() < self.bytes.len() {
            return false;
        }

        self.bytes
            .iter()
            .zip(data.iter())
            .all(|(pattern, &byte)| pattern.matches(byte))
    }

    /// Check if this pattern matches at a specific offset.
    pub fn matches_at(&self, data: &[u8], offset: usize) -> bool {
        if offset + self.bytes.len() > data.len() {
            return false;
        }

        self.matches(&data[offset..])
    }

    /// Get the first N concrete bytes for indexing.
    /// Returns None if there aren't enough concrete bytes.
    pub fn prefix_bytes(&self, n: usize) -> Option<Vec<u8>> {
        let mut result = Vec::with_capacity(n);
        for byte in &self.bytes {
            if result.len() >= n {
                break;
            }
            if let PatternByte::Concrete(b) = byte {
                result.push(*b);
            }
        }
        if result.len() >= n {
            Some(result)
        } else {
            None
        }
    }

    /// Get the number of leading concrete bytes.
    pub fn concrete_prefix_len(&self) -> usize {
        self.bytes.iter().take_while(|b| b.is_concrete()).count()
    }

    /// Convert to hex string representation.
    pub fn to_hex_string(&self) -> String {
        self.bytes
            .iter()
            .map(|b| match b {
                PatternByte::Concrete(v) => format!("{:02X}", v),
                PatternByte::Wildcard => "??".to_string(),
                PatternByte::Masked { value, mask } => format!("{:02X}&{:02X}", value, mask),
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl Default for BytePattern {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for BytePattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_parse() {
        let pattern = BytePattern::parse("55 48 89 E5").unwrap();
        assert_eq!(pattern.len(), 4);
        assert_eq!(pattern.bytes()[0], PatternByte::Concrete(0x55));
        assert_eq!(pattern.bytes()[3], PatternByte::Concrete(0xE5));
    }

    #[test]
    fn test_pattern_parse_wildcard() {
        let pattern = BytePattern::parse("55 ?? 89 ??").unwrap();
        assert_eq!(pattern.len(), 4);
        assert_eq!(pattern.bytes()[0], PatternByte::Concrete(0x55));
        assert_eq!(pattern.bytes()[1], PatternByte::Wildcard);
        assert_eq!(pattern.bytes()[3], PatternByte::Wildcard);
    }

    #[test]
    fn test_pattern_matches() {
        let pattern = BytePattern::parse("55 48 89 E5").unwrap();
        assert!(pattern.matches(&[0x55, 0x48, 0x89, 0xE5]));
        assert!(!pattern.matches(&[0x55, 0x48, 0x89, 0x00]));
        assert!(pattern.matches(&[0x55, 0x48, 0x89, 0xE5, 0x00, 0x00])); // Extra bytes OK
    }

    #[test]
    fn test_pattern_matches_wildcard() {
        let pattern = BytePattern::parse("55 ?? 89 E5").unwrap();
        assert!(pattern.matches(&[0x55, 0x00, 0x89, 0xE5]));
        assert!(pattern.matches(&[0x55, 0xFF, 0x89, 0xE5]));
        assert!(!pattern.matches(&[0x55, 0x00, 0x89, 0x00]));
    }

    #[test]
    fn test_pattern_matches_masked() {
        // Match lower nibble only
        let pattern = BytePattern::parse("55 00&0F").unwrap();
        assert!(pattern.matches(&[0x55, 0x00])); // 0x00 & 0x0F == 0
        assert!(pattern.matches(&[0x55, 0xF0])); // 0xF0 & 0x0F == 0
        assert!(!pattern.matches(&[0x55, 0x01])); // 0x01 & 0x0F == 1
    }

    #[test]
    fn test_prefix_bytes() {
        let pattern = BytePattern::parse("55 48 ?? E5").unwrap();
        assert_eq!(pattern.prefix_bytes(2), Some(vec![0x55, 0x48]));
        assert_eq!(pattern.prefix_bytes(3), Some(vec![0x55, 0x48, 0xE5]));
        assert_eq!(pattern.prefix_bytes(4), None); // Only 3 concrete bytes
    }

    #[test]
    fn test_concrete_prefix_len() {
        let pattern = BytePattern::parse("55 48 89 E5").unwrap();
        assert_eq!(pattern.concrete_prefix_len(), 4);

        let pattern = BytePattern::parse("55 ?? 89 E5").unwrap();
        assert_eq!(pattern.concrete_prefix_len(), 1);

        let pattern = BytePattern::parse("?? 55 89 E5").unwrap();
        assert_eq!(pattern.concrete_prefix_len(), 0);
    }

    #[test]
    fn test_to_hex_string() {
        let pattern = BytePattern::parse("55 ?? 89 E5").unwrap();
        assert_eq!(pattern.to_hex_string(), "55 ?? 89 E5");
    }
}
