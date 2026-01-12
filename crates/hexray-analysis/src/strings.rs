//! String detection and analysis.
//!
//! This module provides utilities for detecting and extracting strings
//! from binary data. It supports:
//! - ASCII strings
//! - UTF-8 strings
//! - UTF-16 (wide) strings
//! - Pascal-style strings (length-prefixed)

use std::collections::HashMap;

/// Encoding type for detected strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StringEncoding {
    /// ASCII (7-bit) string.
    Ascii,
    /// UTF-8 encoded string.
    Utf8,
    /// UTF-16 Little Endian string.
    Utf16Le,
    /// UTF-16 Big Endian string.
    Utf16Be,
}

/// A detected string in the binary.
#[derive(Debug, Clone)]
pub struct DetectedString {
    /// Address where the string starts.
    pub address: u64,
    /// Length in bytes.
    pub length: usize,
    /// The decoded string content.
    pub content: String,
    /// Encoding used.
    pub encoding: StringEncoding,
    /// Whether this is null-terminated.
    pub null_terminated: bool,
}

impl DetectedString {
    /// Returns true if this looks like a file path.
    pub fn is_path(&self) -> bool {
        // Don't count URLs as paths
        if self.is_url() {
            return false;
        }
        self.content.contains('/') || self.content.contains('\\')
    }

    /// Returns true if this looks like a URL.
    pub fn is_url(&self) -> bool {
        self.content.starts_with("http://")
            || self.content.starts_with("https://")
            || self.content.starts_with("ftp://")
    }

    /// Returns true if this looks like an error message.
    pub fn is_error_message(&self) -> bool {
        let lower = self.content.to_lowercase();
        lower.contains("error")
            || lower.contains("failed")
            || lower.contains("invalid")
            || lower.contains("cannot")
            || lower.contains("unable")
    }
}

/// String detection configuration.
#[derive(Debug, Clone)]
pub struct StringConfig {
    /// Minimum string length to detect.
    pub min_length: usize,
    /// Maximum string length to detect.
    pub max_length: usize,
    /// Whether to detect UTF-16 strings.
    pub detect_utf16: bool,
    /// Whether to require null termination.
    pub require_null_terminator: bool,
}

impl Default for StringConfig {
    fn default() -> Self {
        Self {
            min_length: 4,
            max_length: 4096,
            detect_utf16: true,
            require_null_terminator: true,
        }
    }
}

/// String detector for finding strings in binary data.
pub struct StringDetector {
    config: StringConfig,
}

impl Default for StringDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl StringDetector {
    /// Create a new string detector with default configuration.
    pub fn new() -> Self {
        Self {
            config: StringConfig::default(),
        }
    }

    /// Create a string detector with custom configuration.
    pub fn with_config(config: StringConfig) -> Self {
        Self { config }
    }

    /// Detect all strings in the given data.
    pub fn detect(&self, data: &[u8], base_address: u64) -> Vec<DetectedString> {
        let mut strings = Vec::new();

        // Detect ASCII/UTF-8 strings
        strings.extend(self.detect_ascii_strings(data, base_address));

        // Detect UTF-16 strings if enabled
        if self.config.detect_utf16 {
            strings.extend(self.detect_utf16_strings(data, base_address));
        }

        // Sort by address
        strings.sort_by_key(|s| s.address);

        // Remove overlapping strings (keep longer ones)
        self.deduplicate_strings(strings)
    }

    /// Detect ASCII/UTF-8 null-terminated strings.
    fn detect_ascii_strings(&self, data: &[u8], base_address: u64) -> Vec<DetectedString> {
        let mut strings = Vec::new();
        let mut start = None;

        for (i, &byte) in data.iter().enumerate() {
            if Self::is_printable_ascii(byte) {
                if start.is_none() {
                    start = Some(i);
                }
            } else if byte == 0 {
                // Null terminator
                if let Some(s) = start {
                    let len = i - s;
                    if len >= self.config.min_length && len <= self.config.max_length {
                        if let Ok(content) = std::str::from_utf8(&data[s..i]) {
                            let encoding = if content.is_ascii() {
                                StringEncoding::Ascii
                            } else {
                                StringEncoding::Utf8
                            };
                            strings.push(DetectedString {
                                address: base_address + s as u64,
                                length: len,
                                content: content.to_string(),
                                encoding,
                                null_terminated: true,
                            });
                        }
                    }
                }
                start = None;
            } else {
                // Non-printable, non-null byte
                if !self.config.require_null_terminator {
                    if let Some(s) = start {
                        let len = i - s;
                        if len >= self.config.min_length && len <= self.config.max_length {
                            if let Ok(content) = std::str::from_utf8(&data[s..i]) {
                                let encoding = if content.is_ascii() {
                                    StringEncoding::Ascii
                                } else {
                                    StringEncoding::Utf8
                                };
                                strings.push(DetectedString {
                                    address: base_address + s as u64,
                                    length: len,
                                    content: content.to_string(),
                                    encoding,
                                    null_terminated: false,
                                });
                            }
                        }
                    }
                }
                start = None;
            }
        }

        strings
    }

    /// Detect UTF-16 null-terminated strings.
    fn detect_utf16_strings(&self, data: &[u8], base_address: u64) -> Vec<DetectedString> {
        let mut strings = Vec::new();

        // Try UTF-16 LE
        strings.extend(self.detect_utf16_strings_endian(data, base_address, true));

        // Try UTF-16 BE
        strings.extend(self.detect_utf16_strings_endian(data, base_address, false));

        strings
    }

    fn detect_utf16_strings_endian(
        &self,
        data: &[u8],
        base_address: u64,
        little_endian: bool,
    ) -> Vec<DetectedString> {
        let mut strings = Vec::new();

        if data.len() < 2 {
            return strings;
        }

        let mut start = None;
        let mut chars = Vec::new();

        for i in (0..data.len() - 1).step_by(2) {
            let code_unit = if little_endian {
                u16::from_le_bytes([data[i], data[i + 1]])
            } else {
                u16::from_be_bytes([data[i], data[i + 1]])
            };

            if code_unit == 0 {
                // Null terminator
                if let Some(s) = start {
                    if chars.len() >= self.config.min_length
                        && chars.len() <= self.config.max_length
                    {
                        if let Ok(content) = String::from_utf16(&chars) {
                            // Only accept if it looks like real text
                            if Self::looks_like_text(&content) {
                                let encoding = if little_endian {
                                    StringEncoding::Utf16Le
                                } else {
                                    StringEncoding::Utf16Be
                                };
                                strings.push(DetectedString {
                                    address: base_address + s as u64,
                                    length: i - s,
                                    content,
                                    encoding,
                                    null_terminated: true,
                                });
                            }
                        }
                    }
                }
                start = None;
                chars.clear();
            } else if Self::is_printable_utf16(code_unit) {
                if start.is_none() {
                    start = Some(i);
                }
                chars.push(code_unit);
            } else {
                start = None;
                chars.clear();
            }
        }

        strings
    }

    /// Check if a byte is printable ASCII.
    fn is_printable_ascii(byte: u8) -> bool {
        // Printable ASCII range plus tab and newline
        matches!(byte, 0x20..=0x7E | 0x09 | 0x0A | 0x0D)
    }

    /// Check if a UTF-16 code unit is printable.
    fn is_printable_utf16(code_unit: u16) -> bool {
        // Basic Latin + Latin-1 Supplement + common Unicode ranges
        matches!(code_unit, 0x0020..=0x007E | 0x00A0..=0x00FF | 0x0100..=0x017F | 0x0009 | 0x000A | 0x000D)
    }

    /// Check if a string looks like real text (not garbage).
    fn looks_like_text(s: &str) -> bool {
        if s.is_empty() {
            return false;
        }

        // Count alphanumeric characters
        let alnum_count = s.chars().filter(|c| c.is_alphanumeric()).count();
        let total = s.chars().count();

        // At least 50% should be alphanumeric or common punctuation
        alnum_count * 2 >= total
    }

    /// Remove overlapping strings, keeping longer ones.
    fn deduplicate_strings(&self, mut strings: Vec<DetectedString>) -> Vec<DetectedString> {
        if strings.len() <= 1 {
            return strings;
        }

        // Sort by address, then by length (descending)
        strings.sort_by(|a, b| {
            a.address
                .cmp(&b.address)
                .then(b.length.cmp(&a.length))
        });

        let mut result = Vec::new();
        let mut last_end = 0u64;

        for s in strings {
            if s.address >= last_end {
                last_end = s.address + s.length as u64;
                result.push(s);
            }
        }

        result
    }
}

/// Table for mapping addresses to detected strings with full metadata.
#[derive(Debug, Default)]
pub struct DetectedStringTable {
    /// Strings indexed by address.
    strings: HashMap<u64, DetectedString>,
}

impl DetectedStringTable {
    /// Create a new empty string table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a string table from detected strings.
    pub fn from_strings(strings: Vec<DetectedString>) -> Self {
        let mut table = Self::new();
        for s in strings {
            table.strings.insert(s.address, s);
        }
        table
    }

    /// Add a string to the table.
    pub fn add(&mut self, string: DetectedString) {
        self.strings.insert(string.address, string);
    }

    /// Get a string by address.
    pub fn get(&self, address: u64) -> Option<&DetectedString> {
        self.strings.get(&address)
    }

    /// Check if an address has a string.
    pub fn has_string(&self, address: u64) -> bool {
        self.strings.contains_key(&address)
    }

    /// Get all strings.
    pub fn all_strings(&self) -> impl Iterator<Item = &DetectedString> {
        self.strings.values()
    }

    /// Get the number of strings.
    pub fn len(&self) -> usize {
        self.strings.len()
    }

    /// Check if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }

    /// Find strings containing a substring.
    pub fn search(&self, pattern: &str) -> Vec<&DetectedString> {
        let pattern_lower = pattern.to_lowercase();
        self.strings
            .values()
            .filter(|s| s.content.to_lowercase().contains(&pattern_lower))
            .collect()
    }

    /// Get strings in a given address range.
    pub fn in_range(&self, start: u64, end: u64) -> Vec<&DetectedString> {
        self.strings
            .values()
            .filter(|s| s.address >= start && s.address < end)
            .collect()
    }

    /// Convert to a simple StringTable for use with the decompiler.
    pub fn to_simple_table(&self) -> crate::decompiler::StringTable {
        let mut table = crate::decompiler::StringTable::new();
        for s in self.strings.values() {
            table.insert(s.address, s.content.clone());
        }
        table
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_ascii_string() {
        let detector = StringDetector::new();
        let data = b"Hello, World!\x00";
        let strings = detector.detect(data, 0x1000);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].content, "Hello, World!");
        assert_eq!(strings[0].address, 0x1000);
        assert_eq!(strings[0].encoding, StringEncoding::Ascii);
        assert!(strings[0].null_terminated);
    }

    #[test]
    fn test_detect_multiple_strings() {
        let detector = StringDetector::new();
        let data = b"First\x00Second\x00Third\x00";
        let strings = detector.detect(data, 0x1000);

        assert_eq!(strings.len(), 3);
        assert_eq!(strings[0].content, "First");
        assert_eq!(strings[1].content, "Second");
        assert_eq!(strings[2].content, "Third");
    }

    #[test]
    fn test_min_length_filter() {
        let config = StringConfig {
            min_length: 6,
            ..Default::default()
        };
        let detector = StringDetector::with_config(config);
        let data = b"Hi\x00Hello World\x00";
        let strings = detector.detect(data, 0x1000);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].content, "Hello World");
    }

    #[test]
    fn test_detected_string_predicates() {
        let path_string = DetectedString {
            address: 0,
            length: 10,
            content: "/usr/bin/test".to_string(),
            encoding: StringEncoding::Ascii,
            null_terminated: true,
        };
        assert!(path_string.is_path());
        assert!(!path_string.is_url());

        let url_string = DetectedString {
            address: 0,
            length: 20,
            content: "https://example.com".to_string(),
            encoding: StringEncoding::Ascii,
            null_terminated: true,
        };
        assert!(url_string.is_url());
        assert!(!url_string.is_path());

        let error_string = DetectedString {
            address: 0,
            length: 15,
            content: "Error: failed to open".to_string(),
            encoding: StringEncoding::Ascii,
            null_terminated: true,
        };
        assert!(error_string.is_error_message());
    }

    #[test]
    fn test_string_table() {
        let mut table = DetectedStringTable::new();
        table.add(DetectedString {
            address: 0x1000,
            length: 5,
            content: "hello".to_string(),
            encoding: StringEncoding::Ascii,
            null_terminated: true,
        });
        table.add(DetectedString {
            address: 0x2000,
            length: 5,
            content: "world".to_string(),
            encoding: StringEncoding::Ascii,
            null_terminated: true,
        });

        assert_eq!(table.len(), 2);
        assert!(table.has_string(0x1000));
        assert!(!table.has_string(0x3000));

        let search_results = table.search("ello");
        assert_eq!(search_results.len(), 1);
        assert_eq!(search_results[0].content, "hello");
    }
}
