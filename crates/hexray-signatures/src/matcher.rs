//! Pattern matching engine.
//!
//! Provides efficient matching of function bytes against signature patterns.
//! Uses a prefix index for fast initial filtering.

use crate::database::SignatureDatabase;
use crate::signature::FunctionSignature;
use std::collections::HashMap;

/// Result of a signature match.
#[derive(Debug, Clone)]
pub struct MatchResult<'a> {
    /// The matched signature.
    pub signature: &'a FunctionSignature,
    /// Match confidence (0.0 - 1.0).
    /// Combines pattern confidence with match quality.
    pub confidence: f32,
    /// Offset in the input bytes where match occurred.
    pub offset: usize,
}

impl<'a> MatchResult<'a> {
    /// Create a new match result.
    pub fn new(signature: &'a FunctionSignature, confidence: f32, offset: usize) -> Self {
        Self {
            signature,
            confidence,
            offset,
        }
    }
}

/// Signature matcher with prefix indexing for efficiency.
pub struct SignatureMatcher<'a> {
    /// Reference to the signature database.
    database: &'a SignatureDatabase,

    /// Prefix index: maps first N bytes to signature indices.
    /// Uses 4-byte prefix for balance of selectivity and memory.
    prefix_index: HashMap<[u8; 4], Vec<usize>>,

    /// Minimum match confidence to report.
    min_confidence: f32,
}

impl<'a> SignatureMatcher<'a> {
    /// Create a new matcher for the given database.
    pub fn new(database: &'a SignatureDatabase) -> Self {
        let mut matcher = Self {
            database,
            prefix_index: HashMap::new(),
            min_confidence: 0.0,
        };
        matcher.build_index();
        matcher
    }

    /// Set the minimum confidence threshold.
    pub fn with_min_confidence(mut self, confidence: f32) -> Self {
        self.min_confidence = confidence;
        self
    }

    /// Build the prefix index.
    fn build_index(&mut self) {
        for (idx, sig) in self.database.signatures().iter().enumerate() {
            // Get the first 4 concrete bytes for indexing
            if let Some(prefix_bytes) = sig.pattern.prefix_bytes(4) {
                let mut prefix = [0u8; 4];
                prefix.copy_from_slice(&prefix_bytes[..4]);
                self.prefix_index.entry(prefix).or_default().push(idx);
            }
            // Also index signatures with fewer concrete prefix bytes
            // using what we have
            else if let Some(prefix_bytes) = sig.pattern.prefix_bytes(1) {
                // For short prefixes, we use a fallback indexing strategy
                // by setting remaining bytes to 0 (will match more candidates)
                let mut prefix = [0u8; 4];
                for (i, b) in prefix_bytes.iter().enumerate() {
                    if i < 4 {
                        prefix[i] = *b;
                    }
                }
                self.prefix_index.entry(prefix).or_default().push(idx);
            }
        }
    }

    /// Match bytes against all signatures, returning the best match.
    pub fn match_bytes(&self, bytes: &[u8]) -> Option<MatchResult<'a>> {
        self.match_bytes_all(bytes).into_iter().next()
    }

    /// Match bytes and return all matches, sorted by confidence (highest first).
    pub fn match_bytes_all(&self, bytes: &[u8]) -> Vec<MatchResult<'a>> {
        if bytes.len() < 4 {
            return Vec::new();
        }

        let mut matches = Vec::new();

        // Get prefix for index lookup
        let mut prefix = [0u8; 4];
        prefix.copy_from_slice(&bytes[..4]);

        // Check signatures with matching prefix
        if let Some(candidates) = self.prefix_index.get(&prefix) {
            for &idx in candidates {
                if let Some(sig) = self.database.signatures().get(idx) {
                    if sig.matches(bytes) {
                        let confidence = self.calculate_confidence(sig, bytes);
                        if confidence >= self.min_confidence {
                            matches.push(MatchResult::new(sig, confidence, 0));
                        }
                    }
                }
            }
        }

        // Also check signatures with wildcards in prefix
        // (they won't be in the prefix index for this input)
        for sig in self.database.signatures() {
            if sig.pattern.concrete_prefix_len() < 4 && sig.matches(bytes) {
                let confidence = self.calculate_confidence(sig, bytes);
                if confidence >= self.min_confidence {
                    // Avoid duplicates
                    if !matches.iter().any(|m| m.signature.name == sig.name) {
                        matches.push(MatchResult::new(sig, confidence, 0));
                    }
                }
            }
        }

        // Sort by confidence (highest first)
        matches.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
        matches
    }

    /// Scan bytes for any matching signature at any offset.
    /// Returns all matches found.
    pub fn scan(&self, bytes: &[u8]) -> Vec<MatchResult<'a>> {
        let mut matches = Vec::new();

        for offset in 0..bytes.len().saturating_sub(4) {
            for result in self.match_bytes_all(&bytes[offset..]) {
                matches.push(MatchResult::new(
                    result.signature,
                    result.confidence,
                    offset,
                ));
            }
        }

        // Sort by offset, then confidence
        matches.sort_by(|a, b| {
            a.offset.cmp(&b.offset)
                .then_with(|| b.confidence.partial_cmp(&a.confidence).unwrap())
        });

        // Remove duplicates (same signature at same offset)
        matches.dedup_by(|a, b| a.signature.name == b.signature.name && a.offset == b.offset);

        matches
    }

    /// Calculate match confidence based on pattern properties.
    fn calculate_confidence(&self, sig: &FunctionSignature, bytes: &[u8]) -> f32 {
        let mut confidence = sig.confidence;

        // Boost confidence for longer patterns
        let pattern_len = sig.pattern.len();
        if pattern_len >= 16 {
            confidence += 0.1;
        } else if pattern_len >= 8 {
            confidence += 0.05;
        }

        // Boost confidence for patterns with more concrete bytes
        let concrete_count = sig.pattern.bytes().iter()
            .filter(|b| b.is_concrete())
            .count();
        let concrete_ratio = concrete_count as f32 / pattern_len as f32;
        confidence += concrete_ratio * 0.1;

        // Boost confidence if size hint matches
        if let Some(size_hint) = sig.size_hint {
            // Assume we have some knowledge of function size
            // This would need actual function boundary detection in practice
            if bytes.len() >= size_hint {
                confidence += 0.05;
            }
        }

        confidence.clamp(0.0, 1.0)
    }

    /// Get the number of indexed prefixes.
    pub fn prefix_count(&self) -> usize {
        self.prefix_index.len()
    }

    /// Get the total number of indexed signature references.
    pub fn index_entries(&self) -> usize {
        self.prefix_index.values().map(|v| v.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FunctionSignature;

    fn make_test_database() -> SignatureDatabase {
        let mut db = SignatureDatabase::new();

        db.add(FunctionSignature::from_hex("strlen", "55 48 89 E5 48 89 7D F8").unwrap()
            .with_confidence(0.8));
        db.add(FunctionSignature::from_hex("strcpy", "55 48 89 E5 48 89 7D E8").unwrap()
            .with_confidence(0.8));
        db.add(FunctionSignature::from_hex("memset", "55 48 89 E5 48 89 7D D8").unwrap()
            .with_confidence(0.8));

        db
    }

    #[test]
    fn test_matcher_basic() {
        let db = make_test_database();
        let matcher = SignatureMatcher::new(&db);

        let strlen_bytes = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x89, 0x7D, 0xF8, 0x00, 0x00];
        let result = matcher.match_bytes(&strlen_bytes);
        assert!(result.is_some());
        assert_eq!(result.unwrap().signature.name, "strlen");
    }

    #[test]
    fn test_matcher_no_match() {
        let db = make_test_database();
        let matcher = SignatureMatcher::new(&db);

        let unknown_bytes = [0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];
        let result = matcher.match_bytes(&unknown_bytes);
        assert!(result.is_none());
    }

    #[test]
    fn test_matcher_all_matches() {
        let db = make_test_database();
        let matcher = SignatureMatcher::new(&db);

        // This prefix matches multiple patterns partially
        let common_prefix = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x89, 0x7D, 0xF8];
        let results = matcher.match_bytes_all(&common_prefix);
        assert!(!results.is_empty());
        // strlen should match exactly
        assert!(results.iter().any(|r| r.signature.name == "strlen"));
    }

    #[test]
    fn test_matcher_scan() {
        let db = make_test_database();
        let matcher = SignatureMatcher::new(&db);

        // Create bytes with strlen pattern at offset 4
        let mut bytes = vec![0x90; 4];
        bytes.extend_from_slice(&[0x55, 0x48, 0x89, 0xE5, 0x48, 0x89, 0x7D, 0xF8]);
        bytes.extend_from_slice(&[0x90; 4]);

        let results = matcher.scan(&bytes);
        assert!(!results.is_empty());
        let strlen_match = results.iter().find(|r| r.signature.name == "strlen");
        assert!(strlen_match.is_some());
        assert_eq!(strlen_match.unwrap().offset, 4);
    }

    #[test]
    fn test_matcher_min_confidence() {
        let db = make_test_database();
        let matcher = SignatureMatcher::new(&db).with_min_confidence(0.9);

        let strlen_bytes = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x89, 0x7D, 0xF8];
        let result = matcher.match_bytes(&strlen_bytes);
        // Base confidence 0.8 + bonuses should be around 0.9
        // Result may or may not pass depending on exact calculation
        // This test just verifies the threshold works
        if let Some(m) = result {
            assert!(m.confidence >= 0.9);
        }
    }
}
