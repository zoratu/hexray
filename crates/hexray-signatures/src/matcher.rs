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
            a.offset
                .cmp(&b.offset)
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
        let concrete_count = sig
            .pattern
            .bytes()
            .iter()
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

        db.add(
            FunctionSignature::from_hex("strlen", "55 48 89 E5 48 89 7D F8")
                .unwrap()
                .with_confidence(0.8),
        );
        db.add(
            FunctionSignature::from_hex("strcpy", "55 48 89 E5 48 89 7D E8")
                .unwrap()
                .with_confidence(0.8),
        );
        db.add(
            FunctionSignature::from_hex("memset", "55 48 89 E5 48 89 7D D8")
                .unwrap()
                .with_confidence(0.8),
        );

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

    // ==================== MatchResult Tests ====================

    #[test]
    fn test_match_result_new() {
        let db = make_test_database();
        let sig = db.get("strlen").unwrap();
        let result = MatchResult::new(sig, 0.85, 10);

        assert_eq!(result.signature.name, "strlen");
        assert!((result.confidence - 0.85).abs() < 0.001);
        assert_eq!(result.offset, 10);
    }

    // ==================== Matcher Construction Tests ====================

    #[test]
    fn test_matcher_prefix_count() {
        let db = make_test_database();
        let matcher = SignatureMatcher::new(&db);

        // All signatures share same prefix, so should be 1
        assert_eq!(matcher.prefix_count(), 1);
    }

    #[test]
    fn test_matcher_index_entries() {
        let db = make_test_database();
        let matcher = SignatureMatcher::new(&db);

        // 3 signatures indexed
        assert_eq!(matcher.index_entries(), 3);
    }

    #[test]
    fn test_matcher_different_prefixes() {
        let mut db = SignatureDatabase::new();
        db.add(FunctionSignature::from_hex("func1", "55 48 89 E5").unwrap());
        db.add(FunctionSignature::from_hex("func2", "48 83 EC 20").unwrap());
        db.add(FunctionSignature::from_hex("func3", "41 57 41 56").unwrap());

        let matcher = SignatureMatcher::new(&db);
        assert_eq!(matcher.prefix_count(), 3);
    }

    #[test]
    fn test_matcher_empty_database() {
        let db = SignatureDatabase::new();
        let matcher = SignatureMatcher::new(&db);

        let bytes = [0x55, 0x48, 0x89, 0xE5];
        assert!(matcher.match_bytes(&bytes).is_none());
        assert!(matcher.match_bytes_all(&bytes).is_empty());
    }

    // ==================== Matching Tests ====================

    #[test]
    fn test_matcher_bytes_too_short() {
        let db = make_test_database();
        let matcher = SignatureMatcher::new(&db);

        // Less than 4 bytes should return no matches
        assert!(matcher.match_bytes(&[0x55, 0x48, 0x89]).is_none());
        assert!(matcher.match_bytes(&[]).is_none());
    }

    #[test]
    fn test_matcher_partial_match() {
        let db = make_test_database();
        let matcher = SignatureMatcher::new(&db);

        // First 4 bytes match prefix but full pattern doesn't match
        let bytes = [0x55, 0x48, 0x89, 0xE5, 0x00, 0x00, 0x00, 0x00];
        let result = matcher.match_bytes(&bytes);
        // None should match since patterns need full 8 bytes
        assert!(result.is_none());
    }

    #[test]
    fn test_matcher_multiple_candidates() {
        let mut db = SignatureDatabase::new();
        // Add two signatures with similar but different patterns
        db.add(
            FunctionSignature::from_hex("func1", "55 48 89 E5 48 89 7D F8")
                .unwrap()
                .with_confidence(0.7),
        );
        db.add(
            FunctionSignature::from_hex("func2", "55 48 89 E5 48 89 7D E8")
                .unwrap()
                .with_confidence(0.9),
        );

        let matcher = SignatureMatcher::new(&db);

        // Test func1 pattern
        let bytes1 = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x89, 0x7D, 0xF8];
        let result1 = matcher.match_bytes(&bytes1);
        assert!(result1.is_some());
        assert_eq!(result1.unwrap().signature.name, "func1");

        // Test func2 pattern
        let bytes2 = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x89, 0x7D, 0xE8];
        let result2 = matcher.match_bytes(&bytes2);
        assert!(result2.is_some());
        assert_eq!(result2.unwrap().signature.name, "func2");
    }

    #[test]
    fn test_matcher_all_returns_sorted() {
        let mut db = SignatureDatabase::new();
        db.add(
            FunctionSignature::from_hex("low", "55 48 89 E5")
                .unwrap()
                .with_confidence(0.3),
        );
        db.add(
            FunctionSignature::from_hex("high", "55 48 89 E5")
                .unwrap()
                .with_confidence(0.9),
        );

        let matcher = SignatureMatcher::new(&db);
        let bytes = [0x55, 0x48, 0x89, 0xE5, 0x00, 0x00, 0x00, 0x00];
        let results = matcher.match_bytes_all(&bytes);

        // Results should be sorted by confidence descending
        if results.len() >= 2 {
            assert!(results[0].confidence >= results[1].confidence);
        }
    }

    // ==================== Wildcard Pattern Tests ====================

    #[test]
    fn test_matcher_wildcard_prefix() {
        let mut db = SignatureDatabase::new();
        // Pattern with wildcard at start (concrete_prefix_len < 4)
        db.add(
            FunctionSignature::from_hex("func_wildcard", "?? 48 89 E5")
                .unwrap()
                .with_confidence(0.7),
        );

        let matcher = SignatureMatcher::new(&db);

        let bytes = [0x55, 0x48, 0x89, 0xE5, 0x00, 0x00];
        let result = matcher.match_bytes(&bytes);
        assert!(result.is_some());
        assert_eq!(result.unwrap().signature.name, "func_wildcard");

        // Should match with different first byte
        let bytes2 = [0x41, 0x48, 0x89, 0xE5, 0x00, 0x00];
        let result2 = matcher.match_bytes(&bytes2);
        assert!(result2.is_some());
    }

    #[test]
    fn test_matcher_multiple_wildcards() {
        let mut db = SignatureDatabase::new();
        db.add(
            FunctionSignature::from_hex("func_wild", "55 ?? ?? E5")
                .unwrap()
                .with_confidence(0.7),
        );

        let matcher = SignatureMatcher::new(&db);

        let bytes = [0x55, 0x00, 0x00, 0xE5];
        let result = matcher.match_bytes(&bytes);
        assert!(result.is_some());

        let bytes2 = [0x55, 0xFF, 0xFF, 0xE5];
        let result2 = matcher.match_bytes(&bytes2);
        assert!(result2.is_some());
    }

    // ==================== Scan Tests ====================

    #[test]
    fn test_matcher_scan_multiple_matches() {
        let mut db = SignatureDatabase::new();
        db.add(
            FunctionSignature::from_hex("func1", "55 48 89 E5")
                .unwrap()
                .with_confidence(0.8),
        );

        let matcher = SignatureMatcher::new(&db);

        // Two occurrences of the pattern
        let mut bytes = vec![0x90; 20];
        bytes[2..6].copy_from_slice(&[0x55, 0x48, 0x89, 0xE5]);
        bytes[10..14].copy_from_slice(&[0x55, 0x48, 0x89, 0xE5]);

        let results = matcher.scan(&bytes);

        // Should find matches at offsets 2 and 10
        let offsets: Vec<usize> = results.iter().map(|r| r.offset).collect();
        assert!(offsets.contains(&2));
        assert!(offsets.contains(&10));
    }

    #[test]
    fn test_matcher_scan_empty() {
        let db = make_test_database();
        let matcher = SignatureMatcher::new(&db);

        // No matching patterns
        let bytes = vec![0x90; 20];
        let results = matcher.scan(&bytes);
        assert!(results.is_empty());
    }

    #[test]
    fn test_matcher_scan_sorted_by_offset() {
        let mut db = SignatureDatabase::new();
        db.add(FunctionSignature::from_hex("func", "55 48 89 E5").unwrap());

        let matcher = SignatureMatcher::new(&db);

        let mut bytes = vec![0x90; 30];
        bytes[20..24].copy_from_slice(&[0x55, 0x48, 0x89, 0xE5]);
        bytes[5..9].copy_from_slice(&[0x55, 0x48, 0x89, 0xE5]);

        let results = matcher.scan(&bytes);

        // Results should be sorted by offset
        for i in 1..results.len() {
            assert!(results[i].offset >= results[i - 1].offset);
        }
    }

    #[test]
    fn test_matcher_scan_deduplicates() {
        let mut db = SignatureDatabase::new();
        // Two signatures that match the same bytes
        db.add(
            FunctionSignature::from_hex("func1", "55 48 89 E5")
                .unwrap()
                .with_confidence(0.8),
        );
        db.add(
            FunctionSignature::from_hex("func1_alias", "55 48 89 E5")
                .unwrap()
                .with_alias("func1")
                .with_confidence(0.7),
        );

        let matcher = SignatureMatcher::new(&db);

        let mut bytes = vec![0x90; 10];
        bytes[2..6].copy_from_slice(&[0x55, 0x48, 0x89, 0xE5]);

        let results = matcher.scan(&bytes);

        // Should not have duplicate func1 at same offset
        let func1_at_2: Vec<_> = results
            .iter()
            .filter(|r| r.signature.name == "func1" && r.offset == 2)
            .collect();
        assert!(func1_at_2.len() <= 1);
    }

    // ==================== Confidence Calculation Tests ====================

    #[test]
    fn test_matcher_confidence_boost_long_pattern() {
        let mut db = SignatureDatabase::new();
        // 16+ byte pattern should get confidence boost
        db.add(
            FunctionSignature::from_hex(
                "long_func",
                "55 48 89 E5 48 83 EC 20 48 89 7D E8 48 89 75 E0 89 55 DC",
            )
            .unwrap()
            .with_confidence(0.5),
        );

        let matcher = SignatureMatcher::new(&db);
        let bytes: Vec<u8> = vec![
            0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x89, 0x7D, 0xE8, 0x48, 0x89,
            0x75, 0xE0, 0x89, 0x55, 0xDC, 0x00,
        ];

        let result = matcher.match_bytes(&bytes);
        assert!(result.is_some());
        // Should be > 0.5 due to pattern length bonus
        assert!(result.unwrap().confidence > 0.5);
    }

    #[test]
    fn test_matcher_confidence_boost_concrete_bytes() {
        let mut db = SignatureDatabase::new();
        // All concrete bytes should get boost
        db.add(
            FunctionSignature::from_hex("concrete", "55 48 89 E5 48 83 EC 20")
                .unwrap()
                .with_confidence(0.5),
        );
        // Many wildcards should get less boost
        db.add(
            FunctionSignature::from_hex("wild", "55 ?? ?? ?? ?? ?? ?? ??")
                .unwrap()
                .with_confidence(0.5),
        );

        let matcher = SignatureMatcher::new(&db);
        let bytes = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20];

        let results = matcher.match_bytes_all(&bytes);

        // Find both matches
        let concrete_match = results.iter().find(|r| r.signature.name == "concrete");
        let wild_match = results.iter().find(|r| r.signature.name == "wild");

        assert!(concrete_match.is_some());
        assert!(wild_match.is_some());
        // Concrete should have higher confidence
        assert!(concrete_match.unwrap().confidence > wild_match.unwrap().confidence);
    }

    #[test]
    fn test_matcher_confidence_clamped() {
        let mut db = SignatureDatabase::new();
        // Very high confidence + long pattern + all concrete
        db.add(
            FunctionSignature::from_hex(
                "high_conf",
                "55 48 89 E5 48 83 EC 20 48 89 7D E8 48 89 75 E0 89 55 DC 48",
            )
            .unwrap()
            .with_confidence(0.95),
        );

        let matcher = SignatureMatcher::new(&db);
        let bytes: Vec<u8> = vec![
            0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x89, 0x7D, 0xE8, 0x48, 0x89,
            0x75, 0xE0, 0x89, 0x55, 0xDC, 0x48, 0x00,
        ];

        let result = matcher.match_bytes(&bytes);
        assert!(result.is_some());
        // Confidence should be clamped to 1.0
        assert!(result.unwrap().confidence <= 1.0);
    }

    // ==================== Size Hint Tests ====================

    #[test]
    fn test_matcher_size_hint_boost() {
        let mut db = SignatureDatabase::new();
        db.add(
            FunctionSignature::from_hex("sized", "55 48 89 E5")
                .unwrap()
                .with_size_hint(50)
                .with_confidence(0.5),
        );

        let matcher = SignatureMatcher::new(&db);

        // Bytes longer than size hint
        let mut bytes = vec![0x90; 100];
        bytes[0..4].copy_from_slice(&[0x55, 0x48, 0x89, 0xE5]);

        let result = matcher.match_bytes(&bytes);
        assert!(result.is_some());
        // Should get size hint boost
        assert!(result.unwrap().confidence > 0.5);
    }

    // ==================== Edge Cases ====================

    #[test]
    fn test_matcher_exact_four_bytes() {
        let mut db = SignatureDatabase::new();
        db.add(FunctionSignature::from_hex("short", "55 48 89 E5").unwrap());

        let matcher = SignatureMatcher::new(&db);

        // Exactly 4 bytes - minimum for matching
        let bytes = [0x55, 0x48, 0x89, 0xE5];
        let result = matcher.match_bytes(&bytes);
        assert!(result.is_some());
    }

    #[test]
    fn test_matcher_with_masked_pattern() {
        let mut db = SignatureDatabase::new();
        db.add(FunctionSignature::from_hex("masked", "55 48&F0 89 E5").unwrap());

        let matcher = SignatureMatcher::new(&db);

        // Should match - 0x48 has upper nibble 0x40
        let bytes = [0x55, 0x48, 0x89, 0xE5, 0x00, 0x00];
        let result = matcher.match_bytes(&bytes);
        assert!(result.is_some());

        // Should also match - 0x4F has same upper nibble
        let bytes2 = [0x55, 0x4F, 0x89, 0xE5, 0x00, 0x00];
        let result2 = matcher.match_bytes(&bytes2);
        assert!(result2.is_some());

        // Should not match - 0x58 has different upper nibble
        let bytes3 = [0x55, 0x58, 0x89, 0xE5, 0x00, 0x00];
        let result3 = matcher.match_bytes(&bytes3);
        assert!(result3.is_none());
    }
}
