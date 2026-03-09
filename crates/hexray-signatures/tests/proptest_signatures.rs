//! Property-based tests for signature parsing and matching.

use proptest::prelude::*;

use hexray_signatures::{
    BytePattern, FunctionSignature, PatternByte, SignatureDatabase, SignatureMatcher,
};

fn arb_pattern_byte() -> impl Strategy<Value = PatternByte> {
    prop_oneof![
        any::<u8>().prop_map(PatternByte::Concrete),
        Just(PatternByte::Wildcard),
        (any::<u8>(), any::<u8>()).prop_map(|(value, mask)| PatternByte::Masked { value, mask }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn pattern_hex_roundtrip(bytes in prop::collection::vec(arb_pattern_byte(), 0..32)) {
        let pattern = BytePattern::from_pattern_bytes(bytes.clone());
        let reparsed = BytePattern::parse(&pattern.to_hex_string()).expect("pattern should reparse");
        prop_assert_eq!(reparsed.bytes(), bytes.as_slice());
    }

    #[test]
    fn exact_patterns_match_inserted_bytes(
        pattern in prop::collection::vec(any::<u8>(), 4..24),
        suffix in prop::collection::vec(any::<u8>(), 0..24),
    ) {
        let signature = FunctionSignature::new("generated", BytePattern::from_bytes(&pattern));
        let mut db = SignatureDatabase::new();
        db.add(signature);
        let matcher = SignatureMatcher::new(&db);

        let mut bytes = pattern.clone();
        bytes.extend_from_slice(&suffix);

        let result = matcher.match_bytes(&bytes).expect("exact match should resolve");
        prop_assert_eq!(&result.signature.name, "generated");
        prop_assert_eq!(result.offset, 0);
    }

    #[test]
    fn scan_reports_inserted_offset(
        prefix in prop::collection::vec(any::<u8>(), 0..16),
        pattern in prop::collection::vec(any::<u8>(), 4..16),
        suffix in prop::collection::vec(any::<u8>(), 0..16),
    ) {
        let signature = FunctionSignature::new("generated", BytePattern::from_bytes(&pattern));
        let mut db = SignatureDatabase::new();
        db.add(signature);
        let matcher = SignatureMatcher::new(&db);

        let mut bytes = prefix.clone();
        bytes.extend_from_slice(&pattern);
        bytes.extend_from_slice(&suffix);

        let matches = matcher.scan(&bytes);
        prop_assert!(
            matches.iter().any(|m| m.signature.name == "generated" && m.offset == prefix.len()),
            "expected a match for the injected pattern at offset {}",
            prefix.len()
        );
    }
}
