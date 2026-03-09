#![no_main]

use hexray_signatures::{BytePattern, FunctionSignature, SignatureDatabase, SignatureMatcher};
use libfuzzer_sys::fuzz_target;

fn pattern_from_bytes(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "??".to_string();
    }

    bytes
        .iter()
        .take(24)
        .map(|byte| match byte % 5 {
            0 => "??".to_string(),
            1 => format!("{:02X}&F0", byte),
            _ => format!("{:02X}", byte),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fuzz_target!(|data: &[u8]| {
    let split = data.len().min(24);
    let pattern = pattern_from_bytes(&data[..split]);
    let haystack = &data[split..];

    let _ = BytePattern::parse(&pattern);

    if let Ok(sig) = FunctionSignature::from_hex("fuzz_signature", &pattern) {
        let mut db = SignatureDatabase::new();
        db.add(sig);

        let matcher = SignatureMatcher::new(&db);
        let _ = matcher.match_bytes(haystack);
        let _ = matcher.match_bytes_all(haystack);
        let _ = matcher.scan(haystack);
        let _ = db.stats();
        let _ = db.to_json();
    }

    let json = String::from_utf8_lossy(data);
    if let Ok(db) = SignatureDatabase::from_json(&json) {
        let matcher = SignatureMatcher::new(&db);
        let _ = matcher.match_bytes(haystack);
        let _ = matcher.scan(haystack);
    }
});
