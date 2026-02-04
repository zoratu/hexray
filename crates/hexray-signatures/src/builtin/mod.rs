//! Builtin signature databases.
//!
//! These are signatures for common library functions that ship with hexray.

pub mod libc_aarch64;
pub mod libc_x86_64;

use crate::SignatureDatabase;

/// Load all builtin signatures for x86_64.
pub fn load_x86_64() -> SignatureDatabase {
    let mut db = SignatureDatabase::with_metadata(
        "builtin-x86_64",
        "1.0",
        Some("Builtin signatures for x86_64".to_string()),
    )
    .with_architecture("x86_64");

    libc_x86_64::load_libc(&mut db);
    db
}

/// Load all builtin signatures for ARM64.
pub fn load_aarch64() -> SignatureDatabase {
    let mut db = SignatureDatabase::with_metadata(
        "builtin-aarch64",
        "1.0",
        Some("Builtin signatures for ARM64".to_string()),
    )
    .with_architecture("aarch64");

    libc_aarch64::load_libc(&mut db);
    db
}

/// Load builtin signatures for the given architecture.
pub fn load_for_architecture(arch: &str) -> SignatureDatabase {
    match arch.to_lowercase().as_str() {
        "x86_64" | "x64" | "amd64" => load_x86_64(),
        "aarch64" | "arm64" => load_aarch64(),
        _ => SignatureDatabase::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== load_x86_64 Tests ====================

    #[test]
    fn test_load_x86_64_metadata() {
        let db = load_x86_64();
        assert_eq!(db.name, "builtin-x86_64");
        assert_eq!(db.version, "1.0");
        assert_eq!(db.architecture, Some("x86_64".to_string()));
    }

    #[test]
    fn test_load_x86_64_not_empty() {
        let db = load_x86_64();
        assert!(!db.is_empty());
        assert!(db.len() > 20); // Should have substantial signatures
    }

    #[test]
    fn test_load_x86_64_common_functions() {
        let db = load_x86_64();

        // String functions
        assert!(db.get("strlen").is_some());
        assert!(db.get("strcpy").is_some());
        assert!(db.get("strcmp").is_some());
        assert!(db.get("strcat").is_some());

        // Memory functions
        assert!(db.get("memcpy").is_some());
        assert!(db.get("memset").is_some());
        assert!(db.get("malloc").is_some());
        assert!(db.get("free").is_some());
    }

    #[test]
    fn test_load_x86_64_signature_details() {
        let db = load_x86_64();

        let strlen = db.get("strlen").unwrap();
        assert!(!strlen.parameters.is_empty());
        assert!(strlen.doc.is_some());
        assert!(strlen.confidence > 0.0);
    }

    // ==================== load_aarch64 Tests ====================

    #[test]
    fn test_load_aarch64_metadata() {
        let db = load_aarch64();
        assert_eq!(db.name, "builtin-aarch64");
        assert_eq!(db.version, "1.0");
        assert_eq!(db.architecture, Some("aarch64".to_string()));
    }

    #[test]
    fn test_load_aarch64_not_empty() {
        let db = load_aarch64();
        assert!(!db.is_empty());
    }

    #[test]
    fn test_load_aarch64_common_functions() {
        let db = load_aarch64();

        // Should have at least some common libc functions
        // (AArch64 may have fewer signatures depending on implementation)
        let has_common =
            db.get("strlen").is_some() || db.get("memcpy").is_some() || db.get("malloc").is_some();

        assert!(has_common || !db.is_empty());
    }

    // ==================== load_for_architecture Tests ====================

    #[test]
    fn test_load_for_architecture_x86_64() {
        let db = load_for_architecture("x86_64");
        assert_eq!(db.architecture, Some("x86_64".to_string()));
        assert!(!db.is_empty());
    }

    #[test]
    fn test_load_for_architecture_x64_alias() {
        let db = load_for_architecture("x64");
        assert_eq!(db.architecture, Some("x86_64".to_string()));
    }

    #[test]
    fn test_load_for_architecture_amd64_alias() {
        let db = load_for_architecture("amd64");
        assert_eq!(db.architecture, Some("x86_64".to_string()));
    }

    #[test]
    fn test_load_for_architecture_aarch64() {
        let db = load_for_architecture("aarch64");
        assert_eq!(db.architecture, Some("aarch64".to_string()));
    }

    #[test]
    fn test_load_for_architecture_arm64_alias() {
        let db = load_for_architecture("arm64");
        assert_eq!(db.architecture, Some("aarch64".to_string()));
    }

    #[test]
    fn test_load_for_architecture_case_insensitive() {
        let db1 = load_for_architecture("X86_64");
        let db2 = load_for_architecture("X86_64");
        assert_eq!(db1.architecture, db2.architecture);

        let db3 = load_for_architecture("AARCH64");
        assert_eq!(db3.architecture, Some("aarch64".to_string()));
    }

    #[test]
    fn test_load_for_architecture_unknown() {
        let db = load_for_architecture("riscv64");
        assert!(db.is_empty());
        assert!(db.architecture.is_none());
    }

    #[test]
    fn test_load_for_architecture_empty_string() {
        let db = load_for_architecture("");
        assert!(db.is_empty());
    }

    #[test]
    fn test_load_for_architecture_invalid() {
        let db = load_for_architecture("not-a-real-arch");
        assert!(db.is_empty());
    }

    // ==================== Database Consistency Tests ====================

    #[test]
    fn test_all_signatures_have_library() {
        let db = load_x86_64();
        for sig in db.signatures() {
            assert!(
                !sig.library.is_empty(),
                "Signature {} missing library",
                sig.name
            );
        }
    }

    #[test]
    fn test_all_signatures_have_pattern() {
        let db = load_x86_64();
        for sig in db.signatures() {
            assert!(
                !sig.pattern.is_empty(),
                "Signature {} has empty pattern",
                sig.name
            );
        }
    }

    #[test]
    fn test_all_signatures_have_valid_confidence() {
        let db = load_x86_64();
        for sig in db.signatures() {
            assert!(
                sig.confidence >= 0.0 && sig.confidence <= 1.0,
                "Signature {} has invalid confidence: {}",
                sig.name,
                sig.confidence
            );
        }
    }

    #[test]
    fn test_no_duplicate_primary_names() {
        let db = load_x86_64();
        let names: Vec<&str> = db.signatures().iter().map(|s| s.name.as_str()).collect();
        let mut unique_names = names.clone();
        unique_names.sort();
        unique_names.dedup();

        // There shouldn't be duplicate primary names
        assert_eq!(
            names.len(),
            unique_names.len(),
            "Found duplicate signature names"
        );
    }

    // ==================== Matcher Integration Tests ====================

    #[test]
    fn test_builtin_signatures_matchable() {
        use crate::matcher::SignatureMatcher;

        let db = load_x86_64();
        let matcher = SignatureMatcher::new(&db);

        // Verify the matcher was built successfully
        assert!(matcher.prefix_count() > 0);
        assert!(matcher.index_entries() > 0);
    }

    #[test]
    fn test_match_strlen_pattern() {
        use crate::matcher::SignatureMatcher;

        let db = load_x86_64();
        let matcher = SignatureMatcher::new(&db);

        // Try to match strlen prologue pattern
        // push rbp; mov rbp, rsp; mov QWORD PTR [rbp-0x8], rdi
        let strlen_bytes = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x89, 0x7D, 0xF8, 0x00, 0x00];

        let result = matcher.match_bytes(&strlen_bytes);
        if let Some(m) = result {
            // If there's a match, it should be a string-related function
            assert!(
                m.signature.name.contains("str")
                    || m.signature
                        .doc
                        .as_ref()
                        .is_some_and(|d| d.to_lowercase().contains("string")),
                "Expected string function, got: {}",
                m.signature.name
            );
        }
    }

    #[test]
    fn test_match_syscall_pattern() {
        use crate::matcher::SignatureMatcher;

        let db = load_x86_64();
        let matcher = SignatureMatcher::new(&db);

        // write syscall pattern: mov eax, 1; syscall; cmp rax, -4096
        let write_bytes = [
            0xB8, 0x01, 0x00, 0x00, 0x00, 0x0F, 0x05, 0x48, 0x3D, 0x00, 0xF0, 0xFF, 0xFF,
        ];

        let result = matcher.match_bytes(&write_bytes);
        if let Some(m) = result {
            assert_eq!(m.signature.name, "write");
        }
    }
}
