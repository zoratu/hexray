//! Signature database storage and management.
//!
//! The database stores function signatures and provides
//! efficient lookup and serialization.

use crate::signature::FunctionSignature;
use crate::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// A database of function signatures.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SignatureDatabase {
    /// Database name.
    pub name: String,

    /// Database version.
    pub version: String,

    /// Description.
    pub description: Option<String>,

    /// Target architecture (e.g., "x86_64", "aarch64", "riscv64").
    pub architecture: Option<String>,

    /// Target OS (e.g., "linux", "macos", "windows").
    pub os: Option<String>,

    /// Function signatures.
    signatures: Vec<FunctionSignature>,

    /// Name index for fast lookup.
    #[serde(skip)]
    name_index: HashMap<String, usize>,
}

impl SignatureDatabase {
    /// Create a new empty database.
    pub fn new() -> Self {
        Self {
            name: "unnamed".to_string(),
            version: "1.0".to_string(),
            description: None,
            architecture: None,
            os: None,
            signatures: Vec::new(),
            name_index: HashMap::new(),
        }
    }

    /// Create a new database with metadata.
    pub fn with_metadata(
        name: impl Into<String>,
        version: impl Into<String>,
        description: Option<String>,
    ) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            description,
            architecture: None,
            os: None,
            signatures: Vec::new(),
            name_index: HashMap::new(),
        }
    }

    /// Set the target architecture.
    pub fn with_architecture(mut self, arch: impl Into<String>) -> Self {
        self.architecture = Some(arch.into());
        self
    }

    /// Set the target OS.
    pub fn with_os(mut self, os: impl Into<String>) -> Self {
        self.os = Some(os.into());
        self
    }

    /// Add a signature to the database.
    pub fn add(&mut self, signature: FunctionSignature) {
        let idx = self.signatures.len();
        self.name_index.insert(signature.name.clone(), idx);

        // Also index aliases, but don't overwrite existing entries
        // This ensures the first function added with a name takes precedence
        for alias in &signature.aliases {
            self.name_index.entry(alias.clone()).or_insert(idx);
        }

        self.signatures.push(signature);
    }

    /// Get a signature by name.
    pub fn get(&self, name: &str) -> Option<&FunctionSignature> {
        self.name_index.get(name).map(|&idx| &self.signatures[idx])
    }

    /// Get all signatures.
    pub fn signatures(&self) -> &[FunctionSignature] {
        &self.signatures
    }

    /// Get the number of signatures.
    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    /// Check if the database is empty.
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Get all signature names.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.signatures.iter().map(|s| s.name.as_str())
    }

    /// Merge another database into this one.
    pub fn merge(&mut self, other: &SignatureDatabase) {
        for sig in &other.signatures {
            if !self.name_index.contains_key(&sig.name) {
                self.add(sig.clone());
            }
        }
    }

    /// Rebuild the name index after deserialization.
    pub fn rebuild_index(&mut self) {
        self.name_index.clear();
        for (idx, sig) in self.signatures.iter().enumerate() {
            self.name_index.insert(sig.name.clone(), idx);
            for alias in &sig.aliases {
                self.name_index.insert(alias.clone(), idx);
            }
        }
    }

    /// Save the database to a JSON file.
    pub fn save_json(&self, path: impl AsRef<Path>) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load a database from a JSON file.
    pub fn load_json(path: impl AsRef<Path>) -> Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let mut db: Self = serde_json::from_str(&json)?;
        db.rebuild_index();
        Ok(db)
    }

    /// Parse a database from JSON string.
    pub fn from_json(json: &str) -> Result<Self> {
        let mut db: Self = serde_json::from_str(json)?;
        db.rebuild_index();
        Ok(db)
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Filter signatures by library.
    pub fn filter_by_library(&self, library: &str) -> Vec<&FunctionSignature> {
        self.signatures
            .iter()
            .filter(|s| s.library == library)
            .collect()
    }

    /// Filter signatures by minimum confidence.
    pub fn filter_by_confidence(&self, min_confidence: f32) -> Vec<&FunctionSignature> {
        self.signatures
            .iter()
            .filter(|s| s.confidence >= min_confidence)
            .collect()
    }

    /// Get statistics about the database.
    pub fn stats(&self) -> DatabaseStats {
        let total = self.signatures.len();
        let mut libraries = HashMap::new();
        let mut total_pattern_len = 0;
        let mut min_pattern_len = usize::MAX;
        let mut max_pattern_len = 0;

        for sig in &self.signatures {
            *libraries.entry(sig.library.clone()).or_insert(0) += 1;
            let len = sig.pattern.len();
            total_pattern_len += len;
            min_pattern_len = min_pattern_len.min(len);
            max_pattern_len = max_pattern_len.max(len);
        }

        if total == 0 {
            min_pattern_len = 0;
        }

        DatabaseStats {
            total_signatures: total,
            libraries,
            avg_pattern_len: if total > 0 {
                total_pattern_len as f32 / total as f32
            } else {
                0.0
            },
            min_pattern_len,
            max_pattern_len,
        }
    }
}

/// Statistics about a signature database.
#[derive(Debug, Clone)]
pub struct DatabaseStats {
    /// Total number of signatures.
    pub total_signatures: usize,
    /// Signatures per library.
    pub libraries: HashMap<String, usize>,
    /// Average pattern length.
    pub avg_pattern_len: f32,
    /// Minimum pattern length.
    pub min_pattern_len: usize,
    /// Maximum pattern length.
    pub max_pattern_len: usize,
}

impl std::fmt::Display for DatabaseStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Total signatures: {}", self.total_signatures)?;
        writeln!(f, "Libraries:")?;
        for (lib, count) in &self.libraries {
            writeln!(f, "  {}: {} signatures", lib, count)?;
        }
        writeln!(
            f,
            "Pattern length: {:.1} avg, {} min, {} max",
            self.avg_pattern_len, self.min_pattern_len, self.max_pattern_len
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_basic() {
        let mut db = SignatureDatabase::new();
        assert!(db.is_empty());

        db.add(FunctionSignature::from_hex("strlen", "55 48 89 E5").unwrap());
        assert_eq!(db.len(), 1);
        assert!(db.get("strlen").is_some());
    }

    #[test]
    fn test_database_alias() {
        let mut db = SignatureDatabase::new();

        db.add(
            FunctionSignature::from_hex("__strlen_sse2", "55 48 89 E5")
                .unwrap()
                .with_alias("strlen"),
        );

        assert!(db.get("__strlen_sse2").is_some());
        assert!(db.get("strlen").is_some());
    }

    #[test]
    fn test_database_json() {
        let mut db =
            SignatureDatabase::with_metadata("test", "1.0", Some("Test database".to_string()));
        db.add(FunctionSignature::from_hex("strlen", "55 48 89 E5").unwrap());
        db.add(FunctionSignature::from_hex("strcpy", "55 48 89 E5 48").unwrap());

        let json = db.to_json().unwrap();
        let loaded = SignatureDatabase::from_json(&json).unwrap();

        assert_eq!(loaded.name, "test");
        assert_eq!(loaded.len(), 2);
        assert!(loaded.get("strlen").is_some());
    }

    #[test]
    fn test_database_merge() {
        let mut db1 = SignatureDatabase::new();
        db1.add(FunctionSignature::from_hex("strlen", "55 48 89 E5").unwrap());

        let mut db2 = SignatureDatabase::new();
        db2.add(FunctionSignature::from_hex("strcpy", "55 48 89 E5 48").unwrap());

        db1.merge(&db2);
        assert_eq!(db1.len(), 2);
        assert!(db1.get("strlen").is_some());
        assert!(db1.get("strcpy").is_some());
    }

    #[test]
    fn test_database_stats() {
        let mut db = SignatureDatabase::new();
        db.add(
            FunctionSignature::from_hex("strlen", "55 48 89 E5")
                .unwrap()
                .with_library("libc"),
        );
        db.add(
            FunctionSignature::from_hex("strcpy", "55 48 89 E5 48 89")
                .unwrap()
                .with_library("libc"),
        );
        db.add(
            FunctionSignature::from_hex("malloc", "55 48 89 E5 48")
                .unwrap()
                .with_library("malloc"),
        );

        let stats = db.stats();
        assert_eq!(stats.total_signatures, 3);
        assert_eq!(stats.libraries.get("libc"), Some(&2));
        assert_eq!(stats.libraries.get("malloc"), Some(&1));
        assert_eq!(stats.min_pattern_len, 4);
        assert_eq!(stats.max_pattern_len, 6);
    }

    // ==================== Database Construction Tests ====================

    #[test]
    fn test_database_new() {
        let db = SignatureDatabase::new();
        assert_eq!(db.name, "unnamed");
        assert_eq!(db.version, "1.0");
        assert!(db.description.is_none());
        assert!(db.architecture.is_none());
        assert!(db.os.is_none());
        assert!(db.is_empty());
    }

    #[test]
    fn test_database_with_metadata() {
        let db = SignatureDatabase::with_metadata(
            "test-db",
            "2.0",
            Some("Test database description".to_string()),
        );
        assert_eq!(db.name, "test-db");
        assert_eq!(db.version, "2.0");
        assert_eq!(
            db.description,
            Some("Test database description".to_string())
        );
    }

    #[test]
    fn test_database_with_architecture() {
        let db = SignatureDatabase::new().with_architecture("x86_64");
        assert_eq!(db.architecture, Some("x86_64".to_string()));
    }

    #[test]
    fn test_database_with_os() {
        let db = SignatureDatabase::new().with_os("linux");
        assert_eq!(db.os, Some("linux".to_string()));
    }

    #[test]
    fn test_database_builder_chain() {
        let db =
            SignatureDatabase::with_metadata("libc", "1.0", Some("LibC signatures".to_string()))
                .with_architecture("aarch64")
                .with_os("macos");

        assert_eq!(db.name, "libc");
        assert_eq!(db.architecture, Some("aarch64".to_string()));
        assert_eq!(db.os, Some("macos".to_string()));
    }

    // ==================== Add and Get Tests ====================

    #[test]
    fn test_database_add_multiple() {
        let mut db = SignatureDatabase::new();
        db.add(FunctionSignature::from_hex("func1", "55 48").unwrap());
        db.add(FunctionSignature::from_hex("func2", "55 48 89").unwrap());
        db.add(FunctionSignature::from_hex("func3", "55 48 89 E5").unwrap());

        assert_eq!(db.len(), 3);
        assert!(db.get("func1").is_some());
        assert!(db.get("func2").is_some());
        assert!(db.get("func3").is_some());
    }

    #[test]
    fn test_database_get_nonexistent() {
        let db = SignatureDatabase::new();
        assert!(db.get("nonexistent").is_none());
    }

    #[test]
    fn test_database_multiple_aliases() {
        let mut db = SignatureDatabase::new();
        db.add(
            FunctionSignature::from_hex("__strlen_sse2", "55 48")
                .unwrap()
                .with_alias("strlen")
                .with_alias("__strlen"),
        );

        assert!(db.get("__strlen_sse2").is_some());
        assert!(db.get("strlen").is_some());
        assert!(db.get("__strlen").is_some());
        // All should point to the same signature
        assert_eq!(db.get("strlen").unwrap().name, "__strlen_sse2");
    }

    #[test]
    fn test_database_alias_precedence() {
        let mut db = SignatureDatabase::new();
        // First add a function with alias "common"
        db.add(
            FunctionSignature::from_hex("func1", "55 48")
                .unwrap()
                .with_alias("common"),
        );
        // Then add another with same alias
        db.add(
            FunctionSignature::from_hex("func2", "55 48 89")
                .unwrap()
                .with_alias("common"),
        );

        // First function should keep the alias
        assert_eq!(db.get("common").unwrap().name, "func1");
    }

    // ==================== Signatures Accessor Tests ====================

    #[test]
    fn test_database_signatures() {
        let mut db = SignatureDatabase::new();
        db.add(FunctionSignature::from_hex("a", "55").unwrap());
        db.add(FunctionSignature::from_hex("b", "55 48").unwrap());

        let sigs = db.signatures();
        assert_eq!(sigs.len(), 2);
        assert_eq!(sigs[0].name, "a");
        assert_eq!(sigs[1].name, "b");
    }

    #[test]
    fn test_database_names() {
        let mut db = SignatureDatabase::new();
        db.add(FunctionSignature::from_hex("strlen", "55").unwrap());
        db.add(FunctionSignature::from_hex("strcpy", "55 48").unwrap());
        db.add(FunctionSignature::from_hex("memcpy", "55 48 89").unwrap());

        let names: Vec<&str> = db.names().collect();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&"strlen"));
        assert!(names.contains(&"strcpy"));
        assert!(names.contains(&"memcpy"));
    }

    // ==================== Merge Tests ====================

    #[test]
    fn test_database_merge_no_overlap() {
        let mut db1 = SignatureDatabase::new();
        db1.add(FunctionSignature::from_hex("func1", "55 48").unwrap());

        let mut db2 = SignatureDatabase::new();
        db2.add(FunctionSignature::from_hex("func2", "55 48 89").unwrap());

        db1.merge(&db2);
        assert_eq!(db1.len(), 2);
        assert!(db1.get("func1").is_some());
        assert!(db1.get("func2").is_some());
    }

    #[test]
    fn test_database_merge_with_overlap() {
        let mut db1 = SignatureDatabase::new();
        db1.add(
            FunctionSignature::from_hex("common", "55 48")
                .unwrap()
                .with_library("lib1"),
        );

        let mut db2 = SignatureDatabase::new();
        db2.add(
            FunctionSignature::from_hex("common", "55 48 89")
                .unwrap()
                .with_library("lib2"),
        );

        db1.merge(&db2);
        // Should keep db1's version
        assert_eq!(db1.len(), 1);
        assert_eq!(db1.get("common").unwrap().library, "lib1");
    }

    #[test]
    fn test_database_merge_empty() {
        let mut db1 = SignatureDatabase::new();
        db1.add(FunctionSignature::from_hex("func", "55").unwrap());

        let db2 = SignatureDatabase::new();
        db1.merge(&db2);
        assert_eq!(db1.len(), 1);
    }

    // ==================== Index Rebuild Tests ====================

    #[test]
    fn test_database_rebuild_index() {
        let mut db = SignatureDatabase::new();
        db.add(
            FunctionSignature::from_hex("func", "55")
                .unwrap()
                .with_alias("alias1")
                .with_alias("alias2"),
        );

        // Rebuild should maintain lookups
        db.rebuild_index();
        assert!(db.get("func").is_some());
        assert!(db.get("alias1").is_some());
        assert!(db.get("alias2").is_some());
    }

    // ==================== Filter Tests ====================

    #[test]
    fn test_database_filter_by_library() {
        let mut db = SignatureDatabase::new();
        db.add(
            FunctionSignature::from_hex("strlen", "55 48")
                .unwrap()
                .with_library("libc"),
        );
        db.add(
            FunctionSignature::from_hex("malloc", "55 48 89")
                .unwrap()
                .with_library("malloc"),
        );
        db.add(
            FunctionSignature::from_hex("strcpy", "55 48 89 E5")
                .unwrap()
                .with_library("libc"),
        );

        let libc_sigs = db.filter_by_library("libc");
        assert_eq!(libc_sigs.len(), 2);
        assert!(libc_sigs.iter().all(|s| s.library == "libc"));

        let malloc_sigs = db.filter_by_library("malloc");
        assert_eq!(malloc_sigs.len(), 1);
        assert_eq!(malloc_sigs[0].name, "malloc");
    }

    #[test]
    fn test_database_filter_by_library_empty() {
        let mut db = SignatureDatabase::new();
        db.add(
            FunctionSignature::from_hex("func", "55")
                .unwrap()
                .with_library("libc"),
        );

        let result = db.filter_by_library("nonexistent");
        assert!(result.is_empty());
    }

    #[test]
    fn test_database_filter_by_confidence() {
        let mut db = SignatureDatabase::new();
        db.add(
            FunctionSignature::from_hex("low", "55")
                .unwrap()
                .with_confidence(0.3),
        );
        db.add(
            FunctionSignature::from_hex("medium", "55 48")
                .unwrap()
                .with_confidence(0.6),
        );
        db.add(
            FunctionSignature::from_hex("high", "55 48 89")
                .unwrap()
                .with_confidence(0.9),
        );

        let high_conf = db.filter_by_confidence(0.8);
        assert_eq!(high_conf.len(), 1);
        assert_eq!(high_conf[0].name, "high");

        let medium_conf = db.filter_by_confidence(0.5);
        assert_eq!(medium_conf.len(), 2);
    }

    // ==================== Stats Tests ====================

    #[test]
    fn test_database_stats_empty() {
        let db = SignatureDatabase::new();
        let stats = db.stats();

        assert_eq!(stats.total_signatures, 0);
        assert!(stats.libraries.is_empty());
        assert!((stats.avg_pattern_len - 0.0).abs() < 0.001);
        assert_eq!(stats.min_pattern_len, 0);
        assert_eq!(stats.max_pattern_len, 0);
    }

    #[test]
    fn test_database_stats_single() {
        let mut db = SignatureDatabase::new();
        db.add(
            FunctionSignature::from_hex("func", "55 48 89 E5")
                .unwrap()
                .with_library("libc"),
        );

        let stats = db.stats();
        assert_eq!(stats.total_signatures, 1);
        assert_eq!(stats.libraries.get("libc"), Some(&1));
        assert!((stats.avg_pattern_len - 4.0).abs() < 0.001);
        assert_eq!(stats.min_pattern_len, 4);
        assert_eq!(stats.max_pattern_len, 4);
    }

    #[test]
    fn test_database_stats_display() {
        let mut db = SignatureDatabase::new();
        db.add(
            FunctionSignature::from_hex("func", "55 48")
                .unwrap()
                .with_library("libc"),
        );

        let stats = db.stats();
        let display = format!("{}", stats);

        assert!(display.contains("Total signatures: 1"));
        assert!(display.contains("libc"));
    }

    // ==================== JSON Serialization Tests ====================

    #[test]
    fn test_database_json_roundtrip() {
        let mut db = SignatureDatabase::with_metadata("test", "1.0", Some("Test".to_string()))
            .with_architecture("x86_64")
            .with_os("linux");

        db.add(
            FunctionSignature::from_hex("strlen", "55 48 89 E5")
                .unwrap()
                .with_library("libc")
                .with_confidence(0.9)
                .with_alias("__strlen"),
        );

        let json = db.to_json().unwrap();
        let loaded = SignatureDatabase::from_json(&json).unwrap();

        assert_eq!(loaded.name, "test");
        assert_eq!(loaded.version, "1.0");
        assert_eq!(loaded.architecture, Some("x86_64".to_string()));
        assert_eq!(loaded.os, Some("linux".to_string()));
        assert_eq!(loaded.len(), 1);
        assert!(loaded.get("strlen").is_some());
        assert!(loaded.get("__strlen").is_some()); // Alias should work after reload
    }

    #[test]
    fn test_database_json_preserves_signature_details() {
        let mut db = SignatureDatabase::new();
        db.add(
            FunctionSignature::from_hex("func", "55 ?? 89 E5")
                .unwrap()
                .with_library("testlib")
                .with_version("1.0")
                .with_doc("Test function")
                .with_confidence(0.75),
        );

        let json = db.to_json().unwrap();
        let loaded = SignatureDatabase::from_json(&json).unwrap();

        let sig = loaded.get("func").unwrap();
        assert_eq!(sig.library, "testlib");
        assert_eq!(sig.version, Some("1.0".to_string()));
        assert_eq!(sig.doc, Some("Test function".to_string()));
        assert!((sig.confidence - 0.75).abs() < 0.001);
    }

    #[test]
    fn test_database_from_json_invalid() {
        let result = SignatureDatabase::from_json("not valid json");
        assert!(result.is_err());
    }
}
