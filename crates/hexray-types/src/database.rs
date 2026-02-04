//! Type database for storing and looking up types.
//!
//! The TypeDatabase stores types, typedefs, and function prototypes,
//! allowing lookup by name and offset-based field access.

use crate::types::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A database of C types.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TypeDatabase {
    /// Named types (structs, unions, enums).
    types: HashMap<String, CType>,

    /// Typedefs.
    typedefs: HashMap<String, CType>,

    /// Function prototypes.
    functions: HashMap<String, FunctionPrototype>,

    /// Architecture info for size calculations.
    #[serde(skip)]
    arch: ArchInfo,
}

/// Architecture information for type sizing.
#[derive(Debug, Clone, Copy)]
pub struct ArchInfo {
    /// Pointer size in bytes.
    pub pointer_size: usize,
    /// Long size in bytes.
    pub long_size: usize,
    /// Is big endian?
    pub big_endian: bool,
}

impl Default for ArchInfo {
    fn default() -> Self {
        // Default to LP64 (Linux/macOS 64-bit)
        Self {
            pointer_size: 8,
            long_size: 8,
            big_endian: false,
        }
    }
}

impl ArchInfo {
    /// LP64 model (Linux, macOS 64-bit).
    pub fn lp64() -> Self {
        Self {
            pointer_size: 8,
            long_size: 8,
            big_endian: false,
        }
    }

    /// LLP64 model (Windows 64-bit).
    pub fn llp64() -> Self {
        Self {
            pointer_size: 8,
            long_size: 4, // long is 4 bytes on Windows
            big_endian: false,
        }
    }

    /// ILP32 model (32-bit).
    pub fn ilp32() -> Self {
        Self {
            pointer_size: 4,
            long_size: 4,
            big_endian: false,
        }
    }
}

impl TypeDatabase {
    /// Create a new empty type database.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with specific architecture info.
    pub fn with_arch(arch: ArchInfo) -> Self {
        Self {
            arch,
            ..Default::default()
        }
    }

    /// Get the architecture info.
    pub fn arch(&self) -> &ArchInfo {
        &self.arch
    }

    /// Set the architecture info.
    pub fn set_arch(&mut self, arch: ArchInfo) {
        self.arch = arch;
    }

    // ==================== Type Management ====================

    /// Add a named type (struct, union, enum).
    pub fn add_type(&mut self, name: impl Into<String>, ty: CType) {
        self.types.insert(name.into(), ty);
    }

    /// Add a typedef.
    pub fn add_typedef(&mut self, name: impl Into<String>, target: CType) {
        self.typedefs.insert(name.into(), target);
    }

    /// Add a function prototype.
    pub fn add_function(&mut self, proto: FunctionPrototype) {
        self.functions.insert(proto.name.clone(), proto);
    }

    /// Get a type by name.
    pub fn get_type(&self, name: &str) -> Option<&CType> {
        // Try direct type lookup first
        if let Some(ty) = self.types.get(name) {
            return Some(ty);
        }

        // Try typedef lookup
        if let Some(ty) = self.typedefs.get(name) {
            return Some(ty);
        }

        // Try with struct/union/enum prefix
        if let Some(ty) = self.types.get(&format!("struct {}", name)) {
            return Some(ty);
        }
        if let Some(ty) = self.types.get(&format!("union {}", name)) {
            return Some(ty);
        }
        if let Some(ty) = self.types.get(&format!("enum {}", name)) {
            return Some(ty);
        }

        None
    }

    /// Get a function prototype by name.
    pub fn get_function(&self, name: &str) -> Option<&FunctionPrototype> {
        self.functions.get(name)
    }

    /// Check if a type exists.
    pub fn has_type(&self, name: &str) -> bool {
        self.get_type(name).is_some()
    }

    /// Check if a function exists.
    pub fn has_function(&self, name: &str) -> bool {
        self.functions.contains_key(name)
    }

    /// Get all type names.
    pub fn type_names(&self) -> impl Iterator<Item = &str> {
        self.types.keys().map(|s| s.as_str())
    }

    /// Get all typedef names.
    pub fn typedef_names(&self) -> impl Iterator<Item = &str> {
        self.typedefs.keys().map(|s| s.as_str())
    }

    /// Get all function names.
    pub fn function_names(&self) -> impl Iterator<Item = &str> {
        self.functions.keys().map(|s| s.as_str())
    }

    // ==================== Struct Field Access ====================

    /// Get field at offset in a struct type.
    pub fn field_at_offset(&self, type_name: &str, offset: usize) -> Option<&StructField> {
        let ty = self.get_type(type_name)?;
        self.resolve_field_at_offset(ty, offset)
    }

    /// Resolve field at offset, following typedefs.
    fn resolve_field_at_offset<'a>(
        &'a self,
        ty: &'a CType,
        offset: usize,
    ) -> Option<&'a StructField> {
        match ty {
            CType::Struct(s) => s.field_at_offset(offset),
            CType::Typedef(t) => self.resolve_field_at_offset(&t.target, offset),
            CType::Named(name) => {
                let resolved = self.get_type(name)?;
                self.resolve_field_at_offset(resolved, offset)
            }
            _ => None,
        }
    }

    /// Format an offset access as a field reference.
    /// Returns something like ".st_size" or ".st_mode" for struct stat.
    pub fn format_field_access(&self, type_name: &str, offset: usize) -> Option<String> {
        let field = self.field_at_offset(type_name, offset)?;
        let base_offset = field.offset;

        if offset == base_offset {
            // Direct field access
            Some(format!(".{}", field.name))
        } else {
            // Access within the field (nested struct or array element)
            let inner_offset = offset - base_offset;
            match &field.field_type {
                CType::Struct(s) => {
                    if let Some(inner_field) = s.field_at_offset(inner_offset) {
                        Some(format!(".{}.{}", field.name, inner_field.name))
                    } else {
                        Some(format!(".{}", field.name))
                    }
                }
                CType::Array(a) => {
                    let elem_size = a.element.size().unwrap_or(1);
                    let index = inner_offset / elem_size;
                    Some(format!(".{}[{}]", field.name, index))
                }
                _ => Some(format!(".{}", field.name)),
            }
        }
    }

    // ==================== Formatting ====================

    /// Format a type as a C type definition.
    pub fn format_type(&self, name: &str) -> String {
        if let Some(ty) = self.get_type(name) {
            match ty {
                CType::Struct(s) => {
                    let mut result =
                        format!("struct {} {{\n", s.name.as_deref().unwrap_or("anonymous"));
                    for field in &s.fields {
                        result.push_str(&format!(
                            "    {}; // offset {}\n",
                            field.field_type.to_c_string(Some(&field.name)),
                            field.offset
                        ));
                    }
                    result.push('}');
                    if s.size > 0 {
                        result.push_str(&format!(" // size: {} bytes", s.size));
                    }
                    result
                }
                CType::Union(u) => {
                    let mut result =
                        format!("union {} {{\n", u.name.as_deref().unwrap_or("anonymous"));
                    for member in &u.members {
                        result.push_str(&format!(
                            "    {};\n",
                            member.member_type.to_c_string(Some(&member.name))
                        ));
                    }
                    result.push('}');
                    result
                }
                CType::Enum(e) => {
                    let mut result =
                        format!("enum {} {{\n", e.name.as_deref().unwrap_or("anonymous"));
                    for (name, value) in &e.values {
                        result.push_str(&format!("    {} = {},\n", name, value));
                    }
                    result.push('}');
                    result
                }
                CType::Typedef(t) => {
                    format!("typedef {} {};", t.target.to_c_string(None), name)
                }
                _ => ty.to_c_string(Some(name)),
            }
        } else if let Some(typedef_target) = self.typedefs.get(name) {
            format!("typedef {} {};", typedef_target.to_c_string(None), name)
        } else {
            format!("// Unknown type: {}", name)
        }
    }

    // ==================== Merging ====================

    /// Merge another database into this one.
    pub fn merge(&mut self, other: &TypeDatabase) {
        for (name, ty) in &other.types {
            self.types.insert(name.clone(), ty.clone());
        }
        for (name, ty) in &other.typedefs {
            self.typedefs.insert(name.clone(), ty.clone());
        }
        for (name, func) in &other.functions {
            self.functions.insert(name.clone(), func.clone());
        }
    }

    // ==================== Serialization ====================

    /// Save database to JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Load database from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    // ==================== Statistics ====================

    /// Get database statistics.
    pub fn stats(&self) -> TypeDatabaseStats {
        TypeDatabaseStats {
            type_count: self.types.len(),
            typedef_count: self.typedefs.len(),
            function_count: self.functions.len(),
        }
    }
}

/// Statistics about a type database.
#[derive(Debug, Clone)]
pub struct TypeDatabaseStats {
    pub type_count: usize,
    pub typedef_count: usize,
    pub function_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_get_type() {
        let mut db = TypeDatabase::new();

        let mut st = StructType::new(Some("point".to_string()));
        st.add_field("x".to_string(), CType::int());
        st.add_field("y".to_string(), CType::int());
        st.finalize();

        db.add_type("struct point", CType::Struct(st));

        assert!(db.has_type("struct point"));
        assert!(db.has_type("point")); // Should work without prefix
    }

    #[test]
    fn test_typedef() {
        let mut db = TypeDatabase::new();

        db.add_typedef("size_t", CType::ulong());
        db.add_typedef("ssize_t", CType::long());

        assert!(db.has_type("size_t"));
        assert_eq!(db.get_type("size_t").unwrap().size(), Some(8));
    }

    #[test]
    fn test_field_at_offset() {
        let mut db = TypeDatabase::new();

        let mut st = StructType::new(Some("test".to_string()));
        st.add_field("a".to_string(), CType::int()); // offset 0
        st.add_field("b".to_string(), CType::long()); // offset 8 (aligned)
        st.add_field("c".to_string(), CType::int()); // offset 16
        st.finalize();

        db.add_type("struct test", CType::Struct(st));

        let field = db.field_at_offset("struct test", 0).unwrap();
        assert_eq!(field.name, "a");

        let field = db.field_at_offset("struct test", 8).unwrap();
        assert_eq!(field.name, "b");

        let field = db.field_at_offset("struct test", 16).unwrap();
        assert_eq!(field.name, "c");
    }

    #[test]
    fn test_format_field_access() {
        let mut db = TypeDatabase::new();

        let mut st = StructType::new(Some("point".to_string()));
        st.add_field("x".to_string(), CType::int());
        st.add_field("y".to_string(), CType::int());
        st.finalize();

        db.add_type("struct point", CType::Struct(st));

        assert_eq!(
            db.format_field_access("struct point", 0),
            Some(".x".to_string())
        );
        assert_eq!(
            db.format_field_access("struct point", 4),
            Some(".y".to_string())
        );
    }

    #[test]
    fn test_function_prototype() {
        let mut db = TypeDatabase::new();

        let proto =
            FunctionPrototype::new("strlen", CType::ulong()).param("s", CType::ptr(CType::char()));

        db.add_function(proto);

        assert!(db.has_function("strlen"));
        let func = db.get_function("strlen").unwrap();
        assert_eq!(func.parameters.len(), 1);
    }

    // --- ArchInfo Tests ---

    #[test]
    fn test_arch_info_default() {
        let arch = ArchInfo::default();
        assert_eq!(arch.pointer_size, 8);
        assert_eq!(arch.long_size, 8);
        assert!(!arch.big_endian);
    }

    #[test]
    fn test_arch_info_lp64() {
        let arch = ArchInfo::lp64();
        assert_eq!(arch.pointer_size, 8);
        assert_eq!(arch.long_size, 8);
        assert!(!arch.big_endian);
    }

    #[test]
    fn test_arch_info_llp64() {
        let arch = ArchInfo::llp64();
        assert_eq!(arch.pointer_size, 8);
        assert_eq!(arch.long_size, 4); // Windows 64-bit has 4-byte long
        assert!(!arch.big_endian);
    }

    #[test]
    fn test_arch_info_ilp32() {
        let arch = ArchInfo::ilp32();
        assert_eq!(arch.pointer_size, 4);
        assert_eq!(arch.long_size, 4);
        assert!(!arch.big_endian);
    }

    // --- TypeDatabase Construction Tests ---

    #[test]
    fn test_database_new() {
        let db = TypeDatabase::new();
        assert_eq!(db.stats().type_count, 0);
        assert_eq!(db.stats().typedef_count, 0);
        assert_eq!(db.stats().function_count, 0);
    }

    #[test]
    fn test_database_with_arch() {
        let arch = ArchInfo::ilp32();
        let db = TypeDatabase::with_arch(arch);
        assert_eq!(db.arch().pointer_size, 4);
    }

    #[test]
    fn test_database_set_arch() {
        let mut db = TypeDatabase::new();
        assert_eq!(db.arch().pointer_size, 8);

        db.set_arch(ArchInfo::ilp32());
        assert_eq!(db.arch().pointer_size, 4);
    }

    // --- Type Lookup Tests ---

    #[test]
    fn test_get_type_with_struct_prefix() {
        let mut db = TypeDatabase::new();
        let st = StructType::new(Some("point".to_string()));
        db.add_type("struct point", CType::Struct(st));

        // Should find with struct prefix
        assert!(db.get_type("struct point").is_some());
        // Should also find without prefix (via fallback)
        assert!(db.get_type("point").is_some());
    }

    #[test]
    fn test_get_type_with_union_prefix() {
        let mut db = TypeDatabase::new();
        let u = UnionType::new(Some("value".to_string()));
        db.add_type("union value", CType::Union(u));

        assert!(db.get_type("union value").is_some());
        assert!(db.get_type("value").is_some());
    }

    #[test]
    fn test_get_type_with_enum_prefix() {
        let mut db = TypeDatabase::new();
        let e = EnumType::new(Some("color".to_string()));
        db.add_type("enum color", CType::Enum(e));

        assert!(db.get_type("enum color").is_some());
        assert!(db.get_type("color").is_some());
    }

    #[test]
    fn test_get_type_nonexistent() {
        let db = TypeDatabase::new();
        assert!(db.get_type("nonexistent").is_none());
    }

    #[test]
    fn test_get_function_nonexistent() {
        let db = TypeDatabase::new();
        assert!(db.get_function("nonexistent").is_none());
    }

    // --- Iterator Tests ---

    #[test]
    fn test_type_names() {
        let mut db = TypeDatabase::new();
        db.add_type(
            "struct foo",
            CType::Struct(StructType::new(Some("foo".to_string()))),
        );
        db.add_type(
            "struct bar",
            CType::Struct(StructType::new(Some("bar".to_string()))),
        );

        let names: Vec<_> = db.type_names().collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"struct foo"));
        assert!(names.contains(&"struct bar"));
    }

    #[test]
    fn test_typedef_names() {
        let mut db = TypeDatabase::new();
        db.add_typedef("size_t", CType::ulong());
        db.add_typedef("ssize_t", CType::long());

        let names: Vec<_> = db.typedef_names().collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"size_t"));
        assert!(names.contains(&"ssize_t"));
    }

    #[test]
    fn test_function_names() {
        let mut db = TypeDatabase::new();
        db.add_function(FunctionPrototype::new("foo", CType::void()));
        db.add_function(FunctionPrototype::new("bar", CType::void()));

        let names: Vec<_> = db.function_names().collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"foo"));
        assert!(names.contains(&"bar"));
    }

    // --- Field Access Tests ---

    #[test]
    fn test_field_at_offset_nonexistent_type() {
        let db = TypeDatabase::new();
        assert!(db.field_at_offset("nonexistent", 0).is_none());
    }

    #[test]
    fn test_field_at_offset_non_struct() {
        let mut db = TypeDatabase::new();
        db.add_typedef("myint", CType::int());

        // Typedef to non-struct should return None
        assert!(db.field_at_offset("myint", 0).is_none());
    }

    #[test]
    fn test_field_at_offset_through_typedef() {
        let mut db = TypeDatabase::new();

        let mut st = StructType::new(Some("point".to_string()));
        st.add_field("x".to_string(), CType::int());
        st.add_field("y".to_string(), CType::int());
        st.finalize();

        db.add_type("struct point", CType::Struct(st));
        db.add_typedef("Point", CType::Named("struct point".to_string()));

        // Should resolve through typedef
        let field = db.field_at_offset("Point", 0);
        assert!(field.is_some());
        assert_eq!(field.unwrap().name, "x");
    }

    #[test]
    fn test_format_field_access_nonexistent() {
        let db = TypeDatabase::new();
        assert!(db.format_field_access("nonexistent", 0).is_none());
    }

    #[test]
    fn test_format_field_access_array_element() {
        let mut db = TypeDatabase::new();

        let mut st = StructType::new(Some("test".to_string()));
        st.add_field("data".to_string(), CType::array(CType::int(), Some(10)));
        st.finalize();

        db.add_type("struct test", CType::Struct(st));

        // Access at offset 0 should be .data[0]
        assert_eq!(
            db.format_field_access("struct test", 0),
            Some(".data".to_string())
        );
        // Access at offset 4 should be .data[1]
        assert_eq!(
            db.format_field_access("struct test", 4),
            Some(".data[1]".to_string())
        );
    }

    // --- Merge Tests ---

    #[test]
    fn test_merge_empty() {
        let mut db1 = TypeDatabase::new();
        let db2 = TypeDatabase::new();

        db1.merge(&db2);
        assert_eq!(db1.stats().type_count, 0);
    }

    #[test]
    fn test_merge_types() {
        let mut db1 = TypeDatabase::new();
        db1.add_type(
            "struct foo",
            CType::Struct(StructType::new(Some("foo".to_string()))),
        );

        let mut db2 = TypeDatabase::new();
        db2.add_type(
            "struct bar",
            CType::Struct(StructType::new(Some("bar".to_string()))),
        );

        db1.merge(&db2);

        assert!(db1.has_type("struct foo"));
        assert!(db1.has_type("struct bar"));
    }

    #[test]
    fn test_merge_typedefs() {
        let mut db1 = TypeDatabase::new();
        db1.add_typedef("type1", CType::int());

        let mut db2 = TypeDatabase::new();
        db2.add_typedef("type2", CType::long());

        db1.merge(&db2);

        assert!(db1.has_type("type1"));
        assert!(db1.has_type("type2"));
    }

    #[test]
    fn test_merge_functions() {
        let mut db1 = TypeDatabase::new();
        db1.add_function(FunctionPrototype::new("func1", CType::void()));

        let mut db2 = TypeDatabase::new();
        db2.add_function(FunctionPrototype::new("func2", CType::void()));

        db1.merge(&db2);

        assert!(db1.has_function("func1"));
        assert!(db1.has_function("func2"));
    }

    #[test]
    fn test_merge_overwrites() {
        let mut db1 = TypeDatabase::new();
        db1.add_typedef("size_t", CType::int());

        let mut db2 = TypeDatabase::new();
        db2.add_typedef("size_t", CType::long());

        db1.merge(&db2);

        // Should have the value from db2
        let ty = db1.get_type("size_t").unwrap();
        assert_eq!(ty.size(), Some(8)); // long is 8 bytes
    }

    // --- Serialization Tests ---

    #[test]
    fn test_to_json_empty() {
        let db = TypeDatabase::new();
        let json = db.to_json().unwrap();
        assert!(json.contains("{"));
        assert!(json.contains("}"));
    }

    #[test]
    fn test_to_json_with_types() {
        let mut db = TypeDatabase::new();
        db.add_typedef("myint", CType::int());

        let json = db.to_json().unwrap();
        assert!(json.contains("myint"));
    }

    #[test]
    fn test_from_json_empty() {
        let json = r#"{"types":{},"typedefs":{},"functions":{}}"#;
        let db = TypeDatabase::from_json(json).unwrap();
        assert_eq!(db.stats().type_count, 0);
    }

    #[test]
    fn test_json_roundtrip() {
        let mut db = TypeDatabase::new();
        db.add_typedef("size_t", CType::ulong());

        let mut st = StructType::new(Some("point".to_string()));
        st.add_field("x".to_string(), CType::int());
        st.add_field("y".to_string(), CType::int());
        st.finalize();
        db.add_type("struct point", CType::Struct(st));

        let json = db.to_json().unwrap();
        let db2 = TypeDatabase::from_json(&json).unwrap();

        assert!(db2.has_type("size_t"));
        assert!(db2.has_type("struct point"));
    }

    #[test]
    fn test_from_json_invalid() {
        let result = TypeDatabase::from_json("not valid json");
        assert!(result.is_err());
    }

    // --- Format Type Tests ---

    #[test]
    fn test_format_type_struct() {
        let mut db = TypeDatabase::new();

        let mut st = StructType::new(Some("point".to_string()));
        st.add_field("x".to_string(), CType::int());
        st.add_field("y".to_string(), CType::int());
        st.finalize();

        db.add_type("struct point", CType::Struct(st));

        let formatted = db.format_type("struct point");
        assert!(formatted.contains("struct point"));
        assert!(formatted.contains("int x"));
        assert!(formatted.contains("int y"));
        assert!(formatted.contains("offset"));
    }

    #[test]
    fn test_format_type_union() {
        let mut db = TypeDatabase::new();

        let mut u = UnionType::new(Some("value".to_string()));
        u.add_member("i".to_string(), CType::int());
        u.add_member("f".to_string(), CType::float());
        u.finalize();

        db.add_type("union value", CType::Union(u));

        let formatted = db.format_type("union value");
        assert!(formatted.contains("union value"));
        assert!(formatted.contains("int i"));
        assert!(formatted.contains("float f"));
    }

    #[test]
    fn test_format_type_enum() {
        let mut db = TypeDatabase::new();

        let mut e = EnumType::new(Some("color".to_string()));
        e.add_value("RED".to_string(), 0);
        e.add_value("GREEN".to_string(), 1);
        e.add_value("BLUE".to_string(), 2);

        db.add_type("enum color", CType::Enum(e));

        let formatted = db.format_type("enum color");
        assert!(formatted.contains("enum color"));
        assert!(formatted.contains("RED"));
        assert!(formatted.contains("GREEN"));
        assert!(formatted.contains("BLUE"));
    }

    #[test]
    fn test_format_type_typedef() {
        let mut db = TypeDatabase::new();
        db.add_typedef("size_t", CType::ulong());

        let formatted = db.format_type("size_t");
        // Format returns the underlying type with the typedef name
        assert!(formatted.contains("size_t"));
    }

    #[test]
    fn test_format_type_unknown() {
        let db = TypeDatabase::new();
        let formatted = db.format_type("unknown");
        assert!(formatted.contains("Unknown"));
    }

    // --- Statistics Tests ---

    #[test]
    fn test_stats() {
        let mut db = TypeDatabase::new();
        db.add_type(
            "struct foo",
            CType::Struct(StructType::new(Some("foo".to_string()))),
        );
        db.add_typedef("myint", CType::int());
        db.add_function(FunctionPrototype::new("test", CType::void()));

        let stats = db.stats();
        assert_eq!(stats.type_count, 1);
        assert_eq!(stats.typedef_count, 1);
        assert_eq!(stats.function_count, 1);
    }

    #[test]
    fn test_stats_debug() {
        let stats = TypeDatabaseStats {
            type_count: 10,
            typedef_count: 5,
            function_count: 3,
        };
        let debug = format!("{:?}", stats);
        assert!(debug.contains("10"));
        assert!(debug.contains("5"));
        assert!(debug.contains("3"));
    }

    // --- Edge Cases ---

    #[test]
    fn test_add_type_overwrite() {
        let mut db = TypeDatabase::new();

        let st1 = StructType::new(Some("test".to_string()));
        db.add_type("struct test", CType::Struct(st1));

        let mut st2 = StructType::new(Some("test".to_string()));
        st2.add_field("x".to_string(), CType::int());
        st2.finalize();
        db.add_type("struct test", CType::Struct(st2));

        // Should have the second version
        let ty = db.get_type("struct test").unwrap();
        if let CType::Struct(s) = ty {
            assert_eq!(s.fields.len(), 1);
        } else {
            panic!("Expected struct");
        }
    }

    #[test]
    fn test_nested_struct_field_access() {
        let mut db = TypeDatabase::new();

        let mut inner = StructType::new(Some("inner".to_string()));
        inner.add_field("a".to_string(), CType::int());
        inner.add_field("b".to_string(), CType::int());
        inner.finalize();

        let mut outer = StructType::new(Some("outer".to_string()));
        outer.add_field("x".to_string(), CType::int());
        outer.add_field("nested".to_string(), CType::Struct(inner));
        outer.finalize();

        db.add_type("struct outer", CType::Struct(outer));

        // Access to nested.a
        let result = db.format_field_access("struct outer", 4);
        assert!(result.is_some());
        let access = result.unwrap();
        assert!(access.contains("nested"));
    }
}
