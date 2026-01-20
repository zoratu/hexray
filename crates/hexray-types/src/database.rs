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
}
