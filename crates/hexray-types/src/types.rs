//! C type representation.
//!
//! This module defines the core type system for representing C types.

use serde::{Deserialize, Serialize};

/// A C type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CType {
    /// void type
    Void,

    /// Integer type (char, short, int, long, etc.)
    Int(IntType),

    /// Floating-point type (float, double, long double)
    Float(FloatType),

    /// Pointer to another type
    Pointer(Box<CType>),

    /// Array of elements
    Array(ArrayType),

    /// Structure type
    Struct(StructType),

    /// Union type
    Union(UnionType),

    /// Enumeration type
    Enum(EnumType),

    /// Function type
    Function(FunctionType),

    /// Typedef (alias to another type)
    Typedef(TypedefType),

    /// Named reference to a type (for forward declarations and recursive types)
    Named(String),
}

impl CType {
    /// Get the size of this type in bytes.
    /// Returns None for incomplete types (void, unsized arrays, forward declarations).
    pub fn size(&self) -> Option<usize> {
        match self {
            CType::Void => None,
            CType::Int(i) => Some(i.size),
            CType::Float(f) => Some(f.size),
            CType::Pointer(_) => Some(8), // Assuming 64-bit
            CType::Array(a) => {
                let elem_size = a.element.size()?;
                Some(elem_size * a.length?)
            }
            CType::Struct(s) => Some(s.size),
            CType::Union(u) => Some(u.size),
            CType::Enum(e) => Some(e.underlying_size),
            CType::Function(_) => None, // Functions don't have a size
            CType::Typedef(t) => t.target.size(),
            CType::Named(_) => None, // Need to resolve from database
        }
    }

    /// Get the alignment of this type in bytes.
    pub fn alignment(&self) -> Option<usize> {
        match self {
            CType::Void => None,
            CType::Int(i) => Some(i.size.min(8)), // Typically aligned to size or max 8
            CType::Float(f) => Some(f.size.min(8)),
            CType::Pointer(_) => Some(8),
            CType::Array(a) => a.element.alignment(),
            CType::Struct(s) => Some(s.alignment),
            CType::Union(u) => Some(u.alignment),
            CType::Enum(e) => Some(e.underlying_size.min(8)),
            CType::Function(_) => None,
            CType::Typedef(t) => t.target.alignment(),
            CType::Named(_) => None,
        }
    }

    /// Check if this is a void type.
    pub fn is_void(&self) -> bool {
        matches!(self, CType::Void)
    }

    /// Check if this is an integer type.
    pub fn is_integer(&self) -> bool {
        matches!(self, CType::Int(_))
    }

    /// Check if this is a floating-point type.
    pub fn is_float(&self) -> bool {
        matches!(self, CType::Float(_))
    }

    /// Check if this is a pointer type.
    pub fn is_pointer(&self) -> bool {
        matches!(self, CType::Pointer(_))
    }

    /// Check if this is a struct type.
    pub fn is_struct(&self) -> bool {
        matches!(self, CType::Struct(_))
    }

    /// Format this type as a C declaration.
    pub fn to_c_string(&self, name: Option<&str>) -> String {
        match self {
            CType::Void => format!("void{}", name.map(|n| format!(" {}", n)).unwrap_or_default()),
            CType::Int(i) => {
                let type_name = match (i.signed, i.size) {
                    (true, 1) => "char",
                    (false, 1) => "unsigned char",
                    (true, 2) => "short",
                    (false, 2) => "unsigned short",
                    (true, 4) => "int",
                    (false, 4) => "unsigned int",
                    (true, 8) => "long long",
                    (false, 8) => "unsigned long long",
                    _ => "int",
                };
                format!("{}{}", type_name, name.map(|n| format!(" {}", n)).unwrap_or_default())
            }
            CType::Float(f) => {
                let type_name = match f.size {
                    4 => "float",
                    8 => "double",
                    16 => "long double",
                    _ => "double",
                };
                format!("{}{}", type_name, name.map(|n| format!(" {}", n)).unwrap_or_default())
            }
            CType::Pointer(inner) => {
                let inner_str = inner.to_c_string(None);
                format!("{}*{}", inner_str, name.map(|n| format!(" {}", n)).unwrap_or_default())
            }
            CType::Array(a) => {
                let elem_str = a.element.to_c_string(name);
                match a.length {
                    Some(len) => format!("{}[{}]", elem_str, len),
                    None => format!("{}[]", elem_str),
                }
            }
            CType::Struct(s) => {
                let tag = s.name.as_ref().map(|n| format!("struct {} ", n)).unwrap_or_else(|| "struct ".to_string());
                format!("{}{}", tag, name.map(|n| n.to_string()).unwrap_or_default())
            }
            CType::Union(u) => {
                let tag = u.name.as_ref().map(|n| format!("union {} ", n)).unwrap_or_else(|| "union ".to_string());
                format!("{}{}", tag, name.map(|n| n.to_string()).unwrap_or_default())
            }
            CType::Enum(e) => {
                let tag = e.name.as_ref().map(|n| format!("enum {} ", n)).unwrap_or_else(|| "enum ".to_string());
                format!("{}{}", tag, name.map(|n| n.to_string()).unwrap_or_default())
            }
            CType::Function(f) => {
                let ret = f.return_type.to_c_string(None);
                let params: Vec<_> = f.parameters.iter()
                    .map(|p| p.param_type.to_c_string(Some(&p.name)))
                    .collect();
                let params_str = if params.is_empty() {
                    "void".to_string()
                } else if f.variadic {
                    format!("{}, ...", params.join(", "))
                } else {
                    params.join(", ")
                };
                format!("{} {}({})", ret, name.unwrap_or(""), params_str)
            }
            CType::Typedef(t) => {
                format!("{}{}", t.name, name.map(|n| format!(" {}", n)).unwrap_or_default())
            }
            CType::Named(n) => {
                format!("{}{}", n, name.map(|nm| format!(" {}", nm)).unwrap_or_default())
            }
        }
    }
}

/// Integer type details.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IntType {
    /// Size in bytes.
    pub size: usize,
    /// Whether the type is signed.
    pub signed: bool,
}

impl IntType {
    pub fn new(size: usize, signed: bool) -> Self {
        Self { size, signed }
    }

    pub fn char() -> Self { Self::new(1, true) }
    pub fn uchar() -> Self { Self::new(1, false) }
    pub fn short() -> Self { Self::new(2, true) }
    pub fn ushort() -> Self { Self::new(2, false) }
    pub fn int() -> Self { Self::new(4, true) }
    pub fn uint() -> Self { Self::new(4, false) }
    pub fn long() -> Self { Self::new(8, true) }  // 64-bit
    pub fn ulong() -> Self { Self::new(8, false) }
    pub fn longlong() -> Self { Self::new(8, true) }
    pub fn ulonglong() -> Self { Self::new(8, false) }
}

/// Floating-point type details.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FloatType {
    /// Size in bytes.
    pub size: usize,
}

impl FloatType {
    pub fn new(size: usize) -> Self {
        Self { size }
    }

    pub fn float() -> Self { Self::new(4) }
    pub fn double() -> Self { Self::new(8) }
    pub fn long_double() -> Self { Self::new(16) }
}

/// Array type details.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArrayType {
    /// Element type.
    pub element: Box<CType>,
    /// Array length (None for flexible array member or incomplete).
    pub length: Option<usize>,
}

impl ArrayType {
    pub fn new(element: CType, length: Option<usize>) -> Self {
        Self {
            element: Box::new(element),
            length,
        }
    }
}

/// Structure type details.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructType {
    /// Optional struct tag name.
    pub name: Option<String>,
    /// Fields in order.
    pub fields: Vec<StructField>,
    /// Total size in bytes (including padding).
    pub size: usize,
    /// Alignment requirement.
    pub alignment: usize,
    /// Whether this is a packed struct.
    pub packed: bool,
}

impl StructType {
    pub fn new(name: Option<String>) -> Self {
        Self {
            name,
            fields: Vec::new(),
            size: 0,
            alignment: 1,
            packed: false,
        }
    }

    /// Add a field and update size/alignment.
    pub fn add_field(&mut self, name: String, field_type: CType) {
        let field_size = field_type.size().unwrap_or(0);
        let field_align = field_type.alignment().unwrap_or(1);

        // Calculate offset with alignment
        let offset = if self.packed {
            self.size
        } else {
            (self.size + field_align - 1) & !(field_align - 1)
        };

        self.fields.push(StructField {
            name,
            field_type,
            offset,
            bit_field: None,
        });

        self.size = offset + field_size;
        self.alignment = self.alignment.max(field_align);
    }

    /// Finalize the struct (add trailing padding).
    pub fn finalize(&mut self) {
        if !self.packed && self.alignment > 1 {
            self.size = (self.size + self.alignment - 1) & !(self.alignment - 1);
        }
    }

    /// Get field at a specific offset.
    pub fn field_at_offset(&self, offset: usize) -> Option<&StructField> {
        self.fields.iter().find(|f| {
            let field_size = f.field_type.size().unwrap_or(0);
            offset >= f.offset && offset < f.offset + field_size
        })
    }

    /// Get field by name.
    pub fn field_by_name(&self, name: &str) -> Option<&StructField> {
        self.fields.iter().find(|f| f.name == name)
    }
}

/// A field in a struct or union.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructField {
    /// Field name.
    pub name: String,
    /// Field type.
    pub field_type: CType,
    /// Byte offset from struct start.
    pub offset: usize,
    /// Bit field info (if this is a bit field).
    pub bit_field: Option<BitFieldInfo>,
}

/// Bit field information.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BitFieldInfo {
    /// Bit offset within the storage unit.
    pub bit_offset: usize,
    /// Number of bits.
    pub bit_width: usize,
}

/// Union type details.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnionType {
    /// Optional union tag name.
    pub name: Option<String>,
    /// Members.
    pub members: Vec<UnionMember>,
    /// Total size (max of all members).
    pub size: usize,
    /// Alignment requirement.
    pub alignment: usize,
}

impl UnionType {
    pub fn new(name: Option<String>) -> Self {
        Self {
            name,
            members: Vec::new(),
            size: 0,
            alignment: 1,
        }
    }

    /// Add a member and update size/alignment.
    pub fn add_member(&mut self, name: String, member_type: CType) {
        let member_size = member_type.size().unwrap_or(0);
        let member_align = member_type.alignment().unwrap_or(1);

        self.members.push(UnionMember {
            name,
            member_type,
        });

        self.size = self.size.max(member_size);
        self.alignment = self.alignment.max(member_align);
    }

    /// Finalize the union (add trailing padding).
    pub fn finalize(&mut self) {
        if self.alignment > 1 {
            self.size = (self.size + self.alignment - 1) & !(self.alignment - 1);
        }
    }
}

/// A member in a union.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnionMember {
    /// Member name.
    pub name: String,
    /// Member type.
    pub member_type: CType,
}

/// Enumeration type details.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnumType {
    /// Optional enum tag name.
    pub name: Option<String>,
    /// Enumerators (name, value).
    pub values: Vec<(String, i64)>,
    /// Size of underlying integer type.
    pub underlying_size: usize,
}

impl EnumType {
    pub fn new(name: Option<String>) -> Self {
        Self {
            name,
            values: Vec::new(),
            underlying_size: 4, // Default to int
        }
    }

    /// Add an enumerator.
    pub fn add_value(&mut self, name: String, value: i64) {
        self.values.push((name, value));

        // Adjust underlying size if needed
        if value > i32::MAX as i64 || value < i32::MIN as i64 {
            self.underlying_size = 8;
        }
    }

    /// Get value by name.
    pub fn value_of(&self, name: &str) -> Option<i64> {
        self.values.iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| *v)
    }

    /// Get name by value.
    pub fn name_of(&self, value: i64) -> Option<&str> {
        self.values.iter()
            .find(|(_, v)| *v == value)
            .map(|(n, _)| n.as_str())
    }
}

/// Function type details.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionType {
    /// Return type.
    pub return_type: Box<CType>,
    /// Parameters.
    pub parameters: Vec<FunctionParam>,
    /// Whether the function is variadic (has ...).
    pub variadic: bool,
}

impl FunctionType {
    pub fn new(return_type: CType) -> Self {
        Self {
            return_type: Box::new(return_type),
            parameters: Vec::new(),
            variadic: false,
        }
    }

    /// Add a parameter.
    pub fn add_param(&mut self, name: String, param_type: CType) {
        self.parameters.push(FunctionParam { name, param_type });
    }
}

/// A function parameter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionParam {
    /// Parameter name.
    pub name: String,
    /// Parameter type.
    pub param_type: CType,
}

/// Typedef details.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TypedefType {
    /// Typedef name.
    pub name: String,
    /// Target type.
    pub target: Box<CType>,
}

impl TypedefType {
    pub fn new(name: String, target: CType) -> Self {
        Self {
            name,
            target: Box::new(target),
        }
    }
}

/// A function prototype (for the function database).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionPrototype {
    /// Function name.
    pub name: String,
    /// Return type.
    pub return_type: CType,
    /// Parameters.
    pub parameters: Vec<(String, CType)>,
    /// Whether variadic.
    pub variadic: bool,
    /// Optional documentation.
    pub doc: Option<String>,
}

impl FunctionPrototype {
    pub fn new(name: impl Into<String>, return_type: CType) -> Self {
        Self {
            name: name.into(),
            return_type,
            parameters: Vec::new(),
            variadic: false,
            doc: None,
        }
    }

    pub fn param(mut self, name: impl Into<String>, param_type: CType) -> Self {
        self.parameters.push((name.into(), param_type));
        self
    }

    pub fn variadic(mut self) -> Self {
        self.variadic = true;
        self
    }

    pub fn doc(mut self, doc: impl Into<String>) -> Self {
        self.doc = Some(doc.into());
        self
    }

    /// Convert to C declaration string.
    pub fn to_c_string(&self) -> String {
        let ret = self.return_type.to_c_string(None);
        let params: Vec<_> = self.parameters.iter()
            .map(|(name, ty)| ty.to_c_string(Some(name)))
            .collect();
        let params_str = if params.is_empty() {
            "void".to_string()
        } else if self.variadic {
            format!("{}, ...", params.join(", "))
        } else {
            params.join(", ")
        };
        format!("{} {}({})", ret, self.name, params_str)
    }

    /// Format for display (includes documentation if available).
    pub fn format(&self) -> String {
        let mut result = self.to_c_string();
        result.push(';');
        if let Some(ref doc) = self.doc {
            result.push_str(&format!("\n// {}", doc));
        }
        result
    }
}

// Common type constructors for convenience
impl CType {
    pub fn void() -> Self { CType::Void }
    pub fn char() -> Self { CType::Int(IntType::char()) }
    pub fn uchar() -> Self { CType::Int(IntType::uchar()) }
    pub fn short() -> Self { CType::Int(IntType::short()) }
    pub fn ushort() -> Self { CType::Int(IntType::ushort()) }
    pub fn int() -> Self { CType::Int(IntType::int()) }
    pub fn uint() -> Self { CType::Int(IntType::uint()) }
    pub fn long() -> Self { CType::Int(IntType::long()) }
    pub fn ulong() -> Self { CType::Int(IntType::ulong()) }
    pub fn longlong() -> Self { CType::Int(IntType::longlong()) }
    pub fn ulonglong() -> Self { CType::Int(IntType::ulonglong()) }
    pub fn float() -> Self { CType::Float(FloatType::float()) }
    pub fn double() -> Self { CType::Float(FloatType::double()) }

    pub fn ptr(inner: CType) -> Self { CType::Pointer(Box::new(inner)) }
    pub fn array(element: CType, length: Option<usize>) -> Self {
        CType::Array(ArrayType::new(element, length))
    }

    /// Create a typedef reference.
    pub fn typedef_ref(name: impl Into<String>) -> Self {
        CType::Named(name.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_int_sizes() {
        assert_eq!(CType::char().size(), Some(1));
        assert_eq!(CType::short().size(), Some(2));
        assert_eq!(CType::int().size(), Some(4));
        assert_eq!(CType::long().size(), Some(8));
    }

    #[test]
    fn test_pointer_size() {
        assert_eq!(CType::ptr(CType::int()).size(), Some(8));
        assert_eq!(CType::ptr(CType::void()).size(), Some(8));
    }

    #[test]
    fn test_struct_layout() {
        let mut s = StructType::new(Some("test".to_string()));
        s.add_field("a".to_string(), CType::char());  // offset 0, size 1
        s.add_field("b".to_string(), CType::int());   // offset 4 (aligned), size 4
        s.add_field("c".to_string(), CType::char());  // offset 8, size 1
        s.finalize();

        assert_eq!(s.fields[0].offset, 0);
        assert_eq!(s.fields[1].offset, 4);
        assert_eq!(s.fields[2].offset, 8);
        assert_eq!(s.size, 12); // Padded to alignment of 4
        assert_eq!(s.alignment, 4);
    }

    #[test]
    fn test_to_c_string() {
        assert_eq!(CType::int().to_c_string(Some("x")), "int x");
        assert_eq!(CType::ptr(CType::char()).to_c_string(Some("s")), "char* s");
        assert_eq!(CType::ptr(CType::void()).to_c_string(None), "void*");
    }

    #[test]
    fn test_function_prototype() {
        let proto = FunctionPrototype::new("printf", CType::int())
            .param("format", CType::ptr(CType::char()))
            .variadic();

        assert_eq!(proto.to_c_string(), "int printf(char* format, ...)");
    }
}
