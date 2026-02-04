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
            CType::Void => format!(
                "void{}",
                name.map(|n| format!(" {}", n)).unwrap_or_default()
            ),
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
                format!(
                    "{}{}",
                    type_name,
                    name.map(|n| format!(" {}", n)).unwrap_or_default()
                )
            }
            CType::Float(f) => {
                let type_name = match f.size {
                    4 => "float",
                    8 => "double",
                    16 => "long double",
                    _ => "double",
                };
                format!(
                    "{}{}",
                    type_name,
                    name.map(|n| format!(" {}", n)).unwrap_or_default()
                )
            }
            CType::Pointer(inner) => {
                let inner_str = inner.to_c_string(None);
                format!(
                    "{}*{}",
                    inner_str,
                    name.map(|n| format!(" {}", n)).unwrap_or_default()
                )
            }
            CType::Array(a) => {
                let elem_str = a.element.to_c_string(name);
                match a.length {
                    Some(len) => format!("{}[{}]", elem_str, len),
                    None => format!("{}[]", elem_str),
                }
            }
            CType::Struct(s) => {
                let tag = s
                    .name
                    .as_ref()
                    .map(|n| format!("struct {} ", n))
                    .unwrap_or_else(|| "struct ".to_string());
                format!("{}{}", tag, name.map(|n| n.to_string()).unwrap_or_default())
            }
            CType::Union(u) => {
                let tag = u
                    .name
                    .as_ref()
                    .map(|n| format!("union {} ", n))
                    .unwrap_or_else(|| "union ".to_string());
                format!("{}{}", tag, name.map(|n| n.to_string()).unwrap_or_default())
            }
            CType::Enum(e) => {
                let tag = e
                    .name
                    .as_ref()
                    .map(|n| format!("enum {} ", n))
                    .unwrap_or_else(|| "enum ".to_string());
                format!("{}{}", tag, name.map(|n| n.to_string()).unwrap_or_default())
            }
            CType::Function(f) => {
                let ret = f.return_type.to_c_string(None);
                let params: Vec<_> = f
                    .parameters
                    .iter()
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
                format!(
                    "{}{}",
                    t.name,
                    name.map(|n| format!(" {}", n)).unwrap_or_default()
                )
            }
            CType::Named(n) => {
                format!(
                    "{}{}",
                    n,
                    name.map(|nm| format!(" {}", nm)).unwrap_or_default()
                )
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

    pub fn char() -> Self {
        Self::new(1, true)
    }
    pub fn uchar() -> Self {
        Self::new(1, false)
    }
    pub fn short() -> Self {
        Self::new(2, true)
    }
    pub fn ushort() -> Self {
        Self::new(2, false)
    }
    pub fn int() -> Self {
        Self::new(4, true)
    }
    pub fn uint() -> Self {
        Self::new(4, false)
    }
    pub fn long() -> Self {
        Self::new(8, true)
    } // 64-bit
    pub fn ulong() -> Self {
        Self::new(8, false)
    }
    pub fn longlong() -> Self {
        Self::new(8, true)
    }
    pub fn ulonglong() -> Self {
        Self::new(8, false)
    }
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

    pub fn float() -> Self {
        Self::new(4)
    }
    pub fn double() -> Self {
        Self::new(8)
    }
    pub fn long_double() -> Self {
        Self::new(16)
    }
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

        self.members.push(UnionMember { name, member_type });

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
        self.values.iter().find(|(n, _)| n == name).map(|(_, v)| *v)
    }

    /// Get name by value.
    pub fn name_of(&self, value: i64) -> Option<&str> {
        self.values
            .iter()
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
        let params: Vec<_> = self
            .parameters
            .iter()
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
    pub fn void() -> Self {
        CType::Void
    }
    pub fn char() -> Self {
        CType::Int(IntType::char())
    }
    pub fn uchar() -> Self {
        CType::Int(IntType::uchar())
    }
    pub fn short() -> Self {
        CType::Int(IntType::short())
    }
    pub fn ushort() -> Self {
        CType::Int(IntType::ushort())
    }
    pub fn int() -> Self {
        CType::Int(IntType::int())
    }
    pub fn uint() -> Self {
        CType::Int(IntType::uint())
    }
    pub fn long() -> Self {
        CType::Int(IntType::long())
    }
    pub fn ulong() -> Self {
        CType::Int(IntType::ulong())
    }
    pub fn longlong() -> Self {
        CType::Int(IntType::longlong())
    }
    pub fn ulonglong() -> Self {
        CType::Int(IntType::ulonglong())
    }
    pub fn float() -> Self {
        CType::Float(FloatType::float())
    }
    pub fn double() -> Self {
        CType::Float(FloatType::double())
    }

    pub fn ptr(inner: CType) -> Self {
        CType::Pointer(Box::new(inner))
    }
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
        s.add_field("a".to_string(), CType::char()); // offset 0, size 1
        s.add_field("b".to_string(), CType::int()); // offset 4 (aligned), size 4
        s.add_field("c".to_string(), CType::char()); // offset 8, size 1
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

    // --- IntType Tests ---

    #[test]
    fn test_int_type_constructors() {
        assert_eq!(IntType::char().size, 1);
        assert!(IntType::char().signed);

        assert_eq!(IntType::uchar().size, 1);
        assert!(!IntType::uchar().signed);

        assert_eq!(IntType::short().size, 2);
        assert!(IntType::short().signed);

        assert_eq!(IntType::ushort().size, 2);
        assert!(!IntType::ushort().signed);

        assert_eq!(IntType::int().size, 4);
        assert!(IntType::int().signed);

        assert_eq!(IntType::uint().size, 4);
        assert!(!IntType::uint().signed);

        assert_eq!(IntType::long().size, 8);
        assert!(IntType::long().signed);

        assert_eq!(IntType::ulong().size, 8);
        assert!(!IntType::ulong().signed);

        assert_eq!(IntType::longlong().size, 8);
        assert!(IntType::longlong().signed);

        assert_eq!(IntType::ulonglong().size, 8);
        assert!(!IntType::ulonglong().signed);
    }

    #[test]
    fn test_int_type_new() {
        let ty = IntType::new(16, true);
        assert_eq!(ty.size, 16);
        assert!(ty.signed);
    }

    #[test]
    fn test_int_type_equality() {
        assert_eq!(IntType::int(), IntType::int());
        assert_ne!(IntType::int(), IntType::uint());
        assert_ne!(IntType::int(), IntType::long());
    }

    // --- FloatType Tests ---

    #[test]
    fn test_float_type_constructors() {
        assert_eq!(FloatType::float().size, 4);
        assert_eq!(FloatType::double().size, 8);
        assert_eq!(FloatType::long_double().size, 16);
    }

    #[test]
    fn test_float_type_new() {
        let ty = FloatType::new(10);
        assert_eq!(ty.size, 10);
    }

    #[test]
    fn test_float_type_equality() {
        assert_eq!(FloatType::float(), FloatType::float());
        assert_ne!(FloatType::float(), FloatType::double());
    }

    // --- CType Helper Constructors Tests ---

    #[test]
    fn test_ctype_helper_constructors() {
        assert!(CType::void().is_void());
        assert!(CType::char().is_integer());
        assert!(CType::short().is_integer());
        assert!(CType::int().is_integer());
        assert!(CType::long().is_integer());
        assert!(CType::uchar().is_integer());
        assert!(CType::ushort().is_integer());
        assert!(CType::uint().is_integer());
        assert!(CType::ulong().is_integer());
        assert!(CType::float().is_float());
        assert!(CType::double().is_float());
    }

    #[test]
    fn test_ctype_ptr() {
        let ptr = CType::ptr(CType::int());
        assert!(ptr.is_pointer());
        assert_eq!(ptr.size(), Some(8));
    }

    #[test]
    fn test_ctype_array() {
        let arr = CType::array(CType::int(), Some(10));
        assert!(matches!(arr, CType::Array(_)));
        assert_eq!(arr.size(), Some(40)); // 10 * 4
    }

    // --- CType Size Tests ---

    #[test]
    fn test_ctype_size_void() {
        assert_eq!(CType::void().size(), None);
    }

    #[test]
    fn test_ctype_size_array_unsized() {
        let arr = CType::Array(ArrayType::new(CType::int(), None));
        assert_eq!(arr.size(), None);
    }

    #[test]
    fn test_ctype_size_function() {
        let func = CType::Function(FunctionType::new(CType::int()));
        assert_eq!(func.size(), None);
    }

    #[test]
    fn test_ctype_size_named() {
        let named = CType::Named("unknown".to_string());
        assert_eq!(named.size(), None);
    }

    #[test]
    fn test_ctype_size_typedef() {
        let typedef = CType::Typedef(TypedefType::new("myint".to_string(), CType::int()));
        assert_eq!(typedef.size(), Some(4));
    }

    #[test]
    fn test_ctype_size_union() {
        let mut u = UnionType::new(Some("test".to_string()));
        u.add_member("a".to_string(), CType::char());
        u.add_member("b".to_string(), CType::int());
        u.finalize();

        let union_type = CType::Union(u);
        assert_eq!(union_type.size(), Some(4)); // Size of largest member
    }

    #[test]
    fn test_ctype_size_enum() {
        let mut e = EnumType::new(Some("test".to_string()));
        e.add_value("A".to_string(), 0);

        let enum_type = CType::Enum(e);
        assert_eq!(enum_type.size(), Some(4)); // Default underlying type
    }

    // --- CType Alignment Tests ---

    #[test]
    fn test_ctype_alignment_int() {
        assert_eq!(CType::int().alignment(), Some(4));
        assert_eq!(CType::char().alignment(), Some(1));
        assert_eq!(CType::short().alignment(), Some(2));
        assert_eq!(CType::long().alignment(), Some(8));
    }

    #[test]
    fn test_ctype_alignment_pointer() {
        assert_eq!(CType::ptr(CType::char()).alignment(), Some(8));
    }

    #[test]
    fn test_ctype_alignment_array() {
        let arr = CType::array(CType::int(), Some(10));
        assert_eq!(arr.alignment(), Some(4)); // Element alignment
    }

    #[test]
    fn test_ctype_alignment_void() {
        assert_eq!(CType::void().alignment(), None);
    }

    #[test]
    fn test_ctype_alignment_function() {
        let func = CType::Function(FunctionType::new(CType::int()));
        assert_eq!(func.alignment(), None);
    }

    // --- CType Predicates Tests ---

    #[test]
    fn test_ctype_is_void() {
        assert!(CType::void().is_void());
        assert!(!CType::int().is_void());
    }

    #[test]
    fn test_ctype_is_integer() {
        assert!(CType::int().is_integer());
        assert!(CType::char().is_integer());
        assert!(!CType::void().is_integer());
        assert!(!CType::double().is_integer());
    }

    #[test]
    fn test_ctype_is_float() {
        assert!(CType::float().is_float());
        assert!(CType::double().is_float());
        assert!(!CType::int().is_float());
    }

    #[test]
    fn test_ctype_is_pointer() {
        assert!(CType::ptr(CType::int()).is_pointer());
        assert!(!CType::int().is_pointer());
    }

    #[test]
    fn test_ctype_is_struct() {
        let st = CType::Struct(StructType::new(Some("test".to_string())));
        assert!(st.is_struct());
        assert!(!CType::int().is_struct());
    }

    // --- to_c_string Tests ---

    #[test]
    fn test_to_c_string_void() {
        assert_eq!(CType::void().to_c_string(None), "void");
        assert_eq!(CType::void().to_c_string(Some("x")), "void x");
    }

    #[test]
    fn test_to_c_string_unsigned_types() {
        assert_eq!(CType::uchar().to_c_string(Some("x")), "unsigned char x");
        assert_eq!(CType::ushort().to_c_string(Some("x")), "unsigned short x");
        assert_eq!(CType::uint().to_c_string(Some("x")), "unsigned int x");
        assert_eq!(
            CType::ulong().to_c_string(Some("x")),
            "unsigned long long x"
        );
    }

    #[test]
    fn test_to_c_string_float_types() {
        assert_eq!(CType::float().to_c_string(Some("x")), "float x");
        assert_eq!(CType::double().to_c_string(Some("x")), "double x");

        let long_double = CType::Float(FloatType::long_double());
        assert_eq!(long_double.to_c_string(Some("x")), "long double x");
    }

    #[test]
    fn test_to_c_string_pointer_to_pointer() {
        let pp = CType::ptr(CType::ptr(CType::char()));
        assert_eq!(pp.to_c_string(Some("x")), "char** x");
    }

    #[test]
    fn test_to_c_string_array() {
        let arr = CType::array(CType::int(), Some(10));
        let s = arr.to_c_string(Some("x"));
        assert!(s.contains("int"));
        assert!(s.contains("[10]"));
    }

    #[test]
    fn test_to_c_string_array_unsized() {
        let arr = CType::Array(ArrayType::new(CType::int(), None));
        let s = arr.to_c_string(Some("x"));
        assert!(s.contains("[]"));
    }

    #[test]
    fn test_to_c_string_struct() {
        let st = CType::Struct(StructType::new(Some("point".to_string())));
        // Note: to_c_string adds trailing space when name is None for composite types
        assert!(st.to_c_string(None).contains("struct point"));
        assert_eq!(st.to_c_string(Some("p")), "struct point p");
    }

    #[test]
    fn test_to_c_string_union() {
        let u = CType::Union(UnionType::new(Some("value".to_string())));
        assert!(u.to_c_string(None).contains("union value"));
    }

    #[test]
    fn test_to_c_string_enum() {
        let e = CType::Enum(EnumType::new(Some("color".to_string())));
        assert!(e.to_c_string(None).contains("enum color"));
    }

    #[test]
    fn test_to_c_string_typedef() {
        let t = CType::Typedef(TypedefType::new("myint".to_string(), CType::int()));
        assert_eq!(t.to_c_string(None), "myint");
        assert_eq!(t.to_c_string(Some("x")), "myint x");
    }

    #[test]
    fn test_to_c_string_named() {
        let n = CType::Named("custom_type".to_string());
        assert_eq!(n.to_c_string(None), "custom_type");
        assert_eq!(n.to_c_string(Some("x")), "custom_type x");
    }

    // --- ArrayType Tests ---

    #[test]
    fn test_array_type_new() {
        let arr = ArrayType::new(CType::int(), Some(10));
        assert_eq!(arr.length, Some(10));
        assert!(arr.element.is_integer());
    }

    #[test]
    fn test_array_type_flexible() {
        let arr = ArrayType::new(CType::char(), None);
        assert_eq!(arr.length, None);
    }

    // --- StructType Tests ---

    #[test]
    fn test_struct_type_new() {
        let st = StructType::new(Some("test".to_string()));
        assert_eq!(st.name, Some("test".to_string()));
        assert!(st.fields.is_empty());
        assert_eq!(st.size, 0);
        assert_eq!(st.alignment, 1);
        assert!(!st.packed);
    }

    #[test]
    fn test_struct_type_add_field() {
        let mut st = StructType::new(Some("test".to_string()));
        st.add_field("x".to_string(), CType::int());

        assert_eq!(st.fields.len(), 1);
        assert_eq!(st.fields[0].name, "x");
        assert_eq!(st.fields[0].offset, 0);
    }

    #[test]
    fn test_struct_type_alignment() {
        let mut st = StructType::new(Some("test".to_string()));
        st.add_field("a".to_string(), CType::char()); // offset 0
        st.add_field("b".to_string(), CType::long()); // offset 8 (aligned)
        st.finalize();

        assert_eq!(st.fields[0].offset, 0);
        assert_eq!(st.fields[1].offset, 8);
        assert_eq!(st.alignment, 8);
    }

    #[test]
    fn test_struct_type_field_at_offset() {
        let mut st = StructType::new(Some("test".to_string()));
        st.add_field("a".to_string(), CType::int()); // offset 0, size 4
        st.add_field("b".to_string(), CType::int()); // offset 4, size 4
        st.finalize();

        assert_eq!(
            st.field_at_offset(0).map(|f| &f.name),
            Some(&"a".to_string())
        );
        assert_eq!(
            st.field_at_offset(2).map(|f| &f.name),
            Some(&"a".to_string())
        ); // Within field a
        assert_eq!(
            st.field_at_offset(4).map(|f| &f.name),
            Some(&"b".to_string())
        );
        assert!(st.field_at_offset(100).is_none());
    }

    #[test]
    fn test_struct_type_field_by_name() {
        let mut st = StructType::new(Some("test".to_string()));
        st.add_field("x".to_string(), CType::int());
        st.add_field("y".to_string(), CType::int());
        st.finalize();

        assert!(st.field_by_name("x").is_some());
        assert!(st.field_by_name("y").is_some());
        assert!(st.field_by_name("z").is_none());
    }

    // --- UnionType Tests ---

    #[test]
    fn test_union_type_new() {
        let u = UnionType::new(Some("value".to_string()));
        assert_eq!(u.name, Some("value".to_string()));
        assert!(u.members.is_empty());
        assert_eq!(u.size, 0);
        assert_eq!(u.alignment, 1);
    }

    #[test]
    fn test_union_type_add_member() {
        let mut u = UnionType::new(Some("value".to_string()));
        u.add_member("i".to_string(), CType::int());
        u.add_member("d".to_string(), CType::double());
        u.finalize();

        assert_eq!(u.members.len(), 2);
        assert_eq!(u.size, 8); // Size of largest member (double)
        assert_eq!(u.alignment, 8);
    }

    #[test]
    fn test_union_type_finalize() {
        let mut u = UnionType::new(None);
        u.add_member("a".to_string(), CType::char());
        u.add_member("b".to_string(), CType::int());
        u.finalize();

        // Size should be padded to alignment
        assert_eq!(u.size, 4);
        assert_eq!(u.alignment, 4);
    }

    // --- EnumType Tests ---

    #[test]
    fn test_enum_type_new() {
        let e = EnumType::new(Some("color".to_string()));
        assert_eq!(e.name, Some("color".to_string()));
        assert!(e.values.is_empty());
        assert_eq!(e.underlying_size, 4);
    }

    #[test]
    fn test_enum_type_add_value() {
        let mut e = EnumType::new(Some("test".to_string()));
        e.add_value("A".to_string(), 0);
        e.add_value("B".to_string(), 1);
        e.add_value("C".to_string(), 2);

        assert_eq!(e.values.len(), 3);
    }

    #[test]
    fn test_enum_type_value_of() {
        let mut e = EnumType::new(Some("test".to_string()));
        e.add_value("A".to_string(), 10);
        e.add_value("B".to_string(), 20);

        assert_eq!(e.value_of("A"), Some(10));
        assert_eq!(e.value_of("B"), Some(20));
        assert_eq!(e.value_of("C"), None);
    }

    #[test]
    fn test_enum_type_name_of() {
        let mut e = EnumType::new(Some("test".to_string()));
        e.add_value("A".to_string(), 10);
        e.add_value("B".to_string(), 20);

        assert_eq!(e.name_of(10), Some("A"));
        assert_eq!(e.name_of(20), Some("B"));
        assert_eq!(e.name_of(30), None);
    }

    #[test]
    fn test_enum_type_large_value() {
        let mut e = EnumType::new(Some("test".to_string()));
        e.add_value("LARGE".to_string(), i64::MAX);

        assert_eq!(e.underlying_size, 8); // Should expand to 8 bytes
    }

    #[test]
    fn test_enum_type_negative_value() {
        let mut e = EnumType::new(Some("test".to_string()));
        e.add_value("NEG".to_string(), i64::MIN);

        assert_eq!(e.underlying_size, 8);
    }

    // --- FunctionType Tests ---

    #[test]
    fn test_function_type_new() {
        let f = FunctionType::new(CType::int());
        assert!(f.return_type.is_integer());
        assert!(f.parameters.is_empty());
        assert!(!f.variadic);
    }

    #[test]
    fn test_function_type_add_param() {
        let mut f = FunctionType::new(CType::void());
        f.add_param("x".to_string(), CType::int());
        f.add_param("y".to_string(), CType::int());

        assert_eq!(f.parameters.len(), 2);
        assert_eq!(f.parameters[0].name, "x");
        assert_eq!(f.parameters[1].name, "y");
    }

    // --- TypedefType Tests ---

    #[test]
    fn test_typedef_type_new() {
        let t = TypedefType::new("myint".to_string(), CType::int());
        assert_eq!(t.name, "myint");
        assert!(t.target.is_integer());
    }

    // --- FunctionPrototype Tests ---

    #[test]
    fn test_function_prototype_new() {
        let proto = FunctionPrototype::new("test", CType::void());
        assert_eq!(proto.name, "test");
        assert!(proto.return_type.is_void());
        assert!(proto.parameters.is_empty());
        assert!(!proto.variadic);
    }

    #[test]
    fn test_function_prototype_param() {
        let proto = FunctionPrototype::new("test", CType::int())
            .param("x", CType::int())
            .param("y", CType::int());

        assert_eq!(proto.parameters.len(), 2);
    }

    #[test]
    fn test_function_prototype_variadic() {
        let proto = FunctionPrototype::new("test", CType::int()).variadic();
        assert!(proto.variadic);
    }

    #[test]
    fn test_function_prototype_to_c_string_void() {
        let proto = FunctionPrototype::new("getchar", CType::int());
        assert_eq!(proto.to_c_string(), "int getchar(void)");
    }

    #[test]
    fn test_function_prototype_to_c_string_params() {
        let proto = FunctionPrototype::new("add", CType::int())
            .param("a", CType::int())
            .param("b", CType::int());

        assert_eq!(proto.to_c_string(), "int add(int a, int b)");
    }

    // --- BitFieldInfo Tests ---

    #[test]
    fn test_bitfield_info() {
        let bf = BitFieldInfo {
            bit_offset: 0,
            bit_width: 3,
        };
        assert_eq!(bf.bit_offset, 0);
        assert_eq!(bf.bit_width, 3);
    }

    // --- CType Debug/Equality Tests ---

    #[test]
    fn test_ctype_debug() {
        let ty = CType::int();
        let debug = format!("{:?}", ty);
        assert!(debug.contains("Int"));
    }

    #[test]
    fn test_ctype_equality() {
        assert_eq!(CType::int(), CType::int());
        assert_ne!(CType::int(), CType::long());
        assert_eq!(CType::ptr(CType::char()), CType::ptr(CType::char()));
    }

    #[test]
    fn test_ctype_clone() {
        let ty = CType::ptr(CType::int());
        let cloned = ty.clone();
        assert_eq!(ty, cloned);
    }
}
