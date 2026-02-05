//! C++ class reconstruction from vtables and RTTI.
//!
//! This module reconstructs C++ class definitions by combining:
//! - Virtual function tables for method signatures
//! - RTTI for class hierarchy and inheritance
//! - Object layout analysis for data members
//!
//! # Example
//!
//! ```ignore
//! use hexray_analysis::class_reconstruction::ClassReconstructor;
//!
//! let reconstructor = ClassReconstructor::new(vtable_db, rtti_db);
//! let classes = reconstructor.reconstruct_all();
//!
//! for class in &classes {
//!     println!("{}", class.to_cpp());
//! }
//! ```

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::rtti::{ClassHierarchy, RttiDatabase, TypeInfo, TypeInfoKind};
use crate::vtable::{Vtable, VtableDatabase, VtableEntry};

/// A reconstructed C++ class.
#[derive(Debug, Clone)]
pub struct ReconstructedClass {
    /// Class name.
    pub name: String,
    /// Address of the typeinfo structure (if available).
    pub typeinfo_addr: Option<u64>,
    /// Address of the primary vtable.
    pub vtable_addr: Option<u64>,
    /// Base classes.
    pub bases: Vec<BaseClass>,
    /// Virtual methods.
    pub virtual_methods: Vec<VirtualMethod>,
    /// Estimated data members.
    pub data_members: Vec<DataMember>,
    /// Whether this is an abstract class (has pure virtual methods).
    pub is_abstract: bool,
    /// Estimated object size in bytes.
    pub estimated_size: Option<usize>,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f64,
}

/// A base class relationship.
#[derive(Debug, Clone)]
pub struct BaseClass {
    /// Name of the base class.
    pub name: String,
    /// Offset to base class subobject.
    pub offset: i64,
    /// Whether this is a virtual base.
    pub is_virtual: bool,
    /// Whether this is a public base.
    pub is_public: bool,
    /// Address of the base class vtable (for secondary vtables).
    pub vtable_addr: Option<u64>,
}

/// A reconstructed virtual method.
#[derive(Debug, Clone)]
pub struct VirtualMethod {
    /// Method name (may be mangled or auto-generated).
    pub name: String,
    /// Index in the vtable.
    pub vtable_index: usize,
    /// Offset in bytes within the vtable.
    pub vtable_offset: usize,
    /// Address of the implementation.
    pub address: u64,
    /// Whether this is a pure virtual method.
    pub is_pure_virtual: bool,
    /// Whether this overrides a base class method.
    pub is_override: bool,
    /// The base class this is inherited from (if applicable).
    pub inherited_from: Option<String>,
    /// Inferred return type.
    pub return_type: String,
    /// Inferred parameter types.
    pub parameters: Vec<MethodParameter>,
    /// This-pointer adjustment for thunks.
    pub this_adjustment: Option<i64>,
}

/// A method parameter.
#[derive(Debug, Clone)]
pub struct MethodParameter {
    /// Parameter name.
    pub name: String,
    /// Parameter type.
    pub type_name: String,
}

/// A reconstructed data member.
#[derive(Debug, Clone)]
pub struct DataMember {
    /// Member name.
    pub name: String,
    /// Member type.
    pub type_name: String,
    /// Offset within the object.
    pub offset: usize,
    /// Size of the member.
    pub size: usize,
    /// Confidence in this reconstruction.
    pub confidence: f64,
}

/// Statistics about class reconstruction.
#[derive(Debug, Clone, Default)]
pub struct ReconstructionStats {
    /// Total number of classes reconstructed.
    pub total_classes: usize,
    /// Number of abstract classes.
    pub abstract_classes: usize,
    /// Number with single inheritance.
    pub single_inheritance: usize,
    /// Number with multiple inheritance.
    pub multiple_inheritance: usize,
    /// Number with virtual inheritance.
    pub virtual_inheritance: usize,
    /// Total virtual methods found.
    pub total_virtual_methods: usize,
    /// Number of pure virtual methods.
    pub pure_virtual_methods: usize,
}

/// C++ class reconstructor.
pub struct ClassReconstructor {
    /// Vtable database.
    vtable_db: Arc<VtableDatabase>,
    /// RTTI database.
    rtti_db: Option<Arc<RttiDatabase>>,
    /// Pointer size in bytes.
    pointer_size: usize,
    /// Symbol table for function names.
    symbols: HashMap<u64, String>,
    /// Function signature hints.
    signatures: HashMap<u64, FunctionSignatureHint>,
}

/// Hint about a function's signature.
#[derive(Debug, Clone)]
pub struct FunctionSignatureHint {
    /// Return type.
    pub return_type: String,
    /// Parameter types.
    pub parameters: Vec<String>,
    /// Whether this is const-qualified.
    pub is_const: bool,
}

impl ClassReconstructor {
    /// Creates a new class reconstructor.
    pub fn new(vtable_db: Arc<VtableDatabase>, rtti_db: Option<Arc<RttiDatabase>>) -> Self {
        Self {
            vtable_db,
            rtti_db,
            pointer_size: 8,
            symbols: HashMap::new(),
            signatures: HashMap::new(),
        }
    }

    /// Sets the pointer size (default: 8).
    pub fn with_pointer_size(mut self, size: usize) -> Self {
        self.pointer_size = size;
        self
    }

    /// Adds symbol information for function names.
    pub fn with_symbols(mut self, symbols: impl IntoIterator<Item = (u64, String)>) -> Self {
        self.symbols.extend(symbols);
        self
    }

    /// Adds function signature hints.
    pub fn with_signatures(
        mut self,
        signatures: impl IntoIterator<Item = (u64, FunctionSignatureHint)>,
    ) -> Self {
        self.signatures.extend(signatures);
        self
    }

    /// Reconstructs all classes from available vtables and RTTI.
    pub fn reconstruct_all(&self) -> Vec<ReconstructedClass> {
        let mut classes = Vec::new();
        let mut seen_vtables = HashSet::new();

        // Process primary vtables first
        for vtable in self.vtable_db.all() {
            if !vtable.is_primary || seen_vtables.contains(&vtable.address) {
                continue;
            }
            seen_vtables.insert(vtable.address);

            if let Some(class) = self.reconstruct_from_vtable(vtable) {
                classes.push(class);
            }
        }

        // Sort by name for consistent output
        classes.sort_by(|a, b| a.name.cmp(&b.name));

        classes
    }

    /// Reconstructs a class from a vtable.
    pub fn reconstruct_from_vtable(&self, vtable: &Vtable) -> Option<ReconstructedClass> {
        let name = self.determine_class_name(vtable)?;

        let mut class = ReconstructedClass {
            name: name.clone(),
            typeinfo_addr: vtable.typeinfo_addr,
            vtable_addr: Some(vtable.address),
            bases: Vec::new(),
            virtual_methods: Vec::new(),
            data_members: Vec::new(),
            is_abstract: false,
            estimated_size: None,
            confidence: vtable.confidence,
        };

        // Extract base classes from RTTI
        if let Some(rtti_db) = &self.rtti_db {
            if let Some(ti_addr) = vtable.typeinfo_addr {
                if let Some(type_info) = rtti_db.hierarchy.get(ti_addr) {
                    self.extract_bases(&mut class, type_info, &rtti_db.hierarchy);
                }
            }
        }

        // Extract virtual methods
        self.extract_virtual_methods(&mut class, vtable);

        // Check for pure virtuals
        class.is_abstract = class.virtual_methods.iter().any(|m| m.is_pure_virtual);

        // Add secondary vtables for multiple inheritance
        self.add_secondary_vtable_methods(&mut class, vtable.address);

        // Estimate data layout
        self.estimate_data_layout(&mut class);

        Some(class)
    }

    /// Determines the class name from vtable or RTTI.
    fn determine_class_name(&self, vtable: &Vtable) -> Option<String> {
        // Prefer RTTI name
        if let Some(name) = &vtable.class_name {
            return Some(name.clone());
        }

        // Try to get from RTTI database
        if let Some(rtti_db) = &self.rtti_db {
            if let Some(ti_addr) = vtable.typeinfo_addr {
                if let Some(ti) = rtti_db.hierarchy.get(ti_addr) {
                    return Some(ti.name.clone());
                }
            }
        }

        // Try to infer from method names
        for entry in &vtable.entries {
            if let Some(name) = &entry.name {
                if let Some(class_name) = self.extract_class_from_method(name) {
                    return Some(class_name);
                }
            }
        }

        // Last resort: generate name from address
        Some(format!("Class_{:x}", vtable.address))
    }

    /// Extracts class name from a method name like "MyClass::method".
    fn extract_class_from_method(&self, method_name: &str) -> Option<String> {
        let parts: Vec<&str> = method_name.split("::").collect();
        if parts.len() >= 2 {
            // Handle nested namespaces, return last class name
            Some(parts[parts.len() - 2].to_string())
        } else {
            None
        }
    }

    /// Extracts base class information from RTTI.
    fn extract_bases(
        &self,
        class: &mut ReconstructedClass,
        type_info: &TypeInfo,
        hierarchy: &ClassHierarchy,
    ) {
        match &type_info.kind {
            TypeInfoKind::SingleInheritance {
                base_typeinfo_addr,
                base_name,
            } => {
                let name = base_name.clone().unwrap_or_else(|| {
                    hierarchy
                        .get(*base_typeinfo_addr)
                        .map(|ti| ti.name.clone())
                        .unwrap_or_else(|| format!("Base_{:x}", base_typeinfo_addr))
                });

                class.bases.push(BaseClass {
                    name,
                    offset: 0,
                    is_virtual: false,
                    is_public: true,
                    vtable_addr: None,
                });
            }
            TypeInfoKind::VirtualMultipleInheritance { bases, .. } => {
                for base in bases {
                    let name = base.type_name.clone().unwrap_or_else(|| {
                        hierarchy
                            .get(base.typeinfo_addr)
                            .map(|ti| ti.name.clone())
                            .unwrap_or_else(|| format!("Base_{:x}", base.typeinfo_addr))
                    });

                    class.bases.push(BaseClass {
                        name,
                        offset: base.offset,
                        is_virtual: base.flags.is_virtual,
                        is_public: base.flags.is_public,
                        vtable_addr: None,
                    });
                }
            }
            _ => {}
        }
    }

    /// Extracts virtual methods from a vtable.
    fn extract_virtual_methods(&self, class: &mut ReconstructedClass, vtable: &Vtable) {
        for (index, entry) in vtable.entries.iter().enumerate() {
            let method = self.create_virtual_method(
                entry,
                index,
                &class.name,
                &class.bases,
                false, // not from secondary vtable
            );
            class.virtual_methods.push(method);
        }
    }

    /// Creates a virtual method from a vtable entry.
    fn create_virtual_method(
        &self,
        entry: &VtableEntry,
        index: usize,
        class_name: &str,
        bases: &[BaseClass],
        _from_secondary: bool,
    ) -> VirtualMethod {
        let name = self.determine_method_name(entry, index, class_name);
        let (return_type, parameters) = self.infer_signature(entry.target);
        let inherited_from = self.check_if_inherited(&name, bases);
        let is_override = inherited_from.is_some();

        VirtualMethod {
            name,
            vtable_index: index,
            vtable_offset: entry.offset,
            address: entry.target,
            is_pure_virtual: entry.is_pure_virtual,
            is_override,
            inherited_from,
            return_type,
            parameters,
            this_adjustment: entry.thunk.as_ref().map(|t| t.this_adjustment),
        }
    }

    /// Determines the method name from entry or generates one.
    fn determine_method_name(&self, entry: &VtableEntry, index: usize, class_name: &str) -> String {
        // Check vtable entry name
        if let Some(name) = &entry.name {
            return self.simplify_method_name(name);
        }

        // Check symbol table
        if let Some(name) = self.symbols.get(&entry.target) {
            return self.simplify_method_name(name);
        }

        // Check for resolved thunk target
        if let Some(thunk) = &entry.thunk {
            if let Some(name) = self.symbols.get(&thunk.target_function) {
                return self.simplify_method_name(name);
            }
        }

        // Generate name based on slot
        format!("{}::vmethod_{}", class_name, index)
    }

    /// Simplifies a demangled method name.
    fn simplify_method_name(&self, full_name: &str) -> String {
        // Remove return type prefix if present
        // e.g., "void MyClass::method()" -> "MyClass::method"
        let name = full_name
            .trim_start_matches("virtual ")
            .trim_start_matches("void ")
            .trim_start_matches("int ")
            .trim_start_matches("bool ");

        // Remove parameter list for cleaner display
        if let Some(paren_pos) = name.find('(') {
            name[..paren_pos].to_string()
        } else {
            name.to_string()
        }
    }

    /// Infers function signature from available information.
    fn infer_signature(&self, func_addr: u64) -> (String, Vec<MethodParameter>) {
        if let Some(hint) = self.signatures.get(&func_addr) {
            let params = hint
                .parameters
                .iter()
                .enumerate()
                .map(|(i, t)| MethodParameter {
                    name: format!("arg{}", i),
                    type_name: t.clone(),
                })
                .collect();
            return (hint.return_type.clone(), params);
        }

        // Default: unknown signature
        ("void".to_string(), Vec::new())
    }

    /// Checks if a method is inherited from a base class.
    fn check_if_inherited(&self, method_name: &str, bases: &[BaseClass]) -> Option<String> {
        // Check if method name contains a base class name
        for base in bases {
            if method_name.contains(&format!("{}::", base.name)) {
                return Some(base.name.clone());
            }
        }
        None
    }

    /// Adds methods from secondary vtables (for multiple inheritance).
    fn add_secondary_vtable_methods(&self, class: &mut ReconstructedClass, primary_addr: u64) {
        let secondaries = self.vtable_db.get_secondaries_for_primary(primary_addr);

        for (idx, secondary) in secondaries.iter().enumerate() {
            // Try to match with a base class
            let base_name = secondary
                .base_class_name
                .clone()
                .or_else(|| class.bases.get(idx + 1).map(|b| b.name.clone()));

            // Update base class vtable address
            if let Some(ref name) = base_name {
                for base in &mut class.bases {
                    if &base.name == name {
                        base.vtable_addr = Some(secondary.address);
                        break;
                    }
                }
            }

            // Add methods from secondary vtable
            for (index, entry) in secondary.entries.iter().enumerate() {
                // Check if this method already exists in primary
                let already_exists = class
                    .virtual_methods
                    .iter()
                    .any(|m| m.address == entry.resolved_target());

                if !already_exists {
                    let method = self.create_virtual_method(
                        entry,
                        index,
                        base_name.as_deref().unwrap_or(&class.name),
                        &class.bases,
                        true,
                    );
                    class.virtual_methods.push(method);
                }
            }
        }
    }

    /// Estimates data layout for the class.
    fn estimate_data_layout(&self, class: &mut ReconstructedClass) {
        // Vtable pointer is at offset 0
        let vtable_ptr_size = self.pointer_size;

        // Calculate minimum size from inheritance
        let mut min_offset = vtable_ptr_size;
        for base in &class.bases {
            if !base.is_virtual && base.offset > 0 {
                // Base at non-zero offset means data between vtable and base
                min_offset = min_offset.max(base.offset as usize);
            }
        }

        // Estimate a potential member after vtable pointer
        if min_offset > vtable_ptr_size {
            let member_size = min_offset - vtable_ptr_size;
            if member_size >= 1 {
                class.data_members.push(DataMember {
                    name: format!("field_{:x}", vtable_ptr_size),
                    type_name: self.guess_type_from_size(member_size),
                    offset: vtable_ptr_size,
                    size: member_size,
                    confidence: 0.3,
                });
            }
        }

        // Calculate estimated size
        let mut max_extent = vtable_ptr_size;
        for base in &class.bases {
            if base.offset > 0 {
                // Assume base class has at least a vtable pointer
                let base_extent = base.offset as usize + vtable_ptr_size;
                max_extent = max_extent.max(base_extent);
            }
        }
        for member in &class.data_members {
            let member_extent = member.offset + member.size;
            max_extent = max_extent.max(member_extent);
        }

        class.estimated_size = Some(max_extent);
    }

    /// Guesses a type name based on size.
    fn guess_type_from_size(&self, size: usize) -> String {
        match size {
            1 => "uint8_t".to_string(),
            2 => "uint16_t".to_string(),
            4 => "uint32_t".to_string(),
            8 => "uint64_t".to_string(),
            _ => format!("uint8_t[{}]", size),
        }
    }

    /// Computes reconstruction statistics.
    pub fn compute_stats(&self, classes: &[ReconstructedClass]) -> ReconstructionStats {
        let mut stats = ReconstructionStats {
            total_classes: classes.len(),
            ..Default::default()
        };

        for class in classes {
            if class.is_abstract {
                stats.abstract_classes += 1;
            }

            match class.bases.len() {
                0 => {}
                1 => stats.single_inheritance += 1,
                _ => stats.multiple_inheritance += 1,
            }

            if class.bases.iter().any(|b| b.is_virtual) {
                stats.virtual_inheritance += 1;
            }

            stats.total_virtual_methods += class.virtual_methods.len();
            stats.pure_virtual_methods += class
                .virtual_methods
                .iter()
                .filter(|m| m.is_pure_virtual)
                .count();
        }

        stats
    }
}

impl ReconstructedClass {
    /// Generates C++ class declaration.
    pub fn to_cpp(&self) -> String {
        let mut output = String::new();

        // Class declaration
        output.push_str(&format!("class {}", self.name));

        // Base classes
        if !self.bases.is_empty() {
            output.push_str(" : ");
            let bases: Vec<String> = self
                .bases
                .iter()
                .map(|b| {
                    let vis = if b.is_public { "public" } else { "private" };
                    let virt = if b.is_virtual { "virtual " } else { "" };
                    format!("{} {}{}", vis, virt, b.name)
                })
                .collect();
            output.push_str(&bases.join(", "));
        }

        output.push_str(" {\n");

        // Virtual methods (public section)
        output.push_str("public:\n");

        // Destructor (assume virtual if class has vtable)
        output.push_str(&format!("    virtual ~{}();\n", self.name));

        // Virtual methods
        for method in &self.virtual_methods {
            let pure = if method.is_pure_virtual { " = 0" } else { "" };
            let override_spec = if method.is_override { " override" } else { "" };

            // Extract just the method name (remove class prefix)
            let method_name = method.name.rsplit("::").next().unwrap_or(&method.name);

            // Parameter list
            let params: Vec<String> = method
                .parameters
                .iter()
                .map(|p| format!("{} {}", p.type_name, p.name))
                .collect();
            let param_str = params.join(", ");

            output.push_str(&format!(
                "    virtual {} {}({}){}{};",
                method.return_type, method_name, param_str, override_spec, pure
            ));

            // Add address comment
            output.push_str(&format!(" // 0x{:x}", method.address));
            if let Some(adj) = method.this_adjustment {
                output.push_str(&format!(" [this+{}]", adj));
            }
            output.push('\n');
        }

        // Data members (private/protected section)
        if !self.data_members.is_empty() {
            output.push_str("\nprivate:\n");
            for member in &self.data_members {
                output.push_str(&format!(
                    "    {} {}; // offset 0x{:x}\n",
                    member.type_name, member.name, member.offset
                ));
            }
        }

        output.push_str("};\n");

        // Add size comment
        if let Some(size) = self.estimated_size {
            output.push_str(&format!("// sizeof({}) >= 0x{:x}\n", self.name, size));
        }

        // Add vtable address comment
        if let Some(vtable_addr) = self.vtable_addr {
            output.push_str(&format!("// vtable at 0x{:x}\n", vtable_addr));
        }

        output
    }

    /// Generates C++ class declaration with minimal formatting.
    pub fn to_cpp_minimal(&self) -> String {
        let mut output = String::new();

        // Forward declaration style
        output.push_str(&format!("class {}", self.name));

        if !self.bases.is_empty() {
            output.push_str(" : ");
            let bases: Vec<String> = self
                .bases
                .iter()
                .map(|b| {
                    if b.is_virtual {
                        format!("virtual {}", b.name)
                    } else {
                        b.name.clone()
                    }
                })
                .collect();
            output.push_str(&bases.join(", "));
        }

        output.push_str(" { /* ");
        output.push_str(&format!("{} virtual methods", self.virtual_methods.len()));
        if self.is_abstract {
            output.push_str(", abstract");
        }
        output.push_str(" */ };");

        output
    }
}

/// Database of reconstructed classes.
#[derive(Debug, Default)]
pub struct ReconstructedClassDatabase {
    /// Classes by name.
    by_name: HashMap<String, ReconstructedClass>,
    /// Classes by vtable address.
    by_vtable: HashMap<u64, String>,
    /// Classes by typeinfo address.
    by_typeinfo: HashMap<u64, String>,
}

impl ReconstructedClassDatabase {
    /// Creates a new empty database.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a database from a list of reconstructed classes.
    pub fn from_classes(classes: Vec<ReconstructedClass>) -> Self {
        let mut db = Self::new();
        for class in classes {
            db.add(class);
        }
        db
    }

    /// Adds a class to the database.
    pub fn add(&mut self, class: ReconstructedClass) {
        if let Some(vtable_addr) = class.vtable_addr {
            self.by_vtable.insert(vtable_addr, class.name.clone());
        }
        if let Some(ti_addr) = class.typeinfo_addr {
            self.by_typeinfo.insert(ti_addr, class.name.clone());
        }
        self.by_name.insert(class.name.clone(), class);
    }

    /// Gets a class by name.
    pub fn get_by_name(&self, name: &str) -> Option<&ReconstructedClass> {
        self.by_name.get(name)
    }

    /// Gets a class by vtable address.
    pub fn get_by_vtable(&self, vtable_addr: u64) -> Option<&ReconstructedClass> {
        self.by_vtable
            .get(&vtable_addr)
            .and_then(|name| self.by_name.get(name))
    }

    /// Gets a class by typeinfo address.
    pub fn get_by_typeinfo(&self, typeinfo_addr: u64) -> Option<&ReconstructedClass> {
        self.by_typeinfo
            .get(&typeinfo_addr)
            .and_then(|name| self.by_name.get(name))
    }

    /// Returns all classes.
    pub fn all(&self) -> impl Iterator<Item = &ReconstructedClass> {
        self.by_name.values()
    }

    /// Returns the number of classes.
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Returns true if the database is empty.
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// Generates C++ header for all classes.
    pub fn to_cpp_header(&self) -> String {
        let mut output = String::new();

        output.push_str("// Reconstructed C++ classes\n");
        output.push_str("// Generated by hexray decompiler\n\n");

        output.push_str("#pragma once\n\n");
        output.push_str("#include <cstdint>\n\n");

        // Forward declarations
        output.push_str("// Forward declarations\n");
        for name in self.by_name.keys() {
            output.push_str(&format!("class {};\n", name));
        }
        output.push('\n');

        // Full class definitions
        output.push_str("// Class definitions\n\n");

        // Sort for consistent output
        let mut classes: Vec<_> = self.by_name.values().collect();
        classes.sort_by(|a, b| a.name.cmp(&b.name));

        for class in classes {
            output.push_str(&class.to_cpp());
            output.push('\n');
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_vtable(addr: u64, class_name: &str, entries: Vec<(u64, Option<&str>)>) -> Vtable {
        let mut vtable = Vtable::new(addr);
        vtable.class_name = Some(class_name.to_string());
        vtable.entries = entries
            .into_iter()
            .enumerate()
            .map(|(i, (target, name))| {
                let mut entry = VtableEntry::new(i * 8, target);
                if let Some(n) = name {
                    entry = entry.with_name(n);
                }
                entry
            })
            .collect();
        vtable
    }

    #[test]
    fn test_reconstruct_simple_class() {
        let vtable = make_test_vtable(
            0x1000,
            "Shape",
            vec![
                (0x2000, Some("Shape::~Shape()")),
                (0x2100, Some("Shape::draw()")),
                (0x2200, Some("Shape::area()")),
            ],
        );

        let db = VtableDatabase::from_vtables(vec![vtable]);
        let reconstructor = ClassReconstructor::new(Arc::new(db), None);
        let classes = reconstructor.reconstruct_all();

        assert_eq!(classes.len(), 1);
        let class = &classes[0];
        assert_eq!(class.name, "Shape");
        assert_eq!(class.virtual_methods.len(), 3);
        assert!(!class.is_abstract);
    }

    #[test]
    fn test_reconstruct_abstract_class() {
        let mut vtable = make_test_vtable(
            0x1000,
            "AbstractShape",
            vec![
                (0x2000, Some("AbstractShape::~AbstractShape()")),
                (0x0, Some("AbstractShape::draw()")), // pure virtual
            ],
        );
        vtable.entries[1] = vtable.entries[1].clone().with_pure_virtual(true);

        let db = VtableDatabase::from_vtables(vec![vtable]);
        let reconstructor = ClassReconstructor::new(Arc::new(db), None);
        let classes = reconstructor.reconstruct_all();

        assert_eq!(classes.len(), 1);
        assert!(classes[0].is_abstract);
    }

    #[test]
    fn test_cpp_output() {
        let vtable = make_test_vtable(
            0x1000,
            "Widget",
            vec![
                (0x2000, Some("Widget::~Widget()")),
                (0x2100, Some("Widget::paint()")),
            ],
        );

        let db = VtableDatabase::from_vtables(vec![vtable]);
        let reconstructor = ClassReconstructor::new(Arc::new(db), None);
        let classes = reconstructor.reconstruct_all();

        let cpp = classes[0].to_cpp();
        assert!(cpp.contains("class Widget"));
        assert!(cpp.contains("virtual ~Widget()"));
        assert!(cpp.contains("virtual void paint()"));
    }

    #[test]
    fn test_class_database() {
        let vtable1 = make_test_vtable(0x1000, "ClassA", vec![(0x2000, None)]);
        let vtable2 = make_test_vtable(0x3000, "ClassB", vec![(0x4000, None)]);

        let db = VtableDatabase::from_vtables(vec![vtable1, vtable2]);
        let reconstructor = ClassReconstructor::new(Arc::new(db), None);
        let classes = reconstructor.reconstruct_all();

        let class_db = ReconstructedClassDatabase::from_classes(classes);

        assert_eq!(class_db.len(), 2);
        assert!(class_db.get_by_name("ClassA").is_some());
        assert!(class_db.get_by_vtable(0x1000).is_some());
    }

    #[test]
    fn test_reconstruction_stats() {
        let mut vtable1 = make_test_vtable(0x1000, "Base", vec![(0x2000, None), (0x0, None)]);
        vtable1.entries[1] = vtable1.entries[1].clone().with_pure_virtual(true);

        let vtable2 = make_test_vtable(0x3000, "Derived", vec![(0x4000, None), (0x4100, None)]);

        let db = VtableDatabase::from_vtables(vec![vtable1, vtable2]);
        let reconstructor = ClassReconstructor::new(Arc::new(db), None);
        let classes = reconstructor.reconstruct_all();

        let stats = reconstructor.compute_stats(&classes);
        assert_eq!(stats.total_classes, 2);
        assert_eq!(stats.abstract_classes, 1);
        assert_eq!(stats.total_virtual_methods, 4);
        assert_eq!(stats.pure_virtual_methods, 1);
    }

    #[test]
    fn test_minimal_cpp_output() {
        let vtable = make_test_vtable(0x1000, "TestClass", vec![(0x2000, None), (0x2100, None)]);

        let db = VtableDatabase::from_vtables(vec![vtable]);
        let reconstructor = ClassReconstructor::new(Arc::new(db), None);
        let classes = reconstructor.reconstruct_all();

        let cpp = classes[0].to_cpp_minimal();
        assert!(cpp.contains("class TestClass"));
        assert!(cpp.contains("2 virtual methods"));
    }
}
