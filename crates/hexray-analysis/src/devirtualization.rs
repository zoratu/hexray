//! Virtual function call devirtualization analysis.
//!
//! This module orchestrates vtable and RTTI information to identify
//! and resolve virtual function calls to their possible implementations.

use std::collections::HashMap;
use std::sync::Arc;

use hexray_core::BasicBlockId;

use crate::rtti::RttiDatabase;
use crate::vtable::{Vtable, VtableDatabase};

/// A virtual function call site.
#[derive(Debug, Clone)]
pub struct VirtualCallSite {
    /// Address of the call instruction.
    pub address: u64,
    /// Block containing the call.
    pub block_id: BasicBlockId,
    /// The object pointer expression (register or memory location).
    pub object_location: ObjectLocation,
    /// Inferred type of the object (if known).
    pub object_type: Option<String>,
    /// Vtable address (if determined statically).
    pub vtable_addr: Option<u64>,
    /// Method index (offset / pointer_size).
    pub method_index: usize,
    /// Method offset in bytes within vtable.
    pub method_offset: usize,
    /// Possible implementations from all known vtables.
    pub possible_implementations: Vec<MethodImplementation>,
    /// Confidence in this being a virtual call.
    pub confidence: DevirtConfidence,
}

/// Where the object pointer is located.
#[derive(Debug, Clone)]
pub enum ObjectLocation {
    /// In a register.
    Register(String),
    /// On the stack (frame offset).
    Stack(i64),
    /// In memory at an address.
    Memory(u64),
    /// Unknown location.
    Unknown,
}

/// A possible method implementation.
#[derive(Debug, Clone)]
pub struct MethodImplementation {
    /// Address of the function.
    pub address: u64,
    /// Name of the function (if known).
    pub name: Option<String>,
    /// Class that provides this implementation.
    pub class_name: Option<String>,
    /// Whether this is a pure virtual placeholder.
    pub is_pure_virtual: bool,
    /// Thunk adjustment (for multiple inheritance).
    pub this_adjustment: Option<i64>,
}

/// Confidence level for devirtualization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DevirtConfidence {
    /// No confidence - speculative.
    None,
    /// Low confidence - pattern matches but no type info.
    Low,
    /// Medium confidence - vtable identified but type uncertain.
    Medium,
    /// High confidence - vtable and type confirmed.
    High,
    /// Certain - single implementation or direct type info.
    Certain,
}

/// Results of devirtualization analysis for a function.
#[derive(Debug, Clone, Default)]
pub struct DevirtualizationResult {
    /// All virtual call sites found.
    pub virtual_calls: Vec<VirtualCallSite>,
    /// Objects with tracked types.
    pub object_types: HashMap<ObjectLocation, TrackedType>,
    /// Number of calls that could be devirtualized.
    pub devirtualized_count: usize,
    /// Number of calls with single implementation (certain).
    pub certain_count: usize,
}

/// Tracked type information for an object.
#[derive(Debug, Clone)]
pub struct TrackedType {
    /// The class name.
    pub class_name: String,
    /// Vtable address if assigned.
    pub vtable_addr: Option<u64>,
    /// Where the type was inferred from.
    pub source: TypeSource,
    /// Confidence in the type.
    pub confidence: DevirtConfidence,
}

/// Source of type information.
#[derive(Debug, Clone)]
pub enum TypeSource {
    /// From constructor call.
    Constructor,
    /// From vtable assignment.
    VtableAssignment,
    /// From RTTI dynamic_cast or typeid.
    RttiCheck,
    /// From parameter type annotation.
    Parameter,
    /// From return type of called function.
    ReturnValue,
    /// Propagated from another location.
    Propagated,
}

/// Main devirtualization analysis engine.
pub struct DevirtualizationAnalysis {
    /// Vtable database.
    vtable_db: Arc<VtableDatabase>,
    /// RTTI database.
    rtti_db: Option<Arc<RttiDatabase>>,
    /// Pointer size in bytes (8 for 64-bit).
    pointer_size: usize,
    /// Method implementations cache by (vtable, offset).
    method_cache: HashMap<(u64, usize), Vec<MethodImplementation>>,
}

impl DevirtualizationAnalysis {
    /// Creates a new devirtualization analysis.
    pub fn new(vtable_db: Arc<VtableDatabase>, rtti_db: Option<Arc<RttiDatabase>>) -> Self {
        Self {
            vtable_db,
            rtti_db,
            pointer_size: 8,
            method_cache: HashMap::new(),
        }
    }

    /// Sets the pointer size (default: 8).
    pub fn with_pointer_size(mut self, size: usize) -> Self {
        self.pointer_size = size;
        self
    }

    /// Resolves a virtual call given the vtable address and method offset.
    pub fn resolve_call(
        &mut self,
        vtable_addr: Option<u64>,
        method_offset: usize,
    ) -> Vec<MethodImplementation> {
        self.find_implementations(vtable_addr, method_offset)
    }

    /// Resolves a virtual call and returns a VirtualCallSite.
    pub fn analyze_call(
        &mut self,
        call_addr: u64,
        block_id: BasicBlockId,
        vtable_addr: Option<u64>,
        method_offset: usize,
        object_type: Option<String>,
    ) -> VirtualCallSite {
        let implementations = self.find_implementations(vtable_addr, method_offset);
        let confidence = if vtable_addr.is_some() {
            if implementations.len() == 1 {
                DevirtConfidence::Certain
            } else {
                DevirtConfidence::High
            }
        } else if !implementations.is_empty() {
            DevirtConfidence::Low
        } else {
            DevirtConfidence::None
        };

        VirtualCallSite {
            address: call_addr,
            block_id,
            object_location: ObjectLocation::Unknown,
            object_type,
            vtable_addr,
            method_index: method_offset / self.pointer_size,
            method_offset,
            possible_implementations: implementations,
            confidence,
        }
    }

    /// Finds all implementations for a method at a given offset.
    fn find_implementations(
        &mut self,
        vtable_addr: Option<u64>,
        offset: usize,
    ) -> Vec<MethodImplementation> {
        // Check cache first
        if let Some(vtable_addr) = vtable_addr {
            if let Some(cached) = self.method_cache.get(&(vtable_addr, offset)) {
                return cached.clone();
            }
        }

        let mut implementations = Vec::new();

        if let Some(vtable_addr) = vtable_addr {
            // We know the exact vtable - get just that implementation
            if let Some(vtable) = self.vtable_db.get_by_address(vtable_addr) {
                if let Some(method) = self.get_method_at_offset(vtable, offset) {
                    implementations.push(method);
                }

                // Also include derived class implementations
                self.add_derived_implementations(vtable_addr, offset, &mut implementations);
            }
        } else {
            // No specific vtable - enumerate all possibilities
            for vtable in self.vtable_db.all() {
                if let Some(method) = self.get_method_at_offset(vtable, offset) {
                    // Avoid duplicates
                    if !implementations.iter().any(|m| m.address == method.address) {
                        implementations.push(method);
                    }
                }
            }
        }

        // Cache the result
        if let Some(vtable_addr) = vtable_addr {
            self.method_cache
                .insert((vtable_addr, offset), implementations.clone());
        }

        implementations
    }

    /// Gets the method at a specific offset in a vtable.
    fn get_method_at_offset(&self, vtable: &Vtable, offset: usize) -> Option<MethodImplementation> {
        let index = offset / self.pointer_size;
        vtable.entries.get(index).map(|entry| MethodImplementation {
            address: entry.target,
            name: entry.name.clone(),
            class_name: vtable.class_name.clone(),
            is_pure_virtual: entry.is_pure_virtual,
            this_adjustment: entry.thunk.as_ref().map(|t| t.this_adjustment),
        })
    }

    /// Adds implementations from derived classes.
    fn add_derived_implementations(
        &self,
        base_vtable_addr: u64,
        offset: usize,
        implementations: &mut Vec<MethodImplementation>,
    ) {
        if let Some(rtti_db) = &self.rtti_db {
            // Get the typeinfo for this vtable
            if let Some(type_info) = rtti_db.typeinfo_for_vtable(base_vtable_addr) {
                // Find all derived classes via the class hierarchy
                let derived_types = rtti_db.hierarchy.all_derived(type_info.address);
                for derived_ti in derived_types {
                    // Find vtable for derived class
                    let derived_vtables = self.vtable_db.get_by_class(&derived_ti.name);
                    for derived_vtable in derived_vtables {
                        if let Some(method) = self.get_method_at_offset(derived_vtable, offset) {
                            if !implementations.iter().any(|m| m.address == method.address) {
                                implementations.push(method);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Query interface: Given a class type and method index, get implementations.
    pub fn get_method_implementations(
        &mut self,
        class_name: &str,
        method_index: usize,
    ) -> Vec<MethodImplementation> {
        let offset = method_index * self.pointer_size;

        // Find vtable for the class
        let vtables = self.vtable_db.get_by_class(class_name);
        if let Some(vtable) = vtables.first() {
            return self.find_implementations(Some(vtable.address), offset);
        }

        // No vtable found - try all vtables
        self.find_implementations(None, offset)
    }

    /// Gets all methods at a specific slot across all vtables.
    pub fn get_all_methods_at_slot(&mut self, method_index: usize) -> Vec<MethodImplementation> {
        let offset = method_index * self.pointer_size;
        self.find_implementations(None, offset)
    }
}

/// Database of devirtualization results for quick queries.
#[derive(Debug, Default)]
pub struct DevirtualizationDatabase {
    /// Virtual calls indexed by call address.
    calls_by_addr: HashMap<u64, VirtualCallSite>,
    /// Virtual calls indexed by block.
    calls_by_block: HashMap<BasicBlockId, Vec<u64>>,
    /// Methods by (class, index).
    methods: HashMap<(String, usize), Vec<MethodImplementation>>,
}

impl DevirtualizationDatabase {
    /// Creates a new empty database.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a devirtualization result.
    pub fn add_result(&mut self, result: &DevirtualizationResult) {
        for call in &result.virtual_calls {
            self.calls_by_addr.insert(call.address, call.clone());
            self.calls_by_block
                .entry(call.block_id)
                .or_default()
                .push(call.address);

            if let Some(class_name) = &call.object_type {
                let key = (class_name.clone(), call.method_index);
                self.methods
                    .entry(key)
                    .or_default()
                    .extend(call.possible_implementations.clone());
            }
        }
    }

    /// Adds a single virtual call site.
    pub fn add_call(&mut self, call: VirtualCallSite) {
        self.calls_by_block
            .entry(call.block_id)
            .or_default()
            .push(call.address);

        if let Some(class_name) = &call.object_type {
            let key = (class_name.clone(), call.method_index);
            self.methods
                .entry(key)
                .or_default()
                .extend(call.possible_implementations.clone());
        }

        self.calls_by_addr.insert(call.address, call);
    }

    /// Gets virtual call info for an address.
    pub fn get_call(&self, addr: u64) -> Option<&VirtualCallSite> {
        self.calls_by_addr.get(&addr)
    }

    /// Gets all virtual calls in a block.
    pub fn get_block_calls(&self, block_id: BasicBlockId) -> Vec<&VirtualCallSite> {
        self.calls_by_block
            .get(&block_id)
            .map(|addrs| {
                addrs
                    .iter()
                    .filter_map(|a| self.calls_by_addr.get(a))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Gets method implementations for a class and method index.
    pub fn get_methods(&self, class_name: &str, method_index: usize) -> &[MethodImplementation] {
        self.methods
            .get(&(class_name.to_string(), method_index))
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Returns the number of virtual calls tracked.
    pub fn call_count(&self) -> usize {
        self.calls_by_addr.len()
    }

    /// Returns all tracked calls.
    pub fn all_calls(&self) -> impl Iterator<Item = &VirtualCallSite> {
        self.calls_by_addr.values()
    }
}

impl std::hash::Hash for ObjectLocation {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            ObjectLocation::Register(r) => {
                0u8.hash(state);
                r.hash(state);
            }
            ObjectLocation::Stack(off) => {
                1u8.hash(state);
                off.hash(state);
            }
            ObjectLocation::Memory(addr) => {
                2u8.hash(state);
                addr.hash(state);
            }
            ObjectLocation::Unknown => {
                3u8.hash(state);
            }
        }
    }
}

impl PartialEq for ObjectLocation {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (ObjectLocation::Register(a), ObjectLocation::Register(b)) => a == b,
            (ObjectLocation::Stack(a), ObjectLocation::Stack(b)) => a == b,
            (ObjectLocation::Memory(a), ObjectLocation::Memory(b)) => a == b,
            (ObjectLocation::Unknown, ObjectLocation::Unknown) => true,
            _ => false,
        }
    }
}

impl Eq for ObjectLocation {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_devirt_confidence_ordering() {
        assert!(DevirtConfidence::None < DevirtConfidence::Low);
        assert!(DevirtConfidence::Low < DevirtConfidence::Medium);
        assert!(DevirtConfidence::Medium < DevirtConfidence::High);
        assert!(DevirtConfidence::High < DevirtConfidence::Certain);
    }

    #[test]
    fn test_object_location_equality() {
        assert_eq!(
            ObjectLocation::Register("rax".to_string()),
            ObjectLocation::Register("rax".to_string())
        );
        assert_ne!(
            ObjectLocation::Register("rax".to_string()),
            ObjectLocation::Register("rbx".to_string())
        );
        assert_eq!(ObjectLocation::Stack(-16), ObjectLocation::Stack(-16));
        assert_eq!(
            ObjectLocation::Memory(0x1000),
            ObjectLocation::Memory(0x1000)
        );
        assert_eq!(ObjectLocation::Unknown, ObjectLocation::Unknown);
    }

    #[test]
    fn test_devirtualization_database() {
        let mut db = DevirtualizationDatabase::new();

        let result = DevirtualizationResult {
            virtual_calls: vec![VirtualCallSite {
                address: 0x1000,
                block_id: BasicBlockId::new(1),
                object_location: ObjectLocation::Register("rdi".to_string()),
                object_type: Some("Shape".to_string()),
                vtable_addr: Some(0x5000),
                method_index: 2,
                method_offset: 16,
                possible_implementations: vec![
                    MethodImplementation {
                        address: 0x2000,
                        name: Some("Shape::draw".to_string()),
                        class_name: Some("Shape".to_string()),
                        is_pure_virtual: false,
                        this_adjustment: None,
                    },
                    MethodImplementation {
                        address: 0x3000,
                        name: Some("Circle::draw".to_string()),
                        class_name: Some("Circle".to_string()),
                        is_pure_virtual: false,
                        this_adjustment: None,
                    },
                ],
                confidence: DevirtConfidence::High,
            }],
            object_types: HashMap::new(),
            devirtualized_count: 1,
            certain_count: 0,
        };

        db.add_result(&result);

        assert_eq!(db.call_count(), 1);
        assert!(db.get_call(0x1000).is_some());
        assert!(db.get_call(0x2000).is_none());

        let methods = db.get_methods("Shape", 2);
        assert_eq!(methods.len(), 2);
    }
}
