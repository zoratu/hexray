//! C++ RTTI (Run-Time Type Information) parsing.
//!
//! This module implements parsing of Itanium C++ ABI RTTI structures:
//! - `std::type_info` and derived classes
//! - Class hierarchy extraction
//! - Base class relationships
//!
//! # Itanium C++ ABI RTTI Structure
//!
//! The ABI defines three typeinfo class types:
//!
//! 1. `__class_type_info` - Classes with no bases
//!    ```text
//!    +0: vtable pointer (points to __class_type_info vtable)
//!    +8: name pointer (null-terminated mangled name like "_ZTS5Shape")
//!    ```
//!
//! 2. `__si_class_type_info` - Single inheritance (one non-virtual public base)
//!    ```text
//!    +0:  vtable pointer (points to __si_class_type_info vtable)
//!    +8:  name pointer
//!    +16: base type pointer (pointer to base class typeinfo)
//!    ```
//!
//! 3. `__vmi_class_type_info` - Virtual/multiple inheritance
//!    ```text
//!    +0:  vtable pointer (points to __vmi_class_type_info vtable)
//!    +8:  name pointer
//!    +16: flags (4 bytes)
//!    +20: base_count (4 bytes)
//!    +24: base_info[] (array of base class descriptors)
//!    ```
//!
//! # Example
//!
//! ```ignore
//! use hexray_analysis::rtti::{RttiParser, TypeInfoKind};
//!
//! let parser = RttiParser::new(8, Endianness::Little);
//! let rtti = parser.parse_typeinfo(data, base_addr, typeinfo_addr)?;
//!
//! println!("Class: {}", rtti.name);
//! if let TypeInfoKind::VirtualMultipleInheritance { bases, .. } = &rtti.kind {
//!     for base in bases {
//!         println!("  Base: {} (offset {})", base.type_name, base.offset);
//!     }
//! }
//! ```

use std::collections::{HashMap, HashSet};
use hexray_core::Endianness;

/// Parsed RTTI type information.
#[derive(Debug, Clone)]
pub struct TypeInfo {
    /// Address of the typeinfo structure.
    pub address: u64,
    /// Demangled class name.
    pub name: String,
    /// Raw mangled name (e.g., "5Shape" or "N9namespace5ClassE").
    pub mangled_name: String,
    /// Kind of type info (determines inheritance structure).
    pub kind: TypeInfoKind,
    /// Address of the typeinfo vtable.
    pub vtable_addr: u64,
}

/// The kind of RTTI type info structure.
#[derive(Debug, Clone)]
pub enum TypeInfoKind {
    /// `__class_type_info` - Class with no bases.
    NoBase,

    /// `__si_class_type_info` - Single inheritance.
    SingleInheritance {
        /// Address of base class typeinfo.
        base_typeinfo_addr: u64,
        /// Name of base class (if resolved).
        base_name: Option<String>,
    },

    /// `__vmi_class_type_info` - Virtual/multiple inheritance.
    VirtualMultipleInheritance {
        /// Flags describing the inheritance.
        flags: VmiFlags,
        /// Base class information.
        bases: Vec<BaseClassInfo>,
    },

    /// Unknown typeinfo format.
    Unknown,
}

/// Flags for `__vmi_class_type_info`.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmiFlags {
    /// Class has non-diamond repeated inheritance.
    pub non_diamond_repeat_mask: bool,
    /// Class is diamond-shaped (base repeated via virtual).
    pub diamond_shaped_mask: bool,
    /// Raw flags value.
    pub raw: u32,
}

impl VmiFlags {
    /// Non-diamond repeat inheritance flag.
    pub const NON_DIAMOND_REPEAT: u32 = 0x1;
    /// Diamond-shaped inheritance flag.
    pub const DIAMOND_SHAPED: u32 = 0x2;

    /// Parse flags from raw value.
    pub fn from_raw(raw: u32) -> Self {
        Self {
            non_diamond_repeat_mask: (raw & Self::NON_DIAMOND_REPEAT) != 0,
            diamond_shaped_mask: (raw & Self::DIAMOND_SHAPED) != 0,
            raw,
        }
    }
}

/// Information about a base class in VMI inheritance.
#[derive(Debug, Clone)]
pub struct BaseClassInfo {
    /// Address of base class typeinfo.
    pub typeinfo_addr: u64,
    /// Name of the base class (if resolved).
    pub type_name: Option<String>,
    /// Offset to base within derived class.
    pub offset: i64,
    /// Flags for this base class.
    pub flags: BaseClassFlags,
}

/// Flags for a base class in VMI inheritance.
#[derive(Debug, Clone, Copy, Default)]
pub struct BaseClassFlags {
    /// Base class is virtual.
    pub is_virtual: bool,
    /// Base class is public.
    pub is_public: bool,
    /// Raw flags value.
    pub raw: u64,
}

impl BaseClassFlags {
    /// Virtual base class flag (low bit of offset_flags).
    pub const VIRTUAL: u64 = 0x1;
    /// Public base class flag.
    pub const PUBLIC: u64 = 0x2;
    /// Mask for offset portion of offset_flags.
    pub const OFFSET_SHIFT: u32 = 8;

    /// Parse flags from raw offset_flags value.
    pub fn from_offset_flags(offset_flags: i64) -> (Self, i64) {
        let raw = offset_flags as u64;
        let flags = Self {
            is_virtual: (raw & Self::VIRTUAL) != 0,
            is_public: (raw & Self::PUBLIC) != 0,
            raw,
        };
        // Offset is stored in upper bits, signed
        let offset = offset_flags >> Self::OFFSET_SHIFT;
        (flags, offset)
    }
}

/// RTTI parser for Itanium C++ ABI.
pub struct RttiParser {
    /// Pointer size in bytes.
    pointer_size: usize,
    /// Byte order.
    endianness: Endianness,
    /// Known typeinfo vtable addresses (for identifying typeinfo kind).
    known_typeinfo_vtables: HashMap<u64, TypeInfoVtableKind>,
    /// Cache of parsed typeinfos.
    cache: HashMap<u64, TypeInfo>,
}

/// The kind of typeinfo vtable (identifies the RTTI class type).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeInfoVtableKind {
    /// `__class_type_info` vtable.
    Class,
    /// `__si_class_type_info` vtable.
    SingleInheritance,
    /// `__vmi_class_type_info` vtable.
    VirtualMultipleInheritance,
}

impl RttiParser {
    /// Creates a new RTTI parser.
    pub fn new(pointer_size: usize, endianness: Endianness) -> Self {
        Self {
            pointer_size,
            endianness,
            known_typeinfo_vtables: HashMap::new(),
            cache: HashMap::new(),
        }
    }

    /// Register known typeinfo vtable addresses.
    ///
    /// This helps identify the kind of typeinfo structure based on its vtable.
    pub fn with_typeinfo_vtables(
        mut self,
        vtables: impl IntoIterator<Item = (u64, TypeInfoVtableKind)>,
    ) -> Self {
        self.known_typeinfo_vtables.extend(vtables);
        self
    }

    /// Reads a pointer from data at the given offset.
    fn read_pointer(&self, data: &[u8], offset: usize) -> Option<u64> {
        if offset + self.pointer_size > data.len() {
            return None;
        }

        let bytes = &data[offset..offset + self.pointer_size];
        match (self.pointer_size, self.endianness) {
            (4, Endianness::Little) => {
                Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64)
            }
            (4, Endianness::Big) => {
                Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64)
            }
            (8, Endianness::Little) => Some(u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5], bytes[6], bytes[7],
            ])),
            (8, Endianness::Big) => Some(u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5], bytes[6], bytes[7],
            ])),
            _ => None,
        }
    }

    /// Reads a u32 from data at the given offset.
    fn read_u32(&self, data: &[u8], offset: usize) -> Option<u32> {
        if offset + 4 > data.len() {
            return None;
        }
        let bytes = &data[offset..offset + 4];
        match self.endianness {
            Endianness::Little => Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
            Endianness::Big => Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
        }
    }

    /// Reads a null-terminated string from data.
    fn read_string(&self, data: &[u8], offset: usize) -> Option<String> {
        if offset >= data.len() {
            return None;
        }

        let mut end = offset;
        while end < data.len() && data[end] != 0 {
            end += 1;
        }

        if end > offset {
            std::str::from_utf8(&data[offset..end]).ok().map(String::from)
        } else {
            None
        }
    }

    /// Demangles a type name from Itanium encoding.
    ///
    /// Format: `<length><name>` for simple names, nested for namespaces.
    pub fn demangle_type_name(&self, mangled: &str) -> String {
        let mut chars = mangled.chars().peekable();
        let mut result = String::new();

        // Handle namespace prefix 'N' ... 'E'
        if chars.peek() == Some(&'N') {
            chars.next(); // consume 'N'

            while chars.peek().is_some() && chars.peek() != Some(&'E') {
                if let Some(component) = self.parse_name_component(&mut chars) {
                    if !result.is_empty() {
                        result.push_str("::");
                    }
                    result.push_str(&component);
                } else {
                    break;
                }
            }

            // Consume trailing 'E'
            if chars.peek() == Some(&'E') {
                chars.next();
            }
        } else {
            // Simple name: just length + name
            if let Some(component) = self.parse_name_component(&mut chars) {
                result = component;
            }
        }

        if result.is_empty() {
            mangled.to_string()
        } else {
            result
        }
    }

    /// Parses a single name component (length + chars).
    fn parse_name_component(&self, chars: &mut std::iter::Peekable<std::str::Chars>) -> Option<String> {
        // Read length digits
        let mut length_str = String::new();
        while let Some(&c) = chars.peek() {
            if c.is_ascii_digit() {
                length_str.push(chars.next().unwrap());
            } else {
                break;
            }
        }

        if length_str.is_empty() {
            return None;
        }

        let length: usize = length_str.parse().ok()?;
        let name: String = chars.take(length).collect();

        if name.len() == length {
            Some(name)
        } else {
            None
        }
    }

    /// Parses a typeinfo structure.
    ///
    /// # Arguments
    /// * `data` - The section data containing the typeinfo
    /// * `base_addr` - Virtual address of the section start
    /// * `typeinfo_addr` - Virtual address of the typeinfo structure
    pub fn parse_typeinfo(
        &mut self,
        data: &[u8],
        base_addr: u64,
        typeinfo_addr: u64,
    ) -> Option<TypeInfo> {
        // Check cache first
        if let Some(cached) = self.cache.get(&typeinfo_addr) {
            return Some(cached.clone());
        }

        let offset = typeinfo_addr.checked_sub(base_addr)? as usize;

        // Read vtable pointer
        let vtable_addr = self.read_pointer(data, offset)?;

        // Read name pointer
        let name_ptr = self.read_pointer(data, offset + self.pointer_size)?;

        // Read name string
        let name_offset = name_ptr.checked_sub(base_addr)? as usize;
        let mangled_name = self.read_string(data, name_offset)?;

        // Demangle the name
        let name = self.demangle_type_name(&mangled_name);

        // Determine the kind based on vtable or structure analysis
        let kind = self.determine_typeinfo_kind(data, base_addr, offset, vtable_addr);

        let type_info = TypeInfo {
            address: typeinfo_addr,
            name,
            mangled_name,
            kind,
            vtable_addr,
        };

        // Cache the result
        self.cache.insert(typeinfo_addr, type_info.clone());

        Some(type_info)
    }

    /// Determines the kind of typeinfo based on vtable or heuristics.
    fn determine_typeinfo_kind(
        &mut self,
        data: &[u8],
        base_addr: u64,
        offset: usize,
        vtable_addr: u64,
    ) -> TypeInfoKind {
        // Check if we know this vtable
        if let Some(&kind) = self.known_typeinfo_vtables.get(&vtable_addr) {
            return match kind {
                TypeInfoVtableKind::Class => TypeInfoKind::NoBase,
                TypeInfoVtableKind::SingleInheritance => {
                    self.parse_si_typeinfo(data, base_addr, offset)
                }
                TypeInfoVtableKind::VirtualMultipleInheritance => {
                    self.parse_vmi_typeinfo(data, base_addr, offset)
                }
            };
        }

        // Heuristic: try to determine kind by structure
        // If there's a third pointer that looks like a typeinfo, it's SI
        // If there are flags + count fields, it's VMI

        let third_offset = offset + 2 * self.pointer_size;

        // Try to read what could be a base typeinfo pointer (SI)
        if let Some(potential_base) = self.read_pointer(data, third_offset) {
            // Check if it looks like a valid typeinfo address
            if self.looks_like_typeinfo(data, base_addr, potential_base) {
                return self.parse_si_typeinfo(data, base_addr, offset);
            }
        }

        // Try to parse as VMI (flags + base_count)
        if let Some(flags) = self.read_u32(data, third_offset) {
            if let Some(base_count) = self.read_u32(data, third_offset + 4) {
                // Sanity check: base_count should be reasonable
                if base_count > 0 && base_count <= 100 && flags <= 3 {
                    return self.parse_vmi_typeinfo(data, base_addr, offset);
                }
            }
        }

        // Default to no base
        TypeInfoKind::NoBase
    }

    /// Checks if an address looks like a typeinfo structure.
    fn looks_like_typeinfo(&self, data: &[u8], base_addr: u64, addr: u64) -> bool {
        let offset = match addr.checked_sub(base_addr) {
            Some(o) if (o as usize) + 2 * self.pointer_size <= data.len() => o as usize,
            _ => return false,
        };

        // Check if it has a vtable pointer and name pointer
        let _vtable_ptr = match self.read_pointer(data, offset) {
            Some(p) if p != 0 => p,
            _ => return false,
        };

        let name_ptr = match self.read_pointer(data, offset + self.pointer_size) {
            Some(p) if p != 0 => p,
            _ => return false,
        };

        // Check if name pointer is in range and points to valid ASCII
        let name_offset = match name_ptr.checked_sub(base_addr) {
            Some(o) if (o as usize) < data.len() => o as usize,
            _ => return false,
        };

        // Name should start with a digit (length prefix) or 'N' (namespace)
        if name_offset < data.len() {
            let first_char = data[name_offset];
            return first_char.is_ascii_digit() || first_char == b'N';
        }

        false
    }

    /// Parses single-inheritance typeinfo.
    fn parse_si_typeinfo(&mut self, data: &[u8], base_addr: u64, offset: usize) -> TypeInfoKind {
        let base_ptr_offset = offset + 2 * self.pointer_size;

        let base_typeinfo_addr = match self.read_pointer(data, base_ptr_offset) {
            Some(addr) => addr,
            None => return TypeInfoKind::Unknown,
        };

        // Try to resolve base name
        let base_name = self
            .parse_typeinfo(data, base_addr, base_typeinfo_addr)
            .map(|ti| ti.name);

        TypeInfoKind::SingleInheritance {
            base_typeinfo_addr,
            base_name,
        }
    }

    /// Parses virtual/multiple inheritance typeinfo.
    fn parse_vmi_typeinfo(&mut self, data: &[u8], base_addr: u64, offset: usize) -> TypeInfoKind {
        let flags_offset = offset + 2 * self.pointer_size;
        let count_offset = flags_offset + 4;
        let bases_offset = count_offset + 4;

        let raw_flags = match self.read_u32(data, flags_offset) {
            Some(f) => f,
            None => return TypeInfoKind::Unknown,
        };

        let base_count = match self.read_u32(data, count_offset) {
            Some(c) => c,
            None => return TypeInfoKind::Unknown,
        };

        let flags = VmiFlags::from_raw(raw_flags);
        let mut bases = Vec::with_capacity(base_count as usize);

        // Each base is: typeinfo_ptr (ptr_size) + offset_flags (ptr_size or long)
        let base_entry_size = 2 * self.pointer_size;

        for i in 0..base_count as usize {
            let entry_offset = bases_offset + i * base_entry_size;

            let typeinfo_addr = match self.read_pointer(data, entry_offset) {
                Some(addr) => addr,
                None => break,
            };

            let offset_flags = match self.read_pointer(data, entry_offset + self.pointer_size) {
                Some(of) => of as i64,
                None => break,
            };

            let (base_flags, offset) = BaseClassFlags::from_offset_flags(offset_flags);

            // Try to resolve base name
            let type_name = self
                .parse_typeinfo(data, base_addr, typeinfo_addr)
                .map(|ti| ti.name);

            bases.push(BaseClassInfo {
                typeinfo_addr,
                type_name,
                offset,
                flags: base_flags,
            });
        }

        TypeInfoKind::VirtualMultipleInheritance { flags, bases }
    }

    /// Clears the typeinfo cache.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
}

/// Class hierarchy built from RTTI.
#[derive(Debug, Default)]
pub struct ClassHierarchy {
    /// All known classes by address.
    classes: HashMap<u64, TypeInfo>,
    /// Class name to addresses (handles multiple typeinfos with same name).
    by_name: HashMap<String, Vec<u64>>,
    /// Direct base classes: derived address -> [(base addr, offset, is_virtual)].
    direct_bases: HashMap<u64, Vec<(u64, i64, bool)>>,
    /// Direct derived classes: base address -> [derived addrs].
    direct_derived: HashMap<u64, Vec<u64>>,
}

impl ClassHierarchy {
    /// Creates a new empty class hierarchy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a typeinfo to the hierarchy.
    pub fn add(&mut self, type_info: TypeInfo) {
        let addr = type_info.address;

        // Index by name
        self.by_name
            .entry(type_info.name.clone())
            .or_default()
            .push(addr);

        // Extract base relationships
        match &type_info.kind {
            TypeInfoKind::SingleInheritance { base_typeinfo_addr, .. } => {
                self.direct_bases.entry(addr).or_default().push((
                    *base_typeinfo_addr,
                    0, // offset is 0 for SI
                    false,
                ));
                self.direct_derived.entry(*base_typeinfo_addr).or_default().push(addr);
            }
            TypeInfoKind::VirtualMultipleInheritance { bases, .. } => {
                for base in bases {
                    self.direct_bases.entry(addr).or_default().push((
                        base.typeinfo_addr,
                        base.offset,
                        base.flags.is_virtual,
                    ));
                    self.direct_derived.entry(base.typeinfo_addr).or_default().push(addr);
                }
            }
            _ => {}
        }

        self.classes.insert(addr, type_info);
    }

    /// Gets a class by its typeinfo address.
    pub fn get(&self, addr: u64) -> Option<&TypeInfo> {
        self.classes.get(&addr)
    }

    /// Gets classes by name.
    pub fn get_by_name(&self, name: &str) -> Vec<&TypeInfo> {
        self.by_name
            .get(name)
            .map(|addrs| addrs.iter().filter_map(|a| self.classes.get(a)).collect())
            .unwrap_or_default()
    }

    /// Gets direct base classes of a class.
    pub fn direct_bases(&self, addr: u64) -> Vec<(&TypeInfo, i64, bool)> {
        self.direct_bases
            .get(&addr)
            .map(|bases| {
                bases
                    .iter()
                    .filter_map(|(base_addr, offset, is_virtual)| {
                        self.classes.get(base_addr).map(|ti| (ti, *offset, *is_virtual))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Gets all base classes (transitive closure).
    pub fn all_bases(&self, addr: u64) -> Vec<&TypeInfo> {
        let mut visited = HashSet::new();
        let mut result = Vec::new();
        self.collect_bases(addr, &mut visited, &mut result);
        result
    }

    fn collect_bases<'a>(
        &'a self,
        addr: u64,
        visited: &mut HashSet<u64>,
        result: &mut Vec<&'a TypeInfo>,
    ) {
        if let Some(bases) = self.direct_bases.get(&addr) {
            for (base_addr, _, _) in bases {
                if visited.insert(*base_addr) {
                    if let Some(ti) = self.classes.get(base_addr) {
                        result.push(ti);
                        self.collect_bases(*base_addr, visited, result);
                    }
                }
            }
        }
    }

    /// Gets direct derived classes.
    pub fn direct_derived(&self, addr: u64) -> Vec<&TypeInfo> {
        self.direct_derived
            .get(&addr)
            .map(|derived| {
                derived
                    .iter()
                    .filter_map(|d| self.classes.get(d))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Gets all derived classes (transitive closure).
    pub fn all_derived(&self, addr: u64) -> Vec<&TypeInfo> {
        let mut visited = HashSet::new();
        let mut result = Vec::new();
        self.collect_derived(addr, &mut visited, &mut result);
        result
    }

    fn collect_derived<'a>(
        &'a self,
        addr: u64,
        visited: &mut HashSet<u64>,
        result: &mut Vec<&'a TypeInfo>,
    ) {
        if let Some(derived) = self.direct_derived.get(&addr) {
            for derived_addr in derived {
                if visited.insert(*derived_addr) {
                    if let Some(ti) = self.classes.get(derived_addr) {
                        result.push(ti);
                        self.collect_derived(*derived_addr, visited, result);
                    }
                }
            }
        }
    }

    /// Returns all classes.
    pub fn all_classes(&self) -> impl Iterator<Item = &TypeInfo> {
        self.classes.values()
    }

    /// Returns the number of classes.
    pub fn len(&self) -> usize {
        self.classes.len()
    }

    /// Returns true if empty.
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty()
    }

    /// Checks if a class is derived from another (directly or indirectly).
    pub fn is_derived_from(&self, derived_addr: u64, base_addr: u64) -> bool {
        if derived_addr == base_addr {
            return false;
        }

        let mut visited = HashSet::new();
        self.is_derived_from_recursive(derived_addr, base_addr, &mut visited)
    }

    fn is_derived_from_recursive(
        &self,
        derived_addr: u64,
        base_addr: u64,
        visited: &mut HashSet<u64>,
    ) -> bool {
        if !visited.insert(derived_addr) {
            return false;
        }

        if let Some(bases) = self.direct_bases.get(&derived_addr) {
            for (direct_base_addr, _, _) in bases {
                if *direct_base_addr == base_addr {
                    return true;
                }
                if self.is_derived_from_recursive(*direct_base_addr, base_addr, visited) {
                    return true;
                }
            }
        }

        false
    }
}

/// RTTI database combining parsed typeinfos with vtable information.
#[derive(Debug, Default)]
pub struct RttiDatabase {
    /// Class hierarchy from RTTI.
    pub hierarchy: ClassHierarchy,
    /// Vtable address to typeinfo address mapping.
    vtable_to_typeinfo: HashMap<u64, u64>,
    /// Typeinfo address to vtable address mapping.
    typeinfo_to_vtable: HashMap<u64, u64>,
}

impl RttiDatabase {
    /// Creates a new empty RTTI database.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a typeinfo with its associated vtable.
    pub fn add(&mut self, type_info: TypeInfo, vtable_addr: Option<u64>) {
        let ti_addr = type_info.address;

        if let Some(vt_addr) = vtable_addr {
            self.vtable_to_typeinfo.insert(vt_addr, ti_addr);
            self.typeinfo_to_vtable.insert(ti_addr, vt_addr);
        }

        self.hierarchy.add(type_info);
    }

    /// Gets class name for a vtable.
    pub fn class_name_for_vtable(&self, vtable_addr: u64) -> Option<&str> {
        let ti_addr = self.vtable_to_typeinfo.get(&vtable_addr)?;
        self.hierarchy.get(*ti_addr).map(|ti| ti.name.as_str())
    }

    /// Gets typeinfo for a vtable.
    pub fn typeinfo_for_vtable(&self, vtable_addr: u64) -> Option<&TypeInfo> {
        let ti_addr = self.vtable_to_typeinfo.get(&vtable_addr)?;
        self.hierarchy.get(*ti_addr)
    }

    /// Gets vtable for a typeinfo.
    pub fn vtable_for_typeinfo(&self, typeinfo_addr: u64) -> Option<u64> {
        self.typeinfo_to_vtable.get(&typeinfo_addr).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_demangle_simple_name() {
        let parser = RttiParser::new(8, Endianness::Little);

        assert_eq!(parser.demangle_type_name("5Shape"), "Shape");
        assert_eq!(parser.demangle_type_name("6Circle"), "Circle");
        assert_eq!(parser.demangle_type_name("10MyLongName"), "MyLongName");
    }

    #[test]
    fn test_demangle_namespace() {
        let parser = RttiParser::new(8, Endianness::Little);

        // N<len><name><len><name>E
        assert_eq!(parser.demangle_type_name("N3std6vectorE"), "std::vector");
        assert_eq!(parser.demangle_type_name("N9namespace5ClassE"), "namespace::Class");
    }

    #[test]
    fn test_vmi_flags() {
        let flags = VmiFlags::from_raw(0);
        assert!(!flags.non_diamond_repeat_mask);
        assert!(!flags.diamond_shaped_mask);

        let flags = VmiFlags::from_raw(VmiFlags::NON_DIAMOND_REPEAT);
        assert!(flags.non_diamond_repeat_mask);
        assert!(!flags.diamond_shaped_mask);

        let flags = VmiFlags::from_raw(VmiFlags::DIAMOND_SHAPED);
        assert!(!flags.non_diamond_repeat_mask);
        assert!(flags.diamond_shaped_mask);

        let flags = VmiFlags::from_raw(VmiFlags::NON_DIAMOND_REPEAT | VmiFlags::DIAMOND_SHAPED);
        assert!(flags.non_diamond_repeat_mask);
        assert!(flags.diamond_shaped_mask);
    }

    #[test]
    fn test_base_class_flags() {
        // Virtual base at offset 16
        let offset_flags: i64 = (16 << 8) | 1;
        let (flags, offset) = BaseClassFlags::from_offset_flags(offset_flags);
        assert!(flags.is_virtual);
        assert!(!flags.is_public);
        assert_eq!(offset, 16);

        // Public non-virtual base at offset 0
        let offset_flags: i64 = 2;
        let (flags, offset) = BaseClassFlags::from_offset_flags(offset_flags);
        assert!(!flags.is_virtual);
        assert!(flags.is_public);
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_class_hierarchy() {
        let mut hierarchy = ClassHierarchy::new();

        // Create a simple hierarchy: Circle -> Shape
        let shape = TypeInfo {
            address: 0x1000,
            name: "Shape".to_string(),
            mangled_name: "5Shape".to_string(),
            kind: TypeInfoKind::NoBase,
            vtable_addr: 0x2000,
        };

        let circle = TypeInfo {
            address: 0x1100,
            name: "Circle".to_string(),
            mangled_name: "6Circle".to_string(),
            kind: TypeInfoKind::SingleInheritance {
                base_typeinfo_addr: 0x1000,
                base_name: Some("Shape".to_string()),
            },
            vtable_addr: 0x2100,
        };

        hierarchy.add(shape);
        hierarchy.add(circle);

        // Test lookups
        assert!(hierarchy.get(0x1000).is_some());
        assert_eq!(hierarchy.get(0x1000).unwrap().name, "Shape");

        // Test base/derived relationships
        let bases = hierarchy.direct_bases(0x1100);
        assert_eq!(bases.len(), 1);
        assert_eq!(bases[0].0.name, "Shape");

        let derived = hierarchy.direct_derived(0x1000);
        assert_eq!(derived.len(), 1);
        assert_eq!(derived[0].name, "Circle");

        // Test is_derived_from
        assert!(hierarchy.is_derived_from(0x1100, 0x1000));
        assert!(!hierarchy.is_derived_from(0x1000, 0x1100));
    }

    #[test]
    fn test_multiple_inheritance_hierarchy() {
        let mut hierarchy = ClassHierarchy::new();

        // Drawable and Serializable as bases
        // Shape derives from both

        let drawable = TypeInfo {
            address: 0x1000,
            name: "Drawable".to_string(),
            mangled_name: "8Drawable".to_string(),
            kind: TypeInfoKind::NoBase,
            vtable_addr: 0x2000,
        };

        let serializable = TypeInfo {
            address: 0x1100,
            name: "Serializable".to_string(),
            mangled_name: "12Serializable".to_string(),
            kind: TypeInfoKind::NoBase,
            vtable_addr: 0x2100,
        };

        let shape = TypeInfo {
            address: 0x1200,
            name: "Shape".to_string(),
            mangled_name: "5Shape".to_string(),
            kind: TypeInfoKind::VirtualMultipleInheritance {
                flags: VmiFlags::default(),
                bases: vec![
                    BaseClassInfo {
                        typeinfo_addr: 0x1000,
                        type_name: Some("Drawable".to_string()),
                        offset: 0,
                        flags: BaseClassFlags::default(),
                    },
                    BaseClassInfo {
                        typeinfo_addr: 0x1100,
                        type_name: Some("Serializable".to_string()),
                        offset: 8,
                        flags: BaseClassFlags::default(),
                    },
                ],
            },
            vtable_addr: 0x2200,
        };

        hierarchy.add(drawable);
        hierarchy.add(serializable);
        hierarchy.add(shape);

        // Shape should have 2 direct bases
        let bases = hierarchy.direct_bases(0x1200);
        assert_eq!(bases.len(), 2);

        // Both Drawable and Serializable should have Shape as derived
        let drawable_derived = hierarchy.direct_derived(0x1000);
        assert_eq!(drawable_derived.len(), 1);
        assert_eq!(drawable_derived[0].name, "Shape");

        let serializable_derived = hierarchy.direct_derived(0x1100);
        assert_eq!(serializable_derived.len(), 1);
        assert_eq!(serializable_derived[0].name, "Shape");
    }
}
