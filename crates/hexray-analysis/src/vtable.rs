//! Virtual function table (vtable) detection and analysis.
//!
//! This module provides detection of C++ virtual function tables in binary data.
//! Vtables are arrays of function pointers used for polymorphism:
//!
//! - Located in read-only data sections (.rodata, __const, .rdata)
//! - Contain consecutive valid function pointers
//! - Referenced by object constructors (to set the vtable pointer)
//! - May have RTTI (type info) pointer at offset -8 (Itanium C++ ABI)
//!
//! # Example
//!
//! ```ignore
//! use hexray_analysis::vtable::VtableDetector;
//! use hexray_formats::{BinaryFormat, Section};
//!
//! let detector = VtableDetector::new(8, Endianness::Little);
//! let vtables = detector.detect_in_binary(&binary);
//!
//! for vtable in &vtables {
//!     println!("Vtable at 0x{:x} with {} entries", vtable.address, vtable.entries.len());
//!     if let Some(name) = &vtable.class_name {
//!         println!("  Class: {}", name);
//!     }
//! }
//! ```

use std::collections::{HashMap, HashSet};

use hexray_core::Endianness;

/// Information about a virtual function thunk.
///
/// Thunks are generated for multiple inheritance when a virtual call through
/// a secondary base pointer needs to adjust `this` before calling the actual
/// implementation.
#[derive(Debug, Clone)]
pub struct ThunkInfo {
    /// The `this` pointer adjustment (typically negative for secondary bases).
    pub this_adjustment: i64,
    /// The address of the actual implementation function.
    pub target_function: u64,
    /// Whether this thunk also has a virtual base adjustment (more complex MI).
    pub has_vcall_adjustment: bool,
}

impl ThunkInfo {
    /// Creates a new thunk info with a simple this-adjustment.
    pub fn new(this_adjustment: i64, target_function: u64) -> Self {
        Self {
            this_adjustment,
            target_function,
            has_vcall_adjustment: false,
        }
    }
}

/// A virtual function table entry.
#[derive(Debug, Clone)]
pub struct VtableEntry {
    /// Offset within the vtable (in bytes).
    pub offset: usize,
    /// Target function address.
    pub target: u64,
    /// Demangled method name, if available.
    pub name: Option<String>,
    /// Whether this is a pure virtual placeholder (e.g., __cxa_pure_virtual).
    pub is_pure_virtual: bool,
    /// Thunk information if this entry points to a thunk rather than direct impl.
    pub thunk: Option<ThunkInfo>,
}

impl VtableEntry {
    /// Creates a new vtable entry.
    pub fn new(offset: usize, target: u64) -> Self {
        Self {
            offset,
            target,
            name: None,
            is_pure_virtual: false,
            thunk: None,
        }
    }

    /// Sets the method name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Marks this entry as a pure virtual function.
    pub fn with_pure_virtual(mut self, is_pure: bool) -> Self {
        self.is_pure_virtual = is_pure;
        self
    }

    /// Returns the virtual method index (0-based).
    pub fn index(&self, pointer_size: usize) -> usize {
        self.offset / pointer_size
    }

    /// Sets thunk information for this entry.
    pub fn with_thunk(mut self, thunk: ThunkInfo) -> Self {
        self.thunk = Some(thunk);
        self
    }

    /// Returns true if this entry is a thunk.
    pub fn is_thunk(&self) -> bool {
        self.thunk.is_some()
    }

    /// Returns the actual implementation address (resolving through thunk if present).
    pub fn resolved_target(&self) -> u64 {
        self.thunk
            .as_ref()
            .map(|t| t.target_function)
            .unwrap_or(self.target)
    }
}

/// A detected virtual function table.
#[derive(Debug, Clone)]
pub struct Vtable {
    /// Address of the vtable in memory.
    pub address: u64,
    /// Function pointer entries in the vtable.
    pub entries: Vec<VtableEntry>,
    /// Inferred class name (from RTTI or symbols).
    pub class_name: Option<String>,
    /// Address of the typeinfo structure (RTTI), if present.
    pub typeinfo_addr: Option<u64>,
    /// Addresses of constructors that reference this vtable.
    pub constructor_refs: Vec<u64>,
    /// Whether this appears to be a primary vtable (vs. secondary for MI).
    pub is_primary: bool,
    /// Confidence score (0.0 - 1.0) for this detection.
    pub confidence: f64,
    /// Offset-to-top value for this vtable (0 for primary, negative for secondary).
    /// In the Itanium ABI, this is stored at vtable_addr - 2*ptr_size.
    pub offset_to_top: Option<i64>,
    /// Address of the associated primary vtable (for secondary vtables).
    pub primary_vtable: Option<u64>,
    /// Name of the base class this secondary vtable belongs to (for MI).
    pub base_class_name: Option<String>,
}

impl Vtable {
    /// Creates a new vtable.
    pub fn new(address: u64) -> Self {
        Self {
            address,
            entries: Vec::new(),
            class_name: None,
            typeinfo_addr: None,
            constructor_refs: Vec::new(),
            is_primary: true,
            confidence: 0.0,
            offset_to_top: None,
            primary_vtable: None,
            base_class_name: None,
        }
    }

    /// Returns the size of this vtable in bytes.
    pub fn size(&self, pointer_size: usize) -> usize {
        self.entries.len() * pointer_size
    }

    /// Returns the number of virtual methods.
    pub fn method_count(&self) -> usize {
        self.entries.len()
    }

    /// Gets an entry by index.
    pub fn get_entry(&self, index: usize) -> Option<&VtableEntry> {
        self.entries.get(index)
    }

    /// Gets the function address at a given index.
    pub fn get_function(&self, index: usize) -> Option<u64> {
        self.entries.get(index).map(|e| e.target)
    }

    /// Returns whether this vtable has RTTI information.
    pub fn has_rtti(&self) -> bool {
        self.typeinfo_addr.is_some()
    }

    /// Adds a constructor reference.
    pub fn add_constructor_ref(&mut self, addr: u64) {
        if !self.constructor_refs.contains(&addr) {
            self.constructor_refs.push(addr);
        }
    }
}

/// Configuration for vtable detection.
#[derive(Debug, Clone)]
pub struct VtableConfig {
    /// Minimum number of entries to consider a valid vtable.
    pub min_entries: usize,
    /// Maximum number of entries (to avoid false positives).
    pub max_entries: usize,
    /// Whether to require pointer alignment.
    pub require_alignment: bool,
    /// Whether to look for RTTI markers.
    pub detect_rtti: bool,
    /// Whether to allow gaps (null pointers) in vtables.
    pub allow_gaps: bool,
    /// Maximum gap size allowed (in entries).
    pub max_gap_size: usize,
    /// Minimum confidence threshold for reporting.
    pub min_confidence: f64,
}

impl Default for VtableConfig {
    fn default() -> Self {
        Self {
            min_entries: 2,
            max_entries: 1000,
            require_alignment: true,
            detect_rtti: true,
            allow_gaps: false,
            max_gap_size: 1,
            min_confidence: 0.3,
        }
    }
}

/// Virtual function table detector.
///
/// Scans binary data sections for vtable candidates and validates them
/// against executable code regions.
pub struct VtableDetector {
    /// Pointer size in bytes (4 for 32-bit, 8 for 64-bit).
    pointer_size: usize,
    /// Byte order for reading pointers.
    endianness: Endianness,
    /// Detection configuration.
    config: VtableConfig,
    /// Known function addresses (for validation).
    known_functions: HashSet<u64>,
    /// Executable address ranges [(start, end), ...].
    executable_ranges: Vec<(u64, u64)>,
    /// Symbol lookup table (address -> name).
    symbols: HashMap<u64, String>,
    /// Pure virtual function addresses.
    pure_virtual_addrs: HashSet<u64>,
}

impl VtableDetector {
    /// Creates a new vtable detector.
    pub fn new(pointer_size: usize, endianness: Endianness) -> Self {
        Self {
            pointer_size,
            endianness,
            config: VtableConfig::default(),
            known_functions: HashSet::new(),
            executable_ranges: Vec::new(),
            symbols: HashMap::new(),
            pure_virtual_addrs: HashSet::new(),
        }
    }

    /// Sets the detection configuration.
    pub fn with_config(mut self, config: VtableConfig) -> Self {
        self.config = config;
        self
    }

    /// Adds known function addresses for validation.
    pub fn with_known_functions(mut self, functions: impl IntoIterator<Item = u64>) -> Self {
        self.known_functions.extend(functions);
        self
    }

    /// Adds executable memory ranges.
    pub fn with_executable_ranges(mut self, ranges: impl IntoIterator<Item = (u64, u64)>) -> Self {
        self.executable_ranges.extend(ranges);
        self
    }

    /// Adds symbol lookup information.
    pub fn with_symbols(mut self, symbols: impl IntoIterator<Item = (u64, String)>) -> Self {
        self.symbols.extend(symbols);
        self
    }

    /// Adds pure virtual function addresses (like __cxa_pure_virtual).
    pub fn with_pure_virtual_addrs(mut self, addrs: impl IntoIterator<Item = u64>) -> Self {
        self.pure_virtual_addrs.extend(addrs);
        self
    }

    /// Returns the pointer size.
    pub fn pointer_size(&self) -> usize {
        self.pointer_size
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
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ])),
            (8, Endianness::Big) => Some(u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ])),
            _ => None,
        }
    }

    /// Reads a pointer-sized signed value from data at the given offset.
    fn read_signed_pointer(&self, data: &[u8], offset: usize) -> Option<i64> {
        if offset + self.pointer_size > data.len() {
            return None;
        }

        let bytes = &data[offset..offset + self.pointer_size];
        match (self.pointer_size, self.endianness) {
            (4, Endianness::Little) => {
                Some(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64)
            }
            (4, Endianness::Big) => {
                Some(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64)
            }
            (8, Endianness::Little) => Some(i64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ])),
            (8, Endianness::Big) => Some(i64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ])),
            _ => None,
        }
    }

    /// Checks if an address is within an executable region.
    fn is_executable(&self, addr: u64) -> bool {
        // If we don't have explicit ranges, be more permissive
        if self.executable_ranges.is_empty() {
            // Heuristic: addresses above 0x1000 and below typical kernel space
            return addr >= 0x1000 && (self.pointer_size == 4 || addr < 0x7fff_ffff_ffff_ffff);
        }

        self.executable_ranges
            .iter()
            .any(|(start, end)| addr >= *start && addr < *end)
    }

    /// Checks if an address looks like a valid function pointer.
    fn is_valid_function_pointer(&self, addr: u64) -> bool {
        // Check if it's in known functions
        if self.known_functions.contains(&addr) {
            return true;
        }

        // Check if it's a pure virtual placeholder
        if self.pure_virtual_addrs.contains(&addr) {
            return true;
        }

        // Check if it's in executable memory
        self.is_executable(addr)
    }

    /// Attempts to extract RTTI class name from typeinfo.
    fn extract_rtti_class_name(
        &self,
        data: &[u8],
        base_addr: u64,
        typeinfo_addr: u64,
    ) -> Option<String> {
        // The typeinfo structure (Itanium C++ ABI) layout:
        //   +0: vtable pointer (for type_info class itself)
        //   +ptr_size: pointer to name string (null-terminated)
        //
        // The name is mangled in the form "_ZTS<mangled_name>" or just the raw type name

        // Calculate offset within data
        let offset = typeinfo_addr.checked_sub(base_addr)? as usize;

        // Skip the vtable pointer, read the name pointer
        let name_ptr_offset = offset + self.pointer_size;
        let name_ptr = self.read_pointer(data, name_ptr_offset)?;

        // Read the name string from the name pointer
        let name_offset = name_ptr.checked_sub(base_addr)? as usize;
        if name_offset >= data.len() {
            return None;
        }

        // Read null-terminated string
        let name_start = name_offset;
        let mut name_end = name_start;
        while name_end < data.len() && data[name_end] != 0 {
            name_end += 1;
        }

        if name_end > name_start {
            let name_bytes = &data[name_start..name_end];
            if let Ok(name) = std::str::from_utf8(name_bytes) {
                // Try to demangle if it starts with mangling prefix
                if let Some(stripped) = name.strip_prefix("_ZTS") {
                    // Extract the class name from _ZTS prefix
                    return Some(self.demangle_type_name(stripped));
                }
                return Some(name.to_string());
            }
        }

        None
    }

    /// Attempts to demangle a type name.
    fn demangle_type_name(&self, mangled: &str) -> String {
        // Very basic Itanium demangling for type names
        // Format: <length><name> for simple names
        let mut chars = mangled.chars().peekable();
        let mut result = String::new();

        while let Some(&c) = chars.peek() {
            if c.is_ascii_digit() {
                // Read length
                let mut length_str = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_ascii_digit() {
                        length_str.push(chars.next().unwrap());
                    } else {
                        break;
                    }
                }

                if let Ok(length) = length_str.parse::<usize>() {
                    // Read name of that length
                    let name: String = chars.by_ref().take(length).collect();
                    if !result.is_empty() {
                        result.push_str("::");
                    }
                    result.push_str(&name);
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        if result.is_empty() {
            mangled.to_string()
        } else {
            result
        }
    }

    /// Scans a data section for vtable candidates.
    ///
    /// # Arguments
    /// * `data` - The section data bytes
    /// * `base_addr` - Virtual address of the start of the section
    ///
    /// # Returns
    /// A vector of detected vtables
    pub fn scan_section(&self, data: &[u8], base_addr: u64) -> Vec<Vtable> {
        let mut vtables = Vec::new();
        let mut i = 0;

        // Align to pointer boundary
        if self.config.require_alignment {
            let align_offset = base_addr as usize % self.pointer_size;
            if align_offset != 0 {
                i = self.pointer_size - align_offset;
            }
        }

        while i + self.pointer_size <= data.len() {
            if let Some(vtable) = self.try_detect_vtable_at(data, base_addr, i) {
                if vtable.confidence >= self.config.min_confidence {
                    // Skip past this vtable
                    let vtable_size = vtable.entries.len() * self.pointer_size;
                    i += vtable_size.max(self.pointer_size);
                    vtables.push(vtable);
                    continue;
                }
            }
            i += self.pointer_size;
        }

        vtables
    }

    /// Tries to detect a vtable starting at a specific offset.
    fn try_detect_vtable_at(&self, data: &[u8], base_addr: u64, offset: usize) -> Option<Vtable> {
        let vtable_addr = base_addr + offset as u64;
        let mut entries = Vec::new();
        let mut current_offset = offset;
        let mut gap_count = 0;

        // Check for RTTI at offset -ptr_size (before vtable start)
        // Itanium C++ ABI layout before vtable:
        //   -2*ptr_size: offset-to-top (signed, displacement to top of object)
        //   -1*ptr_size: typeinfo pointer
        //   0: first virtual function pointer
        let typeinfo_addr = if self.config.detect_rtti && offset >= self.pointer_size {
            let rtti_offset = offset - self.pointer_size;
            self.read_pointer(data, rtti_offset)
                .filter(|&ptr| ptr != 0 && !self.is_executable(ptr))
        } else {
            None
        };

        // Read offset-to-top at -2*ptr_size (Itanium ABI)
        // This is 0 for primary vtables, negative for secondary vtables in MI
        let offset_to_top = if offset >= 2 * self.pointer_size {
            let ott_offset = offset - 2 * self.pointer_size;
            self.read_signed_pointer(data, ott_offset)
        } else {
            None
        };

        // Scan for consecutive function pointers
        while current_offset + self.pointer_size <= data.len() {
            if let Some(ptr) = self.read_pointer(data, current_offset) {
                if ptr == 0 {
                    // Null pointer - could be a gap or end of vtable
                    if self.config.allow_gaps && gap_count < self.config.max_gap_size {
                        gap_count += 1;
                        entries.push(VtableEntry::new(current_offset - offset, ptr));
                        current_offset += self.pointer_size;
                        continue;
                    } else {
                        break;
                    }
                }

                if self.is_valid_function_pointer(ptr) {
                    gap_count = 0; // Reset gap count on valid pointer

                    let mut entry = VtableEntry::new(current_offset - offset, ptr);

                    // Check if this is a pure virtual function
                    if self.pure_virtual_addrs.contains(&ptr) {
                        entry = entry.with_pure_virtual(true);
                    }

                    // Look up symbol name
                    if let Some(name) = self.symbols.get(&ptr) {
                        entry = entry.with_name(name.clone());
                    }

                    entries.push(entry);
                    current_offset += self.pointer_size;

                    // Limit max entries
                    if entries.len() >= self.config.max_entries {
                        break;
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        // Check minimum entry count
        if entries.len() < self.config.min_entries {
            return None;
        }

        // Calculate confidence score
        let confidence = self.calculate_confidence(&entries, typeinfo_addr.is_some());

        // Try to get class name from RTTI
        let class_name = if let Some(ti_addr) = typeinfo_addr {
            self.extract_rtti_class_name(data, base_addr, ti_addr)
        } else {
            None
        };

        let mut vtable = Vtable::new(vtable_addr);
        vtable.entries = entries;
        vtable.typeinfo_addr = typeinfo_addr;
        vtable.class_name = class_name;
        vtable.confidence = confidence;
        vtable.offset_to_top = offset_to_top;

        // Determine if this is a primary or secondary vtable based on offset-to-top
        // Primary vtables have offset-to-top == 0, secondary have negative values
        if let Some(ott) = offset_to_top {
            vtable.is_primary = ott == 0;
        }

        Some(vtable)
    }

    /// Calculates a confidence score for a vtable candidate.
    fn calculate_confidence(&self, entries: &[VtableEntry], has_rtti: bool) -> f64 {
        let mut score = 0.0;

        // Base score from entry count
        let entry_count = entries.len();
        if entry_count >= 2 {
            score += 0.2;
        }
        if entry_count >= 4 {
            score += 0.1;
        }
        if entry_count >= 8 {
            score += 0.1;
        }

        // Bonus for RTTI
        if has_rtti {
            score += 0.3;
        }

        // Bonus for entries pointing to known functions
        let known_count = entries
            .iter()
            .filter(|e| self.known_functions.contains(&e.target))
            .count();
        if known_count > 0 {
            score += 0.2 * (known_count as f64 / entry_count as f64);
        }

        // Bonus for entries with symbols
        let named_count = entries.iter().filter(|e| e.name.is_some()).count();
        if named_count > 0 {
            score += 0.1 * (named_count as f64 / entry_count as f64);
        }

        // Penalty for pure virtual only (abstract class, less common)
        let pure_count = entries.iter().filter(|e| e.is_pure_virtual).count();
        if pure_count == entry_count && entry_count > 0 {
            score -= 0.1;
        }

        score.clamp(0.0, 1.0)
    }

    /// Detects vtables in multiple read-only data sections.
    ///
    /// This is a convenience method that scans common read-only section names.
    pub fn detect_in_sections<S: AsRef<[u8]>>(&self, sections: &[(String, u64, S)]) -> Vec<Vtable> {
        let rodata_names = [
            ".rodata",
            ".rdata",
            "__const",
            "__DATA.__const",
            ".data.rel.ro",
            ".data.rel.ro.local",
        ];

        let mut vtables = Vec::new();

        for (name, addr, data) in sections {
            // Check if this is a read-only data section
            let is_rodata = rodata_names.iter().any(|&n| name.contains(n) || name == n);

            if is_rodata {
                let detected = self.scan_section(data.as_ref(), *addr);
                vtables.extend(detected);
            }
        }

        // Sort by address
        vtables.sort_by_key(|v| v.address);

        vtables
    }

    /// Detects if a function at the given address is a thunk.
    ///
    /// Thunks are small functions that adjust the `this` pointer before jumping
    /// to the real implementation. Common patterns:
    ///
    /// x86_64:
    ///   - `add rdi, IMM; jmp TARGET`
    ///   - `sub rdi, IMM; jmp TARGET`
    ///   - `lea rdi, [rdi + IMM]; jmp TARGET`
    ///
    /// ARM64:
    ///   - `add x0, x0, #IMM; b TARGET`
    ///
    /// Returns `Some(ThunkInfo)` if a thunk pattern is detected, `None` otherwise.
    pub fn detect_thunk(&self, code: &[u8], func_addr: u64) -> Option<ThunkInfo> {
        if code.len() < 8 {
            return None;
        }

        // Check for x86_64 thunk patterns
        if self.pointer_size == 8 {
            // Pattern: REX.W + add rdi, imm8 (48 83 c7 XX) + jmp rel32 (e9 XX XX XX XX)
            if code.len() >= 9
                && code[0] == 0x48
                && code[1] == 0x83
                && code[2] == 0xc7
                && code[4] == 0xe9
            {
                let adjustment = code[3] as i8 as i64;
                let rel32 = i32::from_le_bytes([code[5], code[6], code[7], code[8]]) as i64;
                let target = func_addr.wrapping_add(9).wrapping_add(rel32 as u64);
                return Some(ThunkInfo::new(adjustment, target));
            }

            // Pattern: REX.W + sub rdi, imm8 (48 83 ef XX) + jmp rel32 (e9 XX XX XX XX)
            if code.len() >= 9
                && code[0] == 0x48
                && code[1] == 0x83
                && code[2] == 0xef
                && code[4] == 0xe9
            {
                let adjustment = -(code[3] as i8 as i64);
                let rel32 = i32::from_le_bytes([code[5], code[6], code[7], code[8]]) as i64;
                let target = func_addr.wrapping_add(9).wrapping_add(rel32 as u64);
                return Some(ThunkInfo::new(adjustment, target));
            }

            // Pattern: REX.W + add rdi, imm32 (48 81 c7 XX XX XX XX) + jmp rel32
            if code.len() >= 12
                && code[0] == 0x48
                && code[1] == 0x81
                && code[2] == 0xc7
                && code[7] == 0xe9
            {
                let adjustment = i32::from_le_bytes([code[3], code[4], code[5], code[6]]) as i64;
                let rel32 = i32::from_le_bytes([code[8], code[9], code[10], code[11]]) as i64;
                let target = func_addr.wrapping_add(12).wrapping_add(rel32 as u64);
                return Some(ThunkInfo::new(adjustment, target));
            }

            // Pattern: REX.W + lea rdi, [rdi + imm8] (48 8d 7f XX) + jmp rel32
            if code.len() >= 9
                && code[0] == 0x48
                && code[1] == 0x8d
                && code[2] == 0x7f
                && code[4] == 0xe9
            {
                let adjustment = code[3] as i8 as i64;
                let rel32 = i32::from_le_bytes([code[5], code[6], code[7], code[8]]) as i64;
                let target = func_addr.wrapping_add(9).wrapping_add(rel32 as u64);
                return Some(ThunkInfo::new(adjustment, target));
            }

            // Pattern: REX.W + lea rdi, [rdi + imm32] (48 8d bf XX XX XX XX) + jmp rel32
            if code.len() >= 12
                && code[0] == 0x48
                && code[1] == 0x8d
                && code[2] == 0xbf
                && code[7] == 0xe9
            {
                let adjustment = i32::from_le_bytes([code[3], code[4], code[5], code[6]]) as i64;
                let rel32 = i32::from_le_bytes([code[8], code[9], code[10], code[11]]) as i64;
                let target = func_addr.wrapping_add(12).wrapping_add(rel32 as u64);
                return Some(ThunkInfo::new(adjustment, target));
            }
        }

        // Check for ARM64 thunk patterns
        if self.pointer_size == 8 && self.endianness == Endianness::Little {
            // ARM64: add x0, x0, #imm12 followed by b target
            // ADD: 0x91000000 | (imm12 << 10) | (Rn << 5) | Rd
            // B:   0x14000000 | imm26
            if code.len() >= 8 {
                let insn1 = u32::from_le_bytes([code[0], code[1], code[2], code[3]]);
                let insn2 = u32::from_le_bytes([code[4], code[5], code[6], code[7]]);

                // Check for ADD x0, x0, #imm
                let is_add_x0 = (insn1 & 0xFFC003FF) == 0x91000000;
                // Check for B (unconditional branch)
                let is_branch = (insn2 & 0xFC000000) == 0x14000000;

                if is_add_x0 && is_branch {
                    let imm12 = ((insn1 >> 10) & 0xFFF) as i64;
                    // Check shift bit
                    let shift = if (insn1 & 0x400000) != 0 { 12 } else { 0 };
                    let adjustment = imm12 << shift;

                    // B target: PC + (imm26 << 2)
                    let imm26 = (insn2 & 0x03FFFFFF) as i32;
                    // Sign extend from 26 bits
                    let imm26 = if imm26 & 0x02000000 != 0 {
                        imm26 | !0x03FFFFFF_u32 as i32
                    } else {
                        imm26
                    };
                    let target = func_addr.wrapping_add(4).wrapping_add((imm26 << 2) as u64);

                    return Some(ThunkInfo::new(adjustment, target));
                }

                // Check for SUB x0, x0, #imm (negative adjustment)
                let is_sub_x0 = (insn1 & 0xFFC003FF) == 0xD1000000;
                if is_sub_x0 && is_branch {
                    let imm12 = ((insn1 >> 10) & 0xFFF) as i64;
                    let shift = if (insn1 & 0x400000) != 0 { 12 } else { 0 };
                    let adjustment = -(imm12 << shift);

                    let imm26 = (insn2 & 0x03FFFFFF) as i32;
                    let imm26 = if imm26 & 0x02000000 != 0 {
                        imm26 | !0x03FFFFFF_u32 as i32
                    } else {
                        imm26
                    };
                    let target = func_addr.wrapping_add(4).wrapping_add((imm26 << 2) as u64);

                    return Some(ThunkInfo::new(adjustment, target));
                }
            }
        }

        None
    }

    /// Analyzes vtable entries to detect and mark thunks.
    ///
    /// This requires access to the executable code sections to read function bytes.
    pub fn detect_thunks_in_vtable(&self, vtable: &mut Vtable, code_sections: &[(u64, &[u8])]) {
        for entry in &mut vtable.entries {
            if entry.is_pure_virtual {
                continue;
            }

            // Find the code section containing this function
            for &(section_addr, section_data) in code_sections {
                let section_end = section_addr + section_data.len() as u64;
                if entry.target >= section_addr && entry.target < section_end {
                    let offset = (entry.target - section_addr) as usize;
                    let remaining = &section_data[offset..];
                    if let Some(thunk_info) = self.detect_thunk(remaining, entry.target) {
                        entry.thunk = Some(thunk_info);
                    }
                    break;
                }
            }
        }
    }
}

/// Result of analyzing virtual calls in code.
#[derive(Debug, Clone)]
pub struct VirtualCallSite {
    /// Address of the call instruction.
    pub call_addr: u64,
    /// Base register used for vtable pointer (e.g., "rax").
    pub base_register: String,
    /// Offset into the vtable (determines which virtual method).
    pub vtable_offset: i64,
    /// Resolved vtable address, if known.
    pub vtable_addr: Option<u64>,
    /// Resolved target function, if known.
    pub target_func: Option<u64>,
}

/// Database of detected vtables for querying.
#[derive(Debug, Default)]
pub struct VtableDatabase {
    /// All detected vtables.
    vtables: Vec<Vtable>,
    /// Index: vtable address -> index in vtables vec.
    by_address: HashMap<u64, usize>,
    /// Index: function address -> vtables containing that function.
    by_function: HashMap<u64, Vec<usize>>,
    /// Index: class name -> vtable indices.
    by_class: HashMap<String, Vec<usize>>,
}

impl VtableDatabase {
    /// Creates a new empty vtable database.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a database from a list of vtables.
    pub fn from_vtables(vtables: Vec<Vtable>) -> Self {
        let mut db = Self::new();
        for vtable in vtables {
            db.add(vtable);
        }
        db
    }

    /// Adds a vtable to the database.
    pub fn add(&mut self, vtable: Vtable) {
        let index = self.vtables.len();

        // Index by address
        self.by_address.insert(vtable.address, index);

        // Index by functions
        for entry in &vtable.entries {
            self.by_function
                .entry(entry.target)
                .or_default()
                .push(index);
        }

        // Index by class name
        if let Some(ref name) = vtable.class_name {
            self.by_class.entry(name.clone()).or_default().push(index);
        }

        self.vtables.push(vtable);
    }

    /// Gets a vtable by its address.
    pub fn get_by_address(&self, addr: u64) -> Option<&Vtable> {
        self.by_address.get(&addr).map(|&i| &self.vtables[i])
    }

    /// Gets all vtables containing a specific function.
    pub fn get_by_function(&self, func_addr: u64) -> Vec<&Vtable> {
        self.by_function
            .get(&func_addr)
            .map(|indices| indices.iter().map(|&i| &self.vtables[i]).collect())
            .unwrap_or_default()
    }

    /// Gets all vtables for a class name.
    pub fn get_by_class(&self, name: &str) -> Vec<&Vtable> {
        self.by_class
            .get(name)
            .map(|indices| indices.iter().map(|&i| &self.vtables[i]).collect())
            .unwrap_or_default()
    }

    /// Returns all vtables.
    pub fn all(&self) -> &[Vtable] {
        &self.vtables
    }

    /// Returns the number of vtables.
    pub fn len(&self) -> usize {
        self.vtables.len()
    }

    /// Returns true if the database is empty.
    pub fn is_empty(&self) -> bool {
        self.vtables.is_empty()
    }

    /// Resolves a virtual call to its target function.
    ///
    /// Given a vtable address and an offset, returns the target function.
    pub fn resolve_virtual_call(&self, vtable_addr: u64, offset: usize) -> Option<u64> {
        let vtable = self.get_by_address(vtable_addr)?;
        let index = offset / std::mem::size_of::<u64>(); // Assuming 64-bit
        vtable.get_function(index)
    }

    /// Finds which classes implement a given virtual method.
    pub fn find_implementors(&self, method_addr: u64) -> Vec<(&Vtable, usize)> {
        let mut results = Vec::new();

        for vtable in &self.vtables {
            for (idx, entry) in vtable.entries.iter().enumerate() {
                if entry.target == method_addr {
                    results.push((vtable, idx));
                }
            }
        }

        results
    }

    /// Finds all unique virtual method addresses across all vtables.
    pub fn all_virtual_methods(&self) -> HashSet<u64> {
        let mut methods = HashSet::new();
        for vtable in &self.vtables {
            for entry in &vtable.entries {
                if entry.target != 0 {
                    methods.insert(entry.target);
                }
            }
        }
        methods
    }

    /// Identifies secondary vtables in the database.
    ///
    /// Secondary vtables are used for multiple inheritance in the Itanium C++ ABI.
    /// They share the same typeinfo pointer as the primary vtable but are located
    /// at different addresses (for base class subobjects).
    ///
    /// This function marks vtables as secondary if they share a typeinfo pointer
    /// with another vtable that appears earlier in memory (the primary).
    pub fn identify_secondary_vtables(&mut self) {
        // Group vtables by typeinfo address
        let mut by_typeinfo: HashMap<u64, Vec<usize>> = HashMap::new();

        for (idx, vtable) in self.vtables.iter().enumerate() {
            if let Some(ti_addr) = vtable.typeinfo_addr {
                by_typeinfo.entry(ti_addr).or_default().push(idx);
            }
        }

        // For each group with multiple vtables, mark all but the first as secondary
        for (_ti_addr, indices) in by_typeinfo {
            if indices.len() > 1 {
                // Sort by address to find the primary (lowest address is typically primary)
                let mut sorted_indices = indices.clone();
                sorted_indices.sort_by_key(|&idx| self.vtables[idx].address);

                let primary_idx = sorted_indices[0];
                let primary_addr = self.vtables[primary_idx].address;
                let primary_class_name = self.vtables[primary_idx].class_name.clone();

                // Mark the rest as secondary
                for &idx in &sorted_indices[1..] {
                    let vtable = &mut self.vtables[idx];
                    vtable.is_primary = false;
                    vtable.primary_vtable = Some(primary_addr);

                    // Copy class name from primary if not set
                    if vtable.class_name.is_none() {
                        if let Some(ref name) = primary_class_name {
                            vtable.class_name = Some(name.clone());
                        }
                    }
                }
            }
        }
    }

    /// Returns all primary vtables.
    pub fn primary_vtables(&self) -> impl Iterator<Item = &Vtable> {
        self.vtables.iter().filter(|v| v.is_primary)
    }

    /// Returns all secondary vtables.
    pub fn secondary_vtables(&self) -> impl Iterator<Item = &Vtable> {
        self.vtables.iter().filter(|v| !v.is_primary)
    }

    /// Gets the primary vtable for a secondary vtable.
    pub fn get_primary_for_secondary(&self, secondary_addr: u64) -> Option<&Vtable> {
        let secondary = self.get_by_address(secondary_addr)?;
        let primary_addr = secondary.primary_vtable?;
        self.get_by_address(primary_addr)
    }

    /// Gets all secondary vtables for a primary vtable.
    pub fn get_secondaries_for_primary(&self, primary_addr: u64) -> Vec<&Vtable> {
        self.vtables
            .iter()
            .filter(|v| v.primary_vtable == Some(primary_addr))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_detector() -> VtableDetector {
        VtableDetector::new(8, Endianness::Little)
            .with_executable_ranges([(0x1000, 0x10000)])
            .with_config(VtableConfig {
                min_entries: 2,
                min_confidence: 0.0, // Accept all for testing
                ..Default::default()
            })
    }

    #[test]
    fn test_read_pointer_le_64() {
        let detector = VtableDetector::new(8, Endianness::Little);
        let data = [0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(detector.read_pointer(&data, 0), Some(0x1000));
    }

    #[test]
    fn test_read_pointer_be_64() {
        let detector = VtableDetector::new(8, Endianness::Big);
        let data = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00];
        assert_eq!(detector.read_pointer(&data, 0), Some(0x1000));
    }

    #[test]
    fn test_read_pointer_le_32() {
        let detector = VtableDetector::new(4, Endianness::Little);
        let data = [0x00, 0x10, 0x00, 0x00];
        assert_eq!(detector.read_pointer(&data, 0), Some(0x1000));
    }

    #[test]
    fn test_detect_simple_vtable() {
        let detector = make_test_detector();

        // Create fake data with two valid function pointers
        let mut data = Vec::new();
        // Pointer 1: 0x2000 (in executable range)
        data.extend_from_slice(&0x2000u64.to_le_bytes());
        // Pointer 2: 0x3000 (in executable range)
        data.extend_from_slice(&0x3000u64.to_le_bytes());
        // Non-pointer value to end vtable
        data.extend_from_slice(&0x00u64.to_le_bytes());

        let vtables = detector.scan_section(&data, 0x100000);
        assert_eq!(vtables.len(), 1);
        assert_eq!(vtables[0].address, 0x100000);
        assert_eq!(vtables[0].entries.len(), 2);
        assert_eq!(vtables[0].entries[0].target, 0x2000);
        assert_eq!(vtables[0].entries[1].target, 0x3000);
    }

    #[test]
    fn test_vtable_with_known_functions() {
        let detector = make_test_detector().with_known_functions([0x2000, 0x3000, 0x4000]);

        // Create data with known functions
        let mut data = Vec::new();
        data.extend_from_slice(&0x2000u64.to_le_bytes());
        data.extend_from_slice(&0x3000u64.to_le_bytes());
        data.extend_from_slice(&0x4000u64.to_le_bytes());
        data.extend_from_slice(&0x00u64.to_le_bytes());

        let vtables = detector.scan_section(&data, 0x100000);
        assert_eq!(vtables.len(), 1);
        assert_eq!(vtables[0].entries.len(), 3);
        // Should have higher confidence due to known functions
        assert!(vtables[0].confidence > 0.3);
    }

    #[test]
    fn test_vtable_with_symbols() {
        let detector = make_test_detector().with_symbols([
            (0x2000, "MyClass::method1".to_string()),
            (0x3000, "MyClass::method2".to_string()),
        ]);

        let mut data = Vec::new();
        data.extend_from_slice(&0x2000u64.to_le_bytes());
        data.extend_from_slice(&0x3000u64.to_le_bytes());
        data.extend_from_slice(&0x00u64.to_le_bytes());

        let vtables = detector.scan_section(&data, 0x100000);
        assert_eq!(vtables.len(), 1);
        assert_eq!(
            vtables[0].entries[0].name.as_deref(),
            Some("MyClass::method1")
        );
        assert_eq!(
            vtables[0].entries[1].name.as_deref(),
            Some("MyClass::method2")
        );
    }

    #[test]
    fn test_vtable_entry_index() {
        let entry = VtableEntry::new(16, 0x2000);
        assert_eq!(entry.index(8), 2); // offset 16 / ptr_size 8 = index 2
        assert_eq!(entry.index(4), 4); // offset 16 / ptr_size 4 = index 4
    }

    #[test]
    fn test_vtable_database() {
        let mut vtable1 = Vtable::new(0x100000);
        vtable1.entries = vec![VtableEntry::new(0, 0x2000), VtableEntry::new(8, 0x3000)];
        vtable1.class_name = Some("ClassA".to_string());

        let mut vtable2 = Vtable::new(0x100020);
        vtable2.entries = vec![
            VtableEntry::new(0, 0x4000),
            VtableEntry::new(8, 0x3000), // Shared method
        ];
        vtable2.class_name = Some("ClassB".to_string());

        let db = VtableDatabase::from_vtables(vec![vtable1, vtable2]);

        // Test get_by_address
        assert!(db.get_by_address(0x100000).is_some());
        assert!(db.get_by_address(0x100020).is_some());
        assert!(db.get_by_address(0x999999).is_none());

        // Test get_by_function
        let vtables_with_3000 = db.get_by_function(0x3000);
        assert_eq!(vtables_with_3000.len(), 2);

        let vtables_with_2000 = db.get_by_function(0x2000);
        assert_eq!(vtables_with_2000.len(), 1);

        // Test get_by_class
        let class_a = db.get_by_class("ClassA");
        assert_eq!(class_a.len(), 1);
        assert_eq!(class_a[0].address, 0x100000);

        // Test all_virtual_methods
        let methods = db.all_virtual_methods();
        assert!(methods.contains(&0x2000));
        assert!(methods.contains(&0x3000));
        assert!(methods.contains(&0x4000));
    }

    #[test]
    fn test_demangle_simple_type_name() {
        let detector = make_test_detector();

        // Test simple class name: "5Shape" -> "Shape"
        assert_eq!(detector.demangle_type_name("5Shape"), "Shape");

        // Test nested name: "N9namespace5ClassE" approximation
        // Our simple demangler handles "9namespace5Class" -> "namespace::Class"
        assert_eq!(
            detector.demangle_type_name("9namespace5Class"),
            "namespace::Class"
        );
    }

    #[test]
    fn test_min_entries_filter() {
        let detector = VtableDetector::new(8, Endianness::Little)
            .with_executable_ranges([(0x1000, 0x10000)])
            .with_config(VtableConfig {
                min_entries: 3,
                min_confidence: 0.0,
                ..Default::default()
            });

        // Only 2 entries - should not be detected
        let mut data = Vec::new();
        data.extend_from_slice(&0x2000u64.to_le_bytes());
        data.extend_from_slice(&0x3000u64.to_le_bytes());
        data.extend_from_slice(&0x00u64.to_le_bytes());

        let vtables = detector.scan_section(&data, 0x100000);
        assert_eq!(vtables.len(), 0);
    }

    #[test]
    fn test_multiple_vtables_in_section() {
        let detector = make_test_detector();

        // Two vtables separated by null
        let mut data = Vec::new();
        // First vtable
        data.extend_from_slice(&0x2000u64.to_le_bytes());
        data.extend_from_slice(&0x3000u64.to_le_bytes());
        data.extend_from_slice(&0x00u64.to_le_bytes()); // End of first vtable
                                                        // Second vtable
        data.extend_from_slice(&0x4000u64.to_le_bytes());
        data.extend_from_slice(&0x5000u64.to_le_bytes());
        data.extend_from_slice(&0x00u64.to_le_bytes()); // End of second vtable

        let vtables = detector.scan_section(&data, 0x100000);
        assert_eq!(vtables.len(), 2);
        assert_eq!(vtables[0].address, 0x100000);
        assert_eq!(vtables[1].address, 0x100018); // 3 * 8 bytes after first
    }

    #[test]
    fn test_pure_virtual_detection() {
        let pure_virtual_addr = 0x9000u64;
        let detector = make_test_detector().with_pure_virtual_addrs([pure_virtual_addr]);

        let mut data = Vec::new();
        data.extend_from_slice(&0x2000u64.to_le_bytes());
        data.extend_from_slice(&pure_virtual_addr.to_le_bytes());
        data.extend_from_slice(&0x00u64.to_le_bytes());

        let vtables = detector.scan_section(&data, 0x100000);
        assert_eq!(vtables.len(), 1);
        assert!(!vtables[0].entries[0].is_pure_virtual);
        assert!(vtables[0].entries[1].is_pure_virtual);
    }

    #[test]
    fn test_vtable_size() {
        let mut vtable = Vtable::new(0x100000);
        vtable.entries = vec![
            VtableEntry::new(0, 0x2000),
            VtableEntry::new(8, 0x3000),
            VtableEntry::new(16, 0x4000),
        ];

        assert_eq!(vtable.size(8), 24); // 3 entries * 8 bytes
        assert_eq!(vtable.method_count(), 3);
    }

    #[test]
    fn test_find_implementors() {
        let mut vtable1 = Vtable::new(0x100000);
        vtable1.entries = vec![VtableEntry::new(0, 0x2000)];
        vtable1.class_name = Some("A".to_string());

        let mut vtable2 = Vtable::new(0x100010);
        vtable2.entries = vec![VtableEntry::new(0, 0x2000)]; // Same method
        vtable2.class_name = Some("B".to_string());

        let db = VtableDatabase::from_vtables(vec![vtable1, vtable2]);

        let implementors = db.find_implementors(0x2000);
        assert_eq!(implementors.len(), 2);
    }

    #[test]
    fn test_thunk_detection_x86_64_add() {
        let detector = make_test_detector();

        // x86_64 thunk: add rdi, -8; jmp 0x1000
        // 48 83 c7 f8  = add rdi, -8
        // e9 XX XX XX XX = jmp rel32
        let mut code = vec![0x48, 0x83, 0xc7, 0xf8]; // add rdi, -8
        code.push(0xe9); // jmp
        code.extend_from_slice(&(0x1000i32 - 9).to_le_bytes()); // target at 0x1000

        let thunk = detector.detect_thunk(&code, 0);
        assert!(thunk.is_some());
        let thunk = thunk.unwrap();
        assert_eq!(thunk.this_adjustment, -8);
        assert_eq!(thunk.target_function, 0x1000);
    }

    #[test]
    fn test_thunk_detection_x86_64_sub() {
        let detector = make_test_detector();

        // x86_64 thunk: sub rdi, 8; jmp 0x2000
        // 48 83 ef 08  = sub rdi, 8
        // e9 XX XX XX XX = jmp rel32
        let mut code = vec![0x48, 0x83, 0xef, 0x08]; // sub rdi, 8
        code.push(0xe9); // jmp
        code.extend_from_slice(&(0x2000i32 - 9).to_le_bytes()); // target at 0x2000

        let thunk = detector.detect_thunk(&code, 0);
        assert!(thunk.is_some());
        let thunk = thunk.unwrap();
        assert_eq!(thunk.this_adjustment, -8);
        assert_eq!(thunk.target_function, 0x2000);
    }

    #[test]
    fn test_thunk_detection_x86_64_lea() {
        let detector = make_test_detector();

        // x86_64 thunk: lea rdi, [rdi-16]; jmp 0x3000
        // 48 8d 7f f0  = lea rdi, [rdi-16]
        // e9 XX XX XX XX = jmp rel32
        let mut code = vec![0x48, 0x8d, 0x7f, 0xf0]; // lea rdi, [rdi-16]
        code.push(0xe9); // jmp
        code.extend_from_slice(&(0x3000i32 - 9).to_le_bytes()); // target at 0x3000

        let thunk = detector.detect_thunk(&code, 0);
        assert!(thunk.is_some());
        let thunk = thunk.unwrap();
        assert_eq!(thunk.this_adjustment, -16);
        assert_eq!(thunk.target_function, 0x3000);
    }

    #[test]
    fn test_vtable_entry_thunk() {
        let thunk_info = ThunkInfo::new(-16, 0x5000);
        let entry = VtableEntry::new(0, 0x4000).with_thunk(thunk_info);

        assert!(entry.is_thunk());
        assert_eq!(entry.target, 0x4000);
        assert_eq!(entry.resolved_target(), 0x5000);
        assert_eq!(entry.thunk.as_ref().unwrap().this_adjustment, -16);
    }

    #[test]
    fn test_not_a_thunk() {
        let detector = make_test_detector();

        // Regular function prologue, not a thunk
        let code = vec![0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10];

        let thunk = detector.detect_thunk(&code, 0);
        assert!(thunk.is_none());
    }
}
