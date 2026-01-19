//! C++ constructor and destructor identification.
//!
//! This module identifies C++ constructors and destructors by analyzing:
//! - Vtable pointer assignments (constructors/destructors set the vtable)
//! - Symbol name patterns (mangled C++ names)
//! - Call patterns (base class constructor/destructor calls)
//! - Code patterns specific to ctors/dtors
//!
//! # Itanium C++ ABI Name Mangling
//!
//! Constructor symbols:
//! - `_ZN<name>C1Ev` - Complete object constructor
//! - `_ZN<name>C2Ev` - Base object constructor
//! - `_ZN<name>C3Ev` - Complete object allocating constructor (rare)
//!
//! Destructor symbols:
//! - `_ZN<name>D0Ev` - Deleting destructor (calls operator delete)
//! - `_ZN<name>D1Ev` - Complete object destructor
//! - `_ZN<name>D2Ev` - Base object destructor
//!
//! # Example
//!
//! ```ignore
//! use hexray_analysis::cpp_special::{CppSpecialDetector, SpecialMemberKind};
//!
//! let detector = CppSpecialDetector::new();
//! let result = detector.analyze_function(&cfg, &instructions);
//!
//! match result.kind {
//!     Some(SpecialMemberKind::Constructor { .. }) => {
//!         println!("Found constructor for {}", result.class_name.unwrap());
//!     }
//!     Some(SpecialMemberKind::Destructor { .. }) => {
//!         println!("Found destructor for {}", result.class_name.unwrap());
//!     }
//!     _ => {}
//! }
//! ```

use std::collections::{HashMap, HashSet};
use hexray_core::{ControlFlowGraph, Instruction, Operation, Operand, Register};

/// Kind of C++ special member function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecialMemberKind {
    /// Constructor.
    Constructor {
        /// Whether this is a complete object constructor (C1).
        is_complete: bool,
        /// Whether this is an allocating constructor (C3).
        is_allocating: bool,
    },
    /// Destructor.
    Destructor {
        /// Whether this is a deleting destructor (D0).
        is_deleting: bool,
        /// Whether this is a complete object destructor (D1).
        is_complete: bool,
    },
    /// Copy constructor.
    CopyConstructor,
    /// Move constructor.
    MoveConstructor,
    /// Copy assignment operator.
    CopyAssignment,
    /// Move assignment operator.
    MoveAssignment,
}

impl SpecialMemberKind {
    /// Returns a human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Constructor { is_complete: true, .. } => "complete object constructor",
            Self::Constructor { is_complete: false, is_allocating: true } => "allocating constructor",
            Self::Constructor { .. } => "base object constructor",
            Self::Destructor { is_deleting: true, .. } => "deleting destructor",
            Self::Destructor { is_complete: true, .. } => "complete object destructor",
            Self::Destructor { .. } => "base object destructor",
            Self::CopyConstructor => "copy constructor",
            Self::MoveConstructor => "move constructor",
            Self::CopyAssignment => "copy assignment operator",
            Self::MoveAssignment => "move assignment operator",
        }
    }
}

/// Result of analyzing a function for special member patterns.
#[derive(Debug, Clone, Default)]
pub struct SpecialMemberAnalysis {
    /// The detected kind of special member (if any).
    pub kind: Option<SpecialMemberKind>,
    /// The class name (from symbol or vtable).
    pub class_name: Option<String>,
    /// Vtable addresses assigned in the function.
    pub vtable_assignments: Vec<VtableAssignment>,
    /// Base class constructor/destructor calls.
    pub base_calls: Vec<BaseCall>,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f64,
    /// Analysis notes.
    pub notes: Vec<String>,
}

/// A vtable pointer assignment detected in code.
#[derive(Debug, Clone)]
pub struct VtableAssignment {
    /// Address of the instruction.
    pub instruction_addr: u64,
    /// The vtable address being stored.
    pub vtable_addr: u64,
    /// Offset within the object where vtable is stored.
    pub object_offset: i64,
}

/// A call to a base class constructor or destructor.
#[derive(Debug, Clone)]
pub struct BaseCall {
    /// Address of the call instruction.
    pub call_addr: u64,
    /// Target function address.
    pub target_addr: u64,
    /// Name of the base class (if known).
    pub class_name: Option<String>,
    /// Whether this is a constructor (true) or destructor (false).
    pub is_constructor: bool,
}

/// Detector for C++ constructors and destructors.
pub struct CppSpecialDetector {
    /// Known vtable addresses and their class names.
    vtable_classes: HashMap<u64, String>,
    /// Known constructor addresses.
    known_constructors: HashSet<u64>,
    /// Known destructor addresses.
    known_destructors: HashSet<u64>,
    /// Pointer size in bytes.
    pointer_size: usize,
}

impl Default for CppSpecialDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CppSpecialDetector {
    /// Creates a new detector.
    pub fn new() -> Self {
        Self {
            vtable_classes: HashMap::new(),
            known_constructors: HashSet::new(),
            known_destructors: HashSet::new(),
            pointer_size: 8,
        }
    }

    /// Sets the pointer size.
    pub fn with_pointer_size(mut self, size: usize) -> Self {
        self.pointer_size = size;
        self
    }

    /// Adds known vtable-to-class mappings.
    pub fn with_vtable_classes(
        mut self,
        vtables: impl IntoIterator<Item = (u64, String)>,
    ) -> Self {
        self.vtable_classes.extend(vtables);
        self
    }

    /// Adds known constructor addresses.
    pub fn with_known_constructors(mut self, addrs: impl IntoIterator<Item = u64>) -> Self {
        self.known_constructors.extend(addrs);
        self
    }

    /// Adds known destructor addresses.
    pub fn with_known_destructors(mut self, addrs: impl IntoIterator<Item = u64>) -> Self {
        self.known_destructors.extend(addrs);
        self
    }

    /// Analyzes a symbol name for constructor/destructor patterns.
    pub fn analyze_symbol(&self, symbol: &str) -> Option<(SpecialMemberKind, String)> {
        // Check for Itanium C++ ABI mangling
        if !symbol.starts_with("_ZN") {
            return None;
        }

        // Find constructor/destructor markers
        // Format: _ZN<class_name>C1Ev, _ZN<class_name>D0Ev, etc.

        // Look for C1, C2, C3 (constructors) or D0, D1, D2 (destructors)
        let ctor_markers = ["C1E", "C2E", "C3E", "C1Ev", "C2Ev", "C3Ev"];
        let dtor_markers = ["D0E", "D1E", "D2E", "D0Ev", "D1Ev", "D2Ev"];

        for marker in ctor_markers {
            if let Some(pos) = symbol.find(marker) {
                let class_part = &symbol[3..pos]; // Skip "_ZN"
                let class_name = self.demangle_class_name(class_part);
                let kind = match &marker[..2] {
                    "C1" => SpecialMemberKind::Constructor {
                        is_complete: true,
                        is_allocating: false,
                    },
                    "C2" => SpecialMemberKind::Constructor {
                        is_complete: false,
                        is_allocating: false,
                    },
                    "C3" => SpecialMemberKind::Constructor {
                        is_complete: false,
                        is_allocating: true,
                    },
                    _ => continue,
                };
                return Some((kind, class_name));
            }
        }

        for marker in dtor_markers {
            if let Some(pos) = symbol.find(marker) {
                let class_part = &symbol[3..pos]; // Skip "_ZN"
                let class_name = self.demangle_class_name(class_part);
                let kind = match &marker[..2] {
                    "D0" => SpecialMemberKind::Destructor {
                        is_deleting: true,
                        is_complete: false,
                    },
                    "D1" => SpecialMemberKind::Destructor {
                        is_deleting: false,
                        is_complete: true,
                    },
                    "D2" => SpecialMemberKind::Destructor {
                        is_deleting: false,
                        is_complete: false,
                    },
                    _ => continue,
                };
                return Some((kind, class_name));
            }
        }

        None
    }

    /// Demangles a class name portion.
    fn demangle_class_name(&self, mangled: &str) -> String {
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

    /// Analyzes a function's instructions for constructor/destructor patterns.
    pub fn analyze_function(
        &self,
        _cfg: &ControlFlowGraph,
        instructions: &[Instruction],
        symbol: Option<&str>,
    ) -> SpecialMemberAnalysis {
        let mut result = SpecialMemberAnalysis::default();

        // First check symbol name
        if let Some(sym) = symbol {
            if let Some((kind, class_name)) = self.analyze_symbol(sym) {
                result.kind = Some(kind);
                result.class_name = Some(class_name);
                result.confidence = 0.9; // High confidence from symbol
                result.notes.push("Identified from symbol name".to_string());
            }
        }

        // Analyze instruction patterns
        self.find_vtable_assignments(instructions, &mut result);
        self.find_base_calls(instructions, &mut result);

        // If we found vtable assignments but no symbol-based identification
        if result.kind.is_none() && !result.vtable_assignments.is_empty() {
            // Vtable assignments are a strong indicator of ctor/dtor
            let has_multiple_vtables = result.vtable_assignments.len() > 1;

            // Heuristic: if vtable is at offset 0 and early in function, likely constructor
            // If vtable is at offset 0 and late in function (after cleanup), likely destructor
            let first_vtable_pos = instructions
                .iter()
                .position(|i| {
                    result.vtable_assignments.iter().any(|va| va.instruction_addr == i.address)
                });

            let is_early = first_vtable_pos.map_or(false, |pos| pos < instructions.len() / 3);

            if is_early {
                result.kind = Some(SpecialMemberKind::Constructor {
                    is_complete: !has_multiple_vtables,
                    is_allocating: false,
                });
                result.confidence = 0.6;
                result.notes.push("Vtable assignment early in function".to_string());
            } else {
                result.kind = Some(SpecialMemberKind::Destructor {
                    is_deleting: false,
                    is_complete: !has_multiple_vtables,
                });
                result.confidence = 0.5;
                result.notes.push("Vtable assignment late in function".to_string());
            }

            // Try to get class name from vtable
            if result.class_name.is_none() {
                for va in &result.vtable_assignments {
                    if let Some(name) = self.vtable_classes.get(&va.vtable_addr) {
                        result.class_name = Some(name.clone());
                        break;
                    }
                }
            }
        }

        // Adjust confidence based on additional evidence
        if !result.base_calls.is_empty() {
            result.confidence = (result.confidence + 0.1).min(1.0);
            result.notes.push(format!("Found {} base class call(s)", result.base_calls.len()));
        }

        result
    }

    /// Finds vtable pointer assignments in instructions.
    fn find_vtable_assignments(&self, instructions: &[Instruction], result: &mut SpecialMemberAnalysis) {
        for instr in instructions {
            // Look for: mov [reg], imm  or  mov [reg+offset], imm
            // where imm looks like a vtable address
            if !matches!(instr.operation, Operation::Move) {
                continue;
            }

            if instr.operands.len() < 2 {
                continue;
            }

            // Check if destination is a memory operand [reg] or [reg+offset]
            let dest = &instr.operands[0];
            let src = &instr.operands[1];

            // Destination should be memory
            let (base_reg, offset) = match dest {
                Operand::Memory(mem) => {
                    if mem.index.is_some() {
                        continue; // Skip indexed memory (like [rax + rcx*8])
                    }
                    if let Some(ref reg) = mem.base {
                        (reg.clone(), mem.displacement)
                    } else {
                        continue;
                    }
                }
                _ => continue,
            };

            // For constructors/destructors, base register is typically the first argument
            // (rdi on System V AMD64, rcx on Windows x64)
            if !self.is_this_pointer_reg(&base_reg) {
                continue;
            }

            // Source should be an immediate that looks like an address
            let vtable_addr = match src {
                Operand::Immediate(imm) => imm.as_u64(),
                _ => continue,
            };

            // Sanity check: vtable addresses are typically in data sections
            // They should be above 0x1000 and look like valid addresses
            if vtable_addr < 0x1000 {
                continue;
            }

            // Either we know this vtable, or it looks like a reasonable address
            if self.vtable_classes.contains_key(&vtable_addr) || self.looks_like_vtable_addr(vtable_addr) {
                result.vtable_assignments.push(VtableAssignment {
                    instruction_addr: instr.address,
                    vtable_addr,
                    object_offset: offset,
                });
            }
        }
    }

    /// Finds calls to base class constructors/destructors.
    fn find_base_calls(&self, instructions: &[Instruction], result: &mut SpecialMemberAnalysis) {
        for instr in instructions {
            if !matches!(instr.operation, Operation::Call) {
                continue;
            }

            // Get call target
            let target = match instr.operands.first() {
                Some(Operand::Immediate(imm)) => imm.as_u64(),
                Some(Operand::PcRelative { target, .. }) => *target,
                _ => continue,
            };

            // Check if target is a known constructor/destructor
            if self.known_constructors.contains(&target) {
                result.base_calls.push(BaseCall {
                    call_addr: instr.address,
                    target_addr: target,
                    class_name: None, // Could be resolved later
                    is_constructor: true,
                });
            } else if self.known_destructors.contains(&target) {
                result.base_calls.push(BaseCall {
                    call_addr: instr.address,
                    target_addr: target,
                    class_name: None,
                    is_constructor: false,
                });
            }
        }
    }

    /// Checks if a register is likely the 'this' pointer.
    fn is_this_pointer_reg(&self, reg: &Register) -> bool {
        // System V AMD64: rdi is first argument
        // Windows x64: rcx is first argument
        // 32-bit: ecx (thiscall) or first stack arg
        matches!(
            reg.name().to_lowercase().as_str(),
            "rdi" | "edi" | "rcx" | "ecx"
        )
    }

    /// Heuristic check if an address looks like a vtable.
    fn looks_like_vtable_addr(&self, addr: u64) -> bool {
        // Vtables are typically in read-only data sections
        // Common address ranges (heuristic):
        // - ELF: often in 0x400000-0x7fffff range for text/rodata
        // - Mach-O: similar ranges
        // - PIE/ASLR: higher addresses

        // Basic sanity: non-zero, reasonable range
        addr >= 0x1000 && addr < 0x7fff_ffff_ffff_ffff
    }
}

/// Database of identified C++ special members.
#[derive(Debug, Default)]
pub struct CppSpecialDatabase {
    /// Constructors by address.
    constructors: HashMap<u64, SpecialMemberAnalysis>,
    /// Destructors by address.
    destructors: HashMap<u64, SpecialMemberAnalysis>,
    /// Class name to constructor addresses.
    class_constructors: HashMap<String, Vec<u64>>,
    /// Class name to destructor addresses.
    class_destructors: HashMap<String, Vec<u64>>,
}

impl CppSpecialDatabase {
    /// Creates a new empty database.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an analysis result.
    pub fn add(&mut self, func_addr: u64, analysis: SpecialMemberAnalysis) {
        if let Some(ref kind) = analysis.kind {
            let class_name = analysis.class_name.clone();

            match kind {
                SpecialMemberKind::Constructor { .. } | SpecialMemberKind::CopyConstructor | SpecialMemberKind::MoveConstructor => {
                    self.constructors.insert(func_addr, analysis);
                    if let Some(name) = class_name {
                        self.class_constructors.entry(name).or_default().push(func_addr);
                    }
                }
                SpecialMemberKind::Destructor { .. } => {
                    self.destructors.insert(func_addr, analysis);
                    if let Some(name) = class_name {
                        self.class_destructors.entry(name).or_default().push(func_addr);
                    }
                }
                _ => {}
            }
        }
    }

    /// Gets constructor info for a function.
    pub fn get_constructor(&self, addr: u64) -> Option<&SpecialMemberAnalysis> {
        self.constructors.get(&addr)
    }

    /// Gets destructor info for a function.
    pub fn get_destructor(&self, addr: u64) -> Option<&SpecialMemberAnalysis> {
        self.destructors.get(&addr)
    }

    /// Gets all constructors for a class.
    pub fn constructors_for_class(&self, class_name: &str) -> Vec<&SpecialMemberAnalysis> {
        self.class_constructors
            .get(class_name)
            .map(|addrs| addrs.iter().filter_map(|a| self.constructors.get(a)).collect())
            .unwrap_or_default()
    }

    /// Gets all destructors for a class.
    pub fn destructors_for_class(&self, class_name: &str) -> Vec<&SpecialMemberAnalysis> {
        self.class_destructors
            .get(class_name)
            .map(|addrs| addrs.iter().filter_map(|a| self.destructors.get(a)).collect())
            .unwrap_or_default()
    }

    /// Returns whether a function is a constructor.
    pub fn is_constructor(&self, addr: u64) -> bool {
        self.constructors.contains_key(&addr)
    }

    /// Returns whether a function is a destructor.
    pub fn is_destructor(&self, addr: u64) -> bool {
        self.destructors.contains_key(&addr)
    }

    /// Returns all constructor addresses.
    pub fn all_constructors(&self) -> impl Iterator<Item = u64> + '_ {
        self.constructors.keys().copied()
    }

    /// Returns all destructor addresses.
    pub fn all_destructors(&self) -> impl Iterator<Item = u64> + '_ {
        self.destructors.keys().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_constructor_symbol() {
        let detector = CppSpecialDetector::new();

        // Complete object constructor
        let result = detector.analyze_symbol("_ZN5ShapeC1Ev");
        assert!(result.is_some());
        let (kind, name) = result.unwrap();
        assert_eq!(name, "Shape");
        assert!(matches!(kind, SpecialMemberKind::Constructor { is_complete: true, .. }));

        // Base object constructor
        let result = detector.analyze_symbol("_ZN5ShapeC2Ev");
        assert!(result.is_some());
        let (kind, _) = result.unwrap();
        assert!(matches!(kind, SpecialMemberKind::Constructor { is_complete: false, .. }));
    }

    #[test]
    fn test_analyze_destructor_symbol() {
        let detector = CppSpecialDetector::new();

        // Deleting destructor
        let result = detector.analyze_symbol("_ZN5ShapeD0Ev");
        assert!(result.is_some());
        let (kind, name) = result.unwrap();
        assert_eq!(name, "Shape");
        assert!(matches!(kind, SpecialMemberKind::Destructor { is_deleting: true, .. }));

        // Complete object destructor
        let result = detector.analyze_symbol("_ZN5ShapeD1Ev");
        assert!(result.is_some());
        let (kind, _) = result.unwrap();
        assert!(matches!(kind, SpecialMemberKind::Destructor { is_complete: true, .. }));

        // Base object destructor
        let result = detector.analyze_symbol("_ZN5ShapeD2Ev");
        assert!(result.is_some());
        let (kind, _) = result.unwrap();
        assert!(matches!(kind, SpecialMemberKind::Destructor { is_complete: false, is_deleting: false }));
    }

    #[test]
    fn test_analyze_namespaced_symbol() {
        let detector = CppSpecialDetector::new();

        // Namespaced class
        let result = detector.analyze_symbol("_ZN3std6vectorC1Ev");
        assert!(result.is_some());
        let (kind, name) = result.unwrap();
        assert_eq!(name, "std::vector");
        assert!(matches!(kind, SpecialMemberKind::Constructor { .. }));
    }

    #[test]
    fn test_non_special_symbol() {
        let detector = CppSpecialDetector::new();

        // Regular method
        assert!(detector.analyze_symbol("_ZN5Shape4drawEv").is_none());

        // Not mangled
        assert!(detector.analyze_symbol("main").is_none());
        assert!(detector.analyze_symbol("Shape::Shape").is_none());
    }

    #[test]
    fn test_special_member_kind_description() {
        assert_eq!(
            SpecialMemberKind::Constructor { is_complete: true, is_allocating: false }.description(),
            "complete object constructor"
        );
        assert_eq!(
            SpecialMemberKind::Destructor { is_deleting: true, is_complete: false }.description(),
            "deleting destructor"
        );
    }

    #[test]
    fn test_database() {
        let mut db = CppSpecialDatabase::new();

        let ctor_analysis = SpecialMemberAnalysis {
            kind: Some(SpecialMemberKind::Constructor {
                is_complete: true,
                is_allocating: false,
            }),
            class_name: Some("Shape".to_string()),
            confidence: 0.9,
            ..Default::default()
        };

        let dtor_analysis = SpecialMemberAnalysis {
            kind: Some(SpecialMemberKind::Destructor {
                is_deleting: false,
                is_complete: true,
            }),
            class_name: Some("Shape".to_string()),
            confidence: 0.9,
            ..Default::default()
        };

        db.add(0x1000, ctor_analysis);
        db.add(0x2000, dtor_analysis);

        assert!(db.is_constructor(0x1000));
        assert!(!db.is_constructor(0x2000));
        assert!(db.is_destructor(0x2000));
        assert!(!db.is_destructor(0x1000));

        assert_eq!(db.constructors_for_class("Shape").len(), 1);
        assert_eq!(db.destructors_for_class("Shape").len(), 1);
    }
}
