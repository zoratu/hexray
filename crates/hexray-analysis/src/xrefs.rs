//! Cross-reference (xref) analysis.
//!
//! This module provides utilities for tracking and querying cross-references
//! between addresses in a binary. Cross-references help understand:
//! - Where a function is called from
//! - What addresses are accessed by code
//! - What strings are referenced

use std::collections::{HashMap, HashSet};

use hexray_core::{ControlFlow, Instruction, Operand, Operation, Register, RegisterClass};

/// Type of cross-reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XrefType {
    /// Direct call to a function.
    Call,
    /// Conditional or unconditional jump.
    Jump,
    /// Data read access.
    DataRead,
    /// Data write access.
    DataWrite,
    /// Unknown or indirect reference.
    Unknown,
}

impl XrefType {
    /// Returns true if this is a code reference (call or jump).
    pub fn is_code(&self) -> bool {
        matches!(self, XrefType::Call | XrefType::Jump)
    }

    /// Returns true if this is a data reference.
    pub fn is_data(&self) -> bool {
        matches!(self, XrefType::DataRead | XrefType::DataWrite)
    }
}

/// A single cross-reference.
#[derive(Debug, Clone)]
pub struct Xref {
    /// Source address (where the reference originates).
    pub from: u64,
    /// Target address (what is being referenced).
    pub to: u64,
    /// Type of reference.
    pub xref_type: XrefType,
}

/// Cross-reference database.
///
/// Maintains bidirectional mappings for efficient queries:
/// - What references point TO a given address
/// - What references originate FROM a given address
#[derive(Debug, Default)]
pub struct XrefDatabase {
    /// References TO each address (target -> sources).
    refs_to: HashMap<u64, Vec<Xref>>,
    /// References FROM each address (source -> targets).
    refs_from: HashMap<u64, Vec<Xref>>,
    /// All unique addresses that are referenced.
    referenced_addrs: HashSet<u64>,
}

impl XrefDatabase {
    /// Create a new empty cross-reference database.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a cross-reference.
    pub fn add_xref(&mut self, from: u64, to: u64, xref_type: XrefType) {
        let xref = Xref {
            from,
            to,
            xref_type,
        };

        if self.refs_from.get(&from).is_some_and(|existing| {
            existing
                .iter()
                .any(|candidate| Self::same_xref(candidate, &xref))
        }) {
            return;
        }

        self.refs_to.entry(to).or_default().push(xref.clone());

        self.refs_from.entry(from).or_default().push(xref);

        self.referenced_addrs.insert(to);
    }

    /// Get all references TO a specific address.
    pub fn refs_to(&self, addr: u64) -> &[Xref] {
        self.refs_to.get(&addr).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Get all references FROM a specific address.
    pub fn refs_from(&self, addr: u64) -> &[Xref] {
        self.refs_from
            .get(&addr)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get the number of references TO a specific address.
    pub fn count_refs_to(&self, addr: u64) -> usize {
        self.refs_to.get(&addr).map(|v| v.len()).unwrap_or(0)
    }

    /// Get the number of references FROM a specific address.
    pub fn count_refs_from(&self, addr: u64) -> usize {
        self.refs_from.get(&addr).map(|v| v.len()).unwrap_or(0)
    }

    /// Check if an address has any references to it.
    pub fn is_referenced(&self, addr: u64) -> bool {
        self.referenced_addrs.contains(&addr)
    }

    /// Get all referenced addresses.
    pub fn all_referenced(&self) -> impl Iterator<Item = u64> + '_ {
        self.referenced_addrs.iter().copied()
    }

    /// Get all addresses that have outgoing references.
    pub fn all_sources(&self) -> impl Iterator<Item = u64> + '_ {
        self.refs_from.keys().copied()
    }

    /// Get code references (calls and jumps) TO a specific address.
    pub fn code_refs_to(&self, addr: u64) -> Vec<&Xref> {
        self.refs_to(addr)
            .iter()
            .filter(|x| x.xref_type.is_code())
            .collect()
    }

    /// Get data references TO a specific address.
    pub fn data_refs_to(&self, addr: u64) -> Vec<&Xref> {
        self.refs_to(addr)
            .iter()
            .filter(|x| x.xref_type.is_data())
            .collect()
    }

    /// Get call references TO a specific address.
    pub fn call_refs_to(&self, addr: u64) -> Vec<&Xref> {
        self.refs_to(addr)
            .iter()
            .filter(|x| x.xref_type == XrefType::Call)
            .collect()
    }

    /// Total number of cross-references in the database.
    pub fn total_xrefs(&self) -> usize {
        self.refs_from.values().map(|v| v.len()).sum()
    }

    /// Merge another xref database into this one.
    pub fn merge(&mut self, other: XrefDatabase) {
        for xrefs in other.refs_from.into_values() {
            for xref in xrefs {
                self.add_xref(xref.from, xref.to, xref.xref_type);
            }
        }
    }

    fn same_xref(left: &Xref, right: &Xref) -> bool {
        left.from == right.from && left.to == right.to && left.xref_type == right.xref_type
    }
}

/// Builder for constructing a cross-reference database from instructions.
pub struct XrefBuilder {
    db: XrefDatabase,
}

impl Default for XrefBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl XrefBuilder {
    /// Create a new xref builder.
    pub fn new() -> Self {
        Self {
            db: XrefDatabase::new(),
        }
    }

    /// Analyze a single instruction for cross-references.
    pub fn analyze_instruction(&mut self, instr: &Instruction) {
        let from = instr.address;

        // Check control flow for code references
        match &instr.control_flow {
            ControlFlow::Call { target, .. } => {
                self.db.add_xref(from, *target, XrefType::Call);
            }
            ControlFlow::UnconditionalBranch { target } => {
                self.db.add_xref(from, *target, XrefType::Jump);
            }
            ControlFlow::ConditionalBranch { target, .. } => {
                self.db.add_xref(from, *target, XrefType::Jump);
            }
            _ => {}
        }

        if instr.operation == Operation::LoadEffectiveAddress {
            if let Some(target) = instr
                .operands
                .get(1)
                .and_then(|operand| Self::extract_effective_address(instr, operand))
            {
                self.db.add_xref(from, target, XrefType::DataRead);
            }
        }

        // Check operands for data references
        for operand in &instr.operands {
            if let Some(addr) = Self::extract_memory_address(operand) {
                // Determine if this is a read or write based on operand position
                // First operand is typically the destination (write)
                let xref_type = if instr.operands.first() == Some(operand) {
                    XrefType::DataWrite
                } else {
                    XrefType::DataRead
                };
                self.db.add_xref(from, addr, xref_type);
            }
        }
    }

    /// Analyze a sequence of instructions.
    pub fn analyze_instructions(&mut self, instructions: &[Instruction]) {
        for instr in instructions {
            self.analyze_instruction(instr);
        }
    }

    fn extract_effective_address(instr: &Instruction, operand: &Operand) -> Option<u64> {
        match operand {
            Operand::Memory(mem_ref)
                if Self::is_pc_relative_base(mem_ref.base.as_ref()) && mem_ref.index.is_none() =>
            {
                let target = i128::from(instr.end_address()) + i128::from(mem_ref.displacement);
                u64::try_from(target).ok()
            }
            Operand::PcRelative { target, .. } => Some(*target),
            _ => None,
        }
    }

    /// Extract a memory address from an operand if it's a direct address.
    fn extract_memory_address(operand: &Operand) -> Option<u64> {
        match operand {
            Operand::Memory(mem_ref) => {
                // Only return addresses that look like absolute addresses
                // (large values, typically in the binary's address space)
                if mem_ref.displacement != 0 && mem_ref.displacement > 0x1000 {
                    Some(mem_ref.displacement as u64)
                } else {
                    None
                }
            }
            Operand::Immediate(imm) => {
                // Immediate values that look like addresses (positive values only)
                if imm.value > 0x1000 && imm.value < 0x7fff_ffff_ffff_ffff {
                    Some(imm.value as u64)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn is_pc_relative_base(base: Option<&Register>) -> bool {
        base.is_some_and(|register| {
            register.class == RegisterClass::ProgramCounter
                || matches!(register.name(), "rip" | "eip" | "pc")
        })
    }

    /// Build the cross-reference database.
    pub fn build(self) -> XrefDatabase {
        self.db
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexray_core::{Architecture, ControlFlow, Instruction, MemoryRef, Register};

    #[test]
    fn test_xref_database_basic() {
        let mut db = XrefDatabase::new();

        db.add_xref(0x1000, 0x2000, XrefType::Call);
        db.add_xref(0x1010, 0x2000, XrefType::Call);
        db.add_xref(0x1000, 0x3000, XrefType::DataRead);

        assert_eq!(db.count_refs_to(0x2000), 2);
        assert_eq!(db.count_refs_from(0x1000), 2);
        assert!(db.is_referenced(0x2000));
        assert!(db.is_referenced(0x3000));
        assert!(!db.is_referenced(0x4000));
    }

    #[test]
    fn test_xref_database_deduplicates_identical_edges() {
        let mut db = XrefDatabase::new();
        db.add_xref(0x1000, 0x2000, XrefType::DataRead);
        db.add_xref(0x1000, 0x2000, XrefType::DataRead);

        assert_eq!(db.count_refs_to(0x2000), 1);
        assert_eq!(db.count_refs_from(0x1000), 1);
    }

    #[test]
    fn test_xref_type_predicates() {
        assert!(XrefType::Call.is_code());
        assert!(XrefType::Jump.is_code());
        assert!(!XrefType::Call.is_data());

        assert!(XrefType::DataRead.is_data());
        assert!(XrefType::DataWrite.is_data());
        assert!(!XrefType::DataRead.is_code());
    }

    #[test]
    fn test_xref_builder_call() {
        let mut builder = XrefBuilder::new();

        let instr = Instruction {
            address: 0x1000,
            size: 5,
            bytes: vec![0xe8, 0x00, 0x10, 0x00, 0x00],
            operation: hexray_core::Operation::Call,
            mnemonic: "call".to_string(),
            operands: vec![],
            control_flow: ControlFlow::Call {
                target: 0x2000,
                return_addr: 0x1005,
            },
            reads: vec![],
            writes: vec![],

            guard: None,
        };

        builder.analyze_instruction(&instr);
        let db = builder.build();

        assert_eq!(db.count_refs_to(0x2000), 1);
        let refs = db.refs_to(0x2000);
        assert_eq!(refs[0].from, 0x1000);
        assert_eq!(refs[0].xref_type, XrefType::Call);
    }

    #[test]
    fn test_xref_builder_jump() {
        let mut builder = XrefBuilder::new();

        let instr = Instruction {
            address: 0x1000,
            size: 2,
            bytes: vec![0xeb, 0x10],
            operation: hexray_core::Operation::Jump,
            mnemonic: "jmp".to_string(),
            operands: vec![],
            control_flow: ControlFlow::UnconditionalBranch { target: 0x1012 },
            reads: vec![],
            writes: vec![],

            guard: None,
        };

        builder.analyze_instruction(&instr);
        let db = builder.build();

        assert_eq!(db.count_refs_to(0x1012), 1);
        let refs = db.refs_to(0x1012);
        assert_eq!(refs[0].xref_type, XrefType::Jump);
    }

    #[test]
    fn test_call_refs_to() {
        let mut db = XrefDatabase::new();

        db.add_xref(0x1000, 0x2000, XrefType::Call);
        db.add_xref(0x1010, 0x2000, XrefType::Jump);
        db.add_xref(0x1020, 0x2000, XrefType::Call);

        let call_refs = db.call_refs_to(0x2000);
        assert_eq!(call_refs.len(), 2);
    }

    #[test]
    fn test_merge_databases() {
        let mut db1 = XrefDatabase::new();
        db1.add_xref(0x1000, 0x2000, XrefType::Call);

        let mut db2 = XrefDatabase::new();
        db2.add_xref(0x1010, 0x2000, XrefType::Call);
        db2.add_xref(0x1020, 0x3000, XrefType::Jump);

        db1.merge(db2);

        assert_eq!(db1.count_refs_to(0x2000), 2);
        assert_eq!(db1.count_refs_to(0x3000), 1);
        assert_eq!(db1.total_xrefs(), 3);
    }

    #[test]
    fn test_xref_builder_tracks_rip_relative_lea_targets() {
        let mut builder = XrefBuilder::new();
        let rip = Register::new(Architecture::X86_64, RegisterClass::ProgramCounter, 16, 64);
        let instr = Instruction {
            address: 0x10b8,
            size: 7,
            bytes: vec![0x48, 0x8d, 0x3d, 0xb1, 0x01, 0x00, 0x00],
            operation: Operation::LoadEffectiveAddress,
            mnemonic: "lea".to_string(),
            operands: vec![
                Operand::Register(Register::new(
                    Architecture::X86_64,
                    RegisterClass::General,
                    7,
                    64,
                )),
                Operand::Memory(MemoryRef::sib(Some(rip), None, 1, 0x1b1, 8)),
            ],
            control_flow: ControlFlow::Sequential,
            reads: vec![rip],
            writes: vec![],
            guard: None,
        };

        builder.analyze_instruction(&instr);
        let db = builder.build();
        let refs = db.refs_to(0x1270);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].from, 0x10b8);
        assert_eq!(refs[0].xref_type, XrefType::DataRead);
    }

    #[test]
    fn test_xref_builder_tracks_pc_relative_operands_for_adrp_like_ops() {
        let mut builder = XrefBuilder::new();
        let instr = Instruction {
            address: 0x4000,
            size: 4,
            bytes: vec![0; 4],
            operation: Operation::LoadEffectiveAddress,
            mnemonic: "adrp".to_string(),
            operands: vec![
                Operand::Register(Register::new(
                    Architecture::Arm64,
                    RegisterClass::General,
                    0,
                    64,
                )),
                Operand::pc_rel(0x2000, 0x6000),
            ],
            control_flow: ControlFlow::Sequential,
            reads: vec![],
            writes: vec![],
            guard: None,
        };

        builder.analyze_instruction(&instr);
        let db = builder.build();
        let refs = db.refs_to(0x6000);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].xref_type, XrefType::DataRead);
    }
}
