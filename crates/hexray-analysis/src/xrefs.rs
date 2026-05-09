//! Cross-reference (xref) analysis.
//!
//! This module provides utilities for tracking and querying cross-references
//! between addresses in a binary. Cross-references help understand:
//! - Where a function is called from
//! - What addresses are accessed by code
//! - What strings are referenced

use std::collections::{HashMap, HashSet};

use hexray_core::{
    Architecture, Bitness, ControlFlow, Endianness, Instruction, Operand, Operation, Register,
    RegisterClass,
};
use hexray_formats::{BinaryFormat, Section};

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
    /// Address materialization without dereference.
    DataAddress,
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
        matches!(
            self,
            XrefType::DataRead | XrefType::DataWrite | XrefType::DataAddress
        )
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

const EXCEPTION_POINTER_SECTION_NAMES: &[&str] = &[
    ".eh_frame",
    "__eh_frame",
    ".gcc_except_table",
    "__gcc_except_tab",
];

/// Scans exception metadata sections for absolute pointers into allocated code/data sections.
///
/// GCC and Clang commonly encode C++ personality pointers and LSDA references as absolute
/// 32-bit values inside 64-bit `.eh_frame` records, so this scans both 4-byte and native-width
/// values on 64-bit binaries.
pub fn add_exception_section_xrefs<B: BinaryFormat + ?Sized>(binary: &B, db: &mut XrefDatabase) {
    let target_ranges = binary
        .sections()
        .filter(|section| is_addressable_target_section(*section))
        .map(|section| {
            (
                section.virtual_address(),
                section.virtual_address().saturating_add(section.size()),
            )
        })
        .collect::<Vec<_>>();
    if target_ranges.is_empty() {
        return;
    }

    let scan_widths: &[usize] = match binary.bitness() {
        Bitness::Bits32 => &[4],
        Bitness::Bits64 => &[4, 8],
    };

    for section in binary.sections() {
        if !matches_exception_pointer_section(section) || !section.is_allocated() {
            continue;
        }

        scan_absolute_pointer_section(
            section,
            binary.endianness(),
            scan_widths,
            &target_ranges,
            db,
        );
    }
}

fn matches_exception_pointer_section(section: &dyn Section) -> bool {
    let name = section.name();
    EXCEPTION_POINTER_SECTION_NAMES
        .iter()
        .any(|candidate| name == *candidate || name.ends_with(candidate))
}

fn is_addressable_target_section(section: &dyn Section) -> bool {
    if !section.is_allocated() || section.size() == 0 {
        return false;
    }

    let name = section.name().to_ascii_lowercase();
    !name.starts_with(".debug")
        && !name.starts_with("__debug")
        && !matches!(
            name.as_str(),
            ".symtab" | ".strtab" | ".shstrtab" | ".comment"
        )
}

fn scan_absolute_pointer_section(
    section: &dyn Section,
    endianness: Endianness,
    scan_widths: &[usize],
    target_ranges: &[(u64, u64)],
    db: &mut XrefDatabase,
) {
    let data = section.data();

    for &width in scan_widths {
        let Some(last_offset) = data.len().checked_sub(width) else {
            continue;
        };

        for offset in 0..=last_offset {
            let Some(candidate) =
                decode_absolute_pointer(&data[offset..offset + width], endianness)
            else {
                continue;
            };
            if candidate == 0
                || !target_ranges
                    .iter()
                    .any(|(start, end)| candidate >= *start && candidate < *end)
            {
                continue;
            }

            let from = section.virtual_address().saturating_add(offset as u64);
            db.add_xref(from, candidate, XrefType::DataAddress);
        }
    }
}

fn decode_absolute_pointer(bytes: &[u8], endianness: Endianness) -> Option<u64> {
    match (endianness, bytes.len()) {
        (Endianness::Little, 4) => Some(u32::from_le_bytes(bytes.try_into().ok()?) as u64),
        (Endianness::Big, 4) => Some(u32::from_be_bytes(bytes.try_into().ok()?) as u64),
        (Endianness::Little, 8) => Some(u64::from_le_bytes(bytes.try_into().ok()?)),
        (Endianness::Big, 8) => Some(u64::from_be_bytes(bytes.try_into().ok()?)),
        _ => None,
    }
}

/// Builder for constructing a cross-reference database from instructions.
pub struct XrefBuilder {
    db: XrefDatabase,
    pending_arm64_page_bases: HashMap<u16, u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperandAccess {
    Read,
    Write,
    Address,
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
            pending_arm64_page_bases: HashMap::new(),
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

        if let Some((target, xref_type)) =
            Self::extract_arm64_pageoff_target(instr, &self.pending_arm64_page_bases)
        {
            self.db.add_xref(from, target, xref_type);
        }

        for (index, operand) in instr.operands.iter().enumerate() {
            let Some(target) = Self::extract_operand_target(instr, operand) else {
                continue;
            };

            for access in Self::operand_accesses(instr, index, operand) {
                self.db
                    .add_xref(from, target, Self::xref_type_for_access(*access));
            }
        }

        self.update_arm64_page_bases(instr);
    }

    /// Analyze a sequence of instructions.
    pub fn analyze_instructions(&mut self, instructions: &[Instruction]) {
        self.pending_arm64_page_bases.clear();
        for instr in instructions {
            self.analyze_instruction(instr);
        }
        self.pending_arm64_page_bases.clear();
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

    fn extract_operand_target(instr: &Instruction, operand: &Operand) -> Option<u64> {
        match operand {
            Operand::Memory(mem_ref) => {
                if Self::is_pc_relative_base(mem_ref.base.as_ref()) && mem_ref.index.is_none() {
                    Self::extract_effective_address(instr, operand)
                } else {
                    Self::extract_absolute_memory_address(mem_ref)
                }
            }
            Operand::Immediate(imm) => {
                if imm.value > 0x1000 && imm.value < 0x7fff_ffff_ffff_ffff {
                    Some(imm.value as u64)
                } else {
                    None
                }
            }
            Operand::PcRelative { target, .. } => Some(*target),
            _ => None,
        }
    }

    fn extract_arm64_pageoff_target(
        instr: &Instruction,
        pending_arm64_page_bases: &HashMap<u16, u64>,
    ) -> Option<(u64, XrefType)> {
        match instr.operation {
            Operation::Add => {
                let source = match instr.operands.get(1) {
                    Some(Operand::Register(register)) => *register,
                    _ => return None,
                };
                let page_base = pending_arm64_page_bases
                    .get(&Self::arm64_page_base_register_key(source)?)
                    .copied()?;
                let offset = match instr.operands.get(2) {
                    Some(Operand::Immediate(immediate)) if immediate.value >= 0 => {
                        u64::try_from(immediate.value).ok()?
                    }
                    _ => return None,
                };

                Self::combine_arm64_page_base(page_base, i64::try_from(offset).ok()?)
                    .map(|target| (target, XrefType::DataRead))
            }
            Operation::Load | Operation::Store => {
                let mem_ref = instr.operands.iter().find_map(|operand| match operand {
                    Operand::Memory(mem_ref) => Some(mem_ref),
                    _ => None,
                })?;

                if mem_ref.index.is_some() {
                    return None;
                }

                let base = mem_ref.base?;
                let page_base = pending_arm64_page_bases
                    .get(&Self::arm64_page_base_register_key(base)?)
                    .copied()?;
                let target = Self::combine_arm64_page_base(page_base, mem_ref.displacement)?;
                let xref_type = if instr.operation == Operation::Store {
                    XrefType::DataWrite
                } else {
                    XrefType::DataRead
                };

                Some((target, xref_type))
            }
            _ => None,
        }
    }

    fn extract_absolute_memory_address(mem_ref: &hexray_core::MemoryRef) -> Option<u64> {
        if mem_ref.base.is_none()
            && mem_ref.displacement > 0x1000
            && mem_ref.displacement < i64::MAX
        {
            Some(mem_ref.displacement as u64)
        } else {
            None
        }
    }

    fn operand_accesses(
        instr: &Instruction,
        index: usize,
        operand: &Operand,
    ) -> &'static [OperandAccess] {
        match operand {
            Operand::Immediate(_) => &[OperandAccess::Address],
            Operand::PcRelative { .. } => {
                if instr.operation == Operation::LoadEffectiveAddress && Self::is_arm64_adrp(instr)
                {
                    &[]
                } else {
                    &[OperandAccess::Address]
                }
            }
            Operand::Memory(_) => match instr.operation {
                Operation::LoadEffectiveAddress if !Self::is_arm64_adrp(instr) => {
                    &[OperandAccess::Address]
                }
                Operation::Exchange if instr.mnemonic.eq_ignore_ascii_case("xchg") => {
                    &[OperandAccess::Read, OperandAccess::Write]
                }
                Operation::Move => {
                    if index == 0 {
                        &[OperandAccess::Write]
                    } else {
                        &[OperandAccess::Read]
                    }
                }
                Operation::Load => &[OperandAccess::Read],
                Operation::Store => {
                    if index == 0 {
                        &[OperandAccess::Read]
                    } else {
                        &[OperandAccess::Write]
                    }
                }
                Operation::Compare | Operation::Test | Operation::BitTest => &[OperandAccess::Read],
                Operation::Neg | Operation::Not | Operation::Inc | Operation::Dec => {
                    &[OperandAccess::Read, OperandAccess::Write]
                }
                _ => {
                    if index == 0 {
                        if instr.operands.len() == 2 {
                            &[OperandAccess::Read, OperandAccess::Write]
                        } else {
                            &[OperandAccess::Write]
                        }
                    } else {
                        &[OperandAccess::Read]
                    }
                }
            },
            _ => &[],
        }
    }

    fn xref_type_for_access(access: OperandAccess) -> XrefType {
        match access {
            OperandAccess::Read => XrefType::DataRead,
            OperandAccess::Write => XrefType::DataWrite,
            OperandAccess::Address => XrefType::DataAddress,
        }
    }

    fn is_pc_relative_base(base: Option<&Register>) -> bool {
        base.is_some_and(|register| {
            register.class == RegisterClass::ProgramCounter
                || matches!(register.name(), "rip" | "eip" | "pc")
        })
    }

    fn is_arm64_adrp(instr: &Instruction) -> bool {
        instr.operation == Operation::LoadEffectiveAddress
            && instr.mnemonic == "adrp"
            && matches!(
                instr.operands.first(),
                Some(Operand::Register(register)) if register.arch == Architecture::Arm64
            )
    }

    fn update_arm64_page_bases(&mut self, instr: &Instruction) {
        for register in &instr.writes {
            let Some(key) = Self::arm64_page_base_register_key(*register) else {
                continue;
            };
            self.pending_arm64_page_bases.remove(&key);
        }

        if !Self::is_arm64_adrp(instr) {
            return;
        }

        let register = match instr.operands.first() {
            Some(Operand::Register(register)) => *register,
            _ => return,
        };
        let Some(key) = Self::arm64_page_base_register_key(register) else {
            return;
        };
        let Some(page_base) = instr
            .operands
            .get(1)
            .and_then(|operand| Self::extract_effective_address(instr, operand))
        else {
            return;
        };

        self.pending_arm64_page_bases.insert(key, page_base);
    }

    fn arm64_page_base_register_key(register: Register) -> Option<u16> {
        (register.arch == Architecture::Arm64 && register.class == RegisterClass::General)
            .then_some(register.id)
    }

    fn combine_arm64_page_base(page_base: u64, displacement: i64) -> Option<u64> {
        const ARM64_PAGE_OFFSET_MASK: u64 = 0x0fff;

        if displacement >= 0 {
            return Some(page_base | (u64::try_from(displacement).ok()? & ARM64_PAGE_OFFSET_MASK));
        }

        let target = i128::from(page_base) + i128::from(displacement);
        u64::try_from(target).ok()
    }

    /// Build the cross-reference database.
    pub fn build(self) -> XrefDatabase {
        self.db
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexray_core::{Architecture, ControlFlow, Instruction, MemoryRef, Register, Symbol};

    #[derive(Clone)]
    struct TestSection {
        name: &'static str,
        virtual_address: u64,
        data: Vec<u8>,
        executable: bool,
        writable: bool,
        allocated: bool,
    }

    impl Section for TestSection {
        fn name(&self) -> &str {
            self.name
        }

        fn virtual_address(&self) -> u64 {
            self.virtual_address
        }

        fn size(&self) -> u64 {
            self.data.len() as u64
        }

        fn data(&self) -> &[u8] {
            &self.data
        }

        fn is_executable(&self) -> bool {
            self.executable
        }

        fn is_writable(&self) -> bool {
            self.writable
        }

        fn is_allocated(&self) -> bool {
            self.allocated
        }
    }

    struct TestBinary {
        bitness: Bitness,
        endianness: Endianness,
        sections: Vec<TestSection>,
        symbols: Vec<Symbol>,
    }

    impl BinaryFormat for TestBinary {
        fn architecture(&self) -> Architecture {
            Architecture::X86_64
        }

        fn endianness(&self) -> Endianness {
            self.endianness
        }

        fn bitness(&self) -> Bitness {
            self.bitness
        }

        fn entry_point(&self) -> Option<u64> {
            None
        }

        fn executable_sections(&self) -> Box<dyn Iterator<Item = &dyn Section> + '_> {
            Box::new(
                self.sections
                    .iter()
                    .filter(|section| section.executable)
                    .map(|section| section as &dyn Section),
            )
        }

        fn sections(&self) -> Box<dyn Iterator<Item = &dyn Section> + '_> {
            Box::new(self.sections.iter().map(|section| section as &dyn Section))
        }

        fn symbols(&self) -> Box<dyn Iterator<Item = &Symbol> + '_> {
            Box::new(self.symbols.iter())
        }

        fn symbol_at(&self, addr: u64) -> Option<&Symbol> {
            self.symbols.iter().find(|symbol| symbol.address == addr)
        }

        fn bytes_at(&self, addr: u64, len: usize) -> Option<&[u8]> {
            let section = self.section_containing(addr)?;
            let start = addr.checked_sub(section.virtual_address())? as usize;
            let end = start.checked_add(len)?;
            section.data().get(start..end)
        }

        fn section_containing(&self, addr: u64) -> Option<&dyn Section> {
            self.sections
                .iter()
                .find(|section| {
                    let start = section.virtual_address;
                    let end = start.saturating_add(section.data.len() as u64);
                    addr >= start && addr < end
                })
                .map(|section| section as &dyn Section)
        }
    }

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
        assert!(XrefType::DataAddress.is_data());
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
    fn test_add_exception_section_xrefs_scans_32bit_values_in_64bit_eh_frame() {
        let binary = TestBinary {
            bitness: Bitness::Bits64,
            endianness: Endianness::Little,
            sections: vec![
                TestSection {
                    name: ".text",
                    virtual_address: 0x401000,
                    data: vec![0x90; 0x400],
                    executable: true,
                    writable: false,
                    allocated: true,
                },
                TestSection {
                    name: ".gcc_except_table",
                    virtual_address: 0x4023c0,
                    data: vec![0; 0x40],
                    executable: false,
                    writable: false,
                    allocated: true,
                },
                TestSection {
                    name: ".eh_frame",
                    virtual_address: 0x402160,
                    data: vec![
                        0x00, 0x03, 0xd0, 0x11, 0x40, 0x00, // absolute 32-bit personality ptr
                        0x7f, 0x00, 0xc0, 0x23, 0x40, 0x00, // absolute 32-bit LSDA ptr
                    ],
                    executable: false,
                    writable: false,
                    allocated: true,
                },
                TestSection {
                    name: ".debug_info",
                    virtual_address: 0x500000,
                    data: vec![0; 0x20],
                    executable: false,
                    writable: false,
                    allocated: false,
                },
            ],
            symbols: Vec::new(),
        };

        let mut db = XrefDatabase::new();
        add_exception_section_xrefs(&binary, &mut db);

        let personality_refs = db.refs_to(0x4011d0);
        assert_eq!(personality_refs.len(), 1);
        assert_eq!(personality_refs[0].from, 0x402162);
        assert_eq!(personality_refs[0].xref_type, XrefType::DataAddress);

        let lsda_refs = db.refs_to(0x4023c0);
        assert_eq!(lsda_refs.len(), 1);
        assert_eq!(lsda_refs[0].from, 0x402168);
        assert_eq!(lsda_refs[0].xref_type, XrefType::DataAddress);
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
        assert_eq!(refs[0].xref_type, XrefType::DataAddress);
    }

    #[test]
    fn test_xref_builder_tracks_rip_relative_mov_load_and_store() {
        let mut builder = XrefBuilder::new();
        let rip = Register::new(Architecture::X86_64, RegisterClass::ProgramCounter, 16, 64);
        let rax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 64);
        let load = Instruction {
            address: 0x2000,
            size: 7,
            bytes: vec![0; 7],
            operation: Operation::Move,
            mnemonic: "mov".to_string(),
            operands: vec![
                Operand::Register(rax),
                Operand::Memory(MemoryRef::sib(Some(rip), None, 1, 0x20, 8)),
            ],
            control_flow: ControlFlow::Sequential,
            reads: vec![rip],
            writes: vec![rax],
            guard: None,
        };
        let store = Instruction {
            address: 0x2010,
            size: 7,
            bytes: vec![0; 7],
            operation: Operation::Move,
            mnemonic: "mov".to_string(),
            operands: vec![
                Operand::Memory(MemoryRef::sib(Some(rip), None, 1, 0x10, 8)),
                Operand::Register(rax),
            ],
            control_flow: ControlFlow::Sequential,
            reads: vec![rip, rax],
            writes: vec![],
            guard: None,
        };

        builder.analyze_instructions(&[load, store]);
        let db = builder.build();
        let refs = db.refs_to(0x2027);

        assert_eq!(refs.len(), 2);
        assert!(refs
            .iter()
            .any(|xref| { xref.from == 0x2000 && xref.xref_type == XrefType::DataRead }));
        assert!(refs
            .iter()
            .any(|xref| { xref.from == 0x2010 && xref.xref_type == XrefType::DataWrite }));
    }

    #[test]
    fn test_xref_builder_tracks_absolute_indexed_sib_load_targets() {
        let mut builder = XrefBuilder::new();
        let rax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 64);
        let instr = Instruction {
            address: 0x40114a,
            size: 8,
            bytes: vec![0; 8],
            operation: Operation::Move,
            mnemonic: "mov".to_string(),
            operands: vec![
                Operand::Register(rax),
                Operand::Memory(MemoryRef::sib(None, Some(rax), 8, 0x402008, 8)),
            ],
            control_flow: ControlFlow::Sequential,
            reads: vec![rax],
            writes: vec![rax],
            guard: None,
        };

        builder.analyze_instruction(&instr);
        let db = builder.build();
        let refs = db.refs_to(0x402008);

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].from, 0x40114a);
        assert_eq!(refs[0].xref_type, XrefType::DataRead);
    }

    #[test]
    fn test_xref_builder_tracks_rip_relative_rmw_accesses() {
        let mut builder = XrefBuilder::new();
        let rip = Register::new(Architecture::X86_64, RegisterClass::ProgramCounter, 16, 64);
        let instr = Instruction {
            address: 0x3000,
            size: 7,
            bytes: vec![0; 7],
            operation: Operation::Add,
            mnemonic: "add".to_string(),
            operands: vec![
                Operand::Memory(MemoryRef::sib(Some(rip), None, 1, 0x24, 4)),
                Operand::imm_unsigned(1, 32),
            ],
            control_flow: ControlFlow::Sequential,
            reads: vec![rip],
            writes: vec![],
            guard: None,
        };

        builder.analyze_instruction(&instr);
        let db = builder.build();
        let refs = db.refs_to(0x302b);

        assert_eq!(refs.len(), 2);
        assert!(refs.iter().any(|xref| xref.xref_type == XrefType::DataRead));
        assert!(refs
            .iter()
            .any(|xref| xref.xref_type == XrefType::DataWrite));
    }

    #[test]
    fn test_xref_builder_tracks_xchg_memory_as_read_and_write() {
        let mut builder = XrefBuilder::new();
        let rip = Register::new(Architecture::X86_64, RegisterClass::ProgramCounter, 16, 64);
        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);
        let instr = Instruction {
            address: 0x401266,
            size: 6,
            bytes: vec![0x87, 0x05, 0xbc, 0x2d, 0x00, 0x00],
            operation: Operation::Exchange,
            mnemonic: "xchg".to_string(),
            operands: vec![
                Operand::Memory(MemoryRef::sib(Some(rip), None, 1, 0x2dbc, 4)),
                Operand::Register(eax),
            ],
            control_flow: ControlFlow::Sequential,
            reads: vec![rip, eax],
            writes: vec![eax],
            guard: None,
        };

        builder.analyze_instruction(&instr);
        let db = builder.build();
        let refs = db.refs_to(0x404028);

        assert_eq!(refs.len(), 2);
        assert!(refs.iter().any(|xref| xref.xref_type == XrefType::DataRead));
        assert!(refs
            .iter()
            .any(|xref| xref.xref_type == XrefType::DataWrite));
    }

    #[test]
    fn test_xref_builder_tracks_pc_relative_operands_for_adr_ops() {
        let mut builder = XrefBuilder::new();
        let instr = Instruction {
            address: 0x4000,
            size: 4,
            bytes: vec![0; 4],
            operation: Operation::LoadEffectiveAddress,
            mnemonic: "adr".to_string(),
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
        assert_eq!(refs[0].xref_type, XrefType::DataAddress);
    }

    #[test]
    fn test_xref_builder_combines_adrp_and_load_pageoff_targets() {
        let mut builder = XrefBuilder::new();
        let page_reg = Register::new(Architecture::Arm64, RegisterClass::General, 16, 64);
        let load_reg = Register::new(Architecture::Arm64, RegisterClass::General, 0, 64);
        let adrp = Instruction {
            address: 0x4000,
            size: 4,
            bytes: vec![0; 4],
            operation: Operation::LoadEffectiveAddress,
            mnemonic: "adrp".to_string(),
            operands: vec![Operand::Register(page_reg), Operand::pc_rel(0x2000, 0x6000)],
            control_flow: ControlFlow::Sequential,
            reads: vec![],
            writes: vec![],
            guard: None,
        };
        let ldr = Instruction {
            address: 0x4004,
            size: 4,
            bytes: vec![0; 4],
            operation: Operation::Load,
            mnemonic: "ldr".to_string(),
            operands: vec![
                Operand::Register(load_reg),
                Operand::Memory(MemoryRef::base_disp(page_reg, 0x28, 8)),
            ],
            control_flow: ControlFlow::Sequential,
            reads: vec![page_reg],
            writes: vec![],
            guard: None,
        };

        builder.analyze_instructions(&[adrp, ldr]);
        let db = builder.build();

        let refs = db.refs_to(0x6028);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].from, 0x4004);
        assert_eq!(refs[0].xref_type, XrefType::DataRead);
        assert!(db.refs_to(0x6000).is_empty());
    }

    #[test]
    fn test_xref_builder_combines_adrp_and_add_pageoff_targets() {
        let mut builder = XrefBuilder::new();
        let page_reg = Register::new(Architecture::Arm64, RegisterClass::General, 8, 64);
        let adrp = Instruction {
            address: 0x5000,
            size: 4,
            bytes: vec![0; 4],
            operation: Operation::LoadEffectiveAddress,
            mnemonic: "adrp".to_string(),
            operands: vec![Operand::Register(page_reg), Operand::pc_rel(0x3000, 0x8000)],
            control_flow: ControlFlow::Sequential,
            reads: vec![],
            writes: vec![],
            guard: None,
        };
        let add = Instruction {
            address: 0x5004,
            size: 4,
            bytes: vec![0; 4],
            operation: Operation::Add,
            mnemonic: "add".to_string(),
            operands: vec![
                Operand::Register(page_reg),
                Operand::Register(page_reg),
                Operand::imm_unsigned(0x70, 64),
            ],
            control_flow: ControlFlow::Sequential,
            reads: vec![page_reg],
            writes: vec![page_reg],
            guard: None,
        };

        builder.analyze_instruction(&adrp);
        builder.analyze_instruction(&add);
        let db = builder.build();

        let refs = db.refs_to(0x8070);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].from, 0x5004);
        assert_eq!(refs[0].xref_type, XrefType::DataRead);
        assert!(db.refs_to(0x8000).is_empty());
    }

    #[test]
    fn test_xref_builder_keeps_adrp_page_base_live_for_later_store() {
        let mut builder = XrefBuilder::new();
        let page_reg = Register::new(Architecture::Arm64, RegisterClass::General, 24, 64);
        let other_reg = Register::new(Architecture::Arm64, RegisterClass::General, 0, 64);
        let value_reg = Register::new(Architecture::Arm64, RegisterClass::General, 22, 32);
        let adrp = Instruction {
            address: 0x4000,
            size: 4,
            bytes: vec![0; 4],
            operation: Operation::LoadEffectiveAddress,
            mnemonic: "adrp".to_string(),
            operands: vec![Operand::Register(page_reg), Operand::pc_rel(0x2000, 0x6000)],
            control_flow: ControlFlow::Sequential,
            reads: vec![],
            writes: vec![page_reg],
            guard: None,
        };
        let unrelated = Instruction {
            address: 0x4004,
            size: 4,
            bytes: vec![0; 4],
            operation: Operation::Move,
            mnemonic: "mov".to_string(),
            operands: vec![Operand::Register(other_reg), Operand::Register(other_reg)],
            control_flow: ControlFlow::Sequential,
            reads: vec![other_reg],
            writes: vec![other_reg],
            guard: None,
        };
        let strb = Instruction {
            address: 0x4008,
            size: 4,
            bytes: vec![0; 4],
            operation: Operation::Store,
            mnemonic: "strb".to_string(),
            operands: vec![
                Operand::Register(value_reg),
                Operand::Memory(MemoryRef::base_disp(page_reg, 0xd0, 1)),
            ],
            control_flow: ControlFlow::Sequential,
            reads: vec![value_reg, page_reg],
            writes: vec![],
            guard: None,
        };

        builder.analyze_instructions(&[adrp, unrelated, strb]);
        let db = builder.build();

        let refs = db.refs_to(0x60d0);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].from, 0x4008);
        assert_eq!(refs[0].xref_type, XrefType::DataWrite);
        assert!(db.refs_to(0x6000).is_empty());
    }
}
