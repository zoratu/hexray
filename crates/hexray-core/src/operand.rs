//! Instruction operand types.

use crate::Register;

/// An instruction operand.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Operand {
    /// Register operand.
    Register(Register),
    /// Immediate value.
    Immediate(Immediate),
    /// Memory reference.
    Memory(MemoryRef),
    /// PC-relative address (used in branches/calls).
    PcRelative {
        /// Offset from PC.
        offset: i64,
        /// Resolved target address.
        target: u64,
    },
}

impl Operand {
    /// Creates a register operand.
    pub fn reg(reg: Register) -> Self {
        Self::Register(reg)
    }

    /// Creates an immediate operand.
    pub fn imm(value: i128, size: u8) -> Self {
        Self::Immediate(Immediate {
            value,
            size,
            signed: true,
        })
    }

    /// Creates an unsigned immediate operand.
    pub fn imm_unsigned(value: u64, size: u8) -> Self {
        Self::Immediate(Immediate {
            value: value as i128,
            size,
            signed: false,
        })
    }

    /// Creates a PC-relative operand.
    pub fn pc_rel(offset: i64, target: u64) -> Self {
        Self::PcRelative { offset, target }
    }

    /// Returns true if this is a register operand.
    pub fn is_register(&self) -> bool {
        matches!(self, Self::Register(_))
    }

    /// Returns true if this is an immediate operand.
    pub fn is_immediate(&self) -> bool {
        matches!(self, Self::Immediate(_))
    }

    /// Returns true if this is a memory operand.
    pub fn is_memory(&self) -> bool {
        matches!(self, Self::Memory(_))
    }
}

/// Immediate value operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Immediate {
    /// The value (sign-extended to i128 for uniformity).
    pub value: i128,
    /// Original size in bits.
    pub size: u8,
    /// Whether this is a signed immediate.
    pub signed: bool,
}

impl Immediate {
    /// Returns the value as an unsigned u64.
    pub fn as_u64(&self) -> u64 {
        self.value as u64
    }

    /// Returns the value as a signed i64.
    pub fn as_i64(&self) -> i64 {
        self.value as i64
    }
}

/// ARM64 memory indexing mode.
///
/// For load/store instructions with pre/post-indexed addressing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum IndexMode {
    /// No writeback: `[base, #offset]` or `[base + index]`
    #[default]
    None,
    /// Pre-indexed: `[base, #offset]!` - compute address first, then writeback
    Pre,
    /// Post-indexed: `[base], #offset` - use base as address, then add offset
    Post,
}

/// Memory reference operand.
///
/// Represents complex memory addressing like `[base + index*scale + disp]`.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MemoryRef {
    /// Base register (if any).
    pub base: Option<Register>,
    /// Index register (if any).
    pub index: Option<Register>,
    /// Scale factor for index (1, 2, 4, or 8).
    pub scale: u8,
    /// Displacement/offset.
    pub displacement: i64,
    /// Access size in bytes.
    pub size: u8,
    /// Segment override (x86 specific).
    pub segment: Option<Register>,
    /// EVEX/SVE-style memory broadcast indicator.
    pub broadcast: bool,
    /// ARM64 index mode (pre/post-indexed with writeback).
    pub index_mode: IndexMode,
}

impl MemoryRef {
    /// Creates a simple memory reference with just a base register.
    pub fn base(reg: Register, size: u8) -> Self {
        Self {
            base: Some(reg),
            index: None,
            scale: 1,
            displacement: 0,
            size,
            segment: None,
            broadcast: false,
            index_mode: IndexMode::None,
        }
    }

    /// Creates a memory reference with base and displacement.
    pub fn base_disp(base: Register, displacement: i64, size: u8) -> Self {
        Self {
            base: Some(base),
            index: None,
            scale: 1,
            displacement,
            size,
            segment: None,
            broadcast: false,
            index_mode: IndexMode::None,
        }
    }

    /// Creates a memory reference with base, displacement, and index mode.
    pub fn base_disp_indexed(
        base: Register,
        displacement: i64,
        size: u8,
        index_mode: IndexMode,
    ) -> Self {
        Self {
            base: Some(base),
            index: None,
            scale: 1,
            displacement,
            size,
            segment: None,
            broadcast: false,
            index_mode,
        }
    }

    /// Creates a memory reference with just a displacement (absolute address).
    pub fn absolute(address: i64, size: u8) -> Self {
        Self {
            base: None,
            index: None,
            scale: 1,
            displacement: address,
            size,
            segment: None,
            broadcast: false,
            index_mode: IndexMode::None,
        }
    }

    /// Creates a full SIB-style memory reference.
    pub fn sib(
        base: Option<Register>,
        index: Option<Register>,
        scale: u8,
        displacement: i64,
        size: u8,
    ) -> Self {
        Self {
            base,
            index,
            scale,
            displacement,
            size,
            segment: None,
            broadcast: false,
            index_mode: IndexMode::None,
        }
    }

    /// Sets the segment override.
    pub fn with_segment(mut self, segment: Register) -> Self {
        self.segment = Some(segment);
        self
    }

    /// Sets EVEX-style broadcast indicator.
    pub fn with_broadcast(mut self, broadcast: bool) -> Self {
        self.broadcast = broadcast;
        self
    }
}

impl std::fmt::Display for Operand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Register(reg) => write!(f, "{}", reg.name()),
            Self::Immediate(imm) => {
                if imm.signed && imm.value < 0 {
                    write!(f, "-{:#x}", -imm.value)
                } else {
                    write!(f, "{:#x}", imm.value)
                }
            }
            Self::Memory(mem) => {
                write!(f, "[")?;
                let mut has_content = false;

                if let Some(ref base) = mem.base {
                    write!(f, "{}", base.name())?;
                    has_content = true;
                }

                if let Some(ref index) = mem.index {
                    if has_content {
                        write!(f, " + ")?;
                    }
                    write!(f, "{}", index.name())?;
                    if mem.scale > 1 {
                        write!(f, "*{}", mem.scale)?;
                    }
                    has_content = true;
                }

                if mem.displacement != 0 {
                    if has_content {
                        if mem.displacement > 0 {
                            write!(f, " + {:#x}", mem.displacement)?;
                        } else {
                            write!(f, " - {:#x}", -mem.displacement)?;
                        }
                    } else {
                        write!(f, "{:#x}", mem.displacement)?;
                    }
                }

                write!(f, "]")?;
                if mem.broadcast {
                    write!(f, "{{bcst}}")?;
                }
                Ok(())
            }
            Self::PcRelative { target, .. } => write!(f, "{:#x}", target),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Architecture, RegisterClass};

    fn make_reg(id: u16, size: u16) -> Register {
        Register::new(Architecture::X86_64, RegisterClass::General, id, size)
    }

    // --- Operand Construction Tests ---

    #[test]
    fn test_operand_reg() {
        let reg = make_reg(0, 64);
        let op = Operand::reg(reg);
        assert!(matches!(op, Operand::Register(_)));
        assert!(op.is_register());
        assert!(!op.is_immediate());
        assert!(!op.is_memory());
    }

    #[test]
    fn test_operand_imm() {
        let op = Operand::imm(42, 32);
        assert!(matches!(op, Operand::Immediate(_)));
        assert!(op.is_immediate());
        assert!(!op.is_register());
        assert!(!op.is_memory());
    }

    #[test]
    fn test_operand_imm_negative() {
        let op = Operand::imm(-100, 32);
        if let Operand::Immediate(imm) = op {
            assert_eq!(imm.value, -100);
            assert!(imm.signed);
        } else {
            panic!("Expected Immediate");
        }
    }

    #[test]
    fn test_operand_imm_unsigned() {
        let op = Operand::imm_unsigned(0xFFFF_FFFF, 32);
        if let Operand::Immediate(imm) = op {
            assert_eq!(imm.value, 0xFFFF_FFFF);
            assert!(!imm.signed);
        } else {
            panic!("Expected Immediate");
        }
    }

    #[test]
    fn test_operand_pc_rel() {
        let op = Operand::pc_rel(0x100, 0x2000);
        if let Operand::PcRelative { offset, target } = op {
            assert_eq!(offset, 0x100);
            assert_eq!(target, 0x2000);
        } else {
            panic!("Expected PcRelative");
        }
    }

    #[test]
    fn test_operand_memory() {
        let reg = make_reg(0, 64);
        let mem = MemoryRef::base(reg, 8);
        let op = Operand::Memory(mem);
        assert!(op.is_memory());
        assert!(!op.is_register());
        assert!(!op.is_immediate());
    }

    // --- Immediate Tests ---

    #[test]
    fn test_immediate_as_u64() {
        let imm = Immediate {
            value: 0x1234_5678_9ABC_DEF0,
            size: 64,
            signed: false,
        };
        assert_eq!(imm.as_u64(), 0x1234_5678_9ABC_DEF0);
    }

    #[test]
    fn test_immediate_as_i64() {
        let imm = Immediate {
            value: -1,
            size: 64,
            signed: true,
        };
        assert_eq!(imm.as_i64(), -1);
    }

    #[test]
    fn test_immediate_as_i64_positive() {
        let imm = Immediate {
            value: 42,
            size: 32,
            signed: true,
        };
        assert_eq!(imm.as_i64(), 42);
    }

    // --- MemoryRef Tests ---

    #[test]
    fn test_memoryref_base() {
        let reg = make_reg(0, 64);
        let mem = MemoryRef::base(reg, 8);

        assert!(mem.base.is_some());
        assert!(mem.index.is_none());
        assert_eq!(mem.scale, 1);
        assert_eq!(mem.displacement, 0);
        assert_eq!(mem.size, 8);
        assert!(mem.segment.is_none());
        assert!(!mem.broadcast);
    }

    #[test]
    fn test_memoryref_base_disp() {
        let reg = make_reg(5, 64); // rbp
        let mem = MemoryRef::base_disp(reg, -8, 8);

        assert!(mem.base.is_some());
        assert_eq!(mem.displacement, -8);
        assert_eq!(mem.size, 8);
    }

    #[test]
    fn test_memoryref_absolute() {
        let mem = MemoryRef::absolute(0x601000, 4);

        assert!(mem.base.is_none());
        assert!(mem.index.is_none());
        assert_eq!(mem.displacement, 0x601000);
        assert_eq!(mem.size, 4);
    }

    #[test]
    fn test_memoryref_sib() {
        let base = make_reg(0, 64); // rax
        let index = make_reg(1, 64); // rcx
        let mem = MemoryRef::sib(Some(base), Some(index), 4, 0x100, 8);

        assert!(mem.base.is_some());
        assert!(mem.index.is_some());
        assert_eq!(mem.scale, 4);
        assert_eq!(mem.displacement, 0x100);
        assert_eq!(mem.size, 8);
    }

    #[test]
    fn test_memoryref_sib_no_base() {
        let index = make_reg(1, 64);
        let mem = MemoryRef::sib(None, Some(index), 8, 0x1000, 4);

        assert!(mem.base.is_none());
        assert!(mem.index.is_some());
        assert_eq!(mem.scale, 8);
    }

    #[test]
    fn test_memoryref_with_segment() {
        let base = make_reg(0, 64);
        let fs = Register::new(Architecture::X86_64, RegisterClass::Segment, 35, 16);
        let mem = MemoryRef::base(base, 8).with_segment(fs);

        assert!(mem.segment.is_some());
    }

    #[test]
    fn test_memoryref_with_broadcast() {
        let base = make_reg(0, 64);
        let mem = MemoryRef::base(base, 4).with_broadcast(true);
        assert!(mem.broadcast);
    }

    // --- Display Tests ---

    #[test]
    fn test_operand_display_register() {
        let reg = make_reg(0, 64); // rax
        let op = Operand::reg(reg);
        let display = format!("{}", op);
        assert_eq!(display, "rax");
    }

    #[test]
    fn test_operand_display_immediate_positive() {
        let op = Operand::imm(42, 32);
        let display = format!("{}", op);
        assert_eq!(display, "0x2a");
    }

    #[test]
    fn test_operand_display_immediate_negative() {
        let op = Operand::imm(-10, 32);
        let display = format!("{}", op);
        assert_eq!(display, "-0xa");
    }

    #[test]
    fn test_operand_display_immediate_unsigned() {
        let op = Operand::imm_unsigned(255, 8);
        let display = format!("{}", op);
        assert_eq!(display, "0xff");
    }

    #[test]
    fn test_operand_display_memory_base() {
        let reg = make_reg(0, 64); // rax
        let mem = MemoryRef::base(reg, 8);
        let op = Operand::Memory(mem);
        let display = format!("{}", op);
        assert_eq!(display, "[rax]");
    }

    #[test]
    fn test_operand_display_memory_base_disp_positive() {
        let reg = make_reg(5, 64); // rbp
        let mem = MemoryRef::base_disp(reg, 0x10, 8);
        let op = Operand::Memory(mem);
        let display = format!("{}", op);
        assert_eq!(display, "[rbp + 0x10]");
    }

    #[test]
    fn test_operand_display_memory_base_disp_negative() {
        let reg = make_reg(5, 64); // rbp
        let mem = MemoryRef::base_disp(reg, -8, 8);
        let op = Operand::Memory(mem);
        let display = format!("{}", op);
        assert_eq!(display, "[rbp - 0x8]");
    }

    #[test]
    fn test_operand_display_memory_absolute() {
        let mem = MemoryRef::absolute(0x601000, 4);
        let op = Operand::Memory(mem);
        let display = format!("{}", op);
        assert_eq!(display, "[0x601000]");
    }

    #[test]
    fn test_operand_display_memory_sib() {
        let base = make_reg(0, 64); // rax
        let index = make_reg(1, 64); // rcx
        let mem = MemoryRef::sib(Some(base), Some(index), 4, 0, 8);
        let op = Operand::Memory(mem);
        let display = format!("{}", op);
        assert_eq!(display, "[rax + rcx*4]");
    }

    #[test]
    fn test_operand_display_memory_sib_with_disp() {
        let base = make_reg(0, 64); // rax
        let index = make_reg(1, 64); // rcx
        let mem = MemoryRef::sib(Some(base), Some(index), 8, 0x100, 8);
        let op = Operand::Memory(mem);
        let display = format!("{}", op);
        assert_eq!(display, "[rax + rcx*8 + 0x100]");
    }

    #[test]
    fn test_operand_display_memory_broadcast() {
        let reg = make_reg(0, 64); // rax
        let mem = MemoryRef::base(reg, 4).with_broadcast(true);
        let op = Operand::Memory(mem);
        let display = format!("{}", op);
        assert_eq!(display, "[rax]{bcst}");
    }

    #[test]
    fn test_operand_display_pc_relative() {
        let op = Operand::pc_rel(0x100, 0x401000);
        let display = format!("{}", op);
        assert_eq!(display, "0x401000");
    }

    // --- Equality Tests ---

    #[test]
    fn test_operand_equality_register() {
        let reg1 = make_reg(0, 64);
        let reg2 = make_reg(0, 64);
        let reg3 = make_reg(1, 64);

        assert_eq!(Operand::reg(reg1), Operand::reg(reg2));
        assert_ne!(Operand::reg(reg1), Operand::reg(reg3));
    }

    #[test]
    fn test_operand_equality_immediate() {
        let op1 = Operand::imm(42, 32);
        let op2 = Operand::imm(42, 32);
        let op3 = Operand::imm(43, 32);

        assert_eq!(op1, op2);
        assert_ne!(op1, op3);
    }

    #[test]
    fn test_operand_equality_memory() {
        let reg = make_reg(0, 64);
        let mem1 = MemoryRef::base(reg, 8);
        let mem2 = MemoryRef::base(reg, 8);
        let mem3 = MemoryRef::base_disp(reg, 0x10, 8);

        assert_eq!(Operand::Memory(mem1.clone()), Operand::Memory(mem2));
        assert_ne!(Operand::Memory(mem1), Operand::Memory(mem3));
    }
}
