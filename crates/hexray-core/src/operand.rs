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
        }
    }

    /// Sets the segment override.
    pub fn with_segment(mut self, segment: Register) -> Self {
        self.segment = Some(segment);
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

                write!(f, "]")
            }
            Self::PcRelative { target, .. } => write!(f, "{:#x}", target),
        }
    }
}
