//! Architecture identification and properties.

/// Supported CPU architectures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Architecture {
    /// x86-64 / AMD64
    X86_64,
    /// 32-bit x86
    X86,
    /// ARM 64-bit (AArch64)
    Arm64,
    /// ARM 32-bit
    Arm,
    /// RISC-V 64-bit
    RiscV64,
    /// RISC-V 32-bit
    RiscV32,
    /// Unknown architecture
    Unknown(u16),
}

impl Architecture {
    /// Returns the pointer size in bytes for this architecture.
    pub fn pointer_size(&self) -> usize {
        match self {
            Self::X86_64 | Self::Arm64 | Self::RiscV64 => 8,
            Self::X86 | Self::Arm | Self::RiscV32 => 4,
            Self::Unknown(_) => 8, // Default assumption
        }
    }

    /// Returns whether this is a 64-bit architecture.
    pub fn is_64bit(&self) -> bool {
        matches!(self, Self::X86_64 | Self::Arm64 | Self::RiscV64)
    }

    /// Returns the name of this architecture.
    pub fn name(&self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::X86 => "x86",
            Self::Arm64 => "arm64",
            Self::Arm => "arm",
            Self::RiscV64 => "riscv64",
            Self::RiscV32 => "riscv32",
            Self::Unknown(_) => "unknown",
        }
    }
}

/// Binary bitness (32-bit or 64-bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Bitness {
    Bits32,
    Bits64,
}

/// Byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Endianness {
    Little,
    Big,
}
