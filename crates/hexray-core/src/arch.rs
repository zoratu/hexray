//! Architecture identification and properties.

/// Supported architectures (CPU and GPU).
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
    /// NVIDIA CUDA (SASS or PTX).
    Cuda(CudaArchitecture),
    /// Unknown architecture
    Unknown(u16),
}

impl Architecture {
    /// Returns the pointer size in bytes for this architecture.
    pub fn pointer_size(&self) -> usize {
        match self {
            Self::X86_64 | Self::Arm64 | Self::RiscV64 => 8,
            Self::X86 | Self::Arm | Self::RiscV32 => 4,
            Self::Cuda(c) => c.pointer_size(),
            Self::Unknown(_) => 8, // Default assumption
        }
    }

    /// Returns whether this is a 64-bit architecture.
    pub fn is_64bit(&self) -> bool {
        matches!(self, Self::X86_64 | Self::Arm64 | Self::RiscV64)
            || matches!(self, Self::Cuda(c) if c.is_64bit())
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
            Self::Cuda(c) => c.name(),
            Self::Unknown(_) => "unknown",
        }
    }

    /// Returns true if this architecture is a GPU architecture.
    pub fn is_gpu(&self) -> bool {
        matches!(self, Self::Cuda(_))
    }
}

/// CUDA flavor: native SASS binary or PTX virtual ISA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CudaArchitecture {
    /// Native SASS machine code for a specific streaming-multiprocessor target.
    Sass(SmArchitecture),
    /// PTX virtual ISA, optionally targeting a specific SM.
    Ptx(PtxVersion),
}

impl CudaArchitecture {
    /// CUDA targets use 64-bit addresses on all modern SM families (sm_3.0+).
    pub fn pointer_size(&self) -> usize {
        match self {
            Self::Sass(_) => 8,
            Self::Ptx(p) => (p.address_size as usize).max(1),
        }
    }

    pub fn is_64bit(&self) -> bool {
        self.pointer_size() == 8
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Sass(_) => "cuda-sass",
            Self::Ptx(_) => "cuda-ptx",
        }
    }
}

/// A specific SM (streaming multiprocessor) target for native SASS.
///
/// Encodes the compute capability (major.minor) plus architecture-specific
/// variant suffixes (e.g. `sm_90a`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SmArchitecture {
    /// Human-friendly family identifier. Provides a stable handle even when
    /// the numeric major/minor are uninterpreted.
    pub family: SmFamily,
    /// Compute capability major number (e.g. `8` for sm_80).
    pub major: u8,
    /// Compute capability minor number (e.g. `0` for sm_80).
    pub minor: u8,
    /// Target-specific variant (base, `a` suffix, `f` suffix, etc.).
    pub variant: SmVariant,
}

impl SmArchitecture {
    /// Construct an `SmArchitecture` from raw compute-capability numbers.
    pub fn new(major: u8, minor: u8, variant: SmVariant) -> Self {
        Self {
            family: SmFamily::from_major_minor(major, minor),
            major,
            minor,
            variant,
        }
    }

    /// Returns the canonical `sm_XY[v]` name used by nvcc / nvdisasm.
    ///
    /// Falls back to `sm_?` when the numbers cannot be determined.
    pub fn canonical_name(&self) -> String {
        if self.major == 0 && self.minor == 0 {
            return "sm_?".to_string();
        }
        let mut s = format!("sm_{}{}", self.major, self.minor);
        match self.variant {
            SmVariant::Base => {}
            SmVariant::A => s.push('a'),
            SmVariant::F => s.push('f'),
            SmVariant::Other(b) => s.push(b as char),
        }
        s
    }

    /// A fully-unknown SM target. Used when the ELF `e_flags` field could not
    /// be interpreted.
    pub const UNKNOWN: Self = Self {
        family: SmFamily::Unknown,
        major: 0,
        minor: 0,
        variant: SmVariant::Base,
    };
}

/// Major families in NVIDIA's compute-capability lineage.
///
/// `Unknown` is used when the numeric major/minor do not fall into a known
/// family — this is a forward-compatibility hatch, not an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SmFamily {
    Tesla,     // sm_1x (obsolete)
    Fermi,     // sm_2x (obsolete)
    Kepler,    // sm_3x
    Maxwell,   // sm_5x
    Pascal,    // sm_6x
    Volta,     // sm_7.0 / 7.2
    Turing,    // sm_7.5
    Ampere,    // sm_8.0 / 8.6 / 8.7
    Ada,       // sm_8.9
    Hopper,    // sm_9.0
    Blackwell, // sm_10.x
    Unknown,
}

impl SmFamily {
    /// Maps compute-capability numbers to their marketing family.
    pub fn from_major_minor(major: u8, minor: u8) -> Self {
        match (major, minor) {
            (1, _) => Self::Tesla,
            (2, _) => Self::Fermi,
            (3, _) => Self::Kepler,
            (5, _) => Self::Maxwell,
            (6, _) => Self::Pascal,
            (7, 0) | (7, 2) => Self::Volta,
            (7, 5) => Self::Turing,
            (8, 0) | (8, 6) | (8, 7) => Self::Ampere,
            (8, 9) => Self::Ada,
            (9, _) => Self::Hopper,
            (10, _) => Self::Blackwell,
            _ => Self::Unknown,
        }
    }
}

/// SM target variant suffix. `sm_90a` carries architecture-specific
/// instructions not available in the base target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SmVariant {
    /// No suffix (e.g. `sm_80`, `sm_90`).
    Base,
    /// `a` suffix — architecture-specific feature subset (e.g. `sm_90a`).
    A,
    /// `f` suffix — forward-compatible family target (e.g. `sm_100f`).
    F,
    /// Any other single-char suffix encountered in the wild.
    Other(u8),
}

/// PTX virtual-ISA version, optionally bound to a concrete SM target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PtxVersion {
    /// `.version` major number.
    pub major: u8,
    /// `.version` minor number.
    pub minor: u8,
    /// `.address_size` directive (8 for 64-bit, 4 for 32-bit).
    pub address_size: u8,
    /// `.target` SM, when known.
    pub target: Option<SmArchitecture>,
}

impl PtxVersion {
    pub const UNKNOWN: Self = Self {
        major: 0,
        minor: 0,
        address_size: 8,
        target: None,
    };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cuda_name_and_gpu_flag() {
        let sm80 = Architecture::Cuda(CudaArchitecture::Sass(SmArchitecture::new(
            8,
            0,
            SmVariant::Base,
        )));
        assert_eq!(sm80.name(), "cuda-sass");
        assert!(sm80.is_gpu());
        assert!(sm80.is_64bit());
        assert_eq!(sm80.pointer_size(), 8);
    }

    #[test]
    fn sm_canonical_names() {
        assert_eq!(
            SmArchitecture::new(8, 0, SmVariant::Base).canonical_name(),
            "sm_80"
        );
        assert_eq!(
            SmArchitecture::new(9, 0, SmVariant::A).canonical_name(),
            "sm_90a"
        );
        assert_eq!(
            SmArchitecture::new(10, 0, SmVariant::F).canonical_name(),
            "sm_100f"
        );
        assert_eq!(SmArchitecture::UNKNOWN.canonical_name(), "sm_?");
    }

    #[test]
    fn sm_family_mapping() {
        assert_eq!(SmFamily::from_major_minor(8, 0), SmFamily::Ampere);
        assert_eq!(SmFamily::from_major_minor(8, 9), SmFamily::Ada);
        assert_eq!(SmFamily::from_major_minor(9, 0), SmFamily::Hopper);
        assert_eq!(SmFamily::from_major_minor(7, 5), SmFamily::Turing);
        // Forward-compat: unknown numeric must not panic or misclassify.
        assert_eq!(SmFamily::from_major_minor(42, 0), SmFamily::Unknown);
    }

    #[test]
    fn cuda_arch_is_distinguishable_from_cpu() {
        let cuda = Architecture::Cuda(CudaArchitecture::Sass(SmArchitecture::UNKNOWN));
        let x86 = Architecture::X86_64;
        assert_ne!(cuda, x86);
        assert!(!x86.is_gpu());
    }

    #[test]
    fn ptx_pointer_size_honors_address_size_directive() {
        let ptx64 = Architecture::Cuda(CudaArchitecture::Ptx(PtxVersion {
            major: 8,
            minor: 3,
            address_size: 8,
            target: None,
        }));
        let ptx32 = Architecture::Cuda(CudaArchitecture::Ptx(PtxVersion {
            major: 8,
            minor: 3,
            address_size: 4,
            target: None,
        }));
        assert_eq!(ptx64.pointer_size(), 8);
        assert_eq!(ptx32.pointer_size(), 4);
    }
}
