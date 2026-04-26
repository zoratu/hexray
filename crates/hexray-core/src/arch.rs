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
    /// AMD GPU (GCN / RDNA / CDNA family).
    Amdgpu(GfxArchitecture),
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
            Self::Amdgpu(_) => 8,
            Self::Unknown(_) => 8, // Default assumption
        }
    }

    /// Returns whether this is a 64-bit architecture.
    pub fn is_64bit(&self) -> bool {
        matches!(
            self,
            Self::X86_64 | Self::Arm64 | Self::RiscV64 | Self::Amdgpu(_)
        ) || matches!(self, Self::Cuda(c) if c.is_64bit())
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
            Self::Amdgpu(_) => "amdgpu",
            Self::Unknown(_) => "unknown",
        }
    }

    /// Returns true if this architecture is a GPU architecture.
    pub fn is_gpu(&self) -> bool {
        matches!(self, Self::Cuda(_) | Self::Amdgpu(_))
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

/// A specific AMDGPU GFX target.
///
/// Encodes the family (GCN/CDNA/RDNA), the major.minor.stepping triple
/// (e.g. `9.0.6` = `gfx906`, `10.3.0` = `gfx1030`), and the per-target
/// `xnack` / `sramecc` feature TriStates that ship in the AMDGPU ELF
/// `e_flags` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GfxArchitecture {
    /// Marketing family (GCN3 / GCN4 / GCN5 / CDNA1 / CDNA2 / CDNA3 / RDNA1 / RDNA2 / RDNA3 / RDNA4).
    pub family: GfxFamily,
    /// GFX major number (9, 10, 11, 12).
    pub major: u8,
    /// GFX minor number.
    pub minor: u8,
    /// GFX stepping. For `gfx906` this is `6`; for `gfx90a` it's `0xA`.
    pub stepping: u8,
    /// `xnack` (replay-on-page-fault) feature.
    pub xnack: TriState,
    /// `sramecc` (SRAM error correction) feature.
    pub sramecc: TriState,
}

impl GfxArchitecture {
    pub fn new(major: u8, minor: u8, stepping: u8) -> Self {
        Self {
            family: GfxFamily::from_target(major, minor, stepping),
            major,
            minor,
            stepping,
            xnack: TriState::Unspecified,
            sramecc: TriState::Unspecified,
        }
    }

    /// Returns the canonical `gfxNNN[v]` name used by `clang
    /// -target=amdgcn-amd-amdhsa --offload-arch=...` and `llvm-objdump
    /// --mcpu=...`.
    ///
    /// For `gfx90a` and similar, the stepping renders as a single hex
    /// digit (`a`, not `10`).
    pub fn canonical_name(&self) -> String {
        if self.major == 0 {
            return "gfx?".to_string();
        }
        let stepping_char = match self.stepping {
            0..=9 => (b'0' + self.stepping) as char,
            10..=15 => (b'a' + (self.stepping - 10)) as char,
            _ => '?',
        };
        format!("gfx{}{}{}", self.major, self.minor, stepping_char)
    }

    /// Renders the full target-id including feature suffixes
    /// (`gfx90a:xnack+:sramecc-`), the format LLVM accepts for
    /// `--offload-arch`. Returns the bare canonical name when no
    /// features are explicitly set.
    pub fn target_id(&self) -> String {
        let mut s = self.canonical_name();
        if let Some(suffix) = self.xnack.suffix("xnack") {
            s.push(':');
            s.push_str(&suffix);
        }
        if let Some(suffix) = self.sramecc.suffix("sramecc") {
            s.push(':');
            s.push_str(&suffix);
        }
        s
    }

    pub const UNKNOWN: Self = Self {
        family: GfxFamily::Unknown,
        major: 0,
        minor: 0,
        stepping: 0,
        xnack: TriState::Unspecified,
        sramecc: TriState::Unspecified,
    };
}

/// Major families in AMD's GPU lineage.
///
/// `Unknown` is the forward-compatibility hatch — a future GFX target
/// not yet recognised here parses as `Unknown` rather than failing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum GfxFamily {
    /// Volcanic Islands / Fiji (gfx8).
    Gcn3,
    /// Polaris (gfx8.0.3 also fits).
    Gcn4,
    /// Vega / Vega20 (gfx9.0.x).
    Gcn5,
    /// Arcturus / MI100 (gfx908).
    Cdna1,
    /// Aldebaran / MI200 series (gfx90a).
    Cdna2,
    /// Aqua Vanjaram / MI300 series (gfx940 / gfx941 / gfx942).
    Cdna3,
    /// Navi 1x (gfx10.1.x).
    Rdna1,
    /// Navi 2x (gfx10.3.x).
    Rdna2,
    /// Navi 3x (gfx11.x.x).
    Rdna3,
    /// Navi 4x (gfx12.x.x).
    Rdna4,
    Unknown,
}

impl GfxFamily {
    /// Maps a raw `(major, minor, stepping)` triple to its marketing
    /// family. `Unknown` is returned for triples not recognised here —
    /// tests and the `Architecture::name()` API stay forward-compatible.
    pub fn from_target(major: u8, minor: u8, stepping: u8) -> Self {
        match (major, minor, stepping) {
            (8, 0, 0..=4) => Self::Gcn3,
            (8, 0, 5..) => Self::Gcn4,
            (9, 0, 0 | 1 | 2 | 4 | 6 | 9 | 0xC) => Self::Gcn5,
            (9, 0, 8) => Self::Cdna1,
            (9, 0, 0xA) => Self::Cdna2,
            (9, 4, _) => Self::Cdna3,
            (10, 1, _) => Self::Rdna1,
            (10, 3, _) => Self::Rdna2,
            (11, _, _) => Self::Rdna3,
            (12, _, _) => Self::Rdna4,
            _ => Self::Unknown,
        }
    }
}

/// Tri-state encoding for AMDGPU `e_flags` feature bits (`xnack`,
/// `sramecc`).
///
/// The AMDGPU V4 ABI reserves two bits per feature with three
/// meaningful values: "any" (unspecified — code is feature-agnostic),
/// "off" (code requires the feature off), "on" (code requires it on).
/// V3 ABI used a single bit, mapped here to `Off`/`On`. The fourth
/// raw bit pattern is invalid; we surface it as `Unspecified` rather
/// than panicking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TriState {
    /// Unspecified / "any" — code works with the feature on or off.
    Unspecified,
    /// Code requires the feature off.
    Off,
    /// Code requires the feature on.
    On,
}

impl TriState {
    /// Renders the LLVM target-id suffix: `name+`, `name-`, or `None`
    /// when unspecified.
    pub fn suffix(self, name: &str) -> Option<String> {
        match self {
            Self::Unspecified => None,
            Self::Off => Some(format!("{name}-")),
            Self::On => Some(format!("{name}+")),
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

    #[test]
    fn amdgpu_canonical_names_round_trip() {
        assert_eq!(GfxArchitecture::new(9, 0, 6).canonical_name(), "gfx906");
        assert_eq!(GfxArchitecture::new(9, 0, 0xA).canonical_name(), "gfx90a");
        assert_eq!(GfxArchitecture::new(10, 3, 0).canonical_name(), "gfx1030");
        assert_eq!(GfxArchitecture::new(11, 0, 0).canonical_name(), "gfx1100");
        assert_eq!(GfxArchitecture::new(12, 0, 0).canonical_name(), "gfx1200");
        assert_eq!(GfxArchitecture::UNKNOWN.canonical_name(), "gfx?");
    }

    #[test]
    fn amdgpu_family_mapping() {
        assert_eq!(GfxFamily::from_target(9, 0, 6), GfxFamily::Gcn5);
        assert_eq!(GfxFamily::from_target(9, 0, 8), GfxFamily::Cdna1);
        assert_eq!(GfxFamily::from_target(9, 0, 0xA), GfxFamily::Cdna2);
        assert_eq!(GfxFamily::from_target(9, 4, 2), GfxFamily::Cdna3);
        assert_eq!(GfxFamily::from_target(10, 1, 2), GfxFamily::Rdna1);
        assert_eq!(GfxFamily::from_target(10, 3, 0), GfxFamily::Rdna2);
        assert_eq!(GfxFamily::from_target(11, 0, 0), GfxFamily::Rdna3);
        assert_eq!(GfxFamily::from_target(12, 0, 0), GfxFamily::Rdna4);
        // Forward-compat: an unrecognized triple must not panic.
        assert_eq!(GfxFamily::from_target(99, 0, 0), GfxFamily::Unknown);
    }

    #[test]
    fn amdgpu_target_id_includes_feature_suffixes() {
        let mut a = GfxArchitecture::new(9, 0, 0xA);
        a.xnack = TriState::On;
        a.sramecc = TriState::Off;
        assert_eq!(a.target_id(), "gfx90a:xnack+:sramecc-");

        let plain = GfxArchitecture::new(10, 3, 0);
        assert_eq!(plain.target_id(), "gfx1030");
    }

    #[test]
    fn amdgpu_arch_is_gpu_and_64bit() {
        let arch = Architecture::Amdgpu(GfxArchitecture::new(9, 0, 6));
        assert_eq!(arch.name(), "amdgpu");
        assert!(arch.is_gpu());
        assert!(arch.is_64bit());
        assert_eq!(arch.pointer_size(), 8);
    }
}
