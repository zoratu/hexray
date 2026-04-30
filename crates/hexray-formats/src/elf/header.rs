//! ELF header parsing.

// File-level allow: bit-math + slice indexing in this parser/decoder
// is bounds-checked at function entry. Per-site annotations would be
// noise; the runtime fuzz gate (`scripts/run-fuzz-corpus`) catches
// actual crashes. New code should prefer `.get()` + `checked_*`.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use crate::ParseError;
use hexray_core::{
    Architecture, CudaArchitecture, Endianness, GfxArchitecture, SmArchitecture, SmVariant,
    TriState,
};

/// ELF magic bytes.
pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// ELF class (32-bit or 64-bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfClass {
    Elf32,
    Elf64,
}

/// ELF file type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfType {
    /// No file type.
    None,
    /// Relocatable file.
    Relocatable,
    /// Executable file.
    Executable,
    /// Shared object file.
    SharedObject,
    /// Core file.
    Core,
    /// Other type.
    Other(u16),
}

impl From<u16> for ElfType {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Relocatable,
            2 => Self::Executable,
            3 => Self::SharedObject,
            4 => Self::Core,
            other => Self::Other(other),
        }
    }
}

/// Machine architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Machine {
    None,
    X86,
    X86_64,
    Arm,
    Arm64,
    RiscV,
    /// NVIDIA CUDA (`EM_CUDA = 190`). Encodes SASS machine code for a specific
    /// SM target; the compute-capability is carried in `e_flags`.
    Cuda,
    /// AMD GPU (`EM_AMDGPU = 224`). Encodes GCN/CDNA/RDNA machine code; the
    /// GFX target and `xnack` / `sramecc` features are carried in `e_flags`.
    Amdgpu,
    Other(u16),
}

impl Machine {
    pub fn from_u16(value: u16) -> Self {
        match value {
            0 => Self::None,
            3 => Self::X86,
            40 => Self::Arm,
            62 => Self::X86_64,
            183 => Self::Arm64,
            // NVIDIA CUDA. Reserved as EM_CUDA in the NVIDIA toolchain and
            // recognised by binutils/LLVM. Cubins emitted by `ptxas` carry this.
            190 => Self::Cuda,
            // AMD GPU. EM_AMDGPU in LLVM. Code objects emitted by `clang
            // -target=amdgcn-amd-amdhsa` and `hipcc --genco` carry this.
            224 => Self::Amdgpu,
            243 => Self::RiscV,
            other => Self::Other(other),
        }
    }
}

/// Parsed ELF header.
#[derive(Debug)]
pub struct ElfHeader {
    /// ELF class (32 or 64 bit).
    pub class: ElfClass,
    /// Endianness.
    pub endianness: Endianness,
    /// ELF version (should be 1).
    pub version: u8,
    /// OS/ABI identification.
    pub osabi: u8,
    /// ABI version.
    pub abi_version: u8,
    /// File type.
    pub file_type: ElfType,
    /// Machine architecture.
    pub machine: Machine,
    /// Entry point virtual address.
    pub e_entry: u64,
    /// Program header table file offset.
    pub e_phoff: u64,
    /// Section header table file offset.
    pub e_shoff: u64,
    /// Processor-specific flags.
    pub e_flags: u32,
    /// ELF header size.
    pub e_ehsize: u16,
    /// Program header table entry size.
    pub e_phentsize: u16,
    /// Program header table entry count.
    pub e_phnum: u16,
    /// Section header table entry size.
    pub e_shentsize: u16,
    /// Section header table entry count.
    pub e_shnum: u16,
    /// Section name string table index.
    pub e_shstrndx: u16,
}

impl ElfHeader {
    /// Minimum size of the ELF identification bytes.
    const EI_NIDENT: usize = 16;

    /// Parse an ELF header from bytes.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        // Check minimum size for ident bytes
        if data.len() < Self::EI_NIDENT {
            return Err(ParseError::too_short(Self::EI_NIDENT, data.len()));
        }

        // Check magic
        if data[0..4] != ELF_MAGIC {
            return Err(ParseError::invalid_magic("ELF", &data[0..4]));
        }

        // Parse ELF class
        let class = match data[4] {
            1 => ElfClass::Elf32,
            2 => ElfClass::Elf64,
            _ => {
                return Err(ParseError::invalid_structure(
                    "ELF header",
                    4,
                    format!("invalid ELF class: {}", data[4]),
                ))
            }
        };

        // Parse endianness
        let endianness = match data[5] {
            1 => Endianness::Little,
            2 => Endianness::Big,
            _ => {
                return Err(ParseError::invalid_structure(
                    "ELF header",
                    5,
                    format!("invalid endianness: {}", data[5]),
                ))
            }
        };

        let version = data[6];
        let osabi = data[7];
        let abi_version = data[8];

        // Parse the rest based on class
        match class {
            ElfClass::Elf32 => Self::parse_elf32(data, endianness, version, osabi, abi_version),
            ElfClass::Elf64 => Self::parse_elf64(data, endianness, version, osabi, abi_version),
        }
    }

    fn parse_elf32(
        data: &[u8],
        endianness: Endianness,
        version: u8,
        osabi: u8,
        abi_version: u8,
    ) -> Result<Self, ParseError> {
        const ELF32_HEADER_SIZE: usize = 52;

        if data.len() < ELF32_HEADER_SIZE {
            return Err(ParseError::too_short(ELF32_HEADER_SIZE, data.len()));
        }

        let read_u16 = |offset: usize| -> u16 {
            let bytes = [data[offset], data[offset + 1]];
            match endianness {
                Endianness::Little => u16::from_le_bytes(bytes),
                Endianness::Big => u16::from_be_bytes(bytes),
            }
        };

        let read_u32 = |offset: usize| -> u32 {
            let bytes = [
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ];
            match endianness {
                Endianness::Little => u32::from_le_bytes(bytes),
                Endianness::Big => u32::from_be_bytes(bytes),
            }
        };

        Ok(Self {
            class: ElfClass::Elf32,
            endianness,
            version,
            osabi,
            abi_version,
            file_type: ElfType::from(read_u16(16)),
            machine: Machine::from_u16(read_u16(18)),
            e_entry: read_u32(24) as u64,
            e_phoff: read_u32(28) as u64,
            e_shoff: read_u32(32) as u64,
            e_flags: read_u32(36),
            e_ehsize: read_u16(40),
            e_phentsize: read_u16(42),
            e_phnum: read_u16(44),
            e_shentsize: read_u16(46),
            e_shnum: read_u16(48),
            e_shstrndx: read_u16(50),
        })
    }

    fn parse_elf64(
        data: &[u8],
        endianness: Endianness,
        version: u8,
        osabi: u8,
        abi_version: u8,
    ) -> Result<Self, ParseError> {
        const ELF64_HEADER_SIZE: usize = 64;

        if data.len() < ELF64_HEADER_SIZE {
            return Err(ParseError::too_short(ELF64_HEADER_SIZE, data.len()));
        }

        let read_u16 = |offset: usize| -> u16 {
            let bytes = [data[offset], data[offset + 1]];
            match endianness {
                Endianness::Little => u16::from_le_bytes(bytes),
                Endianness::Big => u16::from_be_bytes(bytes),
            }
        };

        let read_u32 = |offset: usize| -> u32 {
            let bytes = [
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ];
            match endianness {
                Endianness::Little => u32::from_le_bytes(bytes),
                Endianness::Big => u32::from_be_bytes(bytes),
            }
        };

        let read_u64 = |offset: usize| -> u64 {
            let bytes = [
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ];
            match endianness {
                Endianness::Little => u64::from_le_bytes(bytes),
                Endianness::Big => u64::from_be_bytes(bytes),
            }
        };

        Ok(Self {
            class: ElfClass::Elf64,
            endianness,
            version,
            osabi,
            abi_version,
            file_type: ElfType::from(read_u16(16)),
            machine: Machine::from_u16(read_u16(18)),
            e_entry: read_u64(24),
            e_phoff: read_u64(32),
            e_shoff: read_u64(40),
            e_flags: read_u32(48),
            e_ehsize: read_u16(52),
            e_phentsize: read_u16(54),
            e_phnum: read_u16(56),
            e_shentsize: read_u16(58),
            e_shnum: read_u16(60),
            e_shstrndx: read_u16(62),
        })
    }

    /// Returns the architecture for this ELF.
    pub fn architecture(&self) -> Architecture {
        match (self.machine, self.class) {
            (Machine::X86_64, _) => Architecture::X86_64,
            (Machine::X86, _) => Architecture::X86,
            (Machine::Arm64, _) => Architecture::Arm64,
            (Machine::Arm, _) => Architecture::Arm,
            (Machine::RiscV, ElfClass::Elf64) => Architecture::RiscV64,
            (Machine::RiscV, ElfClass::Elf32) => Architecture::RiscV32,
            (Machine::Cuda, _) => Architecture::Cuda(CudaArchitecture::Sass(sm_from_cuda_elf(
                self.abi_version,
                self.e_flags,
            ))),
            (Machine::Amdgpu, _) => {
                Architecture::Amdgpu(gfx_from_amdgpu_elf(self.abi_version, self.e_flags))
            }
            (Machine::Other(m), _) => Architecture::Unknown(m),
            (Machine::None, _) => Architecture::Unknown(0),
        }
    }
}

/// Decode an SM target from an NVIDIA CUBIN's `EI_ABIVERSION` and `e_flags`.
///
/// NVIDIA has shipped two incompatible bit layouts for `e_flags`:
///
/// - **V1** (`EI_ABIVERSION = 7`, Ampere/Ada/Hopper-era cubins):
///   - bits 0..8  — real SM code (`major*10 + minor`)
///   - bit 8  (`0x100`)  — `EF_CUDA_TEXMODE_UNIFIED`
///   - bit 9  (`0x200`)  — `EF_CUDA_TEXMODE_INDEPENDANT`
///   - bit 10 (`0x400`)  — `EF_CUDA_64BIT_ADDRESS`
///   - bit 11 (`0x800`)  — `EF_CUDA_ACCELERATORS_V1` (the `a` variant, e.g. `sm_90a`)
///   - bit 12 (`0x1000`) — `EF_CUDA_SW_FLAG_V2` (undocumented)
///   - bits 16..24 — PTX virtual-arch code (`compute_XY`)
///
/// - **V2** (`EI_ABIVERSION = 8`, Blackwell and later):
///   - bit 3 (`0x8`) — `EF_CUDA_ACCELERATORS` (the `a` variant)
///   - bits 8..16   — real SM code
///   - bits 16..24  — PTX virtual-arch code
///
/// The `f` forward-compat suffix (`sm_100f`) is *not* recoverable here:
/// NVIDIA documents that `code=sm_100` and `code=sm_100f` emit identical
/// cubins. `f` only exists at `nvcc`/fatbin target-selection level.
///
/// Source: LLVM `llvm/include/llvm/BinaryFormat/ELF.h` `EF_CUDA_*` constants
/// and `llvm-readobj` CUDA decode logic.
fn sm_from_cuda_elf(abi_version: u8, e_flags: u32) -> SmArchitecture {
    const EF_CUDA_V1_ACCELERATORS: u32 = 0x800;
    const EF_CUDA_V2_ACCELERATORS: u32 = 0x8;

    // Choose layout. For unknown ABI versions, default to V1 because it is
    // the layout of every cubin shipping today on sm_80..sm_90.
    let (sm_code, accelerator) = match abi_version {
        8 => (
            ((e_flags >> 8) & 0xFF) as u8,
            (e_flags & EF_CUDA_V2_ACCELERATORS) != 0,
        ),
        _ => (
            (e_flags & 0xFF) as u8,
            (e_flags & EF_CUDA_V1_ACCELERATORS) != 0,
        ),
    };

    let major = sm_code / 10;
    let minor = sm_code % 10;

    // Conservative sanity check: known SM majors are 1..=10 today. Anything
    // beyond sm_XX with major > 20 is more likely a different flag layout
    // than a real future SM, so bail to UNKNOWN rather than mislead.
    if sm_code == 0 || !(1..=20).contains(&major) || minor > 9 {
        return SmArchitecture::UNKNOWN;
    }

    let variant = if accelerator {
        SmVariant::A
    } else {
        SmVariant::Base
    };

    SmArchitecture::new(major, minor, variant)
}

/// Decode a GFX target from an AMDGPU ELF's `EI_ABIVERSION` and `e_flags`.
///
/// AMDGPU has shipped multiple `e_flags` layouts (V2 / V3 / V4); LLVM
/// uses the `EI_ABIVERSION` byte to disambiguate. The most common
/// encountered today is V4 (`EI_ABIVERSION = 2`), which is what
/// every recent ROCm and `clang` build emits.
///
/// **V4 layout** (`EI_ABIVERSION = 2`, the modern path):
/// - bits 0..8  — `EF_AMDGPU_MACH` (a *table-encoded* value, not the
///   raw `(major, minor, stepping)` triple — the LLVM table maps e.g.
///   `0x2F → gfx906`, `0x36 → gfx1030`, `0x41 → gfx1100`).
/// - bits 8..10 — `EF_AMDGPU_FEATURE_XNACK_V4` (TriState).
/// - bits 10..12 — `EF_AMDGPU_FEATURE_SRAMECC_V4` (TriState).
///
/// **V3 layout** (`EI_ABIVERSION = 1`, older ROCm):
/// - bits 0..8  — `EF_AMDGPU_MACH` (same table).
/// - bit 8       — `EF_AMDGPU_FEATURE_XNACK_V3` (boolean).
/// - bit 9       — `EF_AMDGPU_FEATURE_SRAMECC_V3` (boolean).
///
/// Source: `llvm/include/llvm/BinaryFormat/ELF.h` `EF_AMDGPU_*`
/// constants and the `mach`-name table in
/// `llvm/lib/ObjectYAML/ELFYAML.cpp` (`AMDGPUElfMagicTable`).
fn gfx_from_amdgpu_elf(abi_version: u8, e_flags: u32) -> GfxArchitecture {
    const EF_AMDGPU_MACH: u32 = 0xff;
    // V4 (modern) uses 2-bit TriState feature fields.
    const EF_AMDGPU_FEATURE_XNACK_V4_SHIFT: u32 = 8;
    const EF_AMDGPU_FEATURE_SRAMECC_V4_SHIFT: u32 = 10;
    const FEATURE_V4_MASK: u32 = 0b11;
    // V3 uses single-bit feature fields.
    const EF_AMDGPU_FEATURE_XNACK_V3: u32 = 1 << 8;
    const EF_AMDGPU_FEATURE_SRAMECC_V3: u32 = 1 << 9;

    let mach = (e_flags & EF_AMDGPU_MACH) as u8;
    let (mut major, mut minor, mut stepping) = mach_to_gfx_target(mach);

    let (xnack, sramecc) = match abi_version {
        // V4 ABI (modern). 2-bit TriState fields.
        2 => {
            let xnack = (e_flags >> EF_AMDGPU_FEATURE_XNACK_V4_SHIFT) & FEATURE_V4_MASK;
            let sramecc = (e_flags >> EF_AMDGPU_FEATURE_SRAMECC_V4_SHIFT) & FEATURE_V4_MASK;
            (tristate_v4(xnack), tristate_v4(sramecc))
        }
        // V3 ABI. 1-bit booleans; map false → Unspecified, true → On
        // (V3 had no "any" state).
        1 => {
            let xnack = if e_flags & EF_AMDGPU_FEATURE_XNACK_V3 != 0 {
                TriState::On
            } else {
                TriState::Unspecified
            };
            let sramecc = if e_flags & EF_AMDGPU_FEATURE_SRAMECC_V3 != 0 {
                TriState::On
            } else {
                TriState::Unspecified
            };
            (xnack, sramecc)
        }
        _ => (TriState::Unspecified, TriState::Unspecified),
    };

    if major == 0 {
        // Unknown mach — pull through the raw bits anyway so the caller
        // can still see "this is an AMDGPU ELF, just an unrecognised
        // target."
        major = 0;
        minor = 0;
        stepping = 0;
    }

    let mut arch = GfxArchitecture::new(major, minor, stepping);
    arch.xnack = xnack;
    arch.sramecc = sramecc;
    arch
}

/// Decode a 2-bit V4 feature field into `TriState`.
///
/// LLVM's V4 encoding:
/// - `0b01` (1) → "any" / unspecified
/// - `0b10` (2) → off
/// - `0b11` (3) → on
/// - `0b00` (0) → invalid (treat as unspecified for forward-compat)
fn tristate_v4(bits: u32) -> TriState {
    match bits {
        0b10 => TriState::Off,
        0b11 => TriState::On,
        _ => TriState::Unspecified,
    }
}

/// Map a raw `EF_AMDGPU_MACH` byte to a `(major, minor, stepping)`
/// triple. Returns `(0, 0, 0)` for unrecognised values.
///
/// The table is harvested from
/// `llvm/include/llvm/BinaryFormat/ELF.h` (`EF_AMDGPU_MACH_AMDGCN_*`
/// constants). Adding a new GFX target is a one-line addition here.
fn mach_to_gfx_target(mach: u8) -> (u8, u8, u8) {
    match mach {
        // GCN3 / GCN4 (Volcanic Islands / Polaris)
        0x20 => (8, 0, 0), // gfx800 (iceland)
        0x21 => (8, 0, 1), // gfx801
        0x22 => (8, 0, 2), // gfx802
        0x23 => (8, 0, 3), // gfx803
        0x24 => (8, 1, 0), // gfx810
        // GCN5 (Vega / Vega20)
        0x2C => (9, 0, 0),   // gfx900
        0x2D => (9, 0, 2),   // gfx902
        0x2E => (9, 0, 4),   // gfx904
        0x2F => (9, 0, 6),   // gfx906
        0x30 => (9, 0, 8),   // gfx908 (CDNA1, MI100)
        0x31 => (9, 0, 9),   // gfx909
        0x32 => (9, 0, 0xC), // gfx90c
        0x3F => (9, 0, 0xA), // gfx90a (CDNA2, MI200)
        0x40 => (9, 4, 0),   // gfx940 (CDNA3 first ID)
        0x4D => (9, 4, 1),   // gfx941 (CDNA3)
        0x4E => (9, 4, 2),   // gfx942 (CDNA3)
        // RDNA1 (Navi 10/12/14)
        0x33 => (10, 1, 0), // gfx1010
        0x34 => (10, 1, 1), // gfx1011
        0x35 => (10, 1, 2), // gfx1012
        0x42 => (10, 1, 3), // gfx1013
        // RDNA2 (Navi 21/22/23/24)
        0x36 => (10, 3, 0), // gfx1030
        0x37 => (10, 3, 1), // gfx1031
        0x38 => (10, 3, 2), // gfx1032
        0x39 => (10, 3, 3), // gfx1033
        0x3D => (10, 3, 5), // gfx1035
        0x3E => (10, 3, 4), // gfx1034
        0x45 => (10, 3, 6), // gfx1036
        // RDNA3 (Navi 31/32/33)
        0x41 => (11, 0, 0), // gfx1100
        0x46 => (11, 0, 1), // gfx1101
        0x47 => (11, 0, 2), // gfx1102
        0x44 => (11, 0, 3), // gfx1103
        0x43 => (11, 5, 0), // gfx1150
        0x4C => (11, 5, 1), // gfx1151
        // RDNA4
        0x48 => (12, 0, 0), // gfx1200
        0x49 => (12, 0, 1), // gfx1201
        _ => (0, 0, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_elf64_header() {
        // Minimal valid ELF64 header (little-endian, x86_64, executable)
        let mut data = vec![0u8; 64];
        // Magic
        data[0..4].copy_from_slice(&ELF_MAGIC);
        // Class: ELF64
        data[4] = 2;
        // Endianness: little
        data[5] = 1;
        // Version
        data[6] = 1;
        // Type: executable (2)
        data[16] = 2;
        data[17] = 0;
        // Machine: x86_64 (62)
        data[18] = 62;
        data[19] = 0;
        // Entry point
        data[24..32].copy_from_slice(&0x401000u64.to_le_bytes());

        let header = ElfHeader::parse(&data).unwrap();
        assert_eq!(header.class, ElfClass::Elf64);
        assert_eq!(header.endianness, Endianness::Little);
        assert_eq!(header.machine, Machine::X86_64);
        assert_eq!(header.e_entry, 0x401000);
        assert_eq!(header.architecture(), Architecture::X86_64);
    }

    #[test]
    fn test_reject_invalid_magic() {
        let data = b"NOT_AN_ELF_FILE!";
        let result = ElfHeader::parse(data);
        assert!(matches!(result, Err(ParseError::InvalidMagic { .. })));
    }

    #[test]
    fn test_reject_too_short() {
        let data = b"\x7fELF";
        let result = ElfHeader::parse(data);
        assert!(matches!(result, Err(ParseError::TooShort { .. })));
    }

    #[test]
    fn machine_from_u16_recognises_cuda() {
        assert_eq!(Machine::from_u16(190), Machine::Cuda);
    }

    #[test]
    fn cuda_elf_header_maps_to_cuda_architecture() {
        // Synthetic ELF64 header with EM_CUDA=190, EI_ABIVERSION=7 (V1), and
        // e_flags = 0x00500550 — the exact value cuobjdump emits for a real
        // sm_80 cubin: virtual compute_80 | 64BIT_ADDRESS | TEXMODE_UNIFIED
        // | real sm_80 (0x50).
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&ELF_MAGIC);
        data[4] = 2; // ELF64
        data[5] = 1; // little-endian
        data[6] = 1; // EI_VERSION
        data[7] = 0; // EI_OSABI (default)
        data[8] = 7; // EI_ABIVERSION = CUDA V1
        data[16] = 2; // executable
        data[18] = 190; // EM_CUDA
        data[48..52].copy_from_slice(&0x0050_0550u32.to_le_bytes());

        let header = ElfHeader::parse(&data).unwrap();
        assert_eq!(header.machine, Machine::Cuda);
        assert_eq!(header.abi_version, 7);
        let arch = header.architecture();
        match arch {
            Architecture::Cuda(CudaArchitecture::Sass(sm)) => {
                assert_eq!(sm.major, 8);
                assert_eq!(sm.minor, 0);
                assert_eq!(sm.variant, SmVariant::Base);
                assert_eq!(sm.canonical_name(), "sm_80");
            }
            other => panic!("expected CUDA SASS, got {other:?}"),
        }
    }

    #[test]
    fn sm_from_cuda_elf_v1_real_world_flags() {
        use super::sm_from_cuda_elf;
        // Values observed in the wild by cuobjdump / CuAssembler / public RE:
        // sm_80  → 0x00500550
        // sm_86  → 0x00500556
        // sm_90  → 0x005a055a
        // sm_90a → 0x005a0d5a  (0x800 EF_CUDA_ACCELERATORS_V1 flag set)
        let sm80 = sm_from_cuda_elf(7, 0x0050_0550);
        assert_eq!(
            (sm80.major, sm80.minor, sm80.variant),
            (8, 0, SmVariant::Base)
        );
        assert_eq!(sm80.canonical_name(), "sm_80");

        let sm86 = sm_from_cuda_elf(7, 0x0050_0556);
        assert_eq!(
            (sm86.major, sm86.minor, sm86.variant),
            (8, 6, SmVariant::Base)
        );

        let sm90 = sm_from_cuda_elf(7, 0x005a_055a);
        assert_eq!(
            (sm90.major, sm90.minor, sm90.variant),
            (9, 0, SmVariant::Base)
        );

        let sm90a = sm_from_cuda_elf(7, 0x005a_0d5a);
        assert_eq!(
            (sm90a.major, sm90a.minor, sm90a.variant),
            (9, 0, SmVariant::A)
        );
        assert_eq!(sm90a.canonical_name(), "sm_90a");
    }

    #[test]
    fn sm_from_cuda_elf_v2_layout() {
        use super::sm_from_cuda_elf;
        // V2 (Blackwell+): real SM in bits 8..15, accelerator bit = 0x8.
        // sm_100 base: bits 8..15 = 0x64 (=100). Put virtual arch 0x64 in
        // bits 16..23. No accelerator.
        let sm100 = sm_from_cuda_elf(8, 0x0064_6400);
        assert_eq!(
            (sm100.major, sm100.minor, sm100.variant),
            (10, 0, SmVariant::Base)
        );
        assert_eq!(sm100.canonical_name(), "sm_100");

        // sm_100a: same as above but with accelerator bit.
        let sm100a = sm_from_cuda_elf(8, 0x0064_6408);
        assert_eq!(
            (sm100a.major, sm100a.minor, sm100a.variant),
            (10, 0, SmVariant::A)
        );
        assert_eq!(sm100a.canonical_name(), "sm_100a");
    }

    #[test]
    fn sm_from_cuda_elf_rejects_gibberish() {
        use super::sm_from_cuda_elf;
        // Zero e_flags under V1 — decode yields SM=0 which we bail on.
        assert_eq!(sm_from_cuda_elf(7, 0x0), SmArchitecture::UNKNOWN);
        // sm_code=0xFE under V1 → major=25, beyond our cap.
        assert_eq!(sm_from_cuda_elf(7, 0x0000_00FE), SmArchitecture::UNKNOWN);
    }

    #[test]
    fn sm_from_cuda_elf_unknown_abi_falls_back_to_v1() {
        use super::sm_from_cuda_elf;
        // Unknown ABI version 99 should still produce a reasonable result
        // by assuming V1 layout (safest — that's what every pre-Blackwell
        // cubin uses).
        let sm = sm_from_cuda_elf(99, 0x0050_0550);
        assert_eq!((sm.major, sm.minor, sm.variant), (8, 0, SmVariant::Base));
    }

    #[test]
    fn machine_recognises_amdgpu() {
        assert_eq!(Machine::from_u16(224), Machine::Amdgpu);
        // 191 sits between EM_CUDA (190) and EM_AMDGPU (224); should be Other.
        assert_eq!(Machine::from_u16(191), Machine::Other(191));
    }

    #[test]
    fn gfx_from_amdgpu_elf_decodes_common_targets() {
        use super::gfx_from_amdgpu_elf;
        // gfx906, V4 ABI, no features set.
        let g = gfx_from_amdgpu_elf(2, 0x2F);
        assert_eq!((g.major, g.minor, g.stepping), (9, 0, 6));
        assert_eq!(g.canonical_name(), "gfx906");
        assert_eq!(g.xnack, TriState::Unspecified);
        assert_eq!(g.sramecc, TriState::Unspecified);
        // gfx1030, V4 ABI.
        let g = gfx_from_amdgpu_elf(2, 0x36);
        assert_eq!(g.canonical_name(), "gfx1030");
        // gfx1100, V4 ABI.
        let g = gfx_from_amdgpu_elf(2, 0x41);
        assert_eq!(g.canonical_name(), "gfx1100");
        // gfx90a, V4 ABI, with xnack=on, sramecc=off.
        let g = gfx_from_amdgpu_elf(2, 0x3F | (0b11 << 8) | (0b10 << 10));
        assert_eq!(g.canonical_name(), "gfx90a");
        assert_eq!(g.xnack, TriState::On);
        assert_eq!(g.sramecc, TriState::Off);
        assert_eq!(g.target_id(), "gfx90a:xnack+:sramecc-");
    }

    #[test]
    fn gfx_from_amdgpu_elf_v3_features() {
        use super::gfx_from_amdgpu_elf;
        // V3 ABI: bit 8 = xnack on, bit 9 = sramecc on, both enabled.
        let g = gfx_from_amdgpu_elf(1, 0x2F | (1 << 8) | (1 << 9));
        assert_eq!(g.canonical_name(), "gfx906");
        assert_eq!(g.xnack, TriState::On);
        assert_eq!(g.sramecc, TriState::On);
        // V3 ABI with bits cleared: features unspecified.
        let g = gfx_from_amdgpu_elf(1, 0x2F);
        assert_eq!(g.xnack, TriState::Unspecified);
        assert_eq!(g.sramecc, TriState::Unspecified);
    }

    #[test]
    fn gfx_from_amdgpu_elf_handles_unknown_mach() {
        use super::gfx_from_amdgpu_elf;
        // 0x88 is not a known mach value; we should fall through to a
        // best-effort UNKNOWN-shaped target rather than panicking.
        let g = gfx_from_amdgpu_elf(2, 0x88);
        assert_eq!(g.major, 0);
        assert_eq!(g.canonical_name(), "gfx?");
    }

    #[test]
    fn architecture_from_synthesized_amdgpu_elf_header() {
        // Construct a minimal valid ELF64 little-endian header with
        // EM_AMDGPU = 224 and gfx906 mach + V4 ABI + xnack on.
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&ELF_MAGIC);
        data[4] = 2; // ELF64
        data[5] = 1; // little-endian
        data[6] = 1; // EI_VERSION
        data[7] = 64; // ELFOSABI_AMDGPU_HSA (HSA OS)
        data[8] = 2; // EI_ABIVERSION = 2 (V4)
        data[16..18].copy_from_slice(&1u16.to_le_bytes()); // ET_REL
        data[18..20].copy_from_slice(&224u16.to_le_bytes()); // EM_AMDGPU
        data[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
                                                           // e_flags at offset 48 (ELF64): mach 0x2F | xnack on (0b11<<8).
        let e_flags: u32 = 0x2F | (0b11 << 8);
        data[48..52].copy_from_slice(&e_flags.to_le_bytes());
        data[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        let header = ElfHeader::parse(&data).expect("synthetic AMDGPU ELF parses");
        match header.architecture() {
            Architecture::Amdgpu(g) => {
                assert_eq!(g.canonical_name(), "gfx906");
                assert_eq!(g.xnack, TriState::On);
            }
            other => panic!("expected Amdgpu, got {other:?}"),
        }
    }
}
