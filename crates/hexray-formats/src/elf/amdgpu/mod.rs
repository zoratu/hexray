//! AMDGPU code-object view over a parsed ELF.
//!
//! An AMDGPU code object is an ELF file with `e_machine =
//! EM_AMDGPU = 224`, a `.text` section holding GCN/CDNA/RDNA
//! instructions, and one or more *kernel descriptor* blobs in
//! `.rodata`. We reuse the existing [`super::Elf`] parser and layer
//! a typed view on top, mirroring the shape of the CUDA `CubinView`.
//!
//! # Kernel detection
//!
//! AMDGPU's HSA ABI has a stable convention: every kernel is
//! described by a *pair* of symbols sharing the same prefix:
//!
//! - `<kernel>`     — `STT_FUNC`, in `.text`. The first instruction.
//! - `<kernel>.kd`  — `STT_OBJECT`, in `.rodata`. The 64-byte
//!   `amdhsa_kernel_descriptor_t` the runtime loads before launch.
//!
//! We walk the symbol table looking for `.kd` symbols, strip the
//! suffix to find the entry symbol, and emit one [`Kernel`] per
//! matched pair.
//!
//! # Out of scope (for now)
//!
//! - The `NT_AMDGPU_METADATA` MessagePack note (kernel arg layout,
//!   per-kernel sgpr/vgpr counts, max workgroup size). The
//!   descriptor block alone gives us enough for resource usage and
//!   for the `hexray cmp` comparator; metadata decoding lands in a
//!   follow-up commit.
//! - HIP fatbin extraction (host-side ELF wrapping AMDGPU code
//!   objects). M10 reads the AMDGPU object directly.

mod descriptor;
mod metadata;
mod msgpack;
mod scale_kinfo;
mod schema;

#[cfg(test)]
mod tests;

pub use descriptor::{KernelDescriptor, KERNEL_DESCRIPTOR_SIZE};
pub use metadata::{AmdMetadata, AmdMetadataArg, AmdMetadataKernel};
pub use scale_kinfo::{ScaleKinfo, ScaleKinfoArg, ScaleKinfoError};
pub use schema::AmdKernelResourceUsage;

use super::Elf;
use crate::{BinaryFormat, ParseError};
use hexray_core::Architecture;

/// Errors raised when building a [`CodeObjectView`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeObjectError {
    /// The ELF is not `EM_AMDGPU`.
    NotAmdgpu,
    /// The ELF parsed but a kernel descriptor failed to read.
    DescriptorParse(String),
}

impl std::fmt::Display for CodeObjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAmdgpu => write!(f, "ELF is not an AMDGPU code object"),
            Self::DescriptorParse(s) => write!(f, "failed to parse kernel descriptor: {s}"),
        }
    }
}

impl std::error::Error for CodeObjectError {}

impl From<ParseError> for CodeObjectError {
    fn from(e: ParseError) -> Self {
        Self::DescriptorParse(e.to_string())
    }
}

/// Soft diagnostics surfaced while building the view. Non-fatal —
/// each diagnostic just means one specific record didn't decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeObjectDiagnostic {
    pub kind: CodeObjectDiagnosticKind,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeObjectDiagnosticKind {
    /// A `<kernel>.kd` symbol was found but the bytes at its address
    /// don't form a valid 64-byte descriptor (truncated, wrong
    /// section, etc.).
    OrphanDescriptor,
    /// A symbol named `<kernel>` exists but no corresponding `.kd`
    /// symbol — the kernel is present but unlaunchable.
    OrphanEntry,
    /// A SCALE-style `.AMDGPU.kinfo` record was located but its bytes
    /// could not be decoded by [`ScaleKinfo::parse`]. The kernel is
    /// still usable for codegen comparison; the per-arg layout just
    /// won't be available.
    MalformedScaleKinfo,
}

/// AMDGPU code-object view.
#[derive(Debug)]
pub struct CodeObjectView<'elf> {
    elf: &'elf Elf<'elf>,
    /// GFX target the ELF was compiled for. Carries family +
    /// xnack/sramecc state.
    pub target: hexray_core::GfxArchitecture,
    /// One entry per detected kernel.
    pub kernels: Vec<Kernel<'elf>>,
    /// `NT_AMDGPU_METADATA` payload, when the ELF carried one.
    /// Provides typed kernel-arg layout, signed reg counts, and
    /// workgroup-size limits beyond what the descriptor block has.
    pub metadata: Option<AmdMetadata>,
    /// Soft diagnostics — orphan descriptors, malformed records.
    pub diagnostics: Vec<CodeObjectDiagnostic>,
}

/// One AMDGPU kernel: entry symbol + descriptor + decoded resource
/// summary.
#[derive(Debug, Clone)]
pub struct Kernel<'elf> {
    /// Display name (with `.kd` suffix stripped).
    pub name: &'elf str,
    /// Address of the entry symbol (`<kernel>` in `.text`).
    pub entry_addr: u64,
    /// Address of the descriptor symbol (`<kernel>.kd` in `.rodata`).
    pub descriptor_addr: u64,
    /// Decoded 64-byte descriptor.
    pub descriptor: KernelDescriptor,
    /// Vendor-specific resource summary (vgpr/sgpr, LDS, scratch,
    /// kernarg).
    pub resource_usage: AmdKernelResourceUsage,
    /// Per-kernel metadata record from `NT_AMDGPU_METADATA`, when
    /// present. Provides argument layout the descriptor block alone
    /// can't surface.
    pub metadata: Option<AmdMetadataKernel>,
}

impl<'elf> CodeObjectView<'elf> {
    /// Build a code-object view from a parsed ELF.
    ///
    /// Returns [`CodeObjectError::NotAmdgpu`] if the ELF's machine
    /// type isn't `EM_AMDGPU`. All other parsing failures (malformed
    /// descriptors, orphan symbols) surface as soft diagnostics.
    pub fn from_elf(elf: &'elf Elf<'elf>) -> Result<Self, CodeObjectError> {
        let target = match elf.architecture() {
            Architecture::Amdgpu(g) => g,
            _ => return Err(CodeObjectError::NotAmdgpu),
        };

        let mut kernels = Vec::new();
        let mut diagnostics = Vec::new();

        // Build a name → address index for quick `<name>` lookup
        // when we find a `<name>.kd` entry.
        let symbols: Vec<_> = elf.symbols().collect();
        let entries: std::collections::HashMap<&str, u64> = symbols
            .iter()
            .filter(|s| !s.name.ends_with(".kd"))
            .map(|s| (s.name.as_str(), s.address))
            .collect();

        for sym in &symbols {
            let Some(stripped) = sym.name.strip_suffix(".kd") else {
                continue;
            };
            let descriptor_addr = sym.address;

            // Read the 64 bytes at descriptor_addr. The .kd symbol is
            // an STT_OBJECT in .rodata; bytes_at handles the
            // address → file-offset mapping.
            let Some(bytes) = elf.bytes_at(descriptor_addr, KERNEL_DESCRIPTOR_SIZE) else {
                diagnostics.push(CodeObjectDiagnostic {
                    kind: CodeObjectDiagnosticKind::OrphanDescriptor,
                    detail: format!(
                        "{stripped}.kd at 0x{descriptor_addr:x}: bytes not addressable"
                    ),
                });
                continue;
            };
            let descriptor = match KernelDescriptor::parse(bytes) {
                Ok(d) => d,
                Err(e) => {
                    diagnostics.push(CodeObjectDiagnostic {
                        kind: CodeObjectDiagnosticKind::OrphanDescriptor,
                        detail: format!("{stripped}.kd: {e}"),
                    });
                    continue;
                }
            };

            let entry_addr = entries.get(stripped).copied().unwrap_or(0);
            if entry_addr == 0 {
                diagnostics.push(CodeObjectDiagnostic {
                    kind: CodeObjectDiagnosticKind::OrphanEntry,
                    detail: format!("{stripped}.kd present but no `{stripped}` entry symbol"),
                });
            }

            let resource_usage = AmdKernelResourceUsage::from_descriptor(&descriptor, target.major);

            kernels.push(Kernel {
                name: stripped,
                entry_addr,
                descriptor_addr,
                descriptor,
                resource_usage,
                metadata: None,
            });
        }

        // Locate the NT_AMDGPU_METADATA note. It can live in any
        // section of type SHT_NOTE. We walk every note section,
        // looking for a record with name "AMDGPU" and type 32.
        let metadata = find_amdgpu_metadata(elf);

        // Hook the per-kernel metadata records onto the matching
        // Kernel by name (or symbol). Falls back to no metadata if
        // the kernel name doesn't appear in the metadata blob.
        if let Some(md) = &metadata {
            for k in &mut kernels {
                if let Some(rec) = md.kernels.iter().find(|rec| {
                    rec.name.as_deref() == Some(k.name)
                        || rec
                            .symbol
                            .as_deref()
                            .map(|sym| sym.strip_suffix(".kd") == Some(k.name))
                            .unwrap_or(false)
                }) {
                    k.metadata = Some(rec.clone());
                }
            }
        } else {
            // Fallback: SCALE-free 1.4.x doesn't emit
            // NT_AMDGPU_METADATA. Look for the private
            // `.AMDGPU.kinfo` section + per-kernel `<kernel>.ki`
            // symbols and synthesise a minimal `AmdMetadataKernel`
            // with the per-arg layout populated. This keeps the cmp
            // comparator (which reads `metadata.args[*].size`)
            // working for SCALE binaries.
            attach_scale_kinfo(elf, &symbols, &mut kernels, &mut diagnostics);
        }

        Ok(Self {
            elf,
            target,
            kernels,
            metadata,
            diagnostics,
        })
    }

    /// Underlying ELF.
    pub fn elf(&self) -> &Elf<'elf> {
        self.elf
    }
}

/// Walk every SHT_NOTE section looking for a record with name
/// `"AMDGPU"` and type `NT_AMDGPU_METADATA = 32`. Decode the
/// descriptor bytes as MessagePack and return the typed
/// [`AmdMetadata`].
///
/// ELF note layout (per gABI, used identically on ELF32 and ELF64):
///
/// ```text
///   u32 namesz   ; length of name including NUL
///   u32 descsz   ; length of descriptor
///   u32 type     ; NT_AMDGPU_METADATA = 32 for AMDGPU metadata
///   <name>       ; padded up to 4-byte alignment
///   <desc>       ; padded up to 4-byte alignment
/// ```
fn find_amdgpu_metadata(elf: &Elf<'_>) -> Option<AmdMetadata> {
    use crate::Section;
    const SHT_NOTE: u32 = 7;
    const NT_AMDGPU_METADATA: u32 = 32;

    for section in &elf.sections {
        if section.sh_type != SHT_NOTE {
            continue;
        }
        let bytes = section.data();
        let mut cursor = 0;
        while cursor + 12 <= bytes.len() {
            let namesz = u32::from_le_bytes([
                bytes[cursor],
                bytes[cursor + 1],
                bytes[cursor + 2],
                bytes[cursor + 3],
            ]) as usize;
            let descsz = u32::from_le_bytes([
                bytes[cursor + 4],
                bytes[cursor + 5],
                bytes[cursor + 6],
                bytes[cursor + 7],
            ]) as usize;
            let ntype = u32::from_le_bytes([
                bytes[cursor + 8],
                bytes[cursor + 9],
                bytes[cursor + 10],
                bytes[cursor + 11],
            ]);

            let name_off = cursor + 12;
            let desc_off = name_off + align_up(namesz, 4);
            let next_off = desc_off + align_up(descsz, 4);
            if next_off > bytes.len() {
                break;
            }

            let name = bytes[name_off..name_off + namesz]
                .split(|&b| b == 0)
                .next()
                .and_then(|n| std::str::from_utf8(n).ok())
                .unwrap_or("");

            if ntype == NT_AMDGPU_METADATA && name == "AMDGPU" {
                if let Ok(md) = AmdMetadata::parse(&bytes[desc_off..desc_off + descsz]) {
                    return Some(md);
                }
            }

            cursor = next_off;
        }
    }
    None
}

fn align_up(n: usize, align: usize) -> usize {
    (n + align - 1) & !(align - 1)
}

/// Walk the symbol table for `<kernel>.ki` records pointing into the
/// private `.AMDGPU.kinfo` section, decode each, and attach the
/// synthesised metadata onto the matching [`Kernel`].
///
/// SCALE-free 1.4.x emits one `<kernel>.ki` symbol per kernel, all
/// living in a single `.AMDGPU.kinfo` section. The symbol's address
/// (file-offset for relocatable ELFs) plus its `st_size` slice
/// addresses one record. Multiple `.ki` symbols in one section are
/// supported even though the v1.4.2 fixtures only ever emit one.
///
/// On parse failure we drop a soft diagnostic — the kernel is still
/// usable for codegen comparison; only per-arg cmp rows are lost.
fn attach_scale_kinfo(
    elf: &Elf<'_>,
    symbols: &[&hexray_core::Symbol],
    kernels: &mut [Kernel<'_>],
    diagnostics: &mut Vec<CodeObjectDiagnostic>,
) {
    use crate::Section;

    // Locate the `.AMDGPU.kinfo` section. Its presence is what
    // distinguishes a SCALE-emitted object from a clang/hipcc one.
    let Some(kinfo_section) = elf.sections.iter().find(|s| s.name() == ".AMDGPU.kinfo") else {
        return;
    };
    let section_base = kinfo_section.sh_offset;
    let section_end = section_base + kinfo_section.sh_size;
    let section_bytes = kinfo_section.data();
    if section_bytes.is_empty() {
        return;
    }

    for sym in symbols {
        let Some(stripped) = sym.name.strip_suffix(".ki") else {
            continue;
        };
        // The symbol must point inside `.AMDGPU.kinfo`. We compare on
        // the relocatable virtual address (file offset for ET_REL),
        // matching how `bytes_at_relocatable` resolves things.
        let addr = sym.address;
        if addr < section_base || addr >= section_end {
            continue;
        }
        let rec_off = (addr - section_base) as usize;
        let rec_len = sym.size as usize;
        if rec_len == 0 || rec_off + rec_len > section_bytes.len() {
            diagnostics.push(CodeObjectDiagnostic {
                kind: CodeObjectDiagnosticKind::MalformedScaleKinfo,
                detail: format!(
                    "{stripped}.ki at 0x{addr:x}: range {rec_off}..{} exceeds .AMDGPU.kinfo",
                    rec_off + rec_len
                ),
            });
            continue;
        }
        let bytes = &section_bytes[rec_off..rec_off + rec_len];
        let info = match scale_kinfo::parse(bytes) {
            Ok(info) => info,
            Err(e) => {
                diagnostics.push(CodeObjectDiagnostic {
                    kind: CodeObjectDiagnosticKind::MalformedScaleKinfo,
                    detail: format!("{stripped}.ki: {e}"),
                });
                continue;
            }
        };

        let Some(kernel) = kernels.iter_mut().find(|k| k.name == stripped) else {
            // Kinfo for a kernel we don't have (e.g. dropped because
            // its `.kd` was orphan-rejected). Skip — no kernel slot
            // to attach to.
            continue;
        };
        if kernel.metadata.is_some() {
            // Already populated (somehow — defensive: don't clobber a
            // real metadata note if both exist).
            continue;
        }
        kernel.metadata = Some(synthesise_metadata_kernel(stripped, &info));
    }
}

/// Build a minimal [`AmdMetadataKernel`] from a decoded
/// `.AMDGPU.kinfo` record. We only populate fields the kinfo blob
/// can authoritatively supply: name, symbol, and the arg array.
///
/// Crucially we leave `kernarg_segment_size` unset. The kinfo records
/// only describe *user* arguments — the kernarg segment also holds
/// SCALE-emitted hidden args (block id, dispatch ptr, etc.) and the
/// descriptor block already reports the full segment size. Filling in
/// our partial view here would clobber that signal in `hexray cmp`'s
/// kernarg/param row.
fn synthesise_metadata_kernel(name: &str, info: &ScaleKinfo) -> AmdMetadataKernel {
    AmdMetadataKernel {
        name: Some(name.to_string()),
        symbol: Some(format!("{name}.kd")),
        kernarg_segment_size: None,
        kernarg_segment_align: None,
        group_segment_fixed_size: None,
        private_segment_fixed_size: None,
        sgpr_count: None,
        vgpr_count: None,
        agpr_count: None,
        max_flat_workgroup_size: None,
        wavefront_size: None,
        args: info
            .args
            .iter()
            .map(|a| AmdMetadataArg {
                name: None,
                type_name: None,
                size: Some(a.size),
                offset: Some(a.offset),
                value_kind: None,
                address_space: None,
                access: None,
            })
            .collect(),
    }
}
