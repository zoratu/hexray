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
mod schema;

#[cfg(test)]
mod tests;

pub use descriptor::{KernelDescriptor, KERNEL_DESCRIPTOR_SIZE};
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
            });
        }

        Ok(Self {
            elf,
            target,
            kernels,
            diagnostics,
        })
    }

    /// Underlying ELF.
    pub fn elf(&self) -> &Elf<'elf> {
        self.elf
    }
}
