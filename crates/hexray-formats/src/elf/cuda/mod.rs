//! CUDA code-object view over a parsed ELF (CUBIN).
//!
//! This is **not** a separate binary-format parser — a CUBIN is an ELF file
//! with `e_machine = EM_CUDA (190)` and a set of NVIDIA-specific sections
//! (`.text.<kernel>`, `.nv.info*`, `.nv.shared*`, `.nv.constant*`, …). We
//! reuse the existing [`super::Elf`] parser and layer a typed view on top.
//!
//! The view is *built* (not lazy): constructing it walks every section
//! once, classifies them, resolves defining symbols, and collects a
//! complete list of kernels, memory regions, and diagnostics. Repeat
//! consumers get stable slices without rescanning.
//!
//! # Kernel detection heuristic
//!
//! `.text.<name>` is not sufficient to claim a section is a kernel — an
//! out-of-line `__device__` helper can also land in a dedicated `.text.*`
//! section. We use this priority order:
//!
//! 1. Some defining function symbol for the section has the
//!    `STO_CUDA_ENTRY` bit in `st_other`. (Highest confidence.)
//! 2. A sibling `.nv.info.<name>` section exists.
//! 3. (Deferred to M5) semantic decoding shows kernel-only `EIATTR_*`.
//! 4. Otherwise we do **not** surface it as a kernel and emit an
//!    [`CubinDiagnosticKind::AmbiguousTextSection`] diagnostic.

mod info;
mod schema;

use crate::elf::section::SHT_NOBITS;
use crate::elf::{Elf, SectionHeader};
use crate::Section;
use hexray_core::Symbol;

pub use info::{parse_nv_info, NvInfoAttribute, NvInfoBlob, NvInfoEntryRef, NvInfoFormat};
pub use schema::{KernelResourceUsage, ParamCbank, ParamInfo, SchemaError};

/// NVIDIA's `STO_CUDA_ENTRY` bit in the low nibble of `st_other`. Marks a
/// symbol as a kernel entry (`__global__` function).
pub const STO_CUDA_ENTRY: u8 = 0x10;

/// Error returned when asking a non-CUDA ELF for its CUBIN view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CubinError {
    /// ELF header's machine field is not `EM_CUDA`.
    NotCuda,
}

impl std::fmt::Display for CubinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotCuda => f.write_str("ELF machine is not EM_CUDA"),
        }
    }
}

impl std::error::Error for CubinError {}

/// A CUBIN-shaped view over an [`Elf`]. Construct via [`Elf::cubin_view`]
/// or [`CubinView::from_elf`]; both return [`CubinError::NotCuda`] for
/// non-EM_CUDA ELFs.
#[derive(Debug)]
pub struct CubinView<'elf> {
    elf: &'elf Elf<'elf>,
    kernels: Vec<Kernel<'elf>>,
    memory_regions: Vec<MemoryRegion<'elf>>,
    module_info: Option<NvInfoBlob<'elf>>,
    diagnostics: Vec<CubinDiagnostic>,
}

impl<'elf> CubinView<'elf> {
    /// Build a CUBIN view from a parsed ELF.
    pub fn from_elf(elf: &'elf Elf<'elf>) -> Result<Self, CubinError> {
        use crate::elf::Machine;
        if elf.header.machine != Machine::Cuda {
            return Err(CubinError::NotCuda);
        }

        let mut diagnostics = Vec::new();

        // Pass 1: bucket sections by name prefix.
        //
        // We build a small set of lookups keyed by `"_Z..."` / `"kernel"`
        // suffix. `.text.<name>` → text candidates; `.nv.info.<name>` →
        // per-kernel info; `.nv.shared.<name>` and `.nv.constantN.<name>` →
        // memory regions.
        let mut text_candidates: Vec<(usize, &str)> = Vec::new(); // (section_index, kernel_name)
        let mut nv_info_module: Option<(usize, &str)> = None; // (section_index, name) where name = ".nv.info"
        let mut nv_info_per_kernel: Vec<(usize, &str)> = Vec::new();
        let mut memory_regions: Vec<MemoryRegion<'elf>> = Vec::new();

        for (idx, section) in elf.sections.iter().enumerate() {
            let name = section_name(section);
            if name.is_empty() {
                continue;
            }

            if let Some(k) = strip_prefix(name, ".text.") {
                text_candidates.push((idx, k));
                continue;
            }

            if name == ".nv.info" {
                nv_info_module = Some((idx, name));
                continue;
            }
            if let Some(k) = strip_prefix(name, ".nv.info.") {
                nv_info_per_kernel.push((idx, k));
                continue;
            }

            if let Some((space, owner)) = classify_memory_section(name) {
                let bytes_opt = if section.sh_type == SHT_NOBITS {
                    None
                } else {
                    Some(section.data())
                };
                memory_regions.push(MemoryRegion {
                    name,
                    space,
                    owner_kernel: owner,
                    section_index: idx,
                    section,
                    virtual_address: section.sh_addr,
                    size: section.sh_size,
                    bytes: bytes_opt,
                });
            }
        }

        // Orphan-info diagnostic: `.nv.info.<kernel>` without a corresponding
        // `.text.<kernel>`.
        for (idx, info_name) in &nv_info_per_kernel {
            if !text_candidates.iter().any(|(_, n)| n == info_name) {
                diagnostics.push(CubinDiagnostic {
                    kind: CubinDiagnosticKind::OrphanNvInfoSection,
                    section_index: Some(*idx),
                });
            }
        }

        // Pass 2: resolve defining symbols for each `.text.<name>`.
        //
        // A section may have several symbols pointing into it; we want the
        // one whose `st_shndx` matches and whose name equals the kernel
        // name (the other symbols are helpers/locals).
        let raw_symbols = elf.raw_symbols();
        let symbols = elf.symbols_slice();

        // Build a parallel index-aligned view so we can use `st_other`
        // without re-parsing strings.
        assert_eq!(raw_symbols.len(), symbols.len());

        // Pass 3: promote text candidates to kernels or emit diagnostics.
        let mut kernels: Vec<Kernel<'elf>> = Vec::with_capacity(text_candidates.len());
        let mut seen_names: Vec<&str> = Vec::with_capacity(text_candidates.len());

        for (sec_idx, kernel_name) in &text_candidates {
            let sec_idx = *sec_idx;
            let kernel_name = *kernel_name;
            let section = &elf.sections[sec_idx];

            // Find the defining symbol for this section that matches the
            // kernel name. We accept: matching name, or matching section
            // index + STT_FUNC as fallback.
            let (sym, raw) = find_defining_symbol(symbols, raw_symbols, sec_idx, kernel_name);

            // Kernel test 1: STO_CUDA_ENTRY.
            let entry_marker = raw
                .map(|r| (r.st_other & STO_CUDA_ENTRY) != 0)
                .unwrap_or(false);

            // Kernel test 2: sibling `.nv.info.<name>`.
            let sibling_info = nv_info_per_kernel
                .iter()
                .find(|(_, n)| *n == kernel_name)
                .map(|(idx, _)| *idx);

            // Decide kernel confidence. A `.nv.info.<name>` sibling is not
            // by itself sufficient on real cubins — out-of-line `__device__`
            // functions can also carry per-function info sections. So we
            // still surface those as candidates, but with `SiblingInfoOnly`
            // confidence so callers can filter before they trust them.
            let confidence = match (entry_marker, sibling_info.is_some()) {
                (true, _) => KernelConfidence::EntryMarker,
                (false, true) => KernelConfidence::SiblingInfoOnly,
                (false, false) => {
                    diagnostics.push(CubinDiagnostic {
                        kind: CubinDiagnosticKind::AmbiguousTextSection,
                        section_index: Some(sec_idx),
                    });
                    continue;
                }
            };

            if seen_names.contains(&kernel_name) {
                diagnostics.push(CubinDiagnostic {
                    kind: CubinDiagnosticKind::DuplicateKernelName,
                    section_index: Some(sec_idx),
                });
                continue;
            }
            seen_names.push(kernel_name);

            let nv_info = sibling_info.map(|info_idx| {
                let data = elf.sections[info_idx].data();
                let blob = parse_nv_info(data);
                if blob.truncated {
                    diagnostics.push(CubinDiagnostic {
                        kind: CubinDiagnosticKind::MalformedNvInfo,
                        section_index: Some(info_idx),
                    });
                }
                blob
            });

            let size = sym
                .map(|s| s.size)
                .filter(|s| *s != 0)
                .unwrap_or(section.sh_size);

            kernels.push(Kernel {
                name: kernel_name,
                code: section.data(),
                virtual_address: section.sh_addr,
                section_index: sec_idx,
                section,
                symbol: sym,
                size,
                nv_info,
                confidence,
            });
        }

        // Module-wide `.nv.info` (if any).
        let module_info = nv_info_module.map(|(idx, _)| {
            let data = elf.sections[idx].data();
            let blob = parse_nv_info(data);
            if blob.truncated {
                diagnostics.push(CubinDiagnostic {
                    kind: CubinDiagnosticKind::MalformedNvInfo,
                    section_index: Some(idx),
                });
            }
            blob
        });

        Ok(Self {
            elf,
            kernels,
            memory_regions,
            module_info,
            diagnostics,
        })
    }

    /// Borrow the underlying ELF.
    pub fn elf(&self) -> &'elf Elf<'elf> {
        self.elf
    }

    /// All recognised kernel *candidates*. Mixes high-confidence entries
    /// (`STO_CUDA_ENTRY` bit set) with ambiguous ones promoted only by the
    /// sibling-`.nv.info.<name>` heuristic. Inspect [`Kernel::confidence`]
    /// or use [`CubinView::entry_kernels`] when only the strict set is
    /// wanted.
    pub fn kernels(&self) -> &[Kernel<'elf>] {
        &self.kernels
    }

    /// Iterate kernels that satisfy the strongest classification test
    /// (`STO_CUDA_ENTRY`). On real cubins emitted by current `ptxas`,
    /// these are the actual `__global__` entries.
    pub fn entry_kernels(&self) -> impl Iterator<Item = &Kernel<'elf>> {
        self.kernels
            .iter()
            .filter(|k| k.confidence == KernelConfidence::EntryMarker)
    }

    /// Look up a kernel by exact (symbol) name. O(n).
    pub fn kernel_by_name(&self, name: &str) -> Option<&Kernel<'elf>> {
        self.kernels.iter().find(|k| k.name == name)
    }

    /// Every `.nv.shared*` / `.nv.constant*` region we found.
    pub fn memory_regions(&self) -> &[MemoryRegion<'elf>] {
        &self.memory_regions
    }

    /// Module-wide `.nv.info`, if present.
    pub fn module_info(&self) -> Option<&NvInfoBlob<'elf>> {
        self.module_info.as_ref()
    }

    /// Diagnostics collected while building the view. M2 emits them; M3+
    /// callers may surface them in the CLI.
    pub fn diagnostics(&self) -> &[CubinDiagnostic] {
        &self.diagnostics
    }
}

/// A kernel candidate recovered from the CUBIN.
///
/// "Candidate" because the `sibling_info_only` path cannot distinguish a
/// real `__global__` entry from an out-of-line `__device__` function; use
/// [`Kernel::confidence`] or [`CubinView::entry_kernels`] to filter down
/// to the strict set when needed.
#[derive(Debug, Clone)]
pub struct Kernel<'elf> {
    /// Kernel symbol name (mangled — we do no demangling here).
    pub name: &'elf str,
    /// Full `.text.<name>` section bytes. May be larger than `size` if the
    /// section also contains inline helpers.
    pub code: &'elf [u8],
    /// Section virtual address (for relocatable cubins, zero).
    pub virtual_address: u64,
    pub section_index: usize,
    pub section: &'elf SectionHeader,
    /// Defining function symbol, if one was found.
    pub symbol: Option<&'elf Symbol>,
    /// `symbol.size` when defined; falls back to `section.sh_size`.
    pub size: u64,
    /// Parsed `.nv.info.<name>` sidecar, if present.
    pub nv_info: Option<NvInfoBlob<'elf>>,
    /// Why this candidate was promoted. Callers who want to match
    /// `nvdisasm`'s `__global__` listing should filter to
    /// [`KernelConfidence::EntryMarker`].
    pub confidence: KernelConfidence,
}

impl<'elf> Kernel<'elf> {
    /// Decode every recognised `.nv.info.<kernel>` attribute into a
    /// typed [`KernelResourceUsage`]. Returns `None` if this kernel
    /// has no sidecar info blob attached.
    pub fn resource_usage(&self) -> Option<KernelResourceUsage> {
        self.nv_info.as_ref().map(KernelResourceUsage::from_nv_info)
    }
}

/// How confident we are that a promoted `.text.<name>` section really is a
/// kernel entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelConfidence {
    /// Defining symbol has `STO_CUDA_ENTRY` set in `st_other`. Matches
    /// `nvdisasm`'s notion of a kernel entry point.
    EntryMarker,
    /// Only a sibling `.nv.info.<name>` section promoted this candidate.
    /// May be a real kernel or an out-of-line `__device__` function. See
    /// [`CubinDiagnosticKind::AmbiguousTextSection`] for cases that are
    /// ambiguous enough to skip entirely.
    SiblingInfoOnly,
}

/// Memory-space classification for CUBIN sections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemorySpace {
    /// `.nv.constantN` — constant bank `N`. Bank `0` is conventionally the
    /// kernel-parameter bank.
    Constant { bank: u8 },
    /// `.nv.shared*` — static `__shared__` allocation (dynamic shared is
    /// not a section).
    Shared,
    /// `.nv.local*` — per-thread local allocations.
    Local,
}

/// A `.nv.shared*` / `.nv.constant*` / `.nv.local*` region.
#[derive(Debug, Clone)]
pub struct MemoryRegion<'elf> {
    /// Section name exactly as it appears in the ELF.
    pub name: &'elf str,
    pub space: MemorySpace,
    /// Per-kernel suffix, if any. Module-wide regions (e.g. `.nv.constant0`
    /// without a kernel suffix) have `None`.
    pub owner_kernel: Option<&'elf str>,
    pub section_index: usize,
    pub section: &'elf SectionHeader,
    pub virtual_address: u64,
    pub size: u64,
    /// `None` for `SHT_NOBITS` sections (e.g. uninitialised shared).
    pub bytes: Option<&'elf [u8]>,
}

/// A diagnostic message from CUBIN parsing. Non-fatal — the view is
/// constructed best-effort and callers can decide whether to warn.
#[derive(Debug, Clone)]
pub struct CubinDiagnostic {
    pub kind: CubinDiagnosticKind,
    pub section_index: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CubinDiagnosticKind {
    /// `.text.<name>` with neither `STO_CUDA_ENTRY` nor a sibling
    /// `.nv.info.<name>`. Might be an out-of-line `__device__` helper; we
    /// don't surface it as a kernel.
    AmbiguousTextSection,
    /// A `.nv.info.<name>` without a corresponding `.text.<name>`.
    OrphanNvInfoSection,
    /// Two `.text.<name>` sections refer to the same kernel name.
    DuplicateKernelName,
    /// `.nv.info` or `.nv.info.<kernel>` TLV framing truncated mid-entry.
    MalformedNvInfo,
}

// ---- helpers ---------------------------------------------------------------

fn section_name(section: &SectionHeader) -> &str {
    section.name()
}

fn strip_prefix<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    s.strip_prefix(prefix).filter(|rest| !rest.is_empty())
}

/// `.nv.constantN[.<kernel>]`, `.nv.shared[.<kernel>]`, `.nv.local[.<kernel>]`.
fn classify_memory_section(name: &str) -> Option<(MemorySpace, Option<&str>)> {
    if let Some(rest) = name.strip_prefix(".nv.constant") {
        let (bank_str, owner) = split_bank_and_owner(rest);
        let bank: u8 = bank_str.parse().ok()?;
        return Some((MemorySpace::Constant { bank }, owner));
    }
    if let Some(rest) = name.strip_prefix(".nv.shared") {
        let owner = strip_dot_prefix(rest);
        return Some((MemorySpace::Shared, owner));
    }
    if let Some(rest) = name.strip_prefix(".nv.local") {
        let owner = strip_dot_prefix(rest);
        return Some((MemorySpace::Local, owner));
    }
    None
}

/// Split a trailing `N[.owner]` into (`N`, `Some(owner)` or `None`).
fn split_bank_and_owner(rest: &str) -> (&str, Option<&str>) {
    match rest.split_once('.') {
        Some((bank, owner)) if !owner.is_empty() => (bank, Some(owner)),
        Some((bank, _)) => (bank, None),
        None => (rest, None),
    }
}

/// Given `""`, `".kernel"`, `".extra.kernel"`, etc, return the suffix past
/// the leading dot if any.
fn strip_dot_prefix(rest: &str) -> Option<&str> {
    rest.strip_prefix('.').filter(|s| !s.is_empty())
}

/// Find the defining symbol for `.text.<kernel_name>`: prefer a name match,
/// fall back to any `STT_FUNC` / `STT_OBJECT` pointing at section index.
fn find_defining_symbol<'a>(
    symbols: &'a [Symbol],
    raw_symbols: &'a [crate::elf::SymbolEntry],
    section_index: usize,
    kernel_name: &str,
) -> (Option<&'a Symbol>, Option<&'a crate::elf::SymbolEntry>) {
    let mut name_match: Option<usize> = None;
    let mut index_match: Option<usize> = None;

    for (i, sym) in symbols.iter().enumerate() {
        if sym.section_index != Some(section_index as u32) {
            continue;
        }
        if sym.name == kernel_name {
            name_match = Some(i);
            break;
        }
        if index_match.is_none() && sym.is_function() {
            index_match = Some(i);
        }
    }

    let idx = name_match.or(index_match);
    match idx {
        Some(i) => (Some(&symbols[i]), Some(&raw_symbols[i])),
        None => (None, None),
    }
}

#[cfg(any(test, doctest))]
mod tests;
