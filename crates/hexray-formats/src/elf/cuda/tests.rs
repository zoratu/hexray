//! Synthetic CUBIN fixtures. Covers the edge cases that the M2 design
//! calls out explicitly: orphan `.nv.info.<name>`, `.text.<name>` without
//! entry marker, constant-bank parsing, NOBITS shared regions, ambiguous
//! text sections, and helper symbols inside a kernel section.

use super::*;
use crate::cuda::FatbinWrapper;
use crate::elf::Elf;

/// Compile-time witness that owned-data CUDA types stay `Send + Sync`.
/// View / borrow types (CubinView, Kernel, MemoryRegion, NvInfoBlob,
/// PtxIndex) are intentionally not asserted — they hold short-lived
/// borrows from a `&Elf` and aren't expected to cross threads. Owned
/// records that *can* legitimately move between threads are.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<KernelResourceUsage>();
    assert_send_sync::<ParamCbank>();
    assert_send_sync::<ParamInfo>();
    assert_send_sync::<MemorySpace>();
    assert_send_sync::<NvInfoAttribute>();
    assert_send_sync::<NvInfoEntryRef>();
    assert_send_sync::<PtxModuleHeader>();
    assert_send_sync::<PtxFunction>();
    assert_send_sync::<PtxFunctionKind>();
    assert_send_sync::<CubinError>();
    assert_send_sync::<CubinDiagnostic>();
    assert_send_sync::<CubinDiagnosticKind>();
    assert_send_sync::<KernelConfidence>();
    assert_send_sync::<FatbinWrapper<'static>>();
};

/// A minimal ELF64 + EM_CUDA builder. Everything is little-endian; we keep
/// sections contiguous right after the section header table.
struct CubinBuilder {
    sections: Vec<SectionBuild>,
    symbols: Vec<SymbolBuild>,
    abi_version: u8,
    e_flags: u32,
}

#[derive(Clone)]
struct SectionBuild {
    name: String,
    sh_type: u32,
    sh_flags: u64,
    data: Vec<u8>,
    /// When non-zero, overrides the section size field so we can model
    /// `SHT_NOBITS` with a logical size bigger than the file-backed bytes.
    nobits_logical_size: u64,
}

#[derive(Clone)]
struct SymbolBuild {
    name: String,
    /// Index into `sections` (not raw ELF index — we fix that up).
    section: Option<usize>,
    value: u64,
    size: u64,
    /// Kind/binding bits packed into `st_info`.
    st_info: u8,
    st_other: u8,
}

impl CubinBuilder {
    fn new() -> Self {
        Self {
            sections: Vec::new(),
            symbols: Vec::new(),
            abi_version: 7,
            e_flags: 0x0050_0550, // sm_80 V1
        }
    }

    fn text(&mut self, name: &str, body: &[u8]) -> usize {
        self.sections.push(SectionBuild {
            name: format!(".text.{}", name),
            sh_type: SHT_PROGBITS,
            sh_flags: SHF_ALLOC | SHF_EXECINSTR,
            data: body.to_vec(),
            nobits_logical_size: 0,
        });
        self.sections.len() - 1
    }

    fn nv_info_module(&mut self, blob: &[u8]) -> usize {
        self.sections.push(SectionBuild {
            name: ".nv.info".to_string(),
            sh_type: SHT_PROGBITS,
            sh_flags: 0,
            data: blob.to_vec(),
            nobits_logical_size: 0,
        });
        self.sections.len() - 1
    }

    fn nv_info_kernel(&mut self, kernel: &str, blob: &[u8]) -> usize {
        self.sections.push(SectionBuild {
            name: format!(".nv.info.{}", kernel),
            sh_type: SHT_PROGBITS,
            sh_flags: 0,
            data: blob.to_vec(),
            nobits_logical_size: 0,
        });
        self.sections.len() - 1
    }

    fn constant_bank(&mut self, bank: u8, owner: Option<&str>, size: u64) -> usize {
        let name = match owner {
            Some(k) => format!(".nv.constant{}.{}", bank, k),
            None => format!(".nv.constant{}", bank),
        };
        self.sections.push(SectionBuild {
            name,
            sh_type: SHT_PROGBITS,
            sh_flags: SHF_ALLOC,
            data: vec![0u8; size as usize],
            nobits_logical_size: 0,
        });
        self.sections.len() - 1
    }

    fn shared_nobits(&mut self, owner: &str, logical: u64) -> usize {
        self.sections.push(SectionBuild {
            name: format!(".nv.shared.{}", owner),
            sh_type: SHT_NOBITS,
            sh_flags: SHF_ALLOC | SHF_WRITE,
            data: Vec::new(),
            nobits_logical_size: logical,
        });
        self.sections.len() - 1
    }

    fn local_region(&mut self, owner: Option<&str>, logical: u64) -> usize {
        let name = match owner {
            Some(k) => format!(".nv.local.{}", k),
            None => ".nv.local".to_string(),
        };
        self.sections.push(SectionBuild {
            name,
            sh_type: SHT_NOBITS,
            sh_flags: SHF_ALLOC | SHF_WRITE,
            data: Vec::new(),
            nobits_logical_size: logical,
        });
        self.sections.len() - 1
    }

    fn kernel_symbol(&mut self, name: &str, section: usize, size: u64, entry: bool) {
        // STT_FUNC | STB_GLOBAL = 0x12; optional STO_CUDA_ENTRY in st_other.
        self.symbols.push(SymbolBuild {
            name: name.to_string(),
            section: Some(section),
            value: 0,
            size,
            st_info: (1u8 << 4) | 2, // STB_GLOBAL | STT_FUNC
            st_other: if entry { STO_CUDA_ENTRY } else { 0 },
        });
    }

    fn helper_symbol(&mut self, name: &str, section: usize, offset: u64, size: u64) {
        // STB_LOCAL | STT_FUNC = 0x02, no entry marker.
        self.symbols.push(SymbolBuild {
            name: name.to_string(),
            section: Some(section),
            value: offset,
            size,
            st_info: 2, // STB_LOCAL | STT_FUNC
            st_other: 0,
        });
    }

    fn build(&self) -> Vec<u8> {
        // Layout: [ELF header][section data (including strtabs)][section headers]
        //
        // Section indices (in order):
        //   0: SHN_UNDEF (empty, required)
        //   1..n+1: user sections in insertion order
        //   n+1: .shstrtab
        //   n+2: .symtab
        //   n+3: .strtab (symbol names)
        //
        // We assemble section data linearly; each section's `sh_offset`
        // points into the concatenated data blob.
        const EHSIZE: usize = 64;
        const SHENTSIZE: usize = 64;
        const SYMENTSIZE: usize = 24;

        // Build shstrtab (section names).
        let mut shstrtab = vec![0u8]; // null at index 0
        let section_name_offsets: Vec<u32> = self
            .sections
            .iter()
            .map(|s| {
                let off = shstrtab.len() as u32;
                shstrtab.extend_from_slice(s.name.as_bytes());
                shstrtab.push(0);
                off
            })
            .collect();
        let shstrtab_name_off = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".shstrtab\0");
        let symtab_name_off = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".symtab\0");
        let strtab_name_off = shstrtab.len() as u32;
        shstrtab.extend_from_slice(b".strtab\0");

        // Build symbol strtab.
        let mut strtab = vec![0u8];
        let sym_name_offsets: Vec<u32> = self
            .symbols
            .iter()
            .map(|s| {
                let off = strtab.len() as u32;
                strtab.extend_from_slice(s.name.as_bytes());
                strtab.push(0);
                off
            })
            .collect();

        // Build the symbol table: one null entry + user symbols.
        let n_user_sections = self.sections.len();
        let shstrtab_idx = 1 + n_user_sections;
        let symtab_idx = shstrtab_idx + 1;
        let strtab_idx = symtab_idx + 1;

        let mut symtab = vec![0u8; SYMENTSIZE]; // null entry
        for (i, sym) in self.symbols.iter().enumerate() {
            let mut entry = [0u8; SYMENTSIZE];
            let name_off = sym_name_offsets[i];
            entry[0..4].copy_from_slice(&name_off.to_le_bytes());
            entry[4] = sym.st_info;
            entry[5] = sym.st_other;
            let shndx: u16 = match sym.section {
                Some(idx) => (1 + idx) as u16,
                None => 0,
            };
            entry[6..8].copy_from_slice(&shndx.to_le_bytes());
            entry[8..16].copy_from_slice(&sym.value.to_le_bytes());
            entry[16..24].copy_from_slice(&sym.size.to_le_bytes());
            symtab.extend_from_slice(&entry);
        }

        // Decide layout: section data goes right after the ELF header.
        let mut data_blob: Vec<u8> = Vec::new();
        let mut user_offsets: Vec<u64> = Vec::with_capacity(n_user_sections);
        for s in &self.sections {
            // 8-byte align the start of each section's payload.
            while data_blob.len() % 8 != 0 {
                data_blob.push(0);
            }
            let off = EHSIZE + data_blob.len();
            user_offsets.push(off as u64);
            data_blob.extend_from_slice(&s.data);
        }

        while data_blob.len() % 8 != 0 {
            data_blob.push(0);
        }
        let shstrtab_off = EHSIZE + data_blob.len();
        data_blob.extend_from_slice(&shstrtab);
        while data_blob.len() % 8 != 0 {
            data_blob.push(0);
        }
        let symtab_off = EHSIZE + data_blob.len();
        data_blob.extend_from_slice(&symtab);
        while data_blob.len() % 8 != 0 {
            data_blob.push(0);
        }
        let strtab_off = EHSIZE + data_blob.len();
        data_blob.extend_from_slice(&strtab);
        while data_blob.len() % 8 != 0 {
            data_blob.push(0);
        }
        let shoff = EHSIZE + data_blob.len();

        // Build section headers. Section 0 is SHN_UNDEF.
        let mut shtable: Vec<u8> = vec![0u8; SHENTSIZE];

        for (i, s) in self.sections.iter().enumerate() {
            let mut h = [0u8; SHENTSIZE];
            h[0..4].copy_from_slice(&section_name_offsets[i].to_le_bytes());
            h[4..8].copy_from_slice(&s.sh_type.to_le_bytes());
            h[8..16].copy_from_slice(&s.sh_flags.to_le_bytes());
            h[16..24].copy_from_slice(&0u64.to_le_bytes()); // sh_addr
            h[24..32].copy_from_slice(&user_offsets[i].to_le_bytes());
            let sh_size = if s.sh_type == SHT_NOBITS {
                if s.nobits_logical_size != 0 {
                    s.nobits_logical_size
                } else {
                    s.data.len() as u64
                }
            } else {
                s.data.len() as u64
            };
            h[32..40].copy_from_slice(&sh_size.to_le_bytes());
            h[40..44].copy_from_slice(&0u32.to_le_bytes()); // sh_link
            h[44..48].copy_from_slice(&0u32.to_le_bytes()); // sh_info
            h[48..56].copy_from_slice(&1u64.to_le_bytes()); // sh_addralign
            h[56..64].copy_from_slice(&0u64.to_le_bytes()); // sh_entsize
            shtable.extend_from_slice(&h);
        }

        // .shstrtab header
        {
            let mut h = [0u8; SHENTSIZE];
            h[0..4].copy_from_slice(&shstrtab_name_off.to_le_bytes());
            h[4..8].copy_from_slice(&SHT_STRTAB.to_le_bytes());
            h[24..32].copy_from_slice(&(shstrtab_off as u64).to_le_bytes());
            h[32..40].copy_from_slice(&(shstrtab.len() as u64).to_le_bytes());
            h[48..56].copy_from_slice(&1u64.to_le_bytes());
            shtable.extend_from_slice(&h);
        }
        // .symtab header
        {
            let mut h = [0u8; SHENTSIZE];
            h[0..4].copy_from_slice(&symtab_name_off.to_le_bytes());
            h[4..8].copy_from_slice(&SHT_SYMTAB.to_le_bytes());
            h[24..32].copy_from_slice(&(symtab_off as u64).to_le_bytes());
            h[32..40].copy_from_slice(&(symtab.len() as u64).to_le_bytes());
            h[40..44].copy_from_slice(&(strtab_idx as u32).to_le_bytes()); // sh_link
            h[56..64].copy_from_slice(&(SYMENTSIZE as u64).to_le_bytes());
            shtable.extend_from_slice(&h);
        }
        // .strtab header
        {
            let mut h = [0u8; SHENTSIZE];
            h[0..4].copy_from_slice(&strtab_name_off.to_le_bytes());
            h[4..8].copy_from_slice(&SHT_STRTAB.to_le_bytes());
            h[24..32].copy_from_slice(&(strtab_off as u64).to_le_bytes());
            h[32..40].copy_from_slice(&(strtab.len() as u64).to_le_bytes());
            h[48..56].copy_from_slice(&1u64.to_le_bytes());
            shtable.extend_from_slice(&h);
        }

        // ELF header.
        let total_sections = (self.sections.len() + 4) as u16; // +SHN_UNDEF +shstrtab +symtab +strtab
        let mut elf = vec![0u8; EHSIZE];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2; // ELF64
        elf[5] = 1; // LE
        elf[6] = 1; // EI_VERSION
        elf[7] = 0; // EI_OSABI
        elf[8] = self.abi_version;
        elf[16] = 2; // ET_EXEC
        elf[18] = 190; // EM_CUDA
        elf[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
                                                          // e_entry, e_phoff left zero
        elf[40..48].copy_from_slice(&(shoff as u64).to_le_bytes()); // e_shoff
        elf[48..52].copy_from_slice(&self.e_flags.to_le_bytes());
        elf[52..54].copy_from_slice(&(EHSIZE as u16).to_le_bytes());
        elf[58..60].copy_from_slice(&(SHENTSIZE as u16).to_le_bytes());
        elf[60..62].copy_from_slice(&total_sections.to_le_bytes());
        elf[62..64].copy_from_slice(&(shstrtab_idx as u16).to_le_bytes()); // e_shstrndx

        elf.extend_from_slice(&data_blob);
        elf.extend_from_slice(&shtable);
        elf
    }
}

// SHF_* / SHT_* constants copied locally so we don't pull from the super
// module's private constants indirectly.
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHF_WRITE: u64 = 0x1;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;

#[test]
fn rejects_non_cuda_elf() {
    // A synthetic ELF64 with machine = x86_64 should fail the view.
    let mut data = vec![0u8; 64];
    data[0..4].copy_from_slice(b"\x7fELF");
    data[4] = 2;
    data[5] = 1;
    data[6] = 1;
    data[16] = 2;
    data[18] = 62; // EM_X86_64
    let elf = Elf::parse(&data).unwrap();
    assert!(matches!(elf.cubin_view(), Err(CubinError::NotCuda)));
}

#[test]
fn sto_cuda_entry_symbol_promotes_to_kernel() {
    let mut b = CubinBuilder::new();
    let ti = b.text("_Z3fooPi", &[0x00, 0x11, 0x22, 0x33]);
    b.kernel_symbol("_Z3fooPi", ti, 4, true);
    let bytes = b.build();

    let elf = Elf::parse(&bytes).unwrap();
    let view = elf.cubin_view().expect("cuda view");

    assert_eq!(view.kernels().len(), 1);
    let k = &view.kernels()[0];
    assert_eq!(k.name, "_Z3fooPi");
    assert_eq!(k.code, &[0x00, 0x11, 0x22, 0x33]);
    assert_eq!(k.size, 4);
    assert_eq!(k.confidence, KernelConfidence::EntryMarker);
    assert!(k.symbol.is_some());
    assert!(view.diagnostics().is_empty(), "{:?}", view.diagnostics());
    assert_eq!(view.entry_kernels().count(), 1);
}

#[test]
fn nv_info_sidecar_promotes_to_kernel_but_with_weak_confidence() {
    // A `.nv.info.<name>` sibling alone is *not* a reliable kernel marker
    // on real cubins — an out-of-line __device__ function can also have a
    // per-function info section. We still surface the candidate so M5
    // semantic decoding can refine it, but flag confidence so strict
    // consumers can filter.
    let mut b = CubinBuilder::new();
    let ti = b.text("myKernel", &[0xde, 0xad, 0xbe, 0xef]);
    let _info = b.nv_info_kernel("myKernel", &[0x03, 0x05, 0x00, 0x01]); // HVAL MaxThreads
    b.kernel_symbol("myKernel", ti, 4, false); // NO entry marker
    let bytes = b.build();

    let elf = Elf::parse(&bytes).unwrap();
    let view = elf.cubin_view().unwrap();
    assert_eq!(view.kernels().len(), 1);
    let k = &view.kernels()[0];
    assert_eq!(k.name, "myKernel");
    assert_eq!(k.confidence, KernelConfidence::SiblingInfoOnly);
    assert!(k.nv_info.is_some());
    assert_eq!(k.nv_info.as_ref().unwrap().entries.len(), 1);
    // entry_kernels() excludes weak matches.
    assert_eq!(view.entry_kernels().count(), 0);
}

#[test]
fn text_without_marker_or_sidecar_is_ambiguous() {
    // A plain `.text.<name>` with only a helper-style symbol, no entry
    // marker, no sibling .nv.info — we refuse to surface it as a kernel
    // and emit a diagnostic instead.
    let mut b = CubinBuilder::new();
    let ti = b.text("helperFn", &[0xaa; 8]);
    b.kernel_symbol("helperFn", ti, 8, false);
    let bytes = b.build();

    let elf = Elf::parse(&bytes).unwrap();
    let view = elf.cubin_view().unwrap();
    assert!(view.kernels().is_empty());
    assert_eq!(view.diagnostics().len(), 1);
    assert!(matches!(
        view.diagnostics()[0].kind,
        CubinDiagnosticKind::AmbiguousTextSection
    ));
}

#[test]
fn orphan_nv_info_is_diagnosed() {
    let mut b = CubinBuilder::new();
    let _info = b.nv_info_kernel("ghost", &[0x01, 0x01]); // NVAL entry, nothing else
    let bytes = b.build();

    let elf = Elf::parse(&bytes).unwrap();
    let view = elf.cubin_view().unwrap();
    assert!(view.kernels().is_empty());
    assert_eq!(view.diagnostics().len(), 1);
    assert!(matches!(
        view.diagnostics()[0].kind,
        CubinDiagnosticKind::OrphanNvInfoSection
    ));
}

#[test]
fn constant_banks_are_parsed_with_correct_bank_number() {
    let mut b = CubinBuilder::new();
    let ti = b.text("kernel", &[0]);
    let _info = b.nv_info_kernel("kernel", &[0x01, 0x01]);
    let _ = b.constant_bank(0, Some("kernel"), 16); // params
    let _ = b.constant_bank(2, None, 32); // module-wide bank 2
    b.kernel_symbol("kernel", ti, 1, true);
    let bytes = b.build();

    let elf = Elf::parse(&bytes).unwrap();
    let view = elf.cubin_view().unwrap();

    let banks: Vec<(u8, Option<&str>)> = view
        .memory_regions()
        .iter()
        .filter_map(|r| match r.space {
            MemorySpace::Constant { bank } => Some((bank, r.owner_kernel)),
            _ => None,
        })
        .collect();

    assert!(banks.contains(&(0, Some("kernel"))), "{:?}", banks);
    assert!(banks.contains(&(2, None)), "{:?}", banks);
}

#[test]
fn nobits_shared_region_has_no_bytes() {
    let mut b = CubinBuilder::new();
    let ti = b.text("kernel", &[0]);
    let _info = b.nv_info_kernel("kernel", &[0x01, 0x01]);
    let _ = b.shared_nobits("kernel", 1024);
    b.kernel_symbol("kernel", ti, 1, true);
    let bytes = b.build();

    let elf = Elf::parse(&bytes).unwrap();
    let view = elf.cubin_view().unwrap();

    let shared: Vec<&MemoryRegion> = view
        .memory_regions()
        .iter()
        .filter(|r| matches!(r.space, MemorySpace::Shared))
        .collect();
    assert_eq!(shared.len(), 1);
    assert!(
        shared[0].bytes.is_none(),
        "SHT_NOBITS must not expose bytes"
    );
    assert_eq!(shared[0].size, 1024);
    assert_eq!(shared[0].owner_kernel, Some("kernel"));
}

#[test]
fn helper_symbol_inside_kernel_section_does_not_spawn_extra_kernel() {
    let mut b = CubinBuilder::new();
    let ti = b.text("_Z6kernelP", &[0; 32]);
    b.kernel_symbol("_Z6kernelP", ti, 32, true);
    b.helper_symbol("__inline_helper", ti, 16, 8); // helper inside same .text
    let bytes = b.build();

    let elf = Elf::parse(&bytes).unwrap();
    let view = elf.cubin_view().unwrap();
    assert_eq!(view.kernels().len(), 1);
    assert_eq!(view.kernels()[0].name, "_Z6kernelP");
}

#[test]
fn module_wide_nv_info_is_captured() {
    let mut b = CubinBuilder::new();
    let ti = b.text("kernel", &[0]);
    let _info = b.nv_info_kernel("kernel", &[0x01, 0x01]);
    b.nv_info_module(&[0x03, 0x1b, 0x40, 0x00]); // HVAL MaxRegCount = 64
    b.kernel_symbol("kernel", ti, 1, true);
    let bytes = b.build();

    let elf = Elf::parse(&bytes).unwrap();
    let view = elf.cubin_view().unwrap();
    let module = view.module_info().expect("module-wide .nv.info");
    assert_eq!(module.entries.len(), 1);
    assert_eq!(module.entries[0].attribute, NvInfoAttribute::MaxRegCount);
}

#[test]
fn duplicate_kernel_names_are_diagnosed() {
    let mut b = CubinBuilder::new();
    let ti1 = b.text("dup", &[0xaa]);
    let ti2 = b.text("dup", &[0xbb]);
    b.kernel_symbol("dup", ti1, 1, true);
    b.kernel_symbol("dup", ti2, 1, true);
    let bytes = b.build();

    let elf = Elf::parse(&bytes).unwrap();
    let view = elf.cubin_view().unwrap();
    assert_eq!(view.kernels().len(), 1);
    assert!(view
        .diagnostics()
        .iter()
        .any(|d| matches!(d.kind, CubinDiagnosticKind::DuplicateKernelName)));
}

#[test]
fn accessor_by_name_works() {
    let mut b = CubinBuilder::new();
    let ti = b.text("kernelA", &[0x1]);
    b.kernel_symbol("kernelA", ti, 1, true);
    let bytes = b.build();

    let elf = Elf::parse(&bytes).unwrap();
    let view = elf.cubin_view().unwrap();
    assert!(view.kernel_by_name("kernelA").is_some());
    assert!(view.kernel_by_name("nope").is_none());
}

#[test]
fn nv_local_region_is_classified_with_owner() {
    let mut b = CubinBuilder::new();
    let ti = b.text("kernel", &[0]);
    let _info = b.nv_info_kernel("kernel", &[0x01, 0x01]);
    let _ = b.local_region(Some("kernel"), 64);
    let _ = b.local_region(None, 128);
    b.kernel_symbol("kernel", ti, 1, true);
    let bytes = b.build();

    let elf = Elf::parse(&bytes).unwrap();
    let view = elf.cubin_view().unwrap();

    let locals: Vec<(&str, Option<&str>, u64)> = view
        .memory_regions()
        .iter()
        .filter(|r| matches!(r.space, MemorySpace::Local))
        .map(|r| (r.name, r.owner_kernel, r.size))
        .collect();

    assert!(
        locals.contains(&(".nv.local.kernel", Some("kernel"), 64)),
        "{:?}",
        locals
    );
    assert!(locals.contains(&(".nv.local", None, 128)), "{:?}", locals);
}

#[test]
fn entry_kernels_filters_out_weak_matches() {
    // One kernel with STO_CUDA_ENTRY + one "device function" with only a
    // sibling .nv.info. kernels() returns both; entry_kernels() returns
    // only the strong one.
    let mut b = CubinBuilder::new();
    let k_idx = b.text("_Z9realKerneli", &[0xaa; 8]);
    b.kernel_symbol("_Z9realKerneli", k_idx, 8, true);

    let h_idx = b.text("_Z8helperFni", &[0xbb; 8]);
    let _info = b.nv_info_kernel("_Z8helperFni", &[0x01, 0x01]); // bare NVAL PAD
    b.kernel_symbol("_Z8helperFni", h_idx, 8, false); // NO entry marker

    let bytes = b.build();
    let elf = Elf::parse(&bytes).unwrap();
    let view = elf.cubin_view().unwrap();

    assert_eq!(view.kernels().len(), 2);
    assert_eq!(view.entry_kernels().count(), 1);
    assert_eq!(view.entry_kernels().next().unwrap().name, "_Z9realKerneli");

    let weak: Vec<&Kernel> = view
        .kernels()
        .iter()
        .filter(|k| k.confidence == KernelConfidence::SiblingInfoOnly)
        .collect();
    assert_eq!(weak.len(), 1);
    assert_eq!(weak[0].name, "_Z8helperFni");
}
