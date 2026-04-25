//! End-to-end tests against synthesised AMDGPU code objects.
//!
//! ROCm isn't available on every dev box, so we hand-build minimal
//! AMDGPU ELFs in-test. The fixtures here cover:
//!
//! - A single-kernel object: one `<kernel>` entry symbol + one
//!   `<kernel>.kd` descriptor symbol, both resolving to readable
//!   bytes through `bytes_at`.
//! - A multi-kernel object: two pairs, ensuring kernels don't shadow
//!   each other.
//! - An orphan-descriptor case: `.kd` symbol present, no entry —
//!   surfaces as a soft diagnostic, not a hard failure.

use super::*;
use crate::Elf;

/// Minimal little-endian ELF64 builder for AMDGPU code-object tests.
///
/// Produces an ET_REL relocatable file with:
/// - a `.text` section holding `entry_bytes` (instruction stream)
/// - a `.rodata` section holding the descriptor blocks
/// - a `.symtab` + `.strtab` with one entry/`.kd` pair per kernel
/// - the standard `.shstrtab` for section names
/// - `EM_AMDGPU = 224`, gfx906 mach (`0x2F`), V4 ABI
struct AmdElfBuilder {
    /// (entry_name, entry_offset_in_text, descriptor_bytes)
    kernels: Vec<(String, u64, [u8; KERNEL_DESCRIPTOR_SIZE])>,
    /// Bytes of the `.text` section.
    text_bytes: Vec<u8>,
    /// Whether to emit an orphan `.kd` symbol with no matching entry.
    orphan_kd: Option<(String, [u8; KERNEL_DESCRIPTOR_SIZE])>,
    /// Mach value to embed in `e_flags`. Defaults to gfx906 (`0x2F`).
    mach: u32,
}

impl AmdElfBuilder {
    fn new() -> Self {
        Self {
            kernels: Vec::new(),
            text_bytes: Vec::new(),
            orphan_kd: None,
            mach: 0x2F,
        }
    }

    fn with_mach(mut self, mach: u32) -> Self {
        self.mach = mach;
        self
    }

    fn push_kernel(
        mut self,
        name: &str,
        instructions: &[u8],
        descriptor: [u8; KERNEL_DESCRIPTOR_SIZE],
    ) -> Self {
        let offset = self.text_bytes.len() as u64;
        self.text_bytes.extend_from_slice(instructions);
        self.kernels.push((name.to_string(), offset, descriptor));
        self
    }

    fn push_orphan_kd(mut self, name: &str, descriptor: [u8; KERNEL_DESCRIPTOR_SIZE]) -> Self {
        self.orphan_kd = Some((name.to_string(), descriptor));
        self
    }

    /// Lay out and emit the ELF. The layout is intentionally simple:
    ///
    /// ```text
    ///   ehdr           [0  .. 64]
    ///   .text          [64 .. 64 + text_len]
    ///   .rodata        [.. + sum(descriptor sizes)]
    ///   .shstrtab      [..]
    ///   .strtab        [..]
    ///   .symtab        [..]
    ///   shdrs          [end .. end + 6 * shentsize]
    /// ```
    fn build(self) -> Vec<u8> {
        // Section names string table.
        // Indices: 0 = "" (null), then names follow.
        let shstr = b"\0.text\0.rodata\0.shstrtab\0.strtab\0.symtab\0";
        let sh_text = 1u32; // ".text"
        let sh_rodata = 7u32;
        let sh_shstrtab = 15u32;
        let sh_strtab = 25u32;
        let sh_symtab = 33u32;

        // .text bytes (instructions for all kernels concatenated).
        let text_bytes = self.text_bytes;

        // .rodata bytes (kernel descriptors concatenated).
        let mut rodata_bytes: Vec<u8> = Vec::new();
        let mut kd_offsets: Vec<u64> = Vec::new();
        for (_, _, desc) in &self.kernels {
            kd_offsets.push(rodata_bytes.len() as u64);
            rodata_bytes.extend_from_slice(desc);
        }
        let orphan_kd_offset = self.orphan_kd.as_ref().map(|(_, desc)| {
            let off = rodata_bytes.len() as u64;
            rodata_bytes.extend_from_slice(desc);
            off
        });

        // .strtab — symbol name string table.
        let mut strtab = vec![0u8]; // index 0 = ""
        let mut entry_name_offs = Vec::new();
        let mut kd_name_offs = Vec::new();
        for (name, _, _) in &self.kernels {
            entry_name_offs.push(strtab.len() as u32);
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
            kd_name_offs.push(strtab.len() as u32);
            strtab.extend_from_slice(name.as_bytes());
            strtab.extend_from_slice(b".kd\0");
        }
        let orphan_kd_name_off = if let Some((name, _)) = &self.orphan_kd {
            let off = strtab.len() as u32;
            strtab.extend_from_slice(name.as_bytes());
            strtab.extend_from_slice(b".kd\0");
            Some(off)
        } else {
            None
        };

        // .symtab. ELF64 Sym is 24 bytes: name(4) info(1) other(1)
        // shndx(2) value(8) size(8). Section indices: 0 = SHN_UNDEF,
        // 1 = .text, 2 = .rodata.
        const SYM_SIZE: usize = 24;
        let st_info_func = 0x12u8; // STB_GLOBAL | STT_FUNC
        let st_info_object = 0x11u8; // STB_GLOBAL | STT_OBJECT

        let mut symtab = vec![0u8; SYM_SIZE]; // Index 0: STN_UNDEF.
        let mut push_sym = |name_off: u32, info: u8, shndx: u16, value: u64, size: u64| {
            let mut s = [0u8; SYM_SIZE];
            s[0..4].copy_from_slice(&name_off.to_le_bytes());
            s[4] = info;
            s[5] = 0; // st_other
            s[6..8].copy_from_slice(&shndx.to_le_bytes());
            s[8..16].copy_from_slice(&value.to_le_bytes());
            s[16..24].copy_from_slice(&size.to_le_bytes());
            symtab.extend_from_slice(&s);
        };

        for (i, (_, entry_off, _)) in self.kernels.iter().enumerate() {
            push_sym(entry_name_offs[i], st_info_func, 1, *entry_off, 4);
            push_sym(
                kd_name_offs[i],
                st_info_object,
                2,
                kd_offsets[i],
                KERNEL_DESCRIPTOR_SIZE as u64,
            );
        }
        if let (Some(off), Some((_, _))) = (orphan_kd_name_off, self.orphan_kd.as_ref()) {
            push_sym(
                off,
                st_info_object,
                2,
                orphan_kd_offset.unwrap(),
                KERNEL_DESCRIPTOR_SIZE as u64,
            );
        }

        // Lay out file offsets.
        let ehdr_size = 64u64;
        let text_off = ehdr_size;
        let text_len = text_bytes.len() as u64;
        let rodata_off = text_off + text_len;
        let rodata_len = rodata_bytes.len() as u64;
        let shstrtab_off = rodata_off + rodata_len;
        let shstrtab_len = shstr.len() as u64;
        let strtab_off = shstrtab_off + shstrtab_len;
        let strtab_len = strtab.len() as u64;
        let symtab_off = strtab_off + strtab_len;
        let symtab_len = symtab.len() as u64;
        let shdrs_off = symtab_off + symtab_len;

        let mut data = Vec::with_capacity(shdrs_off as usize + 6 * 64);

        // ELF64 header.
        let mut ehdr = vec![0u8; 64];
        ehdr[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        ehdr[4] = 2; // ELF64
        ehdr[5] = 1; // little-endian
        ehdr[6] = 1; // EI_VERSION
        ehdr[7] = 64; // ELFOSABI_AMDGPU_HSA
        ehdr[8] = 2; // EI_ABIVERSION = V4
        ehdr[16..18].copy_from_slice(&1u16.to_le_bytes()); // ET_REL
        ehdr[18..20].copy_from_slice(&224u16.to_le_bytes()); // EM_AMDGPU
        ehdr[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        ehdr[40..48].copy_from_slice(&shdrs_off.to_le_bytes()); // e_shoff
        ehdr[48..52].copy_from_slice(&self.mach.to_le_bytes()); // e_flags
        ehdr[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        ehdr[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        ehdr[60..62].copy_from_slice(&6u16.to_le_bytes()); // e_shnum (null + 5)
        ehdr[62..64].copy_from_slice(&3u16.to_le_bytes()); // e_shstrndx = 3
        data.extend_from_slice(&ehdr);

        // Section data, in the order described above.
        data.extend_from_slice(&text_bytes);
        data.extend_from_slice(&rodata_bytes);
        data.extend_from_slice(shstr);
        data.extend_from_slice(&strtab);
        data.extend_from_slice(&symtab);

        // Section headers (each 64 bytes for ELF64).
        // sh_name (4) sh_type (4) sh_flags (8) sh_addr (8) sh_offset (8)
        // sh_size (8) sh_link (4) sh_info (4) sh_addralign (8)
        // sh_entsize (8) = 64 bytes.
        let make_shdr = |name: u32,
                         ty: u32,
                         flags: u64,
                         addr: u64,
                         off: u64,
                         size: u64,
                         link: u32,
                         info: u32,
                         align: u64,
                         entsize: u64|
         -> Vec<u8> {
            let mut h = vec![0u8; 64];
            h[0..4].copy_from_slice(&name.to_le_bytes());
            h[4..8].copy_from_slice(&ty.to_le_bytes());
            h[8..16].copy_from_slice(&flags.to_le_bytes());
            h[16..24].copy_from_slice(&addr.to_le_bytes());
            h[24..32].copy_from_slice(&off.to_le_bytes());
            h[32..40].copy_from_slice(&size.to_le_bytes());
            h[40..44].copy_from_slice(&link.to_le_bytes());
            h[44..48].copy_from_slice(&info.to_le_bytes());
            h[48..56].copy_from_slice(&align.to_le_bytes());
            h[56..64].copy_from_slice(&entsize.to_le_bytes());
            h
        };

        // 0: null section.
        data.extend_from_slice(&[0u8; 64]);
        // 1: .text — SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR.
        data.extend_from_slice(&make_shdr(
            sh_text, 1, 0x6, 0, text_off, text_len, 0, 0, 1, 0,
        ));
        // 2: .rodata — SHT_PROGBITS, SHF_ALLOC.
        data.extend_from_slice(&make_shdr(
            sh_rodata, 1, 0x2, 0, rodata_off, rodata_len, 0, 0, 1, 0,
        ));
        // 3: .shstrtab — SHT_STRTAB.
        data.extend_from_slice(&make_shdr(
            sh_shstrtab,
            3,
            0,
            0,
            shstrtab_off,
            shstrtab_len,
            0,
            0,
            1,
            0,
        ));
        // 4: .strtab — SHT_STRTAB.
        data.extend_from_slice(&make_shdr(
            sh_strtab, 3, 0, 0, strtab_off, strtab_len, 0, 0, 1, 0,
        ));
        // 5: .symtab — SHT_SYMTAB. sh_link points to .strtab (4),
        // sh_info is "first non-local symbol index" — we have no
        // local symbols beyond STN_UNDEF, so info = 1.
        data.extend_from_slice(&make_shdr(
            sh_symtab,
            2,
            0,
            0,
            symtab_off,
            symtab_len,
            4,
            1,
            8,
            SYM_SIZE as u64,
        ));

        data
    }
}

fn descriptor_with_vgpr_sgpr(vgpr_raw: u32, sgpr_raw: u32, kernarg_size: u32) -> [u8; 64] {
    let rsrc1 = (vgpr_raw & 0x3f) | ((sgpr_raw & 0xf) << 6);
    let mut d = [0u8; 64];
    d[8..12].copy_from_slice(&kernarg_size.to_le_bytes());
    d[16..24].copy_from_slice(&0x100i64.to_le_bytes()); // entry offset
    d[48..52].copy_from_slice(&rsrc1.to_le_bytes());
    d
}

#[test]
fn rejects_non_amdgpu_elf() {
    // Build an ELF with a non-AMDGPU machine type.
    let bytes = AmdElfBuilder::new().with_mach(0).build();
    // Override the e_machine field to x86_64 (62).
    let mut bytes = bytes;
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    let elf = Elf::parse(&bytes).expect("parses as generic ELF");
    let err = elf.code_object_view().unwrap_err();
    assert_eq!(err, CodeObjectError::NotAmdgpu);
}

#[test]
fn single_kernel_round_trips() {
    let desc = descriptor_with_vgpr_sgpr(2, 1, 24);
    let bytes = AmdElfBuilder::new()
        .push_kernel("vector_add", &[0x00, 0x80, 0x00, 0xbf], desc)
        .build();
    let elf = Elf::parse(&bytes).expect("synthetic AMDGPU ELF parses");
    let view = elf.code_object_view().expect("code object view builds");

    assert_eq!(view.target.canonical_name(), "gfx906");
    assert_eq!(view.kernels.len(), 1);
    assert_eq!(view.diagnostics.len(), 0);

    let k = &view.kernels[0];
    assert_eq!(k.name, "vector_add");
    assert_eq!(k.descriptor.kernarg_size, 24);
    // raw=2 → (2+1)*4 = 12 vgprs on gfx906 (wave64).
    assert_eq!(k.resource_usage.vgpr_count, 12);
    // raw=1 → (1+1)*8 = 16 sgprs.
    assert_eq!(k.resource_usage.sgpr_count, 16);
    assert_eq!(k.resource_usage.kernarg_size, 24);
}

#[test]
fn multiple_kernels_each_get_their_own_summary() {
    let desc1 = descriptor_with_vgpr_sgpr(0, 0, 16); // 4 vgpr, 8 sgpr
    let desc2 = descriptor_with_vgpr_sgpr(3, 2, 32); // 16 vgpr, 24 sgpr
    let bytes = AmdElfBuilder::new()
        .push_kernel("k1", &[0u8; 4], desc1)
        .push_kernel("k2", &[0u8; 4], desc2)
        .build();
    let elf = Elf::parse(&bytes).expect("synthetic AMDGPU ELF parses");
    let view = elf.code_object_view().expect("code object view builds");
    assert_eq!(view.kernels.len(), 2);

    let names: Vec<&str> = view.kernels.iter().map(|k| k.name).collect();
    assert!(names.contains(&"k1"));
    assert!(names.contains(&"k2"));

    let k1 = view.kernels.iter().find(|k| k.name == "k1").unwrap();
    let k2 = view.kernels.iter().find(|k| k.name == "k2").unwrap();
    assert_eq!(k1.resource_usage.vgpr_count, 4);
    assert_eq!(k2.resource_usage.vgpr_count, 16);
}

#[test]
fn orphan_kd_surfaces_diagnostic_not_panic() {
    let desc = descriptor_with_vgpr_sgpr(0, 0, 0);
    let bytes = AmdElfBuilder::new().push_orphan_kd("ghost", desc).build();
    let elf = Elf::parse(&bytes).expect("synthetic AMDGPU ELF parses");
    let view = elf.code_object_view().expect("view still builds");
    // The kernel still appears, just with a diagnostic for the
    // missing entry symbol.
    assert_eq!(view.kernels.len(), 1);
    assert_eq!(view.kernels[0].name, "ghost");
    assert_eq!(view.kernels[0].entry_addr, 0);
    assert!(view
        .diagnostics
        .iter()
        .any(|d| d.kind == CodeObjectDiagnosticKind::OrphanEntry));
}

#[test]
fn target_id_carries_through_view() {
    // Build with gfx1030 mach.
    let desc = descriptor_with_vgpr_sgpr(0, 0, 0);
    let bytes = AmdElfBuilder::new()
        .with_mach(0x36)
        .push_kernel("k", &[0u8; 4], desc)
        .build();
    let elf = Elf::parse(&bytes).expect("synthetic AMDGPU ELF parses");
    let view = elf.code_object_view().expect("code object view builds");
    assert_eq!(view.target.canonical_name(), "gfx1030");
}
