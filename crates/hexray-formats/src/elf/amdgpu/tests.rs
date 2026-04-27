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

/// Build a minimal `NT_AMDGPU_METADATA` note (header + name +
/// descriptor) ready to be embedded in a SHT_NOTE section.
fn build_amdgpu_metadata_note(msgpack_payload: &[u8]) -> Vec<u8> {
    let name = b"AMDGPU\0";
    let mut out = Vec::new();
    // namesz, descsz, type
    out.extend_from_slice(&(name.len() as u32).to_le_bytes());
    out.extend_from_slice(&(msgpack_payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&32u32.to_le_bytes()); // NT_AMDGPU_METADATA
    out.extend_from_slice(name);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out.extend_from_slice(msgpack_payload);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

/// Build a tiny MessagePack metadata blob with one kernel.
fn build_msgpack_for(kernel_name: &str, vgpr: u32, sgpr: u32, kernarg: u64) -> Vec<u8> {
    let mut b = Vec::new();
    // top-level fixmap len=2: amdhsa.version, amdhsa.kernels
    b.push(0x82);
    push_str(&mut b, "amdhsa.version");
    b.extend_from_slice(&[0x92, 0x01, 0x00]); // [1, 0]
    push_str(&mut b, "amdhsa.kernels");
    b.push(0x91); // array len=1
                  // kernel: fixmap len=5
    b.push(0x85);
    push_str(&mut b, ".name");
    push_str(&mut b, kernel_name);
    push_str(&mut b, ".symbol");
    push_str(&mut b, &format!("{kernel_name}.kd"));
    push_str(&mut b, ".kernarg_segment_size");
    push_uint(&mut b, kernarg);
    push_str(&mut b, ".vgpr_count");
    push_uint(&mut b, vgpr as u64);
    push_str(&mut b, ".sgpr_count");
    push_uint(&mut b, sgpr as u64);
    b
}

fn push_str(b: &mut Vec<u8>, s: &str) {
    if s.len() <= 31 {
        b.push(0xa0 | (s.len() as u8));
    } else {
        b.push(0xd9);
        b.push(s.len() as u8);
    }
    b.extend_from_slice(s.as_bytes());
}

fn push_uint(b: &mut Vec<u8>, n: u64) {
    if n < 128 {
        b.push(n as u8);
    } else if n <= 0xff {
        b.push(0xcc);
        b.push(n as u8);
    } else {
        b.push(0xcd);
        b.extend_from_slice(&(n as u16).to_be_bytes());
    }
}

#[test]
fn metadata_note_attaches_to_matching_kernel() {
    // Synthesise an AMDGPU ELF where the metadata blob's
    // ".name": "vector_add" matches the kernel symbol. The view
    // builder should attach the metadata record to the Kernel.
    let desc = descriptor_with_vgpr_sgpr(2, 1, 24);
    let msgpack = build_msgpack_for("vector_add", 12, 16, 24);
    let note_bytes = build_amdgpu_metadata_note(&msgpack);

    // Hand-build an ELF with a SHT_NOTE section carrying the note.
    // Reuses the same scaffolding as AmdElfBuilder but inlines the
    // note section since the existing builder doesn't expose it.
    let mut elf_bytes = AmdElfBuilder::new()
        .push_kernel("vector_add", &[0u8; 4], desc)
        .build();

    // Append a SHT_NOTE section: append note bytes to file end and
    // add a section header pointing at it.
    elf_bytes.extend_from_slice(&note_bytes);

    // The existing ELF has 6 section headers; we need to bump
    // e_shnum and append one more shdr. The shdr table is at
    // e_shoff (offset 40-48 of the ehdr). Read it and rebuild.
    let e_shoff = u64::from_le_bytes([
        elf_bytes[40],
        elf_bytes[41],
        elf_bytes[42],
        elf_bytes[43],
        elf_bytes[44],
        elf_bytes[45],
        elf_bytes[46],
        elf_bytes[47],
    ]);
    let e_shnum = u16::from_le_bytes([elf_bytes[60], elf_bytes[61]]);

    // The shdrs start at e_shoff. We split: keep [0..e_shoff],
    // insert the note bytes (already done above as elf_bytes
    // append before this point — wait, the note was appended AFTER
    // the shdrs, which is fine), then update the shdr table.
    //
    // Since we appended note_bytes to the end *after* the shdr
    // table, the existing shdrs are still at e_shoff and we need to
    // physically grow the shdr table by 64 bytes — easier: rebuild
    // the file by truncating to e_shoff, appending shdrs +1, then
    // appending the note bytes after.
    //
    // Refactor: take the existing layout apart.
    let shdrs_size = (e_shnum as usize) * 64;
    let shdrs_end = e_shoff as usize + shdrs_size;
    let pre_shdrs = elf_bytes[..e_shoff as usize].to_vec();
    let shdrs = elf_bytes[e_shoff as usize..shdrs_end].to_vec();
    // The note bytes we appended live after shdrs_end.

    // New layout:
    //   [pre_shdrs]
    //   [note_bytes]   -- needs new offset
    //   [old shdrs] [new shdr for note]
    let mut rebuilt = Vec::new();
    rebuilt.extend_from_slice(&pre_shdrs);
    let new_note_off = rebuilt.len() as u64;
    rebuilt.extend_from_slice(&note_bytes);
    let new_shoff = rebuilt.len() as u64;
    rebuilt.extend_from_slice(&shdrs);

    // Append a new section header for the note. SHT_NOTE = 7.
    let mut nh = vec![0u8; 64];
    // sh_name: re-use string offset 0 (section name table doesn't
    // have ".note" — that's OK for our test, the section walker
    // checks sh_type, not the name).
    nh[4..8].copy_from_slice(&7u32.to_le_bytes()); // SHT_NOTE
    nh[24..32].copy_from_slice(&new_note_off.to_le_bytes()); // sh_offset
    nh[32..40].copy_from_slice(&(note_bytes.len() as u64).to_le_bytes()); // sh_size
    nh[48..56].copy_from_slice(&4u64.to_le_bytes()); // sh_addralign
    rebuilt.extend_from_slice(&nh);

    // Update the ehdr fields: e_shoff and e_shnum.
    rebuilt[40..48].copy_from_slice(&new_shoff.to_le_bytes());
    rebuilt[60..62].copy_from_slice(&((e_shnum + 1) as u16).to_le_bytes());

    let elf = Elf::parse(&rebuilt).expect("ELF with note parses");
    let view = elf.code_object_view().expect("view builds");

    assert!(view.metadata.is_some(), "metadata should be parsed");
    assert_eq!(view.kernels.len(), 1);
    let k = &view.kernels[0];
    assert!(k.metadata.is_some(), "metadata should attach to kernel");
    let m = k.metadata.as_ref().unwrap();
    assert_eq!(m.name.as_deref(), Some("vector_add"));
    assert_eq!(m.kernarg_segment_size, Some(24));
    assert_eq!(m.vgpr_count, Some(12));
    assert_eq!(m.sgpr_count, Some(16));
}

/// Encode a minimal `.AMDGPU.kinfo` record for one kernel, in the
/// SCALE-free 1.4.x layout reverse-engineered from the corpus.
/// `args` is `[(offset, size)]`.
fn build_scale_kinfo(flags: u32, args: &[(u32, u32)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + args.len() * 8);
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(args.len() as u32).to_le_bytes());
    for (off, size) in args {
        out.extend_from_slice(&off.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
    }
    out
}

#[test]
fn scale_kinfo_section_synthesises_kernel_metadata() {
    // Synthesise an AMDGPU ELF with NO `NT_AMDGPU_METADATA` note but
    // WITH a `.AMDGPU.kinfo` section + a `vector_add.ki` symbol. The
    // view should fall back to kinfo and populate kernel.metadata
    // with the per-arg layout.
    let desc = descriptor_with_vgpr_sgpr(2, 1, 28);
    let elf_bytes = AmdElfBuilder::new()
        .push_kernel("vector_add", &[0u8; 4], desc)
        .build();

    // Append a `.AMDGPU.kinfo` section + a `.ki` symbol, surgically.
    let kinfo = build_scale_kinfo(0x400, &[(0, 8), (8, 8), (16, 8), (24, 4)]);
    let extra_sym_name = b"vector_add.ki\0";

    // Read existing offsets from the ELF header.
    let e_shoff = u64::from_le_bytes(elf_bytes[40..48].try_into().unwrap());
    let e_shnum = u16::from_le_bytes(elf_bytes[60..62].try_into().unwrap());
    let e_shstrndx = u16::from_le_bytes(elf_bytes[62..64].try_into().unwrap());

    // Section 3 is `.shstrtab`, section 4 is `.strtab`, section 5 is
    // `.symtab` (see AmdElfBuilder::build). We'll grow `.shstrtab`
    // and `.strtab` to add the new names, append a kinfo section
    // header, and add a new symbol entry for `vector_add.ki`.
    //
    // To keep the surgery simple we re-lay-out the file from the
    // ELF header forward: pre-shdr region is everything except the
    // shdr table; we patch what we need and rebuild.
    let shdrs_size = (e_shnum as usize) * 64;
    let shdrs_end = e_shoff as usize + shdrs_size;
    let pre_shdrs = elf_bytes[..e_shoff as usize].to_vec();
    let mut shdrs = elf_bytes[e_shoff as usize..shdrs_end].to_vec();

    // Build a new shstrtab containing ".AMDGPU.kinfo".
    let shstr_idx = e_shstrndx as usize;
    let shstr_shdr_off = shstr_idx * 64;
    let shstr_off = u64::from_le_bytes(
        shdrs[shstr_shdr_off + 24..shstr_shdr_off + 32]
            .try_into()
            .unwrap(),
    ) as usize;
    let shstr_size = u64::from_le_bytes(
        shdrs[shstr_shdr_off + 32..shstr_shdr_off + 40]
            .try_into()
            .unwrap(),
    ) as usize;
    let mut new_shstr = pre_shdrs[shstr_off..shstr_off + shstr_size].to_vec();
    let kinfo_name_off = new_shstr.len() as u32;
    new_shstr.extend_from_slice(b".AMDGPU.kinfo\0");

    // Grow `.strtab` for the `.ki` symbol name.
    let strtab_idx = 4usize;
    let strtab_shdr_off = strtab_idx * 64;
    let strtab_off = u64::from_le_bytes(
        shdrs[strtab_shdr_off + 24..strtab_shdr_off + 32]
            .try_into()
            .unwrap(),
    ) as usize;
    let strtab_size = u64::from_le_bytes(
        shdrs[strtab_shdr_off + 32..strtab_shdr_off + 40]
            .try_into()
            .unwrap(),
    ) as usize;
    let mut new_strtab = pre_shdrs[strtab_off..strtab_off + strtab_size].to_vec();
    let ki_name_off = new_strtab.len() as u32;
    new_strtab.extend_from_slice(extra_sym_name);

    // Lay out the new file:
    //   [pre-shstrtab bytes]
    //   [new_shstr]
    //   [new_strtab]
    //   [old symtab bytes... + extra symbol]
    //   [kinfo bytes]
    //   [shdrs (patched)]
    //
    // Pull the existing symtab body out of `pre_shdrs`.
    let symtab_idx = 5usize;
    let symtab_shdr_off = symtab_idx * 64;
    let symtab_off = u64::from_le_bytes(
        shdrs[symtab_shdr_off + 24..symtab_shdr_off + 32]
            .try_into()
            .unwrap(),
    ) as usize;
    let symtab_size = u64::from_le_bytes(
        shdrs[symtab_shdr_off + 32..symtab_shdr_off + 40]
            .try_into()
            .unwrap(),
    ) as usize;
    let mut new_symtab = pre_shdrs[symtab_off..symtab_off + symtab_size].to_vec();

    // Compose the rebuilt file. We assume layout is:
    //   [ehdr][text][rodata][shstrtab][strtab][symtab][shdrs]
    // — exactly what AmdElfBuilder::build emits.
    let new_shstr_off = shstr_off as u64;
    let new_shstr_size = new_shstr.len() as u64;
    let new_strtab_off = new_shstr_off + new_shstr_size;
    let new_strtab_size = new_strtab.len() as u64;
    let new_symtab_off = new_strtab_off + new_strtab_size;

    // Append a new symbol entry for `vector_add.ki`. STT_OBJECT (1) +
    // STB_GLOBAL (1) → info = 0x11. shndx = 6 (the new kinfo section).
    let mut sym_entry = [0u8; 24];
    sym_entry[0..4].copy_from_slice(&ki_name_off.to_le_bytes());
    sym_entry[4] = 0x11;
    sym_entry[6..8].copy_from_slice(&6u16.to_le_bytes()); // section index
    sym_entry[8..16].copy_from_slice(&0u64.to_le_bytes()); // value (offset within section)
    sym_entry[16..24].copy_from_slice(&(kinfo.len() as u64).to_le_bytes());
    new_symtab.extend_from_slice(&sym_entry);
    let new_symtab_size = new_symtab.len() as u64;

    let kinfo_off = new_symtab_off + new_symtab_size;
    let kinfo_size = kinfo.len() as u64;
    let new_shoff = kinfo_off + kinfo_size;

    // Patch the shdrs in place: shstrtab size, strtab size, symtab
    // size + kinfo offsets are baked into the shdr table.
    shdrs[shstr_shdr_off + 32..shstr_shdr_off + 40].copy_from_slice(&new_shstr_size.to_le_bytes());
    shdrs[strtab_shdr_off + 24..strtab_shdr_off + 32]
        .copy_from_slice(&new_strtab_off.to_le_bytes());
    shdrs[strtab_shdr_off + 32..strtab_shdr_off + 40]
        .copy_from_slice(&new_strtab_size.to_le_bytes());
    shdrs[symtab_shdr_off + 24..symtab_shdr_off + 32]
        .copy_from_slice(&new_symtab_off.to_le_bytes());
    shdrs[symtab_shdr_off + 32..symtab_shdr_off + 40]
        .copy_from_slice(&new_symtab_size.to_le_bytes());

    // Build a new shdr for `.AMDGPU.kinfo` (SHT_PROGBITS, no flags).
    let mut kinfo_shdr = [0u8; 64];
    kinfo_shdr[0..4].copy_from_slice(&kinfo_name_off.to_le_bytes());
    kinfo_shdr[4..8].copy_from_slice(&1u32.to_le_bytes()); // SHT_PROGBITS
    kinfo_shdr[24..32].copy_from_slice(&kinfo_off.to_le_bytes());
    kinfo_shdr[32..40].copy_from_slice(&kinfo_size.to_le_bytes());
    kinfo_shdr[48..56].copy_from_slice(&4u64.to_le_bytes()); // align

    // Reassemble the file.
    let mut rebuilt = Vec::new();
    rebuilt.extend_from_slice(&pre_shdrs[..shstr_off]);
    rebuilt.extend_from_slice(&new_shstr);
    rebuilt.extend_from_slice(&new_strtab);
    rebuilt.extend_from_slice(&new_symtab);
    rebuilt.extend_from_slice(&kinfo);
    rebuilt.extend_from_slice(&shdrs);
    rebuilt.extend_from_slice(&kinfo_shdr);

    // Update ehdr: e_shoff and e_shnum.
    rebuilt[40..48].copy_from_slice(&new_shoff.to_le_bytes());
    rebuilt[60..62].copy_from_slice(&((e_shnum + 1) as u16).to_le_bytes());

    let elf = Elf::parse(&rebuilt).expect("ELF with kinfo parses");
    let view = elf.code_object_view().expect("view builds");

    // No standard metadata note → fallback path runs.
    assert!(view.metadata.is_none());
    assert_eq!(view.kernels.len(), 1);
    let k = &view.kernels[0];
    assert!(k.metadata.is_some(), "metadata should be synthesised");
    let m = k.metadata.as_ref().unwrap();
    assert_eq!(m.name.as_deref(), Some("vector_add"));
    assert_eq!(m.symbol.as_deref(), Some("vector_add.kd"));
    assert_eq!(m.args.len(), 4);
    assert_eq!(m.args[0].size, Some(8));
    assert_eq!(m.args[3].size, Some(4));
    assert_eq!(m.args[0].offset, Some(0));
    assert_eq!(m.args[3].offset, Some(24));
    // Synthesised metadata never reports kernarg_segment_size — see
    // the comment on `synthesise_metadata_kernel`.
    assert_eq!(m.kernarg_segment_size, None);
    assert_eq!(m.vgpr_count, None);
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

#[test]
fn code_object_error_has_distinct_display_messages() {
    // The Display impl for CodeObjectError must not return an empty
    // string; both variants must be distinguishable.
    let not_amdgpu = CodeObjectError::NotAmdgpu;
    let parse_err = CodeObjectError::DescriptorParse("fake".into());
    let s1 = format!("{not_amdgpu}");
    let s2 = format!("{parse_err}");
    assert!(s1.contains("AMDGPU"), "got {s1:?}");
    assert!(s2.contains("descriptor"), "got {s2:?}");
    assert_ne!(s1, s2, "Display variants must be distinguishable");
}

#[test]
fn parse_error_converts_to_descriptor_parse_error() {
    // The From<ParseError> conversion must produce a
    // DescriptorParse variant carrying the original error message.
    let p = crate::ParseError::too_short(64, 32);
    let err: CodeObjectError = p.into();
    match err {
        CodeObjectError::DescriptorParse(msg) => {
            assert!(!msg.is_empty(), "converted message must be non-empty");
        }
        other => panic!("expected DescriptorParse, got {other:?}"),
    }
}

#[test]
fn metadata_attaches_via_symbol_match_not_name() {
    // Build a kernel whose `.name` in metadata differs from the
    // ELF entry symbol, but whose `.symbol` field carries
    // `<entry_name>.kd`. The view-builder should still attach the
    // metadata record by matching `symbol.strip_suffix(".kd")`.
    let desc = descriptor_with_vgpr_sgpr(0, 0, 0);
    let mut b = Vec::new();
    // top-level fixmap len=2
    b.push(0x82);
    push_str(&mut b, "amdhsa.version");
    b.extend_from_slice(&[0x92, 0x01, 0x00]);
    push_str(&mut b, "amdhsa.kernels");
    b.push(0x91); // array len=1
    b.push(0x82); // fixmap len=2
    push_str(&mut b, ".name");
    push_str(&mut b, "different_name");
    push_str(&mut b, ".symbol");
    push_str(&mut b, "matched_kernel.kd");
    let note_bytes = build_amdgpu_metadata_note(&b);

    let mut elf_bytes = AmdElfBuilder::new()
        .push_kernel("matched_kernel", &[0u8; 4], desc)
        .build();
    elf_bytes.extend_from_slice(&note_bytes);
    let e_shoff = u64::from_le_bytes([
        elf_bytes[40],
        elf_bytes[41],
        elf_bytes[42],
        elf_bytes[43],
        elf_bytes[44],
        elf_bytes[45],
        elf_bytes[46],
        elf_bytes[47],
    ]);
    let e_shnum = u16::from_le_bytes([elf_bytes[60], elf_bytes[61]]);
    let shdrs_size = (e_shnum as usize) * 64;
    let shdrs_end = e_shoff as usize + shdrs_size;
    let pre_shdrs = elf_bytes[..e_shoff as usize].to_vec();
    let shdrs = elf_bytes[e_shoff as usize..shdrs_end].to_vec();
    let mut rebuilt = Vec::new();
    rebuilt.extend_from_slice(&pre_shdrs);
    let new_note_off = rebuilt.len() as u64;
    rebuilt.extend_from_slice(&note_bytes);
    let new_shoff = rebuilt.len() as u64;
    rebuilt.extend_from_slice(&shdrs);
    let mut nh = vec![0u8; 64];
    nh[4..8].copy_from_slice(&7u32.to_le_bytes());
    nh[24..32].copy_from_slice(&new_note_off.to_le_bytes());
    nh[32..40].copy_from_slice(&(note_bytes.len() as u64).to_le_bytes());
    nh[48..56].copy_from_slice(&4u64.to_le_bytes());
    rebuilt.extend_from_slice(&nh);
    rebuilt[40..48].copy_from_slice(&new_shoff.to_le_bytes());
    rebuilt[60..62].copy_from_slice(&((e_shnum + 1) as u16).to_le_bytes());

    let elf = Elf::parse(&rebuilt).expect("ELF parses");
    let view = elf.code_object_view().expect("view builds");
    assert_eq!(view.kernels.len(), 1);
    let k = &view.kernels[0];
    let m = k
        .metadata
        .as_ref()
        .expect("metadata should attach via .symbol match");
    assert_eq!(m.name.as_deref(), Some("different_name"));
    assert_eq!(m.symbol.as_deref(), Some("matched_kernel.kd"));
}

#[test]
fn metadata_does_not_attach_when_neither_name_nor_symbol_matches() {
    // Build a kernel where the metadata `.name` is "ghost" and the
    // ELF entry symbol is "real". No attachment should happen.
    let desc = descriptor_with_vgpr_sgpr(0, 0, 0);
    let msgpack = build_msgpack_for("ghost", 0, 0, 0);
    let note_bytes = build_amdgpu_metadata_note(&msgpack);

    let mut elf_bytes = AmdElfBuilder::new()
        .push_kernel("real", &[0u8; 4], desc)
        .build();
    elf_bytes.extend_from_slice(&note_bytes);
    let e_shoff = u64::from_le_bytes([
        elf_bytes[40],
        elf_bytes[41],
        elf_bytes[42],
        elf_bytes[43],
        elf_bytes[44],
        elf_bytes[45],
        elf_bytes[46],
        elf_bytes[47],
    ]);
    let e_shnum = u16::from_le_bytes([elf_bytes[60], elf_bytes[61]]);
    let shdrs_size = (e_shnum as usize) * 64;
    let shdrs_end = e_shoff as usize + shdrs_size;
    let pre_shdrs = elf_bytes[..e_shoff as usize].to_vec();
    let shdrs = elf_bytes[e_shoff as usize..shdrs_end].to_vec();
    let mut rebuilt = Vec::new();
    rebuilt.extend_from_slice(&pre_shdrs);
    let new_note_off = rebuilt.len() as u64;
    rebuilt.extend_from_slice(&note_bytes);
    let new_shoff = rebuilt.len() as u64;
    rebuilt.extend_from_slice(&shdrs);
    let mut nh = vec![0u8; 64];
    nh[4..8].copy_from_slice(&7u32.to_le_bytes());
    nh[24..32].copy_from_slice(&new_note_off.to_le_bytes());
    nh[32..40].copy_from_slice(&(note_bytes.len() as u64).to_le_bytes());
    nh[48..56].copy_from_slice(&4u64.to_le_bytes());
    rebuilt.extend_from_slice(&nh);
    rebuilt[40..48].copy_from_slice(&new_shoff.to_le_bytes());
    rebuilt[60..62].copy_from_slice(&((e_shnum + 1) as u16).to_le_bytes());

    let elf = Elf::parse(&rebuilt).expect("ELF parses");
    let view = elf.code_object_view().expect("view builds");
    assert_eq!(view.kernels.len(), 1);
    assert!(
        view.kernels[0].metadata.is_none(),
        "metadata should not attach when both name and symbol differ"
    );
}

#[test]
fn metadata_note_with_wrong_name_is_ignored() {
    // Build a SHT_NOTE record with type = NT_AMDGPU_METADATA but
    // name = "WRONG" (instead of "AMDGPU"). The metadata-finder
    // must ignore it; view.metadata should be None.
    let desc = descriptor_with_vgpr_sgpr(0, 0, 0);
    let msgpack = build_msgpack_for("k", 0, 0, 0);

    // Build the note manually with name "WRONG".
    let name = b"WRONG\0";
    let mut note = Vec::new();
    note.extend_from_slice(&(name.len() as u32).to_le_bytes());
    note.extend_from_slice(&(msgpack.len() as u32).to_le_bytes());
    note.extend_from_slice(&32u32.to_le_bytes()); // NT_AMDGPU_METADATA
    note.extend_from_slice(name);
    while note.len() % 4 != 0 {
        note.push(0);
    }
    note.extend_from_slice(&msgpack);
    while note.len() % 4 != 0 {
        note.push(0);
    }

    let mut elf_bytes = AmdElfBuilder::new()
        .push_kernel("k", &[0u8; 4], desc)
        .build();
    elf_bytes.extend_from_slice(&note);
    let e_shoff = u64::from_le_bytes([
        elf_bytes[40],
        elf_bytes[41],
        elf_bytes[42],
        elf_bytes[43],
        elf_bytes[44],
        elf_bytes[45],
        elf_bytes[46],
        elf_bytes[47],
    ]);
    let e_shnum = u16::from_le_bytes([elf_bytes[60], elf_bytes[61]]);
    let shdrs_size = (e_shnum as usize) * 64;
    let shdrs_end = e_shoff as usize + shdrs_size;
    let pre_shdrs = elf_bytes[..e_shoff as usize].to_vec();
    let shdrs = elf_bytes[e_shoff as usize..shdrs_end].to_vec();
    let mut rebuilt = Vec::new();
    rebuilt.extend_from_slice(&pre_shdrs);
    let new_note_off = rebuilt.len() as u64;
    rebuilt.extend_from_slice(&note);
    let new_shoff = rebuilt.len() as u64;
    rebuilt.extend_from_slice(&shdrs);
    let mut nh = vec![0u8; 64];
    nh[4..8].copy_from_slice(&7u32.to_le_bytes());
    nh[24..32].copy_from_slice(&new_note_off.to_le_bytes());
    nh[32..40].copy_from_slice(&(note.len() as u64).to_le_bytes());
    nh[48..56].copy_from_slice(&4u64.to_le_bytes());
    rebuilt.extend_from_slice(&nh);
    rebuilt[40..48].copy_from_slice(&new_shoff.to_le_bytes());
    rebuilt[60..62].copy_from_slice(&((e_shnum + 1) as u16).to_le_bytes());

    let elf = Elf::parse(&rebuilt).expect("ELF parses");
    let view = elf.code_object_view().expect("view builds");
    assert!(
        view.metadata.is_none(),
        "note with name != \"AMDGPU\" must not be picked up as metadata"
    );
}

#[test]
fn metadata_note_with_wrong_type_is_ignored() {
    // Same setup as above but ntype = 1 (NT_VERSION) — the
    // metadata-finder should skip it because it's gated on
    // `ntype == NT_AMDGPU_METADATA && name == "AMDGPU"`. Mutating
    // `&&` to `||` would let this through.
    let desc = descriptor_with_vgpr_sgpr(0, 0, 0);
    let msgpack = build_msgpack_for("k", 0, 0, 0);

    let name = b"AMDGPU\0";
    let mut note = Vec::new();
    note.extend_from_slice(&(name.len() as u32).to_le_bytes());
    note.extend_from_slice(&(msgpack.len() as u32).to_le_bytes());
    note.extend_from_slice(&1u32.to_le_bytes()); // wrong ntype
    note.extend_from_slice(name);
    while note.len() % 4 != 0 {
        note.push(0);
    }
    note.extend_from_slice(&msgpack);
    while note.len() % 4 != 0 {
        note.push(0);
    }

    let mut elf_bytes = AmdElfBuilder::new()
        .push_kernel("k", &[0u8; 4], desc)
        .build();
    elf_bytes.extend_from_slice(&note);
    let e_shoff = u64::from_le_bytes([
        elf_bytes[40],
        elf_bytes[41],
        elf_bytes[42],
        elf_bytes[43],
        elf_bytes[44],
        elf_bytes[45],
        elf_bytes[46],
        elf_bytes[47],
    ]);
    let e_shnum = u16::from_le_bytes([elf_bytes[60], elf_bytes[61]]);
    let shdrs_size = (e_shnum as usize) * 64;
    let shdrs_end = e_shoff as usize + shdrs_size;
    let pre_shdrs = elf_bytes[..e_shoff as usize].to_vec();
    let shdrs = elf_bytes[e_shoff as usize..shdrs_end].to_vec();
    let mut rebuilt = Vec::new();
    rebuilt.extend_from_slice(&pre_shdrs);
    let new_note_off = rebuilt.len() as u64;
    rebuilt.extend_from_slice(&note);
    let new_shoff = rebuilt.len() as u64;
    rebuilt.extend_from_slice(&shdrs);
    let mut nh = vec![0u8; 64];
    nh[4..8].copy_from_slice(&7u32.to_le_bytes());
    nh[24..32].copy_from_slice(&new_note_off.to_le_bytes());
    nh[32..40].copy_from_slice(&(note.len() as u64).to_le_bytes());
    nh[48..56].copy_from_slice(&4u64.to_le_bytes());
    rebuilt.extend_from_slice(&nh);
    rebuilt[40..48].copy_from_slice(&new_shoff.to_le_bytes());
    rebuilt[60..62].copy_from_slice(&((e_shnum + 1) as u16).to_le_bytes());

    let elf = Elf::parse(&rebuilt).expect("ELF parses");
    let view = elf.code_object_view().expect("view builds");
    assert!(
        view.metadata.is_none(),
        "note with wrong ntype must not be picked up as metadata"
    );
}

#[test]
fn metadata_search_iterates_past_non_amdgpu_notes() {
    // Build a SHT_NOTE section containing TWO records:
    //   1. A junk note (name="OTHER", type=42) that should be skipped.
    //   2. The real NT_AMDGPU_METADATA note.
    // The loop in `find_amdgpu_metadata` must walk past the first
    // record and find the second; mutating the bound check from
    // `cursor + 12 <= bytes.len()` to a multiplicative form would
    // exit the loop before reaching the second record.
    let desc = descriptor_with_vgpr_sgpr(0, 0, 0);

    // Note 1: junk record.
    let junk_name = b"OTHER\0";
    let junk_payload: &[u8] = &[];
    let mut note = Vec::new();
    note.extend_from_slice(&(junk_name.len() as u32).to_le_bytes());
    note.extend_from_slice(&(junk_payload.len() as u32).to_le_bytes());
    note.extend_from_slice(&42u32.to_le_bytes());
    note.extend_from_slice(junk_name);
    while note.len() % 4 != 0 {
        note.push(0);
    }
    note.extend_from_slice(junk_payload);
    while note.len() % 4 != 0 {
        note.push(0);
    }

    // Note 2: real AMDGPU metadata.
    let msgpack = build_msgpack_for("k", 4, 8, 0);
    let amdgpu_name = b"AMDGPU\0";
    note.extend_from_slice(&(amdgpu_name.len() as u32).to_le_bytes());
    note.extend_from_slice(&(msgpack.len() as u32).to_le_bytes());
    note.extend_from_slice(&32u32.to_le_bytes());
    note.extend_from_slice(amdgpu_name);
    while note.len() % 4 != 0 {
        note.push(0);
    }
    note.extend_from_slice(&msgpack);
    while note.len() % 4 != 0 {
        note.push(0);
    }

    let mut elf_bytes = AmdElfBuilder::new()
        .push_kernel("k", &[0u8; 4], desc)
        .build();
    elf_bytes.extend_from_slice(&note);
    let e_shoff = u64::from_le_bytes([
        elf_bytes[40],
        elf_bytes[41],
        elf_bytes[42],
        elf_bytes[43],
        elf_bytes[44],
        elf_bytes[45],
        elf_bytes[46],
        elf_bytes[47],
    ]);
    let e_shnum = u16::from_le_bytes([elf_bytes[60], elf_bytes[61]]);
    let shdrs_size = (e_shnum as usize) * 64;
    let shdrs_end = e_shoff as usize + shdrs_size;
    let pre_shdrs = elf_bytes[..e_shoff as usize].to_vec();
    let shdrs = elf_bytes[e_shoff as usize..shdrs_end].to_vec();
    let mut rebuilt = Vec::new();
    rebuilt.extend_from_slice(&pre_shdrs);
    let new_note_off = rebuilt.len() as u64;
    rebuilt.extend_from_slice(&note);
    let new_shoff = rebuilt.len() as u64;
    rebuilt.extend_from_slice(&shdrs);
    let mut nh = vec![0u8; 64];
    nh[4..8].copy_from_slice(&7u32.to_le_bytes());
    nh[24..32].copy_from_slice(&new_note_off.to_le_bytes());
    nh[32..40].copy_from_slice(&(note.len() as u64).to_le_bytes());
    nh[48..56].copy_from_slice(&4u64.to_le_bytes());
    rebuilt.extend_from_slice(&nh);
    rebuilt[40..48].copy_from_slice(&new_shoff.to_le_bytes());
    rebuilt[60..62].copy_from_slice(&((e_shnum + 1) as u16).to_le_bytes());

    let elf = Elf::parse(&rebuilt).expect("ELF parses");
    let view = elf.code_object_view().expect("view builds");
    let m = view
        .metadata
        .as_ref()
        .expect("must skip non-AMDGPU note and find AMDGPU metadata at the second record");
    assert_eq!(m.kernels.len(), 1);
    assert_eq!(m.kernels[0].name.as_deref(), Some("k"));
}

#[test]
fn truncated_note_record_breaks_loop_without_panic() {
    // Build a SHT_NOTE section containing a header that *claims* a
    // descsz larger than the section body. The walker's bounds
    // check (`if next_off > bytes.len() { break; }`) must trigger
    // — without it, we'd index out-of-bounds. Mutating the
    // comparison to `<` would walk into invalid memory.
    let desc = descriptor_with_vgpr_sgpr(0, 0, 0);

    // Note header claims descsz = 0xFFFF but actual body is empty.
    let mut note = Vec::new();
    note.extend_from_slice(&7u32.to_le_bytes()); // namesz
    note.extend_from_slice(&0xFFFFu32.to_le_bytes()); // descsz (lying)
    note.extend_from_slice(&32u32.to_le_bytes()); // ntype
    note.extend_from_slice(b"AMDGPU\0");
    while note.len() % 4 != 0 {
        note.push(0);
    }
    // No descriptor bytes at all.

    let mut elf_bytes = AmdElfBuilder::new()
        .push_kernel("k", &[0u8; 4], desc)
        .build();
    elf_bytes.extend_from_slice(&note);
    let e_shoff = u64::from_le_bytes([
        elf_bytes[40],
        elf_bytes[41],
        elf_bytes[42],
        elf_bytes[43],
        elf_bytes[44],
        elf_bytes[45],
        elf_bytes[46],
        elf_bytes[47],
    ]);
    let e_shnum = u16::from_le_bytes([elf_bytes[60], elf_bytes[61]]);
    let shdrs_size = (e_shnum as usize) * 64;
    let shdrs_end = e_shoff as usize + shdrs_size;
    let pre_shdrs = elf_bytes[..e_shoff as usize].to_vec();
    let shdrs = elf_bytes[e_shoff as usize..shdrs_end].to_vec();
    let mut rebuilt = Vec::new();
    rebuilt.extend_from_slice(&pre_shdrs);
    let new_note_off = rebuilt.len() as u64;
    rebuilt.extend_from_slice(&note);
    let new_shoff = rebuilt.len() as u64;
    rebuilt.extend_from_slice(&shdrs);
    let mut nh = vec![0u8; 64];
    nh[4..8].copy_from_slice(&7u32.to_le_bytes());
    nh[24..32].copy_from_slice(&new_note_off.to_le_bytes());
    nh[32..40].copy_from_slice(&(note.len() as u64).to_le_bytes());
    nh[48..56].copy_from_slice(&4u64.to_le_bytes());
    rebuilt.extend_from_slice(&nh);
    rebuilt[40..48].copy_from_slice(&new_shoff.to_le_bytes());
    rebuilt[60..62].copy_from_slice(&((e_shnum + 1) as u16).to_le_bytes());

    let elf = Elf::parse(&rebuilt).expect("ELF parses");
    let view = elf
        .code_object_view()
        .expect("view builds even with bad note");
    assert!(
        view.metadata.is_none(),
        "truncated note must not produce metadata"
    );
}
