//! Deterministic synthetic ELF64 fixture for the database acceleration tests.
//!
//! The fixture is built byte-by-byte so every test is hermetic: no C compiler,
//! no network, no GPU, and the generated object is never executed. It carries
//! two adjacent executable sections (`.text` and `.packed`), one read-only
//! section with strings and a small jump table, a real symbol table and real
//! `PT_LOAD` program headers, so `hexray_formats::Elf` and the database
//! discovery/analysis pipeline see an ordinary x86-64 executable.
//!
//! The returned [`FixtureLayout`] is the only address source tests should use.
#![allow(dead_code)]

use std::path::Path;

/// Base virtual address of the single image produced by the generator.
pub const IMAGE_BASE: u64 = 0x40_0000;
/// File offset (and virtual address delta) of `.text`.
pub const TEXT_FILE_OFFSET: u64 = 0x1000;
/// Virtual address of the first `.text` function.
pub const TEXT_VA: u64 = IMAGE_BASE + TEXT_FILE_OFFSET;

/// Every generated body is `6` bytes: `mov eax, imm32; ret` or `call rel32; ret`.
const BODY_SIZE: u64 = 6;
/// The boundary-spanning function declares `BODY_SIZE + 16` bytes.
const BOUNDARY_OVERHANG: u64 = 16;

const ELF_HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;
const SECTION_HEADER_SIZE: usize = 64;
const SYMBOL_SIZE: usize = 24;
const PAGE_SIZE: u64 = 0x1000;

const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 0x1;
const PF_R: u32 = 0x4;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;

/// Section header indices of the entries referenced by symbols and `sh_link`.
const IDX_TEXT: u16 = 1;
const IDX_PACKED: u16 = 2;
const IDX_STRTAB: u16 = 5;
const IDX_SHSTRTAB: u16 = 6;

/// The `PT_LOAD` pair plus the five real section headers.
const SECTION_COUNT: usize = 7;
/// The first four `.text` functions after the helper are callers.
const CALLER_COUNT: usize = 4;
/// Index of the helper, the callers and the cross-section caller in `.text`.
const HELPER_INDEX: usize = 0;
const FIRST_CALLER_INDEX: usize = 1;
const CROSS_SECTION_INDEX: usize = 5;
/// Below this the helper / callers / cross-section caller / boundary layout
/// cannot be expressed without aliasing two roles onto one body.
pub const MIN_FUNCTIONS_PER_SECTION: usize = 7;

/// A deterministic `.packed` padding generator seed. The function bodies are
/// left intact; only the trailing padding is pseudo-random.
const HIGH_ENTROPY_SEED: u64 = 0xE17A_5EED_0BAD_F00D;

/// Addresses and symbols of one generated fixture.
///
/// Tests never guess an address: every field is derived from the buffers that
/// were actually written.
#[derive(Debug, Clone)]
pub struct FixtureLayout {
    pub text_start: u64,
    pub text_end: u64,
    pub packed_start: u64,
    pub packed_end: u64,
    pub rodata_start: u64,
    pub entry: u64,
    /// Single helper called by every entry in [`FixtureLayout::callers`].
    pub helper: u64,
    /// Callers in `.text` that `call` the helper.
    pub callers: Vec<u64>,
    /// `.text` caller whose `call` target is inside `.packed`.
    pub cross_section_caller: u64,
    /// `(name, VA, size)` of the functions inside `.packed`.
    pub packed_functions: Vec<(String, u64, u64)>,
    /// `(name, VA, size)` of the functions inside `.text`.
    pub text_functions: Vec<(String, u64, u64)>,
    /// A `.text` function whose declared size runs past `text_end` into
    /// `.packed`: `(VA, declared size)`.
    pub boundary_spanning: (u64, u64),
    /// `(name, VA, size)` of the mapped sections.
    pub sections: Vec<(String, u64, u64)>,
}

/// Write the default (low padding entropy) fixture.
pub fn write_analysis_fixture(
    path: &Path,
    functions_per_section: usize,
) -> std::io::Result<FixtureLayout> {
    write_analysis_fixture_with_entropy(path, functions_per_section, false)
}

/// Write the fixture, choosing whether `.packed` padding is zeroed or
/// pseudo-random. Function bodies are identical in both variants.
///
/// `functions_per_section` must be at least [`MIN_FUNCTIONS_PER_SECTION`] so the
/// helper, callers, cross-section caller and boundary function all have their
/// own six-byte body.
pub fn write_analysis_fixture_with_entropy(
    path: &Path,
    functions_per_section: usize,
    high_entropy: bool,
) -> std::io::Result<FixtureLayout> {
    let (bytes, layout) = build_image(functions_per_section, high_entropy)?;
    std::fs::write(path, bytes)?;
    Ok(layout)
}

/// SplitMix64: tiny, deterministic, and dependency-free.
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn seeded(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn next_byte(&mut self) -> u8 {
        (self.next_u64() >> 56) as u8
    }
}

/// NUL-terminated string table with the leading empty string reserved so
/// `st_name == 0` / `sh_name == 0` mean "no name".
struct StringTable {
    data: Vec<u8>,
}

impl Default for StringTable {
    fn default() -> Self {
        Self { data: vec![0] }
    }
}

impl StringTable {
    fn new() -> Self {
        Self::default()
    }

    fn add(&mut self, text: &str) -> u32 {
        let offset = self.data.len() as u32;
        self.data.extend_from_slice(text.as_bytes());
        self.data.push(0);
        offset
    }
}

fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

fn function_immediate(index: usize) -> u32 {
    let mut random = SplitMix64::seeded(0x5EED_0000_0000_0000 ^ index as u64);
    (random.next_u64() >> 32) as u32
}

/// `mov eax, imm32; ret`.
fn ordinary_body(immediate: u32) -> [u8; 6] {
    let mut body = [0u8; 6];
    body[0] = 0xB8;
    body[1..5].copy_from_slice(&immediate.to_le_bytes());
    body[5] = 0xC3;
    body
}

/// `call rel32` (target is `call_site + 5 + displacement) then `ret`.
fn call_body(call_site: u64, target: u64) -> [u8; 6] {
    let displacement = (target as i64 - (call_site as i64 + 5)) as i32;
    let mut body = [0u8; 6];
    body[0] = 0xE8;
    body[1..5].copy_from_slice(&displacement.to_le_bytes());
    body[5] = 0xC3;
    body
}

/// Names are stable and unique; the four callers use the same helper.
fn text_function_name(index: usize, count: usize) -> String {
    if index == HELPER_INDEX {
        "helper".to_string()
    } else if (FIRST_CALLER_INDEX..=CALLER_COUNT).contains(&index) {
        let caller = index - FIRST_CALLER_INDEX;
        format!("caller_{caller}")
    } else if index == CROSS_SECTION_INDEX {
        "cross_section_caller".to_string()
    } else if index == count - 1 {
        "boundary_spanning".to_string()
    } else {
        format!("text_fn_{index:03}")
    }
}

fn index_va(index: usize) -> u64 {
    TEXT_VA + BODY_SIZE * index as u64
}

#[allow(clippy::too_many_arguments)] // mirrors the ten ELF64 section-header fields
fn section_header(
    name: u32,
    sh_type: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    align: u64,
    entsize: u64,
) -> [u8; 64] {
    let mut header = [0u8; 64];
    header[0..4].copy_from_slice(&name.to_le_bytes());
    header[4..8].copy_from_slice(&sh_type.to_le_bytes());
    header[8..16].copy_from_slice(&flags.to_le_bytes());
    header[16..24].copy_from_slice(&addr.to_le_bytes());
    header[24..32].copy_from_slice(&offset.to_le_bytes());
    header[32..40].copy_from_slice(&size.to_le_bytes());
    header[40..44].copy_from_slice(&link.to_le_bytes());
    header[44..48].copy_from_slice(&info.to_le_bytes());
    header[48..56].copy_from_slice(&align.to_le_bytes());
    header[56..64].copy_from_slice(&entsize.to_le_bytes());
    header
}

fn program_header(
    p_type: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    file_size: u64,
    memory_size: u64,
) -> [u8; 56] {
    let mut header = [0u8; 56];
    header[0..4].copy_from_slice(&p_type.to_le_bytes());
    header[4..8].copy_from_slice(&flags.to_le_bytes());
    header[8..16].copy_from_slice(&offset.to_le_bytes());
    header[16..24].copy_from_slice(&vaddr.to_le_bytes());
    header[24..32].copy_from_slice(&vaddr.to_le_bytes()); // p_paddr
    header[32..40].copy_from_slice(&file_size.to_le_bytes());
    header[40..48].copy_from_slice(&memory_size.to_le_bytes());
    header[48..56].copy_from_slice(&PAGE_SIZE.to_le_bytes());
    header
}

fn append_symbol(
    symtab: &mut Vec<u8>,
    strtab: &mut StringTable,
    name: &str,
    value: u64,
    size: u64,
    section_index: u16,
) {
    let name_offset = strtab.add(name);
    let mut entry = [0u8; SYMBOL_SIZE];
    entry[0..4].copy_from_slice(&name_offset.to_le_bytes());
    entry[4] = (1 << 4) | 2; // STB_GLOBAL | STT_FUNC
    entry[6..8].copy_from_slice(&section_index.to_le_bytes());
    entry[8..16].copy_from_slice(&value.to_le_bytes());
    entry[16..24].copy_from_slice(&size.to_le_bytes());
    symtab.extend_from_slice(&entry);
}

fn build_image(
    functions_per_section: usize,
    high_entropy: bool,
) -> std::io::Result<(Vec<u8>, FixtureLayout)> {
    if functions_per_section < MIN_FUNCTIONS_PER_SECTION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "functions_per_section must be at least {MIN_FUNCTIONS_PER_SECTION} \
                 (helper, callers, cross-section caller and boundary function all \
                 need distinct bodies)"
            ),
        ));
    }
    let count = functions_per_section;

    // Addresses and section sizes.
    let text_size = BODY_SIZE * count as u64;
    let text_end = TEXT_VA + text_size;
    let packed_start = text_end;
    let body_bytes = BODY_SIZE * count as u64;
    let packed_size = if high_entropy {
        (body_bytes * 4).max(4096)
    } else {
        (body_bytes + 4096).max(4096)
    };
    let packed_end = packed_start + packed_size;
    let packed_payload_len = packed_size as usize;

    // Function bodies. Every `.text` function is six bytes wide, so the
    // boundary-spanning function is last and its declared size reaches into
    // `.packed`.
    let mut text_bytes = Vec::with_capacity(text_size as usize);
    for index in 0..count {
        let address = index_va(index);
        let body = if (FIRST_CALLER_INDEX..=CALLER_COUNT).contains(&index) {
            call_body(address, index_va(HELPER_INDEX))
        } else if index == CROSS_SECTION_INDEX {
            call_body(address, packed_start)
        } else {
            ordinary_body(function_immediate(index))
        };
        text_bytes.extend_from_slice(&body);
    }
    debug_assert_eq!(text_bytes.len() as u64, text_size);

    let mut packed_bytes = Vec::with_capacity(packed_payload_len);
    for index in 0..count {
        packed_bytes.extend_from_slice(&ordinary_body(function_immediate(0x1000 + index)));
    }
    if high_entropy {
        let mut random = SplitMix64::seeded(HIGH_ENTROPY_SEED);
        while packed_bytes.len() < packed_payload_len {
            packed_bytes.push(random.next_byte());
        }
    } else {
        packed_bytes.resize(packed_payload_len, 0);
    }
    debug_assert_eq!(packed_bytes.len() as u64, packed_size);

    // `.rodata`: a few recognizable C strings plus a small jump table of real
    // `.text` entry addresses.
    let mut rodata = Vec::new();
    rodata.extend_from_slice(b"hexray analysis fixture\0");
    rodata.extend_from_slice(b"analysis scope packed payload\0");
    rodata.extend_from_slice(b"text section payload\0");
    for index in 0..4 {
        rodata.extend_from_slice(&index_va(index).to_le_bytes());
    }

    // Symbols: every generated function is a global STT_FUNC with an exact
    // declared size (the boundary function deliberately over-declares).
    let mut text_functions = Vec::with_capacity(count);
    let mut packed_functions = Vec::with_capacity(count);
    for index in 0..count {
        let size = if index == count - 1 {
            BODY_SIZE + BOUNDARY_OVERHANG
        } else {
            BODY_SIZE
        };
        text_functions.push((text_function_name(index, count), index_va(index), size));
    }
    for index in 0..count {
        packed_functions.push((
            format!("packed_fn_{index:03}"),
            packed_start + BODY_SIZE * index as u64,
            BODY_SIZE,
        ));
    }

    let mut strtab = StringTable::new();
    let mut symtab = vec![0u8; SYMBOL_SIZE]; // STN_UNDEF
    for (name, address, size) in &text_functions {
        append_symbol(&mut symtab, &mut strtab, name, *address, *size, IDX_TEXT);
    }
    for (name, address, size) in &packed_functions {
        append_symbol(&mut symtab, &mut strtab, name, *address, *size, IDX_PACKED);
    }

    let mut shstrtab = StringTable::new();
    let name_text = shstrtab.add(".text");
    let name_packed = shstrtab.add(".packed");
    let name_rodata = shstrtab.add(".rodata");
    let name_symtab = shstrtab.add(".symtab");
    let name_strtab = shstrtab.add(".strtab");
    let name_shstrtab = shstrtab.add(".shstrtab");

    // File layout: header | text | packed | pad | rodata | symtab | strtab |
    // shstrtab | pad | section headers.
    let packed_offset = TEXT_FILE_OFFSET + text_size;
    let rodata_offset = align_up(packed_offset + packed_size, PAGE_SIZE);
    let rodata_va = IMAGE_BASE + rodata_offset;
    let rodata_size = rodata.len() as u64;

    let mut data = vec![0u8; TEXT_FILE_OFFSET as usize];
    data.extend_from_slice(&text_bytes);
    data.extend_from_slice(&packed_bytes);
    data.resize(rodata_offset as usize, 0);
    data.extend_from_slice(&rodata);

    let symtab_offset = align_up(data.len() as u64, 8);
    data.resize(symtab_offset as usize, 0);
    data.extend_from_slice(&symtab);
    let strtab_offset = data.len() as u64;
    data.extend_from_slice(&strtab.data);
    let shstrtab_offset = data.len() as u64;
    data.extend_from_slice(&shstrtab.data);
    let section_headers_offset = align_up(data.len() as u64, 8);
    data.resize(section_headers_offset as usize, 0);

    let mut headers = Vec::with_capacity(SECTION_COUNT);
    headers.push([0u8; SECTION_HEADER_SIZE]);
    headers.push(section_header(
        name_text,
        SHT_PROGBITS,
        SHF_ALLOC | SHF_EXECINSTR,
        TEXT_VA,
        TEXT_FILE_OFFSET,
        text_size,
        0,
        0,
        1, // bodies are byte-packed; x86 code needs no section alignment
        0,
    ));
    headers.push(section_header(
        name_packed,
        SHT_PROGBITS,
        SHF_ALLOC | SHF_EXECINSTR,
        packed_start,
        packed_offset,
        packed_size,
        0,
        0,
        1, // 6-byte bodies: packed_start is not 16-aligned for every count
        0,
    ));
    headers.push(section_header(
        name_rodata,
        SHT_PROGBITS,
        SHF_ALLOC,
        rodata_va,
        rodata_offset,
        rodata_size,
        0,
        0,
        16,
        0,
    ));
    headers.push(section_header(
        name_symtab,
        SHT_SYMTAB,
        0,
        0,
        symtab_offset,
        symtab.len() as u64,
        u32::from(IDX_STRTAB),
        1, // one local symbol: the STN_UNDEF entry
        8,
        SYMBOL_SIZE as u64,
    ));
    headers.push(section_header(
        name_strtab,
        SHT_STRTAB,
        0,
        0,
        strtab_offset,
        strtab.data.len() as u64,
        0,
        0,
        1,
        0,
    ));
    headers.push(section_header(
        name_shstrtab,
        SHT_STRTAB,
        0,
        0,
        shstrtab_offset,
        shstrtab.data.len() as u64,
        0,
        0,
        1,
        0,
    ));
    debug_assert_eq!(headers.len(), SECTION_COUNT);
    for header in &headers {
        data.extend_from_slice(header);
    }

    let first_load_size = packed_offset + packed_size;
    let program_headers = [
        program_header(
            PT_LOAD,
            PF_R | PF_X,
            0,
            IMAGE_BASE,
            first_load_size,
            first_load_size,
        ),
        program_header(
            PT_LOAD,
            PF_R,
            rodata_offset,
            rodata_va,
            rodata_size,
            rodata_size,
        ),
    ];

    let mut elf_header = [0u8; ELF_HEADER_SIZE];
    elf_header[0..4].copy_from_slice(b"\x7fELF");
    elf_header[4] = 2; // ELFCLASS64
    elf_header[5] = 1; // ELFDATA2LSB
    elf_header[6] = 1; // EV_CURRENT
    elf_header[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
    elf_header[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
    elf_header[20..24].copy_from_slice(&1u32.to_le_bytes()); // EV_CURRENT
    elf_header[24..32].copy_from_slice(&index_va(HELPER_INDEX).to_le_bytes());
    elf_header[32..40].copy_from_slice(&(ELF_HEADER_SIZE as u64).to_le_bytes());
    elf_header[40..48].copy_from_slice(&section_headers_offset.to_le_bytes());
    elf_header[52..54].copy_from_slice(&(ELF_HEADER_SIZE as u16).to_le_bytes());
    elf_header[54..56].copy_from_slice(&(PROGRAM_HEADER_SIZE as u16).to_le_bytes());
    elf_header[56..58].copy_from_slice(&(program_headers.len() as u16).to_le_bytes());
    elf_header[58..60].copy_from_slice(&(SECTION_HEADER_SIZE as u16).to_le_bytes());
    elf_header[60..62].copy_from_slice(&(SECTION_COUNT as u16).to_le_bytes());
    elf_header[62..64].copy_from_slice(&IDX_SHSTRTAB.to_le_bytes());
    data[0..ELF_HEADER_SIZE].copy_from_slice(&elf_header);

    let mut program_header_offset = ELF_HEADER_SIZE;
    for header in &program_headers {
        data[program_header_offset..program_header_offset + PROGRAM_HEADER_SIZE]
            .copy_from_slice(header);
        program_header_offset += PROGRAM_HEADER_SIZE;
    }

    let layout = FixtureLayout {
        text_start: TEXT_VA,
        text_end,
        packed_start,
        packed_end,
        rodata_start: rodata_va,
        entry: index_va(HELPER_INDEX),
        helper: index_va(HELPER_INDEX),
        callers: (FIRST_CALLER_INDEX..=CALLER_COUNT).map(index_va).collect(),
        cross_section_caller: index_va(CROSS_SECTION_INDEX),
        packed_functions,
        text_functions,
        boundary_spanning: (index_va(count - 1), BODY_SIZE + BOUNDARY_OVERHANG),
        sections: vec![
            (".text".to_string(), TEXT_VA, text_size),
            (".packed".to_string(), packed_start, packed_size),
            (".rodata".to_string(), rodata_va, rodata_size),
        ],
    };
    Ok((data, layout))
}
