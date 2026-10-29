//! GPU (AMDGPU gfx906) decode-only support in `.hxdb` projects.
//!
//! Every fixture is synthesized inside a temporary directory: a minimal ELF64
//! code object with one `s_endpgm` kernel. No ROCm install, GPU, or compiler is
//! required. What these tests pin down is the *boundary* of GPU projects:
//! decoded instructions and kernel metadata are persisted and queryable,
//! pseudo-C is refused with a stable message, and that refusal never mutates
//! the database.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

/// Kernel symbol carried by the synthetic code object.
const KERNEL: &str = "vector_add";

/// `s_endpgm` on gfx906: SOPP, OP = 0x01, raw dword `0xbf810000`.
const S_ENDPGM: [u8; 4] = [0x00, 0x00, 0x81, 0xbf];

/// File offset of `.text`. Relocatable ELF files use `sh_offset` as the virtual
/// address (see `SectionHeader::virtual_address`), so this is also the kernel
/// address and the mapping base; the symbol stays at `st_value == 0`.
const TEXT_VA: u64 = 0x1000;

fn hexray_bin() -> &'static str {
    env!("CARGO_BIN_EXE_hexray")
}

fn run(args: &[&str]) -> Output {
    Command::new(hexray_bin())
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to run hexray {args:?}: {error}"))
}

fn expect_success(output: &Output) -> String {
    assert!(
        output.status.success(),
        "command failed (status {:?})\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// Expect a refused operation: exit code 1 (a real runtime refusal, not a clap
/// usage error) with the caller's message checked by the caller.
fn expect_failure(output: &Output) -> (String, String) {
    assert!(
        !output.status.success(),
        "command unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "operation errors must exit 1, not {:?}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

// ---------------------------------------------------------------------------
// Synthetic gfx906 code object
// ---------------------------------------------------------------------------

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
    let mut h = [0u8; 64];
    h[0..4].copy_from_slice(&name.to_le_bytes());
    h[4..8].copy_from_slice(&sh_type.to_le_bytes());
    h[8..16].copy_from_slice(&flags.to_le_bytes());
    h[16..24].copy_from_slice(&addr.to_le_bytes());
    h[24..32].copy_from_slice(&offset.to_le_bytes());
    h[32..40].copy_from_slice(&size.to_le_bytes());
    h[40..44].copy_from_slice(&link.to_le_bytes());
    h[44..48].copy_from_slice(&info.to_le_bytes());
    h[48..56].copy_from_slice(&align.to_le_bytes());
    h[56..64].copy_from_slice(&entsize.to_le_bytes());
    h
}

/// Minimal `clang -target=amdgcn-amd-amdhsa -mcpu=gfx906` style object:
/// ELF64/EM_AMDGPU, one `STT_FUNC` symbol named `vector_add` pointing at a
/// four-byte `.text` holding `s_endpgm`.
fn synth_gfx906_kernel_body() -> Vec<u8> {
    const EHDR: usize = 64;
    const SYM: usize = 24;
    /// gfx906 mach. V4 ABI, xnack/sramecc unspecified (feature bits clear).
    const E_FLAGS_GFX906: u32 = 0x2F;

    // Section name table; these offsets are the sh_name values.
    let shstr = b"\0.text\0.shstrtab\0.strtab\0.symtab\0";
    let (name_text, name_shstrtab, name_strtab, name_symtab) = (1u32, 7, 17, 25);
    // Section indices, in header order. `sh_link` is an index, never a name.
    const IDX_STRTAB: u32 = 3;
    const IDX_SHSTRTAB: u32 = 2;

    let strtab = b"\0vector_add\0";

    // STN_UNDEF then one global function symbol.
    let mut symtab = vec![0u8; SYM];
    let mut symbol = [0u8; SYM];
    symbol[0..4].copy_from_slice(&1u32.to_le_bytes()); // st_name: "vector_add"
    symbol[4] = 0x12; // STB_GLOBAL | STT_FUNC
    symbol[6..8].copy_from_slice(&1u16.to_le_bytes()); // st_shndx: .text
    symbol[8..16].copy_from_slice(&0u64.to_le_bytes()); // st_value: relocatable
    symbol[16..24].copy_from_slice(&(S_ENDPGM.len() as u64).to_le_bytes());
    symtab.extend_from_slice(&symbol);

    let mut data = vec![0u8; EHDR];
    data.resize(TEXT_VA as usize, 0);
    data.extend_from_slice(&S_ENDPGM);
    let shstrtab_off = data.len() as u64;
    data.extend_from_slice(shstr);
    let strtab_off = data.len() as u64;
    data.extend_from_slice(strtab);
    let symtab_off = data.len() as u64;
    data.extend_from_slice(&symtab);
    while !data.len().is_multiple_of(8) {
        data.push(0);
    }
    let shdrs_off = data.len() as u64;

    data.extend_from_slice(&[0u8; 64]); // SHN_UNDEF
    data.extend_from_slice(&section_header(
        name_text,
        1,   // SHT_PROGBITS
        0x6, // SHF_ALLOC | SHF_EXECINSTR
        TEXT_VA,
        TEXT_VA,
        S_ENDPGM.len() as u64,
        0,
        0,
        4,
        0,
    ));
    data.extend_from_slice(&section_header(
        name_shstrtab,
        3, // SHT_STRTAB
        0,
        0,
        shstrtab_off,
        shstr.len() as u64,
        0,
        0,
        1,
        0,
    ));
    data.extend_from_slice(&section_header(
        name_strtab,
        3, // SHT_STRTAB
        0,
        0,
        strtab_off,
        strtab.len() as u64,
        0,
        0,
        1,
        0,
    ));
    data.extend_from_slice(&section_header(
        name_symtab,
        2, // SHT_SYMTAB
        0,
        0,
        symtab_off,
        symtab.len() as u64,
        IDX_STRTAB, // sh_link: section index of .strtab
        1,          // sh_info: one local symbol (STN_UNDEF)
        1,
        SYM as u64,
    ));

    let mut ehdr = [0u8; EHDR];
    ehdr[0..4].copy_from_slice(b"\x7fELF");
    ehdr[4] = 2; // ELFCLASS64
    ehdr[5] = 1; // ELFDATA2LSB
    ehdr[6] = 1; // EV_CURRENT
    ehdr[7] = 64; // ELFOSABI_AMDGPU_HSA
    ehdr[8] = 2; // ABI version 4
    ehdr[16..18].copy_from_slice(&1u16.to_le_bytes()); // ET_REL
    ehdr[18..20].copy_from_slice(&224u16.to_le_bytes()); // EM_AMDGPU
    ehdr[20..24].copy_from_slice(&1u32.to_le_bytes()); // EV_CURRENT
    ehdr[40..48].copy_from_slice(&shdrs_off.to_le_bytes());
    ehdr[48..52].copy_from_slice(&E_FLAGS_GFX906.to_le_bytes());
    ehdr[52..54].copy_from_slice(&(EHDR as u16).to_le_bytes());
    ehdr[58..60].copy_from_slice(&(64u16).to_le_bytes());
    ehdr[60..62].copy_from_slice(&5u16.to_le_bytes());
    ehdr[62..64].copy_from_slice(&(IDX_SHSTRTAB as u16).to_le_bytes());
    data[0..EHDR].copy_from_slice(&ehdr);

    data
}

fn write_fixture(dir: &Path) -> PathBuf {
    let path = dir.join("vector_add.co");
    std::fs::write(&path, synth_gfx906_kernel_body()).expect("write synthetic code object");
    path
}

// ---------------------------------------------------------------------------
// Project helper
// ---------------------------------------------------------------------------

struct GpuProject {
    _dir: tempfile::TempDir,
    database: PathBuf,
}

impl GpuProject {
    fn create() -> GpuProject {
        let dir = tempfile::tempdir().expect("temp dir");
        let source = write_fixture(dir.path());
        let database = dir.path().join("gpu.hxdb");
        let output = run(&[
            "db",
            "create",
            source.to_str().unwrap(),
            "-o",
            database.to_str().unwrap(),
        ]);
        expect_success(&output);
        GpuProject {
            _dir: dir,
            database,
        }
    }

    fn db_str(&self) -> &str {
        self.database.to_str().unwrap()
    }

    fn query(&self, args: &[&str]) -> Output {
        let mut all = vec!["db", "query", self.db_str()];
        all.extend_from_slice(args);
        run(&all)
    }

    fn info_json(&self) -> Value {
        serde_json::from_str(&expect_success(&self.query(&["info", "--json"]))).expect("info json")
    }

    /// Address of the kernel as reported by the database, rendered as `0x...`.
    fn kernel_address(&self) -> String {
        let functions: Value =
            serde_json::from_str(&expect_success(&self.query(&["functions", "--json"])))
                .expect("functions json");
        functions
            .as_array()
            .expect("functions array")
            .iter()
            .find(|row| row["name"] == KERNEL)
            .unwrap_or_else(|| panic!("kernel {KERNEL} missing from {functions}"))["address"]
            .as_str()
            .expect("kernel address")
            .to_string()
    }
}

/// Instruction lines are `<address>  <hex bytes>  <mnemonic>  <operands>`.
fn mnemonics(disasm: &str) -> Vec<String> {
    disasm
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let address = fields.next()?;
            if !address.starts_with("0x") {
                return None;
            }
            fields.next()?; // hex bytes
            fields.next().map(str::to_string)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn code_object_is_recognised_as_gpu() {
    let dir = tempfile::tempdir().expect("temp dir");
    let source = write_fixture(dir.path());

    let stdout = expect_success(&run(&[source.to_str().unwrap(), "info"]));
    assert!(
        stdout.to_ascii_lowercase().contains("amdgpu"),
        "the fixture must be recognised as an AMDGPU code object, got:\n{stdout}"
    );
    assert!(
        stdout.contains("gfx906"),
        "the synthetic target must survive parsing, got:\n{stdout}"
    );
}

#[test]
fn create_persists_gpu_image_and_kernel_state() {
    let project = GpuProject::create();

    let info = project.info_json();
    assert_eq!(info["image"]["format"], "elf");
    let architecture = info["image"]["architecture"]
        .as_str()
        .unwrap_or_else(|| panic!("architecture must be a string: {info}"));
    assert!(
        architecture.to_ascii_lowercase().contains("amdgpu"),
        "GPU projects must keep their target in image.architecture, got {architecture}"
    );

    let functions: Value =
        serde_json::from_str(&expect_success(&project.query(&["functions", "--json"])))
            .expect("functions json");
    let rows = functions.as_array().expect("functions array");
    assert!(!rows.is_empty(), "no functions were persisted: {functions}");
    for row in rows {
        assert!(
            row["state"].is_string(),
            "every function row must carry an analysis state: {row}"
        );
    }
    let kernel = rows
        .iter()
        .find(|row| row["name"] == KERNEL)
        .unwrap_or_else(|| panic!("kernel {KERNEL} missing from {functions}"));
    assert_eq!(
        kernel["state"], "current",
        "a successfully decoded kernel must be current: {kernel}"
    );

    assert_ne!(
        info["overall_state"], "ready",
        "pseudo-C is unsupported for GPU objects, so a GPU project can never be ready: {info}"
    );
}

#[test]
fn disasm_renders_gpu_mnemonics_not_x86() {
    let project = GpuProject::create();

    let disasm = expect_success(&project.query(&["disasm", KERNEL]));
    assert!(
        !disasm.trim().is_empty(),
        "GPU disassembly must not be empty"
    );
    assert!(
        disasm
            .lines()
            .any(|line| line.contains("000081bf") && line.contains("s_endpgm")),
        "the persisted kernel body must decode as `s_endpgm`, got:\n{disasm}"
    );

    let mnemonics = mnemonics(&disasm);
    assert!(
        !mnemonics.is_empty(),
        "no instruction lines parsed from:\n{disasm}"
    );
    assert!(
        mnemonics.iter().any(|mnemonic| mnemonic == "s_endpgm"),
        "the decoded kernel must render the s_endpgm mnemonic, parsed {mnemonics:?} from:\n{disasm}"
    );
    for mnemonic in &mnemonics {
        let lower = mnemonic.to_ascii_lowercase();
        assert_ne!(
            lower, "push",
            "x86 mnemonic leaked into GPU disassembly:\n{disasm}"
        );
        assert_ne!(
            lower, "ret",
            "x86 mnemonic leaked into GPU disassembly:\n{disasm}"
        );
        assert!(
            !lower.starts_with("mov"),
            "x86 mnemonic {mnemonic} leaked into GPU disassembly:\n{disasm}"
        );
    }
}

#[test]
fn decompile_is_refused_and_writes_nothing() {
    let project = GpuProject::create();
    let revision_before = project.info_json()["revision"].clone();

    let (stdout, stderr) = expect_failure(&project.query(&["decompile", KERNEL]));
    assert!(
        stderr.contains("pseudo-C is unsupported for GPU code objects"),
        "GPU decompile must be refused with the documented message, got stderr:\n{stderr}"
    );
    assert!(
        stdout.trim().is_empty(),
        "a refused decompile must not emit text, got stdout:\n{stdout}"
    );

    let info_after = project.info_json();
    assert_eq!(
        info_after["revision"], revision_before,
        "a refused decompile must not commit anything: {info_after}"
    );
}

#[test]
fn decompile_update_is_refused_too() {
    let project = GpuProject::create();
    let revision_before = project.info_json()["revision"].clone();

    let (stdout, stderr) = expect_failure(&project.query(&["decompile", KERNEL, "--update"]));
    assert!(
        stderr.contains("pseudo-C is unsupported for GPU code objects"),
        "GPU decompile must be refused even with --update, got stderr:\n{stderr}"
    );
    assert!(
        stdout.trim().is_empty(),
        "a refused decompile must not emit text, got stdout:\n{stdout}"
    );
    assert_eq!(
        project.info_json()["revision"],
        revision_before,
        "--update must not silently write a GPU artifact"
    );
}

#[test]
fn bytes_reads_the_decoded_kernel_body() {
    let project = GpuProject::create();
    let address = project.kernel_address();

    let bytes: Value = serde_json::from_str(&expect_success(
        &project.query(&["bytes", &address, "4", "--json"]),
    ))
    .expect("bytes json");
    assert_eq!(bytes["address"], address.as_str());
    assert_eq!(bytes["length"], 4);
    assert_eq!(
        bytes["hex"], "000081bf",
        "the kernel body must be file-backed and readable at {address}: {bytes}"
    );
}

#[test]
fn deep_check_accepts_the_gpu_project() {
    let project = GpuProject::create();
    expect_success(&run(&["db", "check", project.db_str(), "--deep"]));
}
