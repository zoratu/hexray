//! Shared fixture for the `hexray-db` integration tests.
//!
//! The fixture builds a small but complete `.hxdb`: an immutable source, one
//! image with a real mapping, symbols (including aliases and very high
//! addresses), functions and a detected string. Tests then publish analysis
//! units through the public API instead of writing derived rows by hand.

#![allow(dead_code)]

use std::path::PathBuf;

use hexray_core::{
    Architecture, BlockTerminator, ControlFlow, Immediate, Instruction, Operand, Operation,
    PredicateGuard, Register, RegisterClass,
};
use hexray_db::address::{Address, FileOffset};
use hexray_db::model::*;
use hexray_db::{Database, DbResult, OpenMode, Revision};

/// The read API lives on [`hexray_db::ReadSnapshot`] so a caller can pin one
/// revision. Tests that just want one value use these forwarding helpers,
/// which open and drop a snapshot per call.
pub trait ReadExt {
    fn symbols(&mut self) -> DbResult<Vec<SymbolInfo>>;
    fn image(&mut self) -> DbResult<ImageInfo>;
    fn patches(&mut self) -> DbResult<Vec<PatchRow>>;
    fn types(&mut self) -> DbResult<Vec<TypeRow>>;
    fn items(&mut self) -> DbResult<Vec<ItemRow>>;
    fn annotations(&mut self) -> DbResult<Vec<(Address, AnnotationKind, String)>>;
    fn bookmarks(&mut self) -> DbResult<Vec<(Address, Option<String>)>>;
    fn function_overrides(&mut self) -> DbResult<Vec<(Address, FunctionOverrideRow)>>;
    fn name_at(&mut self, address: Address) -> DbResult<Option<String>>;
    fn names(&mut self) -> DbResult<Vec<(Address, String)>>;
    fn functions(&mut self) -> DbResult<Vec<FunctionRow>>;
    fn function_at(&mut self, address: Address) -> DbResult<Option<FunctionRow>>;
    fn instructions(&mut self, function: Address) -> DbResult<Vec<hexray_core::Instruction>>;
    fn cfg(&mut self, function: Address) -> DbResult<hexray_db::store::CfgData>;
    fn xrefs_from(&mut self, address: Address) -> DbResult<Vec<XrefRow>>;
    fn xrefs_to(&mut self, address: Address) -> DbResult<Vec<XrefRow>>;
    fn all_xrefs(&mut self) -> DbResult<Vec<XrefRow>>;
    fn info(&mut self) -> DbResult<DatabaseInfo>;
    fn history_depth(&mut self) -> DbResult<(usize, usize)>;
    fn history_events(&mut self, limit: usize, offset: usize) -> DbResult<Vec<HistoryEvent>>;
}

impl ReadExt for Database {
    fn symbols(&mut self) -> DbResult<Vec<SymbolInfo>> {
        self.snapshot()?.symbols()
    }
    fn image(&mut self) -> DbResult<ImageInfo> {
        self.snapshot()?.image()
    }
    fn patches(&mut self) -> DbResult<Vec<PatchRow>> {
        self.snapshot()?.patches()
    }
    fn types(&mut self) -> DbResult<Vec<TypeRow>> {
        self.snapshot()?.types()
    }
    fn items(&mut self) -> DbResult<Vec<ItemRow>> {
        self.snapshot()?.items()
    }
    fn annotations(&mut self) -> DbResult<Vec<(Address, AnnotationKind, String)>> {
        self.snapshot()?.annotations()
    }
    fn bookmarks(&mut self) -> DbResult<Vec<(Address, Option<String>)>> {
        self.snapshot()?.bookmarks()
    }
    fn function_overrides(&mut self) -> DbResult<Vec<(Address, FunctionOverrideRow)>> {
        self.snapshot()?.function_overrides()
    }
    fn name_at(&mut self, address: Address) -> DbResult<Option<String>> {
        self.snapshot()?.name_at(address)
    }
    fn names(&mut self) -> DbResult<Vec<(Address, String)>> {
        self.snapshot()?.names()
    }
    fn functions(&mut self) -> DbResult<Vec<FunctionRow>> {
        self.snapshot()?.functions()
    }
    fn function_at(&mut self, address: Address) -> DbResult<Option<FunctionRow>> {
        self.snapshot()?.function_at(address)
    }
    fn instructions(&mut self, function: Address) -> DbResult<Vec<hexray_core::Instruction>> {
        self.snapshot()?.instructions(function)
    }
    fn cfg(&mut self, function: Address) -> DbResult<hexray_db::store::CfgData> {
        self.snapshot()?.cfg(function)
    }
    fn xrefs_from(&mut self, address: Address) -> DbResult<Vec<XrefRow>> {
        self.snapshot()?.xrefs_from(address)
    }
    fn xrefs_to(&mut self, address: Address) -> DbResult<Vec<XrefRow>> {
        self.snapshot()?.xrefs_to(address)
    }
    fn all_xrefs(&mut self) -> DbResult<Vec<XrefRow>> {
        self.snapshot()?.all_xrefs()
    }
    fn info(&mut self) -> DbResult<DatabaseInfo> {
        self.snapshot()?.info()
    }
    fn history_depth(&mut self) -> DbResult<(usize, usize)> {
        self.snapshot()?.history_depth()
    }
    fn history_events(&mut self, limit: usize, offset: usize) -> DbResult<Vec<HistoryEvent>> {
        self.snapshot()?.history_events(limit, offset)
    }
}

pub const BASE_VA: u64 = 0x1000;
pub const BASE_LEN: u64 = 0x200;
pub const SOURCE_LEN: usize = 0x200;

pub const MAIN: Address = Address(0x1000);
pub const MAIN_END: Address = Address(0x1010);
pub const HELPER: Address = Address(0x1020);
pub const HELPER_END: Address = Address(0x1030);
pub const UNRELATED: Address = Address(0x1040);
pub const UNRELATED_END: Address = Address(0x1050);
pub const STRING_ADDRESS: Address = Address(0x1100);
/// A file offset inside the base mapping (address `0x1010`).
pub const PATCH_OFFSET: FileOffset = FileOffset(0x10);

/// Addresses that exercise the SQLite INTEGER boundary and the BLOB
/// encoding: zero, 2^53+1, `i64::MAX`, `i64::MAX + 1` and `u64::MAX`.
pub const HIGH_ADDRESSES: [u64; 5] = [
    0,
    (1u64 << 53) + 1,
    i64::MAX as u64,
    i64::MAX as u64 + 1,
    u64::MAX,
];

pub fn engine_fingerprint() -> [u8; 32] {
    [0x5a; 32]
}

pub fn layout_fingerprint() -> [u8; 32] {
    [0x11; 32]
}

pub fn default_source() -> Vec<u8> {
    (0..SOURCE_LEN).map(|index| (index % 251) as u8).collect()
}

pub struct Project {
    pub dir: tempfile::TempDir,
    pub db_path: PathBuf,
    pub source_path: PathBuf,
    pub source_bytes: Vec<u8>,
}

impl Project {
    pub fn open(&self) -> Database {
        Database::open(&self.db_path, OpenMode::ReadWrite).expect("open writable")
    }

    pub fn open_read_only(&self) -> Database {
        Database::open(&self.db_path, OpenMode::ReadOnly).expect("open read-only")
    }

    pub fn revision(&self) -> Revision {
        let db = self.open();
        db.revision().expect("revision")
    }
}

pub fn mapping(
    name: &str,
    va: u64,
    size: u64,
    file_offset: Option<u64>,
    file_size: u64,
) -> MappingInfo {
    MappingInfo {
        name: name.to_string(),
        va: Address(va),
        memory_size: size,
        file_offset: file_offset.map(FileOffset),
        file_size,
        permissions: MappingPermissions {
            read: true,
            write: false,
            execute: true,
        },
        origin: "test".into(),
    }
}

pub fn default_image(abi: AbiInfo) -> ImageInfo {
    let mut mappings = vec![mapping("base", BASE_VA, BASE_LEN, Some(0), BASE_LEN)];
    for value in HIGH_ADDRESSES {
        // Zero file size: these mappings exist only to round-trip the full
        // `FileOffset` range through the BLOB columns.
        mappings.push(mapping(
            &format!("high_{value:x}"),
            value,
            0x10,
            Some(value),
            0,
        ));
    }
    ImageInfo {
        format: "elf".into(),
        architecture: "x86_64".into(),
        bitness: 64,
        endianness: "little".into(),
        abi,
        entry_address: Some(MAIN),
        selector_json: "{}".into(),
        container_offset: FileOffset(0),
        container_length: SOURCE_LEN as u64,
        member_name: None,
        member_index: None,
        slice_label: None,
        layout_fingerprint: layout_fingerprint(),
        mappings,
        sections: vec![SectionInfo {
            name: ".text".into(),
            va: Address(BASE_VA),
            memory_size: BASE_LEN,
            file_offset: Some(FileOffset(0)),
            file_size: BASE_LEN,
            flags: "ax".into(),
        }],
    }
}

pub fn function_row(address: Address, end: Address) -> FunctionRow {
    FunctionRow {
        address,
        declared_end: Some(end),
        bounds_origin: BoundsOrigin::Symbol,
        origin: FunctionOrigin::Auto,
        excluded: false,
        user_removed: false,
        present: true,
    }
}

pub fn main_function() -> FunctionRow {
    function_row(MAIN, MAIN_END)
}

pub fn helper_function() -> FunctionRow {
    function_row(HELPER, HELPER_END)
}

pub fn unrelated_function() -> FunctionRow {
    function_row(UNRELATED, UNRELATED_END)
}

pub fn core_functions() -> Vec<FunctionRow> {
    vec![main_function(), helper_function(), unrelated_function()]
}

pub fn symbol(address: Address, name: &str) -> SymbolInfo {
    SymbolInfo {
        address,
        name: name.to_string(),
        kind: "function".into(),
        size: 0x10,
        origin: SymbolOrigin::Loader,
    }
}

/// Symbols of the three primary functions, including an alias at `MAIN`.
pub fn core_symbols() -> Vec<SymbolInfo> {
    vec![
        symbol(MAIN, "main"),
        symbol(MAIN, "main_alias"),
        symbol(HELPER, "helper"),
        symbol(UNRELATED, "unrelated"),
    ]
}

/// Fixture symbols: the core set plus one row for every high address.
pub fn fixture_symbols() -> Vec<SymbolInfo> {
    let mut symbols = core_symbols();
    for value in HIGH_ADDRESSES {
        symbols.push(symbol(Address(value), &format!("addr_{value:x}")));
    }
    symbols
}

pub fn sample_string() -> StringRow {
    StringRow {
        address: STRING_ADDRESS,
        encoding: StringEncoding::Ascii,
        bytes: b"hello world".to_vec(),
        text: Some("hello world".into()),
    }
}

pub fn create_project() -> Project {
    create_project_with_abi(AbiInfo::lp64())
}

pub fn create_project_with_abi(abi: AbiInfo) -> Project {
    let dir = tempfile::tempdir().expect("temp dir");
    let source_bytes = default_source();
    let source_path = dir.path().join("sample.bin");
    std::fs::write(&source_path, &source_bytes).expect("write source");
    let db_path = dir.path().join("sample.hxdb");
    let input = CreateInput {
        original_path: source_path.clone(),
        source_bytes: source_bytes.clone(),
        container_kind: ContainerKind::Elf,
        image: default_image(abi),
        engine_fingerprint: engine_fingerprint(),
        symbols: fixture_symbols(),
        functions: core_functions(),
        strings: vec![sample_string()],
        xrefs: Vec::new(),
        builtin_types_json: Some("{}".into()),
        analysis_scope: AnalysisScope::empty(),
        diagnostics: Vec::new(),
    };
    let database = Database::create(&db_path, &input).expect("create database");
    drop(database);
    Project {
        dir,
        db_path,
        source_path,
        source_bytes,
    }
}

// ---------------------------------------------------------------------------
// Analysis payload builders
// ---------------------------------------------------------------------------

pub fn revision_of(db: &Database) -> Revision {
    db.revision().expect("revision")
}

pub fn unit_state(db: &mut Database, key: &UnitKey) -> Option<AnalysisState> {
    let snapshot = db.snapshot().expect("snapshot");
    snapshot.unit(key).expect("unit").map(|unit| unit.state)
}

pub fn unit_generation(db: &mut Database, key: &UnitKey) -> Option<u64> {
    let snapshot = db.snapshot().expect("snapshot");
    snapshot.analysis_generation(key).expect("generation")
}

pub fn unit_row(db: &mut Database, key: &UnitKey) -> Option<AnalysisUnitRow> {
    let snapshot = db.snapshot().expect("snapshot");
    snapshot.unit(key).expect("unit")
}

pub fn publish_units(db: &mut Database, base: Revision, units: Vec<UnitPublish>) {
    db.publish(base, &AnalysisBatch { units })
        .expect("publish analysis batch");
}

pub fn index_unit(
    expected: Option<u64>,
    state: AnalysisState,
    functions: Vec<FunctionRow>,
    symbols: Vec<SymbolInfo>,
    strings: Vec<StringRow>,
    xrefs: Vec<XrefRow>,
) -> UnitPublish {
    UnitPublish {
        key: UnitKey::image_index(),
        expected_generation: expected,
        state,
        input_fingerprint: [0x21; 32],
        dependencies_complete: true,
        diagnostics: Vec::new(),
        dependencies: Vec::new(),
        payload: AnalysisPayload::ImageIndex(Box::new(ImageIndexPayload {
            functions,
            symbols,
            strings,
            xrefs,
        })),
    }
}

pub fn default_index_unit(expected: Option<u64>) -> UnitPublish {
    index_unit(
        expected,
        AnalysisState::Current,
        core_functions(),
        core_symbols(),
        vec![sample_string()],
        Vec::new(),
    )
}

pub const LAYOUT_TEXT: &str = "int main(void) { return 0; }";

pub fn category_function(
    address: Address,
    mnemonic: &str,
    operation: Operation,
    flow: ControlFlow,
) -> Instruction {
    let size = 4;
    let mut instruction = Instruction::new(address.0, size, vec![0x90; size], mnemonic);
    instruction.operation = operation;
    instruction.control_flow = flow;
    instruction
}

pub fn sequential_instruction(address: Address) -> Instruction {
    category_function(address, "mov", Operation::Move, ControlFlow::Sequential)
}

/// An instruction with every semantic field populated, used to prove the
/// round trip keeps more than the address and mnemonic.
pub fn rich_instruction() -> Instruction {
    let mut instruction = Instruction::new(MAIN.0, 5, vec![0xe8, 0x1b, 0x00, 0x00, 0x00], "call");
    instruction.operation = Operation::Call;
    instruction.operands = vec![
        Operand::Immediate(Immediate {
            value: 0x1020,
            size: 32,
            signed: true,
        }),
        Operand::Register(rax()),
    ];
    instruction.control_flow = ControlFlow::Call {
        target: 0x1020,
        return_addr: 0x1005,
    };
    instruction.reads = vec![rax(), rsp()];
    instruction.writes = vec![rsp()];
    instruction.guard = Some(PredicateGuard::negated(Register::new(
        Architecture::X86_64,
        RegisterClass::Predicate,
        0,
        1,
    )));
    instruction
}

pub fn rax() -> Register {
    Register::new(Architecture::X86_64, RegisterClass::General, 0, 64)
}

pub fn rsp() -> Register {
    Register::new(Architecture::X86_64, RegisterClass::StackPointer, 4, 64)
}

pub fn block(id: u32, start: Address, end: Address, terminator: BlockTerminator) -> BlockPayload {
    BlockPayload {
        id,
        start,
        end,
        terminator,
    }
}

/// One block holding every instruction, terminating in `Return`.
pub fn simple_blocks(
    instructions: &[Instruction],
) -> (Vec<BlockPayload>, Vec<(u32, Vec<Address>)>) {
    let mut addresses: Vec<Address> = instructions
        .iter()
        .map(|instruction| Address(instruction.address))
        .collect();
    addresses.sort();
    let start = addresses.first().copied().unwrap_or(ADDRESS_ZERO);
    let end_address = instructions
        .last()
        .map(|instruction| Address(instruction.address + instruction.size as u64))
        .unwrap_or(start);
    let blocks = vec![block(0, start, end_address, BlockTerminator::Return)];
    (blocks, vec![(0, addresses)])
}

pub const ADDRESS_ZERO: Address = Address(0);

pub struct CfgSpec {
    pub function: FunctionRow,
    pub instructions: Vec<Instruction>,
    pub blocks: Vec<BlockPayload>,
    pub block_instructions: Vec<(u32, Vec<Address>)>,
    pub edges: Vec<(u32, u32, EdgeKind)>,
    pub xrefs: Vec<XrefRow>,
    pub expected: Option<u64>,
    pub state: AnalysisState,
    pub dependencies_complete: bool,
    pub dependencies: Vec<Dependency>,
}

impl CfgSpec {
    pub fn new(function: FunctionRow) -> Self {
        Self {
            function,
            instructions: Vec::new(),
            blocks: Vec::new(),
            block_instructions: Vec::new(),
            edges: Vec::new(),
            xrefs: Vec::new(),
            expected: None,
            state: AnalysisState::Current,
            dependencies_complete: true,
            dependencies: Vec::new(),
        }
    }

    pub fn simple(function: FunctionRow, instructions: Vec<Instruction>) -> Self {
        let (blocks, block_instructions) = simple_blocks(&instructions);
        let mut spec = Self::new(function);
        spec.instructions = instructions;
        spec.blocks = blocks;
        spec.block_instructions = block_instructions;
        spec
    }

    pub fn into_unit(self) -> UnitPublish {
        let function_address = self.function.address;
        UnitPublish {
            key: UnitKey::function_cfg(function_address),
            expected_generation: self.expected,
            state: self.state,
            input_fingerprint: [0x31; 32],
            dependencies_complete: self.dependencies_complete,
            diagnostics: Vec::new(),
            dependencies: self.dependencies,
            payload: AnalysisPayload::FunctionCfg(Box::new(FunctionCfgPayload {
                function: self.function,
                instructions: self.instructions,
                blocks: self.blocks,
                block_instructions: self.block_instructions,
                edges: self.edges,
                xrefs: self.xrefs,
            })),
        }
    }
}

pub fn sample_render_config() -> RenderConfig {
    RenderConfig {
        optimization_level: "default".into(),
        enable_passes: Vec::new(),
        disable_passes: Vec::new(),
        show_addresses: false,
        indent: "    ".into(),
        type_snapshot_sha256: [0; 32],
        engine_fingerprint: engine_fingerprint(),
    }
}

pub fn render_unit(
    function: Address,
    text: &str,
    config: &RenderConfig,
    expected: Option<u64>,
    state: AnalysisState,
) -> UnitPublish {
    UnitPublish {
        key: UnitKey::function_render(function, config.fingerprint()),
        expected_generation: expected,
        state,
        input_fingerprint: [0x41; 32],
        dependencies_complete: true,
        diagnostics: Vec::new(),
        dependencies: Vec::new(),
        payload: AnalysisPayload::FunctionRender(Box::new(RenderPayload {
            function,
            config_fingerprint: config.fingerprint(),
            text: text.to_string(),
        })),
    }
}

pub fn call_xref(from: Address, to: Address, owner: Option<Address>) -> XrefRow {
    XrefRow {
        from,
        to,
        kind: XrefKind::Call,
        owner,
        origin: XrefOrigin::Auto,
    }
}

pub fn signature_dependency(function: Address, target_generation: u64) -> Dependency {
    Dependency {
        kind: DependencyKind::Signature,
        key: format!("function:{:x}", function.0),
        range: None,
        target_generation,
    }
}

/// Compare every semantic field of two instructions; `Instruction` has no
/// `PartialEq`, and comparing only the address would hide lost operands.
pub fn assert_instruction_eq(actual: &Instruction, expected: &Instruction) {
    assert_eq!(actual.address, expected.address, "instruction address");
    assert_eq!(actual.size, expected.size, "instruction size");
    assert_eq!(actual.bytes, expected.bytes, "instruction bytes");
    assert_eq!(
        actual.operation, expected.operation,
        "instruction operation"
    );
    assert_eq!(actual.mnemonic, expected.mnemonic, "instruction mnemonic");
    assert_eq!(actual.operands, expected.operands, "instruction operands");
    assert_eq!(
        actual.control_flow, expected.control_flow,
        "instruction control flow"
    );
    assert_eq!(actual.reads, expected.reads, "instruction reads");
    assert_eq!(actual.writes, expected.writes, "instruction writes");
    assert_eq!(actual.guard, expected.guard, "instruction guard");
}

/// Open a second, independent SQLite connection to inspect rows the store API
/// intentionally does not expose (audit tables, raw payload corruption).
pub fn raw_connection(path: &std::path::Path) -> rusqlite::Connection {
    rusqlite::Connection::open(path).expect("raw sqlite connection")
}

pub fn file_digest(path: &std::path::Path) -> [u8; 32] {
    hexray_db::sha256(&std::fs::read(path).expect("read file"))
}
