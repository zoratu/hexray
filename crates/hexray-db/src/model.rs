//! Persisted project model.
//!
//! Every struct here is a *storage DTO*: plain data, explicit `snake_case`
//! wire names, and an explicit `payload_version` wherever the payload is
//! JSON. Parser borrows, `Arc`s and analysis caches never cross this
//! boundary — the store must be readable without the parsers that produced it.

use crate::address::{Address, AddressRange, FileOffset};
use serde::{Deserialize, Serialize};

/// `application_id` written into the SQLite header: `"HXDB"`.
pub const DB_APPLICATION_ID: i32 = 0x4858_4442;
/// The only schema version this build creates or opens.
pub const SCHEMA_VERSION: u32 = 1;
/// Bumped whenever an engine change alters analysis output for the same input.
pub const ANALYSIS_FORMAT_REVISION: u32 = 1;
/// Version of the JSON payloads stored in the database.
pub const PAYLOAD_VERSION: u32 = 1;
/// Version of the layout fingerprint construction.
pub const LAYOUT_FINGERPRINT_VERSION: u32 = 1;
/// Zero config key used by units that have no render configuration.
pub const NO_CONFIG_FINGERPRINT: [u8; 32] = [0u8; 32];

/// Monotonic user-content revision. Analysis publication never advances it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Revision(pub u64);

impl std::fmt::Display for Revision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Revision {
    pub fn next(self) -> Result<Self, crate::DbError> {
        i64::try_from(self.0)
            .ok()
            .and_then(|revision| revision.checked_add(1))
            .map(|revision| Self(revision as u64))
            .ok_or(crate::DbError::ResourceLimit(
                "revision counter exhausted".to_string(),
            ))
    }
}

/// The container the analyzed image came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerKind {
    Elf,
    MachO,
    Pe,
    Ar,
    Cubin,
}

impl ContainerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Elf => "elf",
            Self::MachO => "macho",
            Self::Pe => "pe",
            Self::Ar => "ar",
            Self::Cubin => "cubin",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "elf" => Self::Elf,
            "macho" => Self::MachO,
            "pe" => Self::Pe,
            "ar" => Self::Ar,
            "cubin" => Self::Cubin,
            _ => return None,
        })
    }
}

/// Data model of the target ABI. `long_size` cannot be derived from
/// `pointer_size`: PE64 is LLP64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbiInfo {
    pub pointer_size: u8,
    pub long_size: u8,
    pub big_endian: bool,
}

impl AbiInfo {
    pub fn lp64() -> Self {
        Self {
            pointer_size: 8,
            long_size: 8,
            big_endian: false,
        }
    }

    pub fn llp64() -> Self {
        Self {
            pointer_size: 8,
            long_size: 4,
            big_endian: false,
        }
    }

    pub fn ilp32() -> Self {
        Self {
            pointer_size: 4,
            long_size: 4,
            big_endian: false,
        }
    }

    /// Map to the `hexray-types` sizing model.
    pub fn to_arch_info(self) -> hexray_types::database::ArchInfo {
        let mut info = if self.pointer_size == 4 {
            hexray_types::database::ArchInfo::ilp32()
        } else if self.long_size == 4 {
            hexray_types::database::ArchInfo::llp64()
        } else {
            hexray_types::database::ArchInfo::lp64()
        };
        info.big_endian = self.big_endian;
        info
    }
}

/// One loaded region of the image address space.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingInfo {
    pub name: String,
    pub va: Address,
    pub memory_size: u64,
    /// `None` for zero-fill-only regions (BSS) with no file backing.
    pub file_offset: Option<FileOffset>,
    pub file_size: u64,
    pub permissions: MappingPermissions,
    pub origin: String,
}

/// Permission bits as recorded by the container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MappingPermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl MappingPermissions {
    pub fn as_str(self) -> String {
        let mut out = String::with_capacity(3);
        out.push(if self.read { 'r' } else { '-' });
        out.push(if self.write { 'w' } else { '-' });
        out.push(if self.execute { 'x' } else { '-' });
        out
    }

    pub fn parse(value: &str) -> Option<Self> {
        let bytes = value.as_bytes();
        if bytes.len() != 3 {
            return None;
        }
        Some(Self {
            read: bytes[0] == b'r',
            write: bytes[1] == b'w',
            execute: bytes[2] == b'x',
        })
    }
}

/// Section metadata. Sections are *not* mappings: BSS has a memory size but
/// no file payload, and several sections may back one mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub va: Address,
    pub memory_size: u64,
    pub file_offset: Option<FileOffset>,
    pub file_size: u64,
    pub flags: String,
}

/// Metadata of the analyzed image inside the container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageInfo {
    pub format: String,
    pub architecture: String,
    pub bitness: u8,
    pub endianness: String,
    pub abi: AbiInfo,
    pub entry_address: Option<Address>,
    /// Canonical selector JSON (slice label / ar member / member index).
    pub selector_json: String,
    pub container_offset: FileOffset,
    pub container_length: u64,
    pub member_name: Option<String>,
    pub member_index: Option<u64>,
    pub slice_label: Option<String>,
    /// SHA-256 over the canonical layout description.
    pub layout_fingerprint: [u8; 32],
    pub mappings: Vec<MappingInfo>,
    pub sections: Vec<SectionInfo>,
}

/// Symbol origin: what produced the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolOrigin {
    /// Read from the container's symbol tables.
    Loader,
    /// Synthesized by function discovery (entry, ENDBR, signature scan, ...).
    Synthetic,
}

impl SymbolOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Loader => "loader",
            Self::Synthetic => "synthetic",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "loader" => Some(Self::Loader),
            "synthetic" => Some(Self::Synthetic),
            _ => None,
        }
    }
}

/// A symbol alias. Several rows may share one address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolInfo {
    pub address: Address,
    pub name: String,
    pub kind: String,
    pub size: u64,
    pub origin: SymbolOrigin,
}

/// What a user-defined item range says about the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    Code,
    Data,
}

impl ItemKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Code => "code",
            Self::Data => "data",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "code" => Some(Self::Code),
            "data" => Some(Self::Data),
            _ => None,
        }
    }
}

/// A user item definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemRow {
    pub address: Address,
    pub length: u64,
    pub kind: ItemKind,
    pub origin: String,
    pub type_name: Option<String>,
}

/// How a function's bounds were established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundsOrigin {
    Symbol,
    Entry,
    Heuristic,
    User,
}

impl BoundsOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Symbol => "symbol",
            Self::Entry => "entry",
            Self::Heuristic => "heuristic",
            Self::User => "user",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "symbol" => Some(Self::Symbol),
            "entry" => Some(Self::Entry),
            "heuristic" => Some(Self::Heuristic),
            "user" => Some(Self::User),
            _ => None,
        }
    }
}

/// Who owns a function row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FunctionOrigin {
    Auto,
    User,
}

impl FunctionOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::User => "user",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "user" => Some(Self::User),
            _ => None,
        }
    }
}

/// A function identity row.
///
/// Rows are never deleted by analysis: `present` records whether the latest
/// discovery still reports the function, and `user_removed` records an
/// explicit user suppression. Keeping the row preserves user overrides that
/// would otherwise cascade away.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionRow {
    pub address: Address,
    pub declared_end: Option<Address>,
    pub bounds_origin: BoundsOrigin,
    pub origin: FunctionOrigin,
    pub excluded: bool,
    pub user_removed: bool,
    pub present: bool,
}

impl FunctionRow {
    /// True when queries should treat this row as an existing function.
    pub fn is_live(&self) -> bool {
        self.present && !self.user_removed
    }
}

/// Direction of a CFG edge. Unwind edges are kept distinct from normal
/// control flow; collapsing them breaks exception recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    Normal,
    Unwind,
}

impl EdgeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Unwind => "unwind",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "normal" => Some(Self::Normal),
            "unwind" => Some(Self::Unwind),
            _ => None,
        }
    }
}

/// Serialized basic block. Instructions are *not* inlined here; they are
/// referenced through `block_instructions` so a shared tail is stored once.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockPayload {
    pub id: u32,
    pub start: Address,
    pub end: Address,
    pub terminator: hexray_core::BlockTerminator,
}

/// Kind of cross reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XrefKind {
    Call,
    Jump,
    Data,
}

impl XrefKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Jump => "jump",
            Self::Data => "data",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "call" => Some(Self::Call),
            "jump" => Some(Self::Jump),
            "data" => Some(Self::Data),
            _ => None,
        }
    }
}

/// Where an xref came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XrefOrigin {
    Auto,
    User,
}

impl XrefOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::User => "user",
        }
    }
}

/// A cross reference row. `owner` is the function whose analysis produced it;
/// `None` means the image index owns it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XrefRow {
    pub from: Address,
    pub to: Address,
    pub kind: XrefKind,
    pub owner: Option<Address>,
    pub origin: XrefOrigin,
}

/// String encodings preserved verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringEncoding {
    Ascii,
    Utf8,
    Utf16Le,
    Utf16Be,
}

impl StringEncoding {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ascii => "ascii",
            Self::Utf8 => "utf8",
            Self::Utf16Le => "utf16le",
            Self::Utf16Be => "utf16be",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "ascii" => Some(Self::Ascii),
            "utf8" => Some(Self::Utf8),
            "utf16le" => Some(Self::Utf16Le),
            "utf16be" => Some(Self::Utf16Be),
            _ => None,
        }
    }
}

/// A detected string. Raw bytes are the source of truth; `text` is the
/// decoded form and may be absent when decoding is lossy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringRow {
    pub address: Address,
    pub encoding: StringEncoding,
    pub bytes: Vec<u8>,
    pub text: Option<String>,
}

/// A user byte patch over file offsets of the full original source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchRow {
    pub offset: FileOffset,
    pub bytes: Vec<u8>,
}

/// Annotation kinds stored in the display overlay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnnotationKind {
    Comment,
    Tag,
}

impl AnnotationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Comment => "comment",
            Self::Tag => "tag",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "comment" => Some(Self::Comment),
            "tag" => Some(Self::Tag),
            _ => None,
        }
    }
}

/// User type kind stored in `types`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeKind {
    Struct,
    Union,
    Enum,
    Typedef,
    Prototype,
}

impl TypeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Struct => "struct",
            Self::Union => "union",
            Self::Enum => "enum",
            Self::Typedef => "typedef",
            Self::Prototype => "prototype",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "struct" => Some(Self::Struct),
            "union" => Some(Self::Union),
            "enum" => Some(Self::Enum),
            "typedef" => Some(Self::Typedef),
            "prototype" => Some(Self::Prototype),
            _ => None,
        }
    }
}

/// A stored user type. `payload_json` is a serialized `hexray_types::CType`
/// (or `FunctionPrototype`), versioned by `payload_version`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeRow {
    pub name: String,
    pub kind: TypeKind,
    pub payload_version: u32,
    pub payload_json: String,
    pub origin: String,
}

/// Locator of an overridden variable, stable across re-analysis only while
/// the function's CFG generation is unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VariableLocator {
    /// Formal parameter by 0-based position.
    Parameter { index: u8 },
    /// Frame-relative stack slot; the offset is a decimal string so the full
    /// `i128` textual range parses before narrowing.
    Stack { offset: String },
    /// Register/temporary key within one CFG generation.
    Expression { generation: u64, key: String },
}

impl VariableLocator {
    /// Canonical JSON used as the storage key.
    pub fn to_key(&self) -> String {
        serde_json::to_string(self).expect("variable locator serializes")
    }

    pub fn from_json(value: &str) -> Result<Self, crate::DbError> {
        serde_json::from_str(value).map_err(|error| {
            crate::DbError::Validation(format!("invalid variable locator: {error}"))
        })
    }

    /// The stack offset as `i64`, when this is a stack locator.
    pub fn stack_offset(&self) -> Result<Option<i64>, crate::DbError> {
        let Self::Stack { offset } = self else {
            return Ok(None);
        };
        let parsed: i128 = offset
            .parse()
            .map_err(|_| crate::DbError::Validation(format!("invalid stack offset '{offset}'")))?;
        i64::try_from(parsed).map(Some).map_err(|_| {
            crate::DbError::Validation(format!("stack offset '{offset}' out of range"))
        })
    }
}

/// A stored variable override.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariableOverrideRow {
    pub function: Address,
    pub locator: VariableLocator,
    pub name: Option<String>,
    pub type_name: Option<String>,
}

/// User function overrides.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionOverrideRow {
    pub signature: Option<String>,
    pub calling_convention: Option<String>,
}

/// Owner categories for units of analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerKind {
    ImageIndex,
    FunctionCfg,
    FunctionRender,
}

impl OwnerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ImageIndex => "image_index",
            Self::FunctionCfg => "function_cfg",
            Self::FunctionRender => "function_render",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "image_index" => Some(Self::ImageIndex),
            "function_cfg" => Some(Self::FunctionCfg),
            "function_render" => Some(Self::FunctionRender),
            _ => None,
        }
    }
}

/// Identity of one analysis unit: owner plus the render config for render
/// units (all-zero for index/CFG units).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct UnitKey {
    pub owner: OwnerKind,
    pub key: Address,
    pub config: [u8; 32],
}

impl UnitKey {
    pub fn image_index() -> Self {
        Self {
            owner: OwnerKind::ImageIndex,
            key: Address(1),
            config: NO_CONFIG_FINGERPRINT,
        }
    }

    pub fn function_cfg(function: Address) -> Self {
        Self {
            owner: OwnerKind::FunctionCfg,
            key: function,
            config: NO_CONFIG_FINGERPRINT,
        }
    }

    pub fn function_render(function: Address, config: [u8; 32]) -> Self {
        Self {
            owner: OwnerKind::FunctionRender,
            key: function,
            config,
        }
    }

    pub fn describe(&self) -> String {
        format!("{}:{}", self.owner.as_str(), self.key.to_hex())
    }
}

/// Unit state. `Pending`/`Stale` dominate the overall state, then `Failed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisState {
    Pending,
    Current,
    Stale,
    Partial,
    Unsupported,
    Failed,
}

impl AnalysisState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Current => "current",
            Self::Stale => "stale",
            Self::Partial => "partial",
            Self::Unsupported => "unsupported",
            Self::Failed => "failed",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "current" => Some(Self::Current),
            "stale" => Some(Self::Stale),
            "partial" => Some(Self::Partial),
            "unsupported" => Some(Self::Unsupported),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }

    /// True when a consumer may display the artifact without a stale marker.
    pub fn is_fresh(self) -> bool {
        matches!(self, Self::Current)
    }

    /// True when the artifact exists but must be labelled as not current.
    pub fn is_stale_like(self) -> bool {
        matches!(
            self,
            Self::Stale | Self::Partial | Self::Failed | Self::Pending
        )
    }
}

/// Overall database state, derived from all unit states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverallState {
    Pending,
    Partial,
    Ready,
}

impl OverallState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Partial => "partial",
            Self::Ready => "ready",
        }
    }
}

/// Severity of a diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

/// One analysis diagnostic. `code` is a stable identifier, not a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub code: String,
    pub severity: Severity,
    pub message: String,
    pub address: Option<Address>,
}

impl Diagnostic {
    pub fn new(code: impl Into<String>, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            severity,
            message: message.into(),
            address: None,
        }
    }

    pub fn warning(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(code, Severity::Warning, message)
    }

    pub fn info(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(code, Severity::Info, message)
    }

    pub fn at(mut self, address: Address) -> Self {
        self.address = Some(address);
        self
    }
}

/// Dependency categories recorded per unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    /// The unit read this address range.
    Range,
    /// The unit read the name at this address.
    Name,
    /// The unit consumed the signature of this function.
    Signature,
    /// The unit consumed this type.
    Type,
    /// The unit depends on a whole stage (data/scalar sweep) it cannot bound.
    Stage,
}

impl DependencyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Range => "range",
            Self::Name => "name",
            Self::Signature => "signature",
            Self::Type => "type",
            Self::Stage => "stage",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "range" => Some(Self::Range),
            "name" => Some(Self::Name),
            "signature" => Some(Self::Signature),
            "type" => Some(Self::Type),
            "stage" => Some(Self::Stage),
            _ => None,
        }
    }
}

/// A dependency edge of an analysis unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dependency {
    pub kind: DependencyKind,
    pub key: String,
    pub range: Option<AddressRange>,
    pub target_generation: u64,
}

impl Dependency {
    /// Key used to compare against unit keys during invalidation.
    pub fn unit_key(&self) -> Option<UnitKey> {
        match self.kind {
            DependencyKind::Signature => self
                .key
                .strip_prefix("function:")
                .and_then(|raw| u64::from_str_radix(raw, 16).ok())
                .map(|address| UnitKey::function_cfg(Address(address))),
            _ => None,
        }
    }
}

/// A published unit row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisUnitRow {
    pub key: UnitKey,
    pub generation: u64,
    pub input_fingerprint: [u8; 32],
    pub engine_fingerprint: [u8; 32],
    pub state: AnalysisState,
    pub diagnostics: Vec<Diagnostic>,
    pub dependencies_complete: bool,
}

/// Decoded-function payload: replaces that function's derived rows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCfgPayload {
    pub function: FunctionRow,
    pub instructions: Vec<hexray_core::Instruction>,
    /// Blocks and, per block, the ordered instruction addresses.
    pub blocks: Vec<BlockPayload>,
    pub block_instructions: Vec<(u32, Vec<Address>)>,
    pub edges: Vec<(u32, u32, EdgeKind)>,
    pub xrefs: Vec<XrefRow>,
}

/// Whole-image index payload: discovery results, symbols, strings and
/// image-owned xrefs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageIndexPayload {
    pub functions: Vec<FunctionRow>,
    pub symbols: Vec<SymbolInfo>,
    pub strings: Vec<StringRow>,
    pub xrefs: Vec<XrefRow>,
}

/// Rendered pseudo-C payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderPayload {
    pub function: Address,
    pub config_fingerprint: [u8; 32],
    pub text: String,
}

/// Payload attached to one published unit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "owner", rename_all = "snake_case")]
pub enum AnalysisPayload {
    ImageIndex(Box<ImageIndexPayload>),
    FunctionCfg(Box<FunctionCfgPayload>),
    FunctionRender(Box<RenderPayload>),
}

impl AnalysisPayload {
    pub fn owner(&self) -> OwnerKind {
        match self {
            Self::ImageIndex(_) => OwnerKind::ImageIndex,
            Self::FunctionCfg(_) => OwnerKind::FunctionCfg,
            Self::FunctionRender(_) => OwnerKind::FunctionRender,
        }
    }
}

/// One unit published by an analysis run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnitPublish {
    pub key: UnitKey,
    /// Generation the publisher observed before computing. `None` means the
    /// unit did not exist yet.
    pub expected_generation: Option<u64>,
    pub state: AnalysisState,
    pub input_fingerprint: [u8; 32],
    pub dependencies_complete: bool,
    pub diagnostics: Vec<Diagnostic>,
    pub dependencies: Vec<Dependency>,
    pub payload: AnalysisPayload,
}

/// A batch of units published in one transaction.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisBatch {
    pub units: Vec<UnitPublish>,
}

impl AnalysisBatch {
    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }
}

/// Canonical render configuration. Every field participates in the
/// fingerprint; nothing here is read from the environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderConfig {
    pub optimization_level: String,
    pub enable_passes: Vec<String>,
    pub disable_passes: Vec<String>,
    pub show_addresses: bool,
    pub indent: String,
    /// SHA-256 of the type snapshot the render consumed.
    pub type_snapshot_sha256: [u8; 32],
    pub engine_fingerprint: [u8; 32],
}

impl RenderConfig {
    /// Canonical serialization: length-prefixed fields, sorted sets.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_field(&mut out, self.optimization_level.as_bytes());
        let mut enable = self.enable_passes.clone();
        enable.sort();
        enable.dedup();
        push_field(&mut out, &(enable.len() as u64).to_be_bytes());
        for pass in &enable {
            push_field(&mut out, pass.as_bytes());
        }
        let mut disable = self.disable_passes.clone();
        disable.sort();
        disable.dedup();
        push_field(&mut out, &(disable.len() as u64).to_be_bytes());
        for pass in &disable {
            push_field(&mut out, pass.as_bytes());
        }
        push_field(&mut out, &[self.show_addresses as u8]);
        push_field(&mut out, self.indent.as_bytes());
        push_field(&mut out, &self.type_snapshot_sha256);
        push_field(&mut out, &self.engine_fingerprint);
        out
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        crate::sha256(&self.canonical_bytes())
    }
}

fn push_field(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

/// One user-declared address range that automatic analysis must not decode.
///
/// Half-open in virtual addresses: `[start, end)`. `section_name` is the
/// user's own label and is display-only — the canonical form of a scope keeps
/// the numbers, never the label, so renaming a section cannot split a render
/// key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeRange {
    pub start: Address,
    pub end: Address,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_name: Option<String>,
}

/// The persisted automatic-analysis range policy of one project.
///
/// This is a *user* decision, not an automatic packing verdict: it only limits
/// which ranges the automatic analysis chain decodes (discovery, CFG, callee
/// signature seeding, cold-thunk scans). Data reads, xrefs to excluded targets
/// and explicit temporary queries keep their original semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AnalysisScope {
    pub payload_version: u32,
    pub excluded_ranges: Vec<ScopeRange>,
}

impl AnalysisScope {
    /// Current payload version. Bump only with a migration.
    pub const CURRENT_PAYLOAD_VERSION: u32 = 1;

    /// No excluded range: automatic analysis covers the whole image.
    pub fn empty() -> Self {
        Self {
            payload_version: Self::CURRENT_PAYLOAD_VERSION,
            excluded_ranges: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.excluded_ranges.is_empty()
    }

    /// Merged `[start, end)` intervals, sorted, adjacent ranges joined.
    ///
    /// Overlapping or adjacent user ranges describe one exclusion window, so
    /// the execution view is the union — never one interval per user range.
    pub fn merged_intervals(&self) -> Vec<(u64, u64)> {
        let mut spans: Vec<(u64, u64)> = self
            .excluded_ranges
            .iter()
            .filter(|range| range.end.0 > range.start.0)
            .map(|range| (range.start.0, range.end.0))
            .collect();
        spans.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(spans.len());
        for (start, end) in spans {
            match merged.last_mut() {
                Some((_, last_end)) if start <= *last_end => {
                    if end > *last_end {
                        *last_end = end;
                    }
                }
                _ => merged.push((start, end)),
            }
        }
        merged
    }

    /// True when `address` is inside an excluded interval.
    pub fn contains(&self, address: u64) -> bool {
        self.merged_intervals()
            .iter()
            .any(|(start, end)| address >= *start && address < *end)
    }

    /// End of the exclusion window containing `address`, if any.
    pub fn barrier_end(&self, address: u64) -> Option<u64> {
        self.merged_intervals()
            .into_iter()
            .find(|(start, end)| address >= *start && address < *end)
            .map(|(_, end)| end)
    }

    /// First excluded address at or after `address`, if any.
    pub fn next_start(&self, address: u64) -> Option<u64> {
        self.merged_intervals()
            .iter()
            .map(|(start, _)| *start)
            .find(|start| *start >= address)
    }

    /// Canonical bytes: payload version plus the merged numeric intervals.
    ///
    /// Section labels are deliberately absent: two user ranges that exclude the
    /// same bytes are the same policy even if they were entered by name.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let spans = self.merged_intervals();
        let mut out = Vec::with_capacity(8 + spans.len() * 16);
        out.extend_from_slice(&self.payload_version.to_be_bytes());
        out.extend_from_slice(&(spans.len() as u64).to_be_bytes());
        for (start, end) in spans {
            out.extend_from_slice(&start.to_be_bytes());
            out.extend_from_slice(&end.to_be_bytes());
        }
        out
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        crate::sha256(&self.canonical_bytes())
    }

    /// Reject a payload that cannot come from this engine.
    pub fn validate(&self) -> Result<(), crate::DbError> {
        if self.payload_version != Self::CURRENT_PAYLOAD_VERSION {
            return Err(crate::DbError::Validation(format!(
                "analysis scope payload version {} is not supported",
                self.payload_version
            )));
        }
        for range in &self.excluded_ranges {
            if range.end.0 <= range.start.0 {
                return Err(crate::DbError::Validation(format!(
                    "analysis scope range {}..{} is empty or reversed",
                    range.start.to_hex(),
                    range.end.to_hex()
                )));
            }
        }
        Ok(())
    }
}

/// Resource kind under which the project's [`AnalysisScope`] is stored.
pub const ANALYSIS_SCOPE_RESOURCE_KIND: &str = "analysis_scope";
/// Logical name of the single scope resource. A missing row means "empty".
pub const ANALYSIS_SCOPE_RESOURCE_NAME: &str = "default";

/// Inputs used to create a database.
#[derive(Debug, Clone)]
pub struct CreateInput {
    pub original_path: std::path::PathBuf,
    pub source_bytes: Vec<u8>,
    pub container_kind: ContainerKind,
    pub image: ImageInfo,
    pub engine_fingerprint: [u8; 32],
    pub symbols: Vec<SymbolInfo>,
    pub functions: Vec<FunctionRow>,
    pub strings: Vec<StringRow>,
    pub xrefs: Vec<XrefRow>,
    /// Snapshot of the built-in type database, as JSON.
    pub builtin_types_json: Option<String>,
    /// Initial automatic-analysis exclusion policy. Written with the initial
    /// resources at revision 0, so creating a filtered project never consumes
    /// an undo entry.
    pub analysis_scope: AnalysisScope,
    pub diagnostics: Vec<Diagnostic>,
}

/// Destination/state overview of one database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseInfo {
    pub uuid: String,
    pub revision: Revision,
    pub created_at: String,
    pub engine_fingerprint: [u8; 32],
    pub stored_engine_fingerprint: [u8; 32],
    pub schema_version: u32,
    pub overall_state: OverallState,
    pub source_size: u64,
    pub source_sha256: [u8; 32],
    pub original_path: String,
    pub image: ImageInfo,
    pub function_count: usize,
    pub instruction_count: usize,
    pub string_count: usize,
    pub xref_count: usize,
    pub patch_count: usize,
    /// Stored split-DWARF sidecars that were embedded at creation.
    pub debug_sidecars: usize,
    pub undo_depth: usize,
    pub redo_depth: usize,
    /// Current automatic-analysis exclusion policy.
    pub analysis_scope: AnalysisScope,
    /// `full` when nothing is excluded, `filtered` otherwise.
    pub coverage: String,
    /// Function rows whose entry address the scope excludes. This counts
    /// *known* rows only; it never claims to know how many functions the
    /// excluded bytes contain.
    pub skipped_functions: usize,
}

/// A row of the `changes`/history audit surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEvent {
    pub id: u64,
    pub action: String,
    pub edit_id: Option<u64>,
    pub revision: Revision,
    pub actor: String,
    pub timestamp: String,
    pub kind: Option<String>,
}

/// Result of `check`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckReport {
    pub quick_check: String,
    pub foreign_key_violations: Vec<String>,
    pub source_digest_matches: bool,
    pub patch_ranges_valid: bool,
    pub problems: Vec<String>,
}

impl CheckReport {
    pub fn passed(&self) -> bool {
        self.quick_check == "ok"
            && self.foreign_key_violations.is_empty()
            && self.source_digest_matches
            && self.patch_ranges_valid
            && self.problems.is_empty()
    }
}

/// Outcome of a single edit application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditOutcome {
    /// Content changed; a new revision is now head.
    Applied(Revision),
    /// The edit was a no-op; the revision is unchanged and no history was
    /// consumed.
    Unchanged(Revision),
}
