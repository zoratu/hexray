//! Database schema: the DDL this build creates, and the validation that a
//! file on disk is exactly that schema.
//!
//! A `.hxdb` is untrusted input. `open` compares the embedded SQL text of
//! every object in `sqlite_schema` against this list, so an unexpected table,
//! index, view, trigger or virtual table is rejected before any write is
//! allowed. Comparing definition text (not just names) also catches a
//! tampered `CHECK`/`FOREIGN KEY` clause that a name-only check would miss.

use crate::model::{DB_APPLICATION_ID, SCHEMA_VERSION};
use crate::{DbError, DbResult};
use rusqlite::Connection;

/// Every schema object, in creation order.
pub const SCHEMA_OBJECTS: &[&str] = &[
    "CREATE TABLE database_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    uuid TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 0),
    engine_fingerprint BLOB NOT NULL CHECK (typeof(engine_fingerprint) = 'blob' AND length(engine_fingerprint) = 32),
    created_at TEXT NOT NULL
)",
    "CREATE TABLE sources (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    original_path TEXT NOT NULL,
    original_size INTEGER NOT NULL CHECK (original_size >= 0),
    sha256 BLOB NOT NULL CHECK (typeof(sha256) = 'blob' AND length(sha256) = 32),
    container_kind TEXT NOT NULL
)",
    "CREATE TABLE source_chunks (
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    offset BLOB NOT NULL CHECK (typeof(offset) = 'blob' AND length(offset) = 8),
    length INTEGER NOT NULL CHECK (length > 0),
    bytes BLOB NOT NULL,
    sha256 BLOB NOT NULL CHECK (typeof(sha256) = 'blob' AND length(sha256) = 32),
    PRIMARY KEY (source_id, offset)
) WITHOUT ROWID",
    "CREATE TABLE images (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    source_id INTEGER NOT NULL REFERENCES sources(id),
    selector_json TEXT NOT NULL,
    format TEXT NOT NULL,
    architecture TEXT NOT NULL,
    bitness INTEGER NOT NULL CHECK (bitness IN (32, 64)),
    endianness TEXT NOT NULL CHECK (endianness IN ('little', 'big')),
    abi_json TEXT NOT NULL,
    entry_address BLOB CHECK (entry_address IS NULL OR (typeof(entry_address) = 'blob' AND length(entry_address) = 8)),
    layout_fingerprint BLOB NOT NULL CHECK (typeof(layout_fingerprint) = 'blob' AND length(layout_fingerprint) = 32),
    layout_fingerprint_version INTEGER NOT NULL,
    container_offset INTEGER NOT NULL CHECK (container_offset >= 0),
    container_length INTEGER NOT NULL CHECK (container_length > 0),
    member_name TEXT,
    member_index INTEGER,
    slice_label TEXT,
    max_analysis_bytes INTEGER NOT NULL CHECK (max_analysis_bytes > 0)
)",
    "CREATE TABLE mappings (
    id INTEGER PRIMARY KEY,
    image_id INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    va BLOB NOT NULL CHECK (typeof(va) = 'blob' AND length(va) = 8),
    memory_size INTEGER NOT NULL CHECK (memory_size >= 0),
    file_offset BLOB CHECK (file_offset IS NULL OR (typeof(file_offset) = 'blob' AND length(file_offset) = 8)),
    file_size INTEGER NOT NULL CHECK (file_size >= 0),
    permissions TEXT NOT NULL,
    origin TEXT NOT NULL
)",
    "CREATE TABLE sections (
    id INTEGER PRIMARY KEY,
    image_id INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    va BLOB NOT NULL CHECK (typeof(va) = 'blob' AND length(va) = 8),
    memory_size INTEGER NOT NULL CHECK (memory_size >= 0),
    file_offset BLOB CHECK (file_offset IS NULL OR (typeof(file_offset) = 'blob' AND length(file_offset) = 8)),
    file_size INTEGER NOT NULL CHECK (file_size >= 0),
    flags TEXT NOT NULL
)",
    "CREATE TABLE patches (
    id INTEGER PRIMARY KEY,
    file_offset BLOB NOT NULL UNIQUE CHECK (typeof(file_offset) = 'blob' AND length(file_offset) = 8),
    bytes BLOB NOT NULL CHECK (length(bytes) > 0)
)",
    "CREATE TABLE symbols (
    image_id INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    address BLOB NOT NULL CHECK (typeof(address) = 'blob' AND length(address) = 8),
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    size INTEGER NOT NULL CHECK (size >= 0),
    origin TEXT NOT NULL,
    PRIMARY KEY (image_id, address, name, origin)
)",
    "CREATE TABLE names (
    image_id INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    address BLOB NOT NULL CHECK (typeof(address) = 'blob' AND length(address) = 8),
    value TEXT NOT NULL,
    PRIMARY KEY (image_id, address)
)",
    "CREATE TABLE items (
    image_id INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    address BLOB NOT NULL CHECK (typeof(address) = 'blob' AND length(address) = 8),
    length INTEGER NOT NULL CHECK (length > 0),
    kind TEXT NOT NULL CHECK (kind IN ('code', 'data')),
    origin TEXT NOT NULL,
    type_name TEXT,
    PRIMARY KEY (image_id, address)
)",
    "CREATE TABLE functions (
    image_id INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    address BLOB NOT NULL CHECK (typeof(address) = 'blob' AND length(address) = 8),
    declared_end BLOB CHECK (declared_end IS NULL OR (typeof(declared_end) = 'blob' AND length(declared_end) = 8)),
    bounds_origin TEXT NOT NULL,
    origin TEXT NOT NULL CHECK (origin IN ('auto', 'user')),
    excluded INTEGER NOT NULL DEFAULT 0 CHECK (excluded IN (0, 1)),
    user_removed INTEGER NOT NULL DEFAULT 0 CHECK (user_removed IN (0, 1)),
    present INTEGER NOT NULL DEFAULT 1 CHECK (present IN (0, 1)),
    PRIMARY KEY (image_id, address)
)",
    "CREATE TABLE instructions (
    image_id INTEGER NOT NULL,
    address BLOB NOT NULL CHECK (typeof(address) = 'blob' AND length(address) = 8),
    size INTEGER NOT NULL CHECK (size > 0),
    payload_version INTEGER NOT NULL,
    payload_json TEXT NOT NULL,
    PRIMARY KEY (image_id, address),
    FOREIGN KEY (image_id) REFERENCES images(id) ON DELETE CASCADE
)",
    "CREATE TABLE function_instructions (
    image_id INTEGER NOT NULL,
    function_address BLOB NOT NULL CHECK (typeof(function_address) = 'blob' AND length(function_address) = 8),
    instruction_address BLOB NOT NULL CHECK (typeof(instruction_address) = 'blob' AND length(instruction_address) = 8),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    PRIMARY KEY (image_id, function_address, instruction_address),
    FOREIGN KEY (image_id, function_address) REFERENCES functions(image_id, address) ON DELETE CASCADE,
    FOREIGN KEY (image_id, instruction_address) REFERENCES instructions(image_id, address) ON DELETE CASCADE
)",
    "CREATE TABLE basic_blocks (
    image_id INTEGER NOT NULL,
    function_address BLOB NOT NULL CHECK (typeof(function_address) = 'blob' AND length(function_address) = 8),
    block_id INTEGER NOT NULL CHECK (block_id >= 0),
    payload_version INTEGER NOT NULL,
    payload_json TEXT NOT NULL,
    PRIMARY KEY (image_id, function_address, block_id),
    FOREIGN KEY (image_id, function_address) REFERENCES functions(image_id, address) ON DELETE CASCADE
)",
    "CREATE TABLE block_instructions (
    image_id INTEGER NOT NULL,
    function_address BLOB NOT NULL CHECK (typeof(function_address) = 'blob' AND length(function_address) = 8),
    block_id INTEGER NOT NULL,
    instruction_address BLOB NOT NULL CHECK (typeof(instruction_address) = 'blob' AND length(instruction_address) = 8),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    PRIMARY KEY (image_id, function_address, block_id, instruction_address),
    FOREIGN KEY (image_id, function_address, block_id) REFERENCES basic_blocks(image_id, function_address, block_id) ON DELETE CASCADE
)",
    "CREATE TABLE cfg_edges (
    image_id INTEGER NOT NULL,
    function_address BLOB NOT NULL CHECK (typeof(function_address) = 'blob' AND length(function_address) = 8),
    from_block INTEGER NOT NULL,
    to_block INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('normal', 'unwind')),
    PRIMARY KEY (image_id, function_address, from_block, to_block, kind),
    FOREIGN KEY (image_id, function_address) REFERENCES functions(image_id, address) ON DELETE CASCADE
)",
    "CREATE TABLE xrefs (
    image_id INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    from_address BLOB NOT NULL CHECK (typeof(from_address) = 'blob' AND length(from_address) = 8),
    to_address BLOB NOT NULL CHECK (typeof(to_address) = 'blob' AND length(to_address) = 8),
    kind TEXT NOT NULL CHECK (kind IN ('call', 'jump', 'data')),
    owner_function BLOB CHECK (owner_function IS NULL OR (typeof(owner_function) = 'blob' AND length(owner_function) = 8)),
    origin TEXT NOT NULL,
    PRIMARY KEY (image_id, from_address, to_address, kind)
)",
    "CREATE INDEX xrefs_to ON xrefs (image_id, to_address)",
    "CREATE INDEX xrefs_from ON xrefs (image_id, from_address)",
    "CREATE TABLE strings (
    image_id INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    address BLOB NOT NULL CHECK (typeof(address) = 'blob' AND length(address) = 8),
    encoding TEXT NOT NULL,
    byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
    bytes BLOB NOT NULL,
    decoded_text TEXT,
    PRIMARY KEY (image_id, address, encoding)
)",
    "CREATE TABLE resources (
    id INTEGER PRIMARY KEY,
    image_id INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    logical_name TEXT NOT NULL,
    content_sha256 BLOB NOT NULL CHECK (typeof(content_sha256) = 'blob' AND length(content_sha256) = 32),
    payload BLOB NOT NULL,
    UNIQUE (image_id, kind, logical_name)
)",
    "CREATE TABLE types (
    id INTEGER PRIMARY KEY,
    image_id INTEGER NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    payload_version INTEGER NOT NULL,
    payload_json TEXT NOT NULL,
    origin TEXT NOT NULL,
    UNIQUE (image_id, name, origin)
)",
    "CREATE TABLE function_overrides (
    image_id INTEGER NOT NULL,
    address BLOB NOT NULL CHECK (typeof(address) = 'blob' AND length(address) = 8),
    payload_json TEXT NOT NULL,
    PRIMARY KEY (image_id, address),
    FOREIGN KEY (image_id, address) REFERENCES functions(image_id, address) ON DELETE CASCADE
)",
    "CREATE TABLE annotations (
    image_id INTEGER NOT NULL,
    address BLOB NOT NULL CHECK (typeof(address) = 'blob' AND length(address) = 8),
    kind TEXT NOT NULL CHECK (kind IN ('comment', 'tag')),
    value TEXT NOT NULL,
    PRIMARY KEY (image_id, address, kind),
    FOREIGN KEY (image_id) REFERENCES images(id) ON DELETE CASCADE
)",
    "CREATE TABLE bookmarks (
    image_id INTEGER NOT NULL,
    address BLOB NOT NULL CHECK (typeof(address) = 'blob' AND length(address) = 8),
    label TEXT,
    PRIMARY KEY (image_id, address),
    FOREIGN KEY (image_id) REFERENCES images(id) ON DELETE CASCADE
)",
    "CREATE TABLE variable_overrides (
    image_id INTEGER NOT NULL,
    function_address BLOB NOT NULL CHECK (typeof(function_address) = 'blob' AND length(function_address) = 8),
    locator_json TEXT NOT NULL,
    value_json TEXT NOT NULL,
    PRIMARY KEY (image_id, function_address, locator_json),
    FOREIGN KEY (image_id, function_address) REFERENCES functions(image_id, address) ON DELETE CASCADE
)",
    "CREATE TABLE analysis_units (
    image_id INTEGER NOT NULL,
    owner_kind TEXT NOT NULL CHECK (owner_kind IN ('image_index', 'function_cfg', 'function_render')),
    owner_key BLOB NOT NULL CHECK (typeof(owner_key) = 'blob' AND length(owner_key) = 8),
    config_fingerprint BLOB NOT NULL CHECK (typeof(config_fingerprint) = 'blob' AND length(config_fingerprint) = 32),
    generation INTEGER NOT NULL CHECK (generation >= 0),
    input_fingerprint BLOB NOT NULL CHECK (typeof(input_fingerprint) = 'blob' AND length(input_fingerprint) = 32),
    engine_fingerprint BLOB NOT NULL CHECK (typeof(engine_fingerprint) = 'blob' AND length(engine_fingerprint) = 32),
    state TEXT NOT NULL CHECK (state IN ('pending', 'current', 'stale', 'partial', 'unsupported', 'failed')),
    diagnostics_json TEXT,
    dependencies_complete INTEGER NOT NULL DEFAULT 1 CHECK (dependencies_complete IN (0, 1)),
    PRIMARY KEY (image_id, owner_kind, owner_key, config_fingerprint)
)",
    "CREATE TABLE analysis_dependencies (
    image_id INTEGER NOT NULL,
    owner_kind TEXT NOT NULL,
    owner_key BLOB NOT NULL CHECK (typeof(owner_key) = 'blob' AND length(owner_key) = 8),
    config_fingerprint BLOB NOT NULL CHECK (typeof(config_fingerprint) = 'blob' AND length(config_fingerprint) = 32),
    dependency_kind TEXT NOT NULL,
    dependency_key TEXT NOT NULL,
    range_start BLOB NOT NULL CHECK (typeof(range_start) = 'blob' AND length(range_start) = 8),
    range_length INTEGER NOT NULL CHECK (range_length >= 0),
    target_generation INTEGER NOT NULL CHECK (target_generation >= 0),
    PRIMARY KEY (image_id, owner_kind, owner_key, config_fingerprint, dependency_kind, dependency_key, range_start),
    FOREIGN KEY (image_id, owner_kind, owner_key, config_fingerprint) REFERENCES analysis_units(image_id, owner_kind, owner_key, config_fingerprint) ON DELETE CASCADE
)",
    "CREATE TABLE decompiled (
    image_id INTEGER NOT NULL,
    function_address BLOB NOT NULL CHECK (typeof(function_address) = 'blob' AND length(function_address) = 8),
    config_fingerprint BLOB NOT NULL CHECK (typeof(config_fingerprint) = 'blob' AND length(config_fingerprint) = 32),
    generation INTEGER NOT NULL CHECK (generation >= 0),
    payload_version INTEGER NOT NULL,
    text TEXT NOT NULL,
    PRIMARY KEY (image_id, function_address, config_fingerprint),
    FOREIGN KEY (image_id, function_address) REFERENCES functions(image_id, address) ON DELETE CASCADE
)",
    "CREATE TABLE edit_log (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER REFERENCES edit_log(id),
    kind TEXT NOT NULL,
    forward_json TEXT NOT NULL,
    inverse_json TEXT NOT NULL,
    committed_revision INTEGER NOT NULL CHECK (committed_revision >= 0),
    actor TEXT NOT NULL,
    timestamp TEXT NOT NULL
)",
    "CREATE TABLE history_head (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    edit_id INTEGER REFERENCES edit_log(id),
    redo_ids_json TEXT NOT NULL
)",
    "CREATE TABLE history_events (
    id INTEGER PRIMARY KEY,
    action TEXT NOT NULL CHECK (action IN ('apply', 'undo', 'redo')),
    edit_id INTEGER REFERENCES edit_log(id),
    revision INTEGER NOT NULL CHECK (revision >= 0),
    actor TEXT NOT NULL,
    timestamp TEXT NOT NULL
)",
    "CREATE TABLE command_history (
    id INTEGER PRIMARY KEY,
    actor TEXT NOT NULL,
    command TEXT NOT NULL,
    output TEXT NOT NULL,
    success INTEGER NOT NULL CHECK (success IN (0, 1)),
    timestamp TEXT NOT NULL,
    truncated INTEGER NOT NULL DEFAULT 0 CHECK (truncated IN (0, 1))
)",
    "CREATE TABLE legacy_imports (
    id INTEGER PRIMARY KEY,
    path TEXT NOT NULL,
    kind TEXT NOT NULL,
    sha256 BLOB NOT NULL CHECK (typeof(sha256) = 'blob' AND length(sha256) = 32),
    identity_status TEXT NOT NULL,
    metadata_json TEXT NOT NULL
)",
    "CREATE TABLE legacy_records (
    id INTEGER PRIMARY KEY,
    legacy_import_id INTEGER NOT NULL REFERENCES legacy_imports(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    payload TEXT NOT NULL
)",
];

/// Set the file identity pragmas. `application_id` is written to the header
/// so a plain `sqlite3` session can tell an `.hxdb` apart immediately.
pub fn apply_identity(conn: &Connection) -> DbResult<()> {
    conn.pragma_update(None, "application_id", DB_APPLICATION_ID)?;
    conn.pragma_update(None, "user_version", SCHEMA_VERSION as i64)?;
    Ok(())
}

/// Create every object. Caller must be inside a transaction.
pub fn create_objects(conn: &Connection) -> DbResult<()> {
    for statement in SCHEMA_OBJECTS {
        conn.execute_batch(statement)?;
    }
    Ok(())
}

/// Read `application_id` and `user_version` from the file header.
pub fn read_identity(conn: &Connection) -> DbResult<(i64, i64)> {
    let application_id: i64 = conn.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    let user_version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    Ok((application_id, user_version))
}

/// Validate that the file is an `.hxdb` of exactly this schema version.
///
/// Rejects: non-SQLite files, foreign SQLite databases (wrong
/// `application_id`), version 0 databases, future schema versions, and any
/// object whose text differs from [`SCHEMA_OBJECTS`].
pub fn validate(conn: &Connection) -> DbResult<()> {
    let (application_id, user_version) = read_identity(conn)?;

    if application_id == 0 && user_version == 0 {
        return Err(DbError::NotADatabase);
    }
    if application_id != i64::from(DB_APPLICATION_ID) {
        return Err(DbError::NotADatabase);
    }
    let version = u32::try_from(user_version)
        .map_err(|_| DbError::UnsupportedSchema(user_version.to_string()))?;
    if version != SCHEMA_VERSION {
        return Err(DbError::UnsupportedSchema(version.to_string()));
    }

    let mut statement = conn.prepare(
        "SELECT type, name, sql FROM sqlite_schema WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%'",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;

    let mut found: Vec<(String, String)> = Vec::new();
    for row in rows {
        let (kind, name, sql) = row?;
        if kind != "table" && kind != "index" {
            return Err(DbError::Corrupt(format!(
                "unexpected {kind} object '{name}' in database"
            )));
        }
        found.push((name, normalize(&sql)));
    }

    let expected: Vec<(String, String)> = SCHEMA_OBJECTS
        .iter()
        .map(|statement| (object_name(statement), normalize(statement)))
        .collect();

    if found.len() != expected.len() {
        let unexpected: Vec<&str> = found
            .iter()
            .filter(|(name, _)| !expected.iter().any(|(expected, _)| expected == name))
            .map(|(name, _)| name.as_str())
            .collect();
        return Err(DbError::Corrupt(format!(
            "schema object count mismatch (found {}, expected {}); unexpected: {:?}",
            found.len(),
            expected.len(),
            unexpected
        )));
    }

    for (name, sql) in &expected {
        let Some((_, actual)) = found.iter().find(|(found_name, _)| found_name == name) else {
            return Err(DbError::Corrupt(format!("missing schema object '{name}'")));
        };
        if actual != sql {
            return Err(DbError::Corrupt(format!(
                "schema object '{name}' does not match this version"
            )));
        }
    }

    Ok(())
}

/// Collapse whitespace so cosmetic reformatting of the stored text does not
/// defeat the comparison, while any structural change still does.
fn normalize(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn object_name(statement: &str) -> String {
    // `CREATE TABLE <name> (` / `CREATE INDEX <name> ON ...`
    let mut parts = statement.split_whitespace();
    match (parts.next(), parts.next(), parts.next()) {
        (Some("CREATE"), Some("TABLE"), Some(name)) => name.trim_matches('(').to_string(),
        (Some("CREATE"), Some("INDEX"), Some(name)) => name.to_string(),
        (Some("CREATE"), Some(kind), None) => kind.to_string(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_names_are_parsed() {
        assert_eq!(
            object_name("CREATE TABLE database_meta (\n    id INTEGER PRIMARY KEY)"),
            "database_meta"
        );
        assert_eq!(
            object_name("CREATE INDEX xrefs_to ON xrefs (image_id, to_address)"),
            "xrefs_to"
        );
    }

    #[test]
    fn normalize_collapses_whitespace() {
        assert_eq!(normalize("CREATE TABLE  a\n ( b )"), "CREATE TABLE a ( b )");
    }
}
