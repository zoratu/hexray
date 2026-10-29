//! Import of the two legacy user-state formats.
//!
//! Neither format is a database this crate creates: a JSON `AnalysisProject`
//! (`.hrp`/`.hxp`) and an SQLite analysis session are read once, translated
//! into the neutral [`LegacyAction`] form, and every original row is preserved
//! verbatim in `legacy_records` for audit. Legacy undo history is kept as
//! records only — it is never replayed, so the new project starts with an
//! honest, empty undo stack.
//!
//! Identity is not negotiable per format:
//! - the JSON project's stored digest is a weak `DefaultHasher`-derived value,
//!   so a match is reported as `weak_verified` and a mismatch is rejected
//!   unless the caller explicitly accepts unverified legacy data;
//! - the SQLite session stores a real SHA-256, so a mismatch is always fatal.

use std::path::Path;

use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};

use crate::address::Address;
use crate::model::*;
use crate::{sha256, DbError, DbResult};

/// Which legacy format a file holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyKind {
    ProjectJson,
    SessionSqlite,
}

impl LegacyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProjectJson => "project_json",
            Self::SessionSqlite => "session_sqlite",
        }
    }
}

/// How well the legacy file's identity could be checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityStatus {
    /// Real SHA-256 matched.
    Verified,
    /// The legacy weak digest matched.
    WeakVerified,
    /// The caller explicitly accepted an unverified file.
    Unverified,
}

impl IdentityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::WeakVerified => "weak_verified",
            Self::Unverified => "unverified",
        }
    }
}

/// One preserved legacy row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyRecord {
    pub kind: String,
    pub payload: String,
}

/// A translated piece of legacy user state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegacyAction {
    Name {
        address: Address,
        value: String,
    },
    Annotation {
        address: Address,
        kind: AnnotationKind,
        value: String,
    },
    Bookmark {
        address: Address,
        label: Option<String>,
    },
    FunctionOverride {
        address: Address,
        signature: Option<String>,
        calling_convention: Option<String>,
        excluded: bool,
    },
    Item {
        address: Address,
        length: u64,
        kind: ItemKind,
        type_name: Option<String>,
    },
    Type {
        name: String,
        kind: TypeKind,
        payload_json: String,
    },
}

impl LegacyAction {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Name { .. } => "name",
            Self::Annotation { kind, .. } => match kind {
                AnnotationKind::Comment => "comment",
                AnnotationKind::Tag => "tag",
            },
            Self::Bookmark { .. } => "bookmark",
            Self::FunctionOverride { .. } => "function_override",
            Self::Item { .. } => "item",
            Self::Type { .. } => "type",
        }
    }
}

/// A fully read legacy file, ready to import.
#[derive(Debug, Clone)]
pub struct LegacySource {
    pub path: String,
    pub kind: LegacyKind,
    pub file_sha256: [u8; 32],
    pub identity_status: IdentityStatus,
    pub stored_identity: String,
    pub metadata_json: String,
    pub records: Vec<LegacyRecord>,
    pub actions: Vec<LegacyAction>,
    pub unresolved: Vec<LegacyRecord>,
}

/// Per-kind import accounting.
#[derive(Debug, Clone, Default)]
pub struct LegacySummary {
    pub imported_records: usize,
    pub applied: usize,
    pub unresolved: usize,
    pub by_kind: Vec<KindCount>,
}

/// One row of [`LegacySummary::by_kind`].
#[derive(Debug, Clone)]
pub struct KindCount {
    pub kind: String,
    pub applied: usize,
    pub unresolved: usize,
}

impl LegacySummary {
    pub fn render(&self) -> String {
        let mut out = format!(
            "imported {} legacy record(s): {} applied, {} unresolved\n",
            self.imported_records, self.applied, self.unresolved
        );
        for row in &self.by_kind {
            out.push_str(&format!(
                "  {:<20} applied {:>5}  unresolved {:>5}\n",
                row.kind, row.applied, row.unresolved
            ));
        }
        out
    }
}

/// Read a legacy file and classify it by content, never by extension.
///
/// `source_sha256` is the digest of the binary the caller selected with
/// `--binary`; it is what the legacy identity is checked against.
pub fn read_legacy_source(
    path: &Path,
    source_sha256: &[u8; 32],
    source_bytes: &[u8],
    accept_unverified: bool,
) -> DbResult<LegacySource> {
    let bytes = std::fs::read(path)?;
    let file_sha256 = sha256(&bytes);
    if bytes.starts_with(b"SQLite format 3\0") {
        read_session(path, &file_sha256, source_sha256, accept_unverified)
    } else if bytes
        .iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|byte| *byte == b'{')
    {
        let text = String::from_utf8(bytes)
            .map_err(|_| DbError::Validation("legacy project is not valid UTF-8".into()))?;
        read_project_json(&text, path, &file_sha256, source_bytes, accept_unverified)
    } else {
        Err(DbError::Validation(format!(
            "{} is neither a JSON analysis project nor an SQLite session",
            path.display()
        )))
    }
}

fn read_project_json(
    text: &str,
    path: &Path,
    file_sha256: &[u8; 32],
    source_bytes: &[u8],
    accept_unverified: bool,
) -> DbResult<LegacySource> {
    let value: serde_json::Value = serde_json::from_str(text)
        .map_err(|error| DbError::Validation(format!("legacy project JSON: {error}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| DbError::Validation("legacy project is not a JSON object".into()))?;

    for required in ["version", "binary_path", "binary_hash"] {
        if !object.contains_key(required) {
            return Err(DbError::Validation(format!(
                "legacy project is missing '{required}'"
            )));
        }
    }

    let stored_text = object
        .get("binary_hash")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let stored_weak = decode_legacy_hash(stored_text)?;
    let weak_matches = stored_weak.is_some_and(|weak| weak == legacy_weak_digest(source_bytes));
    let identity_status = if weak_matches {
        IdentityStatus::WeakVerified
    } else if accept_unverified {
        IdentityStatus::Unverified
    } else {
        return Err(DbError::IdentityMismatch(format!(
            "legacy project records a different binary digest ({stored_text}); \
             re-run with --accept-unverified-legacy to import it anyway"
        )));
    };

    let mut records: Vec<LegacyRecord> = Vec::new();
    let mut actions: Vec<LegacyAction> = Vec::new();
    let mut unresolved: Vec<LegacyRecord> = Vec::new();
    let mut push = |kind: &str, payload: serde_json::Value| {
        records.push(LegacyRecord {
            kind: kind.to_string(),
            payload: payload.to_string(),
        })
    };

    push(
        "project_meta",
        serde_json::json!({
            "version": object.get("version").cloned(),
            "binary_path": object.get("binary_path").cloned(),
            "binary_hash": stored_text,
        }),
    );

    if let Some(annotations) = object
        .get("annotations")
        .and_then(|value| value.as_object())
    {
        for (key, value) in annotations {
            let Some(address) = parse_json_address(key) else {
                unresolved.push(LegacyRecord {
                    kind: "annotation_unresolved".into(),
                    payload: format!("{key}: {value}"),
                });
                continue;
            };
            let Some(list) = value.as_array() else {
                continue;
            };
            for annotation in list {
                push("annotation", annotation.clone());
                let kind = annotation
                    .get("kind")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default();
                let text = annotation
                    .get("value")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default();
                match kind {
                    "comment" => actions.push(LegacyAction::Annotation {
                        address: Address(address),
                        kind: AnnotationKind::Comment,
                        value: text.to_string(),
                    }),
                    "tag" => actions.push(LegacyAction::Annotation {
                        address: Address(address),
                        kind: AnnotationKind::Tag,
                        value: text.to_string(),
                    }),
                    "label" => actions.push(LegacyAction::Name {
                        address: Address(address),
                        value: text.to_string(),
                    }),
                    // A variable name has no locator in the legacy format, so it
                    // cannot be rebound; keep the text for the audit trail.
                    other => unresolved.push(LegacyRecord {
                        kind: format!("annotation_{other}_unresolved"),
                        payload: format!("{}: {text}", Address(address).to_hex()),
                    }),
                }
            }
        }
    }

    if let Some(overrides) = object
        .get("function_overrides")
        .and_then(|value| value.as_object())
    {
        for (key, value) in overrides {
            let Some(address) = parse_json_address(key) else {
                unresolved.push(LegacyRecord {
                    kind: "function_override_unresolved".into(),
                    payload: format!("{key}: {value}"),
                });
                continue;
            };
            push("function_override", value.clone());
            let name = value
                .get("name")
                .and_then(|value| value.as_str())
                .map(str::to_string);
            let signature = value
                .get("signature")
                .filter(|signature| !signature.is_null())
                .and_then(|signature| render_legacy_signature(signature, name.as_deref(), address));
            if value.get("signature").is_some_and(|sig| !sig.is_null()) && signature.is_none() {
                unresolved.push(LegacyRecord {
                    kind: "function_signature_unresolved".into(),
                    payload: format!("{}: {}", Address(address).to_hex(), value["signature"]),
                });
            }
            if let Some(name) = name {
                actions.push(LegacyAction::Name {
                    address: Address(address),
                    value: name,
                });
            }
            if let Some(notes) = value.get("notes").and_then(|value| value.as_str()) {
                actions.push(LegacyAction::Annotation {
                    address: Address(address),
                    kind: AnnotationKind::Comment,
                    value: notes.to_string(),
                });
            }
            actions.push(LegacyAction::FunctionOverride {
                address: Address(address),
                signature,
                calling_convention: value
                    .get("calling_convention")
                    .and_then(|value| value.as_str())
                    .map(str::to_string),
                excluded: value
                    .get("excluded")
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false),
            });
        }
    }

    if let Some(overrides) = object
        .get("type_overrides")
        .and_then(|value| value.as_object())
    {
        for (key, value) in overrides {
            let Some(address) = parse_json_address(key) else {
                unresolved.push(LegacyRecord {
                    kind: "type_override_unresolved".into(),
                    payload: format!("{key}: {value}"),
                });
                continue;
            };
            push("type_override", value.clone());
            match convert_legacy_type_override(value) {
                Ok(Some(action)) => {
                    actions.push(action);
                    let length = value
                        .get("size")
                        .and_then(|size| size.as_u64())
                        .or_else(|| array_length(value));
                    if let Some(length) = length {
                        if length > 0 {
                            actions.push(LegacyAction::Item {
                                address: Address(address),
                                length,
                                kind: ItemKind::Data,
                                type_name: value
                                    .get("type_name")
                                    .and_then(|name| name.as_str())
                                    .map(str::to_string),
                            });
                        }
                    }
                }
                Ok(None) => {}
                Err(reason) => unresolved.push(LegacyRecord {
                    kind: "type_override_unresolved".into(),
                    payload: format!("{}: {reason}", Address(address).to_hex()),
                }),
            }
        }
    }

    if let Some(bookmarks) = object.get("bookmarks").and_then(|value| value.as_array()) {
        for bookmark in bookmarks {
            push("bookmark", bookmark.clone());
            let Some(address) = bookmark.get("address").and_then(|value| value.as_u64()) else {
                unresolved.push(LegacyRecord {
                    kind: "bookmark_unresolved".into(),
                    payload: bookmark.to_string(),
                });
                continue;
            };
            actions.push(LegacyAction::Bookmark {
                address: Address(address),
                label: bookmark
                    .get("label")
                    .and_then(|value| value.as_str())
                    .map(str::to_string),
            });
        }
    }

    let metadata = serde_json::json!({
        "binary_path": object.get("binary_path").cloned(),
        "version": object.get("version").cloned(),
        "binary_hash": stored_text,
        "identity": identity_status.as_str(),
    })
    .to_string();

    Ok(LegacySource {
        path: path.to_string_lossy().into_owned(),
        kind: LegacyKind::ProjectJson,
        file_sha256: *file_sha256,
        identity_status,
        stored_identity: stored_text.to_string(),
        metadata_json: metadata,
        records,
        actions,
        unresolved,
    })
}

fn read_session(
    path: &Path,
    file_sha256: &[u8; 32],
    source_sha256: &[u8; 32],
    accept_unverified: bool,
) -> DbResult<LegacySource> {
    if accept_unverified {
        return Err(DbError::Validation(
            "--accept-unverified-legacy does not apply to SQLite sessions: they store a real SHA-256"
                .into(),
        ));
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(std::time::Duration::from_millis(5000))?;
    conn.pragma_update(None, "trusted_schema", "OFF")?;

    for table in ["session_meta", "history", "annotations", "undo_history"] {
        let present: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1",
                rusqlite::params![table],
                |row| row.get(0),
            )
            .optional()?;
        if present.is_none() {
            return Err(DbError::Validation(format!(
                "{} is not a legacy analysis session (missing table '{table}')",
                path.display()
            )));
        }
    }

    let meta_count: i64 =
        conn.query_row("SELECT COUNT(*) FROM session_meta", [], |row| row.get(0))?;
    if meta_count != 1 {
        return Err(DbError::Ambiguous(format!(
            "legacy session holds {meta_count} session_meta rows; exactly one is required"
        )));
    }

    let (id, name, binary_path, binary_hash, created_at): (String, String, String, String, String) =
        conn.query_row(
            "SELECT id, name, binary_path, binary_hash, created_at FROM session_meta",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;

    let stored = decode_legacy_hash(&binary_hash)?.ok_or_else(|| {
        DbError::Validation(format!("legacy session digest '{binary_hash}' is not hex"))
    })?;
    if &stored != source_sha256 {
        return Err(DbError::IdentityMismatch(format!(
            "legacy session belongs to a different binary (stored {}, selected {})",
            crate::hex_encode(&stored),
            crate::hex_encode(source_sha256)
        )));
    }

    let mut records = vec![LegacyRecord {
        kind: "session_meta".into(),
        payload: serde_json::json!({
            "id": id,
            "name": name,
            "binary_path": binary_path,
            "binary_hash": binary_hash,
            "created_at": created_at,
        })
        .to_string(),
    }];
    let mut actions = Vec::new();
    let mut unresolved = Vec::new();

    {
        let mut statement = conn.prepare(
            "SELECT address, kind, value, created_at FROM annotations ORDER BY address, kind",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let raw: i64 = row.get(0)?;
            let address = Address(raw as u64);
            let kind: String = row.get(1)?;
            let value: String = row.get(2)?;
            let created_at: String = row.get(3)?;
            records.push(LegacyRecord {
                kind: "annotation".into(),
                payload: serde_json::json!({
                    "address": address.to_hex(),
                    "kind": kind,
                    "value": value,
                    "created_at": created_at,
                })
                .to_string(),
            });
            match kind.to_ascii_lowercase().as_str() {
                "rename" | "name" => actions.push(LegacyAction::Name { address, value }),
                "comment" => actions.push(LegacyAction::Annotation {
                    address,
                    kind: AnnotationKind::Comment,
                    value,
                }),
                "tag" => actions.push(LegacyAction::Annotation {
                    address,
                    kind: AnnotationKind::Tag,
                    value,
                }),
                "label" | "bookmark" => actions.push(LegacyAction::Bookmark {
                    address,
                    label: Some(value),
                }),
                other => unresolved.push(LegacyRecord {
                    kind: format!("annotation_{other}_unresolved"),
                    payload: format!("{}: {value}", address.to_hex()),
                }),
            }
        }
    }

    // Command history and legacy undo entries are audit-only: they are
    // preserved verbatim and never replayed.
    {
        let mut statement = conn.prepare(
            "SELECT idx, timestamp, command, output, duration_ms, success FROM history ORDER BY idx",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            records.push(LegacyRecord {
                kind: "history".into(),
                payload: serde_json::json!({
                    "idx": row.get::<_, i64>(0)?,
                    "timestamp": row.get::<_, String>(1)?,
                    "command": row.get::<_, String>(2)?,
                    "output": row.get::<_, String>(3)?,
                    "duration_ms": row.get::<_, i64>(4)?,
                    "success": row.get::<_, i64>(5)? != 0,
                })
                .to_string(),
            });
        }
    }
    {
        let mut statement = conn.prepare(
            "SELECT id, description, action_type, action_data, timestamp, undone
             FROM undo_history ORDER BY id",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            records.push(LegacyRecord {
                kind: "undo_history".into(),
                payload: serde_json::json!({
                    "id": row.get::<_, i64>(0)?,
                    "description": row.get::<_, String>(1)?,
                    "action_type": row.get::<_, String>(2)?,
                    "action_data": row.get::<_, String>(3)?,
                    "timestamp": row.get::<_, String>(4)?,
                    "undone": row.get::<_, i64>(5)? != 0,
                })
                .to_string(),
            });
        }
    }

    let metadata = serde_json::json!({
        "name": name,
        "binary_path": binary_path,
        "created_at": created_at,
        "identity": IdentityStatus::Verified.as_str(),
    })
    .to_string();

    Ok(LegacySource {
        path: path.to_string_lossy().into_owned(),
        kind: LegacyKind::SessionSqlite,
        file_sha256: *file_sha256,
        identity_status: IdentityStatus::Verified,
        stored_identity: binary_hash,
        metadata_json: metadata,
        records,
        actions,
        unresolved,
    })
}

/// Parse a 64-character hex digest, tolerating the malformed values the legacy
/// writer could produce (odd length, non-ASCII): those are reported, never
/// panicked on.
fn decode_legacy_hash(text: &str) -> DbResult<Option<[u8; 32]>> {
    if text.is_empty() {
        return Ok(None);
    }
    if !text.is_ascii() || !text.len().is_multiple_of(2) {
        return Err(DbError::Validation(format!(
            "legacy digest '{text}' is not an even-length ASCII hex string"
        )));
    }
    crate::hex_decode_32(text).map(Some).or_else(|_| {
        // Not a 32-byte digest: still valid hex, just not usable for identity.
        let raw: Vec<u8> = text
            .as_bytes()
            .chunks(2)
            .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap_or(""), 16))
            .collect::<Result<_, _>>()
            .map_err(|_| DbError::Validation(format!("legacy digest '{text}' is not hex")))?;
        let mut out = [0u8; 32];
        if raw.len() == 32 {
            out.copy_from_slice(&raw);
        }
        Ok(Some(out))
    })
}

/// Reproduce the legacy `AnalysisProject::compute_hash` digest so a project
/// written by an older hexray can still be identified as "probably this
/// binary". This is *not* a security boundary and is only used to pick between
/// `weak_verified` and "refuse unless the user insists".
pub fn legacy_weak_digest(content: &[u8]) -> [u8; 32] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    content.hash(&mut hasher);
    let hash = hasher.finish();

    let mut result = [0u8; 32];
    result[..8].copy_from_slice(&hash.to_le_bytes());
    let len = content.len() as u64;
    result[8..16].copy_from_slice(&len.to_le_bytes());
    let checksum: u64 = content.iter().map(|&byte| byte as u64).sum();
    result[16..24].copy_from_slice(&checksum.to_le_bytes());
    result
}

fn parse_json_address(key: &str) -> Option<u64> {
    let key = key.trim();
    if let Some(hex) = key.strip_prefix("0x").or_else(|| key.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    key.parse().ok()
}

fn array_length(value: &serde_json::Value) -> Option<u64> {
    value.get("array_length").and_then(|length| length.as_u64())
}

/// Turn a legacy `TypeOverride` into a stored user type.
///
/// The legacy format only carries a textual type name plus optional size and
/// array information, so the text is resolved through the C header parser and
/// rejected when it does not parse — an unresolvable name stays a legacy
/// record instead of silently becoming an active type.
fn convert_legacy_type_override(value: &serde_json::Value) -> Result<Option<LegacyAction>, String> {
    let Some(type_name) = value.get("type_name").and_then(|name| name.as_str()) else {
        return Err("missing type_name".into());
    };
    let is_array = value
        .get("is_array")
        .and_then(|flag| flag.as_bool())
        .unwrap_or(false);
    let size = value.get("size").and_then(|size| size.as_u64());
    let length = array_length(value);

    let header = format!("typedef {type_name} __hxdb_legacy_t;");
    let database = hexray_types::parser::parse_header(&header)
        .map_err(|error| format!("'{type_name}' does not parse as a C type: {error}"))?;
    let Some(base) = database.get_type("__hxdb_legacy_t").cloned() else {
        return Err(format!("'{type_name}' did not resolve to a type"));
    };
    let resolved = if is_array {
        let count = length.ok_or_else(|| "'is_array' without 'array_length'".to_string())?;
        hexray_types::CType::Array(hexray_types::ArrayType {
            element: Box::new(base),
            length: Some(count as usize),
        })
    } else {
        base
    };

    if let (Some(size), Some(actual)) = (size, resolved.size()) {
        if size as usize != actual {
            return Err(format!(
                "declared size {size} disagrees with the parsed size {actual}"
            ));
        }
    }

    let payload_json =
        serde_json::to_string(&resolved).map_err(|error| format!("type payload: {error}"))?;
    let name = match value.get("name").and_then(|name| name.as_str()) {
        Some(name) if !name.is_empty() => name.to_string(),
        _ => type_name.replace([' ', '*', '[', ']'], "_"),
    };
    Ok(Some(LegacyAction::Type {
        name,
        // The legacy format only carries a textual type, so everything it
        // produces becomes a typedef of the parsed type.
        kind: TypeKind::Typedef,
        payload_json,
    }))
}

fn render_legacy_signature(
    signature: &serde_json::Value,
    name: Option<&str>,
    address: u64,
) -> Option<String> {
    let return_type = signature
        .get("return_type")
        .and_then(|value| value.as_str())?
        .to_string();
    let variadic = signature
        .get("variadic")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let mut parameters = Vec::new();
    if let Some(list) = signature
        .get("parameters")
        .and_then(|value| value.as_array())
    {
        for parameter in list {
            let pair = parameter.as_array()?;
            let parameter_name = pair.first().and_then(|value| value.as_str()).unwrap_or("");
            let parameter_type = pair
                .get(1)
                .and_then(|value| value.as_str())
                .unwrap_or("int");
            if parameter_name.is_empty() {
                parameters.push(parameter_type.to_string());
            } else {
                parameters.push(format!("{parameter_type} {parameter_name}"));
            }
        }
    }
    if variadic {
        parameters.push("...".to_string());
    }
    let function_name = name
        .map(str::to_string)
        .unwrap_or_else(|| format!("sub_{address:x}"));
    Some(format!(
        "{return_type} {function_name}({})",
        if parameters.is_empty() {
            "void".to_string()
        } else {
            parameters.join(", ")
        }
    ))
}

/// Write a legacy source into the database: user state plus the full audit
/// trail. Runs in one transaction so a partially imported project cannot be
/// published.
pub(crate) fn write_records(
    tx: &Transaction<'_>,
    source: &LegacySource,
) -> DbResult<LegacySummary> {
    let mut summary = LegacySummary {
        imported_records: source.records.len(),
        ..Default::default()
    };
    let mut counts: std::collections::BTreeMap<(String, bool), usize> =
        std::collections::BTreeMap::new();

    for action in &source.actions {
        let applied = write_action(tx, action)?;
        let entry = counts
            .entry((action.label().to_string(), applied))
            .or_default();
        *entry += 1;
        if applied {
            summary.applied += 1;
        } else {
            summary.unresolved += 1;
        }
    }
    for record in &source.unresolved {
        *counts.entry((record.kind.clone(), false)).or_default() += 1;
        summary.unresolved += 1;
    }

    tx.execute(
        "INSERT INTO legacy_imports (path, kind, sha256, identity_status, metadata_json)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            source.path,
            source.kind.as_str(),
            &source.file_sha256[..],
            source.identity_status.as_str(),
            source.metadata_json
        ],
    )?;
    let import_id = tx.last_insert_rowid();

    {
        let mut statement = tx.prepare(
            "INSERT INTO legacy_records (legacy_import_id, kind, payload) VALUES (?1, ?2, ?3)",
        )?;
        for record in source.records.iter().chain(source.unresolved.iter()) {
            statement.execute(rusqlite::params![import_id, record.kind, record.payload])?;
        }
    }

    for ((kind, applied), count) in counts {
        let entry = summary.by_kind.iter_mut().find(|row| row.kind == kind);
        match entry {
            Some(row) => {
                if applied {
                    row.applied += count;
                } else {
                    row.unresolved += count;
                }
            }
            None => summary.by_kind.push(KindCount {
                kind,
                applied: if applied { count } else { 0 },
                unresolved: if applied { 0 } else { count },
            }),
        }
    }
    Ok(summary)
}

fn write_action(tx: &Transaction<'_>, action: &LegacyAction) -> DbResult<bool> {
    match action {
        LegacyAction::Name { address, value } => {
            tx.execute(
                "INSERT OR REPLACE INTO names (image_id, address, value) VALUES (1, ?1, ?2)",
                rusqlite::params![&address.to_blob()[..], value],
            )?;
            Ok(true)
        }
        LegacyAction::Annotation {
            address,
            kind,
            value,
        } => {
            tx.execute(
                "INSERT OR REPLACE INTO annotations (image_id, address, kind, value)
                 VALUES (1, ?1, ?2, ?3)",
                rusqlite::params![&address.to_blob()[..], kind.as_str(), value],
            )?;
            Ok(true)
        }
        LegacyAction::Bookmark { address, label } => {
            tx.execute(
                "INSERT OR REPLACE INTO bookmarks (image_id, address, label) VALUES (1, ?1, ?2)",
                rusqlite::params![&address.to_blob()[..], label],
            )?;
            Ok(true)
        }
        LegacyAction::FunctionOverride {
            address,
            signature,
            calling_convention,
            excluded,
        } => {
            // The function row must exist for the override foreign key.
            tx.execute(
                "INSERT OR IGNORE INTO functions
                    (image_id, address, declared_end, bounds_origin, origin, excluded,
                     user_removed, present)
                 VALUES (1, ?1, NULL, 'heuristic', 'auto', ?2, 0, 1)",
                rusqlite::params![&address.to_blob()[..], *excluded as i64],
            )?;
            let payload = FunctionOverrideRow {
                signature: signature.clone(),
                calling_convention: calling_convention.clone(),
            };
            if payload.signature.is_none() && payload.calling_convention.is_none() {
                if *excluded {
                    tx.execute(
                        "UPDATE functions SET excluded = 1 WHERE image_id = 1 AND address = ?1",
                        rusqlite::params![&address.to_blob()[..]],
                    )?;
                }
                return Ok(true);
            }
            let json = serde_json::to_string(&payload)
                .map_err(|error| DbError::Validation(format!("override payload: {error}")))?;
            tx.execute(
                "INSERT OR REPLACE INTO function_overrides (image_id, address, payload_json)
                 VALUES (1, ?1, ?2)",
                rusqlite::params![&address.to_blob()[..], json],
            )?;
            if *excluded {
                tx.execute(
                    "UPDATE functions SET excluded = 1 WHERE image_id = 1 AND address = ?1",
                    rusqlite::params![&address.to_blob()[..]],
                )?;
            }
            Ok(true)
        }
        LegacyAction::Item {
            address,
            length,
            kind,
            type_name,
        } => {
            // Range definitions need a mapped target; otherwise they stay
            // unresolved rather than becoming an out-of-image item.
            if !address_mapped(tx, *address)? {
                return Ok(false);
            }
            tx.execute(
                "INSERT OR REPLACE INTO items (image_id, address, length, kind, origin, type_name)
                 VALUES (1, ?1, ?2, ?3, 'legacy', ?4)",
                rusqlite::params![
                    &address.to_blob()[..],
                    *length as i64,
                    kind.as_str(),
                    type_name
                ],
            )?;
            Ok(true)
        }
        LegacyAction::Type {
            name,
            kind,
            payload_json,
        } => {
            tx.execute(
                "INSERT OR REPLACE INTO types (image_id, name, kind, payload_version, payload_json, origin)
                 VALUES (1, ?1, ?2, ?3, ?4, 'legacy')",
                rusqlite::params![
                    name,
                    kind.as_str(),
                    PAYLOAD_VERSION as i64,
                    payload_json
                ],
            )?;
            Ok(true)
        }
    }
}

fn address_mapped(tx: &Transaction<'_>, address: Address) -> DbResult<bool> {
    let mut statement =
        tx.prepare("SELECT va, memory_size FROM mappings WHERE image_id = 1 ORDER BY va")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let va = Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?;
        let size = u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0);
        if address.0 >= va.0 && address.0 < va.0.saturating_add(size) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_digest_is_deterministic() {
        let here = legacy_weak_digest(b"hexray");
        let there = legacy_weak_digest(b"hexray");
        assert_eq!(here, there);
        assert_ne!(here, legacy_weak_digest(b"hexrays"));
        // The digest mixes in length and a byte sum, so single-byte edits move it.
        let mut other = b"hexray".to_vec();
        other[0] = b'H';
        assert_ne!(here, legacy_weak_digest(&other));
    }

    #[test]
    fn malformed_legacy_hash_does_not_panic() {
        assert!(decode_legacy_hash("abc").is_err());
        assert!(decode_legacy_hash("é").is_err());
        assert!(decode_legacy_hash("zz").is_err());
        assert!(decode_legacy_hash("").unwrap().is_none());
    }

    #[test]
    fn signature_rendering_uses_name_or_address() {
        let signature = serde_json::json!({
            "return_type": "int",
            "parameters": [["a", "int"], ["b", "char *"]],
            "variadic": true,
        });
        assert_eq!(
            render_legacy_signature(&signature, Some("main"), 0x1000).unwrap(),
            "int main(int a, char * b, ...)"
        );
        assert_eq!(
            render_legacy_signature(&signature, None, 0x1000).unwrap(),
            "int sub_1000(int a, char * b, ...)"
        );
    }

    #[test]
    fn type_override_conversion_rejects_garbage() {
        let value = serde_json::json!({ "type_name": "int int", "size": null });
        assert!(convert_legacy_type_override(&value).is_err());
    }

    #[test]
    fn type_override_conversion_accepts_arrays() {
        let value = serde_json::json!({
            "type_name": "int",
            "is_array": true,
            "array_length": 4,
            "size": 16,
        });
        let action = convert_legacy_type_override(&value).unwrap().unwrap();
        match action {
            LegacyAction::Type { payload_json, .. } => {
                let ty: hexray_types::CType = serde_json::from_str(&payload_json).unwrap();
                assert_eq!(ty.size(), Some(16));
            }
            other => panic!("unexpected action {other:?}"),
        }
    }
}
