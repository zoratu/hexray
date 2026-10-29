//! User edits: validation, application, inverse, and invalidation.
//!
//! Every edit runs inside the caller's `BEGIN IMMEDIATE` transaction and
//! re-validates against the state it finds there — never against a snapshot
//! read earlier — so the range/type/function checks cannot lose a race with a
//! concurrent session.
//!
//! Validation is split by information need: structural rules (ranges, sizes,
//! instruction alignment, reference counts) live here because the store owns
//! that data; format rules (which file regions may be patched, whether a C
//! prototype or ABI name parses) live in the CLI, which owns the parsers.

use std::collections::BTreeSet;

use rusqlite::{OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};

use crate::address::{Address, AddressRange, FileOffset};
use crate::model::*;
use crate::store::{MAX_PATCH_BYTES, MAX_PAYLOAD_BYTES};
use crate::{DbError, DbResult};

/// One user edit. Every value that can be cleared carries an explicit `None`
/// so "delete" and "empty string" stay distinguishable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "edit", rename_all = "snake_case")]
pub enum Edit {
    /// Overwrite file bytes of the original input.
    PatchBytes {
        file_offset: FileOffset,
        bytes: Vec<u8>,
    },
    /// Declare an address range to be code or typed data.
    SetItem {
        address: Address,
        length: u64,
        kind: ItemKind,
        type_name: Option<String>,
    },
    /// Remove a user item definition. The range must match one item exactly.
    ClearItem {
        address: Address,
        length: u64,
    },
    CreateFunction {
        start: Address,
        end: Address,
    },
    SetFunctionBounds {
        start: Address,
        end: Address,
    },
    RemoveFunction {
        start: Address,
    },
    SetFunctionExcluded {
        start: Address,
        excluded: bool,
    },
    SetName {
        address: Address,
        name: Option<String>,
    },
    SetComment {
        address: Address,
        text: Option<String>,
    },
    SetTag {
        address: Address,
        text: Option<String>,
    },
    SetBookmark {
        address: Address,
        label: Option<String>,
    },
    SetFunctionSignature {
        start: Address,
        prototype: Option<String>,
    },
    SetCallingConvention {
        start: Address,
        convention: Option<String>,
    },
    PutType {
        name: String,
        kind: TypeKind,
        payload_json: String,
    },
    RemoveType {
        name: String,
    },
    ApplyType {
        address: Address,
        type_name: Option<String>,
        length: Option<u64>,
    },
    SetVariableOverride {
        function: Address,
        locator: VariableLocator,
        name: Option<String>,
        type_name: Option<String>,
    },
    RemoveOverride {
        target: OverrideTarget,
        address: Address,
        locator: Option<VariableLocator>,
    },
    /// Replace the project's automatic-analysis exclusion policy as a whole.
    ///
    /// This is a user edit like any other: it bumps the revision, lands in the
    /// undo history, and invalidates the automatic analysis. An empty scope
    /// clears the policy.
    SetAnalysisScope {
        scope: AnalysisScope,
    },
}

/// What a `clear`/`remove` command targets. Selecting the kind is mandatory:
/// clearing one kind never removes the other user state at that address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverrideTarget {
    Name,
    Comment,
    Tag,
    Bookmark,
    Signature,
    CallingConvention,
    Type,
    Variable,
}

impl OverrideTarget {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "name" => Self::Name,
            "comment" => Self::Comment,
            "tag" => Self::Tag,
            "bookmark" => Self::Bookmark,
            "signature" => Self::Signature,
            "calling-convention" => Self::CallingConvention,
            "type" => Self::Type,
            "variable" => Self::Variable,
            _ => return None,
        })
    }
}

impl Edit {
    /// Stable kind string for `edit_log.kind` and the `changes` view.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::PatchBytes { .. } => "patch",
            Self::SetItem { .. } => "set-item",
            Self::ClearItem { .. } => "clear-item",
            Self::CreateFunction { .. } => "function-create",
            Self::SetFunctionBounds { .. } => "function-bounds",
            Self::RemoveFunction { .. } => "function-remove",
            Self::SetFunctionExcluded { .. } => "function-exclude",
            Self::SetName { .. } => "name",
            Self::SetComment { .. } => "comment",
            Self::SetTag { .. } => "tag",
            Self::SetBookmark { .. } => "bookmark",
            Self::SetFunctionSignature { .. } => "signature",
            Self::SetCallingConvention { .. } => "calling-convention",
            Self::PutType { .. } => "type-import",
            Self::RemoveType { .. } => "type-remove",
            Self::ApplyType { .. } => "apply-type",
            Self::SetVariableOverride { .. } => "variable",
            Self::RemoveOverride { target, .. } => match target {
                OverrideTarget::Name => "clear-name",
                OverrideTarget::Comment => "clear-comment",
                OverrideTarget::Tag => "clear-tag",
                OverrideTarget::Bookmark => "clear-bookmark",
                OverrideTarget::Signature => "clear-signature",
                OverrideTarget::CallingConvention => "clear-calling-convention",
                OverrideTarget::Type => "clear-type",
                OverrideTarget::Variable => "clear-variable",
            },
            Self::SetAnalysisScope { .. } => "scope",
        }
    }
}

/// The inverse of an applied edit: exact previous user state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum InverseOp {
    /// Restore the exact patch rows that overlapped `[start, end)`.
    PatchRegion {
        start: FileOffset,
        end: FileOffset,
        rows: Vec<PatchRow>,
    },
    PutItem(ItemRow),
    DeleteItem {
        address: Address,
    },
    PutFunction(FunctionRow),
    PutName {
        address: Address,
        value: String,
    },
    DeleteName {
        address: Address,
    },
    PutAnnotation {
        address: Address,
        kind: AnnotationKind,
        value: String,
    },
    DeleteAnnotation {
        address: Address,
        kind: AnnotationKind,
    },
    PutBookmark {
        address: Address,
        label: Option<String>,
    },
    DeleteBookmark {
        address: Address,
    },
    PutFunctionOverride {
        address: Address,
        payload: FunctionOverrideRow,
    },
    DeleteFunctionOverride {
        address: Address,
    },
    PutType(TypeRow),
    DeleteType {
        name: String,
    },
    PutVariableOverride {
        function: Address,
        locator_json: String,
        value_json: String,
    },
    DeleteVariableOverride {
        function: Address,
        locator_json: String,
    },
    /// Restore the analysis-scope resource exactly: `None` means the row did
    /// not exist before the edit, so undo deletes it again.
    RestoreAnalysisScope {
        previous_payload: Option<String>,
    },
}

/// What an applied edit changed and how to undo it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditResult {
    pub changed: bool,
    pub inverse: Vec<InverseOp>,
}

impl EditResult {
    fn unchanged() -> Self {
        Self {
            changed: false,
            inverse: Vec::new(),
        }
    }

    fn changed(inverse: Vec<InverseOp>) -> Self {
        Self {
            changed: true,
            inverse,
        }
    }
}

/// Apply one edit inside the caller's transaction.
pub fn apply(tx: &Transaction<'_>, edit: &Edit) -> DbResult<EditResult> {
    match edit {
        Edit::PatchBytes { file_offset, bytes } => apply_patch(tx, *file_offset, bytes),
        Edit::SetItem {
            address,
            length,
            kind,
            type_name,
        } => apply_set_item(tx, *address, *length, *kind, type_name.as_deref()),
        Edit::ClearItem { address, length } => apply_clear_item(tx, *address, *length),
        Edit::CreateFunction { start, end } => apply_create_function(tx, *start, *end),
        Edit::SetFunctionBounds { start, end } => apply_set_bounds(tx, *start, *end),
        Edit::RemoveFunction { start } => apply_remove_function(tx, *start),
        Edit::SetFunctionExcluded { start, excluded } => apply_set_excluded(tx, *start, *excluded),
        Edit::SetName { address, name } => apply_name(tx, *address, name.as_deref()),
        Edit::SetComment { address, text } => {
            apply_annotation(tx, *address, AnnotationKind::Comment, text.as_deref())
        }
        Edit::SetTag { address, text } => {
            apply_annotation(tx, *address, AnnotationKind::Tag, text.as_deref())
        }
        Edit::SetBookmark { address, label } => apply_bookmark(tx, *address, label.as_deref()),
        Edit::SetFunctionSignature { start, prototype } => {
            apply_override(tx, *start, OverrideField::Signature, prototype.as_deref())
        }
        Edit::SetCallingConvention { start, convention } => apply_override(
            tx,
            *start,
            OverrideField::CallingConvention,
            convention.as_deref(),
        ),
        Edit::PutType {
            name,
            kind,
            payload_json,
        } => apply_put_type(tx, name, *kind, payload_json),
        Edit::RemoveType { name } => apply_remove_type(tx, name),
        Edit::ApplyType {
            address,
            type_name,
            length,
        } => apply_apply_type(tx, *address, type_name.as_deref(), *length),
        Edit::SetVariableOverride {
            function,
            locator,
            name,
            type_name,
        } => apply_variable_override(
            tx,
            *function,
            locator,
            name.as_deref(),
            type_name.as_deref(),
        ),
        Edit::RemoveOverride {
            target,
            address,
            locator,
        } => apply_remove_override(tx, *target, *address, locator.as_ref()),
        Edit::SetAnalysisScope { scope } => apply_analysis_scope(tx, scope),
    }
}

/// Replay an inverse. Ops are applied in the order stored, which is the
/// reverse of application order for the cases that matter.
pub fn apply_inverse(tx: &Transaction<'_>, inverse: &[InverseOp]) -> DbResult<()> {
    for op in inverse {
        match op {
            InverseOp::PatchRegion { start, end, rows } => {
                delete_patches_in_range(tx, *start, *end)?;
                let mut statement = tx.prepare(
                    "INSERT OR REPLACE INTO patches (file_offset, bytes) VALUES (?1, ?2)",
                )?;
                for row in rows {
                    statement
                        .execute(rusqlite::params![&row.offset.to_blob()[..], &row.bytes[..]])?;
                }
            }
            InverseOp::PutItem(row) => {
                tx.execute(
                    "INSERT OR REPLACE INTO items (image_id, address, length, kind, origin, type_name)
                     VALUES (1, ?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        &row.address.to_blob()[..],
                        row.length as i64,
                        row.kind.as_str(),
                        row.origin,
                        row.type_name
                    ],
                )?;
            }
            InverseOp::DeleteItem { address } => {
                tx.execute(
                    "DELETE FROM items WHERE image_id = 1 AND address = ?1",
                    rusqlite::params![&address.to_blob()[..]],
                )?;
            }
            InverseOp::PutFunction(row) => {
                tx.execute(
                    "INSERT OR REPLACE INTO functions
                        (image_id, address, declared_end, bounds_origin, origin, excluded,
                         user_removed, present)
                     VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    rusqlite::params![
                        &row.address.to_blob()[..],
                        row.declared_end.map(|address| address.to_blob().to_vec()),
                        row.bounds_origin.as_str(),
                        row.origin.as_str(),
                        row.excluded as i64,
                        row.user_removed as i64,
                        row.present as i64
                    ],
                )?;
            }
            InverseOp::PutName { address, value } => {
                tx.execute(
                    "INSERT OR REPLACE INTO names (image_id, address, value) VALUES (1, ?1, ?2)",
                    rusqlite::params![&address.to_blob()[..], value],
                )?;
            }
            InverseOp::DeleteName { address } => {
                tx.execute(
                    "DELETE FROM names WHERE image_id = 1 AND address = ?1",
                    rusqlite::params![&address.to_blob()[..]],
                )?;
            }
            InverseOp::PutAnnotation {
                address,
                kind,
                value,
            } => {
                tx.execute(
                    "INSERT OR REPLACE INTO annotations (image_id, address, kind, value)
                     VALUES (1, ?1, ?2, ?3)",
                    rusqlite::params![&address.to_blob()[..], kind.as_str(), value],
                )?;
            }
            InverseOp::DeleteAnnotation { address, kind } => {
                tx.execute(
                    "DELETE FROM annotations WHERE image_id = 1 AND address = ?1 AND kind = ?2",
                    rusqlite::params![&address.to_blob()[..], kind.as_str()],
                )?;
            }
            InverseOp::PutBookmark { address, label } => {
                tx.execute(
                    "INSERT OR REPLACE INTO bookmarks (image_id, address, label) VALUES (1, ?1, ?2)",
                    rusqlite::params![&address.to_blob()[..], label],
                )?;
            }
            InverseOp::DeleteBookmark { address } => {
                tx.execute(
                    "DELETE FROM bookmarks WHERE image_id = 1 AND address = ?1",
                    rusqlite::params![&address.to_blob()[..]],
                )?;
            }
            InverseOp::PutFunctionOverride { address, payload } => {
                let json = serde_json::to_string(payload)
                    .map_err(|error| DbError::Validation(format!("override payload: {error}")))?;
                tx.execute(
                    "INSERT OR REPLACE INTO function_overrides (image_id, address, payload_json)
                     VALUES (1, ?1, ?2)",
                    rusqlite::params![&address.to_blob()[..], json],
                )?;
            }
            InverseOp::DeleteFunctionOverride { address } => {
                tx.execute(
                    "DELETE FROM function_overrides WHERE image_id = 1 AND address = ?1",
                    rusqlite::params![&address.to_blob()[..]],
                )?;
            }
            InverseOp::PutType(row) => {
                upsert_type(tx, row)?;
            }
            InverseOp::DeleteType { name } => {
                tx.execute(
                    "DELETE FROM types WHERE image_id = 1 AND name = ?1",
                    rusqlite::params![name],
                )?;
            }
            InverseOp::PutVariableOverride {
                function,
                locator_json,
                value_json,
            } => {
                tx.execute(
                    "INSERT OR REPLACE INTO variable_overrides
                        (image_id, function_address, locator_json, value_json)
                     VALUES (1, ?1, ?2, ?3)",
                    rusqlite::params![&function.to_blob()[..], locator_json, value_json],
                )?;
            }
            InverseOp::DeleteVariableOverride {
                function,
                locator_json,
            } => {
                tx.execute(
                    "DELETE FROM variable_overrides
                     WHERE image_id = 1 AND function_address = ?1 AND locator_json = ?2",
                    rusqlite::params![&function.to_blob()[..], locator_json],
                )?;
            }
            InverseOp::RestoreAnalysisScope { previous_payload } => {
                write_scope_resource(tx, previous_payload.as_deref())?;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Individual edits
// ---------------------------------------------------------------------------

fn apply_patch(tx: &Transaction<'_>, offset: FileOffset, bytes: &[u8]) -> DbResult<EditResult> {
    if bytes.is_empty() {
        return Err(DbError::Validation("patch bytes must not be empty".into()));
    }
    if bytes.len() > MAX_PATCH_BYTES {
        return Err(DbError::ResourceLimit(format!(
            "patch is {} bytes, above the {MAX_PATCH_BYTES} byte limit",
            bytes.len()
        )));
    }
    let size: i64 = tx.query_row(
        "SELECT original_size FROM sources WHERE id = 1",
        [],
        |row| row.get(0),
    )?;
    let size = u64::try_from(size).unwrap_or(0);
    let end = offset.checked_end(bytes.len() as u64)?;
    if end > size {
        return Err(DbError::Validation(format!(
            "patch {}..{end:#x} exceeds the {size} byte input",
            offset.to_hex()
        )));
    }

    let existing = read_all_patches(tx)?;
    let touching: Vec<&PatchRow> = existing
        .iter()
        .filter(|row| {
            let row_start = row.offset.0;
            let row_end = row_start.saturating_add(row.bytes.len() as u64);
            row_start < end && offset.0 < row_end
        })
        .collect();

    let inverse = InverseOp::PatchRegion {
        start: offset,
        end: FileOffset(end),
        rows: touching.iter().map(|row| (*row).clone()).collect(),
    };

    // Build the merged result over the union of the touched range.
    let mut merged_start = offset.0;
    let mut merged_end = end;
    for row in &touching {
        merged_start = merged_start.min(row.offset.0);
        merged_end = merged_end.max(row.offset.0.saturating_add(row.bytes.len() as u64));
    }
    let mut merged = vec![
        0u8;
        usize::try_from(merged_end - merged_start).map_err(|_| {
            DbError::ResourceLimit("patch range too large for this platform".into())
        })?
    ];
    for row in &touching {
        let start = usize::try_from(row.offset.0 - merged_start).unwrap_or(0);
        merged[start..start + row.bytes.len()].copy_from_slice(&row.bytes);
    }
    let write_start = usize::try_from(offset.0 - merged_start).unwrap_or(0);
    merged[write_start..write_start + bytes.len()].copy_from_slice(bytes);

    if touching.len() == 1
        && touching[0].offset == FileOffset(merged_start)
        && touching[0].bytes == merged
    {
        return Ok(EditResult::unchanged());
    }

    delete_patches_in_range(tx, FileOffset(merged_start), FileOffset(merged_end))?;
    tx.execute(
        "INSERT INTO patches (file_offset, bytes) VALUES (?1, ?2)",
        rusqlite::params![&FileOffset(merged_start).to_blob()[..], &merged[..]],
    )?;
    Ok(EditResult::changed(vec![inverse]))
}

fn apply_set_item(
    tx: &Transaction<'_>,
    address: Address,
    length: u64,
    kind: ItemKind,
    type_name: Option<&str>,
) -> DbResult<EditResult> {
    let range = AddressRange::new(address, length)?;
    require_mapped(tx, address)?;
    require_mapped(tx, Address(range.end()? - 1))?;

    let previous = read_item(tx, address)?;
    let existing = read_items(tx)?;
    for item in &existing {
        if item.address == address {
            continue;
        }
        let item_range = AddressRange::new(item.address, item.length)?;
        if item_range.overlaps(range)? {
            return Err(DbError::Validation(format!(
                "range {}..{} overlaps the existing {} item at {}",
                address.to_hex(),
                Address(range.end()?).to_hex(),
                item.kind.as_str(),
                item.address.to_hex()
            )));
        }
    }

    if kind == ItemKind::Code {
        require_instruction_alignment(tx, range)?;
        // A code item may not cut through a function body it does not own.
        let declared = declared_function_ranges(tx)?;
        for (function_start, function_end) in declared {
            if function_start == address {
                continue;
            }
            let function_range =
                AddressRange::new(function_start, function_end.0 - function_start.0)?;
            if function_range.overlaps(range)? {
                return Err(DbError::Validation(format!(
                    "code range {}..{} overlaps the function at {}",
                    address.to_hex(),
                    Address(range.end()?).to_hex(),
                    function_start.to_hex()
                )));
            }
        }
    }

    let row = ItemRow {
        address,
        length,
        kind,
        origin: "user".to_string(),
        type_name: type_name.map(str::to_string),
    };
    if previous.as_ref() == Some(&row) {
        return Ok(EditResult::unchanged());
    }
    tx.execute(
        "INSERT OR REPLACE INTO items (image_id, address, length, kind, origin, type_name)
         VALUES (1, ?1, ?2, ?3, 'user', ?4)",
        rusqlite::params![
            &address.to_blob()[..],
            length as i64,
            kind.as_str(),
            type_name
        ],
    )?;
    let inverse = match previous {
        Some(previous) => InverseOp::PutItem(previous),
        None => InverseOp::DeleteItem { address },
    };
    Ok(EditResult::changed(vec![inverse]))
}

fn apply_clear_item(tx: &Transaction<'_>, address: Address, length: u64) -> DbResult<EditResult> {
    let Some(item) = read_item(tx, address)? else {
        return Err(DbError::NotFound(format!(
            "no user item at {}",
            address.to_hex()
        )));
    };
    if item.length != length {
        return Err(DbError::Validation(format!(
            "item at {} is {} bytes; clearing a partial item is not allowed",
            address.to_hex(),
            item.length
        )));
    }
    tx.execute(
        "DELETE FROM items WHERE image_id = 1 AND address = ?1",
        rusqlite::params![&address.to_blob()[..]],
    )?;
    Ok(EditResult::changed(vec![InverseOp::PutItem(item)]))
}

fn apply_create_function(
    tx: &Transaction<'_>,
    start: Address,
    end: Address,
) -> DbResult<EditResult> {
    if end <= start {
        return Err(DbError::Validation(
            "function end must be after start".into(),
        ));
    }
    let range = AddressRange::new(start, end.0 - start.0)?;
    require_mapped(tx, start)?;
    require_mapped(tx, Address(end.0 - 1))?;
    require_instruction_alignment(tx, range)?;

    let previous = read_function(tx, start)?;
    if let Some(existing) = &previous {
        if existing.present && !existing.user_removed {
            return Err(DbError::Validation(format!(
                "a function already exists at {}",
                start.to_hex()
            )));
        }
    }
    let row = FunctionRow {
        address: start,
        declared_end: Some(end),
        bounds_origin: BoundsOrigin::User,
        origin: FunctionOrigin::User,
        excluded: false,
        user_removed: false,
        present: true,
    };
    write_function(tx, &row)?;
    let inverse = match previous {
        Some(previous) => InverseOp::PutFunction(previous),
        None => InverseOp::PutFunction(FunctionRow {
            address: start,
            declared_end: None,
            bounds_origin: BoundsOrigin::Heuristic,
            origin: FunctionOrigin::User,
            excluded: false,
            user_removed: true,
            present: false,
        }),
    };
    Ok(EditResult::changed(vec![inverse]))
}

fn apply_set_bounds(tx: &Transaction<'_>, start: Address, end: Address) -> DbResult<EditResult> {
    if end <= start {
        return Err(DbError::Validation(
            "function end must be after start".into(),
        ));
    }
    let Some(previous) = require_function(tx, start)? else {
        return Err(DbError::NotFound(format!(
            "no function at {}",
            start.to_hex()
        )));
    };
    let range = AddressRange::new(start, end.0 - start.0)?;
    require_instruction_alignment(tx, range)?;

    let mut row = previous.clone();
    row.declared_end = Some(end);
    row.bounds_origin = BoundsOrigin::User;
    row.present = true;
    row.user_removed = false;
    if row == previous {
        return Ok(EditResult::unchanged());
    }
    write_function(tx, &row)?;
    Ok(EditResult::changed(vec![InverseOp::PutFunction(previous)]))
}

fn apply_remove_function(tx: &Transaction<'_>, start: Address) -> DbResult<EditResult> {
    let Some(previous) = require_function(tx, start)? else {
        return Err(DbError::NotFound(format!(
            "no function at {}",
            start.to_hex()
        )));
    };
    if previous.user_removed {
        return Ok(EditResult::unchanged());
    }
    let mut row = previous.clone();
    row.user_removed = true;
    write_function(tx, &row)?;
    // Only derived rows go away; bytes, annotations, items and overrides stay.
    let blob = start.to_blob();
    tx.execute(
        "DELETE FROM function_instructions WHERE image_id = 1 AND function_address = ?1",
        rusqlite::params![&blob[..]],
    )?;
    tx.execute(
        "DELETE FROM basic_blocks WHERE image_id = 1 AND function_address = ?1",
        rusqlite::params![&blob[..]],
    )?;
    tx.execute(
        "DELETE FROM cfg_edges WHERE image_id = 1 AND function_address = ?1",
        rusqlite::params![&blob[..]],
    )?;
    tx.execute(
        "DELETE FROM xrefs WHERE image_id = 1 AND owner_function = ?1",
        rusqlite::params![&blob[..]],
    )?;
    tx.execute(
        "DELETE FROM decompiled WHERE image_id = 1 AND function_address = ?1",
        rusqlite::params![&blob[..]],
    )?;
    tx.execute(
        "DELETE FROM analysis_units
         WHERE image_id = 1 AND owner_key = ?1 AND owner_kind IN ('function_cfg', 'function_render')",
        rusqlite::params![&blob[..]],
    )?;
    Ok(EditResult::changed(vec![InverseOp::PutFunction(previous)]))
}

fn apply_set_excluded(
    tx: &Transaction<'_>,
    start: Address,
    excluded: bool,
) -> DbResult<EditResult> {
    let Some(previous) = require_function(tx, start)? else {
        return Err(DbError::NotFound(format!(
            "no function at {}",
            start.to_hex()
        )));
    };
    if previous.excluded == excluded {
        return Ok(EditResult::unchanged());
    }
    let mut row = previous.clone();
    row.excluded = excluded;
    write_function(tx, &row)?;
    Ok(EditResult::changed(vec![InverseOp::PutFunction(previous)]))
}

fn apply_name(tx: &Transaction<'_>, address: Address, name: Option<&str>) -> DbResult<EditResult> {
    let previous: Option<String> = tx
        .query_row(
            "SELECT value FROM names WHERE image_id = 1 AND address = ?1",
            rusqlite::params![&address.to_blob()[..]],
            |row| row.get(0),
        )
        .optional()?;

    let Some(name) = name else {
        let Some(previous) = previous else {
            return Ok(EditResult::unchanged());
        };
        tx.execute(
            "DELETE FROM names WHERE image_id = 1 AND address = ?1",
            rusqlite::params![&address.to_blob()[..]],
        )?;
        return Ok(EditResult::changed(vec![InverseOp::PutName {
            address,
            value: previous,
        }]));
    };
    let name = name.trim();
    if name.is_empty() {
        return Err(DbError::Validation("name must not be empty".into()));
    }
    if name.len() > 4096 {
        return Err(DbError::ResourceLimit("name is too long".into()));
    }
    if previous.as_deref() == Some(name) {
        return Ok(EditResult::unchanged());
    }
    tx.execute(
        "INSERT OR REPLACE INTO names (image_id, address, value) VALUES (1, ?1, ?2)",
        rusqlite::params![&address.to_blob()[..], name],
    )?;
    let inverse = match previous {
        Some(previous) => InverseOp::PutName {
            address,
            value: previous,
        },
        None => InverseOp::DeleteName { address },
    };
    Ok(EditResult::changed(vec![inverse]))
}

fn apply_annotation(
    tx: &Transaction<'_>,
    address: Address,
    kind: AnnotationKind,
    text: Option<&str>,
) -> DbResult<EditResult> {
    let previous: Option<String> = tx
        .query_row(
            "SELECT value FROM annotations WHERE image_id = 1 AND address = ?1 AND kind = ?2",
            rusqlite::params![&address.to_blob()[..], kind.as_str()],
            |row| row.get(0),
        )
        .optional()?;

    let Some(text) = text else {
        let Some(previous) = previous else {
            return Ok(EditResult::unchanged());
        };
        tx.execute(
            "DELETE FROM annotations WHERE image_id = 1 AND address = ?1 AND kind = ?2",
            rusqlite::params![&address.to_blob()[..], kind.as_str()],
        )?;
        return Ok(EditResult::changed(vec![InverseOp::PutAnnotation {
            address,
            kind,
            value: previous,
        }]));
    };
    if text.len() > MAX_PAYLOAD_BYTES {
        return Err(DbError::ResourceLimit("annotation is too long".into()));
    }
    if previous.as_deref() == Some(text) {
        return Ok(EditResult::unchanged());
    }
    tx.execute(
        "INSERT OR REPLACE INTO annotations (image_id, address, kind, value)
         VALUES (1, ?1, ?2, ?3)",
        rusqlite::params![&address.to_blob()[..], kind.as_str(), text],
    )?;
    let inverse = match previous {
        Some(previous) => InverseOp::PutAnnotation {
            address,
            kind,
            value: previous,
        },
        None => InverseOp::DeleteAnnotation { address, kind },
    };
    Ok(EditResult::changed(vec![inverse]))
}

fn apply_bookmark(
    tx: &Transaction<'_>,
    address: Address,
    label: Option<&str>,
) -> DbResult<EditResult> {
    let previous: Option<Option<String>> = tx
        .query_row(
            "SELECT label FROM bookmarks WHERE image_id = 1 AND address = ?1",
            rusqlite::params![&address.to_blob()[..]],
            |row| row.get(0),
        )
        .optional()?;

    let same = matches!(&previous, Some(Some(current)) if Some(current.as_str()) == label)
        || matches!(&previous, Some(None) if label.is_none());
    if same {
        return Ok(EditResult::unchanged());
    }
    tx.execute(
        "INSERT OR REPLACE INTO bookmarks (image_id, address, label) VALUES (1, ?1, ?2)",
        rusqlite::params![&address.to_blob()[..], label],
    )?;
    let inverse = match previous {
        Some(previous) => InverseOp::PutBookmark {
            address,
            label: previous,
        },
        None => InverseOp::DeleteBookmark { address },
    };
    Ok(EditResult::changed(vec![inverse]))
}

enum OverrideField {
    Signature,
    CallingConvention,
}

fn apply_override(
    tx: &Transaction<'_>,
    start: Address,
    field: OverrideField,
    value: Option<&str>,
) -> DbResult<EditResult> {
    let Some(function) = require_function(tx, start)? else {
        return Err(DbError::NotFound(format!(
            "no function at {}",
            start.to_hex()
        )));
    };
    if !function.present || function.user_removed {
        return Err(DbError::Validation(format!(
            "function at {} is not present",
            start.to_hex()
        )));
    }

    let previous = read_function_override(tx, start)?.unwrap_or_default();
    let mut updated = previous.clone();
    match field {
        OverrideField::Signature => {
            if let Some(value) = value {
                if value.trim().is_empty() {
                    return Err(DbError::Validation("signature must not be empty".into()));
                }
            }
            updated.signature = value.map(str::to_string);
        }
        OverrideField::CallingConvention => {
            if let Some(value) = value {
                if value.trim().is_empty() {
                    return Err(DbError::Validation(
                        "calling convention must not be empty".into(),
                    ));
                }
            }
            updated.calling_convention = value.map(str::to_string);
        }
    }

    if updated == previous {
        return Ok(EditResult::unchanged());
    }

    let inverse = if previous.signature.is_none() && previous.calling_convention.is_none() {
        InverseOp::DeleteFunctionOverride { address: start }
    } else {
        InverseOp::PutFunctionOverride {
            address: start,
            payload: previous,
        }
    };

    if updated.signature.is_none() && updated.calling_convention.is_none() {
        tx.execute(
            "DELETE FROM function_overrides WHERE image_id = 1 AND address = ?1",
            rusqlite::params![&start.to_blob()[..]],
        )?;
    } else {
        let json = serde_json::to_string(&updated)
            .map_err(|error| DbError::Validation(format!("override payload: {error}")))?;
        tx.execute(
            "INSERT OR REPLACE INTO function_overrides (image_id, address, payload_json)
             VALUES (1, ?1, ?2)",
            rusqlite::params![&start.to_blob()[..], json],
        )?;
    }
    Ok(EditResult::changed(vec![inverse]))
}

fn apply_put_type(
    tx: &Transaction<'_>,
    name: &str,
    kind: TypeKind,
    payload_json: &str,
) -> DbResult<EditResult> {
    let name = name.trim();
    if name.is_empty() {
        return Err(DbError::Validation("type name must not be empty".into()));
    }
    if payload_json.len() > MAX_PAYLOAD_BYTES {
        return Err(DbError::ResourceLimit("type payload is too large".into()));
    }
    let previous: Option<TypeRow> = tx
        .query_row(
            "SELECT name, kind, payload_version, payload_json, origin FROM types
             WHERE image_id = 1 AND name = ?1 AND origin = 'user'",
            rusqlite::params![name],
            |row| {
                Ok(TypeRow {
                    name: row.get(0)?,
                    kind: TypeKind::parse(&row.get::<_, String>(1)?).unwrap_or(kind),
                    payload_version: u32::try_from(row.get::<_, i64>(2)?)
                        .unwrap_or(PAYLOAD_VERSION),
                    payload_json: row.get(3)?,
                    origin: row.get(4)?,
                })
            },
        )
        .optional()?;

    let row = TypeRow {
        name: name.to_string(),
        kind,
        payload_version: PAYLOAD_VERSION,
        payload_json: payload_json.to_string(),
        origin: "user".to_string(),
    };
    if previous.as_ref() == Some(&row) {
        return Ok(EditResult::unchanged());
    }
    let inverse = match previous {
        Some(previous) => InverseOp::PutType(previous),
        None => InverseOp::DeleteType {
            name: name.to_string(),
        },
    };
    upsert_type(tx, &row)?;
    Ok(EditResult::changed(vec![inverse]))
}

fn apply_remove_type(tx: &Transaction<'_>, name: &str) -> DbResult<EditResult> {
    let previous: Option<TypeRow> = tx
        .query_row(
            "SELECT name, kind, payload_version, payload_json, origin FROM types
             WHERE image_id = 1 AND name = ?1 AND origin = 'user'",
            rusqlite::params![name],
            |row| {
                Ok(TypeRow {
                    name: row.get(0)?,
                    kind: TypeKind::parse(&row.get::<_, String>(1)?).unwrap_or(TypeKind::Struct),
                    payload_version: u32::try_from(row.get::<_, i64>(2)?)
                        .unwrap_or(PAYLOAD_VERSION),
                    payload_json: row.get(3)?,
                    origin: row.get(4)?,
                })
            },
        )
        .optional()?;
    let Some(previous) = previous else {
        return Err(DbError::NotFound(format!("no user type named '{name}'")));
    };

    let item_references: i64 = tx.query_row(
        "SELECT COUNT(*) FROM items WHERE image_id = 1 AND type_name = ?1",
        rusqlite::params![name],
        |row| row.get(0),
    )?;
    let variable_references: i64 = tx.query_row(
        "SELECT COUNT(*) FROM variable_overrides
         WHERE image_id = 1 AND json_extract(value_json, '$.type_name') = ?1",
        rusqlite::params![name],
        |row| row.get(0),
    )?;
    let field_references: i64 = tx.query_row(
        "SELECT COUNT(*) FROM types
         WHERE image_id = 1 AND payload_json LIKE ?1",
        rusqlite::params![format!("%\"{}\"%", name.replace('"', ""))],
        |row| row.get(0),
    )?;
    let total = item_references + variable_references + field_references;
    if total > 0 {
        return Err(DbError::Validation(format!(
            "type '{name}' is still referenced by {item_references} item(s), \
             {variable_references} variable override(s) and {field_references} type(s); \
             clear those references first"
        )));
    }

    tx.execute(
        "DELETE FROM types WHERE image_id = 1 AND name = ?1 AND origin = 'user'",
        rusqlite::params![name],
    )?;
    Ok(EditResult::changed(vec![InverseOp::PutType(previous)]))
}

fn apply_apply_type(
    tx: &Transaction<'_>,
    address: Address,
    type_name: Option<&str>,
    length: Option<u64>,
) -> DbResult<EditResult> {
    let previous = read_item(tx, address)?;
    let Some(previous_item) = previous.clone() else {
        let Some(length) = length else {
            return Err(DbError::Validation(format!(
                "no item at {}; supply a length to create one",
                address.to_hex()
            )));
        };
        return apply_set_item(tx, address, length, ItemKind::Data, type_name);
    };
    if let Some(length) = length {
        if length != previous_item.length {
            return Err(DbError::Validation(format!(
                "item at {} is {} bytes; apply-type cannot resize it",
                address.to_hex(),
                previous_item.length
            )));
        }
    }
    let mut row = previous_item;
    row.type_name = type_name.map(str::to_string);
    if previous.as_ref() == Some(&row) {
        return Ok(EditResult::unchanged());
    }
    tx.execute(
        "INSERT OR REPLACE INTO items (image_id, address, length, kind, origin, type_name)
         VALUES (1, ?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            &address.to_blob()[..],
            row.length as i64,
            row.kind.as_str(),
            row.origin,
            row.type_name
        ],
    )?;
    let inverse = match previous {
        Some(previous) => InverseOp::PutItem(previous),
        None => InverseOp::DeleteItem { address },
    };
    Ok(EditResult::changed(vec![inverse]))
}

fn apply_variable_override(
    tx: &Transaction<'_>,
    function: Address,
    locator: &VariableLocator,
    name: Option<&str>,
    type_name: Option<&str>,
) -> DbResult<EditResult> {
    if name.is_none() && type_name.is_none() {
        return Err(DbError::Validation(
            "a variable override needs a name, a type, or both".into(),
        ));
    }
    if let Some(name) = name {
        if name.trim().is_empty() {
            return Err(DbError::Validation(
                "variable name must not be empty".into(),
            ));
        }
    }
    if let Some(type_name) = type_name {
        if type_name.trim().is_empty() {
            return Err(DbError::Validation(
                "variable type must not be empty".into(),
            ));
        }
    }
    // Validate the locator shape before it becomes a storage key.
    let _ = locator.stack_offset()?;
    if let VariableLocator::Expression { key, .. } = locator {
        if !key.starts_with("register:") && !key.starts_with("temp:") {
            return Err(DbError::Validation(format!(
                "expression key '{key}' must start with register: or temp:"
            )));
        }
    }

    let Some(function_row) = require_function(tx, function)? else {
        return Err(DbError::NotFound(format!(
            "no function at {}",
            function.to_hex()
        )));
    };
    if !function_row.present || function_row.user_removed {
        return Err(DbError::Validation(format!(
            "function at {} is not present",
            function.to_hex()
        )));
    }

    let locator_json = locator.to_key();
    let previous: Option<String> = tx
        .query_row(
            "SELECT value_json FROM variable_overrides
             WHERE image_id = 1 AND function_address = ?1 AND locator_json = ?2",
            rusqlite::params![&function.to_blob()[..], locator_json],
            |row| row.get(0),
        )
        .optional()?;

    let value_json = serde_json::json!({ "name": name, "type_name": type_name }).to_string();
    if previous.as_deref() == Some(value_json.as_str()) {
        return Ok(EditResult::unchanged());
    }
    tx.execute(
        "INSERT OR REPLACE INTO variable_overrides
            (image_id, function_address, locator_json, value_json)
         VALUES (1, ?1, ?2, ?3)",
        rusqlite::params![&function.to_blob()[..], locator_json, value_json],
    )?;
    let inverse = match previous {
        Some(previous) => InverseOp::PutVariableOverride {
            function,
            locator_json,
            value_json: previous,
        },
        None => InverseOp::DeleteVariableOverride {
            function,
            locator_json,
        },
    };
    Ok(EditResult::changed(vec![inverse]))
}

fn apply_remove_override(
    tx: &Transaction<'_>,
    target: OverrideTarget,
    address: Address,
    locator: Option<&VariableLocator>,
) -> DbResult<EditResult> {
    match target {
        OverrideTarget::Name => apply_name(tx, address, None),
        OverrideTarget::Comment => apply_annotation(tx, address, AnnotationKind::Comment, None),
        OverrideTarget::Tag => apply_annotation(tx, address, AnnotationKind::Tag, None),
        OverrideTarget::Bookmark => {
            let previous: Option<Option<String>> = tx
                .query_row(
                    "SELECT label FROM bookmarks WHERE image_id = 1 AND address = ?1",
                    rusqlite::params![&address.to_blob()[..]],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(previous) = previous else {
                return Ok(EditResult::unchanged());
            };
            tx.execute(
                "DELETE FROM bookmarks WHERE image_id = 1 AND address = ?1",
                rusqlite::params![&address.to_blob()[..]],
            )?;
            Ok(EditResult::changed(vec![InverseOp::PutBookmark {
                address,
                label: previous,
            }]))
        }
        OverrideTarget::Signature => apply_override(tx, address, OverrideField::Signature, None),
        OverrideTarget::CallingConvention => {
            apply_override(tx, address, OverrideField::CallingConvention, None)
        }
        OverrideTarget::Type => {
            let previous = read_item(tx, address)?;
            let Some(previous) = previous else {
                return Ok(EditResult::unchanged());
            };
            if previous.type_name.is_none() {
                return Ok(EditResult::unchanged());
            }
            let mut row = previous.clone();
            row.type_name = None;
            tx.execute(
                "INSERT OR REPLACE INTO items (image_id, address, length, kind, origin, type_name)
                 VALUES (1, ?1, ?2, ?3, ?4, NULL)",
                rusqlite::params![
                    &address.to_blob()[..],
                    row.length as i64,
                    row.kind.as_str(),
                    row.origin
                ],
            )?;
            Ok(EditResult::changed(vec![InverseOp::PutItem(previous)]))
        }
        OverrideTarget::Variable => {
            let Some(locator) = locator else {
                return Err(DbError::Validation(
                    "clearing a variable override needs a locator".into(),
                ));
            };
            let locator_json = locator.to_key();
            let previous: Option<String> = tx
                .query_row(
                    "SELECT value_json FROM variable_overrides
                     WHERE image_id = 1 AND function_address = ?1 AND locator_json = ?2",
                    rusqlite::params![&address.to_blob()[..], locator_json],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(previous) = previous else {
                return Ok(EditResult::unchanged());
            };
            tx.execute(
                "DELETE FROM variable_overrides
                 WHERE image_id = 1 AND function_address = ?1 AND locator_json = ?2",
                rusqlite::params![&address.to_blob()[..], locator_json],
            )?;
            Ok(EditResult::changed(vec![InverseOp::PutVariableOverride {
                function: address,
                locator_json,
                value_json: previous,
            }]))
        }
    }
}

// ---------------------------------------------------------------------------
// Analysis scope
// ---------------------------------------------------------------------------

/// Read the stored scope payload, if the project has one.
fn read_scope_resource(tx: &Transaction<'_>) -> DbResult<Option<Vec<u8>>> {
    Ok(tx
        .query_row(
            "SELECT payload FROM resources WHERE image_id = 1 AND kind = ?1 AND logical_name = ?2",
            rusqlite::params![
                ANALYSIS_SCOPE_RESOURCE_KIND,
                ANALYSIS_SCOPE_RESOURCE_NAME
            ],
            |row| row.get(0),
        )
        .optional()?)
}

/// Decode a stored scope payload. A missing row is the empty scope.
fn decode_scope_payload(payload: Option<&[u8]>) -> DbResult<AnalysisScope> {
    match payload {
        None => Ok(AnalysisScope::empty()),
        Some(bytes) => {
            if bytes.is_empty() {
                return Ok(AnalysisScope::empty());
            }
            let scope: AnalysisScope = serde_json::from_slice(bytes).map_err(|error| {
                DbError::Corrupt(format!("stored analysis scope is unreadable: {error}"))
            })?;
            scope.validate()?;
            Ok(scope)
        }
    }
}

/// Write or delete the scope resource. `None` deletes the row, which is how a
/// project that never had a scope gets restored exactly.
fn write_scope_resource(tx: &Transaction<'_>, payload: Option<&str>) -> DbResult<()> {
    match payload {
        Some(text) => {
            // Re-validate on the way back in: an inverse payload is data from
            // the log, not trusted code.
            let scope: AnalysisScope = serde_json::from_str(text).map_err(|error| {
                DbError::Corrupt(format!("stored analysis scope is unreadable: {error}"))
            })?;
            scope.validate()?;
            tx.execute(
                "INSERT OR REPLACE INTO resources
                    (image_id, kind, logical_name, content_sha256, payload)
                 VALUES (1, ?1, ?2, ?3, ?4)",
                rusqlite::params![
                    ANALYSIS_SCOPE_RESOURCE_KIND,
                    ANALYSIS_SCOPE_RESOURCE_NAME,
                    &crate::sha256(text.as_bytes())[..],
                    text.as_bytes()
                ],
            )?;
        }
        None => {
            tx.execute(
                "DELETE FROM resources WHERE image_id = 1 AND kind = ?1 AND logical_name = ?2",
                rusqlite::params![
                    ANALYSIS_SCOPE_RESOURCE_KIND,
                    ANALYSIS_SCOPE_RESOURCE_NAME
                ],
            )?;
        }
    }
    Ok(())
}

/// Replace the analysis-scope policy. Canonically equal payloads are a no-op,
/// so re-declaring the same exclusions never burns a revision or an undo step.
fn apply_analysis_scope(tx: &Transaction<'_>, scope: &AnalysisScope) -> DbResult<EditResult> {
    scope.validate()?;
    let previous = read_scope_resource(tx)?;
    let current = decode_scope_payload(previous.as_deref())?;
    if current.canonical_bytes() == scope.canonical_bytes() {
        return Ok(EditResult::unchanged());
    }
    let payload = serde_json::to_string(scope)
        .map_err(|error| DbError::Validation(format!("analysis scope payload: {error}")))?;
    write_scope_resource(tx, Some(&payload))?;
    Ok(EditResult::changed(vec![
        InverseOp::RestoreAnalysisScope {
            previous_payload: previous
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
        },
    ]))
}

// ---------------------------------------------------------------------------
// Invalidation
// ---------------------------------------------------------------------------

/// Mark exactly the units whose inputs an edit changed.
///
/// Rules, one per edit family:
/// - annotations/bookmarks: display overlay only, plus the containing
///   function's rendered text (comments appear inside it).
/// - name: the named function's CFG and render, plus every caller's render
///   and signature-dependent structure.
/// - signature/calling convention/variables: that function and its callers.
/// - bytes/items/bounds/exclusions: intersecting functions, image discovery,
///   and any unit whose recorded dependency touches the range.
/// - data patches: strings in the range are dropped, and units with
///   incomplete dependency records fall back to whole-image staleness rather
///   than claiming precision they do not have.
pub fn invalidate(tx: &Transaction<'_>, edit: &Edit, revision: Revision) -> DbResult<()> {
    let mut cfg_targets: BTreeSet<u64> = BTreeSet::new();
    let mut render_targets: BTreeSet<u64> = BTreeSet::new();
    let mut index_stale = false;
    let mut ranges: Vec<AddressRange> = Vec::new();
    let mut signature_targets: BTreeSet<u64> = BTreeSet::new();
    let mut name_targets: BTreeSet<u64> = BTreeSet::new();
    let mut type_names: BTreeSet<String> = BTreeSet::new();
    let mut data_ranges: Vec<AddressRange> = Vec::new();

    match edit {
        Edit::SetComment { address, .. }
        | Edit::SetTag { address, .. }
        | Edit::SetBookmark { address, .. } => {
            if let Some(function) = containing_function(tx, *address)? {
                render_targets.insert(function);
            }
        }
        Edit::RemoveOverride {
            target: OverrideTarget::Name,
            address,
            ..
        } => {
            name_targets.insert(address.0);
            if let Some(function) = function_at(tx, *address)? {
                render_targets.insert(function);
            }
            for caller in callers_of(tx, *address)? {
                render_targets.insert(caller);
            }
        }
        Edit::RemoveOverride {
            target: OverrideTarget::Comment | OverrideTarget::Tag | OverrideTarget::Bookmark,
            address,
            ..
        } => {
            if let Some(function) = containing_function(tx, *address)? {
                render_targets.insert(function);
            }
        }
        Edit::SetName { address, .. } => {
            // A rename changes no instruction: the named function's own CFG
            // stays current, and only the rendered text that prints the name
            // (its own and its callers') has to be rebuilt.
            name_targets.insert(address.0);
            if let Some(function) = function_at(tx, *address)? {
                render_targets.insert(function);
            }
            for caller in callers_of(tx, *address)? {
                render_targets.insert(caller);
            }
        }
        Edit::SetFunctionSignature { start, .. }
        | Edit::SetCallingConvention { start, .. }
        | Edit::SetVariableOverride {
            function: start, ..
        } => {
            signature_targets.insert(start.0);
            cfg_targets.insert(start.0);
            render_targets.insert(start.0);
            for caller in callers_of(tx, *start)? {
                cfg_targets.insert(caller);
                render_targets.insert(caller);
            }
        }
        Edit::RemoveOverride {
            target: OverrideTarget::Signature | OverrideTarget::CallingConvention,
            address,
            ..
        } => {
            signature_targets.insert(address.0);
            cfg_targets.insert(address.0);
            render_targets.insert(address.0);
            for caller in callers_of(tx, *address)? {
                cfg_targets.insert(caller);
                render_targets.insert(caller);
            }
        }
        Edit::RemoveOverride {
            target: OverrideTarget::Variable,
            address,
            ..
        } => {
            signature_targets.insert(address.0);
            cfg_targets.insert(address.0);
            render_targets.insert(address.0);
        }
        Edit::PatchBytes { file_offset, bytes } => {
            index_stale = true;
            let file_range = crate::address::FileRange::new(
                *file_offset,
                u64::try_from(bytes.len())
                    .map_err(|_| DbError::ResourceLimit("patch too large".into()))?,
            )?;
            let mapped = translate_file_range(tx, file_range)?;
            ranges.extend(mapped.iter().copied());
            data_ranges.extend(mapped);
        }
        Edit::SetItem {
            address,
            length,
            kind,
            ..
        } => {
            index_stale = true;
            let range = AddressRange::new(*address, *length)?;
            ranges.push(range);
            if *kind == ItemKind::Data {
                data_ranges.push(range);
            }
        }
        Edit::ClearItem { address, length } => {
            index_stale = true;
            ranges.push(AddressRange::new(*address, *length)?);
        }
        Edit::ApplyType { address, .. }
        | Edit::RemoveOverride {
            target: OverrideTarget::Type,
            address,
            ..
        } => {
            let _ = address;
            for function in intersecting_functions(tx, AddressRange::new(*address, 1)?)? {
                render_targets.insert(function);
                cfg_targets.insert(function);
            }
        }
        Edit::CreateFunction { start, end } | Edit::SetFunctionBounds { start, end } => {
            index_stale = true;
            let range = AddressRange::new(*start, end.0.saturating_sub(start.0))?;
            ranges.push(range);
            cfg_targets.insert(start.0);
            render_targets.insert(start.0);
        }
        Edit::RemoveFunction { start } => {
            index_stale = true;
            cfg_targets.remove(&start.0);
            render_targets.remove(&start.0);
        }
        Edit::SetFunctionExcluded { start, .. } => {
            index_stale = true;
            cfg_targets.insert(start.0);
            render_targets.insert(start.0);
        }
        Edit::PutType { name, .. } => {
            type_names.insert(name.clone());
        }
        Edit::RemoveType { name } => {
            type_names.insert(name.clone());
        }
        Edit::SetAnalysisScope { .. } => {
            // A scope change redefines which ranges the automatic chain may
            // decode. Cross-range dependencies (a caller in `.text` seeding a
            // callee in `.packed`) are not modelled precisely enough to spare
            // anything, so the conservative answer is: every automatic artifact
            // is stale. User overrides, bytes and earlier rendered text are
            // kept — they are still the last thing the engine saw.
            tx.execute(
                "UPDATE analysis_units SET state = 'stale'
                 WHERE image_id = 1 AND state <> 'pending'",
                [],
            )?;
            return Ok(());
        }
    }

    for range in &ranges {
        for function in intersecting_functions(tx, *range)? {
            cfg_targets.insert(function);
            render_targets.insert(function);
        }
    }

    if index_stale {
        mark_units_stale(tx, OwnerKind::ImageIndex, None)?;
    }
    for function in &cfg_targets {
        mark_units_stale(tx, OwnerKind::FunctionCfg, Some(Address(*function)))?;
    }
    for function in &render_targets {
        mark_units_stale(tx, OwnerKind::FunctionRender, Some(Address(*function)))?;
    }

    invalidate_by_dependencies(
        tx,
        &ranges,
        &data_ranges,
        &signature_targets,
        &name_targets,
        &type_names,
    )?;

    // Patching data changes the strings embedded in it; drop the affected
    // rows so the next index pass re-detects them from the current bytes.
    for range in &data_ranges {
        drop_strings_in_range(tx, *range)?;
    }

    // Every invalidation is anchored to a revision so a stale-analysis
    // observer can tell how far behind it is.
    tx.execute(
        "INSERT INTO history_events (action, edit_id, revision, actor, timestamp)
         SELECT 'invalidate', NULL, ?1, 'system', ?2 WHERE 0",
        rusqlite::params![revision.0 as i64, chrono::Utc::now().to_rfc3339()],
    )
    .ok();

    Ok(())
}

fn invalidate_by_dependencies(
    tx: &Transaction<'_>,
    ranges: &[AddressRange],
    data_ranges: &[AddressRange],
    signature_targets: &BTreeSet<u64>,
    name_targets: &BTreeSet<u64>,
    type_names: &BTreeSet<String>,
) -> DbResult<()> {
    let mut statement = tx.prepare(
        "SELECT u.owner_kind, u.owner_key, u.config_fingerprint, d.dependency_kind,
                d.dependency_key, d.range_start, d.range_length
         FROM analysis_dependencies d
         JOIN analysis_units u
           ON u.image_id = d.image_id AND u.owner_kind = d.owner_kind
          AND u.owner_key = d.owner_key AND u.config_fingerprint = d.config_fingerprint
         WHERE d.image_id = 1",
    )?;
    let mut rows = statement.query([])?;
    let mut stale: BTreeSet<(OwnerKind, u64, [u8; 32])> = BTreeSet::new();
    while let Some(row) = rows.next()? {
        let owner_kind =
            OwnerKind::parse(&row.get::<_, String>(0)?).unwrap_or(OwnerKind::FunctionRender);
        let owner_key = Address::from_blob(&row.get::<_, Vec<u8>>(1)?).unwrap_or(Address(0));
        let config_bytes: Vec<u8> = row.get(2)?;
        let mut config = [0u8; 32];
        if config_bytes.len() == 32 {
            config.copy_from_slice(&config_bytes);
        }
        let dependency_kind =
            DependencyKind::parse(&row.get::<_, String>(3)?).unwrap_or(DependencyKind::Range);
        let dependency_key: String = row.get(4)?;
        let range_start = Address::from_blob(&row.get::<_, Vec<u8>>(5)?).unwrap_or(Address(0));
        let range_length = u64::try_from(row.get::<_, i64>(6)?).unwrap_or(0);

        let key = (owner_kind, owner_key.0, config);
        let dependency_range = if range_length > 0 {
            AddressRange::new(range_start, range_length).ok()
        } else {
            None
        };

        let hit = match dependency_kind {
            DependencyKind::Range => match dependency_range {
                Some(dependency_range) => ranges
                    .iter()
                    .any(|range| range.overlaps(dependency_range).unwrap_or(false)),
                None => false,
            },
            DependencyKind::Stage => !data_ranges.is_empty(),
            DependencyKind::Signature => dependency_key
                .strip_prefix("function:")
                .and_then(|raw| u64::from_str_radix(raw, 16).ok())
                .is_some_and(|address| signature_targets.contains(&address)),
            DependencyKind::Name => dependency_key
                .strip_prefix("address:")
                .and_then(|raw| u64::from_str_radix(raw, 16).ok())
                .is_some_and(|address| name_targets.contains(&address)),
            DependencyKind::Type => type_names.contains(&dependency_key),
        };
        if hit {
            stale.insert(key);
        }
    }
    drop(rows);
    drop(statement);

    // A unit that could not record exact ranges is conservatively stale for
    // any data edit; claiming otherwise would silently reuse wrong results.
    // This scans the unit table itself because such a unit may have no
    // dependency rows at all (it could not record any).
    if !data_ranges.is_empty() {
        let mut statement = tx.prepare(
            "SELECT owner_kind, owner_key, config_fingerprint FROM analysis_units
             WHERE image_id = 1 AND dependencies_complete = 0",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let owner_kind =
                OwnerKind::parse(&row.get::<_, String>(0)?).unwrap_or(OwnerKind::FunctionRender);
            let owner_key = Address::from_blob(&row.get::<_, Vec<u8>>(1)?).unwrap_or(Address(0));
            let config_bytes: Vec<u8> = row.get(2)?;
            let mut config = [0u8; 32];
            if config_bytes.len() == 32 {
                config.copy_from_slice(&config_bytes);
            }
            stale.insert((owner_kind, owner_key.0, config));
        }
    }

    for (owner_kind, owner_key, config) in stale {
        tx.execute(
            "UPDATE analysis_units SET state = 'stale'
             WHERE image_id = 1 AND owner_kind = ?1 AND owner_key = ?2 AND config_fingerprint = ?3
               AND state <> 'pending'",
            rusqlite::params![
                owner_kind.as_str(),
                &Address(owner_key).to_blob()[..],
                &config[..]
            ],
        )?;
    }
    Ok(())
}

fn mark_units_stale(
    tx: &Transaction<'_>,
    owner_kind: OwnerKind,
    key: Option<Address>,
) -> DbResult<()> {
    match key {
        Some(key) => tx.execute(
            "UPDATE analysis_units SET state = 'stale'
             WHERE image_id = 1 AND owner_kind = ?1 AND owner_key = ?2 AND state <> 'pending'",
            rusqlite::params![owner_kind.as_str(), &key.to_blob()[..]],
        )?,
        None => tx.execute(
            "UPDATE analysis_units SET state = 'stale'
             WHERE image_id = 1 AND owner_kind = ?1 AND state <> 'pending'",
            rusqlite::params![owner_kind.as_str()],
        )?,
    };
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_all_patches(tx: &Transaction<'_>) -> DbResult<Vec<PatchRow>> {
    let mut statement =
        tx.prepare("SELECT file_offset, bytes FROM patches ORDER BY file_offset")?;
    let mut rows = statement.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(PatchRow {
            offset: FileOffset::from_blob(&row.get::<_, Vec<u8>>(0)?)?,
            bytes: row.get(1)?,
        });
    }
    Ok(out)
}

fn delete_patches_in_range(
    tx: &Transaction<'_>,
    start: FileOffset,
    end: FileOffset,
) -> DbResult<()> {
    let existing = read_all_patches(tx)?;
    let mut statement = tx.prepare("DELETE FROM patches WHERE file_offset = ?1")?;
    for row in existing {
        let row_end = row.offset.0.saturating_add(row.bytes.len() as u64);
        if row.offset.0 < end.0 && start.0 < row_end {
            statement.execute(rusqlite::params![&row.offset.to_blob()[..]])?;
        }
    }
    Ok(())
}

fn read_items(tx: &Transaction<'_>) -> DbResult<Vec<ItemRow>> {
    let mut statement = tx.prepare(
        "SELECT address, length, kind, origin, type_name FROM items WHERE image_id = 1 ORDER BY address",
    )?;
    let mut rows = statement.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(ItemRow {
            address: Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?,
            length: u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0),
            kind: ItemKind::parse(&row.get::<_, String>(2)?).unwrap_or(ItemKind::Data),
            origin: row.get(3)?,
            type_name: row.get(4)?,
        });
    }
    Ok(out)
}

fn read_item(tx: &Transaction<'_>, address: Address) -> DbResult<Option<ItemRow>> {
    Ok(read_items(tx)?
        .into_iter()
        .find(|item| item.address == address))
}

fn read_function(tx: &Transaction<'_>, address: Address) -> DbResult<Option<FunctionRow>> {
    Ok(read_functions(tx)?
        .into_iter()
        .find(|function| function.address == address))
}

fn read_functions(tx: &Transaction<'_>) -> DbResult<Vec<FunctionRow>> {
    let mut statement = tx.prepare(
        "SELECT address, declared_end, bounds_origin, origin, excluded, user_removed, present
         FROM functions WHERE image_id = 1 ORDER BY address",
    )?;
    let mut rows = statement.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let declared_end: Option<Vec<u8>> = row.get(1)?;
        out.push(FunctionRow {
            address: Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?,
            declared_end: declared_end
                .as_deref()
                .map(Address::from_blob)
                .transpose()?,
            bounds_origin: BoundsOrigin::parse(&row.get::<_, String>(2)?)
                .unwrap_or(BoundsOrigin::Heuristic),
            origin: FunctionOrigin::parse(&row.get::<_, String>(3)?)
                .unwrap_or(FunctionOrigin::Auto),
            excluded: row.get::<_, i64>(4)? != 0,
            user_removed: row.get::<_, i64>(5)? != 0,
            present: row.get::<_, i64>(6)? != 0,
        });
    }
    Ok(out)
}

fn write_function(tx: &Transaction<'_>, row: &FunctionRow) -> DbResult<()> {
    tx.execute(
        "INSERT OR REPLACE INTO functions
            (image_id, address, declared_end, bounds_origin, origin, excluded, user_removed, present)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            &row.address.to_blob()[..],
            row.declared_end.map(|address| address.to_blob().to_vec()),
            row.bounds_origin.as_str(),
            row.origin.as_str(),
            row.excluded as i64,
            row.user_removed as i64,
            row.present as i64
        ],
    )?;
    Ok(())
}

fn upsert_type(tx: &Transaction<'_>, row: &TypeRow) -> DbResult<()> {
    tx.execute(
        "INSERT OR REPLACE INTO types (image_id, name, kind, payload_version, payload_json, origin)
         VALUES (1, ?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            row.name,
            row.kind.as_str(),
            row.payload_version as i64,
            row.payload_json,
            row.origin
        ],
    )?;
    Ok(())
}

fn read_function_override(
    tx: &Transaction<'_>,
    address: Address,
) -> DbResult<Option<FunctionOverrideRow>> {
    let json: Option<String> = tx
        .query_row(
            "SELECT payload_json FROM function_overrides WHERE image_id = 1 AND address = ?1",
            rusqlite::params![&address.to_blob()[..]],
            |row| row.get(0),
        )
        .optional()?;
    Ok(json.and_then(|json| serde_json::from_str(&json).ok()))
}

/// A function row that exists (live or suppressed), for mutation checks.
fn require_function(tx: &Transaction<'_>, address: Address) -> DbResult<Option<FunctionRow>> {
    read_function(tx, address)
}

fn function_at(tx: &Transaction<'_>, address: Address) -> DbResult<Option<u64>> {
    Ok(read_functions(tx)?
        .into_iter()
        .find(|function| function.address == address && function.is_live())
        .map(|function| function.address.0))
}

fn containing_function(tx: &Transaction<'_>, address: Address) -> DbResult<Option<u64>> {
    let functions = read_functions(tx)?;
    Ok(functions
        .into_iter()
        .filter(|function| function.is_live() && !function.excluded)
        .find(|function| match function.declared_end {
            Some(end) => address.0 >= function.address.0 && address.0 < end.0,
            None => false,
        })
        .map(|function| function.address.0))
}

fn intersecting_functions(tx: &Transaction<'_>, range: AddressRange) -> DbResult<Vec<u64>> {
    let mut out = Vec::new();
    for function in read_functions(tx)? {
        if !function.is_live() {
            continue;
        }
        if let Some(end) = function.declared_end {
            if let Ok(function_range) =
                AddressRange::new(function.address, end.0.saturating_sub(function.address.0))
            {
                if function_range.overlaps(range)? {
                    out.push(function.address.0);
                }
            }
        }
    }
    // Functions without declared bounds are located through their decoded
    // instructions instead — but only instructions that actually intersect
    // the range. Returning every function that has any instruction would
    // invalidate the whole image on every patch.
    let range_end = range.end()?;
    let mut statement = tx.prepare(
        "SELECT fi.function_address, i.address, i.size FROM function_instructions fi
         JOIN instructions i ON i.image_id = fi.image_id AND i.address = fi.instruction_address
         WHERE fi.image_id = 1",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let function = Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?;
        let instruction = Address::from_blob(&row.get::<_, Vec<u8>>(1)?)?;
        let size = u64::try_from(row.get::<_, i64>(2)?).unwrap_or(0);
        let Some(instruction_end) = instruction.0.checked_add(size) else {
            continue;
        };
        if instruction.0 < range_end && range.start.0 < instruction_end {
            out.push(function.0);
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

fn callers_of(tx: &Transaction<'_>, target: Address) -> DbResult<Vec<u64>> {
    let mut statement = tx.prepare(
        "SELECT DISTINCT owner_function FROM xrefs
         WHERE image_id = 1 AND to_address = ?1 AND kind = 'call' AND owner_function IS NOT NULL",
    )?;
    let mut rows = statement.query(rusqlite::params![&target.to_blob()[..]])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?.0);
    }
    out.sort_unstable();
    Ok(out)
}

fn declared_function_ranges(tx: &Transaction<'_>) -> DbResult<Vec<(Address, Address)>> {
    let mut out = Vec::new();
    for function in read_functions(tx)? {
        if !function.is_live() {
            continue;
        }
        if let Some(end) = function.declared_end {
            out.push((function.address, end));
        }
    }
    Ok(out)
}

/// Every decoded instruction inside `range` must be fully inside it: a user
/// range may not cut through an instruction.
fn require_instruction_alignment(tx: &Transaction<'_>, range: AddressRange) -> DbResult<()> {
    let range_end = range.end()?;
    let mut statement = tx.prepare("SELECT address, size FROM instructions WHERE image_id = 1")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let address = Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?;
        let size = u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0);
        let Some(instruction_end) = address.0.checked_add(size) else {
            continue;
        };
        let intersects = address.0 < range_end && range.start.0 < instruction_end;
        if !intersects {
            continue;
        }
        if address.0 < range.start.0 || instruction_end > range_end {
            return Err(DbError::Validation(format!(
                "range {}..{} cuts through the instruction at {}",
                range.start.to_hex(),
                Address(range_end).to_hex(),
                address.to_hex()
            )));
        }
    }
    Ok(())
}

fn require_mapped(tx: &Transaction<'_>, address: Address) -> DbResult<()> {
    let mut statement =
        tx.prepare("SELECT va, memory_size FROM mappings WHERE image_id = 1 ORDER BY va")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let va = Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?;
        let size = u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0);
        if address.0 >= va.0 && address.0 < va.0.saturating_add(size) {
            return Ok(());
        }
    }
    Err(DbError::Validation(format!(
        "{} is not inside any mapping of the analyzed image",
        address.to_hex()
    )))
}

/// Translate a file range into address ranges through the loaded mappings.
fn translate_file_range(
    tx: &Transaction<'_>,
    file_range: crate::address::FileRange,
) -> DbResult<Vec<AddressRange>> {
    let mut statement = tx.prepare(
        "SELECT va, memory_size, file_offset, file_size FROM mappings
         WHERE image_id = 1 AND file_offset IS NOT NULL ORDER BY va",
    )?;
    let mut rows = statement.query([])?;
    let mut out = Vec::new();
    let patch_end = file_range.end()?;
    while let Some(row) = rows.next()? {
        let va = Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?;
        let _memory_size = u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0);
        let file_offset = FileOffset::from_blob(&row.get::<_, Vec<u8>>(2)?)?;
        let file_size = u64::try_from(row.get::<_, i64>(3)?).unwrap_or(0);
        let mapping_end = file_offset.0.saturating_add(file_size);
        let start = file_range.start.0.max(file_offset.0);
        let end = patch_end.min(mapping_end);
        if start >= end {
            continue;
        }
        let va_start =
            va.0.checked_add(start - file_offset.0)
                .ok_or(DbError::Range(crate::address::RangeError::Overflow {
                    start: va.0,
                    len: start - file_offset.0,
                }))?;
        out.push(AddressRange::new(Address(va_start), end - start)?);
    }
    if out.is_empty() {
        return Err(DbError::Validation(format!(
            "patch at {} does not overlap any file-backed mapping",
            file_range.start.to_hex()
        )));
    }
    Ok(out)
}

fn drop_strings_in_range(tx: &Transaction<'_>, range: AddressRange) -> DbResult<()> {
    let mut statement =
        tx.prepare("SELECT address, byte_length FROM strings WHERE image_id = 1 ORDER BY address")?;
    let mut rows = statement.query([])?;
    let mut doomed = Vec::new();
    let range_end = range.end()?;
    while let Some(row) = rows.next()? {
        let address = Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?;
        let length = u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0);
        let string_end = address.0.saturating_add(length);
        if address.0 < range_end && range.start.0 < string_end {
            doomed.push(address);
        }
    }
    drop(rows);
    drop(statement);
    for address in doomed {
        tx.execute(
            "DELETE FROM strings WHERE image_id = 1 AND address = ?1",
            rusqlite::params![&address.to_blob()[..]],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_targets_round_trip() {
        for name in [
            "name",
            "comment",
            "tag",
            "bookmark",
            "signature",
            "calling-convention",
            "type",
            "variable",
        ] {
            assert!(OverrideTarget::parse(name).is_some(), "{name}");
        }
        assert!(OverrideTarget::parse("everything").is_none());
    }

    #[test]
    fn edit_kinds_are_stable() {
        assert_eq!(
            Edit::SetName {
                address: Address(1),
                name: None
            }
            .kind(),
            "name"
        );
        assert_eq!(
            Edit::RemoveOverride {
                target: OverrideTarget::Bookmark,
                address: Address(1),
                locator: None
            }
            .kind(),
            "clear-bookmark"
        );
    }
}
