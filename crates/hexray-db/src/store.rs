//! The `.hxdb` store: creation, opening, snapshots, and transactions.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{
    Connection, DatabaseName, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};

use crate::address::{Address, AddressRange, FileOffset};
use crate::edit::{self, Edit, InverseOp};
use crate::model::*;
use crate::schema;
use crate::{sha256, DbError, DbResult};

/// Source chunk size. The input is never held as one SQLite BLOB.
pub const SOURCE_CHUNK_SIZE: usize = 1024 * 1024;
/// Default cap on the complete original input.
pub const MAX_SOURCE_BYTES_DEFAULT: u64 = 8 * 1024 * 1024 * 1024;
/// Default cap on the analyzed image.
pub const MAX_ANALYSIS_BYTES_DEFAULT: u64 = 256 * 1024 * 1024;
/// Cap on a single stored payload (JSON or text).
pub const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
/// Cap on a single byte patch.
pub const MAX_PATCH_BYTES: usize = 1024 * 1024;
/// Cap on cumulative edit history.
pub const MAX_HISTORY_ENTRIES: u64 = 100_000;
/// Lock wait before reporting `DbError::Busy`.
pub const BUSY_TIMEOUT: Duration = Duration::from_millis(5000);
/// Maximum number of bound values in one batch-read `IN` query.
const MAX_ADDRESS_CHUNK: usize = 128;
/// Identity of one stored xref row, used to deduplicate chunked lookups.
type XrefKey = ([u8; 8], [u8; 8], String, Option<[u8; 8]>, String);

/// How the file is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    ReadOnly,
    ReadWrite,
}

impl OpenMode {
    pub fn is_writable(self) -> bool {
        matches!(self, OpenMode::ReadWrite)
    }
}

/// An open analysis project.
#[derive(Debug)]
pub struct Database {
    conn: Connection,
    path: PathBuf,
    mode: OpenMode,
}

/// A project being built in a private staging directory.
///
/// Creation, legacy import and the first analysis pass all run before
/// publication, so a failure at any step leaves no project file behind and an
/// existing project is never overwritten. Publication uses a no-clobber link.
pub struct StagedProject {
    _dir: tempfile::TempDir,
    path: PathBuf,
    database: Option<Database>,
}

impl StagedProject {
    /// Stage a new project inside `directory` (same filesystem as the final
    /// destination, which keeps publication atomic).
    pub fn create(directory: &Path, input: &CreateInput) -> DbResult<StagedProject> {
        validate_create_input(input)?;
        let dir = tempfile_dir(directory)?;
        let path = dir.path().join("project.hxdb");
        let database = Database::create_at(&path, input)?;
        Ok(StagedProject {
            _dir: dir,
            path,
            database: Some(database),
        })
    }

    pub fn database(&mut self) -> &mut Database {
        self.database
            .as_mut()
            .expect("staged project is consumed on publish")
    }

    /// Publish the staged file at `destination`, then reopen it.
    pub fn publish(mut self, destination: &Path) -> DbResult<Database> {
        drop(self.database.take());
        publish_no_clobber(&self.path, destination)?;
        Database::open(destination, OpenMode::ReadWrite)
    }
}

impl Database {
    /// Create a database at `path` holding the complete original input.
    pub fn create(path: &Path, input: &CreateInput) -> DbResult<Database> {
        if path.exists() {
            return Err(DbError::Validation(format!(
                "destination already exists: {}",
                path.display()
            )));
        }
        let parent = parent_directory(path);
        let staged = StagedProject::create(&parent, input)?;
        staged.publish(path)
    }

    fn create_at(path: &Path, input: &CreateInput) -> DbResult<Database> {
        let conn = Connection::open(path)?;
        configure_writable(&conn)?;
        schema::apply_identity(&conn)?;

        {
            let tx = conn.unchecked_transaction()?;
            schema::create_objects(&conn)?;
            write_initial_content(&conn, input)?;
            tx.commit()?;
        }

        let created = Database {
            conn,
            path: path.to_path_buf(),
            mode: OpenMode::ReadWrite,
        };
        created.preseed_pending_units()?;
        Ok(created)
    }

    /// Open an existing database. Never creates a file.
    pub fn open(path: &Path, mode: OpenMode) -> DbResult<Database> {
        if !path.exists() {
            return Err(DbError::NotFound(format!(
                "database file not found: {}",
                path.display()
            )));
        }
        if !path.is_file() {
            return Err(DbError::Validation(format!(
                "not a regular file: {}",
                path.display()
            )));
        }

        let flags = match mode {
            OpenMode::ReadOnly => OpenFlags::SQLITE_OPEN_READ_ONLY,
            OpenMode::ReadWrite => OpenFlags::SQLITE_OPEN_READ_WRITE,
        };
        let conn = Connection::open_with_flags(path, flags)?;

        // Connection-scoped, safe on a read-only handle.
        conn.busy_timeout(BUSY_TIMEOUT)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "trusted_schema", "OFF")?;
        if mode.is_writable() {
            configure_writable(&conn)?;
        }

        if let Err(error) = schema::validate(&conn) {
            return Err(match error {
                DbError::Sqlite(rusqlite::Error::SqliteFailure(code, _))
                    if code.code == rusqlite::ErrorCode::NotADatabase =>
                {
                    DbError::NotADatabase
                }
                other => other,
            });
        }

        Ok(Database {
            conn,
            path: path.to_path_buf(),
            mode,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn mode(&self) -> OpenMode {
        self.mode
    }

    fn ensure_writable(&self) -> DbResult<()> {
        if self.mode.is_writable() {
            Ok(())
        } else {
            Err(DbError::Unsupported(
                "database is open read-only; reopen it writable to modify it".into(),
            ))
        }
    }

    /// Current user-content revision.
    pub fn revision(&self) -> DbResult<Revision> {
        read_revision(&self.conn)
    }

    pub fn engine_fingerprint(&self) -> DbResult<[u8; 32]> {
        read_engine_fingerprint(&self.conn)
    }

    /// Open a consistent read snapshot (one read transaction).
    pub fn snapshot(&mut self) -> DbResult<ReadSnapshot<'_>> {
        self.conn.execute_batch("BEGIN DEFERRED")?;
        match ReadSnapshot::new(&self.conn) {
            Ok(snapshot) => Ok(snapshot),
            Err(error) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    /// Apply one user edit under a compare-and-swap on `expected`.
    pub fn apply(&mut self, expected: Revision, edit: &Edit) -> DbResult<EditOutcome> {
        self.ensure_writable()?;
        let mut tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let outcome = apply_in_transaction(&mut tx, expected, edit, "cli")?;
        tx.commit()?;
        Ok(outcome)
    }

    /// Undo the current history head.
    pub fn undo(&mut self, expected: Revision) -> DbResult<EditOutcome> {
        self.ensure_writable()?;
        let mut tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let outcome = undo_in_transaction(&mut tx, expected, "cli")?;
        tx.commit()?;
        Ok(outcome)
    }

    /// Redo the next history entry.
    pub fn redo(&mut self, expected: Revision) -> DbResult<EditOutcome> {
        self.ensure_writable()?;
        let mut tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let outcome = redo_in_transaction(&mut tx, expected, "cli")?;
        tx.commit()?;
        Ok(outcome)
    }

    /// Publish analysis units computed from the snapshot at `base`.
    ///
    /// Content revision must still be `base`, and every unit's observed
    /// generation must still match. The content revision does not advance:
    /// publishing results is not a user change.
    pub fn publish(&mut self, base: Revision, batch: &AnalysisBatch) -> DbResult<()> {
        self.ensure_writable()?;
        if batch.is_empty() {
            return Ok(());
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = read_revision(&tx)?;
        if current != base {
            return Err(DbError::RevisionConflict {
                expected: base.0,
                actual: current.0,
            });
        }
        let mut orphan_candidates: BTreeSet<Address> = BTreeSet::new();
        for unit in &batch.units {
            publish_unit(&tx, unit, &mut orphan_candidates)?;
        }
        // Two owners may share a tail instruction, so the sweep stays global
        // and inside the same transaction: a row is judged an orphan against
        // the batch's final state. It only runs when a republished function
        // dropped ownership of some address; a batch that keeps every row
        // unchanged (or touches no instruction rows at all) skips it.
        if !orphan_candidates.is_empty() {
            sweep_orphan_instructions(&tx)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Copy the database to `destination` using the SQLite backup API.
    pub fn backup(&self, destination: &Path) -> DbResult<()> {
        if destination.exists() {
            return Err(DbError::Validation(format!(
                "destination already exists: {}",
                destination.display()
            )));
        }
        let parent = parent_directory(destination);
        let staging = tempfile_dir(&parent)?;
        let staged_path = staging.path().join("backup.hxdb");
        self.conn
            .backup(DatabaseName::Main, &staged_path, None)
            .map_err(DbError::from_sqlite)?;
        publish_no_clobber(&staged_path, destination)
    }

    /// Append one entry to the command log. Never touches the content
    /// revision and never enters the undo stack.
    pub fn record_command(
        &self,
        actor: &str,
        command: &str,
        output: &str,
        success: bool,
    ) -> DbResult<()> {
        self.ensure_writable()?;
        let truncated = output.len() > MAX_PAYLOAD_BYTES;
        let stored = if truncated {
            // Truncate on a character boundary.
            let mut end = MAX_PAYLOAD_BYTES;
            while end > 0 && !output.is_char_boundary(end) {
                end -= 1;
            }
            &output[..end]
        } else {
            output
        };
        self.conn.execute(
            "INSERT INTO command_history (actor, command, output, success, timestamp, truncated)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                actor,
                command,
                stored,
                success as i64,
                now(),
                truncated as i64
            ],
        )?;
        Ok(())
    }

    /// Store a binary resource (split-DWARF sidecar, type snapshot).
    ///
    /// Resources are immutable inputs captured at creation, so a later tool
    /// upgrade or a missing file on disk cannot change what the project means.
    pub fn put_resource(&self, kind: &str, logical_name: &str, payload: &[u8]) -> DbResult<()> {
        self.ensure_writable()?;
        self.conn.execute(
            "INSERT OR REPLACE INTO resources (image_id, kind, logical_name, content_sha256, payload)
             VALUES (1, ?1, ?2, ?3, ?4)",
            rusqlite::params![kind, logical_name, &sha256(payload)[..], payload],
        )?;
        Ok(())
    }

    /// Import legacy user state plus its audit trail in one transaction.
    ///
    /// Legacy undo history is stored as records only: the new project starts
    /// with an empty undo stack rather than a fabricated one.
    pub fn import_legacy(
        &mut self,
        source: &crate::legacy::LegacySource,
    ) -> DbResult<crate::legacy::LegacySummary> {
        self.ensure_writable()?;
        let tx = self.conn.unchecked_transaction()?;
        let summary = crate::legacy::write_records(&tx, source)?;
        tx.commit()?;
        Ok(summary)
    }

    /// Run integrity checks. `deep` additionally re-hashes the embedded
    /// source and validates patch ranges.
    pub fn check(&self, deep: bool) -> DbResult<CheckReport> {
        let quick = {
            let mut statement = self.conn.prepare("PRAGMA quick_check")?;
            let mut rows = statement.query([])?;
            let mut messages = Vec::new();
            while let Some(row) = rows.next()? {
                messages.push(row.get::<_, String>(0)?);
            }
            messages.join("; ")
        };

        let mut foreign_key_violations = Vec::new();
        {
            let mut statement = self.conn.prepare("PRAGMA foreign_key_check")?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                let table: String = row.get(0)?;
                let rowid: Option<i64> = row.get(1).ok();
                let parent: String = row.get(2)?;
                foreign_key_violations.push(format!("{table} row {rowid:?} -> {parent}"));
            }
        }

        let mut problems = Vec::new();
        let source_digest_matches = if deep {
            verify_source_digest(&self.conn, &mut problems)?
        } else {
            true
        };
        let patch_ranges_valid = if deep {
            verify_patch_ranges(&self.conn, &mut problems)?
        } else {
            true
        };

        Ok(CheckReport {
            quick_check: quick,
            foreign_key_violations,
            source_digest_matches,
            patch_ranges_valid,
            problems,
        })
    }

    fn preseed_pending_units(&self) -> DbResult<()> {
        let engine = read_engine_fingerprint(&self.conn)?;
        let image_index = UnitKey::image_index();
        self.conn.execute(
            "INSERT INTO analysis_units
                (image_id, owner_kind, owner_key, config_fingerprint, generation,
                 input_fingerprint, engine_fingerprint, state, diagnostics_json, dependencies_complete)
             VALUES (1, ?1, ?2, ?3, 0, ?4, ?5, 'pending', NULL, 0)",
            rusqlite::params![
                image_index.owner.as_str(),
                &image_index.key.to_blob()[..],
                &image_index.config[..],
                &[0u8; 32][..],
                &engine[..],
            ],
        )?;
        Ok(())
    }
}

/// A consistent read view. All values are read inside one read transaction so
/// a caller never stitches a revision from two different states.
pub struct ReadSnapshot<'a> {
    conn: &'a Connection,
    revision: Revision,
    engine: [u8; 32],
}

impl Drop for ReadSnapshot<'_> {
    fn drop(&mut self) {
        let _ = self.conn.execute_batch("ROLLBACK");
    }
}

impl<'a> ReadSnapshot<'a> {
    fn new(conn: &'a Connection) -> DbResult<Self> {
        let revision = read_revision(conn)?;
        let engine = read_engine_fingerprint(conn)?;
        Ok(Self {
            conn,
            revision,
            engine,
        })
    }

    pub fn data_revision(&self) -> Revision {
        self.revision
    }

    pub fn engine_fingerprint(&self) -> [u8; 32] {
        self.engine
    }

    pub fn analysis_generation(&self, key: &UnitKey) -> DbResult<Option<u64>> {
        let generation: Option<i64> = self
            .conn
            .query_row(
                "SELECT generation FROM analysis_units
                 WHERE image_id = 1 AND owner_kind = ?1 AND owner_key = ?2 AND config_fingerprint = ?3",
                rusqlite::params![key.owner.as_str(), &key.key.to_blob()[..], &key.config[..]],
                |row| row.get(0),
            )
            .optional()?;
        Ok(generation.and_then(|value| u64::try_from(value).ok()))
    }

    pub fn unit(&self, key: &UnitKey) -> DbResult<Option<AnalysisUnitRow>> {
        self.conn
            .query_row(
                "SELECT generation, input_fingerprint, engine_fingerprint, state,
                        diagnostics_json, dependencies_complete
                 FROM analysis_units
                 WHERE image_id = 1 AND owner_kind = ?1 AND owner_key = ?2 AND config_fingerprint = ?3",
                rusqlite::params![key.owner.as_str(), &key.key.to_blob()[..], &key.config[..]],
                |row| {
                    let diagnostics_json: Option<String> = row.get(4)?;
                    Ok(AnalysisUnitRow {
                        key: *key,
                        generation: u64::try_from(row.get::<_, i64>(0)?).unwrap_or_default(),
                        input_fingerprint: blob32(row.get(1)?),
                        engine_fingerprint: blob32(row.get(2)?),
                        state: AnalysisState::parse(&row.get::<_, String>(3)?)
                            .unwrap_or(AnalysisState::Failed),
                        diagnostics: diagnostics_json
                            .and_then(|json| serde_json::from_str(&json).ok())
                            .unwrap_or_default(),
                        dependencies_complete: row.get::<_, i64>(5)? != 0,
                    })
                },
            )
            .optional()
            .map_err(DbError::from_sqlite)
    }

    /// Overall state derived from every published unit.
    pub fn overall_state(&self) -> DbResult<OverallState> {
        let mut statement = self
            .conn
            .prepare("SELECT state, engine_fingerprint FROM analysis_units WHERE image_id = 1")?;
        let mut rows = statement.query([])?;
        let mut saw_unit = false;
        let mut saw_not_ready = false;
        while let Some(row) = rows.next()? {
            saw_unit = true;
            let state = row.get::<_, String>(0)?;
            let stored_engine = blob32(row.get(1)?);
            let state = AnalysisState::parse(&state).unwrap_or(AnalysisState::Failed);
            if stored_engine != self.engine {
                saw_not_ready = true;
                continue;
            }
            if state != AnalysisState::Current {
                saw_not_ready = true;
            }
        }
        Ok(if !saw_unit {
            OverallState::Pending
        } else if saw_not_ready {
            // `partial` covers pending/stale/failed/unsupported units: the
            // database has results but not a complete current set.
            OverallState::Partial
        } else {
            OverallState::Ready
        })
    }

    /// True when at least one unit is current with the stored engine.
    pub fn has_current_units(&self) -> DbResult<bool> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM analysis_units WHERE image_id = 1 AND state = 'current'",
            [],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn source_sha256(&self) -> DbResult<[u8; 32]> {
        let blob: Vec<u8> =
            self.conn
                .query_row("SELECT sha256 FROM sources WHERE id = 1", [], |row| {
                    row.get(0)
                })?;
        Ok(blob32(blob))
    }

    pub fn source_size(&self) -> DbResult<u64> {
        let size: i64 = self.conn.query_row(
            "SELECT original_size FROM sources WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        u64::try_from(size).map_err(|_| DbError::Corrupt("negative source size".into()))
    }

    pub fn original_path(&self) -> DbResult<String> {
        self.conn
            .query_row(
                "SELECT original_path FROM sources WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(DbError::from_sqlite)
    }

    pub fn container_kind(&self) -> DbResult<ContainerKind> {
        let raw: String = self.conn.query_row(
            "SELECT container_kind FROM sources WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        ContainerKind::parse(&raw)
            .ok_or_else(|| DbError::Corrupt(format!("unknown container kind '{raw}'")))
    }

    /// Reassemble the complete original input from its chunks.
    pub fn source_bytes(&self) -> DbResult<Vec<u8>> {
        let size = self.source_size()?;
        let capacity = usize::try_from(size)
            .map_err(|_| DbError::ResourceLimit("source too large for this platform".into()))?;
        let mut out = Vec::new();
        out.try_reserve_exact(capacity).map_err(|_| {
            DbError::ResourceLimit(format!("cannot reserve {capacity} bytes for the source"))
        })?;
        let mut statement = self.conn.prepare(
            "SELECT offset, bytes, sha256 FROM source_chunks WHERE source_id = 1 ORDER BY offset",
        )?;
        let mut rows = statement.query([])?;
        let mut expected_offset = 0u64;
        while let Some(row) = rows.next()? {
            let offset = FileOffset::from_blob(&row.get::<_, Vec<u8>>(0)?)?;
            let bytes: Vec<u8> = row.get(1)?;
            let digest = blob32(row.get(2)?);
            if sha256(&bytes) != digest {
                return Err(DbError::Corrupt(format!(
                    "source chunk at {} fails its digest",
                    offset.to_hex()
                )));
            }
            if offset.0 != expected_offset {
                return Err(DbError::Corrupt(format!(
                    "source chunk gap at {} (expected {})",
                    offset.to_hex(),
                    FileOffset(expected_offset).to_hex()
                )));
            }
            out.extend_from_slice(&bytes);
            expected_offset = offset
                .checked_end(bytes.len() as u64)
                .map_err(DbError::from)?;
        }
        if out.len() as u64 != size {
            return Err(DbError::Corrupt(format!(
                "source is {} bytes but the header says {}",
                out.len(),
                size
            )));
        }
        Ok(out)
    }

    pub fn patches(&self) -> DbResult<Vec<PatchRow>> {
        let mut statement = self
            .conn
            .prepare("SELECT file_offset, bytes FROM patches ORDER BY file_offset")?;
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

    pub fn image(&self) -> DbResult<ImageInfo> {
        let mut image = self.conn.query_row(
            "SELECT format, architecture, bitness, endianness, abi_json, entry_address,
                    selector_json, container_offset, container_length, member_name,
                    member_index, slice_label, layout_fingerprint
             FROM images WHERE id = 1",
            [],
            |row| {
                let entry: Option<Vec<u8>> = row.get(5)?;
                let abi_json: String = row.get(4)?;
                let fingerprint: Vec<u8> = row.get(12)?;
                let member_index: Option<i64> = row.get(10)?;
                Ok(ImageInfo {
                    format: row.get(0)?,
                    architecture: row.get(1)?,
                    bitness: u8::try_from(row.get::<_, i64>(2)?).unwrap_or(64),
                    endianness: row.get(3)?,
                    abi: serde_json::from_str(&abi_json).unwrap_or(AbiInfo::lp64()),
                    entry_address: entry
                        .as_deref()
                        .map(Address::from_blob)
                        .transpose()
                        .ok()
                        .flatten(),
                    selector_json: row.get(6)?,
                    container_offset: FileOffset(u64::try_from(row.get::<_, i64>(7)?).unwrap_or(0)),
                    container_length: u64::try_from(row.get::<_, i64>(8)?).unwrap_or(0),
                    member_name: row.get(9)?,
                    member_index: member_index.and_then(|value| u64::try_from(value).ok()),
                    slice_label: row.get(11)?,
                    layout_fingerprint: blob32(fingerprint),
                    mappings: Vec::new(),
                    sections: Vec::new(),
                })
            },
        )?;
        image.mappings = self.mappings()?;
        image.sections = self.sections()?;
        Ok(image)
    }

    pub fn mappings(&self) -> DbResult<Vec<MappingInfo>> {
        let mut statement = self.conn.prepare(
            "SELECT name, va, memory_size, file_offset, file_size, permissions, origin
             FROM mappings WHERE image_id = 1 ORDER BY va, id",
        )?;
        let mut rows = statement.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let file_offset: Option<Vec<u8>> = row.get(3)?;
            let permissions: String = row.get(5)?;
            out.push(MappingInfo {
                name: row.get(0)?,
                va: Address::from_blob(&row.get::<_, Vec<u8>>(1)?)?,
                memory_size: u64::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
                file_offset: file_offset
                    .as_deref()
                    .map(FileOffset::from_blob)
                    .transpose()?,
                file_size: u64::try_from(row.get::<_, i64>(4)?).unwrap_or(0),
                permissions: MappingPermissions::parse(&permissions).unwrap_or(
                    MappingPermissions {
                        read: true,
                        write: false,
                        execute: false,
                    },
                ),
                origin: row.get(6)?,
            });
        }
        Ok(out)
    }

    pub fn sections(&self) -> DbResult<Vec<SectionInfo>> {
        let mut statement = self.conn.prepare(
            "SELECT name, va, memory_size, file_offset, file_size, flags
             FROM sections WHERE image_id = 1 ORDER BY va, name, id",
        )?;
        let mut rows = statement.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let file_offset: Option<Vec<u8>> = row.get(3)?;
            out.push(SectionInfo {
                name: row.get(0)?,
                va: Address::from_blob(&row.get::<_, Vec<u8>>(1)?)?,
                memory_size: u64::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
                file_offset: file_offset
                    .as_deref()
                    .map(FileOffset::from_blob)
                    .transpose()?,
                file_size: u64::try_from(row.get::<_, i64>(4)?).unwrap_or(0),
                flags: row.get(5)?,
            });
        }
        Ok(out)
    }

    pub fn symbols(&self) -> DbResult<Vec<SymbolInfo>> {
        let mut statement = self.conn.prepare(
            "SELECT address, name, kind, size, origin FROM symbols
             WHERE image_id = 1 ORDER BY address, name",
        )?;
        let mut rows = statement.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(read_symbol_row(row)?);
        }
        Ok(out)
    }

    /// User names, ordered by address. These override loader symbols.
    pub fn names(&self) -> DbResult<Vec<(Address, String)>> {
        let mut statement = self
            .conn
            .prepare("SELECT address, value FROM names WHERE image_id = 1 ORDER BY address")?;
        let mut rows = statement.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push((Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?, row.get(1)?));
        }
        Ok(out)
    }

    pub fn name_at(&self, address: Address) -> DbResult<Option<String>> {
        self.conn
            .query_row(
                "SELECT value FROM names WHERE image_id = 1 AND address = ?1",
                rusqlite::params![&address.to_blob()[..]],
                |row| row.get(0),
            )
            .optional()
            .map_err(DbError::from_sqlite)
    }

    /// Live functions (present and not user-removed), ordered by address.
    pub fn functions(&self) -> DbResult<Vec<FunctionRow>> {
        self.functions_with_state(false)
    }

    /// Functions including suppressed rows, for `changes`/diagnostics.
    pub fn functions_with_state(&self, include_hidden: bool) -> DbResult<Vec<FunctionRow>> {
        let sql = if include_hidden {
            "SELECT address, declared_end, bounds_origin, origin, excluded, user_removed, present
             FROM functions WHERE image_id = 1 ORDER BY address"
        } else {
            "SELECT address, declared_end, bounds_origin, origin, excluded, user_removed, present
             FROM functions WHERE image_id = 1 AND present = 1 AND user_removed = 0 ORDER BY address"
        };
        let mut statement = self.conn.prepare(sql)?;
        let mut rows = statement.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(read_function_row(row)?);
        }
        Ok(out)
    }

    pub fn function_at(&self, address: Address) -> DbResult<Option<FunctionRow>> {
        self.conn
            .query_row(
                "SELECT address, declared_end, bounds_origin, origin, excluded, user_removed, present
                 FROM functions WHERE image_id = 1 AND address = ?1",
                rusqlite::params![&address.to_blob()[..]],
                read_function_row,
            )
            .optional()
            .map_err(DbError::from_sqlite)
    }

    pub fn items(&self) -> DbResult<Vec<ItemRow>> {
        let mut statement = self.conn.prepare(
            "SELECT address, length, kind, origin, type_name FROM items
             WHERE image_id = 1 ORDER BY address",
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

    pub fn annotations(&self) -> DbResult<Vec<(Address, AnnotationKind, String)>> {
        let mut statement = self.conn.prepare(
            "SELECT address, kind, value FROM annotations WHERE image_id = 1 ORDER BY address, kind",
        )?;
        let mut rows = statement.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let kind: String = row.get(1)?;
            out.push((
                Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?,
                AnnotationKind::parse(&kind).unwrap_or(AnnotationKind::Comment),
                row.get(2)?,
            ));
        }
        Ok(out)
    }

    pub fn bookmarks(&self) -> DbResult<Vec<(Address, Option<String>)>> {
        let mut statement = self
            .conn
            .prepare("SELECT address, label FROM bookmarks WHERE image_id = 1 ORDER BY address")?;
        let mut rows = statement.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push((Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?, row.get(1)?));
        }
        Ok(out)
    }

    pub fn function_overrides(&self) -> DbResult<Vec<(Address, FunctionOverrideRow)>> {
        let mut statement = self.conn.prepare(
            "SELECT address, payload_json FROM function_overrides WHERE image_id = 1 ORDER BY address",
        )?;
        let mut rows = statement.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let json: String = row.get(1)?;
            out.push((
                Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?,
                serde_json::from_str(&json).unwrap_or_default(),
            ));
        }
        Ok(out)
    }

    pub fn variable_overrides(&self) -> DbResult<Vec<VariableOverrideRow>> {
        let mut statement = self.conn.prepare(
            "SELECT function_address, locator_json, value_json FROM variable_overrides
             WHERE image_id = 1 ORDER BY function_address, locator_json",
        )?;
        let mut rows = statement.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let locator_json: String = row.get(1)?;
            let value_json: String = row.get(2)?;
            let value: serde_json::Value = serde_json::from_str(&value_json).unwrap_or_default();
            out.push(VariableOverrideRow {
                function: Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?,
                locator: VariableLocator::from_json(&locator_json)?,
                name: value
                    .get("name")
                    .and_then(|value| value.as_str())
                    .map(str::to_string),
                type_name: value
                    .get("type_name")
                    .and_then(|value| value.as_str())
                    .map(str::to_string),
            });
        }
        Ok(out)
    }

    pub fn types(&self) -> DbResult<Vec<TypeRow>> {
        let mut statement = self.conn.prepare(
            "SELECT name, kind, payload_version, payload_json, origin FROM types
             WHERE image_id = 1 ORDER BY name, origin",
        )?;
        let mut rows = statement.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(read_type_row(row)?);
        }
        Ok(out)
    }

    /// Read a stored resource (embedded DWARF sidecar, type snapshot, ...).
    pub fn resource(&self, kind: &str, logical_name: &str) -> DbResult<Option<Vec<u8>>> {
        self.conn
            .query_row(
                "SELECT payload FROM resources WHERE image_id = 1 AND kind = ?1 AND logical_name = ?2",
                rusqlite::params![kind, logical_name],
                |row| row.get(0),
            )
            .optional()
            .map_err(DbError::from_sqlite)
    }

    pub fn resource_names(&self, kind: &str) -> DbResult<Vec<String>> {
        let mut statement = self.conn.prepare(
            "SELECT logical_name FROM resources WHERE image_id = 1 AND kind = ?1 ORDER BY logical_name",
        )?;
        let mut rows = statement.query(rusqlite::params![kind])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(row.get::<_, String>(0)?);
        }
        Ok(out)
    }

    /// Instructions of one function in address order.
    pub fn instructions(&self, function: Address) -> DbResult<Vec<hexray_core::Instruction>> {
        let mut statement = self.conn.prepare(
            "SELECT i.address, i.payload_json FROM function_instructions fi
             JOIN instructions i
               ON i.image_id = fi.image_id AND i.address = fi.instruction_address
             WHERE fi.image_id = 1 AND fi.function_address = ?1
             ORDER BY fi.ordinal, i.address",
        )?;
        let mut rows = statement.query(rusqlite::params![&function.to_blob()[..]])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let address = Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?;
            let json: String = row.get(1)?;
            let instruction = serde_json::from_str(&json).map_err(|_| {
                DbError::Corrupt(format!(
                    "instruction payload at {} is not readable",
                    address.to_hex()
                ))
            })?;
            out.push(instruction);
        }
        Ok(out)
    }

    /// Reconstructed CFG payload of one function.
    pub fn cfg(&self, function: Address) -> DbResult<CfgData> {
        let mut blocks = Vec::new();
        {
            let mut statement = self.conn.prepare(
                "SELECT payload_json FROM basic_blocks
                 WHERE image_id = 1 AND function_address = ?1 ORDER BY block_id",
            )?;
            let mut rows = statement.query(rusqlite::params![&function.to_blob()[..]])?;
            while let Some(row) = rows.next()? {
                let json: String = row.get(0)?;
                match serde_json::from_str::<BlockPayload>(&json) {
                    Ok(block) => blocks.push(block),
                    Err(_) => {
                        return Err(DbError::Corrupt(format!(
                            "block payload of {} is not readable",
                            function.to_hex()
                        )))
                    }
                }
            }
        }

        let mut block_instructions: Vec<(u32, Vec<Address>)> = Vec::new();
        {
            let mut statement = self.conn.prepare(
                "SELECT block_id, instruction_address FROM block_instructions
                 WHERE image_id = 1 AND function_address = ?1 ORDER BY block_id, ordinal",
            )?;
            let mut rows = statement.query(rusqlite::params![&function.to_blob()[..]])?;
            while let Some(row) = rows.next()? {
                let block_id = u32::try_from(row.get::<_, i64>(0)?).unwrap_or(0);
                let address = Address::from_blob(&row.get::<_, Vec<u8>>(1)?)?;
                match block_instructions.last_mut() {
                    Some((id, list)) if *id == block_id => list.push(address),
                    _ => block_instructions.push((block_id, vec![address])),
                }
            }
        }

        let mut edges = Vec::new();
        {
            let mut statement = self.conn.prepare(
                "SELECT from_block, to_block, kind FROM cfg_edges
                 WHERE image_id = 1 AND function_address = ?1 ORDER BY from_block, to_block, kind",
            )?;
            let mut rows = statement.query(rusqlite::params![&function.to_blob()[..]])?;
            while let Some(row) = rows.next()? {
                let kind = EdgeKind::parse(&row.get::<_, String>(2)?).unwrap_or(EdgeKind::Normal);
                edges.push((
                    u32::try_from(row.get::<_, i64>(0)?).unwrap_or(0),
                    u32::try_from(row.get::<_, i64>(1)?).unwrap_or(0),
                    kind,
                ));
            }
        }

        Ok(CfgData {
            blocks,
            block_instructions,
            edges,
        })
    }

    pub fn xrefs_from(&self, address: Address) -> DbResult<Vec<XrefRow>> {
        self.query_xrefs(
            "SELECT from_address, to_address, kind, owner_function, origin FROM xrefs
             WHERE image_id = 1 AND from_address = ?1 ORDER BY to_address, kind",
            address,
        )
    }

    pub fn xrefs_to(&self, address: Address) -> DbResult<Vec<XrefRow>> {
        self.query_xrefs(
            "SELECT from_address, to_address, kind, owner_function, origin FROM xrefs
             WHERE image_id = 1 AND to_address = ?1 ORDER BY from_address, kind",
            address,
        )
    }

    /// All xrefs, ordered by source then target.
    pub fn all_xrefs(&self) -> DbResult<Vec<XrefRow>> {
        let mut statement = self.conn.prepare(
            "SELECT from_address, to_address, kind, owner_function, origin FROM xrefs
             WHERE image_id = 1 ORDER BY from_address, to_address, kind",
        )?;
        let mut rows = statement.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(read_xref_row(row)?);
        }
        Ok(out)
    }

    fn query_xrefs(&self, sql: &str, address: Address) -> DbResult<Vec<XrefRow>> {
        let mut statement = self.conn.prepare(sql)?;
        let mut rows = statement.query(rusqlite::params![&address.to_blob()[..]])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(read_xref_row(row)?);
        }
        Ok(out)
    }

    pub fn strings(&self) -> DbResult<Vec<StringRow>> {
        let mut statement = self.conn.prepare(
            "SELECT address, encoding, bytes, decoded_text FROM strings
             WHERE image_id = 1 ORDER BY address, encoding",
        )?;
        let mut rows = statement.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(read_string_row(row)?);
        }
        Ok(out)
    }

    /// Stored pseudo-C for one function and configuration.
    pub fn decompiled(
        &self,
        function: Address,
        config: &[u8; 32],
    ) -> DbResult<Option<(u64, String)>> {
        self.conn
            .query_row(
                "SELECT generation, text FROM decompiled
                 WHERE image_id = 1 AND function_address = ?1 AND config_fingerprint = ?2",
                rusqlite::params![&function.to_blob()[..], &config[..]],
                |row| {
                    Ok((
                        u64::try_from(row.get::<_, i64>(0)?).unwrap_or(0),
                        row.get::<_, String>(1)?,
                    ))
                },
            )
            .optional()
            .map_err(DbError::from_sqlite)
    }

    pub fn history_events(&self, limit: usize, offset: usize) -> DbResult<Vec<HistoryEvent>> {
        let mut statement = self.conn.prepare(
            "SELECT e.id, e.action, e.edit_id, e.revision, e.actor, e.timestamp, l.kind
             FROM history_events e LEFT JOIN edit_log l ON l.id = e.edit_id
             ORDER BY e.id DESC LIMIT ?1 OFFSET ?2",
        )?;
        let mut rows = statement.query(rusqlite::params![limit as i64, offset as i64])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(HistoryEvent {
                id: u64::try_from(row.get::<_, i64>(0)?).unwrap_or(0),
                action: row.get(1)?,
                edit_id: row
                    .get::<_, Option<i64>>(2)?
                    .and_then(|value| u64::try_from(value).ok()),
                revision: Revision(u64::try_from(row.get::<_, i64>(3)?).unwrap_or(0)),
                actor: row.get(4)?,
                timestamp: row.get(5)?,
                kind: row.get(6)?,
            });
        }
        Ok(out)
    }

    pub fn command_history(&self, limit: usize, offset: usize) -> DbResult<Vec<CommandHistoryRow>> {
        let mut statement = self.conn.prepare(
            "SELECT id, actor, command, output, success, timestamp, truncated
             FROM command_history ORDER BY id DESC LIMIT ?1 OFFSET ?2",
        )?;
        let mut rows = statement.query(rusqlite::params![limit as i64, offset as i64])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(CommandHistoryRow {
                id: u64::try_from(row.get::<_, i64>(0)?).unwrap_or(0),
                actor: row.get(1)?,
                command: row.get(2)?,
                output: row.get(3)?,
                success: row.get::<_, i64>(4)? != 0,
                timestamp: row.get(5)?,
                truncated: row.get::<_, i64>(6)? != 0,
            });
        }
        Ok(out)
    }

    /// Undo/redo depth for reporting.
    pub fn history_depth(&self) -> DbResult<(usize, usize)> {
        let mut undo = 0usize;
        let mut head: Option<i64> =
            self.conn
                .query_row("SELECT edit_id FROM history_head WHERE id = 1", [], |row| {
                    row.get(0)
                })?;
        while let Some(id) = head {
            undo += 1;
            head = self
                .conn
                .query_row(
                    "SELECT parent_id FROM edit_log WHERE id = ?1",
                    rusqlite::params![id],
                    |row| row.get(0),
                )
                .optional()?
                .flatten();
            if undo > MAX_HISTORY_ENTRIES as usize {
                break;
            }
        }
        let redo_json: String = self.conn.query_row(
            "SELECT redo_ids_json FROM history_head WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        let redo: Vec<u64> = serde_json::from_str(&redo_json).unwrap_or_default();
        Ok((undo, redo.len()))
    }

    pub fn info(&self) -> DbResult<DatabaseInfo> {
        let (uuid, created_at, stored_engine) = self.conn.query_row(
            "SELECT uuid, created_at, engine_fingerprint FROM database_meta WHERE id = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    blob32(row.get(2)?),
                ))
            },
        )?;
        let (undo_depth, redo_depth) = self.history_depth()?;
        let analysis_scope = self.scope()?;
        let coverage = if analysis_scope.is_empty() {
            "full"
        } else {
            "filtered"
        };
        let skipped_functions = self.count_skipped_functions(&analysis_scope)?;
        Ok(DatabaseInfo {
            uuid,
            revision: self.revision,
            created_at,
            engine_fingerprint: self.engine,
            stored_engine_fingerprint: stored_engine,
            schema_version: SCHEMA_VERSION,
            overall_state: self.overall_state()?,
            source_size: self.source_size()?,
            source_sha256: self.source_sha256()?,
            original_path: self.original_path()?,
            image: self.image()?,
            function_count: self.count_live_functions()?,
            instruction_count: self.count("instructions")?,
            string_count: self.count("strings")?,
            xref_count: self.count("xrefs")?,
            patch_count: self.patch_count()?,
            debug_sidecars: self.resource_names("dwarf_sidecar")?.len(),
            undo_depth,
            redo_depth,
            analysis_scope,
            coverage: coverage.to_string(),
            skipped_functions,
        })
    }

    fn count(&self, table: &str) -> DbResult<usize> {
        // Table names come from this module only.
        let sql = format!("SELECT COUNT(*) FROM {table} WHERE image_id = 1");
        let count: i64 = self.conn.query_row(&sql, [], |row| row.get(0))?;
        Ok(usize::try_from(count).unwrap_or(0))
    }

    /// `patches` is keyed by file offset, not by image.
    fn patch_count(&self) -> DbResult<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM patches", [], |row| row.get(0))?;
        Ok(usize::try_from(count).unwrap_or(0))
    }

    /// Locate a function containing `address` by range.
    pub fn function_containing(&self, address: Address) -> DbResult<Option<FunctionRow>> {
        let functions = self.functions()?;
        Ok(functions.into_iter().find(|function| {
            let Some(end) = function.declared_end else {
                return false;
            };
            let start = function.address.0;
            address.0 >= start && address.0 < end.0 && start < end.0
        }))
    }

    /// Every published unit, ordered by owner.
    pub fn all_units(&self) -> DbResult<Vec<AnalysisUnitRow>> {
        let mut statement = self.conn.prepare(
            "SELECT owner_kind, owner_key, config_fingerprint, generation, input_fingerprint,
                engine_fingerprint, state, diagnostics_json, dependencies_complete
         FROM analysis_units WHERE image_id = 1
         ORDER BY owner_kind, owner_key, config_fingerprint",
        )?;
        let mut rows = statement.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let config_bytes: Vec<u8> = row.get(2)?;
            let mut config = [0u8; 32];
            if config_bytes.len() == 32 {
                config.copy_from_slice(&config_bytes);
            }
            let diagnostics_json: Option<String> = row.get(7)?;
            out.push(AnalysisUnitRow {
                key: UnitKey {
                    owner: OwnerKind::parse(&row.get::<_, String>(0)?)
                        .unwrap_or(OwnerKind::ImageIndex),
                    key: Address::from_blob(&row.get::<_, Vec<u8>>(1)?)?,
                    config,
                },
                generation: u64::try_from(row.get::<_, i64>(3)?).unwrap_or(0),
                input_fingerprint: blob32(row.get(4)?),
                engine_fingerprint: blob32(row.get(5)?),
                state: AnalysisState::parse(&row.get::<_, String>(6)?)
                    .unwrap_or(AnalysisState::Failed),
                diagnostics: diagnostics_json
                    .and_then(|json| serde_json::from_str(&json).ok())
                    .unwrap_or_default(),
                dependencies_complete: row.get::<_, i64>(8)? != 0,
            });
        }
        Ok(out)
    }

    /// Every stored pseudo-C rendering, keyed by function and config.
    pub fn all_decompiled(&self) -> DbResult<Vec<(Address, [u8; 32], String)>> {
        let mut statement = self.conn.prepare(
            "SELECT function_address, config_fingerprint, text FROM decompiled
         WHERE image_id = 1 ORDER BY function_address, config_fingerprint",
        )?;
        let mut rows = statement.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let config_bytes: Vec<u8> = row.get(1)?;
            let mut config = [0u8; 32];
            if config_bytes.len() == 32 {
                config.copy_from_slice(&config_bytes);
            }
            out.push((
                Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?,
                config,
                row.get(2)?,
            ));
        }
        Ok(out)
    }

    // -----------------------------------------------------------------------
    // Batch readers
    //
    // Each method answers one bounded question so a command never has to
    // materialize a whole table. Address lists are split into disjoint groups
    // of at most `MAX_ADDRESS_CHUNK` values; a group prepares its statement
    // once and binds every value.
    // -----------------------------------------------------------------------

    /// One page of live functions, ordered by address, plus the CFG unit state
    /// stored for the function under the all-zero config, when such a unit
    /// exists.
    pub fn functions_page(&self, limit: usize, offset: usize) -> DbResult<Vec<FunctionListRow>> {
        let mut statement = self.conn.prepare(
            "SELECT f.address, f.declared_end, f.bounds_origin, f.origin,
                    f.excluded, f.user_removed, f.present, u.state
             FROM functions f
             LEFT JOIN analysis_units u
               ON u.image_id = f.image_id
              AND u.owner_kind = 'function_cfg'
              AND u.owner_key = f.address
              AND u.config_fingerprint = ?3
             WHERE f.image_id = 1 AND f.present = 1 AND f.user_removed = 0
             ORDER BY f.address
             LIMIT ?1 OFFSET ?2",
        )?;
        let mut rows = statement.query(rusqlite::params![
            page_bound(limit),
            page_bound(offset),
            &NO_CONFIG_FINGERPRINT[..]
        ])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let state: Option<String> = row.get(7)?;
            out.push(FunctionListRow {
                function: read_function_row(row)?,
                state: state.and_then(|value| AnalysisState::parse(&value)),
            });
        }
        Ok(out)
    }

    /// One page of symbols in the order of [`ReadSnapshot::symbols`].
    pub fn symbols_page(&self, limit: usize, offset: usize) -> DbResult<Vec<SymbolInfo>> {
        let mut statement = self.conn.prepare(
            "SELECT address, name, kind, size, origin FROM symbols
             WHERE image_id = 1 ORDER BY address, name LIMIT ?1 OFFSET ?2",
        )?;
        let mut rows = statement.query(rusqlite::params![page_bound(limit), page_bound(offset)])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(read_symbol_row(row)?);
        }
        Ok(out)
    }

    /// One page of strings in the order of [`ReadSnapshot::strings`].
    pub fn strings_page(&self, limit: usize, offset: usize) -> DbResult<Vec<StringRow>> {
        let mut statement = self.conn.prepare(
            "SELECT address, encoding, bytes, decoded_text FROM strings
             WHERE image_id = 1 ORDER BY address, encoding LIMIT ?1 OFFSET ?2",
        )?;
        let mut rows = statement.query(rusqlite::params![page_bound(limit), page_bound(offset)])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(read_string_row(row)?);
        }
        Ok(out)
    }

    /// One page of user types in the order of [`ReadSnapshot::types`].
    pub fn types_page(&self, limit: usize, offset: usize) -> DbResult<Vec<TypeRow>> {
        let mut statement = self.conn.prepare(
            "SELECT name, kind, payload_version, payload_json, origin FROM types
             WHERE image_id = 1 ORDER BY name, origin LIMIT ?1 OFFSET ?2",
        )?;
        let mut rows = statement.query(rusqlite::params![page_bound(limit), page_bound(offset)])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(read_type_row(row)?);
        }
        Ok(out)
    }

    /// User names at exactly these addresses. Addresses without a row are
    /// absent from the map.
    pub fn names_for(&self, addresses: &[Address]) -> DbResult<BTreeMap<Address, String>> {
        let mut out = BTreeMap::new();
        for chunk in address_chunks(addresses) {
            let sql = format!(
                "SELECT address, value FROM names
                 WHERE image_id = 1 AND address IN ({})
                 ORDER BY address",
                placeholders(chunk.len())
            );
            let blobs: Vec<[u8; 8]> = chunk.iter().map(|address| address.to_blob()).collect();
            let mut statement = self.conn.prepare(&sql)?;
            let mut rows = statement
                .query(rusqlite::params_from_iter(blobs.iter().map(|blob| blob.as_slice())))?;
            while let Some(row) = rows.next()? {
                out.insert(Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?, row.get(1)?);
            }
        }
        Ok(out)
    }

    /// The preferred symbol row of each requested address: the first row that
    /// [`ReadSnapshot::symbols`] would surface for it. Addresses without a row
    /// are absent from the map.
    pub fn symbols_for(&self, addresses: &[Address]) -> DbResult<BTreeMap<Address, SymbolInfo>> {
        let mut out = BTreeMap::new();
        for chunk in address_chunks(addresses) {
            let sql = format!(
                "SELECT address, name, kind, size, origin FROM symbols
                 WHERE image_id = 1 AND address IN ({})
                 ORDER BY address, name",
                placeholders(chunk.len())
            );
            let blobs: Vec<[u8; 8]> = chunk.iter().map(|address| address.to_blob()).collect();
            let mut statement = self.conn.prepare(&sql)?;
            let mut rows = statement
                .query(rusqlite::params_from_iter(blobs.iter().map(|blob| blob.as_slice())))?;
            while let Some(row) = rows.next()? {
                let symbol = read_symbol_row(row)?;
                let address = symbol.address;
                out.entry(address).or_insert(symbol);
            }
        }
        Ok(out)
    }

    /// Instructions owned by each requested function. A function with no
    /// instruction row is absent from the map; per-function order matches
    /// [`ReadSnapshot::instructions`].
    pub fn instructions_for_functions(
        &self,
        functions: &[Address],
    ) -> DbResult<BTreeMap<Address, Vec<hexray_core::Instruction>>> {
        let mut out: BTreeMap<Address, Vec<hexray_core::Instruction>> = BTreeMap::new();
        for chunk in address_chunks(functions) {
            let sql = format!(
                "SELECT fi.function_address, i.address, i.payload_json
                 FROM function_instructions fi
                 JOIN instructions i
                   ON i.image_id = fi.image_id AND i.address = fi.instruction_address
                 WHERE fi.image_id = 1 AND fi.function_address IN ({})
                 ORDER BY fi.function_address, fi.ordinal, i.address",
                placeholders(chunk.len())
            );
            let blobs: Vec<[u8; 8]> = chunk.iter().map(|address| address.to_blob()).collect();
            let mut statement = self.conn.prepare(&sql)?;
            let mut rows = statement
                .query(rusqlite::params_from_iter(blobs.iter().map(|blob| blob.as_slice())))?;
            while let Some(row) = rows.next()? {
                let function = Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?;
                let address = Address::from_blob(&row.get::<_, Vec<u8>>(1)?)?;
                let json: String = row.get(2)?;
                let instruction = serde_json::from_str(&json).map_err(|_| {
                    DbError::Corrupt(format!(
                        "instruction payload at {} is not readable",
                        address.to_hex()
                    ))
                })?;
                out.entry(function).or_default().push(instruction);
            }
        }
        Ok(out)
    }

    /// CFGs owned by each requested function, with the block/edge/instruction
    /// order of [`ReadSnapshot::cfg`]. A function with no basic block is
    /// absent from the map; a CFG is never fabricated.
    pub fn cfgs_for_functions(
        &self,
        functions: &[Address],
    ) -> DbResult<BTreeMap<Address, CfgData>> {
        let mut out: BTreeMap<Address, CfgData> = BTreeMap::new();
        for chunk in address_chunks(functions) {
            let blobs: Vec<[u8; 8]> = chunk.iter().map(|address| address.to_blob()).collect();
            let params: Vec<&[u8]> = blobs.iter().map(|blob| blob.as_slice()).collect();

            {
                let sql = format!(
                    "SELECT function_address, payload_json FROM basic_blocks
                     WHERE image_id = 1 AND function_address IN ({})
                     ORDER BY function_address, block_id",
                    placeholders(chunk.len())
                );
                let mut statement = self.conn.prepare(&sql)?;
                let mut rows =
                    statement.query(rusqlite::params_from_iter(params.iter().copied()))?;
                while let Some(row) = rows.next()? {
                    let function = Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?;
                    let json: String = row.get(1)?;
                    match serde_json::from_str::<BlockPayload>(&json) {
                        Ok(block) => out.entry(function).or_default().blocks.push(block),
                        Err(_) => {
                            return Err(DbError::Corrupt(format!(
                                "block payload of {} is not readable",
                                function.to_hex()
                            )))
                        }
                    }
                }
            }

            {
                let sql = format!(
                    "SELECT function_address, block_id, instruction_address FROM block_instructions
                     WHERE image_id = 1 AND function_address IN ({})
                     ORDER BY function_address, block_id, ordinal",
                    placeholders(chunk.len())
                );
                let mut statement = self.conn.prepare(&sql)?;
                let mut rows =
                    statement.query(rusqlite::params_from_iter(params.iter().copied()))?;
                while let Some(row) = rows.next()? {
                    let function = Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?;
                    let block_id = u32::try_from(row.get::<_, i64>(1)?).unwrap_or(0);
                    let address = Address::from_blob(&row.get::<_, Vec<u8>>(2)?)?;
                    let Some(cfg) = out.get_mut(&function) else {
                        continue;
                    };
                    match cfg.block_instructions.last_mut() {
                        Some((id, list)) if *id == block_id => list.push(address),
                        _ => cfg.block_instructions.push((block_id, vec![address])),
                    }
                }
            }

            {
                let sql = format!(
                    "SELECT function_address, from_block, to_block, kind FROM cfg_edges
                     WHERE image_id = 1 AND function_address IN ({})
                     ORDER BY function_address, from_block, to_block, kind",
                    placeholders(chunk.len())
                );
                let mut statement = self.conn.prepare(&sql)?;
                let mut rows =
                    statement.query(rusqlite::params_from_iter(params.iter().copied()))?;
                while let Some(row) = rows.next()? {
                    let function = Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?;
                    let from_block = u32::try_from(row.get::<_, i64>(1)?).unwrap_or(0);
                    let to_block = u32::try_from(row.get::<_, i64>(2)?).unwrap_or(0);
                    let kind =
                        EdgeKind::parse(&row.get::<_, String>(3)?).unwrap_or(EdgeKind::Normal);
                    if let Some(cfg) = out.get_mut(&function) {
                        cfg.edges.push((from_block, to_block, kind));
                    }
                }
            }
        }
        Ok(out)
    }

    /// One page of cross references, ordered by source, target and kind.
    pub fn xrefs_page(&self, limit: usize, offset: usize) -> DbResult<Vec<XrefRow>> {
        let mut statement = self.conn.prepare(
            "SELECT from_address, to_address, kind, owner_function, origin FROM xrefs
             WHERE image_id = 1 ORDER BY from_address, to_address, kind
             LIMIT ?1 OFFSET ?2",
        )?;
        let mut rows = statement.query(rusqlite::params![page_bound(limit), page_bound(offset)])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(read_xref_row(row)?);
        }
        Ok(out)
    }

    /// Cross references whose source or target is one of `addresses`, ordered
    /// by source then target. A reference collides only when both ends are
    /// requested; it is returned once either way.
    pub fn xrefs_for_addresses(&self, addresses: &[Address]) -> DbResult<Vec<XrefRow>> {
        let mut out = Vec::new();
        let mut seen: BTreeSet<XrefKey> = BTreeSet::new();
        for chunk in address_chunks(addresses) {
            let sql = format!(
                "SELECT from_address, to_address, kind, owner_function, origin FROM xrefs
                 WHERE image_id = 1 AND (from_address IN ({0}) OR to_address IN ({0}))
                 ORDER BY from_address, to_address",
                placeholders(chunk.len())
            );
            let blobs: Vec<[u8; 8]> = chunk.iter().map(|address| address.to_blob()).collect();
            let mut statement = self.conn.prepare(&sql)?;
            let mut rows = statement
                .query(rusqlite::params_from_iter(blobs.iter().map(|blob| blob.as_slice())))?;
            while let Some(row) = rows.next()? {
                let xref = read_xref_row(row)?;
                let key = (
                    xref.from.to_blob(),
                    xref.to.to_blob(),
                    xref.kind.as_str().to_string(),
                    xref.owner.map(|owner| owner.to_blob()),
                    xref.origin.as_str().to_string(),
                );
                if seen.insert(key) {
                    out.push(xref);
                }
            }
        }
        out.sort_by(|left, right| {
            (
                left.from.0,
                left.to.0,
                left.kind.as_str(),
                left.owner.map(|owner| owner.0),
                left.origin.as_str(),
            )
                .cmp(&(
                    right.from.0,
                    right.to.0,
                    right.kind.as_str(),
                    right.owner.map(|owner| owner.0),
                    right.origin.as_str(),
                ))
        });
        Ok(out)
    }

    /// Call references, optionally restricted to the calls owned by one
    /// function, ordered by source then target.
    pub fn call_xrefs(&self, owner: Option<Address>) -> DbResult<Vec<XrefRow>> {
        let mut out = Vec::new();
        match owner {
            Some(owner) => {
                let mut statement = self.conn.prepare(
                    "SELECT from_address, to_address, kind, owner_function, origin FROM xrefs
                     WHERE image_id = 1 AND kind = ?1 AND owner_function = ?2
                     ORDER BY from_address, to_address",
                )?;
                let mut rows = statement.query(rusqlite::params![
                    XrefKind::Call.as_str(),
                    &owner.to_blob()[..]
                ])?;
                while let Some(row) = rows.next()? {
                    out.push(read_xref_row(row)?);
                }
            }
            None => {
                let mut statement = self.conn.prepare(
                    "SELECT from_address, to_address, kind, owner_function, origin FROM xrefs
                     WHERE image_id = 1 AND kind = ?1
                     ORDER BY from_address, to_address",
                )?;
                let mut rows = statement.query(rusqlite::params![XrefKind::Call.as_str()])?;
                while let Some(row) = rows.next()? {
                    out.push(read_xref_row(row)?);
                }
            }
        }
        Ok(out)
    }

    /// Addresses carrying this exact user name, ordered by address.
    pub fn addresses_for_name(&self, value: &str) -> DbResult<Vec<Address>> {
        let mut statement = self.conn.prepare(
            "SELECT address FROM names WHERE image_id = 1 AND value = ?1 ORDER BY address",
        )?;
        let mut rows = statement.query(rusqlite::params![value])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?);
        }
        Ok(out)
    }

    /// Addresses carrying this exact symbol name, ordered by address.
    pub fn addresses_for_symbol(&self, name: &str) -> DbResult<Vec<Address>> {
        let mut statement = self.conn.prepare(
            "SELECT DISTINCT address FROM symbols WHERE image_id = 1 AND name = ?1 ORDER BY address",
        )?;
        let mut rows = statement.query(rusqlite::params![name])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            out.push(Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?);
        }
        Ok(out)
    }

    /// Functions among `functions` that own at least one instruction row.
    pub fn functions_with_instructions(
        &self,
        functions: &[Address],
    ) -> DbResult<BTreeSet<Address>> {
        let mut out = BTreeSet::new();
        for chunk in address_chunks(functions) {
            let sql = format!(
                "SELECT DISTINCT function_address FROM function_instructions
                 WHERE image_id = 1 AND function_address IN ({})
                 ORDER BY function_address",
                placeholders(chunk.len())
            );
            let blobs: Vec<[u8; 8]> = chunk.iter().map(|address| address.to_blob()).collect();
            let mut statement = self.conn.prepare(&sql)?;
            let mut rows = statement
                .query(rusqlite::params_from_iter(blobs.iter().map(|blob| blob.as_slice())))?;
            while let Some(row) = rows.next()? {
                out.insert(Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?);
            }
        }
        Ok(out)
    }

    /// Stored payload footprint of each requested function, measured with
    /// `LENGTH()` so the payload rows themselves are never fetched. Functions
    /// without any stored artifact are absent from the map.
    pub fn payload_bytes_for_functions(
        &self,
        functions: &[Address],
    ) -> DbResult<BTreeMap<Address, PayloadBytes>> {
        let mut out: BTreeMap<Address, PayloadBytes> = BTreeMap::new();
        for chunk in address_chunks(functions) {
            let blobs: Vec<[u8; 8]> = chunk.iter().map(|address| address.to_blob()).collect();
            let params: Vec<&[u8]> = blobs.iter().map(|blob| blob.as_slice()).collect();

            {
                let sql = format!(
                    "SELECT fi.function_address, SUM(LENGTH(i.payload_json))
                     FROM function_instructions fi
                     JOIN instructions i
                       ON i.image_id = fi.image_id AND i.address = fi.instruction_address
                     WHERE fi.image_id = 1 AND fi.function_address IN ({})
                     GROUP BY fi.function_address",
                    placeholders(chunk.len())
                );
                let mut statement = self.conn.prepare(&sql)?;
                let mut rows =
                    statement.query(rusqlite::params_from_iter(params.iter().copied()))?;
                while let Some(row) = rows.next()? {
                    let function = Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?;
                    out.entry(function).or_default().instructions =
                        u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0);
                }
            }

            {
                let sql = format!(
                    "SELECT function_address, SUM(LENGTH(payload_json)) FROM basic_blocks
                     WHERE image_id = 1 AND function_address IN ({})
                     GROUP BY function_address",
                    placeholders(chunk.len())
                );
                let mut statement = self.conn.prepare(&sql)?;
                let mut rows =
                    statement.query(rusqlite::params_from_iter(params.iter().copied()))?;
                while let Some(row) = rows.next()? {
                    let function = Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?;
                    out.entry(function).or_default().cfg =
                        u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0);
                }
            }

            {
                let sql = format!(
                    "SELECT function_address, SUM(LENGTH(text)) FROM decompiled
                     WHERE image_id = 1 AND function_address IN ({})
                     GROUP BY function_address",
                    placeholders(chunk.len())
                );
                let mut statement = self.conn.prepare(&sql)?;
                let mut rows =
                    statement.query(rusqlite::params_from_iter(params.iter().copied()))?;
                while let Some(row) = rows.next()? {
                    let function = Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?;
                    out.entry(function).or_default().render =
                        u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0);
                }
            }
        }
        Ok(out)
    }

    /// Functions that already have stored pseudo-C for one render config.
    pub fn rendered_for(
        &self,
        config: &[u8; 32],
        functions: &[Address],
    ) -> DbResult<BTreeSet<Address>> {
        let mut out = BTreeSet::new();
        for chunk in address_chunks(functions) {
            let sql = format!(
                "SELECT DISTINCT function_address FROM decompiled
                 WHERE image_id = 1 AND function_address IN ({0}) AND config_fingerprint = ?{1}",
                placeholders(chunk.len()),
                chunk.len() + 1
            );
            let blobs: Vec<[u8; 8]> = chunk.iter().map(|address| address.to_blob()).collect();
            let mut params: Vec<&[u8]> = blobs.iter().map(|blob| blob.as_slice()).collect();
            params.push(&config[..]);
            let mut statement = self.conn.prepare(&sql)?;
            let mut rows = statement.query(rusqlite::params_from_iter(params))?;
            while let Some(row) = rows.next()? {
                out.insert(Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?);
            }
        }
        Ok(out)
    }

    /// Recorded dependencies of the given units, keyed by unit. A unit with no
    /// dependency row is absent from the map.
    pub fn dependencies_for_units(
        &self,
        keys: &[UnitKey],
    ) -> DbResult<BTreeMap<UnitKey, Vec<Dependency>>> {
        let mut out: BTreeMap<UnitKey, Vec<Dependency>> = BTreeMap::new();
        for chunk in unit_key_chunks(keys) {
            let sql = format!(
                "SELECT owner_kind, owner_key, config_fingerprint, dependency_kind,
                        dependency_key, range_start, range_length, target_generation
                 FROM analysis_dependencies
                 WHERE image_id = 1 AND (owner_kind, owner_key, config_fingerprint) IN ({})
                 ORDER BY owner_kind, owner_key, config_fingerprint",
                unit_key_placeholders(chunk.len())
            );
            let mut params: Vec<rusqlite::types::Value> = Vec::with_capacity(chunk.len() * 3);
            for key in &chunk {
                params.push(rusqlite::types::Value::Text(
                    key.owner.as_str().to_string(),
                ));
                params.push(rusqlite::types::Value::Blob(key.key.to_blob().to_vec()));
                params.push(rusqlite::types::Value::Blob(key.config.to_vec()));
            }
            let mut statement = self.conn.prepare(&sql)?;
            let mut rows = statement.query(rusqlite::params_from_iter(params))?;
            while let Some(row) = rows.next()? {
                // The row-value filter already matched a requested key, so an
                // unparsable kind cannot correspond to one; skip instead of
                // inventing a map entry.
                let Some(owner) = OwnerKind::parse(&row.get::<_, String>(0)?) else {
                    continue;
                };
                let key = UnitKey {
                    owner,
                    key: Address::from_blob(&row.get::<_, Vec<u8>>(1)?)?,
                    config: blob32(row.get(2)?),
                };
                let range_start =
                    Address::from_blob(&row.get::<_, Vec<u8>>(5)?).unwrap_or(Address(0));
                let range_length = u64::try_from(row.get::<_, i64>(6)?).unwrap_or(0);
                let dependency = Dependency {
                    kind: DependencyKind::parse(&row.get::<_, String>(3)?)
                        .unwrap_or(DependencyKind::Range),
                    key: row.get(4)?,
                    range: if range_length > 0 {
                        AddressRange::new(range_start, range_length).ok()
                    } else {
                        None
                    },
                    target_generation: u64::try_from(row.get::<_, i64>(7)?).unwrap_or(0),
                };
                out.entry(key).or_default().push(dependency);
            }
        }
        Ok(out)
    }

    /// The project's current automatic-analysis exclusion policy.
    ///
    /// A missing or empty resource row is the empty scope; an unreadable
    /// payload is `Corrupt`, never a panic.
    pub fn scope(&self) -> DbResult<AnalysisScope> {
        read_stored_scope(self.conn)
    }

    /// Live functions, counted without materializing the rows.
    fn count_live_functions(&self) -> DbResult<usize> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM functions
             WHERE image_id = 1 AND present = 1 AND user_removed = 0",
            [],
            |row| row.get(0),
        )?;
        Ok(usize::try_from(count).unwrap_or(0))
    }

    /// Live function entry addresses inside the merged exclusion intervals.
    fn count_skipped_functions(&self, scope: &AnalysisScope) -> DbResult<usize> {
        let mut skipped = 0usize;
        for (start, end) in scope.merged_intervals() {
            let count: i64 = self.conn.query_row(
                "SELECT COUNT(*) FROM functions
                 WHERE image_id = 1 AND present = 1 AND user_removed = 0
                   AND address >= ?1 AND address < ?2",
                rusqlite::params![
                    &Address(start).to_blob()[..],
                    &Address(end).to_blob()[..]
                ],
                |row| row.get(0),
            )?;
            skipped += usize::try_from(count).unwrap_or(0);
        }
        Ok(skipped)
    }
}

/// A row of the command log.
#[derive(Debug, Clone)]
pub struct CommandHistoryRow {
    pub id: u64,
    pub actor: String,
    pub command: String,
    pub output: String,
    pub success: bool,
    pub timestamp: String,
    pub truncated: bool,
}

/// Reconstructed CFG of one function.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct CfgData {
    pub blocks: Vec<BlockPayload>,
    pub block_instructions: Vec<(u32, Vec<Address>)>,
    pub edges: Vec<(u32, u32, EdgeKind)>,
}

impl CfgData {
    pub fn block_instructions(&self, block_id: u32) -> &[Address] {
        self.block_instructions
            .iter()
            .find(|(id, _)| *id == block_id)
            .map(|(_, list)| list.as_slice())
            .unwrap_or(&[])
    }
}

/// One live function row plus the state of its stored CFG unit, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionListRow {
    pub function: FunctionRow,
    pub state: Option<AnalysisState>,
}

/// Stored payload footprint of one function, in bytes of JSON/text.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PayloadBytes {
    pub instructions: u64,
    pub cfg: u64,
    pub render: u64,
}

fn configure_writable(conn: &Connection) -> DbResult<()> {
    // A rollback journal (not WAL) keeps the project a single self-contained
    // file: no persistent `-wal`/`-shm` sidecars to forget when copying.
    let mode: String = conn.query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("delete") {
        return Err(DbError::Unsupported(format!(
            "cannot force rollback journal mode (got '{mode}')"
        )));
    }
    conn.pragma_update(None, "synchronous", "FULL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "temp_store", "MEMORY")?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    Ok(())
}

fn validate_create_input(input: &CreateInput) -> DbResult<()> {
    if input.source_bytes.is_empty() {
        return Err(DbError::Validation("input is empty".into()));
    }
    if input.source_bytes.len() as u64 > MAX_SOURCE_BYTES_DEFAULT {
        return Err(DbError::ResourceLimit(format!(
            "input is {} bytes, above the {} byte limit",
            input.source_bytes.len(),
            MAX_SOURCE_BYTES_DEFAULT
        )));
    }
    if input.image.container_length == 0 {
        return Err(DbError::Validation("selected image is empty".into()));
    }
    if input.image.container_length > MAX_ANALYSIS_BYTES_DEFAULT {
        return Err(DbError::ResourceLimit(format!(
            "selected image is {} bytes, above the {} byte analysis limit",
            input.image.container_length, MAX_ANALYSIS_BYTES_DEFAULT
        )));
    }
    let end = input
        .image
        .container_offset
        .checked_end(input.image.container_length)?;
    if end > input.source_bytes.len() as u64 {
        return Err(DbError::Validation(format!(
            "selected image {}..{:#x} exceeds the {} byte input",
            input.image.container_offset.to_hex(),
            end,
            input.source_bytes.len()
        )));
    }
    Ok(())
}

fn write_initial_content(conn: &Connection, input: &CreateInput) -> DbResult<()> {
    let source_digest = sha256(&input.source_bytes);
    conn.execute(
        "INSERT INTO database_meta (id, uuid, revision, engine_fingerprint, created_at)
         VALUES (1, ?1, 0, ?2, ?3)",
        rusqlite::params![
            uuid::Uuid::new_v4().to_string(),
            &input.engine_fingerprint[..],
            now()
        ],
    )?;
    conn.execute(
        "INSERT INTO sources (id, original_path, original_size, sha256, container_kind)
         VALUES (1, ?1, ?2, ?3, ?4)",
        rusqlite::params![
            input.original_path.to_string_lossy(),
            input.source_bytes.len() as i64,
            &source_digest[..],
            input.container_kind.as_str()
        ],
    )?;

    {
        let mut statement = conn.prepare(
            "INSERT INTO source_chunks (source_id, offset, length, bytes, sha256)
             VALUES (1, ?1, ?2, ?3, ?4)",
        )?;
        for (index, chunk) in input.source_bytes.chunks(SOURCE_CHUNK_SIZE).enumerate() {
            let offset = FileOffset((index * SOURCE_CHUNK_SIZE) as u64);
            statement.execute(rusqlite::params![
                &offset.to_blob()[..],
                chunk.len() as i64,
                chunk,
                &sha256(chunk)[..]
            ])?;
        }
    }

    let image = &input.image;
    let abi_json = serde_json::to_string(&image.abi)
        .map_err(|error| DbError::Validation(format!("abi: {error}")))?;
    conn.execute(
        "INSERT INTO images (id, source_id, selector_json, format, architecture, bitness,
                             endianness, abi_json, entry_address, layout_fingerprint,
                             layout_fingerprint_version, container_offset, container_length,
                             member_name, member_index, slice_label, max_analysis_bytes)
         VALUES (1, 1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        rusqlite::params![
            image.selector_json,
            image.format,
            image.architecture,
            image.bitness as i64,
            image.endianness,
            abi_json,
            image
                .entry_address
                .map(|address| address.to_blob().to_vec()),
            &image.layout_fingerprint[..],
            LAYOUT_FINGERPRINT_VERSION as i64,
            image.container_offset.0 as i64,
            image.container_length as i64,
            image.member_name,
            image
                .member_index
                .and_then(|value| i64::try_from(value).ok()),
            image.slice_label,
            MAX_ANALYSIS_BYTES_DEFAULT as i64,
        ],
    )?;

    insert_mappings(conn, &image.mappings)?;
    insert_sections(conn, &image.sections)?;
    insert_symbols(conn, &input.symbols)?;
    insert_strings(conn, &input.strings)?;

    {
        let mut statement = conn.prepare(
            "INSERT INTO functions (image_id, address, declared_end, bounds_origin, origin,
                                    excluded, user_removed, present)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        for function in &input.functions {
            statement.execute(rusqlite::params![
                &function.address.to_blob()[..],
                function
                    .declared_end
                    .map(|address| address.to_blob().to_vec()),
                function.bounds_origin.as_str(),
                function.origin.as_str(),
                function.excluded as i64,
                function.user_removed as i64,
                function.present as i64,
            ])?;
        }
    }

    insert_xrefs(conn, None, &input.xrefs)?;

    if let Some(json) = &input.builtin_types_json {
        conn.execute(
            "INSERT INTO resources (image_id, kind, logical_name, content_sha256, payload)
             VALUES (1, 'type_snapshot', 'builtin', ?1, ?2)",
            rusqlite::params![&sha256(json.as_bytes())[..], json.as_bytes()],
        )?;
    }

    // A non-empty initial policy is part of the created project, not a user
    // edit: it lands at revision 0 with an empty undo stack. An empty policy
    // writes no row at all, which reads back as the empty scope.
    if !input.analysis_scope.is_empty() {
        input.analysis_scope.validate()?;
        let payload = serde_json::to_string(&input.analysis_scope)
            .map_err(|error| DbError::Validation(format!("analysis scope payload: {error}")))?;
        conn.execute(
            "INSERT INTO resources (image_id, kind, logical_name, content_sha256, payload)
             VALUES (1, ?1, ?2, ?3, ?4)",
            rusqlite::params![
                ANALYSIS_SCOPE_RESOURCE_KIND,
                ANALYSIS_SCOPE_RESOURCE_NAME,
                &sha256(payload.as_bytes())[..],
                payload.as_bytes()
            ],
        )?;
    }

    if !input.diagnostics.is_empty() {
        let json = serde_json::to_string(&input.diagnostics)
            .map_err(|error| DbError::Validation(format!("diagnostics: {error}")))?;
        conn.execute(
            "UPDATE analysis_units SET diagnostics_json = ?1
             WHERE image_id = 1 AND owner_kind = 'image_index'",
            rusqlite::params![json],
        )?;
    }

    conn.execute(
        "INSERT INTO history_head (id, edit_id, redo_ids_json) VALUES (1, NULL, '[]')",
        [],
    )?;

    Ok(())
}

fn insert_mappings(conn: &Connection, mappings: &[MappingInfo]) -> DbResult<()> {
    let mut statement = conn.prepare(
        "INSERT INTO mappings (image_id, name, va, memory_size, file_offset, file_size,
                               permissions, origin)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?;
    for mapping in mappings {
        statement.execute(rusqlite::params![
            mapping.name,
            &mapping.va.to_blob()[..],
            mapping.memory_size as i64,
            mapping.file_offset.map(|offset| offset.to_blob().to_vec()),
            mapping.file_size as i64,
            mapping.permissions.as_str(),
            mapping.origin,
        ])?;
    }
    Ok(())
}

fn insert_sections(conn: &Connection, sections: &[SectionInfo]) -> DbResult<()> {
    let mut statement = conn.prepare(
        "INSERT INTO sections (image_id, name, va, memory_size, file_offset, file_size, flags)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
    )?;
    for section in sections {
        statement.execute(rusqlite::params![
            section.name,
            &section.va.to_blob()[..],
            section.memory_size as i64,
            section.file_offset.map(|offset| offset.to_blob().to_vec()),
            section.file_size as i64,
            section.flags,
        ])?;
    }
    Ok(())
}

fn insert_symbols(conn: &Connection, symbols: &[SymbolInfo]) -> DbResult<()> {
    let mut statement = conn.prepare(
        "INSERT OR IGNORE INTO symbols (image_id, address, name, kind, size, origin)
         VALUES (1, ?1, ?2, ?3, ?4, ?5)",
    )?;
    for symbol in symbols {
        statement.execute(rusqlite::params![
            &symbol.address.to_blob()[..],
            symbol.name,
            symbol.kind,
            symbol.size as i64,
            symbol.origin.as_str(),
        ])?;
    }
    Ok(())
}

fn insert_strings(conn: &Connection, strings: &[StringRow]) -> DbResult<()> {
    let mut statement = conn.prepare(
        "INSERT OR REPLACE INTO strings (image_id, address, encoding, byte_length, bytes, decoded_text)
         VALUES (1, ?1, ?2, ?3, ?4, ?5)",
    )?;
    for string in strings {
        if string.bytes.len() > MAX_PAYLOAD_BYTES {
            continue;
        }
        statement.execute(rusqlite::params![
            &string.address.to_blob()[..],
            string.encoding.as_str(),
            string.bytes.len() as i64,
            &string.bytes[..],
            string.text,
        ])?;
    }
    Ok(())
}

fn insert_xrefs(conn: &Connection, owner: Option<Address>, xrefs: &[XrefRow]) -> DbResult<()> {
    if xrefs.is_empty() {
        return Ok(());
    }
    let mut statement = conn.prepare(
        "INSERT OR IGNORE INTO xrefs (image_id, from_address, to_address, kind, owner_function, origin)
         VALUES (1, ?1, ?2, ?3, ?4, ?5)",
    )?;
    for xref in xrefs {
        statement.execute(rusqlite::params![
            &xref.from.to_blob()[..],
            &xref.to.to_blob()[..],
            xref.kind.as_str(),
            owner
                .or(xref.owner)
                .map(|address| address.to_blob().to_vec()),
            xref.origin.as_str(),
        ])?;
    }
    Ok(())
}

fn read_revision(conn: &Connection) -> DbResult<Revision> {
    let revision: i64 = conn.query_row(
        "SELECT revision FROM database_meta WHERE id = 1",
        [],
        |row| row.get(0),
    )?;
    let revision = u64::try_from(revision)
        .map_err(|_| DbError::Corrupt("negative content revision".into()))?;
    Ok(Revision(revision))
}

fn read_engine_fingerprint(conn: &Connection) -> DbResult<[u8; 32]> {
    let blob: Vec<u8> = conn.query_row(
        "SELECT engine_fingerprint FROM database_meta WHERE id = 1",
        [],
        |row| row.get(0),
    )?;
    if blob.len() != 32 {
        return Err(DbError::Corrupt(
            "engine fingerprint is not 32 bytes".into(),
        ));
    }
    Ok(blob32(blob))
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn blob32(bytes: Vec<u8>) -> [u8; 32] {
    let mut out = [0u8; 32];
    if bytes.len() == 32 {
        out.copy_from_slice(&bytes);
    }
    out
}

fn read_function_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FunctionRow> {
    let declared_end: Option<Vec<u8>> = row.get(1)?;
    Ok(FunctionRow {
        address: Address::from_blob(&row.get::<_, Vec<u8>>(0)?).unwrap_or(Address(0)),
        declared_end: declared_end
            .as_deref()
            .map(Address::from_blob)
            .transpose()
            .ok()
            .flatten(),
        bounds_origin: BoundsOrigin::parse(&row.get::<_, String>(2)?)
            .unwrap_or(BoundsOrigin::Heuristic),
        origin: FunctionOrigin::parse(&row.get::<_, String>(3)?).unwrap_or(FunctionOrigin::Auto),
        excluded: row.get::<_, i64>(4)? != 0,
        user_removed: row.get::<_, i64>(5)? != 0,
        present: row.get::<_, i64>(6)? != 0,
    })
}

fn read_xref_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<XrefRow> {
    let owner: Option<Vec<u8>> = row.get(3)?;
    Ok(XrefRow {
        from: Address::from_blob(&row.get::<_, Vec<u8>>(0)?).unwrap_or(Address(0)),
        to: Address::from_blob(&row.get::<_, Vec<u8>>(1)?).unwrap_or(Address(0)),
        kind: XrefKind::parse(&row.get::<_, String>(2)?).unwrap_or(XrefKind::Data),
        owner: owner
            .as_deref()
            .map(Address::from_blob)
            .transpose()
            .ok()
            .flatten(),
        origin: match row.get::<_, String>(4)?.as_str() {
            "user" => XrefOrigin::User,
            _ => XrefOrigin::Auto,
        },
    })
}

fn read_symbol_row(row: &rusqlite::Row<'_>) -> DbResult<SymbolInfo> {
    let origin: String = row.get(4)?;
    Ok(SymbolInfo {
        address: Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?,
        name: row.get(1)?,
        kind: row.get(2)?,
        size: u64::try_from(row.get::<_, i64>(3)?).unwrap_or(0),
        origin: SymbolOrigin::parse(&origin).unwrap_or(SymbolOrigin::Loader),
    })
}

fn read_string_row(row: &rusqlite::Row<'_>) -> DbResult<StringRow> {
    let encoding: String = row.get(1)?;
    Ok(StringRow {
        address: Address::from_blob(&row.get::<_, Vec<u8>>(0)?)?,
        encoding: StringEncoding::parse(&encoding).unwrap_or(StringEncoding::Ascii),
        bytes: row.get(2)?,
        text: row.get(3)?,
    })
}

fn read_type_row(row: &rusqlite::Row<'_>) -> DbResult<TypeRow> {
    Ok(TypeRow {
        name: row.get(0)?,
        kind: TypeKind::parse(&row.get::<_, String>(1)?).unwrap_or(TypeKind::Struct),
        payload_version: u32::try_from(row.get::<_, i64>(2)?).unwrap_or(PAYLOAD_VERSION),
        payload_json: row.get(3)?,
        origin: row.get(4)?,
    })
}

/// Read and validate the stored analysis-scope resource.
///
/// A missing or empty row is the empty scope. Decoding follows the same rules
/// as the edit path: an unreadable payload is `Corrupt`, an unsupported
/// payload version is a validation error, and neither is a panic.
fn read_stored_scope(conn: &Connection) -> DbResult<AnalysisScope> {
    let payload: Option<Vec<u8>> = conn
        .query_row(
            "SELECT payload FROM resources WHERE image_id = 1 AND kind = ?1 AND logical_name = ?2",
            rusqlite::params![ANALYSIS_SCOPE_RESOURCE_KIND, ANALYSIS_SCOPE_RESOURCE_NAME],
            |row| row.get(0),
        )
        .optional()?;
    match payload {
        None => Ok(AnalysisScope::empty()),
        Some(bytes) if bytes.is_empty() => Ok(AnalysisScope::empty()),
        Some(bytes) => {
            let scope: AnalysisScope = serde_json::from_slice(&bytes).map_err(|error| {
                DbError::Corrupt(format!("stored analysis scope is unreadable: {error}"))
            })?;
            scope.validate()?;
            Ok(scope)
        }
    }
}

/// Split a caller-supplied address list into disjoint, sorted groups of at
/// most [`MAX_ADDRESS_CHUNK`] values.
///
/// Deduplicating first keeps an address out of two groups, so a chunked `IN`
/// query can never return one row twice.
fn address_chunks(addresses: &[Address]) -> Vec<Vec<Address>> {
    let unique: BTreeSet<Address> = addresses.iter().copied().collect();
    let values: Vec<Address> = unique.into_iter().collect();
    values
        .chunks(MAX_ADDRESS_CHUNK)
        .map(|chunk| chunk.to_vec())
        .collect()
}

/// Split a caller-supplied unit-key list into disjoint, sorted groups of at
/// most [`MAX_ADDRESS_CHUNK`] keys.
fn unit_key_chunks(keys: &[UnitKey]) -> Vec<Vec<UnitKey>> {
    let unique: BTreeSet<UnitKey> = keys.iter().copied().collect();
    let values: Vec<UnitKey> = unique.into_iter().collect();
    values
        .chunks(MAX_ADDRESS_CHUNK)
        .map(|chunk| chunk.to_vec())
        .collect()
}

/// `(?1, ?2, ?3), (?4, ?5, ?6), ...` for one row-value group per unit key.
fn unit_key_placeholders(count: usize) -> String {
    let mut sql = String::new();
    for group in 0..count {
        if group > 0 {
            sql.push_str(", ");
        }
        let base = group * 3;
        sql.push_str(&format!("(?{}, ?{}, ?{})", base + 1, base + 2, base + 3));
    }
    sql
}

/// `?1, ?2, ...` for a statement with `count` bound values.
fn placeholders(count: usize) -> String {
    let mut sql = String::new();
    for index in 1..=count {
        if index > 1 {
            sql.push_str(", ");
        }
        sql.push('?');
        sql.push_str(&index.to_string());
    }
    sql
}

/// Clamp a page window into the SQLite integer range. `LIMIT 0` stays 0.
fn page_bound(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Create a private temporary directory next to `parent` so staging and
/// publication stay on one filesystem.
fn tempfile_dir(parent: &Path) -> DbResult<tempfile::TempDir> {
    tempfile::Builder::new()
        .prefix(".hexray-staging-")
        .tempdir_in(parent)
        .map_err(DbError::Io)
}

fn parent_directory(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Publish `staged` at `destination`, failing if the destination exists.
fn publish_no_clobber(staged: &Path, destination: &Path) -> DbResult<()> {
    if destination.exists() {
        return Err(DbError::Validation(format!(
            "destination already exists: {}",
            destination.display()
        )));
    }
    match std::fs::hard_link(staged, destination) {
        Ok(()) => {
            let _ = std::fs::remove_file(staged);
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(DbError::Validation(format!(
                "destination already exists: {}",
                destination.display()
            )))
        }
        Err(_) => {
            // Filesystems without hard links (some network mounts): fall back
            // to rename after re-checking, which is still no-clobber for the
            // common case because the target was absent a moment ago.
            if destination.exists() {
                return Err(DbError::Validation(format!(
                    "destination already exists: {}",
                    destination.display()
                )));
            }
            std::fs::rename(staged, destination).map_err(DbError::Io)
        }
    }
}

// ---------------------------------------------------------------------------
// Transaction work
// ---------------------------------------------------------------------------

fn apply_in_transaction(
    tx: &mut Transaction<'_>,
    expected: Revision,
    edit: &Edit,
    actor: &str,
) -> DbResult<EditOutcome> {
    let current = read_revision(tx)?;
    if current != expected {
        return Err(DbError::RevisionConflict {
            expected: expected.0,
            actual: current.0,
        });
    }

    let outcome = edit::apply(tx, edit)?;
    if !outcome.changed {
        return Ok(EditOutcome::Unchanged(current));
    }

    let revision = current.next()?;
    edit::invalidate(tx, edit, revision)?;
    let parent: Option<i64> =
        tx.query_row("SELECT edit_id FROM history_head WHERE id = 1", [], |row| {
            row.get(0)
        })?;
    let forward = serde_json::to_string(edit)
        .map_err(|error| DbError::Validation(format!("edit payload: {error}")))?;
    let inverse = serde_json::to_string(&outcome.inverse)
        .map_err(|error| DbError::Validation(format!("inverse payload: {error}")))?;
    tx.execute(
        "INSERT INTO edit_log (parent_id, kind, forward_json, inverse_json,
                               committed_revision, actor, timestamp)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            parent,
            edit.kind(),
            forward,
            inverse,
            revision.0 as i64,
            actor,
            now()
        ],
    )?;
    let edit_id = tx.last_insert_rowid();
    tx.execute(
        "UPDATE history_head SET edit_id = ?1, redo_ids_json = '[]' WHERE id = 1",
        rusqlite::params![edit_id],
    )?;
    tx.execute(
        "UPDATE database_meta SET revision = ?1 WHERE id = 1",
        rusqlite::params![revision.0 as i64],
    )?;
    tx.execute(
        "INSERT INTO history_events (action, edit_id, revision, actor, timestamp)
         VALUES ('apply', ?1, ?2, ?3, ?4)",
        rusqlite::params![edit_id, revision.0 as i64, actor, now()],
    )?;
    enforce_history_budget(tx)?;
    Ok(EditOutcome::Applied(revision))
}

fn undo_in_transaction(
    tx: &mut Transaction<'_>,
    expected: Revision,
    actor: &str,
) -> DbResult<EditOutcome> {
    let current = read_revision(tx)?;
    if current != expected {
        return Err(DbError::RevisionConflict {
            expected: expected.0,
            actual: current.0,
        });
    }
    let head: Option<i64> =
        tx.query_row("SELECT edit_id FROM history_head WHERE id = 1", [], |row| {
            row.get(0)
        })?;
    let Some(edit_id) = head else {
        return Err(DbError::NothingToUndo);
    };

    let (parent, forward_json, inverse_json): (Option<i64>, String, String) = tx.query_row(
        "SELECT parent_id, forward_json, inverse_json FROM edit_log WHERE id = ?1",
        rusqlite::params![edit_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let forward: Edit = serde_json::from_str(&forward_json)
        .map_err(|error| DbError::Corrupt(format!("edit log row {edit_id}: {error}")))?;
    let inverse: Vec<InverseOp> = serde_json::from_str(&inverse_json)
        .map_err(|error| DbError::Corrupt(format!("inverse log row {edit_id}: {error}")))?;

    let revision = current.next()?;
    edit::apply_inverse(tx, &inverse)?;
    edit::invalidate(tx, &forward, revision)?;

    let mut redo: Vec<u64> = serde_json::from_str(&read_redo_ids(tx)?).unwrap_or_default();
    redo.push(u64::try_from(edit_id).unwrap_or(0));
    tx.execute(
        "UPDATE history_head SET edit_id = ?1, redo_ids_json = ?2 WHERE id = 1",
        rusqlite::params![
            parent,
            serde_json::to_string(&redo).unwrap_or_else(|_| "[]".into())
        ],
    )?;
    tx.execute(
        "UPDATE database_meta SET revision = ?1 WHERE id = 1",
        rusqlite::params![revision.0 as i64],
    )?;
    tx.execute(
        "INSERT INTO history_events (action, edit_id, revision, actor, timestamp)
         VALUES ('undo', ?1, ?2, ?3, ?4)",
        rusqlite::params![edit_id, revision.0 as i64, actor, now()],
    )?;
    Ok(EditOutcome::Applied(revision))
}

fn redo_in_transaction(
    tx: &mut Transaction<'_>,
    expected: Revision,
    actor: &str,
) -> DbResult<EditOutcome> {
    let current = read_revision(tx)?;
    if current != expected {
        return Err(DbError::RevisionConflict {
            expected: expected.0,
            actual: current.0,
        });
    }
    let mut redo: Vec<u64> = serde_json::from_str(&read_redo_ids(tx)?).unwrap_or_default();
    let Some(edit_id) = redo.pop() else {
        return Err(DbError::NothingToRedo);
    };
    let forward_json: String = tx.query_row(
        "SELECT forward_json FROM edit_log WHERE id = ?1",
        rusqlite::params![edit_id as i64],
        |row| row.get(0),
    )?;
    let forward: Edit = serde_json::from_str(&forward_json)
        .map_err(|error| DbError::Corrupt(format!("edit log row {edit_id}: {error}")))?;

    let revision = current.next()?;
    let outcome = edit::apply(tx, &forward)?;
    if outcome.changed {
        edit::invalidate(tx, &forward, revision)?;
    }
    // Refresh the inverse so a re-applied edit reflects the state it was
    // actually applied to.
    let inverse = serde_json::to_string(&outcome.inverse)
        .map_err(|error| DbError::Validation(format!("inverse payload: {error}")))?;
    tx.execute(
        "UPDATE edit_log SET inverse_json = ?1 WHERE id = ?2",
        rusqlite::params![inverse, edit_id as i64],
    )?;
    tx.execute(
        "UPDATE history_head SET edit_id = ?1, redo_ids_json = ?2 WHERE id = 1",
        rusqlite::params![
            edit_id as i64,
            serde_json::to_string(&redo).unwrap_or_else(|_| "[]".into())
        ],
    )?;
    tx.execute(
        "UPDATE database_meta SET revision = ?1 WHERE id = 1",
        rusqlite::params![revision.0 as i64],
    )?;
    tx.execute(
        "INSERT INTO history_events (action, edit_id, revision, actor, timestamp)
         VALUES ('redo', ?1, ?2, ?3, ?4)",
        rusqlite::params![edit_id as i64, revision.0 as i64, actor, now()],
    )?;
    Ok(EditOutcome::Applied(revision))
}

fn read_redo_ids(tx: &Transaction<'_>) -> DbResult<String> {
    Ok(tx.query_row(
        "SELECT redo_ids_json FROM history_head WHERE id = 1",
        [],
        |row| row.get(0),
    )?)
}

fn enforce_history_budget(tx: &Transaction<'_>) -> DbResult<()> {
    let count: i64 = tx.query_row("SELECT COUNT(*) FROM edit_log", [], |row| row.get(0))?;
    if u64::try_from(count).unwrap_or(0) >= MAX_HISTORY_ENTRIES {
        return Err(DbError::ResourceLimit(format!(
            "edit history holds {count} entries; the limit is {MAX_HISTORY_ENTRIES}"
        )));
    }
    let bytes: i64 = tx.query_row(
        "SELECT COALESCE(SUM(LENGTH(forward_json) + LENGTH(inverse_json)), 0) FROM edit_log",
        [],
        |row| row.get(0),
    )?;
    if u64::try_from(bytes).unwrap_or(0) >= 1024 * 1024 * 1024 {
        return Err(DbError::ResourceLimit(
            "edit history exceeds the 1 GiB budget".into(),
        ));
    }
    Ok(())
}

fn publish_unit(
    tx: &Transaction<'_>,
    unit: &UnitPublish,
    orphan_candidates: &mut BTreeSet<Address>,
) -> DbResult<()> {
    if unit.payload.owner() != unit.key.owner {
        return Err(DbError::Validation(format!(
            "unit {} carries a {} payload",
            unit.key.describe(),
            unit.payload.owner().as_str()
        )));
    }

    let current: Option<i64> = tx
        .query_row(
            "SELECT generation FROM analysis_units
             WHERE image_id = 1 AND owner_kind = ?1 AND owner_key = ?2 AND config_fingerprint = ?3",
            rusqlite::params![
                unit.key.owner.as_str(),
                &unit.key.key.to_blob()[..],
                &unit.key.config[..]
            ],
            |row| row.get(0),
        )
        .optional()?;

    let actual = current.and_then(|value| u64::try_from(value).ok());
    if actual != unit.expected_generation {
        return Err(DbError::AnalysisGenerationConflict {
            owner: unit.key.describe(),
            expected: unit.expected_generation.unwrap_or(0),
            actual,
        });
    }

    let generation = actual.unwrap_or(0).saturating_add(1);
    let diagnostics = if unit.diagnostics.is_empty() {
        None
    } else {
        Some(
            serde_json::to_string(&unit.diagnostics)
                .map_err(|error| DbError::Validation(format!("diagnostics: {error}")))?,
        )
    };

    let engine = read_engine_fingerprint(tx)?;
    tx.execute(
        "INSERT INTO analysis_units
            (image_id, owner_kind, owner_key, config_fingerprint, generation,
             input_fingerprint, engine_fingerprint, state, diagnostics_json, dependencies_complete)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT (image_id, owner_kind, owner_key, config_fingerprint) DO UPDATE SET
            generation = excluded.generation,
            input_fingerprint = excluded.input_fingerprint,
            engine_fingerprint = excluded.engine_fingerprint,
            state = excluded.state,
            diagnostics_json = excluded.diagnostics_json,
            dependencies_complete = excluded.dependencies_complete",
        rusqlite::params![
            unit.key.owner.as_str(),
            &unit.key.key.to_blob()[..],
            &unit.key.config[..],
            generation as i64,
            &unit.input_fingerprint[..],
            &engine[..],
            unit.state.as_str(),
            diagnostics,
            unit.dependencies_complete as i64,
        ],
    )?;

    tx.execute(
        "DELETE FROM analysis_dependencies
         WHERE image_id = 1 AND owner_kind = ?1 AND owner_key = ?2 AND config_fingerprint = ?3",
        rusqlite::params![
            unit.key.owner.as_str(),
            &unit.key.key.to_blob()[..],
            &unit.key.config[..]
        ],
    )?;
    if !unit.dependencies.is_empty() {
        let mut statement = tx.prepare(
            "INSERT OR REPLACE INTO analysis_dependencies
                (image_id, owner_kind, owner_key, config_fingerprint, dependency_kind,
                 dependency_key, range_start, range_length, target_generation)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?;
        for dependency in &unit.dependencies {
            let (start, length) = match dependency.range {
                Some(range) => (range.start.to_blob(), range.len as i64),
                None => ([0u8; 8], 0),
            };
            statement.execute(rusqlite::params![
                unit.key.owner.as_str(),
                &unit.key.key.to_blob()[..],
                &unit.key.config[..],
                dependency.kind.as_str(),
                dependency.key,
                &start[..],
                length,
                dependency.target_generation as i64,
            ])?;
        }
    }

    match &unit.payload {
        AnalysisPayload::ImageIndex(payload) => publish_image_index(tx, payload, generation)?,
        AnalysisPayload::FunctionCfg(payload) => {
            publish_function_cfg(tx, payload, orphan_candidates)?;
        }
        AnalysisPayload::FunctionRender(payload) => {
            publish_render(tx, payload, generation, unit.state)?;
        }
    }
    Ok(())
}

fn publish_image_index(
    tx: &Transaction<'_>,
    payload: &ImageIndexPayload,
    generation: u64,
) -> DbResult<()> {
    tx.execute("DELETE FROM symbols WHERE image_id = 1", [])?;
    insert_symbols(tx, &payload.symbols)?;

    tx.execute("DELETE FROM strings WHERE image_id = 1", [])?;
    insert_strings(tx, &payload.strings)?;

    tx.execute(
        "DELETE FROM xrefs WHERE image_id = 1 AND owner_function IS NULL",
        [],
    )?;
    insert_xrefs(tx, None, &payload.xrefs)?;

    // Auto functions that discovery no longer reports are marked absent, not
    // deleted: user overrides on them must survive.
    tx.execute(
        "UPDATE functions SET present = 0 WHERE image_id = 1 AND origin = 'auto'",
        [],
    )?;
    let mut statement = tx.prepare(
        "INSERT INTO functions (image_id, address, declared_end, bounds_origin, origin,
                                excluded, user_removed, present)
         VALUES (1, ?1, ?2, ?3, 'auto', ?4, 0, 1)
         ON CONFLICT (image_id, address) DO UPDATE SET
            present = 1,
            declared_end = CASE WHEN functions.origin = 'user' THEN functions.declared_end
                                ELSE excluded.declared_end END,
            bounds_origin = CASE WHEN functions.origin = 'user' THEN functions.bounds_origin
                                 ELSE excluded.bounds_origin END,
            excluded = CASE WHEN functions.user_removed = 1 THEN functions.excluded
                            ELSE excluded.excluded END",
    )?;
    for function in &payload.functions {
        statement.execute(rusqlite::params![
            &function.address.to_blob()[..],
            function
                .declared_end
                .map(|address| address.to_blob().to_vec()),
            function.bounds_origin.as_str(),
            function.excluded as i64,
        ])?;
    }
    drop(statement);

    // Index generation is recorded on the image row snapshot for diagnostics.
    let _ = generation;
    Ok(())
}

fn publish_function_cfg(
    tx: &Transaction<'_>,
    payload: &FunctionCfgPayload,
    orphan_candidates: &mut BTreeSet<Address>,
) -> DbResult<()> {
    let function = &payload.function;
    tx.execute(
        "INSERT INTO functions (image_id, address, declared_end, bounds_origin, origin,
                                excluded, user_removed, present)
         VALUES (1, ?1, ?2, ?3, 'auto', 0, 0, 1)
         ON CONFLICT (image_id, address) DO UPDATE SET
            present = 1,
            declared_end = CASE WHEN functions.origin = 'user' THEN functions.declared_end
                                ELSE excluded.declared_end END,
            bounds_origin = CASE WHEN functions.origin = 'user' THEN functions.bounds_origin
                                 ELSE excluded.bounds_origin END",
        rusqlite::params![
            &function.address.to_blob()[..],
            function
                .declared_end
                .map(|address| address.to_blob().to_vec()),
            function.bounds_origin.as_str(),
        ],
    )?;

    let function_blob = function.address.to_blob();
    // Only addresses this function stops owning can become orphans; the sweep
    // itself stays global because another owner may still reference them.
    let mut statement = tx.prepare(
        "SELECT instruction_address FROM function_instructions
         WHERE image_id = 1 AND function_address = ?1",
    )?;
    let old_blobs: Vec<Vec<u8>> = statement
        .query_map(rusqlite::params![&function_blob[..]], |row| row.get(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    let new_addresses: BTreeSet<Address> = payload
        .instructions
        .iter()
        .map(|instruction| Address(instruction.address))
        .collect();
    orphan_candidates.extend(
        old_blobs
            .iter()
            .filter_map(|blob| Address::from_blob(blob).ok())
            .filter(|address| !new_addresses.contains(address)),
    );
    tx.execute(
        "DELETE FROM function_instructions WHERE image_id = 1 AND function_address = ?1",
        rusqlite::params![&function_blob[..]],
    )?;
    tx.execute(
        "DELETE FROM basic_blocks WHERE image_id = 1 AND function_address = ?1",
        rusqlite::params![&function_blob[..]],
    )?;
    tx.execute(
        "DELETE FROM cfg_edges WHERE image_id = 1 AND function_address = ?1",
        rusqlite::params![&function_blob[..]],
    )?;
    tx.execute(
        "DELETE FROM xrefs WHERE image_id = 1 AND owner_function = ?1",
        rusqlite::params![&function_blob[..]],
    )?;

    {
        let mut statement = tx.prepare(
            "INSERT INTO instructions (image_id, address, size, payload_version, payload_json)
             VALUES (1, ?1, ?2, ?3, ?4)
             ON CONFLICT (image_id, address) DO UPDATE SET
                size = excluded.size,
                payload_version = excluded.payload_version,
                payload_json = excluded.payload_json",
        )?;
        let mut order = tx.prepare(
            "INSERT OR REPLACE INTO function_instructions
                (image_id, function_address, instruction_address, ordinal)
             VALUES (1, ?1, ?2, ?3)",
        )?;
        for (ordinal, instruction) in payload.instructions.iter().enumerate() {
            let json = serde_json::to_string(instruction)
                .map_err(|error| DbError::Validation(format!("instruction payload: {error}")))?;
            if json.len() > MAX_PAYLOAD_BYTES {
                return Err(DbError::ResourceLimit(
                    "instruction payload exceeds the size limit".into(),
                ));
            }
            statement.execute(rusqlite::params![
                &instruction.address.to_be_bytes()[..],
                instruction.size as i64,
                PAYLOAD_VERSION as i64,
                json
            ])?;
            order.execute(rusqlite::params![
                &function_blob[..],
                &instruction.address.to_be_bytes()[..],
                ordinal as i64
            ])?;
        }
    }

    {
        let mut block_statement = tx.prepare(
            "INSERT INTO basic_blocks (image_id, function_address, block_id,
                                       payload_version, payload_json)
             VALUES (1, ?1, ?2, ?3, ?4)",
        )?;
        for block in &payload.blocks {
            let json = serde_json::to_string(block)
                .map_err(|error| DbError::Validation(format!("block payload: {error}")))?;
            block_statement.execute(rusqlite::params![
                &function_blob[..],
                block.id as i64,
                PAYLOAD_VERSION as i64,
                json
            ])?;
        }
    }

    {
        let mut statement = tx.prepare(
            "INSERT OR REPLACE INTO block_instructions
                (image_id, function_address, block_id, instruction_address, ordinal)
             VALUES (1, ?1, ?2, ?3, ?4)",
        )?;
        for (block_id, addresses) in &payload.block_instructions {
            for (ordinal, address) in addresses.iter().enumerate() {
                statement.execute(rusqlite::params![
                    &function_blob[..],
                    *block_id as i64,
                    &address.to_blob()[..],
                    ordinal as i64
                ])?;
            }
        }
    }

    {
        // OR REPLACE, like `block_instructions` and `xrefs`: the edges are a
        // *set* keyed by (function, from, to, kind). A CFG can legitimately
        // carry the same transfer twice (a conditional branch whose target is
        // its fallthrough), and a duplicate row must not abort the whole
        // publish transaction — it simply describes one edge.
        let mut statement = tx.prepare(
            "INSERT OR REPLACE INTO cfg_edges (image_id, function_address, from_block, to_block, kind)
             VALUES (1, ?1, ?2, ?3, ?4)",
        )?;
        for (from, to, kind) in &payload.edges {
            statement.execute(rusqlite::params![
                &function_blob[..],
                *from as i64,
                *to as i64,
                kind.as_str()
            ])?;
        }
    }

    insert_xrefs(tx, Some(payload.function.address), &payload.xrefs)?;
    Ok(())
}

/// Drop instructions that no function references any more.
///
/// Called once per batch from [`Database::publish`], inside the same
/// transaction, when some republished function dropped ownership of an
/// instruction. The statement itself stays global so a shared tail
/// instruction is only an orphan once its last owner relationship is gone.
fn sweep_orphan_instructions(tx: &Transaction<'_>) -> DbResult<()> {
    tx.execute(
        "DELETE FROM instructions
         WHERE image_id = 1
           AND address NOT IN (SELECT instruction_address FROM function_instructions WHERE image_id = 1)",
        [],
    )?;
    Ok(())
}

fn publish_render(
    tx: &Transaction<'_>,
    payload: &RenderPayload,
    generation: u64,
    state: AnalysisState,
) -> DbResult<()> {
    if state == AnalysisState::Unsupported || state == AnalysisState::Failed {
        tx.execute(
            "DELETE FROM decompiled WHERE image_id = 1 AND function_address = ?1 AND config_fingerprint = ?2",
            rusqlite::params![&payload.function.to_blob()[..], &payload.config_fingerprint[..]],
        )?;
        return Ok(());
    }
    if payload.text.len() > MAX_PAYLOAD_BYTES {
        return Err(DbError::ResourceLimit(
            "rendered pseudo-C exceeds the payload limit".into(),
        ));
    }
    tx.execute(
        "INSERT INTO functions (image_id, address, declared_end, bounds_origin, origin,
                                excluded, user_removed, present)
         VALUES (1, ?1, NULL, 'heuristic', 'auto', 0, 0, 1)
         ON CONFLICT (image_id, address) DO UPDATE SET present = 1",
        rusqlite::params![&payload.function.to_blob()[..]],
    )?;
    tx.execute(
        "INSERT INTO decompiled (image_id, function_address, config_fingerprint, generation,
                                 payload_version, text)
         VALUES (1, ?1, ?2, ?3, ?4, ?5)
         ON CONFLICT (image_id, function_address, config_fingerprint) DO UPDATE SET
            generation = excluded.generation,
            payload_version = excluded.payload_version,
            text = excluded.text",
        rusqlite::params![
            &payload.function.to_blob()[..],
            &payload.config_fingerprint[..],
            generation as i64,
            PAYLOAD_VERSION as i64,
            payload.text
        ],
    )?;
    Ok(())
}

fn verify_source_digest(conn: &Connection, problems: &mut Vec<String>) -> DbResult<bool> {
    let expected: Vec<u8> =
        conn.query_row("SELECT sha256 FROM sources WHERE id = 1", [], |row| {
            row.get(0)
        })?;
    let mut statement = conn.prepare(
        "SELECT offset, bytes, sha256 FROM source_chunks WHERE source_id = 1 ORDER BY offset",
    )?;
    let mut rows = statement.query([])?;
    let mut all = Vec::new();
    let mut ok = true;
    while let Some(row) = rows.next()? {
        let offset = FileOffset::from_blob(&row.get::<_, Vec<u8>>(0)?)?;
        let bytes: Vec<u8> = row.get(1)?;
        let stored = blob32(row.get(2)?);
        if sha256(&bytes) != stored {
            problems.push(format!("chunk at {} fails its digest", offset.to_hex()));
            ok = false;
        }
        all.extend_from_slice(&bytes);
    }
    if sha256(&all) != blob32(expected) {
        problems.push("reassembled source does not match the stored digest".into());
        ok = false;
    }
    Ok(ok)
}

fn verify_patch_ranges(conn: &Connection, problems: &mut Vec<String>) -> DbResult<bool> {
    let size: i64 = conn.query_row(
        "SELECT original_size FROM sources WHERE id = 1",
        [],
        |row| row.get(0),
    )?;
    let size = u64::try_from(size).unwrap_or(0);
    let mut statement =
        conn.prepare("SELECT file_offset, bytes FROM patches ORDER BY file_offset")?;
    let mut rows = statement.query([])?;
    let mut ok = true;
    let mut previous_end = 0u64;
    while let Some(row) = rows.next()? {
        let offset = FileOffset::from_blob(&row.get::<_, Vec<u8>>(0)?)?;
        let bytes: Vec<u8> = row.get(1)?;
        let end = match offset.checked_end(bytes.len() as u64) {
            Ok(end) => end,
            Err(_) => {
                problems.push(format!("patch at {} overflows", offset.to_hex()));
                ok = false;
                continue;
            }
        };
        if end > size {
            problems.push(format!(
                "patch at {} ends at {end:#x}, beyond the source size",
                offset.to_hex()
            ));
            ok = false;
        }
        if offset.0 < previous_end {
            problems.push(format!("patches overlap at {}", offset.to_hex()));
            ok = false;
        }
        previous_end = end;
    }
    Ok(ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staging_directory_is_private() {
        let parent = tempfile::tempdir().unwrap();
        let staging = tempfile_dir(parent.path()).unwrap();
        assert!(staging.path().starts_with(parent.path()));
    }

    #[test]
    fn no_clobber_refuses_existing_destination() {
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("staged");
        std::fs::write(&staged, b"a").unwrap();
        let destination = dir.path().join("destination");
        std::fs::write(&destination, b"b").unwrap();
        assert!(publish_no_clobber(&staged, &destination).is_err());
        assert_eq!(std::fs::read(&destination).unwrap(), b"b");
    }

    #[test]
    fn no_clobber_publishes_absent_destination() {
        let dir = tempfile::tempdir().unwrap();
        let staged = dir.path().join("staged");
        std::fs::write(&staged, b"a").unwrap();
        let destination = dir.path().join("destination");
        publish_no_clobber(&staged, &destination).unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"a");
        assert!(!staged.exists());
    }

    // ------------------------------------------------------------------
    // Transaction atomicity
    //
    // The child test is `#[ignore]`d so a plain `cargo test` never blocks on
    // stdin. The parent spawns this same test binary with `--ignored
    // --exact`, hands it the database path on stdin, waits for the line the
    // child prints *after* staging the edit but *before* `COMMIT`, kills it,
    // and then checks that SQLite recovered a database with none of the
    // staged rows.
    // ------------------------------------------------------------------

    const CHILD_TEST: &str = "store::tests::crash_before_commit_child";

    fn test_input() -> CreateInput {
        let source = vec![0x90u8; 0x100];
        CreateInput {
            original_path: PathBuf::from("memory.bin"),
            source_bytes: source,
            container_kind: ContainerKind::Elf,
            image: ImageInfo {
                format: "elf".into(),
                architecture: "x86_64".into(),
                bitness: 64,
                endianness: "little".into(),
                abi: AbiInfo::lp64(),
                entry_address: Some(Address(0x1000)),
                selector_json: "{}".into(),
                container_offset: FileOffset(0),
                container_length: 0x100,
                member_name: None,
                member_index: None,
                slice_label: None,
                layout_fingerprint: [9u8; 32],
                mappings: vec![MappingInfo {
                    name: ".text".into(),
                    va: Address(0x1000),
                    memory_size: 0x100,
                    file_offset: Some(FileOffset(0)),
                    file_size: 0x100,
                    permissions: MappingPermissions {
                        read: true,
                        write: false,
                        execute: true,
                    },
                    origin: "test".into(),
                }],
                sections: Vec::new(),
            },
            engine_fingerprint: [3u8; 32],
            symbols: Vec::new(),
            functions: Vec::new(),
            strings: Vec::new(),
            xrefs: Vec::new(),
            builtin_types_json: None,
            analysis_scope: AnalysisScope::empty(),
            diagnostics: Vec::new(),
        }
    }

    /// Child process: stage an edit, announce that it is pre-commit, block,
    /// then roll back. Being killed at the blocking read is the test.
    #[test]
    #[ignore = "driven as a subprocess by crash_before_commit_rolls_back"]
    fn crash_before_commit_child() {
        use std::io::{IsTerminal, Write};

        // The parent always supplies a pipe. A human running `cargo test
        // -- --ignored` from a terminal would otherwise block on stdin.
        if std::io::stdin().is_terminal() {
            return;
        }
        let mut path = String::new();
        let read = std::io::stdin()
            .read_line(&mut path)
            .expect("read database path");
        if read == 0 {
            // Invoked directly with no parent: nothing to crash.
            return;
        }
        let path = PathBuf::from(path.trim());

        let mut database =
            Database::open(&path, OpenMode::ReadWrite).expect("child opens the project");
        let mut transaction = database
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("child begins immediate transaction");
        let revision = read_revision(&transaction).expect("child reads revision");
        let edit = Edit::SetComment {
            address: Address(0x1000),
            text: Some("staged but never committed".into()),
        };
        let outcome =
            apply_in_transaction(&mut transaction, revision, &edit, "child").expect("stage edit");
        assert!(
            matches!(outcome, EditOutcome::Applied(_)),
            "the edit must be staged inside the transaction"
        );
        // Visible to the writer, invisible everywhere else until COMMIT.
        let staged: i64 = transaction
            .query_row("SELECT COUNT(*) FROM annotations", [], |row| row.get(0))
            .expect("staged row count");
        assert_eq!(staged, 1, "the staged row exists in the open transaction");

        println!("READY_FOR_CRASH");
        std::io::stdout().flush().expect("flush ready line");

        // Blocks until the parent kills the process (a pipe EOF can also
        // release it, in which case rolling back is the safe outcome).
        let mut release = String::new();
        let _ = std::io::stdin().read_line(&mut release);
        transaction.rollback().expect("explicit rollback");
    }

    #[test]
    fn crash_before_commit_rolls_back_and_leaves_valid_state() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("atomic.hxdb");
        {
            let database = Database::create(&db_path, &test_input()).expect("create project");
            assert_eq!(database.revision().expect("revision"), Revision(0));
            assert!(database.check(true).expect("check").passed());
        }

        let mut child = std::process::Command::new(std::env::current_exe().expect("test exe"))
            .args([
                "--ignored",
                "--exact",
                CHILD_TEST,
                "--nocapture",
                "--test-threads=1",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn child test process");

        {
            use std::io::Write;
            let stdin = child.stdin.as_mut().expect("child stdin");
            writeln!(stdin, "{}", db_path.display()).expect("send database path");
            stdin.flush().expect("flush database path");
        }

        let stdout = child.stdout.take().expect("child stdout");
        // Read lines on a helper thread and bound the whole handshake with an
        // absolute deadline. A blocking `read_line` on the test thread could
        // hang the suite if the child never reaches the sentinel.
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(stdout);
            loop {
                let mut line = String::new();
                match std::io::BufRead::read_line(&mut reader, &mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if sender.send(line).is_err() {
                            break;
                        }
                    }
                }
            }
        });

        let started = std::time::Instant::now();
        let limit = std::time::Duration::from_secs(60);
        let mut saw_ready = false;
        loop {
            let remaining = match limit.checked_sub(started.elapsed()) {
                Some(remaining) if !remaining.is_zero() => remaining,
                _ => break,
            };
            match receiver.recv_timeout(remaining) {
                Ok(line) if line.contains("READY_FOR_CRASH") => {
                    saw_ready = true;
                    break;
                }
                Ok(_) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => break,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        if !saw_ready {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "the child never reached the pre-commit handshake within {limit:?} \
                 (child test name changed, or the child is stuck)"
            );
        }

        child.kill().expect("kill the child before it commits");
        let _ = child.wait();

        // Reopen: SQLite must roll the hot journal back, not leave a half
        // applied edit or a corrupt file.
        let mut database =
            Database::open(&db_path, OpenMode::ReadWrite).expect("reopen after kill");
        let report = database.check(true).expect("deep check after kill");
        assert!(
            report.passed(),
            "database failed integrity checks after the kill: {report:?}"
        );
        assert_eq!(
            database.revision().expect("revision"),
            Revision(0),
            "an uncommitted edit must not advance the revision"
        );
        assert!(
            database
                .snapshot()
                .expect("snapshot")
                .annotations()
                .expect("annotations")
                .is_empty(),
            "no user row from the killed transaction may survive"
        );
        let edit_rows: i64 = database
            .conn
            .query_row("SELECT COUNT(*) FROM edit_log", [], |row| row.get(0))
            .expect("edit_log count");
        assert_eq!(edit_rows, 0, "no history row may survive the kill");
        let event_rows: i64 = database
            .conn
            .query_row("SELECT COUNT(*) FROM history_events", [], |row| row.get(0))
            .expect("history_events count");
        assert_eq!(event_rows, 0, "no audit row may survive the kill");
        let head: Option<i64> = database
            .conn
            .query_row("SELECT edit_id FROM history_head WHERE id = 1", [], |row| {
                row.get(0)
            })
            .expect("history head");
        assert_eq!(head, None, "the history head still points at nothing");

        // The project remains writable afterwards.
        let mut database = database;
        let applied = database
            .apply(
                Revision(0),
                &Edit::SetComment {
                    address: Address(0x1000),
                    text: Some("after recovery".into()),
                },
            )
            .expect("editing after recovery");
        assert_eq!(applied, EditOutcome::Applied(Revision(1)));
        assert_eq!(
            database
                .snapshot()
                .expect("snapshot")
                .annotations()
                .expect("annotations")
                .len(),
            1
        );
    }
}
