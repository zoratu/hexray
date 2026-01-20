//! Interactive analysis session with persistent history
//!
//! Provides a REPL (Read-Eval-Print-Loop) for interactive binary analysis
//! with SQLite-backed persistence for:
//! - Command history with captured outputs
//! - Annotations (renames, comments, bookmarks, tags)
//! - Analysis cache (disassembly, strings, xrefs)

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use rustyline::error::ReadlineError;
use rustyline::history::DefaultHistory;
use rustyline::{Config, Editor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{BufWriter, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;
use uuid::Uuid;

/// Session metadata stored in SQLite
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMeta {
    pub id: String,
    pub name: String,
    pub binary_path: String,
    pub binary_hash: String,
    pub created_at: DateTime<Utc>,
    pub last_accessed: DateTime<Utc>,
}

/// A single command history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub index: i64,
    pub timestamp: DateTime<Utc>,
    pub command: String,
    pub output: String,
    pub duration_ms: u64,
    pub success: bool,
}

/// Annotation for an address
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Annotation {
    pub address: u64,
    pub kind: AnnotationKind,
    pub value: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnnotationKind {
    Rename,
    Comment,
    Type,
    Bookmark,
    Tag,
}

impl std::fmt::Display for AnnotationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rename => write!(f, "rename"),
            Self::Comment => write!(f, "comment"),
            Self::Type => write!(f, "type"),
            Self::Bookmark => write!(f, "bookmark"),
            Self::Tag => write!(f, "tag"),
        }
    }
}

impl std::str::FromStr for AnnotationKind {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "rename" => Ok(Self::Rename),
            "comment" => Ok(Self::Comment),
            "type" => Ok(Self::Type),
            "bookmark" => Ok(Self::Bookmark),
            "tag" => Ok(Self::Tag),
            _ => bail!("Unknown annotation kind: {}", s),
        }
    }
}

/// An undo/redo action record
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct UndoAction {
    /// Unique ID for this action
    pub id: i64,
    /// Description of the action
    pub description: String,
    /// Type of action
    pub action_type: UndoActionType,
    /// Timestamp when the action was performed
    pub timestamp: DateTime<Utc>,
}

/// Type of undo action
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code, clippy::enum_variant_names)]
pub enum UndoActionType {
    /// Annotation was added
    AnnotationAdd {
        address: u64,
        kind: AnnotationKind,
        new_value: String,
    },
    /// Annotation was modified
    AnnotationModify {
        address: u64,
        kind: AnnotationKind,
        old_value: String,
        new_value: String,
    },
    /// Annotation was deleted
    AnnotationDelete {
        address: u64,
        kind: AnnotationKind,
        old_value: String,
    },
}

/// Interactive analysis session
pub struct Session {
    /// Database connection
    conn: Connection,
    /// Session metadata
    pub meta: SessionMeta,
    /// Cached annotations (address -> kind -> value)
    annotations: HashMap<u64, HashMap<AnnotationKind, String>>,
    /// Path to session file
    pub session_path: PathBuf,
    /// Lines threshold for paging
    pager_threshold: usize,
    /// Current undo position (ID of last action that is "done")
    undo_position: Option<i64>,
}

impl Session {
    /// Create a new session for a binary
    pub fn create(binary_path: &Path, session_path: &Path) -> Result<Self> {
        // Verify binary exists and compute hash
        let binary_data = fs::read(binary_path)
            .with_context(|| format!("Failed to read binary: {}", binary_path.display()))?;
        let binary_hash = compute_hash(&binary_data);

        // Create the session database
        let conn = Connection::open(session_path).with_context(|| {
            format!("Failed to create session file: {}", session_path.display())
        })?;

        // Initialize schema
        Self::init_schema(&conn)?;

        // Create session metadata
        let meta = SessionMeta {
            id: Uuid::new_v4().to_string(),
            name: binary_path
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "unnamed".to_string()),
            binary_path: binary_path
                .canonicalize()
                .unwrap_or_else(|_| binary_path.to_path_buf())
                .to_string_lossy()
                .to_string(),
            binary_hash,
            created_at: Utc::now(),
            last_accessed: Utc::now(),
        };

        // Save metadata
        conn.execute(
            "INSERT INTO session_meta (id, name, binary_path, binary_hash, created_at, last_accessed)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                &meta.id,
                &meta.name,
                &meta.binary_path,
                &meta.binary_hash,
                meta.created_at.to_rfc3339(),
                meta.last_accessed.to_rfc3339(),
            ],
        )?;

        Ok(Self {
            conn,
            meta,
            annotations: HashMap::new(),
            session_path: session_path.to_path_buf(),
            pager_threshold: 50,
            undo_position: None,
        })
    }

    /// Resume an existing session
    pub fn resume(session_path: &Path) -> Result<Self> {
        let conn = Connection::open(session_path)
            .with_context(|| format!("Failed to open session: {}", session_path.display()))?;

        // Load metadata
        let meta: SessionMeta = conn.query_row(
            "SELECT id, name, binary_path, binary_hash, created_at, last_accessed FROM session_meta LIMIT 1",
            [],
            |row| {
                let created_str: String = row.get(4)?;
                let accessed_str: String = row.get(5)?;
                Ok(SessionMeta {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    binary_path: row.get(2)?,
                    binary_hash: row.get(3)?,
                    created_at: DateTime::parse_from_rfc3339(&created_str)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    last_accessed: DateTime::parse_from_rfc3339(&accessed_str)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                })
            },
        ).context("Failed to load session metadata")?;

        // Update last accessed
        conn.execute(
            "UPDATE session_meta SET last_accessed = ?1",
            params![Utc::now().to_rfc3339()],
        )?;

        // Load annotations into cache
        let annotations = {
            let mut annotations = HashMap::new();
            let mut stmt = conn.prepare("SELECT address, kind, value FROM annotations")?;
            let rows = stmt.query_map([], |row| {
                let addr: i64 = row.get(0)?;
                let kind_str: String = row.get(1)?;
                let value: String = row.get(2)?;
                Ok((addr as u64, kind_str, value))
            })?;

            for row in rows {
                let (addr, kind_str, value) = row?;
                if let Ok(kind) = kind_str.parse::<AnnotationKind>() {
                    annotations
                        .entry(addr)
                        .or_insert_with(HashMap::new)
                        .insert(kind, value);
                }
            }
            annotations
        };

        // Load undo position (max ID that is "done", i.e., not undone)
        let undo_position: Option<i64> = conn
            .query_row(
                "SELECT MAX(id) FROM undo_history WHERE undone = 0",
                [],
                |row| row.get(0),
            )
            .ok()
            .flatten();

        Ok(Self {
            conn,
            meta,
            annotations,
            session_path: session_path.to_path_buf(),
            pager_threshold: 50,
            undo_position,
        })
    }

    /// Initialize database schema
    fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS session_meta (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                binary_path TEXT NOT NULL,
                binary_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_accessed TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS history (
                idx INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                command TEXT NOT NULL,
                output TEXT NOT NULL,
                duration_ms INTEGER NOT NULL,
                success INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS annotations (
                address INTEGER NOT NULL,
                kind TEXT NOT NULL,
                value TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (address, kind)
            );

            CREATE TABLE IF NOT EXISTS undo_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                description TEXT NOT NULL,
                action_type TEXT NOT NULL,
                action_data TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                undone INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_history_timestamp ON history(timestamp);
            CREATE INDEX IF NOT EXISTS idx_annotations_address ON annotations(address);
            CREATE INDEX IF NOT EXISTS idx_undo_history_undone ON undo_history(undone);
        "#,
        )?;
        Ok(())
    }

    /// Verify the binary hash matches
    pub fn verify_binary(&self) -> Result<bool> {
        let binary_data = fs::read(&self.meta.binary_path)
            .with_context(|| format!("Failed to read binary: {}", self.meta.binary_path))?;
        let current_hash = compute_hash(&binary_data);
        Ok(current_hash == self.meta.binary_hash)
    }

    /// Record a command and its output to history
    pub fn record_history(
        &self,
        command: &str,
        output: &str,
        duration_ms: u64,
        success: bool,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO history (timestamp, command, output, duration_ms, success) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                Utc::now().to_rfc3339(),
                command,
                output,
                duration_ms as i64,
                success as i32,
            ],
        )?;
        Ok(())
    }

    /// Get command history
    pub fn get_history(&self, limit: Option<usize>) -> Result<Vec<HistoryEntry>> {
        let limit_clause = limit.map(|l| format!("LIMIT {}", l)).unwrap_or_default();
        let query = format!(
            "SELECT idx, timestamp, command, output, duration_ms, success FROM history ORDER BY idx DESC {}",
            limit_clause
        );

        let mut stmt = self.conn.prepare(&query)?;
        let rows = stmt.query_map([], |row| {
            let ts_str: String = row.get(1)?;
            Ok(HistoryEntry {
                index: row.get(0)?,
                timestamp: DateTime::parse_from_rfc3339(&ts_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                command: row.get(2)?,
                output: row.get(3)?,
                duration_ms: row.get::<_, i64>(4)? as u64,
                success: row.get::<_, i32>(5)? != 0,
            })
        })?;

        let mut entries: Vec<_> = rows.filter_map(|r| r.ok()).collect();
        entries.reverse(); // Oldest first
        Ok(entries)
    }

    /// Get a specific history entry by index
    pub fn get_history_entry(&self, index: i64) -> Result<Option<HistoryEntry>> {
        let result = self.conn.query_row(
            "SELECT idx, timestamp, command, output, duration_ms, success FROM history WHERE idx = ?1",
            params![index],
            |row| {
                let ts_str: String = row.get(1)?;
                Ok(HistoryEntry {
                    index: row.get(0)?,
                    timestamp: DateTime::parse_from_rfc3339(&ts_str)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    command: row.get(2)?,
                    output: row.get(3)?,
                    duration_ms: row.get::<_, i64>(4)? as u64,
                    success: row.get::<_, i32>(5)? != 0,
                })
            },
        );

        match result {
            Ok(entry) => Ok(Some(entry)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Add an annotation (with undo support)
    pub fn add_annotation(
        &mut self,
        address: u64,
        kind: AnnotationKind,
        value: &str,
    ) -> Result<()> {
        // Check if there's an existing value (for undo)
        let old_value = self
            .annotations
            .get(&address)
            .and_then(|kinds| kinds.get(&kind))
            .cloned();

        // Insert the annotation
        self.conn.execute(
            "INSERT OR REPLACE INTO annotations (address, kind, value, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![
                address as i64,
                kind.to_string(),
                value,
                Utc::now().to_rfc3339(),
            ],
        )?;

        // Record undo action
        let action_type = if let Some(old_val) = old_value {
            UndoActionType::AnnotationModify {
                address,
                kind,
                old_value: old_val,
                new_value: value.to_string(),
            }
        } else {
            UndoActionType::AnnotationAdd {
                address,
                kind,
                new_value: value.to_string(),
            }
        };

        self.record_undo_action(&format!("{} at 0x{:x}", kind, address), action_type)?;

        // Update cache
        self.annotations
            .entry(address)
            .or_default()
            .insert(kind, value.to_string());

        Ok(())
    }

    /// Delete an annotation (with undo support)
    pub fn delete_annotation(&mut self, address: u64, kind: AnnotationKind) -> Result<bool> {
        // Check if there's an existing value
        let old_value = self
            .annotations
            .get(&address)
            .and_then(|kinds| kinds.get(&kind))
            .cloned();

        if let Some(old_val) = old_value {
            // Delete from database
            self.conn.execute(
                "DELETE FROM annotations WHERE address = ?1 AND kind = ?2",
                params![address as i64, kind.to_string()],
            )?;

            // Record undo action
            let action_type = UndoActionType::AnnotationDelete {
                address,
                kind,
                old_value: old_val,
            };
            self.record_undo_action(&format!("delete {} at 0x{:x}", kind, address), action_type)?;

            // Update cache
            if let Some(kinds) = self.annotations.get_mut(&address) {
                kinds.remove(&kind);
                if kinds.is_empty() {
                    self.annotations.remove(&address);
                }
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Record an undo action
    fn record_undo_action(&mut self, description: &str, action_type: UndoActionType) -> Result<()> {
        // Clear any "redo" actions (actions after current position)
        if let Some(pos) = self.undo_position {
            self.conn
                .execute("DELETE FROM undo_history WHERE id > ?1", params![pos])?;
        }

        // Serialize action type
        let action_data = serde_json::to_string(&action_type)?;
        let type_name = match &action_type {
            UndoActionType::AnnotationAdd { .. } => "add",
            UndoActionType::AnnotationModify { .. } => "modify",
            UndoActionType::AnnotationDelete { .. } => "delete",
        };

        // Insert the action
        self.conn.execute(
            "INSERT INTO undo_history (description, action_type, action_data, timestamp, undone) VALUES (?1, ?2, ?3, ?4, 0)",
            params![
                description,
                type_name,
                action_data,
                Utc::now().to_rfc3339(),
            ],
        )?;

        // Update undo position
        self.undo_position = Some(self.conn.last_insert_rowid());

        Ok(())
    }

    /// Undo the last action
    pub fn undo(&mut self) -> Result<Option<String>> {
        // Find the last non-undone action
        let action: Option<(i64, String, String)> = self.conn.query_row(
            "SELECT id, description, action_data FROM undo_history WHERE undone = 0 ORDER BY id DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).ok();

        if let Some((id, description, action_data)) = action {
            let action_type: UndoActionType = serde_json::from_str(&action_data)?;

            // Apply the reverse action
            match action_type {
                UndoActionType::AnnotationAdd { address, kind, .. } => {
                    // Undo add = delete
                    self.conn.execute(
                        "DELETE FROM annotations WHERE address = ?1 AND kind = ?2",
                        params![address as i64, kind.to_string()],
                    )?;
                    if let Some(kinds) = self.annotations.get_mut(&address) {
                        kinds.remove(&kind);
                    }
                }
                UndoActionType::AnnotationModify {
                    address,
                    kind,
                    old_value,
                    ..
                } => {
                    // Undo modify = restore old value
                    self.conn.execute(
                        "UPDATE annotations SET value = ?1 WHERE address = ?2 AND kind = ?3",
                        params![&old_value, address as i64, kind.to_string()],
                    )?;
                    if let Some(kinds) = self.annotations.get_mut(&address) {
                        kinds.insert(kind, old_value);
                    }
                }
                UndoActionType::AnnotationDelete {
                    address,
                    kind,
                    old_value,
                } => {
                    // Undo delete = restore
                    self.conn.execute(
                        "INSERT INTO annotations (address, kind, value, created_at) VALUES (?1, ?2, ?3, ?4)",
                        params![address as i64, kind.to_string(), &old_value, Utc::now().to_rfc3339()],
                    )?;
                    self.annotations
                        .entry(address)
                        .or_default()
                        .insert(kind, old_value);
                }
            }

            // Mark as undone
            self.conn.execute(
                "UPDATE undo_history SET undone = 1 WHERE id = ?1",
                params![id],
            )?;

            // Update undo position
            self.undo_position = self
                .conn
                .query_row(
                    "SELECT MAX(id) FROM undo_history WHERE undone = 0",
                    [],
                    |row| row.get(0),
                )
                .ok()
                .flatten();

            Ok(Some(format!("Undone: {}", description)))
        } else {
            Ok(None)
        }
    }

    /// Redo the last undone action
    pub fn redo(&mut self) -> Result<Option<String>> {
        // Find the first undone action
        let action: Option<(i64, String, String)> = self.conn.query_row(
            "SELECT id, description, action_data FROM undo_history WHERE undone = 1 ORDER BY id ASC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).ok();

        if let Some((id, description, action_data)) = action {
            let action_type: UndoActionType = serde_json::from_str(&action_data)?;

            // Re-apply the action
            match action_type {
                UndoActionType::AnnotationAdd {
                    address,
                    kind,
                    new_value,
                } => {
                    self.conn.execute(
                        "INSERT OR REPLACE INTO annotations (address, kind, value, created_at) VALUES (?1, ?2, ?3, ?4)",
                        params![address as i64, kind.to_string(), &new_value, Utc::now().to_rfc3339()],
                    )?;
                    self.annotations
                        .entry(address)
                        .or_default()
                        .insert(kind, new_value);
                }
                UndoActionType::AnnotationModify {
                    address,
                    kind,
                    new_value,
                    ..
                } => {
                    self.conn.execute(
                        "UPDATE annotations SET value = ?1 WHERE address = ?2 AND kind = ?3",
                        params![&new_value, address as i64, kind.to_string()],
                    )?;
                    if let Some(kinds) = self.annotations.get_mut(&address) {
                        kinds.insert(kind, new_value);
                    }
                }
                UndoActionType::AnnotationDelete { address, kind, .. } => {
                    self.conn.execute(
                        "DELETE FROM annotations WHERE address = ?1 AND kind = ?2",
                        params![address as i64, kind.to_string()],
                    )?;
                    if let Some(kinds) = self.annotations.get_mut(&address) {
                        kinds.remove(&kind);
                    }
                }
            }

            // Mark as not undone
            self.conn.execute(
                "UPDATE undo_history SET undone = 0 WHERE id = ?1",
                params![id],
            )?;

            // Update undo position
            self.undo_position = Some(id);

            Ok(Some(format!("Redone: {}", description)))
        } else {
            Ok(None)
        }
    }

    /// Check if undo is available
    #[allow(dead_code)]
    pub fn can_undo(&self) -> bool {
        self.undo_position.is_some()
    }

    /// Check if redo is available
    #[allow(dead_code)]
    pub fn can_redo(&self) -> bool {
        self.conn
            .query_row::<i64, _, _>(
                "SELECT COUNT(*) FROM undo_history WHERE undone = 1",
                [],
                |row| row.get(0),
            )
            .map(|count| count > 0)
            .unwrap_or(false)
    }

    /// Get annotations for an address
    #[allow(dead_code)]
    pub fn get_annotations(&self, address: u64) -> Option<&HashMap<AnnotationKind, String>> {
        self.annotations.get(&address)
    }

    /// Get all annotations of a specific kind
    pub fn get_all_annotations(&self, kind: AnnotationKind) -> Vec<(u64, String)> {
        self.annotations
            .iter()
            .filter_map(|(addr, kinds)| kinds.get(&kind).map(|v| (*addr, v.clone())))
            .collect()
    }

    /// Get a rename for an address, if any
    pub fn get_rename(&self, address: u64) -> Option<&str> {
        self.annotations
            .get(&address)
            .and_then(|kinds: &HashMap<AnnotationKind, String>| kinds.get(&AnnotationKind::Rename))
            .map(|s: &String| s.as_str())
    }

    /// Get a comment for an address, if any
    pub fn get_comment(&self, address: u64) -> Option<&str> {
        self.annotations
            .get(&address)
            .and_then(|kinds: &HashMap<AnnotationKind, String>| kinds.get(&AnnotationKind::Comment))
            .map(|s: &String| s.as_str())
    }

    /// Display output, using pager for long output
    pub fn display_output(&self, output: &str) -> Result<()> {
        let line_count = output.lines().count();

        if line_count <= self.pager_threshold {
            println!("{}", output);
            return Ok(());
        }

        // Pipe to less
        match Command::new("less")
            .args(["-R", "-S", "-F", "-X"])
            .stdin(Stdio::piped())
            .spawn()
        {
            Ok(mut child) => {
                if let Some(stdin) = child.stdin.take() {
                    let mut writer = BufWriter::new(stdin);
                    writer.write_all(output.as_bytes())?;
                    writer.flush()?;
                }
                child.wait()?;
            }
            Err(_) => {
                // Fallback if less is not available
                println!("{}", output);
            }
        }

        Ok(())
    }

    /// Get session statistics
    pub fn stats(&self) -> Result<SessionStats> {
        let history_count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM history", [], |row| row.get(0))?;

        let annotation_count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM annotations", [], |row| row.get(0))?;

        Ok(SessionStats {
            history_entries: history_count as usize,
            annotations: annotation_count as usize,
            renames: self.get_all_annotations(AnnotationKind::Rename).len(),
            comments: self.get_all_annotations(AnnotationKind::Comment).len(),
            bookmarks: self.get_all_annotations(AnnotationKind::Bookmark).len(),
        })
    }
}

/// Session statistics
#[derive(Debug)]
pub struct SessionStats {
    pub history_entries: usize,
    pub annotations: usize,
    pub renames: usize,
    pub comments: usize,
    pub bookmarks: usize,
}

/// Compute SHA256 hash of data
fn compute_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}

// We need the hex crate, but we can implement it inline
mod hex {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        data.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// REPL for interactive analysis
pub struct Repl {
    session: Session,
    editor: Editor<(), DefaultHistory>,
}

impl Repl {
    /// Create a new REPL with a session
    pub fn new(session: Session) -> Result<Self> {
        let config = Config::builder()
            .history_ignore_space(true)
            .auto_add_history(true)
            .build();

        let editor = Editor::with_config(config)?;

        Ok(Self { session, editor })
    }

    /// Run the REPL
    pub fn run<F>(&mut self, mut execute_command: F) -> Result<()>
    where
        F: FnMut(&mut Session, &str) -> Result<String>,
    {
        println!("hexray session: {}", self.session.meta.name);
        println!("Binary: {}", self.session.meta.binary_path);

        // Verify binary
        match self.session.verify_binary() {
            Ok(true) => {}
            Ok(false) => {
                println!("WARNING: Binary has changed since session was created!");
            }
            Err(e) => {
                println!("WARNING: Could not verify binary: {}", e);
            }
        }

        let stats = self.session.stats()?;
        println!(
            "History: {} commands, {} annotations",
            stats.history_entries, stats.annotations
        );
        println!();
        println!("Type 'help' for available commands, Ctrl+D to detach");
        println!();

        loop {
            let prompt = format!("hexray({})> ", self.session.meta.name);

            match self.editor.readline(&prompt) {
                Ok(line) => {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }

                    // Handle built-in REPL commands
                    if let Some(result) = self.handle_builtin(line)? {
                        self.session.display_output(&result)?;
                        continue;
                    }

                    // Execute the command
                    let start = Instant::now();
                    let result = execute_command(&mut self.session, line);
                    let duration_ms = start.elapsed().as_millis() as u64;

                    match result {
                        Ok(output) => {
                            self.session
                                .record_history(line, &output, duration_ms, true)?;
                            self.session.display_output(&output)?;
                        }
                        Err(e) => {
                            let error_msg = format!("Error: {}", e);
                            self.session
                                .record_history(line, &error_msg, duration_ms, false)?;
                            eprintln!("{}", error_msg);
                        }
                    }
                }
                Err(ReadlineError::Eof) => {
                    println!(
                        "\nSession detached. Resume with: hexray session resume {}",
                        self.session.session_path.display()
                    );
                    break;
                }
                Err(ReadlineError::Interrupted) => {
                    println!("^C");
                    continue;
                }
                Err(e) => {
                    eprintln!("Error reading input: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle built-in REPL commands
    fn handle_builtin(&mut self, line: &str) -> Result<Option<String>> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            return Ok(None);
        }

        match parts[0] {
            "help" | "?" => Ok(Some(HELP_TEXT.to_string())),
            "history" => {
                let limit = parts.get(1).and_then(|s| s.parse().ok());
                let entries = self.session.get_history(limit)?;
                let mut output = String::new();
                for entry in entries {
                    output.push_str(&format!(
                        "[{}] {} ({}ms)\n  {}\n",
                        entry.index,
                        entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
                        entry.duration_ms,
                        entry.command
                    ));
                }
                Ok(Some(output))
            }
            "recall" | "!" => {
                if let Some(idx_str) = parts.get(1) {
                    if let Ok(idx) = idx_str.parse::<i64>() {
                        if let Some(entry) = self.session.get_history_entry(idx)? {
                            let mut output = format!("Command: {}\n", entry.command);
                            output.push_str("---\n");
                            output.push_str(&entry.output);
                            return Ok(Some(output));
                        }
                    }
                }
                Ok(Some("Usage: recall <index>".to_string()))
            }
            "rename" => {
                if parts.len() >= 3 {
                    let addr = parse_address(parts[1])?;
                    let name = parts[2..].join(" ");
                    self.session
                        .add_annotation(addr, AnnotationKind::Rename, &name)?;
                    Ok(Some(format!("Renamed 0x{:x} to '{}'", addr, name)))
                } else {
                    Ok(Some("Usage: rename <address> <name>".to_string()))
                }
            }
            "comment" => {
                if parts.len() >= 3 {
                    let addr = parse_address(parts[1])?;
                    let comment = parts[2..].join(" ");
                    self.session
                        .add_annotation(addr, AnnotationKind::Comment, &comment)?;
                    Ok(Some(format!("Added comment at 0x{:x}", addr)))
                } else {
                    Ok(Some("Usage: comment <address> <text>".to_string()))
                }
            }
            "bookmark" => {
                if parts.len() >= 2 {
                    let addr = parse_address(parts[1])?;
                    let label = if parts.len() > 2 {
                        parts[2..].join(" ")
                    } else {
                        format!("bookmark_{:x}", addr)
                    };
                    self.session
                        .add_annotation(addr, AnnotationKind::Bookmark, &label)?;
                    Ok(Some(format!("Bookmarked 0x{:x} as '{}'", addr, label)))
                } else {
                    Ok(Some("Usage: bookmark <address> [label]".to_string()))
                }
            }
            "bookmarks" => {
                let bookmarks = self.session.get_all_annotations(AnnotationKind::Bookmark);
                if bookmarks.is_empty() {
                    Ok(Some("No bookmarks".to_string()))
                } else {
                    let mut output = String::new();
                    for (addr, label) in bookmarks {
                        output.push_str(&format!("0x{:016x}  {}\n", addr, label));
                    }
                    Ok(Some(output))
                }
            }
            "renames" => {
                let renames = self.session.get_all_annotations(AnnotationKind::Rename);
                if renames.is_empty() {
                    Ok(Some("No renames".to_string()))
                } else {
                    let mut output = String::new();
                    for (addr, name) in renames {
                        output.push_str(&format!("0x{:016x}  {}\n", addr, name));
                    }
                    Ok(Some(output))
                }
            }
            "comments" => {
                let comments = self.session.get_all_annotations(AnnotationKind::Comment);
                if comments.is_empty() {
                    Ok(Some("No comments".to_string()))
                } else {
                    let mut output = String::new();
                    for (addr, comment) in comments {
                        output.push_str(&format!("0x{:016x}  {}\n", addr, comment));
                    }
                    Ok(Some(output))
                }
            }
            "undo" => match self.session.undo()? {
                Some(msg) => Ok(Some(msg)),
                None => Ok(Some("Nothing to undo".to_string())),
            },
            "redo" => match self.session.redo()? {
                Some(msg) => Ok(Some(msg)),
                None => Ok(Some("Nothing to redo".to_string())),
            },
            "delete" => {
                if parts.len() >= 3 {
                    let addr = parse_address(parts[1])?;
                    let kind_str = parts[2];
                    if let Ok(kind) = kind_str.parse::<AnnotationKind>() {
                        if self.session.delete_annotation(addr, kind)? {
                            Ok(Some(format!("Deleted {} at 0x{:x}", kind, addr)))
                        } else {
                            Ok(Some(format!("No {} found at 0x{:x}", kind, addr)))
                        }
                    } else {
                        Ok(Some(format!("Unknown annotation kind: {}. Use: rename, comment, bookmark, type, tag", kind_str)))
                    }
                } else {
                    Ok(Some("Usage: delete <address> <kind>  (kind: rename, comment, bookmark, type, tag)".to_string()))
                }
            }
            "stats" => {
                let stats = self.session.stats()?;
                Ok(Some(format!(
                    "Session Statistics:\n  History entries: {}\n  Annotations: {}\n    Renames: {}\n    Comments: {}\n    Bookmarks: {}",
                    stats.history_entries,
                    stats.annotations,
                    stats.renames,
                    stats.comments,
                    stats.bookmarks,
                )))
            }
            "quit" | "exit" => {
                // This will be handled by EOF
                println!("Session saved. Goodbye!");
                std::process::exit(0);
            }
            _ => Ok(None), // Not a built-in command
        }
    }
}

fn parse_address(s: &str) -> Result<u64> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).context("Invalid address")
}

const HELP_TEXT: &str = r#"
hexray REPL Commands
====================

Session:
  history [n]           Show command history (last n entries)
  recall <n> | !<n>     Show output from history entry n
  stats                 Show session statistics
  quit | exit           Save and exit

Annotations:
  rename <addr> <name>  Rename a function/address
  comment <addr> <text> Add a comment to an address
  bookmark <addr> [lbl] Bookmark an address with optional label
  delete <addr> <kind>  Delete an annotation (kind: rename, comment, bookmark, type, tag)

Undo/Redo:
  undo                  Undo the last annotation change
  redo                  Redo the last undone change

List Annotations:
  renames               List all renamed addresses
  comments              List all comments
  bookmarks             List all bookmarks

Analysis Commands:
  info                  Show binary info
  sections              List sections
  symbols | syms        List all symbols
  functions | funcs     List only functions
  imports               List imported symbols
  exports               List exported symbols
  strings [min_len]     List detected strings

Disassembly & Decompilation:
  disasm | d <sym> [n]  Disassemble (n instructions, default 50)
  decompile | dec <sym> Decompile to pseudo-code
  cfg <symbol>          Show control flow graph
  hexdump | x <addr> [len]  Show hex dump (default 256 bytes)

Navigation:
  xrefs <address>       Show cross-references to address

Keyboard:
  Ctrl+D                Detach (session is preserved)
  Ctrl+C                Cancel current input
  Up/Down               Navigate history
"#;

/// List all session files in a directory
pub fn list_sessions(dir: &Path) -> Result<Vec<(PathBuf, SessionMeta)>> {
    let mut sessions = Vec::new();

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map(|e| e == "hrp").unwrap_or(false) {
            if let Ok(session) = Session::resume(&path) {
                sessions.push((path, session.meta));
            }
        }
    }

    // Sort by last accessed (most recent first)
    sessions.sort_by(|a, b| b.1.last_accessed.cmp(&a.1.last_accessed));

    Ok(sessions)
}
