//! Analysis project persistence and annotations.
//!
//! This module provides functionality for:
//! - Persisting user annotations (function names, comments, types)
//! - Saving/loading analysis projects
//! - Undo/redo history
//!
//! # Example
//!
//! ```ignore
//! use hexray_analysis::project::{AnalysisProject, Annotation, AnnotationKind};
//!
//! // Create a new project
//! let mut project = AnalysisProject::new("/bin/ls")?;
//!
//! // Add annotations
//! project.set_function_name(0x1234, "process_input");
//! project.set_comment(0x1240, "Validate user input");
//!
//! // Save project
//! project.save("ls.hrp")?;
//!
//! // Load project
//! let loaded = AnalysisProject::load("ls.hrp")?;
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Project file version for compatibility checking.
const PROJECT_VERSION: u32 = 1;

/// Errors that can occur during project operations.
#[derive(Debug, Error)]
pub enum ProjectError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Binary not found: {0}")]
    BinaryNotFound(PathBuf),

    #[error("Binary hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("Invalid project file: {0}")]
    InvalidProject(String),

    #[error("Unsupported project version: {0}")]
    UnsupportedVersion(u32),

    #[error("Nothing to undo")]
    NothingToUndo,

    #[error("Nothing to redo")]
    NothingToRedo,
}

/// Result type for project operations.
pub type ProjectResult<T> = Result<T, ProjectError>;

/// An analysis project containing annotations and overrides for a binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisProject {
    /// Project file format version.
    pub version: u32,

    /// Path to the binary being analyzed.
    pub binary_path: PathBuf,

    /// SHA-256 hash of the binary for verification.
    #[serde(with = "hex_hash")]
    pub binary_hash: [u8; 32],

    /// User annotations by address.
    pub annotations: HashMap<u64, Vec<Annotation>>,

    /// Function overrides (name, signature, calling convention).
    pub function_overrides: HashMap<u64, FunctionOverride>,

    /// Data type overrides at specific addresses.
    pub type_overrides: HashMap<u64, TypeOverride>,

    /// Bookmarked addresses with optional labels.
    pub bookmarks: Vec<Bookmark>,

    /// History for undo/redo.
    #[serde(skip)]
    history: Vec<HistoryEntry>,

    /// Current position in history (for redo).
    #[serde(skip)]
    history_position: usize,

    /// Whether the project has unsaved changes.
    #[serde(skip)]
    pub dirty: bool,
}

/// Custom serialization for the hash as hex string.
mod hex_hash {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(hash: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
        serializer.serialize_str(&hex)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect::<Result<Vec<_>, _>>()
            .map_err(serde::de::Error::custom)?;

        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid hash length"))
    }
}

/// A user annotation at a specific address.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Annotation {
    /// The kind of annotation.
    pub kind: AnnotationKind,

    /// The annotation value.
    pub value: String,

    /// Optional timestamp when annotation was created.
    #[serde(default)]
    pub timestamp: Option<u64>,
}

/// Types of annotations that can be attached to addresses.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AnnotationKind {
    /// User comment.
    Comment,

    /// Label for the address.
    Label,

    /// Variable name (for stack/register variables).
    VariableName,

    /// Custom tag for organization.
    Tag,
}

/// Override for a function's metadata.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FunctionOverride {
    /// Custom function name.
    pub name: Option<String>,

    /// Function signature override.
    pub signature: Option<SignatureOverride>,

    /// Calling convention override.
    pub calling_convention: Option<String>,

    /// Whether this function should be excluded from analysis.
    pub excluded: bool,

    /// User notes about the function.
    pub notes: Option<String>,
}

/// Override for a function's signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureOverride {
    /// Return type as a string (e.g., "int", "void *").
    pub return_type: String,

    /// Parameters as (name, type) pairs.
    pub parameters: Vec<(String, String)>,

    /// Whether the function is variadic.
    pub variadic: bool,
}

/// Override for a data type at an address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeOverride {
    /// The type name or definition.
    pub type_name: String,

    /// Size in bytes (if known).
    pub size: Option<usize>,

    /// Whether this is an array.
    pub is_array: bool,

    /// Array length (if is_array).
    pub array_length: Option<usize>,
}

/// A bookmarked address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bookmark {
    /// The bookmarked address.
    pub address: u64,

    /// Optional label for the bookmark.
    pub label: Option<String>,

    /// Optional color/category.
    pub category: Option<String>,

    /// Timestamp when bookmark was created.
    pub timestamp: u64,
}

/// An entry in the undo/redo history.
#[derive(Debug, Clone)]
struct HistoryEntry {
    /// Description of the action.
    description: String,

    /// The action that was performed.
    action: HistoryAction,

    /// Data needed to undo this action.
    undo_data: serde_json::Value,

    /// Data needed to redo this action.
    redo_data: serde_json::Value,
}

/// Types of actions that can be undone/redone.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum HistoryAction {
    AddAnnotation { address: u64 },
    RemoveAnnotation { address: u64, index: usize },
    SetFunctionOverride { address: u64 },
    RemoveFunctionOverride { address: u64 },
    SetTypeOverride { address: u64 },
    RemoveTypeOverride { address: u64 },
    AddBookmark { index: usize },
    RemoveBookmark { address: u64 },
}

impl AnalysisProject {
    /// Create a new project for a binary.
    pub fn new<P: AsRef<Path>>(binary_path: P) -> ProjectResult<Self> {
        let binary_path = binary_path.as_ref().to_path_buf();

        if !binary_path.exists() {
            return Err(ProjectError::BinaryNotFound(binary_path));
        }

        let hash = Self::compute_hash(&binary_path)?;

        Ok(Self {
            version: PROJECT_VERSION,
            binary_path,
            binary_hash: hash,
            annotations: HashMap::new(),
            function_overrides: HashMap::new(),
            type_overrides: HashMap::new(),
            bookmarks: Vec::new(),
            history: Vec::new(),
            history_position: 0,
            dirty: false,
        })
    }

    /// Load a project from a file.
    pub fn load<P: AsRef<Path>>(path: P) -> ProjectResult<Self> {
        let content = fs::read_to_string(path)?;
        let mut project: Self = serde_json::from_str(&content)?;

        if project.version > PROJECT_VERSION {
            return Err(ProjectError::UnsupportedVersion(project.version));
        }

        project.history = Vec::new();
        project.history_position = 0;
        project.dirty = false;

        Ok(project)
    }

    /// Load and verify the binary hash matches.
    pub fn load_and_verify<P: AsRef<Path>>(path: P) -> ProjectResult<Self> {
        let project = Self::load(path)?;

        if project.binary_path.exists() {
            let actual_hash = Self::compute_hash(&project.binary_path)?;
            if actual_hash != project.binary_hash {
                return Err(ProjectError::HashMismatch {
                    expected: hex_encode(&project.binary_hash),
                    actual: hex_encode(&actual_hash),
                });
            }
        }

        Ok(project)
    }

    /// Save the project to a file.
    pub fn save<P: AsRef<Path>>(&mut self, path: P) -> ProjectResult<()> {
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)?;
        self.dirty = false;
        Ok(())
    }

    /// Compute SHA-256 hash of a file.
    fn compute_hash<P: AsRef<Path>>(path: P) -> ProjectResult<[u8; 32]> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // Simple hash for now - in production would use SHA-256
        let content = fs::read(path)?;
        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);
        let hash = hasher.finish();

        let mut result = [0u8; 32];
        result[..8].copy_from_slice(&hash.to_le_bytes());
        // Fill rest with content length and simple checksum
        let len = content.len() as u64;
        result[8..16].copy_from_slice(&len.to_le_bytes());

        let checksum: u64 = content.iter().map(|&b| b as u64).sum();
        result[16..24].copy_from_slice(&checksum.to_le_bytes());

        Ok(result)
    }

    // ==================== Annotation Methods ====================

    /// Add an annotation at an address.
    pub fn add_annotation(&mut self, address: u64, kind: AnnotationKind, value: impl Into<String>) {
        let annotation = Annotation {
            kind,
            value: value.into(),
            timestamp: Some(current_timestamp()),
        };

        let undo_data = serde_json::json!({
            "address": address,
            "index": self.annotations.get(&address).map(|v| v.len()).unwrap_or(0)
        });

        self.annotations
            .entry(address)
            .or_default()
            .push(annotation.clone());

        self.record_history(
            "Add annotation",
            HistoryAction::AddAnnotation { address },
            undo_data,
            serde_json::to_value(&annotation).unwrap(),
        );
    }

    /// Set a comment at an address (replaces existing comment).
    pub fn set_comment(&mut self, address: u64, comment: impl Into<String>) {
        // Remove existing comments at this address
        if let Some(annotations) = self.annotations.get_mut(&address) {
            annotations.retain(|a| a.kind != AnnotationKind::Comment);
        }
        self.add_annotation(address, AnnotationKind::Comment, comment);
    }

    /// Get the comment at an address.
    pub fn get_comment(&self, address: u64) -> Option<&str> {
        self.annotations.get(&address).and_then(|annotations| {
            annotations
                .iter()
                .find(|a| a.kind == AnnotationKind::Comment)
                .map(|a| a.value.as_str())
        })
    }

    /// Set a label at an address.
    pub fn set_label(&mut self, address: u64, label: impl Into<String>) {
        if let Some(annotations) = self.annotations.get_mut(&address) {
            annotations.retain(|a| a.kind != AnnotationKind::Label);
        }
        self.add_annotation(address, AnnotationKind::Label, label);
    }

    /// Get the label at an address.
    pub fn get_label(&self, address: u64) -> Option<&str> {
        self.annotations.get(&address).and_then(|annotations| {
            annotations
                .iter()
                .find(|a| a.kind == AnnotationKind::Label)
                .map(|a| a.value.as_str())
        })
    }

    /// Get all annotations at an address.
    pub fn get_annotations(&self, address: u64) -> Option<&[Annotation]> {
        self.annotations.get(&address).map(|v| v.as_slice())
    }

    /// Remove all annotations of a specific kind at an address.
    pub fn remove_annotations(&mut self, address: u64, kind: AnnotationKind) {
        if let Some(annotations) = self.annotations.get_mut(&address) {
            annotations.retain(|a| a.kind != kind);
            if annotations.is_empty() {
                self.annotations.remove(&address);
            }
            self.dirty = true;
        }
    }

    // ==================== Function Override Methods ====================

    /// Set a custom name for a function.
    pub fn set_function_name(&mut self, address: u64, name: impl Into<String>) {
        let old_value = self
            .function_overrides
            .get(&address)
            .map(|e| serde_json::to_value(e).unwrap())
            .unwrap_or(serde_json::Value::Null);

        let entry = self.function_overrides.entry(address).or_default();
        entry.name = Some(name.into());
        let new_value = serde_json::to_value(&*entry).unwrap();

        self.record_history(
            "Set function name",
            HistoryAction::SetFunctionOverride { address },
            old_value,
            new_value,
        );
    }

    /// Get the custom name for a function.
    pub fn get_function_name(&self, address: u64) -> Option<&str> {
        self.function_overrides
            .get(&address)
            .and_then(|f| f.name.as_deref())
    }

    /// Set the calling convention for a function.
    pub fn set_calling_convention(&mut self, address: u64, convention: impl Into<String>) {
        let entry = self.function_overrides.entry(address).or_default();
        entry.calling_convention = Some(convention.into());
        self.dirty = true;
    }

    /// Set the signature for a function.
    pub fn set_function_signature(
        &mut self,
        address: u64,
        return_type: impl Into<String>,
        parameters: Vec<(String, String)>,
        variadic: bool,
    ) {
        let entry = self.function_overrides.entry(address).or_default();
        entry.signature = Some(SignatureOverride {
            return_type: return_type.into(),
            parameters,
            variadic,
        });
        self.dirty = true;
    }

    /// Get the function override at an address.
    pub fn get_function_override(&self, address: u64) -> Option<&FunctionOverride> {
        self.function_overrides.get(&address)
    }

    /// Remove all overrides for a function.
    pub fn remove_function_override(&mut self, address: u64) {
        if let Some(old) = self.function_overrides.remove(&address) {
            self.record_history(
                "Remove function override",
                HistoryAction::RemoveFunctionOverride { address },
                serde_json::to_value(&old).unwrap(),
                serde_json::Value::Null,
            );
        }
    }

    // ==================== Type Override Methods ====================

    /// Set a type override at an address.
    pub fn set_type_override(&mut self, address: u64, type_name: impl Into<String>) {
        let override_data = TypeOverride {
            type_name: type_name.into(),
            size: None,
            is_array: false,
            array_length: None,
        };

        let old = self.type_overrides.insert(address, override_data.clone());

        self.record_history(
            "Set type override",
            HistoryAction::SetTypeOverride { address },
            serde_json::to_value(&old).unwrap_or(serde_json::Value::Null),
            serde_json::to_value(&override_data).unwrap(),
        );
    }

    /// Set an array type override at an address.
    pub fn set_array_override(
        &mut self,
        address: u64,
        element_type: impl Into<String>,
        length: usize,
    ) {
        let override_data = TypeOverride {
            type_name: element_type.into(),
            size: None,
            is_array: true,
            array_length: Some(length),
        };
        self.type_overrides.insert(address, override_data);
        self.dirty = true;
    }

    /// Get the type override at an address.
    pub fn get_type_override(&self, address: u64) -> Option<&TypeOverride> {
        self.type_overrides.get(&address)
    }

    // ==================== Bookmark Methods ====================

    /// Add a bookmark.
    pub fn add_bookmark(&mut self, address: u64, label: Option<String>) {
        // Don't add duplicate bookmarks
        if self.bookmarks.iter().any(|b| b.address == address) {
            return;
        }

        let bookmark = Bookmark {
            address,
            label,
            category: None,
            timestamp: current_timestamp(),
        };

        let index = self.bookmarks.len();
        self.bookmarks.push(bookmark);

        self.record_history(
            "Add bookmark",
            HistoryAction::AddBookmark { index },
            serde_json::Value::Null,
            serde_json::json!({ "address": address }),
        );
    }

    /// Remove a bookmark by address.
    pub fn remove_bookmark(&mut self, address: u64) {
        if let Some(pos) = self.bookmarks.iter().position(|b| b.address == address) {
            let old = self.bookmarks.remove(pos);
            self.record_history(
                "Remove bookmark",
                HistoryAction::RemoveBookmark { address },
                serde_json::to_value(&old).unwrap(),
                serde_json::Value::Null,
            );
        }
    }

    /// Get all bookmarks.
    pub fn get_bookmarks(&self) -> &[Bookmark] {
        &self.bookmarks
    }

    /// Check if an address is bookmarked.
    pub fn is_bookmarked(&self, address: u64) -> bool {
        self.bookmarks.iter().any(|b| b.address == address)
    }

    // ==================== History Methods ====================

    /// Record an action in the history.
    fn record_history(
        &mut self,
        description: &str,
        action: HistoryAction,
        undo_data: serde_json::Value,
        redo_data: serde_json::Value,
    ) {
        // Truncate any redo history
        self.history.truncate(self.history_position);

        self.history.push(HistoryEntry {
            description: description.to_string(),
            action,
            undo_data,
            redo_data,
        });

        self.history_position = self.history.len();
        self.dirty = true;
    }

    /// Undo the last action.
    pub fn undo(&mut self) -> ProjectResult<String> {
        if self.history_position == 0 {
            return Err(ProjectError::NothingToUndo);
        }

        self.history_position -= 1;
        let entry = &self.history[self.history_position];
        let description = entry.description.clone();

        // Apply undo based on action type
        match &entry.action {
            HistoryAction::AddAnnotation { address } => {
                if let Some(annotations) = self.annotations.get_mut(address) {
                    annotations.pop();
                    if annotations.is_empty() {
                        self.annotations.remove(address);
                    }
                }
            }
            HistoryAction::SetFunctionOverride { address } => {
                if entry.undo_data.is_null() {
                    self.function_overrides.remove(address);
                } else {
                    let old: FunctionOverride =
                        serde_json::from_value(entry.undo_data.clone()).unwrap();
                    self.function_overrides.insert(*address, old);
                }
            }
            HistoryAction::RemoveFunctionOverride { address } => {
                let old: FunctionOverride =
                    serde_json::from_value(entry.undo_data.clone()).unwrap();
                self.function_overrides.insert(*address, old);
            }
            HistoryAction::SetTypeOverride { address } => {
                if entry.undo_data.is_null() {
                    self.type_overrides.remove(address);
                } else {
                    let old: TypeOverride =
                        serde_json::from_value(entry.undo_data.clone()).unwrap();
                    self.type_overrides.insert(*address, old);
                }
            }
            HistoryAction::RemoveTypeOverride { address } => {
                let old: TypeOverride = serde_json::from_value(entry.undo_data.clone()).unwrap();
                self.type_overrides.insert(*address, old);
            }
            HistoryAction::AddBookmark { .. } => {
                self.bookmarks.pop();
            }
            HistoryAction::RemoveBookmark { .. } => {
                let old: Bookmark = serde_json::from_value(entry.undo_data.clone()).unwrap();
                self.bookmarks.push(old);
            }
            _ => {}
        }

        self.dirty = true;
        Ok(format!("Undo: {}", description))
    }

    /// Redo the last undone action.
    pub fn redo(&mut self) -> ProjectResult<String> {
        if self.history_position >= self.history.len() {
            return Err(ProjectError::NothingToRedo);
        }

        let entry = &self.history[self.history_position];
        let description = entry.description.clone();

        // Apply redo based on action type
        match &entry.action {
            HistoryAction::AddAnnotation { address } => {
                let annotation: Annotation =
                    serde_json::from_value(entry.redo_data.clone()).unwrap();
                self.annotations
                    .entry(*address)
                    .or_default()
                    .push(annotation);
            }
            HistoryAction::SetFunctionOverride { address } => {
                let new: FunctionOverride =
                    serde_json::from_value(entry.redo_data.clone()).unwrap();
                self.function_overrides.insert(*address, new);
            }
            HistoryAction::RemoveFunctionOverride { address } => {
                self.function_overrides.remove(address);
            }
            HistoryAction::SetTypeOverride { address } => {
                let new: TypeOverride = serde_json::from_value(entry.redo_data.clone()).unwrap();
                self.type_overrides.insert(*address, new);
            }
            HistoryAction::RemoveTypeOverride { address } => {
                self.type_overrides.remove(address);
            }
            HistoryAction::AddBookmark { .. } => {
                let bookmark: Bookmark = serde_json::from_value(entry.redo_data.clone()).unwrap();
                self.bookmarks.push(Bookmark {
                    address: bookmark.address,
                    label: bookmark.label,
                    category: bookmark.category,
                    timestamp: current_timestamp(),
                });
            }
            HistoryAction::RemoveBookmark { address } => {
                self.bookmarks.retain(|b| b.address != *address);
            }
            _ => {}
        }

        self.history_position += 1;
        self.dirty = true;
        Ok(format!("Redo: {}", description))
    }

    /// Check if undo is available.
    pub fn can_undo(&self) -> bool {
        self.history_position > 0
    }

    /// Check if redo is available.
    pub fn can_redo(&self) -> bool {
        self.history_position < self.history.len()
    }

    /// Get the description of the action that would be undone.
    pub fn undo_description(&self) -> Option<&str> {
        if self.history_position > 0 {
            Some(&self.history[self.history_position - 1].description)
        } else {
            None
        }
    }

    /// Get the description of the action that would be redone.
    pub fn redo_description(&self) -> Option<&str> {
        if self.history_position < self.history.len() {
            Some(&self.history[self.history_position].description)
        } else {
            None
        }
    }

    // ==================== Query Methods ====================

    /// Get all annotated addresses.
    pub fn annotated_addresses(&self) -> impl Iterator<Item = u64> + '_ {
        self.annotations.keys().copied()
    }

    /// Get all function addresses with overrides.
    pub fn overridden_functions(&self) -> impl Iterator<Item = u64> + '_ {
        self.function_overrides.keys().copied()
    }

    /// Get statistics about the project.
    pub fn stats(&self) -> ProjectStats {
        let mut comment_count = 0;
        let mut label_count = 0;

        for annotations in self.annotations.values() {
            for ann in annotations {
                match ann.kind {
                    AnnotationKind::Comment => comment_count += 1,
                    AnnotationKind::Label => label_count += 1,
                    _ => {}
                }
            }
        }

        ProjectStats {
            annotation_count: self.annotations.values().map(|v| v.len()).sum(),
            comment_count,
            label_count,
            function_override_count: self.function_overrides.len(),
            type_override_count: self.type_overrides.len(),
            bookmark_count: self.bookmarks.len(),
            history_size: self.history.len(),
        }
    }
}

/// Statistics about a project.
#[derive(Debug, Clone)]
pub struct ProjectStats {
    pub annotation_count: usize,
    pub comment_count: usize,
    pub label_count: usize,
    pub function_override_count: usize,
    pub type_override_count: usize,
    pub bookmark_count: usize,
    pub history_size: usize,
}

/// Get current Unix timestamp.
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Encode bytes as hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_binary() -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"test binary content").unwrap();
        file
    }

    #[test]
    fn test_new_project() {
        let binary = create_test_binary();
        let project = AnalysisProject::new(binary.path()).unwrap();

        assert_eq!(project.version, PROJECT_VERSION);
        assert!(project.annotations.is_empty());
        assert!(!project.dirty);
    }

    #[test]
    fn test_annotations() {
        let binary = create_test_binary();
        let mut project = AnalysisProject::new(binary.path()).unwrap();

        project.set_comment(0x1000, "This is main");
        assert_eq!(project.get_comment(0x1000), Some("This is main"));
        assert!(project.dirty);

        project.set_label(0x1000, "main");
        assert_eq!(project.get_label(0x1000), Some("main"));
    }

    #[test]
    fn test_function_overrides() {
        let binary = create_test_binary();
        let mut project = AnalysisProject::new(binary.path()).unwrap();

        project.set_function_name(0x1000, "process_input");
        assert_eq!(project.get_function_name(0x1000), Some("process_input"));
    }

    #[test]
    fn test_bookmarks() {
        let binary = create_test_binary();
        let mut project = AnalysisProject::new(binary.path()).unwrap();

        project.add_bookmark(0x1000, Some("entry".to_string()));
        assert!(project.is_bookmarked(0x1000));
        assert!(!project.is_bookmarked(0x2000));

        project.remove_bookmark(0x1000);
        assert!(!project.is_bookmarked(0x1000));
    }

    #[test]
    fn test_undo_redo() {
        let binary = create_test_binary();
        let mut project = AnalysisProject::new(binary.path()).unwrap();

        project.set_function_name(0x1000, "foo");
        assert_eq!(project.get_function_name(0x1000), Some("foo"));

        project.undo().unwrap();
        assert_eq!(project.get_function_name(0x1000), None);

        project.redo().unwrap();
        assert_eq!(project.get_function_name(0x1000), Some("foo"));
    }

    #[test]
    fn test_save_load() {
        let binary = create_test_binary();
        let mut project = AnalysisProject::new(binary.path()).unwrap();

        project.set_comment(0x1000, "Test comment");
        project.set_function_name(0x2000, "my_func");
        project.add_bookmark(0x3000, Some("bookmark".to_string()));

        let project_file = NamedTempFile::new().unwrap();
        project.save(project_file.path()).unwrap();

        let loaded = AnalysisProject::load(project_file.path()).unwrap();
        assert_eq!(loaded.get_comment(0x1000), Some("Test comment"));
        assert_eq!(loaded.get_function_name(0x2000), Some("my_func"));
        assert!(loaded.is_bookmarked(0x3000));
    }

    // ==================== Error Path Tests ====================

    #[test]
    fn test_new_project_binary_not_found() {
        let result = AnalysisProject::new("/nonexistent/path/to/binary");
        assert!(result.is_err());
        match result.unwrap_err() {
            ProjectError::BinaryNotFound(path) => {
                assert!(path.to_str().unwrap().contains("nonexistent"));
            }
            e => panic!("Expected BinaryNotFound, got {:?}", e),
        }
    }

    #[test]
    fn test_load_nonexistent_project() {
        let result = AnalysisProject::load("/nonexistent/project.hrp");
        assert!(result.is_err());
        match result.unwrap_err() {
            ProjectError::Io(_) => {}
            e => panic!("Expected Io error, got {:?}", e),
        }
    }

    #[test]
    fn test_load_invalid_json() {
        let project_file = NamedTempFile::new().unwrap();
        std::fs::write(project_file.path(), "not valid json {{{").unwrap();

        let result = AnalysisProject::load(project_file.path());
        assert!(result.is_err());
        match result.unwrap_err() {
            ProjectError::Json(_) => {}
            e => panic!("Expected Json error, got {:?}", e),
        }
    }

    #[test]
    fn test_load_future_version() {
        let project_file = NamedTempFile::new().unwrap();
        let json = r#"{
            "version": 999,
            "binary_path": "/tmp/test",
            "binary_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "annotations": {},
            "function_overrides": {},
            "type_overrides": {},
            "bookmarks": []
        }"#;
        std::fs::write(project_file.path(), json).unwrap();

        let result = AnalysisProject::load(project_file.path());
        assert!(result.is_err());
        match result.unwrap_err() {
            ProjectError::UnsupportedVersion(v) => assert_eq!(v, 999),
            e => panic!("Expected UnsupportedVersion, got {:?}", e),
        }
    }

    #[test]
    fn test_undo_nothing() {
        let binary = create_test_binary();
        let mut project = AnalysisProject::new(binary.path()).unwrap();

        let result = project.undo();
        assert!(result.is_err());
        match result.unwrap_err() {
            ProjectError::NothingToUndo => {}
            e => panic!("Expected NothingToUndo, got {:?}", e),
        }
    }

    #[test]
    fn test_redo_nothing() {
        let binary = create_test_binary();
        let mut project = AnalysisProject::new(binary.path()).unwrap();

        let result = project.redo();
        assert!(result.is_err());
        match result.unwrap_err() {
            ProjectError::NothingToRedo => {}
            e => panic!("Expected NothingToRedo, got {:?}", e),
        }
    }

    #[test]
    fn test_undo_after_multiple_operations() {
        let binary = create_test_binary();
        let mut project = AnalysisProject::new(binary.path()).unwrap();

        // Do multiple operations
        project.set_comment(0x1000, "comment1");
        project.set_comment(0x2000, "comment2");
        project.set_function_name(0x3000, "func");

        // Undo all of them
        assert!(project.undo().is_ok());
        assert!(project.undo().is_ok());
        assert!(project.undo().is_ok());

        // Next undo should fail
        assert!(matches!(project.undo(), Err(ProjectError::NothingToUndo)));
    }

    #[test]
    fn test_redo_after_new_operation() {
        let binary = create_test_binary();
        let mut project = AnalysisProject::new(binary.path()).unwrap();

        project.set_comment(0x1000, "comment1");
        project.undo().unwrap();

        // New operation should clear redo history
        project.set_comment(0x2000, "comment2");

        // Redo should fail (history was cleared)
        assert!(matches!(project.redo(), Err(ProjectError::NothingToRedo)));
    }

    #[test]
    fn test_can_undo_can_redo_consistency() {
        let binary = create_test_binary();
        let mut project = AnalysisProject::new(binary.path()).unwrap();

        assert!(!project.can_undo());
        assert!(!project.can_redo());

        project.set_comment(0x1000, "test");
        assert!(project.can_undo());
        assert!(!project.can_redo());

        project.undo().unwrap();
        assert!(!project.can_undo());
        assert!(project.can_redo());

        project.redo().unwrap();
        assert!(project.can_undo());
        assert!(!project.can_redo());
    }

    #[test]
    fn test_load_and_verify_hash_mismatch() {
        let binary = create_test_binary();
        let mut project = AnalysisProject::new(binary.path()).unwrap();

        // Save the project
        let project_file = NamedTempFile::new().unwrap();
        project.save(project_file.path()).unwrap();

        // Modify the binary file to cause hash mismatch
        std::fs::write(binary.path(), b"modified content").unwrap();

        let result = AnalysisProject::load_and_verify(project_file.path());
        assert!(result.is_err());
        match result.unwrap_err() {
            ProjectError::HashMismatch { expected, actual } => {
                assert_ne!(expected, actual);
            }
            e => panic!("Expected HashMismatch, got {:?}", e),
        }
    }

    #[test]
    fn test_load_missing_fields() {
        let project_file = NamedTempFile::new().unwrap();
        // JSON with missing required fields
        let json = r#"{"version": 1}"#;
        std::fs::write(project_file.path(), json).unwrap();

        let result = AnalysisProject::load(project_file.path());
        assert!(result.is_err());
        match result.unwrap_err() {
            ProjectError::Json(_) => {}
            e => panic!("Expected Json error for missing fields, got {:?}", e),
        }
    }

    #[test]
    fn test_load_invalid_hash_format() {
        let project_file = NamedTempFile::new().unwrap();
        let json = r#"{
            "version": 1,
            "binary_path": "/tmp/test",
            "binary_hash": "not_a_valid_hex_hash",
            "annotations": {},
            "function_overrides": {},
            "type_overrides": {},
            "bookmarks": []
        }"#;
        std::fs::write(project_file.path(), json).unwrap();

        let result = AnalysisProject::load(project_file.path());
        assert!(result.is_err());
        match result.unwrap_err() {
            ProjectError::Json(_) => {}
            e => panic!("Expected Json error for invalid hash, got {:?}", e),
        }
    }

    #[test]
    fn test_project_error_display() {
        let err = ProjectError::BinaryNotFound(PathBuf::from("/test/path"));
        assert!(err.to_string().contains("Binary not found"));

        let err = ProjectError::NothingToUndo;
        assert!(err.to_string().contains("Nothing to undo"));

        let err = ProjectError::NothingToRedo;
        assert!(err.to_string().contains("Nothing to redo"));

        let err = ProjectError::UnsupportedVersion(42);
        assert!(err.to_string().contains("42"));

        let err = ProjectError::HashMismatch {
            expected: "aaa".to_string(),
            actual: "bbb".to_string(),
        };
        assert!(err.to_string().contains("aaa"));
        assert!(err.to_string().contains("bbb"));

        let err = ProjectError::InvalidProject("test reason".to_string());
        assert!(err.to_string().contains("test reason"));
    }

    #[test]
    fn test_stats_empty_project() {
        let binary = create_test_binary();
        let project = AnalysisProject::new(binary.path()).unwrap();

        let stats = project.stats();
        assert_eq!(stats.annotation_count, 0);
        assert_eq!(stats.comment_count, 0);
        assert_eq!(stats.label_count, 0);
        assert_eq!(stats.function_override_count, 0);
        assert_eq!(stats.type_override_count, 0);
        assert_eq!(stats.bookmark_count, 0);
        assert_eq!(stats.history_size, 0);
    }

    #[test]
    fn test_stats_populated_project() {
        let binary = create_test_binary();
        let mut project = AnalysisProject::new(binary.path()).unwrap();

        project.set_comment(0x1000, "comment1");
        project.set_comment(0x2000, "comment2");
        project.set_label(0x3000, "label1");
        project.set_function_name(0x4000, "func");
        project.add_bookmark(0x5000, None);

        let stats = project.stats();
        assert_eq!(stats.comment_count, 2);
        assert_eq!(stats.label_count, 1);
        assert_eq!(stats.function_override_count, 1);
        assert_eq!(stats.bookmark_count, 1);
    }

    #[test]
    fn test_overwrite_comment() {
        let binary = create_test_binary();
        let mut project = AnalysisProject::new(binary.path()).unwrap();

        project.set_comment(0x1000, "first comment");
        assert_eq!(project.get_comment(0x1000), Some("first comment"));

        project.set_comment(0x1000, "second comment");
        assert_eq!(project.get_comment(0x1000), Some("second comment"));

        // Should only have one comment
        let annotations = project.annotations.get(&0x1000).unwrap();
        let comment_count = annotations
            .iter()
            .filter(|a| a.kind == AnnotationKind::Comment)
            .count();
        assert_eq!(comment_count, 1);
    }

    #[test]
    fn test_empty_function_name() {
        let binary = create_test_binary();
        let mut project = AnalysisProject::new(binary.path()).unwrap();

        project.set_function_name(0x1000, "");
        assert_eq!(project.get_function_name(0x1000), Some(""));
    }

    #[test]
    fn test_unicode_annotations() {
        let binary = create_test_binary();
        let mut project = AnalysisProject::new(binary.path()).unwrap();

        project.set_comment(0x1000, "日本語コメント");
        project.set_label(0x2000, "函数名称");
        project.set_function_name(0x3000, "функция");

        assert_eq!(project.get_comment(0x1000), Some("日本語コメント"));
        assert_eq!(project.get_label(0x2000), Some("函数名称"));
        assert_eq!(project.get_function_name(0x3000), Some("функция"));

        // Test save/load with unicode
        let project_file = NamedTempFile::new().unwrap();
        project.save(project_file.path()).unwrap();

        let loaded = AnalysisProject::load(project_file.path()).unwrap();
        assert_eq!(loaded.get_comment(0x1000), Some("日本語コメント"));
    }
}
