//! Symbol and relocation types.

/// Parsed GNU symbol-version metadata from a symbol name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymbolVersion<'a> {
    /// Version name, such as `GLIBC_2.2.5`.
    pub name: &'a str,
    /// Whether this is the default exported version (`@@name`).
    pub is_default: bool,
}

/// Strip a synthesized `@plt` suffix from a symbol name.
pub fn strip_plt_suffix(name: &str) -> &str {
    name.strip_suffix("@plt").unwrap_or(name)
}

/// Parse a GNU version suffix from a symbol name, if present.
pub fn gnu_symbol_version(name: &str) -> Option<SymbolVersion<'_>> {
    let bare = strip_plt_suffix(name);

    if let Some((base, version)) = bare.split_once("@@") {
        if !base.is_empty() && !version.is_empty() {
            return Some(SymbolVersion {
                name: version,
                is_default: true,
            });
        }
    }

    let (base, version) = bare.rsplit_once('@')?;
    if base.is_empty() || version.is_empty() {
        return None;
    }

    Some(SymbolVersion {
        name: version,
        is_default: false,
    })
}

/// Return the symbol name without any GNU version or synthesized `@plt` suffix.
pub fn unversioned_symbol_name(name: &str) -> &str {
    let bare = strip_plt_suffix(name);

    if let Some((base, version)) = bare.split_once("@@") {
        if !base.is_empty() && !version.is_empty() {
            return base;
        }
    }

    if let Some((base, version)) = bare.rsplit_once('@') {
        if !base.is_empty() && !version.is_empty() {
            return base;
        }
    }

    bare
}

/// A symbol from the binary's symbol table.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Symbol {
    /// Symbol name (may be empty for some symbols).
    pub name: String,
    /// Virtual address of the symbol.
    pub address: u64,
    /// Size of the symbol (0 if unknown).
    pub size: u64,
    /// Symbol type.
    pub kind: SymbolKind,
    /// Symbol binding (local, global, weak).
    pub binding: SymbolBinding,
    /// Section index this symbol is defined in (or None for special sections).
    pub section_index: Option<u32>,
}

impl Symbol {
    /// Returns true if this symbol is a function.
    pub fn is_function(&self) -> bool {
        matches!(self.kind, SymbolKind::Function)
    }

    /// Returns true if this symbol is a data object.
    pub fn is_object(&self) -> bool {
        matches!(self.kind, SymbolKind::Object)
    }

    /// Returns true if this symbol is defined (has an address).
    pub fn is_defined(&self) -> bool {
        self.address != 0 || self.section_index.is_some()
    }

    /// Returns true if this symbol is global.
    pub fn is_global(&self) -> bool {
        matches!(self.binding, SymbolBinding::Global)
    }

    /// Returns the symbol name without any synthesized `@plt` suffix.
    pub fn name_without_plt(&self) -> &str {
        strip_plt_suffix(&self.name)
    }

    /// Returns the symbol name without any GNU version or `@plt` suffix.
    pub fn unversioned_name(&self) -> &str {
        unversioned_symbol_name(&self.name)
    }

    /// Returns GNU version metadata parsed from the symbol name, if present.
    pub fn version(&self) -> Option<SymbolVersion<'_>> {
        gnu_symbol_version(&self.name)
    }

    /// Returns true if this symbol has the default exported GNU version.
    pub fn is_default_version(&self) -> bool {
        self.version().is_some_and(|version| version.is_default)
    }

    /// Returns true if this symbol name carries the synthesized `@plt` suffix.
    pub fn is_plt(&self) -> bool {
        self.name_without_plt().len() != self.name.len()
    }
}

/// Symbol type/kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SymbolKind {
    /// No type (unspecified).
    None,
    /// Data object (variable, array, etc.).
    Object,
    /// Function or other executable code.
    Function,
    /// Section symbol.
    Section,
    /// File name symbol.
    File,
    /// Common data object.
    Common,
    /// Thread-local storage object.
    Tls,
    /// Other/unknown type.
    Other(u8),
}

/// Symbol binding (visibility/linkage).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SymbolBinding {
    /// Local symbol (not visible outside object file).
    Local,
    /// Global symbol (visible to all object files).
    Global,
    /// Weak symbol (like global but can be overridden).
    Weak,
    /// Other/unknown binding.
    Other(u8),
}

/// A relocation entry.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Relocation {
    /// Offset in the section where the relocation applies.
    pub offset: u64,
    /// Symbol index this relocation refers to.
    pub symbol_index: u32,
    /// Relocation type (architecture-specific).
    pub reloc_type: u32,
    /// Addend (for RELA relocations).
    pub addend: i64,
}
