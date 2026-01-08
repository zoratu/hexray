//! Symbol and relocation types.

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
