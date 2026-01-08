//! Traits for binary format abstraction.

use hexray_core::{Architecture, Bitness, Endianness, Symbol};

/// A parsed binary file.
///
/// This trait abstracts over different binary formats (ELF, Mach-O, etc.)
/// to provide a uniform interface for the disassembler.
pub trait BinaryFormat {
    /// Returns the target architecture.
    fn architecture(&self) -> Architecture;

    /// Returns the byte order.
    fn endianness(&self) -> Endianness;

    /// Returns whether this is a 32-bit or 64-bit binary.
    fn bitness(&self) -> Bitness;

    /// Returns the entry point address, if any.
    fn entry_point(&self) -> Option<u64>;

    /// Returns an iterator over executable sections.
    fn executable_sections(&self) -> Box<dyn Iterator<Item = &dyn Section> + '_>;

    /// Returns an iterator over all sections.
    fn sections(&self) -> Box<dyn Iterator<Item = &dyn Section> + '_>;

    /// Returns an iterator over symbols.
    fn symbols(&self) -> Box<dyn Iterator<Item = &Symbol> + '_>;

    /// Resolves an address to a symbol name, if known.
    fn symbol_at(&self, addr: u64) -> Option<&Symbol>;

    /// Returns raw bytes at a given virtual address.
    fn bytes_at(&self, addr: u64, len: usize) -> Option<&[u8]>;

    /// Returns the section containing the given address.
    fn section_containing(&self, addr: u64) -> Option<&dyn Section>;
}

/// A section in a binary.
pub trait Section {
    /// Section name.
    fn name(&self) -> &str;

    /// Virtual address where this section is loaded.
    fn virtual_address(&self) -> u64;

    /// Size in bytes.
    fn size(&self) -> u64;

    /// Raw section data.
    fn data(&self) -> &[u8];

    /// Returns true if this section contains executable code.
    fn is_executable(&self) -> bool;

    /// Returns true if this section is writable.
    fn is_writable(&self) -> bool;

    /// Returns true if this section is loaded into memory.
    fn is_allocated(&self) -> bool;
}
