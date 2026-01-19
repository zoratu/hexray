//! Sparse memory model for emulation.
//!
//! Memory is stored in pages to efficiently handle large address spaces
//! while only allocating memory for accessed regions.

use crate::value::Value;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Page size for memory (4KB).
const PAGE_SIZE: u64 = 4096;
const PAGE_MASK: u64 = PAGE_SIZE - 1;

/// A page of memory containing byte values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MemoryPage {
    /// Byte values in this page.
    bytes: Vec<Value>, // Changed from array for serde compatibility
}

impl Default for MemoryPage {
    fn default() -> Self {
        Self {
            bytes: (0..PAGE_SIZE as usize).map(|_| Value::Unknown).collect(),
        }
    }
}

impl MemoryPage {
    fn get(&self, offset: usize) -> &Value {
        &self.bytes[offset]
    }

    fn set(&mut self, offset: usize, value: Value) {
        self.bytes[offset] = value;
    }
}

/// Sparse memory model that only allocates pages when accessed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparseMemory {
    /// Pages indexed by page number (address >> 12).
    pages: HashMap<u64, MemoryPage>,
    /// Initial memory contents loaded from binary.
    initial_data: HashMap<u64, Vec<u8>>,
}

impl SparseMemory {
    /// Create a new empty sparse memory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load initial data from a binary section.
    pub fn load_section(&mut self, base_address: u64, data: &[u8]) {
        self.initial_data.insert(base_address, data.to_vec());
    }

    /// Read a single byte from memory.
    pub fn read_byte(&self, address: u64) -> Value {
        let page_num = address >> 12;
        let page_offset = (address & PAGE_MASK) as usize;

        // Check if we have a modified page
        if let Some(page) = self.pages.get(&page_num) {
            let value = page.get(page_offset);
            if !value.is_unknown() {
                return value.clone();
            }
        }

        // Fall back to initial data
        for (&base, data) in &self.initial_data {
            if address >= base && address < base + data.len() as u64 {
                let offset = (address - base) as usize;
                return Value::Concrete(data[offset] as u64);
            }
        }

        Value::Unknown
    }

    /// Write a single byte to memory.
    pub fn write_byte(&mut self, address: u64, value: Value) {
        let page_num = address >> 12;
        let page_offset = (address & PAGE_MASK) as usize;

        let page = self.pages.entry(page_num).or_default();
        page.set(page_offset, value);
    }

    /// Read an N-byte value (little-endian).
    pub fn read(&self, address: u64, size: usize) -> Value {
        if size == 0 || size > 8 {
            return Value::Unknown;
        }

        // Try to read all bytes as concrete
        let mut result: u64 = 0;
        let mut all_concrete = true;

        for i in 0..size {
            let byte = self.read_byte(address + i as u64);
            match byte {
                Value::Concrete(b) => {
                    result |= (b & 0xFF) << (i * 8);
                }
                _ => {
                    all_concrete = false;
                    break;
                }
            }
        }

        if all_concrete {
            Value::Concrete(result)
        } else {
            Value::Unknown
        }
    }

    /// Write an N-byte value (little-endian).
    pub fn write(&mut self, address: u64, value: Value, size: usize) {
        match value {
            Value::Concrete(v) => {
                for i in 0..size {
                    let byte = (v >> (i * 8)) & 0xFF;
                    self.write_byte(address + i as u64, Value::Concrete(byte));
                }
            }
            _ => {
                // For non-concrete values, mark all bytes as the same symbolic/unknown
                for i in 0..size {
                    self.write_byte(address + i as u64, value.clone());
                }
            }
        }
    }

    /// Read an 8-bit value.
    pub fn read_u8(&self, address: u64) -> Value {
        self.read_byte(address)
    }

    /// Read a 16-bit value (little-endian).
    pub fn read_u16(&self, address: u64) -> Value {
        self.read(address, 2)
    }

    /// Read a 32-bit value (little-endian).
    pub fn read_u32(&self, address: u64) -> Value {
        self.read(address, 4)
    }

    /// Read a 64-bit value (little-endian).
    pub fn read_u64(&self, address: u64) -> Value {
        self.read(address, 8)
    }

    /// Write an 8-bit value.
    pub fn write_u8(&mut self, address: u64, value: Value) {
        self.write_byte(address, value.trunc(8));
    }

    /// Write a 16-bit value.
    pub fn write_u16(&mut self, address: u64, value: Value) {
        self.write(address, value.trunc(16), 2);
    }

    /// Write a 32-bit value.
    pub fn write_u32(&mut self, address: u64, value: Value) {
        self.write(address, value.trunc(32), 4);
    }

    /// Write a 64-bit value.
    pub fn write_u64(&mut self, address: u64, value: Value) {
        self.write(address, value, 8);
    }

    /// Check if an address has been written to.
    pub fn is_written(&self, address: u64) -> bool {
        let page_num = address >> 12;
        let page_offset = (address & PAGE_MASK) as usize;

        if let Some(page) = self.pages.get(&page_num) {
            !page.get(page_offset).is_unknown()
        } else {
            false
        }
    }

    /// Get all written addresses (for debugging).
    pub fn written_addresses(&self) -> Vec<u64> {
        let mut addrs = Vec::new();
        for (&page_num, page) in &self.pages {
            for (offset, value) in page.bytes.iter().enumerate() {
                if !value.is_unknown() {
                    addrs.push((page_num << 12) | offset as u64);
                }
            }
        }
        addrs.sort();
        addrs
    }

    /// Clear all modifications.
    pub fn clear(&mut self) {
        self.pages.clear();
    }

    /// Get number of allocated pages.
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_write_byte() {
        let mut mem = SparseMemory::new();

        mem.write_byte(0x1000, Value::Concrete(0x42));
        assert_eq!(mem.read_byte(0x1000), Value::Concrete(0x42));

        // Unwritten memory is unknown
        assert_eq!(mem.read_byte(0x2000), Value::Unknown);
    }

    #[test]
    fn test_read_write_multi_byte() {
        let mut mem = SparseMemory::new();

        mem.write_u32(0x1000, Value::Concrete(0xDEADBEEF));
        assert_eq!(mem.read_u32(0x1000), Value::Concrete(0xDEADBEEF));

        // Check individual bytes (little-endian)
        assert_eq!(mem.read_byte(0x1000), Value::Concrete(0xEF));
        assert_eq!(mem.read_byte(0x1001), Value::Concrete(0xBE));
        assert_eq!(mem.read_byte(0x1002), Value::Concrete(0xAD));
        assert_eq!(mem.read_byte(0x1003), Value::Concrete(0xDE));
    }

    #[test]
    fn test_initial_data() {
        let mut mem = SparseMemory::new();

        // Load a section
        mem.load_section(0x1000, &[0x11, 0x22, 0x33, 0x44]);

        assert_eq!(mem.read_byte(0x1000), Value::Concrete(0x11));
        assert_eq!(mem.read_byte(0x1003), Value::Concrete(0x44));
        assert_eq!(mem.read_u32(0x1000), Value::Concrete(0x44332211));

        // Write over initial data
        mem.write_byte(0x1000, Value::Concrete(0xFF));
        assert_eq!(mem.read_byte(0x1000), Value::Concrete(0xFF));

        // Other bytes still use initial data
        assert_eq!(mem.read_byte(0x1001), Value::Concrete(0x22));
    }

    #[test]
    fn test_cross_page_access() {
        let mut mem = SparseMemory::new();

        // Write at page boundary
        mem.write_u32(0xFFE, Value::Concrete(0xAABBCCDD));

        // Read back (spans two pages)
        assert_eq!(mem.read_u32(0xFFE), Value::Concrete(0xAABBCCDD));
    }
}
