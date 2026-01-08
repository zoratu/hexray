//! Function boundary detection.

use hexray_core::Symbol;

/// Finds function boundaries in a binary.
pub struct FunctionFinder;

impl FunctionFinder {
    /// Find function entry points from symbols.
    ///
    /// Returns addresses of functions sorted by address.
    pub fn from_symbols(symbols: &[Symbol]) -> Vec<u64> {
        let mut functions: Vec<u64> = symbols
            .iter()
            .filter(|s| s.is_function() && s.is_defined())
            .map(|s| s.address)
            .collect();

        functions.sort_unstable();
        functions.dedup();
        functions
    }
}
