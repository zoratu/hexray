//! Automatic-analysis range policy and packing *hints*.
//!
//! Two separate concerns live here on purpose:
//!
//! - [`ScopeMap`] is the execution view of a persisted
//!   [`hexray_db::AnalysisScope`]: merged, sorted half-open excluded spans that
//!   limit where the automatic analysis chain may decode. It never hides
//!   sections from the image; it only clamps decode windows and target queues.
//! - [`section_hint`] is a read-only heuristic table shown on request. High
//!   entropy or a UPX-looking section name is evidence for the user, never an
//!   automatic skip: nothing here changes analysis unless the user edits the
//!   scope.
//!
//! Nothing in this module touches the database, prints, or depends on the
//! current time; the same inputs always produce the same output.

use anyhow::{bail, Result};
use hexray_db::AnalysisScope;
use serde::Serialize;

/// Warning that must accompany every section-hint table.
pub(crate) const SECTION_HINTS_WARNING: &str = "heuristic hints only; high entropy and section names do not prove packing; no section is skipped automatically";

/// Minimum Shannon entropy (bits per byte) at which the high-entropy hint fires.
const HIGH_ENTROPY_BITS_PER_BYTE: f64 = 7.5;

/// Minimum file-backed size for the high-entropy hint. Zero padding and tiny
/// sections never qualify; the entropy value itself is still reported.
const HIGH_ENTROPY_MIN_BYTES: usize = 4096;

/// Parse a `start:end` skip range into two virtual addresses.
///
/// Both sides are hexadecimal with an optional `0x`/`0X` prefix; the range is
/// half-open (`end` excluded). Signs, whitespace and empty sides are rejected,
/// as are reversed/empty ranges and values that do not fit in `u64`.
pub(crate) fn parse_skip_range(text: &str) -> Result<(u64, u64)> {
    let Some((start_text, end_text)) = text.split_once(':') else {
        bail!(
            "invalid skip range '{text}': expected start:end (hexadecimal virtual addresses, end excluded)"
        );
    };
    let start = parse_hex_address(start_text, text)?;
    let end = parse_hex_address(end_text, text)?;
    if end <= start {
        bail!(
            "invalid skip range '{text}': expected start:end with end > start (got 0x{start:x}:0x{end:x})"
        );
    }
    Ok((start, end))
}

fn parse_hex_address(side: &str, whole: &str) -> Result<u64> {
    let digits = if let Some(stripped) = side.strip_prefix("0x") {
        stripped
    } else if let Some(stripped) = side.strip_prefix("0X") {
        stripped
    } else {
        side
    };
    let valid_digits = !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_hexdigit());
    if !valid_digits {
        bail!(
            "invalid skip range '{whole}': '{side}' is not a 64-bit hexadecimal address (expected start:end)"
        );
    }
    let Ok(address) = u64::from_str_radix(digits, 16) else {
        bail!(
            "invalid skip range '{whole}': '{side}' does not fit in 64 bits (expected start:end)"
        );
    };
    Ok(address)
}

/// Immutable execution view of a persisted [`AnalysisScope`].
///
/// Spans are merged, sorted and half-open, so point queries binary-search them.
/// The canonical fingerprint is the persisted policy's own fingerprint (merged
/// numeric spans plus payload version); section labels are display-only and
/// never enter it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScopeMap {
    spans: Vec<(u64, u64)>,
    fingerprint: [u8; 32],
}

impl ScopeMap {
    pub(crate) fn from_scope(scope: &AnalysisScope) -> Self {
        Self {
            spans: scope.merged_intervals(),
            fingerprint: scope.fingerprint(),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    pub(crate) fn spans(&self) -> &[(u64, u64)] {
        &self.spans
    }

    /// True when `address` is inside an excluded span.
    pub(crate) fn contains(&self, address: u64) -> bool {
        self.span_containing(address).is_some()
    }

    /// Exclusive end of the excluded span containing `address`.
    pub(crate) fn barrier_end(&self, address: u64) -> Option<u64> {
        self.span_containing(address).map(|(_, end)| end)
    }

    /// Start of the first excluded span at or after `address`.
    pub(crate) fn next_start(&self, address: u64) -> Option<u64> {
        let index = self.spans.partition_point(|(start, _)| *start < address);
        self.spans.get(index).map(|(start, _)| *start)
    }

    /// Clamp a `[start, start + max_bytes)` decode window to the next exclusion
    /// boundary.
    ///
    /// An entry point that is itself excluded yields `(0, true)`: such a
    /// function may not be decoded at all. Otherwise the returned byte count is
    /// the smaller of `max_bytes` and the distance to the next span start;
    /// `stopped_at_scope` reports that a span start truncated the request (an
    /// exact landing on the boundary does not count as truncation).
    pub(crate) fn clamp_window(&self, start: u64, max_bytes: usize) -> (usize, bool) {
        if self.contains(start) {
            return (0, true);
        }
        // u128 keeps `start + max_bytes` from wrapping: the requested end is
        // only lowered by the next span start, never by arithmetic saturation.
        let requested_end = start as u128 + max_bytes as u128;
        let span_start = self.next_start(start).map(u128::from);
        let end = match span_start {
            Some(span) => requested_end.min(span),
            None => requested_end,
        };
        let allowed = (end - u128::from(start)) as usize;
        let stopped_at_scope = span_start.is_some_and(|span| span < requested_end);
        (allowed, stopped_at_scope)
    }

    /// Canonical fingerprint of the persisted policy: merged spans plus the
    /// payload version.
    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// Sub-ranges of `[start, end)` that the scope leaves included.
    ///
    /// Used to keep whole-range scans (the ENDBR seed sweep) off excluded bytes
    /// instead of scanning and then discarding the result. An empty scope
    /// returns the input unchanged; a fully excluded range returns nothing.
    pub(crate) fn included_ranges(&self, start: u64, end: u64) -> Vec<(u64, u64)> {
        if end <= start {
            return Vec::new();
        }
        if self.spans.is_empty() {
            return vec![(start, end)];
        }
        let mut included = Vec::new();
        let mut cursor = start;
        for (span_start, span_end) in &self.spans {
            if *span_end <= cursor {
                continue;
            }
            if *span_start >= end {
                break;
            }
            if *span_start > cursor {
                included.push((cursor, (*span_start).min(end)));
            }
            cursor = cursor.max(*span_end);
            if cursor >= end {
                break;
            }
        }
        if cursor < end {
            included.push((cursor, end));
        }
        included
    }

    fn span_containing(&self, address: u64) -> Option<(u64, u64)> {
        let index = self.spans.partition_point(|(_, end)| *end <= address);
        let span = *self.spans.get(index)?;
        (span.0 <= address).then_some(span)
    }
}

/// One executable section's packing evidence. Display-only; never persisted.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct SectionHint {
    pub name: String,
    pub start: u64,
    pub end: u64,
    pub file_bytes: u64,
    pub entropy_bits_per_byte: Option<f64>,
    pub reasons: Vec<&'static str>,
    pub suggest_skip: bool,
}

/// Shannon entropy of `bytes` in bits per byte.
///
/// One `O(bytes)` pass over 256 `u64` buckets; `None` only for an empty slice.
/// Callers must pass file-backed bytes only — zero-filled virtual regions are
/// not file samples.
pub(crate) fn entropy_bits_per_byte(bytes: &[u8]) -> Option<f64> {
    if bytes.is_empty() {
        return None;
    }
    let mut counts = [0u64; 256];
    for &byte in bytes {
        counts[byte as usize] += 1;
    }
    let total = bytes.len() as f64;
    let mut entropy = 0.0f64;
    for count in counts {
        if count > 0 {
            let probability = count as f64 / total;
            entropy -= probability * probability.log2();
        }
    }
    Some(entropy)
}

/// Classify one executable section as a read-only packing *hint*.
///
/// `writable`/`executable` must be the mapping permissions (for Mach-O the
/// segment mapping, not the section's always-false writable flag). The caller
/// passes only file-backed bytes; `file_bytes` is their length. Reasons are
/// fixed-order: `high_entropy`, `upx_section_name`, `writable_executable`.
/// Only the first two suggest skipping; W+X alone is evidence, not a verdict.
pub(crate) fn section_hint(
    name: &str,
    start: u64,
    end: u64,
    bytes: &[u8],
    writable: bool,
    executable: bool,
) -> SectionHint {
    let entropy = entropy_bits_per_byte(bytes);
    let mut reasons: Vec<&'static str> = Vec::new();
    if bytes.len() >= HIGH_ENTROPY_MIN_BYTES
        && entropy.is_some_and(|bits| bits >= HIGH_ENTROPY_BITS_PER_BYTE)
    {
        reasons.push("high_entropy");
    }
    if is_upx_section_name(name) {
        reasons.push("upx_section_name");
    }
    if writable && executable {
        reasons.push("writable_executable");
    }
    let suggest_skip = reasons
        .iter()
        .any(|reason| *reason == "high_entropy" || *reason == "upx_section_name");
    SectionHint {
        name: name.to_string(),
        start,
        end,
        file_bytes: bytes.len() as u64,
        entropy_bits_per_byte: entropy,
        reasons,
        suggest_skip,
    }
}

/// Case-insensitive exact UPX stub name (`UPX0`/`UPX1`/`UPX2`, one optional
/// leading dot). Nothing else: `UPX3`, `.UPX1x` or a second dot do not match.
fn is_upx_section_name(name: &str) -> bool {
    let bare = name.strip_prefix('.').unwrap_or(name);
    ["UPX0", "UPX1", "UPX2"]
        .iter()
        .any(|upx| bare.eq_ignore_ascii_case(upx))
}

#[cfg(test)]
mod tests {
    use super::{
        entropy_bits_per_byte, parse_skip_range, section_hint, ScopeMap, SECTION_HINTS_WARNING,
    };
    use hexray_db::{Address, AnalysisScope, ScopeRange};
    use proptest::prelude::*;

    /// Small address window used by the naive per-byte reference test.
    const REFERENCE_LIMIT: u64 = 64;

    fn scope_from_raw(ranges: &[(u64, u64)]) -> AnalysisScope {
        AnalysisScope {
            payload_version: AnalysisScope::CURRENT_PAYLOAD_VERSION,
            excluded_ranges: ranges
                .iter()
                .map(|&(start, end)| ScopeRange {
                    start: Address(start),
                    end: Address(end),
                    section_name: None,
                })
                .collect(),
        }
    }

    fn range_strategy() -> impl Strategy<Value = (u64, u64)> {
        (0u64..REFERENCE_LIMIT, 0u64..REFERENCE_LIMIT)
            .prop_map(|(a, b)| (a.min(b), a.max(b)))
    }

    fn high_entropy_bytes(len: usize) -> Vec<u8> {
        (0..len).map(|index| (index % 256) as u8).collect()
    }

    #[test]
    fn parse_skip_range_accepts_hex_pairs() {
        assert_eq!(parse_skip_range("1000:2000").unwrap(), (0x1000, 0x2000));

        let lower_prefixed = parse_skip_range("0x1000:0x2000").unwrap();
        assert_eq!(lower_prefixed, (0x1000, 0x2000));
        let upper_prefixed = parse_skip_range("0X1000:2000").unwrap();
        assert_eq!(upper_prefixed, (0x1000, 0x2000));

        let full = parse_skip_range("0:ffffffffffffffff").unwrap();
        assert_eq!(full, (0, u64::MAX));
    }

    #[test]
    fn parse_skip_range_rejects_invalid_input() {
        for text in [
            "0x2000:0x1000",
            "1000",
            "zz:2000",
            "1:2:3",
            "ffffffffffffffffff:1",
            "",
            "1000:",
            ":2000",
            "+1:2",
            "1000:2000 ",
            "1000:1000",
        ] {
            assert!(parse_skip_range(text).is_err(), "accepted '{text}'");
        }

        let error = parse_skip_range("zz:2000").unwrap_err().to_string();
        assert!(error.contains("zz:2000"), "unhelpful error: {error}");
        assert!(error.contains("start:end"), "unhelpful error: {error}");
    }

    #[test]
    fn entropy_of_uniform_bytes_is_exactly_eight_bits() {
        let bytes = high_entropy_bytes(4096);
        let entropy = entropy_bits_per_byte(&bytes);
        assert_eq!(entropy, Some(8.0));
    }

    #[test]
    fn entropy_of_zeros_is_zero() {
        assert_eq!(entropy_bits_per_byte(&[0u8; 4096]), Some(0.0));
    }

    #[test]
    fn entropy_of_tiny_and_empty_inputs() {
        assert_eq!(entropy_bits_per_byte(&[]), None);
        assert_eq!(entropy_bits_per_byte(&[0x42]), Some(0.0));
        assert_eq!(entropy_bits_per_byte(&[0x00, 0xff]), Some(1.0));
    }

    proptest! {
        #[test]
        fn entropy_stays_within_bounds(
            bytes in proptest::collection::vec(any::<u8>(), 1..=4096)
        ) {
            let entropy = entropy_bits_per_byte(&bytes).expect("non-empty input has entropy");
            prop_assert!(
                (0.0..=8.0).contains(&entropy),
                "entropy {} left [0, 8]",
                entropy
            );
        }

        #[test]
        fn entropy_is_permutation_invariant(
            input in (1usize..=1024).prop_flat_map(|len| (
                proptest::collection::vec(any::<u8>(), len..=len),
                proptest::collection::vec(any::<u32>(), len..=len),
            ))
        ) {
            let (bytes, keys) = input;
            let mut order: Vec<usize> = (0..bytes.len()).collect();
            order.sort_by_key(|&index| keys[index]);
            let permuted: Vec<u8> = order.iter().map(|&index| bytes[index]).collect();
            let original = entropy_bits_per_byte(&bytes).expect("non-empty input has entropy");
            let shuffled = entropy_bits_per_byte(&permuted).expect("non-empty input has entropy");
            prop_assert!(
                (original - shuffled).abs() < 1e-9,
                "entropy changed under permutation: {} vs {}",
                original,
                shuffled
            );
        }
    }

    #[test]
    fn section_hints_warning_is_the_documented_text() {
        assert_eq!(
            SECTION_HINTS_WARNING,
            "heuristic hints only; high entropy and section names do not prove packing; no section is skipped automatically"
        );
    }

    #[test]
    fn high_entropy_section_suggests_skipping() {
        let bytes = high_entropy_bytes(4096);
        let hint = section_hint(".packed", 0x1000, 0x2000, &bytes, false, true);
        assert_eq!(hint.name, ".packed");
        assert_eq!(hint.start, 0x1000);
        assert_eq!(hint.end, 0x2000);
        assert_eq!(hint.file_bytes, 4096);
        assert_eq!(hint.entropy_bits_per_byte, Some(8.0));
        assert_eq!(hint.reasons, vec!["high_entropy"]);
        assert!(hint.suggest_skip);
    }

    #[test]
    fn zero_filled_section_is_not_suspicious() {
        let hint = section_hint(".text", 0x1000, 0x2000, &[0u8; 4096], false, true);
        assert_eq!(hint.entropy_bits_per_byte, Some(0.0));
        assert!(hint.reasons.is_empty());
        assert!(!hint.suggest_skip);
    }

    #[test]
    fn upx_names_are_case_insensitive_with_one_optional_dot() {
        for name in [".UPX1", "upx0", "UPX2", ".upx1"] {
            let hint = section_hint(name, 0, 0x100, &[0u8; 32], false, true);
            assert_eq!(hint.reasons, vec!["upx_section_name"], "{name}");
            assert!(hint.suggest_skip, "{name}");
        }

        for name in ["..UPX1", "UPX3", ".UPX1x", "text"] {
            let hint = section_hint(name, 0, 0x100, &[0u8; 32], false, true);
            assert!(hint.reasons.is_empty(), "{name}");
            assert!(!hint.suggest_skip, "{name}");
        }
    }

    #[test]
    fn plain_low_entropy_text_section_has_no_reasons() {
        let hint = section_hint(".text", 0x1000, 0x2000, &[0x90; 64], false, true);
        assert_eq!(hint.file_bytes, 64);
        assert_eq!(hint.entropy_bits_per_byte, Some(0.0));
        assert!(hint.reasons.is_empty());
        assert!(!hint.suggest_skip);
    }

    #[test]
    fn writable_executable_alone_never_suggests_skipping() {
        let hint = section_hint(".data", 0, 0x100, &[0u8; 32], true, true);
        assert_eq!(hint.reasons, vec!["writable_executable"]);
        assert!(!hint.suggest_skip);
    }

    #[test]
    fn high_entropy_below_the_size_floor_is_reported_but_not_suggested() {
        let bytes = high_entropy_bytes(1024);
        let hint = section_hint(".packed", 0, 0x400, &bytes, false, true);
        assert_eq!(hint.file_bytes, 1024);
        assert_eq!(hint.entropy_bits_per_byte, Some(8.0));
        assert!(!hint.reasons.contains(&"high_entropy"));
        assert!(!hint.suggest_skip);
    }

    #[test]
    fn reasons_keep_their_fixed_order() {
        let bytes = high_entropy_bytes(4096);
        let hint = section_hint(".UPX0", 0, 0x1000, &bytes, true, true);
        assert_eq!(
            hint.reasons,
            vec!["high_entropy", "upx_section_name", "writable_executable"]
        );
        assert!(hint.suggest_skip);
    }

    #[test]
    fn empty_scope_allows_every_window() {
        let map = ScopeMap::from_scope(&AnalysisScope::empty());
        assert!(map.is_empty());
        assert!(map.spans().is_empty());
        assert!(!map.contains(0x4000));
        assert_eq!(map.barrier_end(0x4000), None);
        assert_eq!(map.next_start(0x4000), None);
        assert_eq!(map.clamp_window(0x4000, 0x20), (0x20, false));
    }

    #[test]
    fn included_ranges_subtract_the_excluded_spans() {
        let map = ScopeMap::from_scope(&scope_from_raw(&[(0x20, 0x30), (0x40, 0x80)]));
        assert_eq!(
            map.included_ranges(0x10, 0x90),
            vec![(0x10, 0x20), (0x30, 0x40), (0x80, 0x90)]
        );
        // Range ends inside an excluded span keep only the included head.
        assert_eq!(map.included_ranges(0x10, 0x28), vec![(0x10, 0x20)]);
        // A range fully inside an excluded span yields nothing.
        assert!(map.included_ranges(0x24, 0x28).is_empty());
        // A fully excluded section is skipped without scanning.
        assert!(map.included_ranges(0x40, 0x80).is_empty());
        // Empty and inverted ranges are empty.
        assert!(map.included_ranges(0x30, 0x30).is_empty());
        assert!(map.included_ranges(0x40, 0x20).is_empty());
        // An empty scope returns the input range unchanged.
        let empty = ScopeMap::from_scope(&AnalysisScope::empty());
        assert_eq!(empty.included_ranges(0x10, 0x20), vec![(0x10, 0x20)]);
    }

    #[test]
    fn overlapping_and_adjacent_ranges_merge() {
        let map = ScopeMap::from_scope(&scope_from_raw(&[
            (0x40, 0x50),
            (0x10, 0x20),
            (0x20, 0x30),
            (0x18, 0x1c),
            (0x60, 0x60),
        ]));
        assert_eq!(map.spans(), &[(0x10, 0x30), (0x40, 0x50)]);
        assert!(map.contains(0x1f));
        assert!(!map.contains(0x30));
        assert_eq!(map.barrier_end(0x1f), Some(0x30));
        assert_eq!(map.next_start(0x30), Some(0x40));
        assert_eq!(map.next_start(0x50), None);
    }

    #[test]
    fn fingerprint_tracks_the_canonical_policy() {
        let scope = scope_from_raw(&[(0x10, 0x20)]);
        let merged = ScopeMap::from_scope(&scope);
        assert_eq!(merged.fingerprint(), scope.fingerprint());

        let split = ScopeMap::from_scope(&scope_from_raw(&[(0x10, 0x18), (0x18, 0x20)]));
        assert_eq!(merged.spans(), split.spans());
        assert_eq!(merged.fingerprint(), split.fingerprint());

        let different = ScopeMap::from_scope(&scope_from_raw(&[(0x10, 0x21)]));
        assert_ne!(merged.fingerprint(), different.fingerprint());
    }

    #[test]
    fn clamp_window_stops_at_the_next_scope_start() {
        let map = ScopeMap::from_scope(&scope_from_raw(&[(0x2000, 0x2010)]));
        assert_eq!(map.clamp_window(0x1000, 0x10), (0x10, false));
        assert_eq!(map.clamp_window(0x1ff8, 0x10), (8, true));
        assert_eq!(map.clamp_window(0x1ff0, 0x10), (0x10, false));
        assert_eq!(map.clamp_window(0x2000, 0x10), (0, true));
        assert_eq!(map.clamp_window(0x2004, 0x10), (0, true));
        assert_eq!(map.clamp_window(0x2010, 0x10), (0x10, false));
    }

    #[test]
    fn merged_spans_and_windows_stay_overflow_safe() {
        let map = ScopeMap::from_scope(&scope_from_raw(&[
            (u64::MAX - 10, u64::MAX - 5),
            (u64::MAX - 5, u64::MAX),
            (u64::MAX - 2, u64::MAX),
        ]));
        assert_eq!(map.spans(), &[(u64::MAX - 10, u64::MAX)]);
        assert!(map.contains(u64::MAX - 10));
        assert!(map.contains(u64::MAX - 1));
        assert!(!map.contains(u64::MAX));
        assert_eq!(map.barrier_end(u64::MAX - 1), Some(u64::MAX));
        assert_eq!(map.next_start(u64::MAX - 11), Some(u64::MAX - 10));
        assert_eq!(map.next_start(u64::MAX), None);
        assert_eq!(map.clamp_window(u64::MAX - 12, 100), (2, true));
        assert_eq!(map.clamp_window(u64::MAX - 2, 100), (0, true));
    }

    #[test]
    fn clamp_window_without_scope_allows_the_whole_request_at_the_top() {
        let map = ScopeMap::from_scope(&AnalysisScope::empty());
        assert_eq!(map.clamp_window(u64::MAX - 4, 100), (100, false));
        assert_eq!(map.clamp_window(u64::MAX, 100), (100, false));
    }

    proptest! {
        #[test]
        fn scope_map_matches_a_per_byte_reference(
            raw in proptest::collection::vec(range_strategy(), 0..=8)
        ) {
            let mut excluded = [false; REFERENCE_LIMIT as usize];
            for &(start, end) in &raw {
                for address in start..end {
                    excluded[address as usize] = true;
                }
            }

            let mut expected: Vec<(u64, u64)> = Vec::new();
            let mut address = 0u64;
            while address < REFERENCE_LIMIT {
                if !excluded[address as usize] {
                    address += 1;
                    continue;
                }
                let start = address;
                while address < REFERENCE_LIMIT && excluded[address as usize] {
                    address += 1;
                }
                expected.push((start, address));
            }

            let map = ScopeMap::from_scope(&scope_from_raw(&raw));
            prop_assert_eq!(map.spans(), expected.as_slice());

            for address in 0..REFERENCE_LIMIT {
                prop_assert_eq!(map.contains(address), excluded[address as usize]);
                let reference_barrier = expected
                    .iter()
                    .find(|(start, end)| address >= *start && address < *end)
                    .map(|(_, end)| *end);
                prop_assert_eq!(map.barrier_end(address), reference_barrier);
                let reference_next = expected
                    .iter()
                    .map(|(start, _)| *start)
                    .find(|start| *start >= address);
                prop_assert_eq!(map.next_start(address), reference_next);
            }
            prop_assert!(!map.contains(REFERENCE_LIMIT));
        }
    }
}
