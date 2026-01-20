//! String detection comparison tests.
//!
//! These tests compare hexray's string detection against the `strings` command
//! to verify string extraction accuracy.

use super::{
    compare_strings as compare_string_sets, fixture_path, parse_strings_ordered,
    parse_strings_output, run_strings, run_strings_with_encoding, StringDiffResult,
};
use hexray_analysis::{DetectedString, StringConfig, StringDetector, StringEncoding};
use std::collections::HashSet;
use std::fs;

/// Minimum match rate threshold for string tests.
/// Lower than other tests because string detection algorithms differ significantly.
const STRING_MATCH_THRESHOLD: f64 = 0.80;

/// Default minimum string length for comparison.
const DEFAULT_MIN_LENGTH: usize = 4;

/// Extract strings from a binary using hexray.
pub fn extract_strings_hexray(binary_path: &str, min_len: usize) -> HashSet<String> {
    let data = match fs::read(binary_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to read {}: {}", binary_path, e);
            return HashSet::new();
        }
    };

    let config = StringConfig {
        min_length: min_len,
        require_null_terminator: true, // Match strings command behavior
        ..Default::default()
    };

    let detector = StringDetector::with_config(config);
    detector
        .detect(&data, 0)
        .into_iter()
        .map(|s| s.content)
        .collect()
}

/// Extract strings with additional configuration options.
pub fn extract_strings_hexray_configured(
    binary_path: &str,
    config: StringConfig,
) -> HashSet<String> {
    let data = match fs::read(binary_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to read {}: {}", binary_path, e);
            return HashSet::new();
        }
    };

    let detector = StringDetector::with_config(config);
    detector
        .detect(&data, 0)
        .into_iter()
        .map(|s| s.content)
        .collect()
}

/// Extract reference strings using the strings command.
pub fn extract_strings_reference(binary_path: &str, min_len: usize) -> HashSet<String> {
    let output = match run_strings(binary_path, min_len) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Failed to run strings on {}: {}", binary_path, e);
            return HashSet::new();
        }
    };

    parse_strings_output(&output)
}

/// Extract reference strings preserving order.
pub fn extract_strings_reference_ordered(binary_path: &str, min_len: usize) -> Vec<String> {
    let output = match run_strings(binary_path, min_len) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("Failed to run strings on {}: {}", binary_path, e);
            return Vec::new();
        }
    };

    parse_strings_ordered(&output)
}

/// Compare string detection for a binary.
pub fn compare_binary_strings(binary_path: &str, min_len: usize) -> StringDiffResult {
    let hexray_strings = extract_strings_hexray(binary_path, min_len);
    let reference_strings = extract_strings_reference(binary_path, min_len);

    compare_string_sets(&hexray_strings, &reference_strings)
}

/// Detailed string comparison with verbose output.
pub fn compare_strings_verbose(binary_path: &str, min_len: usize) -> StringDiffResult {
    println!("\n=== String Comparison: {} ===", binary_path);
    println!("Minimum string length: {}", min_len);

    let hexray_strings = extract_strings_hexray(binary_path, min_len);
    let reference_strings = extract_strings_reference(binary_path, min_len);

    println!("Hexray found {} strings", hexray_strings.len());
    println!("strings command found {} strings", reference_strings.len());

    let result = compare_string_sets(&hexray_strings, &reference_strings);
    println!("{}", result.summary());

    result
}

/// Compare with analysis of string characteristics.
pub fn compare_strings_analyzed(binary_path: &str, min_len: usize) {
    let data = match fs::read(binary_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to read {}: {}", binary_path, e);
            return;
        }
    };

    let config = StringConfig {
        min_length: min_len,
        ..Default::default()
    };

    let detector = StringDetector::with_config(config);
    let hexray_strings = detector.detect(&data, 0);

    println!("\n=== String Analysis: {} ===", binary_path);
    println!("Total strings found: {}", hexray_strings.len());

    // Categorize strings
    let paths: Vec<&DetectedString> = hexray_strings.iter().filter(|s| s.is_path()).collect();
    let urls: Vec<&DetectedString> = hexray_strings.iter().filter(|s| s.is_url()).collect();
    let errors: Vec<&DetectedString> = hexray_strings
        .iter()
        .filter(|s| s.is_error_message())
        .collect();

    let ascii_count = hexray_strings
        .iter()
        .filter(|s| s.encoding == StringEncoding::Ascii)
        .count();
    let utf8_count = hexray_strings
        .iter()
        .filter(|s| s.encoding == StringEncoding::Utf8)
        .count();
    let utf16_count = hexray_strings
        .iter()
        .filter(|s| s.encoding == StringEncoding::Utf16Le || s.encoding == StringEncoding::Utf16Be)
        .count();

    println!("\nEncoding distribution:");
    println!("  ASCII: {}", ascii_count);
    println!("  UTF-8: {}", utf8_count);
    println!("  UTF-16: {}", utf16_count);

    println!("\nString categories:");
    println!("  Paths: {}", paths.len());
    println!("  URLs: {}", urls.len());
    println!("  Error messages: {}", errors.len());

    if !paths.is_empty() {
        println!("\nSample paths (first 5):");
        for s in paths.iter().take(5) {
            println!("  {}", s.content);
        }
    }

    if !urls.is_empty() {
        println!("\nSample URLs (first 5):");
        for s in urls.iter().take(5) {
            println!("  {}", s.content);
        }
    }
}

/// Compare string detection with different length thresholds.
pub fn compare_strings_at_thresholds(binary_path: &str) {
    println!(
        "\n=== String Comparison at Different Thresholds: {} ===",
        binary_path
    );

    for min_len in [4, 6, 8, 10] {
        let result = compare_binary_strings(binary_path, min_len);
        println!(
            "  min_len={}: hexray={}, ref={}, match={:.1}%",
            min_len,
            result.matching_strings + result.hexray_only.len(),
            result.total_strings,
            result.match_rate * 100.0
        );
    }
}

/// Compare UTF-16 string detection.
pub fn compare_utf16_strings(binary_path: &str, min_len: usize) -> (usize, usize, f64) {
    // Extract UTF-16 strings with hexray
    let data = match fs::read(binary_path) {
        Ok(d) => d,
        Err(_) => return (0, 0, 0.0),
    };

    let config = StringConfig {
        min_length: min_len,
        detect_utf16: true,
        require_null_terminator: true,
        ..Default::default()
    };

    let detector = StringDetector::with_config(config);
    let hexray_utf16: HashSet<String> = detector
        .detect(&data, 0)
        .into_iter()
        .filter(|s| s.encoding == StringEncoding::Utf16Le || s.encoding == StringEncoding::Utf16Be)
        .map(|s| s.content)
        .collect();

    // Try to get UTF-16 strings from strings command (if supported)
    // The -e l option enables little-endian 16-bit encoding
    let ref_output = match run_strings_with_encoding(binary_path, min_len, "l") {
        Ok(o) => o,
        Err(_) => return (0, 0, 0.0),
    };

    let reference_utf16 = parse_strings_output(&ref_output);

    let matching = hexray_utf16.intersection(&reference_utf16).count();
    let total = reference_utf16.len();
    let rate = if total > 0 {
        matching as f64 / total as f64
    } else {
        1.0
    };

    (matching, total, rate)
}

/// Find strings that exist in hexray but not in reference.
pub fn find_hexray_unique_strings(binary_path: &str, min_len: usize) -> Vec<String> {
    let hexray = extract_strings_hexray(binary_path, min_len);
    let reference = extract_strings_reference(binary_path, min_len);

    hexray.difference(&reference).cloned().collect()
}

/// Find strings that exist in reference but not in hexray.
pub fn find_missing_strings(binary_path: &str, min_len: usize) -> Vec<String> {
    let hexray = extract_strings_hexray(binary_path, min_len);
    let reference = extract_strings_reference(binary_path, min_len);

    reference.difference(&hexray).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::differential::{check_prerequisites, command_available, fixture_exists};

    /// Helper to skip test if prerequisites are not met.
    macro_rules! skip_if_missing {
        ($fixture:expr, $tool:expr) => {
            if let Err(reason) = check_prerequisites($fixture, $tool) {
                eprintln!("Skipping test: {}", reason);
                return;
            }
        };
    }

    #[test]
    fn test_strings_test_strings() {
        skip_if_missing!("test_strings", "strings");

        let path = fixture_path("test_strings");
        let result = compare_strings_verbose(&path, DEFAULT_MIN_LENGTH);

        assert!(result.total_strings > 0, "No strings found by reference");

        // String detection differs between implementations, so we use a lower threshold
        assert!(
            result.meets_threshold(STRING_MATCH_THRESHOLD),
            "Match rate {:.2}% below threshold {:.2}%",
            result.match_rate * 100.0,
            STRING_MATCH_THRESHOLD * 100.0
        );
    }

    #[test]
    fn test_strings_test_strings2() {
        skip_if_missing!("test_strings2", "strings");

        let path = fixture_path("test_strings2");
        let result = compare_strings_verbose(&path, DEFAULT_MIN_LENGTH);

        assert!(result.total_strings > 0, "No strings found by reference");
        assert!(
            result.meets_threshold(STRING_MATCH_THRESHOLD),
            "Match rate {:.2}% below threshold {:.2}%",
            result.match_rate * 100.0,
            STRING_MATCH_THRESHOLD * 100.0
        );
    }

    #[test]
    fn test_strings_test_decompile() {
        skip_if_missing!("test_decompile", "strings");

        let path = fixture_path("test_decompile");
        let result = compare_strings_verbose(&path, DEFAULT_MIN_LENGTH);

        assert!(result.total_strings > 0, "No strings found by reference");
        assert!(
            result.meets_threshold(STRING_MATCH_THRESHOLD),
            "Match rate {:.2}% below threshold {:.2}%",
            result.match_rate * 100.0,
            STRING_MATCH_THRESHOLD * 100.0
        );
    }

    #[test]
    fn test_strings_macho_x86_64() {
        skip_if_missing!("test_x86_64_macho", "strings");

        let path = fixture_path("test_x86_64_macho");
        let result = compare_strings_verbose(&path, DEFAULT_MIN_LENGTH);

        if result.total_strings > 0 {
            assert!(
                result.meets_threshold(STRING_MATCH_THRESHOLD),
                "Match rate {:.2}% below threshold {:.2}%",
                result.match_rate * 100.0,
                STRING_MATCH_THRESHOLD * 100.0
            );
        }
    }

    #[test]
    fn test_strings_different_min_lengths() {
        skip_if_missing!("test_strings", "strings");

        let path = fixture_path("test_strings");

        // Test with different minimum lengths
        for min_len in [4, 6, 8, 10, 12] {
            let result = compare_binary_strings(&path, min_len);
            println!(
                "min_len={}: match rate = {:.2}%",
                min_len,
                result.match_rate * 100.0
            );

            // Higher min_len should generally give better match rates
            // as both tools agree more on longer strings
            if min_len >= 8 && result.total_strings > 0 {
                assert!(
                    result.meets_threshold(0.85),
                    "Match rate at min_len={} is too low: {:.2}%",
                    min_len,
                    result.match_rate * 100.0
                );
            }
        }
    }

    #[test]
    fn test_strings_analysis() {
        skip_if_missing!("test_strings", "strings");

        let path = fixture_path("test_strings");
        compare_strings_analyzed(&path, DEFAULT_MIN_LENGTH);
    }

    #[test]
    fn test_strings_threshold_comparison() {
        skip_if_missing!("test_strings", "strings");

        let path = fixture_path("test_strings");
        compare_strings_at_thresholds(&path);
    }

    #[test]
    fn test_missing_strings_analysis() {
        skip_if_missing!("test_strings", "strings");

        let path = fixture_path("test_strings");
        let missing = find_missing_strings(&path, DEFAULT_MIN_LENGTH);

        println!("\n=== Missing Strings Analysis ===");
        println!("Total strings missed by hexray: {}", missing.len());

        if !missing.is_empty() {
            println!("\nFirst 20 missing strings:");
            for s in missing.iter().take(20) {
                let display = if s.len() > 60 {
                    format!("{}...", &s[..60])
                } else {
                    s.clone()
                };
                println!("  '{}'", display);
            }
        }
    }

    #[test]
    fn test_extra_strings_analysis() {
        skip_if_missing!("test_strings", "strings");

        let path = fixture_path("test_strings");
        let extra = find_hexray_unique_strings(&path, DEFAULT_MIN_LENGTH);

        println!("\n=== Extra Strings Analysis ===");
        println!("Total strings found only by hexray: {}", extra.len());

        if !extra.is_empty() {
            println!("\nFirst 20 hexray-only strings:");
            for s in extra.iter().take(20) {
                let display = if s.len() > 60 {
                    format!("{}...", &s[..60])
                } else {
                    s.clone()
                };
                println!("  '{}'", display);
            }
        }
    }

    #[test]
    fn test_strings_all_fixtures() {
        // Run string comparison on all available fixtures
        let fixtures = [
            "test_strings",
            "test_strings2",
            "test_decompile",
            "test_x86_64_macho",
        ];

        if !command_available("strings") {
            eprintln!("Skipping test: strings command not available");
            return;
        }

        let mut total_tests = 0;
        let mut passed_tests = 0;

        for fixture in fixtures {
            if !fixture_exists(fixture) {
                eprintln!("Fixture not found: {}", fixture);
                continue;
            }

            total_tests += 1;
            let path = fixture_path(fixture);
            let result = compare_strings_verbose(&path, DEFAULT_MIN_LENGTH);

            if result.total_strings > 0 && result.meets_threshold(STRING_MATCH_THRESHOLD) {
                passed_tests += 1;
            }
        }

        println!(
            "\n=== Summary: {}/{} fixtures passed ===",
            passed_tests, total_tests
        );

        assert!(
            passed_tests > 0 || total_tests == 0,
            "At least some fixtures should pass"
        );
    }

    #[test]
    fn test_string_config_options() {
        // Test that different config options work
        let configs = [
            StringConfig {
                min_length: 4,
                max_length: 1024,
                detect_utf16: false,
                require_null_terminator: true,
            },
            StringConfig {
                min_length: 8,
                max_length: 256,
                detect_utf16: true,
                require_null_terminator: true,
            },
            StringConfig {
                min_length: 4,
                max_length: 4096,
                detect_utf16: true,
                require_null_terminator: false,
            },
        ];

        for config in configs {
            let detector: StringDetector = StringDetector::with_config(config.clone());
            let test_data = b"Hello, World!\x00Short\x00This is a longer test string\x00";
            let strings: Vec<DetectedString> = detector.detect(test_data, 0);

            // Verify min_length filter
            for s in &strings {
                assert!(
                    s.content.len() >= config.min_length,
                    "String '{}' is shorter than min_length {}",
                    s.content,
                    config.min_length
                );
            }

            // Verify max_length filter
            for s in &strings {
                assert!(
                    s.content.len() <= config.max_length,
                    "String '{}' is longer than max_length {}",
                    s.content,
                    config.max_length
                );
            }
        }
    }

    #[test]
    fn test_string_categories() {
        // Test string categorization
        let data =
            b"/usr/bin/test\x00https://example.com\x00Error: failed to open\x00Normal string\x00";
        let detector = StringDetector::with_config(StringConfig {
            min_length: 4,
            ..Default::default()
        });
        let strings: Vec<DetectedString> = detector.detect(data, 0);

        let paths: Vec<&DetectedString> = strings.iter().filter(|s| s.is_path()).collect();
        let urls: Vec<&DetectedString> = strings.iter().filter(|s| s.is_url()).collect();
        let errors: Vec<&DetectedString> =
            strings.iter().filter(|s| s.is_error_message()).collect();

        assert!(!paths.is_empty(), "Should find path string");
        assert!(!urls.is_empty(), "Should find URL string");
        assert!(!errors.is_empty(), "Should find error message");

        // URL should not be counted as path
        for url in &urls {
            assert!(!url.is_path(), "URL should not be detected as path");
        }
    }
}
