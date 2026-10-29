//! End-to-end tests for the analysis-acceleration surface of `hexray db`.
//!
//! Every fixture is a deterministic ELF64 image built by
//! `tests/common/analysis_fixture.rs`; no compiler, network or sample is
//! needed and the generated object is never executed. The assertions target
//! the pinned CLI contract:
//!
//! - `-j/--jobs`, `--analysis-memory-mib` and `--timings` do not change
//!   analysis results;
//! - user-declared analysis scope only hides automatic analysis of explicit
//!   ranges, and is fully undone by a scope clear;
//! - packing hints are read-only, explainable and never skip a section on
//!   their own.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

#[path = "common/analysis_fixture.rs"]
mod analysis_fixture;

use analysis_fixture::{write_analysis_fixture_with_entropy, FixtureLayout};

const FUNCTIONS_PER_SECTION: usize = 32;

/// Fixed warning every hint surface must print: the hint is evidence, not a
/// packing verdict.
const HINT_WARNING: &str = "heuristic hints only; high entropy and section names do not prove \
                             packing; no section is skipped automatically";

fn hexray_bin() -> &'static str {
    env!("CARGO_BIN_EXE_hexray")
}

fn run(args: &[&str]) -> Output {
    Command::new(hexray_bin())
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to run hexray {args:?}: {error}"))
}

fn expect_success(output: &Output) -> String {
    assert!(
        output.status.success(),
        "command failed (status {:?})\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn expect_code(output: &Output, expected: i32, context: &str) {
    assert_eq!(
        output.status.code(),
        Some(expected),
        "{context}: expected exit {expected}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn parse_json(text: &str, context: &str) -> Value {
    serde_json::from_str(text)
        .unwrap_or_else(|error| panic!("{context}: expected JSON output, got {error}\n{text}"))
}

fn hex(address: u64) -> String {
    format!("0x{address:x}")
}

fn query(database: &Path, args: &[&str]) -> Output {
    let database = database.to_string_lossy();
    let mut argv = vec!["db", "query", database.as_ref()];
    argv.extend_from_slice(args);
    run(&argv)
}

fn edit(database: &Path, args: &[&str]) -> Output {
    let database = database.to_string_lossy();
    let mut argv = vec!["db", "edit", database.as_ref()];
    argv.extend_from_slice(args);
    run(&argv)
}

fn analyze(database: &Path, args: &[&str]) -> Output {
    let database = database.to_string_lossy();
    let mut argv = vec!["db", "analyze", database.as_ref()];
    argv.extend_from_slice(args);
    run(&argv)
}

fn query_json(database: &Path, args: &[&str]) -> Value {
    let output = query(database, args);
    let stdout = expect_success(&output);
    parse_json(&stdout, &format!("db query {args:?}"))
}

fn function_rows(database: &Path) -> Vec<Value> {
    query_json(database, &["functions", "--json"])
        .as_array()
        .expect("functions --json must be an array")
        .clone()
}

fn find_function(rows: &[Value], address: u64) -> &Value {
    let address = hex(address);
    rows.iter()
        .find(|row| row["address"].as_str() == Some(address.as_str()))
        .unwrap_or_else(|| panic!("no function row at {address}"))
}

fn revision(database: &Path) -> u64 {
    let info = query_json(database, &["info", "--json"]);
    info["revision"].as_u64().expect("info revision")
}

/// Fields that may legitimately differ between two projects are removed here.
///
/// The compared surfaces (`functions`, `disasm`, `cfg`, `xrefs`, `callgraph`
/// and `decompile`) carry no timestamp, UUID, path or wall-clock value, so no
/// key is removed today. Keeping this hook explicit means a future volatile
/// field must be named deliberately instead of wiped by a blanket filter that
/// would also hide semantic differences.
fn normalize(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for child in map.values_mut() {
                normalize(child);
            }
        }
        Value::Array(items) => {
            for child in items {
                normalize(child);
            }
        }
        _ => {}
    }
}

fn assert_same_json(reference: &str, candidate: &str, label: &str) {
    let mut reference = parse_json(reference, label);
    let mut candidate = parse_json(candidate, label);
    normalize(&mut reference);
    normalize(&mut candidate);
    assert_eq!(
        reference, candidate,
        "{label} must not depend on the worker count"
    );
}

/// A fixture file plus the temporary directory backing it.
struct Fixture {
    _dir: tempfile::TempDir,
    source: PathBuf,
    layout: FixtureLayout,
}

impl Fixture {
    fn new(high_entropy: bool) -> Fixture {
        let dir = tempfile::tempdir().expect("temp dir");
        let source = dir.path().join("analysis_fixture.elf");
        let written =
            write_analysis_fixture_with_entropy(&source, FUNCTIONS_PER_SECTION, high_entropy);
        let layout = written.expect("write analysis fixture");
        Fixture {
            _dir: dir,
            source,
            layout,
        }
    }

    fn create_project(&self, name: &str) -> PathBuf {
        let database = self._dir.path().join(name);
        let source = self.source.to_string_lossy().into_owned();
        let database_arg = database.to_string_lossy().into_owned();
        let output = run(&[
            "db",
            "create",
            source.as_str(),
            "-o",
            database_arg.as_str(),
        ]);
        expect_success(&output);
        database
    }
}

fn run_query_matrix(serial: &Path, parallel: &Path, automatic: &Path, args: &[&str]) {
    let reference = expect_success(&query(serial, args));
    let parallel_output = expect_success(&query(parallel, args));
    let automatic_output = expect_success(&query(automatic, args));
    assert_same_json(
        &reference,
        &parallel_output,
        &format!("db query {args:?} with --jobs 4"),
    );
    assert_same_json(
        &reference,
        &automatic_output,
        &format!("db query {args:?} with automatic jobs"),
    );
}

#[test]
fn jobs_values_produce_identical_analysis() {
    let fixture = Fixture::new(false);
    let layout = &fixture.layout;
    let serial = fixture.create_project("jobs_1.hxdb");
    let parallel = fixture.create_project("jobs_4.hxdb");
    let automatic = fixture.create_project("jobs_auto.hxdb");

    let serial_analysis = analyze(&serial, &["--force", "--jobs", "1"]);
    let parallel_analysis = analyze(&parallel, &["--force", "--jobs", "4"]);
    let automatic_analysis = analyze(&automatic, &["--force"]);
    assert_eq!(
        serial_analysis.status.code(),
        parallel_analysis.status.code(),
        "exit status must not depend on --jobs"
    );
    assert_eq!(
        serial_analysis.status.code(),
        automatic_analysis.status.code(),
        "exit status must not depend on the automatic worker count"
    );
    expect_success(&serial_analysis);
    expect_success(&parallel_analysis);
    expect_success(&automatic_analysis);

    let helper = hex(layout.helper);
    let caller = hex(layout.callers[0]);
    let cross_section_caller = hex(layout.cross_section_caller);

    run_query_matrix(&serial, &parallel, &automatic, &["functions", "--json"]);
    run_query_matrix(&serial, &parallel, &automatic, &["disasm", helper.as_str(), "--json"]);
    run_query_matrix(&serial, &parallel, &automatic, &["disasm", caller.as_str(), "--json"]);
    run_query_matrix(
        &serial,
        &parallel,
        &automatic,
        &["cfg", cross_section_caller.as_str(), "--json"],
    );
    run_query_matrix(&serial, &parallel, &automatic, &["xrefs", helper.as_str(), "--json"]);
    run_query_matrix(&serial, &parallel, &automatic, &["callgraph", "--json"]);

    // Rendering is the second parallel stage; the stored pseudo-C must be
    // identical too.
    let serial_render = analyze(&serial, &["--force", "--render", "--jobs", "1"]);
    let parallel_render = analyze(&parallel, &["--force", "--render", "--jobs", "4"]);
    let automatic_render = analyze(&automatic, &["--force", "--render"]);
    assert_eq!(
        serial_render.status.code(),
        parallel_render.status.code(),
        "render exit status must not depend on --jobs"
    );
    assert_eq!(
        serial_render.status.code(),
        automatic_render.status.code(),
        "render exit status must not depend on the automatic worker count"
    );
    expect_success(&serial_render);
    expect_success(&parallel_render);
    expect_success(&automatic_render);

    run_query_matrix(&serial, &parallel, &automatic, &["decompile", helper.as_str(), "--json"]);
}

#[test]
fn execution_options_are_validated() {
    let fixture = Fixture::new(false);
    let database = fixture.create_project("validation.hxdb");

    let invalid: &[&[&str]] = &[
        &["--force", "--jobs", "257"],
        &["--force", "--jobs", "-1"],
        &["--force", "--jobs=-1"],
        &["--force", "--analysis-memory-mib", "63"],
        &["--force", "--analysis-memory-mib", "65537"],
    ];
    for &args in invalid {
        let output = analyze(&database, args);
        expect_code(&output, 2, &format!("db analyze {args:?}"));
    }

    let valid: &[&[&str]] = &[&["--force", "-j", "0"], &["--force", "--jobs", "1"]];
    for &args in valid {
        expect_success(&analyze(&database, args));
    }
}

#[test]
fn analysis_scope_hides_packed_functions_until_cleared() {
    let fixture = Fixture::new(false);
    let layout = &fixture.layout;
    let database = fixture.create_project("scope.hxdb");

    let packed_first = hex(layout.packed_functions[0].1);
    let rows = function_rows(&database);
    assert!(
        rows.iter().any(|row| row["address"].as_str() == Some(packed_first.as_str())),
        "a default project must discover .packed functions: {rows:?}"
    );

    let before_edit = revision(&database);
    expect_success(&edit(&database, &["scope", "--skip-section", ".packed"]));
    assert_eq!(
        revision(&database),
        before_edit + 1,
        "a scope edit is exactly one user revision"
    );

    let scope = expect_success(&query(&database, &["scope", "--json"]));
    assert!(
        scope.contains(&hex(layout.packed_start)),
        "the stored scope must report the resolved .packed start: {scope}"
    );
    assert!(
        scope.contains(&hex(layout.packed_end)),
        "the stored scope must report the resolved .packed end: {scope}"
    );

    expect_success(&analyze(&database, &["--force"]));
    let rows = function_rows(&database);
    for (name, address, _) in &layout.packed_functions {
        let row = find_function(&rows, *address);
        assert_eq!(
            row["skipped_by_scope"],
            Value::Bool(true),
            "{name} must be marked skipped by the analysis scope: {row}"
        );
        assert_ne!(
            row["state"].as_str(),
            Some("current"),
            "{name} is excluded and must not publish a current CFG: {row}"
        );
    }
    for (name, address, _) in &layout.text_functions {
        let row = find_function(&rows, *address);
        assert_eq!(
            row["skipped_by_scope"],
            Value::Bool(false),
            "{name} is inside the allowed range: {row}"
        );
        assert_eq!(
            row["state"].as_str(),
            Some("current"),
            "{name} is inside .text and must still analyze: {row}"
        );
    }

    let cross_section_caller = hex(layout.cross_section_caller);
    let xrefs = query_json(&database, &["xrefs", cross_section_caller.as_str(), "--json"]);
    let packed_target = hex(layout.packed_functions[0].1);
    let kept = xrefs
        .as_array()
        .expect("xrefs --json must be an array")
        .iter()
        .any(|row| {
            row["to"].as_str() == Some(packed_target.as_str())
                && row["kind"].as_str() == Some("call")
        });
    assert!(
        kept,
        "the cross-section call xref must survive the scope: {xrefs}"
    );

    let info = query_json(&database, &["info", "--json"]);
    assert_eq!(info["coverage"], "filtered");
    let skipped = info["skipped_functions"].as_u64().expect("skipped_functions");
    assert!(
        skipped >= layout.packed_functions.len() as u64,
        "known packed rows must be counted as skipped, got {skipped}"
    );
    assert!(
        info["analysis_scope"]["excluded_ranges"]
            .as_array()
            .is_some_and(|ranges| !ranges.is_empty()),
        "info must expose the stored exclusion policy: {info}"
    );
    // The text surfaces must report the same policy, not only the JSON.
    let info_text = expect_success(&run(&[
        "db",
        "query",
        database.to_str().expect("utf-8 database"),
        "info",
    ]));
    assert!(
        info_text.contains("coverage    filtered"),
        "`query info` text must show the filtered coverage:\n{info_text}"
    );
    assert!(
        info_text.contains("scope     0x"),
        "`query info` text must list the excluded ranges:\n{info_text}"
    );
    let db_info_text = expect_success(&run(&["db", "info", database.to_str().expect("utf-8 database")]));
    assert!(
        db_info_text.contains("Coverage:       filtered"),
        "`db info` text must show the filtered coverage:\n{db_info_text}"
    );

    // Clearing the scope restores automatic analysis of .packed.
    let before_clear = revision(&database);
    expect_success(&edit(&database, &["scope"]));
    assert_eq!(revision(&database), before_clear + 1);
    expect_success(&analyze(&database, &["--force"]));
    let rows = function_rows(&database);
    for (name, address, _) in &layout.packed_functions {
        let row = find_function(&rows, *address);
        assert_eq!(
            row["state"].as_str(),
            Some("current"),
            "{name} must be analyzed again after the scope is cleared: {row}"
        );
        assert_eq!(
            row["skipped_by_scope"],
            Value::Bool(false),
            "{name} is no longer excluded: {row}"
        );
    }

    // Rejected policies never bump the revision or write a partial change.
    let stable = revision(&database);
    let unknown = edit(&database, &["scope", "--skip-section", ".not_a_section"]);
    assert!(!unknown.status.success(), "an unknown section name must be refused");
    let stderr = String::from_utf8_lossy(&unknown.stderr);
    assert!(
        stderr.contains(".text") && stderr.contains(".packed"),
        "the error must list the valid section names: {stderr}"
    );
    assert_eq!(revision(&database), stable);

    let reversed = edit(&database, &["scope", "--skip-range", "2000:1000"]);
    assert!(!reversed.status.success(), "reversed ranges must be refused");
    assert_eq!(revision(&database), stable);
}

fn find_hint<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    match value {
        Value::Object(map) => {
            let is_hint = map.get("name").and_then(Value::as_str) == Some(name)
                && map.contains_key("entropy_bits_per_byte");
            if is_hint {
                return Some(value);
            }
            map.values().find_map(|child| find_hint(child, name))
        }
        Value::Array(items) => items.iter().find_map(|child| find_hint(child, name)),
        _ => None,
    }
}

#[test]
fn section_hints_explain_packed_bytes_without_changing_anything() {
    let fixture = Fixture::new(true);
    let layout = &fixture.layout;
    let before = std::fs::read(&fixture.source).expect("read fixture");

    let source = fixture.source.to_string_lossy().into_owned();
    let output = run(&["db", "input-info", source.as_str(), "--json", "--section-hints"]);
    let stdout = expect_success(&output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains(HINT_WARNING) || stderr.contains(HINT_WARNING),
        "the fixed hint warning must be printed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let json = parse_json(&stdout, "db input-info --json --section-hints");
    let packed =
        find_hint(&json, ".packed").unwrap_or_else(|| panic!("missing .packed hint: {json}"));
    let entropy = packed["entropy_bits_per_byte"]
        .as_f64()
        .expect("hint must report entropy_bits_per_byte");
    assert!(
        entropy >= 7.5,
        "the high-entropy fixture must reach 7.5 bits/byte, got {entropy}"
    );
    assert_eq!(packed["suggest_skip"], Value::Bool(true));
    assert_eq!(
        packed["file_bytes"].as_u64(),
        Some(layout.packed_end - layout.packed_start),
        "hint file_bytes must describe the whole file-backed section"
    );

    let text = find_hint(&json, ".text").expect("missing .text hint");
    assert_eq!(
        text["suggest_skip"],
        Value::Bool(false),
        "low-entropy .text must not be suggested for skipping"
    );

    let after = std::fs::read(&fixture.source).expect("read fixture");
    assert_eq!(before, after, "hints must never modify the input file");
    assert_eq!(
        hexray_db::sha256(&before),
        hexray_db::sha256(&after),
        "the input hash must be unchanged"
    );

    // The same read-only table is available for a stored project, and asking
    // for it is not a user edit.
    let database = fixture.create_project("hints.hxdb");
    let scope_output = query(&database, &["scope", "--json", "--section-hints"]);
    let scope_stdout = expect_success(&scope_output);
    assert!(
        scope_stdout.contains(".packed"),
        "the project hint table must list .packed: {scope_stdout}"
    );
    assert!(
        scope_stdout.contains(HINT_WARNING)
            || String::from_utf8_lossy(&scope_output.stderr).contains(HINT_WARNING),
        "the project hint table must print the fixed warning"
    );
    assert_eq!(revision(&database), 0, "printing hints must not create a user revision");
}

#[test]
fn timings_report_stages_without_changing_the_result() {
    let fixture = Fixture::new(false);
    let database = fixture.create_project("timings.hxdb");

    let output = analyze(&database, &["--force", "--timings", "--json", "--jobs", "4"]);
    let stdout = expect_success(&output);
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    assert!(
        stderr.contains("discovery"),
        "stage timings must reach stderr: {stderr}"
    );
    assert!(
        stderr.contains("total"),
        "the total stage must be reported: {stderr}"
    );
    assert!(
        stderr.contains("ms"),
        "stage timings must use milliseconds: {stderr}"
    );

    let report = parse_json(&stdout, "db analyze --json --timings");
    assert!(
        report["timings"].is_object(),
        "analyze JSON must carry a timings object: {report}"
    );
    assert!(
        report["timings"]["effective_jobs"].as_u64().unwrap_or(0) >= 2,
        "a forced analysis must use more than one worker: {report}"
    );
}

/// Fix A witness: the render stage reuses the analysis pool, so the pool must be
/// sized from the render targets even when this command has no pending CFG work.
#[test]
fn render_after_analyze_uses_the_pool() {
    let fixture = Fixture::new(false);
    let database = fixture.create_project("render_pool.hxdb");
    expect_success(&analyze(&database, &["--force"]));

    let output = analyze(
        &database,
        &["--render", "--timings", "--json", "--jobs", "4"],
    );
    let stdout = expect_success(&output);
    let report = parse_json(&stdout, "db analyze --render --json");
    assert!(
        report["rendered"].as_u64().unwrap_or(0) > 0,
        "the render pass must decompile something: {report}"
    );
    // Without this the witness is vacuous: leftover analysis batches would size
    // the pool even if the render targets were ignored.
    assert_eq!(
        report["analyzed"].as_u64(),
        Some(0),
        "the render-only run must have no pending analysis batches: {report}"
    );
    assert!(
        report["timings"]["effective_jobs"].as_u64().unwrap_or(0) >= 2,
        "rendering with no pending analysis must still use the pool: {report}"
    );
}

/// Fix B witness: a callee published by a later batch must record the same
/// generation the next run will observe, so the second run analyzes nothing.
#[test]
fn multi_batch_analysis_reaches_a_fixed_point() {
    let fixture = Fixture::new(false);
    let database = fixture.create_project("fixed_point.hxdb");
    expect_success(&analyze(
        &database,
        &["--force", "--jobs", "1", "--analysis-memory-mib", "64"],
    ));

    let output = analyze(&database, &["--jobs", "1", "--json"]);
    let stdout = expect_success(&output);
    let report = parse_json(&stdout, "db analyze --json");
    assert_eq!(
        report["analyzed"].as_u64(),
        Some(0),
        "a second run must find every unit current: {report}"
    );
}
