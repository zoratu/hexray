//! End-to-end tests for `hexray db`.
//!
//! These drive the real binary, so every assertion is about observable CLI
//! behaviour: a project created from a fixture, reopened without the fixture,
//! edited, undone, exported, and checked. The required fixture is treated as
//! mandatory — a missing sample fails the test instead of silently skipping.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn hexray_bin() -> &'static str {
    env!("CARGO_BIN_EXE_hexray")
}

/// ELF fixture with `_start`/`main`/`helper` at 0x401000/0x40100f/0x40101d.
fn elf_fixture() -> PathBuf {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/elf/test_with_symbols");
    assert!(
        path.exists(),
        "required fixture is missing: {}",
        path.display()
    );
    path
}

fn run(args: &[&str]) -> Output {
    Command::new(hexray_bin())
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to run hexray {args:?}: {error}"))
}

fn run_stdin(args: &[&str], stdin: &str) -> Output {
    use std::io::Write;
    let mut child = Command::new(hexray_bin())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn hexray");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(stdin.as_bytes())
        .expect("write stdin");
    child.wait_with_output().expect("wait for hexray")
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

/// A project created from the ELF fixture, plus its temporary directory.
struct Project {
    dir: tempfile::TempDir,
    source: PathBuf,
    database: PathBuf,
}

impl Project {
    fn create() -> Project {
        let dir = tempfile::tempdir().expect("temp dir");
        let source = dir.path().join("sample.bin");
        std::fs::copy(elf_fixture(), &source).expect("copy fixture");
        let database = dir.path().join("sample.hxdb");
        let output = run(&[
            "db",
            "create",
            source.to_str().unwrap(),
            "-o",
            database.to_str().unwrap(),
        ]);
        expect_success(&output);
        Project {
            dir,
            source,
            database,
        }
    }

    fn db_str(&self) -> &str {
        self.database.to_str().unwrap()
    }

    fn query(&self, args: &[&str]) -> Output {
        let mut all = vec!["db", "query", self.db_str()];
        all.extend_from_slice(args);
        run(&all)
    }

    fn edit(&self, args: &[&str]) -> Output {
        let mut all = vec!["db", "edit", self.db_str()];
        all.extend_from_slice(args);
        run(&all)
    }

    fn revision(&self) -> u64 {
        let output = self.query(&["info", "--json"]);
        let json: serde_json::Value =
            serde_json::from_str(&expect_success(&output)).expect("info json");
        json["revision"].as_u64().expect("revision")
    }
}

#[test]
fn create_then_query_matches_standalone_decompile() {
    let project = Project::create();

    let info: serde_json::Value = serde_json::from_str(&expect_success(&project.query(&[
        "info", "--json",
    ])))
    .expect("info json");
    assert_eq!(info["image"]["format"], "elf");
    assert_eq!(info["image"]["architecture"], "x86_64");
    assert_eq!(info["image"]["entry_address"], "0x401000");
    assert_eq!(info["function_count"], 3);
    assert_eq!(info["overall_state"], "ready");

    let functions = expect_success(&project.query(&["functions", "--json"]));
    let functions: serde_json::Value = serde_json::from_str(&functions).expect("functions json");
    let names: Vec<&str> = functions
        .as_array()
        .expect("array")
        .iter()
        .map(|row| row["name"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(names, vec!["_start", "main", "helper"]);

    let from_project = expect_success(&project.query(&["decompile", "main", "--update"]));
    let standalone = expect_success(&run(&[
        project.source.to_str().unwrap(),
        "decompile",
        "main",
    ]));
    let standalone_body: String = standalone
        .lines()
        .skip_while(|line| line.starts_with("Decompiling "))
        .collect::<Vec<_>>()
        .join("\n");
    assert_eq!(
        from_project.trim(),
        standalone_body.trim(),
        "database rendering must match the standalone decompiler"
    );
    assert!(from_project.contains("int32_t main(void)"));
}

#[test]
fn reopening_without_the_source_still_answers() {
    let project = Project::create();
    expect_success(&project.query(&["decompile", "main", "--update"]));

    // Move the input away: a project is self-contained.
    let moved = project.dir.path().join("sample.bin.moved");
    std::fs::rename(&project.source, &moved).expect("move source");

    let text = expect_success(&project.query(&["decompile", "main"]));
    assert!(text.contains("int32_t main(void)"));

    let bytes = expect_success(&project.query(&["bytes", "0x401022", "1"]));
    assert!(
        bytes.trim().ends_with("2a"),
        "embedded bytes must be readable offline: {bytes}"
    );

    let check = run(&["db", "check", project.db_str(), "--deep"]);
    expect_success(&check);
}

#[test]
fn rename_updates_callers_and_keeps_instructions_current() {
    let project = Project::create();
    expect_success(&project.query(&["decompile", "main", "--update"]));

    expect_success(&project.edit(&["name", "0x40101d", "recovered_helper"]));

    let stale = project.query(&["decompile", "main"]);
    assert!(
        !stale.status.success(),
        "the rendered text must be marked stale after a rename"
    );
    assert!(
        String::from_utf8_lossy(&stale.stderr).contains("stale"),
        "stale marker missing: {}",
        String::from_utf8_lossy(&stale.stderr)
    );

    let updated = expect_success(&project.query(&["decompile", "main", "--update"]));
    assert!(updated.contains("recovered_helper()"), "{updated}");

    // A rename changes no instruction, so no CFG unit may be invalidated.
    let functions = expect_success(&project.query(&["functions", "--json"]));
    let functions: serde_json::Value = serde_json::from_str(&functions).expect("functions json");
    for row in functions.as_array().expect("array") {
        assert_eq!(
            row["state"], "current",
            "rename must not invalidate instructions: {row}"
        );
    }
}

#[test]
fn patch_undo_redo_and_export_roundtrip() {
    let project = Project::create();
    let before = std::fs::read(&project.source).expect("read source");
    assert_eq!(before[0x9a], 0x2a, "fixture layout changed");

    let original = expect_success(&project.query(&["decompile", "helper", "--update"]));
    assert!(original.contains("return 42;"), "{original}");

    let revision_before = project.revision();
    expect_success(&project.edit(&["patch", "0x401022", "2b"]));
    assert_eq!(project.revision(), revision_before + 1);

    let patched = expect_success(&project.query(&["decompile", "helper", "--update"]));
    assert!(patched.contains("return 43;"), "{patched}");

    expect_success(&run(&["db", "undo", project.db_str()]));
    let undone = expect_success(&project.query(&["decompile", "helper", "--update"]));
    assert!(undone.contains("return 42;"), "{undone}");

    expect_success(&run(&["db", "redo", project.db_str()]));
    let redone = expect_success(&project.query(&["decompile", "helper", "--update"]));
    assert!(redone.contains("return 43;"), "{redone}");

    let export = project.dir.path().join("export.bin");
    expect_success(&run(&[
        "db",
        "export-binary",
        project.db_str(),
        "-o",
        export.to_str().unwrap(),
    ]));
    let exported = std::fs::read(&export).expect("read export");
    assert_eq!(exported.len(), before.len(), "export must not resize");
    let changed: Vec<usize> = before
        .iter()
        .zip(exported.iter())
        .enumerate()
        .filter(|(_, (left, right))| left != right)
        .map(|(index, _)| index)
        .collect();
    assert_eq!(changed, vec![0x9a], "only the patched byte may change");
    assert_eq!(exported[0x9a], 0x2b);

    // The input file itself is untouched.
    assert_eq!(std::fs::read(&project.source).expect("read source"), before);
}

#[test]
fn protected_and_existing_targets_are_rejected() {
    let project = Project::create();

    let header_patch = project.edit(&["patch", "0x0", "90"]);
    assert!(!header_patch.status.success());
    assert!(
        String::from_utf8_lossy(&header_patch.stderr).contains("not inside a patchable"),
        "header patching must be refused: {}",
        String::from_utf8_lossy(&header_patch.stderr)
    );

    let unmapped = project.edit(&["patch", "0xdeadbeef", "90"]);
    assert!(!unmapped.status.success());

    let export = project.dir.path().join("export.bin");
    std::fs::write(&export, b"occupied").expect("seed export target");
    let refused = run(&[
        "db",
        "export-binary",
        project.db_str(),
        "-o",
        export.to_str().unwrap(),
    ]);
    assert!(!refused.status.success(), "must not overwrite a file");
    assert_eq!(
        std::fs::read(&export).expect("read"),
        b"occupied",
        "the existing file must be left alone"
    );

    let duplicate_backup = run(&[
        "db",
        "backup",
        project.db_str(),
        "-o",
        project.source.to_str().unwrap(),
    ]);
    assert!(!duplicate_backup.status.success());

    // The project is still healthy after every rejection.
    expect_success(&run(&["db", "check", project.db_str(), "--deep"]));
}

#[test]
fn revision_conflict_exits_three() {
    let project = Project::create();
    expect_success(&project.edit(&["name", "0x40101d", "first", "--expect-revision", "0"]));

    let conflict = run(&[
        "db",
        "edit",
        project.db_str(),
        "name",
        "0x40101d",
        "second",
        "--expect-revision",
        "0",
    ]);
    assert_eq!(conflict.status.code(), Some(3));
    assert!(
        String::from_utf8_lossy(&conflict.stderr).contains("expected revision 0, actual 1"),
        "{}",
        String::from_utf8_lossy(&conflict.stderr)
    );

    expect_success(&project.edit(&[
        "name",
        "0x40101d",
        "second",
        "--expect-revision",
        "1",
    ]));
}

#[test]
fn legacy_project_import_verifies_identity() {
    let dir = tempfile::tempdir().expect("temp dir");
    let source = dir.path().join("sample.bin");
    std::fs::copy(elf_fixture(), &source).expect("copy fixture");
    let legacy = dir.path().join("legacy.hxp");
    expect_success(&run(&[
        source.to_str().unwrap(),
        "project",
        "create",
        "-o",
        legacy.to_str().unwrap(),
    ]));
    expect_success(&run(&[
        source.to_str().unwrap(),
        "project",
        "name",
        legacy.to_str().unwrap(),
        "0x40101d",
        "legacy_helper",
    ]));
    let before = std::fs::read(&source).expect("read source");

    let database = dir.path().join("imported.hxdb");
    let imported = expect_success(&run(&[
        "db",
        "import-legacy",
        legacy.to_str().unwrap(),
        "--binary",
        source.to_str().unwrap(),
        "-o",
        database.to_str().unwrap(),
    ]));
    assert!(imported.contains("weak_verified"), "{imported}");
    assert_eq!(
        std::fs::read(&source).expect("read source"),
        before,
        "import must not touch the legacy binary"
    );

    let functions = expect_success(&run(&[
        "db",
        "query",
        database.to_str().unwrap(),
        "functions",
    ]));
    assert!(functions.contains("legacy_helper"), "{functions}");

    // A project recorded against another binary is refused unless the user
    // explicitly accepts an unverified import.
    let other = dir.path().join("other.bin");
    std::fs::copy(elf_fixture(), &other).expect("copy fixture");
    let mut bytes = std::fs::read(&other).expect("read");
    bytes[0x200] ^= 0xff;
    std::fs::write(&other, &bytes).expect("rewrite");

    let rejected = run(&[
        "db",
        "import-legacy",
        legacy.to_str().unwrap(),
        "--binary",
        other.to_str().unwrap(),
        "-o",
        dir.path().join("rejected.hxdb").to_str().unwrap(),
    ]);
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("identity mismatch"),
        "{}",
        String::from_utf8_lossy(&rejected.stderr)
    );

    let accepted = expect_success(&run(&[
        "db",
        "import-legacy",
        legacy.to_str().unwrap(),
        "--binary",
        other.to_str().unwrap(),
        "-o",
        dir.path().join("accepted.hxdb").to_str().unwrap(),
        "--accept-unverified-legacy",
    ]));
    assert!(accepted.contains("unverified"), "{accepted}");
}

#[test]
fn shell_batch_mode_applies_edits() {
    let project = Project::create();
    let script = "functions\ndecompile helper --update\nname 0x40101d shell_named\n\
         decompile helper --update\nundo\nredo\nrefresh\ncheck --deep\n\
         decompile no_such_function --update\nfunctions\nquit\n";
    let output = run_stdin(&["db", "open", project.db_str()], script);
    // The failing `decompile` sits mid-script on purpose: batch mode must stop
    // there, so the trailing `functions` never runs.
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("int32_t helper(void)"), "{stdout}");
    assert!(stdout.contains("int32_t shell_named(void)"), "{stdout}");
    assert!(stdout.contains("Undone"), "{stdout}");
    assert!(stdout.contains("Redone"), "{stdout}");
    assert!(stdout.contains("quick_check:        ok"), "{stdout}");
    assert_eq!(
        stdout.matches("hxdb> functions").count(),
        1,
        "a failing step must abort the remaining script: {stdout}"
    );

    // The edit survived the shell session.
    let functions = expect_success(&project.query(&["functions"]));
    assert!(functions.contains("shell_named"), "{functions}");
}

#[test]
fn branch_to_its_own_fallthrough_publishes_once() {
    let project = Project::create();

    // `je +0` is a conditional branch whose target *is* the fallthrough: the
    // CFG records the same `from -> to` transfer twice. That must not abort the
    // analysis transaction (the edge table is a set), and the stored CFG must
    // show the transfer once.
    expect_success(&project.edit(&["patch", "0x401000", "7400c3"]));
    let analyzed = expect_success(&run(&[
        "db",
        "analyze",
        project.db_str(),
        "--force",
        "--jobs",
        "1",
    ]));
    assert!(
        analyzed.contains("Analyzed"),
        "analysis must complete after the patch: {analyzed}"
    );

    let cfg: serde_json::Value = serde_json::from_str(&expect_success(
        &project.query(&["cfg", "_start", "--json"]),
    ))
    .expect("cfg json");
    let blocks = cfg["blocks"].as_array().expect("blocks array");
    let block_id_at = |start: &str| {
        blocks
            .iter()
            .find(|block| block["start"].as_str() == Some(start))
            .map(|block| block["id"].as_u64().expect("block id"))
            .unwrap_or_else(|| panic!("no block starts at {start}: {blocks:?}"))
    };
    let src = block_id_at("0x401000");
    let dst = block_id_at("0x401002");
    assert_ne!(
        src, dst,
        "the branch and its fallthrough must be separate blocks: {blocks:?}"
    );

    let edges = cfg["edges"].as_array().expect("edges array");
    let normal = edges
        .iter()
        .filter(|edge| {
            edge[0].as_u64() == Some(src)
                && edge[1].as_u64() == Some(dst)
                && edge[2].as_str() == Some("normal")
        })
        .count();
    assert_eq!(
        normal, 1,
        "the `je +0` transfer must be stored exactly once: {edges:?}"
    );
    assert!(
        !edges.iter().any(|edge| {
            edge[0].as_u64() == Some(src)
                && edge[1].as_u64() == Some(dst)
                && edge[2].as_str() == Some("unwind")
        }),
        "the fallthrough transfer is not an unwind edge: {edges:?}"
    );

    // The whole payload carries no duplicate transfer at all.
    let mut unique: Vec<(u64, u64, String)> = edges
        .iter()
        .map(|edge| {
            (
                edge[0].as_u64().expect("from"),
                edge[1].as_u64().expect("to"),
                edge[2].as_str().expect("kind").to_string(),
            )
        })
        .collect();
    let total = unique.len();
    unique.sort();
    unique.dedup();
    assert_eq!(
        total,
        unique.len(),
        "a duplicated transfer must be stored once: {edges:?}"
    );
}

#[test]
fn query_surfaces_are_readable() {
    let project = Project::create();
    expect_success(&project.query(&["decompile", "main", "--update"]));

    let disasm = expect_success(&project.query(&["disasm", "helper"]));
    assert!(disasm.contains("ret"), "{disasm}");

    let cfg = expect_success(&project.query(&["cfg", "helper"]));
    assert!(cfg.contains("bb0"), "{cfg}");

    let dot = expect_success(&project.query(&["cfg", "main", "--dot"]));
    assert!(dot.starts_with("digraph"), "{dot}");

    let callgraph = expect_success(&project.query(&["callgraph", "--json"]));
    assert!(callgraph.contains("helper"), "{callgraph}");

    let strings = expect_success(&project.query(&["strings", "--limit", "5"]));
    assert!(!strings.is_empty());

    let symbols = expect_success(&project.query(&["symbols", "--limit", "5"]));
    assert!(symbols.contains("0x40100f"), "{symbols}");

    // Paging is honoured.
    let first_page = expect_success(&project.query(&["functions", "--limit", "1"]));
    assert_eq!(first_page.lines().count(), 1);
    let second_page = expect_success(&project.query(&["functions", "--limit", "1", "--offset", "1"]));
    assert!(second_page.contains("main"), "{second_page}");

    let bad = project.query(&["bytes", "0x40100f", "99999999"]);
    assert!(!bad.status.success(), "byte requests are bounded");
}
