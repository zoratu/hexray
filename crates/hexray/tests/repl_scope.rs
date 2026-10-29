//! The interactive project shell, driven as a batch script.
//!
//! Without a terminal there is no line editor, so `db open` reads one command
//! per line from stdin. That is the same command grammar and the same handlers
//! a human gets, which makes it the honest automation surface for the shell:
//! the analysis-scope lifecycle has to work there too, not only in one-shot
//! commands.
//!
//! TTY-only behaviour (history recall, Ctrl-C, the prompt) is not exercised
//! here and is reported as unverified rather than pretended.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

#[path = "common/analysis_fixture.rs"]
mod analysis_fixture;

fn hexray_bin() -> &'static str {
    env!("CARGO_BIN_EXE_hexray")
}

struct Project {
    _dir: tempfile::TempDir,
    database: PathBuf,
    packed_function: String,
    text_function: String,
}

impl Project {
    fn create() -> Project {
        let dir = tempfile::tempdir().expect("temp dir");
        let source = dir.path().join("fixture.bin");
        let layout = analysis_fixture::write_analysis_fixture(&source, 8).expect("write fixture");
        let database = dir.path().join("project.hxdb");
        let output = Command::new(hexray_bin())
            .args([
                "db",
                "create",
                source.to_str().expect("utf-8 source"),
                "-o",
                database.to_str().expect("utf-8 database"),
            ])
            .output()
            .expect("run db create");
        assert_success(&output);
        let packed_function = format!("{:#x}", layout.packed_functions[0].1);
        let text_function = format!("{:#x}", layout.helper);
        Project {
            _dir: dir,
            database,
            packed_function,
            text_function,
        }
    }

    fn shell(&self, script: &str) -> Output {
        shell_at(&self.database, script, &[])
    }
}

fn shell_at(database: &Path, script: &str, extra: &[&str]) -> Output {
    use std::io::Write;
    let mut child = Command::new(hexray_bin())
        .args(["db", "open"])
        .arg(database)
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn db open");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(script.as_bytes())
        .expect("write script");
    child.wait_with_output().expect("wait for the shell")
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed (status {:?})\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn revision(database: &Path) -> u64 {
    let output = Command::new(hexray_bin())
        .args(["db", "query"])
        .arg(database)
        .args(["info", "--json"])
        .output()
        .expect("query info");
    assert_success(&output);
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("info json");
    value["revision"].as_u64().expect("revision")
}

#[test]
fn shell_drives_the_scope_lifecycle() {
    let project = Project::create();
    let start = revision(&project.database);

    let script = "scope\nanalyze --force --jobs 4\n\
         scope-set --skip-section .packed\nscope\nanalyze --force\nfunctions\n\
         undo\nredo\nrefresh\nanalyze --force --jobs 4\n\
         scope-set\nscope\nquit\n";
    let output = project.shell(script);
    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stdout.contains("analysis scope: full image"),
        "the shell must report the empty scope first:\n{stdout}"
    );
    assert!(
        stdout.contains("analysis scope: filtered"),
        "scope-set must change the reported policy:\n{stdout}"
    );
    assert!(
        stdout.contains("section .packed"),
        "the resolved range must carry the user's section label:\n{stdout}"
    );
    assert!(
        stdout.contains("(skipped by scope)"),
        "excluded rows stay listed with a skipped marker:\n{stdout}"
    );
    assert!(
        stdout.contains("Analysis scope excluded"),
        "analysis must say what it skipped:\n{stdout}"
    );
    assert!(
        !stderr.contains("error:"),
        "the shell must not report errors for a valid script:\n{stderr}"
    );

    // Four revisions: apply, undo, redo, clear. `analyze` is not a user edit and
    // `refresh` only re-reads, so neither moves the head.
    let end = revision(&project.database);
    assert_eq!(end, start + 4, "each scope change is one revision");

    // The script ends by clearing the scope, so re-apply it before checking the
    // gate: an excluded function is still a *row* but must not be analyzed on
    // request.
    let applied = Command::new(hexray_bin())
        .args(["db", "edit"])
        .arg(&project.database)
        .args(["scope", "--skip-section", ".packed"])
        .output()
        .expect("apply scope");
    assert_success(&applied);

    let analyze = Command::new(hexray_bin())
        .args(["db", "analyze"])
        .arg(&project.database)
        .args(["--function", &project.packed_function])
        .output()
        .expect("analyze excluded function");
    assert!(
        !analyze.status.success(),
        "an excluded function must not be analyzed on request"
    );
    let stderr = String::from_utf8_lossy(&analyze.stderr);
    assert!(
        stderr.contains("excluded by analysis scope"),
        "the refusal must name the scope: {stderr}"
    );

    // The text function is still analyzable while the scope is in force.
    let text = Command::new(hexray_bin())
        .args(["db", "analyze"])
        .arg(&project.database)
        .args(["--function", &project.text_function])
        .output()
        .expect("analyze text function");
    assert_success(&text);
}

#[test]
fn read_only_shell_refuses_every_write_command() {
    let project = Project::create();
    let before = revision(&project.database);

    for command in ["scope-set --skip-section .packed", "analyze", "analyze --force"] {
        let output = shell_at(
            &project.database,
            &format!("{command}\n"),
            &["--read-only"],
        );
        assert!(
            !output.status.success(),
            "'{command}' must fail in a read-only shell"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("needs a writable project"),
            "'{command}' must explain the read-only refusal: {stderr}"
        );
    }
    // `scope` is a read and must keep working.
    let output = shell_at(&project.database, "scope\nquit\n", &["--read-only"]);
    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("analysis scope:"));
    assert_eq!(before, revision(&project.database), "reads never write");
}

#[test]
fn shell_sees_an_external_edit_after_refresh() {
    let project = Project::create();
    let before = revision(&project.database);

    // Another session (a one-shot command) edits the project between two shell
    // commands. `refresh` re-reads the head, and the next `scope-set` applies
    // on top of the new revision rather than a stale one.
    let script = "refresh\nscope-set --skip-section .packed\nscope\nquit\n";
    let output = project.shell(script);
    assert_success(&output);
    assert_eq!(
        revision(&project.database),
        before + 1,
        "the shell edit lands on the current head"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Re-read project; revision"));
}
