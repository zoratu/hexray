use std::fs;
use std::path::PathBuf;

use hexray_analysis::decompiler::benchmark::{create_standard_suite, BenchmarkConfig};

fn fixture_output(case_id: &str) -> Result<String, String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/decompiler_quality")
        .join(format!("{case_id}.c.txt"));

    fs::read_to_string(&path)
        .map_err(|e| format!("failed to read fixture {}: {}", path.display(), e))
}

#[test]
fn test_control_flow_quality_smoke_from_fixtures() {
    let suite = create_standard_suite().with_config(BenchmarkConfig {
        categories: vec!["control_flow_quality".to_string()],
        continue_on_failure: false,
        ..Default::default()
    });

    let results = suite.run_all(fixture_output);

    assert_eq!(
        results.failed,
        0,
        "control-flow quality smoke failed:\n{}",
        results.report()
    );
    assert_eq!(
        results.passed, 3,
        "expected exactly 3 control-flow quality cases to run"
    );
}
