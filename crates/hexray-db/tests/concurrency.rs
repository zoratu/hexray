//! Multi-connection semantics: compare-and-swap edits, generation-checked
//! analysis publication, bounded lock waits and consistent snapshots.

mod common;

use std::time::{Duration, Instant};

use common::*;
use hexray_db::address::Address;
use hexray_db::model::*;
use hexray_db::{DbError, Edit, EditOutcome};

const LOCK_WAIT_LIMIT: Duration = Duration::from_secs(30);

#[test]
fn only_one_editor_of_the_same_revision_wins() {
    let project = create_project();
    let mut first = project.open();
    let mut second = project.open();

    let base = first.revision().expect("revision");
    assert_eq!(
        second.revision().expect("revision"),
        base,
        "both sessions start at the same revision"
    );

    let first_outcome = first
        .apply(
            base,
            &Edit::SetComment {
                address: MAIN,
                text: Some("first session".into()),
            },
        )
        .expect("first editor commits");
    assert_eq!(first_outcome, EditOutcome::Applied(Revision(base.0 + 1)));

    let error = second
        .apply(
            base,
            &Edit::SetName {
                address: HELPER,
                name: Some("second session".into()),
            },
        )
        .expect_err("the stale revision must be refused");
    match error {
        DbError::RevisionConflict { expected, actual } => {
            assert_eq!(expected, base.0, "the conflict reports the caller's base");
            assert_eq!(actual, base.0 + 1, "the conflict reports the current head");
        }
        other => panic!("expected RevisionConflict, got {other:?}"),
    }

    // After refresh the second session commits, and the first edit survives.
    let refreshed = second.revision().expect("refresh revision");
    assert_eq!(refreshed, Revision(base.0 + 1));
    let second_outcome = second
        .apply(
            refreshed,
            &Edit::SetName {
                address: HELPER,
                name: Some("second session".into()),
            },
        )
        .expect("second editor commits after refresh");
    assert_eq!(second_outcome, EditOutcome::Applied(Revision(base.0 + 2)));

    let mut observer = project.open();
    assert_eq!(observer.revision().expect("revision"), Revision(base.0 + 2));
    assert!(
        observer
            .annotations()
            .expect("annotations")
            .iter()
            .any(|(address, kind, value)| *address == MAIN
                && *kind == AnnotationKind::Comment
                && value == "first session"),
        "the first session's edit must not be lost"
    );
    assert_eq!(
        observer.name_at(HELPER).expect("name").as_deref(),
        Some("second session")
    );
}

#[test]
fn publication_from_a_stale_content_revision_is_rejected() {
    let project = create_project();
    let mut db = project.open();
    let stale = db.revision().expect("revision");

    db.apply(
        stale,
        &Edit::SetName {
            address: MAIN,
            name: Some("renamed".into()),
        },
    )
    .expect("commit before publishing");

    let error = db
        .publish(
            stale,
            &AnalysisBatch {
                units: vec![default_index_unit(Some(0))],
            },
        )
        .expect_err("stale base revision must be refused");
    match error {
        DbError::RevisionConflict { expected, actual } => {
            assert_eq!(expected, stale.0);
            assert_eq!(actual, stale.0 + 1);
        }
        other => panic!("expected RevisionConflict, got {other:?}"),
    }

    // Nothing was published: the pre-seeded index unit still has generation 0.
    {
        let snapshot = db.snapshot().expect("snapshot");
        assert_eq!(
            snapshot
                .analysis_generation(&UnitKey::image_index())
                .expect("generation"),
            Some(0),
            "a refused publish leaves the unit generation unchanged"
        );
        assert_eq!(
            snapshot
                .unit(&UnitKey::image_index())
                .expect("unit")
                .expect("row")
                .state,
            AnalysisState::Pending
        );
    }

    // Republishing from the current revision succeeds.
    let current = db.revision().expect("revision");
    db.publish(
        current,
        &AnalysisBatch {
            units: vec![default_index_unit(Some(0))],
        },
    )
    .expect("publish at the current revision");
    let snapshot = db.snapshot().expect("snapshot");
    assert_eq!(
        snapshot
            .analysis_generation(&UnitKey::image_index())
            .expect("generation"),
        Some(1)
    );
}

#[test]
fn publication_with_a_stale_unit_generation_is_rejected() {
    let project = create_project();
    let mut db = project.open();
    let revision = db.revision().expect("revision");

    db.publish(
        revision,
        &AnalysisBatch {
            units: vec![default_index_unit(Some(0))],
        },
    )
    .expect("first publish");
    let generation_after_first = unit_generation(&mut db, &UnitKey::image_index());
    assert_eq!(generation_after_first, Some(1));

    // Even at the same content revision, a second publisher that computed
    // from generation 0 must not overwrite the newer result.
    let error = db
        .publish(
            revision,
            &AnalysisBatch {
                units: vec![default_index_unit(Some(0))],
            },
        )
        .expect_err("stale generation must be refused");
    match error {
        DbError::AnalysisGenerationConflict {
            owner,
            expected,
            actual,
        } => {
            assert_eq!(expected, 0);
            assert_eq!(actual, Some(1));
            assert!(owner.contains("image_index"), "owner: {owner}");
        }
        other => panic!("expected AnalysisGenerationConflict, got {other:?}"),
    }
    assert_eq!(
        unit_generation(&mut db, &UnitKey::image_index()),
        Some(1),
        "the refused publish did not advance the generation"
    );

    db.publish(
        revision,
        &AnalysisBatch {
            units: vec![default_index_unit(Some(1))],
        },
    )
    .expect("publish with the observed generation");
    assert_eq!(unit_generation(&mut db, &UnitKey::image_index()), Some(2));
    assert_eq!(
        db.revision().expect("revision"),
        revision,
        "analysis publication never advances the content revision"
    );
}

#[test]
fn lock_contention_is_bounded_and_snapshots_do_not_stitch_states() {
    let project = create_project();
    let mut reader_db = project.open();
    let revision = reader_db.revision().expect("revision");

    publish_units(&mut reader_db, revision, vec![default_index_unit(Some(0))]);
    let mut spec = CfgSpec::simple(
        main_function(),
        vec![
            sequential_instruction(MAIN),
            sequential_instruction(Address(0x1004)),
        ],
    );
    spec.xrefs = vec![call_xref(MAIN, HELPER, Some(MAIN))];
    publish_units(&mut reader_db, revision, vec![spec.into_unit()]);
    let config = sample_render_config();
    publish_units(
        &mut reader_db,
        revision,
        vec![render_unit(
            MAIN,
            LAYOUT_TEXT,
            &config,
            None,
            AnalysisState::Current,
        )],
    );

    let key = UnitKey::function_cfg(MAIN);
    let render_key = UnitKey::function_render(MAIN, config.fingerprint());
    let snapshot = reader_db.snapshot().expect("snapshot");
    let observed_revision = snapshot.data_revision();
    let observed_generation = snapshot
        .analysis_generation(&key)
        .expect("generation")
        .expect("unit exists");
    assert_eq!(observed_generation, 1);
    assert_eq!(
        snapshot.unit(&key).expect("unit").expect("row").state,
        AnalysisState::Current
    );
    assert_eq!(
        snapshot.overall_state().expect("state"),
        OverallState::Ready
    );
    let observed_instructions = snapshot.instructions(MAIN).expect("instructions");
    let observed_xrefs = snapshot.all_xrefs().expect("xrefs");
    assert_eq!(observed_xrefs.len(), 1);
    assert_eq!(observed_revision, revision);

    // A second connection tries to commit while the snapshot holds the read
    // lock. SQLite must wait a bounded time, then report busy.
    let mut writer = project.open();
    let started = Instant::now();
    let error = writer
        .apply(
            observed_revision,
            &Edit::SetName {
                address: HELPER,
                name: Some("blocked rename".into()),
            },
        )
        .expect_err("the write must not succeed under a read lock");
    let elapsed = started.elapsed();
    assert!(
        matches!(error, DbError::Busy(_)),
        "expected Busy, got {error:?} after {elapsed:?}"
    );
    assert!(
        elapsed >= Duration::from_millis(10),
        "the writer must actually contend for the lock, not bypass it"
    );
    assert!(
        elapsed < LOCK_WAIT_LIMIT,
        "lock contention must be bounded, took {elapsed:?}"
    );

    // Re-reading every value from the same snapshot still returns the state
    // the snapshot started with: no mixing with the failed writer's state.
    assert_eq!(snapshot.data_revision(), observed_revision);
    assert_eq!(
        snapshot.analysis_generation(&key).expect("generation"),
        Some(observed_generation)
    );
    let reread_instructions = snapshot.instructions(MAIN).expect("instructions");
    assert_eq!(
        reread_instructions.len(),
        observed_instructions.len(),
        "instruction rows from one snapshot must not change"
    );
    assert_eq!(
        snapshot.all_xrefs().expect("xrefs"),
        observed_xrefs,
        "xrefs from one snapshot must not be stitched from another revision"
    );
    drop(snapshot);

    // With the snapshot released, the same edit commits; the next snapshot
    // observes the new revision and the invalidated unit.
    writer
        .apply(
            observed_revision,
            &Edit::SetName {
                address: HELPER,
                name: Some("blocked rename".into()),
            },
        )
        .expect("write succeeds once the snapshot is gone");
    let new_revision = writer.revision().expect("revision");
    assert_eq!(new_revision, Revision(observed_revision.0 + 1));
    let fresh = reader_db.snapshot().expect("fresh snapshot");
    assert_eq!(fresh.data_revision(), new_revision);
    assert_eq!(
        fresh.unit(&key).expect("unit").expect("row").state,
        AnalysisState::Current,
        "a rename does not force instruction re-decoding: the CFG stays current"
    );
    assert_eq!(
        fresh.unit(&render_key).expect("unit").expect("row").state,
        AnalysisState::Stale,
        "the caller's rendered text embeds the callee name"
    );
    assert_eq!(
        fresh.overall_state().expect("state"),
        OverallState::Partial,
        "a stale render unit must not be reported as ready"
    );
}
