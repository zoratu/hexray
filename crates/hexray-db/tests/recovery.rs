//! Undo/redo durability, dependency invalidation and user-defined ranges.

mod common;

use std::time::{Duration, Instant};

use common::*;
use hexray_db::address::{Address, AddressRange, FileOffset};
use hexray_db::model::*;
use hexray_db::{DbError, Edit};
use hexray_types::CType;

fn array_payload() -> String {
    serde_json::to_string(&CType::array(CType::int(), Some(4))).expect("serialize array")
}

// ---------------------------------------------------------------------------
// Undo / redo
// ---------------------------------------------------------------------------

#[test]
fn undo_redo_survive_reopen_for_every_edit_kind() {
    let project = create_project();
    let mut db = project.open();

    let edits = vec![
        Edit::PatchBytes {
            file_offset: PATCH_OFFSET,
            bytes: vec![0xaa, 0xbb],
        },
        Edit::SetName {
            address: HELPER,
            name: Some("renamed_helper".into()),
        },
        Edit::PutType {
            name: "vec4".into(),
            kind: TypeKind::Typedef,
            payload_json: array_payload(),
        },
        Edit::SetFunctionBounds {
            start: HELPER,
            end: Address(0x1028),
        },
        Edit::SetItem {
            address: STRING_ADDRESS,
            length: 4,
            kind: ItemKind::Data,
            type_name: None,
        },
    ];
    for edit in &edits {
        let revision = db.revision().expect("revision");
        db.apply(revision, edit).expect("apply edit");
    }
    let after_apply = Revision(edits.len() as u64);
    assert_eq!(db.revision().expect("revision"), after_apply);
    assert_eq!(db.history_depth().expect("depth"), (edits.len(), 0));
    drop(db);

    // Reopen: the stack and the user state are durable.
    let mut db = project.open();
    assert_eq!(db.revision().expect("revision"), after_apply);
    assert_eq!(db.history_depth().expect("depth"), (edits.len(), 0));
    assert_eq!(db.patches().expect("patches").len(), 1);
    assert_eq!(
        db.name_at(HELPER).expect("name").as_deref(),
        Some("renamed_helper")
    );
    assert_eq!(db.types().expect("types").len(), 1);
    assert_eq!(
        db.function_at(HELPER)
            .expect("function")
            .expect("row")
            .declared_end,
        Some(Address(0x1028))
    );
    assert_eq!(db.items().expect("items").len(), 1);

    for _ in 0..edits.len() {
        let revision = db.revision().expect("revision");
        db.undo(revision).expect("undo");
    }
    let after_undo = Revision((edits.len() * 2) as u64);
    assert_eq!(db.revision().expect("revision"), after_undo);
    assert_eq!(db.history_depth().expect("depth"), (0, edits.len()));
    assert!(db.patches().expect("patches").is_empty());
    assert!(db.name_at(HELPER).expect("name").is_none());
    assert!(db.types().expect("types").is_empty());
    assert_eq!(
        db.function_at(HELPER)
            .expect("function")
            .expect("row")
            .declared_end,
        Some(HELPER_END),
        "undo restores the original declared bounds"
    );
    assert!(db.items().expect("items").is_empty());
    drop(db);

    let mut db = project.open();
    assert_eq!(db.revision().expect("revision"), after_undo);
    assert_eq!(db.history_depth().expect("depth"), (0, edits.len()));
    for _ in 0..edits.len() {
        let revision = db.revision().expect("revision");
        db.redo(revision).expect("redo");
    }
    assert_eq!(
        db.revision().expect("revision"),
        Revision((edits.len() * 3) as u64)
    );
    assert_eq!(db.history_depth().expect("depth"), (edits.len(), 0));

    let patched = db.patches().expect("patches");
    assert_eq!(patched.len(), 1);
    assert_eq!(patched[0].offset, PATCH_OFFSET);
    assert_eq!(patched[0].bytes, vec![0xaa, 0xbb]);
    assert_eq!(
        db.name_at(HELPER).expect("name").as_deref(),
        Some("renamed_helper")
    );
    assert_eq!(db.types().expect("types").len(), 1);
    assert_eq!(
        db.function_at(HELPER)
            .expect("function")
            .expect("row")
            .declared_end,
        Some(Address(0x1028))
    );
    assert_eq!(db.items().expect("items").len(), 1);
}

#[test]
fn new_edit_after_undo_clears_redo_but_keeps_the_audit_trail() {
    let project = create_project();
    let mut db = project.open();

    let revision = db.revision().expect("revision");
    db.apply(
        revision,
        &Edit::SetName {
            address: MAIN,
            name: Some("first".into()),
        },
    )
    .expect("first edit");
    let revision = db.revision().expect("revision");
    db.apply(
        revision,
        &Edit::SetComment {
            address: MAIN,
            text: Some("second".into()),
        },
    )
    .expect("second edit");
    let revision = db.revision().expect("revision");
    db.undo(revision).expect("undo second edit");
    assert_eq!(db.history_depth().expect("depth"), (1, 1));

    let revision = db.revision().expect("revision");
    db.apply(
        revision,
        &Edit::SetTag {
            address: MAIN,
            text: Some("third".into()),
        },
    )
    .expect("edit after undo");
    assert_eq!(
        db.history_depth().expect("depth"),
        (2, 0),
        "a new edit discards the redo branch"
    );

    let events = db
        .snapshot()
        .expect("snapshot")
        .history_events(100, 0)
        .expect("events");
    let actions: Vec<&str> = events.iter().map(|event| event.action.as_str()).collect();
    assert_eq!(
        actions,
        vec!["apply", "undo", "apply", "apply"],
        "history_events keeps apply/undo/apply/apply newest-first"
    );
    // The discarded redo edit still has its audit row.
    {
        let connection = raw_connection(&project.db_path);
        let log_rows: i64 = connection
            .query_row("SELECT COUNT(*) FROM edit_log", [], |row| row.get(0))
            .expect("count edit log");
        assert_eq!(
            log_rows, 3,
            "every applied edit keeps its log row, including the undone one"
        );
    }
}

#[test]
fn analysis_publication_does_not_consume_undo_or_change_revision() {
    let project = create_project();
    let mut db = project.open();
    let revision = db.revision().expect("revision");
    publish_units(&mut db, revision, vec![default_index_unit(Some(0))]);
    db.publish(
        revision,
        &AnalysisBatch {
            units: vec![
                CfgSpec::simple(main_function(), vec![sequential_instruction(MAIN)]).into_unit(),
            ],
        },
    )
    .expect("publish cfg");

    assert_eq!(
        db.revision().expect("revision"),
        revision,
        "publishing analysis is not a user edit"
    );
    assert_eq!(db.history_depth().expect("depth"), (0, 0));
    let events = db
        .snapshot()
        .expect("snapshot")
        .history_events(100, 0)
        .expect("events");
    assert!(
        events.is_empty(),
        "publication must not write user history: {events:?}"
    );
}

#[test]
fn empty_history_reports_nothing_to_undo_or_redo() {
    let project = create_project();
    let mut db = project.open();
    let revision = db.revision().expect("revision");

    let error = db.undo(revision).expect_err("undo must fail");
    assert!(
        matches!(error, DbError::NothingToUndo),
        "expected NothingToUndo, got {error:?}"
    );
    let error = db.redo(revision).expect_err("redo must fail");
    assert!(
        matches!(error, DbError::NothingToRedo),
        "expected NothingToRedo, got {error:?}"
    );
    assert_eq!(
        db.revision().expect("revision"),
        revision,
        "failed undo/redo do not consume a revision"
    );
    assert_eq!(db.history_depth().expect("depth"), (0, 0));
}

// ---------------------------------------------------------------------------
// Dependency invalidation
// ---------------------------------------------------------------------------

#[test]
fn renaming_a_callee_invalidates_render_and_recorded_name_dependencies() {
    let project = create_project();
    let mut db = project.open();
    let revision = db.revision().expect("revision");

    publish_units(&mut db, revision, vec![default_index_unit(Some(0))]);
    let mut main_spec = CfgSpec::simple(main_function(), vec![sequential_instruction(MAIN)]);
    main_spec.xrefs = vec![call_xref(MAIN, HELPER, Some(MAIN))];
    // A structured result that used the callee's name records the dependency.
    main_spec.dependencies = vec![Dependency {
        kind: DependencyKind::Name,
        key: format!("address:{:x}", HELPER.0),
        range: None,
        target_generation: 1,
    }];
    publish_units(&mut db, revision, vec![main_spec.into_unit()]);
    publish_units(
        &mut db,
        revision,
        vec![
            CfgSpec::simple(helper_function(), vec![sequential_instruction(HELPER)]).into_unit(),
            CfgSpec::simple(
                unrelated_function(),
                vec![sequential_instruction(UNRELATED)],
            )
            .into_unit(),
        ],
    );
    let config = sample_render_config();
    publish_units(
        &mut db,
        revision,
        vec![
            render_unit(
                MAIN,
                "int main(void) {}",
                &config,
                None,
                AnalysisState::Current,
            ),
            render_unit(
                HELPER,
                "int helper(void) {}",
                &config,
                None,
                AnalysisState::Current,
            ),
            render_unit(
                UNRELATED,
                "int unrelated(void) {}",
                &config,
                None,
                AnalysisState::Current,
            ),
        ],
    );
    for function in [MAIN, HELPER, UNRELATED] {
        assert_eq!(
            unit_state(&mut db, &UnitKey::function_cfg(function)),
            Some(AnalysisState::Current)
        );
    }

    let revision = db.revision().expect("revision");
    db.apply(
        revision,
        &Edit::SetName {
            address: HELPER,
            name: Some("renamed_helper".into()),
        },
    )
    .expect("rename callee");

    assert_eq!(
        unit_state(&mut db, &UnitKey::function_cfg(HELPER)),
        Some(AnalysisState::Current),
        "a rename changes no instruction, so the renamed function's CFG is not re-decoded"
    );
    assert_eq!(
        unit_state(
            &mut db,
            &UnitKey::function_render(HELPER, config.fingerprint())
        ),
        Some(AnalysisState::Stale),
        "the renamed function's rendered text is stale"
    );
    assert_eq!(
        unit_state(&mut db, &UnitKey::function_cfg(MAIN)),
        Some(AnalysisState::Stale),
        "a unit that recorded a name dependency on the callee is stale"
    );
    assert_eq!(
        unit_state(
            &mut db,
            &UnitKey::function_render(MAIN, config.fingerprint())
        ),
        Some(AnalysisState::Stale),
        "the caller's rendered text embeds the callee name"
    );
    assert_eq!(
        unit_state(&mut db, &UnitKey::function_cfg(UNRELATED)),
        Some(AnalysisState::Current),
        "an unrelated function must not be invalidated"
    );
    assert_eq!(
        unit_state(
            &mut db,
            &UnitKey::function_render(UNRELATED, config.fingerprint())
        ),
        Some(AnalysisState::Current)
    );
    assert_eq!(
        unit_state(&mut db, &UnitKey::image_index()),
        Some(AnalysisState::Current),
        "a rename is not an image-index edit"
    );
}

#[test]
fn patching_a_call_site_replaces_the_old_xref_after_publish() {
    let project = create_project();
    let mut db = project.open();
    let revision = db.revision().expect("revision");

    publish_units(&mut db, revision, vec![default_index_unit(Some(0))]);
    let mut spec = CfgSpec::simple(main_function(), vec![sequential_instruction(MAIN)]);
    spec.xrefs = vec![call_xref(MAIN, HELPER, Some(MAIN))];
    publish_units(&mut db, revision, vec![spec.into_unit()]);
    assert_eq!(
        db.xrefs_to(HELPER).expect("xrefs"),
        vec![call_xref(MAIN, HELPER, Some(MAIN))],
        "the fixture starts with the original call target"
    );

    let revision = db.revision().expect("revision");
    db.apply(
        revision,
        &Edit::PatchBytes {
            file_offset: FileOffset(0),
            bytes: vec![0x90],
        },
    )
    .expect("patch call site");
    assert_eq!(
        unit_state(&mut db, &UnitKey::function_cfg(MAIN)),
        Some(AnalysisState::Stale),
        "code bytes intersecting the function make its CFG stale"
    );

    let revision = db.revision().expect("revision");
    let mut republished = CfgSpec::new(main_function());
    republished.expected = Some(1);
    republished.instructions = vec![sequential_instruction(MAIN)];
    republished.blocks = vec![block(
        0,
        MAIN,
        Address(0x1004),
        hexray_core::BlockTerminator::Return,
    )];
    republished.block_instructions = vec![(0, vec![MAIN])];
    republished.xrefs = vec![call_xref(MAIN, UNRELATED, Some(MAIN))];
    publish_units(&mut db, revision, vec![republished.into_unit()]);

    let xrefs = db.xrefs_from(MAIN).expect("xrefs");
    assert!(
        !xrefs.iter().any(|xref| xref.to == HELPER),
        "the old call target must disappear with the replaced CFG: {xrefs:?}"
    );
    assert!(
        xrefs.iter().any(|xref| xref.to == UNRELATED),
        "the new call target appears: {xrefs:?}"
    );
    assert!(
        db.xrefs_to(HELPER).expect("xrefs").is_empty(),
        "no stale xref to the old target survives"
    );
    assert_eq!(xrefs.len(), 1, "exactly one call xref remains");
}

#[test]
fn data_patch_invalidates_units_with_incomplete_dependencies() {
    let project = create_project();
    let mut db = project.open();
    let revision = db.revision().expect("revision");

    publish_units(&mut db, revision, vec![default_index_unit(Some(0))]);

    let mut incomplete = CfgSpec::simple(helper_function(), vec![sequential_instruction(HELPER)]);
    incomplete.dependencies_complete = false;
    // No dependency rows at all: the unit could not record any range, so only
    // the conservative `dependencies_complete = false` scan can protect it.
    publish_units(&mut db, revision, vec![incomplete.into_unit()]);
    let mut complete = CfgSpec::simple(main_function(), vec![sequential_instruction(MAIN)]);
    complete.dependencies = vec![Dependency {
        kind: DependencyKind::Range,
        key: "own".into(),
        range: Some(AddressRange::new(MAIN, 4).expect("range")),
        target_generation: 0,
    }];
    publish_units(&mut db, revision, vec![complete.into_unit()]);

    let revision = db.revision().expect("revision");
    db.apply(
        revision,
        &Edit::PatchBytes {
            // Address 0x1100: inside the image, outside every declared
            // function, so only dependency-driven invalidation applies.
            file_offset: FileOffset(0x100),
            bytes: vec![0xcc],
        },
    )
    .expect("patch data bytes");

    assert_eq!(
        unit_state(&mut db, &UnitKey::function_cfg(HELPER)),
        Some(AnalysisState::Stale),
        "a unit that could not record complete ranges goes stale on any data edit"
    );
    assert_eq!(
        unit_state(&mut db, &UnitKey::function_cfg(MAIN)),
        Some(AnalysisState::Current),
        "a fully recorded unit outside the patched range stays current"
    );
}

#[test]
fn cyclic_dependencies_terminate_and_still_invalidate_both_sides() {
    let project = create_project();
    let mut db = project.open();
    let revision = db.revision().expect("revision");

    publish_units(&mut db, revision, vec![default_index_unit(Some(0))]);
    let mut main_spec = CfgSpec::simple(main_function(), vec![sequential_instruction(MAIN)]);
    main_spec.dependencies = vec![signature_dependency(HELPER, 1)];
    main_spec.xrefs = vec![call_xref(MAIN, HELPER, Some(MAIN))];
    publish_units(&mut db, revision, vec![main_spec.into_unit()]);

    let mut helper_spec = CfgSpec::simple(helper_function(), vec![sequential_instruction(HELPER)]);
    helper_spec.dependencies = vec![signature_dependency(MAIN, 1)];
    helper_spec.xrefs = vec![call_xref(HELPER, MAIN, Some(HELPER))];
    publish_units(&mut db, revision, vec![helper_spec.into_unit()]);
    publish_units(
        &mut db,
        revision,
        vec![CfgSpec::simple(
            unrelated_function(),
            vec![sequential_instruction(UNRELATED)],
        )
        .into_unit()],
    );

    let revision = db.revision().expect("revision");
    let started = Instant::now();
    // A signature change feeds `signature_targets`, and each unit depends on
    // the other's signature: a real A→B→A cycle through both the dependency
    // graph and the call xrefs.
    db.apply(
        revision,
        &Edit::SetFunctionSignature {
            start: MAIN,
            prototype: Some("int cycle_root(int value)".into()),
        },
    )
    .expect("cyclic invalidation must terminate");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "cycle closure took too long: {:?}",
        started.elapsed()
    );

    assert_eq!(
        unit_state(&mut db, &UnitKey::function_cfg(MAIN)),
        Some(AnalysisState::Stale)
    );
    assert_eq!(
        unit_state(&mut db, &UnitKey::function_cfg(HELPER)),
        Some(AnalysisState::Stale),
        "the caller in the cycle is invalidated through both the xref and the signature dependency"
    );
    assert_eq!(
        unit_state(&mut db, &UnitKey::function_cfg(UNRELATED)),
        Some(AnalysisState::Current),
        "the cycle closure does not reach unrelated units"
    );
}

// ---------------------------------------------------------------------------
// User-defined ranges and functions
// ---------------------------------------------------------------------------

#[test]
fn user_data_item_survives_automatic_index_publication() {
    let project = create_project();
    let mut db = project.open();
    let revision = db.revision().expect("revision");
    publish_units(&mut db, revision, vec![default_index_unit(Some(0))]);

    let revision = db.revision().expect("revision");
    db.apply(
        revision,
        &Edit::SetItem {
            address: STRING_ADDRESS,
            length: 4,
            kind: ItemKind::Data,
            type_name: None,
        },
    )
    .expect("define data");
    let defined = db.items().expect("items");
    assert_eq!(defined.len(), 1);
    assert_eq!(defined[0].origin, "user");

    let revision = db.revision().expect("revision");
    publish_units(&mut db, revision, vec![default_index_unit(Some(1))]);
    let after = db.items().expect("items");
    assert_eq!(
        after, defined,
        "automatic index publication must not overwrite user item definitions"
    );
}

#[test]
fn clearing_a_partial_item_is_refused_and_never_cuts_an_instruction() {
    let project = create_project();
    let mut db = project.open();
    let revision = db.revision().expect("revision");
    publish_units(
        &mut db,
        revision,
        vec![CfgSpec::simple(
            main_function(),
            vec![
                sequential_instruction(MAIN),
                sequential_instruction(Address(0x1004)),
                sequential_instruction(Address(0x1008)),
                sequential_instruction(Address(0x100c)),
            ],
        )
        .into_unit()],
    );

    let revision = db.revision().expect("revision");
    db.apply(
        revision,
        &Edit::SetItem {
            address: MAIN,
            length: 4,
            kind: ItemKind::Data,
            type_name: None,
        },
    )
    .expect("define a four-byte item over one instruction");
    let revision = db.revision().expect("revision");

    let error = db
        .apply(
            revision,
            &Edit::ClearItem {
                address: MAIN,
                length: 2,
            },
        )
        .expect_err("clearing two of four bytes must fail");
    match error {
        DbError::Validation(message) => {
            assert!(message.contains("partial"), "unexpected message: {message}")
        }
        other => panic!("expected Validation, got {other:?}"),
    }
    assert_eq!(db.revision().expect("revision"), revision);
    assert_eq!(db.items().expect("items").len(), 1);

    let error = db
        .apply(
            revision,
            &Edit::SetItem {
                address: MAIN,
                length: 2,
                kind: ItemKind::Code,
                type_name: None,
            },
        )
        .expect_err("a two-byte code range cuts a four-byte instruction");
    match error {
        DbError::Validation(message) => assert!(
            message.contains("cuts through"),
            "unexpected message: {message}"
        ),
        other => panic!("expected Validation, got {other:?}"),
    }
    assert_eq!(
        db.revision().expect("revision"),
        revision,
        "a refused edit does not advance the revision"
    );
}

#[test]
fn removing_one_of_two_functions_sharing_a_tail_keeps_the_other_intact() {
    let project = create_project();
    let mut db = project.open();
    let revision = db.revision().expect("revision");

    // A second user function overlapping the helper's tail.
    db.apply(
        revision,
        &Edit::CreateFunction {
            start: Address(0x1028),
            end: HELPER_END,
        },
    )
    .expect("create overlapping tail function");
    let revision = db.revision().expect("revision");
    let tail = Address(0x1028);
    let shared = vec![
        sequential_instruction(HELPER),
        sequential_instruction(Address(0x1024)),
        sequential_instruction(tail),
        sequential_instruction(Address(0x102c)),
    ];
    let mut helper_spec = CfgSpec::new(helper_function());
    helper_spec.instructions = shared.clone();
    helper_spec.blocks = vec![block(
        0,
        HELPER,
        HELPER_END,
        hexray_core::BlockTerminator::Return,
    )];
    helper_spec.block_instructions =
        vec![(0, vec![HELPER, Address(0x1024), tail, Address(0x102c)])];
    publish_units(&mut db, revision, vec![helper_spec.into_unit()]);

    let mut tail_spec = CfgSpec::new(function_row(tail, HELPER_END));
    tail_spec.instructions = vec![
        sequential_instruction(tail),
        sequential_instruction(Address(0x102c)),
    ];
    tail_spec.blocks = vec![block(
        0,
        tail,
        HELPER_END,
        hexray_core::BlockTerminator::Return,
    )];
    tail_spec.block_instructions = vec![(0, vec![tail, Address(0x102c)])];
    publish_units(&mut db, revision, vec![tail_spec.into_unit()]);

    assert_eq!(db.instructions(HELPER).expect("instructions").len(), 4);
    assert_eq!(db.instructions(tail).expect("instructions").len(), 2);

    let revision = db.revision().expect("revision");
    db.apply(revision, &Edit::RemoveFunction { start: HELPER })
        .expect("remove helper");

    let helper_row = db
        .function_at(HELPER)
        .expect("function")
        .expect("helper row is retained");
    assert!(helper_row.user_removed, "removal is a suppression marker");
    assert!(
        !db.functions()
            .expect("functions")
            .iter()
            .any(|row| row.address == HELPER),
        "suppressed functions disappear from live queries"
    );
    assert!(
        db.functions()
            .expect("functions")
            .iter()
            .any(|row| row.address == tail),
        "the other function sharing the tail stays live"
    );
    let tail_instructions = db.instructions(tail).expect("tail instructions");
    assert_eq!(
        tail_instructions.len(),
        2,
        "removing the other function must not delete the shared instructions"
    );
    assert_eq!(tail_instructions[0].address, tail.0);
    assert_eq!(db.cfg(tail).expect("tail cfg").blocks.len(), 1);

    // Re-creating the function clears the suppression marker.
    let revision = db.revision().expect("revision");
    db.apply(
        revision,
        &Edit::CreateFunction {
            start: HELPER,
            end: HELPER_END,
        },
    )
    .expect("re-create helper");
    let restored = db.function_at(HELPER).expect("function").expect("row");
    assert!(!restored.user_removed);
    assert!(db
        .functions()
        .expect("functions")
        .iter()
        .any(|row| row.address == HELPER));
}

#[test]
fn invalid_ranges_unmapped_addresses_and_referenced_types_leave_no_state() {
    let project = create_project();
    let mut db = project.open();
    let revision = db.revision().expect("revision");

    let unmapped = Address(0x9000);
    let error = db
        .apply(
            revision,
            &Edit::CreateFunction {
                start: unmapped,
                end: Address(0x9010),
            },
        )
        .expect_err("a function outside every mapping must fail");
    assert!(
        matches!(error, DbError::Validation(_)),
        "expected Validation, got {error:?}"
    );
    let error = db
        .apply(
            revision,
            &Edit::SetItem {
                address: unmapped,
                length: 4,
                kind: ItemKind::Data,
                type_name: None,
            },
        )
        .expect_err("an item outside every mapping must fail");
    assert!(matches!(error, DbError::Validation(_)));
    let error = db
        .apply(
            revision,
            &Edit::SetItem {
                address: MAIN,
                length: 0,
                kind: ItemKind::Data,
                type_name: None,
            },
        )
        .expect_err("a zero-length range must fail");
    assert!(
        matches!(error, DbError::Range(_)),
        "expected Range, got {error:?}"
    );
    assert_eq!(
        db.revision().expect("revision"),
        revision,
        "failed edits never advance the revision"
    );

    db.apply(
        revision,
        &Edit::PutType {
            name: "vec4".into(),
            kind: TypeKind::Typedef,
            payload_json: array_payload(),
        },
    )
    .expect("put type");
    let revision = db.revision().expect("revision");
    db.apply(
        revision,
        &Edit::SetItem {
            address: STRING_ADDRESS,
            length: 16,
            kind: ItemKind::Data,
            type_name: Some("vec4".into()),
        },
    )
    .expect("reference the type from an item");
    let revision = db.revision().expect("revision");

    let error = db
        .apply(
            revision,
            &Edit::RemoveType {
                name: "vec4".into(),
            },
        )
        .expect_err("a referenced type must not be deleted");
    match error {
        DbError::Validation(message) => assert!(
            message.contains("referenced"),
            "unexpected message: {message}"
        ),
        other => panic!("expected Validation, got {other:?}"),
    }
    assert_eq!(db.revision().expect("revision"), revision);
    assert_eq!(db.types().expect("types").len(), 1);

    // Clearing the reference unblocks the removal.
    db.apply(
        revision,
        &Edit::ClearItem {
            address: STRING_ADDRESS,
            length: 16,
        },
    )
    .expect("clear the item");
    let revision = db.revision().expect("revision");
    db.apply(
        revision,
        &Edit::RemoveType {
            name: "vec4".into(),
        },
    )
    .expect("type removal succeeds once unreferenced");
    assert!(db.types().expect("types").is_empty());
}
