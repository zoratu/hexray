//! Batch read APIs and batch-scoped publication invariants.
//!
//! Every assertion names the storage property it protects: instruction-row
//! lifetime across a shared owner, whole-batch rollback, paging equivalence
//! with the whole-table readers, and the persisted analysis scope.

mod common;

use std::collections::BTreeSet;

use common::*;
use hexray_core::{BasicBlockId, BlockTerminator, Condition, Instruction};
use hexray_db::address::Address;
use hexray_db::model::*;
use hexray_db::store::PayloadBytes;
use hexray_db::{Database, DbError, Edit, EditOutcome, Revision};

/// Entry point of the first fixture function (`MAIN`).
const ENTRY_A: Address = Address(0x1000);
/// Entry point of the second fixture function (`HELPER`).
const ENTRY_B: Address = Address(0x1020);
/// Instruction address owned by both functions.
const SHARED_TAIL: Address = Address(0x1008);
/// An address that belongs to no function at all.
const UNKNOWN: Address = Address(0x9999);

// ---------------------------------------------------------------------------
// Fixtures beyond the shared module
// ---------------------------------------------------------------------------

fn cfg_unit(
    function: FunctionRow,
    instructions: Vec<Instruction>,
    expected: Option<u64>,
) -> UnitPublish {
    let mut spec = CfgSpec::simple(function, instructions);
    spec.expected = expected;
    spec.into_unit()
}

fn string_row(address: Address, encoding: StringEncoding, text: &str) -> StringRow {
    StringRow {
        address,
        encoding,
        bytes: text.as_bytes().to_vec(),
        text: Some(text.to_string()),
    }
}

fn typed_xref(from: Address, to: Address, kind: XrefKind, owner: Option<Address>) -> XrefRow {
    XrefRow {
        from,
        to,
        kind,
        owner,
        origin: XrefOrigin::Auto,
    }
}

fn scope_of(ranges: &[(u64, u64, Option<&str>)]) -> AnalysisScope {
    AnalysisScope {
        payload_version: AnalysisScope::CURRENT_PAYLOAD_VERSION,
        excluded_ranges: ranges
            .iter()
            .map(|(start, end, name)| ScopeRange {
                start: Address(*start),
                end: Address(*end),
                section_name: name.map(str::to_string),
            })
            .collect(),
    }
}

fn create_project_with_scope(initial: AnalysisScope) -> Project {
    let dir = tempfile::tempdir().expect("temp dir");
    let source_bytes = default_source();
    let source_path = dir.path().join("sample.bin");
    std::fs::write(&source_path, &source_bytes).expect("write source");
    let db_path = dir.path().join("sample.hxdb");
    let input = CreateInput {
        original_path: source_path.clone(),
        source_bytes: source_bytes.clone(),
        container_kind: ContainerKind::Elf,
        image: default_image(AbiInfo::lp64()),
        engine_fingerprint: engine_fingerprint(),
        symbols: fixture_symbols(),
        functions: core_functions(),
        strings: vec![sample_string()],
        xrefs: Vec::new(),
        builtin_types_json: Some("{}".into()),
        analysis_scope: initial,
        diagnostics: Vec::new(),
    };
    Database::create(&db_path, &input).expect("create database");
    Project {
        dir,
        db_path,
        source_path,
        source_bytes,
    }
}

fn instruction_rows(project: &Project) -> Vec<Address> {
    let conn = raw_connection(&project.db_path);
    let mut statement = conn
        .prepare("SELECT address FROM instructions WHERE image_id = 1 ORDER BY address")
        .expect("prepare instruction query");
    let mut rows = statement.query([]).expect("query instructions");
    let mut out = Vec::new();
    while let Some(row) = rows.next().expect("instruction row") {
        out.push(Address::from_blob(&row.get::<_, Vec<u8>>(0).expect("address")).expect("blob"));
    }
    out
}

fn has_instruction_row(project: &Project, address: Address) -> bool {
    instruction_rows(project).contains(&address)
}

fn scope_resource_rows(project: &Project) -> i64 {
    let conn = raw_connection(&project.db_path);
    conn.query_row(
        "SELECT COUNT(*) FROM resources WHERE image_id = 1 AND kind = 'analysis_scope'",
        [],
        |row| row.get(0),
    )
    .expect("count scope resources")
}

fn page<T: Clone>(rows: &[T], limit: usize, offset: usize) -> Vec<T> {
    rows.iter().skip(offset).take(limit).cloned().collect()
}

const WINDOWS: [(usize, usize); 10] = [
    (0, 0),
    (1, 0),
    (2, 0),
    (3, 0),
    (2, 1),
    (2, 2),
    (2, 3),
    (100, 0),
    (0, 10),
    (1, 10),
];

// ---------------------------------------------------------------------------
// Instruction rows shared by two owners
// ---------------------------------------------------------------------------

/// Publishing owner A's replacement must not delete a tail instruction that
/// only the still-standing owner B relationship keeps alive.
#[test]
fn shared_tail_survives_single_owner_replacement() {
    let project = create_project();
    let mut db = project.open();
    let revision = revision_of(&db);

    publish_units(
        &mut db,
        revision,
        vec![
            cfg_unit(
                main_function(),
                vec![
                    sequential_instruction(ENTRY_A),
                    sequential_instruction(SHARED_TAIL),
                ],
                None,
            ),
            cfg_unit(
                helper_function(),
                vec![
                    sequential_instruction(ENTRY_B),
                    sequential_instruction(SHARED_TAIL),
                ],
                None,
            ),
        ],
    );
    assert_eq!(
        instruction_rows(&project),
        vec![ENTRY_A, SHARED_TAIL, ENTRY_B],
        "the initial batch stores three distinct instruction rows"
    );
    assert_eq!(unit_generation(&mut db, &UnitKey::function_cfg(ENTRY_A)), Some(1));
    assert_eq!(unit_generation(&mut db, &UnitKey::function_cfg(ENTRY_B)), Some(1));

    // Replace A *without* the tail: the sweep runs, but B still owns the row.
    publish_units(
        &mut db,
        revision,
        vec![cfg_unit(
            main_function(),
            vec![sequential_instruction(ENTRY_A)],
            Some(1),
        )],
    );

    assert!(
        has_instruction_row(&project, SHARED_TAIL),
        "owner B still references the tail instruction"
    );
    let snapshot = db.snapshot().expect("snapshot");
    let main_addresses: Vec<u64> = snapshot
        .instructions(ENTRY_A)
        .expect("main instructions")
        .iter()
        .map(|instruction| instruction.address)
        .collect();
    assert_eq!(
        main_addresses,
        vec![ENTRY_A.0],
        "owner A's replacement dropped its own reference"
    );
    let helper_addresses: Vec<u64> = snapshot
        .instructions(ENTRY_B)
        .expect("helper instructions")
        .iter()
        .map(|instruction| instruction.address)
        .collect();
    assert_eq!(helper_addresses, vec![ENTRY_B.0, SHARED_TAIL.0]);
}

/// Once the last owner that references the tail is replaced without it, the
/// row is an orphan and disappears — but only after the whole batch ran.
#[test]
fn shared_tail_is_swept_only_after_last_owner_replaced() {
    let project = create_project();
    let mut db = project.open();
    let revision = revision_of(&db);

    publish_units(
        &mut db,
        revision,
        vec![
            cfg_unit(
                main_function(),
                vec![
                    sequential_instruction(ENTRY_A),
                    sequential_instruction(SHARED_TAIL),
                ],
                None,
            ),
            cfg_unit(
                helper_function(),
                vec![
                    sequential_instruction(ENTRY_B),
                    sequential_instruction(SHARED_TAIL),
                ],
                None,
            ),
        ],
    );

    // One batch replaces both owners; neither payload keeps the tail.
    publish_units(
        &mut db,
        revision,
        vec![
            cfg_unit(
                main_function(),
                vec![sequential_instruction(ENTRY_A)],
                Some(1),
            ),
            cfg_unit(
                helper_function(),
                vec![sequential_instruction(ENTRY_B)],
                Some(1),
            ),
        ],
    );

    assert_eq!(
        instruction_rows(&project),
        vec![ENTRY_A, ENTRY_B],
        "only the two owned instruction rows remain"
    );
    assert!(
        !has_instruction_row(&project, SHARED_TAIL),
        "the unreferenced tail is swept after the batch"
    );
}

/// Replacing both owners in one publish ends in the same rows regardless of
/// the unit order inside the batch.
#[test]
fn batch_replacement_order_does_not_change_instruction_rows() {
    for order in [[ENTRY_A, ENTRY_B], [ENTRY_B, ENTRY_A]] {
        let project = create_project();
        let mut db = project.open();
        let revision = revision_of(&db);

        publish_units(
            &mut db,
            revision,
            vec![
                cfg_unit(
                    main_function(),
                    vec![
                        sequential_instruction(ENTRY_A),
                        sequential_instruction(SHARED_TAIL),
                    ],
                    None,
                ),
                cfg_unit(
                    helper_function(),
                    vec![
                        sequential_instruction(ENTRY_B),
                        sequential_instruction(SHARED_TAIL),
                    ],
                    None,
                ),
            ],
        );

        let mut units = Vec::new();
        for entry in order {
            let (function, only) = if entry == ENTRY_A {
                (main_function(), ENTRY_A)
            } else {
                (helper_function(), ENTRY_B)
            };
            units.push(cfg_unit(function, vec![sequential_instruction(only)], Some(1)));
        }
        publish_units(&mut db, revision, units);

        assert_eq!(
            instruction_rows(&project),
            vec![ENTRY_A, ENTRY_B],
            "order {order:?}: exactly the payload instruction rows remain"
        );
        assert!(
            !has_instruction_row(&project, SHARED_TAIL),
            "order {order:?}: the shared tail is gone once neither owner references it"
        );
        let snapshot = db.snapshot().expect("snapshot");
        assert_eq!(
            snapshot
                .functions_with_instructions(&[ENTRY_A, ENTRY_B])
                .expect("grouped instruction ownership"),
            BTreeSet::from([ENTRY_A, ENTRY_B]),
            "order {order:?}: both owners still have stored instructions"
        );
    }
}

/// A stale generation on the second unit must discard the first unit's
/// replacement, including its instruction rows.
#[test]
fn stale_generation_rolls_back_the_whole_batch() {
    let project = create_project();
    let mut db = project.open();
    let revision = revision_of(&db);

    publish_units(
        &mut db,
        revision,
        vec![
            cfg_unit(
                main_function(),
                vec![
                    sequential_instruction(ENTRY_A),
                    sequential_instruction(SHARED_TAIL),
                ],
                None,
            ),
            cfg_unit(
                helper_function(),
                vec![
                    sequential_instruction(ENTRY_B),
                    sequential_instruction(SHARED_TAIL),
                ],
                None,
            ),
        ],
    );

    let error = db
        .publish(
            revision,
            &AnalysisBatch {
                units: vec![
                    // Valid on its own: drops A's reference to the tail.
                    cfg_unit(
                        main_function(),
                        vec![sequential_instruction(ENTRY_A)],
                        Some(1),
                    ),
                    // Stale: the helper owner is already at generation 1.
                    cfg_unit(
                        helper_function(),
                        vec![sequential_instruction(ENTRY_B)],
                        None,
                    ),
                ],
            },
        )
        .expect_err("a stale generation must refuse the batch");

    match error {
        DbError::AnalysisGenerationConflict {
            owner,
            expected,
            actual,
        } => {
            assert!(owner.contains("function_cfg"), "owner: {owner}");
            assert_eq!(expected, 0);
            assert_eq!(actual, Some(1));
        }
        other => panic!("expected AnalysisGenerationConflict, got {other:?}"),
    }

    assert_eq!(
        unit_generation(&mut db, &UnitKey::function_cfg(ENTRY_A)),
        Some(1),
        "the first unit's generation update was rolled back"
    );
    assert!(
        has_instruction_row(&project, SHARED_TAIL),
        "the rollback restores the shared tail row"
    );
    assert_eq!(
        instruction_rows(&project),
        vec![ENTRY_A, SHARED_TAIL, ENTRY_B],
        "no row from the refused batch is visible"
    );
    let snapshot = db.snapshot().expect("snapshot");
    let main_addresses: Vec<u64> = snapshot
        .instructions(ENTRY_A)
        .expect("main instructions")
        .iter()
        .map(|instruction| instruction.address)
        .collect();
    assert_eq!(
        main_addresses,
        vec![ENTRY_A.0, SHARED_TAIL.0],
        "owner A still carries its pre-batch instruction set"
    );
}

/// Render-only and index-only publications keep unrelated instruction rows,
/// including an orphan written outside the analysis path.
#[test]
fn render_and_index_publishes_never_sweep_instructions() {
    let project = create_project();
    let mut db = project.open();
    let revision = revision_of(&db);

    publish_units(
        &mut db,
        revision,
        vec![cfg_unit(
            main_function(),
            vec![
                sequential_instruction(ENTRY_A),
                sequential_instruction(SHARED_TAIL),
            ],
            None,
        )],
    );

    // A row that no function references, inserted directly so the sweep has
    // something it could wrongly collect.
    let orphan = Address(0x7777);
    {
        let conn = raw_connection(&project.db_path);
        let payload = serde_json::to_string(&sequential_instruction(orphan)).expect("json");
        conn.execute(
            "INSERT INTO instructions (image_id, address, size, payload_version, payload_json)
             VALUES (1, ?1, 4, 1, ?2)",
            rusqlite::params![&orphan.to_blob()[..], payload],
        )
        .expect("insert orphan instruction");
    }
    assert!(has_instruction_row(&project, orphan));

    let config = sample_render_config();
    publish_units(
        &mut db,
        revision,
        vec![render_unit(
            ENTRY_A,
            LAYOUT_TEXT,
            &config,
            None,
            AnalysisState::Current,
        )],
    );
    assert!(
        has_instruction_row(&project, orphan),
        "a render-only publish never sweeps instruction rows"
    );

    publish_units(&mut db, revision, vec![default_index_unit(Some(0))]);
    assert!(
        has_instruction_row(&project, orphan),
        "an index-only publish never sweeps instruction rows"
    );
    assert_eq!(
        instruction_rows(&project),
        vec![ENTRY_A, SHARED_TAIL, orphan],
        "both analysis rows and the orphan survive"
    );
}

/// Republishing an identical CFG deletes and reinserts the same ownership
/// rows, so the function drops no instruction: the batch has no orphan
/// candidates and the global sweep stays out of the transaction.
#[test]
fn republishing_an_unchanged_cfg_leaves_unowned_rows_alone() {
    let project = create_project();
    let mut db = project.open();
    let revision = revision_of(&db);

    let instructions = || {
        vec![
            sequential_instruction(ENTRY_A),
            sequential_instruction(SHARED_TAIL),
        ]
    };
    publish_units(
        &mut db,
        revision,
        vec![cfg_unit(main_function(), instructions(), None)],
    );

    // A row that no function references, inserted directly so a stray sweep
    // would collect it.
    let orphan = Address(0x7777);
    {
        let conn = raw_connection(&project.db_path);
        let payload = serde_json::to_string(&sequential_instruction(orphan)).expect("json");
        conn.execute(
            "INSERT INTO instructions (image_id, address, size, payload_version, payload_json)
             VALUES (1, ?1, 4, 1, ?2)",
            rusqlite::params![&orphan.to_blob()[..], payload],
        )
        .expect("insert orphan instruction");
    }

    // The same payload again: old minus new ownership is empty.
    publish_units(
        &mut db,
        revision,
        vec![cfg_unit(main_function(), instructions(), Some(1))],
    );

    assert!(
        has_instruction_row(&project, orphan),
        "an unchanged republish never sweeps instruction rows"
    );
    assert_eq!(
        instruction_rows(&project),
        vec![ENTRY_A, SHARED_TAIL, orphan],
        "the function's instruction rows and the unowned row survive"
    );
}

// ---------------------------------------------------------------------------
// Paging equivalence with the whole-table readers
// ---------------------------------------------------------------------------

#[test]
fn function_pages_match_whole_table_reader() {
    let project = create_project();
    let mut db = project.open();
    let revision = revision_of(&db);

    // Drop the unrelated function from the image index so the live filter has
    // something to do, and store a CFG unit for MAIN only.
    let mut index = default_index_unit(Some(0));
    if let AnalysisPayload::ImageIndex(payload) = &mut index.payload {
        payload.functions = vec![main_function(), helper_function()];
    }
    publish_units(&mut db, revision, vec![index]);
    publish_units(
        &mut db,
        revision,
        vec![cfg_unit(
            main_function(),
            vec![sequential_instruction(ENTRY_A)],
            None,
        )],
    );

    let snapshot = db.snapshot().expect("snapshot");
    let all = snapshot.functions().expect("functions");
    assert_eq!(
        all.iter().map(|function| function.address).collect::<Vec<_>>(),
        vec![ENTRY_A, ENTRY_B],
        "the user-visible function list is live-only"
    );

    for (limit, offset) in WINDOWS {
        let actual: Vec<FunctionRow> = snapshot
            .functions_page(limit, offset)
            .expect("functions page")
            .into_iter()
            .map(|row| row.function)
            .collect();
        assert_eq!(
            actual,
            page(&all, limit, offset),
            "functions_page({limit}, {offset})"
        );
    }

    let page_one = snapshot.functions_page(10, 0).expect("functions page");
    assert_eq!(page_one.len(), 2);
    assert_eq!(
        page_one[0].state,
        Some(AnalysisState::Current),
        "MAIN has a stored CFG unit"
    );
    assert_eq!(page_one[1].state, None, "HELPER has no CFG unit");
}

#[test]
fn symbol_string_and_type_pages_match_whole_table_readers() {
    let project = create_project();
    let mut db = project.open();
    let revision = revision_of(&db);

    let strings = vec![
        string_row(Address(0x1108), StringEncoding::Ascii, "beta"),
        string_row(Address(0x1100), StringEncoding::Ascii, "alpha"),
        string_row(Address(0x1100), StringEncoding::Utf8, "alpha-utf8"),
        string_row(Address(0x1110), StringEncoding::Utf16Le, "gamma"),
    ];
    publish_units(
        &mut db,
        revision,
        vec![index_unit(
            Some(0),
            AnalysisState::Current,
            core_functions(),
            core_symbols(),
            strings,
            Vec::new(),
        )],
    );

    for (name, kind) in [
        ("gamma", TypeKind::Struct),
        ("alpha", TypeKind::Enum),
        ("beta", TypeKind::Union),
    ] {
        let revision = revision_of(&db);
        db.apply(
            revision,
            &Edit::PutType {
                name: name.into(),
                kind,
                payload_json: "{}".into(),
            },
        )
        .expect("put type");
    }

    let snapshot = db.snapshot().expect("snapshot");
    let all_symbols = snapshot.symbols().expect("symbols");
    assert!(all_symbols.len() > 1, "the fixture has several symbols");
    let all_strings = snapshot.strings().expect("strings");
    assert_eq!(all_strings.len(), 4);
    let all_types = snapshot.types().expect("types");
    assert_eq!(all_types.len(), 3);

    for (limit, offset) in WINDOWS {
        assert_eq!(
            snapshot.symbols_page(limit, offset).expect("symbols page"),
            page(&all_symbols, limit, offset),
            "symbols_page({limit}, {offset})"
        );
        assert_eq!(
            snapshot.strings_page(limit, offset).expect("strings page"),
            page(&all_strings, limit, offset),
            "strings_page({limit}, {offset})"
        );
        assert_eq!(
            snapshot.types_page(limit, offset).expect("types page"),
            page(&all_types, limit, offset),
            "types_page({limit}, {offset})"
        );
    }
}

// ---------------------------------------------------------------------------
// Per-owner artifact readers
// ---------------------------------------------------------------------------

#[test]
fn batch_artifact_readers_match_per_function_readers() {
    let project = create_project();
    let mut db = project.open();
    let revision = revision_of(&db);

    let main_instructions = vec![
        sequential_instruction(ENTRY_A),
        sequential_instruction(SHARED_TAIL),
    ];
    let helper_instructions = vec![
        sequential_instruction(ENTRY_B),
        sequential_instruction(Address(0x1028)),
    ];
    let mut main_spec = CfgSpec::simple(main_function(), main_instructions.clone());
    main_spec.edges = vec![
        (0, 1, EdgeKind::Normal),
        (0, 1, EdgeKind::Unwind),
        (1, 0, EdgeKind::Normal),
    ];
    main_spec.block_instructions = vec![
        (0, vec![ENTRY_A, SHARED_TAIL]),
        (1, vec![Address(0x1028)]),
    ];
    main_spec.blocks = vec![
        block(0, ENTRY_A, SHARED_TAIL, hexray_core::BlockTerminator::Unknown),
        block(
            1,
            Address(0x1028),
            Address(0x102c),
            hexray_core::BlockTerminator::Return,
        ),
    ];
    main_spec.xrefs = vec![call_xref(SHARED_TAIL, ENTRY_B, Some(ENTRY_A))];

    publish_units(
        &mut db,
        revision,
        vec![
            main_spec.into_unit(),
            CfgSpec::simple(helper_function(), helper_instructions.clone()).into_unit(),
        ],
    );

    let snapshot = db.snapshot().expect("snapshot");
    let requested = [ENTRY_A, ENTRY_B, UNRELATED, UNKNOWN];
    let instructions = snapshot
        .instructions_for_functions(&requested)
        .expect("batch instructions");
    assert_eq!(
        instructions.keys().copied().collect::<Vec<_>>(),
        vec![ENTRY_A, ENTRY_B],
        "only owners with instruction rows appear"
    );
    for (function, expected) in [(ENTRY_A, &main_instructions), (ENTRY_B, &helper_instructions)] {
        let actual = &instructions[&function];
        assert_eq!(actual.len(), expected.len(), "instruction count of {function:?}");
        for (actual, expected) in actual.iter().zip(expected.iter()) {
            assert_instruction_eq(actual, expected);
        }
        let one = snapshot.instructions(function).expect("single instructions");
        assert_eq!(actual.len(), one.len());
        for (actual, one) in actual.iter().zip(one.iter()) {
            assert_instruction_eq(actual, one);
        }
    }

    let cfgs = snapshot
        .cfgs_for_functions(&requested)
        .expect("batch cfgs");
    assert_eq!(
        cfgs.keys().copied().collect::<Vec<_>>(),
        vec![ENTRY_A, ENTRY_B],
        "only owners with basic blocks appear"
    );
    for function in [ENTRY_A, ENTRY_B] {
        let batched = &cfgs[&function];
        let single = snapshot.cfg(function).expect("single cfg");
        assert_eq!(batched.blocks, single.blocks, "blocks of {function:?}");
        assert_eq!(
            batched.block_instructions, single.block_instructions,
            "block instructions of {function:?}"
        );
        assert_eq!(batched.edges, single.edges, "edges of {function:?}");
    }
    assert_eq!(
        cfgs[&ENTRY_A].edges,
        vec![
            (0, 1, EdgeKind::Normal),
            (0, 1, EdgeKind::Unwind),
            (1, 0, EdgeKind::Normal)
        ]
    );
    assert_eq!(
        snapshot
            .functions_with_instructions(&requested)
            .expect("grouped instruction ownership"),
        BTreeSet::from([ENTRY_A, ENTRY_B]),
        "grouped instruction ownership"
    );

    // The payload footprint is measured with LENGTH(); the render column only
    // appears once a rendering is stored.
    let bytes = snapshot
        .payload_bytes_for_functions(&requested)
        .expect("payload bytes");
    let main_bytes: &PayloadBytes = bytes.get(&ENTRY_A).expect("MAIN footprint");
    assert!(main_bytes.instructions > 0);
    assert!(main_bytes.cfg > 0);
    assert_eq!(main_bytes.render, 0);
    assert!(
        !bytes.contains_key(&UNRELATED),
        "functions without artifacts have no footprint entry"
    );
    assert!(
        snapshot
            .rendered_for(&sample_render_config().fingerprint(), &requested)
            .expect("rendered lookup")
            .is_empty()
    );
    drop(snapshot);

    let config = sample_render_config();
    publish_units(
        &mut db,
        revision,
        vec![render_unit(
            ENTRY_A,
            LAYOUT_TEXT,
            &config,
            None,
            AnalysisState::Current,
        )],
    );
    let snapshot = db.snapshot().expect("snapshot");
    let bytes = snapshot
        .payload_bytes_for_functions(&requested)
        .expect("payload bytes");
    assert_eq!(
        bytes[&ENTRY_A].render,
        LAYOUT_TEXT.len() as u64,
        "render footprint is the stored text length"
    );
    assert_eq!(
        snapshot
            .rendered_for(&config.fingerprint(), &requested)
            .expect("rendered lookup"),
        BTreeSet::from([ENTRY_A])
    );
}

// ---------------------------------------------------------------------------
// Point and xref readers
// ---------------------------------------------------------------------------

#[test]
fn point_and_xref_readers_follow_their_contracts() {
    let project = create_project();
    let mut db = project.open();
    let revision = revision_of(&db);

    // Neither end (x4) is requested; both ends of x1 are requested.
    let x1 = call_xref(ENTRY_A, ENTRY_B, None);
    let x2 = typed_xref(Address(0x1080), ENTRY_B, XrefKind::Jump, None);
    let x3 = typed_xref(ENTRY_A, Address(0x1090), XrefKind::Data, None);
    let x4 = typed_xref(Address(0x1080), Address(0x1090), XrefKind::Jump, None);
    let x5 = call_xref(Address(0x1030), ENTRY_B, Some(ENTRY_B));
    publish_units(
        &mut db,
        revision,
        vec![index_unit(
            Some(0),
            AnalysisState::Current,
            core_functions(),
            core_symbols(),
            vec![sample_string()],
            vec![x1.clone(), x2.clone(), x3.clone(), x4, x5.clone()],
        )],
    );

    let revision = revision_of(&db);
    db.apply(
        revision,
        &Edit::SetName {
            address: ENTRY_B,
            name: Some("helper_ref".into()),
        },
    )
    .expect("set name");

    let snapshot = db.snapshot().expect("snapshot");

    let names = snapshot
        .names_for(&[ENTRY_A, ENTRY_B, UNKNOWN])
        .expect("names");
    assert_eq!(
        names.keys().copied().collect::<Vec<_>>(),
        vec![ENTRY_B],
        "only the address with a user name has an entry"
    );
    assert_eq!(names[&ENTRY_B], "helper_ref");

    let symbols = snapshot
        .symbols_for(&[ENTRY_A, ENTRY_B, UNKNOWN])
        .expect("symbols");
    assert_eq!(
        symbols.keys().copied().collect::<Vec<_>>(),
        vec![ENTRY_A, ENTRY_B],
        "addresses without a symbol row are absent"
    );
    assert_eq!(
        symbols[&ENTRY_A].name, "main",
        "the preferred row is the first one in symbols() order"
    );
    assert_eq!(symbols[&ENTRY_B].name, "helper");

    let all = snapshot.all_xrefs().expect("all xrefs");
    assert_eq!(all.len(), 5);
    for (limit, offset) in WINDOWS {
        assert_eq!(
            snapshot.xrefs_page(limit, offset).expect("xrefs page"),
            page(&all, limit, offset),
            "xrefs_page({limit}, {offset})"
        );
    }

    let point = snapshot
        .xrefs_for_addresses(&[ENTRY_A, ENTRY_B])
        .expect("xrefs for addresses");
    assert_eq!(
        point,
        vec![x1.clone(), x3, x5.clone(), x2],
        "from-or-to matches sort by (from, to); the A->B row appears once"
    );
    assert!(
        snapshot
            .xrefs_for_addresses(&[UNKNOWN])
            .expect("xrefs for addresses")
            .is_empty()
    );

    assert_eq!(
        snapshot.call_xrefs(None).expect("call xrefs"),
        vec![x1, x5.clone()],
        "every call reference, ordered by source"
    );
    assert_eq!(
        snapshot
            .call_xrefs(Some(ENTRY_B))
            .expect("call xrefs by owner"),
        vec![x5],
        "owner restriction keeps only that function's calls"
    );
    assert!(
        snapshot
            .call_xrefs(Some(ENTRY_A))
            .expect("call xrefs by owner")
            .is_empty(),
        "x1 is image-owned, not owned by MAIN"
    );
}

// ---------------------------------------------------------------------------
// Function-name resolution queries
// ---------------------------------------------------------------------------

#[test]
fn name_and_symbol_lookup_queries() {
    let project = create_project();
    let mut db = project.open();
    let revision = revision_of(&db);

    db.apply(
        revision,
        &Edit::SetName {
            address: ENTRY_B,
            name: Some("helper_ref".into()),
        },
    )
    .expect("set name");

    let snapshot = db.snapshot().expect("snapshot");
    assert_eq!(
        snapshot
            .addresses_for_name("helper_ref")
            .expect("addresses for name"),
        vec![ENTRY_B]
    );
    assert!(
        snapshot
            .addresses_for_name("missing")
            .expect("addresses for name")
            .is_empty()
    );

    // The fixture has two symbols at MAIN ("main" and "main_alias").
    assert_eq!(
        snapshot
            .addresses_for_symbol("main")
            .expect("addresses for symbol"),
        vec![ENTRY_A]
    );
    assert_eq!(
        snapshot
            .addresses_for_symbol("main_alias")
            .expect("addresses for symbol"),
        vec![ENTRY_A]
    );
    assert!(
        snapshot
            .addresses_for_symbol("missing")
            .expect("addresses for symbol")
            .is_empty()
    );
}

// ---------------------------------------------------------------------------
// Unit dependency rows
// ---------------------------------------------------------------------------

#[test]
fn dependency_reader_returns_stored_rows_per_unit() {
    let project = create_project();
    let mut db = project.open();
    let revision = revision_of(&db);

    let dependency = signature_dependency(ENTRY_B, 7);
    let mut main_spec = CfgSpec::simple(main_function(), vec![sequential_instruction(ENTRY_A)]);
    main_spec.dependencies = vec![dependency.clone()];
    publish_units(
        &mut db,
        revision,
        vec![
            main_spec.into_unit(),
            CfgSpec::simple(helper_function(), vec![sequential_instruction(ENTRY_B)]).into_unit(),
        ],
    );

    let snapshot = db.snapshot().expect("snapshot");
    let requested = [
        UnitKey::function_cfg(ENTRY_A),
        UnitKey::function_cfg(ENTRY_B),
        UnitKey::image_index(),
    ];
    let dependencies = snapshot
        .dependencies_for_units(&requested)
        .expect("dependencies");
    assert_eq!(
        dependencies.len(),
        1,
        "only the unit that recorded a dependency has an entry"
    );
    assert_eq!(
        dependencies[&UnitKey::function_cfg(ENTRY_A)],
        vec![dependency],
        "the rebuild keeps kind, key, range and target generation"
    );
}

// ---------------------------------------------------------------------------
// Analysis scope persistence
// ---------------------------------------------------------------------------

#[test]
fn scope_round_trips_through_user_edit_undo_and_reopen() {
    let project = create_project();
    let expected = scope_of(&[
        (0x1000, 0x1008, Some(".text")),
        (0x1008, 0x1010, Some(".text_tail")),
    ]);

    {
        let mut db = project.open();
        {
            let snapshot = db.snapshot().expect("snapshot");
            assert_eq!(
                snapshot.scope().expect("scope"),
                AnalysisScope::empty(),
                "a project created without a policy reads as the empty scope"
            );
            let info = snapshot.info().expect("info");
            assert_eq!(info.analysis_scope, AnalysisScope::empty());
            assert_eq!(info.coverage, "full");
            assert_eq!(info.skipped_functions, 0);
            assert_eq!(info.function_count, 3);
        }

        let base = db.revision().expect("revision");
        let outcome = db
            .apply(
                base,
                &Edit::SetAnalysisScope {
                    scope: expected.clone(),
                },
            )
            .expect("apply scope");
        assert_eq!(outcome, EditOutcome::Applied(Revision(base.0 + 1)));

        let current = db.revision().expect("revision");
        {
            let snapshot = db.snapshot().expect("snapshot");
            assert_eq!(snapshot.scope().expect("scope"), expected);
            let info = snapshot.info().expect("info");
            assert_eq!(info.analysis_scope, expected);
            assert_eq!(info.coverage, "filtered");
            assert_eq!(
                info.skipped_functions, 1,
                "only the known MAIN row starts inside the excluded range"
            );
            assert_eq!(info.function_count, 3, "a scope never deletes user rows");
        }

        // A canonically equal policy is a no-op even when its label differs:
        // two adjacent ranges and one merged range describe the same bytes.
        let merged = scope_of(&[(0x1000, 0x1010, None)]);
        let second = db
            .apply(
                current,
                &Edit::SetAnalysisScope { scope: merged },
            )
            .expect("apply equal scope");
        assert_eq!(second, EditOutcome::Unchanged(current));
        assert_eq!(
            db.revision().expect("revision"),
            current,
            "an unchanged scope burns no revision"
        );
        assert_eq!(
            db.snapshot().expect("snapshot").scope().expect("scope"),
            expected,
            "the stored payload keeps the user's original ranges"
        );
    }

    // Close and reopen: the policy is durable.
    {
        let mut db = project.open();
        assert_eq!(db.snapshot().expect("snapshot").scope().expect("scope"), expected);
        assert_eq!(scope_resource_rows(&project), 1);
        let revision = db.revision().expect("revision");
        db.undo(revision).expect("undo scope");
        assert_eq!(
            db.snapshot().expect("snapshot").scope().expect("scope"),
            AnalysisScope::empty()
        );
        assert_eq!(
            scope_resource_rows(&project),
            0,
            "undo restores the exact 'no resource row' state"
        );
    }

    // The undo survives another reopen; redo reinstates the same policy.
    {
        let mut db = project.open();
        assert_eq!(
            db.snapshot().expect("snapshot").scope().expect("scope"),
            AnalysisScope::empty()
        );
        let revision = db.revision().expect("revision");
        db.redo(revision).expect("redo scope");
        assert_eq!(db.snapshot().expect("snapshot").scope().expect("scope"), expected);
        assert_eq!(scope_resource_rows(&project), 1);
    }
}

#[test]
fn initial_scope_is_stored_at_revision_zero() {
    let expected = scope_of(&[(0x1000, 0x1010, Some(".text"))]);
    let project = create_project_with_scope(expected.clone());
    {
        let mut db = project.open();
        assert_eq!(
            db.revision().expect("revision"),
            Revision(0),
            "a create-time policy is not a user edit"
        );
        assert_eq!(
            db.history_depth().expect("history depth"),
            (0, 0),
            "a create-time policy lands with an empty undo stack"
        );
    }
    let mut db = project.open();
    let snapshot = db.snapshot().expect("snapshot");
    assert_eq!(snapshot.scope().expect("scope"), expected);
    let info = snapshot.info().expect("info");
    assert_eq!(info.coverage, "filtered");
    assert_eq!(info.skipped_functions, 1);
}

#[test]
fn empty_create_writes_no_scope_resource() {
    let project = create_project();
    assert_eq!(
        scope_resource_rows(&project),
        0,
        "absence of the row is the empty scope"
    );
    let mut db = project.open();
    assert_eq!(
        db.snapshot().expect("snapshot").scope().expect("scope"),
        AnalysisScope::empty()
    );
}

#[test]
fn corrupt_scope_payload_is_corrupt_not_a_panic() {
    let project = create_project();
    {
        let conn = raw_connection(&project.db_path);
        let payload = b"not a scope";
        conn.execute(
            "INSERT INTO resources (image_id, kind, logical_name, content_sha256, payload)
             VALUES (1, 'analysis_scope', 'default', ?1, ?2)",
            rusqlite::params![&hexray_db::sha256(payload)[..], &payload[..]],
        )
        .expect("insert corrupt scope");
    }
    let mut db = project.open();
    let snapshot = db.snapshot().expect("snapshot");
    let error = snapshot.scope().expect_err("corrupt payload must fail");
    assert!(
        matches!(error, DbError::Corrupt(_)),
        "expected Corrupt, got {error:?}"
    );
}

// ---------------------------------------------------------------------------
// Edge rows are a set
// ---------------------------------------------------------------------------

#[test]
fn duplicate_cfg_edges_publish_idempotently() {
    let project = create_project();
    let mut db = project.open();
    let first = sequential_instruction(MAIN);
    let second_address = Address(first.address + first.size as u64);
    let second = sequential_instruction(second_address);
    let second_end = Address(second_address.0 + second.size as u64);
    let instructions = vec![first, second];
    let mut spec = CfgSpec::simple(main_function(), instructions);
    // A legal two-block CFG: `je +0` is a conditional branch whose taken and
    // fallthrough targets are both block 1, so the CFG legitimately holds the
    // same transfer twice. The store keys edges by (function, from, to, kind),
    // so the second row must collapse instead of failing the transaction.
    spec.blocks = vec![
        block(
            0,
            MAIN,
            second_address,
            BlockTerminator::ConditionalBranch {
                condition: Condition::Equal,
                true_target: BasicBlockId(1),
                false_target: BasicBlockId(1),
            },
        ),
        block(1, second_address, second_end, BlockTerminator::Return),
    ];
    spec.block_instructions = vec![(0, vec![MAIN]), (1, vec![second_address])];
    spec.edges = vec![(0, 1, EdgeKind::Normal), (0, 1, EdgeKind::Normal)];
    let generation = unit_generation(&mut db, &UnitKey::function_cfg(ENTRY_A));
    let revision = db.revision().expect("revision");
    publish_units(&mut db, revision, vec![spec.into_unit()]);
    assert_eq!(
        unit_generation(&mut db, &UnitKey::function_cfg(ENTRY_A)),
        Some(generation.unwrap_or(0) + 1),
        "the publish must have committed"
    );
    let cfgs = db
        .snapshot()
        .expect("snapshot")
        .cfgs_for_functions(&[ENTRY_A])
        .expect("cfgs");
    let cfg = &cfgs[&ENTRY_A];
    assert_eq!(
        cfg.blocks.len(),
        2,
        "both blocks of the legal CFG are stored"
    );
    assert_eq!(
        cfg.blocks[0].terminator,
        BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId(1),
            false_target: BasicBlockId(1),
        },
        "block 0 must keep the je +0 shape"
    );
    assert_eq!(
        cfg.edges,
        vec![(0, 1, EdgeKind::Normal)],
        "the duplicate transfer collapses into one stored row"
    );
}
