//! Storage-level properties of `.hxdb`: address encoding, round trips,
//! corruption/version rejection, backups and legacy import.
//!
//! Every assertion names the property it protects so a failure points at the
//! contract rather than at an anonymous value mismatch.

mod common;

use common::*;
use hexray_core::{BasicBlockId, BlockTerminator};
use hexray_db::address::{Address, AddressRange, FileOffset, FileRange, RangeError};
use hexray_db::legacy::{read_legacy_source, IdentityStatus, LegacyKind};
use hexray_db::model::*;
use hexray_db::{DbError, Edit, OpenMode};
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// 1. Addresses above the SQLite INTEGER range
// ---------------------------------------------------------------------------

#[test]
fn high_addresses_round_trip_in_numeric_order() {
    let project = create_project();
    let mut db = project.open();
    let expected: Vec<u64> = {
        let mut values = HIGH_ADDRESSES.to_vec();
        values.sort_unstable();
        values
    };

    // Symbols cover every boundary value (including 2^53+1, i64::MAX+1).
    let symbols = db.symbols().expect("symbols");
    let high: Vec<&SymbolInfo> = symbols
        .iter()
        .filter(|symbol| symbol.name.starts_with("addr_"))
        .collect();
    assert_eq!(
        high.len(),
        HIGH_ADDRESSES.len(),
        "every boundary address has a symbol row"
    );
    let addresses: Vec<u64> = high.iter().map(|symbol| symbol.address.0).collect();
    assert_eq!(
        addresses, expected,
        "symbol query order must match numeric order across i64::MAX"
    );

    // File offsets use the same BLOB encoding and may exceed i64::MAX even
    // though the fixture source is tiny (mappings are not validated against
    // the source at creation time).
    let mappings = db.image().expect("image").mappings;
    let high_mappings: Vec<&MappingInfo> = mappings
        .iter()
        .filter(|mapping| mapping.name.starts_with("high_"))
        .collect();
    assert_eq!(high_mappings.len(), HIGH_ADDRESSES.len());
    for (mapping, value) in high_mappings.iter().zip(expected.iter()) {
        assert_eq!(mapping.va.0, *value, "mapping VA decodes exactly");
        assert_eq!(
            mapping.file_offset.expect("file offset").0,
            *value,
            "FileOffset {value:#x} must survive the 8-byte BLOB encoding"
        );
    }

    // The same ordering guarantee applies to `FileOffset` columns, checked
    // through SQL (no public query orders by file offset).
    {
        let connection = raw_connection(&project.db_path);
        let mut statement = connection
            .prepare(
                "SELECT file_offset FROM mappings
                 WHERE name LIKE 'high_%' ORDER BY file_offset",
            )
            .expect("prepare file offset query");
        let decoded: Vec<u64> = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .expect("query")
            .map(|blob| {
                FileOffset::from_blob(&blob.expect("blob"))
                    .expect("decode")
                    .0
            })
            .collect();
        assert_eq!(
            decoded, expected,
            "ORDER BY on the FileOffset BLOB must sort numerically"
        );
    }

    // Direct codec boundary checks, including the value one past i64::MAX.
    for value in HIGH_ADDRESSES {
        assert_eq!(
            Address::from_blob(&Address(value).to_blob()).expect("address blob"),
            Address(value)
        );
        assert_eq!(
            FileOffset::from_blob(&FileOffset(value).to_blob()).expect("offset blob"),
            FileOffset(value)
        );
    }
    assert_eq!(
        Address::from_blob(&[0u8; 7]),
        Err(RangeError::BadBlobLength(7)),
        "a wrong-width address blob is rejected"
    );

    // Invalid end ranges are refused rather than wrapping.
    assert_eq!(
        Address(u64::MAX).range(1),
        Err(RangeError::Overflow {
            start: u64::MAX,
            len: 1
        })
    );
    assert_eq!(
        FileRange::new(FileOffset(u64::MAX), 1),
        Err(RangeError::Overflow {
            start: u64::MAX,
            len: 1
        })
    );
    assert_eq!(
        AddressRange::new(Address(0), 0),
        Err(RangeError::EmptyRange)
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// BLOB order (bytewise big-endian) must equal numeric order for every
    /// u64, not only for the boundary samples above.
    #[test]
    fn address_blob_sort_matches_numeric_sort(values in prop::collection::vec(any::<u64>(), 1..48)) {
        let mut numeric = values.clone();
        numeric.sort_unstable();

        let mut blobs: Vec<[u8; 8]> = values.iter().map(|value| Address(*value).to_blob()).collect();
        blobs.sort_unstable();
        let decoded: Vec<u64> = blobs
            .iter()
            .map(|blob| Address::from_blob(blob).expect("decode").0)
            .collect();
        prop_assert_eq!(decoded, numeric.clone());

        let mut file_blobs: Vec<[u8; 8]> =
            values.iter().map(|value| FileOffset(*value).to_blob()).collect();
        file_blobs.sort_unstable();
        let decoded_files: Vec<u64> = file_blobs
            .iter()
            .map(|blob| FileOffset::from_blob(blob).expect("decode").0)
            .collect();
        prop_assert_eq!(decoded_files, numeric.clone());
    }

    /// Witness strategy: drive the generator across the i64::MAX seam so the
    /// high-address property is not vacuously satisfied by small values.
    #[test]
    fn address_blob_roundtrip_crosses_i64_boundary(
        value in prop_oneof![
            Just(0u64),
            Just((1u64 << 53) + 1),
            Just(i64::MAX as u64),
            Just(i64::MAX as u64 + 1),
            Just(u64::MAX),
            any::<u64>(),
        ]
    ) {
        let blob = Address(value).to_blob();
        prop_assert_eq!(Address::from_blob(&blob).expect("decode"), Address(value));
        prop_assert_eq!(&blob[..], &value.to_be_bytes()[..]);
        if value > i64::MAX as u64 {
            prop_assert!(value.ilog2() >= 63);
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Storage round trips
// ---------------------------------------------------------------------------

#[test]
fn instruction_semantic_fields_round_trip() {
    let project = create_project();
    let mut db = project.open();
    let revision = revision_of(&db);
    let instructions = vec![rich_instruction(), sequential_instruction(Address(0x1005))];
    let expected = instructions.clone();
    publish_units(
        &mut db,
        revision,
        vec![CfgSpec::simple(main_function(), instructions).into_unit()],
    );

    let read_back = db.instructions(MAIN).expect("instructions");
    assert_eq!(read_back.len(), 2, "both instructions are stored");
    assert_instruction_eq(&read_back[0], &expected[0]);
    assert_instruction_eq(&read_back[1], &expected[1]);

    let blocks = db.cfg(MAIN).expect("cfg");
    assert_eq!(blocks.blocks.len(), 1, "one serialized block");
    assert_eq!(blocks.blocks[0].terminator, BlockTerminator::Return);
    assert_eq!(
        blocks.block_instructions(0),
        &[MAIN, Address(0x1005)],
        "block membership keeps the ordered instruction addresses"
    );
}

#[test]
fn cfg_normal_and_unwind_edges_stay_distinct() {
    let project = create_project();
    let mut db = project.open();
    let revision = revision_of(&db);

    let mut spec = CfgSpec::new(main_function());
    spec.instructions = vec![
        sequential_instruction(MAIN),
        sequential_instruction(Address(0x1004)),
        sequential_instruction(Address(0x1008)),
    ];
    spec.blocks = vec![
        block(
            0,
            MAIN,
            Address(0x1004),
            BlockTerminator::Jump {
                target: BasicBlockId(1),
            },
        ),
        block(1, Address(0x1004), Address(0x1008), BlockTerminator::Return),
        block(2, Address(0x1008), Address(0x100c), BlockTerminator::Return),
    ];
    spec.block_instructions = vec![
        (0, vec![MAIN]),
        (1, vec![Address(0x1004)]),
        (2, vec![Address(0x1008)]),
    ];
    spec.edges = vec![
        (0, 1, EdgeKind::Normal),
        (1, 2, EdgeKind::Unwind),
        (2, 1, EdgeKind::Normal),
    ];
    publish_units(&mut db, revision, vec![spec.into_unit()]);

    let cfg = db.cfg(MAIN).expect("cfg");
    assert_eq!(
        cfg.edges,
        vec![
            (0, 1, EdgeKind::Normal),
            (1, 2, EdgeKind::Unwind),
            (2, 1, EdgeKind::Normal),
        ],
        "normal and unwind edges must not be collapsed"
    );
    let unwind: Vec<_> = cfg
        .edges
        .iter()
        .filter(|(_, _, kind)| *kind == EdgeKind::Unwind)
        .collect();
    assert_eq!(unwind, vec![&(1, 2, EdgeKind::Unwind)]);
}

#[test]
fn symbol_aliases_at_one_address_survive_index_publication() {
    let project = create_project();
    let mut db = project.open();
    let revision = revision_of(&db);
    publish_units(&mut db, revision, vec![default_index_unit(Some(0))]);

    let aliases: Vec<String> = db
        .symbols()
        .expect("symbols")
        .into_iter()
        .filter(|symbol| symbol.address == MAIN)
        .map(|symbol| symbol.name)
        .collect();
    assert_eq!(
        aliases,
        vec!["main".to_string(), "main_alias".to_string()],
        "publishing the index keeps every alias at one address, ordered by name"
    );
}

#[test]
fn image_abi_llp64_round_trips() {
    let project = create_project_with_abi(AbiInfo::llp64());
    let mut db = project.open();
    let image = db.image().expect("image");
    assert_eq!(image.abi, AbiInfo::llp64(), "PE64 must stay LLP64");
    assert_eq!(image.abi.pointer_size, 8);
    assert_eq!(
        image.abi.long_size, 4,
        "long size is stored separately from pointer size"
    );
    assert_ne!(image.abi, AbiInfo::lp64());
    assert_eq!(image.bitness, 64);
    assert_eq!(image.endianness, "little");
    assert_eq!(image.entry_address, Some(MAIN));
    // The same ABI reaches the type sizing model.
    assert_eq!(image.abi.to_arch_info().long_size, 4);
}

#[test]
fn unicode_annotations_round_trip() {
    let project = create_project();
    let mut db = project.open();
    let revision = revision_of(&db);
    let text = "入口 — комментарий 🚀 \u{1F600}";
    db.apply(
        revision,
        &Edit::SetComment {
            address: MAIN,
            text: Some(text.to_string()),
        },
    )
    .expect("set comment");
    db.apply(
        revision_of(&db),
        &Edit::SetTag {
            address: MAIN,
            text: Some("важно".to_string()),
        },
    )
    .expect("set tag");

    let annotations = db.annotations().expect("annotations");
    assert!(
        annotations
            .iter()
            .any(|(address, kind, value)| *address == MAIN
                && *kind == AnnotationKind::Comment
                && value == text),
        "Unicode comment must return byte-identical, got {annotations:?}"
    );
    assert!(annotations
        .iter()
        .any(|(address, kind, value)| *address == MAIN
            && *kind == AnnotationKind::Tag
            && value == "важно"));
}

#[test]
fn array_type_override_survives_in_types_table() {
    use hexray_types::CType;

    let project = create_project();
    let mut db = project.open();
    let array = CType::array(CType::int(), Some(4));
    let payload = serde_json::to_string(&array).expect("serialize type");

    db.apply(
        revision_of(&db),
        &Edit::PutType {
            name: "vec4".into(),
            kind: TypeKind::Typedef,
            payload_json: payload.clone(),
        },
    )
    .expect("put type");
    db.apply(
        revision_of(&db),
        &Edit::ApplyType {
            address: STRING_ADDRESS,
            type_name: Some("vec4".into()),
            length: Some(16),
        },
    )
    .expect("apply type");

    let stored = db
        .types()
        .expect("types")
        .into_iter()
        .find(|row| row.name == "vec4")
        .expect("vec4 row");
    let decoded: CType = serde_json::from_str(&stored.payload_json).expect("decode type");
    assert_eq!(
        decoded, array,
        "array element type and length are preserved"
    );
    assert_eq!(decoded.size(), Some(16), "array size is 4 * sizeof(int)");

    let item = db
        .items()
        .expect("items")
        .into_iter()
        .find(|item| item.address == STRING_ADDRESS)
        .expect("typed item");
    assert_eq!(item.length, 16);
    assert_eq!(item.type_name.as_deref(), Some("vec4"));
}

// ---------------------------------------------------------------------------
// 3. Corruption and version rejection
// ---------------------------------------------------------------------------

fn copy_database(project: &Project, name: &str) -> std::path::PathBuf {
    let target = project.dir.path().join(name);
    std::fs::copy(&project.db_path, &target).expect("copy database");
    target
}

#[test]
fn random_bytes_are_not_a_database() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("random.hxdb");
    let bytes: Vec<u8> = (0..4096u32)
        .map(|value| (value.wrapping_mul(37) % 251) as u8)
        .collect();
    std::fs::write(&path, &bytes).expect("write random file");

    let error = hexray_db::Database::open(&path, OpenMode::ReadOnly)
        .expect_err("random bytes must not open");
    assert!(
        matches!(error, DbError::NotADatabase),
        "expected NotADatabase, got {error:?}"
    );
    assert_eq!(
        std::fs::read(&path).expect("re-read"),
        bytes,
        "a failed open must not rewrite the input"
    );
}

#[test]
fn truncated_sqlite_is_rejected() {
    let project = create_project();
    let path = copy_database(&project, "truncated.hxdb");
    let bytes = std::fs::read(&path).expect("read db");
    // The header is 100 bytes and a page is 4096 bytes, so keeping only 128
    // bytes guarantees no complete page (in particular no `sqlite_schema`
    // page) remains. Truncating to a fraction of the file would depend on how
    // much of the schema happens to sit in the retained pages.
    assert!(
        bytes.len() > 4096,
        "fixture database is larger than one page"
    );
    let truncated = &bytes[..128];
    std::fs::write(&path, truncated).expect("truncate");

    let error = hexray_db::Database::open(&path, OpenMode::ReadWrite)
        .expect_err("truncated database must not open");
    assert!(
        matches!(
            error,
            DbError::Corrupt(_) | DbError::NotADatabase | DbError::Sqlite(_)
        ),
        "truncated file must fail structurally, got {error:?}"
    );
    assert_eq!(
        std::fs::read(&path).expect("re-read"),
        truncated,
        "open must leave the truncated file untouched"
    );
}

#[test]
fn wrong_application_id_is_rejected() {
    let project = create_project();
    let path = copy_database(&project, "foreign.hxdb");
    {
        let connection = raw_connection(&path);
        connection
            .pragma_update(None, "application_id", 0x1234_i64)
            .expect("rewrite application id");
    }
    let error = hexray_db::Database::open(&path, OpenMode::ReadOnly)
        .expect_err("foreign application id must be rejected");
    assert!(
        matches!(error, DbError::NotADatabase),
        "expected NotADatabase, got {error:?}"
    );
}

#[test]
fn future_schema_version_is_rejected() {
    let project = create_project();
    let path = copy_database(&project, "future.hxdb");
    {
        let connection = raw_connection(&path);
        connection
            .pragma_update(None, "user_version", 2_i64)
            .expect("bump user version");
    }
    let error = hexray_db::Database::open(&path, OpenMode::ReadOnly)
        .expect_err("future schema must be rejected");
    match error {
        DbError::UnsupportedSchema(version) => assert_eq!(version, "2"),
        other => panic!("expected UnsupportedSchema(\"2\"), got {other:?}"),
    }
}

#[test]
fn unexpected_schema_objects_are_rejected() {
    let project = create_project();
    let path = copy_database(&project, "triggered.hxdb");
    {
        let connection = raw_connection(&path);
        connection
            .execute_batch("CREATE TRIGGER sneaky AFTER INSERT ON names BEGIN SELECT 1; END;")
            .expect("create trigger");
    }
    let error = hexray_db::Database::open(&path, OpenMode::ReadOnly)
        .expect_err("trigger must be rejected before any write");
    match error {
        DbError::Corrupt(message) => {
            assert!(message.contains("trigger"), "unexpected message: {message}")
        }
        other => panic!("expected Corrupt for an unexpected trigger, got {other:?}"),
    }
}

#[test]
fn invalid_block_payload_fails_explicitly() {
    let project = create_project();
    let mut db = project.open();
    let revision = revision_of(&db);
    publish_units(
        &mut db,
        revision,
        vec![CfgSpec::simple(main_function(), vec![sequential_instruction(MAIN)]).into_unit()],
    );
    drop(db);

    {
        let connection = raw_connection(&project.db_path);
        connection
            .execute(
                "UPDATE basic_blocks SET payload_json = '{\"not\": a block' WHERE image_id = 1",
                [],
            )
            .expect("corrupt block payload");
    }

    let mut db = project.open();
    let error = db.cfg(MAIN).expect_err("corrupt block must not parse");
    assert!(
        matches!(error, DbError::Corrupt(_)),
        "expected Corrupt, got {error:?}"
    );
}

#[test]
fn invalid_instruction_payload_fails_explicitly() {
    let project = create_project();
    let mut db = project.open();
    let revision = revision_of(&db);
    publish_units(
        &mut db,
        revision,
        vec![CfgSpec::simple(main_function(), vec![sequential_instruction(MAIN)]).into_unit()],
    );
    drop(db);

    {
        let connection = raw_connection(&project.db_path);
        let changed = connection
            .execute(
                "UPDATE instructions SET payload_json = 'not json' WHERE image_id = 1",
                [],
            )
            .expect("corrupt instruction payload");
        assert_eq!(changed, 1, "one instruction row was corrupted");
    }

    let mut db = project.open();
    let error = db
        .instructions(MAIN)
        .expect_err("corrupt instruction payload must be reported, not skipped");
    assert!(
        matches!(error, DbError::Corrupt(_)),
        "expected Corrupt, got {error:?}"
    );
}

#[test]
fn broken_foreign_keys_are_reported_by_check() {
    let project = create_project();
    let mut db = project.open();
    let revision = revision_of(&db);
    publish_units(
        &mut db,
        revision,
        vec![CfgSpec::simple(main_function(), vec![sequential_instruction(MAIN)]).into_unit()],
    );
    drop(db);

    {
        let connection = raw_connection(&project.db_path);
        connection
            .pragma_update(None, "foreign_keys", "OFF")
            .expect("disable fk for the tampering connection");
        // reference a function row that does not exist
        connection
            .execute(
                "INSERT INTO function_instructions
                    (image_id, function_address, instruction_address, ordinal)
                 VALUES (1, X'000000000000DEAD', X'0000000000001000', 0)",
                [],
            )
            .expect("insert dangling row");
    }

    let db = project.open();
    let report = db.check(false).expect("check");
    assert!(
        !report.foreign_key_violations.is_empty(),
        "foreign_key_check must see the dangling row"
    );
    assert!(
        report
            .foreign_key_violations
            .iter()
            .any(|violation| violation.contains("function_instructions")),
        "violation names the table, got {:?}",
        report.foreign_key_violations
    );
    assert!(!report.passed(), "a broken FK must fail the report");
}

#[test]
fn read_only_open_rejects_writes_without_touching_metadata() {
    let project = create_project();
    let before = std::fs::read(&project.db_path).expect("read db");
    let revision_before = project.revision();
    let events_before = {
        let mut db = project.open();
        db.history_events(100, 0).expect("events").len()
    };

    let mut db = project.open_read_only();
    // Reads are allowed.
    let info = db.info().expect("info");
    assert_eq!(info.revision, revision_before);
    assert_eq!(db.functions().expect("functions").len(), 3);
    {
        let snapshot = db.snapshot().expect("snapshot");
        assert_eq!(snapshot.data_revision(), revision_before);
        assert_eq!(
            snapshot.overall_state().expect("state"),
            OverallState::Partial
        );
        assert!(snapshot.all_xrefs().expect("xrefs").is_empty());
    }

    // Writes are refused with a stable error class.
    let expected = revision_before;
    let errors = [
        db.apply(
            expected,
            &Edit::SetName {
                address: MAIN,
                name: Some("nope".into()),
            },
        )
        .expect_err("apply must fail"),
        db.undo(expected).expect_err("undo must fail"),
        db.redo(expected).expect_err("redo must fail"),
        db.record_command("cli", "info", "", true)
            .expect_err("record_command must fail"),
        db.publish(expected, &AnalysisBatch::default())
            .expect_err("publish must fail"),
    ];
    for error in errors {
        assert!(
            matches!(error, DbError::Unsupported(_)),
            "read-only write must return Unsupported, got {error:?}"
        );
    }

    drop(db);
    assert_eq!(
        std::fs::read(&project.db_path).expect("re-read db"),
        before,
        "read-only access must not modify a byte of the project"
    );
    let mut reopened = project.open();
    assert_eq!(reopened.revision().expect("revision"), revision_before);
    assert_eq!(
        reopened
            .snapshot()
            .expect("snapshot")
            .history_events(100, 0)
            .expect("events")
            .len(),
        events_before,
        "no audit rows appear on the read-only path"
    );
    assert!(reopened.names().expect("names").is_empty());
}

// ---------------------------------------------------------------------------
// 4. Backup
// ---------------------------------------------------------------------------

#[test]
fn backup_from_a_second_connection_opens_independently() {
    let project = create_project();
    let mut writer = project.open();
    let revision = revision_of(&writer);
    writer
        .apply(
            revision,
            &Edit::SetComment {
                address: MAIN,
                text: Some("backed up".into()),
            },
        )
        .expect("commit edit");
    let expected_revision = writer.revision().expect("revision");
    assert_eq!(expected_revision, Revision(revision.0 + 1));

    let reader = project.open();
    let target = project.dir.path().join("backup.hxdb");
    reader.backup(&target).expect("backup");
    assert!(target.exists());

    // The backup is a standalone project: open it with no source file around.
    let mut backup = hexray_db::Database::open(&target, OpenMode::ReadOnly).expect("open backup");
    assert_eq!(backup.revision().expect("revision"), expected_revision);
    assert_eq!(
        backup
            .annotations()
            .expect("annotations")
            .into_iter()
            .find(|(address, kind, _)| *address == MAIN && *kind == AnnotationKind::Comment)
            .map(|(_, _, value)| value),
        Some("backed up".to_string())
    );
    let report = backup.check(true).expect("deep check");
    assert!(report.passed(), "backup deep check failed: {report:?}");

    // Existing targets are never overwritten.
    let sentinel = b"do not touch".to_vec();
    std::fs::write(&target, &sentinel).expect("write sentinel");
    let error = reader.backup(&target).expect_err("second backup must fail");
    assert!(
        matches!(error, DbError::Validation(_)),
        "expected Validation for an existing destination, got {error:?}"
    );
    assert_eq!(
        std::fs::read(&target).expect("sentinel"),
        sentinel,
        "a refused backup leaves the existing file intact"
    );
}

// ---------------------------------------------------------------------------
// 5. Legacy import
// ---------------------------------------------------------------------------

fn write_legacy_project(path: &std::path::Path, hash_hex: &str) -> serde_json::Value {
    let document = serde_json::json!({
        "version": 2,
        "binary_path": "old/input.bin",
        "binary_hash": hash_hex,
        "annotations": {
            "4096": [
                { "kind": "comment", "value": "legacy comment" },
                { "kind": "label", "value": "legacy_label" },
                { "kind": "variable_name", "value": "unbound" },
            ],
            "not-an-address": [ { "kind": "comment", "value": "lost" } ],
        },
        "function_overrides": {
            "4096": {
                "name": "old_main",
                "signature": {
                    "return_type": "int",
                    "parameters": [["a", "int"]],
                    "variadic": false,
                },
                "calling_convention": "SystemV",
                "notes": "legacy note",
            },
            "0xzz": { "name": "nowhere" },
        },
        "type_overrides": {
            "4352": {
                "type_name": "int",
                "is_array": true,
                "array_length": 4,
                "size": 16,
            },
            "4353": { "type_name": "int int", "size": null },
            "bad": { "type_name": "int" },
        },
        "bookmarks": [
            { "address": 4096, "label": "entry", "category": "user" },
            { "address": "not-a-number" },
        ],
    });
    std::fs::write(path, serde_json::to_vec(&document).expect("json")).expect("write project");
    document
}

#[test]
fn malformed_legacy_hashes_are_errors_not_panics() {
    let dir = tempfile::tempdir().expect("temp dir");
    let source = b"hexray source".to_vec();
    let source_sha = hexray_db::sha256(&source);

    for (name, hash) in [
        ("odd.json", "abc"),
        ("unicode.json", "éé"),
        ("hex.json", "zz"),
    ] {
        let path = dir.path().join(name);
        write_legacy_project(&path, hash);
        let error = read_legacy_source(&path, &source_sha, &source, false)
            .expect_err("malformed hash must be rejected");
        assert!(
            matches!(error, DbError::Validation(_)),
            "{name}: expected Validation, got {error:?}"
        );
    }
}

#[test]
fn project_identity_states_are_reported_and_enforced() {
    let dir = tempfile::tempdir().expect("temp dir");
    let source = b"legacy source bytes".to_vec();
    let source_sha = hexray_db::sha256(&source);

    let matching = dir.path().join("matching.json");
    let weak = hexray_db::legacy::legacy_weak_digest(&source);
    write_legacy_project(&matching, &hexray_db::hex_encode(&weak));
    let source_result =
        read_legacy_source(&matching, &source_sha, &source, false).expect("weak match");
    assert_eq!(source_result.kind, LegacyKind::ProjectJson);
    assert_eq!(source_result.identity_status, IdentityStatus::WeakVerified);

    let mismatching = dir.path().join("mismatching.json");
    let other = hexray_db::sha256(b"a different binary");
    write_legacy_project(&mismatching, &hexray_db::hex_encode(&other));
    let error = read_legacy_source(&mismatching, &source_sha, &source, false)
        .expect_err("weak mismatch must be refused by default");
    assert!(
        matches!(error, DbError::IdentityMismatch(_)),
        "expected IdentityMismatch, got {error:?}"
    );
    let accepted =
        read_legacy_source(&mismatching, &source_sha, &source, true).expect("explicit acceptance");
    assert_eq!(accepted.identity_status, IdentityStatus::Unverified);
    assert_eq!(
        accepted.stored_identity,
        hexray_db::hex_encode(&other),
        "the unverified legacy value is preserved for the audit trail"
    );
}

#[test]
fn project_import_applies_actions_and_preserves_the_source_file() {
    let project = create_project();
    let legacy_path = project.dir.path().join("old_project.json");
    let weak = hexray_db::legacy::legacy_weak_digest(&project.source_bytes);
    write_legacy_project(&legacy_path, &hexray_db::hex_encode(&weak));

    let source_bytes = std::fs::read(&project.source_path).expect("source bytes");
    let source_meta = std::fs::metadata(&project.source_path)
        .expect("source metadata")
        .modified()
        .expect("mtime");
    let source_sha = hexray_db::sha256(&source_bytes);

    let legacy = read_legacy_source(&legacy_path, &source_sha, &source_bytes, false)
        .expect("read legacy project");
    assert_eq!(legacy.identity_status, IdentityStatus::WeakVerified);
    let records = legacy.records.len();
    let unresolved_records = legacy.unresolved.len();
    let actions = legacy.actions.len();
    assert!(
        records > 0 && unresolved_records > 0,
        "fixture exercises both"
    );

    let mut db = project.open();
    let summary = db.import_legacy(&legacy).expect("import");
    assert_eq!(summary.imported_records, records);
    assert_eq!(
        summary.applied + summary.unresolved,
        actions + unresolved_records,
        "every converted action is counted once"
    );
    let by_kind_applied: usize = summary.by_kind.iter().map(|row| row.applied).sum();
    let by_kind_unresolved: usize = summary.by_kind.iter().map(|row| row.unresolved).sum();
    assert_eq!(by_kind_applied, summary.applied);
    assert_eq!(by_kind_unresolved, summary.unresolved);

    // Every payload, including unresolved ones, reaches the audit table.
    {
        let connection = raw_connection(&project.db_path);
        let stored: i64 = connection
            .query_row("SELECT COUNT(*) FROM legacy_records", [], |row| row.get(0))
            .expect("count records");
        assert_eq!(
            stored as usize,
            records + unresolved_records,
            "legacy_records must hold records plus unresolved records"
        );
        let imports: i64 = connection
            .query_row("SELECT COUNT(*) FROM legacy_imports", [], |row| row.get(0))
            .expect("count imports");
        assert_eq!(imports, 1);
        let (status, digest): (String, Vec<u8>) = connection
            .query_row(
                "SELECT identity_status, sha256 FROM legacy_imports",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("import row");
        assert_eq!(status, "weak_verified");
        assert_eq!(
            digest,
            hexray_db::sha256(&std::fs::read(&legacy_path).expect("legacy bytes")).to_vec(),
            "the imported file digest is recorded"
        );
    }

    // Applied user state is live.
    assert_eq!(
        db.name_at(MAIN).expect("name"),
        Some("old_main".to_string()),
        "the function override name wins over the earlier label action"
    );
    let annotations = db.annotations().expect("annotations");
    assert!(annotations
        .iter()
        .any(|(address, kind, value)| *address == MAIN
            && *kind == AnnotationKind::Comment
            && value == "legacy note"));
    let overrides = db.function_overrides().expect("overrides");
    let (_, override_row) = overrides
        .iter()
        .find(|(address, _)| *address == MAIN)
        .expect("function override row");
    assert_eq!(
        override_row.signature.as_deref(),
        Some("int old_main(int a)"),
        "the legacy signature was rendered and stored"
    );
    assert_eq!(override_row.calling_convention.as_deref(), Some("SystemV"));
    let types = db.types().expect("types");
    let legacy_type = types
        .iter()
        .find(|row| row.name == "int" && row.origin == "legacy")
        .expect("array type row");
    let decoded: hexray_types::CType =
        serde_json::from_str(&legacy_type.payload_json).expect("decode legacy type");
    assert_eq!(decoded.size(), Some(16), "array length survives");
    let item = db
        .items()
        .expect("items")
        .into_iter()
        .find(|item| item.address == Address(0x1100))
        .expect("legacy data item");
    assert_eq!((item.length, item.origin.as_str()), (16, "legacy"));
    assert_eq!(item.type_name.as_deref(), Some("int"));
    assert!(db
        .bookmarks()
        .expect("bookmarks")
        .iter()
        .any(|(address, label)| *address == MAIN && label.as_deref() == Some("entry")));
    // Legacy undo/history are audit only: the new project starts empty.
    assert_eq!(db.history_depth().expect("history depth"), (0, 0));

    // The analyzed source file is never touched by reading or importing.
    assert_eq!(
        std::fs::read(&project.source_path).expect("re-read source"),
        source_bytes
    );
    assert_eq!(
        std::fs::metadata(&project.source_path)
            .expect("metadata")
            .modified()
            .expect("mtime"),
        source_meta,
        "import must not modify the source mtime"
    );
}

fn write_legacy_session(path: &std::path::Path, hash_hex: &str, meta_rows: usize) {
    let connection = rusqlite::Connection::open(path).expect("session db");
    connection
        .execute_batch(
            "CREATE TABLE session_meta (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                binary_path TEXT NOT NULL,
                binary_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_accessed TEXT NOT NULL
            );
            CREATE TABLE history (
                idx INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                command TEXT NOT NULL,
                output TEXT NOT NULL,
                duration_ms INTEGER NOT NULL,
                success INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE annotations (
                address INTEGER NOT NULL,
                kind TEXT NOT NULL,
                value TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (address, kind)
            );
            CREATE TABLE undo_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                description TEXT NOT NULL,
                action_type TEXT NOT NULL,
                action_data TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                undone INTEGER NOT NULL DEFAULT 0
            );",
        )
        .expect("session schema");

    for index in 0..meta_rows {
        connection
            .execute(
                "INSERT INTO session_meta
                    (id, name, binary_path, binary_hash, created_at, last_accessed)
                 VALUES (?1, 'old', '/old/input', ?2, '2024-01-01', '2024-01-01')",
                rusqlite::params![format!("session-{index}"), hash_hex],
            )
            .expect("session meta");
    }
    for (address, kind, value) in [
        (0x1000_i64, "rename", "session_main"),
        (0x1000, "comment", "session comment"),
        (0x1000, "tag", "session tag"),
        (0x1000, "bookmark", "session bookmark"),
        (0x1010, "variable", "cannot rebind"),
    ] {
        connection
            .execute(
                "INSERT INTO annotations (address, kind, value, created_at)
                 VALUES (?1, ?2, ?3, '2024-01-01')",
                rusqlite::params![address, kind, value],
            )
            .expect("annotation");
    }
    connection
        .execute(
            "INSERT INTO history (timestamp, command, output, duration_ms, success)
             VALUES ('2024-01-01', 'disasm', 'mov eax, 1', 3, 1)",
            [],
        )
        .expect("history");
    connection
        .execute(
            "INSERT INTO undo_history (description, action_type, action_data, timestamp, undone)
             VALUES ('rename', 'Rename', '{\"old\":\"x\"}', '2024-01-01', 0)",
            [],
        )
        .expect("undo history");
}

#[test]
fn sqlite_session_identity_rules_are_strict() {
    let project = create_project();
    let source_sha = hexray_db::sha256(&project.source_bytes);
    let good_hash = hexray_db::hex_encode(&source_sha);

    let valid = project.dir.path().join("valid.session");
    write_legacy_session(&valid, &good_hash, 1);
    let legacy = read_legacy_source(&valid, &source_sha, &project.source_bytes, false)
        .expect("valid session");
    assert_eq!(legacy.kind, LegacyKind::SessionSqlite);
    assert_eq!(legacy.identity_status, IdentityStatus::Verified);

    let missing = project.dir.path().join("missing.session");
    write_legacy_session(&missing, &good_hash, 0);
    let error = read_legacy_source(&missing, &source_sha, &project.source_bytes, false)
        .expect_err("zero meta rows must be rejected");
    assert!(
        matches!(error, DbError::Ambiguous(_)),
        "expected Ambiguous, got {error:?}"
    );

    let ambiguous = project.dir.path().join("ambiguous.session");
    write_legacy_session(&ambiguous, &good_hash, 2);
    let error = read_legacy_source(&ambiguous, &source_sha, &project.source_bytes, false)
        .expect_err("two meta rows must be rejected, never picked with LIMIT 1");
    assert!(
        matches!(error, DbError::Ambiguous(_)),
        "expected Ambiguous, got {error:?}"
    );

    let mismatched = project.dir.path().join("mismatched.session");
    let other_hash = hexray_db::hex_encode(&hexray_db::sha256(b"another binary"));
    write_legacy_session(&mismatched, &other_hash, 1);
    let error = read_legacy_source(&mismatched, &source_sha, &project.source_bytes, false)
        .expect_err("SHA-256 mismatch must always be refused");
    assert!(
        matches!(error, DbError::IdentityMismatch(_)),
        "expected IdentityMismatch, got {error:?}"
    );
    // The escape hatch only exists for weakly hashed JSON projects.
    let error = read_legacy_source(&mismatched, &source_sha, &project.source_bytes, true)
        .expect_err("--accept-unverified is not applicable to sessions");
    match error {
        DbError::Validation(message) => assert!(
            message.contains("does not apply"),
            "unexpected message: {message}"
        ),
        other => panic!("expected Validation, got {other:?}"),
    }

    let malformed = project.dir.path().join("malformed.session");
    write_legacy_session(&malformed, "abc", 1);
    let error = read_legacy_source(&malformed, &source_sha, &project.source_bytes, false)
        .expect_err("odd-length session hash must be an error");
    assert!(
        matches!(error, DbError::Validation(_)),
        "expected Validation, got {error:?}"
    );
}

#[test]
fn session_import_keeps_history_as_audit_only() {
    let project = create_project();
    let source_sha = hexray_db::sha256(&project.source_bytes);
    let path = project
        .dir
        .path()
        .join("session_with_trailing_json_extension.json");
    write_legacy_session(&path, &hexray_db::hex_encode(&source_sha), 1);
    let source_bytes = std::fs::read(&project.source_path).expect("source");
    let source_meta = std::fs::metadata(&project.source_path)
        .expect("metadata")
        .modified()
        .expect("mtime");

    let legacy = read_legacy_source(&path, &source_sha, &source_bytes, false)
        .expect("classification is by content, not extension");
    assert_eq!(legacy.kind, LegacyKind::SessionSqlite);
    let records = legacy.records.len();
    let unresolved = legacy.unresolved.len();
    assert_eq!(records, 8, "meta + 5 annotations + history + undo");
    assert_eq!(unresolved, 1, "a variable name has no locator");

    let mut db = project.open();
    let summary = db.import_legacy(&legacy).expect("import session");
    assert_eq!(summary.imported_records, records);
    assert_eq!(
        summary.applied, 4,
        "rename, comment, tag and bookmark apply"
    );
    assert_eq!(summary.unresolved, unresolved);

    assert_eq!(
        db.name_at(MAIN).expect("name").as_deref(),
        Some("session_main")
    );
    let annotations = db.annotations().expect("annotations");
    assert!(annotations
        .iter()
        .any(|(address, kind, value)| *address == MAIN
            && *kind == AnnotationKind::Comment
            && value == "session comment"));
    assert!(annotations
        .iter()
        .any(|(address, kind, value)| *address == MAIN
            && *kind == AnnotationKind::Tag
            && value == "session tag"));
    assert!(db
        .bookmarks()
        .expect("bookmarks")
        .iter()
        .any(|(address, label)| *address == MAIN && label.as_deref() == Some("session bookmark")));
    assert_eq!(
        db.history_depth().expect("history depth"),
        (0, 0),
        "legacy undo rows are never replayed into the new history"
    );

    {
        let connection = raw_connection(&project.db_path);
        let stored: i64 = connection
            .query_row("SELECT COUNT(*) FROM legacy_records", [], |row| row.get(0))
            .expect("count");
        assert_eq!(stored as usize, records + unresolved);
        let history_records: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM legacy_records WHERE kind IN ('history', 'undo_history')",
                [],
                |row| row.get(0),
            )
            .expect("count legacy history rows");
        assert_eq!(
            history_records, 2,
            "history and undo are preserved verbatim"
        );
    }

    assert_eq!(
        std::fs::read(&project.source_path).expect("source"),
        source_bytes
    );
    assert_eq!(
        std::fs::metadata(&project.source_path)
            .expect("metadata")
            .modified()
            .expect("mtime"),
        source_meta
    );
}

/// Guard against the fixture silently becoming trivial.
#[test]
fn fixture_is_a_complete_project() {
    let project = create_project();
    let mut db = project.open();
    let info = db.info().expect("info");
    assert_eq!(info.source_size, SOURCE_LEN as u64);
    assert_eq!(info.source_sha256, hexray_db::sha256(&project.source_bytes));
    assert_eq!(info.function_count, 3);
    assert_eq!(info.string_count, 1);
    let report = db.check(true).expect("deep check");
    assert!(
        report.passed(),
        "fresh fixture failed deep check: {report:?}"
    );
}
