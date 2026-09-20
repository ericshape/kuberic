#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::Path;
use std::process::Command;

use rusqlite::{Connection, params};
use sqlserver_replicated::journal::{
    JOURNAL_SCHEMA_VERSION, JournalError, MAX_ACTION_PAYLOAD_BYTES, MAX_ACTIONS_PER_OPERATION,
    MAX_AUTHORITY_BINDING_BYTES, MAX_CHECKPOINT_BYTES, MAX_CHECKPOINTS, MAX_RESULT_BYTES,
    OperationJournal, Registration, TransitionCommit,
};
use sqlserver_replicated::{
    AvailabilityGroupIdentity, AvailabilityGroupName, DatabaseIdentity, DatabaseLineage,
    DecimalProgress, DestructiveApproval, FenceReference, Guid, OpaqueId, OperationEnvelope,
    OperationPayload, OperationRequest, ReplicaIdentity, SqlIdentifier,
};
use tempfile::TempDir;

const RESOURCE: &str = "default/sqlserver";
const CONFIGURATION: &str = "configuration-7";
const EPOCH: u64 = 7;
const BINDING: &[u8] = b"authenticated-configuration-and-incarnation-fingerprint";

fn directory() -> TempDir {
    tempfile::Builder::new()
        .prefix(".sqlserver-journal-test-")
        .tempdir_in(std::env::current_dir().unwrap())
        .unwrap()
}

fn guid(value: u32) -> Guid {
    Guid::parse("test", format!("{value:08x}-0000-4000-8000-000000000001")).unwrap()
}

fn replica(value: u32) -> ReplicaIdentity {
    ReplicaIdentity::observed(
        format!("replica-{value}"),
        guid(value),
        format!("pod-{value}"),
    )
    .unwrap()
}

fn ag() -> AvailabilityGroupIdentity {
    AvailabilityGroupIdentity {
        name: AvailabilityGroupName::new("ag").unwrap(),
        group_id: guid(10),
    }
}

fn join_at(
    resource: &str,
    operation_id: &str,
    target: u32,
    configuration: &str,
    epoch: u64,
) -> OperationEnvelope {
    OperationEnvelope::new(
        OperationRequest::new(
            resource,
            operation_id,
            configuration,
            epoch,
            epoch,
            OperationPayload::EnsureReplicaJoined {
                availability_group: ag(),
                target: replica(target),
            },
        )
        .unwrap(),
        None,
        None,
    )
    .unwrap()
}

fn join(operation_id: &str, target: u32) -> OperationEnvelope {
    join_at(RESOURCE, operation_id, target, CONFIGURATION, EPOCH)
}

fn reseed(approval_id: &str, receipt_id: &str) -> OperationEnvelope {
    let request = OperationRequest::new(
        RESOURCE,
        "reseed-1",
        CONFIGURATION,
        EPOCH,
        EPOCH,
        OperationPayload::ReseedReplica {
            availability_group: ag(),
            database: DatabaseIdentity {
                name: SqlIdentifier::new("app").unwrap(),
                group_database_id: guid(20),
            },
            expected_database_id: 5,
            expected_database_guid: guid(21),
            expected_recovery_fork_id: guid(30),
            source: replica(1),
            target: replica(2),
        },
    )
    .unwrap();
    let approval = DestructiveApproval::new(
        approval_id,
        request.operation_id(),
        request.input_signature(),
    )
    .unwrap();
    let fence = FenceReference::new(
        "container-runtime",
        receipt_id,
        request.operation_id(),
        request.input_signature(),
        replica(2),
    )
    .unwrap();
    OperationEnvelope::new(request, Some(approval), Some(fence)).unwrap()
}

fn open(path: &Path) -> OperationJournal {
    OperationJournal::open(path, RESOURCE).unwrap()
}

fn authorized(path: &Path) -> OperationJournal {
    let mut journal = open(path);
    journal
        .accept_authority(CONFIGURATION, EPOCH, BINDING)
        .unwrap();
    journal
}

fn assert_open_error(path: &Path, expected: JournalError) {
    assert!(matches!(OperationJournal::open(path, RESOURCE), Err(error) if error == expected));
}

#[test]
fn observe_only_lookup_reads_records_without_accepting_authority_or_writing_commands() {
    let directory = directory();
    let path = directory.path().join("journal.db");
    let mut journal = open(&path);
    let candidate = join("join-1", 2);
    let before = fs::read(&path).unwrap();
    assert!(journal.entry("join-1").unwrap().is_none());
    assert!(journal.lookup(&candidate).unwrap().is_none());
    assert!(journal.authority().unwrap().is_none());
    assert_eq!(fs::read(&path).unwrap(), before);

    journal
        .accept_authority(CONFIGURATION, EPOCH, BINDING)
        .unwrap();
    journal.register(&candidate).unwrap();
    journal
        .persist_intent("join-1", "joined-action", br#"{"kind":"join"}"#)
        .unwrap();
    journal
        .acknowledge_action("join-1", "joined-action")
        .unwrap();
    journal
        .persist_intent("join-1", "uncertain-action", br#"{"kind":"add_database"}"#)
        .unwrap();
    let before = fs::read(&path).unwrap();
    let authority = journal.authority().unwrap();
    let entry = journal.entry("join-1").unwrap().unwrap();
    let lookup = journal.lookup(&candidate).unwrap().unwrap();
    assert_eq!(lookup, entry);
    assert_eq!(
        lookup.acknowledged_action_keys().collect::<Vec<_>>(),
        ["joined-action"]
    );
    assert_eq!(lookup.pending_intents().count(), 1);
    assert!(lookup.terminal_result.is_none());
    assert_eq!(journal.lookup(&join("join-alias", 2)).unwrap(), Some(entry));
    assert_eq!(
        journal.lookup(&join("join-1", 3)),
        Err(JournalError::OperationIdReuse)
    );
    assert!(journal.lookup(&join("unrelated", 3)).unwrap().is_none());
    assert_eq!(journal.authority().unwrap(), authority);
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn intent_ack_and_terminal_result_survive_real_close_and_reopen() {
    let directory = directory();
    let path = directory.path().join("journal.db");
    let operation = join("join-1", 2);
    {
        let mut journal = open(&path);
        assert_eq!(journal.authority().unwrap(), None);
        assert_eq!(
            journal.register(&operation),
            Err(JournalError::AuthorityRequired)
        );
        journal
            .accept_authority(CONFIGURATION, EPOCH, BINDING)
            .unwrap();
        assert_eq!(journal.register(&operation), Ok(Registration::New));
        journal
            .persist_intent("join-1", "join-ag", b"opaque-action-v1")
            .unwrap();
        let entry = journal.entry("join-1").unwrap().unwrap();
        assert_eq!(entry.pending_intents().count(), 1);
        assert_eq!(entry.acknowledged_action_keys().count(), 0);
        assert!(entry.terminal_result.is_none());
    }
    {
        let mut journal = open(&path);
        let authority = journal.authority().unwrap().unwrap();
        assert_eq!(authority.epoch, EPOCH);
        assert_eq!(authority.binding, BINDING);
        assert_eq!(journal.register(&operation), Ok(Registration::Pending));
        assert_eq!(
            journal.entry("join-1").unwrap().unwrap().actions[0].action_payload,
            b"opaque-action-v1"
        );
        journal.acknowledge_action("join-1", "join-ag").unwrap();
        let entry = journal.entry("join-1").unwrap().unwrap();
        assert_eq!(entry.pending_intents().count(), 0);
        assert_eq!(
            entry.acknowledged_action_keys().collect::<Vec<_>>(),
            ["join-ag"]
        );
        assert!(entry.terminal_result.is_none());
    }
    {
        let mut journal = open(&path);
        assert_eq!(journal.register(&operation), Ok(Registration::Pending));
        journal
            .finish("join-1", b"verified-native-postcondition")
            .unwrap();
        journal
            .finish("join-1", b"verified-native-postcondition")
            .unwrap();
        assert_eq!(
            journal.finish("join-1", b"different-result"),
            Err(JournalError::ResultConflict)
        );
    }
    let mut journal = open(&path);
    assert_eq!(
        journal.register(&operation),
        Ok(Registration::Completed(
            b"verified-native-postcondition".to_vec()
        ))
    );
    let entry = journal.entry("join-1").unwrap().unwrap();
    assert_eq!(entry.actions.len(), 1);
    assert!(entry.actions[0].acknowledged);
    assert_eq!(
        journal.persist_intent("join-1", "another-action", b"new-effect"),
        Err(JournalError::TerminalOperation)
    );
    assert_eq!(
        journal.persist_intent("join-1", "join-ag", b"opaque-action-v1"),
        Err(JournalError::TerminalOperation)
    );
    journal
        .accept_authority("configuration-8", EPOCH + 1, b"new-binding")
        .unwrap();
    assert_eq!(
        journal.register(&operation),
        Ok(Registration::Completed(
            b"verified-native-postcondition".to_vec()
        ))
    );
}

#[test]
fn identifier_conflicts_and_unrelated_pending_operations_fail_closed() {
    let directory = directory();
    let path = directory.path().join("journal.db");
    let mut journal = authorized(&path);
    assert_eq!(journal.register(&join("join-1", 2)), Ok(Registration::New));
    assert_eq!(
        journal.register(&join("join-1", 3)),
        Err(JournalError::OperationIdReuse)
    );
    assert_eq!(
        journal.register(&join("join-2", 3)),
        Err(JournalError::OperationInProgress)
    );
    journal.persist_intent("join-1", "join", b"first").unwrap();
    journal.persist_intent("join-1", "join", b"first").unwrap();
    assert_eq!(
        journal.persist_intent("join-1", "join", b"changed"),
        Err(JournalError::ActionConflict)
    );
    assert_eq!(
        journal.acknowledge_action("join-1", "absent"),
        Err(JournalError::UnknownAction)
    );
    assert_eq!(
        journal.persist_intent("missing", "join", b"first"),
        Err(JournalError::UnknownOperation)
    );
    assert_eq!(
        journal.finish("missing", b"result"),
        Err(JournalError::UnknownOperation)
    );
    journal.acknowledge_action("join-1", "join").unwrap();
    journal.acknowledge_action("join-1", "join").unwrap();
    journal.persist_intent("join-1", "join", b"first").unwrap();
    assert!(journal.entry("join-1").unwrap().unwrap().actions[0].acknowledged);
    assert_eq!(
        journal.register(&join("join-2", 3)),
        Err(JournalError::OperationInProgress)
    );
    journal.finish("join-1", b"verified").unwrap();
    assert_eq!(journal.register(&join("join-2", 3)), Ok(Registration::New));
}

#[test]
fn duplicate_effect_never_authorizes_dispatch_or_borrows_completion() {
    let directory = directory();
    let path = directory.path().join("journal.db");
    let mut journal = authorized(&path);
    journal.register(&join("join-1", 2)).unwrap();
    journal.persist_intent("join-1", "join", b"intent").unwrap();
    let candidate = join("join-2", 2);
    assert_eq!(
        journal.register(&candidate),
        Ok(Registration::DuplicateEffect {
            operation_id: "join-1".to_owned(),
            result: None,
        })
    );
    assert!(journal.entry("join-2").unwrap().is_none());
    assert_eq!(
        journal.persist_intent("join-2", "join", b"intent"),
        Err(JournalError::UnknownOperation)
    );
    assert_eq!(
        journal.finish("join-2", b"borrowed"),
        Err(JournalError::UnknownOperation)
    );
    assert_eq!(
        journal.finish_observed_duplicate(&candidate, b"premature-alias-result"),
        Err(JournalError::OperationInProgress)
    );
    assert!(journal.entry("join-2").unwrap().is_none());
    // Independent postcondition verification can resolve a lost SQL ACK.
    journal.finish("join-1", b"original-observation").unwrap();
    assert!(!journal.entry("join-1").unwrap().unwrap().actions[0].acknowledged);
    drop(journal);
    let mut journal = open(&path);
    assert_eq!(
        journal.register(&candidate),
        Ok(Registration::DuplicateEffect {
            operation_id: "join-1".to_owned(),
            result: Some(b"original-observation".to_vec()),
        })
    );
    journal.register(&join("unrelated-owner", 3)).unwrap();
    assert_eq!(
        journal.finish_observed_duplicate(&candidate, b"new-independent-observation"),
        Err(JournalError::OperationInProgress)
    );
    journal
        .finish("unrelated-owner", b"unrelated-observed-goal")
        .unwrap();
    journal
        .finish_observed_duplicate(&candidate, b"new-independent-observation")
        .unwrap();
    journal
        .finish_observed_duplicate(&candidate, b"new-independent-observation")
        .unwrap();
    assert_eq!(
        journal.finish_observed_duplicate(&candidate, b"changed"),
        Err(JournalError::ResultConflict)
    );
    assert_eq!(
        journal.finish_observed_duplicate(&join("unrelated", 4), b"result"),
        Err(JournalError::NotDuplicateEffect)
    );
    drop(journal);
    let mut journal = open(&path);
    assert_eq!(
        journal.register(&candidate),
        Ok(Registration::Completed(
            b"new-independent-observation".to_vec()
        ))
    );
    assert!(journal.entry("join-2").unwrap().unwrap().actions.is_empty());
}

#[test]
fn renewed_proof_references_preserve_pending_intent_and_canonical_inputs() {
    let directory = directory();
    let path = directory.path().join("journal.db");
    let original = reseed("approval-old", "fence-old");
    let renewed = reseed("approval-renewed", "fence-renewed");
    assert_eq!(original.canonical_input(), renewed.canonical_input());
    {
        let mut journal = authorized(&path);
        journal.register(&original).unwrap();
        journal
            .persist_intent("reseed-1", "drop-old-local", b"database-5-guid-21-fork-30")
            .unwrap();
        let before = fs::read(&path).unwrap();
        assert_eq!(
            journal.lookup(&renewed).unwrap().unwrap().envelope,
            original
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(journal.register(&renewed), Ok(Registration::Pending));
    }
    let mut journal = open(&path);
    let entry = journal.entry("reseed-1").unwrap().unwrap();
    assert_eq!(entry.envelope, renewed);
    assert_eq!(entry.pending_intents().count(), 1);
    journal.finish("reseed-1", b"seeded-postcondition").unwrap();
    assert_eq!(
        journal.register(&original),
        Ok(Registration::Completed(b"seeded-postcondition".to_vec()))
    );
}

#[test]
fn authority_high_water_is_resource_bound_exact_and_durable_through_u64_max() {
    let directory = directory();
    let path = directory.path().join("journal.db");
    {
        let mut journal = authorized(&path);
        assert_eq!(
            journal.accept_authority(CONFIGURATION, EPOCH - 1, BINDING),
            Err(JournalError::AuthorityRegression)
        );
        assert_eq!(
            journal.accept_authority("other-config", EPOCH, BINDING),
            Err(JournalError::AuthorityConflict)
        );
        assert_eq!(
            journal.accept_authority(CONFIGURATION, EPOCH, b"other-incarnation"),
            Err(JournalError::AuthorityConflict)
        );
        journal
            .accept_authority(CONFIGURATION, EPOCH, BINDING)
            .unwrap();
        assert_eq!(
            journal.register(&join_at(RESOURCE, "old", 2, CONFIGURATION, EPOCH - 1)),
            Err(JournalError::AuthorityMismatch)
        );
        assert_eq!(
            journal.register(&join_at(RESOURCE, "other", 2, "other-config", EPOCH)),
            Err(JournalError::AuthorityMismatch)
        );
        assert_eq!(
            journal.register(&join_at(
                "another/resource",
                "join-1",
                2,
                CONFIGURATION,
                EPOCH
            )),
            Err(JournalError::ResourceMismatch)
        );
        journal.register(&join("join-1", 2)).unwrap();
        assert_eq!(
            journal.accept_authority("configuration-8", EPOCH + 1, b"new-binding"),
            Err(JournalError::OperationInProgress)
        );
    }
    {
        let mut journal = open(&path);
        assert_eq!(journal.authority().unwrap().unwrap().epoch, EPOCH);
        assert_eq!(
            journal.accept_authority("configuration-8", EPOCH + 1, b"new-binding"),
            Err(JournalError::OperationInProgress)
        );
        journal.finish("join-1", b"postcondition").unwrap();
        journal
            .accept_authority("last", u64::MAX, b"final-binding")
            .unwrap();
        assert_eq!(
            journal.register(&join_at(RESOURCE, "last-op", 3, "last", u64::MAX)),
            Ok(Registration::New)
        );
        journal.finish("last-op", b"last-postcondition").unwrap();
    }
    let mut journal = open(&path);
    assert_eq!(journal.authority().unwrap().unwrap().epoch, u64::MAX);
    assert_eq!(
        journal.accept_authority("last", u64::MAX - 1, b"final-binding"),
        Err(JournalError::AuthorityRegression)
    );
    drop(journal);
    assert!(matches!(
        OperationJournal::open(&path, "other/resource"),
        Err(JournalError::ResourceMismatch)
    ));
}

#[test]
fn bounds_and_empty_identifiers_are_checked_before_durable_changes() {
    let directory = directory();
    let path = directory.path().join("journal.db");
    assert!(matches!(
        OperationJournal::open(&path, ""),
        Err(JournalError::InvalidInput)
    ));
    let mut journal = open(&path);
    assert_eq!(
        journal.accept_authority(CONFIGURATION, EPOCH, &[]),
        Err(JournalError::InvalidInput)
    );
    assert_eq!(
        journal.accept_authority(
            CONFIGURATION,
            EPOCH,
            &vec![0; MAX_AUTHORITY_BINDING_BYTES + 1]
        ),
        Err(JournalError::TooLarge)
    );
    journal
        .accept_authority(CONFIGURATION, EPOCH, BINDING)
        .unwrap();
    journal.register(&join("join-1", 2)).unwrap();
    assert_eq!(
        journal.persist_intent("join-1", "", b"action"),
        Err(JournalError::InvalidInput)
    );
    assert_eq!(
        journal.persist_intent(
            "join-1",
            "oversized",
            &vec![0; MAX_ACTION_PAYLOAD_BYTES + 1]
        ),
        Err(JournalError::TooLarge)
    );
    journal
        .persist_intent("join-1", "at-limit", &vec![0; MAX_ACTION_PAYLOAD_BYTES])
        .unwrap();
    for index in 1..MAX_ACTIONS_PER_OPERATION {
        journal
            .persist_intent("join-1", &format!("action-{index}"), b"")
            .unwrap();
    }
    assert_eq!(
        journal.persist_intent("join-1", "one-too-many", b""),
        Err(JournalError::TooManyActions)
    );
    assert_eq!(
        journal.finish("join-1", &vec![0; MAX_RESULT_BYTES + 1]),
        Err(JournalError::TooLarge)
    );
    journal
        .finish("join-1", &vec![7; MAX_RESULT_BYTES])
        .unwrap();
    drop(journal);
    let journal = open(&path);
    let entry = journal.entry("join-1").unwrap().unwrap();
    assert_eq!(entry.actions.len(), MAX_ACTIONS_PER_OPERATION);
    assert_eq!(entry.terminal_result.unwrap(), vec![7; MAX_RESULT_BYTES]);
}

#[test]
fn path_aliases_share_the_lifetime_lock_and_new_files_are_private() {
    let directory = directory();
    let path = directory.path().join("journal.db");
    let journal = open(&path);
    assert_eq!(journal.path(), fs::canonicalize(&path).unwrap());
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o077, 0);
    assert_eq!(
        fs::metadata(directory.path().join("journal.db.lock"))
            .unwrap()
            .mode()
            & 0o077,
        0
    );
    assert_open_error(&path, JournalError::Busy);
    assert_open_error(&directory.path().join("./journal.db"), JournalError::Busy);
    let alias = directory.path().join("alias.db");
    symlink(&path, &alias).unwrap();
    assert_open_error(&alias, JournalError::Busy);
    let parent_alias = directory.path().join("parent-alias");
    symlink(directory.path(), &parent_alias).unwrap();
    assert_open_error(&parent_alias.join("journal.db"), JournalError::Busy);
    drop(journal);
    let reopened = open(&alias);
    assert_eq!(reopened.path(), fs::canonicalize(&path).unwrap());
    drop(reopened);
    let hardlink = directory.path().join("hardlink.db");
    fs::hard_link(&path, &hardlink).unwrap();
    assert_open_error(&hardlink, JournalError::InvalidPath);
    assert_open_error(directory.path(), JournalError::InvalidPath);
    assert_open_error(Path::new(":memory:"), JournalError::InvalidPath);
    let dangling = directory.path().join("dangling.db");
    symlink(directory.path().join("absent.db"), &dangling).unwrap();
    assert_open_error(&dangling, JournalError::InvalidPath);
}

fn child(path: &Path, action: &str) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "journal_process_helper", "--nocapture"])
        .env("SQLSERVER_JOURNAL_TEST_PATH", path)
        .env("SQLSERVER_JOURNAL_TEST_ACTION", action)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn separate_process_cannot_open_until_lifetime_lock_is_released() {
    let directory = directory();
    let path = directory.path().join("journal.db");
    let journal = open(&path);
    child(&path, "busy");
    drop(journal);
    child(&path, "open");
}

#[test]
fn abrupt_process_exit_retains_every_prepare_dispatch_ack_and_finish_boundary() {
    for boundary in [
        "registered",
        "prepared",
        "dispatched",
        "acknowledged",
        "finished",
    ] {
        let directory = directory();
        let path = directory.path().join("journal.db");
        child(&path, boundary);
        let mut journal = open(&path);
        let entry = journal.entry("join-1").unwrap().unwrap();
        assert_eq!(
            path.with_extension("native-effect").exists(),
            matches!(boundary, "dispatched" | "acknowledged" | "finished")
        );
        if boundary == "registered" {
            assert!(entry.actions.is_empty());
        } else {
            assert_eq!(entry.actions.len(), 1);
            assert_eq!(entry.actions[0].action_payload, b"opaque-native-action");
            assert_eq!(
                entry.actions[0].acknowledged,
                matches!(boundary, "acknowledged" | "finished")
            );
        }
        assert_eq!(
            journal.register(&join("join-1", 2)),
            Ok(if boundary == "finished" {
                Registration::Completed(b"verified-native-result".to_vec())
            } else {
                Registration::Pending
            })
        );
    }
}

#[test]
fn journal_process_helper() {
    let Some(path) = std::env::var_os("SQLSERVER_JOURNAL_TEST_PATH") else {
        return;
    };
    let action = std::env::var("SQLSERVER_JOURNAL_TEST_ACTION").unwrap();
    let path = Path::new(&path);
    if action == "busy" {
        assert_open_error(path, JournalError::Busy);
        return;
    }
    let mut journal = open(path);
    if action == "open" {
        return;
    }
    journal
        .accept_authority(CONFIGURATION, EPOCH, BINDING)
        .unwrap();
    journal.register(&join("join-1", 2)).unwrap();
    if action != "registered" {
        journal
            .persist_intent("join-1", "join", b"opaque-native-action")
            .unwrap();
    }
    if matches!(action.as_str(), "dispatched" | "acknowledged" | "finished") {
        // Simulates a native effect independently of the journal transaction.
        fs::write(path.with_extension("native-effect"), b"possibly-applied").unwrap();
    }
    if matches!(action.as_str(), "acknowledged" | "finished") {
        journal.acknowledge_action("join-1", "join").unwrap();
    }
    if action == "finished" {
        journal.finish("join-1", b"verified-native-result").unwrap();
    }
    // Deliberately bypass all Rust destructors/SQLite connection close.
    std::process::exit(0);
}

#[test]
fn unknown_or_changed_schema_and_non_sqlite_files_are_rejected() {
    for (sql, expected) in [
        (
            "PRAGMA user_version = 1",
            JournalError::UnsupportedSchemaVersion,
        ),
        (
            "PRAGMA user_version = 999",
            JournalError::UnsupportedSchemaVersion,
        ),
        ("PRAGMA application_id = 0", JournalError::CorruptSchema),
        (
            "CREATE TABLE unexpected (value TEXT)",
            JournalError::CorruptSchema,
        ),
        ("DROP INDEX operations_effect", JournalError::CorruptSchema),
        ("DROP TABLE actions", JournalError::CorruptSchema),
        ("DROP TABLE checkpoints", JournalError::CorruptSchema),
    ] {
        let directory = directory();
        let path = directory.path().join("journal.db");
        drop(open(&path));
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(sql).unwrap();
        drop(connection);
        assert_open_error(&path, expected);
    }
    let directory = directory();
    let path = directory.path().join("not-sqlite.db");
    fs::write(&path, b"private-diagnostic-that-must-not-be-echoed").unwrap();
    assert_open_error(&path, JournalError::CorruptSchema);
    let error = match OperationJournal::open(&path, RESOURCE) {
        Err(error) => error,
        Ok(_) => panic!("corrupt file opened"),
    };
    assert!(!format!("{error:?}: {error}").contains("private-diagnostic"));
}

#[test]
fn corrupt_records_intents_acknowledgements_and_results_never_become_success() {
    for sql in [
        "UPDATE operations SET input_signature = zeroblob(32)",
        "UPDATE operations SET effect_signature = zeroblob(32)",
        "UPDATE operations SET envelope = X'7b7d'",
        "UPDATE operations SET record_hash = zeroblob(32)",
        "UPDATE operations SET result = X'00'",
        "UPDATE operations SET result_hash = zeroblob(32)",
        "UPDATE actions SET payload = X'00'",
        "UPDATE actions SET payload_hash = zeroblob(32)",
        "UPDATE actions SET acknowledged = 1",
        "DELETE FROM actions",
        "UPDATE journal_metadata SET epoch = zeroblob(8)",
        "UPDATE journal_metadata SET binding = X'00'",
        "UPDATE journal_metadata SET state_hash = zeroblob(32)",
        "DELETE FROM journal_metadata",
    ] {
        let directory = directory();
        let path = directory.path().join("journal.db");
        {
            let mut journal = authorized(&path);
            journal.register(&join("join-1", 2)).unwrap();
            journal
                .persist_intent("join-1", "join", b"opaque-action")
                .unwrap();
            journal.finish("join-1", b"verified-result").unwrap();
        }
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(sql).unwrap();
        drop(connection);
        assert_open_error(&path, JournalError::CorruptRecord);
    }
}

#[test]
fn malformed_oversized_records_and_old_operation_contracts_are_rejected() {
    for kind in [
        "oversized-envelope",
        "oversized-action",
        "bad-epoch",
        "old-contract",
        "previous-contract",
    ] {
        let directory = directory();
        let path = directory.path().join("journal.db");
        {
            let mut journal = authorized(&path);
            journal.register(&join("join-1", 2)).unwrap();
            journal
                .persist_intent("join-1", "join", b"opaque-action")
                .unwrap();
        }

        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("PRAGMA ignore_check_constraints = ON")
            .unwrap();
        match kind {
            "oversized-envelope" => {
                connection
                    .execute("UPDATE operations SET envelope = zeroblob(65537)", [])
                    .unwrap();
            }
            "oversized-action" => {
                connection
                    .execute("UPDATE actions SET payload = zeroblob(65537)", [])
                    .unwrap();
            }
            "bad-epoch" => {
                connection
                    .execute("UPDATE journal_metadata SET epoch = X'07'", [])
                    .unwrap();
            }
            "old-contract" | "previous-contract" => {
                let bytes: Vec<u8> = connection
                    .query_row("SELECT envelope FROM operations", [], |row| row.get(0))
                    .unwrap();
                let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                value["version"] = serde_json::json!(if kind == "old-contract" { 1 } else { 2 });
                connection
                    .execute(
                        "UPDATE operations SET envelope = ?1",
                        params![serde_json::to_vec(&value).unwrap()],
                    )
                    .unwrap();
            }
            _ => unreachable!(),
        }
        drop(connection);
        // quick_check can detect the violated SQL bounds before record decoding.
        assert!(matches!(
            OperationJournal::open(&path, RESOURCE),
            Err(JournalError::CorruptRecord | JournalError::CorruptSchema)
        ));
    }
}

fn transition(forced: bool, epoch: u64) -> OperationEnvelope {
    let database = DatabaseLineage {
        database: DatabaseIdentity {
            name: SqlIdentifier::new("app").unwrap(),
            group_database_id: guid(20),
        },
        recovery_fork_id: guid(30),
    };
    let target_configuration_id = OpaqueId::new("configuration", "configuration-next").unwrap();
    let payload = if forced {
        OperationPayload::ForcedFailover {
            availability_group: ag(),
            database,
            source: replica(1),
            target: replica(2),
            target_configuration_id,
            last_known_commit: None,
        }
    } else {
        OperationPayload::PlannedSwitchover {
            availability_group: ag(),
            database,
            source: replica(1),
            target: replica(2),
            target_configuration_id,
            commit_boundary: DecimalProgress::parse("500").unwrap(),
        }
    };
    let request = OperationRequest::new(
        RESOURCE,
        "transition-1",
        CONFIGURATION,
        epoch,
        epoch + 1,
        payload,
    )
    .unwrap();
    let approval = forced.then(|| {
        DestructiveApproval::new(
            "explicit-data-loss",
            request.operation_id(),
            request.input_signature(),
        )
        .unwrap()
    });
    let fence = FenceReference::new(
        "verified-container-removal",
        "fence",
        request.operation_id(),
        request.input_signature(),
        replica(1),
    )
    .unwrap();
    OperationEnvelope::new(request, approval, Some(fence)).unwrap()
}

fn transition_commit(epoch: u64) -> TransitionCommit {
    TransitionCommit {
        configuration_id: "configuration-next".into(),
        epoch: epoch + 1,
        binding: b"authenticated-target-authority".to_vec(),
        checkpoint_name: "ha-controller".into(),
        checkpoint: b"target-is-active-and-pending-is-cleared".to_vec(),
    }
}

#[test]
fn checkpoints_are_bounded_integrity_checked_durable_and_read_only_when_queried() {
    let directory = directory();
    let path = directory.path().join("journal.db");
    let mut journal = authorized(&path);
    assert_eq!(JOURNAL_SCHEMA_VERSION, 2);
    assert_eq!(journal.checkpoint("controller").unwrap(), None);
    assert!(journal.pending_entry().unwrap().is_none());
    journal.put_checkpoint("controller", b"pending").unwrap();
    let before = fs::read(&path).unwrap();
    assert_eq!(
        journal.checkpoint("controller").unwrap().as_deref(),
        Some(b"pending".as_slice())
    );
    assert_eq!(journal.checkpoint("missing").unwrap(), None);
    assert_eq!(fs::read(&path).unwrap(), before);
    // Inspection must work while the exclusive writer is still alive and must
    // not create a second writer or release its lifetime flock.
    let pair = OperationJournal::inspect_read_only(&path, RESOURCE, "controller").unwrap();
    assert_eq!(pair.0, journal.authority().unwrap());
    assert_eq!(pair.1.as_deref(), Some(b"pending".as_slice()));
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(matches!(
        OperationJournal::open(&path, RESOURCE),
        Err(JournalError::Busy)
    ));
    assert_eq!(
        OperationJournal::inspect_read_only(&path, "foreign", "controller"),
        Err(JournalError::ResourceMismatch)
    );
    let missing = directory.path().join("missing.db");
    assert!(OperationJournal::inspect_read_only(&missing, RESOURCE, "controller").is_err());
    assert!(!missing.exists());
    assert!(!missing.with_extension("db.lock").exists());
    assert_eq!(journal.checkpoint(""), Err(JournalError::InvalidInput));
    assert_eq!(
        journal.put_checkpoint("", b"v"),
        Err(JournalError::InvalidInput)
    );
    assert_eq!(
        journal.put_checkpoint("controller", &vec![0; MAX_CHECKPOINT_BYTES + 1]),
        Err(JournalError::TooLarge)
    );
    assert_eq!(
        journal.checkpoint("controller").unwrap().as_deref(),
        Some(b"pending".as_slice())
    );
    journal
        .put_checkpoint("controller", &vec![255; MAX_CHECKPOINT_BYTES])
        .unwrap();
    journal.put_checkpoint("empty", b"").unwrap();
    drop(journal);
    let journal = open(&path);
    assert_eq!(
        journal.checkpoint("controller").unwrap(),
        Some(vec![255; MAX_CHECKPOINT_BYTES])
    );
    assert_eq!(journal.checkpoint("empty").unwrap(), Some(Vec::new()));
}

#[test]
fn read_only_inspection_never_creates_a_missing_lock_sidecar_or_mutates_the_database() {
    let directory = directory();
    let path = directory.path().join("journal.db");
    let mut journal = authorized(&path);
    journal
        .put_checkpoint("ha-control", b"active-epoch-7")
        .unwrap();
    let authority = journal.authority().unwrap();
    drop(journal);

    let snapshot = directory.path().join("read-only.db");
    fs::copy(&path, &snapshot).unwrap();
    let before = fs::read(&snapshot).unwrap();
    assert!(!snapshot.with_extension("db.lock").exists());
    assert_eq!(
        OperationJournal::inspect_read_only(&snapshot, RESOURCE, "ha-control").unwrap(),
        (authority, Some(b"active-epoch-7".to_vec()))
    );
    assert_eq!(fs::read(&snapshot).unwrap(), before);
    assert!(!snapshot.with_extension("db.lock").exists());
    assert!(!snapshot.with_extension("db-journal").exists());
}

#[test]
fn read_only_inspection_observes_committed_state_and_denies_genuine_sqlite_busy() {
    let directory = directory();
    let path = directory.path().join("journal.db");
    let mut journal = authorized(&path);
    journal
        .put_checkpoint("ha-control", b"active-epoch-7")
        .unwrap();
    let authority = journal.authority().unwrap();
    let blocker = Connection::open(&path).unwrap();
    blocker
        .execute_batch(
            "BEGIN IMMEDIATE;
         UPDATE checkpoints SET value = X'00' WHERE name = 'ha-control';",
        )
        .unwrap();
    assert_eq!(
        OperationJournal::inspect_read_only(&path, RESOURCE, "ha-control").unwrap(),
        (authority, Some(b"active-epoch-7".to_vec()))
    );
    blocker.execute_batch("ROLLBACK; BEGIN EXCLUSIVE;").unwrap();
    assert_eq!(
        OperationJournal::inspect_read_only(&path, RESOURCE, "ha-control"),
        Err(JournalError::Busy)
    );
    blocker.execute_batch("ROLLBACK").unwrap();
    drop(blocker);
    assert_eq!(
        journal.checkpoint("ha-control").unwrap(),
        Some(b"active-epoch-7".to_vec())
    );
    assert!(matches!(
        OperationJournal::open(&path, RESOURCE),
        Err(JournalError::Busy)
    ));
}

#[test]
fn pending_entry_exposes_unresolved_pr3_intents_read_only_before_any_ha_freeze() {
    let directory = directory();
    let path = directory.path().join("journal.db");
    let mut journal = authorized(&path);
    let operation = reseed("approval", "fence");
    journal.register(&operation).unwrap();
    journal
        .persist_intent(operation.operation_id(), "detach", b"possibly-dispatched")
        .unwrap();
    journal
        .persist_intent(operation.operation_id(), "earlier-step", b"acknowledged")
        .unwrap();
    journal
        .acknowledge_action(operation.operation_id(), "earlier-step")
        .unwrap();
    let before = fs::read(&path).unwrap();
    let authority = journal.authority().unwrap();
    let pending = journal.pending_entry().unwrap().unwrap();
    assert_eq!(pending.envelope, operation);
    assert!(pending.terminal_result.is_none());
    assert_eq!(pending.actions.len(), 2);
    assert_eq!(pending.pending_intents().count(), 1);
    assert_eq!(journal.authority().unwrap(), authority);
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(
        journal.register(&transition(false, EPOCH)),
        Err(JournalError::OperationInProgress)
    );
    journal
        .finish(operation.operation_id(), b"verified-pr3-postcondition")
        .unwrap();
    let before = fs::read(&path).unwrap();
    assert!(journal.pending_entry().unwrap().is_none());
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(
        journal
            .entry(operation.operation_id())
            .unwrap()
            .unwrap()
            .actions,
        pending.actions
    );
}

#[test]
fn checkpoint_count_is_bounded_but_existing_checkpoints_remain_updatable() {
    let directory = directory();
    let path = directory.path().join("journal.db");
    let mut journal = authorized(&path);
    for index in 0..MAX_CHECKPOINTS {
        journal
            .put_checkpoint(&format!("checkpoint-{index}"), b"value")
            .unwrap();
    }
    assert_eq!(
        journal.put_checkpoint("one-too-many", b"value"),
        Err(JournalError::TooManyCheckpoints)
    );
    journal
        .put_checkpoint("checkpoint-0", b"replacement")
        .unwrap();
    assert_eq!(
        journal.checkpoint("checkpoint-0").unwrap().as_deref(),
        Some(b"replacement".as_slice())
    );
    let operation = transition(false, EPOCH);
    journal.register(&operation).unwrap();
    assert_eq!(
        journal.finish_transition(
            operation.operation_id(),
            b"result",
            &transition_commit(EPOCH)
        ),
        Err(JournalError::TooManyCheckpoints)
    );
    assert!(
        journal
            .entry(operation.operation_id())
            .unwrap()
            .unwrap()
            .terminal_result
            .is_none()
    );
    assert_eq!(journal.authority().unwrap().unwrap().epoch, EPOCH);
}

#[test]
fn checkpoint_deletion_renaming_corruption_and_oversized_values_fail_closed() {
    for sql in [
        "UPDATE checkpoints SET value = X'00'",
        "UPDATE checkpoints SET value_hash = zeroblob(32)",
        "UPDATE checkpoints SET name = 'different-controller'",
        "DELETE FROM checkpoints",
        "UPDATE journal_metadata SET checkpoints_hash = zeroblob(32)",
        "PRAGMA ignore_check_constraints = ON; UPDATE checkpoints SET value = zeroblob(65537)",
    ] {
        let directory = directory();
        let path = directory.path().join("journal.db");
        let mut journal = authorized(&path);
        journal.put_checkpoint("controller", b"valid").unwrap();
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(sql).unwrap();
        drop(connection);
        assert!(journal.checkpoint("controller").is_err(), "{sql}");
        assert!(
            journal
                .put_checkpoint("controller", b"must-not-repair")
                .is_err(),
            "{sql}"
        );
        assert!(
            OperationJournal::inspect_read_only(&path, RESOURCE, "controller").is_err(),
            "{sql}"
        );
        drop(journal);
        assert!(
            matches!(
                OperationJournal::open(&path, RESOURCE),
                Err(JournalError::CorruptRecord | JournalError::CorruptSchema)
            ),
            "{sql}"
        );
    }
}

#[test]
fn transition_atomically_commits_target_result_checkpoint_and_retains_all_intents() {
    for forced in [false, true] {
        let directory = directory();
        let path = directory.path().join("journal.db");
        let mut journal = authorized(&path);
        journal
            .put_checkpoint("ha-controller", b"source-with-pending-transition")
            .unwrap();
        let operation = transition(forced, EPOCH);
        let commit = transition_commit(EPOCH);
        assert_eq!(journal.register(&operation).unwrap(), Registration::New);
        journal
            .persist_intent(operation.operation_id(), "promote", b"exact-promotion")
            .unwrap();
        journal
            .persist_intent(
                operation.operation_id(),
                "secondary-reset",
                b"uncertain-reset",
            )
            .unwrap();
        journal
            .acknowledge_action(operation.operation_id(), "promote")
            .unwrap();
        let before = journal.pending_entry().unwrap().unwrap();
        let inspected =
            OperationJournal::inspect_read_only(&path, RESOURCE, "ha-controller").unwrap();
        assert_eq!(inspected.0.unwrap().epoch, EPOCH);
        assert_eq!(
            inspected.1.as_deref(),
            Some(b"source-with-pending-transition".as_slice())
        );
        journal
            .finish_transition(
                operation.operation_id(),
                b"verified-native-postcondition",
                &commit,
            )
            .unwrap();
        let completed = journal.entry(operation.operation_id()).unwrap().unwrap();
        assert_eq!(completed.actions, before.actions);
        assert_eq!(completed.pending_intents().count(), 1);
        assert_eq!(completed.transition_commit, Some(commit.clone()));
        assert!(journal.pending_entry().unwrap().is_none());
        let (authority, checkpoint) =
            OperationJournal::inspect_read_only(&path, RESOURCE, "ha-controller").unwrap();
        let authority = authority.unwrap();
        assert_eq!(authority.configuration_id, commit.configuration_id);
        assert_eq!(authority.epoch, commit.epoch);
        assert_eq!(authority.binding, commit.binding);
        assert_eq!(checkpoint, Some(commit.checkpoint.clone()));
        drop(journal);
        let mut journal = open(&path);
        assert_eq!(
            journal.entry(operation.operation_id()).unwrap(),
            Some(completed)
        );
        assert_eq!(
            journal.register(&operation).unwrap(),
            Registration::Completed(b"verified-native-postcondition".to_vec())
        );
        journal
            .finish_transition(
                operation.operation_id(),
                b"verified-native-postcondition",
                &commit,
            )
            .unwrap();
    }
}

#[test]
fn transition_failure_rolls_back_checkpoint_authority_and_result_together() {
    let directory = directory();
    let path = directory.path().join("journal.db");
    let mut journal = authorized(&path);
    journal
        .put_checkpoint("ha-controller", b"source-pending")
        .unwrap();
    let operation = transition(false, EPOCH);
    journal.register(&operation).unwrap();
    journal
        .persist_intent(operation.operation_id(), "promote", b"possibly-dispatched")
        .unwrap();
    let old_entry = journal.entry(operation.operation_id()).unwrap();
    let old_authority = journal.authority().unwrap();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER injected_failure BEFORE UPDATE OF result ON operations
                 WHEN NEW.result IS NOT NULL BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        )
        .unwrap();
    assert_eq!(
        journal.finish_transition(
            operation.operation_id(),
            b"result",
            &transition_commit(EPOCH)
        ),
        Err(JournalError::Storage)
    );
    assert_eq!(journal.entry(operation.operation_id()).unwrap(), old_entry);
    assert_eq!(journal.authority().unwrap(), old_authority);
    assert_eq!(
        journal.checkpoint("ha-controller").unwrap().as_deref(),
        Some(b"source-pending".as_slice())
    );
    connection
        .execute_batch("DROP TRIGGER injected_failure")
        .unwrap();
    drop(connection);
    drop(journal);
    let mut journal = open(&path);
    assert_eq!(journal.entry(operation.operation_id()).unwrap(), old_entry);
    journal
        .finish_transition(
            operation.operation_id(),
            b"result",
            &transition_commit(EPOCH),
        )
        .unwrap();
}

#[test]
fn transition_rejects_wrong_operation_configuration_epoch_and_non_atomic_finish() {
    let directory = directory();
    let path = directory.path().join("journal.db");
    let mut journal = authorized(&path);
    let commit = transition_commit(EPOCH);
    assert_eq!(
        journal.finish_transition("missing", b"result", &commit),
        Err(JournalError::UnknownOperation)
    );
    journal.register(&join("join-1", 2)).unwrap();
    assert_eq!(
        journal.finish_transition("join-1", b"result", &commit),
        Err(JournalError::InvalidTransition)
    );
    journal.finish("join-1", b"join-result").unwrap();
    let operation = transition(false, EPOCH);
    journal.register(&operation).unwrap();
    assert_eq!(
        journal.finish(operation.operation_id(), b"result"),
        Err(JournalError::InvalidTransition)
    );
    assert_eq!(
        journal.finish_observed_duplicate(&operation, b"result"),
        Err(JournalError::InvalidTransition)
    );
    let changes: &[fn(&mut TransitionCommit)] = &[
        |c| c.configuration_id = CONFIGURATION.into(),
        |c| c.configuration_id = "unrequested-target".into(),
        |c| c.epoch = EPOCH,
        |c| c.epoch = EPOCH + 2,
        |c| c.epoch = u64::MAX,
    ];
    for change in changes {
        let mut bad = commit.clone();
        change(&mut bad);
        assert_eq!(
            journal.finish_transition(operation.operation_id(), b"result", &bad),
            Err(JournalError::InvalidTransition)
        );
    }
    assert_eq!(journal.authority().unwrap().unwrap().epoch, EPOCH);
    assert_eq!(journal.checkpoint("ha-controller").unwrap(), None);
    assert!(journal.pending_entry().unwrap().is_some());
    assert_eq!(
        journal.accept_authority("cannot-skip", EPOCH + 2, b"binding"),
        Err(JournalError::OperationInProgress)
    );
}

#[test]
fn transition_requires_the_current_source_authority_including_after_pending_corruption() {
    let directory = directory();
    let path = directory.path().join("journal.db");
    let mut journal = authorized(&path);
    let operation = transition(false, EPOCH);
    journal.register(&operation).unwrap();
    // Build a separately valid metadata row for a different accepted authority,
    // simulating external replacement rather than merely a broken hash.
    let other_path = directory.path().join("other.db");
    let mut other = open(&other_path);
    other
        .accept_authority("other-source", EPOCH, BINDING)
        .unwrap();
    drop(other);
    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "ATTACH DATABASE ?1 AS other",
            [other_path.to_str().unwrap()],
        )
        .unwrap();
    connection
        .execute_batch(
            "UPDATE journal_metadata SET
                 configuration_id = (SELECT configuration_id FROM other.journal_metadata),
                 state_hash = (SELECT state_hash FROM other.journal_metadata);",
        )
        .unwrap();
    assert_eq!(
        journal.finish_transition(
            operation.operation_id(),
            b"result",
            &transition_commit(EPOCH)
        ),
        Err(JournalError::AuthorityMismatch)
    );
    assert!(
        journal
            .entry(operation.operation_id())
            .unwrap()
            .unwrap()
            .terminal_result
            .is_none()
    );
    assert_eq!(journal.checkpoint("ha-controller").unwrap(), None);
    drop(connection);
    drop(journal);
    assert_open_error(&path, JournalError::CorruptRecord);
}

#[test]
fn terminal_transition_replay_is_exact_immutable_and_cannot_rewind_later_state() {
    let directory = directory();
    let path = directory.path().join("journal.db");
    let mut journal = authorized(&path);
    let operation = transition(false, EPOCH);
    let commit = transition_commit(EPOCH);
    journal.register(&operation).unwrap();
    journal
        .finish_transition(operation.operation_id(), b"result", &commit)
        .unwrap();
    assert_eq!(
        journal.finish_transition(operation.operation_id(), b"changed-result", &commit),
        Err(JournalError::ResultConflict)
    );
    let changes: &[fn(&mut TransitionCommit)] = &[
        |c| c.binding.push(1),
        |c| c.checkpoint.push(1),
        |c| c.checkpoint_name = "different-controller".into(),
    ];
    for change in changes {
        let mut bad = commit.clone();
        change(&mut bad);
        assert_eq!(
            journal.finish_transition(operation.operation_id(), b"result", &bad),
            Err(JournalError::TransitionConflict)
        );
    }
    journal
        .put_checkpoint("ha-controller", b"later-lease-state")
        .unwrap();
    journal
        .accept_authority("later-authority", EPOCH + 2, b"later-binding")
        .unwrap();
    let before = fs::read(&path).unwrap();
    journal
        .finish_transition(operation.operation_id(), b"result", &commit)
        .unwrap();
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(journal.authority().unwrap().unwrap().epoch, EPOCH + 2);
    assert_eq!(
        journal.checkpoint("ha-controller").unwrap().as_deref(),
        Some(b"later-lease-state".as_slice())
    );
    drop(journal);
    let mut journal = open(&path);
    journal
        .finish_transition(operation.operation_id(), b"result", &commit)
        .unwrap();
}

#[test]
fn transition_commit_bounds_are_checked_without_changing_pending_records() {
    let directory = directory();
    let path = directory.path().join("journal.db");
    let mut journal = authorized(&path);
    let operation = transition(false, EPOCH);
    journal.register(&operation).unwrap();
    let changes: &[fn(&mut TransitionCommit)] = &[
        |c| c.binding.clear(),
        |c| c.binding = vec![0; MAX_AUTHORITY_BINDING_BYTES + 1],
        |c| c.checkpoint_name.clear(),
        |c| c.checkpoint_name = "x".repeat(257),
        |c| c.configuration_id.clear(),
        |c| c.checkpoint = vec![0; MAX_CHECKPOINT_BYTES + 1],
    ];
    for change in changes {
        let mut commit = transition_commit(EPOCH);
        change(&mut commit);
        assert!(
            journal
                .finish_transition(operation.operation_id(), b"result", &commit)
                .is_err()
        );
        assert!(journal.pending_entry().unwrap().is_some());
        assert_eq!(journal.checkpoint("ha-controller").unwrap(), None);
    }
    assert_eq!(
        journal.finish_transition(
            operation.operation_id(),
            &vec![0; MAX_RESULT_BYTES + 1],
            &transition_commit(EPOCH)
        ),
        Err(JournalError::TooLarge)
    );
    let mut largest = transition_commit(EPOCH);
    largest.binding = vec![255; MAX_AUTHORITY_BINDING_BYTES];
    largest.checkpoint = vec![255; MAX_CHECKPOINT_BYTES];
    journal
        .finish_transition(
            operation.operation_id(),
            &vec![255; MAX_RESULT_BYTES],
            &largest,
        )
        .unwrap();
    drop(journal);
    let journal = open(&path);
    assert_eq!(
        journal
            .entry(operation.operation_id())
            .unwrap()
            .unwrap()
            .transition_commit,
        Some(largest)
    );
}

#[test]
fn immutable_transition_commit_corruption_cannot_be_replayed_as_success() {
    for sql in [
        "UPDATE operations SET transition_commit = NULL",
        "UPDATE operations SET transition_commit = X'7b7d'",
        "UPDATE operations SET transition_commit = zeroblob(294913)",
        "DELETE FROM checkpoints",
    ] {
        let directory = directory();
        let path = directory.path().join("journal.db");
        let mut journal = authorized(&path);
        let operation = transition(false, EPOCH);
        journal.register(&operation).unwrap();
        journal
            .finish_transition(
                operation.operation_id(),
                b"result",
                &transition_commit(EPOCH),
            )
            .unwrap();
        drop(journal);
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("PRAGMA ignore_check_constraints = ON")
            .unwrap();
        connection.execute_batch(sql).unwrap();
        drop(connection);
        assert!(matches!(
            OperationJournal::open(&path, RESOURCE),
            Err(JournalError::CorruptRecord | JournalError::CorruptSchema)
        ));
    }
}

#[test]
fn exact_last_representable_transition_epoch_remains_lossless() {
    let directory = directory();
    let path = directory.path().join("journal.db");
    let mut journal = open(&path);
    journal
        .accept_authority(CONFIGURATION, u64::MAX - 1, BINDING)
        .unwrap();
    let operation = transition(false, u64::MAX - 1);
    let commit = transition_commit(u64::MAX - 1);
    journal.register(&operation).unwrap();
    journal
        .finish_transition(operation.operation_id(), b"result", &commit)
        .unwrap();
    drop(journal);
    let mut journal = open(&path);
    assert_eq!(journal.authority().unwrap().unwrap().epoch, u64::MAX);
    journal
        .finish_transition(operation.operation_id(), b"result", &commit)
        .unwrap();
}
