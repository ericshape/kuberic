use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use sqlserver_replicated::adapter::{AdapterError, AdapterOutcome, AgAdapter};
use sqlserver_replicated::convergence::{
    AcceptedAuthority, DatabaseProbe, NativeAction, NodeEvidence,
};
use sqlserver_replicated::instance::unix_millis;
use sqlserver_replicated::journal::{JournalError, OperationJournal};
use sqlserver_replicated::mutation::{AgBackend, AuthorizationVerifier};
use sqlserver_replicated::observation::{
    AvailabilityGroupSnapshot, DatabaseReplicaSnapshot, DatabaseSnapshot, InstanceMetadata,
    InstanceSnapshot, LocalDatabaseSnapshot, LocalRecoveryMetadata, LocalReplicaSnapshot,
    NativeProvenance, RecoveryLineageObservation, ReplicaSnapshot, ReplicaState,
};
use sqlserver_replicated::runtime_error::RuntimeError;
use sqlserver_replicated::{
    AvailabilityGroupIdentity, AvailabilityGroupName, DatabaseIdentity, DatabaseLineage,
    DecimalProgress, Endpoint, Guid, MutationMode, NativeProgress, NativeRole, Observation,
    ObservationFailureKind, OpaqueId, OperationEnvelope, OperationPayload, OperationRequest,
    ReplicaDescriptor, ReplicaIdentity, ServerName, SqlIdentifier,
};

fn guid(id: u32) -> Guid {
    Guid::parse("fixture", format!("{id:08x}-1111-2222-3333-444444444444")).unwrap()
}

fn desired(id: u32) -> ReplicaIdentity {
    ReplicaIdentity::desired(format!("replica-{id}"), format!("pod-{id}")).unwrap()
}

fn observed(id: u32) -> ReplicaIdentity {
    ReplicaIdentity::observed(format!("replica-{id}"), guid(10 + id), format!("pod-{id}")).unwrap()
}

fn authority() -> AcceptedAuthority {
    AcceptedAuthority {
        resource_id: OpaqueId::new("resource", "resource").unwrap(),
        configuration_id: OpaqueId::new("configuration", "configuration").unwrap(),
        epoch: 1,
        primary: desired(0),
        replicas: (0..3)
            .map(|id| ReplicaDescriptor {
                identity: desired(id),
                server_name: ServerName::new(format!("sql-{id}")).unwrap(),
                endpoint: Endpoint::new(format!("sql-{id}.example"), 5022).unwrap(),
            })
            .collect(),
    }
}

fn request(id: &str) -> OperationEnvelope {
    let authority = authority();
    OperationEnvelope::new(
        OperationRequest::new(
            "resource",
            id,
            "configuration",
            1,
            1,
            OperationPayload::EnsureAvailabilityGroup {
                name: AvailabilityGroupName::new("group").unwrap(),
                expected_group_id: None,
                database_name: SqlIdentifier::new("database").unwrap(),
                write_lease_seconds: 30,
                primary: authority.primary,
                replicas: authority.replicas,
            },
        )
        .unwrap(),
        None,
        None,
    )
    .unwrap()
}

#[derive(Default)]
struct State {
    created: bool,
    observations: usize,
    effects: usize,
    request_checks: usize,
    action_checks: usize,
    fail_after_effect: bool,
    fail_observation: bool,
    database_generation: u32,
    group_generation: u32,
    deny: bool,
    action_delay_ms: u64,
}

#[derive(Clone)]
struct Backend(Arc<Mutex<State>>);

#[derive(Clone)]
struct Verifier(Arc<Mutex<State>>);

fn error(kind: ObservationFailureKind) -> RuntimeError {
    RuntimeError::new(kind, "fixture", "injected test failure")
}

#[async_trait]
impl AuthorizationVerifier for Verifier {
    async fn verify_request(
        &self,
        _: &OperationEnvelope,
        _: &AcceptedAuthority,
    ) -> Result<(), RuntimeError> {
        let mut state = self.0.lock().unwrap();
        state.request_checks += 1;
        if state.deny {
            Err(error(ObservationFailureKind::PermissionDenied))
        } else {
            Ok(())
        }
    }

    async fn verify(
        &self,
        _: &OperationEnvelope,
        _: &AcceptedAuthority,
        _: &NativeAction,
    ) -> Result<(), RuntimeError> {
        let (deny, delay) = {
            let mut state = self.0.lock().unwrap();
            state.action_checks += 1;
            (state.deny, state.action_delay_ms)
        };
        if delay > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }
        if deny {
            Err(error(ObservationFailureKind::PermissionDenied))
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl AgBackend for Backend {
    async fn observe(
        &self,
        _: &OperationEnvelope,
        _: &AcceptedAuthority,
        _: MutationMode,
    ) -> Result<Vec<NodeEvidence>, RuntimeError> {
        let mut state = self.0.lock().unwrap();
        state.observations += 1;
        if state.fail_observation {
            return Err(error(ObservationFailureKind::Unreachable));
        }
        Ok(evidence(&state, unix_millis()?))
    }

    async fn execute(
        &self,
        envelope: &OperationEnvelope,
        authority: &AcceptedAuthority,
        action: &NativeAction,
        verifier: &dyn AuthorizationVerifier,
    ) -> Result<(), RuntimeError> {
        verifier.verify(envelope, authority, action).await?;
        assert!(matches!(
            action,
            NativeAction::CreateAvailabilityGroup { .. }
        ));
        let mut state = self.0.lock().unwrap();
        state.effects += 1;
        state.created = true;
        if state.fail_after_effect {
            Err(error(ObservationFailureKind::TimedOut))
        } else {
            Ok(())
        }
    }
}

fn evidence(state: &State, now: u64) -> Vec<NodeEvidence> {
    let authority = authority();
    authority
        .replicas
        .iter()
        .enumerate()
        .map(|(index, member)| {
            let mut snapshot = InstanceSnapshot {
                observed_at_unix_millis: now,
                instance: InstanceMetadata {
                    server_name: member.server_name.clone(),
                    property_server_name: member.server_name.clone(),
                    product_version: "16.0.4185.3".to_owned(),
                    product_major_version: 16,
                    edition: "Developer Edition (64-bit)".to_owned(),
                    engine_edition: 3,
                    hadr_enabled: true,
                    host_platform: "Linux".to_owned(),
                    host_distribution: Some("Ubuntu".to_owned()),
                    architecture: "x86_64".to_owned(),
                    sqlserver_start_time: "2026-09-19T00:00:00".to_owned(),
                },
                availability_group: Observation::Absent {
                    observed_at_unix_millis: now,
                },
            };
            let mut probe = DatabaseProbe {
                name: SqlIdentifier::new("database").unwrap(),
                database_id: 5,
                database_guid: guid(100 + state.database_generation),
                recovery_fork_id: guid(200),
                group_database_id: None,
                replica_id: None,
                state: "ONLINE".to_owned(),
                recovery_model: "FULL".to_owned(),
                backup_ready: true,
            };
            if index == 0 && state.created {
                let database = DatabaseIdentity {
                    name: probe.name.clone(),
                    group_database_id: guid(2),
                };
                probe.group_database_id = Some(guid(2));
                probe.replica_id = Some(guid(10));
                snapshot.availability_group = Observation::Present {
                    observed_at_unix_millis: now,
                    value: AvailabilityGroupSnapshot {
                        identity: AvailabilityGroupIdentity {
                            name: AvailabilityGroupName::new("group").unwrap(),
                            group_id: guid(1 + state.group_generation),
                        },
                        configuration_sequence: DecimalProgress::parse("1").unwrap(),
                        cluster_type: "EXTERNAL".to_owned(),
                        required_synchronized_secondaries_to_commit: 1,
                        basic_features: false,
                        is_distributed: false,
                        local_replica: LocalReplicaSnapshot {
                            identity: observed(0),
                            state_available: true,
                            role: Some(NativeRole::Primary),
                        },
                        replicas: authority
                            .replicas
                            .iter()
                            .enumerate()
                            .map(|(index, member)| ReplicaSnapshot {
                                replica_id: guid(10 + u32::try_from(index).unwrap()),
                                server_name: member.server_name.clone(),
                                endpoint_url: Some(member.endpoint.to_string()),
                                availability_mode: "SYNCHRONOUS_COMMIT".to_owned(),
                                failover_mode: "EXTERNAL".to_owned(),
                                seeding_mode: "AUTOMATIC".to_owned(),
                                state: (index == 0).then_some(ReplicaState {
                                    provenance: NativeProvenance::Local,
                                    role: Some(NativeRole::Primary),
                                    operational_state: Some("ONLINE".to_owned()),
                                    connected_state: Some("CONNECTED".to_owned()),
                                    recovery_health: Some("ONLINE".to_owned()),
                                    synchronization_health: Some("HEALTHY".to_owned()),
                                    last_connect_error_number: None,
                                }),
                            })
                            .collect(),
                        databases: vec![DatabaseSnapshot {
                            identity: database.clone(),
                            local: Some(LocalDatabaseSnapshot {
                                database_id: 5,
                                replica_id: guid(10),
                                state: Some("ONLINE".to_owned()),
                                recovery_model: Some("FULL".to_owned()),
                                recovery: Some(LocalRecoveryMetadata {
                                    database_guid: Some(probe.database_guid.clone()),
                                    family_guid: Some(guid(300)),
                                    recovery_fork_guid: Some(guid(200)),
                                    first_recovery_fork_guid: Some(guid(200)),
                                    fork_point_lsn: None,
                                }),
                            }),
                            replicas: vec![DatabaseReplicaSnapshot {
                                group_database_id: guid(2),
                                replica_id: guid(10),
                                database_id: 5,
                                provenance: NativeProvenance::Local,
                                lineage: RecoveryLineageObservation::Local {
                                    value: DatabaseLineage {
                                        database,
                                        recovery_fork_id: guid(200),
                                    },
                                },
                                is_primary_replica: Some(true),
                                synchronization_state: Some("SYNCHRONIZED".to_owned()),
                                synchronization_health: Some("HEALTHY".to_owned()),
                                database_state: Some("ONLINE".to_owned()),
                                is_suspended: Some(false),
                                suspend_reason: None,
                                is_commit_participant: Some(true),
                                progress: NativeProgress {
                                    hardened_block: Some(DecimalProgress::parse("10").unwrap()),
                                    redone_record: Some(DecimalProgress::parse("10").unwrap()),
                                    committed_record: Some(DecimalProgress::parse("10").unwrap()),
                                },
                            }],
                        }],
                        automatic_seeding: Vec::new(),
                        physical_seeding: Vec::new(),
                    },
                };
            }
            NodeEvidence {
                identity: member.identity.clone(),
                server_name: member.server_name.clone(),
                endpoint: member.endpoint.clone(),
                instance: Observation::Present {
                    value: snapshot,
                    observed_at_unix_millis: now,
                },
                database: if index == 0 {
                    Observation::Present {
                        value: probe,
                        observed_at_unix_millis: now,
                    }
                } else {
                    Observation::Absent {
                        observed_at_unix_millis: now,
                    }
                },
            }
        })
        .collect()
}

fn enabled(path: &std::path::Path, state: Arc<Mutex<State>>) -> AgAdapter<Backend, Verifier> {
    AgAdapter::new(
        OperationJournal::open(path, "resource").unwrap(),
        Backend(state.clone()),
    )
    .with_verifier(Verifier(state))
    .with_mode(MutationMode::Enabled)
}

#[tokio::test]
async fn observe_only_proposes_without_recording_or_authorizing_effects() {
    let directory = tempfile::tempdir().unwrap();
    let state = Arc::new(Mutex::new(State::default()));
    let mut adapter = AgAdapter::new(
        OperationJournal::open(&directory.path().join("journal"), "resource").unwrap(),
        Backend(state.clone()),
    );
    assert!(matches!(
        adapter
            .reconcile(&request("operation"), &authority())
            .await
            .unwrap(),
        AdapterOutcome::Proposed(_)
    ));
    assert!(adapter.journal().authority().unwrap().is_none());
    assert!(adapter.journal().entry("operation").unwrap().is_none());
    assert_eq!(state.lock().unwrap().effects, 0);
}

#[tokio::test]
async fn enabled_mode_does_not_override_default_denial_or_poison_authority() {
    let directory = tempfile::tempdir().unwrap();
    let state = Arc::new(Mutex::new(State::default()));
    let mut adapter = AgAdapter::new(
        OperationJournal::open(&directory.path().join("journal"), "resource").unwrap(),
        Backend(state.clone()),
    )
    .with_mode(MutationMode::Enabled);
    assert!(matches!(
        adapter.reconcile(&request("operation"), &authority()).await,
        Err(AdapterError::Runtime(_))
    ));
    assert!(adapter.journal().authority().unwrap().is_none());
    assert!(adapter.journal().entry("operation").unwrap().is_none());
    assert_eq!(state.lock().unwrap().observations, 0);
}

#[tokio::test]
async fn preparation_dispatch_and_completion_use_distinct_calls_and_survive_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal");
    let state = Arc::new(Mutex::new(State::default()));
    let mut adapter = enabled(&path, state.clone());
    let envelope = request("operation");
    assert!(matches!(
        adapter.reconcile(&envelope, &authority()).await.unwrap(),
        AdapterOutcome::Prepared(_)
    ));
    assert_eq!(state.lock().unwrap().effects, 0);
    drop(adapter);
    let mut adapter = enabled(&path, state.clone());
    assert!(matches!(
        adapter.reconcile(&envelope, &authority()).await.unwrap(),
        AdapterOutcome::Dispatched(_)
    ));
    assert!(
        adapter
            .journal()
            .entry("operation")
            .unwrap()
            .unwrap()
            .terminal_result
            .is_none()
    );
    assert!(matches!(
        adapter.reconcile(&envelope, &authority()).await.unwrap(),
        AdapterOutcome::Complete {
            replayed: false,
            retained: true,
            ..
        }
    ));
    drop(adapter);
    state.lock().unwrap().fail_observation = true;
    let mut adapter = enabled(&path, state.clone());
    assert!(matches!(
        adapter.reconcile(&envelope, &authority()).await.unwrap(),
        AdapterOutcome::Complete { replayed: true, .. }
    ));
    assert_eq!(state.lock().unwrap().effects, 1);
}

#[tokio::test]
async fn lost_sql_reply_is_resolved_by_observation_without_reexecuting() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal");
    let state = Arc::new(Mutex::new(State {
        fail_after_effect: true,
        ..State::default()
    }));
    let envelope = request("operation");
    let mut adapter = enabled(&path, state.clone());
    assert!(matches!(
        adapter.reconcile(&envelope, &authority()).await.unwrap(),
        AdapterOutcome::Prepared(_)
    ));
    assert!(matches!(
        adapter.reconcile(&envelope, &authority()).await,
        Err(AdapterError::Runtime(_))
    ));
    assert_eq!(
        adapter
            .journal()
            .entry("operation")
            .unwrap()
            .unwrap()
            .pending_intents()
            .count(),
        1
    );
    drop(adapter);
    let mut adapter = enabled(&path, state.clone());
    assert!(matches!(
        adapter.reconcile(&envelope, &authority()).await.unwrap(),
        AdapterOutcome::Complete {
            replayed: false,
            ..
        }
    ));
    assert_eq!(state.lock().unwrap().effects, 1);
}

#[tokio::test]
async fn preparation_cannot_be_retargeted_to_a_recreated_primary_database() {
    let directory = tempfile::tempdir().unwrap();
    let state = Arc::new(Mutex::new(State::default()));
    let mut adapter = enabled(&directory.path().join("journal"), state.clone());
    let envelope = request("operation");
    assert!(matches!(
        adapter.reconcile(&envelope, &authority()).await.unwrap(),
        AdapterOutcome::Prepared(_)
    ));
    state.lock().unwrap().database_generation += 1;
    assert!(matches!(
        adapter.reconcile(&envelope, &authority()).await,
        Err(AdapterError::Journal(JournalError::ActionConflict))
    ));
    assert_eq!(state.lock().unwrap().effects, 0);
}

#[tokio::test]
async fn changed_database_after_ambiguous_create_does_not_complete_the_old_intent() {
    let directory = tempfile::tempdir().unwrap();
    let state = Arc::new(Mutex::new(State {
        fail_after_effect: true,
        ..State::default()
    }));
    let mut adapter = enabled(&directory.path().join("journal"), state.clone());
    let envelope = request("operation");
    adapter.reconcile(&envelope, &authority()).await.unwrap();
    assert!(adapter.reconcile(&envelope, &authority()).await.is_err());
    state.lock().unwrap().database_generation += 1;
    assert!(matches!(
        adapter.reconcile(&envelope, &authority()).await.unwrap(),
        AdapterOutcome::Unsafe(_)
    ));
    assert!(
        adapter
            .journal()
            .entry("operation")
            .unwrap()
            .unwrap()
            .terminal_result
            .is_none()
    );
}

#[tokio::test]
async fn equivalent_new_id_reobserves_but_never_borrows_or_redispatches_a_result() {
    let directory = tempfile::tempdir().unwrap();
    let state = Arc::new(Mutex::new(State::default()));
    let mut adapter = enabled(&directory.path().join("journal"), state.clone());
    let original = request("original");
    adapter.reconcile(&original, &authority()).await.unwrap();
    assert!(matches!(
        adapter
            .reconcile(&request("pending-alias"), &authority())
            .await
            .unwrap(),
        AdapterOutcome::Wait(_)
    ));
    assert!(adapter.journal().entry("pending-alias").unwrap().is_none());
    adapter.reconcile(&original, &authority()).await.unwrap();
    adapter.reconcile(&original, &authority()).await.unwrap();
    let observations = state.lock().unwrap().observations;
    assert!(matches!(
        adapter
            .reconcile(&request("alias"), &authority())
            .await
            .unwrap(),
        AdapterOutcome::Complete {
            replayed: false,
            retained: true,
            ..
        }
    ));
    assert!(state.lock().unwrap().observations > observations);
    assert_eq!(state.lock().unwrap().effects, 1);
    state.lock().unwrap().group_generation = 500;
    assert!(matches!(
        adapter
            .reconcile(&request("drifted-alias"), &authority())
            .await
            .unwrap(),
        AdapterOutcome::Unsafe(_)
    ));
    assert!(adapter.journal().entry("drifted-alias").unwrap().is_none());
}

#[tokio::test]
async fn authority_is_rechecked_after_preparation_before_native_dispatch() {
    let directory = tempfile::tempdir().unwrap();
    let state = Arc::new(Mutex::new(State::default()));
    let mut adapter = enabled(&directory.path().join("journal"), state.clone());
    let envelope = request("operation");
    adapter.reconcile(&envelope, &authority()).await.unwrap();
    state.lock().unwrap().deny = true;
    assert!(adapter.reconcile(&envelope, &authority()).await.is_err());
    assert_eq!(state.lock().unwrap().effects, 0);
    assert_eq!(
        adapter
            .journal()
            .entry("operation")
            .unwrap()
            .unwrap()
            .pending_intents()
            .count(),
        1
    );
}

#[tokio::test]
async fn a_journal_write_failure_prevents_dispatch() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal");
    let state = Arc::new(Mutex::new(State::default()));
    let mut adapter = enabled(&path, state.clone());
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute_batch("CREATE TRIGGER fail_intent BEFORE INSERT ON actions BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
    assert!(matches!(
        adapter.reconcile(&request("operation"), &authority()).await,
        Err(AdapterError::Journal(_))
    ));
    assert_eq!(state.lock().unwrap().effects, 0);
    connection
        .execute_batch("DROP TRIGGER fail_intent;")
        .unwrap();
    assert!(matches!(
        adapter
            .reconcile(&request("operation"), &authority())
            .await
            .unwrap(),
        AdapterOutcome::Prepared(_)
    ));
}

#[tokio::test]
async fn terminal_storage_failure_recovers_without_repeating_the_native_effect() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal");
    let state = Arc::new(Mutex::new(State::default()));
    let mut adapter = enabled(&path, state.clone());
    let envelope = request("operation");
    adapter.reconcile(&envelope, &authority()).await.unwrap();
    adapter.reconcile(&envelope, &authority()).await.unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute_batch("CREATE TRIGGER fail_result BEFORE UPDATE ON operations WHEN NEW.result IS NOT NULL BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
    assert!(matches!(
        adapter.reconcile(&envelope, &authority()).await,
        Err(AdapterError::Journal(_))
    ));
    assert!(
        adapter
            .journal()
            .entry("operation")
            .unwrap()
            .unwrap()
            .terminal_result
            .is_none()
    );
    connection
        .execute_batch("DROP TRIGGER fail_result;")
        .unwrap();
    drop(connection);
    drop(adapter);
    let mut adapter = enabled(&path, state.clone());
    assert!(matches!(
        adapter.reconcile(&envelope, &authority()).await.unwrap(),
        AdapterOutcome::Complete { .. }
    ));
    assert_eq!(state.lock().unwrap().effects, 1);
}

#[tokio::test]
async fn an_acknowledgement_write_failure_is_still_an_uncertain_native_outcome() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal");
    let state = Arc::new(Mutex::new(State::default()));
    let mut adapter = enabled(&path, state.clone());
    let envelope = request("operation");
    adapter.reconcile(&envelope, &authority()).await.unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute_batch(
        "CREATE TRIGGER fail_ack BEFORE INSERT ON actions WHEN NEW.acknowledged = 1 BEGIN SELECT RAISE(ABORT, 'injected failure'); END;"
    ).unwrap();
    assert!(matches!(
        adapter.reconcile(&envelope, &authority()).await,
        Err(AdapterError::Journal(_))
    ));
    assert_eq!(state.lock().unwrap().effects, 1);
    assert_eq!(
        adapter
            .journal()
            .entry("operation")
            .unwrap()
            .unwrap()
            .pending_intents()
            .count(),
        1
    );
    connection.execute_batch("DROP TRIGGER fail_ack;").unwrap();
    assert!(matches!(
        adapter.reconcile(&envelope, &authority()).await.unwrap(),
        AdapterOutcome::Complete { .. }
    ));
    assert_eq!(state.lock().unwrap().effects, 1);
}

#[tokio::test]
async fn slow_verification_does_not_prepare_or_dispatch_stale_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let state = Arc::new(Mutex::new(State {
        action_delay_ms: 400,
        ..State::default()
    }));
    let mut adapter = enabled(&directory.path().join("journal"), state.clone())
        .with_max_age_millis(200)
        .unwrap();
    let envelope = request("operation");
    assert!(matches!(
        adapter.reconcile(&envelope, &authority()).await.unwrap(),
        AdapterOutcome::Wait(_)
    ));
    let checked = state.lock().unwrap();
    assert_eq!(checked.action_checks, 1);
    assert_eq!(checked.effects, 0);
    assert!(adapter.journal().entry("operation").unwrap().is_none());
    assert!(adapter.journal().authority().unwrap().is_none());
}
