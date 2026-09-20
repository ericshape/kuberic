use std::collections::BTreeSet;

use sqlserver_replicated::convergence::{
    AcceptedAuthority, DatabaseProbe, Decision, NativeAction, NodeEvidence, plan,
};
use sqlserver_replicated::observation::{
    AutomaticSeedingSnapshot, AvailabilityGroupSnapshot, DatabaseReplicaSnapshot, InstanceMetadata,
    NativeProvenance, PhysicalSeedingSnapshot, RecoveryLineageObservation,
};
use sqlserver_replicated::{
    AvailabilityGroupName, DatabaseIdentity, DatabaseLineage, DecimalProgress, Endpoint,
    NativeRole, Observation, ObservationFailure, ObservationFailureKind, OpaqueId,
    OperationEnvelope, OperationPayload, OperationRequest, ReplicaIdentity, ServerName,
};

#[path = "support/convergence.rs"]
mod fixtures;
use fixtures::*;

const NOW: u64 = 1_000;
const MAX_AGE: u64 = 100;

fn ack(keys: &[&str]) -> BTreeSet<String> {
    keys.iter().map(|key| (*key).to_owned()).collect()
}

fn decide(payload: OperationPayload, nodes: &[NodeEvidence], keys: &[&str]) -> Decision {
    plan(
        &envelope(payload),
        &authority(),
        nodes,
        &ack(keys),
        NOW,
        MAX_AGE,
    )
}

fn action(decision: Decision, key: &str) -> NativeAction {
    match decision {
        Decision::Execute(action) => {
            assert_eq!(action.key(), key);
            action
        }
        other => panic!("expected {key}, got {other:?}"),
    }
}

fn wait(decision: Decision) {
    assert!(
        matches!(decision, Decision::Wait(_)),
        "expected wait, got {decision:?}"
    );
}

fn unsafe_decision(decision: Decision) {
    assert!(
        matches!(decision, Decision::Unsafe(_)),
        "expected refusal, got {decision:?}"
    );
}

#[test]
fn bootstrap_creates_once_on_the_bound_designated_primary_with_canonical_membership() {
    let operation = envelope(bootstrap_payload(None));
    let mut accepted = authority();
    accepted.replicas.reverse();
    let first = action(
        plan(
            &operation,
            &accepted,
            &before_create_nodes(),
            &BTreeSet::new(),
            NOW,
            MAX_AGE,
        ),
        "create_availability_group",
    );
    assert_eq!(first.execution_target(), &desired(1));
    assert!(!first.is_destructive());
    match &first {
        NativeAction::CreateAvailabilityGroup {
            primary,
            name,
            database_name,
            write_lease_seconds,
            replicas,
            expected_database_id,
            expected_database_guid,
            expected_recovery_fork_id,
        } => {
            assert_eq!(primary, &desired(1));
            assert_eq!(name, &ag().name);
            assert_eq!(database_name, &database().name);
            assert_eq!(*write_lease_seconds, 30);
            assert_eq!(replicas, &authority().replicas);
            assert_eq!(*expected_database_id, 5);
            assert_eq!(expected_database_guid, &guid(201));
            assert_eq!(expected_recovery_fork_id, &guid(300));
        }
        _ => unreachable!(),
    }
    let second = action(
        decide(bootstrap_payload(None), &before_create_nodes(), &[]),
        "create_availability_group",
    );
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&second).unwrap()
    );
    wait(decide(
        bootstrap_payload(None),
        &before_create_nodes(),
        &["create_availability_group"],
    ));
}

#[test]
fn bootstrap_requires_fresh_absence_on_every_member_and_never_recreates_a_bound_guid() {
    let nodes = before_create_nodes();
    wait(decide(bootstrap_payload(None), &nodes[..2], &[]));
    unsafe_decision(decide(bootstrap_payload(Some(guid(10))), &nodes, &[]));
    let mut nodes = before_create_nodes();
    nodes[2] = existing(3, false);
    unsafe_decision(decide(bootstrap_payload(None), &nodes, &[]));
}

#[test]
fn bootstrap_requires_preprovisioned_online_full_backup_ready_unassociated_primary_database() {
    for state in ["RESTORING", "RECOVERY_PENDING", "UNKNOWN"] {
        let mut nodes = before_create_nodes();
        database_probe(&mut nodes[0]).state = state.into();
        wait(decide(bootstrap_payload(None), &nodes, &[]));
    }
    let mut nodes = before_create_nodes();
    database_probe(&mut nodes[0]).recovery_model = "SIMPLE".into();
    wait(decide(bootstrap_payload(None), &nodes, &[]));
    let mut nodes = before_create_nodes();
    database_probe(&mut nodes[0]).backup_ready = false;
    wait(decide(bootstrap_payload(None), &nodes, &[]));
    let mut nodes = before_create_nodes();
    nodes[0].database = absent();
    wait(decide(bootstrap_payload(None), &nodes, &[]));
    let mut nodes = before_create_nodes();
    nodes[0].database = present(probe(1, true));
    unsafe_decision(decide(bootstrap_payload(None), &nodes, &[]));
}

#[test]
fn bootstrap_refuses_secondary_same_named_databases_and_malformed_probe_ids() {
    let mut nodes = before_create_nodes();
    nodes[1].database = present(probe(2, false));
    unsafe_decision(decide(bootstrap_payload(None), &nodes, &[]));
    for id in [0, 4, u32::MAX] {
        let mut nodes = before_create_nodes();
        database_probe(&mut nodes[0]).database_id = id;
        unsafe_decision(decide(bootstrap_payload(None), &nodes, &[]));
    }
}

#[test]
fn existing_bootstrap_completion_requires_exact_native_topology_and_managed_database() {
    let nodes = seed_nodes();
    let Decision::Complete(result) = decide(bootstrap_payload(Some(guid(10))), &nodes, &[]) else {
        panic!("complete native bootstrap")
    };
    assert_eq!(result.availability_group, ag());
    assert_eq!(result.database, Some(database()));
    assert_eq!(result.replica, observed(1));
    assert_eq!(result.database_id, Some(5));
    assert_eq!(result.database_guid, Some(guid(201)));
    assert_eq!(result.recovery_fork_id, Some(guid(300)));
    assert_eq!(
        serde_json::to_value(result).unwrap()["availability_group"]["group_id"],
        guid(10).as_str()
    );
    unsafe_decision(decide(bootstrap_payload(Some(guid(999))), &nodes, &[]));
    let mut nodes = seed_nodes();
    group(&mut nodes[0]).replicas.pop();
    wait(decide(bootstrap_payload(None), &nodes, &[]));
    let mut nodes = seed_nodes();
    group(&mut nodes[0]).databases.clear();
    wait(decide(bootstrap_payload(None), &nodes, &[]));
    let mut nodes = seed_nodes();
    group(&mut nodes[0]).replicas[2].endpoint_url = Some("TCP://foreign.example:5022".into());
    unsafe_decision(decide(bootstrap_payload(None), &nodes, &[]));
}

#[test]
fn existing_bootstrap_does_not_adopt_a_foreign_secondary_database() {
    let mut nodes = seed_nodes();
    nodes[1].database = present(probe(2, false));
    unsafe_decision(decide(bootstrap_payload(None), &nodes, &[]));
    let mut nodes = seed_nodes();
    install_database(&mut nodes[1], 2, Some(probe(2, true)));
    assert!(matches!(
        decide(bootstrap_payload(None), &nodes, &[]),
        Decision::Complete(_)
    ));
}

#[test]
fn authority_binding_is_order_independent_but_includes_every_identity_and_epoch_dimension() {
    let original = authority();
    let mut shuffled = original.clone();
    shuffled.replicas.rotate_left(1);
    assert_eq!(original.canonical_binding(), shuffled.canonical_binding());
    let baseline = original.canonical_binding();
    let changes: &[fn(&mut AcceptedAuthority)] = &[
        |a| a.resource_id = OpaqueId::new("resource", "other").unwrap(),
        |a| a.configuration_id = OpaqueId::new("configuration", "other").unwrap(),
        |a| a.epoch += 1,
        |a| a.primary = desired(2),
        |a| {
            a.replicas[2].identity = ReplicaIdentity::desired("replica-3", "different-pod").unwrap()
        },
        |a| a.replicas[2].server_name = ServerName::new("different-server").unwrap(),
        |a| a.replicas[2].endpoint = Endpoint::new("different.example", 5022).unwrap(),
    ];
    for change in changes {
        let mut changed = original.clone();
        change(&mut changed);
        assert_ne!(baseline, changed.canonical_binding());
    }
}

#[test]
fn authority_rejects_wrong_membership_resource_configuration_epoch_and_bootstrap_primary() {
    let operation = envelope(bootstrap_payload(None));
    let changes: &[fn(&mut AcceptedAuthority)] = &[
        |a| {
            a.replicas.pop();
        },
        |a| a.primary = observed(1),
        |a| a.primary = desired(2),
        |a| a.replicas[2].identity = observed(3),
        |a| a.replicas[2].identity = a.replicas[1].identity.clone(),
        |a| a.replicas[2].identity = ReplicaIdentity::desired("replica-3", "pod-2").unwrap(),
        |a| a.replicas[2].server_name = a.replicas[1].server_name.clone(),
        |a| a.replicas[2].endpoint = a.replicas[1].endpoint.clone(),
        |a| a.resource_id = OpaqueId::new("resource", "wrong").unwrap(),
        |a| a.configuration_id = OpaqueId::new("configuration", "wrong").unwrap(),
        |a| a.epoch = 8,
    ];
    for change in changes {
        let mut accepted = authority();
        change(&mut accepted);
        assert!(accepted.validate_for(&operation).is_err());
        unsafe_decision(plan(
            &operation,
            &accepted,
            &before_create_nodes(),
            &BTreeSet::new(),
            NOW,
            MAX_AGE,
        ));
    }
    let mut payload = bootstrap_payload(None);
    if let OperationPayload::EnsureAvailabilityGroup { replicas, .. } = &mut payload {
        replicas[2].endpoint = Endpoint::new("foreign.example", 5022).unwrap();
    }
    assert!(authority().validate_for(&envelope(payload)).is_err());
}

#[test]
fn convergence_never_advances_epochs_or_uses_a_non_designated_seeding_source() {
    let request = OperationRequest::new(
        "default/example",
        "operation-1",
        "configuration-1",
        7,
        8,
        seed_payload(),
    )
    .unwrap();
    let operation = OperationEnvelope::new(request, None, None).unwrap();
    assert!(authority().validate_for(&operation).is_err());
    let payload = OperationPayload::EnsureReplicaSeeded {
        availability_group: ag(),
        database: database(),
        source: observed(3),
        target: observed(2),
    };
    unsafe_decision(decide(payload, &seed_nodes(), &[]));
    let payload = OperationPayload::EnsureReplicaJoined {
        availability_group: ag(),
        target: observed(1),
    };
    unsafe_decision(decide(payload, &seed_nodes(), &[]));
}

#[test]
fn v1_and_both_primary_transition_payloads_are_refused() {
    assert!(
        OperationRequest::from_decoded_parts(
            1,
            "default/example",
            "op",
            "configuration-1",
            7,
            7,
            seed_payload()
        )
        .is_err()
    );
    for payload in [
        OperationPayload::PlannedSwitchover {
            availability_group: ag(),
            database: DatabaseLineage {
                database: database(),
                recovery_fork_id: guid(300),
            },
            source: observed(1),
            target: observed(2),
            target_configuration_id: OpaqueId::new("target configuration", "configuration-2")
                .unwrap(),
            commit_boundary: DecimalProgress::parse("9999999999999999999999999").unwrap(),
        },
        OperationPayload::ForcedFailover {
            availability_group: ag(),
            database: DatabaseLineage {
                database: database(),
                recovery_fork_id: guid(300),
            },
            source: observed(1),
            target: observed(2),
            target_configuration_id: OpaqueId::new("target configuration", "configuration-2")
                .unwrap(),
            last_known_commit: None,
        },
    ] {
        unsafe_decision(decide(payload, &seed_nodes(), &[]));
    }
}

#[test]
fn evidence_must_bind_exact_desired_incarnation_server_and_endpoint() {
    let changes: &[fn(&mut NodeEvidence)] = &[
        |n| n.identity = desired(99),
        |n| n.identity = observed(2),
        |n| n.identity = ReplicaIdentity::desired("replica-2", "old-pod").unwrap(),
        |n| n.server_name = ServerName::new("wrong-server").unwrap(),
        |n| n.endpoint = Endpoint::new("foreign.example", 5022).unwrap(),
        |n| snapshot(n).instance.server_name = ServerName::new("wrong-server").unwrap(),
        |n| snapshot(n).instance.property_server_name = ServerName::new("wrong-server").unwrap(),
        |n| {
            group(n).local_replica.identity =
                ReplicaIdentity::observed("replica-2", guid(102), "old-pod").unwrap()
        },
    ];
    for change in changes {
        let mut nodes = seed_nodes();
        change(&mut nodes[1]);
        unsafe_decision(decide(seed_payload(), &nodes, &[]));
    }
    let mut nodes = seed_nodes();
    nodes.push(nodes[1].clone());
    unsafe_decision(decide(seed_payload(), &nodes, &[]));
}

#[test]
fn unsupported_native_capability_evidence_is_not_actionable() {
    let changes: &[fn(&mut InstanceMetadata)] = &[
        |m| m.product_major_version = 17,
        |m| m.product_version = "17.0.1.1".into(),
        |m| m.edition = "Enterprise Evaluation Edition (64-bit)".into(),
        |m| m.engine_edition = 2,
        |m| m.hadr_enabled = false,
        |m| m.host_platform = "Windows".into(),
        |m| m.architecture = "aarch64".into(),
    ];
    for change in changes {
        let mut nodes = seed_nodes();
        change(&mut snapshot(&mut nodes[0]).instance);
        unsafe_decision(decide(seed_payload(), &nodes, &[]));
    }
}

#[test]
fn missing_failed_stale_and_future_evidence_never_establishes_completion() {
    let nodes = seed_nodes();
    wait(decide(seed_payload(), &nodes[..1], &[]));
    for field in 0..5 {
        let mut nodes = seed_nodes();
        match field {
            0 => nodes[1].instance = absent(),
            1 => nodes[1].instance = failed(),
            2 => nodes[1].database = failed(),
            3 => snapshot(&mut nodes[1]).availability_group = failed(),
            _ => nodes[0].database = absent(),
        }
        wait(decide(
            seed_payload(),
            &nodes,
            &["grant_seeding", "trigger_seeding"],
        ));
    }
    for time in [NOW - MAX_AGE - 1, NOW + 1] {
        let mut nodes = seed_nodes();
        if let Observation::Present {
            observed_at_unix_millis,
            ..
        } = &mut nodes[1].instance
        {
            *observed_at_unix_millis = time;
        }
        wait(decide(seed_payload(), &nodes, &[]));
        let mut nodes = seed_nodes();
        nodes[1].database = Observation::Absent {
            observed_at_unix_millis: time,
        };
        wait(decide(seed_payload(), &nodes, &[]));
    }
}

#[test]
fn inner_outer_snapshot_timestamp_mismatches_are_rejected() {
    let mut nodes = seed_nodes();
    snapshot(&mut nodes[1]).observed_at_unix_millis -= 1;
    unsafe_decision(decide(seed_payload(), &nodes, &[]));
    let mut nodes = seed_nodes();
    if let Observation::Present {
        observed_at_unix_millis,
        ..
    } = &mut snapshot(&mut nodes[1]).availability_group
    {
        *observed_at_unix_millis -= 1;
    }
    unsafe_decision(decide(seed_payload(), &nodes, &[]));
}

#[test]
fn duplicate_or_inconsistent_native_guids_endpoints_and_group_ids_are_refused() {
    let changes: &[fn(&mut AvailabilityGroupSnapshot)] = &[
        |g| g.replicas[2].replica_id = g.replicas[1].replica_id.clone(),
        |g| g.replicas[2].endpoint_url = g.replicas[1].endpoint_url.clone(),
        |g| g.replicas[2].server_name = g.replicas[1].server_name.clone(),
        |g| g.replicas[2].replica_id = guid(999),
        |g| g.identity.group_id = guid(999),
        |g| g.identity.name = AvailabilityGroupName::new("different-ag").unwrap(),
        |g| g.replicas[0].endpoint_url = Some("https://sql-1.sql.default.svc:5022".into()),
        |g| g.replicas[0].failover_mode = "MANUAL".into(),
        |g| g.replicas[0].availability_mode = "ASYNCHRONOUS_COMMIT".into(),
        |g| g.replicas[0].seeding_mode = "MANUAL".into(),
        |g| g.cluster_type = "NONE".into(),
        |g| g.required_synchronized_secondaries_to_commit = 0,
        |g| g.is_distributed = true,
    ];
    for change in changes {
        let mut nodes = seed_nodes();
        change(group(&mut nodes[0]));
        unsafe_decision(decide(seed_payload(), &nodes, &[]));
    }
    let mut nodes = seed_nodes();
    group(&mut nodes[0]).replicas[0].endpoint_url = None;
    wait(decide(seed_payload(), &nodes, &[]));
}

#[test]
fn join_requires_source_catalog_native_identity_and_allows_fresh_absent_target_discovery() {
    let mut nodes = seed_nodes();
    set_role(&mut nodes[1], None);
    let join = action(
        decide(join_payload(), &nodes, &[]),
        "join_availability_group",
    );
    assert_eq!(join.execution_target(), &observed(2));
    assert!(!join.is_destructive());
    wait(decide(join_payload(), &nodes, &["join_availability_group"]));
    snapshot(&mut nodes[1]).availability_group = absent();
    let join = action(
        decide(join_payload(), &nodes, &[]),
        "join_availability_group",
    );
    assert_eq!(join.execution_target(), &observed(2));
    wait(decide(join_payload(), &nodes, &["join_availability_group"]));
    let payload = OperationPayload::EnsureReplicaJoined {
        availability_group: ag(),
        target: ReplicaIdentity::observed("replica-2", guid(999), "pod-2").unwrap(),
    };
    unsafe_decision(decide(payload, &nodes, &[]));
}

#[test]
fn join_completes_from_fresh_secondary_identity_without_command_acknowledgment() {
    let Decision::Complete(result) = decide(join_payload(), &seed_nodes(), &[]) else {
        panic!("native join complete")
    };
    assert_eq!(result.replica, observed(2));
    assert_eq!(result.availability_group, ag());
    assert_eq!(result.database, None);
    assert_eq!(result.database_guid, None);
}

#[test]
fn native_roles_are_never_inferred_from_designated_authority_or_catalog_membership() {
    let mut nodes = seed_nodes();
    set_role(&mut nodes[1], Some(NativeRole::Primary));
    unsafe_decision(decide(join_payload(), &nodes, &[]));
    unsafe_decision(decide(seed_payload(), &nodes, &[]));
    let mut nodes = seed_nodes();
    set_role(&mut nodes[0], Some(NativeRole::Secondary));
    unsafe_decision(decide(seed_payload(), &nodes, &[]));
    for role in [
        Some(NativeRole::Resolving),
        Some(NativeRole::parse("FUTURE_ROLE").unwrap()),
        None,
    ] {
        let mut nodes = seed_nodes();
        set_role(&mut nodes[1], role);
        wait(decide(seed_payload(), &nodes, &[]));
    }
    let mut nodes = seed_nodes();
    set_role(
        &mut nodes[1],
        Some(NativeRole::parse("FUTURE_ROLE").unwrap()),
    );
    wait(decide(join_payload(), &nodes, &[]));
}

#[test]
fn seed_grants_then_triggers_on_primary_and_waits_for_native_completion_not_acks() {
    let nodes = seed_nodes();
    let grant = action(decide(seed_payload(), &nodes, &[]), "grant_seeding");
    assert_eq!(grant.execution_target(), &observed(2));
    let trigger = action(
        decide(seed_payload(), &nodes, &["grant_seeding"]),
        "trigger_seeding",
    );
    assert_eq!(trigger.execution_target(), &observed(1));
    assert!(!trigger.is_destructive());
    match trigger {
        NativeAction::TriggerSeeding {
            target_server_name,
            source,
            target,
            ..
        } => {
            assert_eq!(source, observed(1));
            assert_eq!(target, observed(2));
            assert_eq!(target_server_name, member(2).server_name);
        }
        _ => unreachable!(),
    }
    wait(decide(
        seed_payload(),
        &nodes,
        &["grant_seeding", "trigger_seeding"],
    ));
}

#[test]
fn seed_completes_only_from_exact_synchronized_local_native_postcondition() {
    let mut nodes = seed_nodes();
    install_database(&mut nodes[1], 2, Some(probe(2, true)));
    let Decision::Complete(result) = decide(seed_payload(), &nodes, &[]) else {
        panic!("native seed complete")
    };
    assert_eq!(result.database, Some(database()));
    assert_eq!(result.replica, observed(2));
    assert_eq!(result.database_guid, Some(guid(202)));
    assert_eq!(result.recovery_fork_id, Some(guid(300)));
    for change in [
        |state: &mut DatabaseReplicaSnapshot| {
            state.synchronization_state = Some("SYNCHRONIZING".into())
        },
        |state: &mut DatabaseReplicaSnapshot| {
            state.synchronization_health = Some("NOT_HEALTHY".into())
        },
        |state: &mut DatabaseReplicaSnapshot| state.is_suspended = Some(true),
        |state: &mut DatabaseReplicaSnapshot| state.is_suspended = None,
        |state: &mut DatabaseReplicaSnapshot| state.database_state = Some("RESTORING".into()),
        |state: &mut DatabaseReplicaSnapshot| state.is_primary_replica = None,
        |state: &mut DatabaseReplicaSnapshot| {
            state.synchronization_health = Some("FUTURE_HEALTH".into())
        },
    ] {
        let mut changed = nodes.clone();
        change(&mut group(&mut changed[1]).databases[0].replicas[0]);
        wait(decide(
            seed_payload(),
            &changed,
            &["grant_seeding", "trigger_seeding"],
        ));
    }
}

#[test]
fn seed_does_not_compare_progress_domains_or_narrow_native_decimal_values() {
    let mut nodes = seed_nodes();
    install_database(&mut nodes[1], 2, Some(probe(2, true)));
    let state = &mut group(&mut nodes[1]).databases[0].replicas[0];
    state.progress.hardened_block = Some(DecimalProgress::parse("0").unwrap());
    state.progress.redone_record =
        Some(DecimalProgress::parse("9999999999999999999999999").unwrap());
    state.progress.committed_record = None;
    assert!(matches!(
        decide(seed_payload(), &nodes, &[]),
        Decision::Complete(_)
    ));
}

#[test]
fn seed_refuses_unassociated_foreign_and_incompatible_fork_databases() {
    let mut nodes = seed_nodes();
    install_database(&mut nodes[1], 2, Some(probe(2, false)));
    unsafe_decision(decide(seed_payload(), &nodes, &[]));
    let mut nodes = seed_nodes();
    let mut wrong_fork = probe(2, true);
    wrong_fork.recovery_fork_id = guid(999);
    install_database(&mut nodes[1], 2, Some(wrong_fork));
    unsafe_decision(decide(seed_payload(), &nodes, &[]));
    let mut nodes = seed_nodes();
    nodes[1].database = present(probe(2, true));
    database_probe(&mut nodes[1]).group_database_id = Some(guid(999));
    unsafe_decision(decide(seed_payload(), &nodes, &[]));
}

#[test]
fn seed_requires_exact_source_database_native_identity_and_visible_lineage() {
    let mut nodes = seed_nodes();
    database_probe(&mut nodes[0]).database_guid = guid(999);
    unsafe_decision(decide(seed_payload(), &nodes, &[]));
    let mut nodes = seed_nodes();
    let source = &mut group(&mut nodes[0]).databases[0];
    source.local.as_mut().unwrap().recovery = None;
    source.replicas[0].lineage = RecoveryLineageObservation::LocalUnavailable;
    wait(decide(seed_payload(), &nodes, &[]));
    let payload = OperationPayload::EnsureReplicaSeeded {
        availability_group: ag(),
        database: DatabaseIdentity {
            name: database().name,
            group_database_id: guid(999),
        },
        source: observed(1),
        target: observed(2),
    };
    unsafe_decision(decide(payload, &seed_nodes(), &[]));
    let payload = OperationPayload::EnsureReplicaSeeded {
        availability_group: ag(),
        database: database(),
        source: ReplicaIdentity::observed("replica-1", guid(999), "pod-1").unwrap(),
        target: observed(2),
    };
    unsafe_decision(decide(payload, &seed_nodes(), &[]));
}

fn automatic(id: u32, state: Option<&str>, source: bool) -> AutomaticSeedingSnapshot {
    AutomaticSeedingSnapshot {
        group_database_id: database().group_database_id,
        remote_replica_id: guid(if source { 102 } else { 101 }),
        operation_id: guid(id),
        is_source: source,
        current_state: state.map(str::to_owned),
        performed_seeding: Some(true),
        failure_state: Some(0),
        error_code: Some(0),
        number_of_attempts: Some(1),
        start_time: Some("2026-08-01T10:00:00".into()),
        completion_time: None,
    }
}

fn physical() -> PhysicalSeedingSnapshot {
    PhysicalSeedingSnapshot {
        group_database_id: database().group_database_id,
        local_replica_id: guid(101),
        local_physical_seeding_id: guid(600),
        remote_physical_seeding_id: Some(guid(601)),
        local_database_id: 5,
        local_database_name: database().name,
        remote_machine_name: Some("not-a-native-replica-identity".into()),
        role: Some("Source".into()),
        internal_state: Some("Preparing".into()),
        transfer_rate_bytes_per_second: None,
        transferred_size_bytes: None,
        database_size_bytes: None,
        failure_code: Some(0),
        is_compression_enabled: Some(true),
        start_time_utc: Some("2026-08-01T10:00:00".into()),
        end_time_utc: None,
        estimate_time_complete_utc: None,
    }
}

#[test]
fn active_unknown_or_unordered_automatic_seeding_waits_without_issuing_effects() {
    for state in [
        Some("PENDING"),
        Some("SEEDING"),
        Some("IN_PROGRESS"),
        Some("FUTURE"),
        None,
    ] {
        let mut nodes = seed_nodes();
        group(&mut nodes[0])
            .automatic_seeding
            .push(automatic(500, state, true));
        wait(decide(seed_payload(), &nodes, &[]));
    }
    let mut nodes = seed_nodes();
    let mut unordered = automatic(500, Some("COMPLETED"), true);
    unordered.start_time = None;
    group(&mut nodes[0]).automatic_seeding.push(unordered);
    wait(decide(seed_payload(), &nodes, &[]));
    let mut nodes = seed_nodes();
    group(&mut nodes[0]).automatic_seeding.extend([
        automatic(500, Some("COMPLETED"), true),
        automatic(501, Some("COMPLETED"), true),
    ]);
    wait(decide(seed_payload(), &nodes, &[]));
}

#[test]
fn completed_seeding_history_is_not_database_completion_or_permission_grant_evidence() {
    let mut nodes = seed_nodes();
    group(&mut nodes[0])
        .automatic_seeding
        .push(automatic(500, Some("COMPLETED"), true));
    action(decide(seed_payload(), &nodes, &[]), "grant_seeding");
    wait(decide(
        seed_payload(),
        &nodes,
        &["grant_seeding", "trigger_seeding"],
    ));
}

#[test]
fn automatic_and_physical_seeding_failures_surface_explicitly() {
    for source in [true, false] {
        let mut nodes = seed_nodes();
        group(&mut nodes[usize::from(!source)])
            .automatic_seeding
            .push(automatic(500, Some("FAILED"), source));
        unsafe_decision(decide(seed_payload(), &nodes, &[]));
    }
    let mut nodes = seed_nodes();
    let mut seed = physical();
    seed.failure_code = Some(50000);
    seed.end_time_utc = Some("2026-08-01T10:00:01".into());
    group(&mut nodes[0]).physical_seeding.push(seed);
    unsafe_decision(decide(seed_payload(), &nodes, &[]));
}

#[test]
fn native_synced_postcondition_can_supersede_failed_historical_attempts() {
    let mut nodes = seed_nodes();
    install_database(&mut nodes[1], 2, Some(probe(2, true)));
    group(&mut nodes[0])
        .automatic_seeding
        .push(automatic(500, Some("FAILED"), true));
    assert!(matches!(
        decide(seed_payload(), &nodes, &[]),
        Decision::Complete(_)
    ));
    let mut nodes = seed_nodes();
    let old = automatic(500, Some("FAILED"), true);
    let mut recent = automatic(501, Some("IN_PROGRESS"), true);
    recent.start_time = Some("2026-08-01T10:00:01".into());
    group(&mut nodes[0]).automatic_seeding.extend([old, recent]);
    wait(decide(seed_payload(), &nodes, &[]));
}

#[test]
fn physical_seeding_is_a_conservative_barrier_without_invented_remote_guid_linkage() {
    let mut nodes = seed_nodes();
    group(&mut nodes[0]).physical_seeding.push(physical());
    wait(decide(seed_payload(), &nodes, &["grant_seeding"]));
    group(&mut nodes[0]).physical_seeding[0].end_time_utc = Some("2026-08-01T10:00:01".into());
    action(
        decide(seed_payload(), &nodes, &["grant_seeding"]),
        "trigger_seeding",
    );
}

#[test]
fn database_during_native_seeding_is_never_overwritten() {
    let mut nodes = seed_nodes();
    install_database(&mut nodes[1], 2, Some(probe(2, false)));
    group(&mut nodes[0])
        .automatic_seeding
        .push(automatic(500, Some("IN_PROGRESS"), true));
    wait(decide(seed_payload(), &nodes, &[]));
}

#[test]
fn reseed_is_not_complete_for_the_old_synchronized_database_and_preserves_exact_delete_guards() {
    let mut nodes = seed_nodes();
    install_database(&mut nodes[1], 2, Some(probe(2, true)));
    let detach = action(decide(reseed_payload(), &nodes, &[]), "detach_database");
    assert_eq!(detach.execution_target(), &observed(2));
    assert!(detach.is_destructive());
    match detach {
        NativeAction::DetachDatabase {
            availability_group,
            database: db,
            target,
            expected_database_id,
            expected_database_guid,
            expected_recovery_fork_id,
        } => {
            assert_eq!(availability_group, ag());
            assert_eq!(db, database());
            assert_eq!(target, observed(2));
            assert_eq!(expected_database_id, 5);
            assert_eq!(expected_database_guid, guid(202));
            assert_eq!(expected_recovery_fork_id, guid(300));
        }
        _ => unreachable!(),
    }
    wait(decide(reseed_payload(), &nodes, &["detach_database"]));
}

#[test]
fn reseed_converges_detach_drop_grant_trigger_native_replacement_one_action_at_a_time() {
    let mut nodes = seed_nodes();
    install_database(&mut nodes[1], 2, Some(probe(2, true)));
    action(decide(reseed_payload(), &nodes, &[]), "detach_database");
    install_database(&mut nodes[1], 2, Some(probe(2, false)));
    let drop = action(
        decide(reseed_payload(), &nodes, &["detach_database"]),
        "drop_database",
    );
    assert!(drop.is_destructive());
    assert_eq!(drop.execution_target(), &observed(2));
    wait(decide(
        reseed_payload(),
        &nodes,
        &["detach_database", "drop_database"],
    ));
    install_database(&mut nodes[1], 2, None);
    action(
        decide(
            reseed_payload(),
            &nodes,
            &["detach_database", "drop_database"],
        ),
        "grant_seeding",
    );
    action(
        decide(
            reseed_payload(),
            &nodes,
            &["detach_database", "drop_database", "grant_seeding"],
        ),
        "trigger_seeding",
    );
    let all = [
        "detach_database",
        "drop_database",
        "grant_seeding",
        "trigger_seeding",
    ];
    wait(decide(reseed_payload(), &nodes, &all));
    let mut replacement = probe(2, true);
    replacement.database_guid = guid(902);
    install_database(&mut nodes[1], 2, Some(replacement));
    let Decision::Complete(result) = decide(reseed_payload(), &nodes, &all) else {
        panic!("new native DB must complete reseed")
    };
    assert_eq!(result.database_guid, Some(guid(902)));
    assert_eq!(
        result.database_id,
        Some(5),
        "database IDs may be reused; database GUID must change"
    );
    assert!(matches!(
        decide(reseed_payload(), &nodes, &[]),
        Decision::Complete(_)
    ));
}

#[test]
fn reseed_resumes_from_native_absence_or_detachment_without_assuming_command_acknowledgments() {
    action(
        decide(reseed_payload(), &seed_nodes(), &[]),
        "grant_seeding",
    );
    let mut nodes = seed_nodes();
    install_database(&mut nodes[1], 2, Some(probe(2, false)));
    action(decide(reseed_payload(), &nodes, &[]), "drop_database");
}

#[test]
fn reseed_never_deletes_replacements_or_old_databases_with_mismatched_id_guid_or_fork() {
    for change in [
        |probe: &mut DatabaseProbe| probe.database_id = 6,
        |probe: &mut DatabaseProbe| probe.recovery_fork_id = guid(999),
    ] {
        let mut nodes = seed_nodes();
        let mut changed = probe(2, true);
        change(&mut changed);
        install_database(&mut nodes[1], 2, Some(changed));
        unsafe_decision(decide(reseed_payload(), &nodes, &[]));
    }
    let mut nodes = seed_nodes();
    let mut replacement = probe(2, true);
    replacement.database_guid = guid(902);
    install_database(&mut nodes[1], 2, Some(replacement));
    group(&mut nodes[1]).databases[0].replicas[0].synchronization_state =
        Some("SYNCHRONIZING".into());
    unsafe_decision(decide(reseed_payload(), &nodes, &[]));
    let mut nodes = seed_nodes();
    let mut replacement = probe(2, false);
    replacement.database_guid = guid(902);
    install_database(&mut nodes[1], 2, Some(replacement));
    unsafe_decision(decide(
        reseed_payload(),
        &nodes,
        &["detach_database", "drop_database"],
    ));
}

#[test]
fn explicit_reseed_can_replace_an_exact_bound_old_divergent_fork() {
    let mut nodes = seed_nodes();
    let mut source = probe(1, true);
    source.recovery_fork_id = guid(301);
    install_database(&mut nodes[0], 1, Some(source));
    install_database(&mut nodes[1], 2, Some(probe(2, true)));
    action(decide(reseed_payload(), &nodes, &[]), "detach_database");
}

#[test]
fn reseed_database_probe_and_native_catalog_disagreement_cannot_authorize_destruction() {
    let mut nodes = seed_nodes();
    install_database(&mut nodes[1], 2, Some(probe(2, true)));
    nodes[1].database = absent();
    wait(decide(reseed_payload(), &nodes, &[]));
    let mut nodes = seed_nodes();
    install_database(&mut nodes[1], 2, Some(probe(2, true)));
    database_probe(&mut nodes[1]).group_database_id = None;
    database_probe(&mut nodes[1]).replica_id = None;
    wait(decide(reseed_payload(), &nodes, &["detach_database"]));
}

#[test]
fn destructive_envelope_binding_is_required_but_is_not_real_fence_verification() {
    let request = OperationRequest::new(
        "default/example",
        "op",
        "configuration-1",
        7,
        7,
        reseed_payload(),
    )
    .unwrap();
    assert!(OperationEnvelope::new(request, None, None).is_err());
    let mut nodes = seed_nodes();
    install_database(&mut nodes[1], 2, Some(probe(2, true)));
    // Arbitrary matching receipt strings satisfy only structural binding. The
    // embedding adapter must still reject this action without real verification.
    assert!(action(decide(reseed_payload(), &nodes, &[]), "detach_database").is_destructive());
}

#[test]
fn acknowledged_action_keys_are_operation_scoped_and_cannot_fake_native_success() {
    unsafe_decision(decide(seed_payload(), &seed_nodes(), &["drop_database"]));
    unsafe_decision(decide(seed_payload(), &seed_nodes(), &["trigger_seeding"]));
    unsafe_decision(decide(join_payload(), &seed_nodes(), &["grant_seeding"]));
    wait(decide(
        reseed_payload(),
        &seed_nodes(),
        &["grant_seeding", "trigger_seeding"],
    ));
}

#[test]
fn duplicate_database_and_seeding_rows_or_forged_remote_lineage_are_refused() {
    let mut nodes = seed_nodes();
    let duplicate = group(&mut nodes[0]).databases[0].replicas[0].clone();
    group(&mut nodes[0]).databases[0].replicas.push(duplicate);
    unsafe_decision(decide(seed_payload(), &nodes, &[]));
    let mut nodes = seed_nodes();
    let repeated = automatic(500, Some("COMPLETED"), true);
    group(&mut nodes[0])
        .automatic_seeding
        .extend([repeated.clone(), repeated]);
    unsafe_decision(decide(seed_payload(), &nodes, &[]));
    let mut nodes = seed_nodes();
    let mut remote = group(&mut nodes[0]).databases[0].replicas[0].clone();
    remote.replica_id = guid(102);
    remote.provenance = NativeProvenance::PrimaryRemote;
    group(&mut nodes[0]).databases[0].replicas.push(remote);
    unsafe_decision(decide(seed_payload(), &nodes, &[]));
}

#[test]
fn source_and_target_only_evidence_is_sufficient_for_non_bootstrap_operations() {
    let nodes = seed_nodes();
    action(decide(seed_payload(), &nodes[..2], &[]), "grant_seeding");
    assert!(matches!(
        decide(join_payload(), &nodes[..2], &[]),
        Decision::Complete(_)
    ));
}

#[test]
fn operation_incarnations_must_match_authority_even_when_native_guids_match() {
    for (source, target) in [
        (
            ReplicaIdentity::observed("replica-1", guid(101), "old-pod").unwrap(),
            observed(2),
        ),
        (
            observed(1),
            ReplicaIdentity::observed("replica-2", guid(102), "old-pod").unwrap(),
        ),
    ] {
        unsafe_decision(decide(
            OperationPayload::EnsureReplicaSeeded {
                availability_group: ag(),
                database: database(),
                source,
                target,
            },
            &seed_nodes(),
            &[],
        ));
    }
}

#[test]
fn seeding_failures_are_not_masked_by_other_in_progress_observations() {
    let mut nodes = seed_nodes();
    group(&mut nodes[0])
        .automatic_seeding
        .push(automatic(500, Some("IN_PROGRESS"), true));
    group(&mut nodes[1])
        .automatic_seeding
        .push(automatic(501, Some("FAILED"), false));
    unsafe_decision(decide(seed_payload(), &nodes, &[]));
    let mut nodes = seed_nodes();
    group(&mut nodes[0])
        .automatic_seeding
        .push(automatic(500, Some("IN_PROGRESS"), true));
    let mut failed = physical();
    failed.failure_code = Some(50000);
    group(&mut nodes[0]).physical_seeding.push(failed);
    unsafe_decision(decide(seed_payload(), &nodes, &[]));
}

#[test]
fn unknown_physical_seeding_outcome_or_role_does_not_authorize_a_new_attempt() {
    for unknown_role in [false, true] {
        let mut nodes = seed_nodes();
        let mut unknown = physical();
        unknown.end_time_utc = Some("2026-08-01T10:00:01".into());
        if unknown_role {
            unknown.role = Some("FUTURE_ROLE".into());
        } else {
            unknown.failure_code = None;
        }
        group(&mut nodes[0]).physical_seeding.push(unknown);
        wait(decide(seed_payload(), &nodes, &[]));
    }
}

#[test]
fn contradictory_primary_flags_cannot_authorize_destructive_reseed() {
    let mut nodes = seed_nodes();
    install_database(&mut nodes[1], 2, Some(probe(2, true)));
    group(&mut nodes[1]).databases[0].replicas[0].is_primary_replica = Some(true);
    unsafe_decision(decide(reseed_payload(), &nodes, &[]));
}

#[test]
fn a_separate_probe_does_not_invent_missing_lineage_for_local_progress() {
    let mut nodes = seed_nodes();
    install_database(&mut nodes[1], 2, Some(probe(2, true)));
    let target = &mut group(&mut nodes[1]).databases[0];
    target.local.as_mut().unwrap().recovery = None;
    target.replicas[0].lineage = RecoveryLineageObservation::LocalUnavailable;
    wait(decide(seed_payload(), &nodes, &[]));
}

#[test]
fn failure_diagnostics_do_not_copy_server_supplied_error_text() {
    const CANARY: &str = "sensitive-server-error-text";
    let mut nodes = seed_nodes();
    nodes[1].instance = Observation::Failed(ObservationFailure {
        kind: ObservationFailureKind::Malformed,
        message: CANARY.into(),
        observed_at_unix_millis: TIME,
    });
    let decision = decide(seed_payload(), &nodes, &[]);
    assert!(matches!(decision, Decision::Wait(_)));
    assert!(!format!("{decision:?}").contains(CANARY));
}

#[test]
fn create_actions_journal_each_primary_database_dispatch_guard_without_changing_the_request() {
    let operation = envelope(bootstrap_payload(None));
    let request_bytes = operation.canonical_input();
    let original = action(
        decide(bootstrap_payload(None), &before_create_nodes(), &[]),
        "create_availability_group",
    );
    let original_json = serde_json::to_value(&original).unwrap();
    assert_eq!(original_json["expected_database_id"], 5);
    assert_eq!(original_json["expected_database_guid"], guid(201).as_str());
    assert_eq!(
        original_json["expected_recovery_fork_id"],
        guid(300).as_str()
    );
    for field in [
        "expected_database_id",
        "expected_database_guid",
        "expected_recovery_fork_id",
    ] {
        let mut nodes = before_create_nodes();
        let primary = database_probe(&mut nodes[0]);
        match field {
            "expected_database_id" => primary.database_id = 6,
            "expected_database_guid" => primary.database_guid = guid(901),
            "expected_recovery_fork_id" => primary.recovery_fork_id = guid(902),
            _ => unreachable!(),
        }
        let changed = action(
            plan(
                &operation,
                &authority(),
                &nodes,
                &BTreeSet::new(),
                NOW,
                MAX_AGE,
            ),
            "create_availability_group",
        );
        assert_ne!(original, changed);
        assert_ne!(
            original_json[field],
            serde_json::to_value(&changed).unwrap()[field]
        );
        assert_eq!(operation.canonical_input(), request_bytes);
        assert_eq!(serde_json::to_value(&original).unwrap(), original_json);
    }
}

#[test]
fn absent_target_join_still_requires_primary_role_complete_topology_and_bound_endpoints() {
    let mut nodes = seed_nodes();
    snapshot(&mut nodes[1]).availability_group = absent();
    action(
        decide(join_payload(), &nodes, &[]),
        "join_availability_group",
    );
    let mut missing_primary = nodes.clone();
    snapshot(&mut missing_primary[0]).availability_group = absent();
    wait(decide(join_payload(), &missing_primary, &[]));
    let mut wrong_primary = nodes.clone();
    set_role(&mut wrong_primary[0], Some(NativeRole::Secondary));
    unsafe_decision(decide(join_payload(), &wrong_primary, &[]));
    let mut partial = nodes.clone();
    group(&mut partial[0]).replicas.pop();
    wait(decide(join_payload(), &partial, &[]));
    let mut wrong_endpoint = nodes.clone();
    group(&mut wrong_endpoint[0]).replicas[2].endpoint_url =
        Some("TCP://unaccepted.example:5022".into());
    unsafe_decision(decide(join_payload(), &wrong_endpoint, &[]));
    snapshot(&mut nodes[1]).availability_group = failed();
    wait(decide(join_payload(), &nodes, &[]));
}

#[test]
fn absent_or_unexpected_join_postconditions_never_enable_seeding_or_grants() {
    let mut nodes = seed_nodes();
    snapshot(&mut nodes[1]).availability_group = absent();
    action(
        decide(join_payload(), &nodes, &[]),
        "join_availability_group",
    );
    wait(decide(join_payload(), &nodes, &["join_availability_group"]));
    wait(decide(seed_payload(), &nodes, &[]));
    wait(decide(
        seed_payload(),
        &nodes,
        &["grant_seeding", "trigger_seeding"],
    ));
    nodes[1] = existing(2, false);
    group(&mut nodes[1]).identity.group_id = guid(999);
    unsafe_decision(decide(join_payload(), &nodes, &["join_availability_group"]));
    unsafe_decision(decide(seed_payload(), &nodes, &[]));
    nodes[1] = existing(2, false);
    let unexpected = group(&mut nodes[1]);
    unexpected.local_replica.identity =
        ReplicaIdentity::observed("replica-2", guid(999), "pod-2").unwrap();
    unexpected.replicas[1].replica_id = guid(999);
    unsafe_decision(decide(join_payload(), &nodes, &["join_availability_group"]));
    unsafe_decision(decide(seed_payload(), &nodes, &[]));
    nodes[1] = existing(2, false);
    assert!(matches!(
        decide(join_payload(), &nodes, &["join_availability_group"]),
        Decision::Complete(_)
    ));
    action(decide(seed_payload(), &nodes, &[]), "grant_seeding");
}

#[test]
fn terminal_postconditions_contain_only_stable_native_identities_across_aliases_and_samples() {
    let mut nodes = seed_nodes();
    let baseline = decide(bootstrap_payload(Some(guid(10))), &nodes, &[]);
    let Decision::Complete(postcondition) = &baseline else {
        panic!("native bootstrap must be complete")
    };
    let fields = serde_json::to_value(postcondition).unwrap();
    assert_eq!(
        fields
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "availability_group",
            "database",
            "replica",
            "database_id",
            "database_guid",
            "recovery_fork_id",
        ])
    );
    for node in &mut nodes {
        if let Observation::Present {
            value,
            observed_at_unix_millis,
        } = &mut node.instance
        {
            *observed_at_unix_millis += 10;
            value.observed_at_unix_millis += 10;
            if let Observation::Present {
                value: native,
                observed_at_unix_millis,
            } = &mut value.availability_group
            {
                *observed_at_unix_millis += 10;
                native.configuration_sequence = DecimalProgress::parse("9007199254740994").unwrap();
                for replica in &mut native.replicas {
                    if let Some(state) = &mut replica.state {
                        state.synchronization_health = Some("PARTIALLY_HEALTHY".into());
                    }
                }
            }
        }
        match &mut node.database {
            Observation::Present {
                observed_at_unix_millis,
                ..
            }
            | Observation::Absent {
                observed_at_unix_millis,
            } => *observed_at_unix_millis += 10,
            Observation::Failed(_) => unreachable!(),
        }
    }
    let alias = OperationEnvelope::new(
        OperationRequest::new(
            "default/example",
            "alias-operation",
            "configuration-1",
            7,
            7,
            bootstrap_payload(Some(guid(10))),
        )
        .unwrap(),
        None,
        None,
    )
    .unwrap();
    assert_eq!(
        baseline,
        plan(&alias, &authority(), &nodes, &BTreeSet::new(), NOW, MAX_AGE)
    );
}

#[test]
fn shared_scenario_fixtures_bind_all_observation_timestamps_and_expected_first_actions() {
    type FixtureBuilder = fn(u64) -> fixtures::ConvergenceFixture;
    let scenarios = [
        (
            fixtures::bootstrap as FixtureBuilder,
            "create_availability_group",
        ),
        (fixtures::join as FixtureBuilder, "join_availability_group"),
        (fixtures::seed as FixtureBuilder, "grant_seeding"),
        (fixtures::reseed as FixtureBuilder, "detach_database"),
    ];
    for timestamp in [0, 42_000, 1_700_000_000_000] {
        let mut operation_ids = BTreeSet::new();
        for (builder, key) in scenarios {
            let (operation, accepted, nodes) = builder(timestamp);
            accepted.validate_for(&operation).unwrap();
            assert!(operation_ids.insert(operation.operation_id().to_owned()));
            assert_eq!(nodes.len(), 3);
            for node in &nodes {
                assert_eq!(node.instance.observed_at_unix_millis(), timestamp);
                assert_eq!(node.database.observed_at_unix_millis(), timestamp);
                let Observation::Present { value, .. } = &node.instance else {
                    panic!("fixture instance must be present")
                };
                assert_eq!(value.observed_at_unix_millis, timestamp);
                assert_eq!(
                    value.availability_group.observed_at_unix_millis(),
                    timestamp
                );
            }
            action(
                plan(
                    &operation,
                    &accepted,
                    &nodes,
                    &BTreeSet::new(),
                    timestamp,
                    0,
                ),
                key,
            );
            wait(plan(
                &operation,
                &accepted,
                &nodes,
                &BTreeSet::new(),
                timestamp + 1,
                0,
            ));
        }
    }
}

#[test]
fn shared_database_transition_helpers_preserve_parameterized_sample_times() {
    let timestamp = 42_000;
    let (operation, accepted, mut nodes) = fixtures::seed(timestamp);
    fixtures::install_database(&mut nodes[1], 2, Some(fixtures::probe(2, true)));
    assert_eq!(nodes[1].database.observed_at_unix_millis(), timestamp);
    assert!(matches!(
        plan(
            &operation,
            &accepted,
            &nodes,
            &BTreeSet::new(),
            timestamp,
            0
        ),
        Decision::Complete(_)
    ));
    wait(plan(
        &operation,
        &accepted,
        &nodes,
        &BTreeSet::new(),
        timestamp + 1,
        0,
    ));
}

#[test]
fn backup_readiness_is_not_serialized_as_evidence_of_a_completed_log_backup() {
    let evidence = serde_json::to_value(fixtures::probe(1, false)).unwrap();
    assert_eq!(evidence["backup_ready"], true);
    assert!(evidence.get("has_log_backup").is_none());
    let (operation, accepted, mut nodes) = fixtures::bootstrap(NOW);
    database_probe(&mut nodes[0]).backup_ready = false;
    let Decision::Wait(message) = plan(
        &operation,
        &accepted,
        &nodes,
        &BTreeSet::new(),
        NOW,
        MAX_AGE,
    ) else {
        panic!("uninitialized backup metadata must block bootstrap")
    };
    assert!(message.contains("initialized log-backup metadata"));
}
