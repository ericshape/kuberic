//! Synthetic native evidence shared by planner and adapter integration tests.
//! Approval/fence references establish structural binding only, not authority.

// Each integration-test binary uses a different subset of these builders.
#![allow(dead_code)]

use sqlserver_replicated::convergence::{AcceptedAuthority, DatabaseProbe, NodeEvidence};
use sqlserver_replicated::observation::{
    AvailabilityGroupSnapshot, DatabaseReplicaSnapshot, DatabaseSnapshot, InstanceMetadata,
    InstanceSnapshot, LocalDatabaseSnapshot, LocalRecoveryMetadata, LocalReplicaSnapshot,
    NativeProvenance, RecoveryLineageObservation, ReplicaSnapshot, ReplicaState,
};
use sqlserver_replicated::{
    AvailabilityGroupIdentity, AvailabilityGroupName, DatabaseIdentity, DatabaseLineage,
    DecimalProgress, DestructiveApproval, Endpoint, FenceReference, Guid, NativeProgress,
    NativeRole, Observation, ObservationFailure, ObservationFailureKind, OpaqueId,
    OperationEnvelope, OperationPayload, OperationRequest, ReplicaDescriptor, ReplicaIdentity,
    ServerName, SqlIdentifier,
};

pub const TIME: u64 = 950;
pub type ConvergenceFixture = (OperationEnvelope, AcceptedAuthority, Vec<NodeEvidence>);

/// All AGs absent, primary database pre-provisioned and backup-ready.
pub fn bootstrap(observed_at_ms: u64) -> ConvergenceFixture {
    fixture(
        "bootstrap-1",
        bootstrap_payload(None),
        before_create_nodes(),
        observed_at_ms,
    )
}

/// Primary catalog defines the target's GUID; target AG discovery is absent.
pub fn join(observed_at_ms: u64) -> ConvergenceFixture {
    let mut nodes = seed_nodes();
    snapshot(&mut nodes[1]).availability_group = absent();
    fixture("join-1", join_payload(), nodes, observed_at_ms)
}

/// Target is SECONDARY with no local managed database; the next step is grant.
pub fn seed(observed_at_ms: u64) -> ConvergenceFixture {
    fixture("seed-1", seed_payload(), seed_nodes(), observed_at_ms)
}

/// Target has the exact bound old synchronized database; next step is detach.
pub fn reseed(observed_at_ms: u64) -> ConvergenceFixture {
    let mut nodes = seed_nodes();
    install_database(&mut nodes[1], 2, Some(probe(2, true)));
    fixture("reseed-1", reseed_payload(), nodes, observed_at_ms)
}

fn fixture(
    operation_id: &str,
    payload: OperationPayload,
    mut nodes: Vec<NodeEvidence>,
    observed_at_ms: u64,
) -> ConvergenceFixture {
    for node in &mut nodes {
        if let Observation::Present { value, .. } = &mut node.instance {
            value.observed_at_unix_millis = observed_at_ms;
            stamp(&mut value.availability_group, observed_at_ms);
        }
        stamp(&mut node.instance, observed_at_ms);
        stamp(&mut node.database, observed_at_ms);
    }
    (envelope_named(operation_id, payload), authority(), nodes)
}

fn stamp<T>(observation: &mut Observation<T>, time: u64) {
    match observation {
        Observation::Present {
            observed_at_unix_millis,
            ..
        }
        | Observation::Absent {
            observed_at_unix_millis,
        } => *observed_at_unix_millis = time,
        Observation::Failed(failure) => failure.observed_at_unix_millis = time,
    }
}

pub fn guid(id: u32) -> Guid {
    Guid::parse("fixture", format!("{id:08x}-0000-4000-8000-000000000001")).unwrap()
}

pub fn desired(id: u32) -> ReplicaIdentity {
    ReplicaIdentity::desired(format!("replica-{id}"), format!("pod-{id}")).unwrap()
}

pub fn observed(id: u32) -> ReplicaIdentity {
    ReplicaIdentity::observed(format!("replica-{id}"), guid(100 + id), format!("pod-{id}")).unwrap()
}

pub fn member(id: u32) -> ReplicaDescriptor {
    ReplicaDescriptor {
        identity: desired(id),
        server_name: ServerName::new(format!("sql-{id}")).unwrap(),
        endpoint: Endpoint::new(format!("sql-{id}.sql.default.svc"), 5022).unwrap(),
    }
}

pub fn authority() -> AcceptedAuthority {
    AcceptedAuthority {
        resource_id: OpaqueId::new("resource", "default/example").unwrap(),
        configuration_id: OpaqueId::new("configuration", "configuration-1").unwrap(),
        epoch: 7,
        primary: desired(1),
        replicas: (1..=3).map(member).collect(),
    }
}

pub fn ag() -> AvailabilityGroupIdentity {
    AvailabilityGroupIdentity {
        name: AvailabilityGroupName::new("test-ag").unwrap(),
        group_id: guid(10),
    }
}

pub fn database() -> DatabaseIdentity {
    DatabaseIdentity {
        name: SqlIdentifier::new("app_db").unwrap(),
        group_database_id: guid(20),
    }
}

pub fn probe(id: u32, associated: bool) -> DatabaseProbe {
    DatabaseProbe {
        name: database().name,
        database_id: 5,
        database_guid: guid(200 + id),
        recovery_fork_id: guid(300),
        group_database_id: associated.then(|| database().group_database_id),
        replica_id: associated.then(|| guid(100 + id)),
        state: "ONLINE".into(),
        recovery_model: "FULL".into(),
        backup_ready: true,
    }
}

pub fn present<T>(value: T) -> Observation<T> {
    Observation::Present {
        value,
        observed_at_unix_millis: TIME,
    }
}

pub fn absent<T>() -> Observation<T> {
    Observation::Absent {
        observed_at_unix_millis: TIME,
    }
}

pub fn failed<T>() -> Observation<T> {
    Observation::Failed(ObservationFailure {
        kind: ObservationFailureKind::Unreachable,
        message: "adapter-owned failure".into(),
        observed_at_unix_millis: TIME,
    })
}

fn metadata(id: u32) -> InstanceMetadata {
    InstanceMetadata {
        server_name: member(id).server_name,
        property_server_name: member(id).server_name,
        product_version: "16.0.4225.2".into(),
        product_major_version: 16,
        edition: "Developer Edition (64-bit)".into(),
        engine_edition: 3,
        hadr_enabled: true,
        host_platform: "Linux".into(),
        host_distribution: Some("Ubuntu".into()),
        architecture: "x86_64".into(),
        sqlserver_start_time: "2026-08-01T10:00:00".into(),
    }
}

fn native_database(id: u32, probe: Option<&DatabaseProbe>) -> DatabaseSnapshot {
    let Some(probe) = probe.filter(|probe| probe.group_database_id.is_some()) else {
        return DatabaseSnapshot {
            identity: database(),
            local: None,
            replicas: Vec::new(),
        };
    };
    DatabaseSnapshot {
        identity: database(),
        local: Some(LocalDatabaseSnapshot {
            database_id: probe.database_id,
            replica_id: guid(100 + id),
            state: Some(probe.state.clone()),
            recovery_model: Some(probe.recovery_model.clone()),
            recovery: Some(LocalRecoveryMetadata {
                database_guid: Some(probe.database_guid.clone()),
                family_guid: Some(guid(400)),
                recovery_fork_guid: Some(probe.recovery_fork_id.clone()),
                first_recovery_fork_guid: Some(probe.recovery_fork_id.clone()),
                fork_point_lsn: None,
            }),
        }),
        replicas: vec![DatabaseReplicaSnapshot {
            group_database_id: database().group_database_id,
            replica_id: guid(100 + id),
            database_id: probe.database_id,
            provenance: NativeProvenance::Local,
            lineage: RecoveryLineageObservation::Local {
                value: DatabaseLineage {
                    database: database(),
                    recovery_fork_id: probe.recovery_fork_id.clone(),
                },
            },
            is_primary_replica: Some(id == 1),
            synchronization_state: Some("SYNCHRONIZED".into()),
            synchronization_health: Some("HEALTHY".into()),
            database_state: Some(probe.state.clone()),
            is_suspended: Some(false),
            suspend_reason: None,
            is_commit_participant: Some(true),
            progress: NativeProgress {
                hardened_block: Some(DecimalProgress::parse("9999999999999999999999999").unwrap()),
                redone_record: Some(DecimalProgress::parse("0").unwrap()),
                committed_record: Some(DecimalProgress::parse("9223372036854775808").unwrap()),
            },
        }],
    }
}

fn native_group(
    id: u32,
    joined: bool,
    local_database: Option<&DatabaseProbe>,
) -> AvailabilityGroupSnapshot {
    let role = if joined {
        Some(if id == 1 {
            NativeRole::Primary
        } else {
            NativeRole::Secondary
        })
    } else {
        None
    };
    AvailabilityGroupSnapshot {
        identity: ag(),
        configuration_sequence: DecimalProgress::parse("9007199254740993").unwrap(),
        cluster_type: "EXTERNAL".into(),
        required_synchronized_secondaries_to_commit: 1,
        basic_features: false,
        is_distributed: false,
        local_replica: LocalReplicaSnapshot {
            identity: observed(id),
            state_available: joined,
            role: role.clone(),
        },
        replicas: (1..=3)
            .map(|replica| ReplicaSnapshot {
                replica_id: guid(100 + replica),
                server_name: member(replica).server_name,
                endpoint_url: Some(
                    member(replica)
                        .endpoint
                        .to_string()
                        .replacen("tcp://", "TCP://", 1),
                ),
                availability_mode: "SYNCHRONOUS_COMMIT".into(),
                failover_mode: "EXTERNAL".into(),
                seeding_mode: "AUTOMATIC".into(),
                state: if replica == id && joined {
                    Some(ReplicaState {
                        provenance: NativeProvenance::Local,
                        role: role.clone(),
                        operational_state: Some("ONLINE".into()),
                        connected_state: Some("CONNECTED".into()),
                        recovery_health: Some("ONLINE".into()),
                        synchronization_health: Some("HEALTHY".into()),
                        last_connect_error_number: Some(0),
                    })
                } else {
                    None
                },
            })
            .collect(),
        databases: vec![native_database(id, local_database)],
        automatic_seeding: Vec::new(),
        physical_seeding: Vec::new(),
    }
}

pub fn existing(id: u32, has_database: bool) -> NodeEvidence {
    let local = has_database.then(|| probe(id, true));
    NodeEvidence {
        identity: desired(id),
        server_name: member(id).server_name,
        endpoint: member(id).endpoint,
        instance: present(InstanceSnapshot {
            observed_at_unix_millis: TIME,
            instance: metadata(id),
            availability_group: present(native_group(id, true, local.as_ref())),
        }),
        database: local.map_or_else(absent, present),
    }
}

pub fn before_create(id: u32) -> NodeEvidence {
    NodeEvidence {
        identity: desired(id),
        server_name: member(id).server_name,
        endpoint: member(id).endpoint,
        instance: present(InstanceSnapshot {
            observed_at_unix_millis: TIME,
            instance: metadata(id),
            availability_group: absent(),
        }),
        database: if id == 1 {
            present(probe(id, false))
        } else {
            absent()
        },
    }
}

pub fn seed_nodes() -> Vec<NodeEvidence> {
    vec![existing(1, true), existing(2, false), existing(3, false)]
}

pub fn before_create_nodes() -> Vec<NodeEvidence> {
    (1..=3).map(before_create).collect()
}

pub fn snapshot(node: &mut NodeEvidence) -> &mut InstanceSnapshot {
    match &mut node.instance {
        Observation::Present { value, .. } => value,
        _ => panic!("fixture instance absent"),
    }
}

pub fn group(node: &mut NodeEvidence) -> &mut AvailabilityGroupSnapshot {
    match &mut snapshot(node).availability_group {
        Observation::Present { value, .. } => value,
        _ => panic!("fixture AG absent"),
    }
}

pub fn database_probe(node: &mut NodeEvidence) -> &mut DatabaseProbe {
    match &mut node.database {
        Observation::Present { value, .. } => value,
        _ => panic!("fixture database absent"),
    }
}

/// Change local database facts without silently refreshing the observation.
pub fn install_database(node: &mut NodeEvidence, id: u32, probe: Option<DatabaseProbe>) {
    let time = node.database.observed_at_unix_millis();
    group(node).databases = vec![native_database(id, probe.as_ref())];
    node.database = match probe {
        Some(value) => Observation::Present {
            value,
            observed_at_unix_millis: time,
        },
        None => Observation::Absent {
            observed_at_unix_millis: time,
        },
    };
}

pub fn set_role(node: &mut NodeEvidence, role: Option<NativeRole>) {
    let group = group(node);
    group.local_replica.role = role.clone();
    group.local_replica.state_available = role.is_some();
    for replica in &mut group.replicas {
        if Some(&replica.replica_id) == group.local_replica.identity.native_replica_id() {
            replica.state = role.as_ref().map(|_| ReplicaState {
                provenance: NativeProvenance::Local,
                role: role.clone(),
                operational_state: Some("ONLINE".into()),
                connected_state: Some("CONNECTED".into()),
                recovery_health: None,
                synchronization_health: None,
                last_connect_error_number: None,
            });
        } else {
            replica.state = None;
        }
    }
}

pub fn bootstrap_payload(expected: Option<Guid>) -> OperationPayload {
    OperationPayload::EnsureAvailabilityGroup {
        name: ag().name,
        expected_group_id: expected,
        database_name: database().name,
        primary: desired(1),
        replicas: authority().replicas,
    }
}

pub fn join_payload() -> OperationPayload {
    OperationPayload::EnsureReplicaJoined {
        availability_group: ag(),
        target: observed(2),
    }
}

pub fn seed_payload() -> OperationPayload {
    OperationPayload::EnsureReplicaSeeded {
        availability_group: ag(),
        database: database(),
        source: observed(1),
        target: observed(2),
    }
}

pub fn reseed_payload() -> OperationPayload {
    OperationPayload::ReseedReplica {
        availability_group: ag(),
        database: database(),
        source: observed(1),
        target: observed(2),
        expected_database_id: 5,
        expected_database_guid: guid(202),
        expected_recovery_fork_id: guid(300),
    }
}

pub fn envelope(payload: OperationPayload) -> OperationEnvelope {
    envelope_named("operation-1", payload)
}

pub fn envelope_named(operation_id: &str, payload: OperationPayload) -> OperationEnvelope {
    let (destructive, fence_target, advance) = match &payload {
        OperationPayload::ReseedReplica { target, .. } => (true, Some(target.clone()), false),
        OperationPayload::ForcedFailover { source, .. } => (true, Some(source.clone()), true),
        OperationPayload::PlannedSwitchover { source, .. } => (false, Some(source.clone()), true),
        _ => (false, None, false),
    };
    let request = OperationRequest::new(
        "default/example",
        operation_id,
        "configuration-1",
        7,
        if advance { 8 } else { 7 },
        payload,
    )
    .unwrap();
    let approval = destructive.then(|| {
        DestructiveApproval::new(
            "structural-only",
            request.operation_id(),
            request.input_signature(),
        )
        .unwrap()
    });
    let fence = fence_target.map(|target| {
        FenceReference::new(
            "not-a-proof",
            "structural-only",
            request.operation_id(),
            request.input_signature(),
            target,
        )
        .unwrap()
    });
    OperationEnvelope::new(request, approval, fence).unwrap()
}
