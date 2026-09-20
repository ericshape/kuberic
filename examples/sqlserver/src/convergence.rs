//! Pure, authority-bound AG convergence. This module executes no SQL and does
//! not verify authorization, fencing, signatures, or cluster leadership.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::observation::{
    AvailabilityGroupSnapshot, DatabaseReplicaSnapshot, DatabaseSnapshot, InstanceSnapshot,
    NativeProvenance, RecoveryLineageObservation, ReplicaSnapshot,
};
use crate::runtime_error::RuntimeError;
use crate::{
    AvailabilityGroupIdentity, AvailabilityGroupName, DatabaseIdentity, Endpoint, Guid, NativeRole,
    Observation, ObservationFailureKind, OpaqueId, OperationEnvelope, OperationPayload,
    ReplicaDescriptor, ReplicaIdentity, ServerName, SqlIdentifier,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AcceptedAuthority {
    pub resource_id: OpaqueId,
    pub configuration_id: OpaqueId,
    pub epoch: u64,
    pub primary: ReplicaIdentity,
    pub replicas: Vec<ReplicaDescriptor>,
}

impl AcceptedAuthority {
    /// Structural binding only. The embedding controller must establish that
    /// this authority is trusted and authorize every emitted native action.
    pub fn validate_for(&self, envelope: &OperationEnvelope) -> Result<(), RuntimeError> {
        envelope
            .validate()
            .map_err(|_| authority_error("invalid operation envelope"))?;
        let request = envelope.request();
        if request.contract_version() != crate::OPERATION_CONTRACT_VERSION {
            return Err(authority_error(
                "convergence requires operation contract version 3",
            ));
        }
        if matches!(
            request.payload(),
            OperationPayload::PlannedSwitchover { .. } | OperationPayload::ForcedFailover { .. }
        ) {
            return Err(authority_error(
                "primary transitions are not supported by AG convergence",
            ));
        }
        if request.resource_id() != self.resource_id.as_str()
            || request.source_configuration_id() != self.configuration_id.as_str()
            || request.source_epoch() != self.epoch
            || request.target_epoch() != self.epoch
        {
            return Err(authority_error(
                "operation does not bind the accepted resource, configuration, and unchanged epoch",
            ));
        }
        if self.replicas.len() != 3 || self.primary.native_replica_id().is_some() {
            return Err(authority_error(
                "authority requires three desired members and a desired primary",
            ));
        }
        let mut logical = BTreeSet::new();
        let mut incarnations = BTreeSet::new();
        let mut servers = BTreeSet::new();
        let mut endpoints = BTreeSet::new();
        for member in &self.replicas {
            if member.identity.native_replica_id().is_some()
                || !logical.insert(member.identity.logical_id())
                || !incarnations.insert(member.identity.incarnation())
                || !servers.insert(&member.server_name)
                || !endpoints.insert(&member.endpoint)
            {
                return Err(authority_error(
                    "authority members must have unique desired identities, incarnations, servers, and endpoints",
                ));
            }
        }
        if !self
            .replicas
            .iter()
            .any(|member| member.identity == self.primary)
        {
            return Err(authority_error(
                "designated primary is not an exact accepted member",
            ));
        }
        match request.payload() {
            OperationPayload::EnsureAvailabilityGroup {
                primary, replicas, ..
            } => {
                if primary != &self.primary
                    || replicas.len() != self.replicas.len()
                    || !replicas.iter().all(|member| self.replicas.contains(member))
                {
                    return Err(authority_error(
                        "bootstrap primary or full replica topology differs from accepted authority",
                    ));
                }
            }
            OperationPayload::EnsureReplicaJoined { target, .. } => self.validate_target(target)?,
            OperationPayload::EnsureReplicaSeeded { source, target, .. }
            | OperationPayload::ReseedReplica { source, target, .. } => {
                self.validate_target(target)?;
                if !same_member(source, &self.primary) || source.native_replica_id().is_none() {
                    return Err(authority_error(
                        "seeding source is not the designated primary incarnation",
                    ));
                }
            }
            OperationPayload::PlannedSwitchover { .. }
            | OperationPayload::ForcedFailover { .. } => {
                return Err(authority_error(
                    "primary transitions are not supported by AG convergence",
                ));
            }
        }
        Ok(())
    }

    fn validate_target(&self, target: &ReplicaIdentity) -> Result<(), RuntimeError> {
        if self.member(target).is_none()
            || target.native_replica_id().is_none()
            || same_member(target, &self.primary)
        {
            return Err(authority_error(
                "operation target is not an accepted non-primary incarnation with a native identity",
            ));
        }
        Ok(())
    }

    fn member(&self, identity: &ReplicaIdentity) -> Option<&ReplicaDescriptor> {
        self.replicas
            .iter()
            .find(|member| same_member(&member.identity, identity))
    }

    /// Deterministic equality binding, not a signature or a proof of authority.
    pub fn canonical_binding(&self) -> Vec<u8> {
        let mut bytes = b"kuberic.sqlserver.accepted-authority.v1\0".to_vec();
        bind_text(&mut bytes, self.resource_id.as_str());
        bind_text(&mut bytes, self.configuration_id.as_str());
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bind_identity(&mut bytes, &self.primary);
        let members = ordered_members(&self.replicas);
        bytes.extend_from_slice(&(members.len() as u64).to_be_bytes());
        for member in members {
            bind_identity(&mut bytes, &member.identity);
            bind_text(&mut bytes, member.server_name.as_str());
            bind_text(&mut bytes, member.endpoint.host());
            bytes.extend_from_slice(&member.endpoint.port().to_be_bytes());
        }
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DatabaseProbe {
    pub name: SqlIdentifier,
    pub database_id: u32,
    pub database_guid: Guid,
    pub recovery_fork_id: Guid,
    pub group_database_id: Option<Guid>,
    pub replica_id: Option<Guid>,
    pub state: String,
    pub recovery_model: String,
    /// Initialized next-log-backup metadata (`last_log_backup_lsn IS NOT NULL`).
    /// This does not prove that any previous log backup completed.
    pub backup_ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NodeEvidence {
    pub identity: ReplicaIdentity,
    pub server_name: ServerName,
    pub endpoint: Endpoint,
    pub instance: Observation<InstanceSnapshot>,
    pub database: Observation<DatabaseProbe>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum NativeAction {
    CreateAvailabilityGroup {
        primary: ReplicaIdentity,
        name: AvailabilityGroupName,
        database_name: SqlIdentifier,
        write_lease_seconds: u32,
        replicas: Vec<ReplicaDescriptor>,
        /// Dispatch guards are part of the persisted action, not new request
        /// fields. A retry must not retarget an already-journaled intent.
        expected_database_id: u32,
        expected_database_guid: Guid,
        expected_recovery_fork_id: Guid,
    },
    /// The target's local catalog may be absent. The executor must authorize
    /// the name-to-GUID binding and verify both native GUIDs after JOIN before
    /// acknowledging this action.
    JoinAvailabilityGroup {
        availability_group: AvailabilityGroupIdentity,
        target: ReplicaIdentity,
    },
    GrantSeeding {
        availability_group: AvailabilityGroupIdentity,
        target: ReplicaIdentity,
    },
    TriggerSeeding {
        availability_group: AvailabilityGroupIdentity,
        database: DatabaseIdentity,
        source: ReplicaIdentity,
        target: ReplicaIdentity,
        target_server_name: ServerName,
    },
    DetachDatabase {
        availability_group: AvailabilityGroupIdentity,
        database: DatabaseIdentity,
        target: ReplicaIdentity,
        expected_database_id: u32,
        expected_database_guid: Guid,
        expected_recovery_fork_id: Guid,
    },
    DropDatabase {
        availability_group: AvailabilityGroupIdentity,
        database: DatabaseIdentity,
        target: ReplicaIdentity,
        expected_database_id: u32,
        expected_database_guid: Guid,
        expected_recovery_fork_id: Guid,
    },
}

impl NativeAction {
    pub const fn key(&self) -> &'static str {
        match self {
            Self::CreateAvailabilityGroup { .. } => "create_availability_group",
            Self::JoinAvailabilityGroup { .. } => "join_availability_group",
            Self::GrantSeeding { .. } => "grant_seeding",
            Self::TriggerSeeding { .. } => "trigger_seeding",
            Self::DetachDatabase { .. } => "detach_database",
            Self::DropDatabase { .. } => "drop_database",
        }
    }

    pub fn execution_target(&self) -> &ReplicaIdentity {
        match self {
            Self::CreateAvailabilityGroup { primary, .. } => primary,
            Self::TriggerSeeding { source, .. } => source,
            Self::JoinAvailabilityGroup { target, .. }
            | Self::GrantSeeding { target, .. }
            | Self::DetachDatabase { target, .. }
            | Self::DropDatabase { target, .. } => target,
        }
    }

    pub const fn is_destructive(&self) -> bool {
        matches!(
            self,
            Self::DetachDatabase { .. } | Self::DropDatabase { .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Postcondition {
    pub availability_group: AvailabilityGroupIdentity,
    pub database: Option<DatabaseIdentity>,
    pub replica: ReplicaIdentity,
    pub database_id: Option<u32>,
    /// The observed replacement GUID for a successful reseed.
    pub database_guid: Option<Guid>,
    pub recovery_fork_id: Option<Guid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Complete(Postcondition),
    Execute(NativeAction),
    Wait(&'static str),
    Unsafe(&'static str),
}

/// Acknowledgments are scoped to this exact operation by the embedding journal.
/// They suppress repeated commands, but never establish native postconditions.
pub fn plan(
    envelope: &OperationEnvelope,
    authority: &AcceptedAuthority,
    evidence: &[NodeEvidence],
    acknowledged: &BTreeSet<String>,
    now_ms: u64,
    max_age_ms: u64,
) -> Decision {
    match plan_checked(
        envelope,
        authority,
        evidence,
        acknowledged,
        now_ms,
        max_age_ms,
    ) {
        Ok(decision) => decision,
        Err(Blocked::Wait(message)) => Decision::Wait(message),
        Err(Blocked::Unsafe(message)) => Decision::Unsafe(message),
    }
}

#[derive(Debug, Clone, Copy)]
enum Blocked {
    Wait(&'static str),
    Unsafe(&'static str),
}

type Check<T> = Result<T, Blocked>;

struct Node<'a> {
    evidence: &'a NodeEvidence,
    group: Option<&'a AvailabilityGroupSnapshot>,
    database: Option<&'a DatabaseProbe>,
}

fn plan_checked(
    envelope: &OperationEnvelope,
    authority: &AcceptedAuthority,
    evidence: &[NodeEvidence],
    acknowledged: &BTreeSet<String>,
    now: u64,
    max_age: u64,
) -> Check<Decision> {
    authority
        .validate_for(envelope)
        .map_err(|error| Blocked::Unsafe(error.message))?;
    let payload = envelope.request().payload();
    check_acknowledgments(payload, acknowledged)?;
    let nodes = check_evidence(authority, payload, evidence, now, max_age)?;
    let primary = node(&nodes, &authority.primary)?;
    match payload {
        OperationPayload::EnsureAvailabilityGroup {
            name,
            expected_group_id,
            database_name,
            write_lease_seconds,
            ..
        } => bootstrap(
            authority,
            &nodes,
            primary,
            name,
            expected_group_id.as_ref(),
            database_name,
            *write_lease_seconds,
            acknowledged,
        ),
        OperationPayload::EnsureReplicaJoined {
            availability_group,
            target,
        } => {
            let source_group = primary_group(primary)?;
            full_topology(source_group, authority)?;
            native_target(source_group, authority, target)?;
            let target_node = node(&nodes, target)?;
            let join = NativeAction::JoinAvailabilityGroup {
                availability_group: availability_group.clone(),
                target: target.clone(),
            };
            if target_node.group.is_none() {
                return Ok(execute_once(join, acknowledged));
            }
            let target_group = target_group(target_node, target)?;
            match &target_group.local_replica.role {
                Some(NativeRole::Secondary) => Ok(Decision::Complete(postcondition(
                    availability_group,
                    None,
                    target,
                    None,
                ))),
                Some(NativeRole::Primary) => {
                    Err(Blocked::Unsafe("join target is a native primary"))
                }
                Some(NativeRole::Unknown(_)) => {
                    Err(Blocked::Wait("join target has an unknown native role"))
                }
                _ => Ok(execute_once(join, acknowledged)),
            }
        }
        OperationPayload::EnsureReplicaSeeded {
            availability_group,
            database,
            source,
            target,
        } => {
            let context = seed_context(
                authority,
                &nodes,
                primary,
                availability_group,
                database,
                source,
                target,
            )?;
            seed(&context, acknowledged)
        }
        OperationPayload::ReseedReplica {
            availability_group,
            database,
            source,
            target,
            expected_database_id,
            expected_database_guid,
            expected_recovery_fork_id,
        } => {
            if !valid_database_id(*expected_database_id) {
                return Err(Blocked::Unsafe(
                    "reseed must bind a valid old user database ID",
                ));
            }
            let context = seed_context(
                authority,
                &nodes,
                primary,
                availability_group,
                database,
                source,
                target,
            )?;
            reseed(
                &context,
                *expected_database_id,
                expected_database_guid,
                expected_recovery_fork_id,
                acknowledged,
            )
        }
        OperationPayload::PlannedSwitchover { .. } | OperationPayload::ForcedFailover { .. } => {
            Err(Blocked::Unsafe(
                "primary transitions are not supported by AG convergence",
            ))
        }
    }
}

fn check_evidence<'a>(
    authority: &AcceptedAuthority,
    payload: &OperationPayload,
    evidence: &'a [NodeEvidence],
    now: u64,
    max_age: u64,
) -> Check<BTreeMap<&'a str, Node<'a>>> {
    let mut nodes = BTreeMap::new();
    let mut observed_group = None;
    let mut native_by_server = BTreeMap::new();
    let mut server_by_native = BTreeMap::new();
    for item in evidence {
        let member = authority.member(&item.identity).ok_or(Blocked::Unsafe(
            "evidence belongs to an unaccepted logical replica or incarnation",
        ))?;
        if item.identity.native_replica_id().is_some()
            || item.server_name != member.server_name
            || item.endpoint != member.endpoint
            || nodes.contains_key(item.identity.logical_id())
        {
            return Err(Blocked::Unsafe(
                "evidence identity, server, endpoint, or uniqueness binding is invalid",
            ));
        }
        let instance = fresh(&item.instance, now, max_age)?
            .ok_or(Blocked::Wait("SQL Server instance evidence is absent"))?;
        if instance.observed_at_unix_millis != item.instance.observed_at_unix_millis()
            || instance.availability_group.observed_at_unix_millis()
                != instance.observed_at_unix_millis
        {
            return Err(Blocked::Unsafe(
                "native snapshot timestamps disagree with their observation provenance",
            ));
        }
        let metadata = &instance.instance;
        let edition = metadata
            .edition
            .strip_suffix(" (64-bit)")
            .unwrap_or(&metadata.edition);
        if metadata.server_name != item.server_name
            || metadata.property_server_name != item.server_name
        {
            return Err(Blocked::Unsafe(
                "native server identity differs from the accepted evidence endpoint",
            ));
        }
        if metadata.product_major_version != 16
            || metadata.engine_edition != 3
            || !supported_version(&metadata.product_version)
            || !matches!(
                edition,
                "Developer"
                    | "Developer Edition"
                    | "Enterprise"
                    | "Enterprise Edition"
                    | "Enterprise Edition: Core-based Licensing"
            )
            || !metadata.hadr_enabled
            || metadata.host_platform != "Linux"
            || metadata.architecture != "x86_64"
        {
            return Err(Blocked::Unsafe(
                "native instance does not satisfy the supported SQL Server profile",
            ));
        }
        let group = fresh(&instance.availability_group, now, max_age)?;
        let database = fresh(&item.database, now, max_age)?;
        if let Some(probe) = database {
            if !valid_database_id(probe.database_id)
                || !valid_state_text(&probe.state)
                || !valid_state_text(&probe.recovery_model)
            {
                return Err(Blocked::Unsafe("local database probe is malformed"));
            }
            if probe.group_database_id.is_some() != probe.replica_id.is_some() {
                return Err(Blocked::Wait(
                    "local database association metadata is incomplete",
                ));
            }
            if requested_database_name(payload).is_some_and(|name| name != &probe.name) {
                return Err(Blocked::Unsafe(
                    "database probe does not describe the requested database",
                ));
            }
        }
        if let Some(group) = group {
            check_group_scope(group, payload)?;
            if observed_group.is_some_and(|identity| identity != &group.identity) {
                return Err(Blocked::Unsafe(
                    "nodes disagree about the native availability group identity",
                ));
            }
            observed_group = Some(&group.identity);
            check_group(group, item, authority)?;
            for replica in &group.replicas {
                if native_by_server
                    .get(&replica.server_name)
                    .is_some_and(|id| *id != &replica.replica_id)
                    || server_by_native
                        .get(&replica.replica_id)
                        .is_some_and(|name| *name != &replica.server_name)
                {
                    return Err(Blocked::Unsafe(
                        "native replica GUID mappings disagree across nodes",
                    ));
                }
                native_by_server.insert(&replica.server_name, &replica.replica_id);
                server_by_native.insert(&replica.replica_id, &replica.server_name);
            }
            check_probe_consistency(group, database)?;
        }
        nodes.insert(
            item.identity.logical_id(),
            Node {
                evidence: item,
                group,
                database,
            },
        );
    }
    Ok(nodes)
}

fn check_group_scope(group: &AvailabilityGroupSnapshot, payload: &OperationPayload) -> Check<()> {
    match payload {
        OperationPayload::EnsureAvailabilityGroup {
            name,
            expected_group_id,
            ..
        } => {
            if &group.identity.name != name
                || expected_group_id
                    .as_ref()
                    .is_some_and(|id| id != &group.identity.group_id)
            {
                return Err(Blocked::Unsafe(
                    "bootstrap observation would adopt a different native availability group",
                ));
            }
        }
        OperationPayload::EnsureReplicaJoined {
            availability_group, ..
        }
        | OperationPayload::EnsureReplicaSeeded {
            availability_group, ..
        }
        | OperationPayload::ReseedReplica {
            availability_group, ..
        } => {
            if &group.identity != availability_group {
                return Err(Blocked::Unsafe(
                    "operation and observed availability group native identities differ",
                ));
            }
        }
        _ => return Err(Blocked::Unsafe("primary transitions are unsupported")),
    }
    Ok(())
}

fn check_group(
    group: &AvailabilityGroupSnapshot,
    node: &NodeEvidence,
    authority: &AcceptedAuthority,
) -> Check<()> {
    if group.cluster_type != "EXTERNAL"
        || group.basic_features
        || group.is_distributed
        || group.required_synchronized_secondaries_to_commit != 1
        || group.configuration_sequence.value() > i64::MAX as u128
        || group.replicas.len() > 3
        || group.databases.len() > 1
    {
        return Err(Blocked::Unsafe(
            "native availability group configuration is unsupported",
        ));
    }
    let local = &group.local_replica;
    if !same_member(&local.identity, &node.identity)
        || (!local.state_available && local.role.is_some())
        || (local.state_available && local.identity.native_replica_id().is_none())
    {
        return Err(Blocked::Unsafe(
            "local replica identity or state provenance is inconsistent",
        ));
    }
    if local.role == Some(NativeRole::Primary) && !same_member(&node.identity, &authority.primary) {
        return Err(Blocked::Unsafe(
            "a non-designated replica is a native primary",
        ));
    }
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut endpoints = BTreeSet::new();
    let mut local_catalog = None;
    let mut local_states = 0;
    for replica in &group.replicas {
        let member = authority
            .replicas
            .iter()
            .find(|member| member.server_name == replica.server_name)
            .ok_or(Blocked::Unsafe(
                "native replica topology contains an unaccepted server",
            ))?;
        let endpoint = native_endpoint(replica.endpoint_url.as_deref().ok_or(Blocked::Wait(
            "native replica endpoint metadata is unavailable",
        ))?)?;
        if endpoint != member.endpoint
            || !ids.insert(&replica.replica_id)
            || !names.insert(&replica.server_name)
            || !endpoints.insert(endpoint)
        {
            return Err(Blocked::Unsafe(
                "native replica GUID, server, or endpoint binding is invalid",
            ));
        }
        if replica.availability_mode != "SYNCHRONOUS_COMMIT"
            || replica.failover_mode != "EXTERNAL"
            || replica.seeding_mode != "AUTOMATIC"
        {
            return Err(Blocked::Unsafe(
                "native replica configuration is unsupported",
            ));
        }
        if replica.server_name == node.server_name {
            local_catalog = Some(&replica.replica_id);
        }
        if let Some(state) = &replica.state {
            match state.provenance {
                NativeProvenance::Local => {
                    local_states += 1;
                    if local.identity.native_replica_id() != Some(&replica.replica_id)
                        || state.role != local.role
                        || replica.server_name != node.server_name
                    {
                        return Err(Blocked::Unsafe(
                            "local role and replica catalog evidence disagree",
                        ));
                    }
                }
                NativeProvenance::PrimaryRemote => {
                    if local.role != Some(NativeRole::Primary)
                        || local.identity.native_replica_id() == Some(&replica.replica_id)
                        || state.role == Some(NativeRole::Primary)
                    {
                        return Err(Blocked::Unsafe(
                            "remote replica state lacks local-primary provenance",
                        ));
                    }
                }
            }
        }
    }
    if local_catalog != local.identity.native_replica_id()
        || local_states != usize::from(local.state_available)
    {
        return Err(Blocked::Unsafe(
            "local native replica metadata is internally inconsistent",
        ));
    }
    for database in &group.databases {
        if let Some(metadata) = &database.local {
            if !valid_database_id(metadata.database_id)
                || Some(&metadata.replica_id) != local.identity.native_replica_id()
            {
                return Err(Blocked::Unsafe(
                    "local database metadata refers to a different native replica",
                ));
            }
        }
        let mut database_replicas = BTreeSet::new();
        for state in &database.replicas {
            if state.group_database_id != database.identity.group_database_id
                || !valid_database_id(state.database_id)
                || !ids.contains(&state.replica_id)
                || !database_replicas.insert(&state.replica_id)
            {
                return Err(Blocked::Unsafe(
                    "database replica GUID associations or uniqueness are invalid",
                ));
            }
            match state.provenance {
                NativeProvenance::Local => {
                    if local.identity.native_replica_id() != Some(&state.replica_id)
                        || !local.state_available
                        || database
                            .local
                            .as_ref()
                            .is_some_and(|metadata| metadata.database_id != state.database_id)
                    {
                        return Err(Blocked::Unsafe(
                            "local database state identity disagrees with its catalog",
                        ));
                    }
                    if matches!(
                        (&local.role, state.is_primary_replica),
                        (Some(NativeRole::Primary), Some(false))
                            | (Some(NativeRole::Secondary), Some(true))
                    ) {
                        return Err(Blocked::Unsafe(
                            "local database primary flag contradicts the native replica role",
                        ));
                    }
                    match &state.lineage {
                        RecoveryLineageObservation::Local { value } => {
                            if value.database != database.identity
                                || database
                                    .local
                                    .as_ref()
                                    .and_then(|metadata| metadata.recovery.as_ref())
                                    .and_then(|recovery| recovery.recovery_fork_guid.as_ref())
                                    != Some(&value.recovery_fork_id)
                            {
                                return Err(Blocked::Unsafe(
                                    "local database state and recovery lineage disagree",
                                ));
                            }
                        }
                        RecoveryLineageObservation::LocalUnavailable => {}
                        RecoveryLineageObservation::RemoteUnavailable => {
                            return Err(Blocked::Unsafe(
                                "local progress is labeled as remote lineage",
                            ));
                        }
                    }
                }
                NativeProvenance::PrimaryRemote => {
                    if local.role != Some(NativeRole::Primary)
                        || local.identity.native_replica_id() == Some(&state.replica_id)
                        || state.lineage != RecoveryLineageObservation::RemoteUnavailable
                        || state.is_primary_replica == Some(true)
                    {
                        return Err(Blocked::Unsafe(
                            "remote database evidence has invalid provenance",
                        ));
                    }
                }
            }
        }
    }
    let mut automatic_ids = BTreeSet::new();
    for seed in &group.automatic_seeding {
        if !automatic_ids.insert(&seed.operation_id)
            || !ids.contains(&seed.remote_replica_id)
            || Some(&seed.remote_replica_id) == local.identity.native_replica_id()
            || !group
                .databases
                .iter()
                .any(|database| database.identity.group_database_id == seed.group_database_id)
        {
            return Err(Blocked::Unsafe(
                "automatic seeding native associations are invalid",
            ));
        }
    }
    let mut physical_ids = BTreeSet::new();
    for seed in &group.physical_seeding {
        if !physical_ids.insert(&seed.local_physical_seeding_id)
            || Some(&seed.local_replica_id) != local.identity.native_replica_id()
            || !group.databases.iter().any(|database| {
                database.identity.group_database_id == seed.group_database_id
                    && database.identity.name == seed.local_database_name
                    && database
                        .local
                        .as_ref()
                        .is_some_and(|metadata| metadata.database_id == seed.local_database_id)
            })
        {
            return Err(Blocked::Unsafe(
                "physical seeding lacks its documented local database association",
            ));
        }
    }
    Ok(())
}

fn check_probe_consistency(
    group: &AvailabilityGroupSnapshot,
    probe: Option<&DatabaseProbe>,
) -> Check<()> {
    for database in &group.databases {
        if let Some(local) = &database.local {
            let probe = probe.ok_or(Blocked::Wait(
                "database absence conflicts with the native local catalog",
            ))?;
            if probe.name != database.identity.name {
                return Err(Blocked::Unsafe(
                    "local catalog and database probe describe different databases",
                ));
            }
            if probe.group_database_id.as_ref() != Some(&database.identity.group_database_id)
                || probe.replica_id.as_ref() != Some(&local.replica_id)
                || probe.database_id != local.database_id
            {
                return Err(Blocked::Wait(
                    "local database association changed between native observations",
                ));
            }
            if let Some(recovery) = &local.recovery {
                if recovery
                    .database_guid
                    .as_ref()
                    .is_some_and(|id| id != &probe.database_guid)
                    || recovery
                        .recovery_fork_guid
                        .as_ref()
                        .is_some_and(|id| id != &probe.recovery_fork_id)
                {
                    return Err(Blocked::Unsafe(
                        "database probe and snapshot native lineage disagree",
                    ));
                }
            }
        } else if probe.is_none()
            && database
                .replicas
                .iter()
                .any(|state| state.provenance == NativeProvenance::Local)
        {
            return Err(Blocked::Wait(
                "database absence conflicts with local native database state",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn bootstrap(
    authority: &AcceptedAuthority,
    nodes: &BTreeMap<&str, Node<'_>>,
    primary: &Node<'_>,
    name: &AvailabilityGroupName,
    expected_group_id: Option<&Guid>,
    database_name: &SqlIdentifier,
    write_lease_seconds: u32,
    acknowledged: &BTreeSet<String>,
) -> Check<Decision> {
    for member in &authority.replicas {
        node(nodes, &member.identity)?;
    }
    let Some(_) = primary.group else {
        if nodes.values().any(|node| node.group.is_some()) {
            return Err(Blocked::Unsafe(
                "an availability group exists away from the designated primary",
            ));
        }
        if expected_group_id.is_some() {
            return Err(Blocked::Unsafe(
                "the bound availability group is absent; a new native GUID must not be created",
            ));
        }
        let probe = primary
            .database
            .ok_or(Blocked::Wait("primary database must be pre-provisioned"))?;
        if probe.group_database_id.is_some() || probe.replica_id.is_some() {
            return Err(Blocked::Unsafe(
                "bootstrap database is already associated with another native availability group",
            ));
        }
        if probe.state != "ONLINE" || probe.recovery_model != "FULL" || !probe.backup_ready {
            return Err(Blocked::Wait(
                "bootstrap requires an ONLINE FULL database with initialized log-backup metadata",
            ));
        }
        for member in &authority.replicas {
            if member.identity != authority.primary
                && node(nodes, &member.identity)?.database.is_some()
            {
                return Err(Blocked::Unsafe(
                    "a secondary already contains a same-named database",
                ));
            }
        }
        return Ok(execute_once(
            NativeAction::CreateAvailabilityGroup {
                primary: authority.primary.clone(),
                name: name.clone(),
                database_name: database_name.clone(),
                write_lease_seconds,
                replicas: ordered_members(&authority.replicas)
                    .into_iter()
                    .cloned()
                    .collect(),
                expected_database_id: probe.database_id,
                expected_database_guid: probe.database_guid.clone(),
                expected_recovery_fork_id: probe.recovery_fork_id.clone(),
            },
            acknowledged,
        ));
    };
    let group = primary_group(primary)?;
    full_topology(group, authority)?;
    let database = group
        .databases
        .iter()
        .find(|database| &database.identity.name == database_name)
        .ok_or(if group.databases.is_empty() {
            Blocked::Wait("managed database is not yet visible in the primary availability group")
        } else {
            Blocked::Unsafe("existing availability group manages a different database")
        })?;
    let probe = source_database(primary, group, &database.identity)?;
    for member in &authority.replicas {
        if member.identity != authority.primary {
            let secondary = node(nodes, &member.identity)?;
            if let Some(probe) = secondary.database {
                let native = native_catalog_member(group, member)?;
                if probe.group_database_id.as_ref() != Some(&database.identity.group_database_id)
                    || probe.replica_id.as_ref() != Some(&native.replica_id)
                {
                    return Err(Blocked::Unsafe(
                        "existing secondary database is not associated with the requested native topology",
                    ));
                }
                if secondary.group.is_none() {
                    return Err(Blocked::Wait(
                        "secondary database association lacks native availability group evidence",
                    ));
                }
            }
        }
    }
    Ok(Decision::Complete(postcondition(
        &group.identity,
        Some(&database.identity),
        &group.local_replica.identity,
        Some(probe),
    )))
}

struct SeedContext<'a> {
    availability_group: &'a AvailabilityGroupIdentity,
    database: &'a DatabaseIdentity,
    source: &'a ReplicaIdentity,
    target: &'a ReplicaIdentity,
    target_node: &'a Node<'a>,
    primary_group: &'a AvailabilityGroupSnapshot,
    target_group: &'a AvailabilityGroupSnapshot,
    source_database: &'a DatabaseProbe,
}

fn seed_context<'a>(
    authority: &AcceptedAuthority,
    nodes: &'a BTreeMap<&str, Node<'a>>,
    primary: &'a Node<'a>,
    availability_group: &'a AvailabilityGroupIdentity,
    database: &'a DatabaseIdentity,
    source: &'a ReplicaIdentity,
    target: &'a ReplicaIdentity,
) -> Check<SeedContext<'a>> {
    let primary_group = primary_group(primary)?;
    full_topology(primary_group, authority)?;
    if primary_group.local_replica.identity != *source {
        return Err(Blocked::Unsafe(
            "seeding source native identity is not the designated native primary",
        ));
    }
    native_target(primary_group, authority, target)?;
    let target_node = node(nodes, target)?;
    let target_group = target_group(target_node, target)?;
    match target_group.local_replica.role {
        Some(NativeRole::Secondary) => {}
        Some(NativeRole::Primary) => {
            return Err(Blocked::Unsafe("seeding target is a native primary"));
        }
        _ => {
            return Err(Blocked::Wait(
                "seeding requires a verified native SECONDARY target",
            ));
        }
    }
    let source_database = source_database(primary, primary_group, database)?;
    if target_group
        .databases
        .iter()
        .any(|observed| &observed.identity != database)
    {
        return Err(Blocked::Unsafe(
            "target availability group has a different native managed database",
        ));
    }
    Ok(SeedContext {
        availability_group,
        database,
        source,
        target,
        target_node,
        primary_group,
        target_group,
        source_database,
    })
}

fn seed(context: &SeedContext<'_>, acknowledged: &BTreeSet<String>) -> Check<Decision> {
    if let Some(probe) = context.target_node.database {
        let associated = probe.group_database_id.as_ref()
            == Some(&context.database.group_database_id)
            && probe.replica_id.as_ref() == context.target.native_replica_id();
        if probe.group_database_id.is_some() && !associated {
            return Err(Blocked::Unsafe(
                "target database belongs to a different native database or replica",
            ));
        }
        if associated && probe.recovery_fork_id != context.source_database.recovery_fork_id {
            return Err(Blocked::Unsafe(
                "source and target recovery forks are incompatible",
            ));
        }
        if associated && synchronized_target(context, probe) {
            return Ok(Decision::Complete(postcondition(
                context.availability_group,
                Some(context.database),
                context.target,
                Some(probe),
            )));
        }
        seeding_barrier(context)?;
        if !associated {
            return Err(Blocked::Unsafe(
                "automatic seeding must not overwrite an existing unassociated database",
            ));
        }
        return Err(Blocked::Wait(
            "associated target database has not reached the exact synchronized native postcondition",
        ));
    }
    seeding_actions(context, acknowledged)
}

fn reseed(
    context: &SeedContext<'_>,
    expected_database_id: u32,
    expected_database_guid: &Guid,
    expected_recovery_fork_id: &Guid,
    acknowledged: &BTreeSet<String>,
) -> Check<Decision> {
    let Some(probe) = context.target_node.database else {
        return seeding_actions(context, acknowledged);
    };
    let old = probe.database_id == expected_database_id
        && &probe.database_guid == expected_database_guid
        && &probe.recovery_fork_id == expected_recovery_fork_id;
    if !old {
        if &probe.database_guid != expected_database_guid && synchronized_target(context, probe) {
            return Ok(Decision::Complete(postcondition(
                context.availability_group,
                Some(context.database),
                context.target,
                Some(probe),
            )));
        }
        return Err(Blocked::Unsafe(
            "a different database appeared; it must not be detached or dropped",
        ));
    }
    let associated = match (&probe.group_database_id, &probe.replica_id) {
        (None, None) => false,
        (Some(database), Some(replica))
            if database == &context.database.group_database_id
                && Some(replica) == context.target.native_replica_id() =>
        {
            true
        }
        _ => {
            return Err(Blocked::Unsafe(
                "old database is associated with an unrelated native database or replica",
            ));
        }
    };
    if acknowledged.contains("drop_database")
        || acknowledged.contains("grant_seeding")
        || acknowledged.contains("trigger_seeding")
    {
        return Err(Blocked::Wait(
            "old database remains visible after an acknowledged later reseed step",
        ));
    }
    let action = if associated {
        NativeAction::DetachDatabase {
            availability_group: context.availability_group.clone(),
            database: context.database.clone(),
            target: context.target.clone(),
            expected_database_id,
            expected_database_guid: expected_database_guid.clone(),
            expected_recovery_fork_id: expected_recovery_fork_id.clone(),
        }
    } else {
        NativeAction::DropDatabase {
            availability_group: context.availability_group.clone(),
            database: context.database.clone(),
            target: context.target.clone(),
            expected_database_id,
            expected_database_guid: expected_database_guid.clone(),
            expected_recovery_fork_id: expected_recovery_fork_id.clone(),
        }
    };
    Ok(execute_once(action, acknowledged))
}

fn seeding_actions(context: &SeedContext<'_>, acknowledged: &BTreeSet<String>) -> Check<Decision> {
    seeding_barrier(context)?;
    if !acknowledged.contains("grant_seeding") {
        return Ok(Decision::Execute(NativeAction::GrantSeeding {
            availability_group: context.availability_group.clone(),
            target: context.target.clone(),
        }));
    }
    if !acknowledged.contains("trigger_seeding") {
        return Ok(Decision::Execute(NativeAction::TriggerSeeding {
            availability_group: context.availability_group.clone(),
            database: context.database.clone(),
            source: context.source.clone(),
            target: context.target.clone(),
            target_server_name: context.target_node.evidence.server_name.clone(),
        }));
    }
    Err(Blocked::Wait(
        "seeding commands are acknowledged but the native database postcondition is not present",
    ))
}

fn seeding_barrier(context: &SeedContext<'_>) -> Check<()> {
    let mut pending = None;
    for (group, remote, is_source) in [
        (context.primary_group, context.target, true),
        (context.target_group, context.source, false),
    ] {
        let relevant: Vec<_> = group
            .automatic_seeding
            .iter()
            .filter(|seed| {
                seed.group_database_id == context.database.group_database_id
                    && Some(&seed.remote_replica_id) == remote.native_replica_id()
                    && seed.is_source == is_source
            })
            .collect();
        if relevant.iter().any(|seed| seed.start_time.is_none()) {
            pending =
                Some("automatic seeding history cannot be ordered without native start times");
        } else if let Some(latest) = relevant.iter().max_by_key(|seed| &seed.start_time) {
            if relevant
                .iter()
                .filter(|seed| seed.start_time == latest.start_time)
                .count()
                != 1
            {
                pending = Some("automatic seeding history has ambiguous latest attempts");
            } else {
                match latest.current_state.as_deref() {
                    Some("FAILED") => {
                        return Err(Blocked::Unsafe(
                            "native automatic seeding reports a failure",
                        ));
                    }
                    Some("COMPLETED") => {}
                    Some("PENDING" | "SEEDING" | "IN_PROGRESS" | "INITIALIZING" | "STARTED") => {
                        pending = Some("native automatic seeding is in progress");
                    }
                    _ => {
                        pending = Some("native automatic seeding state is unavailable or unknown");
                    }
                }
            }
        }
        for seed in group
            .physical_seeding
            .iter()
            .filter(|seed| seed.group_database_id == context.database.group_database_id)
        {
            if seed.failure_code.is_some_and(|code| code != 0) {
                return Err(Blocked::Unsafe(
                    "native physical seeding reports a failure for the managed database",
                ));
            }
            if seed.end_time_utc.is_none() {
                // Physical rows have no documented remote native replica ID.
                // Any active process for this database is a conservative
                // barrier; remote_machine_name is never used for attribution.
                pending = Some("native physical seeding for the managed database is still active");
            } else if seed.failure_code.is_none()
                || !matches!(seed.role.as_deref(), Some("Source" | "Destination"))
            {
                pending = Some("native physical seeding outcome or role is unavailable or unknown");
            }
        }
    }
    pending.map_or(Ok(()), |message| Err(Blocked::Wait(message)))
}

fn synchronized_target(context: &SeedContext<'_>, probe: &DatabaseProbe) -> bool {
    if probe.name != context.database.name
        || probe.state != "ONLINE"
        || probe.recovery_model != "FULL"
        || probe.group_database_id.as_ref() != Some(&context.database.group_database_id)
        || probe.replica_id.as_ref() != context.target.native_replica_id()
        || probe.recovery_fork_id != context.source_database.recovery_fork_id
    {
        return false;
    }
    let Some(database) = context
        .target_group
        .databases
        .iter()
        .find(|database| &database.identity == context.database)
    else {
        return false;
    };
    if !local_metadata_matches(database, probe) {
        return false;
    }
    local_database_state(database, context.target).is_some_and(|state| {
        state.database_id == probe.database_id && state.database_state.as_deref() == Some("ONLINE")
            && state.synchronization_state.as_deref() == Some("SYNCHRONIZED")
            && state.synchronization_health.as_deref() == Some("HEALTHY")
            && state.is_suspended == Some(false) && state.is_primary_replica == Some(false)
            && matches!(&state.lineage, RecoveryLineageObservation::Local { value }
                if value.database == *context.database && value.recovery_fork_id == probe.recovery_fork_id)
    })
}

fn source_database<'a>(
    primary: &'a Node<'_>,
    group: &'a AvailabilityGroupSnapshot,
    expected: &DatabaseIdentity,
) -> Check<&'a DatabaseProbe> {
    let database = group
        .databases
        .iter()
        .find(|database| &database.identity == expected)
        .ok_or(if group.databases.is_empty() {
            Blocked::Wait("primary native database metadata is unavailable")
        } else {
            Blocked::Unsafe("primary native database identity differs from the operation")
        })?;
    let probe = primary
        .database
        .ok_or(Blocked::Wait("primary database probe is absent"))?;
    if probe.name != expected.name
        || probe.group_database_id.as_ref() != Some(&expected.group_database_id)
        || probe.replica_id.as_ref() != group.local_replica.identity.native_replica_id()
    {
        return Err(Blocked::Unsafe(
            "primary database probe is not associated with the bound native database",
        ));
    }
    if probe.state != "ONLINE"
        || probe.recovery_model != "FULL"
        || !local_metadata_matches(database, probe)
    {
        return Err(Blocked::Wait(
            "primary database requires ONLINE FULL state and known local native lineage",
        ));
    }
    let state = local_database_state(database, &group.local_replica.identity)
        .ok_or(Blocked::Wait("primary local database state is unavailable"))?;
    if state.database_id != probe.database_id
        || state.database_state.as_deref() != Some("ONLINE")
        || state.is_primary_replica != Some(true)
        || state.is_suspended != Some(false)
        || !matches!(&state.lineage, RecoveryLineageObservation::Local { value }
            if &value.database == expected && value.recovery_fork_id == probe.recovery_fork_id)
    {
        return Err(Blocked::Wait(
            "primary local database state and lineage are not ready",
        ));
    }
    Ok(probe)
}

fn local_metadata_matches(database: &DatabaseSnapshot, probe: &DatabaseProbe) -> bool {
    database.local.as_ref().is_some_and(|local| {
        local.database_id == probe.database_id
            && Some(&local.replica_id) == probe.replica_id.as_ref()
            && local.state.as_deref() == Some("ONLINE")
            && local.recovery_model.as_deref() == Some("FULL")
            && local.recovery.as_ref().is_some_and(|recovery| {
                recovery.database_guid.as_ref() == Some(&probe.database_guid)
                    && recovery.recovery_fork_guid.as_ref() == Some(&probe.recovery_fork_id)
            })
    })
}

fn local_database_state<'a>(
    database: &'a DatabaseSnapshot,
    replica: &ReplicaIdentity,
) -> Option<&'a DatabaseReplicaSnapshot> {
    database.replicas.iter().find(|state| {
        state.provenance == NativeProvenance::Local
            && Some(&state.replica_id) == replica.native_replica_id()
    })
}

fn primary_group<'a>(node: &'a Node<'_>) -> Check<&'a AvailabilityGroupSnapshot> {
    let group = node.group.ok_or(Blocked::Wait(
        "designated primary availability group is absent",
    ))?;
    match group.local_replica.role {
        Some(NativeRole::Primary) if group.local_replica.state_available => Ok(group),
        Some(NativeRole::Secondary) => Err(Blocked::Unsafe(
            "designated primary is natively a secondary",
        )),
        _ => Err(Blocked::Wait(
            "designated primary native PRIMARY role is not established",
        )),
    }
}

fn target_group<'a>(
    node: &'a Node<'_>,
    target: &ReplicaIdentity,
) -> Check<&'a AvailabilityGroupSnapshot> {
    let group = node.group.ok_or(Blocked::Wait(
        "target availability group native metadata is absent",
    ))?;
    let native = group
        .local_replica
        .identity
        .native_replica_id()
        .ok_or(Blocked::Wait(
            "target local native replica identity is unavailable",
        ))?;
    if Some(native) != target.native_replica_id() {
        return Err(Blocked::Unsafe(
            "target local native replica GUID differs from the operation",
        ));
    }
    Ok(group)
}

fn full_topology(group: &AvailabilityGroupSnapshot, authority: &AcceptedAuthority) -> Check<()> {
    if group.replicas.len() != authority.replicas.len() {
        return Err(Blocked::Wait(
            "primary native configuration does not yet contain the full accepted topology",
        ));
    }
    for member in &authority.replicas {
        native_catalog_member(group, member)?;
    }
    Ok(())
}

fn native_catalog_member<'a>(
    group: &'a AvailabilityGroupSnapshot,
    member: &ReplicaDescriptor,
) -> Check<&'a ReplicaSnapshot> {
    group
        .replicas
        .iter()
        .find(|replica| replica.server_name == member.server_name)
        .ok_or(Blocked::Wait(
            "accepted replica is not yet defined in the native primary catalog",
        ))
}

fn native_target(
    group: &AvailabilityGroupSnapshot,
    authority: &AcceptedAuthority,
    target: &ReplicaIdentity,
) -> Check<()> {
    let member = authority
        .member(target)
        .ok_or(Blocked::Unsafe("target is not an accepted member"))?;
    if Some(&native_catalog_member(group, member)?.replica_id) != target.native_replica_id() {
        return Err(Blocked::Unsafe(
            "target native replica GUID differs from the primary catalog",
        ));
    }
    Ok(())
}

fn node<'a, 'b>(
    nodes: &'a BTreeMap<&str, Node<'b>>,
    identity: &ReplicaIdentity,
) -> Check<&'a Node<'b>> {
    nodes
        .get(identity.logical_id())
        .ok_or(Blocked::Wait("required replica evidence is missing"))
}

fn fresh<T>(observation: &Observation<T>, now: u64, max_age: u64) -> Check<Option<&T>> {
    if !observation.is_fresh_at(now, max_age) {
        return Err(Blocked::Wait(
            "required native evidence is failed, stale, or dated in the future",
        ));
    }
    match observation {
        Observation::Present { value, .. } => Ok(Some(value)),
        Observation::Absent { .. } => Ok(None),
        Observation::Failed(_) => Err(Blocked::Wait("required native evidence is unavailable")),
    }
}

fn check_acknowledgments(payload: &OperationPayload, acknowledged: &BTreeSet<String>) -> Check<()> {
    let allowed: &[&str] = match payload {
        OperationPayload::EnsureAvailabilityGroup { .. } => &["create_availability_group"],
        OperationPayload::EnsureReplicaJoined { .. } => &["join_availability_group"],
        OperationPayload::EnsureReplicaSeeded { .. } => &["grant_seeding", "trigger_seeding"],
        OperationPayload::ReseedReplica { .. } => &[
            "detach_database",
            "drop_database",
            "grant_seeding",
            "trigger_seeding",
        ],
        _ => &[],
    };
    if acknowledged
        .iter()
        .any(|key| !allowed.contains(&key.as_str()))
        || (acknowledged.contains("trigger_seeding") && !acknowledged.contains("grant_seeding"))
    {
        return Err(Blocked::Unsafe(
            "retained action acknowledgments do not match this convergence operation",
        ));
    }
    Ok(())
}

fn execute_once(action: NativeAction, acknowledged: &BTreeSet<String>) -> Decision {
    if acknowledged.contains(action.key()) {
        Decision::Wait("command is acknowledged but its native postcondition is not yet observed")
    } else {
        Decision::Execute(action)
    }
}

fn postcondition(
    group: &AvailabilityGroupIdentity,
    database: Option<&DatabaseIdentity>,
    replica: &ReplicaIdentity,
    probe: Option<&DatabaseProbe>,
) -> Postcondition {
    Postcondition {
        availability_group: group.clone(),
        database: database.cloned(),
        replica: replica.clone(),
        database_id: probe.map(|probe| probe.database_id),
        database_guid: probe.map(|probe| probe.database_guid.clone()),
        recovery_fork_id: probe.map(|probe| probe.recovery_fork_id.clone()),
    }
}

fn requested_database_name(payload: &OperationPayload) -> Option<&SqlIdentifier> {
    match payload {
        OperationPayload::EnsureAvailabilityGroup { database_name, .. } => Some(database_name),
        OperationPayload::EnsureReplicaSeeded { database, .. }
        | OperationPayload::ReseedReplica { database, .. } => Some(&database.name),
        _ => None,
    }
}

fn native_endpoint(value: &str) -> Check<Endpoint> {
    let authority = value
        .get(..6)
        .filter(|scheme| scheme.eq_ignore_ascii_case("tcp://"))
        .and_then(|_| value.get(6..))
        .ok_or(Blocked::Unsafe(
            "native endpoint URL is not a supported TCP endpoint",
        ))?;
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or(Blocked::Unsafe("native endpoint URL has no port"))?;
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Blocked::Unsafe("native endpoint port is malformed"));
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| Blocked::Unsafe("native endpoint port is out of range"))?;
    Endpoint::new(host, port).map_err(|_| Blocked::Unsafe("native endpoint URL is malformed"))
}

fn same_member(left: &ReplicaIdentity, right: &ReplicaIdentity) -> bool {
    left.logical_id() == right.logical_id() && left.incarnation() == right.incarnation()
}

fn valid_database_id(id: u32) -> bool {
    id > 4 && id <= i32::MAX as u32
}

fn valid_state_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn supported_version(version: &str) -> bool {
    let components: Vec<_> = version.split('.').collect();
    components.len() == 4
        && components[0] == "16"
        && components.iter().all(|component| {
            !component.is_empty()
                && component.bytes().all(|byte| byte.is_ascii_digit())
                && component.parse::<u32>().is_ok()
        })
}

fn authority_error(message: &'static str) -> RuntimeError {
    RuntimeError::new(ObservationFailureKind::Inconsistent, "authority", message)
}

fn ordered_members(replicas: &[ReplicaDescriptor]) -> Vec<&ReplicaDescriptor> {
    let mut members: Vec<_> = replicas.iter().collect();
    members.sort_by(|left, right| {
        left.identity
            .cmp(&right.identity)
            .then_with(|| left.server_name.cmp(&right.server_name))
            .then_with(|| left.endpoint.cmp(&right.endpoint))
    });
    members
}

fn bind_text(bytes: &mut Vec<u8>, text: &str) {
    bytes.extend_from_slice(&(text.len() as u64).to_be_bytes());
    bytes.extend_from_slice(text.as_bytes());
}

fn bind_identity(bytes: &mut Vec<u8>, identity: &ReplicaIdentity) {
    bind_text(bytes, identity.logical_id());
    bind_text(bytes, identity.incarnation());
    match identity.native_replica_id() {
        Some(id) => {
            bytes.push(1);
            bind_text(bytes, id.as_str());
        }
        None => bytes.push(0),
    }
}
