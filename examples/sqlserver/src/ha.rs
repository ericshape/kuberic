//! Pure HA decisions over authenticated authority and independently collected
//! self-observations. This module performs no I/O and authenticates no proof.
//! A fence projection is usable only after the controller has verified permanent
//! removal of the exact old incarnation; a timeout is never a substitute.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::convergence::{AcceptedAuthority, DatabaseProbe, NodeEvidence};
use crate::observation::{
    AvailabilityGroupSnapshot, DatabaseReplicaSnapshot, InstanceSnapshot, NativeProvenance,
    RecoveryLineageObservation,
};
use crate::runtime_error::RuntimeError;
use crate::{
    AvailabilityGroupIdentity, DatabaseLineage, DecimalProgress, Endpoint, Guid, NativeRole,
    Observation, ObservationFailureKind, OpaqueId, OperationEnvelope, OperationPayload,
    OperationRequest, ReplicaDescriptor, ReplicaIdentity,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HaContext {
    pub source: AcceptedAuthority,
    pub target: AcceptedAuthority,
}

impl HaContext {
    /// Checks structure, not whether either accepted authority is authentic.
    pub fn validate(&self, request: &OperationRequest) -> Result<(), RuntimeError> {
        request
            .validate()
            .map_err(|_| invalid("invalid HA operation request"))?;
        let (source, target, configuration) = match request.payload() {
            OperationPayload::PlannedSwitchover {
                source,
                target,
                target_configuration_id,
                ..
            }
            | OperationPayload::ForcedFailover {
                source,
                target,
                target_configuration_id,
                ..
            } => (source, target, target_configuration_id),
            _ => return Err(invalid("operation is not a primary transition")),
        };
        validate_authority(&self.source)?;
        validate_authority(&self.target)?;
        if self.source.resource_id.as_str() != request.resource_id()
            || self.target.resource_id != self.source.resource_id
            || self.source.configuration_id.as_str() != request.source_configuration_id()
            || &self.target.configuration_id != configuration
            || self.source.configuration_id == self.target.configuration_id
            || self.source.epoch != request.source_epoch()
            || self.target.epoch != request.target_epoch()
            || self.source.epoch.checked_add(1) != Some(self.target.epoch)
            || !same_member(&self.source.primary, source)
            || !same_member(&self.target.primary, target)
            || same_member(source, target)
            || source.native_replica_id().is_none()
            || target.native_replica_id().is_none()
            || source.native_replica_id() == target.native_replica_id()
            || !self
                .source
                .replicas
                .iter()
                .all(|member| self.target.replicas.contains(member))
        {
            return Err(invalid(
                "HA request must bind an exact next-epoch primary change within unchanged membership",
            ));
        }
        Ok(())
    }

    /// Order-independent membership binding with ordered source/target roles.
    /// This digest is not a signature or evidence of authority.
    pub fn binding(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"kuberic.sqlserver.ha-context.v1\0");
        hash_field(&mut hash, &self.source.canonical_binding());
        hash_field(&mut hash, &self.target.canonical_binding());
        hash.finalize().into()
    }
}

fn validate_authority(authority: &AcceptedAuthority) -> Result<(), RuntimeError> {
    if authority.replicas.len() != 3
        || authority.primary.native_replica_id().is_some()
        || !authority
            .replicas
            .iter()
            .any(|member| member.identity == authority.primary)
    {
        return Err(invalid(
            "HA authority requires three desired members and an exact primary",
        ));
    }
    let mut logical = BTreeSet::new();
    let mut incarnations = BTreeSet::new();
    let mut servers = BTreeSet::new();
    let mut endpoints = BTreeSet::new();
    for member in &authority.replicas {
        if member.identity.native_replica_id().is_some()
            || !logical.insert(member.identity.logical_id())
            || !incarnations.insert(member.identity.incarnation())
            || !servers.insert(&member.server_name)
            || !endpoints.insert(&member.endpoint)
        {
            return Err(invalid(
                "HA authority membership contains ambiguous identities",
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HaPolicy {
    pub max_age_millis: u64,
    pub max_clock_skew_millis: u64,
    pub configuration_commit_timeout_millis: u64,
    pub lease_seconds: u32,
    pub renewal_interval_millis: u64,
    pub command_timeout_millis: u64,
    pub health_threshold: u8,
}

impl Default for HaPolicy {
    fn default() -> Self {
        Self {
            max_age_millis: 60_000,
            max_clock_skew_millis: 2_000,
            configuration_commit_timeout_millis: 60_000,
            lease_seconds: 30,
            renewal_interval_millis: 5_000,
            command_timeout_millis: 5_000,
            health_threshold: 3,
        }
    }
}

impl HaPolicy {
    /// Observation and configuration-commit windows are bounded to five minutes;
    /// tolerated server clock skew is at most thirty seconds. Native leases are
    /// five through sixty seconds, with a strictly positive renewal margin.
    pub fn validate(&self) -> Result<(), RuntimeError> {
        let budget = self
            .renewal_interval_millis
            .checked_add(self.command_timeout_millis)
            .and_then(|value| value.checked_add(self.max_clock_skew_millis));
        if !(1..=300_000).contains(&self.max_age_millis)
            || self.max_clock_skew_millis > 30_000
            || !(1..=300_000).contains(&self.configuration_commit_timeout_millis)
            || !(5..=60).contains(&self.lease_seconds)
            || self.renewal_interval_millis == 0
            || self.command_timeout_millis == 0
            || !matches!(self.health_threshold, 3..=5)
            || budget.is_none_or(|value| value >= u64::from(self.lease_seconds) * 1000)
        {
            return Err(invalid(
                "invalid HA policy bounds or insufficient native lease renewal margin",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HealthSample {
    pub sql_utc_millis: u64,
    pub system: u8,
    pub resource: u8,
    pub query_processing: u8,
    /// Age at the health observation; elapsed observation age is added when
    /// checking the timeout. None means SQL reports no commit in progress.
    pub configuration_commit_age_millis: Option<u64>,
    pub db_failover: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HaNode {
    /// AG configuration and health self-reports remain usable independently of
    /// this node's database probe during recovery. Database readiness is checked
    /// on the promotion target and on both survivors at completion.
    pub node: NodeEvidence,
    pub health: Observation<HealthSample>,
}

/// A projection of a verified permanent-infrastructure-removal receipt. It does
/// not verify a signature, prove removal, or authorize a destructive operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FenceEvidence {
    pub source: ReplicaIdentity,
    pub proof_id: String,
    pub fenced_at_unix_millis: u64,
    pub expires_at_unix_millis: u64,
    pub final_committed_record: Option<DecimalProgress>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum HaAction {
    Promote {
        availability_group: AvailabilityGroupIdentity,
        database: DatabaseLineage,
        source: ReplicaIdentity,
        target: ReplicaIdentity,
        expected_sequence: DecimalProgress,
        forced: bool,
    },
    OfflineSecondary {
        availability_group: AvailabilityGroupIdentity,
        replica: ReplicaIdentity,
    },
    StartSecondary {
        availability_group: AvailabilityGroupIdentity,
        replica: ReplicaIdentity,
    },
}

impl HaAction {
    pub fn key(&self) -> String {
        match self {
            Self::Promote { .. } => "promote".into(),
            Self::OfflineSecondary {
                availability_group,
                replica,
            } => reset_key("offline_secondary", availability_group, replica),
            Self::StartSecondary {
                availability_group,
                replica,
            } => reset_key("start_secondary", availability_group, replica),
        }
    }

    pub fn execution_target(&self) -> &ReplicaIdentity {
        match self {
            Self::Promote { target, .. } => target,
            Self::OfflineSecondary { replica, .. } | Self::StartSecondary { replica, .. } => {
                replica
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HaPostcondition {
    pub availability_group: AvailabilityGroupIdentity,
    /// The observed final recovery fork, not an invented ancestry relationship.
    pub database: DatabaseLineage,
    /// The target-local file GUID. RESTORE can create different local GUIDs on
    /// different replicas; database.database.group_database_id is the shared AG
    /// database identity, checked independently against every surviving catalog.
    pub database_guid: Guid,
    pub target: ReplicaIdentity,
    pub target_configuration_id: OpaqueId,
    pub target_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HaDecision {
    Complete(HaPostcondition),
    Execute(HaAction),
    Wait(&'static str),
    Unsafe(&'static str),
}

enum Blocked {
    Wait(&'static str),
    Unsafe(&'static str),
}
type Check<T> = Result<T, Blocked>;

/// A SQL ACK never substitutes for PRIMARY/database readiness or secondary
/// rejoin. The controller must renew the target's native lease before dispatch,
/// verify the permanent fence again, and atomically commit the target authority
/// only after a Complete decision and a still-active target lease.
#[allow(clippy::too_many_arguments)]
pub fn plan(
    envelope: &OperationEnvelope,
    ctx: &HaContext,
    nodes: &[HaNode],
    fence: &FenceEvidence,
    acknowledged: &BTreeSet<String>,
    promotion_prepared: bool,
    now_ms: u64,
    policy: &HaPolicy,
) -> HaDecision {
    match decide(
        envelope,
        ctx,
        nodes,
        fence,
        acknowledged,
        promotion_prepared,
        now_ms,
        policy,
    ) {
        Ok(decision) => decision,
        Err(Blocked::Wait(reason)) => HaDecision::Wait(reason),
        Err(Blocked::Unsafe(reason)) => HaDecision::Unsafe(reason),
    }
}

#[allow(clippy::too_many_arguments)]
fn decide(
    envelope: &OperationEnvelope,
    ctx: &HaContext,
    nodes: &[HaNode],
    fence: &FenceEvidence,
    acknowledged: &BTreeSet<String>,
    promotion_prepared: bool,
    now: u64,
    policy: &HaPolicy,
) -> Check<HaDecision> {
    if envelope.validate().is_err()
        || ctx.validate(envelope.request()).is_err()
        || policy.validate().is_err()
    {
        return Err(Blocked::Unsafe(
            "invalid HA authority, operation, approval, or policy binding",
        ));
    }
    let (group, lineage, source, target, boundary, forced) = match envelope.request().payload() {
        OperationPayload::PlannedSwitchover {
            availability_group,
            database,
            source,
            target,
            commit_boundary,
            ..
        } => (
            availability_group,
            database,
            source,
            target,
            Some(commit_boundary),
            false,
        ),
        OperationPayload::ForcedFailover {
            availability_group,
            database,
            source,
            target,
            ..
        } => (availability_group, database, source, target, None, true),
        _ => return Err(Blocked::Unsafe("operation is not a primary transition")),
    };
    if &fence.source != source
        || OpaqueId::new("fence proof ID", &fence.proof_id).is_err()
        || envelope
            .fence()
            .is_none_or(|reference| reference.receipt_id() != fence.proof_id)
        || fence.fenced_at_unix_millis > now
        || fence.expires_at_unix_millis <= now
        || fence.expires_at_unix_millis <= fence.fenced_at_unix_millis
        || (!forced && fence.final_committed_record.is_none())
    {
        return Err(Blocked::Unsafe(
            "missing, expired, or mismatched permanent source fence",
        ));
    }
    let mut supplied = BTreeMap::new();
    for node in nodes {
        let member = ctx
            .source
            .replicas
            .iter()
            .find(|member| same_member(&member.identity, &node.node.identity))
            .ok_or(Blocked::Unsafe(
                "evidence names an unaccepted member or incarnation",
            ))?;
        if node.node.identity.native_replica_id().is_some()
            || node.node.server_name != member.server_name
            || node.node.endpoint != member.endpoint
            || supplied
                .insert(node.node.identity.logical_id(), node)
                .is_some()
        {
            return Err(Blocked::Unsafe(
                "evidence identity, endpoint, or uniqueness is invalid",
            ));
        }
        if same_member(&node.node.identity, source) {
            check_removed_source(node, fence, now)?;
        }
    }
    let target_node = supplied
        .get(target.logical_id())
        .ok_or(Blocked::Wait("target self-observation is missing"))?;
    let witness_member = ctx
        .source
        .replicas
        .iter()
        .find(|member| {
            !same_member(&member.identity, source) && !same_member(&member.identity, target)
        })
        .ok_or(Blocked::Unsafe("accepted surviving membership is invalid"))?;
    let witness_node = supplied
        .get(witness_member.identity.logical_id())
        .ok_or(Blocked::Wait(
            "two surviving configuration self-reports are required",
        ))?;

    // Remote DMV state, including any old source report, is never a vote.
    let target_group = check_node(target_node, &ctx.source, group, lineage, now, policy)?;
    let witness_group = check_node(witness_node, &ctx.source, group, lineage, now, policy)?;
    check_native_mapping(target_group, witness_group)?;
    for (identity, member) in [(source, &ctx.source.primary), (target, &ctx.target.primary)] {
        let descriptor = ctx
            .source
            .replicas
            .iter()
            .find(|item| &item.identity == member)
            .ok_or(Blocked::Unsafe("request primary is not an accepted member"))?;
        if catalog_id(target_group, descriptor) != identity.native_replica_id() {
            return Err(Blocked::Unsafe(
                "native source or target GUID differs from the request",
            ));
        }
    }
    if &target_group.local_replica.identity != target {
        return Err(Blocked::Unsafe(
            "target local native identity differs from the request",
        ));
    }
    if !matches!(
        witness_group.local_replica.role,
        Some(NativeRole::Secondary | NativeRole::Resolving)
    ) {
        return Err(Blocked::Unsafe(
            "surviving witness is an unexpected primary or unsupported role",
        ));
    }
    if target_group.configuration_sequence < witness_group.configuration_sequence {
        return Err(Blocked::Unsafe(
            "target is not the maximum surviving native configuration sequence",
        ));
    }
    let promote = HaAction::Promote {
        availability_group: group.clone(),
        database: lineage.clone(),
        source: source.clone(),
        target: target.clone(),
        expected_sequence: target_group.configuration_sequence,
        forced,
    };
    let offline = HaAction::OfflineSecondary {
        availability_group: group.clone(),
        replica: witness_group.local_replica.identity.clone(),
    };
    let start = HaAction::StartSecondary {
        availability_group: group.clone(),
        replica: witness_group.local_replica.identity.clone(),
    };
    let promotion_ack = acknowledged.contains(&promote.key());
    let offline_ack = acknowledged.contains(&offline.key());
    let start_ack = acknowledged.contains(&start.key());
    if start_ack && !offline_ack {
        return Err(Blocked::Unsafe(
            "secondary restart acknowledgement has no preceding offline acknowledgement",
        ));
    }
    let primary = target_group.local_replica.role == Some(NativeRole::Primary);
    if primary && !promotion_prepared && !promotion_ack {
        return Err(Blocked::Unsafe(
            "a fresh transition cannot adopt an already-primary target",
        ));
    }
    if !primary && (offline_ack || start_ack) {
        return Err(Blocked::Unsafe(
            "target lost PRIMARY after secondary reset began",
        ));
    }
    let witness_resolving = witness_group.local_replica.role == Some(NativeRole::Resolving);
    if !primary {
        if !matches!(
            target_group.local_replica.role,
            Some(NativeRole::Secondary | NativeRole::Resolving)
        ) {
            return Err(Blocked::Unsafe(
                "target is not a readable secondary or resolving replica",
            ));
        }
        let target_db = local_database(target_node, target_group, now, policy)?;
        if target_db.probe.recovery_fork_id != lineage.recovery_fork_id {
            return Err(Blocked::Unsafe(
                "pre-promotion target recovery fork differs from the request",
            ));
        }
        if let Some(boundary) = boundary {
            let final_record = fence.final_committed_record.ok_or(Blocked::Unsafe(
                "planned transition requires the signed drained commit record",
            ))?;
            let required = (*boundary).max(final_record);
            if target_db
                .state
                .progress
                .committed_record
                .is_none_or(|value| value < required)
            {
                return Err(Blocked::Wait(
                    "target has not reached the final fenced commit record",
                ));
            }
        }
        return if promotion_ack {
            Err(Blocked::Wait(
                "promotion acknowledged; native PRIMARY and database readiness are still required",
            ))
        } else {
            Ok(HaDecision::Execute(promote))
        };
    }
    // Configuration votes and secondary role resets use fresh AG/replica/health
    // self-reports, not database probes. OFFLINE and recovery can legitimately
    // hide local database/progress/lineage rows until SET (ROLE = SECONDARY).
    // Those rows remain mandatory for promotion above and completion below.
    if !offline_ack {
        return Ok(HaDecision::Execute(offline));
    }
    if !start_ack {
        return if witness_resolving {
            Ok(HaDecision::Execute(start))
        } else {
            Err(Blocked::Wait(
                "secondary OFFLINE acknowledged; waiting for native RESOLVING",
            ))
        };
    }
    if witness_resolving {
        return Err(Blocked::Wait(
            "secondary restart acknowledged; waiting for native SECONDARY",
        ));
    }
    let target_db = local_database(target_node, target_group, now, policy)?;
    let witness_db = local_database(witness_node, witness_group, now, policy)?;
    if witness_db.probe.recovery_fork_id != lineage.recovery_fork_id
        && witness_db.probe.recovery_fork_id != target_db.probe.recovery_fork_id
    {
        return Err(Blocked::Unsafe(
            "witness recovery fork is unrelated to the bound transition",
        ));
    }
    if witness_db.probe.recovery_fork_id != target_db.probe.recovery_fork_id
        || witness_db.state.synchronization_state.as_deref() != Some("SYNCHRONIZED")
        || witness_db.state.synchronization_health.as_deref() != Some("HEALTHY")
        || witness_db.state.is_commit_participant != Some(true)
        || local_replica_connected(witness_group) != Some("CONNECTED")
    {
        return Err(Blocked::Wait(
            "surviving secondary has not synchronized on the target recovery fork",
        ));
    }
    Ok(HaDecision::Complete(HaPostcondition {
        availability_group: group.clone(),
        database: DatabaseLineage {
            database: lineage.database.clone(),
            recovery_fork_id: target_db.probe.recovery_fork_id.clone(),
        },
        database_guid: target_db.probe.database_guid.clone(),
        target: target.clone(),
        target_configuration_id: ctx.target.configuration_id.clone(),
        target_epoch: ctx.target.epoch,
    }))
}

fn check_removed_source(node: &HaNode, fence: &FenceEvidence, now: u64) -> Check<()> {
    fn check<T>(observation: &Observation<T>, fenced_at: u64, now: u64) -> Check<()> {
        if observation.observed_at_unix_millis() > now {
            return Err(Blocked::Unsafe("fenced source evidence is future-dated"));
        }
        match observation {
            Observation::Present {
                observed_at_unix_millis,
                ..
            } if *observed_at_unix_millis > fenced_at => Err(Blocked::Unsafe(
                "old source self-observation is newer than permanent removal",
            )),
            Observation::Failed(failure)
                if !matches!(
                    failure.kind,
                    ObservationFailureKind::Unreachable | ObservationFailureKind::TimedOut
                ) =>
            {
                Err(Blocked::Unsafe(
                    "fenced source has unsupported or unauthenticated evidence",
                ))
            }
            _ => Ok(()),
        }
    }
    check(&node.node.instance, fence.fenced_at_unix_millis, now)?;
    check(&node.node.database, fence.fenced_at_unix_millis, now)?;
    check(&node.health, fence.fenced_at_unix_millis, now)?;
    if let Observation::Present {
        value,
        observed_at_unix_millis,
    } = &node.node.instance
    {
        if value.observed_at_unix_millis != *observed_at_unix_millis {
            return Err(Blocked::Unsafe(
                "fenced source snapshot timestamps are inconsistent",
            ));
        }
        check(&value.availability_group, fence.fenced_at_unix_millis, now)?;
    }
    Ok(())
}

fn check_node<'a>(
    node: &'a HaNode,
    authority: &AcceptedAuthority,
    expected_group: &AvailabilityGroupIdentity,
    lineage: &DatabaseLineage,
    now: u64,
    policy: &HaPolicy,
) -> Check<&'a AvailabilityGroupSnapshot> {
    let snapshot = present(&node.node.instance, now, policy)?;
    if snapshot.observed_at_unix_millis != node.node.instance.observed_at_unix_millis()
        || snapshot.availability_group.observed_at_unix_millis() != snapshot.observed_at_unix_millis
    {
        return Err(Blocked::Unsafe(
            "native self-observation timestamps are inconsistent",
        ));
    }
    check_instance(snapshot, &node.node)?;
    let health = present(&node.health, now, policy)?;
    // Measure clock offset at this health RPC, not at the instance attempt or
    // the later planning time after other peers may have timed out.
    if health
        .sql_utc_millis
        .abs_diff(node.health.observed_at_unix_millis())
        > policy.max_clock_skew_millis
        || !health.db_failover
        || [health.system, health.resource, health.query_processing]
            .iter()
            .any(|state| !(1..=3).contains(state))
    {
        return Err(Blocked::Unsafe(
            "unknown diagnostics, excessive SQL clock skew, or DB_FAILOVER is not enabled",
        ));
    }
    if health.system == 3
        || (policy.health_threshold >= 4 && health.resource == 3)
        || (policy.health_threshold >= 5 && health.query_processing == 3)
        || health.configuration_commit_age_millis.is_some_and(|age| {
            age.checked_add(now - node.health.observed_at_unix_millis())
                .is_none_or(|age| age >= policy.configuration_commit_timeout_millis)
        })
    {
        return Err(Blocked::Wait(
            "native health or configuration commit timeout forbids lease renewal and promotion",
        ));
    }
    let group = present(&snapshot.availability_group, now, policy)?;
    if &group.identity != expected_group
        || group.cluster_type != "EXTERNAL"
        || group.basic_features
        || group.is_distributed
        || group.required_synchronized_secondaries_to_commit != 1
        || group.configuration_sequence.value() == 0
        || group.configuration_sequence.value() > i64::MAX as u128
        || group.replicas.len() != 3
        || group.databases.len() != 1
        || group.databases[0].identity != lineage.database
        || !same_member(&group.local_replica.identity, &node.node.identity)
        || group.local_replica.identity.native_replica_id().is_none()
        || !group.local_replica.state_available
        || !matches!(
            group.local_replica.role,
            Some(NativeRole::Primary | NativeRole::Secondary | NativeRole::Resolving)
        )
    {
        return Err(Blocked::Unsafe(
            "native AG identity, positive bigint sequence, role, database, or HA profile is invalid",
        ));
    }
    let mut ids = BTreeSet::new();
    let mut servers = BTreeSet::new();
    let mut local_count = 0;
    for replica in &group.replicas {
        let member = authority
            .replicas
            .iter()
            .find(|member| member.server_name == replica.server_name)
            .ok_or(Blocked::Unsafe("native AG contains an unaccepted server"))?;
        if !ids.insert(&replica.replica_id)
            || !servers.insert(&replica.server_name)
            || replica.availability_mode != "SYNCHRONOUS_COMMIT"
            || replica.failover_mode != "EXTERNAL"
            || replica.seeding_mode != "AUTOMATIC"
            || endpoint(replica.endpoint_url.as_deref())? != member.endpoint
        {
            return Err(Blocked::Unsafe(
                "native replica identities, endpoints, or modes differ from accepted membership",
            ));
        }
        let local = replica.server_name == node.node.server_name;
        if local && group.local_replica.identity.native_replica_id() != Some(&replica.replica_id) {
            return Err(Blocked::Unsafe(
                "local native replica GUID differs from its catalog",
            ));
        }
        if let Some(state) = &replica.state {
            match state.provenance {
                NativeProvenance::Local => {
                    local_count += 1;
                    if !local || state.role != group.local_replica.role {
                        return Err(Blocked::Unsafe(
                            "local role provenance contradicts native catalog identity",
                        ));
                    }
                    if !matches!(
                        state.operational_state.as_deref(),
                        Some("ONLINE" | "OFFLINE" | "PENDING" | "PENDING_FAILOVER")
                    ) || !matches!(
                        state.connected_state.as_deref(),
                        Some("CONNECTED" | "DISCONNECTED")
                    ) {
                        return Err(Blocked::Wait(
                            "local operational or connection state is unavailable or unsafe",
                        ));
                    }
                    if group.local_replica.role != Some(NativeRole::Resolving)
                        && state.operational_state.as_deref() != Some("ONLINE")
                    {
                        return Err(Blocked::Wait(
                            "local native replica is not operationally ONLINE",
                        ));
                    }
                }
                NativeProvenance::PrimaryRemote => {
                    if local
                        || group.local_replica.role != Some(NativeRole::Primary)
                        || state.role == Some(NativeRole::Primary)
                    {
                        return Err(Blocked::Unsafe(
                            "remote replica state is not a valid local-primary report",
                        ));
                    }
                }
            }
        }
    }
    if local_count != 1 {
        return Err(Blocked::Unsafe(
            "configuration vote has no unique local role self-report",
        ));
    }
    let mut database_replicas = BTreeSet::new();
    for state in &group.databases[0].replicas {
        if state.group_database_id != lineage.database.group_database_id
            || state.database_id <= 4
            || state.database_id > i32::MAX as u32
            || !ids.contains(&state.replica_id)
            || !database_replicas.insert(&state.replica_id)
        {
            return Err(Blocked::Unsafe(
                "native database replica membership is ambiguous",
            ));
        }
        match state.provenance {
            NativeProvenance::Local
                if Some(&state.replica_id) != group.local_replica.identity.native_replica_id() =>
            {
                return Err(Blocked::Unsafe(
                    "database self-report belongs to another replica",
                ));
            }
            NativeProvenance::PrimaryRemote
                if group.local_replica.role != Some(NativeRole::Primary)
                    || Some(&state.replica_id)
                        == group.local_replica.identity.native_replica_id()
                    || state.lineage != RecoveryLineageObservation::RemoteUnavailable
                    || state.is_primary_replica == Some(true) =>
            {
                return Err(Blocked::Unsafe(
                    "remote database state has invalid provenance",
                ));
            }
            _ => {}
        }
    }
    Ok(group)
}

struct LocalDatabase<'a> {
    probe: &'a DatabaseProbe,
    state: &'a DatabaseReplicaSnapshot,
}

fn local_database<'a>(
    node: &'a HaNode,
    group: &'a AvailabilityGroupSnapshot,
    now: u64,
    policy: &HaPolicy,
) -> Check<LocalDatabase<'a>> {
    let probe = present(&node.node.database, now, policy)?;
    let database = &group.databases[0];
    let local = database
        .local
        .as_ref()
        .ok_or(Blocked::Wait("local database catalog is unavailable"))?;
    let recovery = local.recovery.as_ref().ok_or(Blocked::Wait(
        "local native recovery metadata is unavailable",
    ))?;
    if node.node.database.observed_at_unix_millis() != node.node.instance.observed_at_unix_millis()
        || probe.database_id <= 4
        || probe.database_id > i32::MAX as u32
        || probe.name != database.identity.name
        || probe.group_database_id.as_ref() != Some(&database.identity.group_database_id)
        || probe.replica_id.as_ref() != group.local_replica.identity.native_replica_id()
        || probe.database_id != local.database_id
        || probe.replica_id.as_ref() != Some(&local.replica_id)
        || recovery.database_guid.as_ref() != Some(&probe.database_guid)
        || recovery.recovery_fork_guid.as_ref() != Some(&probe.recovery_fork_id)
    {
        return Err(Blocked::Unsafe(
            "local database GUID, fork, user database, or observation association differs",
        ));
    }
    let state = database
        .replicas
        .iter()
        .find(|state| state.provenance == NativeProvenance::Local)
        .ok_or(Blocked::Wait(
            "local database DMV self-report is unavailable",
        ))?;
    if state.database_id != probe.database_id
        || state.is_primary_replica != Some(group.local_replica.role == Some(NativeRole::Primary))
        || !matches!(&state.lineage, RecoveryLineageObservation::Local { value }
            if value.database == database.identity && value.recovery_fork_id == probe.recovery_fork_id)
    {
        return Err(Blocked::Unsafe(
            "database role flag or self-reported lineage contradicts the local replica",
        ));
    }
    if probe.state != "ONLINE"
        || probe.recovery_model != "FULL"
        || local.state.as_deref() != Some("ONLINE")
        || local.recovery_model.as_deref() != Some("FULL")
        || state.database_state.as_deref() != Some("ONLINE")
        || state.is_suspended != Some(false)
        || state
            .suspend_reason
            .as_deref()
            .is_some_and(|reason| !matches!(reason, "" | "NONE"))
        || state.is_commit_participant.is_none()
        || state.progress.committed_record.is_none()
        || !matches!(
            state.synchronization_state.as_deref(),
            Some("SYNCHRONIZED" | "SYNCHRONIZING" | "NOT SYNCHRONIZING" | "NOT_SYNCHRONIZING")
        )
        || !matches!(
            state.synchronization_health.as_deref(),
            Some("HEALTHY" | "PARTIALLY_HEALTHY" | "NOT_HEALTHY")
        )
    {
        return Err(Blocked::Wait(
            "local ONLINE FULL unsuspended database, known progress, and readable synchronization state are required",
        ));
    }
    Ok(LocalDatabase { probe, state })
}

fn check_native_mapping(
    left: &AvailabilityGroupSnapshot,
    right: &AvailabilityGroupSnapshot,
) -> Check<()> {
    if left.replicas.iter().any(|replica| {
        !right.replicas.iter().any(|other| {
            other.replica_id == replica.replica_id && other.server_name == replica.server_name
        })
    }) {
        return Err(Blocked::Unsafe(
            "surviving native replica GUID mappings disagree",
        ));
    }
    Ok(())
}

fn catalog_id<'a>(
    group: &'a AvailabilityGroupSnapshot,
    member: &ReplicaDescriptor,
) -> Option<&'a Guid> {
    group
        .replicas
        .iter()
        .find(|replica| replica.server_name == member.server_name)
        .map(|replica| &replica.replica_id)
}

fn local_replica_connected(group: &AvailabilityGroupSnapshot) -> Option<&str> {
    group
        .replicas
        .iter()
        .find(|replica| {
            Some(&replica.replica_id) == group.local_replica.identity.native_replica_id()
        })
        .and_then(|replica| replica.state.as_ref())
        .and_then(|state| state.connected_state.as_deref())
}

fn check_instance(snapshot: &InstanceSnapshot, node: &NodeEvidence) -> Check<()> {
    let metadata = &snapshot.instance;
    let edition = metadata
        .edition
        .strip_suffix(" (64-bit)")
        .unwrap_or(&metadata.edition);
    let version = metadata
        .product_version
        .split('.')
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>();
    if metadata.server_name != node.server_name
        || metadata.property_server_name != node.server_name
        || metadata.product_major_version != 16
        || metadata.engine_edition != 3
        || !matches!(version.as_deref(), Ok([16, _, _, _]))
        || !metadata
            .product_version
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
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
        || metadata.sqlserver_start_time.is_empty()
        || metadata.sqlserver_start_time.len() > 33
        || metadata.sqlserver_start_time.chars().any(char::is_control)
    {
        return Err(Blocked::Unsafe(
            "native SQL Server identity, incarnation metadata, or supported profile is invalid",
        ));
    }
    Ok(())
}

fn present<'a, T>(observation: &'a Observation<T>, now: u64, policy: &HaPolicy) -> Check<&'a T> {
    if now
        .checked_sub(observation.observed_at_unix_millis())
        .is_none_or(|age| age > policy.max_age_millis)
    {
        return Err(Blocked::Wait("self-observation is stale or future-dated"));
    }
    match observation {
        Observation::Present { value, .. } => Ok(value),
        Observation::Absent { .. } => Err(Blocked::Wait("required self-observation is absent")),
        Observation::Failed(failure)
            if matches!(
                failure.kind,
                ObservationFailureKind::Unreachable | ObservationFailureKind::TimedOut
            ) =>
        {
            Err(Blocked::Wait("required self-observation is unavailable"))
        }
        Observation::Failed(_) => Err(Blocked::Unsafe(
            "self-observation failed authentication, permissions, consistency, or supported parsing",
        )),
    }
}

fn endpoint(value: Option<&str>) -> Check<Endpoint> {
    let value = value.ok_or(Blocked::Unsafe("native replica endpoint is missing"))?;
    let (scheme, address) = value
        .split_once("://")
        .ok_or(Blocked::Unsafe("native replica endpoint is malformed"))?;
    let (host, port) = address
        .rsplit_once(':')
        .ok_or(Blocked::Unsafe("native replica endpoint is malformed"))?;
    if !scheme.eq_ignore_ascii_case("tcp") {
        return Err(Blocked::Unsafe(
            "native replica endpoint protocol is unsupported",
        ));
    }
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Blocked::Unsafe("native endpoint port is malformed"));
    }
    Endpoint::new(
        host,
        port.parse()
            .map_err(|_| Blocked::Unsafe("native endpoint port is malformed"))?,
    )
    .map_err(|_| Blocked::Unsafe("native replica endpoint is malformed"))
}

fn same_member(left: &ReplicaIdentity, right: &ReplicaIdentity) -> bool {
    left.logical_id() == right.logical_id() && left.incarnation() == right.incarnation()
}

fn reset_key(prefix: &str, group: &AvailabilityGroupIdentity, replica: &ReplicaIdentity) -> String {
    let mut hash = Sha256::new();
    hash.update(b"kuberic.sqlserver.ha-reset-action.v1\0");
    for value in [
        group.name.as_str(),
        group.group_id.as_str(),
        replica.logical_id(),
        replica.incarnation(),
    ] {
        hash_field(&mut hash, value.as_bytes());
    }
    match replica.native_replica_id() {
        Some(id) => {
            hash.update([1]);
            hash_field(&mut hash, id.as_str().as_bytes());
        }
        None => hash.update([0]),
    }
    let mut key = format!("{prefix}:");
    for byte in hash.finalize() {
        write!(key, "{byte:02x}").expect("writing to a String cannot fail");
    }
    key
}

fn hash_field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

fn invalid(message: &'static str) -> RuntimeError {
    RuntimeError::new(
        ObservationFailureKind::Inconsistent,
        "HA transition",
        message,
    )
}
