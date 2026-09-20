//! SQL Server EXTERNAL-cluster protocol, derived from the pinned Microsoft
//! resource-agent contract rather than standalone failover statements.

use async_trait::async_trait;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::convergence::{AcceptedAuthority, DatabaseProbe, NodeEvidence};
use crate::executor::QueryRow;
use crate::ha::{HaAction, HaContext, HaNode, HaPolicy, HealthSample};
use crate::instance::{SqlServerInstanceManager, unix_millis};
use crate::mutation::{MutationEndpoint, TdsAgBackend};
use crate::runtime_error::RuntimeError;
use crate::tds::{TdsExecutor, TdsPurpose, TdsSession, connect_session, driver_error};
use crate::{
    AvailabilityGroupIdentity, DatabaseLineage, DecimalProgress, Observation,
    ObservationFailureKind, OperationEnvelope, OperationPayload, OperationRequest, ReplicaIdentity,
};

pub const NATIVE_PROTOCOL_REVISION: &str = "1bcf1aeaa7906c8284a8bbbd5863afd75586fd0b";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LeaseSpec {
    pub resource_id: String,
    pub configuration_id: String,
    pub epoch: u64,
    pub authority_binding: [u8; 32],
    pub availability_group: AvailabilityGroupIdentity,
    pub primary: ReplicaIdentity,
    pub sql_start_time: String,
    pub lease_seconds: u32,
    pub candidate: bool,
}

impl LeaseSpec {
    pub fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"kuberic.sqlserver.lease.v1\0");
        // This type contains only bounded native identities and integers.
        hash.update(serde_json::to_vec(self).expect("lease fields are serializable"));
        hash.finalize().into()
    }
}

/// Only the controller can mint a short-lived execution capability after
/// checking the current journal authority, signatures, and concrete fence.
pub struct HaPermit {
    binding: [u8; 32],
    action: [u8; 32],
    expires_at: u64,
    dispatch_deadline: u64,
}

impl HaPermit {
    pub(crate) fn new(binding: [u8; 32], action: [u8; 32], expires_at: u64) -> Self {
        Self {
            binding,
            action,
            expires_at,
            dispatch_deadline: expires_at,
        }
    }

    pub(crate) fn with_dispatch_deadline(mut self, deadline: u64) -> Self {
        self.dispatch_deadline = deadline.min(self.expires_at);
        self
    }

    fn check(&self, binding: [u8; 32], action: [u8; 32]) -> Result<(), RuntimeError> {
        if self.binding != binding
            || self.action != action
            || unix_millis()? >= self.dispatch_deadline
        {
            return Err(error(
                ObservationFailureKind::PermissionDenied,
                "HA execution capability is expired or bound to another action",
            ));
        }
        Ok(())
    }
}

pub fn policy_binding(context: &HaContext, policy: &HaPolicy) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"kuberic.sqlserver.ha.policy.v1\0");
    hash.update(context.binding());
    for value in [
        policy.max_age_millis,
        policy.max_clock_skew_millis,
        policy.configuration_commit_timeout_millis,
        u64::from(policy.lease_seconds),
        policy.renewal_interval_millis,
        policy.command_timeout_millis,
        u64::from(policy.health_threshold),
    ] {
        hash.update(value.to_be_bytes());
    }
    hash.finalize().into()
}

pub(crate) fn action_digest(action: &HaAction) -> [u8; 32] {
    Sha256::digest(serde_json::to_vec(action).expect("native action fields are serializable"))
        .into()
}

pub(crate) fn drain_digest(request: &OperationRequest) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"kuberic.sqlserver.ha.drain.v1\0");
    hash.update(request.canonical_input());
    hash.finalize().into()
}

#[async_trait]
pub trait HaBackend: Send + Sync {
    async fn observe_current(
        &self,
        authority: &AcceptedAuthority,
        group: &AvailabilityGroupIdentity,
        policy: &HaPolicy,
    ) -> Result<Vec<HaNode>, RuntimeError>;
    async fn observe(
        &self,
        request: &OperationRequest,
        context: &HaContext,
        policy: &HaPolicy,
    ) -> Result<Vec<HaNode>, RuntimeError>;
    async fn drain(
        &self,
        request: &OperationRequest,
        context: &HaContext,
        policy: &HaPolicy,
        permit: &HaPermit,
    ) -> Result<(), RuntimeError>;
    async fn drained_commit(
        &self,
        request: &OperationRequest,
        context: &HaContext,
        policy: &HaPolicy,
    ) -> Result<DecimalProgress, RuntimeError>;
    async fn execute(
        &self,
        envelope: &OperationEnvelope,
        context: &HaContext,
        action: &HaAction,
        policy: &HaPolicy,
        permit: &HaPermit,
    ) -> Result<(), RuntimeError>;
    async fn renew(
        &self,
        lease: &LeaseSpec,
        policy: &HaPolicy,
        permit: &HaPermit,
    ) -> Result<u64, RuntimeError>;
}

#[derive(Clone)]
pub struct TdsHaBackend {
    cluster: TdsAgBackend,
}

impl TdsHaBackend {
    pub fn new(cluster: TdsAgBackend) -> Self {
        Self { cluster }
    }

    fn validate(
        &self,
        request: &OperationRequest,
        context: &HaContext,
        policy: &HaPolicy,
    ) -> Result<(), RuntimeError> {
        context.validate(request)?;
        policy.validate()?;
        let (group, lineage, _, _) = transition_parts(request)?;
        if lineage.database.name != *self.cluster.managed_database() {
            return Err(error(
                ObservationFailureKind::Inconsistent,
                "HA request names an unregistered database",
            ));
        }
        for node in self.cluster.registered_nodes() {
            let target = node.observer().target();
            if target.availability_group != group.name
                || !context.source.replicas.iter().any(|member| {
                    member.identity == target.replica
                        && member.server_name == target.expected_server_name
                        && member.endpoint == *node.replication_endpoint()
                })
            {
                return Err(error(
                    ObservationFailureKind::Inconsistent,
                    "HA endpoint registry does not match the accepted topology",
                ));
            }
        }
        Ok(())
    }

    fn node(&self, identity: &ReplicaIdentity) -> Result<&MutationEndpoint, RuntimeError> {
        self.cluster
            .registered_nodes()
            .iter()
            .find(|node| {
                node.observer().target().replica.logical_id() == identity.logical_id()
                    && node.observer().target().replica.incarnation() == identity.incarnation()
            })
            .ok_or_else(|| {
                error(
                    ObservationFailureKind::Inconsistent,
                    "HA incarnation is not registered",
                )
            })
    }

    async fn session(&self, node: &MutationEndpoint) -> Result<TdsSession, RuntimeError> {
        let mut observer =
            connect_session(node.observer().connection(), TdsPurpose::Observer).await?;
        node.connect_privileged(&mut observer).await
    }

    async fn health(
        &self,
        node: &MutationEndpoint,
        group: &AvailabilityGroupIdentity,
        at: u64,
    ) -> Observation<HealthSample> {
        let result = tokio::time::timeout(node.observer().sample_timeout(), async {
            let mut session = self.session(node).await?;
            let rows = session
                .query_text(HEALTH_SQL, group.name.as_str(), HEALTH_COLUMNS, "HA health")
                .await?;
            parse_health(
                &rows,
                group,
                &node.observer().target().expected_server_name.to_string(),
            )
        })
        .await
        .unwrap_or_else(|_| {
            Err(error(
                ObservationFailureKind::TimedOut,
                "HA health deadline exceeded",
            ))
        });
        match result {
            Ok(value) => Observation::Present {
                value,
                observed_at_unix_millis: at,
            },
            Err(failure) => Observation::Failed(failure.into_failure(at)),
        }
    }

    async fn batch(
        &self,
        node: &MutationEndpoint,
        sql: String,
        policy: &HaPolicy,
    ) -> Result<(), RuntimeError> {
        tokio::time::timeout(
            std::time::Duration::from_millis(policy.command_timeout_millis),
            async {
                let mut session = self.session(node).await?;
                session
                    .client
                    .execute(sql, &[])
                    .await
                    .map_err(|error| driver_error("native HA protocol", error))?;
                Ok(())
            },
        )
        .await
        .map_err(|_| {
            error(
                ObservationFailureKind::TimedOut,
                "native HA outcome is uncertain after the command deadline",
            )
        })?
    }
}

#[async_trait]
impl HaBackend for TdsHaBackend {
    async fn observe_current(
        &self,
        authority: &AcceptedAuthority,
        group: &AvailabilityGroupIdentity,
        policy: &HaPolicy,
    ) -> Result<Vec<HaNode>, RuntimeError> {
        policy.validate()?;
        let mut nodes = Vec::new();
        for node in self.cluster.registered_nodes() {
            if node.observer().target().availability_group != group.name
                || !authority.replicas.iter().any(|member| {
                    member.identity == node.observer().target().replica
                        && member.server_name == node.observer().target().expected_server_name
                        && member.endpoint == *node.replication_endpoint()
                })
            {
                return Err(error(
                    ObservationFailureKind::Inconsistent,
                    "lease observation registry differs from accepted authority",
                ));
            }
            let instance = SqlServerInstanceManager::new(
                TdsExecutor::new(node.observer().connection().clone()),
                node.observer().clone(),
            )
            .observe()
            .await?;
            let database = database_observation(&instance, self.cluster.managed_database());
            let evidence = NodeEvidence {
                identity: node.observer().target().replica.clone(),
                server_name: node.observer().target().expected_server_name.clone(),
                endpoint: node.replication_endpoint().clone(),
                instance,
                database,
            };
            let health = if let Observation::Failed(failure) = &evidence.instance {
                Observation::Failed(failure.clone())
            } else {
                self.health(node, group, unix_millis()?).await
            };
            nodes.push(HaNode {
                node: evidence,
                health,
            });
        }
        Ok(nodes)
    }

    async fn observe(
        &self,
        request: &OperationRequest,
        context: &HaContext,
        policy: &HaPolicy,
    ) -> Result<Vec<HaNode>, RuntimeError> {
        self.validate(request, context, policy)?;
        let (group, _, _, _) = transition_parts(request)?;
        self.observe_current(&context.source, group, policy).await
    }

    async fn drain(
        &self,
        request: &OperationRequest,
        context: &HaContext,
        policy: &HaPolicy,
        permit: &HaPermit,
    ) -> Result<(), RuntimeError> {
        self.validate(request, context, policy)?;
        if !matches!(
            request.payload(),
            OperationPayload::PlannedSwitchover { .. }
        ) {
            return Err(error(
                ObservationFailureKind::Unsupported,
                "only planned switchover can drain a live source",
            ));
        }
        permit.check(policy_binding(context, policy), drain_digest(request))?;
        let (group, lineage, source, _) = transition_parts(request)?;
        let node = self.node(source)?;
        let mut sql = identity_guard(node, group, source)?;
        sql.push_str(&health_guard(group, policy));
        sql.push_str(&format!(
            "IF EXISTS (SELECT 1 FROM sys.dm_hadr_availability_replica_states WHERE group_id={} AND is_local=1 AND role_desc=N'PRIMARY') BEGIN\n{} ALTER AVAILABILITY GROUP {} OFFLINE; END;\n\
             ELSE IF NOT EXISTS (SELECT 1 FROM sys.dm_hadr_availability_replica_states WHERE group_id={} AND is_local=1 AND role_desc=N'RESOLVING') THROW 51000, 'Unexpected source role while draining', 1;\n",
            literal(group.group_id.as_str()), lineage_guard(lineage), group.name.quoted(), literal(group.group_id.as_str())
        ));
        self.batch(
            node,
            locked(
                sql,
                permit.expires_at,
                policy,
                unix_millis()?,
                permit.dispatch_deadline,
            ),
            policy,
        )
        .await
    }

    async fn drained_commit(
        &self,
        request: &OperationRequest,
        context: &HaContext,
        policy: &HaPolicy,
    ) -> Result<DecimalProgress, RuntimeError> {
        self.validate(request, context, policy)?;
        let (group, lineage, source, _) = transition_parts(request)?;
        let node = self.node(source)?;
        let id = source.native_replica_id().ok_or_else(|| {
            error(
                ObservationFailureKind::Malformed,
                "source replica GUID required",
            )
        })?;
        let sql = format!(
            "SELECT CONVERT(nvarchar(25),drs.last_commit_lsn) AS committed_record\n\
             FROM sys.dm_hadr_database_replica_states AS drs\n\
             INNER JOIN sys.dm_hadr_availability_replica_states AS ars ON ars.group_id=drs.group_id AND ars.replica_id=drs.replica_id AND ars.is_local=1\n\
             INNER JOIN sys.databases AS d ON d.database_id=drs.database_id AND d.group_database_id=drs.group_database_id AND d.replica_id=drs.replica_id\n\
             INNER JOIN sys.database_recovery_status AS r ON r.database_id=d.database_id\n\
             WHERE drs.is_local=1 AND drs.group_id={} AND drs.replica_id={} AND drs.group_database_id={} AND d.name=@P1 AND ars.role_desc=N'RESOLVING' AND r.recovery_fork_guid={};",
            literal(group.group_id.as_str()),
            literal(id.as_str()),
            literal(lineage.database.group_database_id.as_str()),
            literal(lineage.recovery_fork_id.as_str())
        );
        let mut session = self.session(node).await?;
        let rows = session
            .query_text(
                &sql,
                lineage.database.name.as_str(),
                &["committed_record"],
                "drained commit witness",
            )
            .await?;
        let [row] = rows.as_slice() else {
            return Err(error(
                ObservationFailureKind::Inconsistent,
                "a stopped-write source and exact final commit witness are required",
            ));
        };
        let value = row
            .get("committed_record")
            .and_then(|value| value.as_deref())
            .ok_or_else(|| {
                error(
                    ObservationFailureKind::Malformed,
                    "final committed-record position is unavailable",
                )
            })?;
        DecimalProgress::parse(value).map_err(|_| {
            error(
                ObservationFailureKind::Malformed,
                "invalid final committed-record position",
            )
        })
    }

    async fn execute(
        &self,
        envelope: &OperationEnvelope,
        context: &HaContext,
        action: &HaAction,
        policy: &HaPolicy,
        permit: &HaPermit,
    ) -> Result<(), RuntimeError> {
        self.validate(envelope.request(), context, policy)?;
        permit.check(policy_binding(context, policy), action_digest(action))?;
        let (group, lineage, source, target) = transition_parts(envelope.request())?;
        let node = self.node(action.execution_target())?;
        let mut sql = identity_guard(node, group, action.execution_target())?;
        sql.push_str(&health_guard(group, policy));
        match action {
            HaAction::Promote {
                availability_group,
                database,
                source: actual_source,
                target: actual_target,
                expected_sequence,
                forced,
            } => {
                if availability_group != group
                    || database != lineage
                    || actual_source != source
                    || actual_target != target
                    || *forced
                        != matches!(
                            envelope.request().payload(),
                            OperationPayload::ForcedFailover { .. }
                        )
                    || expected_sequence.value() == 0
                    || expected_sequence.value() > i64::MAX as u128
                {
                    return Err(error(
                        ObservationFailureKind::Inconsistent,
                        "promotion action differs from the bound request",
                    ));
                }
                sql.push_str("IF NOT EXISTS (SELECT 1 FROM sys.dm_hadr_availability_replica_states WHERE is_local=1 AND group_id=");
                sql.push_str(&literal(group.group_id.as_str()));
                sql.push_str(" AND role_desc=N'PRIMARY') BEGIN\n");
                sql.push_str(&lineage_guard(lineage));
                sql.push_str(&format!("IF NOT EXISTS (SELECT 1 FROM sys.availability_groups WHERE group_id={} AND sequence_number={}) THROW 51000, 'Promotion sequence changed', 1;\n", literal(group.group_id.as_str()), expected_sequence));
                sql.push_str(&lease_statement(
                    group,
                    policy.lease_seconds,
                    permit.expires_at,
                    policy.max_clock_skew_millis,
                ));
                sql.push_str(
                    "EXEC sys.sp_set_session_context @key=N'external_cluster', @value=N'yes';\n",
                );
                sql.push_str(&format!(
                    "ALTER AVAILABILITY GROUP {} {};\nEND;\n",
                    group.name.quoted(),
                    if *forced {
                        "FORCE_FAILOVER_ALLOW_DATA_LOSS"
                    } else {
                        "FAILOVER"
                    }
                ));
                // FAILOVER may return before PRIMARY. A subsequent observation and
                // lease renewal, not this acknowledgement, establish readiness.
            }
            HaAction::OfflineSecondary {
                availability_group,
                replica,
            } => {
                validate_survivor(context, group, source, target, availability_group, replica)?;
                sql.push_str(&format!(
                    "IF EXISTS (SELECT 1 FROM sys.dm_hadr_availability_replica_states WHERE group_id={} AND is_local=1 AND role_desc=N'PRIMARY') THROW 51000, 'Unexpected additional primary', 1;\n\
                     IF EXISTS (SELECT 1 FROM sys.dm_hadr_availability_replica_states WHERE group_id={} AND is_local=1 AND role_desc=N'SECONDARY') ALTER AVAILABILITY GROUP {} OFFLINE;\n",
                    literal(group.group_id.as_str()), literal(group.group_id.as_str()), group.name.quoted()
                ));
            }
            HaAction::StartSecondary {
                availability_group,
                replica,
            } => {
                validate_survivor(context, group, source, target, availability_group, replica)?;
                sql.push_str(&format!(
                    "IF EXISTS (SELECT 1 FROM sys.dm_hadr_availability_replica_states WHERE group_id={} AND is_local=1 AND role_desc=N'PRIMARY') THROW 51000, 'Unexpected additional primary', 1;\n\
                     IF EXISTS (SELECT 1 FROM sys.dm_hadr_availability_replica_states WHERE group_id={} AND is_local=1 AND role_desc=N'RESOLVING') ALTER AVAILABILITY GROUP {} SET (ROLE=SECONDARY);\n",
                    literal(group.group_id.as_str()), literal(group.group_id.as_str()), group.name.quoted()
                ));
            }
        }
        self.batch(
            node,
            locked(
                sql,
                permit.expires_at,
                policy,
                unix_millis()?,
                permit.dispatch_deadline,
            ),
            policy,
        )
        .await
    }

    async fn renew(
        &self,
        lease: &LeaseSpec,
        policy: &HaPolicy,
        permit: &HaPermit,
    ) -> Result<u64, RuntimeError> {
        policy.validate()?;
        permit.check(lease.authority_binding, lease.digest())?;
        if lease.lease_seconds != policy.lease_seconds
            || lease.sql_start_time.is_empty()
            || lease.sql_start_time.len() > 33
            || lease.sql_start_time.chars().any(char::is_control)
        {
            return Err(error(
                ObservationFailureKind::Malformed,
                "invalid lease descriptor",
            ));
        }
        let node = self.node(&lease.primary)?;
        let mut sql = identity_guard(node, &lease.availability_group, &lease.primary)?;
        sql.push_str(&health_guard(&lease.availability_group, policy));
        sql.push_str(&format!(
            "IF NOT EXISTS (SELECT 1 FROM sys.dm_os_sys_info WHERE CONVERT(nvarchar(33),sqlserver_start_time,126)={}) THROW 51000, 'Lease engine incarnation changed', 1;\n",
            literal(&lease.sql_start_time)
        ));
        if !lease.candidate {
            sql.push_str(&format!("IF NOT EXISTS (SELECT 1 FROM sys.dm_hadr_availability_replica_states WHERE group_id={} AND is_local=1 AND role_desc=N'PRIMARY') THROW 51000, 'Lease owner is not primary', 1;\n", literal(lease.availability_group.group_id.as_str())));
        }
        sql.push_str(&lease_statement(
            &lease.availability_group,
            lease.lease_seconds,
            permit.expires_at,
            policy.max_clock_skew_millis,
        ));
        self.batch(
            node,
            locked(
                sql,
                permit.expires_at,
                policy,
                unix_millis()?,
                permit.dispatch_deadline,
            ),
            policy,
        )
        .await?;
        Ok(permit.expires_at)
    }
}

pub(crate) fn transition_parts(
    request: &OperationRequest,
) -> Result<
    (
        &AvailabilityGroupIdentity,
        &DatabaseLineage,
        &ReplicaIdentity,
        &ReplicaIdentity,
    ),
    RuntimeError,
> {
    match request.payload() {
        OperationPayload::PlannedSwitchover {
            availability_group,
            database,
            source,
            target,
            ..
        }
        | OperationPayload::ForcedFailover {
            availability_group,
            database,
            source,
            target,
            ..
        } => Ok((availability_group, database, source, target)),
        _ => Err(error(
            ObservationFailureKind::Unsupported,
            "request is not a primary transition",
        )),
    }
}

fn validate_survivor(
    context: &HaContext,
    group: &AvailabilityGroupIdentity,
    source: &ReplicaIdentity,
    target: &ReplicaIdentity,
    actual: &AvailabilityGroupIdentity,
    replica: &ReplicaIdentity,
) -> Result<(), RuntimeError> {
    if actual != group
        || replica.logical_id() == source.logical_id()
        || replica.logical_id() == target.logical_id()
        || !context.target.replicas.iter().any(|member| {
            member.identity.logical_id() == replica.logical_id()
                && member.identity.incarnation() == replica.incarnation()
        })
    {
        return Err(error(
            ObservationFailureKind::Inconsistent,
            "secondary reset is not an accepted surviving member",
        ));
    }
    Ok(())
}

fn literal(value: &str) -> String {
    format!("N'{}'", value.replace('\'', "''"))
}

fn database_observation(
    observation: &Observation<crate::observation::InstanceSnapshot>,
    name: &crate::SqlIdentifier,
) -> Observation<DatabaseProbe> {
    if let Observation::Failed(failure) = observation {
        return Observation::Failed(failure.clone());
    }
    let at = observation.observed_at_unix_millis();
    let failure = || {
        Observation::Failed(
            error(
                ObservationFailureKind::Unsupported,
                "local HA database identity is not currently readable",
            )
            .into_failure(at),
        )
    };
    let Observation::Present {
        value: snapshot, ..
    } = observation
    else {
        return failure();
    };
    let Observation::Present { value: group, .. } = &snapshot.availability_group else {
        return failure();
    };
    let Some(database) = group
        .databases
        .iter()
        .find(|database| database.identity.name == *name)
    else {
        return failure();
    };
    let Some(local) = &database.local else {
        return failure();
    };
    let Some(recovery) = &local.recovery else {
        return failure();
    };
    let (Some(guid), Some(fork), Some(state), Some(model)) = (
        &recovery.database_guid,
        &recovery.recovery_fork_guid,
        &local.state,
        &local.recovery_model,
    ) else {
        return failure();
    };
    Observation::Present {
        observed_at_unix_millis: at,
        value: DatabaseProbe {
            name: name.clone(),
            database_id: local.database_id,
            database_guid: guid.clone(),
            recovery_fork_id: fork.clone(),
            group_database_id: Some(database.identity.group_database_id.clone()),
            replica_id: Some(local.replica_id.clone()),
            state: state.clone(),
            recovery_model: model.clone(),
            // HA never bootstraps a database from this observation.
            backup_ready: false,
        },
    }
}

fn identity_guard(
    node: &MutationEndpoint,
    group: &AvailabilityGroupIdentity,
    replica: &ReplicaIdentity,
) -> Result<String, RuntimeError> {
    let id = replica.native_replica_id().ok_or_else(|| {
        error(
            ObservationFailureKind::Malformed,
            "native replica GUID required",
        )
    })?;
    Ok(format!(
        "IF @@SERVERNAME IS NULL OR UPPER(CONVERT(nvarchar(128),@@SERVERNAME))<>UPPER({}) THROW 51000, 'Native server changed', 1;\n\
         IF NOT EXISTS (SELECT 1 FROM sys.availability_groups WHERE group_id={} AND name={} AND cluster_type=2 AND basic_features=0 AND is_distributed=0 AND db_failover=1 AND required_synchronized_secondaries_to_commit=1) THROW 51000, 'Native HA profile changed', 1;\n\
         IF NOT EXISTS (SELECT 1 FROM sys.dm_hadr_availability_replica_states WHERE group_id={} AND replica_id={} AND is_local=1) THROW 51000, 'Native replica changed', 1;\n",
        literal(node.observer().target().expected_server_name.as_str()),
        literal(group.group_id.as_str()),
        literal(group.name.as_str()),
        literal(group.group_id.as_str()),
        literal(id.as_str())
    ))
}

fn lineage_guard(lineage: &DatabaseLineage) -> String {
    format!(
        "IF NOT EXISTS (SELECT 1 FROM sys.databases AS d INNER JOIN sys.database_recovery_status AS r ON r.database_id=d.database_id WHERE d.name={} AND d.group_database_id={} AND r.recovery_fork_guid={}) THROW 51000, 'Native database lineage changed', 1;\n",
        literal(lineage.database.name.as_str()),
        literal(lineage.database.group_database_id.as_str()),
        literal(lineage.recovery_fork_id.as_str())
    )
}

fn lease_statement(
    group: &AvailabilityGroupIdentity,
    seconds: u32,
    deadline: u64,
    skew: u64,
) -> String {
    format!(
        "IF DATEDIFF_BIG(millisecond,CONVERT(datetime2,N'1970-01-01T00:00:00'),SYSUTCDATETIME())+{}+{skew}>={deadline} THROW 51000, 'Insufficient authorized lease lifetime', 1;\n\
         ALTER AVAILABILITY GROUP {} SET (WRITE_LEASE_VALIDITY={seconds});\n",
        u64::from(seconds) * 1000,
        group.name.quoted()
    )
}

fn health_guard(group: &AvailabilityGroupIdentity, policy: &HaPolicy) -> String {
    format!(
        "DECLARE @h TABLE (create_time datetime,component_type sysname,component_name sysname,state int,state_desc sysname,data xml);\n\
         INSERT INTO @h EXEC sys.sp_server_diagnostics @repeat_interval=0;\n\
         IF (SELECT COUNT(*) FROM @h WHERE component_name=N'system')<>1 OR (SELECT COUNT(*) FROM @h WHERE component_name=N'resource')<>1 OR (SELECT COUNT(*) FROM @h WHERE component_name=N'query_processing')<>1 THROW 51000, 'Incomplete server health', 1;\n\
         IF EXISTS (SELECT 1 FROM @h WHERE component_name IN (N'system',N'resource',N'query_processing') AND (state IS NULL OR state NOT IN (1,2,3))) THROW 51000, 'Unknown server health', 1;\n\
         IF EXISTS (SELECT 1 FROM @h WHERE state=3 AND (component_name=N'system' OR ({}>=4 AND component_name=N'resource') OR ({}>=5 AND component_name=N'query_processing'))) THROW 51000, 'Unhealthy server; no lease or promotion', 1;\n\
         IF EXISTS (SELECT 1 FROM sys.dm_hadr_availability_replica_states WHERE group_id={} AND is_local=1 AND current_configuration_commit_start_time_utc IS NOT NULL AND (DATEDIFF_BIG(millisecond,current_configuration_commit_start_time_utc,SYSUTCDATETIME())<0 OR DATEDIFF_BIG(millisecond,current_configuration_commit_start_time_utc,SYSUTCDATETIME())>={})) THROW 51000, 'Configuration commit is stalled; no lease renewal', 1;\n",
        policy.health_threshold,
        policy.health_threshold,
        literal(group.group_id.as_str()),
        policy.configuration_commit_timeout_millis
    )
}
fn locked(
    body: String,
    expires: u64,
    policy: &HaPolicy,
    sent: u64,
    dispatch_deadline: u64,
) -> String {
    let earliest = sent.saturating_sub(policy.max_clock_skew_millis);
    let latest = sent
        .saturating_add(policy.command_timeout_millis)
        .saturating_add(policy.max_clock_skew_millis)
        .min(expires)
        .min(dispatch_deadline.saturating_sub(policy.max_clock_skew_millis));
    format!(
        "SET NOCOUNT ON; SET XACT_ABORT ON; SET IMPLICIT_TRANSACTIONS OFF;\n\
         IF @@TRANCOUNT<>0 THROW 51000, 'HA actions require autocommit', 1;\n\
         DECLARE @lock int; EXEC @lock=sys.sp_getapplock @Resource=N'kuberic.sqlserver.ag-mutation',@LockMode=N'Exclusive',@LockOwner=N'Session',@LockTimeout=0;\n\
         IF @lock<0 THROW 51001, 'Another native action is active', 1;\n\
         BEGIN TRY\n\
         DECLARE @now bigint=DATEDIFF_BIG(millisecond,CONVERT(datetime2,N'1970-01-01T00:00:00'),SYSUTCDATETIME());\n\
         IF @now<{earliest} OR @now>={latest} OR @now>={expires} THROW 51000, 'HA capability expired or clock skew exceeded', 1;\n\
         {body}\nEND TRY BEGIN CATCH\n\
         EXEC sys.sp_releaseapplock @Resource=N'kuberic.sqlserver.ag-mutation',@LockOwner=N'Session'; THROW;\nEND CATCH;\n\
         EXEC sys.sp_releaseapplock @Resource=N'kuberic.sqlserver.ag-mutation',@LockOwner=N'Session';"
    )
}

const HEALTH_COLUMNS: &[&str] = &[
    "server_name",
    "group_id",
    "sql_utc_millis",
    "system",
    "resource",
    "query_processing",
    "system_count",
    "resource_count",
    "query_count",
    "configuration_commit_age_millis",
    "db_failover",
];
const HEALTH_SQL: &str = r#"DECLARE @health TABLE (create_time datetime,component_type sysname,component_name sysname,state int,state_desc sysname,data xml);
INSERT INTO @health EXEC sys.sp_server_diagnostics @repeat_interval=0;
SELECT CONVERT(nvarchar(128),@@SERVERNAME) AS server_name,
CONVERT(nvarchar(36),ag.group_id) AS group_id,
CONVERT(nvarchar(20),DATEDIFF_BIG(millisecond,CONVERT(datetime2,N'1970-01-01T00:00:00'),SYSUTCDATETIME())) AS sql_utc_millis,
CONVERT(nvarchar(3),(SELECT MAX(state) FROM @health WHERE component_name=N'system')) AS system,
CONVERT(nvarchar(3),(SELECT MAX(state) FROM @health WHERE component_name=N'resource')) AS resource,
CONVERT(nvarchar(3),(SELECT MAX(state) FROM @health WHERE component_name=N'query_processing')) AS query_processing,
CONVERT(nvarchar(3),(SELECT COUNT(*) FROM @health WHERE component_name=N'system')) AS system_count,
CONVERT(nvarchar(3),(SELECT COUNT(*) FROM @health WHERE component_name=N'resource')) AS resource_count,
CONVERT(nvarchar(3),(SELECT COUNT(*) FROM @health WHERE component_name=N'query_processing')) AS query_count,
CONVERT(nvarchar(20),DATEDIFF_BIG(millisecond,ars.current_configuration_commit_start_time_utc,SYSUTCDATETIME())) AS configuration_commit_age_millis,
CONVERT(nvarchar(1),ag.db_failover) AS db_failover
FROM sys.availability_groups AS ag
INNER JOIN sys.dm_hadr_availability_replica_states AS ars ON ars.group_id=ag.group_id AND ars.is_local=1
WHERE ag.name=@P1;"#;

fn parse_health(
    rows: &[QueryRow],
    group: &AvailabilityGroupIdentity,
    server: &str,
) -> Result<HealthSample, RuntimeError> {
    let [row] = rows else {
        return Err(error(
            ObservationFailureKind::Malformed,
            "expected one HA health row",
        ));
    };
    let required = |key: &str| {
        row.get(key)
            .and_then(|value| value.as_deref())
            .ok_or_else(|| {
                error(
                    ObservationFailureKind::Malformed,
                    "missing HA health evidence",
                )
            })
    };
    if !required("server_name")?.eq_ignore_ascii_case(server)
        || !required("group_id")?.eq_ignore_ascii_case(group.group_id.as_str())
    {
        return Err(error(
            ObservationFailureKind::Inconsistent,
            "HA health evidence belongs to another native instance",
        ));
    }
    for key in ["system_count", "resource_count", "query_count"] {
        if required(key)? != "1" {
            return Err(error(
                ObservationFailureKind::Malformed,
                "missing or duplicate health component",
            ));
        }
    }
    let integer = |key| {
        required(key)?.parse::<u64>().map_err(|_| {
            error(
                ObservationFailureKind::Malformed,
                "invalid HA health integer",
            )
        })
    };
    let component = |key| {
        u8::try_from(integer(key)?).map_err(|_| {
            error(
                ObservationFailureKind::Malformed,
                "invalid health component state",
            )
        })
    };
    let commit = row
        .get("configuration_commit_age_millis")
        .ok_or_else(|| {
            error(
                ObservationFailureKind::Malformed,
                "missing configuration-commit evidence",
            )
        })?
        .as_deref()
        .map(|value| {
            value.parse::<u64>().map_err(|_| {
                error(
                    ObservationFailureKind::Malformed,
                    "invalid configuration-commit age",
                )
            })
        })
        .transpose()?;
    let db_failover = match required("db_failover")? {
        "1" => true,
        "0" => false,
        _ => {
            return Err(error(
                ObservationFailureKind::Malformed,
                "invalid DB_FAILOVER flag",
            ));
        }
    };
    Ok(HealthSample {
        sql_utc_millis: integer("sql_utc_millis")?,
        system: component("system")?,
        resource: component("resource")?,
        query_processing: component("query_processing")?,
        configuration_commit_age_millis: commit,
        db_failover,
    })
}

fn error(kind: ObservationFailureKind, message: &'static str) -> RuntimeError {
    RuntimeError::new(kind, "native HA protocol", message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AvailabilityGroupName, Guid};

    fn group() -> AvailabilityGroupIdentity {
        AvailabilityGroupIdentity {
            name: AvailabilityGroupName::new("ha-group").unwrap(),
            group_id: Guid::parse("group", "00000001-1111-2222-3333-444444444444").unwrap(),
        }
    }

    #[test]
    fn native_lease_is_expiry_bounded_and_does_not_suppress_sql_errors() {
        let sql = lease_statement(&group(), 30, 123_456, 2000);
        assert!(sql.contains("+30000+2000>=123456"));
        assert!(sql.contains("SET (WRITE_LEASE_VALIDITY=30)"));
        assert!(!sql.contains("47116"));
        assert!(!sql.contains("47119"));
        assert!(!sql.contains("CATCH"));
    }

    #[test]
    fn native_guard_checks_clock_deadline_autocommit_and_session_lock() {
        let sql = locked(
            "SELECT 1;".into(),
            25_000,
            &HaPolicy::default(),
            10_000,
            25_000,
        );
        for text in [
            "@now<8000",
            "@now>=17000",
            "@now>=25000",
            "@@TRANCOUNT<>0",
            "@LockOwner=N'Session'",
            "@LockTimeout=0",
            "sys.sp_releaseapplock",
            "THROW;",
        ] {
            assert!(sql.contains(text), "missing native guard: {text}");
        }
    }

    #[test]
    fn health_guard_cannot_renew_on_unknown_health_or_stalled_configuration() {
        let sql = health_guard(&group(), &HaPolicy::default());
        assert!(sql.contains("sp_server_diagnostics"));
        assert!(sql.contains("state IS NULL OR state NOT IN (1,2,3)"));
        assert!(sql.contains("current_configuration_commit_start_time_utc"));
        assert!(sql.contains(">=60000"));
        assert!(sql.contains("Unhealthy server; no lease or promotion"));
    }

    #[test]
    fn permits_cannot_be_reused_for_another_binding_action_or_expired_time() {
        let permit = HaPermit::new([1; 32], [2; 32], unix_millis().unwrap() + 1000);
        permit.check([1; 32], [2; 32]).unwrap();
        assert!(permit.check([9; 32], [2; 32]).is_err());
        assert!(permit.check([1; 32], [9; 32]).is_err());
        let expired = HaPermit::new([1; 32], [2; 32], 0);
        assert!(expired.check([1; 32], [2; 32]).is_err());
    }

    #[test]
    fn malformed_or_missing_health_components_are_not_healthy_defaults() {
        let mut row = HEALTH_COLUMNS
            .iter()
            .map(|name| ((*name).to_owned(), None))
            .collect::<QueryRow>();
        let native_group = group();
        for (name, value) in [
            ("server_name", "sql-1".to_owned()),
            ("group_id", native_group.group_id.to_string()),
            ("sql_utc_millis", "1000".to_owned()),
            ("system", "1".to_owned()),
            ("resource", "1".to_owned()),
            ("query_processing", "1".to_owned()),
            ("system_count", "1".to_owned()),
            ("resource_count", "1".to_owned()),
            ("query_count", "1".to_owned()),
            ("db_failover", "1".to_owned()),
        ] {
            row.insert(name.to_owned(), Some(value));
        }
        assert!(
            parse_health(&[row.clone()], &native_group, "sql-1")
                .unwrap()
                .db_failover
        );
        row.insert("query_count".to_owned(), Some("0".into()));
        assert!(parse_health(&[row.clone()], &native_group, "sql-1").is_err());
        row.insert("query_count".to_owned(), Some("1".into()));
        row.insert(
            "configuration_commit_age_millis".to_owned(),
            Some("-1".into()),
        );
        assert!(parse_health(&[row], &native_group, "sql-1").is_err());
    }

    #[test]
    fn removed_source_database_projection_preserves_connectivity_failure() {
        for kind in [
            ObservationFailureKind::Unreachable,
            ObservationFailureKind::TimedOut,
        ] {
            let failed = error(kind, "source connection unavailable").into_failure(123);
            let instance = Observation::Failed(failed.clone());
            assert_eq!(
                database_observation(&instance, &crate::SqlIdentifier::new("database").unwrap()),
                Observation::Failed(failed)
            );
        }
    }
}
