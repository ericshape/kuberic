use std::collections::BTreeSet;

use serde::Serialize;

use crate::config::{
    AvailabilityMode, ClusterType, Edition, FailoverMode, SUPPORTED_ENGINE_MAJOR,
    SUPPORTED_REPLICA_COUNT, SUPPORTED_REQUIRED_SECONDARIES, SeedingMode,
};
use crate::error::ContractError;
use crate::tds::{
    TdsError, TdsErrorKind, TdsExecutor, TdsQuery, TdsQueryKind, TdsResultSet, TdsRow,
};
use crate::types::{
    AvailabilityGroupIdentity, AvailabilityGroupName, DatabaseIdentity, DatabaseLineage,
    DecimalProgress, Endpoint, Guid, NativeProgress, NativeRole, Observation, ObservationFailure,
    ObservationFailureKind, ServerName, SqlIdentifier, validate_text,
};

const MAX_NATIVE_VALUE_BYTES: usize = 512;

const CAPABILITIES_QUERY: &str = r#"
SELECT
    CONVERT(nvarchar(128), SERVERPROPERTY('ServerName')) AS server_name,
    CONVERT(nvarchar(128), @@SERVERNAME) AS configured_server_name,
    CONVERT(varchar(128), SERVERPROPERTY('ProductVersion')) AS product_version,
    CONVERT(varchar(10), SERVERPROPERTY('ProductMajorVersion')) AS product_major_version,
    CONVERT(varchar(20), SERVERPROPERTY('EditionID')) AS edition_id,
    CONVERT(nvarchar(128), SERVERPROPERTY('Edition')) AS edition_name,
    CONVERT(varchar(1), SERVERPROPERTY('IsHadrEnabled')) AS is_hadr_enabled,
    CONVERT(varchar(10), SERVERPROPERTY('HadrManagerStatus')) AS hadr_manager_status,
    CONVERT(nvarchar(256), host.host_platform) AS host_platform,
    CONVERT(nvarchar(256), host.host_distribution) AS host_distribution,
    CONVERT(nvarchar(256), host.host_release) AS host_release,
    CONVERT(varchar(1), HAS_PERMS_BY_NAME(NULL, NULL, 'VIEW SERVER PERFORMANCE STATE'))
        AS can_view_server_performance_state,
    CONVERT(varchar(1), HAS_PERMS_BY_NAME(NULL, NULL, 'VIEW ANY DEFINITION'))
        AS can_view_any_definition,
    CONVERT(varchar(1), HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER ANY AVAILABILITY GROUP'))
        AS can_alter_any_availability_group,
    CONVERT(varchar(1), HAS_PERMS_BY_NAME(@P1, 'AVAILABILITY GROUP', 'ALTER'))
        AS can_alter_target_availability_group,
    CONVERT(varchar(1), HAS_PERMS_BY_NAME(@P1, 'AVAILABILITY GROUP', 'CONTROL'))
        AS can_control_target_availability_group,
    CONVERT(varchar(1), IS_SRVROLEMEMBER('sysadmin')) AS is_sysadmin
FROM sys.dm_os_host_info AS host;
"#;

const ANCHOR_QUERY: &str = r#"
SELECT
    CONVERT(nvarchar(128), @@SERVERNAME) AS configured_server_name,
    CONVERT(varchar(36), groups.group_id) AS group_id,
    CONVERT(varchar(20), groups.sequence_number) AS sequence_number,
    CONVERT(varchar(36), states.replica_id) AS local_replica_id,
    CONVERT(varchar(10), states.role) AS local_role,
    CONVERT(nvarchar(60), states.role_desc) AS local_role_desc
FROM sys.availability_groups AS groups
JOIN sys.dm_hadr_availability_replica_states AS states
  ON states.group_id = groups.group_id
 AND states.is_local = 1
WHERE groups.name = @P1;
"#;

const AVAILABILITY_GROUP_QUERY: &str = r#"
SELECT
    CONVERT(varchar(36), group_id) AS group_id,
    CONVERT(nvarchar(128), name) AS group_name,
    CONVERT(varchar(10), cluster_type) AS cluster_type,
    CONVERT(nvarchar(60), cluster_type_desc) AS cluster_type_desc,
    CONVERT(varchar(20), sequence_number) AS sequence_number,
    CONVERT(varchar(1), basic_features) AS basic_features,
    CONVERT(varchar(1), is_distributed) AS is_distributed,
    CONVERT(varchar(10), required_synchronized_secondaries_to_commit)
        AS required_synchronized_secondaries_to_commit
FROM sys.availability_groups
WHERE name = @P1;
"#;

const AVAILABILITY_REPLICAS_QUERY: &str = r#"
SELECT
    CONVERT(varchar(36), replicas.group_id) AS group_id,
    CONVERT(varchar(36), replicas.replica_id) AS replica_id,
    CONVERT(nvarchar(128), replicas.replica_server_name) AS replica_server_name,
    CONVERT(nvarchar(256), replicas.endpoint_url) AS endpoint_url,
    CONVERT(varchar(10), replicas.availability_mode) AS availability_mode,
    CONVERT(nvarchar(60), replicas.availability_mode_desc) AS availability_mode_desc,
    CONVERT(varchar(10), replicas.failover_mode) AS failover_mode,
    CONVERT(nvarchar(60), replicas.failover_mode_desc) AS failover_mode_desc,
    CONVERT(varchar(10), replicas.seeding_mode) AS seeding_mode,
    CONVERT(nvarchar(60), replicas.seeding_mode_desc) AS seeding_mode_desc
FROM sys.availability_replicas AS replicas
JOIN sys.availability_groups AS groups ON groups.group_id = replicas.group_id
WHERE groups.name = @P1
ORDER BY replicas.replica_id;
"#;

const REPLICA_STATES_QUERY: &str = r#"
SELECT
    CONVERT(varchar(36), states.group_id) AS group_id,
    CONVERT(varchar(36), states.replica_id) AS replica_id,
    CONVERT(varchar(1), states.is_local) AS is_local,
    CONVERT(varchar(10), states.role) AS role,
    CONVERT(nvarchar(60), states.role_desc) AS role_desc,
    CONVERT(nvarchar(60), states.operational_state_desc) AS operational_state_desc,
    CONVERT(nvarchar(60), states.connected_state_desc) AS connected_state_desc,
    CONVERT(nvarchar(60), states.recovery_health_desc) AS recovery_health_desc,
    CONVERT(nvarchar(60), states.synchronization_health_desc)
        AS synchronization_health_desc,
    CONVERT(varchar(20), states.last_connect_error_number) AS last_connect_error_number,
    CONVERT(nvarchar(512), states.last_connect_error_description)
        AS last_connect_error_description,
    CONVERT(varchar(33), states.last_connect_error_timestamp, 126)
        AS last_connect_error_timestamp
FROM sys.dm_hadr_availability_replica_states AS states
JOIN sys.availability_groups AS groups ON groups.group_id = states.group_id
WHERE groups.name = @P1
ORDER BY states.is_local DESC, states.replica_id;
"#;

const AVAILABILITY_DATABASE_QUERY: &str = r#"
SELECT
    CONVERT(varchar(36), databases.group_id) AS group_id,
    CONVERT(varchar(36), databases.group_database_id) AS group_database_id,
    CONVERT(nvarchar(128), databases.database_name) AS database_name,
    CONVERT(varchar(36), states.replica_id) AS replica_id,
    CONVERT(varchar(20), states.database_id) AS database_id,
    CONVERT(varchar(1), states.is_local) AS is_local,
    CONVERT(varchar(1), states.is_primary_replica) AS is_primary_replica,
    CONVERT(nvarchar(60), states.synchronization_state_desc)
        AS synchronization_state_desc,
    CONVERT(nvarchar(60), states.synchronization_health_desc)
        AS synchronization_health_desc,
    CONVERT(nvarchar(60), states.database_state_desc) AS database_state_desc,
    CONVERT(varchar(1), states.is_suspended) AS is_suspended,
    CONVERT(nvarchar(60), states.suspend_reason_desc) AS suspend_reason_desc,
    CONVERT(varchar(25), states.last_hardened_lsn) AS last_hardened_lsn,
    CONVERT(varchar(33), states.last_hardened_time, 126) AS last_hardened_time,
    CONVERT(varchar(25), states.last_redone_lsn) AS last_redone_lsn,
    CONVERT(varchar(33), states.last_redone_time, 126) AS last_redone_time,
    CONVERT(varchar(25), states.last_commit_lsn) AS last_commit_lsn,
    CONVERT(varchar(33), states.last_commit_time, 126) AS last_commit_time,
    CONVERT(varchar(36), recovery.database_guid) AS database_guid,
    CONVERT(varchar(36), recovery.recovery_fork_guid) AS recovery_fork_guid,
    CONVERT(varchar(36), recovery.family_guid) AS family_guid,
    CONVERT(varchar(36), recovery.first_recovery_fork_guid) AS first_recovery_fork_guid,
    CONVERT(varchar(25), recovery.fork_point_lsn) AS fork_point_lsn
FROM sys.availability_databases_cluster AS databases
LEFT JOIN sys.dm_hadr_database_replica_states AS states
  ON states.group_id = databases.group_id
 AND states.group_database_id = databases.group_database_id
LEFT JOIN sys.database_recovery_status AS recovery
  ON states.is_local = 1
 AND recovery.database_id = states.database_id
WHERE databases.group_id = (
    SELECT group_id FROM sys.availability_groups WHERE name = @P1
)
  AND databases.database_name = @P2
ORDER BY states.is_local DESC, states.replica_id;
"#;

const AUTOMATIC_SEEDING_QUERY: &str = r#"
SELECT
    CONVERT(varchar(33), seeding.start_time, 126) AS start_time,
    CONVERT(varchar(33), seeding.completion_time, 126) AS completion_time,
    CONVERT(varchar(36), seeding.ag_id) AS group_id,
    CONVERT(varchar(36), seeding.ag_db_id) AS group_database_id,
    CONVERT(varchar(36), seeding.ag_remote_replica_id) AS remote_replica_id,
    CONVERT(varchar(36), seeding.operation_id) AS operation_id,
    CONVERT(varchar(1), seeding.is_source) AS is_source,
    CONVERT(nvarchar(60), seeding.current_state) AS current_state,
    CONVERT(varchar(1), seeding.performed_seeding) AS performed_seeding,
    CONVERT(varchar(20), seeding.failure_state) AS failure_state,
    CONVERT(nvarchar(512), seeding.failure_state_desc) AS failure_state_desc,
    CONVERT(varchar(20), seeding.error_code) AS error_code,
    CONVERT(varchar(20), seeding.number_of_attempts) AS number_of_attempts
FROM sys.dm_hadr_automatic_seeding AS seeding
WHERE seeding.ag_id = (
    SELECT group_id FROM sys.availability_groups WHERE name = @P1
)
  AND seeding.ag_db_id = (
    SELECT group_database_id
    FROM sys.availability_databases_cluster
    WHERE group_id = seeding.ag_id AND database_name = @P2
)
ORDER BY seeding.start_time, seeding.operation_id;
"#;

const PHYSICAL_SEEDING_QUERY: &str = r#"
SELECT
    CONVERT(varchar(36), seeding.local_physical_seeding_id) AS local_seeding_id,
    CONVERT(varchar(36), seeding.remote_physical_seeding_id) AS remote_seeding_id,
    CONVERT(nvarchar(128), seeding.local_database_name) AS local_database_name,
    CONVERT(nvarchar(128), seeding.remote_machine_name) AS remote_machine_name,
    CONVERT(nvarchar(60), seeding.role_desc) AS role_desc,
    CONVERT(nvarchar(60), seeding.internal_state_desc) AS internal_state_desc,
    CONVERT(varchar(25), seeding.transferred_size_bytes) AS transferred_size_bytes,
    CONVERT(varchar(25), seeding.database_size_bytes) AS database_size_bytes,
    CONVERT(varchar(33), seeding.start_time_utc, 126) AS start_time_utc,
    CONVERT(varchar(33), seeding.end_time_utc, 126) AS end_time_utc,
    CONVERT(varchar(33), seeding.estimate_time_complete_utc, 126)
        AS estimate_time_complete_utc,
    CONVERT(varchar(20), seeding.failure_code) AS failure_code,
    CONVERT(nvarchar(512), seeding.failure_message) AS failure_message,
    CONVERT(varchar(1), seeding.is_compression_enabled) AS is_compression_enabled
FROM sys.dm_hadr_physical_seeding_stats AS seeding
WHERE seeding.local_database_name = @P1
ORDER BY seeding.start_time_utc, seeding.local_physical_seeding_id;
"#;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObservationTarget {
    pub availability_group: AvailabilityGroupName,
    pub database: SqlIdentifier,
}

impl ObservationTarget {
    pub fn new(availability_group: AvailabilityGroupName, database: SqlIdentifier) -> Self {
        Self {
            availability_group,
            database,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeValue(String);

impl NativeValue {
    fn parse(field: &'static str, value: &str) -> Result<Self, RuntimeError> {
        validate_text(field, value, MAX_NATIVE_VALUE_BYTES)
            .map_err(|error| malformed(field, error))?;
        Ok(Self(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServerCapabilities {
    pub server_name: ServerName,
    pub configured_server_name: ServerName,
    pub product_version: NativeValue,
    pub product_major_version: u16,
    pub edition: Edition,
    pub edition_name: NativeValue,
    pub host_platform: NativeValue,
    pub host_distribution: NativeValue,
    pub host_release: NativeValue,
    pub is_hadr_enabled: bool,
    pub hadr_manager_running: bool,
    pub can_view_server_performance_state: bool,
    pub can_view_any_definition: bool,
    pub can_alter_any_availability_group: bool,
    pub can_alter_target_availability_group: bool,
    pub can_control_target_availability_group: bool,
    pub is_sysadmin: bool,
}

impl ServerCapabilities {
    pub fn least_privilege_warnings(&self) -> Vec<&'static str> {
        let mut warnings = Vec::new();
        if self.is_sysadmin {
            warnings.push("observation principal is a sysadmin");
        }
        if self.can_alter_any_availability_group
            || self.can_alter_target_availability_group
            || self.can_control_target_availability_group
        {
            warnings.push("observation principal can alter availability groups");
        }
        warnings
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AvailabilityGroupSnapshot {
    pub identity: AvailabilityGroupIdentity,
    pub cluster_type: ClusterType,
    pub sequence_number: u64,
    pub required_synchronized_secondaries_to_commit: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AvailabilityReplicaSnapshot {
    pub group_id: Guid,
    pub replica_id: Guid,
    pub server_name: ServerName,
    pub endpoint: Endpoint,
    pub availability_mode: AvailabilityMode,
    pub failover_mode: FailoverMode,
    pub seeding_mode: SeedingMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceScope {
    Local,
    PrimaryReportedRemote,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReplicaStateSnapshot {
    pub group_id: Guid,
    pub replica_id: Guid,
    pub scope: EvidenceScope,
    pub role: Option<NativeRole>,
    pub operational_state: Option<NativeValue>,
    pub connected_state: Option<NativeValue>,
    pub recovery_health: Option<NativeValue>,
    pub synchronization_health: Option<NativeValue>,
    pub last_connect_error_number: Option<i32>,
    pub last_connect_error_description: Option<NativeValue>,
    pub last_connect_error_timestamp: Option<NativeValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveryLineageSnapshot {
    pub database_guid: Guid,
    pub recovery_fork_guid: Guid,
    pub family_guid: Guid,
    pub first_recovery_fork_guid: Guid,
    pub fork_point_lsn: Option<DecimalProgress>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DatabaseReplicaStateSnapshot {
    pub replica_id: Guid,
    pub scope: EvidenceScope,
    pub database_id: Option<u32>,
    pub is_primary_replica: Option<bool>,
    pub synchronization_state: Option<NativeValue>,
    pub synchronization_health: Option<NativeValue>,
    pub database_state: Option<NativeValue>,
    pub is_suspended: Option<bool>,
    pub suspend_reason: Option<NativeValue>,
    pub progress: NativeProgress,
    pub last_hardened_time: Option<NativeValue>,
    pub last_redone_time: Option<NativeValue>,
    pub last_commit_time: Option<NativeValue>,
    pub local_recovery_lineage: Option<RecoveryLineageSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AvailabilityDatabaseSnapshot {
    pub identity: DatabaseIdentity,
    pub replica_states: Vec<DatabaseReplicaStateSnapshot>,
}

impl AvailabilityDatabaseSnapshot {
    pub fn local_lineage(&self) -> Option<DatabaseLineage> {
        self.replica_states
            .iter()
            .find_map(|state| state.local_recovery_lineage.as_ref())
            .map(|lineage| DatabaseLineage {
                database: self.identity.clone(),
                recovery_fork_id: lineage.recovery_fork_guid.clone(),
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AutomaticSeedingSnapshot {
    pub start_time: Option<NativeValue>,
    pub completion_time: Option<NativeValue>,
    pub group_id: Guid,
    pub group_database_id: Guid,
    pub remote_replica_id: Guid,
    pub operation_id: Guid,
    pub is_source: bool,
    pub current_state: NativeValue,
    pub performed_seeding: bool,
    pub failure_state: Option<i32>,
    pub failure_state_description: Option<NativeValue>,
    pub error_code: Option<i32>,
    pub number_of_attempts: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PhysicalSeedingSnapshot {
    pub local_seeding_id: Guid,
    pub remote_seeding_id: Option<Guid>,
    pub local_database_name: SqlIdentifier,
    pub remote_machine_name: NativeValue,
    pub role: NativeValue,
    pub internal_state: NativeValue,
    pub transferred_size_bytes: Option<DecimalProgress>,
    pub database_size_bytes: Option<DecimalProgress>,
    pub start_time_utc: Option<NativeValue>,
    pub end_time_utc: Option<NativeValue>,
    pub estimate_time_complete_utc: Option<NativeValue>,
    pub failure_code: Option<i32>,
    pub failure_message: Option<NativeValue>,
    pub is_compression_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Healthy,
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HealthSummary {
    pub status: HealthStatus,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SqlServerSnapshot {
    pub capabilities: ServerCapabilities,
    pub availability_group: AvailabilityGroupSnapshot,
    pub local_replica_id: Guid,
    pub local_role: NativeRole,
    pub replicas: Vec<AvailabilityReplicaSnapshot>,
    pub replica_states: Vec<ReplicaStateSnapshot>,
    pub database: Option<AvailabilityDatabaseSnapshot>,
    pub automatic_seeding: Vec<AutomaticSeedingSnapshot>,
    pub physical_seeding: Vec<PhysicalSeedingSnapshot>,
    pub health: HealthSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Tds(#[from] TdsError),
    #[error("malformed SQL Server observation field {field}: {detail}")]
    Malformed { field: &'static str, detail: String },
    #[error("unsupported SQL Server capability {field}: expected {expected}, observed {actual}")]
    UnsupportedCapability {
        field: &'static str,
        expected: &'static str,
        actual: String,
    },
    #[error("observation principal lacks {0}")]
    PermissionDenied(&'static str),
    #[error("SQL Server observation changed while it was being collected")]
    InconsistentSnapshot,
}

impl RuntimeError {
    fn failure_kind(&self) -> ObservationFailureKind {
        match self {
            Self::Tds(error) => match error.kind() {
                TdsErrorKind::Unreachable => ObservationFailureKind::Unreachable,
                TdsErrorKind::Authentication | TdsErrorKind::PermissionDenied => {
                    ObservationFailureKind::PermissionDenied
                }
                TdsErrorKind::TimedOut => ObservationFailureKind::TimedOut,
                TdsErrorKind::Protocol | TdsErrorKind::Query => ObservationFailureKind::Malformed,
            },
            Self::PermissionDenied(_) => ObservationFailureKind::PermissionDenied,
            Self::UnsupportedCapability { .. } => ObservationFailureKind::Unsupported,
            Self::Malformed { .. } | Self::InconsistentSnapshot => {
                ObservationFailureKind::Malformed
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservationAnchor {
    configured_server_name: ServerName,
    group_id: Guid,
    sequence_number: u64,
    local_replica_id: Guid,
    local_role: NativeRole,
}

pub(crate) fn capability_queries(target: &ObservationTarget) -> Vec<TdsQuery> {
    vec![TdsQuery::new(
        TdsQueryKind::Capabilities,
        CAPABILITIES_QUERY,
        [target.availability_group.as_str().to_string()],
    )]
}

pub(crate) fn observation_queries(target: &ObservationTarget) -> Vec<TdsQuery> {
    let group = || target.availability_group.as_str().to_string();
    let database = || target.database.as_str().to_string();
    vec![
        TdsQuery::new(TdsQueryKind::Capabilities, CAPABILITIES_QUERY, [group()]),
        TdsQuery::new(TdsQueryKind::AnchorBefore, ANCHOR_QUERY, [group()]),
        TdsQuery::new(
            TdsQueryKind::AvailabilityGroup,
            AVAILABILITY_GROUP_QUERY,
            [group()],
        ),
        TdsQuery::new(
            TdsQueryKind::AvailabilityReplicas,
            AVAILABILITY_REPLICAS_QUERY,
            [group()],
        ),
        TdsQuery::new(TdsQueryKind::ReplicaStates, REPLICA_STATES_QUERY, [group()]),
        TdsQuery::new(
            TdsQueryKind::AvailabilityDatabase,
            AVAILABILITY_DATABASE_QUERY,
            [group(), database()],
        ),
        TdsQuery::new(
            TdsQueryKind::AutomaticSeeding,
            AUTOMATIC_SEEDING_QUERY,
            [group(), database()],
        ),
        TdsQuery::new(
            TdsQueryKind::PhysicalSeeding,
            PHYSICAL_SEEDING_QUERY,
            [database()],
        ),
        TdsQuery::new(TdsQueryKind::AnchorAfter, ANCHOR_QUERY, [group()]),
    ]
}

pub(crate) async fn check_capabilities(
    executor: &dyn TdsExecutor,
    target: &ObservationTarget,
) -> Result<ServerCapabilities, RuntimeError> {
    let mut results = executor.execute(&capability_queries(target)).await?;
    if results.len() != 1 {
        return Err(malformed(
            "capability result sets",
            format!("expected 1, observed {}", results.len()),
        ));
    }
    parse_capabilities(results.remove(0))
}

pub(crate) async fn observe(
    executor: &dyn TdsExecutor,
    target: &ObservationTarget,
    observed_at_unix_millis: u64,
) -> Observation<SqlServerSnapshot> {
    match collect_snapshot(executor, target).await {
        Ok(Some(value)) => Observation::Present {
            value,
            observed_at_unix_millis,
        },
        Ok(None) => Observation::Absent {
            observed_at_unix_millis,
        },
        Err(error) => Observation::Failed(ObservationFailure {
            kind: error.failure_kind(),
            message: error.to_string(),
            observed_at_unix_millis,
        }),
    }
}

async fn collect_snapshot(
    executor: &dyn TdsExecutor,
    target: &ObservationTarget,
) -> Result<Option<SqlServerSnapshot>, RuntimeError> {
    let mut results = executor.execute(&observation_queries(target)).await?;
    if results.len() != 9 {
        return Err(malformed(
            "observation result sets",
            format!("expected 9, observed {}", results.len()),
        ));
    }

    let anchor_after = parse_anchor(results.pop().expect("length checked"))?;
    let physical_seeding = parse_physical_seeding(results.pop().expect("length checked"))?;
    let automatic_seeding = parse_automatic_seeding(results.pop().expect("length checked"))?;
    let database_rows = results.pop().expect("length checked");
    let replica_states = parse_replica_states(results.pop().expect("length checked"))?;
    let replicas = parse_replicas(results.pop().expect("length checked"))?;
    let group = parse_group(results.pop().expect("length checked"))?;
    let anchor_before = parse_anchor(results.pop().expect("length checked"))?;
    let capabilities = parse_capabilities(results.pop().expect("length checked"))?;

    let Some(group) = group else {
        if anchor_before.is_some() || anchor_after.is_some() {
            return Err(RuntimeError::InconsistentSnapshot);
        }
        return Ok(None);
    };

    let (Some(anchor_before), Some(anchor_after)) = (anchor_before, anchor_after) else {
        return Err(RuntimeError::InconsistentSnapshot);
    };
    if anchor_before != anchor_after
        || anchor_before.group_id != group.identity.group_id
        || anchor_before.sequence_number != group.sequence_number
        || anchor_before.configured_server_name != capabilities.configured_server_name
    {
        return Err(RuntimeError::InconsistentSnapshot);
    }

    validate_replica_crosswalk(&group.identity.group_id, &replicas, &replica_states)?;
    if !replicas
        .iter()
        .any(|replica| replica.replica_id == anchor_before.local_replica_id)
    {
        return Err(malformed(
            "local replica ID",
            "local DMV identity is absent from sys.availability_replicas",
        ));
    }
    let local_states: Vec<&ReplicaStateSnapshot> = replica_states
        .iter()
        .filter(|state| state.scope == EvidenceScope::Local)
        .collect();
    if local_states.len() != 1
        || local_states[0].replica_id != anchor_before.local_replica_id
        || local_states[0].role.as_ref() != Some(&anchor_before.local_role)
    {
        return Err(RuntimeError::InconsistentSnapshot);
    }

    let database = parse_database(database_rows, &group.identity.group_id, &replicas)?;
    if let Some(local_database) = database.as_ref().and_then(|database| {
        database
            .replica_states
            .iter()
            .find(|state| state.scope == EvidenceScope::Local)
    }) {
        if local_database.replica_id != anchor_before.local_replica_id {
            return Err(malformed(
                "local database replica ID",
                "database and replica DMVs disagree about local identity",
            ));
        }
        match anchor_before.local_role {
            NativeRole::Primary if local_database.is_primary_replica != Some(true) => {
                return Err(RuntimeError::InconsistentSnapshot);
            }
            NativeRole::Secondary if local_database.is_primary_replica != Some(false) => {
                return Err(RuntimeError::InconsistentSnapshot);
            }
            _ => {}
        }
    }
    validate_seeding(
        &group.identity.group_id,
        database.as_ref(),
        &automatic_seeding,
    )?;

    let health = evaluate_health(
        anchor_before.local_replica_id.clone(),
        &anchor_before.local_role,
        &replicas,
        &replica_states,
        database.as_ref(),
    );

    Ok(Some(SqlServerSnapshot {
        capabilities,
        availability_group: group,
        local_replica_id: anchor_before.local_replica_id,
        local_role: anchor_before.local_role,
        replicas,
        replica_states,
        database,
        automatic_seeding,
        physical_seeding,
        health,
    }))
}

fn parse_capabilities(rows: TdsResultSet) -> Result<ServerCapabilities, RuntimeError> {
    let row = exactly_one(rows, "server capabilities")?;
    let product_major_version = parse_required::<u16>(&row, "product_major_version")?;
    if product_major_version != SUPPORTED_ENGINE_MAJOR {
        return Err(unsupported(
            "engine major version",
            "16 (SQL Server 2022)",
            product_major_version,
        ));
    }

    let edition_id = parse_required::<i64>(&row, "edition_id")?;
    let edition = match edition_id {
        -2_117_995_310 => Edition::Developer,
        1_804_890_536 | 1_872_460_670 => Edition::Enterprise,
        other => {
            return Err(unsupported("edition ID", "Developer or Enterprise", other));
        }
    };
    let host_platform = native_required(&row, "host_platform")?;
    if !host_platform.as_str().eq_ignore_ascii_case("linux") {
        return Err(unsupported(
            "host platform",
            "Linux",
            host_platform.as_str(),
        ));
    }
    let is_hadr_enabled = parse_bool_required(&row, "is_hadr_enabled")?;
    if !is_hadr_enabled {
        return Err(unsupported("Always On availability groups", "enabled", 0));
    }
    let hadr_manager_status = parse_required::<u8>(&row, "hadr_manager_status")?;
    if hadr_manager_status != 1 {
        return Err(unsupported(
            "HADR manager status",
            "started (1)",
            hadr_manager_status,
        ));
    }
    let can_view_server_performance_state =
        parse_bool_required(&row, "can_view_server_performance_state")?;
    if !can_view_server_performance_state {
        return Err(RuntimeError::PermissionDenied(
            "VIEW SERVER PERFORMANCE STATE",
        ));
    }
    let can_view_any_definition = parse_bool_required(&row, "can_view_any_definition")?;
    if !can_view_any_definition {
        return Err(RuntimeError::PermissionDenied("VIEW ANY DEFINITION"));
    }

    Ok(ServerCapabilities {
        server_name: parse_server_name(&row, "server_name")?,
        configured_server_name: parse_server_name(&row, "configured_server_name")?,
        product_version: native_required(&row, "product_version")?,
        product_major_version,
        edition,
        edition_name: native_required(&row, "edition_name")?,
        host_platform,
        host_distribution: native_required(&row, "host_distribution")?,
        host_release: native_required(&row, "host_release")?,
        is_hadr_enabled,
        hadr_manager_running: true,
        can_view_server_performance_state,
        can_view_any_definition,
        can_alter_any_availability_group: parse_bool_required(
            &row,
            "can_alter_any_availability_group",
        )?,
        can_alter_target_availability_group: parse_bool_optional(
            &row,
            "can_alter_target_availability_group",
        )?
        .unwrap_or(false),
        can_control_target_availability_group: parse_bool_optional(
            &row,
            "can_control_target_availability_group",
        )?
        .unwrap_or(false),
        is_sysadmin: parse_bool_required(&row, "is_sysadmin")?,
    })
}

fn parse_anchor(rows: TdsResultSet) -> Result<Option<ObservationAnchor>, RuntimeError> {
    let Some(row) = zero_or_one(rows, "observation anchor")? else {
        return Ok(None);
    };
    Ok(Some(ObservationAnchor {
        configured_server_name: parse_server_name(&row, "configured_server_name")?,
        group_id: parse_guid(&row, "group_id")?,
        sequence_number: parse_required(&row, "sequence_number")?,
        local_replica_id: parse_guid(&row, "local_replica_id")?,
        local_role: parse_role(&row, "local_role", "local_role_desc")?,
    }))
}

fn parse_group(rows: TdsResultSet) -> Result<Option<AvailabilityGroupSnapshot>, RuntimeError> {
    let Some(row) = zero_or_one(rows, "availability group")? else {
        return Ok(None);
    };
    let cluster_type_code = parse_required::<u8>(&row, "cluster_type")?;
    let cluster_type_desc = required(&row, "cluster_type_desc")?;
    if cluster_type_code != 2 || cluster_type_desc != "EXTERNAL" {
        return Err(unsupported(
            "availability group cluster type",
            "EXTERNAL (2)",
            format!("{cluster_type_desc} ({cluster_type_code})"),
        ));
    }
    if parse_bool_required(&row, "basic_features")? {
        return Err(unsupported("availability group kind", "full", "basic"));
    }
    if parse_bool_required(&row, "is_distributed")? {
        return Err(unsupported(
            "availability group kind",
            "non-distributed",
            "distributed",
        ));
    }
    let required_secondaries =
        parse_required::<u8>(&row, "required_synchronized_secondaries_to_commit")?;
    if required_secondaries != SUPPORTED_REQUIRED_SECONDARIES {
        return Err(unsupported(
            "required synchronized secondaries",
            "1",
            required_secondaries,
        ));
    }

    Ok(Some(AvailabilityGroupSnapshot {
        identity: AvailabilityGroupIdentity {
            name: AvailabilityGroupName::new(required(&row, "group_name")?)
                .map_err(|error| malformed("group_name", error))?,
            group_id: parse_guid(&row, "group_id")?,
        },
        cluster_type: ClusterType::External,
        sequence_number: parse_required(&row, "sequence_number")?,
        required_synchronized_secondaries_to_commit: required_secondaries,
    }))
}

fn parse_replicas(rows: TdsResultSet) -> Result<Vec<AvailabilityReplicaSnapshot>, RuntimeError> {
    rows.into_iter()
        .map(|row| {
            let availability_mode_code = parse_required::<u8>(&row, "availability_mode")?;
            let availability_mode_desc = required(&row, "availability_mode_desc")?;
            if availability_mode_code != 1 || availability_mode_desc != "SYNCHRONOUS_COMMIT" {
                return Err(unsupported(
                    "replica availability mode",
                    "SYNCHRONOUS_COMMIT (1)",
                    format!("{availability_mode_desc} ({availability_mode_code})"),
                ));
            }
            let _failover_mode_code = parse_required::<u8>(&row, "failover_mode")?;
            let failover_mode_desc = required(&row, "failover_mode_desc")?;
            if failover_mode_desc != "EXTERNAL" {
                return Err(unsupported(
                    "replica failover mode",
                    "EXTERNAL",
                    failover_mode_desc,
                ));
            }
            let seeding_mode_code = parse_required::<u8>(&row, "seeding_mode")?;
            let seeding_mode_desc = required(&row, "seeding_mode_desc")?;
            if seeding_mode_code != 0 || seeding_mode_desc != "AUTOMATIC" {
                return Err(unsupported(
                    "replica seeding mode",
                    "AUTOMATIC (0)",
                    format!("{seeding_mode_desc} ({seeding_mode_code})"),
                ));
            }

            Ok(AvailabilityReplicaSnapshot {
                group_id: parse_guid(&row, "group_id")?,
                replica_id: parse_guid(&row, "replica_id")?,
                server_name: parse_server_name(&row, "replica_server_name")?,
                endpoint: parse_endpoint(required(&row, "endpoint_url")?)?,
                availability_mode: AvailabilityMode::SynchronousCommit,
                failover_mode: FailoverMode::External,
                seeding_mode: SeedingMode::Automatic,
            })
        })
        .collect()
}

fn parse_replica_states(rows: TdsResultSet) -> Result<Vec<ReplicaStateSnapshot>, RuntimeError> {
    rows.into_iter()
        .map(|row| {
            Ok(ReplicaStateSnapshot {
                group_id: parse_guid(&row, "group_id")?,
                replica_id: parse_guid(&row, "replica_id")?,
                scope: parse_scope(&row)?,
                role: parse_optional_role(&row, "role", "role_desc")?,
                operational_state: native_optional(&row, "operational_state_desc")?,
                connected_state: native_optional(&row, "connected_state_desc")?,
                recovery_health: native_optional(&row, "recovery_health_desc")?,
                synchronization_health: native_optional(&row, "synchronization_health_desc")?,
                last_connect_error_number: parse_optional(&row, "last_connect_error_number")?,
                last_connect_error_description: native_optional(
                    &row,
                    "last_connect_error_description",
                )?,
                last_connect_error_timestamp: native_optional(
                    &row,
                    "last_connect_error_timestamp",
                )?,
            })
        })
        .collect()
}

fn parse_database(
    rows: TdsResultSet,
    expected_group_id: &Guid,
    replicas: &[AvailabilityReplicaSnapshot],
) -> Result<Option<AvailabilityDatabaseSnapshot>, RuntimeError> {
    let Some(first) = rows.first() else {
        return Ok(None);
    };
    let identity = DatabaseIdentity {
        name: SqlIdentifier::new(required(first, "database_name")?)
            .map_err(|error| malformed("database_name", error))?,
        group_database_id: parse_guid(first, "group_database_id")?,
    };
    if parse_guid(first, "group_id")? != *expected_group_id {
        return Err(malformed(
            "database group ID",
            "database belongs to another availability group",
        ));
    }

    let known_replicas: BTreeSet<Guid> = replicas
        .iter()
        .map(|replica| replica.replica_id.clone())
        .collect();
    let mut seen_replicas = BTreeSet::new();
    let mut local_count = 0;
    let mut replica_states = Vec::new();
    for row in rows {
        if parse_guid(&row, "group_id")? != *expected_group_id
            || parse_guid(&row, "group_database_id")? != identity.group_database_id
            || required(&row, "database_name")? != identity.name.as_str()
        {
            return Err(malformed(
                "database identity",
                "database rows do not share one native identity",
            ));
        }

        let Some(replica_id) = optional_guid(&row, "replica_id")? else {
            continue;
        };
        if !known_replicas.contains(&replica_id) {
            return Err(malformed(
                "database replica ID",
                "database state refers to an unknown replica",
            ));
        }
        if !seen_replicas.insert(replica_id.clone()) {
            return Err(malformed(
                "database replica ID",
                "database state contains a duplicate replica",
            ));
        }

        let scope = parse_scope(&row)?;
        if scope == EvidenceScope::Local {
            local_count += 1;
        }
        let local_recovery_lineage = parse_recovery_lineage(&row, scope)?;
        replica_states.push(DatabaseReplicaStateSnapshot {
            replica_id,
            scope,
            database_id: parse_optional(&row, "database_id")?,
            is_primary_replica: parse_bool_optional(&row, "is_primary_replica")?,
            synchronization_state: native_optional(&row, "synchronization_state_desc")?,
            synchronization_health: native_optional(&row, "synchronization_health_desc")?,
            database_state: native_optional(&row, "database_state_desc")?,
            is_suspended: parse_bool_optional(&row, "is_suspended")?,
            suspend_reason: native_optional(&row, "suspend_reason_desc")?,
            progress: NativeProgress {
                hardened_block: parse_progress(&row, "last_hardened_lsn")?,
                redone_record: parse_progress(&row, "last_redone_lsn")?,
                committed_record: parse_progress(&row, "last_commit_lsn")?,
            },
            last_hardened_time: native_optional(&row, "last_hardened_time")?,
            last_redone_time: native_optional(&row, "last_redone_time")?,
            last_commit_time: native_optional(&row, "last_commit_time")?,
            local_recovery_lineage,
        });
    }
    if local_count > 1 {
        return Err(malformed(
            "local database state",
            "more than one row is marked local",
        ));
    }

    Ok(Some(AvailabilityDatabaseSnapshot {
        identity,
        replica_states,
    }))
}

fn parse_recovery_lineage(
    row: &TdsRow,
    scope: EvidenceScope,
) -> Result<Option<RecoveryLineageSnapshot>, RuntimeError> {
    let database_guid = optional_guid(row, "database_guid")?;
    let recovery_fork_guid = optional_guid(row, "recovery_fork_guid")?;
    let family_guid = optional_guid(row, "family_guid")?;
    let first_recovery_fork_guid = optional_guid(row, "first_recovery_fork_guid")?;
    let has_any = database_guid.is_some()
        || recovery_fork_guid.is_some()
        || family_guid.is_some()
        || first_recovery_fork_guid.is_some();
    if scope != EvidenceScope::Local {
        if has_any {
            return Err(malformed(
                "database recovery lineage",
                "remote rows must not carry local recovery metadata",
            ));
        }
        return Ok(None);
    }
    if !has_any {
        return Ok(None);
    }

    Ok(Some(RecoveryLineageSnapshot {
        database_guid: database_guid.ok_or_else(|| {
            malformed(
                "database_guid",
                "local recovery lineage is only partially populated",
            )
        })?,
        recovery_fork_guid: recovery_fork_guid.ok_or_else(|| {
            malformed(
                "recovery_fork_guid",
                "local recovery lineage is only partially populated",
            )
        })?,
        family_guid: family_guid.ok_or_else(|| {
            malformed(
                "family_guid",
                "local recovery lineage is only partially populated",
            )
        })?,
        first_recovery_fork_guid: first_recovery_fork_guid.ok_or_else(|| {
            malformed(
                "first_recovery_fork_guid",
                "local recovery lineage is only partially populated",
            )
        })?,
        fork_point_lsn: parse_progress(row, "fork_point_lsn")?,
    }))
}

fn parse_automatic_seeding(
    rows: TdsResultSet,
) -> Result<Vec<AutomaticSeedingSnapshot>, RuntimeError> {
    rows.into_iter()
        .map(|row| {
            Ok(AutomaticSeedingSnapshot {
                start_time: native_optional(&row, "start_time")?,
                completion_time: native_optional(&row, "completion_time")?,
                group_id: parse_guid(&row, "group_id")?,
                group_database_id: parse_guid(&row, "group_database_id")?,
                remote_replica_id: parse_guid(&row, "remote_replica_id")?,
                operation_id: parse_guid(&row, "operation_id")?,
                is_source: parse_bool_required(&row, "is_source")?,
                current_state: native_required(&row, "current_state")?,
                performed_seeding: parse_bool_required(&row, "performed_seeding")?,
                failure_state: parse_optional(&row, "failure_state")?,
                failure_state_description: native_optional(&row, "failure_state_desc")?,
                error_code: parse_optional(&row, "error_code")?,
                number_of_attempts: parse_required(&row, "number_of_attempts")?,
            })
        })
        .collect()
}

fn parse_physical_seeding(
    rows: TdsResultSet,
) -> Result<Vec<PhysicalSeedingSnapshot>, RuntimeError> {
    rows.into_iter()
        .map(|row| {
            Ok(PhysicalSeedingSnapshot {
                local_seeding_id: parse_guid(&row, "local_seeding_id")?,
                remote_seeding_id: optional_guid(&row, "remote_seeding_id")?,
                local_database_name: SqlIdentifier::new(required(&row, "local_database_name")?)
                    .map_err(|error| malformed("local_database_name", error))?,
                remote_machine_name: native_required(&row, "remote_machine_name")?,
                role: native_required(&row, "role_desc")?,
                internal_state: native_required(&row, "internal_state_desc")?,
                transferred_size_bytes: parse_progress(&row, "transferred_size_bytes")?,
                database_size_bytes: parse_progress(&row, "database_size_bytes")?,
                start_time_utc: native_optional(&row, "start_time_utc")?,
                end_time_utc: native_optional(&row, "end_time_utc")?,
                estimate_time_complete_utc: native_optional(&row, "estimate_time_complete_utc")?,
                failure_code: parse_optional(&row, "failure_code")?,
                failure_message: native_optional(&row, "failure_message")?,
                is_compression_enabled: parse_bool_required(&row, "is_compression_enabled")?,
            })
        })
        .collect()
}

fn validate_replica_crosswalk(
    group_id: &Guid,
    replicas: &[AvailabilityReplicaSnapshot],
    states: &[ReplicaStateSnapshot],
) -> Result<(), RuntimeError> {
    let mut known = BTreeSet::new();
    for replica in replicas {
        if replica.group_id != *group_id {
            return Err(malformed(
                "replica group ID",
                "replica belongs to another availability group",
            ));
        }
        if !known.insert(replica.replica_id.clone()) {
            return Err(malformed(
                "replica ID",
                "sys.availability_replicas contains a duplicate",
            ));
        }
    }

    let mut state_ids = BTreeSet::new();
    for state in states {
        if state.group_id != *group_id || !known.contains(&state.replica_id) {
            return Err(malformed(
                "replica state identity",
                "DMV state does not match the availability group catalog",
            ));
        }
        if !state_ids.insert(state.replica_id.clone()) {
            return Err(malformed(
                "replica state identity",
                "DMV state contains a duplicate replica",
            ));
        }
    }
    Ok(())
}

fn validate_seeding(
    group_id: &Guid,
    database: Option<&AvailabilityDatabaseSnapshot>,
    automatic: &[AutomaticSeedingSnapshot],
) -> Result<(), RuntimeError> {
    for seeding in automatic {
        if seeding.group_id != *group_id
            || database.is_none_or(|database| {
                seeding.group_database_id != database.identity.group_database_id
            })
        {
            return Err(malformed(
                "automatic seeding identity",
                "seeding history does not match the observed database",
            ));
        }
    }
    Ok(())
}

fn evaluate_health(
    local_replica_id: Guid,
    local_role: &NativeRole,
    replicas: &[AvailabilityReplicaSnapshot],
    replica_states: &[ReplicaStateSnapshot],
    database: Option<&AvailabilityDatabaseSnapshot>,
) -> HealthSummary {
    let mut issues = Vec::new();
    if replicas.len() != usize::from(SUPPORTED_REPLICA_COUNT) {
        issues.push(format!(
            "expected {SUPPORTED_REPLICA_COUNT} configured replicas, observed {}",
            replicas.len()
        ));
    }
    if !matches!(local_role, NativeRole::Primary | NativeRole::Secondary) {
        issues.push(format!("local replica role is {local_role:?}"));
    }

    if let Some(local) = replica_states
        .iter()
        .find(|state| state.replica_id == local_replica_id && state.scope == EvidenceScope::Local)
    {
        require_healthy_value(
            &mut issues,
            "local replica operational state",
            local.operational_state.as_ref(),
            "ONLINE",
        );
        require_healthy_value(
            &mut issues,
            "local replica connection state",
            local.connected_state.as_ref(),
            "CONNECTED",
        );
        require_healthy_value(
            &mut issues,
            "local replica synchronization health",
            local.synchronization_health.as_ref(),
            "HEALTHY",
        );
    } else {
        issues.push("local replica state is missing".to_string());
    }
    if matches!(local_role, NativeRole::Primary) {
        let healthy_secondaries = replica_states
            .iter()
            .filter(|state| {
                state.scope == EvidenceScope::PrimaryReportedRemote
                    && state.connected_state.as_ref().map(NativeValue::as_str) == Some("CONNECTED")
                    && state
                        .synchronization_health
                        .as_ref()
                        .map(NativeValue::as_str)
                        == Some("HEALTHY")
            })
            .count();
        if healthy_secondaries < usize::from(SUPPORTED_REQUIRED_SECONDARIES) {
            issues.push(format!(
                "primary sees {healthy_secondaries} healthy connected secondaries, expected at least {SUPPORTED_REQUIRED_SECONDARIES}"
            ));
        }
    }

    match database {
        None => issues.push("managed availability database is absent".to_string()),
        Some(database) => {
            let local = database
                .replica_states
                .iter()
                .find(|state| state.scope == EvidenceScope::Local);
            match local {
                None => issues.push("local managed database state is missing".to_string()),
                Some(local) => {
                    require_healthy_value(
                        &mut issues,
                        "local database state",
                        local.database_state.as_ref(),
                        "ONLINE",
                    );
                    require_healthy_value(
                        &mut issues,
                        "local database synchronization health",
                        local.synchronization_health.as_ref(),
                        "HEALTHY",
                    );
                    if matches!(local_role, NativeRole::Secondary) {
                        require_healthy_value(
                            &mut issues,
                            "local secondary synchronization state",
                            local.synchronization_state.as_ref(),
                            "SYNCHRONIZED",
                        );
                    }
                    if local.is_suspended != Some(false) {
                        issues.push(
                            "local database is suspended or suspension is unknown".to_string(),
                        );
                    }
                    if local.local_recovery_lineage.is_none() {
                        issues.push("local database recovery lineage is unavailable".to_string());
                    }
                }
            }
            if matches!(local_role, NativeRole::Primary) {
                let synchronized_secondaries = database
                    .replica_states
                    .iter()
                    .filter(|state| {
                        state.scope == EvidenceScope::PrimaryReportedRemote
                            && state
                                .synchronization_state
                                .as_ref()
                                .map(NativeValue::as_str)
                                == Some("SYNCHRONIZED")
                            && state
                                .synchronization_health
                                .as_ref()
                                .map(NativeValue::as_str)
                                == Some("HEALTHY")
                    })
                    .count();
                if synchronized_secondaries < usize::from(SUPPORTED_REQUIRED_SECONDARIES) {
                    issues.push(format!(
                        "primary sees {synchronized_secondaries} synchronized database secondaries, expected at least {SUPPORTED_REQUIRED_SECONDARIES}"
                    ));
                }
            }
        }
    }

    HealthSummary {
        status: if issues.is_empty() {
            HealthStatus::Healthy
        } else {
            HealthStatus::Degraded
        },
        issues,
    }
}

fn require_healthy_value(
    issues: &mut Vec<String>,
    field: &str,
    observed: Option<&NativeValue>,
    expected: &str,
) {
    if observed.map(NativeValue::as_str) != Some(expected) {
        issues.push(format!(
            "{field} is {}, expected {expected}",
            observed.map_or("unknown", NativeValue::as_str)
        ));
    }
}

fn exactly_one(rows: TdsResultSet, field: &'static str) -> Result<TdsRow, RuntimeError> {
    if rows.len() != 1 {
        return Err(malformed(
            field,
            format!("expected exactly one row, observed {}", rows.len()),
        ));
    }
    Ok(rows.into_iter().next().expect("length checked"))
}

fn zero_or_one(rows: TdsResultSet, field: &'static str) -> Result<Option<TdsRow>, RuntimeError> {
    if rows.len() > 1 {
        return Err(malformed(
            field,
            format!("expected at most one row, observed {}", rows.len()),
        ));
    }
    Ok(rows.into_iter().next())
}

fn required<'a>(row: &'a TdsRow, column: &'static str) -> Result<&'a str, RuntimeError> {
    row.get(column)
        .ok_or_else(|| malformed(column, "column is missing"))?
        .ok_or_else(|| malformed(column, "value is NULL"))
}

fn optional<'a>(row: &'a TdsRow, column: &'static str) -> Result<Option<&'a str>, RuntimeError> {
    row.get(column)
        .ok_or_else(|| malformed(column, "column is missing"))
}

fn parse_required<T>(row: &TdsRow, column: &'static str) -> Result<T, RuntimeError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    required(row, column)?
        .parse()
        .map_err(|error| malformed(column, error))
}

fn parse_optional<T>(row: &TdsRow, column: &'static str) -> Result<Option<T>, RuntimeError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    optional(row, column)?
        .map(|value| value.parse().map_err(|error| malformed(column, error)))
        .transpose()
}

fn parse_bool_required(row: &TdsRow, column: &'static str) -> Result<bool, RuntimeError> {
    parse_bool(required(row, column)?, column)
}

fn parse_bool_optional(row: &TdsRow, column: &'static str) -> Result<Option<bool>, RuntimeError> {
    optional(row, column)?
        .map(|value| parse_bool(value, column))
        .transpose()
}

fn parse_bool(value: &str, column: &'static str) -> Result<bool, RuntimeError> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(malformed(column, "expected 0 or 1")),
    }
}

fn parse_guid(row: &TdsRow, column: &'static str) -> Result<Guid, RuntimeError> {
    Guid::parse(column, required(row, column)?).map_err(|error| malformed(column, error))
}

fn optional_guid(row: &TdsRow, column: &'static str) -> Result<Option<Guid>, RuntimeError> {
    optional(row, column)?
        .map(|value| Guid::parse(column, value).map_err(|error| malformed(column, error)))
        .transpose()
}

fn parse_server_name(row: &TdsRow, column: &'static str) -> Result<ServerName, RuntimeError> {
    ServerName::new(required(row, column)?).map_err(|error| malformed(column, error))
}

fn native_required(row: &TdsRow, column: &'static str) -> Result<NativeValue, RuntimeError> {
    NativeValue::parse(column, required(row, column)?)
}

fn native_optional(
    row: &TdsRow,
    column: &'static str,
) -> Result<Option<NativeValue>, RuntimeError> {
    optional(row, column)?
        .map(|value| NativeValue::parse(column, value))
        .transpose()
}

fn parse_progress(
    row: &TdsRow,
    column: &'static str,
) -> Result<Option<DecimalProgress>, RuntimeError> {
    optional(row, column)?
        .map(|value| DecimalProgress::parse(value).map_err(|error| malformed(column, error)))
        .transpose()
}

fn parse_scope(row: &TdsRow) -> Result<EvidenceScope, RuntimeError> {
    Ok(if parse_bool_required(row, "is_local")? {
        EvidenceScope::Local
    } else {
        EvidenceScope::PrimaryReportedRemote
    })
}

fn parse_role(
    row: &TdsRow,
    code_column: &'static str,
    description_column: &'static str,
) -> Result<NativeRole, RuntimeError> {
    let code = parse_required::<u8>(row, code_column)?;
    let description = required(row, description_column)?;
    parse_role_values(code, description, description_column)
}

fn parse_optional_role(
    row: &TdsRow,
    code_column: &'static str,
    description_column: &'static str,
) -> Result<Option<NativeRole>, RuntimeError> {
    match (
        parse_optional::<u8>(row, code_column)?,
        optional(row, description_column)?,
    ) {
        (None, None) => Ok(None),
        (Some(code), Some(description)) => {
            parse_role_values(code, description, description_column).map(Some)
        }
        _ => Err(malformed(
            description_column,
            "numeric and descriptive role values must both be NULL or both be present",
        )),
    }
}

fn parse_role_values(
    code: u8,
    description: &str,
    description_column: &'static str,
) -> Result<NativeRole, RuntimeError> {
    let expected = match code {
        0 => Some("RESOLVING"),
        1 => Some("PRIMARY"),
        2 => Some("SECONDARY"),
        _ => None,
    };
    if expected.is_some_and(|expected| expected != description) {
        return Err(malformed(
            description_column,
            "numeric and descriptive role values disagree",
        ));
    }
    if expected.is_none() && matches!(description, "RESOLVING" | "PRIMARY" | "SECONDARY") {
        return Err(malformed(
            description_column,
            "numeric and descriptive role values disagree",
        ));
    }
    NativeRole::parse(description).map_err(|error| malformed(description_column, error))
}

fn parse_endpoint(value: &str) -> Result<Endpoint, RuntimeError> {
    let Some((scheme, address)) = value.split_once("://") else {
        return Err(malformed("endpoint_url", "endpoint URL has no scheme"));
    };
    if !scheme.eq_ignore_ascii_case("tcp") {
        return Err(malformed("endpoint_url", "endpoint scheme is not TCP"));
    }
    let Some((host, port)) = address.rsplit_once(':') else {
        return Err(malformed("endpoint_url", "endpoint URL has no port"));
    };
    let port = port
        .parse::<u16>()
        .map_err(|error| malformed("endpoint_url", error))?;
    Endpoint::new(host, port).map_err(|error| malformed("endpoint_url", error))
}

fn malformed(field: &'static str, detail: impl std::fmt::Display) -> RuntimeError {
    RuntimeError::Malformed {
        field,
        detail: detail.to_string(),
    }
}

fn unsupported(
    field: &'static str,
    expected: &'static str,
    actual: impl std::fmt::Display,
) -> RuntimeError {
    RuntimeError::UnsupportedCapability {
        field,
        expected,
        actual: actual.to_string(),
    }
}

impl From<ContractError> for RuntimeError {
    fn from(error: ContractError) -> Self {
        malformed("contract value", error)
    }
}
