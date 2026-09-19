use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use sqlserver_replicated::{
    AvailabilityGroupName, Endpoint, EvidenceScope, HealthStatus, NativeRole, Observation,
    ObservationFailureKind, ObservationTarget, RuntimeError, SqlIdentifier, SqlServerHealthMonitor,
    SqlServerInstanceManager, TdsConnectionConfig, TdsError, TdsErrorKind, TdsExecutor, TdsQuery,
    TdsQueryKind, TdsResultSet, TdsRow,
};

const GROUP_ID: &str = "0000000a-0000-4000-8000-000000000001";
const DATABASE_ID: &str = "00000014-0000-4000-8000-000000000001";
const REPLICA_1: &str = "00000001-0000-4000-8000-000000000001";
const REPLICA_2: &str = "00000002-0000-4000-8000-000000000001";
const REPLICA_3: &str = "00000003-0000-4000-8000-000000000001";
const DATABASE_GUID: &str = "00000015-0000-4000-8000-000000000001";
const RECOVERY_FORK: &str = "00000016-0000-4000-8000-000000000001";
const FAMILY_GUID: &str = "00000017-0000-4000-8000-000000000001";
const FIRST_RECOVERY_FORK: &str = "00000018-0000-4000-8000-000000000001";
const MAX_PROGRESS: &str = "9999999999999999999999999";

struct ScriptedExecutor {
    responses: Mutex<VecDeque<Result<Vec<TdsResultSet>, TdsError>>>,
    calls: Mutex<Vec<Vec<TdsQuery>>>,
}

impl ScriptedExecutor {
    fn new(responses: impl IntoIterator<Item = Result<Vec<TdsResultSet>, TdsError>>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
            calls: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl TdsExecutor for ScriptedExecutor {
    async fn execute(&self, queries: &[TdsQuery]) -> Result<Vec<TdsResultSet>, TdsError> {
        self.calls.lock().unwrap().push(queries.to_vec());
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected executor call")
    }
}

fn row(values: &[(&str, Option<&str>)]) -> TdsRow {
    TdsRow::new(
        values
            .iter()
            .map(|(name, value)| ((*name).to_string(), value.map(str::to_string)))
            .collect::<BTreeMap<_, _>>(),
    )
}

fn capabilities(major: &str, sysadmin: &str) -> TdsResultSet {
    vec![row(&[
        ("server_name", Some("SQL-0")),
        ("configured_server_name", Some("SQL-0")),
        ("product_version", Some("16.0.4195.2")),
        ("product_major_version", Some(major)),
        ("edition_id", Some("-2117995310")),
        ("edition_name", Some("Developer Edition (64-bit)")),
        ("is_hadr_enabled", Some("1")),
        ("hadr_manager_status", Some("1")),
        ("host_platform", Some("Linux")),
        ("host_distribution", Some("Ubuntu")),
        ("host_release", Some("22.04")),
        ("can_view_server_performance_state", Some("1")),
        ("can_view_any_definition", Some("1")),
        ("can_alter_any_availability_group", Some(sysadmin)),
        ("is_sysadmin", Some(sysadmin)),
    ])]
}

fn anchor(sequence_number: &str) -> TdsResultSet {
    vec![row(&[
        ("configured_server_name", Some("SQL-0")),
        ("group_id", Some(GROUP_ID)),
        ("sequence_number", Some(sequence_number)),
        ("local_replica_id", Some(REPLICA_1)),
        ("local_role", Some("1")),
        ("local_role_desc", Some("PRIMARY")),
    ])]
}

fn group() -> TdsResultSet {
    vec![row(&[
        ("group_id", Some(GROUP_ID)),
        ("group_name", Some("kuberic-ag")),
        ("cluster_type", Some("2")),
        ("cluster_type_desc", Some("EXTERNAL")),
        ("sequence_number", Some("17")),
        ("basic_features", Some("0")),
        ("is_distributed", Some("0")),
        ("required_synchronized_secondaries_to_commit", Some("1")),
    ])]
}

fn replica(replica_id: &'static str, server_name: &'static str) -> TdsRow {
    let endpoint = match server_name {
        "SQL-0" => "TCP://sql-0.sql.default.svc:5022",
        "SQL-1" => "TCP://sql-1.sql.default.svc:5022",
        _ => "TCP://sql-2.sql.default.svc:5022",
    };
    row(&[
        ("group_id", Some(GROUP_ID)),
        ("replica_id", Some(replica_id)),
        ("replica_server_name", Some(server_name)),
        ("endpoint_url", Some(endpoint)),
        ("availability_mode", Some("1")),
        ("availability_mode_desc", Some("SYNCHRONOUS_COMMIT")),
        ("failover_mode", Some("3")),
        ("failover_mode_desc", Some("EXTERNAL")),
        ("seeding_mode", Some("0")),
        ("seeding_mode_desc", Some("AUTOMATIC")),
    ])
}

fn replicas() -> TdsResultSet {
    vec![
        replica(REPLICA_1, "SQL-0"),
        replica(REPLICA_2, "SQL-1"),
        replica(REPLICA_3, "SQL-2"),
    ]
}

fn replica_state(
    replica_id: &'static str,
    is_local: &'static str,
    role: &'static str,
    role_desc: &'static str,
) -> TdsRow {
    row(&[
        ("group_id", Some(GROUP_ID)),
        ("replica_id", Some(replica_id)),
        ("is_local", Some(is_local)),
        ("role", Some(role)),
        ("role_desc", Some(role_desc)),
        ("operational_state_desc", Some("ONLINE")),
        ("connected_state_desc", Some("CONNECTED")),
        ("recovery_health_desc", Some("ONLINE")),
        ("synchronization_health_desc", Some("HEALTHY")),
        ("last_connect_error_number", Some("0")),
        ("last_connect_error_description", None),
        ("last_connect_error_timestamp", None),
    ])
}

fn replica_states() -> TdsResultSet {
    vec![
        replica_state(REPLICA_1, "1", "1", "PRIMARY"),
        replica_state(REPLICA_2, "0", "2", "SECONDARY"),
        replica_state(REPLICA_3, "0", "2", "SECONDARY"),
    ]
}

fn database_state(
    replica_id: &'static str,
    is_local: &'static str,
    database_guid: Option<&'static str>,
    recovery_fork: Option<&'static str>,
    synchronization_state: &'static str,
    is_primary: &'static str,
) -> TdsRow {
    row(&[
        ("group_id", Some(GROUP_ID)),
        ("group_database_id", Some(DATABASE_ID)),
        ("database_name", Some("application")),
        ("replica_id", Some(replica_id)),
        ("database_id", Some("5")),
        ("is_local", Some(is_local)),
        ("is_primary_replica", Some(is_primary)),
        ("synchronization_state_desc", Some(synchronization_state)),
        ("synchronization_health_desc", Some("HEALTHY")),
        ("database_state_desc", Some("ONLINE")),
        ("is_suspended", Some("0")),
        ("suspend_reason_desc", None),
        ("last_hardened_lsn", Some(MAX_PROGRESS)),
        ("last_hardened_time", Some("2026-09-19T20:57:42.000")),
        ("last_redone_lsn", Some("9999999999999999999999998")),
        ("last_redone_time", Some("2026-09-19T20:57:41.000")),
        ("last_commit_lsn", Some("9999999999999999999999997")),
        ("last_commit_time", Some("2026-09-19T20:57:40.000")),
        ("database_guid", database_guid),
        ("recovery_fork_guid", recovery_fork),
        ("family_guid", database_guid.map(|_| FAMILY_GUID)),
        (
            "first_recovery_fork_guid",
            database_guid.map(|_| FIRST_RECOVERY_FORK),
        ),
        ("fork_point_lsn", None),
    ])
}

fn database_states(local_synchronization_state: &'static str) -> TdsResultSet {
    vec![
        database_state(
            REPLICA_1,
            "1",
            Some(DATABASE_GUID),
            Some(RECOVERY_FORK),
            local_synchronization_state,
            "1",
        ),
        database_state(REPLICA_2, "0", None, None, "SYNCHRONIZED", "0"),
        database_state(REPLICA_3, "0", None, None, "SYNCHRONIZED", "0"),
    ]
}

fn healthy_results() -> Vec<TdsResultSet> {
    vec![
        capabilities("16", "0"),
        anchor("17"),
        group(),
        replicas(),
        replica_states(),
        database_states("SYNCHRONIZED"),
        Vec::new(),
        Vec::new(),
        anchor("17"),
    ]
}

fn target() -> ObservationTarget {
    ObservationTarget::new(
        AvailabilityGroupName::new("kuberic-ag").unwrap(),
        SqlIdentifier::new("application").unwrap(),
    )
}

fn manager(executor: Arc<dyn TdsExecutor>) -> SqlServerInstanceManager {
    SqlServerInstanceManager::new(executor, target())
}

#[tokio::test]
async fn startup_capabilities_require_the_supported_server() {
    let executor = Arc::new(ScriptedExecutor::new([Ok(vec![capabilities("16", "0")])]));
    let capabilities = manager(executor)
        .check_startup_capabilities()
        .await
        .unwrap();

    assert_eq!(capabilities.product_major_version, 16);
    assert_eq!(capabilities.configured_server_name.as_str(), "sql-0");
    assert!(capabilities.least_privilege_warnings().is_empty());
}

#[tokio::test]
async fn elevated_observer_is_reported_without_hiding_observations() {
    let executor = Arc::new(ScriptedExecutor::new([Ok(vec![capabilities("16", "1")])]));
    let capabilities = manager(executor)
        .check_startup_capabilities()
        .await
        .unwrap();

    assert_eq!(
        capabilities.least_privilege_warnings(),
        vec![
            "observation principal is a sysadmin",
            "observation principal can alter availability groups"
        ]
    );
}

#[tokio::test]
async fn unsupported_engine_is_rejected_at_startup() {
    let executor = Arc::new(ScriptedExecutor::new([Ok(vec![capabilities("15", "0")])]));
    assert!(matches!(
        manager(executor).check_startup_capabilities().await,
        Err(RuntimeError::UnsupportedCapability {
            field: "engine major version",
            ..
        })
    ));
}

#[tokio::test]
async fn observation_preserves_identity_scope_role_and_exact_progress() {
    let executor = Arc::new(ScriptedExecutor::new([Ok(healthy_results())]));
    let instance = manager(executor.clone());

    let observation = instance.observe_at(1_000).await;
    let Observation::Present {
        value,
        observed_at_unix_millis,
    } = observation
    else {
        panic!("expected a present observation");
    };

    assert_eq!(observed_at_unix_millis, 1_000);
    assert_eq!(value.local_role, NativeRole::Primary);
    assert_eq!(value.health.status, HealthStatus::Healthy);
    assert_eq!(value.replicas.len(), 3);
    assert_eq!(
        value.replica_states[1].scope,
        EvidenceScope::PrimaryReportedRemote
    );
    let local_database = value.database.unwrap();
    let local_state = local_database
        .replica_states
        .iter()
        .find(|state| state.scope == EvidenceScope::Local)
        .unwrap();
    assert_eq!(
        local_state
            .progress
            .hardened_block
            .as_ref()
            .unwrap()
            .to_string(),
        MAX_PROGRESS
    );
    assert_eq!(
        local_database
            .local_lineage()
            .unwrap()
            .recovery_fork_id
            .as_str(),
        RECOVERY_FORK
    );

    let json = serde_json::to_value(local_state).unwrap();
    assert_eq!(json["progress"]["hardened_block"], MAX_PROGRESS);

    let calls = executor.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].len(), 9);
    assert_eq!(calls[0][0].kind(), TdsQueryKind::Capabilities);
    assert_eq!(calls[0][1].kind(), TdsQueryKind::AnchorBefore);
    assert_eq!(calls[0][8].kind(), TdsQueryKind::AnchorAfter);
    assert_eq!(calls[0][1].parameters(), &["kuberic-ag".to_string()]);
    assert!(!calls[0][1].statement().contains("kuberic-ag"));
}

#[tokio::test]
async fn absent_group_is_not_reported_as_a_failed_query() {
    let mut results = healthy_results();
    results[1].clear();
    results[2].clear();
    results[3].clear();
    results[4].clear();
    results[5].clear();
    results[8].clear();
    let executor = Arc::new(ScriptedExecutor::new([Ok(results)]));

    assert_eq!(
        manager(executor).observe_at(2_000).await,
        Observation::Absent {
            observed_at_unix_millis: 2_000
        }
    );
}

#[tokio::test]
async fn changed_anchor_rejects_a_torn_snapshot() {
    let mut results = healthy_results();
    results[8] = anchor("18");
    let executor = Arc::new(ScriptedExecutor::new([Ok(results)]));

    let Observation::Failed(failure) = manager(executor).observe_at(3_000).await else {
        panic!("expected failed observation");
    };
    assert_eq!(failure.kind, ObservationFailureKind::Malformed);
    assert!(failure.message.contains("changed while"));
}

#[tokio::test]
async fn permission_error_is_not_collapsed_into_absence() {
    let executor = Arc::new(ScriptedExecutor::new([Err(TdsError::new(
        TdsErrorKind::PermissionDenied,
        "SELECT permission denied",
    ))]));

    let Observation::Failed(failure) = manager(executor).observe_at(4_000).await else {
        panic!("expected failed observation");
    };
    assert_eq!(failure.kind, ObservationFailureKind::PermissionDenied);
    assert_eq!(failure.observed_at_unix_millis, 4_000);
}

#[tokio::test]
async fn malformed_native_crosswalk_fails_closed() {
    let mut results = healthy_results();
    results[4][1] = replica_state(
        "000000ff-0000-4000-8000-000000000001",
        "0",
        "2",
        "SECONDARY",
    );
    let executor = Arc::new(ScriptedExecutor::new([Ok(results)]));

    let Observation::Failed(failure) = manager(executor).observe_at(5_000).await else {
        panic!("expected failed observation");
    };
    assert_eq!(failure.kind, ObservationFailureKind::Malformed);
    assert!(failure.message.contains("catalog"));
}

#[tokio::test]
async fn health_degrades_without_discarding_the_snapshot() {
    let mut results = healthy_results();
    results[5] = database_states("SYNCHRONIZING");
    let executor = Arc::new(ScriptedExecutor::new([Ok(results)]));

    let Observation::Present { value, .. } = manager(executor).observe_at(6_000).await else {
        panic!("expected present observation");
    };
    assert_eq!(value.health.status, HealthStatus::Healthy);

    let mut secondary_results = healthy_results();
    secondary_results[1] = vec![row(&[
        ("configured_server_name", Some("SQL-0")),
        ("group_id", Some(GROUP_ID)),
        ("sequence_number", Some("17")),
        ("local_replica_id", Some(REPLICA_1)),
        ("local_role", Some("2")),
        ("local_role_desc", Some("SECONDARY")),
    ])];
    secondary_results[4][0] = replica_state(REPLICA_1, "1", "2", "SECONDARY");
    secondary_results[5] = database_states("SYNCHRONIZING");
    secondary_results[5][0] = database_state(
        REPLICA_1,
        "1",
        Some(DATABASE_GUID),
        Some(RECOVERY_FORK),
        "SYNCHRONIZING",
        "0",
    );
    secondary_results[8] = secondary_results[1].clone();
    let executor = Arc::new(ScriptedExecutor::new([Ok(secondary_results)]));
    let Observation::Present { value, .. } = manager(executor).observe_at(6_001).await else {
        panic!("expected present observation");
    };
    assert_eq!(value.health.status, HealthStatus::Degraded);
    assert!(
        value
            .health
            .issues
            .iter()
            .any(|issue| issue.contains("secondary synchronization"))
    );
}

#[tokio::test]
async fn monitor_keeps_stale_success_separate_from_latest_failure() {
    let executor = Arc::new(ScriptedExecutor::new([
        Ok(healthy_results()),
        Err(TdsError::new(
            TdsErrorKind::Unreachable,
            "connection refused",
        )),
    ]));
    let instance = Arc::new(manager(executor));
    let monitor = SqlServerHealthMonitor::new(instance, Duration::from_secs(1)).unwrap();

    let first = monitor.poll_once_at(7_000).await;
    assert!(matches!(first.latest_attempt, Observation::Present { .. }));
    let second = monitor.poll_once_at(8_001).await;
    assert!(matches!(second.latest_attempt, Observation::Failed(_)));
    let last_successful = second.last_successful.unwrap();
    assert_eq!(last_successful.observed_at_unix_millis, 7_000);
    assert!(!last_successful.is_fresh_at(8_001, 1_000));
}

#[test]
fn tds_connection_configuration_rejects_unsafe_empty_values() {
    let endpoint = Endpoint::new("sql-0.sql.default.svc", 1433).unwrap();
    assert!(
        TdsConnectionConfig::new(
            endpoint.clone(),
            "",
            "password",
            None,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .is_err()
    );
    assert!(
        TdsConnectionConfig::new(
            endpoint,
            "observer",
            "password",
            None,
            Duration::ZERO,
            Duration::from_secs(1),
        )
        .is_err()
    );
}
