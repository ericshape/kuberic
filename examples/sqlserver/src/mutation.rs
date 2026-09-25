use std::collections::BTreeSet;
use std::path::PathBuf;

use async_trait::async_trait;
use tokio::time::timeout;

use crate::config::MutationMode;
use crate::convergence::{AcceptedAuthority, DatabaseProbe, NativeAction, NodeEvidence};
use crate::executor::QueryRow;
use crate::instance::unix_millis;
use crate::observation::{InstanceSnapshot, observe_session};
use crate::runtime_config::{ConnectionSettings, ObserverConfig, validate_path};
use crate::runtime_error::RuntimeError;
use crate::tds::{TdsPurpose, TdsSession, connect_session, read_secret};
use crate::{
    AvailabilityGroupIdentity, AvailabilityGroupName, DatabaseIdentity, Endpoint, Guid,
    Observation, ObservationFailureKind, OperationEnvelope, OperationPayload, ReplicaIdentity,
    SUPPORTED_ENGINE_MAJOR, SUPPORTED_REPLICA_COUNT, SUPPORTED_REQUIRED_SECONDARIES, ServerName,
    SqlIdentifier,
};

/// The embedding authority must authenticate the command and, for reseed,
/// independently verify current destructive approval and the exact target fence.
/// Structural receipt binding and local journal/application locks are not proof.
#[async_trait]
pub trait AuthorizationVerifier: Send + Sync {
    async fn verify_request(
        &self,
        envelope: &OperationEnvelope,
        authority: &AcceptedAuthority,
    ) -> Result<(), RuntimeError>;

    async fn verify(
        &self,
        envelope: &OperationEnvelope,
        authority: &AcceptedAuthority,
        action: &NativeAction,
    ) -> Result<(), RuntimeError>;
}

pub struct DenyMutations;

#[async_trait]
impl AuthorizationVerifier for DenyMutations {
    async fn verify_request(
        &self,
        _: &OperationEnvelope,
        _: &AcceptedAuthority,
    ) -> Result<(), RuntimeError> {
        Err(failure(
            ObservationFailureKind::PermissionDenied,
            "no trusted mutation authority or fence verifier is configured",
        ))
    }

    async fn verify(
        &self,
        _: &OperationEnvelope,
        _: &AcceptedAuthority,
        _: &NativeAction,
    ) -> Result<(), RuntimeError> {
        Err(failure(
            ObservationFailureKind::PermissionDenied,
            "no trusted mutation authority or fence verifier is configured",
        ))
    }
}

#[async_trait]
pub trait AgBackend: Send + Sync {
    async fn observe(
        &self,
        envelope: &OperationEnvelope,
        authority: &AcceptedAuthority,
        mode: MutationMode,
    ) -> Result<Vec<NodeEvidence>, RuntimeError>;

    async fn execute(
        &self,
        envelope: &OperationEnvelope,
        authority: &AcceptedAuthority,
        action: &NativeAction,
        verifier: &dyn AuthorizationVerifier,
    ) -> Result<(), RuntimeError>;
}

#[derive(Clone)]
pub struct MutationEndpoint {
    observer: ObserverConfig,
    replication_endpoint: Endpoint,
    mutation: Option<ConnectionSettings>,
}

impl MutationEndpoint {
    pub fn observe_only(observer: ObserverConfig, replication_endpoint: Endpoint) -> Self {
        Self {
            observer,
            replication_endpoint,
            mutation: None,
        }
    }

    pub fn new(
        observer: ObserverConfig,
        replication_endpoint: Endpoint,
        username_file: PathBuf,
        password_file: PathBuf,
    ) -> Result<Self, RuntimeError> {
        validate_path(&username_file)?;
        validate_path(&password_file)?;
        let observation = observer.connection();
        if username_file == password_file
            || [&username_file, &password_file].iter().any(|path| {
                **path == observation.username_file || **path == observation.password_file
            })
        {
            return Err(failure(
                ObservationFailureKind::Malformed,
                "mutation credentials must use distinct mounted Secret files",
            ));
        }
        let mut mutation = observation.clone();
        mutation.username_file = username_file;
        mutation.password_file = password_file;
        Ok(Self {
            observer,
            replication_endpoint,
            mutation: Some(mutation),
        })
    }

    async fn check_principals(&self) -> Result<(), RuntimeError> {
        let mutation_settings = self.mutation.as_ref().ok_or_else(|| {
            failure(
                ObservationFailureKind::PermissionDenied,
                "mutation credentials are not configured",
            )
        })?;
        let observer = read_secret(
            &self.observer.connection().username_file,
            "observer username",
        )
        .await?;
        let mutation = read_secret(&mutation_settings.username_file, "mutation username").await?;
        if observer.eq_ignore_ascii_case(&mutation) {
            return Err(failure(
                ObservationFailureKind::PermissionDenied,
                "observation and mutation principals must be distinct",
            ));
        }
        Ok(())
    }

    async fn connect_privileged(
        &self,
        observer: &mut TdsSession,
    ) -> Result<TdsSession, RuntimeError> {
        self.check_principals().await?;
        let observation_identity = connection_identity(observer).await?;
        let mutation_settings = self.mutation.as_ref().ok_or_else(|| {
            failure(
                ObservationFailureKind::PermissionDenied,
                "mutation credentials are not configured",
            )
        })?;
        let mut mutation = connect_session(mutation_settings, TdsPurpose::Mutation).await?;
        let mutation_identity = connection_identity(&mut mutation).await?;
        if observation_identity.0 != self.observer.target().expected_server_name
            || observation_identity.0 != mutation_identity.0
            || observation_identity.1 != mutation_identity.1
        {
            return Err(failure(
                ObservationFailureKind::Inconsistent,
                "observation and mutation connections identify different engine instances",
            ));
        }
        if observation_identity.2 == mutation_identity.2 {
            return Err(failure(
                ObservationFailureKind::PermissionDenied,
                "observation and mutation logins resolved to the same server principal",
            ));
        }
        Ok(mutation)
    }
}

#[derive(Clone)]
pub struct TdsAgBackend {
    nodes: Vec<MutationEndpoint>,
    database_name: SqlIdentifier,
}

impl TdsAgBackend {
    pub fn new(
        nodes: Vec<MutationEndpoint>,
        database_name: SqlIdentifier,
    ) -> Result<Self, RuntimeError> {
        let mut identities = BTreeSet::new();
        let mut servers = BTreeSet::new();
        let mut endpoints = BTreeSet::new();
        if nodes.len() != usize::from(SUPPORTED_REPLICA_COUNT)
            || nodes.iter().any(|node| {
                !identities.insert(node.observer.target().replica.logical_id())
                    || !servers.insert(node.observer.target().expected_server_name.clone())
                    || !endpoints.insert(node.replication_endpoint.clone())
            })
        {
            return Err(failure(
                ObservationFailureKind::Malformed,
                "exactly three distinct registered instances are required",
            ));
        }
        Ok(Self {
            nodes,
            database_name,
        })
    }

    fn validate_bindings(
        &self,
        envelope: &OperationEnvelope,
        authority: &AcceptedAuthority,
    ) -> Result<(), RuntimeError> {
        authority.validate_for(envelope)?;
        let (group, database) = request_names(envelope);
        if database.is_some_and(|name| name != &self.database_name) {
            return Err(failure(
                ObservationFailureKind::Inconsistent,
                "request database differs from the registered managed database",
            ));
        }
        for node in &self.nodes {
            let configured = node.observer.target();
            let member = authority
                .replicas
                .iter()
                .find(|member| member.identity == configured.replica);
            if configured.availability_group != *group
                || member.is_none_or(|member| {
                    member.server_name != configured.expected_server_name
                        || member.endpoint != node.replication_endpoint
                })
            {
                return Err(failure(
                    ObservationFailureKind::Inconsistent,
                    "registered endpoint, server, or incarnation differs from accepted authority",
                ));
            }
        }
        Ok(())
    }

    async fn observe_node(
        &self,
        node: &MutationEndpoint,
        mode: MutationMode,
    ) -> Result<NodeEvidence, RuntimeError> {
        let attempted_at = unix_millis()?;
        let result = timeout(node.observer.sample_timeout(), async {
            let mut session =
                connect_session(node.observer.connection(), TdsPurpose::Observer).await?;
            let before =
                observe_session(&mut session, node.observer.target(), attempted_at).await?;
            let database = if mode == MutationMode::Enabled {
                let mut privileged = node.connect_privileged(&mut session).await?;
                let rows = privileged
                    .query_text(
                        DATABASE_PROBE_SQL,
                        self.database_name.as_str(),
                        DATABASE_PROBE_COLUMNS,
                        "database probe",
                    )
                    .await?;
                parse_database_probe(
                    &rows,
                    &self.database_name,
                    &node.observer.target().expected_server_name,
                    attempted_at,
                )?
            } else {
                let rows = session
                    .query_text(
                        DATABASE_PROBE_SQL,
                        self.database_name.as_str(),
                        DATABASE_PROBE_COLUMNS,
                        "database probe",
                    )
                    .await?;
                parse_database_probe(
                    &rows,
                    &self.database_name,
                    &node.observer.target().expected_server_name,
                    attempted_at,
                )?
            };
            let after = observe_session(&mut session, node.observer.target(), attempted_at).await?;
            if !same_native_anchor(&before, &after) {
                return Err(failure(
                    ObservationFailureKind::Inconsistent,
                    "native identity changed around the local database probe",
                ));
            }
            Ok((after, database))
        })
        .await
        .unwrap_or_else(|_| {
            Err(failure(
                ObservationFailureKind::TimedOut,
                "cluster observation deadline exceeded",
            ))
        });
        let (instance, database) = match result {
            Ok((instance, database)) => (
                Observation::Present {
                    value: instance,
                    observed_at_unix_millis: attempted_at,
                },
                database,
            ),
            Err(error) => {
                let failed = error.into_failure(attempted_at);
                (
                    Observation::Failed(failed.clone()),
                    Observation::Failed(failed),
                )
            }
        };
        Ok(NodeEvidence {
            identity: node.observer.target().replica.clone(),
            server_name: node.observer.target().expected_server_name.clone(),
            endpoint: node.replication_endpoint.clone(),
            instance,
            database,
        })
    }
}

#[async_trait]
impl AgBackend for TdsAgBackend {
    async fn observe(
        &self,
        envelope: &OperationEnvelope,
        authority: &AcceptedAuthority,
        mode: MutationMode,
    ) -> Result<Vec<NodeEvidence>, RuntimeError> {
        self.validate_bindings(envelope, authority)?;
        let mut observations = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            if required_member(envelope, authority, &node.observer.target().replica) {
                observations.push(self.observe_node(node, mode).await?);
            }
        }
        Ok(observations)
    }

    async fn execute(
        &self,
        envelope: &OperationEnvelope,
        authority: &AcceptedAuthority,
        action: &NativeAction,
        verifier: &dyn AuthorizationVerifier,
    ) -> Result<(), RuntimeError> {
        self.validate_bindings(envelope, authority)?;
        validate_action(envelope, authority, action)?;
        verifier.verify_request(envelope, authority).await?;
        let target = action.execution_target();
        let node = self
            .nodes
            .iter()
            .find(|node| {
                node.observer.target().replica.logical_id() == target.logical_id()
                    && node.observer.target().replica.incarnation() == target.incarnation()
            })
            .ok_or_else(|| {
                failure(
                    ObservationFailureKind::Inconsistent,
                    "mutation target incarnation is not registered",
                )
            })?;
        timeout(node.observer.sample_timeout(), async {
            let mut observer =
                connect_session(node.observer.connection(), TdsPurpose::Observer).await?;
            observe_session(&mut observer, node.observer.target(), unix_millis()?).await?;
            let session = node.connect_privileged(&mut observer).await?;
            verifier.verify(envelope, authority, action).await?;
            let sql = render_action(
                action,
                &node.observer.target().expected_server_name,
                &self.database_name,
                node.replication_endpoint.port(),
            )?;
            session.execute_mutation(&sql).await
        })
        .await
        .map_err(|_| {
            failure(
                ObservationFailureKind::TimedOut,
                "native outcome is uncertain after the mutation deadline",
            )
        })?
    }
}

pub(crate) fn required_member(
    envelope: &OperationEnvelope,
    authority: &AcceptedAuthority,
    identity: &ReplicaIdentity,
) -> bool {
    match envelope.request().payload() {
        OperationPayload::EnsureAvailabilityGroup { .. } => true,
        OperationPayload::EnsureReplicaJoined { target, .. } => {
            identity.logical_id() == authority.primary.logical_id()
                || identity.logical_id() == target.logical_id()
        }
        OperationPayload::EnsureReplicaSeeded { source, target, .. }
        | OperationPayload::ReseedReplica { source, target, .. } => {
            identity.logical_id() == source.logical_id()
                || identity.logical_id() == target.logical_id()
        }
        _ => false,
    }
}

const CONNECTION_IDENTITY_SQL: &str = r#"SELECT
    CONVERT(nvarchar(128), @@SERVERNAME) AS server_name,
    CONVERT(nvarchar(33), sqlserver_start_time, 126) AS start_time,
    CONVERT(nvarchar(170), CONVERT(varchar(170), SUSER_SID(), 2)) AS principal_sid
FROM sys.dm_os_sys_info WHERE @P1 IS NOT NULL;"#;

async fn connection_identity(
    session: &mut TdsSession,
) -> Result<(ServerName, String, String), RuntimeError> {
    let rows = session
        .query_text(
            CONNECTION_IDENTITY_SQL,
            "identity",
            &["server_name", "start_time", "principal_sid"],
            "connection identity",
        )
        .await?;
    let [row] = rows.as_slice() else {
        return Err(failure(
            ObservationFailureKind::Malformed,
            "expected one connection identity row",
        ));
    };
    let value = |key: &str| {
        row.get(key)
            .and_then(|value| value.as_deref())
            .filter(|text| !text.is_empty() && !text.chars().any(char::is_control))
            .ok_or_else(|| {
                failure(
                    ObservationFailureKind::Malformed,
                    "connection identity metadata is incomplete",
                )
            })
    };
    let server = ServerName::new(value("server_name")?).map_err(|_| {
        failure(
            ObservationFailureKind::Malformed,
            "invalid connection server identity",
        )
    })?;
    let start = value("start_time")?.to_owned();
    let sid = value("principal_sid")?.to_owned();
    if start.len() > 33 || sid.len() > 170 || !sid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(failure(
            ObservationFailureKind::Malformed,
            "invalid connection identity metadata",
        ));
    }
    Ok((server, start, sid.to_ascii_lowercase()))
}

fn request_names(envelope: &OperationEnvelope) -> (&AvailabilityGroupName, Option<&SqlIdentifier>) {
    match envelope.request().payload() {
        OperationPayload::EnsureAvailabilityGroup {
            name,
            database_name,
            ..
        } => (name, Some(database_name)),
        OperationPayload::EnsureReplicaJoined {
            availability_group, ..
        } => (&availability_group.name, None),
        OperationPayload::EnsureReplicaSeeded {
            availability_group,
            database,
            ..
        }
        | OperationPayload::ReseedReplica {
            availability_group,
            database,
            ..
        } => (&availability_group.name, Some(&database.name)),
        OperationPayload::PlannedSwitchover {
            availability_group,
            database,
            ..
        }
        | OperationPayload::ForcedFailover {
            availability_group,
            database,
            ..
        } => (&availability_group.name, Some(&database.database.name)),
    }
}

pub(crate) fn validate_action(
    envelope: &OperationEnvelope,
    authority: &AcceptedAuthority,
    action: &NativeAction,
) -> Result<(), RuntimeError> {
    let matches_request = match (envelope.request().payload(), action) {
        (
            OperationPayload::EnsureAvailabilityGroup {
                name,
                expected_group_id,
                database_name,
                primary,
                replicas,
            },
            NativeAction::CreateAvailabilityGroup {
                name: actual_name,
                database_name: actual_database,
                primary: actual_primary,
                replicas: actual_replicas,
                expected_database_id,
                ..
            },
        ) => {
            // CREATE allocates a new GUID; it cannot satisfy an existing-GUID binding.
            expected_group_id.is_none()
                && name == actual_name
                && database_name == actual_database
                && primary == actual_primary
                && *expected_database_id > 4
                && replicas.len() == actual_replicas.len()
                && replicas
                    .iter()
                    .all(|replica| actual_replicas.contains(replica))
        }
        (
            OperationPayload::EnsureReplicaJoined {
                availability_group,
                target,
            },
            NativeAction::DisableAutomaticSeeding {
                availability_group: actual_group,
                source,
                target: actual_target,
                target_server_name,
            },
        ) => {
            availability_group == actual_group
                && target == actual_target
                && source.logical_id() == authority.primary.logical_id()
                && source.incarnation() == authority.primary.incarnation()
                && source.native_replica_id().is_some()
                && source.native_replica_id() != target.native_replica_id()
                && authority.replicas.iter().any(|replica| {
                    replica.identity.logical_id() == target.logical_id()
                        && replica.identity.incarnation() == target.incarnation()
                        && replica.server_name == *target_server_name
                })
        }
        (
            OperationPayload::EnsureReplicaJoined {
                availability_group,
                target,
            },
            NativeAction::JoinAvailabilityGroup {
                availability_group: actual_group,
                target: actual_target,
            },
        ) => availability_group == actual_group && target == actual_target,
        (
            OperationPayload::EnsureReplicaSeeded {
                availability_group,
                target,
                ..
            }
            | OperationPayload::ReseedReplica {
                availability_group,
                target,
                ..
            },
            NativeAction::GrantSeeding {
                availability_group: actual_group,
                target: actual_target,
            },
        ) => availability_group == actual_group && target == actual_target,
        (
            OperationPayload::EnsureReplicaSeeded {
                availability_group,
                database,
                source,
                target,
            }
            | OperationPayload::ReseedReplica {
                availability_group,
                database,
                source,
                target,
                ..
            },
            NativeAction::TriggerSeeding {
                availability_group: actual_group,
                database: actual_database,
                source: actual_source,
                target: actual_target,
                target_server_name,
            },
        ) => {
            availability_group == actual_group
                && database == actual_database
                && source == actual_source
                && target == actual_target
                && authority.replicas.iter().any(|replica| {
                    replica.identity.logical_id() == target.logical_id()
                        && replica.identity.incarnation() == target.incarnation()
                        && replica.server_name == *target_server_name
                })
        }
        (
            OperationPayload::ReseedReplica {
                availability_group,
                database,
                target,
                expected_database_id,
                expected_database_guid,
                expected_recovery_fork_id,
                ..
            },
            NativeAction::DetachDatabase {
                availability_group: actual_group,
                database: actual_database,
                target: actual_target,
                expected_database_id: actual_id,
                expected_database_guid: actual_guid,
                expected_recovery_fork_id: actual_fork,
            }
            | NativeAction::DropDatabase {
                availability_group: actual_group,
                database: actual_database,
                target: actual_target,
                expected_database_id: actual_id,
                expected_database_guid: actual_guid,
                expected_recovery_fork_id: actual_fork,
            },
        ) => {
            availability_group == actual_group
                && database == actual_database
                && target == actual_target
                && expected_database_id == actual_id
                && expected_database_guid == actual_guid
                && expected_recovery_fork_id == actual_fork
        }
        _ => false,
    };
    if !matches_request {
        return Err(failure(
            ObservationFailureKind::Inconsistent,
            "native action is not bound to the exact operation inputs",
        ));
    }
    Ok(())
}

fn same_native_anchor(left: &InstanceSnapshot, right: &InstanceSnapshot) -> bool {
    if left.instance != right.instance {
        return false;
    }
    match (&left.availability_group, &right.availability_group) {
        (Observation::Absent { .. }, Observation::Absent { .. }) => true,
        (Observation::Present { value: left, .. }, Observation::Present { value: right, .. }) => {
            left.identity == right.identity
                && left.configuration_sequence == right.configuration_sequence
                && left.local_replica == right.local_replica
                && left.databases.len() == right.databases.len()
                && left
                    .databases
                    .iter()
                    .zip(&right.databases)
                    .all(|(left, right)| {
                        left.identity == right.identity
                            && left.local.as_ref().map(|local| {
                                (local.database_id, &local.replica_id, &local.recovery)
                            }) == right.local.as_ref().map(|local| {
                                (local.database_id, &local.replica_id, &local.recovery)
                            })
                    })
        }
        _ => false,
    }
}

const DATABASE_PROBE_COLUMNS: &[&str] = &[
    "server_name",
    "can_observe_absence",
    "database_id",
    "database_name",
    "database_guid",
    "recovery_fork_id",
    "group_database_id",
    "replica_id",
    "state",
    "recovery_model",
    "backup_ready",
];

const DATABASE_PROBE_SQL: &str = r#"SELECT
    CONVERT(nvarchar(128), @@SERVERNAME) AS server_name,
    CONVERT(nvarchar(1), CASE WHEN HAS_PERMS_BY_NAME(NULL, NULL, N'ALTER ANY DATABASE') = 1
        OR HAS_PERMS_BY_NAME(N'master', N'DATABASE', N'CREATE DATABASE') = 1 THEN 1 ELSE 0 END) AS can_observe_absence,
    CONVERT(nvarchar(11), d.database_id) AS database_id,
    CONVERT(nvarchar(128), d.name) AS database_name,
    CONVERT(nvarchar(36), recovery.database_guid) AS database_guid,
    CONVERT(nvarchar(36), recovery.recovery_fork_guid) AS recovery_fork_id,
    CONVERT(nvarchar(36), d.group_database_id) AS group_database_id,
    CONVERT(nvarchar(36), d.replica_id) AS replica_id,
    CONVERT(nvarchar(60), d.state_desc) AS state,
    CONVERT(nvarchar(60), d.recovery_model_desc) AS recovery_model,
    CONVERT(nvarchar(1), CASE WHEN recovery.last_log_backup_lsn > 0 THEN 1 ELSE 0 END) AS backup_ready
FROM (VALUES (1)) AS probe(single_row)
LEFT JOIN sys.databases AS d ON d.name = @P1
LEFT JOIN sys.database_recovery_status AS recovery ON recovery.database_id = d.database_id;"#;

fn parse_database_probe(
    rows: &[QueryRow],
    expected_name: &SqlIdentifier,
    expected_server: &ServerName,
    attempted_at: u64,
) -> Result<Observation<DatabaseProbe>, RuntimeError> {
    let [row] = rows else {
        return Err(failure(
            ObservationFailureKind::Malformed,
            "expected one local database probe row",
        ));
    };
    let optional = |name: &str| -> Result<Option<&str>, RuntimeError> {
        row.get(name).map(|value| value.as_deref()).ok_or_else(|| {
            failure(
                ObservationFailureKind::Malformed,
                "database probe omitted a column",
            )
        })
    };
    let required = |name: &str| -> Result<&str, RuntimeError> {
        optional(name)?.ok_or_else(|| {
            failure(
                ObservationFailureKind::Malformed,
                "local database identity or lineage is unavailable",
            )
        })
    };
    if ServerName::new(required("server_name")?).map_err(|_| {
        failure(
            ObservationFailureKind::Malformed,
            "invalid probe server identity",
        )
    })? != *expected_server
    {
        return Err(failure(
            ObservationFailureKind::Inconsistent,
            "database probe connected to another native server",
        ));
    }
    let can_observe_absence = match required("can_observe_absence")? {
        "1" => true,
        "0" => false,
        _ => {
            return Err(failure(
                ObservationFailureKind::Malformed,
                "invalid database visibility permission result",
            ));
        }
    };
    let Some(id) = optional("database_id")? else {
        if !can_observe_absence {
            return Err(failure(
                ObservationFailureKind::PermissionDenied,
                "complete local database visibility requires ALTER ANY DATABASE or CREATE DATABASE in master",
            ));
        }
        for column in [
            "database_name",
            "database_guid",
            "recovery_fork_id",
            "group_database_id",
            "replica_id",
            "state",
            "recovery_model",
        ] {
            if optional(column)?.is_some() {
                return Err(failure(
                    ObservationFailureKind::Malformed,
                    "absent database has associated metadata",
                ));
            }
        }
        if required("backup_ready")? != "0" {
            return Err(failure(
                ObservationFailureKind::Malformed,
                "absent database has backup metadata",
            ));
        }
        return Ok(Observation::Absent {
            observed_at_unix_millis: attempted_at,
        });
    };
    let signed_id: i32 = id.parse().map_err(|_| {
        failure(
            ObservationFailureKind::Malformed,
            "invalid local database ID",
        )
    })?;
    let database_id = u32::try_from(signed_id).map_err(|_| {
        failure(
            ObservationFailureKind::Malformed,
            "invalid local database ID",
        )
    })?;
    if database_id <= 4 || !id.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(failure(
            ObservationFailureKind::Malformed,
            "managed database must be a user database",
        ));
    }
    let name = SqlIdentifier::new(required("database_name")?)
        .map_err(|_| failure(ObservationFailureKind::Malformed, "invalid database name"))?;
    if name != *expected_name {
        return Err(failure(
            ObservationFailureKind::Inconsistent,
            "local database name differs from the managed database",
        ));
    }
    let guid = |value: &str| {
        Guid::parse("database probe GUID", value).map_err(|_| {
            failure(
                ObservationFailureKind::Malformed,
                "invalid database probe GUID",
            )
        })
    };
    let group_database_id = optional("group_database_id")?.map(guid).transpose()?;
    let replica_id = optional("replica_id")?.map(guid).transpose()?;
    if group_database_id.is_some() != replica_id.is_some() {
        return Err(failure(
            ObservationFailureKind::Malformed,
            "partial database availability-group association",
        ));
    }
    let boolean = |name: &str| match required(name)? {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(failure(
            ObservationFailureKind::Malformed,
            "invalid probe Boolean",
        )),
    };
    Ok(Observation::Present {
        value: DatabaseProbe {
            name,
            database_id,
            database_guid: guid(required("database_guid")?)?,
            recovery_fork_id: guid(required("recovery_fork_id")?)?,
            group_database_id,
            replica_id,
            state: SqlIdentifier::new(required("state")?)
                .map_err(|_| failure(ObservationFailureKind::Malformed, "invalid database state"))?
                .to_string(),
            recovery_model: SqlIdentifier::new(required("recovery_model")?)
                .map_err(|_| failure(ObservationFailureKind::Malformed, "invalid recovery model"))?
                .to_string(),
            backup_ready: boolean("backup_ready")?,
        },
        observed_at_unix_millis: attempted_at,
    })
}

fn literal(value: &str) -> String {
    format!("N'{}'", value.replace('\'', "''"))
}

fn require_native(identity: &ReplicaIdentity) -> Result<&Guid, RuntimeError> {
    identity.native_replica_id().ok_or_else(|| {
        failure(
            ObservationFailureKind::Malformed,
            "native action requires a replica GUID",
        )
    })
}

fn group_guard(group: &AvailabilityGroupIdentity) -> String {
    let required = SUPPORTED_REQUIRED_SECONDARIES;
    format!(
        "IF NOT EXISTS (SELECT 1 FROM sys.availability_groups WHERE name = {} AND group_id = {} AND cluster_type = 2 AND basic_features = 0 AND is_distributed = 0 AND required_synchronized_secondaries_to_commit = {required}) THROW 51000, 'Availability-group identity or profile changed', 1;\n",
        literal(group.name.as_str()),
        literal(group.group_id.as_str())
    )
}

fn role_guard(
    group: &AvailabilityGroupIdentity,
    replica: &ReplicaIdentity,
    role: &str,
) -> Result<String, RuntimeError> {
    Ok(format!(
        "IF NOT EXISTS (SELECT 1 FROM sys.dm_hadr_availability_replica_states WHERE group_id = {} AND replica_id = {} AND is_local = 1 AND role_desc = {}) THROW 51000, 'Local native role or replica identity changed', 1;\n",
        literal(group.group_id.as_str()),
        literal(require_native(replica)?.as_str()),
        literal(role)
    ))
}

fn database_guard(
    database: &DatabaseIdentity,
    replica: &ReplicaIdentity,
) -> Result<String, RuntimeError> {
    Ok(format!(
        "IF NOT EXISTS (SELECT 1 FROM sys.databases WHERE name = {} AND group_database_id = {} AND replica_id = {} AND state_desc = N'ONLINE') THROW 51000, 'Managed database identity or state changed', 1;\n",
        literal(database.name.as_str()),
        literal(database.group_database_id.as_str()),
        literal(require_native(replica)?.as_str())
    ))
}

fn target_replica_guard(
    group: &AvailabilityGroupIdentity,
    target: &ReplicaIdentity,
    server: &ServerName,
) -> Result<String, RuntimeError> {
    Ok(format!(
        "IF NOT EXISTS (SELECT 1 FROM sys.availability_replicas WHERE group_id = {} AND replica_id = {} AND UPPER(replica_server_name) = UPPER({}) AND availability_mode = 1 AND failover_mode = 2 AND seeding_mode IN (0, 1)) THROW 51000, 'Native seed target changed', 1;\n",
        literal(group.group_id.as_str()),
        literal(require_native(target)?.as_str()),
        literal(server.as_str())
    ))
}

fn old_database_guard(
    name: &SqlIdentifier,
    database_id: u32,
    database_guid: &Guid,
    fork: &Guid,
) -> String {
    format!(
        "IF NOT EXISTS (SELECT 1 FROM sys.databases AS d INNER JOIN sys.database_recovery_status AS r ON r.database_id = d.database_id WHERE d.name = {} AND d.database_id = {database_id} AND r.database_guid = {} AND r.recovery_fork_guid = {}) THROW 51000, 'Exact local database incarnation changed', 1;\n",
        literal(name.as_str()),
        literal(database_guid.as_str()),
        literal(fork.as_str())
    )
}

/// The one AG mutation is surrounded by local identity guards and a session
/// application lock. The lock serializes cooperating callers, not cluster authority.
fn render_action(
    action: &NativeAction,
    server: &ServerName,
    managed_database: &SqlIdentifier,
    replication_port: u16,
) -> Result<String, RuntimeError> {
    let major = SUPPORTED_ENGINE_MAJOR;
    let required = SUPPORTED_REQUIRED_SECONDARIES;
    let mut body = format!(
        "IF @@SERVERNAME IS NULL OR UPPER(CONVERT(nvarchar(128), @@SERVERNAME)) <> UPPER({}) THROW 51000, 'Native server identity changed', 1;\n\
         IF ISNULL(CONVERT(int, SERVERPROPERTY(N'ProductMajorVersion')), 0) <> {major} OR ISNULL(CONVERT(int, SERVERPROPERTY(N'EngineEdition')), 0) <> 3 OR ISNULL(CONVERT(int, SERVERPROPERTY(N'IsHadrEnabled')), 0) <> 1 THROW 51000, 'Unsupported SQL Server capability', 1;\n\
         IF ISNULL(CONVERT(nvarchar(128), SERVERPROPERTY(N'Edition')), N'') NOT IN (N'Developer Edition (64-bit)', N'Enterprise Edition (64-bit)', N'Enterprise Edition: Core-based Licensing (64-bit)', N'Developer Edition', N'Enterprise Edition', N'Enterprise Edition: Core-based Licensing', N'Developer', N'Enterprise') THROW 51000, 'Unsupported SQL Server edition', 1;\n\
         IF NOT EXISTS (SELECT 1 FROM sys.dm_os_host_info WHERE host_platform = N'Linux') OR CHARINDEX(N'(X64)', CONVERT(nvarchar(4000), @@VERSION)) = 0 THROW 51000, 'Unsupported SQL Server platform', 1;\n\
         IF NOT EXISTS (SELECT 1 FROM sys.database_mirroring_endpoints AS m INNER JOIN sys.tcp_endpoints AS t ON t.endpoint_id = m.endpoint_id WHERE m.state_desc = N'STARTED' AND t.port = {replication_port} AND m.connection_auth = 4 AND m.certificate_id > 0 AND m.is_encryption_enabled = 1 AND m.encryption_algorithm = 2) THROW 51000, 'A started certificate-authenticated AES mirroring endpoint is required', 1;\n",
        literal(server.as_str())
    );
    match action {
        NativeAction::CreateAvailabilityGroup {
            name,
            database_name,
            replicas,
            expected_database_id,
            expected_database_guid,
            expected_recovery_fork_id,
            ..
        } => {
            if database_name != managed_database
                || replicas.len() != usize::from(SUPPORTED_REPLICA_COUNT)
            {
                return Err(failure(
                    ObservationFailureKind::Malformed,
                    "invalid bootstrap native action",
                ));
            }
            body.push_str(&format!("IF EXISTS (SELECT 1 FROM sys.availability_groups WHERE name = {}) THROW 51000, 'Availability group already exists; reobserve', 1;\n", literal(name.as_str())));
            body.push_str(&old_database_guard(
                database_name,
                *expected_database_id,
                expected_database_guid,
                expected_recovery_fork_id,
            ));
            body.push_str(&format!(
                "IF NOT EXISTS (SELECT 1 FROM sys.databases AS d INNER JOIN sys.database_recovery_status AS r ON r.database_id = d.database_id WHERE d.name = {} AND d.group_database_id IS NULL AND d.replica_id IS NULL AND d.state_desc = N'ONLINE' AND d.recovery_model_desc = N'FULL' AND r.last_log_backup_lsn > 0) THROW 51000, 'Bootstrap database is not prepared', 1;\n",
                literal(database_name.as_str())
            ));
            let replicas = replicas.iter().map(|replica| format!(
                "{} WITH (ENDPOINT_URL = {}, AVAILABILITY_MODE = SYNCHRONOUS_COMMIT, FAILOVER_MODE = EXTERNAL, SEEDING_MODE = AUTOMATIC, SECONDARY_ROLE (ALLOW_CONNECTIONS = ALL))",
                literal(replica.server_name.as_str()), literal(&replica.endpoint.to_string())
            )).collect::<Vec<_>>().join(",\n");
            body.push_str(&format!(
                "CREATE AVAILABILITY GROUP {} WITH (CLUSTER_TYPE = EXTERNAL, REQUIRED_SYNCHRONIZED_SECONDARIES_TO_COMMIT = {required}) FOR DATABASE {} REPLICA ON {replicas};\n",
                name.quoted(), database_name.quoted()
            ));
        }
        NativeAction::DisableAutomaticSeeding {
            availability_group: group,
            source,
            target,
            target_server_name,
        } => {
            body.push_str(&group_guard(group));
            body.push_str(&role_guard(group, source, "PRIMARY")?);
            body.push_str(&target_replica_guard(group, target, target_server_name)?);
            body.push_str(&format!(
                "IF EXISTS (SELECT 1 FROM sys.dm_hadr_automatic_seeding WHERE ag_id = {} AND ag_remote_replica_id = {} AND (current_state IS NULL OR current_state NOT IN (N'COMPLETED', N'FAILED'))) THROW 51000, 'Automatic seeding is active or unknown; reobserve', 1;\n\
                 IF EXISTS (SELECT 1 FROM sys.dm_hadr_physical_seeding_stats AS s INNER JOIN sys.databases AS d ON d.database_id = s.local_database_id INNER JOIN sys.availability_databases_cluster AS adc ON adc.group_database_id = d.group_database_id WHERE adc.group_id = {} AND s.end_time_utc IS NULL) THROW 51000, 'Physical seeding is active; reobserve', 1;\n\
                 ALTER AVAILABILITY GROUP {} MODIFY REPLICA ON {} WITH (SEEDING_MODE = MANUAL);\n",
                literal(group.group_id.as_str()), literal(require_native(target)?.as_str()),
                literal(group.group_id.as_str()), group.name.quoted(), literal(target_server_name.as_str())
            ));
        }
        NativeAction::JoinAvailabilityGroup {
            availability_group: group,
            target,
        } => {
            let group_id = literal(group.group_id.as_str());
            let replica_id = literal(require_native(target)?.as_str());
            body.push_str(&format!(
                "IF EXISTS (SELECT 1 FROM sys.availability_groups WHERE name = {} AND group_id <> {group_id}) THROW 51000, 'A different native group already exists', 1;\n\
                 IF EXISTS (SELECT 1 FROM sys.dm_hadr_availability_replica_states WHERE group_id = {group_id} AND is_local = 1 AND role_desc = N'PRIMARY') THROW 51000, 'Cannot join over a primary', 1;\n\
                 IF NOT EXISTS (SELECT 1 FROM sys.dm_hadr_availability_replica_states WHERE group_id = {group_id} AND replica_id = {replica_id} AND is_local = 1 AND role_desc = N'SECONDARY')\n\
                 BEGIN ALTER AVAILABILITY GROUP {} JOIN WITH (CLUSTER_TYPE = EXTERNAL); END;\n",
                literal(group.name.as_str()), group.name.quoted()
            ));
            body.push_str(&group_guard(group));
            body.push_str(&role_guard(group, target, "SECONDARY")?);
        }
        NativeAction::GrantSeeding {
            availability_group: group,
            target,
        } => {
            body.push_str(&group_guard(group));
            body.push_str(&role_guard(group, target, "SECONDARY")?);
            body.push_str(&format!(
                "IF EXISTS (SELECT 1 FROM sys.availability_databases_cluster WHERE group_id = {} AND database_name <> {}) THROW 51000, 'An unmanaged database is configured', 1;\n\
                 ALTER AVAILABILITY GROUP {} GRANT CREATE ANY DATABASE;\n",
                literal(group.group_id.as_str()), literal(managed_database.as_str()), group.name.quoted()
            ));
        }
        NativeAction::TriggerSeeding {
            availability_group: group,
            database,
            source,
            target,
            target_server_name,
        } => {
            body.push_str(&group_guard(group));
            body.push_str(&role_guard(group, source, "PRIMARY")?);
            body.push_str(&database_guard(database, source)?);
            body.push_str(&target_replica_guard(group, target, target_server_name)?);
            let target_id = literal(require_native(target)?.as_str());
            body.push_str(&format!(
                "IF NOT EXISTS (SELECT 1 FROM sys.dm_hadr_automatic_seeding WHERE ag_id = {} AND ag_db_id = {} AND ag_remote_replica_id = {target_id} AND current_state IN (N'PENDING', N'IN_PROGRESS'))\n\
                 BEGIN ALTER AVAILABILITY GROUP {} MODIFY REPLICA ON {} WITH (SEEDING_MODE = AUTOMATIC); END;\n",
                literal(group.group_id.as_str()),
                literal(database.group_database_id.as_str()), group.name.quoted(), literal(target_server_name.as_str())
            ));
        }
        NativeAction::DetachDatabase {
            availability_group: group,
            database,
            target,
            expected_database_id,
            expected_database_guid,
            expected_recovery_fork_id,
        }
        | NativeAction::DropDatabase {
            availability_group: group,
            database,
            target,
            expected_database_id,
            expected_database_guid,
            expected_recovery_fork_id,
        } => {
            body.push_str(&group_guard(group));
            body.push_str(&role_guard(group, target, "SECONDARY")?);
            body.push_str(&format!(
                "IF EXISTS (SELECT 1 FROM sys.databases WHERE name = {}) BEGIN\n",
                literal(database.name.as_str())
            ));
            body.push_str(&old_database_guard(
                &database.name,
                *expected_database_id,
                expected_database_guid,
                expected_recovery_fork_id,
            ));
            if matches!(action, NativeAction::DetachDatabase { .. }) {
                body.push_str(&format!(
                    "IF EXISTS (SELECT 1 FROM sys.databases WHERE name = {} AND group_database_id IS NOT NULL) BEGIN\n\
                     IF NOT EXISTS (SELECT 1 FROM sys.databases WHERE name = {} AND group_database_id = {} AND replica_id = {}) THROW 51000, 'Database belongs to another native group or replica', 1;\n\
                     ALTER DATABASE {} SET HADR OFF; END;\n",
                    literal(database.name.as_str()), literal(database.name.as_str()), literal(database.group_database_id.as_str()),
                    literal(require_native(target)?.as_str()), database.name.quoted()
                ));
            } else {
                body.push_str(&format!(
                    "IF EXISTS (SELECT 1 FROM sys.databases WHERE name = {} AND (group_database_id IS NOT NULL OR replica_id IS NOT NULL)) THROW 51000, 'Database is still joined; reobserve', 1;\n\
                     DROP DATABASE {};\n",
                    literal(database.name.as_str()), database.name.quoted()
                ));
            }
            body.push_str("END;\n");
        }
    }
    Ok(format!(
        "SET NOCOUNT ON;\nSET XACT_ABORT ON;\nSET IMPLICIT_TRANSACTIONS OFF;\nIF @@TRANCOUNT <> 0 THROW 51000, 'Native mutations require autocommit', 1;\nDECLARE @lock_result int;\n\
         EXEC @lock_result = sys.sp_getapplock @Resource = N'kuberic.sqlserver.ag-mutation', @LockMode = N'Exclusive', @LockOwner = N'Session', @LockTimeout = 0;\n\
         IF @lock_result < 0 THROW 51001, 'Another native mutation is still active', 1;\n\
         BEGIN TRY\n{body}\
         END TRY BEGIN CATCH\n\
         EXEC sys.sp_releaseapplock @Resource = N'kuberic.sqlserver.ag-mutation', @LockOwner = N'Session';\nTHROW;\nEND CATCH;\n\
         EXEC sys.sp_releaseapplock @Resource = N'kuberic.sqlserver.ag-mutation', @LockOwner = N'Session';"
    ))
}

fn failure(kind: ObservationFailureKind, message: &'static str) -> RuntimeError {
    RuntimeError::new(kind, "AG adapter", message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DestructiveApproval, FenceReference, OpaqueId, OperationRequest, ReplicaDescriptor,
    };

    fn guid(id: u32) -> Guid {
        Guid::parse("test", format!("{id:08x}-1111-2222-3333-444444444444")).unwrap()
    }

    fn replica(id: u32) -> ReplicaIdentity {
        ReplicaIdentity::observed(format!("replica-{id}"), guid(id + 10), format!("pod-{id}"))
            .unwrap()
    }

    fn authority() -> AcceptedAuthority {
        let replicas = (0..3)
            .map(|id| ReplicaDescriptor {
                identity: ReplicaIdentity::desired(format!("replica-{id}"), format!("pod-{id}"))
                    .unwrap(),
                server_name: ServerName::new(format!("sql-{id}")).unwrap(),
                endpoint: Endpoint::new(format!("sql-{id}.example"), 5022).unwrap(),
            })
            .collect::<Vec<_>>();
        AcceptedAuthority {
            resource_id: OpaqueId::new("resource", "resource").unwrap(),
            configuration_id: OpaqueId::new("configuration", "configuration").unwrap(),
            epoch: 1,
            primary: replicas[0].identity.clone(),
            replicas,
        }
    }

    fn group() -> AvailabilityGroupIdentity {
        AvailabilityGroupIdentity {
            name: AvailabilityGroupName::new("group").unwrap(),
            group_id: guid(1),
        }
    }

    fn database() -> DatabaseIdentity {
        DatabaseIdentity {
            name: SqlIdentifier::new("database").unwrap(),
            group_database_id: guid(2),
        }
    }

    fn reseed() -> OperationEnvelope {
        let request = OperationRequest::new(
            "resource",
            "reseed",
            "configuration",
            1,
            1,
            OperationPayload::ReseedReplica {
                availability_group: group(),
                database: database(),
                source: replica(0),
                target: replica(1),
                expected_database_id: 6,
                expected_database_guid: guid(3),
                expected_recovery_fork_id: guid(4),
            },
        )
        .unwrap();
        let approval = DestructiveApproval::new(
            "approval",
            request.operation_id(),
            request.input_signature(),
        )
        .unwrap();
        let fence = FenceReference::new(
            "provider",
            "receipt",
            request.operation_id(),
            request.input_signature(),
            replica(1),
        )
        .unwrap();
        OperationEnvelope::new(request, Some(approval), Some(fence)).unwrap()
    }

    fn drop_action() -> NativeAction {
        NativeAction::DropDatabase {
            availability_group: group(),
            database: database(),
            target: replica(1),
            expected_database_id: 6,
            expected_database_guid: guid(3),
            expected_recovery_fork_id: guid(4),
        }
    }

    #[tokio::test]
    async fn bound_receipts_are_not_authenticated_fencing_proof() {
        let result = DenyMutations
            .verify(&reseed(), &authority(), &drop_action())
            .await;
        assert_eq!(
            result.unwrap_err().kind,
            ObservationFailureKind::PermissionDenied
        );
    }

    #[tokio::test]
    async fn observe_only_endpoints_do_not_require_or_read_mutation_secrets() {
        let observer =
            ObserverConfig::from_json(include_bytes!("../observer.example.json")).unwrap();
        let endpoint = Endpoint::new("sql-0.example.internal", 5022).unwrap();
        let node = MutationEndpoint::observe_only(observer, endpoint);
        assert!(node.mutation.is_none());
        let error = node.check_principals().await.unwrap_err();
        assert_eq!(error.kind, ObservationFailureKind::PermissionDenied);
        assert_eq!(error.message, "mutation credentials are not configured");
    }

    #[test]
    fn credential_paths_cannot_reuse_observation_keys() {
        let observer =
            ObserverConfig::from_json(include_bytes!("../observer.example.json")).unwrap();
        let endpoint = Endpoint::new("sql-0.example.internal", 5022).unwrap();
        let observer_username = observer.connection().username_file.clone();
        assert!(
            MutationEndpoint::new(
                observer.clone(),
                endpoint.clone(),
                observer_username,
                PathBuf::from("/mutator/password")
            )
            .is_err()
        );
        assert!(
            MutationEndpoint::new(
                observer.clone(),
                endpoint.clone(),
                PathBuf::from("relative"),
                PathBuf::from("/mutator/password")
            )
            .is_err()
        );
        assert!(
            MutationEndpoint::new(
                observer,
                endpoint,
                PathBuf::from("/mutator/username"),
                PathBuf::from("/mutator/password")
            )
            .is_ok()
        );
    }

    #[test]
    fn native_actions_must_match_the_authorized_request_not_only_its_target() {
        let envelope = reseed();
        validate_action(&envelope, &authority(), &drop_action()).unwrap();
        let mut unrelated = drop_action();
        if let NativeAction::DropDatabase {
            expected_database_guid,
            ..
        } = &mut unrelated
        {
            *expected_database_guid = guid(999);
        }
        assert!(validate_action(&envelope, &authority(), &unrelated).is_err());
        let join = OperationEnvelope::new(
            OperationRequest::new(
                "resource",
                "join",
                "configuration",
                1,
                1,
                OperationPayload::EnsureReplicaJoined {
                    availability_group: group(),
                    target: replica(1),
                },
            )
            .unwrap(),
            None,
            None,
        )
        .unwrap();
        assert!(validate_action(&join, &authority(), &drop_action()).is_err());
    }

    #[tokio::test]
    async fn public_backend_cannot_create_a_new_guid_for_an_expected_existing_group() {
        struct NoSideEffects;
        #[async_trait]
        impl AuthorizationVerifier for NoSideEffects {
            async fn verify_request(
                &self,
                _: &OperationEnvelope,
                _: &AcceptedAuthority,
            ) -> Result<(), RuntimeError> {
                panic!("native binding rejection must precede authorization and connection");
            }
            async fn verify(
                &self,
                _: &OperationEnvelope,
                _: &AcceptedAuthority,
                _: &NativeAction,
            ) -> Result<(), RuntimeError> {
                panic!("native binding rejection must precede SQL dispatch");
            }
        }
        let authority = authority();
        let envelope = OperationEnvelope::new(
            OperationRequest::new(
                "resource",
                "existing-group",
                "configuration",
                1,
                1,
                OperationPayload::EnsureAvailabilityGroup {
                    name: group().name,
                    expected_group_id: Some(guid(55)),
                    database_name: database().name,
                    primary: authority.primary.clone(),
                    replicas: authority.replicas.clone(),
                },
            )
            .unwrap(),
            None,
            None,
        )
        .unwrap();
        let action = NativeAction::CreateAvailabilityGroup {
            primary: authority.primary.clone(),
            name: group().name,
            database_name: database().name,
            replicas: authority.replicas.clone(),
            expected_database_id: 5,
            expected_database_guid: guid(3),
            expected_recovery_fork_id: guid(4),
        };
        let nodes = authority
            .replicas
            .iter()
            .map(|member| {
                let config = serde_json::json!({
                    "host": member.endpoint.host(),
                    "availability_group": "group",
                    "expected_server_name": member.server_name.as_str(),
                    "replica_id": member.identity.logical_id(),
                    "incarnation": member.identity.incarnation(),
                    "observer_username_file": "/not-provisioned/observer/username",
                    "observer_password_file": "/not-provisioned/observer/password"
                });
                let observer =
                    ObserverConfig::from_json(&serde_json::to_vec(&config).unwrap()).unwrap();
                MutationEndpoint::observe_only(observer, member.endpoint.clone())
            })
            .collect();
        let backend = TdsAgBackend::new(nodes, database().name).unwrap();
        let error = backend
            .execute(&envelope, &authority, &action, &NoSideEffects)
            .await
            .unwrap_err();
        assert_eq!(error.kind, ObservationFailureKind::Inconsistent);
    }

    #[test]
    fn drop_is_guarded_by_exact_old_database_role_and_native_group() {
        let sql = render_action(
            &drop_action(),
            &ServerName::new("sql-1").unwrap(),
            &database().name,
            5022,
        )
        .unwrap();
        for expected in [
            "sys.sp_getapplock",
            "@LockOwner = N'Session'",
            "@LockTimeout = 0",
            "role_desc = N'SECONDARY'",
            "d.database_id = 6",
            "r.database_guid",
            "r.recovery_fork_guid",
            "group_database_id IS NOT NULL",
            "replica_id IS NOT NULL",
            "DROP DATABASE [database]",
            "sys.sp_releaseapplock",
            "m.connection_auth = 4",
            "m.encryption_algorithm = 2",
            "t.port = 5022",
        ] {
            assert!(sql.contains(expected), "missing SQL guard: {expected}");
        }
        assert_eq!(sql.matches("DROP DATABASE ").count(), 1);
        assert!(!sql.contains("FORCE_FAILOVER"));
        assert!(!sql.contains("ROLLBACK IMMEDIATE"));
    }

    #[test]
    fn bootstrap_has_one_bound_native_effect_and_does_not_replace_existing_groups() {
        let authority = authority();
        let action = NativeAction::CreateAvailabilityGroup {
            name: group().name,
            database_name: database().name,
            primary: authority.primary,
            replicas: authority.replicas,
            expected_database_id: 5,
            expected_database_guid: guid(3),
            expected_recovery_fork_id: guid(4),
        };
        let sql = render_action(
            &action,
            &ServerName::new("sql-0").unwrap(),
            &database().name,
            5022,
        )
        .unwrap();
        assert_eq!(sql.matches("CREATE AVAILABILITY GROUP ").count(), 1);
        assert_eq!(sql.matches("FAILOVER_MODE = EXTERNAL").count(), 3);
        assert_eq!(sql.matches("SEEDING_MODE = AUTOMATIC").count(), 3);
        assert!(sql.contains("Availability group already exists; reobserve"));
        assert!(sql.contains("REQUIRED_SYNCHRONIZED_SECONDARIES_TO_COMMIT = 1"));
        assert!(sql.contains("d.recovery_model_desc = N'FULL'"));
        assert!(sql.contains("r.last_log_backup_lsn > 0"));
        assert!(!sql.contains("DROP "));
    }

    #[test]
    fn disabling_automatic_seeding_is_bound_to_the_join_and_accepted_primary() {
        let request = OperationEnvelope::new(
            OperationRequest::new(
                "resource",
                "join",
                "configuration",
                1,
                1,
                OperationPayload::EnsureReplicaJoined {
                    availability_group: group(),
                    target: replica(1),
                },
            )
            .unwrap(),
            None,
            None,
        )
        .unwrap();
        let action = NativeAction::DisableAutomaticSeeding {
            availability_group: group(),
            source: replica(0),
            target: replica(1),
            target_server_name: ServerName::new("sql-1").unwrap(),
        };
        validate_action(&request, &authority(), &action).unwrap();
        assert!(validate_action(&reseed(), &authority(), &action).is_err());
        for change in 0..7 {
            let mut changed = action.clone();
            let NativeAction::DisableAutomaticSeeding {
                availability_group,
                source,
                target,
                target_server_name,
            } = &mut changed
            else {
                unreachable!()
            };
            match change {
                0 => availability_group.group_id = guid(999),
                1 => *source = replica(2),
                2 => *source = authority().primary,
                3 => *source = ReplicaIdentity::observed("replica-0", guid(10), "old-pod").unwrap(),
                4 => *target = replica(2),
                5 => *target_server_name = ServerName::new("foreign-server").unwrap(),
                6 => *source = ReplicaIdentity::observed("replica-0", guid(11), "pod-0").unwrap(),
                _ => unreachable!(),
            }
            assert!(validate_action(&request, &authority(), &changed).is_err());
        }
    }

    #[test]
    fn manual_seeding_is_one_primary_effect_guarded_against_active_copy() {
        let action = NativeAction::DisableAutomaticSeeding {
            availability_group: group(),
            source: replica(0),
            target: replica(1),
            target_server_name: ServerName::new("sql-1").unwrap(),
        };
        let sql = render_action(
            &action,
            &ServerName::new("sql-0").unwrap(),
            &database().name,
            5022,
        )
        .unwrap();
        let mutation = sql.find("ALTER AVAILABILITY GROUP ").unwrap();
        for guard in [
            "cluster_type = 2",
            "role_desc = N'PRIMARY'",
            "Native seed target changed",
            "seeding_mode IN (0, 1)",
            "current_state IS NULL OR current_state NOT IN (N'COMPLETED', N'FAILED')",
            "ag_remote_replica_id",
            "s.end_time_utc IS NULL",
        ] {
            assert!(sql[..mutation].contains(guard), "missing guard: {guard}");
        }
        assert!(sql.contains(
            "ALTER AVAILABILITY GROUP [group] MODIFY REPLICA ON N'sql-1' WITH (SEEDING_MODE = MANUAL)"
        ));
        assert_eq!(sql.matches("ALTER AVAILABILITY GROUP ").count(), 1);
        assert!(!sql.contains(" JOIN WITH "));
        assert!(!sql.contains("GRANT CREATE ANY DATABASE"));
        assert!(!sql.contains("DROP DATABASE"));
    }

    #[test]
    fn join_checks_identity_after_discovery_before_acknowledgement() {
        let action = NativeAction::JoinAvailabilityGroup {
            availability_group: group(),
            target: replica(1),
        };
        let sql = render_action(
            &action,
            &ServerName::new("sql-1").unwrap(),
            &database().name,
            5022,
        )
        .unwrap();
        assert_eq!(sql.matches(" JOIN WITH ").count(), 1);
        assert!(sql.contains("Cannot join over a primary"));
        let join = sql.find("JOIN WITH").unwrap();
        assert!(sql[join..].contains("Availability-group identity or profile changed"));
        assert!(sql[join..].contains("Local native role or replica identity changed"));
        assert!(!sql.contains("GRANT CREATE ANY DATABASE"));
    }

    #[test]
    fn identifier_and_literal_escaping_does_not_allow_sql_injection() {
        let name = AvailabilityGroupName::new("ag']; THROW 1,--").unwrap();
        let action = NativeAction::JoinAvailabilityGroup {
            availability_group: AvailabilityGroupIdentity {
                name: name.clone(),
                group_id: guid(1),
            },
            target: replica(1),
        };
        let sql = render_action(
            &action,
            &ServerName::new("sql'1").unwrap(),
            &database().name,
            5022,
        )
        .unwrap();
        assert!(sql.contains("N'ag'']; THROW 1,--'"));
        assert!(sql.contains("[ag']]; THROW 1,--] JOIN"));
        assert!(sql.contains("N'sql''1'"));
    }

    fn absent_probe() -> QueryRow {
        let mut row = DATABASE_PROBE_COLUMNS
            .iter()
            .map(|name| ((*name).to_owned(), None))
            .collect::<QueryRow>();
        for (key, value) in [
            ("server_name", "sql-1"),
            ("can_observe_absence", "1"),
            ("backup_ready", "0"),
        ] {
            row.insert(key.to_owned(), Some(value.to_owned()));
        }
        row
    }

    #[test]
    fn hidden_or_malformed_database_metadata_is_not_absence() {
        let server = ServerName::new("sql-1").unwrap();
        let mut row = absent_probe();
        assert!(matches!(
            parse_database_probe(&[row.clone()], &database().name, &server, 123).unwrap(),
            Observation::Absent {
                observed_at_unix_millis: 123
            }
        ));
        row.insert("can_observe_absence".to_owned(), Some("0".to_owned()));
        assert_eq!(
            parse_database_probe(&[row.clone()], &database().name, &server, 123)
                .unwrap_err()
                .kind,
            ObservationFailureKind::PermissionDenied
        );
        row.insert("can_observe_absence".to_owned(), Some("1".to_owned()));
        row.insert("database_guid".to_owned(), Some(guid(3).to_string()));
        assert_eq!(
            parse_database_probe(&[row], &database().name, &server, 123)
                .unwrap_err()
                .kind,
            ObservationFailureKind::Malformed
        );
    }

    #[test]
    fn a_standalone_database_probe_preserves_its_identity_and_lineage() {
        let mut row = absent_probe();
        for (key, value) in [
            ("database_id", "6".to_owned()),
            ("database_name", "database".to_owned()),
            ("database_guid", guid(3).to_string()),
            ("recovery_fork_id", guid(4).to_string()),
            ("state", "ONLINE".to_owned()),
            ("recovery_model", "FULL".to_owned()),
            ("backup_ready", "1".to_owned()),
        ] {
            row.insert(key.to_owned(), Some(value));
        }
        let probe = parse_database_probe(
            &[row.clone()],
            &database().name,
            &ServerName::new("sql-1").unwrap(),
            123,
        )
        .unwrap();
        let Observation::Present { value, .. } = probe else {
            panic!("expected a database")
        };
        assert_eq!(value.database_guid, guid(3));
        assert_eq!(value.recovery_fork_id, guid(4));
        assert!(value.backup_ready);
        assert!(value.group_database_id.is_none());
        row.insert("can_observe_absence".to_owned(), Some("0".to_owned()));
        assert!(matches!(
            parse_database_probe(
                &[row.clone()],
                &database().name,
                &ServerName::new("sql-1").unwrap(),
                123
            )
            .unwrap(),
            Observation::Present { .. }
        ));
        row.insert("database_id".to_owned(), Some("4294967295".to_owned()));
        assert!(
            parse_database_probe(
                &[row],
                &database().name,
                &ServerName::new("sql-1").unwrap(),
                123
            )
            .is_err()
        );
    }
}
