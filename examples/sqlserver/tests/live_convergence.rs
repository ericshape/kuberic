//! Opt-in, non-destructive AG setup on an explicitly owned disposable fixture.
//! This never authorizes reseed, primary transitions, or arbitrary SQL.

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use sqlserver_replicated::adapter::{AdapterOutcome, AgAdapter};
use sqlserver_replicated::convergence::{AcceptedAuthority, NativeAction, Postcondition};
use sqlserver_replicated::journal::OperationJournal;
use sqlserver_replicated::mutation::{
    AgBackend, AuthorizationVerifier, MutationEndpoint, TdsAgBackend,
};
use sqlserver_replicated::observation::AvailabilityGroupSnapshot;
use sqlserver_replicated::runtime_config::ObserverConfig;
use sqlserver_replicated::runtime_error::RuntimeError;
use sqlserver_replicated::{
    Endpoint, MutationMode, Observation, ObservationFailureKind, OpaqueId, OperationEnvelope,
    OperationPayload, OperationRequest, PinnedImage, ReplicaDescriptor, ReplicaIdentity,
    SqlIdentifier,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LabConfig {
    resource_id: String,
    configuration_id: String,
    epoch: u64,
    primary_replica_id: String,
    database_name: String,
    journal_path: PathBuf,
    nodes: Vec<LabNode>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LabNode {
    observer_config: PathBuf,
    replication_host: String,
    replication_port: u16,
    mutation_username_file: PathBuf,
    mutation_password_file: PathBuf,
}

/// Test-only authorization by the disposable fixture's explicit owner.
/// It cannot stand in for a production authority or authenticate a fence.
struct NonDestructiveLabAuthorization {
    resource_id: String,
}

#[async_trait]
impl AuthorizationVerifier for NonDestructiveLabAuthorization {
    async fn verify_request(
        &self,
        envelope: &OperationEnvelope,
        authority: &AcceptedAuthority,
    ) -> Result<(), RuntimeError> {
        authority.validate_for(envelope)?;
        if envelope.request().resource_id() == self.resource_id
            && matches!(
                envelope.request().payload(),
                OperationPayload::EnsureAvailabilityGroup { .. }
                    | OperationPayload::EnsureReplicaJoined { .. }
                    | OperationPayload::EnsureReplicaSeeded { .. }
            )
        {
            Ok(())
        } else {
            Err(RuntimeError::new(
                ObservationFailureKind::PermissionDenied,
                "lab",
                "only fixture-owned non-destructive operations are authorized",
            ))
        }
    }

    async fn verify(
        &self,
        envelope: &OperationEnvelope,
        authority: &AcceptedAuthority,
        action: &NativeAction,
    ) -> Result<(), RuntimeError> {
        self.verify_request(envelope, authority).await?;
        if action.is_destructive() {
            return Err(RuntimeError::new(
                ObservationFailureKind::PermissionDenied,
                "lab",
                "this lab does not provide a real fence verifier",
            ));
        }
        Ok(())
    }
}

fn envelope(authority: &AcceptedAuthority, payload: OperationPayload) -> OperationEnvelope {
    let candidate = OperationRequest::new(
        authority.resource_id.as_str(),
        "effect-key",
        authority.configuration_id.as_str(),
        authority.epoch,
        authority.epoch,
        payload.clone(),
    )
    .unwrap();
    let request = OperationRequest::new(
        authority.resource_id.as_str(),
        format!("lab:{}", candidate.effect_signature()),
        authority.configuration_id.as_str(),
        authority.epoch,
        authority.epoch,
        payload,
    )
    .unwrap();
    OperationEnvelope::new(request, None, None).unwrap()
}

async fn drive(
    adapter: &mut AgAdapter<TdsAgBackend, NonDestructiveLabAuthorization>,
    request: &OperationEnvelope,
    authority: &AcceptedAuthority,
) -> Postcondition {
    tokio::time::timeout(Duration::from_secs(300), async {
        loop {
            match adapter
                .reconcile(request, authority)
                .await
                .expect("authorized lab reconciliation failed; intent is retained")
            {
                AdapterOutcome::Complete { postcondition, .. } => return postcondition,
                AdapterOutcome::Prepared(_)
                | AdapterOutcome::Dispatched(_)
                | AdapterOutcome::Wait(_) => {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                other => panic!("lab cannot proceed: {other:?}"),
            }
        }
    })
    .await
    .expect("native postcondition was not established within five minutes")
}

async fn primary_group(
    backend: &TdsAgBackend,
    request: &OperationEnvelope,
    authority: &AcceptedAuthority,
) -> AvailabilityGroupSnapshot {
    let evidence = backend
        .observe(request, authority, MutationMode::Enabled)
        .await
        .unwrap();
    let primary = evidence
        .iter()
        .find(|node| node.identity == authority.primary)
        .expect("registered primary");
    match &primary.instance {
        Observation::Present { value, .. } => match &value.availability_group {
            Observation::Present { value, .. } => value.clone(),
            other => panic!("expected a current native AG, got {other:?}"),
        },
        other => panic!("expected a current primary observation, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "requires explicitly owned licensed three-instance SQL Server fixture and mutation acknowledgement"]
async fn live_bootstrap_join_seed_and_replay() {
    assert_eq!(
        std::env::var("SQLSERVER_AG_LAB_ALLOW_MUTATIONS").as_deref(),
        Ok("true"),
        "SQLSERVER_AG_LAB_ALLOW_MUTATIONS=true is required for this disposable fixture"
    );
    assert_eq!(
        std::env::var("SQLSERVER_TEST_EULA_ACCEPTED").as_deref(),
        Ok("true"),
        "fixture owner must explicitly acknowledge EULA acceptance"
    );
    PinnedImage::new(
        std::env::var("SQLSERVER_TEST_IMAGE").expect("fixture image must be supplied"),
    )
    .expect("fixture image must be digest pinned");
    let path = PathBuf::from(
        std::env::var("SQLSERVER_AG_LAB_CONFIG").expect("SQLSERVER_AG_LAB_CONFIG is required"),
    );
    assert!(
        path.is_absolute(),
        "fixture config must have an absolute path"
    );
    let bytes = tokio::fs::read(path)
        .await
        .expect("read the explicit fixture configuration");
    assert!(
        bytes.len() <= 65_536,
        "fixture configuration exceeds 64 KiB"
    );
    let fixture: LabConfig = serde_json::from_slice(&bytes)
        .expect("valid fixture configuration without inline credentials");
    assert_eq!(fixture.nodes.len(), 3);
    let mut nodes = Vec::new();
    let mut replicas = Vec::new();
    let mut group_name = None;
    for node in fixture.nodes {
        let observer = ObserverConfig::read(&node.observer_config).await.unwrap();
        let endpoint = Endpoint::new(node.replication_host, node.replication_port).unwrap();
        if let Some(expected) = &group_name {
            assert_eq!(expected, &observer.target().availability_group);
        } else {
            group_name = Some(observer.target().availability_group.clone());
        }
        replicas.push(ReplicaDescriptor {
            identity: observer.target().replica.clone(),
            server_name: observer.target().expected_server_name.clone(),
            endpoint: endpoint.clone(),
        });
        nodes.push(
            MutationEndpoint::new(
                observer,
                endpoint,
                node.mutation_username_file,
                node.mutation_password_file,
            )
            .unwrap(),
        );
    }
    let primary = replicas
        .iter()
        .find(|member| member.identity.logical_id() == fixture.primary_replica_id)
        .expect("explicit primary must be a registered member")
        .identity
        .clone();
    let authority = AcceptedAuthority {
        resource_id: OpaqueId::new("resource", fixture.resource_id.clone()).unwrap(),
        configuration_id: OpaqueId::new("configuration", fixture.configuration_id).unwrap(),
        epoch: fixture.epoch,
        primary: primary.clone(),
        replicas,
    };
    let database_name = SqlIdentifier::new(fixture.database_name).unwrap();
    let backend = TdsAgBackend::new(nodes, database_name.clone()).unwrap();
    let journal = OperationJournal::open(&fixture.journal_path, &fixture.resource_id).unwrap();
    let mut adapter = AgAdapter::new(journal, backend.clone())
        .with_verifier(NonDestructiveLabAuthorization {
            resource_id: fixture.resource_id.clone(),
        })
        .with_mode(MutationMode::Enabled);
    let bootstrap = envelope(
        &authority,
        OperationPayload::EnsureAvailabilityGroup {
            name: group_name.unwrap(),
            expected_group_id: None,
            database_name,
            primary,
            replicas: authority.replicas.clone(),
        },
    );
    let created = drive(&mut adapter, &bootstrap, &authority).await;
    let native = primary_group(&backend, &bootstrap, &authority).await;
    assert_eq!(
        created.availability_group, native.identity,
        "historical replay cannot adopt a replacement AG"
    );
    let database = native
        .databases
        .first()
        .expect("managed primary database")
        .identity
        .clone();
    for member in &authority.replicas {
        if member.identity == authority.primary {
            continue;
        }
        let configured = native
            .replicas
            .iter()
            .find(|replica| replica.server_name == member.server_name)
            .unwrap();
        let target = ReplicaIdentity::observed(
            member.identity.logical_id(),
            configured.replica_id.clone(),
            member.identity.incarnation(),
        )
        .unwrap();
        let join = envelope(
            &authority,
            OperationPayload::EnsureReplicaJoined {
                availability_group: native.identity.clone(),
                target: target.clone(),
            },
        );
        drive(&mut adapter, &join, &authority).await;
        let seed = envelope(
            &authority,
            OperationPayload::EnsureReplicaSeeded {
                availability_group: native.identity.clone(),
                database: database.clone(),
                source: native.local_replica.identity.clone(),
                target,
            },
        );
        let seeded = drive(&mut adapter, &seed, &authority).await;
        assert_eq!(seeded.database.as_ref(), Some(&database));
        assert!(seeded.database_guid.is_some());
        assert!(matches!(
            adapter.reconcile(&seed, &authority).await.unwrap(),
            AdapterOutcome::Complete {
                replayed: true,
                retained: true,
                ..
            }
        ));
    }
    // Deliberately retain the fixture and journal. There is no implicit DROP,
    // fence release, role transition, or deployment cleanup in a test.
}
