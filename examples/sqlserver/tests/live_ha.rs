//! Run only against a fresh, owned, disposable three-node HA laboratory.
//! Planned and forced tests require distinct fixtures; fencing removes an old
//! container incarnation and deliberately keeps its database volumes.

use std::path::PathBuf;
use std::time::Duration;

use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlserver_replicated::convergence::AcceptedAuthority;
use sqlserver_replicated::fence::DockerFenceProvider;
use sqlserver_replicated::ha::{HaContext, HaPolicy};
use sqlserver_replicated::ha_controller::{FenceProgress, HaController, HaIssuers, HaOutcome};
use sqlserver_replicated::ha_native::{TdsHaBackend, policy_binding};
use sqlserver_replicated::instance::unix_millis;
use sqlserver_replicated::journal::OperationJournal;
use sqlserver_replicated::mutation::{AgBackend, MutationEndpoint, TdsAgBackend};
use sqlserver_replicated::proof::{
    ProofBundle, ProofClaim, ProofClaims, ProofKind, ProofScope, ProofSigner, ProofVerifier,
    SignedProof, TrustedIssuer,
};
use sqlserver_replicated::runtime_config::ObserverConfig;
use sqlserver_replicated::{
    DatabaseLineage, DecimalProgress, Endpoint, MutationMode, Observation, OpaqueId,
    OperationEnvelope, OperationPayload, OperationRequest, PinnedImage, ReplicaDescriptor,
};
use tokio_util::compat::TokioAsyncWriteCompatExt;
use zeroize::Zeroizing;

#[derive(Debug)]
enum ProbeFailure {
    Transport,
    Server(u32),
}

async fn direct_write(node: &Value, statement: &str) -> Result<(), ProbeFailure> {
    let raw = tokio::fs::read(text(node, "observer_config"))
        .await
        .map_err(|_| ProbeFailure::Transport)?;
    let observer = ObserverConfig::from_json(&raw).map_err(|_| ProbeFailure::Transport)?;
    let config: Value = serde_json::from_slice(&raw).map_err(|_| ProbeFailure::Transport)?;
    let username = Zeroizing::new(
        tokio::fs::read_to_string(text(node, "mutation_username_file"))
            .await
            .map_err(|_| ProbeFailure::Transport)?,
    );
    let password = Zeroizing::new(
        tokio::fs::read_to_string(text(node, "mutation_password_file"))
            .await
            .map_err(|_| ProbeFailure::Transport)?,
    );
    let mut tds = tiberius::Config::new();
    tds.host(observer.connection().endpoint().host());
    tds.port(observer.connection().endpoint().port());
    tds.database("master");
    tds.encryption(tiberius::EncryptionLevel::Required);
    tds.trust_cert_ca(text(&config, "ca_certificate_file"));
    tds.authentication(tiberius::AuthMethod::sql_server(
        username.as_str(),
        password.as_str(),
    ));
    tokio::time::timeout(Duration::from_secs(15), async {
        let tcp = tokio::net::TcpStream::connect(tds.get_addr())
            .await
            .map_err(|_| ProbeFailure::Transport)?;
        let mut client = tiberius::Client::connect(tds, tcp.compat_write())
            .await
            .map_err(|_| ProbeFailure::Transport)?;
        client.execute(statement, &[]).await.map_err(|error| {
            error
                .code()
                .map_or(ProbeFailure::Transport, ProbeFailure::Server)
        })?;
        Ok(())
    })
    .await
    .map_err(|_| ProbeFailure::Transport)?
}

fn text<'a>(value: &'a Value, field: &str) -> &'a str {
    value
        .get(field)
        .and_then(Value::as_str)
        .expect("required non-secret lab manifest field")
}

fn signer(manifest: &Value, purpose: &str, kind: ProofKind) -> ProofSigner {
    let bytes = Zeroizing::new(
        std::fs::read(text(&manifest["issuer_keys"], purpose))
            .expect("read private lab issuer seed"),
    );
    assert_eq!(bytes.len(), 32, "issuer seed must have 32 bytes");
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&bytes);
    ProofSigner::from_seed(format!("lab-{purpose}"), kind, &seed).unwrap()
}

fn signed(
    key: &ProofSigner,
    request: &OperationRequest,
    binding: [u8; 32],
    claim: ProofClaim,
) -> SignedProof {
    let now = unix_millis().unwrap();
    key.sign(ProofClaims {
        version: 1,
        proof_id: format!("{}-{now}", key.issuer_id()),
        issuer_id: key.issuer_id().to_owned(),
        issued_at_unix_millis: now,
        not_before_unix_millis: now,
        expires_at_unix_millis: now + 300_000,
        scope: ProofScope::for_operation(request, binding),
        claim,
    })
    .unwrap()
}

async fn run(variable: &str, forced: bool, lease_expiry_only: bool) {
    assert_eq!(
        std::env::var("SQLSERVER_HA_LAB_ALLOW_MUTATIONS").as_deref(),
        Ok("true"),
        "explicit HA lab mutation acknowledgement is required"
    );
    assert_eq!(
        std::env::var("SQLSERVER_TEST_EULA_ACCEPTED").as_deref(),
        Ok("true"),
        "explicit fixture EULA acknowledgement is required"
    );
    if forced {
        assert_eq!(
            std::env::var("SQLSERVER_HA_LAB_ALLOW_DATA_LOSS").as_deref(),
            Ok("true"),
            "forced failover requires explicit data-loss acknowledgement"
        );
    }
    let path =
        PathBuf::from(std::env::var(variable).expect("a dedicated HA lab manifest is required"));
    assert!(path.is_absolute());
    if let (Ok(left), Ok(right)) = (
        std::env::var("SQLSERVER_HA_SWITCH_LAB_CONFIG"),
        std::env::var("SQLSERVER_HA_FAILOVER_LAB_CONFIG"),
    ) {
        assert_ne!(
            std::fs::canonicalize(left).unwrap(),
            std::fs::canonicalize(right).unwrap(),
            "use independent fixtures for the two destructive scenarios"
        );
    }
    let bytes = tokio::fs::read(&path).await.unwrap();
    assert!(bytes.len() <= 65_536);
    let manifest: Value = serde_json::from_slice(&bytes).expect("valid lab manifest");
    assert_eq!(manifest["version"], 1);
    assert_eq!(
        manifest["bootstrap_ag"], true,
        "create the lab with native AG bootstrap enabled"
    );
    assert_eq!(
        manifest["state"], "ready",
        "the owned fixture must finish provisioning"
    );
    PinnedImage::new(text(&manifest, "image")).unwrap();
    let authority_key = signer(&manifest, "authority", ProofKind::Authority);
    let approval_key = signer(&manifest, "approval", ProofKind::Approval);
    let fence_key = signer(&manifest, "fence", ProofKind::Fence);
    let lease_key = signer(&manifest, "lease", ProofKind::Lease);
    let trusted = [&authority_key, &approval_key, &fence_key, &lease_key]
        .iter()
        .map(|key| TrustedIssuer {
            issuer_id: key.issuer_id().to_owned(),
            kind: key.kind(),
            public_key: key.public_key(),
        })
        .collect();
    let verifier = ProofVerifier::new(trusted, 300_000).unwrap();
    let mut members = Vec::new();
    let mut endpoints = Vec::new();
    let mut group_name = None;
    for node in manifest["nodes"].as_array().expect("three lab nodes") {
        let observer = ObserverConfig::read(&PathBuf::from(text(node, "observer_config")))
            .await
            .unwrap();
        assert_eq!(
            observer.target().replica.incarnation(),
            text(node, "container_id")
        );
        let endpoint = Endpoint::new(
            text(node, "replication_host"),
            u16::try_from(node["replication_port"].as_u64().unwrap()).unwrap(),
        )
        .unwrap();
        group_name = Some(observer.target().availability_group.clone());
        members.push(ReplicaDescriptor {
            identity: observer.target().replica.clone(),
            server_name: observer.target().expected_server_name.clone(),
            endpoint: endpoint.clone(),
        });
        endpoints.push(
            MutationEndpoint::new(
                observer,
                endpoint,
                PathBuf::from(text(node, "mutation_username_file")),
                PathBuf::from(text(node, "mutation_password_file")),
            )
            .unwrap(),
        );
    }
    assert_eq!(members.len(), 3);
    let primary = members
        .iter()
        .find(|member| member.identity.logical_id() == text(&manifest, "primary_replica_id"))
        .unwrap()
        .identity
        .clone();
    let source = AcceptedAuthority {
        resource_id: OpaqueId::new("resource", text(&manifest, "resource_id")).unwrap(),
        configuration_id: OpaqueId::new("configuration", text(&manifest, "configuration_id"))
            .unwrap(),
        epoch: manifest["epoch"].as_u64().unwrap(),
        primary,
        replicas: members.clone(),
    };
    let database_name =
        sqlserver_replicated::SqlIdentifier::new(text(&manifest, "database_name")).unwrap();
    let cluster = TdsAgBackend::new(endpoints, database_name.clone()).unwrap();
    let discovery = OperationEnvelope::new(
        OperationRequest::new(
            source.resource_id.as_str(),
            "lab-discover",
            source.configuration_id.as_str(),
            source.epoch,
            source.epoch,
            OperationPayload::EnsureAvailabilityGroup {
                name: group_name.clone().unwrap(),
                expected_group_id: None,
                database_name: database_name.clone(),
                primary: source.primary.clone(),
                replicas: members.clone(),
                write_lease_seconds: 30,
            },
        )
        .unwrap(),
        None,
        None,
    )
    .unwrap();
    let nodes = cluster
        .observe(&discovery, &source, MutationMode::Enabled)
        .await
        .unwrap();
    let source_node = nodes
        .iter()
        .find(|node| node.identity == source.primary)
        .unwrap();
    let Observation::Present {
        value: snapshot, ..
    } = &source_node.instance
    else {
        panic!("primary observation unavailable")
    };
    let Observation::Present { value: group, .. } = &snapshot.availability_group else {
        panic!("lab create must provision and synchronize the native AG")
    };
    let target_member = members
        .iter()
        .find(|member| member.identity != source.primary)
        .unwrap();
    let target_native = group
        .replicas
        .iter()
        .find(|replica| replica.server_name == target_member.server_name)
        .unwrap();
    let target = sqlserver_replicated::ReplicaIdentity::observed(
        target_member.identity.logical_id(),
        target_native.replica_id.clone(),
        target_member.identity.incarnation(),
    )
    .unwrap();
    let database = group.databases.first().unwrap();
    let local = database.local.as_ref().unwrap();
    let fork = local
        .recovery
        .as_ref()
        .unwrap()
        .recovery_fork_guid
        .clone()
        .unwrap();
    let source_replica = group.local_replica.identity.clone();
    let adopted = OperationEnvelope::new(
        OperationRequest::new(
            source.resource_id.as_str(),
            "lab-adopt",
            source.configuration_id.as_str(),
            source.epoch,
            source.epoch,
            OperationPayload::EnsureAvailabilityGroup {
                name: group.identity.name.clone(),
                expected_group_id: Some(group.identity.group_id.clone()),
                database_name,
                primary: source.primary.clone(),
                replicas: members.clone(),
                write_lease_seconds: 30,
            },
        )
        .unwrap(),
        None,
        None,
    )
    .unwrap();
    let adopted_proof = signed(
        &authority_key,
        adopted.request(),
        Sha256::digest(source.canonical_binding()).into(),
        ProofClaim::Authority,
    );
    let infrastructure = DockerFenceProvider::new(
        text(&manifest, "docker_context").to_owned(),
        text(&manifest, "engine_id").to_owned(),
        text(&manifest, "owner_id").to_owned(),
        members
            .iter()
            .map(|member| member.identity.clone())
            .collect(),
    )
    .unwrap();
    let journal_path = PathBuf::from(text(&manifest, "journal_path"));
    let journal = OperationJournal::open(&journal_path, source.resource_id.as_str()).unwrap();
    let policy = HaPolicy {
        lease_seconds: u32::try_from(
            manifest["write_lease_seconds"]
                .as_u64()
                .expect("configured native lease duration"),
        )
        .unwrap(),
        ..HaPolicy::default()
    };
    policy.validate().unwrap();
    let mut controller = HaController::new(
        journal,
        TdsHaBackend::new(cluster),
        infrastructure,
        verifier,
        HaIssuers {
            fence: fence_key,
            lease: lease_key,
        },
        policy.clone(),
    )
    .unwrap()
    .with_mode(MutationMode::Enabled);
    controller
        .adopt(
            &adopted,
            &source,
            &ProofBundle {
                authority: adopted_proof,
                approval: None,
                fence: None,
            },
        )
        .await
        .unwrap();
    let node_values = manifest["nodes"].as_array().unwrap();
    let old_node = node_values
        .iter()
        .find(|node| text(node, "logical_id") == source.primary.logical_id())
        .unwrap();
    let table = format!(
        "{}.dbo.[kuberic_ha_probe]",
        sqlserver_replicated::SqlIdentifier::new(text(&manifest, "database_name"))
            .unwrap()
            .quoted()
    );
    let object = table.replace('\'', "''");
    direct_write(old_node, &format!("IF OBJECT_ID(N'{object}',N'U') IS NULL CREATE TABLE {table} (id int NOT NULL PRIMARY KEY); INSERT INTO {table}(id) VALUES(1);"))
        .await.expect("initial direct TDS write must succeed under the native lease");
    if lease_expiry_only {
        tokio::time::sleep(Duration::from_secs(u64::from(policy.lease_seconds) + 5)).await;
        let statement = format!("INSERT INTO {table}(id) VALUES(2);");
        match direct_write(old_node, &statement).await {
            Err(ProbeFailure::Server(code)) => assert!(code > 0),
            other => panic!(
                "lease expiry must reject a real SQL write, not merely lose connectivity: {other:?}"
            ),
        }
        controller
            .renew_primary(&source)
            .await
            .expect("current authority can reestablish the native lease");
        direct_write(old_node, &statement)
            .await
            .expect("same write succeeds only after authorized lease renewal");
        return;
    }
    let mut destination = source.clone();
    destination.epoch = source.epoch.checked_add(1).unwrap();
    destination.configuration_id = OpaqueId::new(
        "target configuration",
        format!("ha-epoch-{}", destination.epoch),
    )
    .unwrap();
    destination.primary = target_member.identity.clone();
    let context = HaContext {
        source,
        target: destination,
    };
    let lineage = DatabaseLineage {
        database: database.identity.clone(),
        recovery_fork_id: fork,
    };
    let payload = if forced {
        OperationPayload::ForcedFailover {
            availability_group: group.identity.clone(),
            database: lineage,
            source: source_replica,
            target,
            target_configuration_id: context.target.configuration_id.clone(),
            last_known_commit: None,
        }
    } else {
        OperationPayload::PlannedSwitchover {
            availability_group: group.identity.clone(),
            database: lineage,
            source: source_replica,
            target,
            target_configuration_id: context.target.configuration_id.clone(),
            commit_boundary: DecimalProgress::parse("0").unwrap(),
        }
    };
    let request = OperationRequest::new(
        context.source.resource_id.as_str(),
        if forced { "lab-force" } else { "lab-switch" },
        context.source.configuration_id.as_str(),
        context.source.epoch,
        context.target.epoch,
        payload,
    )
    .unwrap();
    let authorization = signed(
        &authority_key,
        &request,
        policy_binding(&context, &policy),
        ProofClaim::Authority,
    );
    let approval = forced.then(|| {
        signed(
            &approval_key,
            &request,
            policy_binding(&context, &policy),
            ProofClaim::Approval {
                allow_data_loss: true,
                allow_unknown_data_loss: true,
            },
        )
    });
    tokio::time::timeout(Duration::from_secs(240), async {
        let command = loop {
            match controller
                .prepare_fence(&request, &context, &authorization, approval.as_ref())
                .await
                .unwrap()
            {
                FenceProgress::Ready(command) => break command,
                FenceProgress::Prepared | FenceProgress::Drained => {
                    tokio::time::sleep(Duration::from_millis(100)).await
                }
            }
        };
        loop {
            match controller
                .reconcile(&command.envelope, &context, &command.proofs)
                .await
                .unwrap()
            {
                HaOutcome::Complete { .. } => break,
                HaOutcome::Prepared(_) | HaOutcome::Dispatched(_) | HaOutcome::Wait(_) => {
                    tokio::time::sleep(Duration::from_millis(200)).await
                }
                other => panic!("HA transition refused: {other:?}"),
            }
        }
        controller.renew_primary(&context.target).await.unwrap();
        assert_eq!(
            controller.journal().authority().unwrap().unwrap().epoch,
            context.target.epoch
        );
        assert!(controller.renew_primary(&context.source).await.is_err());
        let new_node = node_values
            .iter()
            .find(|node| text(node, "logical_id") == context.target.primary.logical_id())
            .unwrap();
        direct_write(new_node, &format!("INSERT INTO {table}(id) VALUES(2);"))
            .await
            .expect("new primary accepts direct writes after native postconditions");
        assert!(
            matches!(
                direct_write(old_node, "SELECT 1;").await,
                Err(ProbeFailure::Transport)
            ),
            "removed old incarnation is not reachable"
        );
    })
    .await
    .expect("native HA transition did not converge within four minutes");
}

#[tokio::test]
#[ignore = "requires a fresh owned three-node SQL Server HA lab and explicit mutation consent"]
async fn live_planned_switchover() {
    run("SQLSERVER_HA_SWITCH_LAB_CONFIG", false, false).await;
}

#[tokio::test]
#[ignore = "requires an independent disposable HA lab and explicit possible-data-loss consent"]
async fn live_forced_failover() {
    run("SQLSERVER_HA_FAILOVER_LAB_CONFIG", true, false).await;
}

#[tokio::test]
#[ignore = "requires an independent disposable HA lab to verify real direct-TDS lease fencing"]
async fn live_write_lease_expiry_blocks_direct_clients() {
    run("SQLSERVER_HA_LEASE_LAB_CONFIG", false, true).await;
}
