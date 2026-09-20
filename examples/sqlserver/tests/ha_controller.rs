#[path = "support/convergence.rs"]
mod fixtures;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use sqlserver_replicated::convergence::AcceptedAuthority;
use sqlserver_replicated::fence::{FenceProvider, RemovedIncarnation};
use sqlserver_replicated::ha::{HaAction, HaContext, HaNode, HaPolicy, HealthSample};
use sqlserver_replicated::ha_controller::{FenceProgress, HaController, HaIssuers, HaOutcome};
use sqlserver_replicated::ha_native::{HaBackend, HaPermit, LeaseSpec, policy_binding};
use sqlserver_replicated::instance::unix_millis;
use sqlserver_replicated::journal::OperationJournal;
use sqlserver_replicated::proof::{
    AuthorityOracle, ProofBundle, ProofClaim, ProofClaims, ProofKind, ProofScope, ProofSigner,
    ProofVerifier, SignedProof, TrustedIssuer,
};
use sqlserver_replicated::runtime_error::RuntimeError;
use sqlserver_replicated::{
    AvailabilityGroupIdentity, DecimalProgress, MutationMode, NativeRole, Observation,
    ObservationFailureKind, OpaqueId, OperationEnvelope, OperationPayload, OperationRequest,
    ReplicaIdentity,
};

struct Model {
    nodes: Vec<HaNode>,
    removed: bool,
    fail_inventory: bool,
    lose_promotion_reply: bool,
    effects: Vec<String>,
    renewals: usize,
}

#[derive(Clone)]
struct Backend(Arc<Mutex<Model>>);
#[derive(Clone)]
struct Fencer(Arc<Mutex<Model>>);

fn fail(kind: ObservationFailureKind) -> RuntimeError {
    RuntimeError::new(kind, "HA fixture", "injected failure")
}

fn set_time<T>(value: &mut Observation<T>, now: u64) {
    match value {
        Observation::Present {
            observed_at_unix_millis,
            ..
        }
        | Observation::Absent {
            observed_at_unix_millis,
        } => *observed_at_unix_millis = now,
        Observation::Failed(failure) => failure.observed_at_unix_millis = now,
    }
}

fn set_role(node: &mut HaNode, role: NativeRole) {
    fixtures::set_role(&mut node.node, Some(role.clone()));
    for database in &mut fixtures::group(&mut node.node).databases {
        for replica in &mut database.replicas {
            replica.is_primary_replica = Some(role == NativeRole::Primary);
        }
    }
}

#[async_trait]
impl HaBackend for Backend {
    async fn observe_current(
        &self,
        _: &AcceptedAuthority,
        _: &AvailabilityGroupIdentity,
        _: &HaPolicy,
    ) -> Result<Vec<HaNode>, RuntimeError> {
        let mut nodes = self.0.lock().unwrap().nodes.clone();
        let now = unix_millis()?;
        for node in &mut nodes {
            set_time(&mut node.node.instance, now);
            set_time(&mut node.node.database, now);
            set_time(&mut node.health, now);
            if let Observation::Present { value, .. } = &mut node.node.instance {
                value.observed_at_unix_millis = now;
                set_time(&mut value.availability_group, now);
            }
            if let Observation::Present { value, .. } = &mut node.health {
                value.sql_utc_millis = now;
            }
        }
        Ok(nodes)
    }

    async fn observe(
        &self,
        _: &OperationRequest,
        context: &HaContext,
        policy: &HaPolicy,
    ) -> Result<Vec<HaNode>, RuntimeError> {
        self.observe_current(&context.source, &fixtures::ag(), policy)
            .await
    }

    async fn drain(
        &self,
        _: &OperationRequest,
        _: &HaContext,
        _: &HaPolicy,
        _: &HaPermit,
    ) -> Result<(), RuntimeError> {
        let mut model = self.0.lock().unwrap();
        model.effects.push("drain".into());
        set_role(&mut model.nodes[0], NativeRole::Resolving);
        Ok(())
    }

    async fn drained_commit(
        &self,
        _: &OperationRequest,
        _: &HaContext,
        _: &HaPolicy,
    ) -> Result<DecimalProgress, RuntimeError> {
        Ok(DecimalProgress::parse("9223372036854775808").unwrap())
    }

    async fn execute(
        &self,
        _: &OperationEnvelope,
        _: &HaContext,
        action: &HaAction,
        _: &HaPolicy,
        _: &HaPermit,
    ) -> Result<(), RuntimeError> {
        let mut model = self.0.lock().unwrap();
        assert!(
            model.removed,
            "no native promotion/reset before permanent fencing"
        );
        model.effects.push(action.key());
        match action {
            HaAction::Promote { forced, .. } => {
                set_role(&mut model.nodes[1], NativeRole::Primary);
                if *forced {
                    let mut replacement =
                        fixtures::database_probe(&mut model.nodes[1].node).clone();
                    replacement.recovery_fork_id = fixtures::guid(301);
                    fixtures::install_database(&mut model.nodes[1].node, 2, Some(replacement));
                    set_role(&mut model.nodes[1], NativeRole::Primary);
                }
                if model.lose_promotion_reply {
                    model.lose_promotion_reply = false;
                    return Err(fail(ObservationFailureKind::TimedOut));
                }
            }
            HaAction::OfflineSecondary { .. } => {
                set_role(&mut model.nodes[2], NativeRole::Resolving);
                model.nodes[2].node.database = Observation::Failed(
                    fail(ObservationFailureKind::Unsupported).into_failure(unix_millis()?),
                );
                let group = fixtures::group(&mut model.nodes[2].node);
                group.databases[0].local = None;
                group.databases[0].replicas.clear();
            }
            HaAction::StartSecondary { .. } => {
                set_role(&mut model.nodes[2], NativeRole::Secondary);
                let fork = fixtures::database_probe(&mut model.nodes[1].node)
                    .recovery_fork_id
                    .clone();
                let mut follower = fixtures::probe(3, true);
                follower.recovery_fork_id = fork;
                fixtures::install_database(&mut model.nodes[2].node, 3, Some(follower));
            }
        }
        Ok(())
    }

    async fn renew(
        &self,
        lease: &LeaseSpec,
        _: &HaPolicy,
        _: &HaPermit,
    ) -> Result<u64, RuntimeError> {
        let mut model = self.0.lock().unwrap();
        if model.removed && lease.primary.logical_id() == "replica-1" {
            return Err(fail(ObservationFailureKind::PermissionDenied));
        }
        model.renewals += 1;
        Ok(unix_millis()? + u64::from(lease.lease_seconds) * 1000)
    }
}

#[async_trait]
impl FenceProvider for Fencer {
    async fn remove(&self, source: &ReplicaIdentity) -> Result<RemovedIncarnation, RuntimeError> {
        let mut model = self.0.lock().unwrap();
        if model.fail_inventory {
            return Err(fail(ObservationFailureKind::Unreachable));
        }
        model.removed = true;
        model.nodes[0].node.instance = Observation::Failed(
            fail(ObservationFailureKind::Unreachable).into_failure(unix_millis()?),
        );
        model.nodes[0].node.database = Observation::Failed(
            fail(ObservationFailureKind::Unreachable).into_failure(unix_millis()?),
        );
        model.nodes[0].health = Observation::Failed(
            fail(ObservationFailureKind::Unreachable).into_failure(unix_millis()?),
        );
        Ok(RemovedIncarnation {
            source: source.clone(),
            engine_id: "engine".into(),
            container_id: source.incarnation().into(),
            removed_at_unix_millis: unix_millis()?,
        })
    }
    async fn verify(&self, _: &RemovedIncarnation) -> Result<(), RuntimeError> {
        let model = self.0.lock().unwrap();
        if !model.removed || model.fail_inventory {
            return Err(fail(ObservationFailureKind::Unreachable));
        }
        Ok(())
    }
}

struct Keys {
    authority: ProofSigner,
    approval: ProofSigner,
}

fn key_material() -> (Keys, HaIssuers, ProofVerifier) {
    let authority = ProofSigner::from_seed("authority", ProofKind::Authority, &[1; 32]).unwrap();
    let approval = ProofSigner::from_seed("approval", ProofKind::Approval, &[2; 32]).unwrap();
    let fence = ProofSigner::from_seed("fence", ProofKind::Fence, &[3; 32]).unwrap();
    let lease = ProofSigner::from_seed("lease", ProofKind::Lease, &[4; 32]).unwrap();
    let issuers = [&authority, &approval, &fence, &lease]
        .iter()
        .map(|key| TrustedIssuer {
            issuer_id: key.issuer_id().into(),
            kind: key.kind(),
            public_key: key.public_key(),
        })
        .collect();
    (
        Keys {
            authority,
            approval,
        },
        HaIssuers { fence, lease },
        ProofVerifier::new(issuers, 300_000).unwrap(),
    )
}

fn sign(
    key: &ProofSigner,
    request: &OperationRequest,
    binding: [u8; 32],
    claim: ProofClaim,
) -> SignedProof {
    let now = unix_millis().unwrap();
    key.sign(ProofClaims {
        version: 1,
        proof_id: format!("{}-proof", key.issuer_id()),
        issuer_id: key.issuer_id().into(),
        issued_at_unix_millis: now,
        not_before_unix_millis: now,
        expires_at_unix_millis: now + 120_000,
        scope: ProofScope::for_operation(request, binding),
        claim,
    })
    .unwrap()
}

fn setup() -> (HaContext, Arc<Mutex<Model>>, OperationEnvelope) {
    let now = unix_millis().unwrap();
    let mut source = fixtures::authority();
    let mut nodes = Vec::new();
    for id in 1..=3 {
        let incarnation = char::from(b'a' + u8::try_from(id - 1).unwrap())
            .to_string()
            .repeat(64);
        source.replicas[usize::try_from(id - 1).unwrap()].identity =
            ReplicaIdentity::desired(format!("replica-{id}"), &incarnation).unwrap();
        let mut node = fixtures::existing(id, true);
        node.identity = source.replicas[usize::try_from(id - 1).unwrap()]
            .identity
            .clone();
        fixtures::group(&mut node).local_replica.identity = ReplicaIdentity::observed(
            format!("replica-{id}"),
            fixtures::guid(100 + id),
            incarnation,
        )
        .unwrap();
        nodes.push(HaNode {
            node,
            health: Observation::Present {
                observed_at_unix_millis: now,
                value: HealthSample {
                    sql_utc_millis: now,
                    system: 1,
                    resource: 1,
                    query_processing: 1,
                    configuration_commit_age_millis: None,
                    db_failover: true,
                },
            },
        });
    }
    source.primary = source.replicas[0].identity.clone();
    let mut target = source.clone();
    target.primary = source.replicas[1].identity.clone();
    target.configuration_id = OpaqueId::new("configuration", "configuration-2").unwrap();
    target.epoch += 1;
    let adopted = OperationEnvelope::new(
        OperationRequest::new(
            source.resource_id.as_str(),
            "adopt",
            source.configuration_id.as_str(),
            source.epoch,
            source.epoch,
            OperationPayload::EnsureAvailabilityGroup {
                name: fixtures::ag().name,
                expected_group_id: Some(fixtures::ag().group_id),
                database_name: fixtures::database().name,
                primary: source.primary.clone(),
                replicas: source.replicas.clone(),
                write_lease_seconds: 30,
            },
        )
        .unwrap(),
        None,
        None,
    )
    .unwrap();
    (
        HaContext { source, target },
        Arc::new(Mutex::new(Model {
            nodes,
            removed: false,
            fail_inventory: false,
            lose_promotion_reply: false,
            effects: Vec::new(),
            renewals: 0,
        })),
        adopted,
    )
}

fn transition(context: &HaContext, model: &Model, forced: bool) -> OperationRequest {
    let source = match &model.nodes[0].node.instance {
        Observation::Present { value, .. } => match &value.availability_group {
            Observation::Present { value, .. } => value.local_replica.identity.clone(),
            _ => panic!("group"),
        },
        _ => panic!("instance"),
    };
    let target = match &model.nodes[1].node.instance {
        Observation::Present { value, .. } => match &value.availability_group {
            Observation::Present { value, .. } => value.local_replica.identity.clone(),
            _ => panic!("group"),
        },
        _ => panic!("instance"),
    };
    let database = sqlserver_replicated::DatabaseLineage {
        database: fixtures::database(),
        recovery_fork_id: fixtures::guid(300),
    };
    let payload = if forced {
        OperationPayload::ForcedFailover {
            availability_group: fixtures::ag(),
            database,
            source,
            target,
            target_configuration_id: context.target.configuration_id.clone(),
            last_known_commit: None,
        }
    } else {
        OperationPayload::PlannedSwitchover {
            availability_group: fixtures::ag(),
            database,
            source,
            target,
            target_configuration_id: context.target.configuration_id.clone(),
            commit_boundary: DecimalProgress::parse("1").unwrap(),
        }
    };
    OperationRequest::new(
        context.source.resource_id.as_str(),
        if forced { "forced" } else { "planned" },
        context.source.configuration_id.as_str(),
        context.source.epoch,
        context.target.epoch,
        payload,
    )
    .unwrap()
}

#[tokio::test]
async fn signed_switch_fences_then_recovers_a_lost_promotion_reply_and_commits_authority() {
    let (context, state, adopt) = setup();
    state.lock().unwrap().lose_promotion_reply = true;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("journal");
    let (keys, issuers, verifier) = key_material();
    let policy = HaPolicy::default();
    let adopted_proof = sign(
        &keys.authority,
        adopt.request(),
        Sha256::digest(context.source.canonical_binding()).into(),
        ProofClaim::Authority,
    );
    let adopted_bundle = ProofBundle {
        authority: adopted_proof,
        approval: None,
        fence: None,
    };
    let request = transition(&context, &state.lock().unwrap(), false);
    let grant = sign(
        &keys.authority,
        &request,
        policy_binding(&context, &policy),
        ProofClaim::Authority,
    );
    let mut controller = HaController::new(
        OperationJournal::open(&path, context.source.resource_id.as_str()).unwrap(),
        Backend(state.clone()),
        Fencer(state.clone()),
        verifier,
        issuers,
        policy.clone(),
    )
    .unwrap()
    .with_mode(MutationMode::Enabled);
    controller
        .adopt(&adopt, &context.source, &adopted_bundle)
        .await
        .unwrap();
    let old_scope = ProofScope::for_operation(
        adopt.request(),
        Sha256::digest(context.source.canonical_binding()).into(),
    );
    let oracle = controller.authority_oracle();
    oracle.check(&old_scope, &ProofClaim::Authority).unwrap();
    let mut fenced = None;
    for _ in 0..8 {
        match controller
            .prepare_fence(&request, &context, &grant, None)
            .await
            .unwrap()
        {
            FenceProgress::Ready(command) => {
                fenced = Some(command);
                break;
            }
            FenceProgress::Prepared | FenceProgress::Drained => {}
        }
    }
    let command = fenced.expect("permanent fence completed");
    assert!(oracle.check(&old_scope, &ProofClaim::Authority).is_err());
    assert!(state.lock().unwrap().removed);
    let mut complete = false;
    for _ in 0..15 {
        match controller
            .reconcile(&command.envelope, &context, &command.proofs)
            .await
        {
            Ok(HaOutcome::Complete {
                replayed: false, ..
            }) => {
                complete = true;
                break;
            }
            Ok(HaOutcome::Prepared(_) | HaOutcome::Dispatched(_) | HaOutcome::Wait(_)) => {}
            Err(sqlserver_replicated::ha_controller::HaError::Runtime(error))
                if error.kind == ObservationFailureKind::TimedOut =>
            {
                drop(controller);
                let (_, issuers, verifier) = key_material();
                controller = HaController::new(
                    OperationJournal::open(&path, context.source.resource_id.as_str()).unwrap(),
                    Backend(state.clone()),
                    Fencer(state.clone()),
                    verifier,
                    issuers,
                    policy.clone(),
                )
                .unwrap()
                .with_mode(MutationMode::Enabled);
            }
            other => panic!("unexpected HA outcome: {other:?}"),
        }
    }
    assert!(complete);
    assert_eq!(
        controller.journal().authority().unwrap().unwrap().epoch,
        context.target.epoch
    );
    assert!(matches!(
        controller
            .reconcile(&command.envelope, &context, &command.proofs)
            .await
            .unwrap(),
        HaOutcome::Complete { replayed: true, .. }
    ));
    assert_eq!(
        state
            .lock()
            .unwrap()
            .effects
            .iter()
            .filter(|key| key.starts_with("promote"))
            .count(),
        1
    );
    assert!(controller.renew_primary(&context.source).await.is_err());
    controller.renew_primary(&context.target).await.unwrap();
}

#[tokio::test]
async fn forced_transition_requires_data_loss_acknowledgement_before_any_fence() {
    let (context, state, adopt) = setup();
    let directory = tempfile::tempdir().unwrap();
    let (keys, issuers, verifier) = key_material();
    let policy = HaPolicy::default();
    let authority = sign(
        &keys.authority,
        adopt.request(),
        Sha256::digest(context.source.canonical_binding()).into(),
        ProofClaim::Authority,
    );
    let mut controller = HaController::new(
        OperationJournal::open(
            &directory.path().join("journal"),
            context.source.resource_id.as_str(),
        )
        .unwrap(),
        Backend(state.clone()),
        Fencer(state.clone()),
        verifier,
        issuers,
        policy.clone(),
    )
    .unwrap()
    .with_mode(MutationMode::Enabled);
    controller
        .adopt(
            &adopt,
            &context.source,
            &ProofBundle {
                authority,
                approval: None,
                fence: None,
            },
        )
        .await
        .unwrap();
    let request = transition(&context, &state.lock().unwrap(), true);
    let authority = sign(
        &keys.authority,
        &request,
        policy_binding(&context, &policy),
        ProofClaim::Authority,
    );
    let insufficient = sign(
        &keys.approval,
        &request,
        policy_binding(&context, &policy),
        ProofClaim::Approval {
            allow_data_loss: true,
            allow_unknown_data_loss: false,
        },
    );
    assert!(
        controller
            .prepare_fence(&request, &context, &authority, None)
            .await
            .is_err()
    );
    assert!(
        controller
            .prepare_fence(&request, &context, &authority, Some(&insufficient))
            .await
            .is_err()
    );
    assert!(!state.lock().unwrap().removed);
    assert!(state.lock().unwrap().effects.is_empty());
}

#[tokio::test]
async fn forced_failover_handles_an_unreachable_source_and_a_new_recovery_fork() {
    let (context, state, adopt) = setup();
    let directory = tempfile::tempdir().unwrap();
    let (keys, issuers, verifier) = key_material();
    let policy = HaPolicy::default();
    let auth = signed_adoption(&keys, &context, &adopt);
    let mut controller = HaController::new(
        OperationJournal::open(
            &directory.path().join("journal"),
            context.source.resource_id.as_str(),
        )
        .unwrap(),
        Backend(state.clone()),
        Fencer(state.clone()),
        verifier,
        issuers,
        policy.clone(),
    )
    .unwrap()
    .with_mode(MutationMode::Enabled);
    controller
        .adopt(&adopt, &context.source, &auth)
        .await
        .unwrap();
    let request = transition(&context, &state.lock().unwrap(), true);
    {
        let mut model = state.lock().unwrap();
        model.nodes[0].node.instance = fixtures::failed();
        model.nodes[0].node.database = fixtures::failed();
        model.nodes[0].health = fixtures::failed();
    }
    let authority = sign(
        &keys.authority,
        &request,
        policy_binding(&context, &policy),
        ProofClaim::Authority,
    );
    let approval = sign(
        &keys.approval,
        &request,
        policy_binding(&context, &policy),
        ProofClaim::Approval {
            allow_data_loss: true,
            allow_unknown_data_loss: true,
        },
    );
    let mut command = None;
    for _ in 0..5 {
        if let FenceProgress::Ready(ready) = controller
            .prepare_fence(&request, &context, &authority, Some(&approval))
            .await
            .unwrap()
        {
            command = Some(ready);
            break;
        }
    }
    let command = command.expect("exact crashed incarnation was removed");
    let mut complete = false;
    for _ in 0..12 {
        match controller
            .reconcile(&command.envelope, &context, &command.proofs)
            .await
            .unwrap()
        {
            HaOutcome::Complete { .. } => {
                complete = true;
                break;
            }
            HaOutcome::Prepared(_) | HaOutcome::Dispatched(_) | HaOutcome::Wait(_) => {}
            outcome => panic!("unexpected force recovery: {outcome:?}"),
        }
    }
    assert!(complete);
    assert!(
        !state
            .lock()
            .unwrap()
            .effects
            .iter()
            .any(|effect| effect == "drain")
    );
    assert_eq!(
        controller.journal().authority().unwrap().unwrap().epoch,
        context.target.epoch
    );
}

fn signed_adoption(keys: &Keys, context: &HaContext, request: &OperationEnvelope) -> ProofBundle {
    ProofBundle {
        authority: sign(
            &keys.authority,
            request.request(),
            Sha256::digest(context.source.canonical_binding()).into(),
            ProofClaim::Authority,
        ),
        approval: None,
        fence: None,
    }
}
