#[path = "support/convergence.rs"]
mod fixtures;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use sqlserver_replicated::adapter::{AdapterOutcome, AgAdapter};
use sqlserver_replicated::convergence::{AcceptedAuthority, NativeAction, NodeEvidence};
use sqlserver_replicated::instance::unix_millis;
use sqlserver_replicated::journal::OperationJournal;
use sqlserver_replicated::mutation::{AgBackend, AuthorizationVerifier};
use sqlserver_replicated::runtime_error::RuntimeError;
use sqlserver_replicated::{
    MutationMode, NativeRole, Observation, ObservationFailureKind, OperationEnvelope,
};

struct State {
    nodes: Vec<NodeEvidence>,
    effects: Vec<NativeAction>,
    lost_reply: Option<&'static str>,
    hold_seeding: bool,
    deny: bool,
}

#[derive(Clone)]
struct Backend(Arc<Mutex<State>>);

#[derive(Clone)]
struct Verifier(Arc<Mutex<State>>);

#[async_trait]
impl AuthorizationVerifier for Verifier {
    async fn verify_request(
        &self,
        _: &OperationEnvelope,
        _: &AcceptedAuthority,
    ) -> Result<(), RuntimeError> {
        if self.0.lock().unwrap().deny {
            Err(failure(ObservationFailureKind::PermissionDenied))
        } else {
            Ok(())
        }
    }

    async fn verify(
        &self,
        envelope: &OperationEnvelope,
        authority: &AcceptedAuthority,
        _: &NativeAction,
    ) -> Result<(), RuntimeError> {
        self.verify_request(envelope, authority).await
    }
}

fn failure(kind: ObservationFailureKind) -> RuntimeError {
    RuntimeError::new(kind, "lifecycle fixture", "injected fixture outcome")
}

fn stamp<T>(value: &mut Observation<T>, now: u64) {
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

#[async_trait]
impl AgBackend for Backend {
    async fn observe(
        &self,
        _: &OperationEnvelope,
        _: &AcceptedAuthority,
        _: MutationMode,
    ) -> Result<Vec<NodeEvidence>, RuntimeError> {
        let mut nodes = self.0.lock().unwrap().nodes.clone();
        let now = unix_millis()?;
        for node in &mut nodes {
            stamp(&mut node.instance, now);
            stamp(&mut node.database, now);
            if let Observation::Present { value, .. } = &mut node.instance {
                value.observed_at_unix_millis = now;
                stamp(&mut value.availability_group, now);
            }
        }
        Ok(nodes)
    }

    async fn execute(
        &self,
        envelope: &OperationEnvelope,
        authority: &AcceptedAuthority,
        action: &NativeAction,
        verifier: &dyn AuthorizationVerifier,
    ) -> Result<(), RuntimeError> {
        verifier.verify(envelope, authority, action).await?;
        let mut state = self.0.lock().unwrap();
        state.effects.push(action.clone());
        match action {
            NativeAction::JoinAvailabilityGroup { .. } => {
                state.nodes[1] = fixtures::existing(2, false)
            }
            NativeAction::DetachDatabase { .. } => {
                let mut probe = fixtures::database_probe(&mut state.nodes[1]).clone();
                probe.group_database_id = None;
                probe.replica_id = None;
                probe.state = "RESTORING".to_owned();
                fixtures::install_database(&mut state.nodes[1], 2, Some(probe));
            }
            NativeAction::DropDatabase { .. } => {
                fixtures::install_database(&mut state.nodes[1], 2, None)
            }
            NativeAction::GrantSeeding { .. } => {}
            NativeAction::TriggerSeeding { .. } if !state.hold_seeding => {
                let mut replacement = fixtures::probe(2, true);
                replacement.database_guid = fixtures::guid(902);
                fixtures::install_database(&mut state.nodes[1], 2, Some(replacement));
            }
            NativeAction::TriggerSeeding { .. } => {}
            other => panic!("unexpected fixture action: {other:?}"),
        }
        if state.lost_reply == Some(action.key()) {
            state.lost_reply = None;
            Err(failure(ObservationFailureKind::TimedOut))
        } else {
            Ok(())
        }
    }
}

fn enabled(
    path: &std::path::Path,
    authority: &AcceptedAuthority,
    state: Arc<Mutex<State>>,
) -> AgAdapter<Backend, Verifier> {
    AgAdapter::new(
        OperationJournal::open(path, authority.resource_id.as_str()).unwrap(),
        Backend(state.clone()),
    )
    .with_verifier(Verifier(state))
    .with_mode(MutationMode::Enabled)
}

fn state(nodes: Vec<NodeEvidence>) -> Arc<Mutex<State>> {
    Arc::new(Mutex::new(State {
        nodes,
        effects: Vec::new(),
        lost_reply: None,
        hold_seeding: false,
        deny: false,
    }))
}

#[tokio::test]
async fn joining_is_prepared_then_confirmed_by_native_identity_not_ack() {
    let (request, authority, nodes) = fixtures::join(unix_millis().unwrap());
    let directory = tempfile::tempdir().unwrap();
    let state = state(nodes);
    let mut adapter = enabled(&directory.path().join("journal"), &authority, state.clone());
    assert!(matches!(
        adapter.reconcile(&request, &authority).await.unwrap(),
        AdapterOutcome::Prepared(NativeAction::JoinAvailabilityGroup { .. })
    ));
    assert!(matches!(
        adapter.reconcile(&request, &authority).await.unwrap(),
        AdapterOutcome::Dispatched(_)
    ));
    assert!(
        adapter
            .journal()
            .entry(request.operation_id())
            .unwrap()
            .unwrap()
            .terminal_result
            .is_none()
    );
    assert!(matches!(
        adapter.reconcile(&request, &authority).await.unwrap(),
        AdapterOutcome::Complete { .. }
    ));
    assert_eq!(state.lock().unwrap().effects.len(), 1);
}

#[tokio::test]
async fn seeding_acks_cannot_complete_a_missing_database() {
    let (request, authority, nodes) = fixtures::seed(unix_millis().unwrap());
    let directory = tempfile::tempdir().unwrap();
    let state = state(nodes);
    state.lock().unwrap().hold_seeding = true;
    let mut adapter = enabled(&directory.path().join("journal"), &authority, state.clone());
    for expected in ["grant_seeding", "trigger_seeding"] {
        let AdapterOutcome::Prepared(action) =
            adapter.reconcile(&request, &authority).await.unwrap()
        else {
            panic!("expected preparation")
        };
        assert_eq!(action.key(), expected);
        assert!(matches!(
            adapter.reconcile(&request, &authority).await.unwrap(),
            AdapterOutcome::Dispatched(_)
        ));
    }
    assert!(matches!(
        adapter.reconcile(&request, &authority).await.unwrap(),
        AdapterOutcome::Wait(_)
    ));
    assert!(
        adapter
            .journal()
            .entry(request.operation_id())
            .unwrap()
            .unwrap()
            .terminal_result
            .is_none()
    );
    let mut replacement = fixtures::probe(2, true);
    replacement.database_guid = fixtures::guid(902);
    fixtures::install_database(&mut state.lock().unwrap().nodes[1], 2, Some(replacement));
    assert!(matches!(
        adapter.reconcile(&request, &authority).await.unwrap(),
        AdapterOutcome::Complete { .. }
    ));
    assert_eq!(state.lock().unwrap().effects.len(), 2);
}

#[tokio::test]
async fn reseed_recovers_lost_destructive_replies_and_never_redrops_the_replacement() {
    for lost_reply in ["detach_database", "drop_database"] {
        let (request, authority, nodes) = fixtures::reseed(unix_millis().unwrap());
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal");
        let state = state(nodes);
        state.lock().unwrap().lost_reply = Some(lost_reply);
        let mut adapter = enabled(&path, &authority, state.clone());
        let mut completed = false;
        for _ in 0..12 {
            let effects_before = state.lock().unwrap().effects.len();
            match adapter.reconcile(&request, &authority).await {
                Ok(AdapterOutcome::Complete { postcondition, .. }) => {
                    assert_eq!(postcondition.database_guid, Some(fixtures::guid(902)));
                    completed = true;
                    break;
                }
                Ok(AdapterOutcome::Prepared(_) | AdapterOutcome::Dispatched(_)) => {}
                Err(sqlserver_replicated::adapter::AdapterError::Runtime(error))
                    if error.kind == ObservationFailureKind::TimedOut =>
                {
                    drop(adapter);
                    adapter = enabled(&path, &authority, state.clone());
                }
                other => panic!("unexpected reseed state: {other:?}"),
            }
            assert!(state.lock().unwrap().effects.len() <= effects_before + 1);
        }
        assert!(completed);
        let effects = state.lock().unwrap().effects.clone();
        assert_eq!(
            effects.iter().map(NativeAction::key).collect::<Vec<_>>(),
            [
                "detach_database",
                "drop_database",
                "grant_seeding",
                "trigger_seeding"
            ]
        );
        assert!(matches!(
            adapter.reconcile(&request, &authority).await.unwrap(),
            AdapterOutcome::Complete { replayed: true, .. }
        ));
        assert_eq!(state.lock().unwrap().effects.len(), 4);
    }
}

#[tokio::test]
async fn a_new_unassociated_database_is_not_deleted_by_an_old_reseed() {
    let (request, authority, nodes) = fixtures::reseed(unix_millis().unwrap());
    let directory = tempfile::tempdir().unwrap();
    let state = state(nodes);
    let mut adapter = enabled(&directory.path().join("journal"), &authority, state.clone());
    adapter.reconcile(&request, &authority).await.unwrap();
    adapter.reconcile(&request, &authority).await.unwrap();
    let mut replacement = fixtures::probe(2, false);
    replacement.database_guid = fixtures::guid(999);
    fixtures::install_database(&mut state.lock().unwrap().nodes[1], 2, Some(replacement));
    assert!(matches!(
        adapter.reconcile(&request, &authority).await.unwrap(),
        AdapterOutcome::Unsafe(_)
    ));
    assert_eq!(state.lock().unwrap().effects.len(), 1);
}

#[tokio::test]
async fn revoked_authority_or_changed_native_role_prevents_the_next_destructive_step() {
    let (request, authority, nodes) = fixtures::reseed(unix_millis().unwrap());
    let directory = tempfile::tempdir().unwrap();
    let state = state(nodes);
    let mut adapter = enabled(&directory.path().join("journal"), &authority, state.clone());
    adapter.reconcile(&request, &authority).await.unwrap();
    adapter.reconcile(&request, &authority).await.unwrap();
    state.lock().unwrap().deny = true;
    assert!(adapter.reconcile(&request, &authority).await.is_err());
    assert_eq!(state.lock().unwrap().effects.len(), 1);
    state.lock().unwrap().deny = false;
    fixtures::set_role(
        &mut state.lock().unwrap().nodes[1],
        Some(NativeRole::Primary),
    );
    assert!(matches!(
        adapter.reconcile(&request, &authority).await.unwrap(),
        AdapterOutcome::Unsafe(_) | AdapterOutcome::Wait(_)
    ));
    assert_eq!(state.lock().unwrap().effects.len(), 1);
}

#[tokio::test]
async fn failed_required_observations_keep_their_diagnostic_without_recording_work() {
    let (request, authority, mut nodes) = fixtures::seed(unix_millis().unwrap());
    nodes[0].instance = fixtures::failed();
    let directory = tempfile::tempdir().unwrap();
    let state = state(nodes);
    let mut adapter = enabled(&directory.path().join("journal"), &authority, state.clone());
    let error = adapter.reconcile(&request, &authority).await.unwrap_err();
    let sqlserver_replicated::adapter::AdapterError::Observation { replica, failure } = error
    else {
        panic!("expected the original observation failure")
    };
    assert_eq!(replica, authority.primary);
    assert_eq!(failure.kind, ObservationFailureKind::Unreachable);
    assert_eq!(failure.message, "adapter-owned failure");
    assert!(adapter.journal().authority().unwrap().is_none());
    assert!(
        adapter
            .journal()
            .entry(request.operation_id())
            .unwrap()
            .is_none()
    );
    assert!(state.lock().unwrap().effects.is_empty());
}

#[tokio::test]
async fn seeding_does_not_require_a_third_node_observation() {
    let (request, authority, mut nodes) = fixtures::seed(unix_millis().unwrap());
    nodes.pop();
    let directory = tempfile::tempdir().unwrap();
    let state = state(nodes);
    let mut adapter = enabled(&directory.path().join("journal"), &authority, state);
    assert!(matches!(
        adapter.reconcile(&request, &authority).await.unwrap(),
        AdapterOutcome::Prepared(NativeAction::GrantSeeding { .. })
    ));
}
