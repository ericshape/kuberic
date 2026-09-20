use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::adapter::AgAdapter;
use crate::convergence::AcceptedAuthority;
use crate::fence::{FenceProvider, RemovedIncarnation};
use crate::ha::{
    FenceEvidence, HaAction, HaContext, HaDecision, HaNode, HaPolicy, HaPostcondition,
};
use crate::ha_native::{
    HaBackend, HaPermit, LeaseSpec, action_digest, drain_digest, policy_binding, transition_parts,
};
use crate::ha_store::{
    self, ActiveAuthority, CHECKPOINT, ControlState, JournalAuthorityOracle, LeaseRecord,
    PendingTransition,
};
use crate::instance::unix_millis;
use crate::journal::{JournalError, OperationJournal, Registration, TransitionCommit};
use crate::mutation::AgBackend;
use crate::proof::{
    AuthorityOracle, ProofBundle, ProofClaim, ProofClaims, ProofError, ProofKind, ProofReplica,
    ProofScope, ProofSigner, ProofVerifier, SignedAuthorizationVerifier, SignedProof,
};
use crate::runtime_error::RuntimeError;
use crate::{
    AvailabilityGroupIdentity, ContractError, DecimalProgress, DestructiveApproval, FenceReference,
    Guid, MutationMode, NativeRole, Observation, OperationEnvelope, OperationPayload,
    OperationRequest, ReplicaIdentity,
};

const PROOF_TTL_MILLIS: u64 = 120_000;

/// Construct the stage-3 adapter with real signature/current-authority checks.
/// Only the initial bootstrap may establish an empty journal's authority;
/// changing an established authority is reserved for a fenced HA commit.
pub fn authenticated_ag_adapter<B>(
    mut journal: OperationJournal,
    backend: B,
    authority: &AcceptedAuthority,
    envelope: &OperationEnvelope,
    bundle: ProofBundle,
    verifier: ProofVerifier,
    mode: MutationMode,
) -> Result<AgAdapter<B, SignedAuthorizationVerifier>, HaError>
where
    B: AgBackend,
{
    authority.validate_for(envelope)?;
    let binding = authority_binding(authority);
    verifier.verify_operation(envelope, binding, &bundle, unix_millis()?)?;
    if ha_store::load(&journal)?.is_some_and(|state| state.pending.is_some()) {
        return Err(HaError::InvalidState);
    }
    match journal.authority()? {
        None if matches!(
            envelope.request().payload(),
            OperationPayload::EnsureAvailabilityGroup { .. }
        ) =>
        {
            if mode == MutationMode::Enabled {
                journal.accept_authority(
                    authority.configuration_id.as_str(),
                    authority.epoch,
                    &binding,
                )?;
            }
        }
        Some(current)
            if current.configuration_id == authority.configuration_id.as_str()
                && current.epoch == authority.epoch
                && current.binding == binding => {}
        _ => return Err(HaError::InvalidState),
    }
    let oracle = Arc::new(JournalAuthorityOracle::new(
        journal.path().to_owned(),
        journal.resource_id().to_owned(),
    ));
    let signed = SignedAuthorizationVerifier::new(verifier, bundle, oracle);
    Ok(AgAdapter::new(journal, backend)
        .with_verifier(signed)
        .with_mode(mode))
}

#[derive(Debug)]
pub enum HaError {
    Contract(ContractError),
    Journal(JournalError),
    Proof(ProofError),
    Runtime(RuntimeError),
    InvalidState,
    ObserveOnly,
}

impl fmt::Display for HaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(value) => value.fmt(f),
            Self::Journal(value) => value.fmt(f),
            Self::Proof(value) => value.fmt(f),
            Self::Runtime(value) => value.fmt(f),
            Self::InvalidState => f.write_str("invalid or incompatible HA controller state"),
            Self::ObserveOnly => {
                f.write_str("HA controller is observe-only; no native effect authorized")
            }
        }
    }
}
impl Error for HaError {}
impl From<ContractError> for HaError {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}
impl From<JournalError> for HaError {
    fn from(value: JournalError) -> Self {
        Self::Journal(value)
    }
}
impl From<ProofError> for HaError {
    fn from(value: ProofError) -> Self {
        Self::Proof(value)
    }
}
impl From<RuntimeError> for HaError {
    fn from(value: RuntimeError) -> Self {
        Self::Runtime(value)
    }
}

pub struct HaIssuers {
    pub fence: ProofSigner,
    pub lease: ProofSigner,
}

pub struct FencedCommand {
    pub envelope: OperationEnvelope,
    pub proofs: ProofBundle,
}

pub enum FenceProgress {
    Prepared,
    Drained,
    Ready(Box<FencedCommand>),
}

#[derive(Debug)]
pub enum HaOutcome {
    Proposed(HaAction),
    Prepared(HaAction),
    Dispatched(HaAction),
    Wait(&'static str),
    Unsafe(&'static str),
    Complete { result: Vec<u8>, replayed: bool },
}

pub struct HaController<B, F> {
    journal: OperationJournal,
    backend: B,
    infrastructure: F,
    verifier: ProofVerifier,
    issuers: HaIssuers,
    policy: HaPolicy,
    mode: MutationMode,
}

impl<B: HaBackend, F: FenceProvider> HaController<B, F> {
    pub fn new(
        journal: OperationJournal,
        backend: B,
        infrastructure: F,
        verifier: ProofVerifier,
        issuers: HaIssuers,
        policy: HaPolicy,
    ) -> Result<Self, HaError> {
        policy.validate()?;
        if issuers.fence.kind() != ProofKind::Fence || issuers.lease.kind() != ProofKind::Lease {
            return Err(HaError::InvalidState);
        }
        ha_store::load(&journal)?;
        Ok(Self {
            journal,
            backend,
            infrastructure,
            verifier,
            issuers,
            policy,
            mode: MutationMode::ObserveOnly,
        })
    }

    pub fn with_mode(mut self, mode: MutationMode) -> Self {
        self.mode = mode;
        self
    }
    pub fn journal(&self) -> &OperationJournal {
        &self.journal
    }

    fn oracle(&self) -> JournalAuthorityOracle {
        JournalAuthorityOracle::new(
            self.journal.path().to_owned(),
            self.journal.resource_id().to_owned(),
        )
    }

    /// Explicitly adopt an already-observed native AG under a signed, GUID-bound
    /// bootstrap request. This does not create or silently migrate an AG.
    pub async fn adopt(
        &mut self,
        envelope: &OperationEnvelope,
        authority: &AcceptedAuthority,
        bundle: &ProofBundle,
    ) -> Result<(), HaError> {
        self.require_enabled()?;
        authority.validate_for(envelope)?;
        let OperationPayload::EnsureAvailabilityGroup {
            name,
            expected_group_id: Some(id),
            database_name,
            ..
        } = envelope.request().payload()
        else {
            return Err(HaError::InvalidState);
        };
        let binding = authority_binding(authority);
        let authorization =
            self.verifier
                .verify_operation(envelope, binding, bundle, unix_millis()?)?;
        if let Some(current) = self.journal.authority()? {
            if current.configuration_id != authority.configuration_id.as_str()
                || current.epoch != authority.epoch
                || current.binding != binding
            {
                return Err(HaError::InvalidState);
            }
        }
        if ha_store::load(&self.journal)?.is_some_and(|state| state.pending.is_some()) {
            return Err(HaError::InvalidState);
        }
        let group = AvailabilityGroupIdentity {
            name: name.clone(),
            group_id: id.clone(),
        };
        let nodes = self
            .backend
            .observe_current(authority, &group, &self.policy)
            .await?;
        let node = eligible_node(&nodes, &authority.primary, unix_millis()?, &self.policy)?;
        let (snapshot, native) = native_group(node)?;
        if native.identity != group
            || native.local_replica.role != Some(NativeRole::Primary)
            || native.databases.len() != 1
            || native.databases[0].identity.name != *database_name
        {
            return Err(HaError::InvalidState);
        }
        if native.replicas.len() != authority.replicas.len()
            || !authority.replicas.iter().all(|member| {
                native.replicas.iter().any(|replica| {
                    replica.server_name == member.server_name
                        && replica.endpoint_url.as_ref().is_some_and(|endpoint| {
                            endpoint.eq_ignore_ascii_case(&member.endpoint.to_string())
                        })
                        && replica.availability_mode == "SYNCHRONOUS_COMMIT"
                        && replica.failover_mode == "EXTERNAL"
                        && replica.seeding_mode == "AUTOMATIC"
                })
            })
        {
            return Err(HaError::InvalidState);
        }
        let active = ActiveAuthority {
            configuration_id: authority.configuration_id.to_string(),
            epoch: authority.epoch,
            binding,
            primary: ProofReplica::from_identity(&native.local_replica.identity)?,
            group_name: name.to_string(),
            group_id: id.to_string(),
            database_name: database_name.to_string(),
            group_database_id: native.databases[0].identity.group_database_id.to_string(),
        };
        let prior = ha_store::load(&self.journal)?;
        if prior.as_ref().is_some_and(|state| {
            state.active.primary != active.primary || state.active.group_id != active.group_id
        }) {
            return Err(HaError::InvalidState);
        }
        let start = snapshot.instance.sqlserver_start_time.clone();
        self.verifier
            .verify_operation(envelope, binding, bundle, unix_millis()?)?;
        self.journal.accept_authority(
            authority.configuration_id.as_str(),
            authority.epoch,
            &binding,
        )?;
        let state = ControlState {
            version: 1,
            resource_id: authority.resource_id.to_string(),
            active,
            pending: None,
            last_lease: prior.as_ref().and_then(|state| state.last_lease.clone()),
            proof_counter: prior.map_or(0, |state| state.proof_counter),
        };
        ha_store::save(&mut self.journal, &state)?;
        self.renew_for(
            &state.active.clone(),
            start,
            false,
            Some(authorization.expires_at_unix_millis()),
        )
        .await?;
        Ok(())
    }

    /// Prepare before effect, then drain a planned source, capture its final
    /// committed record, and permanently remove the exact old incarnation.
    pub async fn prepare_fence(
        &mut self,
        request: &OperationRequest,
        context: &HaContext,
        authority_proof: &SignedProof,
        approval: Option<&SignedProof>,
    ) -> Result<FenceProgress, HaError> {
        self.require_enabled()?;
        context.validate(request)?;
        let scope = ProofScope::for_operation(request, policy_binding(context, &self.policy));
        let authorized = self.verifier.verify(
            authority_proof,
            &scope,
            ProofKind::Authority,
            unix_millis()?,
        )?;
        let deadline = authorized.claims().expires_at_unix_millis;
        verify_loss_approval(&self.verifier, request, &scope, approval, unix_millis()?)?;
        let mut state = self.state()?;
        if let Some(active_operation) = self.journal.pending_entry()? {
            if active_operation.envelope.operation_id() != request.operation_id()
                || active_operation.envelope.input_signature() != request.input_signature()
            {
                return Err(JournalError::OperationInProgress.into());
            }
        }
        let (group, lineage, source, target) = transition_parts(request)?;
        if state.active.binding != authority_binding(&context.source)
            || state.active.primary.to_identity()? != *source
            || state.active.group_id != group.group_id.as_str()
            || state.active.group_database_id != lineage.database.group_database_id.as_str()
        {
            return Err(HaError::InvalidState);
        }
        if let Some(pending) = &state.pending {
            if pending.scope != scope {
                return Err(HaError::InvalidState);
            }
        } else {
            let nodes = self.backend.observe(request, context, &self.policy).await?;
            preflight(request, context, &nodes, &self.policy)?;
            state.pending = Some(PendingTransition {
                scope: scope.clone(),
                target_authority: ActiveAuthority {
                    configuration_id: context.target.configuration_id.to_string(),
                    epoch: context.target.epoch,
                    binding: authority_binding(&context.target),
                    primary: ProofReplica::from_identity(target)?,
                    group_name: group.name.to_string(),
                    group_id: group.group_id.to_string(),
                    database_name: lineage.database.name.to_string(),
                    group_database_id: lineage.database.group_database_id.to_string(),
                },
                source: ProofReplica::from_identity(source)?,
                target: ProofReplica::from_identity(target)?,
                drain_prepared: false,
                drain_acknowledged: false,
                final_committed_record: None,
                fence_prepared: false,
                fence: None,
                promotion_intent_key: None,
            });
            ha_store::save(&mut self.journal, &state)?;
            return Ok(FenceProgress::Prepared);
        }
        if matches!(
            request.payload(),
            OperationPayload::PlannedSwitchover { .. }
        ) {
            if !state
                .pending
                .as_ref()
                .ok_or(HaError::InvalidState)?
                .drain_prepared
            {
                state
                    .pending
                    .as_mut()
                    .ok_or(HaError::InvalidState)?
                    .drain_prepared = true;
                ha_store::save(&mut self.journal, &state)?;
                return Ok(FenceProgress::Prepared);
            }
            if !state
                .pending
                .as_ref()
                .ok_or(HaError::InvalidState)?
                .drain_acknowledged
            {
                self.oracle().check(&scope, &ProofClaim::Authority)?;
                let permit = HaPermit::new(
                    policy_binding(context, &self.policy),
                    drain_digest(request),
                    deadline,
                );
                self.backend
                    .drain(request, context, &self.policy, &permit)
                    .await?;
                state
                    .pending
                    .as_mut()
                    .ok_or(HaError::InvalidState)?
                    .drain_acknowledged = true;
                ha_store::save(&mut self.journal, &state)?;
                return Ok(FenceProgress::Drained);
            }
            if state
                .pending
                .as_ref()
                .ok_or(HaError::InvalidState)?
                .final_committed_record
                .is_none()
            {
                let final_record = self
                    .backend
                    .drained_commit(request, context, &self.policy)
                    .await?;
                state
                    .pending
                    .as_mut()
                    .ok_or(HaError::InvalidState)?
                    .final_committed_record = Some(final_record.to_string());
                ha_store::save(&mut self.journal, &state)?;
            }
        }
        if !state
            .pending
            .as_ref()
            .ok_or(HaError::InvalidState)?
            .fence_prepared
        {
            state
                .pending
                .as_mut()
                .ok_or(HaError::InvalidState)?
                .fence_prepared = true;
            ha_store::save(&mut self.journal, &state)?;
            return Ok(FenceProgress::Prepared);
        }
        // Removal is retryable and retains volumes. Every attempt requires fresh
        // authorization; an inspection failure cannot become a fencing receipt.
        let current_authority = self.verifier.verify(
            authority_proof,
            &scope,
            ProofKind::Authority,
            unix_millis()?,
        )?;
        let approval_expiry =
            verify_loss_approval(&self.verifier, request, &scope, approval, unix_millis()?)?;
        self.oracle().check(&scope, &ProofClaim::Authority)?;
        let fence_deadline = current_authority
            .claims()
            .expires_at_unix_millis
            .min(approval_expiry);
        let remaining = fence_deadline
            .checked_sub(unix_millis()?)
            .filter(|remaining| *remaining > 0)
            .ok_or(HaError::InvalidState)?;
        let removed = tokio::time::timeout(
            Duration::from_millis(remaining),
            self.infrastructure.remove(source),
        )
        .await
        .map_err(|_| {
            RuntimeError::new(
                crate::ObservationFailureKind::TimedOut,
                "HA fence",
                "fence outcome is uncertain after authorization expired",
            )
        })??;
        let now = unix_millis()?;
        self.verifier
            .verify(authority_proof, &scope, ProofKind::Authority, now)?;
        verify_loss_approval(&self.verifier, request, &scope, approval, now)?;
        let proof_id = state.next_proof_id("fence")?;
        let issuer = self.issuers.fence.issuer_id().to_owned();
        let final_record = state
            .pending
            .as_ref()
            .ok_or(HaError::InvalidState)?
            .final_committed_record
            .clone();
        let claims = ProofClaims {
            version: 1,
            proof_id: proof_id.clone(),
            issuer_id: issuer.clone(),
            issued_at_unix_millis: now,
            not_before_unix_millis: now,
            expires_at_unix_millis: now
                .checked_add(PROOF_TTL_MILLIS)
                .ok_or(HaError::InvalidState)?,
            scope: scope.clone(),
            claim: ProofClaim::Fence {
                provider: issuer.clone(),
                replica: ProofReplica::from_identity(source)?,
                engine_id: removed.engine_id,
                container_id: removed.container_id,
                removed_at_unix_millis: removed.removed_at_unix_millis,
                final_committed_record: final_record,
            },
        };
        let signed = self.issuers.fence.sign(claims)?;
        self.verifier
            .verify(&signed, &scope, ProofKind::Fence, now)?;
        state.pending.as_mut().ok_or(HaError::InvalidState)?.fence = Some(signed.encode()?);
        ha_store::save(&mut self.journal, &state)?;
        let destructive = approval
            .map(|proof| {
                let verified = self
                    .verifier
                    .verify(proof, &scope, ProofKind::Approval, now)?;
                DestructiveApproval::new(
                    verified.claims().proof_id.clone(),
                    request.operation_id(),
                    request.input_signature(),
                )
                .map_err(HaError::from)
            })
            .transpose()?;
        let reference = FenceReference::new(
            issuer,
            proof_id,
            request.operation_id(),
            request.input_signature(),
            source.clone(),
        )?;
        let envelope = OperationEnvelope::new(request.clone(), destructive, Some(reference))?;
        let bundle = ProofBundle {
            authority: authority_proof.clone(),
            approval: approval.cloned(),
            fence: Some(signed),
        };
        self.verifier
            .verify_operation(&envelope, scope.authority_binding, &bundle, now)?;
        Ok(FenceProgress::Ready(Box::new(FencedCommand {
            envelope,
            proofs: bundle,
        })))
    }

    pub async fn reconcile(
        &mut self,
        envelope: &OperationEnvelope,
        context: &HaContext,
        bundle: &ProofBundle,
    ) -> Result<HaOutcome, HaError> {
        context.validate(envelope.request())?;
        envelope.validate()?;
        let binding = policy_binding(context, &self.policy);
        let known = self.journal.lookup(envelope)?;
        if let Some(entry) = &known {
            if entry.envelope.operation_id() == envelope.operation_id() {
                if let Some(result) = &entry.terminal_result {
                    validate_result(result, context, envelope)?;
                    return Ok(HaOutcome::Complete {
                        result: result.clone(),
                        replayed: true,
                    });
                }
            } else {
                return Ok(HaOutcome::Unsafe(
                    "HA transitions require their exact retained operation ID",
                ));
            }
        }
        let state = self.state()?;
        let pending = state.pending.as_ref().ok_or(HaError::InvalidState)?;
        let scope = ProofScope::for_operation(envelope.request(), binding);
        if pending.scope != scope {
            return Err(HaError::InvalidState);
        }
        let verified = self
            .verifier
            .verify_operation(envelope, binding, bundle, unix_millis()?)?;
        self.oracle().check(&scope, &ProofClaim::Authority)?;
        let fence = self.verified_fence(envelope, context, bundle).await?;
        let nodes = self
            .backend
            .observe(envelope.request(), context, &self.policy)
            .await?;
        let acknowledged = known
            .as_ref()
            .map(|entry| {
                entry
                    .acknowledged_action_keys()
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let promotion_prepared = pending.promotion_intent_key.as_ref().is_some_and(|key| {
            known
                .as_ref()
                .is_some_and(|entry| entry.actions.iter().any(|action| &action.action_key == key))
        });
        let decision = crate::ha::plan(
            envelope,
            context,
            &nodes,
            &fence,
            &acknowledged,
            promotion_prepared,
            unix_millis()?,
            &self.policy,
        );
        // Preserve the provisional target's lease during native recovery and
        // secondary resets, but never renew without a fresh two-node quorum.
        if promotion_prepared
            && self.mode == MutationMode::Enabled
            && matches!(&decision, HaDecision::Wait(_))
            && candidate_primary_ready(&nodes, context, unix_millis()?, &self.policy)
        {
            let candidate = eligible_node(
                &nodes,
                &pending.target.to_identity()?,
                unix_millis()?,
                &self.policy,
            )?;
            let (snapshot, _) = native_group(candidate)?;
            self.renew_for(
                &pending.target_authority.clone(),
                snapshot.instance.sqlserver_start_time.clone(),
                true,
                Some(verified.expires_at_unix_millis()),
            )
            .await?;
        }
        match decision {
            HaDecision::Wait(reason) => Ok(HaOutcome::Wait(reason)),
            HaDecision::Unsafe(reason) => Ok(HaOutcome::Unsafe(reason)),
            HaDecision::Execute(action) => {
                if self.mode == MutationMode::ObserveOnly {
                    return Ok(HaOutcome::Proposed(action));
                }
                self.verifier
                    .verify_operation(envelope, binding, bundle, unix_millis()?)?;
                self.oracle().check(&scope, &ProofClaim::Authority)?;
                let bytes = serde_json::to_vec(&action).map_err(|_| HaError::InvalidState)?;
                let prior = known.as_ref().and_then(|entry| {
                    entry
                        .actions
                        .iter()
                        .find(|intent| intent.action_key == action.key())
                });
                if prior.is_some_and(|intent| intent.action_payload != bytes) {
                    return Err(JournalError::ActionConflict.into());
                }
                match self.journal.register(envelope)? {
                    Registration::New | Registration::Pending => {}
                    _ => return Err(HaError::InvalidState),
                }
                if prior.is_none() {
                    self.journal
                        .persist_intent(envelope.operation_id(), &action.key(), &bytes)?;
                    if matches!(action, HaAction::Promote { .. }) {
                        let mut current = self.state()?;
                        current
                            .pending
                            .as_mut()
                            .ok_or(HaError::InvalidState)?
                            .promotion_intent_key = Some(action.key());
                        ha_store::save(&mut self.journal, &current)?;
                    }
                    return Ok(HaOutcome::Prepared(action));
                }
                if matches!(action, HaAction::Promote { .. }) && !promotion_prepared {
                    let mut current = self.state()?;
                    current
                        .pending
                        .as_mut()
                        .ok_or(HaError::InvalidState)?
                        .promotion_intent_key = Some(action.key());
                    ha_store::save(&mut self.journal, &current)?;
                }
                let target_node = eligible_node(
                    &nodes,
                    &pending.target.to_identity()?,
                    unix_millis()?,
                    &self.policy,
                )?;
                let (target_snapshot, _) = native_group(target_node)?;
                let lease_expiry = self
                    .renew_for(
                        &pending.target_authority.clone(),
                        target_snapshot.instance.sqlserver_start_time.clone(),
                        true,
                        Some(verified.expires_at_unix_millis()),
                    )
                    .await?;
                let current_fence = self.verified_fence(envelope, context, bundle).await?;
                let expiry = self
                    .verifier
                    .verify_operation(envelope, binding, bundle, unix_millis()?)?
                    .expires_at_unix_millis();
                match crate::ha::plan(
                    envelope,
                    context,
                    &nodes,
                    &current_fence,
                    &acknowledged,
                    promotion_prepared || matches!(action, HaAction::Promote { .. }),
                    unix_millis()?,
                    &self.policy,
                ) {
                    HaDecision::Execute(current) if current == action => {}
                    HaDecision::Wait(reason) => return Ok(HaOutcome::Wait(reason)),
                    HaDecision::Unsafe(reason) => return Ok(HaOutcome::Unsafe(reason)),
                    _ => {
                        return Ok(HaOutcome::Unsafe(
                            "HA action changed while validating its execution authority",
                        ));
                    }
                }
                let dispatch_deadline = evidence_deadline(&nodes, context, &self.policy)?;
                let permit = HaPermit::new(
                    binding,
                    action_digest(&action),
                    expiry
                        .min(verified.expires_at_unix_millis())
                        .min(lease_expiry),
                )
                .with_dispatch_deadline(dispatch_deadline);
                self.backend
                    .execute(envelope, context, &action, &self.policy, &permit)
                    .await?;
                self.journal
                    .acknowledge_action(envelope.operation_id(), &action.key())?;
                Ok(HaOutcome::Dispatched(action))
            }
            HaDecision::Complete(postcondition) => {
                self.require_enabled()?;
                let target_node = eligible_node(
                    &nodes,
                    &pending.target.to_identity()?,
                    unix_millis()?,
                    &self.policy,
                )?;
                let (target_snapshot, _) = native_group(target_node)?;
                self.renew_for(
                    &pending.target_authority.clone(),
                    target_snapshot.instance.sqlserver_start_time.clone(),
                    false,
                    Some(verified.expires_at_unix_millis()),
                )
                .await?;
                let current_fence = self.verified_fence(envelope, context, bundle).await?;
                self.verifier
                    .verify_operation(envelope, binding, bundle, unix_millis()?)?;
                self.oracle().check(&scope, &ProofClaim::Authority)?;
                match crate::ha::plan(
                    envelope,
                    context,
                    &nodes,
                    &current_fence,
                    &acknowledged,
                    promotion_prepared,
                    unix_millis()?,
                    &self.policy,
                ) {
                    HaDecision::Complete(current) if current == postcondition => {}
                    HaDecision::Wait(reason) => return Ok(HaOutcome::Wait(reason)),
                    HaDecision::Unsafe(reason) => return Ok(HaOutcome::Unsafe(reason)),
                    _ => {
                        return Ok(HaOutcome::Unsafe(
                            "native completion evidence changed before authority commit",
                        ));
                    }
                }
                let result = result_bytes(&postcondition, context, envelope)?;
                let mut current = self.state()?;
                current.active = current
                    .pending
                    .as_ref()
                    .ok_or(HaError::InvalidState)?
                    .target_authority
                    .clone();
                current.pending = None;
                let commit = TransitionCommit {
                    configuration_id: context.target.configuration_id.to_string(),
                    epoch: context.target.epoch,
                    binding: authority_binding(&context.target).to_vec(),
                    checkpoint_name: CHECKPOINT.to_owned(),
                    checkpoint: current.encode()?,
                };
                self.journal
                    .finish_transition(envelope.operation_id(), &result, &commit)?;
                Ok(HaOutcome::Complete {
                    result,
                    replayed: false,
                })
            }
        }
    }

    pub async fn renew_primary(&mut self, authority: &AcceptedAuthority) -> Result<u64, HaError> {
        self.require_enabled()?;
        let state = self.state()?;
        if state.pending.is_some() || state.active.binding != authority_binding(authority) {
            return Err(HaError::InvalidState);
        }
        let group = active_group(&state.active)?;
        let nodes = self
            .backend
            .observe_current(authority, &group, &self.policy)
            .await?;
        let primary = state.active.primary.to_identity()?;
        let node = eligible_node(&nodes, &primary, unix_millis()?, &self.policy)?;
        let (snapshot, native) = native_group(node)?;
        if native.identity != group
            || native.local_replica.identity != primary
            || native.local_replica.role != Some(NativeRole::Primary)
        {
            return Err(HaError::InvalidState);
        }
        self.renew_for(
            &state.active,
            snapshot.instance.sqlserver_start_time.clone(),
            false,
            None,
        )
        .await
    }

    pub async fn run_lease_keeper(
        &mut self,
        authority: &AcceptedAuthority,
        cancellation: CancellationToken,
    ) -> Result<(), HaError> {
        loop {
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Ok(()),
                result = self.renew_primary(authority) => { result?; }
            }
            tokio::select! {
                biased;
                _ = cancellation.cancelled() => return Ok(()),
                _ = tokio::time::sleep(Duration::from_millis(self.policy.renewal_interval_millis)) => {}
            }
        }
    }

    async fn renew_for(
        &mut self,
        owner: &ActiveAuthority,
        start: String,
        candidate: bool,
        authority_expiry: Option<u64>,
    ) -> Result<u64, HaError> {
        self.require_enabled()?;
        let mut state = self.state()?;
        let primary = owner.primary.to_identity()?;
        let lease = LeaseSpec {
            resource_id: state.resource_id.clone(),
            configuration_id: owner.configuration_id.clone(),
            epoch: owner.epoch,
            authority_binding: owner.binding,
            availability_group: active_group(owner)?,
            primary,
            sql_start_time: start,
            lease_seconds: self.policy.lease_seconds,
            candidate,
        };
        let now = unix_millis()?;
        let expires_at = now
            .checked_add(PROOF_TTL_MILLIS)
            .ok_or(HaError::InvalidState)?
            .min(authority_expiry.unwrap_or(u64::MAX));
        if now
            .saturating_add(u64::from(self.policy.lease_seconds) * 1000)
            .saturating_add(self.policy.max_clock_skew_millis)
            .saturating_add(self.policy.command_timeout_millis)
            >= expires_at
        {
            return Err(HaError::InvalidState);
        }
        let scope = ProofScope {
            resource_id: state.resource_id.clone(),
            operation_id: format!("lease-{}", owner.epoch),
            input_signature: lease.digest(),
            authority_binding: owner.binding,
            source_configuration_id: owner.configuration_id.clone(),
            source_epoch: owner.epoch,
            target_epoch: owner.epoch,
        };
        let claims = ProofClaims {
            version: 1,
            proof_id: state.next_proof_id("lease")?,
            issuer_id: self.issuers.lease.issuer_id().to_owned(),
            issued_at_unix_millis: now,
            not_before_unix_millis: now,
            expires_at_unix_millis: expires_at,
            scope: scope.clone(),
            claim: ProofClaim::Lease {
                group_name: owner.group_name.clone(),
                group_id: owner.group_id.clone(),
                primary: owner.primary.clone(),
                sql_start_time: lease.sql_start_time.clone(),
                lease_seconds: lease.lease_seconds,
            },
        };
        self.oracle().check(&scope, &claims.claim)?;
        let proof = self.issuers.lease.sign(claims)?;
        let verified = self
            .verifier
            .verify(&proof, &scope, ProofKind::Lease, now)?;
        let expires = verified.claims().expires_at_unix_millis;
        state.last_lease = Some(LeaseRecord {
            owner: owner.primary.clone(),
            configuration_id: owner.configuration_id.clone(),
            epoch: owner.epoch,
            authorization_expires_at: expires,
            attempted_at: now,
            acknowledged: false,
        });
        ha_store::save(&mut self.journal, &state)?;
        let permit = HaPermit::new(owner.binding, lease.digest(), expires);
        let bound = self.backend.renew(&lease, &self.policy, &permit).await?;
        if bound > expires {
            return Err(HaError::InvalidState);
        }
        state
            .last_lease
            .as_mut()
            .ok_or(HaError::InvalidState)?
            .acknowledged = true;
        ha_store::save(&mut self.journal, &state)?;
        Ok(bound)
    }

    async fn verified_fence(
        &self,
        envelope: &OperationEnvelope,
        context: &HaContext,
        bundle: &ProofBundle,
    ) -> Result<FenceEvidence, HaError> {
        let scope =
            ProofScope::for_operation(envelope.request(), policy_binding(context, &self.policy));
        let proof = bundle.fence.as_ref().ok_or(HaError::InvalidState)?;
        let verified = self
            .verifier
            .verify(proof, &scope, ProofKind::Fence, unix_millis()?)?;
        let claims = verified.claims();
        let ProofClaim::Fence {
            replica,
            engine_id,
            container_id,
            removed_at_unix_millis,
            final_committed_record,
            ..
        } = &claims.claim
        else {
            return Err(HaError::InvalidState);
        };
        let removed = RemovedIncarnation {
            source: replica.to_identity()?,
            engine_id: engine_id.clone(),
            container_id: container_id.clone(),
            removed_at_unix_millis: *removed_at_unix_millis,
        };
        self.infrastructure.verify(&removed).await?;
        Ok(FenceEvidence {
            source: removed.source,
            proof_id: claims.proof_id.clone(),
            fenced_at_unix_millis: *removed_at_unix_millis,
            expires_at_unix_millis: claims.expires_at_unix_millis,
            final_committed_record: final_committed_record
                .as_deref()
                .map(DecimalProgress::parse)
                .transpose()?,
        })
    }

    fn require_enabled(&self) -> Result<(), HaError> {
        if self.mode != MutationMode::Enabled {
            Err(HaError::ObserveOnly)
        } else {
            Ok(())
        }
    }

    fn state(&self) -> Result<ControlState, HaError> {
        ha_store::load(&self.journal)?.ok_or(HaError::InvalidState)
    }

    pub fn authority_oracle(&self) -> Arc<JournalAuthorityOracle> {
        Arc::new(self.oracle())
    }
}

fn authority_binding(authority: &AcceptedAuthority) -> [u8; 32] {
    Sha256::digest(authority.canonical_binding()).into()
}

fn active_group(active: &ActiveAuthority) -> Result<AvailabilityGroupIdentity, HaError> {
    Ok(AvailabilityGroupIdentity {
        name: crate::AvailabilityGroupName::new(&active.group_name)?,
        group_id: Guid::parse("active group", &active.group_id)?,
    })
}

fn verify_loss_approval(
    verifier: &ProofVerifier,
    request: &OperationRequest,
    scope: &ProofScope,
    proof: Option<&SignedProof>,
    now: u64,
) -> Result<u64, HaError> {
    match request.payload() {
        OperationPayload::ForcedFailover {
            last_known_commit, ..
        } => {
            let verified = verifier.verify(
                proof.ok_or(HaError::InvalidState)?,
                scope,
                ProofKind::Approval,
                now,
            )?;
            match &verified.claims().claim {
                ProofClaim::Approval {
                    allow_data_loss: true,
                    allow_unknown_data_loss,
                } if last_known_commit.is_some() || *allow_unknown_data_loss => {
                    Ok(verified.claims().expires_at_unix_millis)
                }
                _ => Err(HaError::InvalidState),
            }
        }
        OperationPayload::PlannedSwitchover { .. } if proof.is_none() => Ok(u64::MAX),
        _ => Err(HaError::InvalidState),
    }
}

fn eligible_node<'a>(
    nodes: &'a [HaNode],
    identity: &ReplicaIdentity,
    now: u64,
    policy: &HaPolicy,
) -> Result<&'a HaNode, HaError> {
    let node = nodes
        .iter()
        .find(|node| {
            node.node.identity.logical_id() == identity.logical_id()
                && node.node.identity.incarnation() == identity.incarnation()
        })
        .ok_or(HaError::InvalidState)?;
    if !node.node.instance.is_fresh_at(now, policy.max_age_millis)
        || !node.health.is_fresh_at(now, policy.max_age_millis)
    {
        return Err(HaError::InvalidState);
    }
    let Observation::Present {
        value: health,
        observed_at_unix_millis,
    } = &node.health
    else {
        return Err(HaError::InvalidState);
    };
    if health.sql_utc_millis.abs_diff(*observed_at_unix_millis) > policy.max_clock_skew_millis
        || !health.db_failover
        || health
            .configuration_commit_age_millis
            .is_some_and(|age| age >= policy.configuration_commit_timeout_millis)
        || [health.system, health.resource, health.query_processing]
            .iter()
            .any(|state| !(1..=3).contains(state))
        || health.system == 3
        || (policy.health_threshold >= 4 && health.resource == 3)
        || (policy.health_threshold >= 5 && health.query_processing == 3)
    {
        return Err(HaError::InvalidState);
    }
    Ok(node)
}

fn native_group(
    node: &HaNode,
) -> Result<
    (
        &crate::observation::InstanceSnapshot,
        &crate::observation::AvailabilityGroupSnapshot,
    ),
    HaError,
> {
    let Observation::Present {
        value: snapshot, ..
    } = &node.node.instance
    else {
        return Err(HaError::InvalidState);
    };
    let Observation::Present { value: group, .. } = &snapshot.availability_group else {
        return Err(HaError::InvalidState);
    };
    Ok((snapshot, group))
}

fn candidate_primary_ready(
    nodes: &[HaNode],
    context: &HaContext,
    now: u64,
    policy: &HaPolicy,
) -> bool {
    let Ok(candidate) = eligible_node(nodes, &context.target.primary, now, policy) else {
        return false;
    };
    let Ok((_, group)) = native_group(candidate) else {
        return false;
    };
    if group.local_replica.role != Some(NativeRole::Primary)
        || group.configuration_sequence.value() == 0
    {
        return false;
    }
    nodes
        .iter()
        .filter(|node| {
            node.node.identity.logical_id() != context.source.primary.logical_id()
                && node.node.identity.logical_id() != context.target.primary.logical_id()
        })
        .any(|node| {
            eligible_node(nodes, &node.node.identity, now, policy).is_ok()
                && native_group(node).is_ok_and(|(_, witness)| {
                    witness.identity == group.identity
                        && witness.configuration_sequence.value() > 0
                        && witness.configuration_sequence <= group.configuration_sequence
                        && matches!(
                            witness.local_replica.role,
                            Some(NativeRole::Secondary | NativeRole::Resolving)
                        )
                })
        })
}

fn evidence_deadline(
    nodes: &[HaNode],
    context: &HaContext,
    policy: &HaPolicy,
) -> Result<u64, HaError> {
    let now = unix_millis()?;
    let mut deadline = u64::MAX;
    for node in nodes
        .iter()
        .filter(|node| node.node.identity.logical_id() != context.source.primary.logical_id())
    {
        for timestamp in [
            node.node.instance.observed_at_unix_millis(),
            node.health.observed_at_unix_millis(),
        ] {
            if timestamp > now {
                return Err(HaError::InvalidState);
            }
            deadline = deadline.min(
                timestamp
                    .checked_add(policy.max_age_millis)
                    .ok_or(HaError::InvalidState)?,
            );
        }
        if node.node.identity.logical_id() == context.target.primary.logical_id() {
            deadline = deadline.min(
                node.node
                    .database
                    .observed_at_unix_millis()
                    .checked_add(policy.max_age_millis)
                    .ok_or(HaError::InvalidState)?,
            );
        }
    }
    if deadline == u64::MAX || deadline <= now {
        return Err(HaError::InvalidState);
    }
    Ok(deadline)
}

fn preflight(
    request: &OperationRequest,
    context: &HaContext,
    nodes: &[HaNode],
    policy: &HaPolicy,
) -> Result<(), HaError> {
    let mut identities = BTreeSet::new();
    for node in nodes {
        if !identities.insert(node.node.identity.logical_id())
            || !context.source.replicas.iter().any(|member| {
                member.identity == node.node.identity
                    && member.server_name == node.node.server_name
                    && member.endpoint == node.node.endpoint
            })
        {
            return Err(HaError::InvalidState);
        }
    }
    let (group, lineage, source, target) = transition_parts(request)?;
    let now = unix_millis()?;
    let target_node = eligible_node(nodes, target, now, policy)?;
    let (_, target_group) = native_group(target_node)?;
    if target_group.identity != *group
        || target_group.local_replica.identity != *target
        || !matches!(
            target_group.local_replica.role,
            Some(NativeRole::Secondary | NativeRole::Resolving)
        )
    {
        return Err(HaError::InvalidState);
    }
    let mut votes = 0;
    let mut highest = 0;
    for node in nodes
        .iter()
        .filter(|node| node.node.identity.logical_id() != source.logical_id())
    {
        eligible_node(nodes, &node.node.identity, now, policy)?;
        let (_, observed) = native_group(node)?;
        if observed.identity != *group || observed.configuration_sequence.value() == 0 {
            return Err(HaError::InvalidState);
        }
        votes += 1;
        highest = highest.max(observed.configuration_sequence.value());
    }
    if votes < 2 || target_group.configuration_sequence.value() != highest {
        return Err(HaError::InvalidState);
    }
    let database = target_group
        .databases
        .iter()
        .find(|database| database.identity == lineage.database)
        .ok_or(HaError::InvalidState)?;
    let local = database.local.as_ref().ok_or(HaError::InvalidState)?;
    if local.state.as_deref() != Some("ONLINE")
        || local
            .recovery
            .as_ref()
            .and_then(|value| value.recovery_fork_guid.as_ref())
            != Some(&lineage.recovery_fork_id)
        || local
            .recovery
            .as_ref()
            .and_then(|value| value.database_guid.as_ref())
            .is_none()
    {
        return Err(HaError::InvalidState);
    }
    let replica = database
        .replicas
        .iter()
        .find(|replica| Some(&replica.replica_id) == target.native_replica_id())
        .ok_or(HaError::InvalidState)?;
    if replica.is_suspended != Some(false) || replica.database_state.as_deref() != Some("ONLINE") {
        return Err(HaError::InvalidState);
    }
    if let OperationPayload::PlannedSwitchover {
        commit_boundary, ..
    } = request.payload()
    {
        let source_node = eligible_node(nodes, source, now, policy)?;
        let (_, source_group) = native_group(source_node)?;
        if source_group.identity != *group
            || source_group.local_replica.identity != *source
            || source_group.local_replica.role != Some(NativeRole::Primary)
            || source_group.configuration_sequence.value() > highest
        {
            return Err(HaError::InvalidState);
        }
        let source_database = source_group
            .databases
            .iter()
            .find(|database| database.identity == lineage.database)
            .ok_or(HaError::InvalidState)?;
        if source_database.local.as_ref().and_then(|local| {
            local
                .recovery
                .as_ref()
                .and_then(|value| value.recovery_fork_guid.as_ref())
        }) != Some(&lineage.recovery_fork_id)
        {
            return Err(HaError::InvalidState);
        }
        if replica.synchronization_state.as_deref() != Some("SYNCHRONIZED")
            || replica.is_suspended != Some(false)
            || replica
                .progress
                .committed_record
                .is_none_or(|record| record < *commit_boundary)
        {
            return Err(HaError::InvalidState);
        }
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredHaResult {
    version: u16,
    operation_id: String,
    input_signature: [u8; 32],
    target_binding: [u8; 32],
    target_configuration_id: String,
    target_epoch: u64,
    native_postcondition: StoredNativeResult,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredNativeResult {
    group_name: String,
    group_id: String,
    database_name: String,
    group_database_id: String,
    recovery_fork_id: String,
    database_guid: String,
    target: ProofReplica,
}

fn result_bytes(
    postcondition: &HaPostcondition,
    context: &HaContext,
    envelope: &OperationEnvelope,
) -> Result<Vec<u8>, HaError> {
    if postcondition.target_configuration_id != context.target.configuration_id
        || postcondition.target_epoch != context.target.epoch
    {
        return Err(HaError::InvalidState);
    }
    let result = serde_json::to_vec(&StoredHaResult {
        version: 1,
        operation_id: envelope.operation_id().to_owned(),
        input_signature: *envelope.input_signature().as_bytes(),
        target_binding: authority_binding(&context.target),
        target_configuration_id: context.target.configuration_id.to_string(),
        target_epoch: context.target.epoch,
        native_postcondition: StoredNativeResult {
            group_name: postcondition.availability_group.name.to_string(),
            group_id: postcondition.availability_group.group_id.to_string(),
            database_name: postcondition.database.database.name.to_string(),
            group_database_id: postcondition
                .database
                .database
                .group_database_id
                .to_string(),
            recovery_fork_id: postcondition.database.recovery_fork_id.to_string(),
            database_guid: postcondition.database_guid.to_string(),
            target: ProofReplica::from_identity(&postcondition.target)?,
        },
    })
    .map_err(|_| HaError::InvalidState)?;
    validate_result(&result, context, envelope)?;
    Ok(result)
}

fn validate_result(
    bytes: &[u8],
    context: &HaContext,
    envelope: &OperationEnvelope,
) -> Result<(), HaError> {
    let result: StoredHaResult =
        serde_json::from_slice(bytes).map_err(|_| HaError::InvalidState)?;
    if result.version != 1
        || result.operation_id != envelope.operation_id()
        || result.input_signature != *envelope.input_signature().as_bytes()
        || result.target_binding != authority_binding(&context.target)
        || result.target_configuration_id != context.target.configuration_id.as_str()
        || result.target_epoch != context.target.epoch
    {
        return Err(HaError::InvalidState);
    }
    let (group, lineage, _, target) = transition_parts(envelope.request())?;
    let native = &result.native_postcondition;
    if native.group_name != group.name.as_str()
        || Guid::parse("retained group", &native.group_id)? != group.group_id
        || native.database_name != lineage.database.name.as_str()
        || Guid::parse("retained group database", &native.group_database_id)?
            != lineage.database.group_database_id
        || native.target.to_identity()? != *target
    {
        return Err(HaError::InvalidState);
    }
    Guid::parse("retained current recovery fork", &native.recovery_fork_id)?;
    Guid::parse("retained local database", &native.database_guid)?;
    Ok(())
}
