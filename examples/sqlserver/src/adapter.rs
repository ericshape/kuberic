use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::MutationMode;
use crate::convergence::{
    AcceptedAuthority, Decision, NativeAction, NodeEvidence, Postcondition, plan,
};
use crate::instance::unix_millis;
use crate::journal::{
    JournalEntry, JournalError, MAX_RESULT_BYTES, OperationJournal, Registration,
};
use crate::mutation::{
    AgBackend, AuthorizationVerifier, DenyMutations, required_member, validate_action,
};
use crate::runtime_error::RuntimeError;
use crate::{
    AvailabilityGroupIdentity, AvailabilityGroupName, ContractError, DatabaseIdentity, Guid,
    Observation, ObservationFailure, ObservationFailureKind, OperationEnvelope, OperationPayload,
    ReplicaIdentity, SqlIdentifier,
};

#[derive(Debug)]
pub enum AdapterError {
    Contract(ContractError),
    Journal(JournalError),
    Runtime(RuntimeError),
    Observation {
        replica: ReplicaIdentity,
        failure: ObservationFailure,
    },
    InvalidOptions,
    InvalidResult,
    Encoding,
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(f, "operation contract: {error}"),
            Self::Journal(error) => write!(f, "operation journal: {error}"),
            Self::Runtime(error) => error.fmt(f),
            Self::Observation { replica, failure } => write!(
                f,
                "replica {} observation: {}",
                replica.logical_id(),
                failure.message
            ),
            Self::InvalidOptions => {
                f.write_str("observation max age must be in 1..=300000 milliseconds")
            }
            Self::InvalidResult => {
                f.write_str("retained result is invalid or does not match its operation")
            }
            Self::Encoding => f.write_str("cannot encode native action or result"),
        }
    }
}

impl Error for AdapterError {}
impl From<ContractError> for AdapterError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}
impl From<JournalError> for AdapterError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}
impl From<RuntimeError> for AdapterError {
    fn from(error: RuntimeError) -> Self {
        Self::Runtime(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", content = "detail", rename_all = "snake_case")]
pub enum AdapterOutcome {
    /// A retained replay is historical evidence, never a fresh health assertion.
    Complete {
        postcondition: Postcondition,
        replayed: bool,
        retained: bool,
    },
    Proposed(NativeAction),
    Prepared(NativeAction),
    Dispatched(NativeAction),
    Wait(&'static str),
    Unsafe(&'static str),
}

pub struct AgAdapter<B, V = DenyMutations> {
    journal: OperationJournal,
    backend: B,
    verifier: V,
    mode: MutationMode,
    max_age_millis: u64,
}

impl<B> AgAdapter<B, DenyMutations> {
    pub fn new(journal: OperationJournal, backend: B) -> Self {
        Self {
            journal,
            backend,
            verifier: DenyMutations,
            mode: MutationMode::ObserveOnly,
            max_age_millis: 60_000,
        }
    }
}

impl<B, V> AgAdapter<B, V> {
    pub fn with_verifier<W>(self, verifier: W) -> AgAdapter<B, W> {
        AgAdapter {
            journal: self.journal,
            backend: self.backend,
            verifier,
            mode: self.mode,
            max_age_millis: self.max_age_millis,
        }
    }

    pub fn with_mode(mut self, mode: MutationMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn with_max_age_millis(mut self, max_age_millis: u64) -> Result<Self, AdapterError> {
        if !(1..=300_000).contains(&max_age_millis) {
            return Err(AdapterError::InvalidOptions);
        }
        self.max_age_millis = max_age_millis;
        Ok(self)
    }

    pub fn journal(&self) -> &OperationJournal {
        &self.journal
    }
}

impl<B: AgBackend, V: AuthorizationVerifier> AgAdapter<B, V> {
    /// Records intent and dispatches in different calls. A SQL acknowledgement
    /// never completes a request; only freshly observed postconditions do.
    pub async fn reconcile(
        &mut self,
        envelope: &OperationEnvelope,
        authority: &AcceptedAuthority,
    ) -> Result<AdapterOutcome, AdapterError> {
        envelope.validate()?;
        if authority.resource_id.as_str() != envelope.request().resource_id() {
            return Err(JournalError::ResourceMismatch.into());
        }
        if matches!(
            envelope.request().payload(),
            OperationPayload::PlannedSwitchover { .. } | OperationPayload::ForcedFailover { .. }
        ) {
            return Ok(AdapterOutcome::Unsafe(
                "primary authority transitions belong to stage 4",
            ));
        }
        let known = self.journal.lookup(envelope)?;
        let exact = known
            .as_ref()
            .filter(|entry| entry.envelope.operation_id() == envelope.operation_id());
        if let Some(result) = exact.and_then(|entry| entry.terminal_result.as_ref()) {
            return Ok(AdapterOutcome::Complete {
                postcondition: decode_result(result, envelope)?,
                replayed: true,
                retained: true,
            });
        }
        authority.validate_for(envelope)?;
        let binding = Sha256::digest(authority.canonical_binding()).to_vec();
        self.check_authority(authority, &binding)?;
        let duplicate = known
            .as_ref()
            .filter(|entry| entry.envelope.operation_id() != envelope.operation_id());
        if duplicate.is_some_and(|entry| entry.terminal_result.is_none()) {
            return Ok(AdapterOutcome::Wait(
                "the equivalent effect still belongs to an unresolved operation",
            ));
        }
        if self.mode == MutationMode::Enabled {
            self.verifier.verify_request(envelope, authority).await?;
        }
        let evidence = self.backend.observe(envelope, authority, self.mode).await?;
        let acknowledged: BTreeSet<String> = exact
            .map(|entry| {
                entry
                    .acknowledged_action_keys()
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let decision = plan(
            envelope,
            authority,
            &evidence,
            &acknowledged,
            unix_millis()?,
            self.max_age_millis,
        );
        if matches!(&decision, Decision::Wait(_) | Decision::Unsafe(_)) {
            for node in &evidence {
                if required_member(envelope, authority, &node.identity) {
                    match (&node.instance, &node.database) {
                        (Observation::Failed(failure), _) | (_, Observation::Failed(failure)) => {
                            return Err(AdapterError::Observation {
                                replica: node.identity.clone(),
                                failure: failure.clone(),
                            });
                        }
                        _ => {}
                    }
                }
            }
        }
        match decision {
            Decision::Complete(postcondition) => {
                validate_postcondition(&postcondition, envelope)?;
                if !bootstrap_intent_matches(exact, envelope, &evidence)? {
                    return Ok(AdapterOutcome::Unsafe(
                        "bootstrap database identity changed after intent persistence",
                    ));
                }
                let result = encode_result(&postcondition)?;
                if let Some(previous) = duplicate {
                    let previous_result = previous
                        .terminal_result
                        .as_ref()
                        .ok_or(AdapterError::InvalidResult)?;
                    if decode_result(previous_result, &previous.envelope)? != postcondition {
                        return Ok(AdapterOutcome::Unsafe(
                            "the retained native identities of an equivalent effect have changed",
                        ));
                    }
                    if self.mode == MutationMode::Enabled {
                        self.accept_authority(authority, &binding)?;
                        self.journal.finish_observed_duplicate(envelope, &result)?;
                    }
                } else if self.mode == MutationMode::Enabled {
                    self.register(envelope, authority, &binding)?;
                    self.journal.finish(envelope.operation_id(), &result)?;
                }
                Ok(AdapterOutcome::Complete {
                    postcondition,
                    replayed: false,
                    retained: self.mode == MutationMode::Enabled,
                })
            }
            Decision::Execute(action) => {
                if duplicate.is_some() {
                    return Ok(AdapterOutcome::Unsafe(
                        "an equivalent retained effect has no proven current postcondition; explicit new intent is required",
                    ));
                }
                let action = canonical_action(action);
                validate_action(envelope, authority, &action)?;
                let payload = encode_action(&action)?;
                let previous = exact.and_then(|entry| {
                    entry
                        .actions
                        .iter()
                        .find(|intent| intent.action_key == action.key())
                });
                if previous.is_some_and(|intent| intent.action_payload != payload) {
                    return Err(JournalError::ActionConflict.into());
                }
                if self.mode == MutationMode::ObserveOnly {
                    return Ok(AdapterOutcome::Proposed(action));
                }
                self.verifier.verify(envelope, authority, &action).await?;
                if let Some(blocked) =
                    self.recheck_action(envelope, authority, &evidence, &acknowledged, &action)?
                {
                    return Ok(blocked);
                }
                self.register(envelope, authority, &binding)?;
                if previous.is_none() {
                    self.journal
                        .persist_intent(envelope.operation_id(), action.key(), &payload)?;
                    return Ok(AdapterOutcome::Prepared(action));
                }
                if previous.is_some_and(|intent| intent.acknowledged) {
                    return Ok(AdapterOutcome::Wait(
                        "acknowledged native action has not established its postcondition",
                    ));
                }
                // Any error or cancellation below leaves the immutable intent
                // unacknowledged. Retry first reobserves, then reapplies its guards.
                if let Some(blocked) =
                    self.recheck_action(envelope, authority, &evidence, &acknowledged, &action)?
                {
                    return Ok(blocked);
                }
                let budget = dispatch_budget(envelope, authority, &evidence, self.max_age_millis)?;
                tokio::time::timeout(
                    budget,
                    self.backend
                        .execute(envelope, authority, &action, &self.verifier),
                )
                .await
                .map_err(|_| {
                    RuntimeError::new(
                        ObservationFailureKind::TimedOut,
                        "AG adapter",
                        "native outcome is uncertain after the observation freshness deadline",
                    )
                })??;
                self.journal
                    .acknowledge_action(envelope.operation_id(), action.key())?;
                Ok(AdapterOutcome::Dispatched(action))
            }
            Decision::Wait(reason) => Ok(AdapterOutcome::Wait(reason)),
            Decision::Unsafe(reason) => Ok(AdapterOutcome::Unsafe(reason)),
        }
    }

    fn recheck_action(
        &self,
        envelope: &OperationEnvelope,
        authority: &AcceptedAuthority,
        evidence: &[NodeEvidence],
        acknowledged: &BTreeSet<String>,
        expected: &NativeAction,
    ) -> Result<Option<AdapterOutcome>, AdapterError> {
        Ok(
            match plan(
                envelope,
                authority,
                evidence,
                acknowledged,
                unix_millis()?,
                self.max_age_millis,
            ) {
                Decision::Execute(action) => {
                    if canonical_action(action) == *expected {
                        None
                    } else {
                        Some(AdapterOutcome::Unsafe(
                            "the native action changed while verifying authority",
                        ))
                    }
                }
                Decision::Wait(reason) => Some(AdapterOutcome::Wait(reason)),
                Decision::Unsafe(reason) => Some(AdapterOutcome::Unsafe(reason)),
                _ => Some(AdapterOutcome::Unsafe(
                    "the native action changed while verifying authority",
                )),
            },
        )
    }

    fn check_authority(
        &self,
        authority: &AcceptedAuthority,
        binding: &[u8],
    ) -> Result<(), AdapterError> {
        if let Some(current) = self.journal.authority()? {
            if authority.epoch < current.epoch {
                return Err(JournalError::AuthorityRegression.into());
            }
            if authority.epoch == current.epoch
                && (current.configuration_id != authority.configuration_id.as_str()
                    || current.binding != binding)
            {
                return Err(JournalError::AuthorityConflict.into());
            }
        }
        Ok(())
    }

    fn accept_authority(
        &mut self,
        authority: &AcceptedAuthority,
        binding: &[u8],
    ) -> Result<(), AdapterError> {
        self.journal.accept_authority(
            authority.configuration_id.as_str(),
            authority.epoch,
            binding,
        )?;
        Ok(())
    }

    fn register(
        &mut self,
        envelope: &OperationEnvelope,
        authority: &AcceptedAuthority,
        binding: &[u8],
    ) -> Result<(), AdapterError> {
        self.accept_authority(authority, binding)?;
        match self.journal.register(envelope)? {
            Registration::New | Registration::Pending => Ok(()),
            Registration::Completed(_) | Registration::DuplicateEffect { .. } => {
                Err(JournalError::OperationInProgress.into())
            }
        }
    }
}

fn canonical_action(mut action: NativeAction) -> NativeAction {
    if let NativeAction::CreateAvailabilityGroup { replicas, .. } = &mut action {
        replicas.sort_by(|left, right| left.identity.cmp(&right.identity));
    }
    action
}

fn dispatch_budget(
    envelope: &OperationEnvelope,
    authority: &AcceptedAuthority,
    evidence: &[NodeEvidence],
    max_age_millis: u64,
) -> Result<Duration, AdapterError> {
    let now = unix_millis()?;
    let mut remaining = max_age_millis + 1;
    for node in evidence
        .iter()
        .filter(|node| required_member(envelope, authority, &node.identity))
    {
        for observed_at in [
            node.instance.observed_at_unix_millis(),
            node.database.observed_at_unix_millis(),
        ] {
            let age = now
                .checked_sub(observed_at)
                .filter(|age| *age <= max_age_millis)
                .ok_or_else(|| {
                    RuntimeError::new(
                        ObservationFailureKind::TimedOut,
                        "AG adapter",
                        "observation became stale or future-dated before native dispatch",
                    )
                })?;
            remaining = remaining.min(max_age_millis - age + 1);
        }
    }
    Ok(Duration::from_millis(remaining))
}

fn encode_action(action: &NativeAction) -> Result<Vec<u8>, AdapterError> {
    serde_json::to_vec(action).map_err(|_| AdapterError::Encoding)
}

fn bootstrap_intent_matches(
    entry: Option<&JournalEntry>,
    envelope: &OperationEnvelope,
    evidence: &[NodeEvidence],
) -> Result<bool, AdapterError> {
    let OperationPayload::EnsureAvailabilityGroup {
        name,
        database_name,
        primary,
        replicas,
        ..
    } = envelope.request().payload()
    else {
        return Ok(true);
    };
    let Some(entry) = entry else {
        return Ok(true);
    };
    let primary_evidence = evidence
        .iter()
        .find(|node| node.identity == *primary)
        .ok_or(AdapterError::InvalidResult)?;
    let Observation::Present {
        value: database, ..
    } = &primary_evidence.database
    else {
        return Err(AdapterError::InvalidResult);
    };
    let action = canonical_action(NativeAction::CreateAvailabilityGroup {
        primary: primary.clone(),
        name: name.clone(),
        database_name: database_name.clone(),
        replicas: replicas.clone(),
        expected_database_id: database.database_id,
        expected_database_guid: database.database_guid.clone(),
        expected_recovery_fork_id: database.recovery_fork_id.clone(),
    });
    let encoded = encode_action(&action)?;
    Ok(entry
        .actions
        .iter()
        .filter(|intent| intent.action_key == action.key())
        .all(|intent| intent.action_payload == encoded))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredResult {
    version: u16,
    group_name: String,
    group_id: String,
    database_name: Option<String>,
    group_database_id: Option<String>,
    logical_replica_id: String,
    native_replica_id: String,
    incarnation: String,
    database_id: Option<u32>,
    database_guid: Option<String>,
    recovery_fork_id: Option<String>,
}

fn encode_result(postcondition: &Postcondition) -> Result<Vec<u8>, AdapterError> {
    let result = StoredResult {
        version: 1,
        group_name: postcondition.availability_group.name.to_string(),
        group_id: postcondition.availability_group.group_id.to_string(),
        database_name: postcondition
            .database
            .as_ref()
            .map(|database| database.name.to_string()),
        group_database_id: postcondition
            .database
            .as_ref()
            .map(|database| database.group_database_id.to_string()),
        logical_replica_id: postcondition.replica.logical_id().to_owned(),
        native_replica_id: postcondition
            .replica
            .native_replica_id()
            .ok_or(AdapterError::InvalidResult)?
            .to_string(),
        incarnation: postcondition.replica.incarnation().to_owned(),
        database_id: postcondition.database_id,
        database_guid: postcondition
            .database_guid
            .as_ref()
            .map(ToString::to_string),
        recovery_fork_id: postcondition
            .recovery_fork_id
            .as_ref()
            .map(ToString::to_string),
    };
    serde_json::to_vec(&result).map_err(|_| AdapterError::Encoding)
}

fn decode_result(
    bytes: &[u8],
    envelope: &OperationEnvelope,
) -> Result<Postcondition, AdapterError> {
    if bytes.len() > MAX_RESULT_BYTES {
        return Err(AdapterError::InvalidResult);
    }
    let result: StoredResult =
        serde_json::from_slice(bytes).map_err(|_| AdapterError::InvalidResult)?;
    if result.version != 1 {
        return Err(AdapterError::InvalidResult);
    }
    let guid = |value: &str| {
        Guid::parse("retained native GUID", value).map_err(|_| AdapterError::InvalidResult)
    };
    let database = match (result.database_name, result.group_database_id) {
        (None, None) => None,
        (Some(name), Some(id)) => Some(DatabaseIdentity {
            name: SqlIdentifier::new(name).map_err(|_| AdapterError::InvalidResult)?,
            group_database_id: guid(&id)?,
        }),
        _ => return Err(AdapterError::InvalidResult),
    };
    let postcondition = Postcondition {
        availability_group: AvailabilityGroupIdentity {
            name: AvailabilityGroupName::new(result.group_name)
                .map_err(|_| AdapterError::InvalidResult)?,
            group_id: guid(&result.group_id)?,
        },
        database,
        replica: ReplicaIdentity::observed(
            result.logical_replica_id,
            guid(&result.native_replica_id)?,
            result.incarnation,
        )
        .map_err(|_| AdapterError::InvalidResult)?,
        database_id: result.database_id,
        database_guid: result.database_guid.as_deref().map(guid).transpose()?,
        recovery_fork_id: result.recovery_fork_id.as_deref().map(guid).transpose()?,
    };
    validate_postcondition(&postcondition, envelope)?;
    Ok(postcondition)
}

fn validate_postcondition(
    value: &Postcondition,
    envelope: &OperationEnvelope,
) -> Result<(), AdapterError> {
    let has_database = value.database.is_some()
        && value
            .database_id
            .is_some_and(|id| id > 4 && i32::try_from(id).is_ok())
        && value.database_guid.is_some()
        && value.recovery_fork_id.is_some();
    let valid = match envelope.request().payload() {
        OperationPayload::EnsureAvailabilityGroup {
            name,
            expected_group_id,
            database_name,
            primary,
            ..
        } => {
            value.availability_group.name == *name
                && expected_group_id
                    .as_ref()
                    .is_none_or(|id| value.availability_group.group_id == *id)
                && value.replica.logical_id() == primary.logical_id()
                && value.replica.incarnation() == primary.incarnation()
                && value.replica.native_replica_id().is_some()
                && value
                    .database
                    .as_ref()
                    .is_some_and(|database| database.name == *database_name)
                && has_database
        }
        OperationPayload::EnsureReplicaJoined {
            availability_group,
            target,
        } => {
            value.availability_group == *availability_group
                && value.replica == *target
                && value.database.is_none()
                && value.database_id.is_none()
                && value.database_guid.is_none()
                && value.recovery_fork_id.is_none()
        }
        OperationPayload::EnsureReplicaSeeded {
            availability_group,
            database,
            target,
            ..
        } => {
            value.availability_group == *availability_group
                && value.replica == *target
                && value.database.as_ref() == Some(database)
                && has_database
        }
        OperationPayload::ReseedReplica {
            availability_group,
            database,
            target,
            expected_database_guid,
            ..
        } => {
            value.availability_group == *availability_group
                && value.replica == *target
                && value.database.as_ref() == Some(database)
                && has_database
                && value.database_guid.as_ref() != Some(expected_database_guid)
        }
        _ => false,
    };
    if !valid {
        return Err(AdapterError::InvalidResult);
    }
    Ok(())
}
