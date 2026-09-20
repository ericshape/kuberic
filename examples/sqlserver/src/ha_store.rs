use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::journal::{AcceptedAuthority, JournalError, OperationJournal};
use crate::proof::{AuthorityOracle, ProofClaim, ProofError, ProofReplica, ProofScope};
use crate::{Guid, OpaqueId};

pub(crate) const CHECKPOINT: &str = "ha-control";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActiveAuthority {
    pub configuration_id: String,
    pub epoch: u64,
    pub binding: [u8; 32],
    pub primary: ProofReplica,
    pub group_name: String,
    pub group_id: String,
    pub database_name: String,
    pub group_database_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingTransition {
    pub scope: ProofScope,
    pub target_authority: ActiveAuthority,
    pub source: ProofReplica,
    pub target: ProofReplica,
    pub drain_prepared: bool,
    pub drain_acknowledged: bool,
    pub final_committed_record: Option<String>,
    pub fence_prepared: bool,
    pub fence: Option<Vec<u8>>,
    pub promotion_intent_key: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LeaseRecord {
    pub owner: ProofReplica,
    pub configuration_id: String,
    pub epoch: u64,
    pub authorization_expires_at: u64,
    pub attempted_at: u64,
    pub acknowledged: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ControlState {
    pub version: u16,
    pub resource_id: String,
    pub active: ActiveAuthority,
    pub pending: Option<PendingTransition>,
    pub last_lease: Option<LeaseRecord>,
    pub proof_counter: u64,
}

impl ControlState {
    pub fn encode(&self) -> Result<Vec<u8>, JournalError> {
        serde_json::to_vec(self).map_err(|_| JournalError::CorruptRecord)
    }

    pub fn next_proof_id(&mut self, purpose: &str) -> Result<String, JournalError> {
        self.proof_counter = self
            .proof_counter
            .checked_add(1)
            .ok_or(JournalError::CorruptRecord)?;
        Ok(format!("{purpose}-{}", self.proof_counter))
    }

    fn validate(&self, resource: &str, authority: &AcceptedAuthority) -> Result<(), JournalError> {
        if self.version != 1
            || self.resource_id != resource
            || self.active.configuration_id != authority.configuration_id
            || self.active.epoch != authority.epoch
            || self.active.binding.as_slice() != authority.binding
        {
            return Err(JournalError::CorruptRecord);
        }
        self.active.validate()?;
        if let Some(pending) = &self.pending {
            pending
                .source
                .to_identity()
                .map_err(|_| JournalError::CorruptRecord)?;
            pending
                .target
                .to_identity()
                .map_err(|_| JournalError::CorruptRecord)?;
            pending.target_authority.validate()?;
            if pending.scope.resource_id != resource
                || pending.scope.source_configuration_id != self.active.configuration_id
                || pending.scope.source_epoch != self.active.epoch
                || self.active.epoch.checked_add(1) != Some(pending.scope.target_epoch)
                || pending.target_authority.epoch != pending.scope.target_epoch
                || pending.target_authority.primary != pending.target
                || pending.source != self.active.primary
                || pending.target_authority.group_id != self.active.group_id
                || pending.target_authority.group_database_id != self.active.group_database_id
            {
                return Err(JournalError::CorruptRecord);
            }
            if let Some(record) = &pending.final_committed_record {
                crate::DecimalProgress::parse(record).map_err(|_| JournalError::CorruptRecord)?;
            }
        }
        if let Some(lease) = &self.last_lease {
            lease
                .owner
                .to_identity()
                .map_err(|_| JournalError::CorruptRecord)?;
            if lease.attempted_at >= lease.authorization_expires_at {
                return Err(JournalError::CorruptRecord);
            }
        }
        Ok(())
    }
}

impl ActiveAuthority {
    fn validate(&self) -> Result<(), JournalError> {
        OpaqueId::new("configuration", &self.configuration_id)
            .map_err(|_| JournalError::CorruptRecord)?;
        self.primary
            .to_identity()
            .map_err(|_| JournalError::CorruptRecord)?;
        crate::AvailabilityGroupName::new(&self.group_name)
            .map_err(|_| JournalError::CorruptRecord)?;
        crate::SqlIdentifier::new(&self.database_name).map_err(|_| JournalError::CorruptRecord)?;
        for value in [&self.group_id, &self.group_database_id] {
            Guid::parse("HA checkpoint GUID", value).map_err(|_| JournalError::CorruptRecord)?;
        }
        Ok(())
    }
}

pub(crate) fn load(journal: &OperationJournal) -> Result<Option<ControlState>, JournalError> {
    decode(
        journal.resource_id(),
        journal.authority()?,
        journal.checkpoint(CHECKPOINT)?,
    )
}

fn decode(
    resource: &str,
    authority: Option<AcceptedAuthority>,
    bytes: Option<Vec<u8>>,
) -> Result<Option<ControlState>, JournalError> {
    let Some(bytes) = bytes else {
        return Ok(None);
    };
    let state: ControlState =
        serde_json::from_slice(&bytes).map_err(|_| JournalError::CorruptRecord)?;
    let authority = authority.ok_or(JournalError::CorruptRecord)?;
    state.validate(resource, &authority)?;
    Ok(Some(state))
}

pub(crate) fn save(
    journal: &mut OperationJournal,
    state: &ControlState,
) -> Result<(), JournalError> {
    let authority = journal
        .authority()?
        .ok_or(JournalError::AuthorityRequired)?;
    state.validate(journal.resource_id(), &authority)?;
    journal.put_checkpoint(CHECKPOINT, &state.encode()?)
}

/// A coherent, read-only view of the resource's real journal, not a cached
/// allow-list. Unavailable/corrupt storage denies authorization.
pub struct JournalAuthorityOracle {
    path: PathBuf,
    resource_id: String,
}

impl JournalAuthorityOracle {
    pub fn new(path: PathBuf, resource_id: String) -> Self {
        Self { path, resource_id }
    }
}

impl AuthorityOracle for JournalAuthorityOracle {
    fn check(&self, scope: &ProofScope, claim: &ProofClaim) -> Result<(), ProofError> {
        let (authority, checkpoint) =
            OperationJournal::inspect_read_only(&self.path, &self.resource_id, CHECKPOINT)
                .map_err(|_| ProofError::AuthorityDenied)?;
        let current = authority.as_ref().ok_or(ProofError::AuthorityDenied)?;
        let state = decode(&self.resource_id, authority.clone(), checkpoint)
            .map_err(|_| ProofError::AuthorityDenied)?;
        if scope.resource_id != self.resource_id {
            return Err(ProofError::AuthorityDenied);
        }
        if let Some(pending) = state.as_ref().and_then(|state| state.pending.as_ref()) {
            if let ProofClaim::Lease {
                group_name,
                group_id,
                primary,
                ..
            } = claim
            {
                let target = &pending.target_authority;
                if pending.fence.is_some()
                    && primary == &target.primary
                    && group_name == &target.group_name
                    && group_id == &target.group_id
                    && scope.source_configuration_id == target.configuration_id
                    && scope.source_epoch == target.epoch
                    && scope.target_epoch == target.epoch
                    && scope.authority_binding == target.binding
                {
                    return Ok(());
                }
            } else if scope == &pending.scope {
                return Ok(());
            }
            return Err(ProofError::AuthorityDenied);
        }
        if scope.source_configuration_id != current.configuration_id
            || scope.source_epoch != current.epoch
            || scope.target_epoch != current.epoch
            || scope.authority_binding.as_slice() != current.binding
        {
            return Err(ProofError::AuthorityDenied);
        }
        if let ProofClaim::Lease {
            group_name,
            group_id,
            primary,
            ..
        } = claim
        {
            let active = &state.as_ref().ok_or(ProofError::AuthorityDenied)?.active;
            if primary != &active.primary
                || group_name != &active.group_name
                || group_id != &active.group_id
            {
                return Err(ProofError::AuthorityDenied);
            }
        }
        Ok(())
    }
}
