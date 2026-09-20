//! Authenticated, short-lived statements from explicitly trusted issuers.
//!
//! A signature authenticates the issuer and the complete statement, not the
//! truth of a fence or current authority. The controller must independently
//! establish permanent removal and consult durable authority on every action.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::convergence::{AcceptedAuthority, NativeAction};
use crate::instance::unix_millis;
use crate::mutation::AuthorizationVerifier;
use crate::runtime_error::RuntimeError;
use crate::{
    AvailabilityGroupName, DecimalProgress, Guid, ObservationFailureKind, OpaqueId,
    OperationEnvelope, OperationPayload, OperationRequest, ReplicaIdentity,
};

pub const PROOF_CONTRACT_VERSION: u16 = 1;
pub const MAX_PROOF_BYTES: usize = 64 * 1024;
pub const MAX_PROOF_TTL_MILLIS: u64 = 300_000;
const SIGNATURE_DOMAIN: &[u8] = b"kuberic.sqlserver.proof.v1\0";

/// Diagnostics never contain input bytes, identifiers, keys, or parser errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofError {
    TooLarge,
    Malformed,
    UnsupportedVersion,
    NonCanonical,
    InvalidClaims,
    InvalidScope,
    InvalidKey,
    InvalidTrustConfiguration,
    UnknownIssuer,
    IssuerMismatch,
    PurposeMismatch,
    SignatureMismatch,
    ScopeMismatch,
    NotYetValid,
    Expired,
    TtlExceeded,
    InvalidOperation,
    MissingProof,
    UnexpectedProof,
    ReferenceMismatch,
    ReplicaMismatch,
    DataLossNotAuthorized,
    MissingCommitBoundary,
    AuthorityDenied,
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "proof exceeds its size limit",
            Self::Malformed => "malformed proof",
            Self::UnsupportedVersion => "unsupported proof version",
            Self::NonCanonical => "proof is not canonically encoded",
            Self::InvalidClaims => "proof claims violate their safety contract",
            Self::InvalidScope => "proof scope violates its safety contract",
            Self::InvalidKey => "invalid proof signing or verification key",
            Self::InvalidTrustConfiguration => "invalid proof issuer configuration",
            Self::UnknownIssuer => "proof issuer is not trusted",
            Self::IssuerMismatch => "proof does not identify the signing issuer",
            Self::PurposeMismatch => "proof issuer or claim has the wrong purpose",
            Self::SignatureMismatch => "proof signature is invalid",
            Self::ScopeMismatch => "proof scope does not match the authorized input",
            Self::NotYetValid => "proof is not yet valid",
            Self::Expired => "proof has expired",
            Self::TtlExceeded => "proof lifetime exceeds the configured limit",
            Self::InvalidOperation => "operation violates its safety contract",
            Self::MissingProof => "required authenticated proof is missing",
            Self::UnexpectedProof => "unused proof is not permitted",
            Self::ReferenceMismatch => "authenticated proof does not match its reference",
            Self::ReplicaMismatch => "authenticated fence identifies a different incarnation",
            Self::DataLossNotAuthorized => "operation lacks the required data-loss authorization",
            Self::MissingCommitBoundary => "planned transition lacks a final committed witness",
            Self::AuthorityDenied => "current authority does not authorize this proof",
        })
    }
}

impl Error for ProofError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ProofKind {
    Authority,
    Approval,
    Fence,
    Lease,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofScope {
    pub resource_id: String,
    pub operation_id: String,
    pub input_signature: [u8; 32],
    pub authority_binding: [u8; 32],
    pub source_configuration_id: String,
    pub source_epoch: u64,
    pub target_epoch: u64,
}

impl ProofScope {
    pub fn for_operation(request: &OperationRequest, authority_binding: [u8; 32]) -> Self {
        Self {
            resource_id: request.resource_id().to_owned(),
            operation_id: request.operation_id().to_owned(),
            input_signature: *request.input_signature().as_bytes(),
            authority_binding,
            source_configuration_id: request.source_configuration_id().to_owned(),
            source_epoch: request.source_epoch(),
            target_epoch: request.target_epoch(),
        }
    }

    pub fn validate(&self) -> Result<(), ProofError> {
        for value in [
            &self.resource_id,
            &self.operation_id,
            &self.source_configuration_id,
        ] {
            validate_id(value).map_err(|_| ProofError::InvalidScope)?;
        }
        // Epoch zero is valid for an initial configuration, unlike empty digests.
        if self.input_signature == [0; 32]
            || self.authority_binding == [0; 32]
            || self.target_epoch < self.source_epoch
        {
            return Err(ProofError::InvalidScope);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofReplica {
    pub logical_id: String,
    pub native_replica_id: String,
    pub incarnation: String,
}

impl ProofReplica {
    pub fn from_identity(identity: &ReplicaIdentity) -> Result<Self, ProofError> {
        let replica = Self {
            logical_id: identity.logical_id().to_owned(),
            native_replica_id: identity
                .native_replica_id()
                .ok_or(ProofError::InvalidClaims)?
                .to_string(),
            incarnation: identity.incarnation().to_owned(),
        };
        replica.to_identity()?;
        Ok(replica)
    }

    pub fn to_identity(&self) -> Result<ReplicaIdentity, ProofError> {
        validate_id(&self.logical_id)?;
        validate_id(&self.incarnation)?;
        ReplicaIdentity::observed(
            self.logical_id.clone(),
            canonical_guid(&self.native_replica_id)?,
            self.incarnation.clone(),
        )
        .map_err(|_| ProofError::InvalidClaims)
    }
}

impl TryFrom<&ReplicaIdentity> for ProofReplica {
    type Error = ProofError;

    fn try_from(value: &ReplicaIdentity) -> Result<Self, Self::Error> {
        Self::from_identity(value)
    }
}

impl TryFrom<&ProofReplica> for ReplicaIdentity {
    type Error = ProofError;

    fn try_from(value: &ProofReplica) -> Result<Self, Self::Error> {
        value.to_identity()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    deny_unknown_fields,
    from = "ProofClaimWire"
)]
pub enum ProofClaim {
    Authority,
    Approval {
        allow_data_loss: bool,
        allow_unknown_data_loss: bool,
    },
    /// Permanent removal of this exact container, not a lease or readiness hint.
    Fence {
        provider: String,
        replica: ProofReplica,
        engine_id: String,
        container_id: String,
        removed_at_unix_millis: u64,
        final_committed_record: Option<String>,
    },
    Lease {
        group_name: String,
        group_id: String,
        primary: ProofReplica,
        sql_start_time: String,
        lease_seconds: u32,
    },
}

// Serde ignores extra fields on an internally tagged unit variant, even with
// deny_unknown_fields. An empty struct variant makes Authority strict as well.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ProofClaimWire {
    Authority {},
    Approval {
        allow_data_loss: bool,
        allow_unknown_data_loss: bool,
    },
    Fence {
        provider: String,
        replica: ProofReplica,
        engine_id: String,
        container_id: String,
        removed_at_unix_millis: u64,
        final_committed_record: Option<String>,
    },
    Lease {
        group_name: String,
        group_id: String,
        primary: ProofReplica,
        sql_start_time: String,
        lease_seconds: u32,
    },
}

impl From<ProofClaimWire> for ProofClaim {
    fn from(value: ProofClaimWire) -> Self {
        match value {
            ProofClaimWire::Authority {} => Self::Authority,
            ProofClaimWire::Approval {
                allow_data_loss,
                allow_unknown_data_loss,
            } => Self::Approval {
                allow_data_loss,
                allow_unknown_data_loss,
            },
            ProofClaimWire::Fence {
                provider,
                replica,
                engine_id,
                container_id,
                removed_at_unix_millis,
                final_committed_record,
            } => Self::Fence {
                provider,
                replica,
                engine_id,
                container_id,
                removed_at_unix_millis,
                final_committed_record,
            },
            ProofClaimWire::Lease {
                group_name,
                group_id,
                primary,
                sql_start_time,
                lease_seconds,
            } => Self::Lease {
                group_name,
                group_id,
                primary,
                sql_start_time,
                lease_seconds,
            },
        }
    }
}

impl ProofClaim {
    pub fn kind(&self) -> ProofKind {
        match self {
            Self::Authority => ProofKind::Authority,
            Self::Approval { .. } => ProofKind::Approval,
            Self::Fence { .. } => ProofKind::Fence,
            Self::Lease { .. } => ProofKind::Lease,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofClaims {
    pub version: u16,
    pub proof_id: String,
    pub issuer_id: String,
    pub issued_at_unix_millis: u64,
    pub not_before_unix_millis: u64,
    pub expires_at_unix_millis: u64,
    pub scope: ProofScope,
    pub claim: ProofClaim,
}

impl ProofClaims {
    /// Structural validation only; this never establishes authenticity.
    pub fn validate(&self) -> Result<(), ProofError> {
        if self.version != PROOF_CONTRACT_VERSION {
            return Err(ProofError::UnsupportedVersion);
        }
        validate_id(&self.proof_id)?;
        validate_id(&self.issuer_id)?;
        self.scope.validate()?;
        if self.issued_at_unix_millis == 0
            || self.issued_at_unix_millis > self.not_before_unix_millis
            || self.not_before_unix_millis >= self.expires_at_unix_millis
        {
            return Err(ProofError::InvalidClaims);
        }
        if self.expires_at_unix_millis - self.issued_at_unix_millis > MAX_PROOF_TTL_MILLIS {
            return Err(ProofError::TtlExceeded);
        }
        match &self.claim {
            ProofClaim::Authority => {}
            ProofClaim::Approval {
                allow_data_loss,
                allow_unknown_data_loss,
            } => {
                if *allow_unknown_data_loss && !allow_data_loss {
                    return Err(ProofError::InvalidClaims);
                }
            }
            ProofClaim::Fence {
                provider,
                replica,
                engine_id,
                container_id,
                removed_at_unix_millis,
                final_committed_record,
            } => {
                validate_id(provider)?;
                validate_id(engine_id)?;
                replica.to_identity()?;
                if provider != &self.issuer_id
                    || container_id != &replica.incarnation
                    || container_id.len() != 64
                    || container_id.bytes().all(|byte| byte == b'0')
                    || !container_id
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                    || *removed_at_unix_millis == 0
                    || *removed_at_unix_millis > self.issued_at_unix_millis
                {
                    return Err(ProofError::InvalidClaims);
                }
                if let Some(value) = final_committed_record {
                    let progress =
                        DecimalProgress::parse(value).map_err(|_| ProofError::InvalidClaims)?;
                    if progress.to_string() != *value {
                        return Err(ProofError::NonCanonical);
                    }
                }
            }
            ProofClaim::Lease {
                group_name,
                group_id,
                primary,
                sql_start_time,
                lease_seconds,
            } => {
                AvailabilityGroupName::new(group_name.clone())
                    .map_err(|_| ProofError::InvalidClaims)?;
                canonical_guid(group_id)?;
                primary.to_identity()?;
                validate_id(sql_start_time)?;
                if !(5..=60).contains(lease_seconds)
                    || self.scope.source_epoch != self.scope.target_epoch
                {
                    return Err(ProofError::InvalidClaims);
                }
            }
        }
        Ok(())
    }
}

/// Untrusted transport DTO. Only `SignedProof::decode` validates its bounds and
/// canonical encoding; only `ProofVerifier` authenticates its contents.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedProofDto {
    pub canonical_claims: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SignedProof {
    canonical_claims: Vec<u8>,
    signature: [u8; 64],
}

impl fmt::Debug for SignedProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignedProof { contents: redacted }")
    }
}

impl SignedProof {
    /// Canonical compact JSON, with the canonical claims JSON stored verbatim.
    /// Signatures cover `kuberic.sqlserver.proof.v1\0` followed by those bytes.
    pub fn encode(&self) -> Result<Vec<u8>, ProofError> {
        let bytes = serde_json::to_vec(&SignedProofDto {
            canonical_claims: self.canonical_claims.clone(),
            signature: self.signature.to_vec(),
        })
        .map_err(|_| ProofError::Malformed)?;
        bounded(&bytes)?;
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProofError> {
        bounded(bytes)?;
        let dto: SignedProofDto =
            serde_json::from_slice(bytes).map_err(|_| ProofError::Malformed)?;
        bounded(&dto.canonical_claims)?;
        let signature = dto
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| ProofError::Malformed)?;
        decode_claims(&dto.canonical_claims)?;
        if serde_json::to_vec(&dto).map_err(|_| ProofError::Malformed)? != bytes {
            return Err(ProofError::NonCanonical);
        }
        Ok(Self {
            canonical_claims: dto.canonical_claims,
            signature,
        })
    }
}

/// Explicitly trusted signing capability. The Ed25519 key is zeroized on drop;
/// the caller remains responsible for the borrowed seed's storage and lifetime.
/// This type deliberately implements neither Debug nor Serialize.
pub struct ProofSigner {
    issuer_id: String,
    kind: ProofKind,
    key: SigningKey,
}

impl ProofSigner {
    pub fn from_seed(
        issuer_id: impl Into<String>,
        kind: ProofKind,
        seed: &[u8; 32],
    ) -> Result<Self, ProofError> {
        let issuer_id = issuer_id.into();
        validate_id(&issuer_id)?;
        if seed == &[0; 32] {
            return Err(ProofError::InvalidKey);
        }
        Ok(Self {
            issuer_id,
            kind,
            key: SigningKey::from_bytes(seed),
        })
    }

    pub fn issuer_id(&self) -> &str {
        &self.issuer_id
    }

    pub fn kind(&self) -> ProofKind {
        self.kind
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    pub fn sign(&self, claims: ProofClaims) -> Result<SignedProof, ProofError> {
        claims.validate()?;
        if claims.issuer_id != self.issuer_id {
            return Err(ProofError::IssuerMismatch);
        }
        if claims.claim.kind() != self.kind {
            return Err(ProofError::PurposeMismatch);
        }
        let canonical_claims = serde_json::to_vec(&claims).map_err(|_| ProofError::Malformed)?;
        bounded(&canonical_claims)?;
        let signature = self
            .key
            .sign(&signature_message(&canonical_claims))
            .to_bytes();
        let signed = SignedProof {
            canonical_claims,
            signature,
        };
        signed.encode()?;
        Ok(signed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedIssuer {
    pub issuer_id: String,
    pub kind: ProofKind,
    pub public_key: [u8; 32],
}

#[derive(Clone)]
pub struct ProofVerifier {
    issuers: BTreeMap<String, (ProofKind, VerifyingKey)>,
    max_ttl_millis: u64,
}

impl ProofVerifier {
    pub fn new(issuers: Vec<TrustedIssuer>, max_ttl_millis: u64) -> Result<Self, ProofError> {
        if issuers.is_empty() || max_ttl_millis == 0 || max_ttl_millis > MAX_PROOF_TTL_MILLIS {
            return Err(ProofError::InvalidTrustConfiguration);
        }
        let mut trusted = BTreeMap::new();
        let mut keys = BTreeSet::new();
        for issuer in issuers {
            validate_id(&issuer.issuer_id).map_err(|_| ProofError::InvalidTrustConfiguration)?;
            let key =
                VerifyingKey::from_bytes(&issuer.public_key).map_err(|_| ProofError::InvalidKey)?;
            if issuer.public_key == [0; 32] || key.is_weak() {
                return Err(ProofError::InvalidKey);
            }
            if !keys.insert(issuer.public_key)
                || trusted
                    .insert(issuer.issuer_id, (issuer.kind, key))
                    .is_some()
            {
                return Err(ProofError::InvalidTrustConfiguration);
            }
        }
        Ok(Self {
            issuers: trusted,
            max_ttl_millis,
        })
    }

    pub fn verify(
        &self,
        signed: &SignedProof,
        expected_scope: &ProofScope,
        expected_kind: ProofKind,
        now_ms: u64,
    ) -> Result<VerifiedProof, ProofError> {
        expected_scope.validate()?;
        let claims = decode_claims(&signed.canonical_claims)?;
        let (kind, key) = self
            .issuers
            .get(&claims.issuer_id)
            .ok_or(ProofError::UnknownIssuer)?;
        if *kind != expected_kind || claims.claim.kind() != expected_kind {
            return Err(ProofError::PurposeMismatch);
        }
        key.verify_strict(
            &signature_message(&signed.canonical_claims),
            &Signature::from_bytes(&signed.signature),
        )
        .map_err(|_| ProofError::SignatureMismatch)?;
        if &claims.scope != expected_scope {
            return Err(ProofError::ScopeMismatch);
        }
        if claims.expires_at_unix_millis - claims.issued_at_unix_millis > self.max_ttl_millis {
            return Err(ProofError::TtlExceeded);
        }
        if now_ms < claims.issued_at_unix_millis || now_ms < claims.not_before_unix_millis {
            return Err(ProofError::NotYetValid);
        }
        if now_ms >= claims.expires_at_unix_millis {
            return Err(ProofError::Expired);
        }
        Ok(VerifiedProof { claims })
    }

    /// Authentication/time checks only. Current origin, epoch and permanent
    /// infrastructure removal still require independent durable verification.
    pub fn verify_operation(
        &self,
        envelope: &OperationEnvelope,
        authority_binding: [u8; 32],
        bundle: &ProofBundle,
        now_ms: u64,
    ) -> Result<VerifiedOperation, ProofError> {
        envelope
            .validate()
            .map_err(|_| ProofError::InvalidOperation)?;
        let scope = ProofScope::for_operation(envelope.request(), authority_binding);
        let authority = self.verify(&bundle.authority, &scope, ProofKind::Authority, now_ms)?;
        let approval = match (envelope.destructive_approval(), &bundle.approval) {
            (Some(reference), Some(signed)) => {
                let verified = self.verify(signed, &scope, ProofKind::Approval, now_ms)?;
                if reference.authorization_id() != verified.claims.proof_id
                    || reference.approved_operation_id() != scope.operation_id
                    || reference.approved_input_signature().as_bytes() != &scope.input_signature
                {
                    return Err(ProofError::ReferenceMismatch);
                }
                let ProofClaim::Approval {
                    allow_data_loss,
                    allow_unknown_data_loss,
                } = &verified.claims.claim
                else {
                    return Err(ProofError::PurposeMismatch);
                };
                match envelope.request().payload() {
                    OperationPayload::ForcedFailover {
                        last_known_commit, ..
                    } if !allow_data_loss
                        || (last_known_commit.is_none() && !allow_unknown_data_loss) =>
                    {
                        return Err(ProofError::DataLossNotAuthorized);
                    }
                    OperationPayload::ReseedReplica { .. }
                        if *allow_data_loss || *allow_unknown_data_loss =>
                    {
                        return Err(ProofError::DataLossNotAuthorized);
                    }
                    _ => {}
                }
                Some(verified)
            }
            (Some(_), None) => return Err(ProofError::MissingProof),
            (None, Some(_)) => return Err(ProofError::UnexpectedProof),
            (None, None) => None,
        };
        let fence = match (envelope.fence(), &bundle.fence) {
            (Some(reference), Some(signed)) => {
                let verified = self.verify(signed, &scope, ProofKind::Fence, now_ms)?;
                let ProofClaim::Fence {
                    provider,
                    replica,
                    final_committed_record,
                    ..
                } = &verified.claims.claim
                else {
                    return Err(ProofError::PurposeMismatch);
                };
                if reference.receipt_id() != verified.claims.proof_id
                    || reference.provider() != provider
                    || reference.provider() != verified.claims.issuer_id
                    || reference.operation_id() != scope.operation_id
                    || reference.input_signature().as_bytes() != &scope.input_signature
                {
                    return Err(ProofError::ReferenceMismatch);
                }
                if &replica.to_identity()? != reference.fenced_replica() {
                    return Err(ProofError::ReplicaMismatch);
                }
                if matches!(
                    envelope.request().payload(),
                    OperationPayload::PlannedSwitchover { .. }
                ) && final_committed_record.is_none()
                {
                    return Err(ProofError::MissingCommitBoundary);
                }
                Some(verified)
            }
            (Some(_), None) => return Err(ProofError::MissingProof),
            (None, Some(_)) => return Err(ProofError::UnexpectedProof),
            (None, None) => None,
        };
        Ok(VerifiedOperation {
            authority,
            approval,
            fence,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProof {
    claims: ProofClaims,
}

impl VerifiedProof {
    pub fn claims(&self) -> &ProofClaims {
        &self.claims
    }

    pub fn expires_at_unix_millis(&self) -> u64 {
        self.claims.expires_at_unix_millis
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofBundle {
    pub authority: SignedProof,
    pub approval: Option<SignedProof>,
    pub fence: Option<SignedProof>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOperation {
    authority: VerifiedProof,
    approval: Option<VerifiedProof>,
    fence: Option<VerifiedProof>,
}

impl VerifiedOperation {
    pub fn authority(&self) -> &VerifiedProof {
        &self.authority
    }

    pub fn approval(&self) -> Option<&VerifiedProof> {
        self.approval.as_ref()
    }

    pub fn fence(&self) -> Option<&ProofClaims> {
        self.fence.as_ref().map(VerifiedProof::claims)
    }

    /// The authorization window ends when any required proof expires.
    pub fn expires_at_unix_millis(&self) -> u64 {
        self.proofs()
            .map(VerifiedProof::expires_at_unix_millis)
            .min()
            .expect("every verified operation has an authority proof")
    }

    fn proofs(&self) -> impl Iterator<Item = &VerifiedProof> {
        std::iter::once(&self.authority)
            .chain(self.approval.iter())
            .chain(self.fence.iter())
    }
}

/// Implementations must consult current, durable authority and fencing state.
/// There is deliberately no permissive default implementation.
pub trait AuthorityOracle: Send + Sync {
    fn check(&self, scope: &ProofScope, claim: &ProofClaim) -> Result<(), ProofError>;
}

pub struct SignedAuthorizationVerifier {
    verifier: ProofVerifier,
    bundle: ProofBundle,
    oracle: Arc<dyn AuthorityOracle>,
}

impl SignedAuthorizationVerifier {
    pub fn new(
        verifier: ProofVerifier,
        bundle: ProofBundle,
        oracle: Arc<dyn AuthorityOracle>,
    ) -> Self {
        Self {
            verifier,
            bundle,
            oracle,
        }
    }

    fn check(
        &self,
        envelope: &OperationEnvelope,
        authority: &AcceptedAuthority,
    ) -> Result<(), RuntimeError> {
        authority.validate_for(envelope)?;
        let binding = Sha256::digest(authority.canonical_binding()).into();
        let verified = self
            .verifier
            .verify_operation(envelope, binding, &self.bundle, unix_millis()?)
            .map_err(authorization_error)?;
        for proof in verified.proofs() {
            self.oracle
                .check(&proof.claims.scope, &proof.claims.claim)
                .map_err(authorization_error)?;
        }
        // An oracle may block; do not return a permit that expired during it.
        let now = unix_millis()?;
        if verified.proofs().any(|proof| {
            now < proof.claims.not_before_unix_millis || now >= proof.claims.expires_at_unix_millis
        }) {
            return Err(authorization_error(ProofError::AuthorityDenied));
        }
        Ok(())
    }
}

#[async_trait]
impl AuthorizationVerifier for SignedAuthorizationVerifier {
    async fn verify_request(
        &self,
        envelope: &OperationEnvelope,
        authority: &AcceptedAuthority,
    ) -> Result<(), RuntimeError> {
        self.check(envelope, authority)
    }

    async fn verify(
        &self,
        envelope: &OperationEnvelope,
        authority: &AcceptedAuthority,
        _: &NativeAction,
    ) -> Result<(), RuntimeError> {
        // Static action/envelope matching remains the backend's responsibility.
        self.check(envelope, authority)
    }
}

fn authorization_error(_: ProofError) -> RuntimeError {
    RuntimeError::new(
        ObservationFailureKind::PermissionDenied,
        "proof authorization",
        "authenticated proof or current authority verification failed",
    )
}

fn bounded(bytes: &[u8]) -> Result<(), ProofError> {
    if bytes.len() > MAX_PROOF_BYTES {
        Err(ProofError::TooLarge)
    } else {
        Ok(())
    }
}

fn validate_id(value: &str) -> Result<(), ProofError> {
    if value.trim() != value || value.is_empty() {
        return Err(ProofError::InvalidClaims);
    }
    OpaqueId::new("proof identifier", value)
        .map(|_| ())
        .map_err(|_| ProofError::InvalidClaims)
}

fn canonical_guid(value: &str) -> Result<Guid, ProofError> {
    let guid = Guid::parse("proof native GUID", value).map_err(|_| ProofError::InvalidClaims)?;
    if guid.as_str() != value {
        return Err(ProofError::NonCanonical);
    }
    Ok(guid)
}

fn decode_claims(bytes: &[u8]) -> Result<ProofClaims, ProofError> {
    bounded(bytes)?;
    let claims: ProofClaims = serde_json::from_slice(bytes).map_err(|_| ProofError::Malformed)?;
    claims.validate()?;
    if serde_json::to_vec(&claims).map_err(|_| ProofError::Malformed)? != bytes {
        return Err(ProofError::NonCanonical);
    }
    Ok(claims)
}

fn signature_message(canonical_claims: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(SIGNATURE_DOMAIN.len() + canonical_claims.len());
    bytes.extend_from_slice(SIGNATURE_DOMAIN);
    bytes.extend_from_slice(canonical_claims);
    bytes
}
