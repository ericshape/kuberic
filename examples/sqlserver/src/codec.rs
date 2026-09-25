//! Bounded, validating operation-envelope transport.
//!
//! The strict JSON wrapper carries the canonical binary request, its SHA-256
//! digest, and complete operation-bound proof references. Decoding a reference
//! checks its binding, not its authenticity or whether fencing actually happened.
//! Callers must independently authenticate approvals and verify fence receipts.

use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::SUPPORTED_REPLICA_COUNT;
use crate::operation::{
    DestructiveApproval, FenceReference, InputSignature, OPERATION_CONTRACT_VERSION,
    OperationEnvelope, OperationPayload, OperationRequest,
};
use crate::types::{
    AvailabilityGroupIdentity, AvailabilityGroupName, DatabaseIdentity, DatabaseLineage,
    DecimalProgress, Endpoint, Guid, ReplicaDescriptor, ReplicaIdentity, ServerName, SqlIdentifier,
};

pub const MAX_ENVELOPE_BYTES: usize = 64 * 1024;

/// Deliberately excludes parser diagnostics and caller-provided field values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    TooLarge,
    Malformed,
    UnsupportedVersion,
    UnknownTag,
    InvalidField,
    InvalidRequest,
    InvalidProof,
    NonCanonical,
    IntegrityMismatch,
    TrailingData,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "operation envelope exceeds its size limit",
            Self::Malformed => "malformed operation envelope",
            Self::UnsupportedVersion => "unsupported operation envelope or contract version",
            Self::UnknownTag => "unknown canonical operation tag",
            Self::InvalidField => "invalid operation envelope field",
            Self::InvalidRequest => "operation request violates its safety contract",
            Self::InvalidProof => "invalid or incorrectly bound operation proof reference",
            Self::NonCanonical => "operation input is not canonically encoded",
            Self::IntegrityMismatch => "operation input digest does not match",
            Self::TrailingData => "unexpected trailing canonical operation data",
        })
    }
}

impl Error for CodecError {}

/// Encodes all request fields and the supplied proof references without
/// credentials, executable SQL, or reconstruction of proof signatures.
pub fn encode_envelope(envelope: &OperationEnvelope) -> Result<Vec<u8>, CodecError> {
    envelope
        .validate()
        .map_err(|_| CodecError::InvalidRequest)?;
    let dto = EnvelopeDto {
        version: OPERATION_CONTRACT_VERSION,
        canonical_request: envelope.canonical_input(),
        input_signature: *envelope.input_signature().as_bytes(),
        destructive_approval: envelope.destructive_approval().map(ApprovalDto::from),
        fence: envelope.fence().map(FenceDto::from),
    };
    let bytes = serde_json::to_vec(&dto).map_err(|_| CodecError::Malformed)?;
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(CodecError::TooLarge);
    }
    Ok(bytes)
}

/// Decodes through validated constructors and rejects v1 rather than inventing
/// the primary/old-database authority absent from that contract.
///
/// Replica member sets are returned in canonical order. JSON object order and
/// insignificant whitespace are not significant; duplicate/unknown fields,
/// noncanonical request fields, and non-whitespace trailing input are rejected.
pub fn decode_envelope(bytes: &[u8]) -> Result<OperationEnvelope, CodecError> {
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(CodecError::TooLarge);
    }
    let dto: EnvelopeDto = serde_json::from_slice(bytes).map_err(|_| CodecError::Malformed)?;
    if dto.version != OPERATION_CONTRACT_VERSION {
        return Err(CodecError::UnsupportedVersion);
    }
    let digest: [u8; 32] = Sha256::digest(&dto.canonical_request).into();
    if digest != dto.input_signature {
        return Err(CodecError::IntegrityMismatch);
    }
    let request = decode_request(&dto.canonical_request)?;
    let approval = dto
        .destructive_approval
        .map(ApprovalDto::validated)
        .transpose()?;
    let fence = dto.fence.map(FenceDto::validated).transpose()?;
    OperationEnvelope::new(request, approval, fence).map_err(|_| CodecError::InvalidProof)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeDto {
    version: u16,
    canonical_request: Vec<u8>,
    input_signature: [u8; 32],
    destructive_approval: Option<ApprovalDto>,
    fence: Option<FenceDto>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalDto {
    authorization_id: String,
    approved_operation_id: String,
    approved_input_signature: [u8; 32],
}

impl From<&DestructiveApproval> for ApprovalDto {
    fn from(value: &DestructiveApproval) -> Self {
        Self {
            authorization_id: value.authorization_id().to_owned(),
            approved_operation_id: value.approved_operation_id().to_owned(),
            approved_input_signature: *value.approved_input_signature().as_bytes(),
        }
    }
}

impl ApprovalDto {
    fn validated(self) -> Result<DestructiveApproval, CodecError> {
        DestructiveApproval::new(
            self.authorization_id,
            self.approved_operation_id,
            InputSignature::from_bytes(self.approved_input_signature),
        )
        .map_err(|_| CodecError::InvalidProof)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FenceDto {
    provider: String,
    receipt_id: String,
    operation_id: String,
    input_signature: [u8; 32],
    fenced_replica: ReplicaDto,
}

impl From<&FenceReference> for FenceDto {
    fn from(value: &FenceReference) -> Self {
        Self {
            provider: value.provider().to_owned(),
            receipt_id: value.receipt_id().to_owned(),
            operation_id: value.operation_id().to_owned(),
            input_signature: *value.input_signature().as_bytes(),
            fenced_replica: ReplicaDto::from(value.fenced_replica()),
        }
    }
}

impl FenceDto {
    fn validated(self) -> Result<FenceReference, CodecError> {
        FenceReference::new(
            self.provider,
            self.receipt_id,
            self.operation_id,
            InputSignature::from_bytes(self.input_signature),
            self.fenced_replica.validated()?,
        )
        .map_err(|_| CodecError::InvalidProof)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplicaDto {
    logical_id: String,
    native_replica_id: Option<String>,
    incarnation: String,
}

impl From<&ReplicaIdentity> for ReplicaDto {
    fn from(value: &ReplicaIdentity) -> Self {
        Self {
            logical_id: value.logical_id().to_owned(),
            native_replica_id: value.native_replica_id().map(ToString::to_string),
            incarnation: value.incarnation().to_owned(),
        }
    }
}

impl ReplicaDto {
    fn validated(self) -> Result<ReplicaIdentity, CodecError> {
        match self.native_replica_id {
            Some(id) => {
                let guid = Guid::parse("fenced replica GUID", &id)
                    .map_err(|_| CodecError::InvalidProof)?;
                if guid.as_str() != id {
                    return Err(CodecError::NonCanonical);
                }
                ReplicaIdentity::observed(self.logical_id, guid, self.incarnation)
                    .map_err(|_| CodecError::InvalidProof)
            }
            None => ReplicaIdentity::desired(self.logical_id, self.incarnation)
                .map_err(|_| CodecError::InvalidProof),
        }
    }
}

fn decode_request(bytes: &[u8]) -> Result<OperationRequest, CodecError> {
    let mut reader = CanonicalReader { remaining: bytes };
    if reader.bytes()? != b"kuberic.sqlserver.operation" {
        return Err(CodecError::Malformed);
    }
    let version = reader.u16()?;
    if version != OPERATION_CONTRACT_VERSION {
        return Err(CodecError::UnsupportedVersion);
    }
    let resource_id = reader.string()?;
    let operation_id = reader.string()?;
    let configuration_id = reader.string()?;
    let source_epoch = reader.u64()?;
    let target_epoch = reader.u64()?;
    let payload = match reader.u8()? {
        1 => {
            let name = AvailabilityGroupName::new(reader.string()?)
                .map_err(|_| CodecError::InvalidField)?;
            let expected_group_id = reader.optional(|reader| reader.guid())?;
            let database_name =
                SqlIdentifier::new(reader.string()?).map_err(|_| CodecError::InvalidField)?;
            let primary = reader.replica()?;
            // Do not allocate from an untrusted member-count prefix.
            if reader.u32()? != u32::from(SUPPORTED_REPLICA_COUNT) {
                return Err(CodecError::InvalidRequest);
            }
            let mut replicas = Vec::with_capacity(usize::from(SUPPORTED_REPLICA_COUNT));
            for _ in 0..SUPPORTED_REPLICA_COUNT {
                replicas.push(ReplicaDescriptor {
                    identity: reader.replica()?,
                    server_name: ServerName::new(reader.string()?)
                        .map_err(|_| CodecError::InvalidField)?,
                    endpoint: Endpoint::new(reader.string()?, reader.u16()?)
                        .map_err(|_| CodecError::InvalidField)?,
                });
            }
            OperationPayload::EnsureAvailabilityGroup {
                name,
                expected_group_id,
                database_name,
                primary,
                replicas,
            }
        }
        2 => OperationPayload::EnsureReplicaJoined {
            availability_group: reader.availability_group()?,
            target: reader.replica()?,
        },
        3 => OperationPayload::EnsureReplicaSeeded {
            availability_group: reader.availability_group()?,
            database: reader.database()?,
            source: reader.replica()?,
            target: reader.replica()?,
        },
        4 => OperationPayload::ReseedReplica {
            availability_group: reader.availability_group()?,
            database: reader.database()?,
            expected_database_id: reader.u32()?,
            expected_database_guid: reader.guid()?,
            expected_recovery_fork_id: reader.guid()?,
            source: reader.replica()?,
            target: reader.replica()?,
        },
        5 => OperationPayload::PlannedSwitchover {
            availability_group: reader.availability_group()?,
            database: reader.lineage()?,
            source: reader.replica()?,
            target: reader.replica()?,
            commit_boundary: reader.progress()?,
        },
        6 => OperationPayload::ForcedFailover {
            availability_group: reader.availability_group()?,
            database: reader.lineage()?,
            source: reader.replica()?,
            target: reader.replica()?,
            last_known_commit: reader.optional(|reader| reader.progress())?,
        },
        _ => return Err(CodecError::UnknownTag),
    };
    if !reader.remaining.is_empty() {
        return Err(CodecError::TrailingData);
    }
    let request = OperationRequest::from_decoded_parts(
        version,
        resource_id,
        operation_id,
        configuration_id,
        source_epoch,
        target_epoch,
        payload,
    )
    .map_err(|_| CodecError::InvalidRequest)?;
    // Constructors normalize GUIDs, DNS names, server names and decimals. The
    // wire must already agree, including the ordering of the bootstrap set.
    if request.canonical_input() != bytes {
        return Err(CodecError::NonCanonical);
    }
    Ok(request)
}

struct CanonicalReader<'a> {
    remaining: &'a [u8],
}

impl<'a> CanonicalReader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], CodecError> {
        let bytes = self.remaining.get(..length).ok_or(CodecError::Malformed)?;
        self.remaining = &self.remaining[length..];
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, CodecError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| CodecError::Malformed)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, CodecError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| CodecError::Malformed)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| CodecError::Malformed)?,
        ))
    }

    fn bytes(&mut self) -> Result<&'a [u8], CodecError> {
        let length = usize::try_from(self.u32()?).map_err(|_| CodecError::TooLarge)?;
        if length > MAX_ENVELOPE_BYTES {
            return Err(CodecError::TooLarge);
        }
        self.take(length)
    }

    fn string(&mut self) -> Result<&'a str, CodecError> {
        std::str::from_utf8(self.bytes()?).map_err(|_| CodecError::InvalidField)
    }

    fn optional<T>(
        &mut self,
        decode: impl FnOnce(&mut Self) -> Result<T, CodecError>,
    ) -> Result<Option<T>, CodecError> {
        match self.u8()? {
            0 => Ok(None),
            1 => decode(self).map(Some),
            _ => Err(CodecError::UnknownTag),
        }
    }

    fn guid(&mut self) -> Result<Guid, CodecError> {
        Guid::parse("operation GUID", self.string()?).map_err(|_| CodecError::InvalidField)
    }

    fn replica(&mut self) -> Result<ReplicaIdentity, CodecError> {
        let logical_id = self.string()?;
        let native_id = self.optional(|reader| reader.guid())?;
        let incarnation = self.string()?;
        match native_id {
            Some(id) => ReplicaIdentity::observed(logical_id, id, incarnation),
            None => ReplicaIdentity::desired(logical_id, incarnation),
        }
        .map_err(|_| CodecError::InvalidField)
    }

    fn availability_group(&mut self) -> Result<AvailabilityGroupIdentity, CodecError> {
        Ok(AvailabilityGroupIdentity {
            name: AvailabilityGroupName::new(self.string()?)
                .map_err(|_| CodecError::InvalidField)?,
            group_id: self.guid()?,
        })
    }

    fn database(&mut self) -> Result<DatabaseIdentity, CodecError> {
        Ok(DatabaseIdentity {
            name: SqlIdentifier::new(self.string()?).map_err(|_| CodecError::InvalidField)?,
            group_database_id: self.guid()?,
        })
    }

    fn lineage(&mut self) -> Result<DatabaseLineage, CodecError> {
        Ok(DatabaseLineage {
            database: self.database()?,
            recovery_fork_id: self.guid()?,
        })
    }

    fn progress(&mut self) -> Result<DecimalProgress, CodecError> {
        DecimalProgress::parse(self.string()?).map_err(|_| CodecError::InvalidField)
    }
}
