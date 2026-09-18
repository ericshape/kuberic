pub mod config;
pub mod error;
pub mod operation;
pub mod types;

pub use config::{
    AvailabilityMode, ClusterType, Edition, FailoverMode, MutationMode, SeedingMode,
    SqlServerSupportConfig, SUPPORTED_DATABASE_COUNT, SUPPORTED_ENGINE_MAJOR,
    SUPPORTED_REPLICA_COUNT, SUPPORTED_REPLICA_COUNT_TEXT, SUPPORTED_REQUIRED_SECONDARIES,
};
pub use error::ContractError;
pub use operation::{
    DestructiveApproval, FenceReference, InputSignature, OperationEnvelope, OperationPayload,
    OperationRecord, OperationRequest, ReplayDisposition, OPERATION_CONTRACT_VERSION,
};
pub use types::{
    AvailabilityGroupIdentity, AvailabilityGroupName, DatabaseIdentity, DatabaseLineage,
    DecimalProgress, Endpoint, Guid, NativeProgress, NativeRole, Observation, ObservationFailure,
    ObservationFailureKind, OpaqueId, PinnedImage, ReplicaDescriptor, ReplicaIdentity, SecretRef,
    ServerName, SqlIdentifier,
};
