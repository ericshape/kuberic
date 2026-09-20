use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlserver_replicated::convergence::{AcceptedAuthority, NativeAction};
use sqlserver_replicated::instance::unix_millis;
use sqlserver_replicated::mutation::AuthorizationVerifier;
use sqlserver_replicated::proof::{
    AuthorityOracle, MAX_PROOF_BYTES, MAX_PROOF_TTL_MILLIS, ProofBundle, ProofClaim, ProofClaims,
    ProofError, ProofKind, ProofReplica, ProofScope, ProofSigner, ProofVerifier,
    SignedAuthorizationVerifier, SignedProof, SignedProofDto, TrustedIssuer,
};
use sqlserver_replicated::{
    AvailabilityGroupIdentity, AvailabilityGroupName, DatabaseIdentity, DatabaseLineage,
    DecimalProgress, DestructiveApproval, Endpoint, FenceReference, Guid, ObservationFailureKind,
    OpaqueId, OperationEnvelope, OperationPayload, OperationRequest, ReplicaDescriptor,
    ReplicaIdentity, ServerName, SqlIdentifier,
};

const NOW: u64 = 1_000_000;
const BINDING: [u8; 32] = [9; 32];
const KINDS: [ProofKind; 4] = [
    ProofKind::Authority,
    ProofKind::Approval,
    ProofKind::Fence,
    ProofKind::Lease,
];

fn signer(kind: ProofKind) -> ProofSigner {
    let (issuer, seed) = match kind {
        ProofKind::Authority => ("authority", 1),
        ProofKind::Approval => ("approval", 2),
        ProofKind::Fence => ("fence", 3),
        ProofKind::Lease => ("lease", 4),
    };
    ProofSigner::from_seed(issuer, kind, &[seed; 32]).unwrap()
}

fn trusted(key: &ProofSigner) -> TrustedIssuer {
    TrustedIssuer {
        issuer_id: key.issuer_id().to_owned(),
        kind: key.kind(),
        public_key: key.public_key(),
    }
}

fn verifier(max_ttl: u64) -> ProofVerifier {
    ProofVerifier::new(
        KINDS
            .into_iter()
            .map(|kind| trusted(&signer(kind)))
            .collect(),
        max_ttl,
    )
    .unwrap()
}

fn guid(id: u32) -> Guid {
    Guid::parse("test", format!("{id:08x}-aaaa-4000-8000-000000000001")).unwrap()
}

fn replica(id: u32) -> ReplicaIdentity {
    ReplicaIdentity::observed(format!("replica-{id}"), guid(id), format!("{id:064x}")).unwrap()
}

fn desired(id: u32) -> ReplicaIdentity {
    ReplicaIdentity::desired(format!("replica-{id}"), format!("{id:064x}")).unwrap()
}

fn descriptor(id: u32) -> ReplicaDescriptor {
    ReplicaDescriptor {
        identity: desired(id),
        server_name: ServerName::new(format!("sql-{id}")).unwrap(),
        endpoint: Endpoint::new(format!("sql-{id}.example"), 5022).unwrap(),
    }
}

fn ag() -> AvailabilityGroupIdentity {
    AvailabilityGroupIdentity {
        name: AvailabilityGroupName::new("group").unwrap(),
        group_id: guid(10),
    }
}

fn database() -> DatabaseIdentity {
    DatabaseIdentity {
        name: SqlIdentifier::new("database").unwrap(),
        group_database_id: guid(20),
    }
}

fn request(tag: u8) -> OperationRequest {
    let lineage = || DatabaseLineage {
        database: database(),
        recovery_fork_id: guid(30),
    };
    let payload = match tag {
        1 => OperationPayload::EnsureAvailabilityGroup {
            name: ag().name,
            expected_group_id: None,
            database_name: database().name,
            write_lease_seconds: 30,
            primary: desired(1),
            replicas: (1..=3).map(descriptor).collect(),
        },
        2 => OperationPayload::EnsureReplicaJoined {
            availability_group: ag(),
            target: replica(2),
        },
        3 => OperationPayload::EnsureReplicaSeeded {
            availability_group: ag(),
            database: database(),
            source: replica(1),
            target: replica(2),
        },
        4 => OperationPayload::ReseedReplica {
            availability_group: ag(),
            database: database(),
            expected_database_id: 5,
            expected_database_guid: guid(21),
            expected_recovery_fork_id: guid(31),
            source: replica(1),
            target: replica(2),
        },
        5 => OperationPayload::PlannedSwitchover {
            availability_group: ag(),
            database: lineage(),
            source: replica(1),
            target: replica(2),
            target_configuration_id: OpaqueId::new("configuration", "configuration-2").unwrap(),
            commit_boundary: DecimalProgress::parse("100").unwrap(),
        },
        6 => OperationPayload::ForcedFailover {
            availability_group: ag(),
            database: lineage(),
            source: replica(1),
            target: replica(2),
            target_configuration_id: OpaqueId::new("configuration", "configuration-2").unwrap(),
            last_known_commit: None,
        },
        _ => unreachable!(),
    };
    OperationRequest::new(
        "resource",
        "operation",
        "configuration-1",
        7,
        if tag >= 5 { 8 } else { 7 },
        payload,
    )
    .unwrap()
}

fn envelope(request: OperationRequest) -> OperationEnvelope {
    let approval = matches!(
        request.payload(),
        OperationPayload::ReseedReplica { .. } | OperationPayload::ForcedFailover { .. }
    )
    .then(|| {
        DestructiveApproval::new(
            "approval-proof",
            request.operation_id(),
            request.input_signature(),
        )
        .unwrap()
    });
    let fenced = match request.payload() {
        OperationPayload::ReseedReplica { target, .. } => Some(target),
        OperationPayload::PlannedSwitchover { source, .. }
        | OperationPayload::ForcedFailover { source, .. } => Some(source),
        _ => None,
    };
    let fence = fenced.map(|identity| {
        FenceReference::new(
            "fence",
            "fence-proof",
            request.operation_id(),
            request.input_signature(),
            identity.clone(),
        )
        .unwrap()
    });
    OperationEnvelope::new(request, approval, fence).unwrap()
}

fn claims(kind: ProofKind, scope: &ProofScope, now: u64) -> ProofClaims {
    let key = signer(kind);
    ProofClaims {
        version: 1,
        proof_id: format!("{}-proof", key.issuer_id()),
        issuer_id: key.issuer_id().to_owned(),
        issued_at_unix_millis: now,
        not_before_unix_millis: now,
        expires_at_unix_millis: now + 60_000,
        scope: scope.clone(),
        claim: match kind {
            ProofKind::Authority => ProofClaim::Authority,
            ProofKind::Approval => ProofClaim::Approval {
                allow_data_loss: true,
                allow_unknown_data_loss: true,
            },
            ProofKind::Fence => ProofClaim::Fence {
                provider: "fence".into(),
                replica: ProofReplica::from_identity(&replica(1)).unwrap(),
                engine_id: "docker-engine-1".into(),
                container_id: replica(1).incarnation().into(),
                removed_at_unix_millis: now,
                final_committed_record: Some("9999999999999999999999999".into()),
            },
            ProofKind::Lease => ProofClaim::Lease {
                group_name: ag().name.to_string(),
                group_id: ag().group_id.to_string(),
                primary: ProofReplica::from_identity(&replica(1)).unwrap(),
                sql_start_time: "2026-09-19T00:00:00.000Z".into(),
                lease_seconds: 30,
            },
        },
    }
}

fn bundle(envelope: &OperationEnvelope, binding: [u8; 32], now: u64) -> ProofBundle {
    let scope = ProofScope::for_operation(envelope.request(), binding);
    let approval = envelope.destructive_approval().map(|_| {
        let mut approval = claims(ProofKind::Approval, &scope, now);
        if matches!(
            envelope.request().payload(),
            OperationPayload::ReseedReplica { .. }
        ) {
            approval.claim = ProofClaim::Approval {
                allow_data_loss: false,
                allow_unknown_data_loss: false,
            };
        }
        approval.expires_at_unix_millis = now + 45_000;
        signer(ProofKind::Approval).sign(approval).unwrap()
    });
    let fence = envelope.fence().map(|reference| {
        let mut fence = claims(ProofKind::Fence, &scope, now);
        if let ProofClaim::Fence {
            replica,
            container_id,
            ..
        } = &mut fence.claim
        {
            *replica = ProofReplica::from_identity(reference.fenced_replica()).unwrap();
            *container_id = replica.incarnation.clone();
        }
        fence.expires_at_unix_millis = now + 30_000;
        signer(ProofKind::Fence).sign(fence).unwrap()
    });
    ProofBundle {
        authority: signer(ProofKind::Authority)
            .sign(claims(ProofKind::Authority, &scope, now))
            .unwrap(),
        approval,
        fence,
    }
}

fn scope() -> ProofScope {
    ProofScope::for_operation(&request(2), BINDING)
}

fn signed(claims: ProofClaims) -> SignedProof {
    signer(claims.claim.kind()).sign(claims).unwrap()
}

fn dto(proof: &SignedProof) -> SignedProofDto {
    serde_json::from_slice(&proof.encode().unwrap()).unwrap()
}

fn untrusted_claims(proof: &SignedProof) -> ProofClaims {
    serde_json::from_slice(&dto(proof).canonical_claims).unwrap()
}

fn raw_signed(canonical_claims: Vec<u8>, domain: &[u8]) -> Vec<u8> {
    let mut message = domain.to_vec();
    message.extend_from_slice(&canonical_claims);
    let signature = SigningKey::from_bytes(&[1; 32])
        .sign(&message)
        .to_bytes()
        .to_vec();
    serde_json::to_vec(&SignedProofDto {
        canonical_claims,
        signature,
    })
    .unwrap()
}

#[test]
fn real_ed25519_round_trip_for_every_purpose() {
    let verifier = verifier(MAX_PROOF_TTL_MILLIS);
    for kind in KINDS {
        let claims = claims(kind, &scope(), NOW);
        let proof = signer(kind).sign(claims.clone()).unwrap();
        let bytes = proof.encode().unwrap();
        let decoded = SignedProof::decode(&bytes).unwrap();
        assert_eq!(decoded, proof);
        assert_eq!(decoded.encode().unwrap(), bytes);
        let verified = verifier.verify(&decoded, &scope(), kind, NOW).unwrap();
        assert_eq!(verified.claims(), &claims);
        assert_eq!(verified.expires_at_unix_millis(), NOW + 60_000);
        assert!(!format!("{proof:?}").contains("canonical_claims"));
    }
}

#[test]
fn trusted_configuration_never_invents_keys_or_cross_purpose_authority() {
    assert!(ProofSigner::from_seed("authority", ProofKind::Authority, &[0; 32]).is_err());
    assert!(ProofSigner::from_seed("", ProofKind::Authority, &[1; 32]).is_err());
    assert!(ProofSigner::from_seed("x".repeat(257), ProofKind::Authority, &[1; 32]).is_err());
    assert!(ProofVerifier::new(vec![], 1).is_err());
    for ttl in [0, MAX_PROOF_TTL_MILLIS + 1, u64::MAX] {
        assert!(ProofVerifier::new(vec![trusted(&signer(ProofKind::Authority))], ttl).is_err());
    }
    for key in [[0; 32], {
        let mut identity = [0; 32];
        identity[0] = 1;
        identity
    }] {
        let mut issuer = trusted(&signer(ProofKind::Authority));
        issuer.public_key = key;
        assert!(matches!(
            ProofVerifier::new(vec![issuer], 1),
            Err(ProofError::InvalidKey)
        ));
    }
    let first = trusted(&signer(ProofKind::Authority));
    let mut duplicate_id = trusted(&signer(ProofKind::Approval));
    duplicate_id.issuer_id = first.issuer_id.clone();
    assert!(ProofVerifier::new(vec![first.clone(), duplicate_id], 1).is_err());
    for kind in [ProofKind::Authority, ProofKind::Fence] {
        let mut duplicate_key = first.clone();
        duplicate_key.issuer_id = "other".into();
        duplicate_key.kind = kind;
        assert!(ProofVerifier::new(vec![first.clone(), duplicate_key], 1).is_err());
    }
    let mut issuer = first;
    issuer.issuer_id = " ".into();
    assert!(ProofVerifier::new(vec![issuer], 1).is_err());
}

#[test]
fn issuer_purpose_signature_and_signature_domain_are_all_authenticated() {
    let authority = claims(ProofKind::Authority, &scope(), NOW);
    let proof = signed(authority.clone());
    let wrong_key = ProofSigner::from_seed("authority", ProofKind::Authority, &[44; 32]).unwrap();
    let wrong_verifier = ProofVerifier::new(vec![trusted(&wrong_key)], 60_000).unwrap();
    assert_eq!(
        wrong_verifier.verify(&proof, &scope(), ProofKind::Authority, NOW),
        Err(ProofError::SignatureMismatch)
    );
    let mut unknown = authority.clone();
    unknown.issuer_id = "not-trusted".into();
    let unknown_signer =
        ProofSigner::from_seed("not-trusted", ProofKind::Authority, &[45; 32]).unwrap();
    assert_eq!(
        verifier(60_000).verify(
            &unknown_signer.sign(unknown).unwrap(),
            &scope(),
            ProofKind::Authority,
            NOW
        ),
        Err(ProofError::UnknownIssuer)
    );
    for wrong_kind in [ProofKind::Approval, ProofKind::Fence, ProofKind::Lease] {
        assert_eq!(
            verifier(60_000).verify(&proof, &scope(), wrong_kind, NOW),
            Err(ProofError::PurposeMismatch)
        );
    }
    let mut wrong_issuer = authority.clone();
    wrong_issuer.issuer_id = "approval".into();
    assert_eq!(
        signer(ProofKind::Authority).sign(wrong_issuer),
        Err(ProofError::IssuerMismatch)
    );
    let mut wrong_kind = authority.clone();
    wrong_kind.claim = ProofClaim::Approval {
        allow_data_loss: false,
        allow_unknown_data_loss: false,
    };
    assert_eq!(
        signer(ProofKind::Authority).sign(wrong_kind),
        Err(ProofError::PurposeMismatch)
    );
    for domain in [b"".as_slice(), b"kuberic.sqlserver.operation".as_slice()] {
        let wire = raw_signed(serde_json::to_vec(&authority).unwrap(), domain);
        let decoded = SignedProof::decode(&wire).unwrap();
        assert_eq!(
            verifier(60_000).verify(&decoded, &scope(), ProofKind::Authority, NOW),
            Err(ProofError::SignatureMismatch)
        );
    }
    let mut wrong_signature = dto(&proof);
    wrong_signature.signature = vec![0; 64];
    let decoded = SignedProof::decode(&serde_json::to_vec(&wrong_signature).unwrap()).unwrap();
    assert_eq!(
        verifier(60_000).verify(&decoded, &scope(), ProofKind::Authority, NOW),
        Err(ProofError::SignatureMismatch)
    );
}

#[test]
fn every_scope_dimension_is_bound_and_changing_signed_claims_invalidates_the_signature() {
    let claims = claims(ProofKind::Authority, &scope(), NOW);
    let proof = signed(claims.clone());
    let verifier = verifier(60_000);
    let changes: &[fn(&mut ProofScope)] = &[
        |scope| scope.resource_id = "other-resource".into(),
        |scope| scope.operation_id = "other-operation".into(),
        |scope| scope.source_configuration_id = "other-configuration".into(),
        |scope| scope.source_epoch -= 1,
        |scope| scope.target_epoch += 1,
        |scope| scope.input_signature[0] ^= 1,
        |scope| scope.authority_binding[0] ^= 1,
    ];
    for change in changes {
        let mut changed = scope();
        change(&mut changed);
        assert_eq!(
            verifier.verify(&proof, &changed, ProofKind::Authority, NOW),
            Err(ProofError::ScopeMismatch)
        );
        let mut tampered = claims.clone();
        tampered.scope = changed.clone();
        let mut wire = dto(&proof);
        wire.canonical_claims = serde_json::to_vec(&tampered).unwrap();
        let decoded = SignedProof::decode(&serde_json::to_vec(&wire).unwrap()).unwrap();
        assert_eq!(
            verifier.verify(&decoded, &changed, ProofKind::Authority, NOW),
            Err(ProofError::SignatureMismatch)
        );
    }
}

#[test]
fn claims_are_not_valid_before_issue_or_start_or_at_expiration() {
    let original = claims(ProofKind::Authority, &scope(), NOW);
    let proof = signed(original.clone());
    let verifier = verifier(60_000);
    assert_eq!(
        verifier.verify(&proof, &scope(), ProofKind::Authority, NOW - 1),
        Err(ProofError::NotYetValid)
    );
    assert!(
        verifier
            .verify(&proof, &scope(), ProofKind::Authority, NOW + 59_999)
            .is_ok()
    );
    for now in [NOW + 60_000, NOW + 60_001, u64::MAX] {
        assert_eq!(
            verifier.verify(&proof, &scope(), ProofKind::Authority, now),
            Err(ProofError::Expired)
        );
    }
    let mut delayed = original.clone();
    delayed.not_before_unix_millis += 1;
    let delayed = signed(delayed);
    assert_eq!(
        verifier.verify(&delayed, &scope(), ProofKind::Authority, NOW),
        Err(ProofError::NotYetValid)
    );
    assert!(
        verifier
            .verify(&delayed, &scope(), ProofKind::Authority, NOW + 1)
            .is_ok()
    );
    let smaller_ttl =
        ProofVerifier::new(vec![trusted(&signer(ProofKind::Authority))], 59_999).unwrap();
    assert_eq!(
        smaller_ttl.verify(&proof, &scope(), ProofKind::Authority, NOW),
        Err(ProofError::TtlExceeded)
    );
    let mutations: &[fn(&mut ProofClaims)] = &[
        |claims| claims.issued_at_unix_millis = 0,
        |claims| claims.issued_at_unix_millis += 1,
        |claims| claims.not_before_unix_millis = claims.expires_at_unix_millis,
        |claims| claims.expires_at_unix_millis = claims.not_before_unix_millis,
        |claims| claims.expires_at_unix_millis = u64::MAX,
    ];
    for mutate in mutations {
        let mut invalid = original.clone();
        mutate(&mut invalid);
        assert!(signer(ProofKind::Authority).sign(invalid).is_err());
    }
    let mut longest = original;
    longest.expires_at_unix_millis = NOW + MAX_PROOF_TTL_MILLIS;
    assert!(signed(longest.clone()).encode().is_ok());
    longest.expires_at_unix_millis += 1;
    assert_eq!(
        signer(ProofKind::Authority).sign(longest),
        Err(ProofError::TtlExceeded)
    );
}

#[test]
fn transport_is_bounded_strict_canonical_and_has_sanitized_diagnostics() {
    let original = signed(claims(ProofKind::Authority, &scope(), NOW));
    let bytes = original.encode().unwrap();
    assert_eq!(
        SignedProof::decode(&vec![b' '; MAX_PROOF_BYTES + 1]),
        Err(ProofError::TooLarge)
    );
    for length in [0, 1, bytes.len() / 2, bytes.len() - 1] {
        assert!(SignedProof::decode(&bytes[..length]).is_err());
    }
    let mut whitespace = bytes.clone();
    whitespace.push(b' ');
    assert_eq!(
        SignedProof::decode(&whitespace),
        Err(ProofError::NonCanonical)
    );
    let mut trailing = bytes.clone();
    trailing.extend_from_slice(b"{}");
    assert_eq!(SignedProof::decode(&trailing), Err(ProofError::Malformed));
    for signature in [vec![], vec![0; 63], vec![0; 65]] {
        let mut malformed = dto(&original);
        malformed.signature = signature;
        assert_eq!(
            SignedProof::decode(&serde_json::to_vec(&malformed).unwrap()),
            Err(ProofError::Malformed)
        );
    }
    let mut oversized = dto(&original);
    oversized.canonical_claims = vec![b'x'; MAX_PROOF_BYTES + 1];
    assert_eq!(
        SignedProof::decode(&serde_json::to_vec(&oversized).unwrap()),
        Err(ProofError::TooLarge)
    );
    let mut unknown: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    unknown["secret-unknown-field"] = json!("private-parser-value");
    let error = SignedProof::decode(&serde_json::to_vec(&unknown).unwrap()).unwrap_err();
    assert_eq!(error, ProofError::Malformed);
    assert!(!format!("{error:?}: {error}").contains("private-parser-value"));
    let duplicate = String::from_utf8(bytes).unwrap().replacen(
        "\"signature\":",
        "\"signature\":[],\"signature\":",
        1,
    );
    assert_eq!(
        SignedProof::decode(duplicate.as_bytes()),
        Err(ProofError::Malformed)
    );
}

#[test]
fn signed_json_rejects_duplicates_unknown_fields_and_unknown_purposes() {
    let authority = claims(ProofKind::Authority, &scope(), NOW);
    for pointer in ["/", "/scope", "/claim"] {
        let mut value = serde_json::to_value(&authority).unwrap();
        let target = if pointer == "/" {
            &mut value
        } else {
            value.pointer_mut(pointer).unwrap()
        };
        target["unknown"] = json!("never-trust-or-echo");
        assert!(serde_json::from_value::<ProofClaims>(value.clone()).is_err());
        let bytes = raw_signed(
            serde_json::to_vec(&value).unwrap(),
            b"kuberic.sqlserver.proof.v1\0",
        );
        let error = SignedProof::decode(&bytes).unwrap_err();
        assert!(!format!("{error:?}: {error}").contains("never-trust-or-echo"));
    }
    let text = serde_json::to_string(&authority).unwrap();
    for (original, duplicate) in [
        ("\"version\":1", "\"version\":1,\"version\":1"),
        (
            "\"source_epoch\":7",
            "\"source_epoch\":7,\"source_epoch\":7",
        ),
        (
            "\"kind\":\"authority\"",
            "\"kind\":\"authority\",\"kind\":\"authority\"",
        ),
    ] {
        let bytes = raw_signed(
            text.replacen(original, duplicate, 1).into_bytes(),
            b"kuberic.sqlserver.proof.v1\0",
        );
        assert!(SignedProof::decode(&bytes).is_err());
    }
    for purpose in ["pod_deleted", "lease_expired", "readiness", "unknown"] {
        let mut value = serde_json::to_value(&authority).unwrap();
        value["claim"]["kind"] = json!(purpose);
        let bytes = raw_signed(
            serde_json::to_vec(&value).unwrap(),
            b"kuberic.sqlserver.proof.v1\0",
        );
        assert_eq!(SignedProof::decode(&bytes), Err(ProofError::Malformed));
    }
    let mut whitespace = serde_json::to_vec(&authority).unwrap();
    whitespace.push(b' ');
    assert_eq!(
        SignedProof::decode(&raw_signed(whitespace, b"kuberic.sqlserver.proof.v1\0")),
        Err(ProofError::NonCanonical)
    );
    let mut future_version = authority;
    future_version.version = 2;
    assert_eq!(
        SignedProof::decode(&raw_signed(
            serde_json::to_vec(&future_version).unwrap(),
            b"kuberic.sqlserver.proof.v1\0"
        )),
        Err(ProofError::UnsupportedVersion)
    );
}

#[test]
fn primitive_dtos_rebuild_native_types_instead_of_trusting_deserialization() {
    assert!(ProofReplica::from_identity(&desired(1)).is_err());
    let valid = ProofReplica::from_identity(&replica(1)).unwrap();
    assert_eq!(valid.to_identity().unwrap(), replica(1));
    for native in ["", "invalid", "00000000-0000-0000-0000-000000000000"] {
        let mut dto = valid.clone();
        dto.native_replica_id = native.into();
        assert!(dto.to_identity().is_err());
    }
    let mut noncanonical = valid.clone();
    noncanonical.native_replica_id.make_ascii_uppercase();
    assert_eq!(noncanonical.to_identity(), Err(ProofError::NonCanonical));
    for field in ["logical_id", "native_replica_id", "incarnation"] {
        let mut missing = serde_json::to_value(&valid).unwrap();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<ProofReplica>(missing).is_err());
    }
    let changes: &[fn(&mut ProofClaims)] = &[
        |claims| claims.proof_id.clear(),
        |claims| claims.issuer_id = "x".repeat(257),
        |claims| claims.scope.resource_id.clear(),
        |claims| claims.scope.operation_id = "x\n".into(),
        |claims| claims.scope.source_configuration_id = " ".into(),
        |claims| claims.scope.authority_binding = [0; 32],
        |claims| claims.scope.input_signature = [0; 32],
        |claims| claims.scope.target_epoch = 0,
    ];
    for change in changes {
        let mut invalid = claims(ProofKind::Authority, &scope(), NOW);
        change(&mut invalid);
        assert!(invalid.validate().is_err());
        assert!(signer(ProofKind::Authority).sign(invalid.clone()).is_err());
        assert!(
            SignedProof::decode(&raw_signed(
                serde_json::to_vec(&invalid).unwrap(),
                b"kuberic.sqlserver.proof.v1\0"
            ))
            .is_err()
        );
    }
}

#[test]
fn fences_require_exact_permanent_docker_container_identity_and_exact_progress() {
    let original = claims(ProofKind::Fence, &scope(), NOW);
    let mutations: &[fn(&mut serde_json::Value)] = &[
        |v| v["claim"]["provider"] = json!("other-provider"),
        |v| v["claim"]["engine_id"] = json!(""),
        |v| v["claim"]["engine_id"] = json!("x".repeat(257)),
        |v| v["claim"]["container_id"] = json!("deadbeef"),
        |v| v["claim"]["container_id"] = json!("A".repeat(64)),
        |v| v["claim"]["container_id"] = json!("0".repeat(64)),
        |v| v["claim"]["container_id"] = json!(replica(2).incarnation()),
        |v| v["claim"]["replica"]["incarnation"] = json!(replica(2).incarnation()),
        |v| v["claim"]["replica"]["native_replica_id"] = json!("not-a-guid"),
        |v| v["claim"]["removed_at_unix_millis"] = json!(NOW + 1),
        |v| v["claim"]["removed_at_unix_millis"] = json!(0),
        |v| v["claim"]["final_committed_record"] = json!("10000000000000000000000000"),
        |v| v["claim"]["final_committed_record"] = json!("01"),
        |v| v["claim"]["final_committed_record"] = json!("-1"),
    ];
    for mutate in mutations {
        let mut value = serde_json::to_value(&original).unwrap();
        mutate(&mut value);
        let invalid: ProofClaims = serde_json::from_value(value).unwrap();
        assert!(signer(ProofKind::Fence).sign(invalid).is_err());
    }
    for progress in [None, Some("0"), Some("9999999999999999999999999")] {
        let mut value = original.clone();
        if let ProofClaim::Fence {
            final_committed_record,
            ..
        } = &mut value.claim
        {
            *final_committed_record = progress.map(str::to_owned);
        }
        let proof = signed(value);
        assert!(
            verifier(60_000)
                .verify(&proof, &scope(), ProofKind::Fence, NOW)
                .is_ok()
        );
    }
}

#[test]
fn lease_statements_bind_a_valid_observed_primary_group_start_time_and_duration() {
    let original = claims(ProofKind::Lease, &scope(), NOW);
    let mutations: &[fn(&mut serde_json::Value)] = &[
        |v| v["claim"]["group_name"] = json!("x".repeat(65)),
        |v| v["claim"]["group_id"] = json!("00000000-0000-0000-0000-000000000000"),
        |v| v["claim"]["primary"]["native_replica_id"] = json!(""),
        |v| v["claim"]["sql_start_time"] = json!(""),
        |v| v["claim"]["sql_start_time"] = json!("x".repeat(257)),
        |v| v["claim"]["lease_seconds"] = json!(4),
        |v| v["claim"]["lease_seconds"] = json!(61),
        |v| v["scope"]["target_epoch"] = json!(8),
    ];
    for mutate in mutations {
        let mut value = serde_json::to_value(&original).unwrap();
        mutate(&mut value);
        let invalid: ProofClaims = serde_json::from_value(value).unwrap();
        assert!(signer(ProofKind::Lease).sign(invalid).is_err());
    }
    for duration in [5, 30, 60] {
        let mut valid = original.clone();
        if let ProofClaim::Lease { lease_seconds, .. } = &mut valid.claim {
            *lease_seconds = duration;
        }
        let proof = signed(valid);
        assert!(
            verifier(60_000)
                .verify(&proof, &scope(), ProofKind::Lease, NOW)
                .is_ok()
        );
    }
}

#[test]
fn all_six_operations_require_authenticated_proofs_and_report_the_minimum_expiry() {
    for tag in 1..=6 {
        let envelope = envelope(request(tag));
        let bundle = bundle(&envelope, BINDING, NOW);
        let verified = verifier(60_000)
            .verify_operation(&envelope, BINDING, &bundle, NOW)
            .unwrap();
        assert_eq!(
            verified.expires_at_unix_millis(),
            NOW + if tag >= 4 { 30_000 } else { 60_000 }
        );
        assert_eq!(verified.approval().is_some(), tag == 4 || tag == 6);
        assert_eq!(verified.fence().is_some(), tag >= 4);
        if let Some(fence) = verified.fence() {
            assert!(matches!(fence.claim, ProofClaim::Fence { .. }));
        }
    }
}

#[test]
fn bound_raw_references_cannot_replace_missing_proofs_and_extra_proofs_are_rejected() {
    let verifier = verifier(60_000);
    for tag in [4, 5, 6] {
        let envelope = envelope(request(tag));
        let mut bundle = bundle(&envelope, BINDING, NOW);
        bundle.fence = None;
        assert_eq!(
            verifier.verify_operation(&envelope, BINDING, &bundle, NOW),
            Err(ProofError::MissingProof)
        );
        if tag != 5 {
            bundle.approval = None;
            assert_eq!(
                verifier.verify_operation(&envelope, BINDING, &bundle, NOW),
                Err(ProofError::MissingProof)
            );
        }
    }
    let envelope = envelope(request(2));
    let clean = bundle(&envelope, BINDING, NOW);
    for extra_kind in [ProofKind::Approval, ProofKind::Fence] {
        let mut extra = clean.clone();
        let proof = signed(claims(extra_kind, &scope(), NOW));
        match extra_kind {
            ProofKind::Approval => extra.approval = Some(proof),
            ProofKind::Fence => extra.fence = Some(proof),
            _ => unreachable!(),
        }
        assert_eq!(
            verifier.verify_operation(&envelope, BINDING, &extra, NOW),
            Err(ProofError::UnexpectedProof)
        );
    }
    let mut false_authority = clean;
    false_authority.authority = signed(claims(ProofKind::Approval, &scope(), NOW));
    assert_eq!(
        verifier.verify_operation(&envelope, BINDING, &false_authority, NOW),
        Err(ProofError::PurposeMismatch)
    );
}

#[test]
fn references_match_authenticated_receipt_id_issuer_provider_and_approval_id() {
    let original = envelope(request(6));
    let bundle = bundle(&original, BINDING, NOW);
    let verifier = verifier(60_000);
    for (provider, id) in [("wrong-provider", "fence-proof"), ("fence", "wrong-proof")] {
        let fence = FenceReference::new(
            provider,
            id,
            original.operation_id(),
            original.input_signature(),
            replica(1),
        )
        .unwrap();
        let changed = OperationEnvelope::new(
            original.request().clone(),
            original.destructive_approval().cloned(),
            Some(fence),
        )
        .unwrap();
        assert_eq!(
            verifier.verify_operation(&changed, BINDING, &bundle, NOW),
            Err(ProofError::ReferenceMismatch)
        );
    }
    let changed = OperationEnvelope::new(
        original.request().clone(),
        Some(
            DestructiveApproval::new(
                "wrong-approval",
                original.operation_id(),
                original.input_signature(),
            )
            .unwrap(),
        ),
        original.fence().cloned(),
    )
    .unwrap();
    assert_eq!(
        verifier.verify_operation(&changed, BINDING, &bundle, NOW),
        Err(ProofError::ReferenceMismatch)
    );
}

#[test]
fn fence_must_authenticate_the_required_native_replica_and_full_incarnation() {
    let verifier = verifier(60_000);
    for tag in [4, 5, 6] {
        let envelope = envelope(request(tag));
        let original = bundle(&envelope, BINDING, NOW);
        for component in ["logical", "native", "incarnation"] {
            let mut claims = untrusted_claims(original.fence.as_ref().unwrap());
            if let ProofClaim::Fence {
                replica,
                container_id,
                ..
            } = &mut claims.claim
            {
                match component {
                    "logical" => replica.logical_id = "wrong-logical".into(),
                    "native" => replica.native_replica_id = guid(99).to_string(),
                    "incarnation" => {
                        replica.incarnation = "f".repeat(64);
                        *container_id = replica.incarnation.clone();
                    }
                    _ => unreachable!(),
                }
            }
            let mut changed = original.clone();
            changed.fence = Some(signed(claims));
            assert_eq!(
                verifier.verify_operation(&envelope, BINDING, &changed, NOW),
                Err(ProofError::ReplicaMismatch)
            );
        }
    }
}

#[test]
fn planned_switchover_requires_authenticated_final_committed_witness() {
    let envelope = envelope(request(5));
    let mut bundle = bundle(&envelope, BINDING, NOW);
    let mut claims = untrusted_claims(bundle.fence.as_ref().unwrap());
    if let ProofClaim::Fence {
        final_committed_record,
        ..
    } = &mut claims.claim
    {
        *final_committed_record = None;
    }
    bundle.fence = Some(signed(claims));
    assert_eq!(
        verifier(60_000).verify_operation(&envelope, BINDING, &bundle, NOW),
        Err(ProofError::MissingCommitBoundary)
    );
}

#[test]
fn forced_failover_requires_both_relevant_data_loss_opt_ins() {
    for known in [false, true] {
        let original = request(6);
        let mut payload = original.payload().clone();
        if let OperationPayload::ForcedFailover {
            last_known_commit, ..
        } = &mut payload
        {
            *last_known_commit = known.then(|| DecimalProgress::parse("200").unwrap());
        }
        let request =
            OperationRequest::new("resource", "operation", "configuration-1", 7, 8, payload)
                .unwrap();
        let envelope = envelope(request);
        let original = bundle(&envelope, BINDING, NOW);
        for (allow_data_loss, allow_unknown_data_loss) in
            [(false, false), (true, false), (true, true)]
        {
            let mut changed = original.clone();
            let mut approval = untrusted_claims(changed.approval.as_ref().unwrap());
            approval.claim = ProofClaim::Approval {
                allow_data_loss,
                allow_unknown_data_loss,
            };
            changed.approval = Some(signed(approval));
            let result = verifier(60_000).verify_operation(&envelope, BINDING, &changed, NOW);
            if allow_data_loss && (known || allow_unknown_data_loss) {
                assert!(result.is_ok());
            } else {
                assert_eq!(result, Err(ProofError::DataLossNotAuthorized));
            }
        }
    }
    let mut invalid = claims(ProofKind::Approval, &scope(), NOW);
    invalid.claim = ProofClaim::Approval {
        allow_data_loss: false,
        allow_unknown_data_loss: true,
    };
    assert_eq!(
        signer(ProofKind::Approval).sign(invalid),
        Err(ProofError::InvalidClaims)
    );
}

#[test]
fn reseed_approval_does_not_authorize_a_data_loss_primary_transition() {
    let reseed = envelope(request(4));
    let mut bundle = bundle(&reseed, BINDING, NOW);
    let forced = envelope(request(6));
    assert_eq!(
        verifier(60_000).verify_operation(&forced, BINDING, &bundle, NOW),
        Err(ProofError::ScopeMismatch)
    );
    let mut approval = untrusted_claims(bundle.approval.as_ref().unwrap());
    approval.claim = ProofClaim::Approval {
        allow_data_loss: true,
        allow_unknown_data_loss: true,
    };
    bundle.approval = Some(signed(approval));
    assert_eq!(
        verifier(60_000).verify_operation(&reseed, BINDING, &bundle, NOW),
        Err(ProofError::DataLossNotAuthorized)
    );
}

struct CurrentAuthority {
    expected: ProofScope,
    revoked: AtomicBool,
    deny_fence: bool,
    calls: AtomicUsize,
}

impl AuthorityOracle for CurrentAuthority {
    fn check(&self, scope: &ProofScope, claim: &ProofClaim) -> Result<(), ProofError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.revoked.load(Ordering::SeqCst)
            || scope != &self.expected
            || (self.deny_fence && matches!(claim, ProofClaim::Fence { .. }))
        {
            Err(ProofError::AuthorityDenied)
        } else {
            Ok(())
        }
    }
}

fn authority() -> AcceptedAuthority {
    AcceptedAuthority {
        resource_id: OpaqueId::new("resource", "resource").unwrap(),
        configuration_id: OpaqueId::new("configuration", "configuration-1").unwrap(),
        epoch: 7,
        primary: desired(1),
        replicas: (1..=3).map(descriptor).collect(),
    }
}

#[tokio::test]
async fn authorization_rechecks_every_authenticated_claim_and_observes_oracle_revocation() {
    let authority = authority();
    let binding = Sha256::digest(authority.canonical_binding()).into();
    let envelope = envelope(request(4));
    let now = unix_millis().unwrap();
    let oracle = Arc::new(CurrentAuthority {
        expected: ProofScope::for_operation(envelope.request(), binding),
        revoked: AtomicBool::new(false),
        deny_fence: false,
        calls: AtomicUsize::new(0),
    });
    let verifier = SignedAuthorizationVerifier::new(
        verifier(60_000),
        bundle(&envelope, binding, now),
        oracle.clone(),
    );
    let action = NativeAction::GrantSeeding {
        availability_group: ag(),
        target: replica(2),
    };
    verifier
        .verify_request(&envelope, &authority)
        .await
        .unwrap();
    assert_eq!(oracle.calls.load(Ordering::SeqCst), 3);
    verifier
        .verify(&envelope, &authority, &action)
        .await
        .unwrap();
    assert_eq!(oracle.calls.load(Ordering::SeqCst), 6);
    oracle.revoked.store(true, Ordering::SeqCst);
    for error in [
        verifier
            .verify_request(&envelope, &authority)
            .await
            .unwrap_err(),
        verifier
            .verify(&envelope, &authority, &action)
            .await
            .unwrap_err(),
    ] {
        assert_eq!(error.kind, ObservationFailureKind::PermissionDenied);
    }
    assert_eq!(oracle.calls.load(Ordering::SeqCst), 8);
}

#[tokio::test]
async fn oracle_fence_denial_and_authority_binding_changes_fail_without_cached_authorization() {
    let mut authority = authority();
    let binding = Sha256::digest(authority.canonical_binding()).into();
    let envelope = envelope(request(4));
    let oracle = Arc::new(CurrentAuthority {
        expected: ProofScope::for_operation(envelope.request(), binding),
        revoked: AtomicBool::new(false),
        deny_fence: true,
        calls: AtomicUsize::new(0),
    });
    let verifier = SignedAuthorizationVerifier::new(
        verifier(60_000),
        bundle(&envelope, binding, unix_millis().unwrap()),
        oracle.clone(),
    );
    let denied = verifier
        .verify_request(&envelope, &authority)
        .await
        .unwrap_err();
    assert_eq!(denied.kind, ObservationFailureKind::PermissionDenied);
    assert_eq!(oracle.calls.load(Ordering::SeqCst), 3);
    authority.replicas[2].endpoint = Endpoint::new("replacement.example", 5022).unwrap();
    assert!(
        verifier
            .verify_request(&envelope, &authority)
            .await
            .is_err()
    );
    assert_eq!(oracle.calls.load(Ordering::SeqCst), 3);
}
