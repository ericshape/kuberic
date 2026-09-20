use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlserver_replicated::codec::{
    CodecError, MAX_ENVELOPE_BYTES, decode_envelope, encode_envelope,
};
use sqlserver_replicated::{
    AvailabilityGroupIdentity, AvailabilityGroupName, DatabaseIdentity, DatabaseLineage,
    DecimalProgress, DestructiveApproval, Endpoint, FenceReference, Guid, OperationEnvelope,
    OperationPayload, OperationRequest, ReplicaDescriptor, ReplicaIdentity, ServerName,
    SqlIdentifier,
};

fn guid(value: u32) -> Guid {
    Guid::parse("test", format!("{value:08x}-0000-4000-8000-000000000001")).unwrap()
}

fn replica(value: u32) -> ReplicaIdentity {
    ReplicaIdentity::observed(
        format!("replica-{value}"),
        guid(value),
        format!("pod-{value}"),
    )
    .unwrap()
}

fn desired(value: u32) -> ReplicaIdentity {
    ReplicaIdentity::desired(format!("replica-{value}"), format!("pod-{value}")).unwrap()
}

fn descriptor(value: u32) -> ReplicaDescriptor {
    ReplicaDescriptor {
        identity: desired(value),
        server_name: ServerName::new(format!("sql-{value}")).unwrap(),
        endpoint: Endpoint::new(format!("sql-{value}.default.svc"), 5022).unwrap(),
    }
}

fn ag() -> AvailabilityGroupIdentity {
    AvailabilityGroupIdentity {
        name: AvailabilityGroupName::new("ag").unwrap(),
        group_id: guid(0xab),
    }
}

fn database() -> DatabaseIdentity {
    DatabaseIdentity {
        name: SqlIdentifier::new("database").unwrap(),
        group_database_id: guid(20),
    }
}

fn payloads() -> Vec<OperationPayload> {
    vec![
        OperationPayload::EnsureAvailabilityGroup {
            name: ag().name,
            expected_group_id: Some(ag().group_id),
            database_name: database().name,
            primary: desired(2),
            replicas: vec![descriptor(1), descriptor(2), descriptor(3)],
        },
        OperationPayload::EnsureReplicaJoined {
            availability_group: ag(),
            target: replica(2),
        },
        OperationPayload::EnsureReplicaSeeded {
            availability_group: ag(),
            database: database(),
            source: replica(1),
            target: replica(2),
        },
        OperationPayload::ReseedReplica {
            availability_group: ag(),
            database: database(),
            expected_database_id: u32::MAX,
            expected_database_guid: guid(21),
            expected_recovery_fork_id: guid(30),
            source: replica(1),
            target: replica(2),
        },
        OperationPayload::PlannedSwitchover {
            availability_group: ag(),
            database: DatabaseLineage {
                database: database(),
                recovery_fork_id: guid(30),
            },
            source: replica(1),
            target: replica(2),
            commit_boundary: DecimalProgress::parse("9999999999999999999999999").unwrap(),
        },
        OperationPayload::ForcedFailover {
            availability_group: ag(),
            database: DatabaseLineage {
                database: database(),
                recovery_fork_id: guid(30),
            },
            source: replica(1),
            target: replica(2),
            last_known_commit: Some(DecimalProgress::parse("9999999999999999999999999").unwrap()),
        },
    ]
}

fn envelope(payload: OperationPayload) -> OperationEnvelope {
    let request = OperationRequest::new(
        "ns/resource",
        "operation-1",
        "configuration-1",
        u64::MAX - 1,
        u64::MAX,
        payload,
    )
    .unwrap();
    let approval = match request.payload() {
        OperationPayload::ReseedReplica { .. } | OperationPayload::ForcedFailover { .. } => Some(
            DestructiveApproval::new(
                "approval-7",
                request.operation_id(),
                request.input_signature(),
            )
            .unwrap(),
        ),
        _ => None,
    };
    let fenced = match request.payload() {
        OperationPayload::ReseedReplica { target, .. } => Some(target.clone()),
        OperationPayload::PlannedSwitchover { source, .. }
        | OperationPayload::ForcedFailover { source, .. } => Some(source.clone()),
        _ => None,
    };
    let fence = fenced.map(|replica| {
        FenceReference::new(
            "container-runtime",
            "receipt-9",
            request.operation_id(),
            request.input_signature(),
            replica,
        )
        .unwrap()
    });
    OperationEnvelope::new(request, approval, fence).unwrap()
}

fn dto(envelope: &OperationEnvelope) -> Value {
    serde_json::from_slice(&encode_envelope(envelope).unwrap()).unwrap()
}

fn decode(dto: &Value) -> Result<OperationEnvelope, CodecError> {
    decode_envelope(&serde_json::to_vec(dto).unwrap())
}

fn raw(dto: &Value) -> Vec<u8> {
    serde_json::from_value(dto["canonical_request"].clone()).unwrap()
}

fn replace_request(dto: &mut Value, bytes: &[u8]) {
    dto["canonical_request"] = json!(bytes);
    dto["input_signature"] = json!(<[u8; 32]>::from(Sha256::digest(bytes)));
}

fn skip_string(bytes: &[u8], offset: &mut usize) {
    let len = u32::from_be_bytes(bytes[*offset..*offset + 4].try_into().unwrap()) as usize;
    *offset += 4 + len;
}

fn payload_offset(bytes: &[u8]) -> usize {
    let mut offset = 0;
    skip_string(bytes, &mut offset);
    offset += 2;
    for _ in 0..3 {
        skip_string(bytes, &mut offset);
    }
    offset + 16
}

fn skip_replica(bytes: &[u8], offset: &mut usize) {
    skip_string(bytes, offset);
    let has_native_id = bytes[*offset] == 1;
    *offset += 1;
    if has_native_id {
        skip_string(bytes, offset);
    }
    skip_string(bytes, offset);
}

#[test]
fn all_six_variants_round_trip_complete_requests_and_proof_references() {
    for payload in payloads() {
        let original = envelope(payload);
        let encoded = encode_envelope(&original).unwrap();
        assert!(encoded.len() <= MAX_ENVELOPE_BYTES);
        let decoded = decode_envelope(&encoded).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.canonical_input(), original.canonical_input());
        assert_eq!(decoded.input_signature(), original.input_signature());
        assert_eq!(decoded.effect_signature(), original.effect_signature());
        assert_eq!(encode_envelope(&decoded).unwrap(), encoded);
    }
    let mut optional = payloads().remove(5);
    if let OperationPayload::ForcedFailover {
        last_known_commit, ..
    } = &mut optional
    {
        *last_known_commit = None;
    }
    let original = envelope(optional);
    assert_eq!(
        decode_envelope(&encode_envelope(&original).unwrap()).unwrap(),
        original
    );
}

#[test]
fn bootstrap_replica_sets_encode_identically_regardless_of_input_order() {
    let original = envelope(payloads().remove(0));
    let mut payload = original.request().payload().clone();
    if let OperationPayload::EnsureAvailabilityGroup { replicas, .. } = &mut payload {
        replicas.reverse();
    }
    let reordered = envelope(payload);
    assert_eq!(encode_envelope(&original), encode_envelope(&reordered));
    assert_eq!(original.canonical_input(), reordered.canonical_input());
}

#[test]
fn binary_bootstrap_members_must_already_be_sorted_and_count_is_bounded() {
    let original = envelope(payloads().remove(0));
    let mut value = dto(&original);
    let bytes = raw(&value);
    let mut offset = payload_offset(&bytes) + 1;
    skip_string(&bytes, &mut offset);
    assert_eq!(bytes[offset], 1);
    offset += 1;
    skip_string(&bytes, &mut offset);
    skip_string(&bytes, &mut offset);
    skip_replica(&bytes, &mut offset);
    let count_offset = offset;
    offset += 4;
    let member_start = offset;
    let mut members = Vec::new();
    for _ in 0..3 {
        let start = offset;
        skip_replica(&bytes, &mut offset);
        skip_string(&bytes, &mut offset);
        skip_string(&bytes, &mut offset);
        offset += 2;
        members.push(&bytes[start..offset]);
    }
    let mut unsorted = bytes[..member_start].to_vec();
    for member in members.into_iter().rev() {
        unsorted.extend_from_slice(member);
    }
    replace_request(&mut value, &unsorted);
    assert_eq!(decode(&value), Err(CodecError::NonCanonical));

    let mut oversized = bytes;
    oversized[count_offset..count_offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    replace_request(&mut value, &oversized);
    assert_eq!(decode(&value), Err(CodecError::InvalidRequest));
}

#[test]
fn wrapper_is_strict_bounded_and_rejects_trailing_data() {
    let original = envelope(payloads().remove(3));
    let encoded = encode_envelope(&original).unwrap();
    assert_eq!(
        decode_envelope(&vec![b' '; MAX_ENVELOPE_BYTES + 1]),
        Err(CodecError::TooLarge)
    );
    for length in 0..encoded.len() {
        assert!(decode_envelope(&encoded[..length]).is_err(), "{length}");
    }
    let mut trailing = encoded.clone();
    trailing.extend_from_slice(b"{}");
    assert_eq!(decode_envelope(&trailing), Err(CodecError::Malformed));
    for path in ["root", "destructive_approval", "fence", "replica"] {
        let mut unknown = dto(&original);
        let object = match path {
            "root" => &mut unknown,
            "replica" => &mut unknown["fence"]["fenced_replica"],
            other => &mut unknown[other],
        };
        object["unexpected"] = json!("credential-not-to-echo");
        let error = decode(&unknown).unwrap_err();
        assert_eq!(error, CodecError::Malformed);
        assert!(!format!("{error:?}: {error}").contains("credential-not-to-echo"));
    }
    let text = String::from_utf8(encoded).unwrap();
    let duplicate = text.replacen("\"version\":2", "\"version\":2,\"version\":2", 1);
    assert_eq!(
        decode_envelope(duplicate.as_bytes()),
        Err(CodecError::Malformed)
    );
    let duplicate = text.replacen(
        "\"receipt_id\":\"receipt-9\"",
        "\"receipt_id\":\"receipt-9\",\"receipt_id\":\"receipt-9\"",
        1,
    );
    assert_eq!(
        decode_envelope(duplicate.as_bytes()),
        Err(CodecError::Malformed)
    );
}

#[test]
fn old_and_unknown_versions_are_never_silently_upgraded() {
    let original = envelope(payloads().remove(1));
    for version in [0, 1, 3, u16::MAX] {
        let mut value = dto(&original);
        value["version"] = json!(version);
        assert_eq!(decode(&value), Err(CodecError::UnsupportedVersion));
        let mut value = dto(&original);
        let mut bytes = raw(&value);
        let mut offset = 0;
        skip_string(&bytes, &mut offset);
        bytes[offset..offset + 2].copy_from_slice(&version.to_be_bytes());
        replace_request(&mut value, &bytes);
        assert_eq!(decode(&value), Err(CodecError::UnsupportedVersion));
    }
}

#[test]
fn binary_reader_rejects_truncation_lengths_tags_and_extra_bytes() {
    let original = envelope(payloads().remove(1));
    let value = dto(&original);
    let bytes = raw(&value);
    for length in 0..bytes.len() {
        let mut truncated = value.clone();
        replace_request(&mut truncated, &bytes[..length]);
        assert!(decode(&truncated).is_err(), "{length}");
    }
    let mut huge = bytes.clone();
    huge[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    let mut corrupt = value.clone();
    replace_request(&mut corrupt, &huge);
    assert_eq!(decode(&corrupt), Err(CodecError::TooLarge));

    let mut unknown_tag = bytes.clone();
    unknown_tag[payload_offset(&bytes)] = 255;
    replace_request(&mut corrupt, &unknown_tag);
    assert_eq!(decode(&corrupt), Err(CodecError::UnknownTag));

    let mut trailing = bytes;
    trailing.push(0);
    replace_request(&mut corrupt, &trailing);
    assert_eq!(decode(&corrupt), Err(CodecError::TrailingData));

    let bootstrap = envelope(payloads().remove(0));
    let mut value = dto(&bootstrap);
    let mut bytes = raw(&value);
    let mut offset = payload_offset(&bytes) + 1;
    skip_string(&bytes, &mut offset);
    bytes[offset] = 2;
    replace_request(&mut value, &bytes);
    assert_eq!(decode(&value), Err(CodecError::UnknownTag));
}

#[test]
fn digests_and_canonical_native_fields_are_checked_without_normalizing_wire_input() {
    let original = envelope(payloads().remove(1));
    let mut value = dto(&original);
    value["input_signature"][0] = json!(256);
    assert_eq!(decode(&value), Err(CodecError::Malformed));
    value["input_signature"] = json!(vec![0_u8; 32]);
    assert_eq!(decode(&value), Err(CodecError::IntegrityMismatch));
    let mut value = dto(&original);
    value["canonical_request"][4] = json!(0);
    assert_eq!(decode(&value), Err(CodecError::IntegrityMismatch));

    for (replacement, expected) in [
        (b'z', CodecError::InvalidField),
        (b'A', CodecError::NonCanonical),
    ] {
        let mut value = dto(&original);
        let mut bytes = raw(&value);
        let position = bytes
            .windows(36)
            .position(|window| window == ag().group_id.as_str().as_bytes())
            .unwrap();
        bytes[position + 6] = replacement;
        replace_request(&mut value, &bytes);
        assert_eq!(decode(&value), Err(expected));
    }
    let mut value = dto(&original);
    let mut bytes = raw(&value);
    let offset = payload_offset(&bytes) + 5;
    bytes[offset] = 0xff;
    replace_request(&mut value, &bytes);
    assert_eq!(decode(&value), Err(CodecError::InvalidField));

    let original = envelope(payloads().remove(4));
    let mut value = dto(&original);
    let mut bytes = raw(&value);
    let last_number = bytes.len() - 25;
    bytes[last_number] = b'0';
    replace_request(&mut value, &bytes);
    assert_eq!(decode(&value), Err(CodecError::NonCanonical));
}

#[test]
fn proof_signatures_operation_ids_and_incarnations_are_not_reconstructed() {
    let original = envelope(payloads().remove(3));
    for (proof, field) in [
        ("destructive_approval", "approved_input_signature"),
        ("fence", "input_signature"),
    ] {
        let mut value = dto(&original);
        value[proof][field] = json!(vec![0_u8; 32]);
        assert_eq!(decode(&value), Err(CodecError::InvalidProof));
    }
    for (proof, field) in [
        ("destructive_approval", "approved_operation_id"),
        ("fence", "operation_id"),
    ] {
        let mut value = dto(&original);
        value[proof][field] = json!("another-operation");
        assert_eq!(decode(&value), Err(CodecError::InvalidProof));
    }
    let mut value = dto(&original);
    value["fence"]["fenced_replica"]["incarnation"] = json!("replacement-pod");
    assert_eq!(decode(&value), Err(CodecError::InvalidProof));
    value["fence"]["fenced_replica"]["native_replica_id"] = json!("bad-guid");
    assert_eq!(decode(&value), Err(CodecError::InvalidProof));
    for proof in ["destructive_approval", "fence"] {
        let mut value = dto(&original);
        value[proof] = Value::Null;
        assert_eq!(decode(&value), Err(CodecError::InvalidProof));
    }
    let mut join = dto(&envelope(payloads().remove(1)));
    join["destructive_approval"] = dto(&original)["destructive_approval"].clone();
    assert_eq!(decode(&join), Err(CodecError::InvalidProof));
}
