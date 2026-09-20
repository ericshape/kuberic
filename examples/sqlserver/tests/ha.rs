use std::collections::BTreeSet;

use sqlserver_replicated::ha::{
    FenceEvidence, HaAction, HaContext, HaDecision, HaNode, HaPolicy, HealthSample, plan,
};
use sqlserver_replicated::observation::{NativeProvenance, RecoveryLineageObservation};
use sqlserver_replicated::{
    DatabaseLineage, DecimalProgress, DestructiveApproval, FenceReference, NativeRole, Observation,
    ObservationFailure, ObservationFailureKind, OpaqueId, OperationEnvelope, OperationPayload,
    OperationRequest, ReplicaIdentity,
};

#[path = "support/convergence.rs"]
mod fixtures;
use fixtures::*;

const NOW: u64 = 100_000;
const AT: u64 = 99_900;
const FENCED: u64 = 99_000;

fn progress(value: u64) -> DecimalProgress {
    DecimalProgress::parse(&value.to_string()).unwrap()
}

fn context() -> HaContext {
    let source = authority();
    let mut target = source.clone();
    target.configuration_id = OpaqueId::new("configuration", "configuration-2").unwrap();
    target.epoch += 1;
    target.primary = desired(2);
    HaContext { source, target }
}

fn operation(forced: bool) -> OperationEnvelope {
    let database = DatabaseLineage {
        database: database(),
        recovery_fork_id: guid(300),
    };
    let target_configuration_id = context().target.configuration_id;
    envelope(if forced {
        OperationPayload::ForcedFailover {
            availability_group: ag(),
            database,
            source: observed(1),
            target: observed(2),
            target_configuration_id,
            last_known_commit: Some(progress(9999)),
        }
    } else {
        OperationPayload::PlannedSwitchover {
            availability_group: ag(),
            database,
            source: observed(1),
            target: observed(2),
            target_configuration_id,
            commit_boundary: progress(400),
        }
    })
}

fn fence() -> FenceEvidence {
    FenceEvidence {
        source: observed(1),
        proof_id: "structural-only".into(),
        fenced_at_unix_millis: FENCED,
        expires_at_unix_millis: NOW + 120_000,
        final_committed_record: Some(progress(500)),
    }
}

fn stamp<T>(observation: &mut Observation<T>, at: u64) {
    match observation {
        Observation::Present {
            observed_at_unix_millis,
            ..
        }
        | Observation::Absent {
            observed_at_unix_millis,
        } => *observed_at_unix_millis = at,
        Observation::Failed(failure) => failure.observed_at_unix_millis = at,
    }
}

fn failure<T>(kind: ObservationFailureKind) -> Observation<T> {
    Observation::Failed(ObservationFailure {
        kind,
        message: "synthetic native failure".into(),
        observed_at_unix_millis: AT,
    })
}

fn health(node: &mut HaNode) -> &mut HealthSample {
    match &mut node.health {
        Observation::Present { value, .. } => value,
        _ => panic!("health unavailable"),
    }
}

fn role(node: &mut HaNode, role: NativeRole) {
    set_role(&mut node.node, Some(role.clone()));
    for state in &mut group(&mut node.node).databases[0].replicas {
        if state.provenance == NativeProvenance::Local {
            state.is_primary_replica = Some(role == NativeRole::Primary);
        }
    }
}

fn fork(node: &mut HaNode, id: u32) {
    database_probe(&mut node.node).recovery_fork_id = guid(id);
    let database = &mut group(&mut node.node).databases[0];
    database
        .local
        .as_mut()
        .unwrap()
        .recovery
        .as_mut()
        .unwrap()
        .recovery_fork_guid = Some(guid(id));
    for state in &mut database.replicas {
        if let RecoveryLineageObservation::Local { value } = &mut state.lineage {
            value.recovery_fork_id = guid(id);
        }
    }
}

fn nodes() -> Vec<HaNode> {
    let mut nodes = (1..=3)
        .map(|id| {
            let mut node = existing(id, true);
            let local = probe(id, true);
            install_database(&mut node, id, Some(local));
            stamp(&mut node.instance, AT);
            stamp(&mut node.database, AT);
            snapshot(&mut node).observed_at_unix_millis = AT;
            stamp(&mut snapshot(&mut node).availability_group, AT);
            let group = group(&mut node);
            group.configuration_sequence = progress(42);
            group.databases[0].replicas[0].progress.committed_record = Some(progress(600));
            HaNode {
                node,
                health: Observation::Present {
                    value: HealthSample {
                        sql_utc_millis: AT,
                        system: 1,
                        resource: 2,
                        query_processing: 1,
                        configuration_commit_age_millis: None,
                        db_failover: true,
                    },
                    observed_at_unix_millis: AT,
                },
            }
        })
        .collect::<Vec<_>>();
    nodes[0].node.instance = failure(ObservationFailureKind::Unreachable);
    nodes[0].node.database = failure(ObservationFailureKind::Unreachable);
    nodes[0].health = failure(ObservationFailureKind::Unreachable);
    nodes
}

fn decide(nodes: &[HaNode], keys: &BTreeSet<String>, prepared: bool) -> HaDecision {
    plan(
        &operation(false),
        &context(),
        nodes,
        &fence(),
        keys,
        prepared,
        NOW,
        &HaPolicy::default(),
    )
}

fn refuse(decision: HaDecision) {
    assert!(
        matches!(decision, HaDecision::Wait(_) | HaDecision::Unsafe(_)),
        "{decision:?}"
    );
}

fn unsafe_decision(decision: HaDecision) {
    assert!(matches!(decision, HaDecision::Unsafe(_)), "{decision:?}");
}

fn action(decision: HaDecision) -> HaAction {
    match decision {
        HaDecision::Execute(action) => action,
        other => panic!("expected executable action, got {other:?}"),
    }
}

fn offline() -> HaAction {
    HaAction::OfflineSecondary {
        availability_group: ag(),
        replica: observed(3),
    }
}

fn start() -> HaAction {
    HaAction::StartSecondary {
        availability_group: ag(),
        replica: observed(3),
    }
}

fn completed_keys() -> BTreeSet<String> {
    BTreeSet::from(["promote".into(), offline().key(), start().key()])
}

#[test]
fn context_binds_exact_next_authority_and_canonical_membership() {
    let ctx = context();
    ctx.validate(operation(false).request()).unwrap();
    let mut shuffled = ctx.clone();
    shuffled.source.replicas.reverse();
    shuffled.target.replicas.rotate_left(1);
    assert_eq!(ctx.binding(), shuffled.binding());
    shuffled.validate(operation(false).request()).unwrap();
    let changes: &[fn(&mut HaContext)] = &[
        |ctx| ctx.source.resource_id = OpaqueId::new("resource", "foreign").unwrap(),
        |ctx| ctx.target.resource_id = OpaqueId::new("resource", "foreign").unwrap(),
        |ctx| ctx.source.configuration_id = OpaqueId::new("configuration", "foreign").unwrap(),
        |ctx| ctx.target.configuration_id = OpaqueId::new("configuration", "foreign").unwrap(),
        |ctx| ctx.source.epoch += 1,
        |ctx| ctx.target.epoch += 1,
        |ctx| ctx.source.primary = desired(2),
        |ctx| ctx.target.primary = desired(3),
        |ctx| ctx.source.primary = observed(1),
        |ctx| ctx.target.replicas[1].identity = observed(2),
        |ctx| {
            ctx.target.replicas[2].identity =
                ReplicaIdentity::desired("replica-3", "new-container").unwrap()
        },
        |ctx| {
            ctx.target.replicas.pop();
        },
        |ctx| ctx.source.replicas[2] = ctx.source.replicas[1].clone(),
        |ctx| {
            ctx.target.replicas[2].endpoint =
                sqlserver_replicated::Endpoint::new("other", 5022).unwrap()
        },
    ];
    for change in changes {
        let mut changed = ctx.clone();
        change(&mut changed);
        assert!(changed.validate(operation(false).request()).is_err());
        assert_ne!(ctx.binding(), changed.binding());
    }
    assert!(ctx.validate(envelope(join_payload()).request()).is_err());
}

#[test]
fn policy_has_bounded_windows_supported_thresholds_and_strict_lease_margin() {
    let default = HaPolicy::default();
    default.validate().unwrap();
    assert_eq!(
        (default.max_age_millis, default.max_clock_skew_millis),
        (60_000, 2000)
    );
    for threshold in 3..=5 {
        HaPolicy {
            health_threshold: threshold,
            ..default.clone()
        }
        .validate()
        .unwrap();
    }
    let invalid: &[fn(&mut HaPolicy)] = &[
        |p| p.max_age_millis = 0,
        |p| p.max_age_millis = u64::MAX,
        |p| p.max_clock_skew_millis = u64::MAX,
        |p| p.configuration_commit_timeout_millis = 0,
        |p| p.configuration_commit_timeout_millis = u64::MAX,
        |p| p.lease_seconds = 4,
        |p| p.lease_seconds = 61,
        |p| p.renewal_interval_millis = 0,
        |p| p.renewal_interval_millis = u64::MAX,
        |p| p.command_timeout_millis = 0,
        |p| p.command_timeout_millis = u64::MAX,
        |p| p.command_timeout_millis = 23_000,
        |p| p.health_threshold = 2,
        |p| p.health_threshold = 6,
    ];
    for change in invalid {
        let mut policy = default.clone();
        change(&mut policy);
        assert!(policy.validate().is_err(), "{policy:?}");
        refuse(plan(
            &operation(false),
            &context(),
            &nodes(),
            &fence(),
            &BTreeSet::new(),
            false,
            NOW,
            &policy,
        ));
    }
}

#[test]
fn planned_and_authorized_forced_promotion_use_two_survivors_and_native_sequence() {
    for forced in [false, true] {
        let mut receipt = fence();
        if forced {
            receipt.final_committed_record = None;
        }
        let result = plan(
            &operation(forced),
            &context(),
            &nodes(),
            &receipt,
            &BTreeSet::new(),
            false,
            NOW,
            &HaPolicy::default(),
        );
        let promotion = action(result);
        assert_eq!(promotion.key(), "promote");
        let HaAction::Promote {
            expected_sequence,
            forced: actual,
            target,
            database: lineage,
            ..
        } = promotion
        else {
            panic!("promotion expected");
        };
        assert_eq!(expected_sequence, progress(42));
        assert_eq!(actual, forced);
        assert_eq!(target, observed(2));
        assert_eq!(lineage.recovery_fork_id, guid(300));
    }
    // A verified permanent fence, not an unavailable-source timer, permits
    // excluding an entirely absent source observation.
    assert!(matches!(
        decide(&nodes()[1..], &BTreeSet::new(), false),
        HaDecision::Execute(HaAction::Promote { .. })
    ));
}

#[test]
fn source_removal_is_mandatory_and_new_source_presence_invalidates_the_fence() {
    let changes: &[fn(&mut FenceEvidence)] = &[
        |f| f.source = observed(3),
        |f| f.source = ReplicaIdentity::observed("replica-1", guid(101), "replacement").unwrap(),
        |f| f.proof_id = "other-proof".into(),
        |f| f.proof_id.clear(),
        |f| f.expires_at_unix_millis = NOW,
        |f| f.fenced_at_unix_millis = NOW + 1,
        |f| f.final_committed_record = None,
    ];
    for change in changes {
        let mut receipt = fence();
        change(&mut receipt);
        unsafe_decision(plan(
            &operation(false),
            &context(),
            &nodes(),
            &receipt,
            &BTreeSet::new(),
            false,
            NOW,
            &HaPolicy::default(),
        ));
    }
    for kind in 0..3 {
        let mut evidence = nodes();
        match kind {
            0 => {
                evidence[0].node.instance = existing(1, true).instance;
                stamp(&mut evidence[0].node.instance, AT);
                snapshot(&mut evidence[0].node).observed_at_unix_millis = AT;
                stamp(&mut snapshot(&mut evidence[0].node).availability_group, AT);
            }
            1 => {
                evidence[0].node.database = Observation::Present {
                    value: probe(1, true),
                    observed_at_unix_millis: AT,
                }
            }
            _ => evidence[0].health = evidence[1].health.clone(),
        }
        unsafe_decision(decide(&evidence, &BTreeSet::new(), false));
    }
    let mut evidence = nodes();
    evidence[0].node.instance = failure(ObservationFailureKind::Tls);
    unsafe_decision(decide(&evidence, &BTreeSet::new(), false));
}

#[test]
fn fenced_source_never_votes_even_with_a_high_pre_fence_sequence() {
    let mut evidence = nodes();
    evidence[0].node = existing(1, true);
    group(&mut evidence[0].node).configuration_sequence = progress(9000);
    assert!(matches!(
        decide(&evidence, &BTreeSet::new(), false),
        HaDecision::Execute(_)
    ));
    evidence[2].node.instance = failure(ObservationFailureKind::Unreachable);
    refuse(decide(&evidence, &BTreeSet::new(), false));
    evidence.pop();
    refuse(decide(&evidence, &BTreeSet::new(), false));
}

#[test]
fn configuration_votes_require_two_positive_native_bigints_and_target_maximum() {
    for value in ["0", "9223372036854775808", "9999999999999999999999999"] {
        for member in [1, 2] {
            let mut evidence = nodes();
            group(&mut evidence[member].node).configuration_sequence =
                DecimalProgress::parse(value).unwrap();
            unsafe_decision(decide(&evidence, &BTreeSet::new(), false));
        }
    }
    let mut evidence = nodes();
    group(&mut evidence[2].node).configuration_sequence = progress(43);
    unsafe_decision(decide(&evidence, &BTreeSet::new(), false));
    group(&mut evidence[1].node).configuration_sequence = progress(44);
    assert!(matches!(
        decide(&evidence, &BTreeSet::new(), false),
        HaDecision::Execute(_)
    ));
    evidence[2].node.instance = failure(ObservationFailureKind::Unreachable);
    // The target's remote report about the witness cannot supply its vote.
    let mut report = group(&mut evidence[1].node).replicas[1]
        .state
        .clone()
        .unwrap();
    report.provenance = NativeProvenance::PrimaryRemote;
    group(&mut evidence[1].node).replicas[2].state = Some(report);
    refuse(decide(&evidence, &BTreeSet::new(), false));
}

#[test]
fn identities_topology_roles_and_database_lineage_never_default_to_safe() {
    let changes: &[fn(&mut HaNode)] = &[
        |n| n.node.identity = ReplicaIdentity::desired("replica-2", "replacement").unwrap(),
        |n| n.node.identity = observed(2),
        |n| n.node.server_name = sqlserver_replicated::ServerName::new("foreign").unwrap(),
        |n| group(&mut n.node).identity.group_id = guid(999),
        |n| {
            group(&mut n.node).local_replica.identity =
                ReplicaIdentity::observed("replica-2", guid(999), "pod-2").unwrap()
        },
        |n| group(&mut n.node).local_replica.state_available = false,
        |n| group(&mut n.node).local_replica.role = None,
        |n| {
            role(
                n,
                NativeRole::Unknown(OpaqueId::new("role", "future").unwrap()),
            )
        },
        |n| group(&mut n.node).cluster_type = "NONE".into(),
        |n| group(&mut n.node).basic_features = true,
        |n| group(&mut n.node).is_distributed = true,
        |n| group(&mut n.node).required_synchronized_secondaries_to_commit = 0,
        |n| group(&mut n.node).required_synchronized_secondaries_to_commit = 2,
        |n| {
            group(&mut n.node).replicas.pop();
        },
        |n| group(&mut n.node).replicas[0].replica_id = guid(999),
        |n| group(&mut n.node).replicas[2] = group(&mut n.node).replicas[1].clone(),
        |n| group(&mut n.node).replicas[2].endpoint_url = None,
        |n| group(&mut n.node).replicas[2].availability_mode = "ASYNCHRONOUS_COMMIT".into(),
        |n| group(&mut n.node).replicas[2].failover_mode = "AUTOMATIC".into(),
        |n| group(&mut n.node).replicas[2].seeding_mode = "MANUAL".into(),
        |n| group(&mut n.node).databases[0].identity.group_database_id = guid(999),
        |n| database_probe(&mut n.node).database_id = 4,
        |n| database_probe(&mut n.node).database_guid = guid(999),
        |n| group(&mut n.node).databases[0].replicas[0].is_primary_replica = None,
        |n| group(&mut n.node).databases[0].replicas[0].is_primary_replica = Some(true),
        |n| {
            group(&mut n.node).databases[0].replicas[0].provenance = NativeProvenance::PrimaryRemote
        },
        |n| {
            group(&mut n.node).databases[0].replicas[0].lineage =
                RecoveryLineageObservation::RemoteUnavailable
        },
        |n| fork(n, 999),
        |n| snapshot(&mut n.node).observed_at_unix_millis -= 1,
        |n| snapshot(&mut n.node).instance.sqlserver_start_time.clear(),
        |n| snapshot(&mut n.node).instance.hadr_enabled = false,
        |n| snapshot(&mut n.node).instance.product_version = "+16.0.4225.2".into(),
        |n| {
            group(&mut n.node).replicas[2].endpoint_url =
                Some("tcp://sql-3.sql.default.svc:+5022".into())
        },
    ];
    for (index, change) in changes.iter().enumerate() {
        let mut evidence = nodes();
        change(&mut evidence[1]);
        let decision = decide(&evidence, &BTreeSet::new(), false);
        assert!(
            matches!(decision, HaDecision::Unsafe(_) | HaDecision::Wait(_)),
            "mutation {index}: {decision:?}"
        );
    }
    let mut evidence = nodes();
    evidence.push(evidence[1].clone());
    unsafe_decision(decide(&evidence, &BTreeSet::new(), false));
    let mut evidence = nodes();
    evidence.push(HaNode {
        node: existing(4, true),
        health: evidence[1].health.clone(),
    });
    unsafe_decision(decide(&evidence, &BTreeSet::new(), false));
    let mut evidence = nodes();
    role(&mut evidence[2], NativeRole::Primary);
    unsafe_decision(decide(&evidence, &BTreeSet::new(), false));
}

#[test]
fn unknown_stale_future_or_failed_health_cannot_be_a_vote() {
    for member in [1, 2] {
        for component in 0..3 {
            for unknown in [0, 4, 255] {
                let mut evidence = nodes();
                let sample = health(&mut evidence[member]);
                match component {
                    0 => sample.system = unknown,
                    1 => sample.resource = unknown,
                    _ => sample.query_processing = unknown,
                }
                refuse(decide(&evidence, &BTreeSet::new(), false));
            }
        }
        for at in [NOW - 60_001, NOW + 1, u64::MAX] {
            let mut evidence = nodes();
            stamp(&mut evidence[member].health, at);
            health(&mut evidence[member]).sql_utc_millis = at;
            refuse(decide(&evidence, &BTreeSet::new(), false));
        }
        for kind in [
            ObservationFailureKind::Tls,
            ObservationFailureKind::Authentication,
            ObservationFailureKind::PermissionDenied,
            ObservationFailureKind::Malformed,
            ObservationFailureKind::Unsupported,
            ObservationFailureKind::Unreachable,
            ObservationFailureKind::TimedOut,
        ] {
            let mut evidence = nodes();
            evidence[member].health = failure(kind);
            refuse(decide(&evidence, &BTreeSet::new(), false));
        }
    }
    for sql_time in [AT - 2001, AT + 2001, u64::MAX] {
        let mut evidence = nodes();
        health(&mut evidence[1]).sql_utc_millis = sql_time;
        unsafe_decision(decide(&evidence, &BTreeSet::new(), false));
    }
    let mut evidence = nodes();
    health(&mut evidence[1]).db_failover = false;
    unsafe_decision(decide(&evidence, &BTreeSet::new(), false));
}

#[test]
fn healthy_samples_can_age_after_an_independent_health_rpc_without_false_clock_skew() {
    let policy = HaPolicy::default();
    let health_rpc = AT + 5_000;
    let later_plan = AT + 20_000;
    for sql_time in [
        health_rpc - policy.max_clock_skew_millis,
        health_rpc,
        health_rpc + policy.max_clock_skew_millis,
    ] {
        let mut evidence = nodes();
        stamp(&mut evidence[1].health, health_rpc);
        health(&mut evidence[1]).sql_utc_millis = sql_time;
        stamp(&mut evidence[2].health, health_rpc + 1_000);
        health(&mut evidence[2]).sql_utc_millis = health_rpc + 1_000;
        assert_eq!(evidence[1].node.instance.observed_at_unix_millis(), AT);
        assert!(matches!(
            action(plan(
                &operation(false),
                &context(),
                &evidence,
                &fence(),
                &BTreeSet::new(),
                false,
                later_plan,
                &policy
            )),
            HaAction::Promote { .. }
        ));

        evidence[2].node.instance = failure(ObservationFailureKind::TimedOut);
        stamp(&mut evidence[2].node.instance, later_plan);
        assert!(matches!(
            plan(
                &operation(false),
                &context(),
                &evidence,
                &fence(),
                &BTreeSet::new(),
                false,
                later_plan,
                &policy
            ),
            HaDecision::Wait(_)
        ));
    }
    let mut evidence = nodes();
    stamp(&mut evidence[1].health, health_rpc);
    health(&mut evidence[1]).sql_utc_millis = health_rpc + policy.max_clock_skew_millis + 1;
    unsafe_decision(plan(
        &operation(false),
        &context(),
        &evidence,
        &fence(),
        &BTreeSet::new(),
        false,
        later_plan,
        &policy,
    ));
}

#[test]
fn independent_health_and_instance_observations_must_both_be_fresh_and_nonfuture() {
    let policy = HaPolicy::default();
    let health_rpc = AT + 5_000;
    let later_plan = AT + 20_000;
    for invalid_at in [later_plan - policy.max_age_millis - 1, later_plan + 1] {
        let mut evidence = nodes();
        stamp(&mut evidence[1].health, health_rpc);
        health(&mut evidence[1]).sql_utc_millis = health_rpc;
        stamp(&mut evidence[1].node.instance, invalid_at);
        assert!(matches!(
            plan(
                &operation(false),
                &context(),
                &evidence,
                &fence(),
                &BTreeSet::new(),
                false,
                later_plan,
                &policy
            ),
            HaDecision::Wait(_)
        ));

        let mut evidence = nodes();
        stamp(&mut evidence[1].health, invalid_at);
        health(&mut evidence[1]).sql_utc_millis = invalid_at;
        assert!(matches!(
            plan(
                &operation(false),
                &context(),
                &evidence,
                &fence(),
                &BTreeSet::new(),
                false,
                later_plan,
                &policy
            ),
            HaDecision::Wait(_)
        ));
    }
}

#[test]
fn health_threshold_and_configuration_commit_timeout_are_fail_closed() {
    for threshold in 3..=5 {
        for component in 0..3 {
            let mut evidence = nodes();
            match component {
                0 => health(&mut evidence[1]).system = 3,
                1 => health(&mut evidence[1]).resource = 3,
                _ => health(&mut evidence[1]).query_processing = 3,
            }
            let policy = HaPolicy {
                health_threshold: threshold,
                ..HaPolicy::default()
            };
            let decision = plan(
                &operation(false),
                &context(),
                &evidence,
                &fence(),
                &BTreeSet::new(),
                false,
                NOW,
                &policy,
            );
            if threshold >= component + 3 {
                refuse(decision);
            } else {
                action(decision);
            }
        }
    }
    for age in [59_900, 59_999, 60_000, 60_001, u64::MAX] {
        let mut evidence = nodes();
        health(&mut evidence[2]).configuration_commit_age_millis = Some(age);
        refuse(decide(&evidence, &BTreeSet::new(), false));
    }
    let mut evidence = nodes();
    health(&mut evidence[2]).configuration_commit_age_millis = Some(59_899);
    action(decide(&evidence, &BTreeSet::new(), false));
}

#[test]
fn planned_transition_compares_only_same_fork_local_commit_to_final_fenced_boundary() {
    let mut evidence = nodes();
    let state = &mut group(&mut evidence[1].node).databases[0].replicas[0];
    state.progress.committed_record = Some(progress(450));
    state.progress.redone_record = Some(progress(9999));
    state.progress.hardened_block = Some(progress(9999));
    refuse(decide(&evidence, &BTreeSet::new(), false));
    group(&mut evidence[1].node).databases[0].replicas[0]
        .progress
        .committed_record = Some(progress(500));
    action(decide(&evidence, &BTreeSet::new(), false));
    let mut receipt = fence();
    receipt.final_committed_record = Some(progress(300));
    group(&mut evidence[1].node).databases[0].replicas[0]
        .progress
        .committed_record = Some(progress(399));
    refuse(plan(
        &operation(false),
        &context(),
        &evidence,
        &receipt,
        &BTreeSet::new(),
        false,
        NOW,
        &HaPolicy::default(),
    ));
    group(&mut evidence[1].node).databases[0].replicas[0]
        .progress
        .committed_record = None;
    refuse(decide(&evidence, &BTreeSet::new(), false));
    fork(&mut evidence[1], 301);
    group(&mut evidence[1].node).databases[0].replicas[0]
        .progress
        .committed_record = Some(progress(999_999));
    unsafe_decision(plan(
        &operation(true),
        &context(),
        &evidence,
        &fence(),
        &BTreeSet::new(),
        true,
        NOW,
        &HaPolicy::default(),
    ));
}

#[test]
fn offlined_source_does_not_require_synchronized_target_but_local_safety_is_mandatory() {
    for native_role in [NativeRole::Secondary, NativeRole::Resolving] {
        let mut evidence = nodes();
        role(&mut evidence[1], native_role);
        let state = &mut group(&mut evidence[1].node).databases[0].replicas[0];
        state.synchronization_state = Some("NOT SYNCHRONIZING".into());
        state.synchronization_health = Some("NOT_HEALTHY".into());
        state.is_commit_participant = Some(false);
        action(decide(&evidence, &BTreeSet::new(), false));
    }
    let changes: &[fn(&mut HaNode)] = &[
        |n| group(&mut n.node).databases[0].replicas[0].is_suspended = Some(true),
        |n| group(&mut n.node).databases[0].replicas[0].is_suspended = None,
        |n| group(&mut n.node).databases[0].replicas[0].is_commit_participant = None,
        |n| group(&mut n.node).databases[0].replicas[0].database_state = None,
        |n| group(&mut n.node).databases[0].replicas[0].synchronization_state = None,
        |n| {
            group(&mut n.node).databases[0].replicas[0].synchronization_state =
                Some("UNKNOWN".into())
        },
        |n| database_probe(&mut n.node).state = "OFFLINE".into(),
        |n| database_probe(&mut n.node).recovery_model = "SIMPLE".into(),
        |n| group(&mut n.node).databases[0].local = None,
    ];
    for change in changes {
        let mut evidence = nodes();
        change(&mut evidence[1]);
        refuse(decide(&evidence, &BTreeSet::new(), false));
        refuse(plan(
            &operation(true),
            &context(),
            &evidence,
            &fence(),
            &BTreeSet::new(),
            false,
            NOW,
            &HaPolicy::default(),
        ));
    }
}

#[test]
fn force_requires_explicit_structurally_bound_approval_and_never_weakens_quorum() {
    let request = operation(true).request().clone();
    let reference = FenceReference::new(
        "provider",
        "structural-only",
        request.operation_id(),
        request.input_signature(),
        observed(1),
    )
    .unwrap();
    assert!(OperationEnvelope::new(request.clone(), None, Some(reference.clone())).is_err());
    let wrong = DestructiveApproval::new("approval", "other", request.input_signature()).unwrap();
    assert!(OperationEnvelope::new(request.clone(), Some(wrong), Some(reference.clone())).is_err());
    let wrong = DestructiveApproval::new(
        "approval",
        request.operation_id(),
        operation(false).input_signature(),
    )
    .unwrap();
    assert!(OperationEnvelope::new(request, Some(wrong), Some(reference)).is_err());
    for member in [1, 2] {
        let mut evidence = nodes();
        evidence[member].node.instance = failure(ObservationFailureKind::Unreachable);
        refuse(plan(
            &operation(true),
            &context(),
            &evidence,
            &fence(),
            &BTreeSet::new(),
            false,
            NOW,
            &HaPolicy::default(),
        ));
    }
    let mut evidence = nodes();
    group(&mut evidence[1].node).databases[0].replicas[0]
        .progress
        .committed_record = Some(progress(1));
    assert!(matches!(
        action(plan(
            &operation(true),
            &context(),
            &evidence,
            &fence(),
            &BTreeSet::new(),
            false,
            NOW,
            &HaPolicy::default()
        )),
        HaAction::Promote { forced: true, .. }
    ));
    assert!(matches!(
        action(decide(&nodes(), &BTreeSet::new(), false)),
        HaAction::Promote { forced: false, .. }
    ));
}

#[test]
fn primary_without_intent_is_not_success_and_ack_does_not_complete_role_transition() {
    let mut evidence = nodes();
    refuse(decide(&evidence, &BTreeSet::from(["promote".into()]), true));
    role(&mut evidence[1], NativeRole::Primary);
    unsafe_decision(decide(&evidence, &BTreeSet::new(), false));
    assert_eq!(action(decide(&evidence, &BTreeSet::new(), true)), offline());
    assert_eq!(
        action(decide(
            &evidence,
            &BTreeSet::from(["promote".into()]),
            false
        )),
        offline()
    );
    role(&mut evidence[2], NativeRole::Primary);
    unsafe_decision(decide(&evidence, &completed_keys(), true));
}

#[test]
fn post_promotion_offline_resolving_start_secondary_and_sync_are_observed_in_order() {
    let mut evidence = nodes();
    role(&mut evidence[1], NativeRole::Primary);
    let mut keys = BTreeSet::from(["promote".into()]);
    assert_eq!(action(decide(&evidence, &keys, true)), offline());
    keys.insert(offline().key());
    assert_eq!(action(decide(&evidence, &keys, true)), start());
    role(&mut evidence[2], NativeRole::Resolving);
    evidence[2].node.database = Observation::Absent {
        observed_at_unix_millis: AT,
    };
    group(&mut evidence[2].node).databases[0].local = None;
    group(&mut evidence[2].node).databases[0].replicas.clear();
    assert_eq!(action(decide(&evidence, &keys, true)), start());
    keys.insert(start().key());
    assert_eq!(action(decide(&evidence, &keys, true)), start());
    let local = probe(3, true);
    install_database(&mut evidence[2].node, 3, Some(local));
    role(&mut evidence[2], NativeRole::Secondary);
    assert!(matches!(
        decide(&evidence, &keys, true),
        HaDecision::Complete(_)
    ));
    group(&mut evidence[2].node).databases[0].replicas[0].synchronization_state =
        Some("SYNCHRONIZING".into());
    refuse(decide(&evidence, &keys, true));
    role(&mut evidence[1], NativeRole::Secondary);
    unsafe_decision(decide(&evidence, &keys, true));
}

#[test]
fn witness_configuration_votes_are_independent_of_local_database_readiness() {
    for witness_role in [NativeRole::Secondary, NativeRole::Resolving] {
        for missing in [
            Observation::Absent {
                observed_at_unix_millis: AT,
            },
            failure(ObservationFailureKind::Unsupported),
            failure(ObservationFailureKind::TimedOut),
        ] {
            let mut evidence = nodes();
            role(&mut evidence[2], witness_role.clone());
            evidence[2].node.database = missing;
            let database = &mut group(&mut evidence[2].node).databases[0];
            database.local.as_mut().unwrap().recovery = None;
            database.local.as_mut().unwrap().state = Some("RECOVERING".into());
            database.replicas[0].lineage = RecoveryLineageObservation::LocalUnavailable;
            database.replicas[0].database_state = None;
            database.replicas[0].is_suspended = None;
            database.replicas[0].is_primary_replica = None;
            database.replicas[0].progress.committed_record = None;
            assert!(matches!(
                action(decide(&evidence, &BTreeSet::new(), false)),
                HaAction::Promote { forced: false, .. }
            ));
            assert!(matches!(
                action(plan(
                    &operation(true),
                    &context(),
                    &evidence,
                    &fence(),
                    &BTreeSet::new(),
                    false,
                    NOW,
                    &HaPolicy::default()
                )),
                HaAction::Promote { forced: true, .. }
            ));
            health(&mut evidence[2]).system = 0;
            refuse(decide(&evidence, &BTreeSet::new(), false));
        }
    }
}

#[test]
fn resolving_reset_can_start_with_unavailable_probes_and_partial_recovery_metadata() {
    let keys = BTreeSet::from(["promote".into(), offline().key()]);
    for missing in [
        Observation::Absent {
            observed_at_unix_millis: AT,
        },
        failure(ObservationFailureKind::Unsupported),
        failure(ObservationFailureKind::TimedOut),
    ] {
        let mut evidence = nodes();
        role(&mut evidence[1], NativeRole::Primary);
        role(&mut evidence[2], NativeRole::Resolving);
        evidence[2].node.database = missing;
        let database = &mut group(&mut evidence[2].node).databases[0];
        database.local.as_mut().unwrap().recovery = None;
        database.local.as_mut().unwrap().state = Some("RECOVERING".into());
        database.replicas[0].lineage = RecoveryLineageObservation::LocalUnavailable;
        database.replicas[0].is_suspended = None;
        database.replicas[0].synchronization_state = None;
        database.replicas[0].synchronization_health = None;
        database.replicas[0].progress.committed_record = None;
        assert_eq!(action(decide(&evidence, &keys, true)), start());
        // Recovery can also temporarily hide the new primary's probe. Neither
        // a role reset nor its ACK is a claim that either database is ready.
        evidence[1].node.database = failure(ObservationFailureKind::Unsupported);
        assert_eq!(action(decide(&evidence, &keys, true)), start());
        assert_eq!(action(decide(&evidence, &completed_keys(), true)), start());
        role(&mut evidence[2], NativeRole::Secondary);
        refuse(decide(&evidence, &completed_keys(), true));
        evidence[2] = nodes()[2].clone();
        refuse(decide(&evidence, &completed_keys(), true));
        evidence[1] = nodes()[1].clone();
        role(&mut evidence[1], NativeRole::Primary);
        assert!(matches!(
            decide(&evidence, &completed_keys(), true),
            HaDecision::Complete(_)
        ));
    }
}

#[test]
fn database_unavailability_never_weakens_reset_configuration_or_health_gates() {
    let changes: &[fn(&mut HaNode)] = &[
        |n| n.node.instance = failure(ObservationFailureKind::Unreachable),
        |n| n.node.instance = failure(ObservationFailureKind::Tls),
        |n| stamp(&mut n.node.instance, NOW - 60_001),
        |n| stamp(&mut n.node.instance, NOW + 1),
        |n| health(n).system = 3,
        |n| n.health = failure(ObservationFailureKind::Unsupported),
        |n| group(&mut n.node).configuration_sequence = progress(0),
        |n| group(&mut n.node).identity.group_id = guid(999),
        |n| group(&mut n.node).local_replica.identity = observed(2),
        |n| group(&mut n.node).local_replica.role = None,
        |n| role(n, NativeRole::Primary),
        |n| group(&mut n.node).databases[0].identity.group_database_id = guid(999),
    ];
    for change in changes {
        let mut evidence = nodes();
        role(&mut evidence[1], NativeRole::Primary);
        role(&mut evidence[2], NativeRole::Resolving);
        evidence[2].node.database = failure(ObservationFailureKind::Unsupported);
        change(&mut evidence[2]);
        refuse(decide(
            &evidence,
            &BTreeSet::from(["promote".into(), offline().key()]),
            true,
        ));
    }
}

#[test]
fn post_promotion_fork_changes_need_primary_intent_same_database_and_rejoined_fork() {
    let mut evidence = nodes();
    role(&mut evidence[1], NativeRole::Primary);
    fork(&mut evidence[1], 301);
    unsafe_decision(decide(&evidence, &BTreeSet::new(), false));
    assert_eq!(action(decide(&evidence, &BTreeSet::new(), true)), offline());
    // No LSN ranking between the source and post-promotion recovery forks.
    group(&mut evidence[1].node).databases[0].replicas[0]
        .progress
        .committed_record = Some(progress(1));
    refuse(decide(&evidence, &completed_keys(), true));
    fork(&mut evidence[2], 301);
    let HaDecision::Complete(result) = decide(&evidence, &completed_keys(), true) else {
        panic!("rejoined new fork must complete");
    };
    assert_eq!(result.database.recovery_fork_id, guid(301));
    assert_eq!(result.database_guid, guid(202));
    assert_eq!(result.target, observed(2));
    assert_eq!(
        result.target_configuration_id,
        context().target.configuration_id
    );
    assert_eq!(result.target_epoch, 8);
    fork(&mut evidence[2], 302);
    unsafe_decision(decide(&evidence, &completed_keys(), true));
}

#[test]
fn postcondition_is_compact_stable_and_reset_keys_include_exact_identity() {
    let mut evidence = nodes();
    role(&mut evidence[1], NativeRole::Primary);
    let HaDecision::Complete(first) = decide(&evidence, &completed_keys(), true) else {
        panic!("complete")
    };
    group(&mut evidence[1].node).configuration_sequence = progress(100);
    health(&mut evidence[1]).resource = 1;
    group(&mut evidence[1].node).databases[0].replicas[0]
        .progress
        .committed_record = Some(progress(1000));
    let HaDecision::Complete(second) = decide(&evidence, &completed_keys(), true) else {
        panic!("complete")
    };
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&second).unwrap()
    );
    let encoded = serde_json::to_string(&first).unwrap();
    for volatile in [
        "observed_at",
        "health",
        "configuration_sequence",
        "committed_record",
    ] {
        assert!(!encoded.contains(volatile));
    }
    assert_eq!(offline().execution_target(), &observed(3));
    assert!(offline().key().len() < 256);
    assert_ne!(offline().key(), start().key());
    for replica in [
        observed(2),
        ReplicaIdentity::observed("replica-3", guid(999), "pod-3").unwrap(),
        ReplicaIdentity::observed("replica-3", guid(103), "replacement").unwrap(),
    ] {
        let changed = HaAction::OfflineSecondary {
            availability_group: ag(),
            replica,
        };
        assert_ne!(offline().key(), changed.key());
    }
    assert!(
        serde_json::to_string(&offline())
            .unwrap()
            .contains("offline_secondary")
    );
}

#[test]
fn request_rejects_skipped_or_wrapped_epochs_before_planning() {
    for (source, target) in [(7, 7), (7, 9), (u64::MAX, 0), (u64::MAX, u64::MAX)] {
        assert!(
            OperationRequest::new(
                "default/example",
                "transition",
                "configuration-1",
                source,
                target,
                operation(false).request().payload().clone()
            )
            .is_err()
        );
    }
}

#[test]
fn distinct_restored_local_guids_preserve_shared_ag_identity_and_terminal_fork_checks() {
    let mut evidence = nodes();
    // A retained pre-fence source sample is not a vote or post-removal presence.
    evidence[0].node = existing(1, true);
    let before_fence = FENCED - 1;
    stamp(&mut evidence[0].node.instance, before_fence);
    stamp(&mut evidence[0].node.database, before_fence);
    snapshot(&mut evidence[0].node).observed_at_unix_millis = before_fence;
    stamp(
        &mut snapshot(&mut evidence[0].node).availability_group,
        before_fence,
    );
    group(&mut evidence[0].node).databases[0].replicas[0]
        .progress
        .committed_record = Some(progress(400));
    let guids: Vec<_> = evidence
        .iter_mut()
        .map(|node| database_probe(&mut node.node).database_guid.clone())
        .collect();
    assert_eq!(guids, [guid(201), guid(202), guid(203)]);
    assert!(matches!(
        action(decide(&evidence, &BTreeSet::new(), false)),
        HaAction::Promote { forced: false, .. }
    ));
    assert!(matches!(
        action(plan(
            &operation(true),
            &context(),
            &evidence,
            &fence(),
            &BTreeSet::new(),
            false,
            NOW,
            &HaPolicy::default()
        )),
        HaAction::Promote { forced: true, .. }
    ));
    role(&mut evidence[1], NativeRole::Primary);
    let HaDecision::Complete(result) = decide(&evidence, &completed_keys(), true) else {
        panic!("local physical GUID differences must not prevent AG completion");
    };
    assert_eq!(result.database_guid, guid(202));
    assert_eq!(
        result.database.database.group_database_id,
        database().group_database_id
    );
    assert_eq!(result.database.recovery_fork_id, guid(300));

    let contradictions: &[fn(&mut HaNode)] = &[
        |n| group(&mut n.node).databases[0].identity.group_database_id = guid(999),
        |n| database_probe(&mut n.node).group_database_id = Some(guid(999)),
        |n| group(&mut n.node).databases[0].replicas[0].group_database_id = guid(999),
        |n| fork(n, 301),
        |n| database_probe(&mut n.node).database_guid = guid(999),
    ];
    for contradiction in contradictions {
        let mut changed = evidence.clone();
        contradiction(&mut changed[2]);
        unsafe_decision(decide(&changed, &completed_keys(), true));
    }
}

#[test]
fn completion_validates_shared_ag_database_each_local_guid_and_fresh_health() {
    let mut evidence = nodes();
    database_probe(&mut evidence[2].node).database_guid = guid(999);
    group(&mut evidence[2].node).databases[0]
        .local
        .as_mut()
        .unwrap()
        .recovery
        .as_mut()
        .unwrap()
        .database_guid = Some(guid(999));
    action(decide(&evidence, &BTreeSet::new(), false));
    action(plan(
        &operation(true),
        &context(),
        &evidence,
        &fence(),
        &BTreeSet::new(),
        false,
        NOW,
        &HaPolicy::default(),
    ));
    role(&mut evidence[1], NativeRole::Primary);
    let HaDecision::Complete(result) = decide(&evidence, &completed_keys(), true) else {
        panic!("per-replica local file GUIDs may differ after restore");
    };
    assert_eq!(result.database_guid, guid(202));
    assert_eq!(result.database.database, database());
    database_probe(&mut evidence[2].node).database_guid = guid(998);
    unsafe_decision(decide(&evidence, &completed_keys(), true));
    let mut evidence = nodes();
    role(&mut evidence[1], NativeRole::Primary);
    group(&mut evidence[2].node).databases[0]
        .identity
        .group_database_id = guid(999);
    unsafe_decision(decide(&evidence, &completed_keys(), true));
    for member in [1, 2] {
        let mut evidence = nodes();
        role(&mut evidence[1], NativeRole::Primary);
        health(&mut evidence[member]).system = 3;
        refuse(decide(&evidence, &completed_keys(), true));
        health(&mut evidence[member]).system = 1;
        stamp(&mut evidence[member].health, NOW - 60_001);
        refuse(decide(&evidence, &completed_keys(), true));
    }
}
