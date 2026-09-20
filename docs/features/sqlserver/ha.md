# SQL Server HA Transitions

This fourth delivery slice adds an explicitly driven, standalone HA controller
for the supported three-synchronous-replica, one-database EXTERNAL profile.
It is **compatible with the level-triggered contract**; it is not classic
operator wiring, operator2 integration, or a Microsoft-supported Kubernetes HA
product. Mutation and automatic authority selection are not enabled by default.

## Native protocol reference

The reference is the published Microsoft `mssql-server-ha` source at commit
`1bcf1aeaa7906c8284a8bbbd5863afd75586fd0b`:

- [Promotion, demotion, monitoring and notification ordering](https://github.com/microsoft/mssql-server-ha/blob/1bcf1aeaa7906c8284a8bbbd5863afd75586fd0b/go/src/ag-helper/main.go)
- [Native AG session and lease operations](https://github.com/microsoft/mssql-server-ha/blob/1bcf1aeaa7906c8284a8bbbd5863afd75586fd0b/go/src/mssqlcommon/ag/lib.go)
- [Server diagnostics](https://github.com/microsoft/mssql-server-ha/blob/1bcf1aeaa7906c8284a8bbbd5863afd75586fd0b/go/src/mssqlcommon/lib.go)

The implementation follows the protocol, rather than invoking an isolated
`FAILOVER` statement:

| Protocol requirement | Behavior |
|---|---|
| Configuration arbitration | Two fresh, positive self-reported native sequence numbers; the target must have the maximum |
| Server health | `sp_server_diagnostics`, explicit health threshold, configuration-commit timeout, bounded clock skew |
| Pre-promotion lease | Native `WRITE_LEASE_VALIDITY` update before the role-changing DDL |
| External-cluster session | `sp_set_session_context` with `external_cluster=yes` |
| Role change | Explicit normal failover or separately approved forced failover; no implicit fallback |
| Completion | Reobserve PRIMARY and database readiness, never infer from SQL acknowledgement |
| Post-promotion | Reset the surviving secondary through OFFLINE/SECONDARY and observe readiness |
| Ongoing writes | Renew only the currently authorized primary's native lease; stop on lost authority, failed health, stalled config commit, cancellation or errors |

There are deliberate stronger boundaries than the reference helper: TDS
certificate/hostname verification stays enabled, unknown evidence fails
closed, raw server errors are not logged, and lease errors 47116/47119 are
not converted into a warning/success. An AG without native external-lease
support is not silently treated as fenced.

## Contract and storage versions

Operation contract **v3** adds:

- an explicit, bounded `write_lease_seconds` bootstrap input;
- `DB_FAILOVER=ON` and native lease support at AG creation; and
- a canonically bound target configuration ID for each primary transition.

The target epoch advances exactly once. These are signature-relevant changes;
v1/v2 commands and their old approvals are not silently upgraded. The journal
schema also changes for integrity-checked HA checkpoints and atomic completion
plus target-authority installation. Unsupported journals fail closed, not as
empty state.

Do not delete a live journal to force an upgrade. Resolve outstanding effects,
fence the old authority, and perform an explicit controlled migration. Existing
AGs created without `WRITE_LEASE_VALIDITY` require explicit operator-led
recreation/migration; this code does not drop/recreate them automatically.

## Authentication and current authority

Proofs use Ed25519 with role-specific trusted issuers for authority, destructive
approval, infrastructure fencing and lease grants. No default private keys,
shared development key, or permissive verifier is supplied. Keys belong in
private mounted files, not manifests, command arguments, logs or journal data.

Every proof binds its purpose, resource, operation, canonical input digest,
configuration/epochs and authority fingerprint. HA authority also binds the
source/target topology and policy. Issued/not-before/expiry times and maximum
lifetime are checked; unknown keys, reused issuer roles, altered scopes and
expired/future proofs are rejected. Retries of the same command are allowed;
proofs cannot authorize a different command or incarnation.

Cryptographic validity is not current authority. `JournalAuthorityOracle`
reads the real resource journal through a coherent read-only transaction.
Unavailable or corrupt state denies authorization. While a transition is
frozen, old stable-operation grants and old-primary lease renewals are denied.
Only the exact transition and its fenced target's provisional lease are
eligible. The final native result, target authority, and controller checkpoint
are committed together.

The authority service is a single owner of one persistent private local
journal per resource. File locks are ownership serialization, not distributed
consensus. Multiple independently copied journals, uncoordinated controllers,
and arbitrary manual changes to managed SQL topology are unsupported. A future
operator integration must preserve these authority boundaries.

## Real old-primary fencing

The supplied infrastructure provider is for the owned Docker laboratory.
Replica incarnation is the full immutable container ID. The provider:

1. Checks the configured Docker context, daemon ID and exact registered
   logical/native/incarnation identity.
2. Verifies ownership labels without reading/logging container environment
   variables.
3. Disables automatic restart, stops the exact container, and removes that
   exact ID without deleting volumes.
4. Positively enumerates containers on the same daemon to prove absence.
5. Revalidates the permanent-removal evidence before promotion.

A stopped container can be restarted and is not sufficient. Failed inspection,
an unavailable daemon, an empty error response, readiness, Pod deletion
requests and Kubernetes Leases are not proof. No timer-only lease-expiry
receipt is issued by this implementation.

Only after the concrete provider succeeds is an operation-bound, expiring
fence proof signed. For planned switching it also binds the final committed
record captured from the stopped-write source. A proof signature authenticates
the issuer; it does not replace the provider's actual infrastructure checks.

The old container cannot be restarted after removal. Its storage is retained.
Recreating/reseeding a new incarnation is a separate, explicitly authorized
operation, not an implicit rollback of a completed switch.

## Planned switchover

The caller supplies an exact source/target request and signed authority.
Preparation freezes the old authority durably, checks viable surviving
replicas, records an OFFLINE intent, and offlines the source using the native
protocol. It then observes the source's final committed-record position and
permanently fences the old container.

No-loss eligibility uses the greater of the requested commit boundary and the
authenticated final source boundary. It compares committed-record positions
only within the same database/recovery lineage, never hardened-block IDs or
generic `i64` progress. If final source evidence is unavailable, planned
switching refuses to proceed; it does not silently become forced failover.

The native `FAILOVER` statement remains the final engine synchronization gate.
DMVs can report NOT_SYNCHRONIZING after losing the primary, so they are not
treated as an independent guarantee that SQL will accept failover.

## Forced failover

Forced failover additionally requires a signed, operation-specific destructive
approval acknowledging possible data loss. An unknown last committed boundary
requires explicit acknowledgement of unknown loss. This does not relax native
identity, incarnation, configuration-quorum, health, lineage or fencing checks.

The old primary is fenced even if it already appears down. The two surviving
replicas must provide current configuration evidence, with the requested target
at the maximum sequence number. The controller never elects a target from
stale remote progress or substitutes FORCE_FAILOVER when a planned operation
fails.

## Lease lifecycle and recovery

Leases are native SQL write fences for direct TDS clients. Grants bind the
accepted primary, native AG, process start time, duration and authority epoch.
Renewal checks current journal authority, current health and the signed
lifetime before sending SQL. SQL-side clock/deadline checks prevent queued
commands from extending a lease beyond their authorization.

Renewal intent is durable before dispatch. An unknown reply is retained as
uncertainty, not treated as a proven expiry. The keeper stops rather than
renewing from stale health or an obsolete epoch. Cancellation and process exit
leave native SQL to enforce the lease, while promotion still requires the
separate permanent infrastructure fence.

During a transition, a provisional target lease is bounded by the transition
proofs and requires a fresh surviving quorum. A prepared promotion alone is not
completion. The controller observes the new primary, restores the surviving
secondary, renews the target lease, and atomically installs the target epoch.
Exact completed retries return historical results rather than fresh write
authority.

## Validation

Server-free tests exercise real signature verification, proof expiry/binding,
authority revocation, stale/unknown health and sequence evidence, controlled
lease loss, exact infrastructure fencing, native SQL protocol shape and durable
reconciliation/crash boundaries.

```bash
cargo fmt --all -- --check
cargo test --locked -p sqlserver-replicated --all-features
cargo clippy --locked -p sqlserver-replicated --all-targets --all-features -- -D warnings
python3 -m unittest discover -s scripts -p sqlserver_ha_lab_test.py
```

See the [owned three-node laboratory](ha-lab.md) for explicit licensing, pinned
images, certificate/credential provisioning, cleanup ownership, and live tests.
Live scenarios are opt-in and fail if prerequisites are missing. Passing mocks
or server-free tests alone is not live SQL Server or production HA validation.
