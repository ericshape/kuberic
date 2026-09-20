# SQL Server AG Convergence

The third delivery slice adds a library adapter for a pre-provisioned,
three-replica SQL Server 2022 Linux EXTERNAL availability group. Its scope is
bootstrap, replica join, automatic seeding, and operation-bound reseed. It is
**compatible with the level-triggered contract**, not an integration with the
classic operator or operator2.

The [observation CLI](observation.md) remains observe-only. There is no
`--force` or receipt-shaped shortcut that enables database deletion. Native
mutation requires an explicit enabled mode and an embedding application's
trusted `AuthorizationVerifier`. The shipped `DenyMutations` implementation
refuses authorization.

## Operation contract version 2

Version 1 described a bootstrap replica set but did not identify which member
was allowed to execute `CREATE AVAILABILITY GROUP`. It also did not bind a
reseed to the target's old local database incarnation. Executing those shapes
unchanged would leave important effects outside the canonical input signature.

Version 2 therefore:

- adds an explicit desired `primary` identity to `EnsureAvailabilityGroup`;
- binds that primary, including incarnation, to exactly one bootstrap member;
- binds `ReseedReplica` to the old local database ID, database GUID, and
  recovery-fork GUID; and
- includes these fields in canonical input/effect signatures and thus in
  approval and fence bindings.

The bounded operation-envelope codec validates native types and canonical
encoding before returning an envelope. It covers requests and their bound
approval/fence references. Version 1 is rejected explicitly, not upgraded
silently: rebuild requests and obtain new approvals against version 2.
Neither a checksum nor successful decoding authenticates a caller or proves
that a fence was installed.

`PlannedSwitchover` and `ForcedFailover` remain vocabulary for the next stage.
The codec can preserve them, but this adapter refuses to execute them.

## Authority and security boundary

`AcceptedAuthority` identifies a resource, accepted configuration, epoch,
designated primary, and three desired members with exact incarnations, server
names, and replication endpoints. The embedding controller supplies this
authority; arbitrary JSON is not a trusted authority source. Stage 3 requires
equal source/target epochs and does not advance primary authority.

The verifier must authenticate the request **before** accepted authority or
active operation state is recorded. It is checked again for each native action
and immediately before SQL dispatch after connecting. For reseed, it must
independently validate the destructive approval and the fence for the exact
target incarnation and operation inputs. The fence and command authority must
remain effective throughout the operation, including uncertain native effects.
A point-in-time check of a receipt string is insufficient.

No production fence/approval issuer or authenticator is included here. Their
implementation, lifetime rules, write-lease handling and failover arbitration
belong to stage 4. Supplying an allow-all verifier defeats the safety boundary;
the crate deliberately does not provide one.

Observation and mutation use separate mounted credential files **and distinct
server principals**. The backend checks their server SIDs and that the two
connections identify the same server/start time. Both use required,
CA/hostname-verified TLS. Driver messages and SQL batches are not logged.
Only a closed, typed set of native actions is executable, and each is checked
against the exact operation payload.

## Provisioning prerequisites

The owner of an isolated environment must provide:

1. Digest-pinned SQL Server 2022 Linux x86-64 instances, explicit EULA acceptance,
   and appropriate licensing. Developer edition is for non-production use.
2. Valid TDS server certificates and mounted observation/mutation credentials.
3. Started database-mirroring endpoints at the registered replication ports,
   with certificate authentication and required AES encryption. Provision and
   rotate the endpoint certificates and peer connection permissions separately.
4. One existing primary user database in `ONLINE`/`FULL` state, with a current
   full/differential backup establishing its log chain. The database probe's
   `backup_ready` derives from `last_log_backup_lsn`; it is not a history of
   completed log backups. The adapter does not create databases or take backups.
5. Mutation-principal permissions for the selected AG/database operations and
   metadata checks, including SQL Server 2022 performance/security-state
   visibility. The adapter does not grant permissions to its own logins.
6. A persistent, private local filesystem journal for the resource and a trusted
   authorization implementation. Do not use a disposable container directory
   for the journal.

A read-only principal with `VIEW ANY DATABASE` can still miss offline databases.
The additional standalone-database probe therefore requires complete visibility
(`ALTER ANY DATABASE` or `CREATE DATABASE` in `master`) before reporting absence.
Enabled mode uses the separate mutation principal for this probe. Observe-only
mode never reads mutation credentials and may report insufficient probe
visibility rather than infer that a database is absent.

Native database identity can be unavailable while a database is offline or
cannot start. That blocks destructive work; a same-named database is never a
substitute for the exact old GUID/fork binding.

## Reconciliation and native effects

The pure planner consumes fresh native snapshots and standalone-database
probes. It returns `Complete`, one `Execute` action, `Wait`, or `Unsafe`.
Failures, unknown metadata, clock skew, stale observations, wrong incarnations
and incompatible native identities never imply success.

The adapter separates intent preparation from dispatch:

1. Validate the request, authority, and registered instance bindings.
2. Resolve operation-ID reuse, retained results and equivalent-effect requests.
3. Reobserve native state and evaluate the complete state.
4. Durably record the exact proposed action and return without dispatching.
5. On a later call, reobserve and reauthorize before dispatching that recorded
   action. At most one native mutation is issued in a call.
6. Retain the command acknowledgement, but complete the operation only after
   native postconditions are observed and the result is durably stored.

An ambiguous response retains the intent. It is not permission to issue a
conflicting operation or a different action under the same action key.
SQL-side session application locks serialize cooperating adapter commands,
including a command still running after its client disconnected. Local native
identity/role checks protect each DDL effect. Application locks and the journal
lock are **not** cluster authority, external write leases, or fencing receipts.

### Bootstrap

Only the designated primary can create the AG. All registered members must be
freshly observed; an unrelated existing AG or secondary database is not adopted.
The prepared action also captures the primary database's local ID, database
GUID and recovery fork, so a replacement between planning and dispatch is
rejected. Creation uses the supported three synchronous replicas, EXTERNAL
failover, automatic seeding and one required synchronized secondary.

An already matching native AG is recognized through its identities, database
and complete replica configuration, not its name alone. An absent AG with an
explicit expected native group GUID is not recreated with a new GUID.

### Join

The source must be the accepted native primary and must configure the exact
target replica GUID. An already matching secondary is complete. JOIN never
runs over a primary or a present, different native group.

EXTERNAL JOIN is named in T-SQL; it has no public join-by-GUID argument. If
target metadata has not yet been discovered, authenticated source authority
and registered peer bindings are required. The executor checks the resulting
group and local replica GUIDs after JOIN, before acknowledgement. An unexpected
result does not enable seeding and is not treated as success.

### Automatic seeding

The adapter grants the target AG `CREATE ANY DATABASE`, then requests automatic
seeding on the source. A retained grant/trigger acknowledgement is scheduling
evidence, not a synchronization proof. Native in-progress seeding is observed
without restarting it. Failure or an unrelated same-named target database is
reported explicitly.

Completion requires the correct database/replica GUIDs, compatible local
recovery lineage, and native `ONLINE`, `SYNCHRONIZED`, healthy, unsuspended target
state. It never compares a hardened-block position with a committed-record
position or narrows native progress to `i64`.

### Reseed

Reseed first detaches and then drops only the exact old, approved target
database on a secondary, with fresh authorization on each action. The target
then follows the grant/trigger/observe path. An old database being synchronized
does not by itself satisfy a reseed request. A different database that appears
after a lost response is never dropped again; only the expected synchronized
replacement can satisfy the operation.

This does not implement offline file deletion, primary demotion, infrastructure
fencing, or force-recovery. Those cannot be inferred from Pod deletion requests,
readiness, a Kubernetes Lease, or the mere presence of a `FenceReference`.

## Journal and recovery

The SQL-specific SQLite journal retains canonical requests, input/effect
signatures, immutable action intents, acknowledgements, authority high-water
marks and terminal results. Writes use durable transactions. A process-lifetime
exclusive advisory file lock prevents concurrent owners of the same journal.
Use a local filesystem that correctly implements locking and synchronization;
shared/network-filesystem ownership and multiple independent journals for one
resource are unsupported.

- The same operation ID with different canonical inputs is rejected.
- An exact duplicate returns its retained **historical** result, not a fresh
  health/role/fencing assertion.
- An equivalent effect under another operation ID must be reobserved; it cannot
  blindly copy a result or dispatch again.
- Lower epochs or changed bindings under the same epoch are rejected.
- Unresolved operations cannot be discarded merely to accept a different
  operation or controller configuration.
- Corrupt, incompatible or unavailable journal state is an error. There is no
  empty-journal or in-memory fallback.

Preserve the journal and its locking files across process restarts. Do not
delete it, copy it while active, or point another controller at a different
path to bypass an unresolved operation. This stage does not automate storage
loss recovery or fenced ownership transfer.

## Validation and limits

Ordinary tests require neither SQL Server nor Kubernetes:

```bash
cargo fmt --all -- --check
cargo test --locked -p sqlserver-replicated --all-features
cargo clippy --locked -p sqlserver-replicated --all-targets --all-features -- -D warnings
```

Live mutation tests require explicitly licensed, isolated fixtures and explicit
mutation authorization. They are opt-in and fail on missing prerequisites when
requested. No live mutation guarantee should be inferred from server-free
tests alone. Real native interoperability, crash/fault injection and the stage 4
fencing provider remain release gates before this can be described as a
production HA implementation.

### Opt-in laboratory test

`live_convergence` drives bootstrap, join, seeding and retained-result replay on
an existing disposable three-instance fixture. Its test-only authorizer accepts
only non-destructive commands for the explicit resource. It cannot authorize
reseed or primary transitions and is not a production authorization example.

Required environment variables:

- `SQLSERVER_AG_LAB_ALLOW_MUTATIONS=true`: the owner authorizes changes to this
  isolated fixture.
- `SQLSERVER_TEST_EULA_ACCEPTED=true` and `SQLSERVER_TEST_IMAGE`: the owner
  attests EULA acceptance and supplies the actual digest-pinned image reference.
- `SQLSERVER_AG_LAB_CONFIG`: absolute path to the fixture configuration below.

The fixture file contains references, never credential contents:

```json
{
  "resource_id": "isolated-sqlserver-lab",
  "configuration_id": "lab-config-1",
  "epoch": 1,
  "primary_replica_id": "replica-0",
  "database_name": "lab_database",
  "journal_path": "/private/persistent-lab/operations.sqlite",
  "nodes": [
    {
      "observer_config": "/private/lab/sql-0-observer.json",
      "replication_host": "sql-0.example.internal",
      "replication_port": 5022,
      "mutation_username_file": "/run/secrets/sql-0-mutation/username",
      "mutation_password_file": "/run/secrets/sql-0-mutation/password"
    },
    {
      "observer_config": "/private/lab/sql-1-observer.json",
      "replication_host": "sql-1.example.internal",
      "replication_port": 5022,
      "mutation_username_file": "/run/secrets/sql-1-mutation/username",
      "mutation_password_file": "/run/secrets/sql-1-mutation/password"
    },
    {
      "observer_config": "/private/lab/sql-2-observer.json",
      "replication_host": "sql-2.example.internal",
      "replication_port": 5022,
      "mutation_username_file": "/run/secrets/sql-2-mutation/username",
      "mutation_password_file": "/run/secrets/sql-2-mutation/password"
    }
  ]
}
```

Each observer configuration uses the same AG name, its own expected SQL server
name, distinct logical replica ID and current incarnation. The primary database
and endpoint/TDS security must already be provisioned. The journal's parent
directory must exist and be private. No container, certificate, database backup
or external write-lease manager is installed by the test.

```bash
cargo test --locked -p sqlserver-replicated --test live_convergence -- --ignored
```

Each logical operation must converge within five minutes. A failed run retains
its journal and uncertain effects; it does not clean up with broad SQL or
filesystem deletion. Successful runs also retain the fixture. Never point
this test at a shared or production SQL Server deployment.
