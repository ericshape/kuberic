# Owned local SQL Server HA laboratory

[`scripts/sqlserver_ha_lab.py`](../../../scripts/sqlserver_ha_lab.py) provisions a
disposable, explicitly licensed, three-instance SQL Server 2022 Developer lab.
It is **not production HA support**, a Kubernetes deployment, or classic
operator/operator2 integration. It never performs failover or forced recovery.
During explicitly authorized initial setup only, it renews the designated
primary's native lease while joining and synchronizing the new AG. The Rust HA
controller owns signed lease maintenance and primary transitions after handoff;
the manager leaves no background lease holder.

The native protocol reference is Microsoft
[`mssql-server-ha` at `1bcf1aeaa7906c8284a8bbbd5863afd75586fd0b`](https://github.com/microsoft/mssql-server-ha/tree/1bcf1aeaa7906c8284a8bbbd5863afd75586fd0b).
The setup SQL here is original; no third-party helper source is copied.
See [HA transitions](ha.md), [observation](observation.md), and
[convergence](convergence.md) for the separate Rust contracts.

## Prerequisites and consent

- Python 3.10+ on a POSIX host, the Docker CLI, and OpenSSL 1.1.1 or 3+.
  LibreSSL is rejected. No Python packages or downloaded helper scripts are used.
- An **explicit named Docker context**, other than `default`, whose endpoint is
  a local `unix://` socket. The daemon must report Linux and native
  `x86_64`/`amd64`. An Intel Docker Desktop Linux VM is acceptable; ARM
  emulation, SSH/TCP contexts, Windows engines, and remote/shared-host
  deployment assumptions are not.
- At least 9 GiB available for the three 3-GiB-limited SQL containers, additional
  daemon/host headroom, and storage for three instances and a tiny backup.
  SQL Server's configured engine memory limit is 2048 MiB per instance.
- A verified SQL Server 2022 image digest supplied by the owner:
  `mcr.microsoft.com/mssql/server[:tag]@sha256:<64 lowercase hex digits>`.
  There is **no mutable-image default**. The image must contain
  `/opt/mssql-tools18/bin/sqlcmd`, `update-ca-certificates`, and the usual
  Ubuntu core utilities. No missing tools are installed into the image.
  Image architecture/digest and the running SQL major version, Developer
  edition, Linux/X64 platform, HADR capability, and server name are checked.
- Three unused loopback ports, default `15433`, `15434`, `15435`.
- A new absolute directory with an existing real parent, **outside the
  repository**. Existing paths, symlink components, root/home directories,
  repository descendants, and repository ancestors are rejected.

Create a named context yourself if necessary; the manager never switches the
current context. For example, on a Linux host with the indicated socket:

```bash
docker context create kuberic-sql-lab --docker host=unix:///var/run/docker.sock
```

Use the correct local Unix socket for your installation. The manager passes
`docker --context <name>` on **every** command. It removes inherited
`DOCKER_HOST`, `DOCKER_CONTEXT`, `DOCKER_TLS_VERIFY`, `DOCKER_CERT_PATH`,
`DOCKER_API_VERSION`, and stale `SQLCMDPASSWORD` overrides from subprocess
environments. It retains Docker's normal credential/config directory.
It pins both the resolved socket endpoint and daemon ID in the manifest and
rechecks them for subsequent resource operations. There is no repointing or
daemon-ID override.

## Commands

Help does not contact Docker or OpenSSL:

```bash
python3 scripts/sqlserver_ha_lab.py --help
python3 scripts/sqlserver_ha_lab.py create --help
python3 scripts/sqlserver_ha_lab.py inspect --help
python3 scripts/sqlserver_ha_lab.py destroy --help
```

Choose a real digest yourself. The placeholder below is intentionally not valid.
Setting a shell variable alone does not imply license consent:

```bash
mkdir -p "$HOME/kuberic-sql-labs"
LAB="$HOME/kuberic-sql-labs/experiment-01"  # Must not already exist.
SQL_IMAGE='mcr.microsoft.com/mssql/server@sha256:<owner-verified-64-hex-digest>'

python3 scripts/sqlserver_ha_lab.py create \
  --directory "$LAB" \
  --docker-context kuberic-sql-lab \
  --image "$SQL_IMAGE" \
  --accept-eula \
  --allow-mutations
```

Both acknowledgement flags are mandatory on **every create invocation**.
Developer edition is for non-production use only. Creating the laboratory
authorizes the pinned image pull, owned Docker resources, setup SQL, and bounded
initial-primary lease renewal during bootstrap.
It does not authorize failover or later Rust mutations.

Create prepares the instances, endpoints, principals, and one
FULL-recovery, full-and-log-backed-up `kuberic_lab` database on `replica-0`.
It **always** creates, joins, automatically seeds, and verifies the initial
`kuberic_lab_ag` on all three nodes before reporting success. The legacy
`--bootstrap-ag` flag is accepted for compatibility but is now redundant; there
is no prepare-only or skip-bootstrap option. The profile is exactly:

- Three synchronous-commit replicas, one database, EXTERNAL cluster/failover.
- Required synchronized secondaries to commit: **1**.
- Automatic seeding, readable secondaries, `DB_FAILOVER=ON`.
- Native `WRITE_LEASE_VALIDITY=60`, or explicitly `--write-lease-seconds 30`.

The owner-authorized setup loop renews `WRITE_LEASE_VALIDITY` before each join,
seeding trigger, and synchronization probe. Renewals check the exact newly
created group/primary replica GUIDs, generated server name, PRIMARY role,
EXTERNAL/DB_FAILOVER/RSSTC profile, and online primary database; Docker context,
daemon, labels, incarnation, and TLS verification remain enforced.
Lease errors (including 47116/47119), failed acknowledgements, role/identity
changes, and timeouts fail setup rather than continuing or ignoring errors.

Each setup SQL step, including its Docker checks, is bounded to one quarter of
the chosen lease duration (7.5 or 15 seconds), inside the overall bootstrap
deadline. Renewals are foreground operations, not a detached process or a
perpetual background worker. A slow command fails closed instead of leaving an
uncontrolled renewer running. This setup consent is **not** a signed Rust
authority/lease proof and cannot be used for subsequent HA transitions.

Success requires a single polling round with all three replicas reporting the
expected local role and an ONLINE, unsuspended, healthy SYNCHRONIZED database.
The primary then reconfirms all three exact replica GUIDs as connected,
healthy and synchronized. Earlier successes are not accumulated across rounds.
No `ready` manifest is published on failed/incomplete seeding.
These are bounded observations, not an atomic distributed snapshot.

Lease renewal stops before create returns. Start the Rust controller/harness
promptly, require its fresh observations and signed authorization, and let it
maintain the native lease before starting a write workload. The last setup
lease is temporary, not a promise of continuing write availability. Never
disable the lease to work around expiration.

Other create options are `--first-port` (three consecutive nonprivileged
ports), `--database-name`, `--availability-group`, and `--ready-timeout`
(30–600 seconds, default 240, for each instance's service startup and separately
for the **entire** AG create/join/seed/synchronization phase).
SQL names are restricted to a letter followed by letters/digits/underscores,
at most 48 characters; system database names are prohibited.

```bash
python3 scripts/sqlserver_ha_lab.py inspect --directory "$LAB"
python3 scripts/sqlserver_ha_lab.py destroy --directory "$LAB"
# Separate, explicit and irreversible data removal, now or during first destroy:
python3 scripts/sqlserver_ha_lab.py destroy --directory "$LAB" --destroy-data
```

`inspect` verifies ownership and reports Docker process/presence evidence.
It does not execute SQL or certify current HA health; the saved `ready` state
only records successful provisioning. `destroy` is itself the explicit cleanup
authorization and needs neither EULA acceptance nor an image argument.
It stops/removes exact owned containers and the private network, retaining
named data volumes by default. `--destroy-data` additionally removes only
positively identified owned named volumes. Repeated cleanup is supported.

## Ownership, storage, and credentials

A new private 0700 directory contains a UUID ownership marker, 0600 manifest,
private credential/key/configuration files, and a process lock. All network,
volume, SQL-container, and initialization-helper resources have
`io.kuberic.sqlserver.lab=<owner UUID>` and a per-resource UUID label.
Containers also have
`io.kuberic.sqlserver.replica=replica-0`, `replica-1`, or `replica-2`.
Generated names include the full owner UUID suffix. Container incarnations
are **full 64-hex immutable Docker IDs**, not names or short IDs.

The SQL containers run as `10001:0`, without automatic restart, on a private
internal bridge. Only TDS is published, bound to `127.0.0.1`; port 5022 remains
inside that bridge. There are no host bind mounts or anonymous data volumes.
An exactly labeled short-lived helper, from the **same pinned image**, runs
only `/bin/sleep` as root with network `none` to initialize each owned named
volume. Its exact ID is verified and removed. The SQL data directory and secret
directory are private; TLS keys are owned by UID 10001 with mode 0600.

Each node gets its own TLS certificate, signed by the lab's private CA, with
SANs for its generated hostname and `127.0.0.1`. Certificates last 30 days;
there is no automatic rotation. The CA is installed **only in each new
container's** trust store, not the host store. SQLcmd uses required encryption
and normal certificate verification; there is no `-C` or
`TrustServerCertificate` bypass. Host Rust observers explicitly trust `ca.crt`.

Mirroring uses a separate shared certificate, with certificate authentication
and required AES encryption. Its exported private key (`endpoint.pvk`) is
encrypted by SQL Server with a generated password; each instance has its own
database master key. The private export is not the TDS server key.

SA passwords reach Docker through private env files. SQLcmd passwords are
passed using `--env SQLCMDPASSWORD` (the **name only** in argv), and setup SQL,
including password-bearing DDL, goes through stdin. Raw SQLcmd stdout/stderr
and failed command output are never printed. Private keys/passwords are absent
from manifests, command arguments, and normal output.

The observer login has only the documented metadata/DMV grants. The separate
`kuberic_mutator` login is deliberately a **lab-only sysadmin** for the native
HA operations; this is not a production least-privilege configuration.
The Docker daemon, host administrator, and lab owner remain trusted: Docker
necessarily retains the SA environment internally, and the owner can read
the private files. Do not export Docker inspect environment data or commit,
upload, or share this directory.

## Manifest and Rust handoff

`<directory>/ha-lab.json` is version 1. Successful create guarantees:

| Field | Contract |
|---|---|
| `owner_id`, `docker_context`, `engine_id`, `image` | Ownership UUID, exact context/daemon binding, supplied digest-pinned image |
| `resource_id`, `configuration_id`, `epoch` | `sqlserver-lab:<owner>`, `initial:<owner>`, integer `1` |
| `primary_replica_id` | Initial designated primary: `replica-0`; not a live role assertion |
| `database_name`, `availability_group` | Validated SQL names |
| `native_group_id` | Canonical lowercase native AG GUID captured from the newly created primary |
| `journal_path` | Absolute `journal.sqlite` path; the Rust owner creates the journal |
| `issuer_keys` | `authority`, `approval`, `fence`, `lease`: absolute private file paths |
| `nodes` | Three records, in logical replica order, described below |
| `network` | Full immutable `id`, generated `name`, ownership `resource_token` |
| `volumes` | Exact `name`, `replica_id`, ownership `resource_token`, pinned `created_at` |

Issuer key files contain **32 raw bytes each**, distinct Ed25519 signing seeds,
not hex strings or PEM. Rust derives the corresponding public keys. Seeds are
never printed. Generation does not create authority, fence, approval, or lease
proofs; the consuming controller must still enforce all authorization rules.

Every node has `logical_id`, full `container_id`, canonical lowercase
`native_replica_id`, `hostname`, absolute
`observer_config`, `replication_host`, `replication_port` (`5022`), and absolute
`mutation_username_file`/`mutation_password_file` references. Manager fields
`container_name`, `resource_token`, and published TDS `port` are also present.
The GUID-only query emits exactly three `group-guid|replica-guid` rows, ordered
by the three configured server names. Extra output, absent/mismatched group
identities, malformed GUIDs, or duplicate replica GUIDs fail provisioning.
Readiness subsequently checks those native identities on every node.
The Rust harness should still discover/revalidate them through its observation
API; manifest GUIDs are setup receipts, not freshness or promotion evidence.

Observer JSON exactly follows
[`observer.example.json`](../../../examples/sqlserver/observer.example.json):
`observe_only`, host `127.0.0.1`, distinct published ports, the exact expected
SQL server name, logical replica ID, full container-ID incarnation, separate
observer credential files, the absolute CA path, and supported timeout fields.

The manifest also has manager fields `directory`, `docker_endpoint`, `image_id`,
`helpers`, `state`, `stage`, `bootstrap_ag`, `write_lease_seconds`, and
`ready_timeout`. Consumers must require `state == "ready"` and valid full
incarnation/native GUIDs before treating it as a completed fixture. New
successful creates always have `bootstrap_ag: true`. Pending/failed
creates retain planned resources with empty identity strings where creation
was not acknowledged. Older version-1 receipts without the native GUID fields
remain accepted by `inspect`/`destroy` for ownership-checked Docker cleanup;
they are not completed fixtures for the new HA-adoption contract.

`convergence.json` is emitted only after successful provisioning and contains
**only** the fields accepted by `examples/sqlserver/tests/live_convergence.rs`:
`resource_id`, `configuration_id`, `epoch`, `primary_replica_id`, `database_name`,
`journal_path`, and `nodes`. Its node records contain only `observer_config`,
`replication_host`, `replication_port`, `mutation_username_file`,
`mutation_password_file`. Do not give that strict reader `ha-lab.json`.

For the existing separately opted-in convergence test, after reviewing its
mutation scope (it now receives an already-created AG, so setup operations
should converge idempotently rather than demonstrate creation from absence):

```bash
SQLSERVER_AG_LAB_ALLOW_MUTATIONS=true \
SQLSERVER_TEST_EULA_ACCEPTED=true \
SQLSERVER_TEST_IMAGE="$SQL_IMAGE" \
SQLSERVER_AG_LAB_CONFIG="$LAB/convergence.json" \
cargo test --locked -p sqlserver-replicated --test live_convergence \
  live_bootstrap_join_seed_and_replay -- --ignored
```

HA/fencing test authorization and issuer loading belong to the Rust test/
controller code, not this manager. Preserve its single authoritative journal;
do not copy/reset journals or reuse an initial manifest as current authority
after a primary transition.

### Separate planned and forced scenarios

The Rust live-HA harness adopts an **already provisioned and synchronized** AG.
Create two independent laboratories for planned and forced scenarios, with
different directories and loopback port ranges. For example:

```bash
python3 scripts/sqlserver_ha_lab.py create \
  --directory "$HOME/kuberic-sql-labs/planned-01" --first-port 15433 \
  --docker-context kuberic-sql-lab --image "$SQL_IMAGE" \
  --accept-eula --allow-mutations

# Run the planned Rust scenario now; its controller takes over lease renewal.

python3 scripts/sqlserver_ha_lab.py create \
  --directory "$HOME/kuberic-sql-labs/forced-01" --first-port 16433 \
  --docker-context kuberic-sql-lab --image "$SQL_IMAGE" \
  --accept-eula --allow-mutations

# Run the forced Rust scenario with the second manifest.
```

Pass each scenario its own `ha-lab.json`, issuer files, and journal. Build the
Rust harness before provisioning, then provision just before each scenario
when possible. Do not copy a manifest or reuse a
previously fenced/removed container incarnation. Each new directory produces
new ownership, containers, native topology, credentials, and issuer seeds.

## Failure and cleanup semantics

Create is not resumable and never adopts an existing directory. It saves
generated names/tokens before resource creation and saves returned IDs as it
progresses. An error or interrupt records `failed` with its stage when storage
remains available. No broad automatic rollback hides partial resources.
Preserve `ha-lab.json` and `owner-id`; use explicit `inspect`/`destroy`.
If failure-state persistence itself fails, that failure is reported and the
last durable manifest remains the starting evidence.

Cleanup first validates **all** known resources before deleting anything.
Labels, immutable IDs, generated names, local-volume creation times, and daemon
identity must match. Lost creation acknowledgements can be recovered only
through the pre-recorded exact name and ownership/resource labels. A replaced
name or changed identity fails closed. Unregistered network attachments also
block cleanup. Inspection/daemon errors are never interpreted as absence:
absence requires successful complete Docker inventory enumeration.

The manager does not prune resources, delete images, use `rm -v`, recursively
delete directories, or delete local key/configuration/journal files. Even after
`--destroy-data`, the private directory and ownership evidence remain.
It also cannot delete a volume still referenced by another container; Docker
failure is retained, not bypassed with force. Stop the Rust controller/tests
before cleanup. A crash or concurrent external Docker change can leave a
partial cleanup, represented by `destroy_failed`; fix the cause, then retry.

## Server-free validation and limits

```bash
PYTHONDONTWRITEBYTECODE=1 \
python3 -m unittest discover -s scripts -p sqlserver_ha_lab_test.py
```

Tests mock subprocess/Docker/OpenSSL behavior, generate only public test
credential material, and check consent, pinning, architecture, environment
isolation, ownership, exact cleanup, failure propagation, secret suppression,
private files, TLS configuration, and handoff schemas.
They also exercise mandatory AG bootstrap, bounded setup-only lease renewal,
strict native GUID parsing, all-member synchronization rounds, final primary
confirmation, and fatal lease/seeding failure with retained ownership receipts.
No daemon, EULA acceptance, real keys, image pull, SQL deployment, or package
installation is needed. These tests do **not** establish real-image SQL/TLS
interoperability or HA guarantees. A deliberately authorized live run on the
selected digest remains necessary before relying on a fixture.
