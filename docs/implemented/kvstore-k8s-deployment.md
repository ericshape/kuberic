# KVStore Kubernetes Deployment

For development and CI, use the [shared Gateway setup](../features/envoy-gateway-kind.md).
It deploys two independent KVStore applications with `deploy/kind-config.yaml`.
Only Envoy owns the loopback host mapping and NodePort `30090`; application
Services remain cluster-private by default.

Optional managed application Services provide additional direct endpoints or
app-only backends for Gateway routes. They do not replace the Gateway setup or
make the operator responsible for Gateway installation and route lifecycle.

## Current State

The reference deployment in namespace `xedio` uses:

```
Just recipes → cargo build → docker build → kind load → kubectl apply
```

Components:
- **kuberic-operator**: Deployment (1 replica) watching `KubericSet` CRD
- **kvstore-a / kvstore-b**: 3 bare Pods per application, managed by the operator
- **Envoy Gateway**: A shared Gateway with one authority-based GRPCRoute per application
- **kind-config.yaml**: The canonical configuration; Envoy owns the `30090` host mapping

The kuberic-operator creates bare Pods (not StatefulSets) and manages
three ports per pod: app (8080), control (9090), data (9091).

## Architecture

```text
127.0.0.1:30090 -> Envoy NodePort 30090 -> Gateway listener 8080
                    | kvstore-a.kuberic.test -> kvstore-a-rw:8080 -> A primary
                    | kvstore-b.kuberic.test -> kvstore-b-rw:8080 -> B primary

Each set: <set>-rw -> primary, <set>-ro -> secondaries, <set>-r -> all ready pods
Operator/replica traffic: cluster-private control (9090) and data (9091) ports
```

## Deployment Artifacts

### 1. Dockerfile

[`examples/kvstore/deploy/Dockerfile`](../../examples/kvstore/deploy/Dockerfile)
packages the pre-built KVStore binary as a non-root container. `just images`
builds both KVStore and operator images and loads them into the owned cluster.

### 2. KubericSet CRD manifests

[`deploy/gateway/applications.yaml`](../../deploy/gateway/applications.yaml)
contains `kvstore-a` and `kvstore-b`. Each uses the following configuration
(shown for `kvstore-a`):

```yaml
apiVersion: kuberic.io/v1
kind: KubericSet
metadata:
  name: kvstore-a
  namespace: xedio
spec:
  replicas: 3
  image: localhost/kvstore:latest
  port: 8080
  controlPort: 9090
  dataPort: 9091
  storage: "256Mi"
  failoverDelay: 5
```

### 3. KinD config — `deploy/kind-config.yaml` (repo root)

The [canonical config](../../deploy/kind-config.yaml) exposes Envoy at
`127.0.0.1:30090`. Do not assign this NodePort to an application Service or
restore direct application overlays. Additional Services do not need extra
host mappings when used as Gateway backends.

### 4. Just recipes — `justfile`

```sh
just create-kind-cluster
just images
just kvstore-deploy
just gateway-test
```

First set the isolated cluster name, kubeconfig, and context as described in the
[Gateway guide](../features/envoy-gateway-kind.md#run-the-reference).
`just kvstore-deploy` installs the operator, pinned Gateway dependencies, both
applications, and [`deploy/gateway/resources.yaml`](../../deploy/gateway/resources.yaml).
Use `just kvstore-delete` to delete the reference applications and routes, or
`just delete-kind-cluster` to remove the dedicated cluster.

### 5. CI

CI uses this same Gateway setup. The `kuberic-tests` scenarios require the
installed Gateway controller and CRDs, not just an operator Deployment.
The [managed Service test instructions](../Dev.md#isolated-kubernetes-routing-test)
describe the additional fixture and its narrower transport coverage.

## kvstore Binary Configuration

The binary supports fixed port binding for container use via env vars.
Defaults remain `127.0.0.1:0` (random port, localhost-only) for backward
compatibility with in-process tests.

| Env Var | Container Value | Default | Purpose |
|---------|----------------|---------|---------|
| `KUBERIC_CONTROL_BIND` | `0.0.0.0:9090` | `127.0.0.1:0` | Operator reaches pod via pod IP |
| `KUBERIC_DATA_BIND` | `0.0.0.0:9091` | `127.0.0.1:0` | Peer pods reach each other |
| `KUBERIC_CLIENT_BIND` | `0.0.0.0:8080` | `127.0.0.1:0` | Clients reach via Service |
| `KUBERIC_REPLICA_ID` | `<pod_index + 1>` | `1` | 1-based replica ID |

The `build_pod()` function in the reconciler sets these env vars in the
container spec. The kvstore binary uses clap `env` attribute for seamless
env var / CLI arg integration.

**Replica ID convention**: `KUBERIC_REPLICA_ID` is **1-based** (matching
the driver's `ReplicaId = pod_index + 1`). The pod label
`kuberic.io/pod-index` is 0-based (for PVC/pod naming).

## Services (CNPG Pattern)

The operator creates CNPG-style label-driven ClusterIP services.
Pod labels are managed by the operator; Kubernetes endpoint controller
automatically re-routes traffic on failover.

### Pod Labels

```
kuberic.io/set: kvstore-a
kuberic.io/role: primary | secondary
kuberic.io/pod-index: "0" | "1" | "2"
```

On failover/switchover, labels are updated in a specific order:

1. **Promote first**: Set new primary's label to `primary`
2. **Demote second**: Set old primary's label to `secondary`

EndpointSlice updates and ready-pod filtering are asynchronous. Clients must
handle transient gaps and reconnect; label changes do not migrate existing
connections.

### Internal Services (created by operator in Creating phase)

| Service | Selector | Routes To |
|---------|----------|-----------|
| `kvstore-a-rw` | `kuberic.io/set=kvstore-a, kuberic.io/role=primary` | Primary only |
| `kvstore-a-ro` | `kuberic.io/set=kvstore-a, kuberic.io/role=secondary` | Secondaries only |
| `kvstore-a-r` | `kuberic.io/set=kvstore-a` | All pods |

All are ClusterIP services (no NodePort). Port mappings:
- Port 8080 → client gRPC
- Port 9090 → control gRPC (operator use)
- Port 9091 → data gRPC (inter-pod replication)

### Optional Managed Application Services

Use `spec.managed.services.additional` to create additional application-facing
Services without changing the three internal Services. An omitted `managed`
section or an empty `additional` list requests no additional Services, preserving
the default deployment.

Each entry has `selectorType: rw`, `ro`, or `r` and a `serviceTemplate`:

- `rw`: the set label plus `kuberic.io/role=primary`.
- `ro`: the set label plus `kuberic.io/role=secondary`.
- `r`: only `kuberic.io/set=kvstore-a`.

Leave the template selector unset. Matching supplied selector entries are
accepted, but mismatches and extra keys are rejected; custom restrictions cannot
silently change role routing. `publishNotReadyAddresses: true` is disallowed.
Normal ready-endpoint filtering remains enabled, but neither that filter nor
`selectorType` verifies application health or read consistency.

#### App-only LoadBalancer

[`examples/kvstore/deploy/managed-services.yaml`](../../examples/kvstore/deploy/managed-services.yaml)
is a complete optional `KubericSet` manifest for the existing `kvstore-a` name and
`xedio` namespace. It retains the normal image, replica, storage, and container
port configuration, adding a `kvstore-a-client` LoadBalancer with **only**
Service port `8080` targeting application port `8080`.

```bash
# After the reference Gateway deployment, update kvstore-a with an additional endpoint.
kubectl apply -f examples/kvstore/deploy/managed-services.yaml
kubectl get service kvstore-a-client -n xedio -w
```

This does not change either reference application's Gateway route. For a
Gateway-only backend, use `type: ClusterIP` instead of `LoadBalancer` and create
a separate route to the additional Service as described below.

No provider-specific annotations are included. On a cloud, configure the
provider's internal/private load-balancer annotations or supported
`loadBalancerClass` before production use; a generic LoadBalancer does not imply
private access. A cloud/load-balancer controller must be installed and configured
to allocate ingress.

Every additional Service must explicitly list nonempty `spec.ports`. The
operator does not inherit, add, or filter ports based on `port`, `controlPort`,
or `dataPort`. The example therefore does not expose `9090`/`9091`. Numeric and
named `targetPort` values are supported; when `targetPort` is omitted,
Kubernetes defaults it to the Service port. Multiple ports require unique names.
Keep control and replication ports internal even though deliberately listing
those numbers is not forbidden by the API.

#### Separate NodePort Alternative

Where clients can reach cluster node addresses, use this separate native Service
instead of, or alongside, the LoadBalancer entry:

```yaml
spec:
  managed:
    services:
      additional:
        - selectorType: rw
          serviceTemplate:
            metadata:
              name: kvstore-a-nodeport
            spec:
              type: NodePort
              ports:
                - name: app
                  protocol: TCP
                  port: 8080
                  targetPort: 8080
```

This is a separate Service, not an overlay of `kvstore-a-rw`. Omit `nodePort` for
automatic allocation if a fixed port is unnecessary; the API server checks the
configured allocation range and whether the requested port is available.

**NodePort `30090` belongs only to Envoy in the reference KinD setup.** Additional
application NodePorts are not host-mapped by that setup. Native allocation does
not imply external reachability; use a Gateway route for local host access
without changing the canonical cluster configuration.

#### Gateway Backends

Additional `ClusterIP`, `NodePort`, and `LoadBalancer` Services can all be
Gateway backends. The
[operator README example](../../kuberic-operator/README.md#using-an-additional-service-behind-the-gateway)
creates a separate `GRPCRoute` with authority `kvstore-a-client.kuberic.test`
targeting `kvstore-a-client:8080`, alongside the unchanged reference routes.
Dial the shared loopback endpoint using that authority as shown in the
[Gateway client guide](../features/envoy-gateway-kind.md#clients-without-hosts-file-changes).

A route references the Service's `port`, not its `targetPort` or `nodePort`.
Keep the Service and route stable across primary transitions. When changing a
Service port, update the route's backend port too. The reference listener admits
same-namespace routes only; keeping Gateway, route, and backend in `xedio` avoids
cross-namespace grants. A cross-namespace backend requires a `ReferenceGrant`
in its namespace, and attaching a route from another namespace also requires
the listener's permission.

Gateway resources remain deployment-owned and outside the operator's managed
Service reconciliation. Check current-generation route `Accepted` and
`ResolvedRefs`, Gateway readiness, and ready endpoints separately from Service
provisioning status. A pending LoadBalancer ingress address need not block
Gateway access to the Service's ready in-cluster backends.

#### Configuration Ownership and Changes

`serviceTemplate.metadata` accepts only a required `name` and optional
`labels`/`annotations`. The operator assigns the namespace and controller owner
reference from the live parent's name and UID. Service names must be unique
DNS1035 names, not the reserved `kvstore-a-rw`, `kvstore-a-ro`, or `kvstore-a-r`.
It injects `kuberic.io/set=kvstore-a` and
`kuberic.io/managed-service=additional`; conflicting template values are rejected.

The private **`kuberic.io/service-template` annotation is operator-owned** and
records versioned template ownership. Do not supply it in a template or
edit/remove it on a generated Service. Missing or corrupt recorded state on an
existing managed Service produces an explicit error rather than guessing which
fields the operator owns.

The template spec is a native Kubernetes `ServiceSpec`: `ClusterIP` (default),
`NodePort`, and `LoadBalancer` are supported. `ExternalName` and a nonempty
`externalName` are incompatible with generated routing. Native settings such as
traffic policies, source ranges, and load-balancer configuration are preserved;
the API server validates additional native combinations and provider limitations.

Only fields controlled by the template and injected routing/ownership fields
are reconciled; unrelated metadata and Kubernetes/provider-owned fields and
allocations are preserved when not controlled by the template. Previously
templated label and annotation keys are removed when omitted from the template.
The operator merges its recorded fields into a freshly read Service and fences
updates/deletes by UID and resource version to avoid acting on stale objects.
Modify the `KubericSet`, not the controlled fields on the generated Service.

Removing an entry prunes only operator-managed Services owned by the current
`KubericSet` UID; deleting the parent allows owner-reference garbage collection.
A foreign same-name Service is an error, not permission to adopt or delete it,
even if its labels match. Renaming changes the Service identity and can change
its address or allocated ports. Immutable edits (such as an incompatible
`clusterIP` or `loadBalancerClass` change) report an error and do **not**
automatically delete/recreate the Service. Plan replacements and client cutover
explicitly; do not assume an address will be retained.

#### Status and Troubleshooting

```bash
kubectl get kubericset kvstore-a -n xedio -o yaml
kubectl get service kvstore-a-client -n xedio -o wide
kubectl describe service kvstore-a-client -n xedio
kubectl get endpointslice -n xedio -l kubernetes.io/service-name=kvstore-a-client
```

Look at **`status.managedServices`**, not replication phase, for this feature.
It contains `observedGeneration`, a `Ready` condition, and per-Service
`name`, `type`, `ready`, `reason`, `message`, `ingress`, and `ports`. Compare
`observedGeneration` with `metadata.generation` before treating the status as
current.

`Ready=True` means the requested Services have reconciled and each LoadBalancer
has an allocated ingress IP or hostname. It does **not** verify application
readiness, ready endpoint count, external reachability, authentication, or
successful requests. Pending load-balancer ingress is **not a replication
failure**. Check the Service events and controller/provider configuration before
changing the replica set. For an error, inspect the reported reason/message:
look for a foreign name collision, invalid port/selector, unavailable NodePort,
or immutable edit. Correct the configuration rather than deleting unrelated
Services.

#### Connecting From Different Environments

| Environment | Connection path and prerequisites |
|-------------|-----------------------------------|
| Cloud provider | Use the allocated ingress IP or hostname and Service port `8080`. Private addresses require connectivity through the VNet/VPC, peering, or VPN. Pending ingress calls for checking the cloud controller, permissions, quota, provider settings, and Service events. |
| MetalLB | Install/configure a controller, an address pool, and L2/BGP advertisements appropriate to your network. Clients must be able to route to the allocated address; MetalLB alone does not guarantee host reachability. |
| Kind | Prefer the reference Gateway at `127.0.0.1:30090` with an application-specific authority. Envoy alone owns that NodePort and host mapping. Direct LoadBalancer access needs a compatible provider such as cloud-provider-kind or correctly networked MetalLB; bare Kind does not allocate ingress. |
| Minikube | Run `minikube tunnel` for LoadBalancer access. For the NodePort alternative, use `minikube service kvstore-a-nodeport -n xedio --url`. Depending on the driver, keep the helper process running. |

For an in-cluster application check independent of ingress allocation, use
`kvstore-a-client.xedio.svc:8080` from a reachable cluster workload. A local
`kubectl -n xedio port-forward svc/kvstore-a-client 8080:8080` can also help when
port-forwarding works in your environment; it is a diagnostic connection, not
proof that the external path works.

Prefer private/internal load balancers. Restrict firewalls/security groups and
supported `loadBalancerSourceRanges`, and apply NetworkPolicy to the application
pods. Do not expose the control/replication plane to untrusted networks. A
Kubernetes Service adds no authentication, authorization, or TLS; provide them
in the application or a gRPC-capable gateway before exposing client traffic.
Clients need reconnection, DNS re-resolution when addresses change, and
idempotent/bounded retries with backoff for failover, switchover, and Service
replacement. Long-lived connections do not automatically follow new endpoints.

### Gateway Development and Integration Tests

`just gateway-test` exercises both reference applications through their shared
Gateway without changing the normal internal Services. See the
[Gateway guide](../features/envoy-gateway-kind.md#primary-transitions-and-validation)
for its authority routing, isolation, failover, and switchover assertions.

The separate [managed Service scenario](../../kuberic-tests/src/managed_services_k8s.rs)
creates its own TCP Gateway, EnvoyProxy, and TCPRoute using the installed
GatewayClass. It forwards a dynamically allocated loopback port to the
fixture's **Envoy proxy Service**, never directly to an application backend.
The TCPRoute targets the additional app-only Service. This checks real
Gateway-to-Service backend routing, EndpointSlice convergence, connection loss,
and fresh connections across primary transitions, while preserving Service and
route identity. The shared Gateway and reference routes are not modified.

This scenario retains native NodePort type/allocation and allocation-preserving
update checks, but **does not test direct NodePort forwarding**. The Service port
edit is also applied to the TCPRoute, retaining application target port `8080`.
Simulated LoadBalancer ingress verifies provisioning status only, not cloud
load-balancer transport. Owner references and fixture-only cleanup remove only
the test's resources. Run it with the [development instructions](../Dev.md#isolated-kubernetes-routing-test).

## Data Address Registration

The operator reads `pod.Status.PodIP` from the Kubernetes API and
constructs `GrpcReplicaHandle` addresses in `create_replica_handle()`
and `build_member_status()`.

**Invariant**: Only read PodIP from pods that pass `is_pod_ready()`.
The reconciler enforces this via the `ready_pods` filter.

## Persistent Storage (PVC)

The operator manages PVCs directly (one per pod, CNPG pattern).
PVCs persist across pod restarts for data recovery.

### PVC Lifecycle

| Scenario | PVC State | Behavior |
|----------|-----------|----------|
| Pod crash/restart | PVC exists | Re-attach, kvstore reads existing data |
| Pod deleted | PVC exists | Operator creates new pod, attaches PVC |
| PVC deleted | Gone | Fresh PVC + pod, copy from primary rebuilds state |
| CR deleted | Depends on policy | `pvcRetentionPolicy: Delete` cleans up; `Retain` preserves |

### PVC Spec

PVCs use labels (no `ownerReferences`) to prevent cascade deletion:

```yaml
metadata:
  name: kvstore-a-0-data
  labels:
    kuberic.io/set: kvstore-a
    kuberic.io/pod-index: "0"
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 256Mi  # from KubericSetSpec.storage
```

### CRD Fields

```rust
pub storage: String,                         // e.g. "256Mi"
pub pvc_retention_policy: PvcRetentionPolicy, // Delete (default) | Retain
```

### Idempotent Creation

`ensure_pvc()` and `ensure_pod()` check existence before creating —
safe to re-run after operator crash mid-creation. Scale-up calls
`ensure_pvc` before `ensure_pod` for each new index.

### Readiness and Liveness Probes

TCP probes on the control port (9090):

- **Readiness**: initialDelay=5s, period=5s, failureThreshold=2
- **Liveness**: initialDelay=10s, period=10s, failureThreshold=3

### RBAC

```yaml
- apiGroups: [""]
  resources: ["persistentvolumeclaims"]
  verbs: ["get", "list", "watch", "create", "delete"]
- apiGroups: [""]
  resources: ["services"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
```

## Deployment Workflow

```
# First configure the owned cluster environment from the Gateway setup guide.
# One-time setup
just create-kind-cluster

# Build and load images
just images
  → builds rust binaries
  → builds kvstore docker image
  → builds kuberic-operator docker image
  → loads both into kind

# Deploy
just kvstore-deploy

# Verify
kubectl get kubericsets -n xedio
kubectl get pods -n xedio
just gateway-test
```

## Implementation Summary

The original Kubernetes deployment landed in two PRs:

### PR 1: Operator Infrastructure (done)

- ClusterApi trait: 7 new PVC/Service methods + KubeClusterApi impls
- `build_pod()`: typed `k8s_openapi` builders with probes, env, labels
- `build_pvc()`, `ensure_pvc()`, `ensure_pod()`: idempotent creation
- `create_services()`: rw/ro/r ClusterIP services
- CRD: `storage` and `pvc_retention_policy` fields
- Mock KvClusterApi: HashMap PVC/Service storage
- Tests: PVC/Service assertions + idempotent creation test (38 tests pass)

### PR 2: KVStore K8s Deployment (done)

- kvstore Dockerfile + Just recipes
- kuberic-operator Dockerfile + manifests (CRD, RBAC, Deployment)
- Binary env var support via clap `env` attribute
- KinD config consolidated at `deploy/kind-config.yaml`
- Original single-set host access and tests, since replaced by the
  [shared Gateway workflow](../features/envoy-gateway-kind.md)

### Current Access Additions

- Shared Gateway deployment and two-application isolation/primary-transition tests
- Optional managed application Services and the Gateway-backed Service
  failover/switchover scenario described above

## Open Questions

1. **Operator CRD extensions**: Should `KubericSetSpec` grow fields
   for `env`/custom volume mounts, or keep it minimal?

2. ~~**RWO volume fencing**~~: Deferred to multi-node support.

3. ~~**PVC retention policy**~~: Resolved — `pvcRetentionPolicy` field
   (Delete default, Retain option).

4. ~~**Stale-epoch PVC reattach**~~: Resolved — copy protocol
   overwrites stale data.

5. ~~**`build_pod()` typed builders**~~: Resolved — implemented with
   `k8s_openapi` typed builders.

6. ~~**KinD config consolidation**~~: Resolved — single canonical
   config; the current KVStore reference shares Envoy's loopback mapping.
