# kuberic-operator

Kubernetes operator for [Kuberic](../README.md). Manages `KubericSet` custom resources — creates pods, orchestrates lifecycle, and handles failover.

## What It Does

1. Watches `KubericSet` CRDs (desired replica count, image, ports)
2. Creates/deletes bare pods to match desired state
3. Persists durable topology intent and delegates ordered effects through each
   pod's `ReplicaAgent`
4. Detects pod failures and triggers automatic failover
5. Sends one coarse scale-up/rebuild or scale-down/force-remove intent to the
   primary agent while retaining durable topology and Kubernetes ownership
6. Optionally reconciles additional application-facing Services without changing
   the internal replication Services

## CRD Example

```yaml
apiVersion: kuberic.io/v1
kind: KubericSet
metadata:
  name: my-app
spec:
  replicas: 3
  image: my-app:latest
  controlPort: 50051
  dataPort: 50052
  port: 50053
```

## Deployment

For development and CI, follow the [shared Gateway KinD setup](../docs/features/envoy-gateway-kind.md).
`just kvstore-deploy` installs the operator, both KVStore applications, and
their Gateway in the owned cluster. Gateway installation remains outside the
operator; the operator continues to manage only Kuberic resources.

## Managed Application Services

`spec.managed.services.additional` opts a `KubericSet` into additional Services.
Omitting `managed`, or using an empty `additional` list, requests no additional
Services. The existing `<set>-rw`, `<set>-ro`, and `<set>-r` Services are unchanged,
including their internal application, control, and replication ports.
These additional Services can provide direct client access or serve as app-only
backends for a deployment-owned Gateway route. The operator does not install a
Gateway controller or create Gateway API resources.

Each entry contains a `selectorType` and a native `serviceTemplate`:

| `selectorType` | Operator-generated pod selector | Routing |
|----------------|----------------------------------|---------|
| `rw` | `kuberic.io/set=<set>`, `kuberic.io/role=primary` | Primary |
| `ro` | `kuberic.io/set=<set>`, `kuberic.io/role=secondary` | Secondaries |
| `r` | `kuberic.io/set=<set>` | All ready matching pods |

Templates normally omit `spec.selector`. A supplied subset must agree with the
generated selector; conflicting values and extra selector keys are rejected.
`publishNotReadyAddresses: true` is rejected so normal Kubernetes ready-endpoint
filtering remains in effect. Role selection is not an application health or
read-consistency check.

### App-only LoadBalancer

The complete optional example,
[`examples/kvstore/deploy/managed-services.yaml`](../examples/kvstore/deploy/managed-services.yaml),
updates `kvstore-a` in namespace `xedio`, as deployed by
[`deploy/gateway/applications.yaml`](../deploy/gateway/applications.yaml).
Apply it after the reference deployment when you want an additional endpoint;
the existing Gateway routes remain unchanged:

```bash
kubectl apply -f examples/kvstore/deploy/managed-services.yaml
```

Its additional configuration is:

```yaml
spec:
  managed:
    services:
      additional:
        - selectorType: rw
          serviceTemplate:
            metadata:
              name: kvstore-a-client
            spec:
              type: LoadBalancer
              ports:
                - name: app
                  protocol: TCP
                  port: 8080
                  targetPort: 8080
```

This exposes only the application port. **Ports are required and never inherited
from `spec.port`, `controlPort`, or `dataPort`.** Numeric or named `targetPort`
values use native Kubernetes semantics; omitting `targetPort` lets Kubernetes use
the Service `port`. No control/data ports are added, and explicitly supplied port
numbers are not silently filtered.

A LoadBalancer needs a working cloud/load-balancer controller. The example has
no provider-specific annotations and does **not** promise a private address.
Configure your provider's private/internal load-balancer settings in the template
before production use.

### Separate NodePort Alternative

Use this entry instead of, or alongside, the LoadBalancer entry in your
`additional` list. It creates a **separate** Service rather than changing
`kvstore-a-rw`:

```yaml
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

Omitting `nodePort` (or setting it to `0`) requests native allocation. To request
a fixed port, choose an unused value in the API server's configured range.
**NodePort `30090` belongs exclusively to Envoy in the reference KinD setup.**
That setup does not map additional application NodePorts to the host. Use a
Gateway route for host access instead; native NodePort allocation does not by
itself guarantee host reachability.

### Using an Additional Service Behind the Gateway

An additional `ClusterIP`, `NodePort`, or `LoadBalancer` Service can be a route
backend. For example, create a separate `GRPCRoute` for the app-only Service
without changing either reference application's route:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: GRPCRoute
metadata:
  name: kvstore-a-client
  namespace: xedio
spec:
  parentRefs:
    - name: kuberic
      sectionName: grpc
  hostnames:
    - kvstore-a-client.kuberic.test
  rules:
    - backendRefs:
        - name: kvstore-a-client
          port: 8080
```

Dial `127.0.0.1:30090` with authority `kvstore-a-client.kuberic.test`, following
the [Gateway client examples](../docs/features/envoy-gateway-kind.md#clients-without-hosts-file-changes).
The route's port is the **Service port**, not `targetPort` or the allocated
NodePort; update it when editing that Service port. Keep these resources in
`xedio` to match the reference listener's same-namespace policy. Cross-namespace
backends require a `ReferenceGrant` in the backend namespace, and cross-namespace
route attachment also needs the listener's permission.

Routes remain deployment-owned, outside managed-Service reconciliation. Route
acceptance, ready endpoints, and connectivity must be checked separately from
`status.managedServices`. In particular, a pending external LoadBalancer address
does not prevent a Gateway from using the Service's ready in-cluster backends.

### Template Boundaries and Lifecycle

- `serviceTemplate.metadata` accepts only `name`, `labels`, and `annotations`.
  The operator supplies the parent's namespace and a controller owner reference
  to that exact `KubericSet` UID. Names must be unique DNS1035 Service names and
  cannot be the reserved `<set>-rw`, `<set>-ro`, or `<set>-r` names.
- The operator injects `kuberic.io/set=<set>` and
  `kuberic.io/managed-service=additional` labels. Matching template labels are
  allowed; conflicting values are rejected.
- The private `kuberic.io/service-template` annotation records versioned
  operator-owned template state. It is reserved: **do not set it in a template
  or edit/remove it on a generated Service**. Missing or corrupt recorded state
  on an existing managed Service is reported explicitly; the operator does not
  guess ownership.
- `spec` is a native Kubernetes `ServiceSpec`. `ClusterIP` is the default;
  `NodePort` and `LoadBalancer` are supported. `ExternalName` and nonempty
  `externalName` are incompatible with operator-controlled routing. Native
  fields such as traffic policies, source ranges, load-balancer class, and
  provider annotations can be configured; Kubernetes still validates native
  field combinations.
- Only template-controlled fields and injected routing/ownership metadata are
  reconciled. Unrelated metadata and Kubernetes/provider-owned allocations are
  preserved when they are not template-controlled. Previously templated label
  and annotation keys are removed when omitted from the template. Edit the
  template, not its controlled fields on the generated Service.
- Removing an entry prunes only operator-managed Services owned by the current
  parent UID. Owner references provide garbage collection on parent deletion.
  A same-name foreign Service is rejected, not adopted, overwritten, or deleted;
  matching labels alone do not grant ownership.
- Renaming an entry creates a different Service identity and prunes the old
  owned Service; its address and allocated ports may change. Immutable edits
  (for example, changing an allocated `clusterIP` or `loadBalancerClass`) report
  an error and **never automatically delete/recreate** the Service. Correct the
  template or plan an explicit replacement and client migration.
  Creation and updates precede pruning; a reconciliation failure preserves the
  previous exposure for retry rather than deleting it first.

### Status and Connectivity

Inspect `status.managedServices`, separately from replication/topology status:

```bash
kubectl get kubericset kvstore-a -n xedio -o yaml
kubectl get service kvstore-a-client -n xedio -o wide
kubectl describe service kvstore-a-client -n xedio
```

`observedGeneration` identifies the processed configuration. The `Ready`
condition means the requested Services have reconciled, and LoadBalancer
Services have an allocated ingress IP or hostname. Per-Service entries report
`name`, `type`, `ready`, `reason`, `message`, native `ingress`, and `ports`.
**This is not application readiness, a guarantee of ready endpoints, or an
end-to-end connectivity check.** Pending load-balancer provisioning is not a
replication failure and does not itself mean the replica set is unhealthy.
Native load-balancer ingress port errors are reported as `LoadBalancerError`,
even if an ingress address has already been assigned. For provider failures
reported only through Kubernetes Events, inspect the Service with `kubectl describe`.

- **Cloud:** connect to the reported ingress IP/hostname on the Service port
  (`8080` here). Private load balancers need private-network/VPN reachability.
  Check provider permissions, quotas, and Service events if ingress stays pending.
- **MetalLB:** install/configure its controller, address pools, and network
  advertisements; ensure clients can route to the allocated address.
- **Kind:** a bare cluster does not provision LoadBalancers. Install a compatible
  provider (for example, cloud-provider-kind) or correctly network MetalLB for
  direct LoadBalancer access. For local development, prefer the reference
  Gateway on `127.0.0.1:30090` with a distinct route authority. Only its Envoy
  proxy Service owns that NodePort and host mapping.
- **Minikube:** use `minikube tunnel` for LoadBalancer access, or
  `minikube service kvstore-a-nodeport -n xedio --url` for NodePort access; some
  drivers require the helper process to remain running.

Prefer private load balancers, restrict firewall/security-group rules and
`loadBalancerSourceRanges` where supported, and apply NetworkPolicy for the
application endpoints. Keep control/replication ports cluster-private. A Service
does not provide authentication, authorization, or TLS: supply those in the
application or an appropriate gRPC-capable gateway. Clients must reconnect,
re-resolve changed addresses, and retry safely with backoff after failover,
switchover, or Service replacement; existing connections do not migrate when
selectors' matching pod labels change.

See the [KVStore deployment guide](../docs/implemented/kvstore-k8s-deployment.md)
for the deployment and troubleshooting walkthrough.

## Architecture

| Module | Purpose |
|--------|---------|
| `crd.rs` | `KubericSet` CRD definition and status types |
| `reconciler.rs` | Main reconcile loop — pod management, lifecycle orchestration |
| `cluster_api.rs` | Kubernetes API helpers for pod/service operations |
| `service_config.rs` | Managed-Service API types, validation, and pure rendering |
| `services.rs` | Additional-Service reconciliation and independently owned status |
| `node_maintenance/` | `NodeMaintenanceRequest` CRD, preflight decisions and affected-replica discovery |
