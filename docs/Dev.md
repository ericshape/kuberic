Install kind on windows
```ps1
winget install Kubernetes.kind
```

Add alias for kind in bashrc
```sh
alias kind="<kind location>/kind.exe"
```

For multiple KVStore applications sharing one loopback host port, see the
[Envoy Gateway KinD setup](features/envoy-gateway-kind.md). Local development
and CI use this single setup, with two applications behind one Gateway. It
replaces the former single-set NodePort setup.

## Managed Service development

Run the focused operator and in-process reconciler tests:

```sh
cargo test -p kuberic-operator --lib
cargo test -p kvstore --test reconciler
```

The managed Service API embeds standard Kubernetes Service types. After changing
these types or updating their dependency, regenerate the two marked schema
sections in the [deployment manifest](../kuberic-operator/deploy/deployment.yaml):

```sh
cargo run --quiet -p kuberic-operator --example crd \
  | python3 scripts/update-managed-service-schema.py
```

The generated JSON fragments are valid YAML values. A unit test compares both
deployed fragments to the derived CRD schema exactly.

### Isolated Kubernetes routing test

The [managed Service integration test](../kuberic-tests/src/managed_services_k8s.rs)
uses the same isolated [Gateway KinD setup](features/envoy-gateway-kind.md),
images, and pinned Gateway API/Envoy dependencies. Follow that guide's platform
and tool prerequisites. Never target a shared cluster or the default kubeconfig.

```sh
export KIND_CLUSTER_NAME=kuberic-managed-services-dev
mkdir -p target/managed-services-dev
export KUBECONFIG="$PWD/target/managed-services-dev/kubeconfig"
export KUBE_CONTEXT="kind-${KIND_CLUSTER_NAME}"
just create-kind-cluster
just images
just kvstore-deploy
cargo test -p kuberic-tests test_managed_services_route_new_connections_after_failover_and_switchover -- --nocapture
just delete-kind-cluster
```

Use a unique cluster name and kubeconfig path; the shared Gateway's loopback
host port `30090` must also be free. Only Envoy owns NodePort `30090`. Do not add
application NodePort mappings or overlays to the reference configuration.

The test creates a unique KubericSet, an app-only NodePort Service with native
port allocation, and a pending LoadBalancer Service. It uses the installed
`kuberic-envoy` GatewayClass for its own TCP Gateway, EnvoyProxy, and TCPRoute in
`xedio`. A dynamically allocated loopback `kubectl port-forward` connects only
to that Gateway's proxy Service, **not** to an application pod or Service.
This preserves a real TCP proxy path through the additional Service's backend
and permits checking that an established connection closes on primary failure.
No shared Gateway, route, host mapping, or reference application is changed.

The test checks Service identity/allocation and EndpointSlice convergence,
fresh connections after failover and switchover, Service-port edits (with the
TCPRoute backend port updated), and owner-reference garbage collection. Its
transport coverage is **Gateway TCP routing, not direct NodePort forwarding**.
It injects LoadBalancer ingress status only to verify provisioning reporting;
it does not provision or validate a real cloud load balancer. Cleanup is limited
to the test-owned Gateway resources and fixture resources.

Cluster-free checks for the managed-Service Gateway helpers can run separately:

```sh
cargo test -p kuberic-tests managed_services_k8s:: -- --skip test_managed_services_route_new_connections_after_failover_and_switchover
```

### Kubernetes API-only validation

The [API integration test](../kuberic-operator/tests/managed_services_api.rs) can
also run without Docker against a fresh, disposable
[envtest](https://book.kubebuilder.io/reference/envtest.html) Kubernetes API server.
It tests CRD admission, Kubernetes defaulting/allocation, no-op updates,
resource-version fencing, ownership conflicts, removal, and status preservation.
It does not test Pod traffic or garbage collection controllers.

Provide the server's HTTPS loopback URL and a file containing its disposable
bearer token (configured through the API server's `--token-auth-file`). The test
never loads a user kubeconfig and refuses non-loopback URLs:

```sh
KUBERIC_API_TEST_URL="https://127.0.0.1:<port>" \
KUBERIC_API_TEST_TOKEN_FILE=/path/to/disposable/token \
cargo test -p kuberic-operator --test managed_services_api -- --ignored
```

Use only a fresh disposable server: this test installs the CRD, creates a unique
test namespace, and removes its own resources. It is ignored during ordinary
test runs.
