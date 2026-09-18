use std::collections::BTreeSet;
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::Result;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{PersistentVolumeClaim, Pod, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::{
    ApiResource, DeleteParams, DynamicObject, ListParams, Patch, PatchParams, PostParams,
    Preconditions,
};
use kube::{Api, ResourceExt};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tonic::transport::Endpoint;

const NAMESPACE: &str = "xedio";
const GATEWAY_CONTROLLER: &str = "gateway.envoyproxy.io/gatewayclass-controller";

fn gateway_api(
    client: kube::Client,
    group: &str,
    version: &str,
    kind: &str,
    plural: &str,
) -> Api<DynamicObject> {
    Api::namespaced_with(
        client,
        NAMESPACE,
        &ApiResource {
            group: group.into(),
            version: version.into(),
            kind: kind.into(),
            api_version: format!("{group}/{version}"),
            plural: plural.into(),
        },
    )
}

fn owned_gateway_resource(
    api_version: &str,
    kind: &str,
    parent: &DynamicObject,
    spec: Value,
) -> DynamicObject {
    serde_json::from_value(json!({
        "apiVersion": api_version,
        "kind": kind,
        "metadata": {
            "name": parent.name_any(),
            "namespace": NAMESPACE,
            "ownerReferences": [{
                "apiVersion": "kuberic.io/v1",
                "kind": "KubericSet",
                "name": parent.name_any(),
                "uid": parent.metadata.uid.as_ref().expect("fixture parent UID"),
                "controller": true
            }]
        },
        "spec": spec
    }))
    .unwrap()
}

fn conditions_ready(conditions: Option<&Value>, generation: i64, required: &[&str]) -> bool {
    conditions
        .and_then(Value::as_array)
        .is_some_and(|conditions| {
            required.iter().all(|required| {
                conditions.iter().any(|condition| {
                    condition["type"].as_str() == Some(required)
                        && condition["status"] == "True"
                        && condition["observedGeneration"].as_i64() == Some(generation)
                })
            })
        })
}

fn tcp_route_ready(route: &DynamicObject, gateway: &str) -> bool {
    route
        .data
        .pointer("/status/parents")
        .and_then(Value::as_array)
        .is_some_and(|parents| {
            parents.iter().any(|parent| {
                let reference = &parent["parentRef"];
                reference["name"] == gateway
                    && reference["sectionName"] == "tcp"
                    && reference["namespace"].as_str().unwrap_or(NAMESPACE) == NAMESPACE
                    && reference["group"]
                        .as_str()
                        .unwrap_or("gateway.networking.k8s.io")
                        == "gateway.networking.k8s.io"
                    && reference["kind"].as_str().unwrap_or("Gateway") == "Gateway"
                    && parent["controllerName"] == GATEWAY_CONTROLLER
                    && conditions_ready(
                        parent.get("conditions"),
                        route.metadata.generation.unwrap_or_default(),
                        &["Accepted", "ResolvedRefs"],
                    )
            })
        })
}

fn tcp_route_targets_service(route: &DynamicObject, service: &str, port: i32) -> bool {
    let Some(rules) = route.data.pointer("/spec/rules").and_then(Value::as_array) else {
        return false;
    };
    let [rule] = rules.as_slice() else {
        return false;
    };
    let Some(backends) = rule.get("backendRefs").and_then(Value::as_array) else {
        return false;
    };
    let [backend] = backends.as_slice() else {
        return false;
    };
    backend["name"] == service
        && backend["port"] == port
        && backend.get("group").is_none_or(|group| group == "")
        && backend.get("kind").is_none_or(|kind| kind == "Service")
        && backend
            .get("namespace")
            .is_none_or(|namespace| namespace == NAMESPACE)
        && backend.get("weight").is_none_or(|weight| weight == 1)
}

async fn wait_gateway_resource(
    api: &Api<DynamicObject>,
    name: &str,
    predicate: impl Fn(&DynamicObject) -> bool,
) -> DynamicObject {
    let deadline = Instant::now() + Duration::from_secs(240);
    loop {
        let object = api.get_opt(name).await.expect("read Gateway resource");
        if let Some(object) = &object
            && predicate(object)
        {
            return object.clone();
        }
        assert!(
            Instant::now() < deadline,
            "Gateway resource {name} did not converge: {object:?}; run just kvstore-deploy first"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn wait_proxy_service(client: kube::Client, gateway: &str) -> Service {
    let services: Api<Service> = Api::all(client.clone());
    let deployments: Api<Deployment> = Api::all(client);
    let params = ListParams::default().labels(&format!(
        "gateway.envoyproxy.io/owning-gateway-name={gateway},gateway.envoyproxy.io/owning-gateway-namespace={NAMESPACE}"
    ));
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let services = services
            .list(&params)
            .await
            .expect("list fixture proxy Service");
        let deployments = deployments
            .list(&params)
            .await
            .expect("list fixture proxy Deployment");
        if let [service] = services.items.as_slice()
            && !deployments.items.is_empty()
            && deployments.items.iter().all(|deployment| {
                let replicas = deployment.spec.as_ref().and_then(|spec| spec.replicas);
                replicas.is_some_and(|replicas| replicas > 0)
                    && deployment.status.as_ref().is_some_and(|status| {
                        status.observed_generation == deployment.metadata.generation
                            && status.available_replicas == replicas
                            && status.updated_replicas == replicas
                    })
            })
        {
            let spec = service.spec.as_ref().expect("proxy Service spec");
            assert_eq!(spec.type_.as_deref(), Some("ClusterIP"));
            assert!(
                spec.ports.as_ref().is_some_and(|ports| {
                    ports
                        .iter()
                        .any(|port| port.port == 8080 && port.node_port.is_none())
                }),
                "fixture proxy must not claim a host NodePort"
            );
            return service.clone();
        }
        assert!(
            Instant::now() < deadline,
            "fixture proxy did not become ready"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

struct GatewayPortForward {
    child: tokio::process::Child,
    output: tokio::task::JoinHandle<()>,
    endpoint: String,
}

impl GatewayPortForward {
    async fn start(service: &Service) -> Self {
        let (kubeconfig, context) = crate::test_utils::isolated_kube_coordinates();
        let mut child = tokio::process::Command::new("kubectl")
            .args([
                "--kubeconfig",
                &kubeconfig,
                "--context",
                &context,
                "--namespace",
                &service.namespace().expect("proxy namespace"),
                "port-forward",
                "--address=127.0.0.1",
                "--pod-running-timeout=120s",
                &format!("service/{}", service.name_any()),
                ":8080",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .expect("start fixture Gateway port-forward");
        let mut output = BufReader::new(child.stdout.take().unwrap()).lines();
        let endpoint = tokio::time::timeout(Duration::from_secs(120), async {
            loop {
                let line = output
                    .next_line()
                    .await
                    .expect("read Gateway port-forward output")
                    .expect("Gateway port-forward exited before listening");
                if let Some(mapping) = line.strip_prefix("Forwarding from 127.0.0.1:")
                    && let Some((port, _target_port)) = mapping.split_once(" -> ")
                {
                    let port: u16 = port.parse().expect("allocated loopback port");
                    assert_ne!(port, 0);
                    return format!("http://127.0.0.1:{port}");
                }
            }
        })
        .await
        .expect("Gateway port-forward did not become ready");
        assert!(child.try_wait().unwrap().is_none());
        let output = tokio::spawn(async move {
            while let Ok(Some(line)) = output.next_line().await {
                tracing::debug!(%line, "fixture Gateway port-forward");
            }
        });
        Self {
            child,
            output,
            endpoint,
        }
    }

    async fn stop(mut self) {
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "Gateway port-forward exited during the scenario"
        );
        self.child
            .kill()
            .await
            .expect("stop fixture Gateway port-forward");
        self.child
            .wait()
            .await
            .expect("reap fixture Gateway port-forward");
    }
}

impl Drop for GatewayPortForward {
    fn drop(&mut self) {
        self.output.abort();
    }
}

fn sets(client: kube::Client) -> Api<DynamicObject> {
    Api::namespaced_with(
        client,
        NAMESPACE,
        &kube::discovery::ApiResource {
            group: "kuberic.io".to_string(),
            version: "v1".to_string(),
            kind: "KubericSet".to_string(),
            api_version: "kuberic.io/v1".to_string(),
            plural: "kubericsets".to_string(),
        },
    )
}

async fn wait_set(
    api: &Api<DynamicObject>,
    name: &str,
    predicate: impl Fn(&DynamicObject) -> bool,
) -> DynamicObject {
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        let set = api.get(name).await.expect("read test KubericSet");
        if predicate(&set) {
            return set;
        }
        assert!(
            Instant::now() < deadline,
            "KubericSet did not converge: {:?}",
            set.data
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn wait_service(api: &Api<Service>, name: &str, exists: bool) {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if api
            .get_opt(name)
            .await
            .expect("read test Service")
            .is_some()
            == exists
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Service {name} existence did not become {exists}"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn wait_primary_endpoint(client: kube::Client, service: &str, primary: &str) {
    let api: Api<EndpointSlice> = Api::namespaced(client, NAMESPACE);
    let params = ListParams::default().labels(&format!("kubernetes.io/service-name={service}"));
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let slices = api
            .list(&params)
            .await
            .expect("list Service EndpointSlices");
        let ready: BTreeSet<String> = slices
            .items
            .iter()
            .flat_map(|slice| &slice.endpoints)
            .filter(|endpoint| {
                endpoint.conditions.as_ref().is_some_and(|condition| {
                    condition.ready == Some(true) && condition.terminating != Some(true)
                })
            })
            .filter_map(|endpoint| {
                endpoint
                    .target_ref
                    .as_ref()
                    .and_then(|target| target.name.clone())
            })
            .collect();
        if ready == BTreeSet::from([primary.to_string()]) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Service {service} endpoints {ready:?} did not converge to {primary}"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn retryable_gateway_error(error: &anyhow::Error) -> bool {
    if let Some(status) = error.downcast_ref::<tonic::Status>() {
        return matches!(
            status.code(),
            tonic::Code::Unavailable | tonic::Code::DeadlineExceeded | tonic::Code::Cancelled
        );
    }
    error.downcast_ref::<tonic::transport::Error>().is_some()
}

async fn connect_and_write(endpoint: &str, key: &str) {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let attempt = async {
            let channel = Endpoint::from_shared(endpoint.to_string())?
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(5))
                .connect()
                .await?;
            let mut client = kvstore::proto::kv_store_client::KvStoreClient::new(channel);
            client
                .put(kvstore::proto::PutRequest {
                    key: key.to_string(),
                    value: key.to_string(),
                })
                .await?;
            for expected in [key, "before-failover"] {
                let value = client
                    .get(kvstore::proto::GetRequest {
                        key: expected.to_string(),
                    })
                    .await?
                    .into_inner();
                assert!(value.found, "missing acknowledged value for {expected}");
                assert_eq!(value.value, expected);
            }
            Ok::<_, anyhow::Error>(())
        };
        let result: Result<Result<()>, _> = tokio::time::timeout(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(10)),
            attempt,
        )
        .await;
        match result {
            Ok(Ok(())) => return,
            Ok(Err(error)) if !retryable_gateway_error(&error) => {
                panic!("permanent failure through {endpoint}: {error:?}");
            }
            failure => {
                assert!(
                    Instant::now() < deadline,
                    "new connection through {endpoint} failed: {failure:?}"
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

async fn established_tcp_connection(endpoint: &str) -> tokio::net::TcpStream {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut connection =
            tokio::net::TcpStream::connect(endpoint.strip_prefix("http://").unwrap())
                .await
                .expect("connect to fixture TCP Gateway");
        // A TCP listener cannot generate HTTP/2 SETTINGS: this proves the proxy reached the app.
        connection
            .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0\0\0\x04\0\0\0\0\0")
            .await
            .unwrap();
        let mut header = [0; 9];
        connection.read_exact(&mut header).await.unwrap();
        assert_eq!(&header[3..], b"\x04\0\0\0\0\0", "expected server SETTINGS");
        let length =
            (usize::from(header[0]) << 16) | (usize::from(header[1]) << 8) | usize::from(header[2]);
        assert!(length <= 16384);
        assert_eq!(length % 6, 0);
        connection.read_exact(&mut vec![0; length]).await.unwrap();
        connection
            .write_all(b"\0\0\0\x04\x01\0\0\0\0")
            .await
            .unwrap();
        connection
    })
    .await
    .expect("TCP connection did not reach the application before primary failure")
}

fn primary(set: &DynamicObject) -> &str {
    set.data["status"]["currentPrimary"]
        .as_str()
        .expect("current primary")
}

fn service_template(name: &str, service_type: &str) -> Value {
    json!({
        "selectorType": "rw",
        "serviceTemplate": {
            "metadata": {"name": name},
            "spec": {"type": service_type, "ports": [{"name": "app", "port": 8080, "targetPort": 8080}]}
        }
    })
}

fn ready_tcp_route_fixture() -> DynamicObject {
    serde_json::from_value(json!({
        "apiVersion": "gateway.networking.k8s.io/v1alpha2",
        "kind": "TCPRoute",
        "metadata": {"name": "fixture", "namespace": NAMESPACE, "generation": 7},
        "status": {"parents": [{
            "parentRef": {"name": "fixture", "sectionName": "tcp"},
            "controllerName": GATEWAY_CONTROLLER,
            "conditions": [
                {"type": "Accepted", "status": "True", "observedGeneration": 7},
                {"type": "ResolvedRefs", "status": "True", "observedGeneration": 7}
            ]
        }]}
    }))
    .unwrap()
}

#[test]
fn managed_tcp_route_requires_its_exact_gateway_parent() {
    let route = ready_tcp_route_fixture();
    assert!(tcp_route_ready(&route, "fixture"));
    assert!(!tcp_route_ready(&route, "another-fixture"));
    for (field, value) in [
        ("name", json!("kuberic")),
        ("namespace", json!("another-namespace")),
        ("sectionName", json!("grpc")),
        ("sectionName", Value::Null),
        ("group", json!("another.group")),
        ("kind", json!("Service")),
    ] {
        let mut other = route.clone();
        other.data["status"]["parents"][0]["parentRef"][field] = value;
        assert!(
            !tcp_route_ready(&other, "fixture"),
            "accepted wrong {field}"
        );
    }
    let mut other_controller = route.clone();
    other_controller.data["status"]["parents"][0]["controllerName"] = json!("other");
    assert!(!tcp_route_ready(&other_controller, "fixture"));
    let mut explicit = route;
    explicit.data["status"]["parents"][0]["parentRef"]["namespace"] = json!(NAMESPACE);
    assert!(tcp_route_ready(&explicit, "fixture"));
}

#[test]
fn managed_tcp_route_rejects_stale_or_unresolved_conditions() {
    let route = ready_tcp_route_fixture();
    for condition in 0..2 {
        for (field, value) in [
            ("status", json!("False")),
            ("status", json!("Unknown")),
            ("observedGeneration", json!(6)),
            ("observedGeneration", Value::Null),
        ] {
            let mut stale = route.clone();
            stale.data["status"]["parents"][0]["conditions"][condition][field] = value;
            assert!(!tcp_route_ready(&stale, "fixture"));
        }
    }
    assert!(!conditions_ready(None, 7, &["Accepted", "Programmed"]));
    let mut missing = route;
    missing.data["status"]["parents"][0]["conditions"] = json!([]);
    assert!(!tcp_route_ready(&missing, "fixture"));
}

#[test]
fn managed_tcp_route_accepts_native_backend_defaults() {
    let mut route = ready_tcp_route_fixture();
    for port in [8080, 8082] {
        for backend in [
            json!({"name": "fixture-external", "port": port}),
            json!({"group": "", "kind": "Service", "name": "fixture-external", "port": port, "weight": 1}),
            json!({"group": "", "kind": "Service", "namespace": NAMESPACE, "name": "fixture-external", "port": port, "weight": 1}),
        ] {
            route.data["spec"] = json!({"rules": [{"backendRefs": [backend]}]});
            assert!(tcp_route_targets_service(&route, "fixture-external", port));
        }
    }
}

#[test]
fn managed_tcp_route_rejects_different_backend_semantics() {
    let mut route = ready_tcp_route_fixture();
    assert!(!tcp_route_targets_service(&route, "fixture-external", 8080));
    let backend = json!({
        "group": "", "kind": "Service", "name": "fixture-external", "port": 8080, "weight": 1
    });
    route.data["spec"] = json!({"rules": [{"backendRefs": [backend]}]});
    for (field, value) in [
        ("name", json!("another-service")),
        ("port", json!(8082)),
        ("port", Value::Null),
        ("group", json!("another.group")),
        ("kind", json!("Gateway")),
        ("kind", Value::Null),
        ("namespace", json!("another-namespace")),
        ("weight", json!(0)),
        ("weight", json!(2)),
    ] {
        let mut other = route.clone();
        other.data["spec"]["rules"][0]["backendRefs"][0][field] = value;
        assert!(
            !tcp_route_targets_service(&other, "fixture-external", 8080),
            "accepted wrong backend {field}"
        );
    }
    let rule = route.data["spec"]["rules"][0].clone();
    for rules in [
        json!([]),
        json!([rule, rule]),
        json!([{"backendRefs": []}]),
        json!([{"backendRefs": [backend, backend]}]),
    ] {
        route.data["spec"]["rules"] = rules;
        assert!(!tcp_route_targets_service(&route, "fixture-external", 8080));
    }
}

#[test]
fn managed_gateway_resources_belong_only_to_the_fixture_parent() {
    let parent: DynamicObject = serde_json::from_value(json!({
        "apiVersion": "kuberic.io/v1", "kind": "KubericSet",
        "metadata": {"name": "fixture", "namespace": NAMESPACE, "uid": "fixture-parent-uid"}
    }))
    .unwrap();
    let route = owned_gateway_resource(
        "gateway.networking.k8s.io/v1alpha2",
        "TCPRoute",
        &parent,
        json!({
            "parentRefs": [{"name": "fixture", "sectionName": "tcp"}],
            "rules": [{"backendRefs": [{"name": "fixture-external", "port": 8082}]}]
        }),
    );
    assert_eq!(route.name_any(), "fixture");
    assert_eq!(route.namespace().as_deref(), Some(NAMESPACE));
    let owners = route.metadata.owner_references.unwrap();
    assert_eq!(owners.len(), 1);
    assert_eq!(owners[0].name, parent.name_any());
    assert_eq!(owners[0].uid, "fixture-parent-uid");
    assert_eq!(owners[0].kind, "KubericSet");
    assert_eq!(owners[0].controller, Some(true));
    assert_eq!(
        route.data["spec"]["rules"][0]["backendRefs"][0]["port"],
        8082
    );
}

#[test]
fn managed_gateway_retries_only_transient_failures() {
    for code in [
        tonic::Code::Unavailable,
        tonic::Code::DeadlineExceeded,
        tonic::Code::Cancelled,
    ] {
        assert!(retryable_gateway_error(&anyhow::Error::new(
            tonic::Status::new(code, "retry")
        )));
    }
    for code in [
        tonic::Code::PermissionDenied,
        tonic::Code::InvalidArgument,
        tonic::Code::DataLoss,
    ] {
        assert!(!retryable_gateway_error(&anyhow::Error::new(
            tonic::Status::new(code, "fail")
        )));
    }
    assert!(!retryable_gateway_error(&anyhow::anyhow!(
        "incorrect stored value"
    )));
}

#[tokio::test]
async fn managed_tcp_connection_reaches_backend_before_failure() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (close, closing) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut preface = [0; 33];
        stream.read_exact(&mut preface).await.unwrap();
        assert_eq!(
            &preface,
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0\0\0\x04\0\0\0\0\0"
        );
        stream.write_all(b"\0\0\0\x04\0\0\0\0\0").await.unwrap();
        let mut ack = [0; 9];
        stream.read_exact(&mut ack).await.unwrap();
        assert_eq!(&ack, b"\0\0\0\x04\x01\0\0\0\0");
        closing.await.unwrap();
    });
    let mut connection = established_tcp_connection(&endpoint).await;
    close.send(()).unwrap();
    let mut buffer = [0; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), connection.read(&mut buffer))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    server.await.unwrap();
}

#[tokio::test]
#[test_log::test]
async fn test_managed_services_route_new_connections_after_failover_and_switchover() {
    tokio::time::timeout(Duration::from_secs(900), managed_services_scenario())
        .await
        .expect("managed-Service Gateway integration timed out");
}

async fn managed_services_scenario() {
    crate::test_utils::ensure_kuberic_operator_deployed().await;
    let client = crate::test_utils::isolated_kube_client().await;
    let classes = Api::<DynamicObject>::all_with(
        client.clone(),
        &ApiResource {
            group: "gateway.networking.k8s.io".into(),
            version: "v1".into(),
            kind: "GatewayClass".into(),
            api_version: "gateway.networking.k8s.io/v1".into(),
            plural: "gatewayclasses".into(),
        },
    );
    let class = wait_gateway_resource(&classes, "kuberic-envoy", |object| {
        conditions_ready(
            object.data.pointer("/status/conditions"),
            object.metadata.generation.unwrap_or_default(),
            &["Accepted"],
        )
    })
    .await;
    assert_eq!(class.data["spec"]["controllerName"], GATEWAY_CONTROLLER);
    let sets = sets(client.clone());
    let services: Api<Service> = Api::namespaced(client.clone(), NAMESPACE);
    let pods: Api<Pod> = Api::namespaced(client.clone(), NAMESPACE);
    let gateways = gateway_api(
        client.clone(),
        "gateway.networking.k8s.io",
        "v1",
        "Gateway",
        "gateways",
    );
    let routes = gateway_api(
        client.clone(),
        "gateway.networking.k8s.io",
        "v1alpha2",
        "TCPRoute",
        "tcproutes",
    );
    let proxies = gateway_api(
        client.clone(),
        "gateway.envoyproxy.io",
        "v1alpha1",
        "EnvoyProxy",
        "envoyproxies",
    );
    let name = format!("managed-client-{:08x}", rand::random::<u32>());
    let external_name = format!("{name}-external");
    let lb_name = format!("{name}-lb");
    let nodeport = service_template(&external_name, "NodePort");
    let mut load_balancer = service_template(&lb_name, "LoadBalancer");
    load_balancer["serviceTemplate"]["spec"]["loadBalancerClass"] =
        json!("test.kuberic.io/no-controller");
    let object: DynamicObject = serde_json::from_value(json!({
        "apiVersion": "kuberic.io/v1", "kind": "KubericSet",
        "metadata": {"name": name, "namespace": NAMESPACE},
        "spec": {
            "image": "localhost/kvstore:latest", "replicas": 3, "minReplicas": 2,
            "port": 8080, "controlPort": 9090, "dataPort": 9091,
            "storage": "256Mi", "failoverDelay": 5,
            "managed": {"services": {"additional": [nodeport, load_balancer]}}
        }
    }))
    .unwrap();
    let created = sets
        .create(&PostParams::default(), &object)
        .await
        .expect("create isolated managed-Service fixture");
    let set_uid = created.metadata.uid.clone().unwrap();
    let healthy = wait_set(&sets, &name, |set| {
        set.data["status"]["phase"] == "Healthy"
            && set.data["status"]["managedServices"]["conditions"][0]["reason"]
                == "AwaitingLoadBalancer"
    })
    .await;
    let original_primary = primary(&healthy).to_string();
    wait_service(&services, &external_name, true).await;
    wait_primary_endpoint(client.clone(), &external_name, &original_primary).await;
    let external_before = services.get(&external_name).await.unwrap();
    let external_spec = external_before.spec.as_ref().unwrap();
    assert_eq!(external_spec.type_.as_deref(), Some("NodePort"));
    assert!(
        external_spec
            .cluster_ip
            .as_ref()
            .is_some_and(|ip| !ip.is_empty() && ip != "None")
    );
    let ports = external_spec.ports.as_ref().unwrap();
    assert_eq!(ports.len(), 1);
    assert_eq!(ports[0].port, 8080);
    assert_eq!(ports[0].target_port, Some(IntOrString::Int(8080)));
    let node_port = ports[0]
        .node_port
        .expect("Kubernetes must allocate a native NodePort");
    assert!(node_port > 0);
    assert_ne!(node_port, 30090, "the shared Gateway owns NodePort 30090");
    assert_eq!(
        external_spec.selector,
        Some(std::collections::BTreeMap::from([
            ("kuberic.io/set".into(), name.clone()),
            ("kuberic.io/role".into(), "primary".into()),
        ]))
    );

    // TCP passthrough preserves connection lifetime; the shared HTTP listener does not.
    proxies
        .create(
            &PostParams::default(),
            &owned_gateway_resource(
                "gateway.envoyproxy.io/v1alpha1",
                "EnvoyProxy",
                &created,
                json!({"provider": {"type": "Kubernetes", "kubernetes": {
                    "envoyDeployment": {"replicas": 1},
                    "envoyService": {"type": "ClusterIP"}
                }}}),
            ),
        )
        .await
        .expect("create fixture EnvoyProxy");
    gateways
        .create(
            &PostParams::default(),
            &owned_gateway_resource(
                "gateway.networking.k8s.io/v1",
                "Gateway",
                &created,
                json!({
                    "gatewayClassName": "kuberic-envoy",
                    "infrastructure": {"parametersRef": {
                        "group": "gateway.envoyproxy.io", "kind": "EnvoyProxy", "name": name
                    }},
                    "listeners": [{
                        "name": "tcp", "protocol": "TCP", "port": 8080,
                        "allowedRoutes": {
                            "namespaces": {"from": "Same"},
                            "kinds": [{"group": "gateway.networking.k8s.io", "kind": "TCPRoute"}]
                        }
                    }]
                }),
            ),
        )
        .await
        .expect("create fixture TCP Gateway");
    routes
        .create(
            &PostParams::default(),
            &owned_gateway_resource(
                "gateway.networking.k8s.io/v1alpha2",
                "TCPRoute",
                &created,
                json!({
                    "parentRefs": [{"name": name, "sectionName": "tcp"}],
                    "rules": [{"backendRefs": [{"name": external_name, "port": 8080}]}]
                }),
            ),
        )
        .await
        .expect("create fixture TCPRoute");
    let gateway_before = wait_gateway_resource(&gateways, &name, |object| {
        conditions_ready(
            object.data.pointer("/status/conditions"),
            object.metadata.generation.unwrap_or_default(),
            &["Accepted", "Programmed"],
        )
    })
    .await;
    let route_before =
        wait_gateway_resource(&routes, &name, |object| tcp_route_ready(object, &name)).await;
    let proxy_service = wait_proxy_service(client.clone(), &name).await;
    let forwarding = GatewayPortForward::start(&proxy_service).await;
    let endpoint = forwarding.endpoint.clone();
    assert!(
        tcp_route_targets_service(&route_before, &external_name, 8080),
        "TCPRoute must target only the fixture Service: {:?}",
        route_before.data["spec"]
    );
    connect_and_write(&endpoint, "before-failover").await;

    // No controller implements this class: inject cloud-style status, not a fake data path.
    let lb_before = services.get(&lb_name).await.unwrap();
    services.patch_status(&lb_name, &PatchParams::default(), &Patch::Merge(json!({
        "metadata": {"uid": lb_before.metadata.uid, "resourceVersion": lb_before.metadata.resource_version},
        "status": {"loadBalancer": {"ingress": [{"hostname": "lb.example.internal"}]}}
    }))).await.expect("publish simulated load-balancer ingress");
    wait_set(&sets, &name, |set| {
        set.data["status"]["managedServices"]["conditions"][0]["status"] == "True"
    })
    .await;

    let mut old_connection = established_tcp_connection(&endpoint).await;
    let old_pod = pods.get(&original_primary).await.unwrap();
    pods.delete(
        &original_primary,
        &DeleteParams {
            grace_period_seconds: Some(0),
            preconditions: Some(Preconditions {
                uid: Some(
                    old_pod
                        .metadata
                        .uid
                        .expect("primary pod UID for fenced deletion"),
                ),
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await
    .expect("crash the fixture primary");
    tokio::time::timeout(Duration::from_secs(60), async {
        let mut bytes = [0; 1024];
        loop {
            match old_connection.read(&mut bytes).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await
    .expect("old TCP connection must close rather than migrate");
    let failed_over = wait_set(&sets, &name, |set| {
        set.data["status"]["phase"] == "Healthy"
            && set.data["status"]["currentPrimary"]
                .as_str()
                .is_some_and(|name| name != original_primary)
    })
    .await;
    let promoted = primary(&failed_over).to_string();
    wait_primary_endpoint(client.clone(), &external_name, &promoted).await;
    connect_and_write(&endpoint, "after-failover").await;

    let target = failed_over.data["status"]["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|member| {
            member["healthy"] == true
                && member["name"].as_str().is_some_and(|name| name != promoted)
        })
        .and_then(|member| member["name"].as_str())
        .expect("healthy switchover target")
        .to_string();
    sets.patch_status(
        &name,
        &PatchParams::default(),
        &Patch::Merge(json!({
            "metadata": {"uid": set_uid},
            "status": {"targetPrimary": target}
        })),
    )
    .await
    .expect("request switchover for the fixture");
    wait_set(&sets, &name, |set| {
        set.data["status"]["phase"] == "Healthy" && set.data["status"]["currentPrimary"] == target
    })
    .await;
    wait_primary_endpoint(client.clone(), &external_name, &target).await;
    connect_and_write(&endpoint, "after-switchover").await;
    let external_after = services.get(&external_name).await.unwrap();
    assert_eq!(external_before.metadata.uid, external_after.metadata.uid);
    assert_eq!(external_before.spec, external_after.spec);
    let lb_after = services.get(&lb_name).await.unwrap();
    assert_eq!(lb_before.metadata.uid, lb_after.metadata.uid);
    assert_eq!(lb_before.spec, lb_after.spec);
    let route_after = routes.get(&name).await.unwrap();
    assert_eq!(route_before.metadata.uid, route_after.metadata.uid);
    assert_eq!(route_before.data["spec"], route_after.data["spec"]);
    assert_eq!(
        route_before.metadata.generation,
        route_after.metadata.generation
    );
    assert!(tcp_route_ready(&route_after, &name));
    let gateway_after = gateways.get(&name).await.unwrap();
    assert_eq!(gateway_before.metadata.uid, gateway_after.metadata.uid);
    assert_eq!(gateway_before.data["spec"], gateway_after.data["spec"]);
    assert_eq!(
        lb_after
            .status
            .as_ref()
            .unwrap()
            .load_balancer
            .as_ref()
            .unwrap()
            .ingress
            .as_ref()
            .unwrap()[0]
            .hostname
            .as_deref(),
        Some("lb.example.internal")
    );

    let mut updated = nodeport.clone();
    updated["serviceTemplate"]["metadata"]["annotations"] =
        json!({"test.kuberic.io/updated": "true"});
    updated["serviceTemplate"]["spec"]["ports"][0]["port"] = json!(8082);
    sets.patch(
        &name,
        &PatchParams::default(),
        &Patch::Merge(json!({
            "metadata": {"uid": set_uid},
            "spec": {"managed": {"services": {"additional": [updated]}}}
        })),
    )
    .await
    .expect("update and remove additional templates");
    wait_service(&services, &lb_name, false).await;
    let current_set = sets.get(&name).await.unwrap();
    wait_set(&sets, &name, |set| {
        set.data["status"]["managedServices"]["observedGeneration"].as_i64()
            == current_set.metadata.generation
            && set.data["status"]["managedServices"]["conditions"][0]["status"] == "True"
    })
    .await;
    let updated = services.get(&external_name).await.unwrap();
    assert_eq!(updated.metadata.uid, external_before.metadata.uid);
    assert_eq!(
        updated.spec.as_ref().unwrap().cluster_ip,
        external_before.spec.as_ref().unwrap().cluster_ip
    );
    assert_eq!(
        updated.spec.as_ref().unwrap().ports.as_ref().unwrap()[0].port,
        8082
    );
    assert_eq!(
        updated.spec.as_ref().unwrap().ports.as_ref().unwrap()[0].node_port,
        Some(node_port)
    );
    assert_eq!(
        updated.spec.as_ref().unwrap().ports.as_ref().unwrap()[0].target_port,
        Some(IntOrString::Int(8080))
    );
    assert_eq!(
        updated.metadata.annotations.as_ref().unwrap()["test.kuberic.io/updated"],
        "true"
    );
    let route = routes.get(&name).await.unwrap();
    routes.patch(&name, &PatchParams::default(), &Patch::Merge(json!({
        "metadata": {"uid": route.metadata.uid, "resourceVersion": route.metadata.resource_version},
        "spec": {"rules": [{"backendRefs": [{"name": external_name, "port": 8082}]}]}
    }))).await.expect("update fixture route to the new Service port, not targetPort or NodePort");
    let route_updated = wait_gateway_resource(&routes, &name, |object| {
        tcp_route_ready(object, &name) && tcp_route_targets_service(object, &external_name, 8082)
    })
    .await;
    assert_eq!(route_before.metadata.uid, route_updated.metadata.uid);
    connect_and_write(&endpoint, "after-service-update").await;

    forwarding.stop().await;
    sets.delete(
        &name,
        &DeleteParams {
            preconditions: Some(Preconditions {
                uid: Some(set_uid),
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await
    .expect("delete fixture parent");
    wait_service(&services, &external_name, false).await;
    for api in [&routes, &gateways, &proxies] {
        let deadline = Instant::now() + Duration::from_secs(120);
        while api.get_opt(&name).await.unwrap().is_some() {
            assert!(
                Instant::now() < deadline,
                "fixture Gateway resources were not collected"
            );
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    wait_service(
        &Api::namespaced(client.clone(), &proxy_service.namespace().unwrap()),
        &proxy_service.name_any(),
        false,
    )
    .await;
    // Legacy internal Services and PVCs have no owner reference; clean up only this fixture.
    for service in services
        .list(&ListParams::default().labels(&format!("kuberic.io/set={name}")))
        .await
        .unwrap()
        .items
    {
        services
            .delete(
                &service.name_any(),
                &DeleteParams {
                    preconditions: Some(Preconditions {
                        uid: Some(service.metadata.uid.expect("fixture internal Service UID")),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }
    let pvcs: Api<PersistentVolumeClaim> = Api::namespaced(client, NAMESPACE);
    for pvc in pvcs
        .list(&ListParams::default().labels(&format!("kuberic.io/set={name}")))
        .await
        .unwrap()
        .items
    {
        pvcs.delete(
            &pvc.name_any(),
            &DeleteParams {
                preconditions: Some(Preconditions {
                    uid: Some(pvc.metadata.uid.expect("fixture PVC UID")),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }
}
