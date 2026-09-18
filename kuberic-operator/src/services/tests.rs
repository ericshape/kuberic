use std::sync::Mutex;

use k8s_openapi::api::core::v1::{LoadBalancerIngress, LoadBalancerStatus, ServiceStatus};
use serde_json::{Value, json};

use super::*;

#[derive(Default)]
struct State {
    services: BTreeMap<String, Service>,
    status: Option<ManagedServicesStatus>,
    revision: u64,
    mutations: Vec<String>,
    fail_create: bool,
    fail_list: bool,
    fail_status: bool,
    replace_race: bool,
    delete_race: bool,
}

#[derive(Default)]
struct FakeApi(Mutex<State>);

fn allocated(mut service: Service, revision: u64) -> Service {
    service.metadata.uid = Some(format!("service-{revision}"));
    service.metadata.resource_version = Some(revision.to_string());
    let spec = service.spec.as_mut().unwrap();
    spec.cluster_ip
        .get_or_insert_with(|| format!("10.0.0.{revision}"));
    spec.cluster_ips
        .get_or_insert_with(|| vec![spec.cluster_ip.clone().unwrap()]);
    spec.ip_families
        .get_or_insert_with(|| vec!["IPv4".to_string()]);
    spec.ip_family_policy
        .get_or_insert_with(|| "SingleStack".to_string());
    spec.session_affinity
        .get_or_insert_with(|| "None".to_string());
    let service_type = spec.type_.as_deref().unwrap_or("ClusterIP");
    if matches!(service_type, "LoadBalancer" | "NodePort") {
        spec.external_traffic_policy
            .get_or_insert_with(|| "Cluster".to_string());
        if service_type == "NodePort" || spec.allocate_load_balancer_node_ports != Some(false) {
            for (index, port) in spec.ports.iter_mut().flatten().enumerate() {
                if port.node_port.is_none() || port.node_port == Some(0) {
                    port.node_port = Some(
                        30_000
                            + i32::try_from(revision * 10 + u64::try_from(index).unwrap()).unwrap(),
                    );
                }
            }
        }
    }
    if service_type == "LoadBalancer" {
        spec.allocate_load_balancer_node_ports.get_or_insert(true);
        if spec.external_traffic_policy.as_deref() == Some("Local") {
            spec.health_check_node_port.get_or_insert(32_001);
        }
    }
    service
}

#[async_trait]
impl ManagedServiceApi for FakeApi {
    async fn find_service(&self, _namespace: &str, name: &str) -> Result<Option<Service>, String> {
        Ok(self.0.lock().unwrap().services.get(name).cloned())
    }

    async fn list_additional_services(&self, _namespace: &str) -> Result<Vec<Service>, String> {
        let state = self.0.lock().unwrap();
        if state.fail_list {
            return Err("injected list failure".to_string());
        }
        Ok(state
            .services
            .values()
            .filter(|service| marked(service))
            .cloned()
            .collect())
    }

    async fn create_additional_service(
        &self,
        _namespace: &str,
        service: &Service,
    ) -> Result<Service, String> {
        let mut state = self.0.lock().unwrap();
        if state.fail_create {
            return Err("injected create conflict".to_string());
        }
        let name = service.name_any();
        if state.services.contains_key(&name) {
            return Err("409 already exists".to_string());
        }
        state.revision += 1;
        let service = allocated(service.clone(), state.revision);
        state.services.insert(name.clone(), service.clone());
        state.mutations.push(format!("create:{name}"));
        Ok(service)
    }

    async fn replace_additional_service(
        &self,
        _namespace: &str,
        service: &Service,
    ) -> Result<Service, String> {
        let mut state = self.0.lock().unwrap();
        let name = service.name_any();
        if state.replace_race {
            state
                .services
                .get_mut(&name)
                .unwrap()
                .metadata
                .resource_version = Some("concurrent-write".to_string());
        }
        let current = state.services.get(&name).ok_or("404 not found")?;
        if current.metadata.uid != service.metadata.uid
            || current.metadata.resource_version != service.metadata.resource_version
        {
            return Err("409 identity/resource-version conflict".to_string());
        }
        state.revision += 1;
        let mut service = service.clone();
        service.metadata.resource_version = Some(state.revision.to_string());
        state.services.insert(name.clone(), service.clone());
        state.mutations.push(format!("replace:{name}"));
        Ok(service)
    }

    async fn delete_additional_service(
        &self,
        _namespace: &str,
        service: &Service,
    ) -> Result<(), String> {
        let mut state = self.0.lock().unwrap();
        let name = service.name_any();
        if state.delete_race {
            state.services.get_mut(&name).unwrap().metadata.uid =
                Some("replacement-uid".to_string());
        }
        if let Some(current) = state.services.get(&name) {
            if current.metadata.uid != service.metadata.uid
                || current.metadata.resource_version != service.metadata.resource_version
            {
                return Err("409 delete precondition conflict".to_string());
            }
            state.services.remove(&name);
            state.mutations.push(format!("delete:{name}"));
        }
        Ok(())
    }

    async fn patch_managed_services_status(
        &self,
        _set: &KubericSet,
        status: Option<&ManagedServicesStatus>,
    ) -> Result<(), String> {
        let mut state = self.0.lock().unwrap();
        if state.fail_status {
            return Err("injected status failure".to_string());
        }
        state.status = status.cloned();
        Ok(())
    }
}

fn additional(name: &str, service_type: &str) -> Value {
    json!({
        "selectorType": "rw",
        "serviceTemplate": {
            "metadata": {"name": name},
            "spec": {
                "type": service_type,
                "ports": [{"name": "app", "port": 8080, "targetPort": 8080}]
            }
        }
    })
}

fn set(additional: Vec<Value>) -> KubericSet {
    serde_json::from_value(json!({
        "apiVersion": "kuberic.io/v1",
        "kind": "KubericSet",
        "metadata": {"name": "myapp", "namespace": "default", "uid": "set-uid", "generation": 1},
        "spec": {"image": "example:latest", "managed": {"services": {"additional": additional}}}
    }))
    .unwrap()
}

fn observed_set(mut set: KubericSet, api: &FakeApi) -> KubericSet {
    set.status
        .get_or_insert_with(Default::default)
        .managed_services = api.0.lock().unwrap().status.clone();
    set
}

#[tokio::test]
async fn creates_all_service_types_without_touching_internal_services() {
    let api = FakeApi::default();
    let internal: Service = serde_json::from_value(json!({
        "metadata": {"name": "myapp-rw"},
        "spec": {"type": "NodePort", "ports": [{"port": 8080, "nodePort": 30090}]}
    }))
    .unwrap();
    api.0
        .lock()
        .unwrap()
        .services
        .insert("myapp-rw".to_string(), internal.clone());
    let set = set(vec![
        additional("client-lb", "LoadBalancer"),
        additional("client-node", "NodePort"),
        additional("client-internal", "ClusterIP"),
    ]);
    reconcile_managed_services(&set, &api).await.unwrap();
    let state = api.0.lock().unwrap();
    assert_eq!(state.services.len(), 4);
    assert_eq!(state.services["myapp-rw"], internal);
    assert_eq!(
        state.status.as_ref().unwrap().conditions[0].reason,
        "AwaitingLoadBalancer"
    );
    assert_eq!(
        state
            .status
            .as_ref()
            .unwrap()
            .services
            .iter()
            .filter(|s| s.ready)
            .count(),
        2
    );
    for name in ["client-lb", "client-node", "client-internal"] {
        assert!(owned_by(&state.services[name], &set));
        assert_eq!(
            state.services[name]
                .spec
                .as_ref()
                .unwrap()
                .ports
                .as_ref()
                .unwrap()
                .len(),
            1
        );
    }
}

#[tokio::test]
async fn repeated_reconciliation_and_restart_are_noops_with_stable_identity() {
    let api = FakeApi::default();
    let set = set(vec![additional("client", "LoadBalancer")]);
    reconcile_managed_services(&set, &api).await.unwrap();
    let before = api.0.lock().unwrap().services["client"].clone();
    let set = observed_set(set, &api);
    let status_before = api.0.lock().unwrap().status.clone();
    for _ in 0..3 {
        reconcile_managed_services(&set, &api).await.unwrap();
    }
    let state = api.0.lock().unwrap();
    assert_eq!(state.services["client"], before);
    assert_eq!(state.status, status_before);
    assert_eq!(state.mutations, ["create:client"]);
}

#[tokio::test]
async fn pending_load_balancer_becomes_ready_for_ip_or_hostname_without_replacing_service() {
    for ingress in [
        LoadBalancerIngress {
            ip: Some("203.0.113.20".to_string()),
            ..Default::default()
        },
        LoadBalancerIngress {
            hostname: Some("lb.example.internal".to_string()),
            ..Default::default()
        },
    ] {
        let api = FakeApi::default();
        let set = set(vec![additional("client", "LoadBalancer")]);
        reconcile_managed_services(&set, &api).await.unwrap();
        assert!(!api.0.lock().unwrap().status.as_ref().unwrap().services[0].ready);
        api.0
            .lock()
            .unwrap()
            .services
            .get_mut("client")
            .unwrap()
            .status = Some(ServiceStatus {
            load_balancer: Some(LoadBalancerStatus {
                ingress: Some(vec![ingress.clone()]),
            }),
            ..Default::default()
        });
        let set = observed_set(set, &api);
        reconcile_managed_services(&set, &api).await.unwrap();
        let state = api.0.lock().unwrap();
        let status = state.status.as_ref().unwrap();
        assert_eq!(status.conditions[0].status, "True");
        assert_eq!(status.services[0].ingress, vec![ingress]);
        assert_eq!(state.mutations, ["create:client"]);
    }
}

#[tokio::test]
async fn load_balancer_port_errors_are_reported_even_when_an_address_exists() {
    let api = FakeApi::default();
    let set = set(vec![additional("client", "LoadBalancer")]);
    reconcile_managed_services(&set, &api).await.unwrap();
    api.0.lock().unwrap().services.get_mut("client").unwrap().status =
        Some(serde_json::from_value(json!({
            "loadBalancer": {"ingress": [{
                "ip": "203.0.113.20",
                "ports": [{"port": 8080, "protocol": "TCP", "error": "provider.example/ProvisioningFailed"}]
            }]}
        })).unwrap());
    reconcile_managed_services(&set, &api).await.unwrap();
    let state = api.0.lock().unwrap();
    let status = state.status.as_ref().unwrap();
    assert_eq!(status.conditions[0].reason, "LoadBalancerError");
    assert!(!status.services[0].ready);
    assert!(status.services[0].message.contains("ProvisioningFailed"));
}

#[tokio::test]
async fn updates_preserve_allocations_and_foreign_metadata_and_remove_owned_fields() {
    let api = FakeApi::default();
    let mut config = additional("client", "LoadBalancer");
    config["serviceTemplate"]["metadata"]["annotations"] = json!({"example.com/old": "old"});
    config["serviceTemplate"]["metadata"]["labels"] = json!({"example.com/old": "old"});
    config["serviceTemplate"]["spec"]["externalTrafficPolicy"] = json!("Local");
    config["serviceTemplate"]["spec"]["loadBalancerSourceRanges"] = json!(["192.0.2.0/24"]);
    config["serviceTemplate"]["spec"]["ports"] = json!([
        {"name": "app", "port": 8080},
        {"name": "metrics", "port": 8081}
    ]);
    reconcile_managed_services(&set(vec![config]), &api)
        .await
        .unwrap();
    {
        let mut state = api.0.lock().unwrap();
        let live = state.services.get_mut("client").unwrap();
        live.metadata
            .annotations
            .as_mut()
            .unwrap()
            .insert("provider.example/owned".to_string(), "keep".to_string());
        live.metadata
            .labels
            .as_mut()
            .unwrap()
            .insert("provider.example/owned".to_string(), "keep".to_string());
    }
    let before = api.0.lock().unwrap().services["client"].clone();
    let mut next = additional("client", "LoadBalancer");
    next["serviceTemplate"]["spec"]["externalTrafficPolicy"] = json!("Local");
    next["serviceTemplate"]["spec"]["ports"] = json!([
        {"name": "metrics", "port": 9081},
        {"name": "app", "port": 9080}
    ]);
    reconcile_managed_services(&set(vec![next]), &api)
        .await
        .unwrap();
    let after = api.0.lock().unwrap().services["client"].clone();
    assert_eq!(before.metadata.uid, after.metadata.uid);
    let old = before.spec.unwrap();
    let new = after.spec.unwrap();
    assert_eq!(old.cluster_ip, new.cluster_ip);
    assert_eq!(old.cluster_ips, new.cluster_ips);
    assert_eq!(old.ip_families, new.ip_families);
    assert_eq!(old.ip_family_policy, new.ip_family_policy);
    assert_eq!(old.health_check_node_port, new.health_check_node_port);
    assert_eq!(
        old.ports.as_ref().unwrap()[0].node_port,
        new.ports.as_ref().unwrap()[1].node_port
    );
    assert_eq!(
        old.ports.as_ref().unwrap()[1].node_port,
        new.ports.as_ref().unwrap()[0].node_port
    );
    assert!(new.load_balancer_source_ranges.is_none());
    for metadata in [
        after.metadata.annotations.unwrap(),
        after.metadata.labels.unwrap(),
    ] {
        assert!(!metadata.contains_key("example.com/old"));
        assert_eq!(metadata["provider.example/owned"], "keep");
    }
}

#[tokio::test]
async fn valid_type_transition_removes_only_inapplicable_allocations() {
    let api = FakeApi::default();
    let mut config = additional("client", "LoadBalancer");
    config["serviceTemplate"]["spec"]["externalTrafficPolicy"] = json!("Local");
    reconcile_managed_services(&set(vec![config]), &api)
        .await
        .unwrap();
    let before = api.0.lock().unwrap().services["client"].clone();
    reconcile_managed_services(&set(vec![additional("client", "ClusterIP")]), &api)
        .await
        .unwrap();
    let after = api.0.lock().unwrap().services["client"].clone();
    assert_eq!(before.metadata.uid, after.metadata.uid);
    let spec = after.spec.unwrap();
    assert_eq!(before.spec.unwrap().cluster_ip, spec.cluster_ip);
    assert!(spec.ports.unwrap()[0].node_port.is_none());
    assert!(spec.health_check_node_port.is_none());
    assert!(spec.allocate_load_balancer_node_ports.is_none());
    assert!(spec.external_traffic_policy.is_none());
}

#[tokio::test]
async fn automatic_health_check_port_and_default_type_are_preserved_on_update() {
    let api = FakeApi::default();
    let mut config = additional("client", "LoadBalancer");
    config["serviceTemplate"]["spec"]["externalTrafficPolicy"] = json!("Local");
    config["serviceTemplate"]["spec"]["healthCheckNodePort"] = json!(0);
    reconcile_managed_services(&set(vec![config.clone()]), &api)
        .await
        .unwrap();
    api.0
        .lock()
        .unwrap()
        .services
        .get_mut("client")
        .unwrap()
        .spec
        .as_mut()
        .unwrap()
        .health_check_node_port = Some(32001);
    let before = api.0.lock().unwrap().services["client"].clone();
    reconcile_managed_services(&set(vec![config]), &api)
        .await
        .unwrap();
    assert_eq!(api.0.lock().unwrap().services["client"], before);

    let api = FakeApi::default();
    let mut config = additional("client", "ClusterIP");
    config["serviceTemplate"]["spec"]
        .as_object_mut()
        .unwrap()
        .remove("type");
    let set = set(vec![config]);
    reconcile_managed_services(&set, &api).await.unwrap();
    api.0
        .lock()
        .unwrap()
        .services
        .get_mut("client")
        .unwrap()
        .spec
        .as_mut()
        .unwrap()
        .type_ = Some("NodePort".to_string());
    reconcile_managed_services(&set, &api).await.unwrap();
    assert_eq!(
        api.0.lock().unwrap().services["client"]
            .spec
            .as_ref()
            .unwrap()
            .type_
            .as_deref(),
        Some("ClusterIP")
    );
}

#[tokio::test]
async fn explicit_node_port_change_is_honored_and_disabling_lb_allocation_preserves_existing_ports()
{
    let api = FakeApi::default();
    let mut config = additional("client", "LoadBalancer");
    config["serviceTemplate"]["spec"]["ports"][0]["nodePort"] = json!(31001);
    reconcile_managed_services(&set(vec![config.clone()]), &api)
        .await
        .unwrap();
    config["serviceTemplate"]["spec"]["ports"][0]["nodePort"] = json!(31002);
    reconcile_managed_services(&set(vec![config.clone()]), &api)
        .await
        .unwrap();
    config["serviceTemplate"]["spec"]["ports"][0]
        .as_object_mut()
        .unwrap()
        .remove("nodePort");
    config["serviceTemplate"]["spec"]["allocateLoadBalancerNodePorts"] = json!(false);
    reconcile_managed_services(&set(vec![config]), &api)
        .await
        .unwrap();
    assert_eq!(
        api.0.lock().unwrap().services["client"]
            .spec
            .as_ref()
            .unwrap()
            .ports
            .as_ref()
            .unwrap()[0]
            .node_port,
        Some(31002)
    );
}

#[tokio::test]
async fn immutable_change_is_reported_without_recreating_or_pruning() {
    let api = FakeApi::default();
    reconcile_managed_services(&set(vec![additional("client", "ClusterIP")]), &api)
        .await
        .unwrap();
    let before = api.0.lock().unwrap().services["client"].clone();
    let mut config = additional("client", "ClusterIP");
    config["serviceTemplate"]["spec"]["clusterIP"] = json!("10.9.8.7");
    let error = reconcile_managed_services(&set(vec![config]), &api)
        .await
        .unwrap_err();
    assert!(error.contains("immutable"));
    assert_eq!(api.0.lock().unwrap().services["client"], before);
    assert_eq!(
        api.0.lock().unwrap().status.as_ref().unwrap().conditions[0].reason,
        "ReconcileFailed"
    );
}

#[tokio::test]
async fn foreign_name_collision_is_never_adopted() {
    let api = FakeApi::default();
    let foreign = Service {
        metadata: kube::api::ObjectMeta {
            name: Some("client".to_string()),
            uid: Some("foreign".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    api.0
        .lock()
        .unwrap()
        .services
        .insert("client".to_string(), foreign.clone());
    let error = reconcile_managed_services(&set(vec![additional("client", "NodePort")]), &api)
        .await
        .unwrap_err();
    assert!(error.contains("not an additional Service owned"));
    assert_eq!(api.0.lock().unwrap().services["client"], foreign);
    assert!(api.0.lock().unwrap().mutations.is_empty());
}

#[tokio::test]
async fn invalid_template_batch_makes_no_service_changes() {
    let api = FakeApi::default();
    let set = set(vec![
        additional("valid", "NodePort"),
        additional("myapp-rw", "NodePort"),
    ]);
    reconcile_managed_services(&set, &api).await.unwrap();
    let state = api.0.lock().unwrap();
    assert!(state.services.is_empty());
    assert_eq!(
        state.status.as_ref().unwrap().conditions[0].reason,
        "InvalidTemplate"
    );
}

#[tokio::test]
async fn removed_templates_are_pruned_only_for_exact_parent_uid_and_marker() {
    let api = FakeApi::default();
    let set = set(vec![additional("client", "ClusterIP")]);
    reconcile_managed_services(&set, &api).await.unwrap();
    {
        let mut state = api.0.lock().unwrap();
        let mut foreign = state.services["client"].clone();
        foreign.metadata.name = Some("other-parent".to_string());
        foreign.metadata.owner_references.as_mut().unwrap()[0].uid = "older-set-uid".to_string();
        state.services.insert("other-parent".to_string(), foreign);
        let mut unmarked = state.services["client"].clone();
        unmarked.metadata.name = Some("unmanaged".to_string());
        unmarked
            .metadata
            .labels
            .as_mut()
            .unwrap()
            .remove(MANAGED_SERVICE_LABEL);
        state.services.insert("unmanaged".to_string(), unmarked);
    }
    let mut set = observed_set(set, &api);
    set.spec.managed = None;
    reconcile_managed_services(&set, &api).await.unwrap();
    let state = api.0.lock().unwrap();
    assert!(!state.services.contains_key("client"));
    assert!(state.services.contains_key("other-parent"));
    assert!(state.services.contains_key("unmanaged"));
    assert!(state.status.is_none());
}

#[tokio::test]
async fn failed_replacement_creation_keeps_previous_exposure_until_retry() {
    let api = FakeApi::default();
    reconcile_managed_services(&set(vec![additional("old", "LoadBalancer")]), &api)
        .await
        .unwrap();
    api.0.lock().unwrap().fail_create = true;
    let next = set(vec![additional("new", "LoadBalancer")]);
    assert!(
        reconcile_managed_services(&next, &api)
            .await
            .unwrap_err()
            .contains("create conflict")
    );
    assert!(api.0.lock().unwrap().services.contains_key("old"));
    api.0.lock().unwrap().fail_create = false;
    reconcile_managed_services(&next, &api).await.unwrap();
    let state = api.0.lock().unwrap();
    assert!(!state.services.contains_key("old"));
    assert!(state.services.contains_key("new"));
    assert_eq!(state.mutations, ["create:old", "create:new", "delete:old"]);
}

#[tokio::test]
async fn resource_version_and_uid_races_are_reported_without_overwriting_or_deleting() {
    let api = FakeApi::default();
    reconcile_managed_services(&set(vec![additional("client", "NodePort")]), &api)
        .await
        .unwrap();
    api.0.lock().unwrap().replace_race = true;
    let mut config = additional("client", "NodePort");
    config["serviceTemplate"]["spec"]["ports"][0]["port"] = json!(8081);
    assert!(
        reconcile_managed_services(&set(vec![config]), &api)
            .await
            .unwrap_err()
            .contains("conflict")
    );
    assert_eq!(
        api.0.lock().unwrap().services["client"]
            .spec
            .as_ref()
            .unwrap()
            .ports
            .as_ref()
            .unwrap()[0]
            .port,
        8080
    );
    api.0.lock().unwrap().delete_race = true;
    assert!(
        reconcile_managed_services(&set(vec![]), &api)
            .await
            .unwrap_err()
            .contains("delete precondition")
    );
    assert_eq!(
        api.0.lock().unwrap().services["client"]
            .metadata
            .uid
            .as_deref(),
        Some("replacement-uid")
    );
}

#[tokio::test]
async fn desired_service_label_drift_is_repaired_and_unmanaged_labels_survive() {
    let api = FakeApi::default();
    let set = set(vec![additional("client", "ClusterIP")]);
    reconcile_managed_services(&set, &api).await.unwrap();
    {
        let mut state = api.0.lock().unwrap();
        let live = state.services.get_mut("client").unwrap();
        live.metadata
            .labels
            .as_mut()
            .unwrap()
            .remove(MANAGED_SERVICE_LABEL);
        live.spec
            .as_mut()
            .unwrap()
            .selector
            .as_mut()
            .unwrap()
            .insert("kuberic.io/role".to_string(), "secondary".to_string());
    }
    reconcile_managed_services(&set, &api).await.unwrap();
    let state = api.0.lock().unwrap();
    let service = &state.services["client"];
    assert!(marked(service));
    assert_eq!(
        service.spec.as_ref().unwrap().selector.as_ref().unwrap()["kuberic.io/role"],
        "primary"
    );
}

#[tokio::test]
async fn corrupt_recorded_template_is_not_silently_ignored() {
    let api = FakeApi::default();
    let set = set(vec![additional("client", "ClusterIP")]);
    reconcile_managed_services(&set, &api).await.unwrap();
    api.0
        .lock()
        .unwrap()
        .services
        .get_mut("client")
        .unwrap()
        .metadata
        .annotations
        .as_mut()
        .unwrap()
        .insert(TEMPLATE_ANNOTATION.to_string(), "invalid-json".to_string());
    assert!(
        reconcile_managed_services(&set, &api)
            .await
            .unwrap_err()
            .contains("invalid recorded")
    );
    assert_eq!(api.0.lock().unwrap().mutations, ["create:client"]);
}

#[tokio::test]
async fn list_and_status_failures_are_explicit() {
    let api = FakeApi::default();
    let set = set(vec![additional("client", "LoadBalancer")]);
    api.0.lock().unwrap().fail_list = true;
    assert!(
        reconcile_managed_services(&set, &api)
            .await
            .unwrap_err()
            .contains("list failure")
    );
    assert_eq!(
        api.0.lock().unwrap().status.as_ref().unwrap().conditions[0].reason,
        "ReconcileFailed"
    );
    api.0.lock().unwrap().fail_list = false;
    api.0.lock().unwrap().fail_status = true;
    assert!(
        reconcile_managed_services(&set, &api)
            .await
            .unwrap_err()
            .contains("status failure")
    );
}

#[tokio::test]
async fn deleting_parent_never_recreates_services() {
    let api = FakeApi::default();
    let mut set = set(vec![additional("client", "LoadBalancer")]);
    set.metadata.deletion_timestamp = Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
        k8s_openapi::jiff::Timestamp::now(),
    ));
    reconcile_managed_services(&set, &api).await.unwrap();
    assert!(api.0.lock().unwrap().services.is_empty());
    assert!(api.0.lock().unwrap().status.is_none());
}
