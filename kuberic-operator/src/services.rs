use std::collections::{BTreeMap, HashSet};

use async_trait::async_trait;
use k8s_openapi::api::core::v1::{Service, ServicePort, ServiceSpec};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::ResourceExt;
use serde::{Deserialize, Serialize};

use crate::crd::{KubericSet, Phase, StatusCondition};
use crate::service_config::{
    MANAGED_SERVICE_LABEL, MANAGED_SERVICE_VALUE, ManagedServiceStatus, ManagedServicesStatus,
    SERVICE_TEMPLATE_ANNOTATION as TEMPLATE_ANNOTATION, build_additional_services,
};

pub(crate) const SERVICE_FIELD_MANAGER: &str = "kuberic-managed-services";

#[async_trait]
pub trait ManagedServiceApi: Send + Sync {
    async fn find_service(&self, namespace: &str, name: &str) -> Result<Option<Service>, String>;
    async fn list_additional_services(&self, namespace: &str) -> Result<Vec<Service>, String>;
    async fn create_additional_service(
        &self,
        namespace: &str,
        service: &Service,
    ) -> Result<Service, String>;
    async fn replace_additional_service(
        &self,
        namespace: &str,
        service: &Service,
    ) -> Result<Service, String>;
    async fn delete_additional_service(
        &self,
        namespace: &str,
        service: &Service,
    ) -> Result<(), String>;
    async fn patch_managed_services_status(
        &self,
        set: &KubericSet,
        status: Option<&ManagedServicesStatus>,
    ) -> Result<(), String>;
}

#[derive(Deserialize, Serialize)]
struct AppliedTemplate {
    version: u32,
    labels: BTreeMap<String, String>,
    annotations: BTreeMap<String, String>,
    spec: ServiceSpec,
}

fn template(service: &Service) -> Result<AppliedTemplate, String> {
    let annotations = service.metadata.annotations.clone().unwrap_or_default();
    if annotations.contains_key(TEMPLATE_ANNOTATION) {
        return Err(format!("annotation {TEMPLATE_ANNOTATION} is reserved"));
    }
    let mut spec = service
        .spec
        .clone()
        .ok_or_else(|| "additional Service has no spec".to_string())?;
    spec.type_.get_or_insert_with(|| "ClusterIP".to_string());
    spec.publish_not_ready_addresses = Some(false);
    for port in spec.ports.iter_mut().flatten() {
        port.protocol.get_or_insert_with(|| "TCP".to_string());
        port.target_port.get_or_insert(IntOrString::Int(port.port));
    }
    Ok(AppliedTemplate {
        version: 1,
        labels: service.metadata.labels.clone().unwrap_or_default(),
        annotations,
        spec,
    })
}

fn for_creation(mut service: Service) -> Result<Service, String> {
    let applied = template(&service)?;
    service.spec = Some(applied.spec.clone());
    let applied = serde_json::to_string(&applied).map_err(|e| e.to_string())?;
    service
        .metadata
        .annotations
        .get_or_insert_with(BTreeMap::new)
        .insert(TEMPLATE_ANNOTATION.to_string(), applied);
    Ok(service)
}

fn owned_by(service: &Service, set: &KubericSet) -> bool {
    let Some(uid) = set.metadata.uid.as_deref().filter(|uid| !uid.is_empty()) else {
        return false;
    };
    let owners = service.metadata.owner_references.as_deref().unwrap_or(&[]);
    let mut controllers = owners.iter().filter(|owner| owner.controller == Some(true));
    let matches = controllers.next().is_some_and(|owner| {
        owner.uid == uid
            && owner.name == set.name_any()
            && owner.kind == "KubericSet"
            && owner.api_version == "kuberic.io/v1"
    });
    matches && controllers.next().is_none()
}

fn marked(service: &Service) -> bool {
    service
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(MANAGED_SERVICE_LABEL))
        .is_some_and(|value| value == MANAGED_SERVICE_VALUE)
}

fn merge_metadata(
    current: &mut BTreeMap<String, String>,
    previous: &BTreeMap<String, String>,
    desired: &BTreeMap<String, String>,
) {
    current.retain(|key, _| !previous.contains_key(key) || desired.contains_key(key));
    current.extend(desired.clone());
}

fn same_port(left: &ServicePort, right: &ServicePort) -> bool {
    left.name == right.name
        && left.protocol.as_deref().unwrap_or("TCP") == right.protocol.as_deref().unwrap_or("TCP")
}

fn merge_spec(
    live: &ServiceSpec,
    previous: &ServiceSpec,
    desired: &ServiceSpec,
) -> Result<ServiceSpec, String> {
    let mut merged = serde_json::to_value(live).map_err(|e| e.to_string())?;
    let previous = serde_json::to_value(previous).map_err(|e| e.to_string())?;
    let wanted = serde_json::to_value(desired).map_err(|e| e.to_string())?;
    let fields = merged
        .as_object_mut()
        .ok_or_else(|| "Service spec is not an object".to_string())?;
    let old_fields = previous
        .as_object()
        .ok_or_else(|| "stored Service template spec is not an object".to_string())?;
    let new_fields = wanted
        .as_object()
        .ok_or_else(|| "desired Service spec is not an object".to_string())?;
    fields.retain(|key, _| !old_fields.contains_key(key) || new_fields.contains_key(key));
    fields.extend(new_fields.clone());
    let mut merged: ServiceSpec = serde_json::from_value(merged).map_err(|e| e.to_string())?;

    if let (Some(old), Some(new)) = (&live.cluster_ip, &desired.cluster_ip)
        && old != new
    {
        return Err("clusterIP is immutable; use a differently named Service".to_string());
    }
    merged.cluster_ip = desired
        .cluster_ip
        .clone()
        .or_else(|| live.cluster_ip.clone());
    merged.cluster_ips = desired
        .cluster_ips
        .clone()
        .or_else(|| live.cluster_ips.clone());
    merged.ip_families = desired
        .ip_families
        .clone()
        .or_else(|| live.ip_families.clone());
    merged.ip_family_policy = desired
        .ip_family_policy
        .clone()
        .or_else(|| live.ip_family_policy.clone());

    let service_type = merged.type_.as_deref().unwrap_or("ClusterIP");
    let uses_node_ports = matches!(service_type, "NodePort" | "LoadBalancer");
    for port in merged.ports.iter_mut().flatten() {
        if uses_node_ports {
            if port.node_port.is_none() || port.node_port == Some(0) {
                port.node_port = live
                    .ports
                    .iter()
                    .flatten()
                    .find(|old| same_port(old, port))
                    .and_then(|old| old.node_port);
            }
        } else if port.node_port.is_some_and(|port| port != 0) {
            return Err("ClusterIP Services cannot specify nodePort".to_string());
        } else {
            port.node_port = None;
        }
    }

    if service_type == "LoadBalancer" && merged.external_traffic_policy.as_deref() == Some("Local")
    {
        merged.health_check_node_port = desired
            .health_check_node_port
            .filter(|port| *port != 0)
            .or(live.health_check_node_port);
    } else if desired.health_check_node_port.is_none() {
        merged.health_check_node_port = None;
    }
    if service_type != "LoadBalancer" {
        if desired.allocate_load_balancer_node_ports.is_none() {
            merged.allocate_load_balancer_node_ports = None;
        }
        if desired.load_balancer_class.is_none() {
            merged.load_balancer_class = None;
        }
    }
    if service_type == "ClusterIP"
        && desired.external_traffic_policy.is_none()
        && merged.external_ips.as_ref().is_none_or(Vec::is_empty)
    {
        merged.external_traffic_policy = None;
    }
    Ok(merged)
}

fn for_update(live: &Service, desired: &Service) -> Result<Option<Service>, String> {
    let stored = live
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(TEMPLATE_ANNOTATION))
        .ok_or_else(|| "managed Service is missing its recorded template".to_string())?;
    let previous: AppliedTemplate = serde_json::from_str(stored)
        .map_err(|e| format!("invalid recorded Service template: {e}"))?;
    if previous.version != 1 {
        return Err(format!(
            "unsupported Service template version {}",
            previous.version
        ));
    }
    let desired_template = template(desired)?;
    let mut updated = live.clone();
    updated.spec = Some(merge_spec(
        live.spec.as_ref().ok_or("existing Service has no spec")?,
        &previous.spec,
        &desired_template.spec,
    )?);
    merge_metadata(
        updated.metadata.labels.get_or_insert_with(BTreeMap::new),
        &previous.labels,
        &desired_template.labels,
    );
    let annotations = updated
        .metadata
        .annotations
        .get_or_insert_with(BTreeMap::new);
    merge_metadata(
        annotations,
        &previous.annotations,
        &desired_template.annotations,
    );
    annotations.insert(
        TEMPLATE_ANNOTATION.to_string(),
        serde_json::to_string(&desired_template).map_err(|e| e.to_string())?,
    );
    if updated == *live {
        Ok(None)
    } else {
        Ok(Some(updated))
    }
}

fn service_status(service: &Service) -> Result<ManagedServiceStatus, String> {
    let spec = service.spec.as_ref().ok_or("Service has no spec")?;
    let service_type = spec.type_.as_deref().unwrap_or("ClusterIP");
    let ingress = service
        .status
        .as_ref()
        .and_then(|status| status.load_balancer.as_ref())
        .and_then(|status| status.ingress.clone())
        .unwrap_or_default();
    let has_address = ingress.iter().any(|entry| {
        entry.ip.as_ref().is_some_and(|ip| !ip.is_empty())
            || entry.hostname.as_ref().is_some_and(|host| !host.is_empty())
    });
    let port_errors: Vec<_> = ingress
        .iter()
        .flat_map(|entry| entry.ports.iter().flatten())
        .filter_map(|port| {
            port.error
                .as_ref()
                .map(|error| format!("{} port {}: {error}", port.protocol, port.port))
        })
        .collect();
    let failed = service_type == "LoadBalancer" && !port_errors.is_empty();
    let ready = !failed && (service_type != "LoadBalancer" || has_address);
    Ok(ManagedServiceStatus {
        name: service.name_any(),
        service_type: service_type.to_string(),
        ready,
        reason: if failed {
            "LoadBalancerError"
        } else if ready {
            "Reconciled"
        } else {
            "AwaitingLoadBalancer"
        }
        .to_string(),
        message: if failed {
            port_errors.join("; ")
        } else if ready {
            "Service reconciled; application availability depends on ready endpoints".to_string()
        } else {
            "Waiting for a load-balancer ingress IP or hostname; check Service events and the cluster's load-balancer controller".to_string()
        },
        ingress,
        ports: spec.ports.clone().unwrap_or_default(),
    })
}

fn report(
    set: &KubericSet,
    services: Vec<ManagedServiceStatus>,
    ready: bool,
    reason: &str,
    message: String,
) -> ManagedServicesStatus {
    let condition_status = if ready { "True" } else { "False" };
    let transition = set
        .status
        .as_ref()
        .and_then(|status| status.managed_services.as_ref())
        .and_then(|status| {
            status
                .conditions
                .iter()
                .find(|condition| condition.type_ == "Ready")
        })
        .filter(|condition| condition.status == condition_status)
        .map(|condition| condition.last_transition_time.clone())
        .unwrap_or_else(|| k8s_openapi::jiff::Timestamp::now().to_string());
    ManagedServicesStatus {
        observed_generation: set.metadata.generation.unwrap_or(0),
        conditions: vec![StatusCondition {
            type_: "Ready".to_string(),
            status: condition_status.to_string(),
            reason: reason.to_string(),
            message,
            last_transition_time: transition,
        }],
        services,
    }
}

async fn reconcile_one<A: ManagedServiceApi + ?Sized>(
    set: &KubericSet,
    api: &A,
    namespace: &str,
    desired: &Service,
) -> Result<Service, String> {
    let Some(live) = api.find_service(namespace, &desired.name_any()).await? else {
        return api
            .create_additional_service(namespace, &for_creation(desired.clone())?)
            .await;
    };
    if !owned_by(&live, set)
        || !(marked(&live)
            || live
                .metadata
                .annotations
                .as_ref()
                .is_some_and(|a| a.contains_key(TEMPLATE_ANNOTATION)))
    {
        return Err(format!(
            "Service {} already exists and is not an additional Service owned by this KubericSet UID",
            desired.name_any()
        ));
    }
    if live.metadata.deletion_timestamp.is_some() {
        return Err(format!("Service {} is still terminating", live.name_any()));
    }
    match for_update(&live, desired)? {
        Some(updated) => api.replace_additional_service(namespace, &updated).await,
        None => Ok(live),
    }
}

pub async fn reconcile_managed_services<A: ManagedServiceApi + ?Sized>(
    set: &KubericSet,
    api: &A,
) -> Result<(), String> {
    if set.metadata.deletion_timestamp.is_some()
        || set
            .status
            .as_ref()
            .is_some_and(|status| status.phase == Phase::Deleting)
    {
        return Ok(());
    }
    let desired = match build_additional_services(set).and_then(|services| {
        for service in &services {
            template(service)?;
        }
        Ok(services)
    }) {
        Ok(desired) => desired,
        Err(error) => {
            let status = report(set, Vec::new(), false, "InvalidTemplate", error);
            return api.patch_managed_services_status(set, Some(&status)).await;
        }
    };
    let namespace = set.namespace().ok_or("KubericSet has no namespace")?;
    let existing = match api.list_additional_services(&namespace).await {
        Ok(existing) => existing,
        Err(error) => {
            let status = report(set, Vec::new(), false, "ReconcileFailed", error.clone());
            api.patch_managed_services_status(set, Some(&status))
                .await?;
            return Err(error);
        }
    };
    let mut statuses = Vec::new();
    let mut errors = Vec::new();
    for service in &desired {
        match reconcile_one(set, api, &namespace, service)
            .await
            .and_then(|s| service_status(&s))
        {
            Ok(status) => statuses.push(status),
            Err(error) => {
                errors.push(format!("{}: {error}", service.name_any()));
                statuses.push(ManagedServiceStatus {
                    name: service.name_any(),
                    service_type: service
                        .spec
                        .as_ref()
                        .and_then(|s| s.type_.clone())
                        .unwrap_or_else(|| "ClusterIP".to_string()),
                    ready: false,
                    reason: "ReconcileFailed".to_string(),
                    message: error,
                    ingress: Vec::new(),
                    ports: Vec::new(),
                });
            }
        }
    }
    // Keep the previous exposure if its replacement could not be reconciled.
    if errors.is_empty() {
        let names: HashSet<_> = desired.iter().map(ResourceExt::name_any).collect();
        for service in existing {
            if marked(&service) && owned_by(&service, set) && !names.contains(&service.name_any()) {
                if let Err(error) = api.delete_additional_service(&namespace, &service).await {
                    errors.push(format!("cannot delete {}: {error}", service.name_any()));
                }
            }
        }
    }
    if !errors.is_empty() {
        let error = errors.join("; ");
        let status = report(set, statuses, false, "ReconcileFailed", error.clone());
        api.patch_managed_services_status(set, Some(&status))
            .await?;
        return Err(error);
    }
    if desired.is_empty() {
        return api.patch_managed_services_status(set, None).await;
    }
    let ready = statuses.iter().all(|status| status.ready);
    let provisioning_errors: Vec<_> = statuses
        .iter()
        .filter(|status| status.reason == "LoadBalancerError")
        .map(|status| format!("{}: {}", status.name, status.message))
        .collect();
    let (reason, message) = if !provisioning_errors.is_empty() {
        ("LoadBalancerError", provisioning_errors.join("; "))
    } else if ready {
        (
            "Reconciled",
            "All additional Services are reconciled".to_string(),
        )
    } else {
        (
            "AwaitingLoadBalancer",
            "Additional Services are reconciled but load-balancer ingress is pending".to_string(),
        )
    };
    let status = report(set, statuses, ready, reason, message);
    api.patch_managed_services_status(set, Some(&status)).await
}

#[cfg(test)]
mod tests;
