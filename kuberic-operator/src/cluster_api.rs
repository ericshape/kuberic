use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use k8s_openapi::api::core::v1::{PersistentVolumeClaim, Pod, Service};

use kuberic_core::driver::ReplicaHandle;
use kuberic_core::types::{ReplicaId, ReplicaInstanceId};

use crate::crd::{KubericSetSpec, KubericSetStatus};
use crate::node_maintenance::NodeMaintenanceRequest;
use crate::service_config::{MANAGED_SERVICE_LABEL, MANAGED_SERVICE_VALUE, ManagedServicesStatus};
use crate::services::{ManagedServiceApi, SERVICE_FIELD_MANAGER};

fn uid_fenced_label_patch(
    pod: &Pod,
    expected_uid: &str,
    labels: BTreeMap<String, String>,
) -> Result<serde_json::Value, String> {
    if pod.metadata.uid.as_deref() != Some(expected_uid) {
        return Err("pod UID precondition failed".to_string());
    }
    let resource_version = pod
        .metadata
        .resource_version
        .as_deref()
        .ok_or_else(|| "pod has no resource version".to_string())?;
    let mut merged_labels = pod.metadata.labels.clone().unwrap_or_default();
    merged_labels.extend(labels);
    Ok(serde_json::json!([
        {
            "op": "test",
            "path": "/metadata/uid",
            "value": expected_uid
        },
        {
            "op": "test",
            "path": "/metadata/resourceVersion",
            "value": resource_version
        },
        {
            "op": "add",
            "path": "/metadata/labels",
            "value": merged_labels
        }
    ]))
}

/// Abstraction over Kubernetes API and replica creation.
/// Real impl uses kube::Client; test impl uses in-memory state.
#[async_trait]
pub trait ClusterApi: ManagedServiceApi + Send + Sync {
    /// List pods matching the label selector.
    async fn list_pods(&self, namespace: &str, selector: &str) -> Result<Vec<Pod>, String>;

    /// Names of nodes with an active NodeMaintenanceRequest.
    async fn list_maintenance_nodes(&self) -> Result<BTreeSet<String>, String>;

    /// Create a pod.
    async fn create_pod(&self, namespace: &str, pod: &Pod) -> Result<(), String>;

    /// Delete exactly one pod incarnation by name and Kubernetes UID.
    async fn delete_pod(
        &self,
        namespace: &str,
        pod_name: &str,
        expected_uid: &str,
    ) -> Result<(), String>;

    /// Update a pod's labels.
    async fn patch_pod_labels(
        &self,
        namespace: &str,
        pod_name: &str,
        labels: BTreeMap<String, String>,
    ) -> Result<(), String>;

    /// Update labels only if the named pod still has the exact expected UID.
    async fn patch_pod_labels_if_uid(
        &self,
        namespace: &str,
        pod_name: &str,
        expected_uid: &str,
        labels: BTreeMap<String, String>,
    ) -> Result<(), String>;

    /// Replace the complete CRD status using optimistic resource-version fencing.
    async fn patch_set_status(
        &self,
        namespace: &str,
        set_name: &str,
        status: &KubericSetStatus,
        expected_resource_version: Option<&str>,
    ) -> Result<(), String>;

    /// Create a ReplicaHandle for a pod (gRPC or in-process).
    async fn create_replica_handle(
        &self,
        replica_id: ReplicaId,
        pod: &Pod,
        spec: &KubericSetSpec,
    ) -> Result<Box<dyn ReplicaHandle>, String>;

    // -- PVC management --

    /// Get a PVC by name.
    async fn get_pvc(&self, namespace: &str, name: &str) -> Result<PersistentVolumeClaim, String>;

    /// Create a PVC.
    async fn create_pvc(&self, namespace: &str, pvc: &PersistentVolumeClaim) -> Result<(), String>;

    /// List PVCs matching the label selector.
    async fn list_pvcs(
        &self,
        namespace: &str,
        selector: &str,
    ) -> Result<Vec<PersistentVolumeClaim>, String>;

    /// Delete a PVC by name.
    async fn delete_pvc(&self, namespace: &str, name: &str) -> Result<(), String>;

    // -- Service management --

    /// Get a Service by name.
    async fn get_service(&self, namespace: &str, name: &str) -> Result<Service, String>;

    /// Create a Service.
    async fn create_service(&self, namespace: &str, svc: &Service) -> Result<(), String>;

    /// Delete a Service by name.
    async fn delete_service(&self, namespace: &str, name: &str) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// Real implementation (kube::Client)
// ---------------------------------------------------------------------------

pub struct KubeClusterApi {
    pub client: kube::Client,
}

#[async_trait]
impl ClusterApi for KubeClusterApi {
    async fn list_pods(&self, namespace: &str, selector: &str) -> Result<Vec<Pod>, String> {
        let api: kube::Api<Pod> = kube::Api::namespaced(self.client.clone(), namespace);
        let params = kube::api::ListParams::default().labels(selector);
        api.list(&params)
            .await
            .map(|list| list.items)
            .map_err(|e| e.to_string())
    }

    async fn list_maintenance_nodes(&self) -> Result<BTreeSet<String>, String> {
        let api: kube::Api<NodeMaintenanceRequest> = kube::Api::all(self.client.clone());
        let list = api
            .list(&kube::api::ListParams::default())
            .await
            .map_err(|e| e.to_string())?;
        Ok(list
            .items
            .into_iter()
            .filter(|request| request.metadata.deletion_timestamp.is_none())
            .filter(|request| !request.spec.desired_state.releases_request())
            .filter(|request| {
                request
                    .status
                    .as_ref()
                    .is_some_and(|status| status.phase.excludes_primary_placement())
            })
            .map(|request| request.spec.node_name)
            .collect())
    }

    async fn create_pod(&self, namespace: &str, pod: &Pod) -> Result<(), String> {
        let api: kube::Api<Pod> = kube::Api::namespaced(self.client.clone(), namespace);
        match api.create(&kube::api::PostParams::default(), pod).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(ae)) if ae.code == 409 => Ok(()), // already exists
            Err(e) => Err(e.to_string()),
        }
    }

    async fn delete_pod(
        &self,
        namespace: &str,
        pod_name: &str,
        expected_uid: &str,
    ) -> Result<(), String> {
        let api: kube::Api<Pod> = kube::Api::namespaced(self.client.clone(), namespace);
        let params = kube::api::DeleteParams {
            preconditions: Some(kube::api::Preconditions {
                uid: Some(expected_uid.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        match api.delete(pod_name, &params).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(()), // already gone
            Err(e) => Err(e.to_string()),
        }
    }

    async fn patch_pod_labels(
        &self,
        namespace: &str,
        pod_name: &str,
        labels: BTreeMap<String, String>,
    ) -> Result<(), String> {
        let api: kube::Api<Pod> = kube::Api::namespaced(self.client.clone(), namespace);
        let patch = serde_json::json!({ "metadata": { "labels": labels } });
        api.patch(
            pod_name,
            &kube::api::PatchParams::apply("kuberic-operator"),
            &kube::api::Patch::Merge(&patch),
        )
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
    }

    async fn patch_pod_labels_if_uid(
        &self,
        namespace: &str,
        pod_name: &str,
        expected_uid: &str,
        labels: BTreeMap<String, String>,
    ) -> Result<(), String> {
        let api: kube::Api<Pod> = kube::Api::namespaced(self.client.clone(), namespace);
        let pod = api.get(pod_name).await.map_err(|e| e.to_string())?;
        let operations = uid_fenced_label_patch(&pod, expected_uid, labels)?;
        api.patch(
            pod_name,
            &kube::api::PatchParams::default(),
            &kube::api::Patch::Json::<serde_json::Value>(
                serde_json::from_value(operations).map_err(|error| error.to_string())?,
            ),
        )
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
    }

    async fn patch_set_status(
        &self,
        namespace: &str,
        set_name: &str,
        status: &KubericSetStatus,
        expected_resource_version: Option<&str>,
    ) -> Result<(), String> {
        let api: kube::Api<crate::crd::KubericSet> =
            kube::Api::namespaced(self.client.clone(), namespace);
        let mut current = api.get(set_name).await.map_err(|e| e.to_string())?;
        if let Some(expected) = expected_resource_version
            && current.metadata.resource_version.as_deref() != Some(expected)
        {
            return Err(format!(
                "status resource version changed from {expected} to {}",
                current
                    .metadata
                    .resource_version
                    .as_deref()
                    .unwrap_or("<none>")
            ));
        }
        let mut topology_status = status.clone();
        topology_status.managed_services = current
            .status
            .as_ref()
            .and_then(|status| status.managed_services.clone());
        current.status = Some(topology_status);
        api.replace_status(set_name, &kube::api::PostParams::default(), &current)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    async fn create_replica_handle(
        &self,
        replica_id: ReplicaId,
        pod: &Pod,
        spec: &KubericSetSpec,
    ) -> Result<Box<dyn ReplicaHandle>, String> {
        let pod_ip = pod
            .status
            .as_ref()
            .and_then(|s| s.pod_ip.as_ref())
            .cloned()
            .ok_or("pod has no IP")?;
        let instance_id = pod
            .metadata
            .uid
            .as_ref()
            .filter(|uid| !uid.is_empty())
            .cloned()
            .map(ReplicaInstanceId::new)
            .ok_or("pod has no UID")?;

        let control_addr = format!("http://{}:{}", pod_ip, spec.control_port);
        let data_addr = format!("http://{}:{}", pod_ip, spec.data_port);

        let handle = kuberic_core::grpc::handle::GrpcReplicaHandle::connect(
            replica_id,
            instance_id,
            control_addr,
            data_addr,
        )
        .await
        .map_err(|e| e.to_string())?;

        Ok(Box::new(handle))
    }

    async fn get_pvc(&self, namespace: &str, name: &str) -> Result<PersistentVolumeClaim, String> {
        let api: kube::Api<PersistentVolumeClaim> =
            kube::Api::namespaced(self.client.clone(), namespace);
        api.get(name).await.map_err(|e| e.to_string())
    }

    async fn create_pvc(&self, namespace: &str, pvc: &PersistentVolumeClaim) -> Result<(), String> {
        let api: kube::Api<PersistentVolumeClaim> =
            kube::Api::namespaced(self.client.clone(), namespace);
        match api.create(&kube::api::PostParams::default(), pvc).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(ae)) if ae.code == 409 => Ok(()), // already exists
            Err(e) => Err(e.to_string()),
        }
    }

    async fn list_pvcs(
        &self,
        namespace: &str,
        selector: &str,
    ) -> Result<Vec<PersistentVolumeClaim>, String> {
        let api: kube::Api<PersistentVolumeClaim> =
            kube::Api::namespaced(self.client.clone(), namespace);
        let params = kube::api::ListParams::default().labels(selector);
        api.list(&params)
            .await
            .map(|list| list.items)
            .map_err(|e| e.to_string())
    }

    async fn delete_pvc(&self, namespace: &str, name: &str) -> Result<(), String> {
        let api: kube::Api<PersistentVolumeClaim> =
            kube::Api::namespaced(self.client.clone(), namespace);
        match api.delete(name, &kube::api::DeleteParams::default()).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    async fn get_service(&self, namespace: &str, name: &str) -> Result<Service, String> {
        let api: kube::Api<Service> = kube::Api::namespaced(self.client.clone(), namespace);
        api.get(name).await.map_err(|e| e.to_string())
    }

    async fn create_service(&self, namespace: &str, svc: &Service) -> Result<(), String> {
        let api: kube::Api<Service> = kube::Api::namespaced(self.client.clone(), namespace);
        match api.create(&kube::api::PostParams::default(), svc).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(ae)) if ae.code == 409 => Ok(()), // already exists
            Err(e) => Err(e.to_string()),
        }
    }

    async fn delete_service(&self, namespace: &str, name: &str) -> Result<(), String> {
        let api: kube::Api<Service> = kube::Api::namespaced(self.client.clone(), namespace);
        match api.delete(name, &kube::api::DeleteParams::default()).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
}

fn service_identity(service: &Service) -> Result<(&str, &str, &str), String> {
    Ok((
        service
            .metadata
            .name
            .as_deref()
            .ok_or("Service has no name")?,
        service
            .metadata
            .uid
            .as_deref()
            .filter(|uid| !uid.is_empty())
            .ok_or("Service has no UID")?,
        service
            .metadata
            .resource_version
            .as_deref()
            .ok_or("Service has no resource version")?,
    ))
}

fn managed_status_patch(
    current: &crate::crd::KubericSet,
    observed: &crate::crd::KubericSet,
    status: Option<&ManagedServicesStatus>,
) -> Result<Option<serde_json::Value>, String> {
    if current.metadata.uid != observed.metadata.uid
        || current.metadata.generation != observed.metadata.generation
        || current.metadata.deletion_timestamp.is_some()
    {
        return Err(
            "KubericSet identity or generation changed during Service reconciliation".to_string(),
        );
    }
    let previous = current
        .status
        .as_ref()
        .and_then(|status| status.managed_services.as_ref());
    let mut next = status.cloned();
    if let (Some(previous), Some(next)) = (previous, next.as_mut()) {
        for condition in &mut next.conditions {
            if let Some(old) = previous
                .conditions
                .iter()
                .find(|old| old.type_ == condition.type_ && old.status == condition.status)
            {
                condition
                    .last_transition_time
                    .clone_from(&old.last_transition_time);
            }
        }
    }
    if previous == next.as_ref() {
        return Ok(None);
    }
    let uid = current
        .metadata
        .uid
        .as_deref()
        .ok_or("KubericSet has no UID")?;
    let resource_version = current
        .metadata
        .resource_version
        .as_deref()
        .ok_or("KubericSet has no resource version")?;
    Ok(Some(serde_json::json!({
        "metadata": {"uid": uid, "resourceVersion": resource_version},
        "status": {"managedServices": next},
    })))
}

#[async_trait]
impl ManagedServiceApi for KubeClusterApi {
    async fn find_service(&self, namespace: &str, name: &str) -> Result<Option<Service>, String> {
        let api: kube::Api<Service> = kube::Api::namespaced(self.client.clone(), namespace);
        api.get_opt(name).await.map_err(|error| error.to_string())
    }

    async fn list_additional_services(&self, namespace: &str) -> Result<Vec<Service>, String> {
        let api: kube::Api<Service> = kube::Api::namespaced(self.client.clone(), namespace);
        let selector = format!("{MANAGED_SERVICE_LABEL}={MANAGED_SERVICE_VALUE}");
        api.list(&kube::api::ListParams::default().labels(&selector))
            .await
            .map(|list| list.items)
            .map_err(|error| error.to_string())
    }

    async fn create_additional_service(
        &self,
        namespace: &str,
        service: &Service,
    ) -> Result<Service, String> {
        let api: kube::Api<Service> = kube::Api::namespaced(self.client.clone(), namespace);
        let params = kube::api::PostParams {
            field_manager: Some(SERVICE_FIELD_MANAGER.to_string()),
            ..Default::default()
        };
        api.create(&params, service)
            .await
            .map_err(|error| error.to_string())
    }

    async fn replace_additional_service(
        &self,
        namespace: &str,
        service: &Service,
    ) -> Result<Service, String> {
        let (name, _, _) = service_identity(service)?;
        let api: kube::Api<Service> = kube::Api::namespaced(self.client.clone(), namespace);
        let params = kube::api::PostParams {
            field_manager: Some(SERVICE_FIELD_MANAGER.to_string()),
            ..Default::default()
        };
        api.replace(name, &params, service)
            .await
            .map_err(|error| error.to_string())
    }

    async fn delete_additional_service(
        &self,
        namespace: &str,
        service: &Service,
    ) -> Result<(), String> {
        let (name, uid, resource_version) = service_identity(service)?;
        let api: kube::Api<Service> = kube::Api::namespaced(self.client.clone(), namespace);
        let params = kube::api::DeleteParams {
            preconditions: Some(kube::api::Preconditions {
                uid: Some(uid.to_string()),
                resource_version: Some(resource_version.to_string()),
            }),
            ..Default::default()
        };
        match api.delete(name, &params).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(error)) if error.code == 404 => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    }

    async fn patch_managed_services_status(
        &self,
        set: &crate::crd::KubericSet,
        status: Option<&ManagedServicesStatus>,
    ) -> Result<(), String> {
        use kube::ResourceExt;
        if status.is_none()
            && set
                .status
                .as_ref()
                .and_then(|s| s.managed_services.as_ref())
                .is_none()
        {
            return Ok(());
        }
        let namespace = set.namespace().ok_or("KubericSet has no namespace")?;
        let api: kube::Api<crate::crd::KubericSet> =
            kube::Api::namespaced(self.client.clone(), &namespace);
        let name = set.name_any();
        let current = api.get(&name).await.map_err(|error| error.to_string())?;
        let Some(patch) = managed_status_patch(&current, set, status)? else {
            return Ok(());
        };
        api.patch_status(
            &name,
            &kube::api::PatchParams::default(),
            &kube::api::Patch::Merge(&patch),
        )
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_with_managed_status() -> crate::crd::KubericSet {
        serde_json::from_value(serde_json::json!({
            "metadata": {"name": "test", "namespace": "default", "uid": "set-uid", "resourceVersion": "10", "generation": 2},
            "spec": {"image": "example:latest"},
            "status": {
                "phase": "Healthy", "currentPrimary": "test-0",
                "managedServices": {
                    "observedGeneration": 2,
                    "conditions": [{
                        "type": "Ready", "status": "False", "reason": "AwaitingLoadBalancer",
                        "message": "pending", "lastTransitionTime": "2026-09-16T00:00:00Z"
                    }],
                    "services": []
                }
            }
        })).unwrap()
    }

    #[test]
    fn managed_status_patch_preserves_topology_and_fences_current_incarnation() {
        let current = set_with_managed_status();
        let mut next = current
            .status
            .as_ref()
            .unwrap()
            .managed_services
            .clone()
            .unwrap();
        next.conditions[0].status = "True".to_string();
        next.conditions[0].reason = "Reconciled".to_string();
        let patch = managed_status_patch(&current, &current, Some(&next))
            .unwrap()
            .unwrap();
        assert_eq!(patch["metadata"]["uid"], "set-uid");
        assert_eq!(patch["metadata"]["resourceVersion"], "10");
        assert_eq!(patch["status"].as_object().unwrap().len(), 1);
        assert_eq!(
            patch["status"]["managedServices"]["conditions"][0]["status"],
            "True"
        );
        let removal = managed_status_patch(&current, &current, None)
            .unwrap()
            .unwrap();
        assert!(removal["status"]["managedServices"].is_null());

        for change in ["uid", "generation"] {
            let mut stale = current.clone();
            if change == "uid" {
                stale.metadata.uid = Some("previous-set".to_string());
            } else {
                stale.metadata.generation = Some(1);
            }
            assert!(
                managed_status_patch(&current, &stale, Some(&next))
                    .unwrap_err()
                    .contains("changed")
            );
        }
    }

    #[test]
    fn managed_status_patch_is_a_noop_when_only_transition_timestamp_differs() {
        let current = set_with_managed_status();
        let mut next = current
            .status
            .as_ref()
            .unwrap()
            .managed_services
            .clone()
            .unwrap();
        next.conditions[0].last_transition_time = "2026-09-17T00:00:00Z".to_string();
        assert!(
            managed_status_patch(&current, &current, Some(&next))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn managed_service_mutations_require_uid_and_resource_version() {
        let mut service = Service::default();
        assert!(service_identity(&service).is_err());
        service.metadata.name = Some("external".to_string());
        service.metadata.uid = Some("service-uid".to_string());
        assert!(
            service_identity(&service)
                .unwrap_err()
                .contains("resource version")
        );
        service.metadata.resource_version = Some("12".to_string());
        assert_eq!(
            service_identity(&service).unwrap(),
            ("external", "service-uid", "12")
        );
    }

    fn pod(labels: Option<BTreeMap<String, String>>) -> Pod {
        Pod {
            metadata: kube::api::ObjectMeta {
                uid: Some("expected-uid".to_string()),
                resource_version: Some("42".to_string()),
                labels,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn uid_fenced_label_patch_preserves_existing_labels_and_creates_missing_map() {
        let existing = BTreeMap::from([
            ("app".to_string(), "kvstore".to_string()),
            ("kuberic.io/role".to_string(), "secondary".to_string()),
        ]);
        let patch = uid_fenced_label_patch(
            &pod(Some(existing)),
            "expected-uid",
            BTreeMap::from([("kuberic.io/role".to_string(), "retired".to_string())]),
        )
        .unwrap();
        assert_eq!(patch[0]["path"], "/metadata/uid");
        assert_eq!(patch[0]["value"], "expected-uid");
        assert_eq!(patch[1]["path"], "/metadata/resourceVersion");
        assert_eq!(patch[1]["value"], "42");
        assert_eq!(patch[2]["path"], "/metadata/labels");
        assert_eq!(patch[2]["value"]["app"], "kvstore");
        assert_eq!(patch[2]["value"]["kuberic.io/role"], "retired");

        let patch = uid_fenced_label_patch(
            &pod(None),
            "expected-uid",
            BTreeMap::from([("kuberic.io/role".to_string(), "retired".to_string())]),
        )
        .unwrap();
        assert_eq!(patch[2]["value"]["kuberic.io/role"], "retired");
        assert!(uid_fenced_label_patch(&pod(None), "replacement-uid", BTreeMap::new()).is_err());
    }
}
