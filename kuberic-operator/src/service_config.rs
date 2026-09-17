//! Configuration and pure rendering for opt-in, application-facing Services.

use std::collections::{BTreeMap, BTreeSet};

use k8s_openapi::api::core::v1::{LoadBalancerIngress, Service, ServicePort, ServiceSpec};
use k8s_openapi::apimachinery::pkg::{
    apis::meta::v1::{ObjectMeta, OwnerReference},
    util::intstr::IntOrString,
};
use kube::Resource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::crd::{KubericSet, StatusCondition};

pub const MANAGED_SERVICE_LABEL: &str = "kuberic.io/managed-service";
pub const MANAGED_SERVICE_VALUE: &str = "additional";

const SET_LABEL: &str = "kuberic.io/set";
const ROLE_LABEL: &str = "kuberic.io/role";
pub(crate) const SERVICE_TEMPLATE_ANNOTATION: &str = "kuberic.io/service-template";

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManagedSpec {
    #[serde(default)]
    pub services: ManagedServicesSpec,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManagedServicesSpec {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional: Vec<AdditionalService>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AdditionalService {
    pub selector_type: ServiceSelectorType,
    pub service_template: ServiceTemplate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ServiceSelectorType {
    Rw,
    Ro,
    R,
}

impl ServiceSelectorType {
    fn selector(self, set_name: &str) -> BTreeMap<String, String> {
        let mut selector = BTreeMap::from([(SET_LABEL.to_owned(), set_name.to_owned())]);
        match self {
            Self::Rw => {
                selector.insert(ROLE_LABEL.to_owned(), "primary".to_owned());
            }
            Self::Ro => {
                selector.insert(ROLE_LABEL.to_owned(), "secondary".to_owned());
            }
            Self::R => {}
        }
        selector
    }
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceTemplate {
    pub metadata: ServiceTemplateMetadata,
    pub spec: ServiceSpec,
}

/// Identity and user metadata only; namespace and ownership come from the parent.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceTemplateMetadata {
    pub name: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManagedServiceStatus {
    pub name: String,
    #[serde(rename = "type")]
    pub service_type: String,
    pub ready: bool,
    pub reason: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ingress: Vec<LoadBalancerIngress>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ports: Vec<ServicePort>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManagedServicesStatus {
    #[serde(default)]
    pub observed_generation: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<StatusCondition>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<ManagedServiceStatus>,
}

/// Validate the entire configuration before rendering any desired Services.
///
/// No ports are inherited from the parent, and this does not alter the internal
/// `-rw`, `-ro`, or `-r` Services.
pub fn build_additional_services(set: &KubericSet) -> Result<Vec<Service>, String> {
    let Some(managed) = &set.spec.managed else {
        return Ok(Vec::new());
    };
    let additional = &managed.services.additional;
    if additional.is_empty() {
        return Ok(Vec::new());
    }

    let set_name = parent_identity(set.metadata.name.as_deref(), "name")?;
    let namespace = parent_identity(set.metadata.namespace.as_deref(), "namespace")?;
    let uid = parent_identity(set.metadata.uid.as_deref(), "uid")?;
    let reserved_names = ["rw", "ro", "r"].map(|suffix| format!("{set_name}-{suffix}"));
    let mut names = BTreeSet::new();

    for (index, entry) in additional.iter().enumerate() {
        let context = format!("managed.services.additional[{index}].serviceTemplate");
        let name = &entry.service_template.metadata.name;
        if !is_service_name(name) {
            return Err(format!(
                "{context}.metadata.name '{name}' must be a DNS1035 Service name: \
                 1-63 lowercase letters, digits, or hyphens, starting with a letter \
                 and ending with a letter or digit"
            ));
        }
        if reserved_names.contains(name) {
            return Err(format!(
                "{context}.metadata.name '{name}' is reserved for an internal Service"
            ));
        }
        if !names.insert(name) {
            return Err(format!(
                "{context}.metadata.name '{name}' duplicates another additional Service name"
            ));
        }
        validate_template(
            &entry.service_template,
            &entry.selector_type.selector(set_name),
            set_name,
            &context,
        )?;
    }

    let owner = OwnerReference {
        api_version: KubericSet::api_version(&()).into_owned(),
        kind: KubericSet::kind(&()).into_owned(),
        name: set_name.to_owned(),
        uid: uid.to_owned(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    };

    Ok(additional
        .iter()
        .map(|entry| {
            let template = &entry.service_template;
            let mut labels = template.metadata.labels.clone();
            labels.insert(SET_LABEL.to_owned(), set_name.to_owned());
            labels.insert(
                MANAGED_SERVICE_LABEL.to_owned(),
                MANAGED_SERVICE_VALUE.to_owned(),
            );
            let mut spec = template.spec.clone();
            spec.selector = Some(entry.selector_type.selector(set_name));
            if spec.type_.is_none() {
                spec.type_ = Some("ClusterIP".to_owned());
            }
            Service {
                metadata: ObjectMeta {
                    name: Some(template.metadata.name.clone()),
                    namespace: Some(namespace.to_owned()),
                    labels: Some(labels),
                    annotations: (!template.metadata.annotations.is_empty())
                        .then(|| template.metadata.annotations.clone()),
                    owner_references: Some(vec![owner.clone()]),
                    ..Default::default()
                },
                spec: Some(spec),
                ..Default::default()
            }
        })
        .collect())
}

fn parent_identity<'a>(value: Option<&'a str>, field: &str) -> Result<&'a str, String> {
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            format!("KubericSet.metadata.{field} must be present and nonempty to render Services")
        })
}

fn validate_template(
    template: &ServiceTemplate,
    selector: &BTreeMap<String, String>,
    set_name: &str,
    context: &str,
) -> Result<(), String> {
    if template
        .metadata
        .annotations
        .contains_key(SERVICE_TEMPLATE_ANNOTATION)
    {
        return Err(format!(
            "{context}.metadata.annotations['{SERVICE_TEMPLATE_ANNOTATION}'] is reserved \
             for operator-owned template state; do not set or edit it"
        ));
    }
    for (key, expected) in [
        (SET_LABEL, set_name),
        (MANAGED_SERVICE_LABEL, MANAGED_SERVICE_VALUE),
    ] {
        if let Some(value) = template
            .metadata
            .labels
            .get(key)
            .filter(|value| value.as_str() != expected)
        {
            return Err(format!(
                "{context}.metadata.labels['{key}'] must equal '{expected}', not '{value}'"
            ));
        }
    }
    let spec = &template.spec;
    if let Some(supplied) = &spec.selector {
        for (key, value) in supplied {
            match selector.get(key) {
                Some(expected) if value == expected => {}
                Some(expected) => {
                    return Err(format!(
                        "{context}.spec.selector['{key}'] must equal '{expected}', not '{value}'"
                    ));
                }
                None => {
                    return Err(format!(
                        "{context}.spec.selector key '{key}' is not generated by selectorType; \
                         additional selector restrictions are not allowed"
                    ));
                }
            }
        }
    }
    match spec.type_.as_deref().unwrap_or("ClusterIP") {
        "ClusterIP" | "NodePort" | "LoadBalancer" => {}
        service_type => {
            return Err(format!(
                "{context}.spec.type '{service_type}' is not supported; \
                 use ClusterIP, NodePort, or LoadBalancer (not ExternalName)"
            ));
        }
    }
    if spec
        .external_name
        .as_deref()
        .is_some_and(|name| !name.is_empty())
    {
        return Err(format!(
            "{context}.spec.externalName is incompatible with operator-routed Services"
        ));
    }
    if spec.publish_not_ready_addresses == Some(true) {
        return Err(format!(
            "{context}.spec.publishNotReadyAddresses must not be true; \
             managed Services use ready endpoints"
        ));
    }
    validate_ports(spec.ports.as_deref(), context)
}

fn validate_ports(ports: Option<&[ServicePort]>, context: &str) -> Result<(), String> {
    let ports = ports.filter(|ports| !ports.is_empty()).ok_or_else(|| {
        format!(
            "{context}.spec.ports must contain explicit ports; KubericSet ports are not inherited"
        )
    })?;
    let mut names = BTreeSet::new();
    let mut service_ports = BTreeSet::new();
    let mut node_ports = BTreeSet::new();
    for (index, port) in ports.iter().enumerate() {
        let field = format!("{context}.spec.ports[{index}]");
        validate_port_number(port.port, &format!("{field}.port"))?;
        let name = port.name.as_deref().unwrap_or("");
        if ports.len() > 1 && name.is_empty() {
            return Err(format!(
                "{field}.name is required when a Service has multiple ports"
            ));
        }
        if !name.is_empty() {
            if !is_dns_label(name) {
                return Err(format!(
                    "{field}.name '{name}' must be a DNS label: 1-63 lowercase letters, \
                     digits, or hyphens, starting and ending with a letter or digit"
                ));
            }
            if !names.insert(name) {
                return Err(format!(
                    "{field}.name '{name}' duplicates another port name"
                ));
            }
        }
        let protocol = port
            .protocol
            .as_deref()
            .filter(|protocol| !protocol.is_empty())
            .unwrap_or("TCP");
        if !service_ports.insert((port.port, protocol)) {
            return Err(format!(
                "{field} duplicates Service port {}/{protocol}",
                port.port
            ));
        }
        if let Some(node_port) = port.node_port.filter(|node_port| *node_port != 0) {
            // Zero requests allocation; the API server checks its configured NodePort range.
            validate_port_number(node_port, &format!("{field}.nodePort"))?;
            if !node_ports.insert((node_port, protocol)) {
                return Err(format!(
                    "{field} duplicates nodePort {node_port}/{protocol}"
                ));
            }
        }
        match &port.target_port {
            Some(IntOrString::Int(number)) => {
                validate_port_number(*number, &format!("{field}.targetPort"))?;
            }
            Some(IntOrString::String(name)) if !is_named_target_port(name) => {
                return Err(format!(
                    "{field}.targetPort '{name}' must be a valid port name: 1-15 lowercase \
                     letters, digits, or hyphens, with at least one letter, no consecutive \
                     hyphens, and no leading or trailing hyphen"
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_port_number(value: i32, field: &str) -> Result<(), String> {
    if !(1..=65535).contains(&value) {
        return Err(format!("{field} must be between 1 and 65535, not {value}"));
    }
    Ok(())
}

fn is_dns_label(name: &str) -> bool {
    let bytes = name.as_bytes();
    let is_alphanumeric = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    (1..=63).contains(&bytes.len())
        && bytes.first().is_some_and(is_alphanumeric)
        && bytes.last().is_some_and(is_alphanumeric)
        && bytes
            .iter()
            .all(|byte| is_alphanumeric(byte) || *byte == b'-')
}

fn is_service_name(name: &str) -> bool {
    is_dns_label(name) && name.as_bytes()[0].is_ascii_lowercase()
}

fn is_named_target_port(name: &str) -> bool {
    (1..=15).contains(&name.len())
        && is_dns_label(name)
        && name.bytes().any(|byte| byte.is_ascii_lowercase())
        && !name.contains("--")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{KubericSetSpec, KubericSetStatus};
    use serde_json::{Value, json};

    fn base_set() -> KubericSet {
        serde_json::from_value(json!({
            "apiVersion": "kuberic.io/v1",
            "kind": "KubericSet",
            "metadata": {
                "name": "kvstore",
                "namespace": "xedio",
                "uid": "b1635720-fdf4-4df3-9911-8e05ca9d465e"
            },
            "spec": {"image": "localhost/kvstore:latest"}
        }))
        .unwrap()
    }

    fn additional(name: &str, selector_type: ServiceSelectorType) -> AdditionalService {
        AdditionalService {
            selector_type,
            service_template: ServiceTemplate {
                metadata: ServiceTemplateMetadata {
                    name: name.to_owned(),
                    ..Default::default()
                },
                spec: ServiceSpec {
                    ports: Some(vec![ServicePort {
                        name: Some("app".to_owned()),
                        port: 8080,
                        target_port: Some(IntOrString::Int(8080)),
                        ..Default::default()
                    }]),
                    ..Default::default()
                },
            },
        }
    }

    fn configured_set(entries: Vec<AdditionalService>) -> KubericSet {
        let mut set = base_set();
        set.spec.managed = Some(ManagedSpec {
            services: ManagedServicesSpec {
                additional: entries,
            },
        });
        set
    }

    fn entry_mut(set: &mut KubericSet) -> &mut AdditionalService {
        &mut set.spec.managed.as_mut().unwrap().services.additional[0]
    }

    fn single_set() -> KubericSet {
        configured_set(vec![additional("kvstore-client", ServiceSelectorType::Rw)])
    }

    fn render_one(set: &KubericSet) -> Service {
        let mut services = build_additional_services(set).unwrap();
        assert_eq!(services.len(), 1);
        services.remove(0)
    }

    fn assert_error(set: &KubericSet, expected: &str) {
        let error = build_additional_services(set).unwrap_err();
        assert!(
            error.contains(expected),
            "{error:?} should contain {expected:?}"
        );
    }

    #[test]
    fn selector_types_serialize_as_rw_ro_r() {
        for (selector, text) in [
            (ServiceSelectorType::Rw, "rw"),
            (ServiceSelectorType::Ro, "ro"),
            (ServiceSelectorType::R, "r"),
        ] {
            assert_eq!(serde_json::to_value(selector).unwrap(), json!(text));
            assert_eq!(
                serde_json::from_value::<ServiceSelectorType>(json!(text)).unwrap(),
                selector
            );
        }
        for invalid in ["RW", "primary", "secondary", "all", ""] {
            assert!(serde_json::from_value::<ServiceSelectorType>(json!(invalid)).is_err());
        }
    }

    #[test]
    fn managed_containers_default_to_no_additional_services() {
        for value in [
            json!({}),
            json!({"services": {}}),
            json!({"services": {"additional": []}}),
        ] {
            let managed: ManagedSpec = serde_json::from_value(value).unwrap();
            assert_eq!(managed, ManagedSpec::default());
            assert!(managed.services.additional.is_empty());
        }
        let metadata: ServiceTemplateMetadata =
            serde_json::from_value(json!({"name": "client"})).unwrap();
        assert!(metadata.labels.is_empty());
        assert!(metadata.annotations.is_empty());
    }

    #[test]
    fn legacy_specs_and_status_remain_compatible() {
        let spec: KubericSetSpec =
            serde_json::from_value(json!({"image": "localhost/kvstore:latest"})).unwrap();
        assert!(spec.managed.is_none());
        assert!(serde_json::to_value(spec).unwrap().get("managed").is_none());
        let status: KubericSetStatus = serde_json::from_value(json!({})).unwrap();
        assert!(status.managed_services.is_none());
        assert!(
            serde_json::to_value(status)
                .unwrap()
                .get("managedServices")
                .is_none()
        );
        assert!(build_additional_services(&base_set()).unwrap().is_empty());
    }

    #[test]
    fn configuration_round_trips_camel_case_and_native_ports() {
        let managed: ManagedSpec = serde_json::from_value(json!({
            "services": {
                "additional": [{
                    "selectorType": "ro",
                    "serviceTemplate": {
                        "metadata": {
                            "name": "kvstore-readers",
                            "labels": {"team": "storage"},
                            "annotations": {"example.test/description": "read traffic"}
                        },
                        "spec": {
                            "type": "NodePort",
                            "externalTrafficPolicy": "Local",
                            "ports": [{"name": "app", "port": 80, "targetPort": "app", "nodePort": 30091}]
                        }
                    }
                }]
            }
        }))
        .unwrap();
        let value = serde_json::to_value(&managed).unwrap();
        let entry = &value["services"]["additional"][0];
        assert_eq!(entry["selectorType"], "ro");
        assert_eq!(
            entry["serviceTemplate"]["spec"]["ports"][0]["targetPort"],
            "app"
        );
        assert_eq!(
            entry["serviceTemplate"]["spec"]["ports"][0]["nodePort"],
            30091
        );
        assert_eq!(
            serde_json::from_value::<ManagedSpec>(value).unwrap(),
            managed
        );
        let mut set = base_set();
        set.spec.managed = Some(managed);
        let value = serde_json::to_value(&set).unwrap();
        assert_eq!(
            value["spec"]["managed"]["services"]["additional"][0]["selectorType"],
            "ro"
        );
        assert_eq!(serde_json::from_value::<KubericSet>(value).unwrap(), set);
    }

    #[test]
    fn managed_status_round_trips_native_ingress_ports_and_conditions() {
        let status = KubericSetStatus {
            managed_services: Some(ManagedServicesStatus {
                observed_generation: 7,
                conditions: vec![StatusCondition {
                    type_: "Ready".to_owned(),
                    status: "True".to_owned(),
                    reason: "Reconciled".to_owned(),
                    message: "Service reconciled and ingress allocated".to_owned(),
                    last_transition_time: "2026-09-17T00:00:00Z".to_owned(),
                }],
                services: vec![ManagedServiceStatus {
                    name: "kvstore-client".to_owned(),
                    service_type: "LoadBalancer".to_owned(),
                    ready: true,
                    reason: "Reconciled".to_owned(),
                    message: "Ingress allocated".to_owned(),
                    ingress: vec![
                        serde_json::from_value(json!({
                            "ip": "192.0.2.10", "ipMode": "VIP",
                            "ports": [{"port": 8080, "protocol": "TCP"}]
                        }))
                        .unwrap(),
                    ],
                    ports: vec![ServicePort {
                        name: Some("app".to_owned()),
                        port: 8080,
                        target_port: Some(IntOrString::String("app".to_owned())),
                        node_port: Some(30091),
                        ..Default::default()
                    }],
                }],
            }),
            ..Default::default()
        };
        let value = serde_json::to_value(&status).unwrap();
        let managed = &value["managedServices"];
        assert_eq!(managed["observedGeneration"], 7);
        assert_eq!(managed["conditions"][0]["type"], "Ready");
        assert_eq!(managed["services"][0]["type"], "LoadBalancer");
        assert!(managed["services"][0].get("serviceType").is_none());
        assert_eq!(managed["services"][0]["ingress"][0]["ipMode"], "VIP");
        assert_eq!(managed["services"][0]["ports"][0]["nodePort"], 30091);
        assert_eq!(
            serde_json::from_value::<KubericSetStatus>(value).unwrap(),
            status
        );
    }

    #[test]
    fn managed_status_defaults_and_omits_empty_lists() {
        let status: ManagedServicesStatus = serde_json::from_value(json!({})).unwrap();
        assert_eq!(status, ManagedServicesStatus::default());
        assert_eq!(
            serde_json::to_value(status).unwrap(),
            json!({"observedGeneration": 0})
        );
        let service: ManagedServiceStatus = serde_json::from_value(json!({
            "name": "client", "type": "ClusterIP", "ready": false,
            "reason": "Pending", "message": "Waiting for reconciliation"
        }))
        .unwrap();
        assert!(service.ingress.is_empty());
        assert!(service.ports.is_empty());
        let value = serde_json::to_value(service).unwrap();
        assert!(value.get("ingress").is_none());
        assert!(value.get("ports").is_none());
    }

    #[test]
    fn template_metadata_rejects_identity_and_ownership_overrides() {
        for (key, value) in [
            ("namespace", json!("another-namespace")),
            ("uid", json!("another-owner")),
            ("generateName", json!("random-")),
            ("resourceVersion", json!("12")),
            ("ownerReferences", json!([])),
            ("finalizers", json!([])),
        ] {
            let mut metadata = json!({"name": "client"});
            metadata[key] = value;
            assert!(
                serde_json::from_value::<ServiceTemplateMetadata>(metadata).is_err(),
                "{key} must not be configurable"
            );
        }
    }

    #[test]
    fn absent_or_empty_configuration_does_not_require_parent_identity() {
        let mut set = base_set();
        set.metadata = ObjectMeta::default();
        assert!(build_additional_services(&set).unwrap().is_empty());
        set.spec.managed = Some(ManagedSpec::default());
        assert!(build_additional_services(&set).unwrap().is_empty());
    }

    #[test]
    fn renders_all_three_routing_selectors() {
        let set = configured_set(vec![
            additional("client-write", ServiceSelectorType::Rw),
            additional("client-read", ServiceSelectorType::Ro),
            additional("client-all", ServiceSelectorType::R),
        ]);
        let rendered = build_additional_services(&set).unwrap();
        assert_eq!(rendered.len(), 3);
        for (service, expected_name, role) in [
            (&rendered[0], "client-write", Some("primary")),
            (&rendered[1], "client-read", Some("secondary")),
            (&rendered[2], "client-all", None),
        ] {
            let mut expected = BTreeMap::from([(SET_LABEL.to_owned(), "kvstore".to_owned())]);
            if let Some(role) = role {
                expected.insert(ROLE_LABEL.to_owned(), role.to_owned());
            }
            assert_eq!(service.metadata.name.as_deref(), Some(expected_name));
            assert_eq!(service.metadata.namespace.as_deref(), Some("xedio"));
            assert_eq!(
                service.spec.as_ref().unwrap().selector.as_ref(),
                Some(&expected)
            );
        }
    }

    #[test]
    fn matching_selector_subsets_are_completed_not_restricted() {
        for (selector_type, role) in [
            (ServiceSelectorType::Rw, Some("primary")),
            (ServiceSelectorType::Ro, Some("secondary")),
            (ServiceSelectorType::R, None),
        ] {
            let mut expected = BTreeMap::from([(SET_LABEL.to_owned(), "kvstore".to_owned())]);
            if let Some(role) = role {
                expected.insert(ROLE_LABEL.to_owned(), role.to_owned());
            }
            let mut subsets = vec![BTreeMap::new(), expected.clone()];
            for (key, value) in &expected {
                subsets.push(BTreeMap::from([(key.clone(), value.clone())]));
            }
            for subset in subsets {
                let mut entry = additional("client", selector_type);
                entry.service_template.spec.selector = Some(subset);
                let service = render_one(&configured_set(vec![entry]));
                assert_eq!(service.spec.unwrap().selector, Some(expected.clone()));
            }
        }
    }

    #[test]
    fn renderer_preserves_explicit_ports_and_other_native_service_fields() {
        let mut set = single_set();
        set.spec.port = 18080;
        set.spec.control_port = 19090;
        set.spec.data_port = 19091;
        let template = &mut entry_mut(&mut set).service_template;
        template.spec = serde_json::from_value(json!({
            "type": "LoadBalancer",
            "allocateLoadBalancerNodePorts": false,
            "loadBalancerClass": "example.test/private",
            "loadBalancerSourceRanges": ["10.0.0.0/8"],
            "externalTrafficPolicy": "Local",
            "internalTrafficPolicy": "Cluster",
            "sessionAffinity": "ClientIP",
            "ipFamilyPolicy": "SingleStack",
            "ipFamilies": ["IPv4"],
            "ports": [
                {"name": "app", "port": 80, "targetPort": 8080, "appProtocol": "kubernetes.io/h2c"},
                {"name": "metrics", "port": 81, "targetPort": "metrics", "protocol": "TCP"}
            ]
        }))
        .unwrap();
        let mut expected = template.spec.clone();
        expected.selector = Some(BTreeMap::from([
            (SET_LABEL.to_owned(), "kvstore".to_owned()),
            (ROLE_LABEL.to_owned(), "primary".to_owned()),
        ]));
        let before = set.clone();
        assert_eq!(render_one(&set).spec, Some(expected));
        assert_eq!(set, before);
    }

    #[test]
    fn explicit_control_and_data_port_numbers_are_not_banned() {
        let mut set = single_set();
        let spec = &mut entry_mut(&mut set).service_template.spec;
        spec.ports = Some(vec![
            ServicePort {
                name: Some("explicit-control".to_owned()),
                port: 9090,
                target_port: Some(IntOrString::Int(9090)),
                ..Default::default()
            },
            ServicePort {
                name: Some("explicit-data".to_owned()),
                port: 9091,
                target_port: Some(IntOrString::Int(9091)),
                ..Default::default()
            },
        ]);
        let expected = spec.ports.clone();
        assert_eq!(render_one(&set).spec.unwrap().ports, expected);
    }

    #[test]
    fn metadata_and_controller_owner_reference_come_from_the_parent() {
        let mut set = single_set();
        set.metadata.labels = Some(BTreeMap::from([(
            "parent-only".to_owned(),
            "ignored".to_owned(),
        )]));
        let metadata = &mut entry_mut(&mut set).service_template.metadata;
        metadata.labels = BTreeMap::from([
            ("team".to_owned(), "storage".to_owned()),
            (SET_LABEL.to_owned(), "kvstore".to_owned()),
            (
                MANAGED_SERVICE_LABEL.to_owned(),
                MANAGED_SERVICE_VALUE.to_owned(),
            ),
        ]);
        metadata.annotations =
            BTreeMap::from([("example.test/note".to_owned(), "clients".to_owned())]);
        let labels = metadata.labels.clone();
        let annotations = metadata.annotations.clone();
        let service = render_one(&set);
        assert_eq!(service.metadata.labels, Some(labels));
        assert_eq!(service.metadata.annotations, Some(annotations));
        assert_eq!(service.metadata.namespace, set.metadata.namespace);
        assert_eq!(service.metadata.name.as_deref(), Some("kvstore-client"));
        let owners = service.metadata.owner_references.unwrap();
        assert_eq!(owners.len(), 1);
        assert_eq!(owners[0].api_version, "kuberic.io/v1");
        assert_eq!(owners[0].kind, "KubericSet");
        assert_eq!(owners[0].name, "kvstore");
        assert_eq!(Some(owners[0].uid.clone()), set.metadata.uid);
        assert_eq!(owners[0].controller, Some(true));
        assert_eq!(owners[0].block_owner_deletion, Some(true));
        assert!(service.metadata.resource_version.is_none());
        assert!(service.metadata.uid.is_none());
    }

    #[test]
    fn missing_management_labels_are_injected() {
        let service = render_one(&single_set());
        assert_eq!(
            service.metadata.labels.unwrap(),
            BTreeMap::from([
                (SET_LABEL.to_owned(), "kvstore".to_owned()),
                (
                    MANAGED_SERVICE_LABEL.to_owned(),
                    MANAGED_SERVICE_VALUE.to_owned()
                )
            ])
        );
        assert!(service.metadata.annotations.is_none());
    }

    #[test]
    fn rendering_requires_nonempty_parent_name_namespace_and_uid() {
        for field in ["name", "namespace", "uid"] {
            for value in [None, Some(""), Some(" \t")] {
                let mut set = single_set();
                let target = match field {
                    "name" => &mut set.metadata.name,
                    "namespace" => &mut set.metadata.namespace,
                    "uid" => &mut set.metadata.uid,
                    _ => unreachable!(),
                };
                *target = value.map(str::to_owned);
                assert_error(&set, &format!("metadata.{field}"));
            }
        }
    }

    #[test]
    fn invalid_dns1035_service_names_are_rejected() {
        for name in [
            "",
            "UPPER",
            "9client",
            "-client",
            "client-",
            "client.name",
            "client_name",
            "cliënt",
            "client\n",
            &"a".repeat(64),
        ] {
            let set = configured_set(vec![additional(name, ServiceSelectorType::Rw)]);
            assert_error(&set, "DNS1035");
        }
        for name in ["a", "a0", "a--b", &"a".repeat(63)] {
            let set = configured_set(vec![additional(name, ServiceSelectorType::Rw)]);
            assert_eq!(render_one(&set).metadata.name.as_deref(), Some(name));
        }
    }

    #[test]
    fn internal_names_and_duplicate_names_are_rejected() {
        for suffix in ["rw", "ro", "r"] {
            let set = configured_set(vec![additional(
                &format!("kvstore-{suffix}"),
                ServiceSelectorType::Rw,
            )]);
            assert_error(&set, "reserved");
        }
        let set = configured_set(vec![
            additional("client", ServiceSelectorType::Rw),
            additional("client", ServiceSelectorType::Ro),
        ]);
        assert_error(&set, "duplicates another additional Service name");
    }

    #[test]
    fn conflicting_managed_metadata_labels_are_rejected() {
        for key in [SET_LABEL, MANAGED_SERVICE_LABEL] {
            let mut set = single_set();
            entry_mut(&mut set)
                .service_template
                .metadata
                .labels
                .insert(key.to_owned(), "foreign".to_owned());
            assert_error(&set, &format!("metadata.labels['{key}']"));
        }
    }

    #[test]
    fn reserved_service_template_annotation_is_rejected() {
        for value in ["", "{}", "not-json"] {
            let mut set = single_set();
            entry_mut(&mut set)
                .service_template
                .metadata
                .annotations
                .insert(SERVICE_TEMPLATE_ANNOTATION.to_owned(), value.to_owned());
            let error = build_additional_services(&set).unwrap_err();
            assert!(
                error.contains(
                    "managed.services.additional[0].serviceTemplate.metadata.annotations['kuberic.io/service-template']"
                ),
                "{error}"
            );
            assert!(error.contains("reserved"), "{error}");
        }
    }

    #[test]
    fn conflicting_or_unknown_selector_entries_are_rejected() {
        for (selector_type, key, value) in [
            (ServiceSelectorType::Rw, SET_LABEL, "foreign"),
            (ServiceSelectorType::Rw, ROLE_LABEL, "secondary"),
            (ServiceSelectorType::Ro, ROLE_LABEL, "primary"),
            (ServiceSelectorType::R, ROLE_LABEL, "primary"),
            (ServiceSelectorType::Rw, "app", "kvstore"),
            (
                ServiceSelectorType::R,
                MANAGED_SERVICE_LABEL,
                MANAGED_SERVICE_VALUE,
            ),
        ] {
            let mut entry = additional("client", selector_type);
            entry.service_template.spec.selector =
                Some(BTreeMap::from([(key.to_owned(), value.to_owned())]));
            assert_error(&configured_set(vec![entry]), key);
        }
    }

    #[test]
    fn supported_types_are_preserved_and_default_to_cluster_ip() {
        for service_type in [
            None,
            Some("ClusterIP"),
            Some("NodePort"),
            Some("LoadBalancer"),
        ] {
            let mut set = single_set();
            entry_mut(&mut set).service_template.spec.type_ = service_type.map(str::to_owned);
            assert_eq!(
                render_one(&set).spec.unwrap().type_.as_deref(),
                Some(service_type.unwrap_or("ClusterIP"))
            );
        }
    }

    #[test]
    fn external_name_and_unknown_service_types_are_rejected() {
        for service_type in ["ExternalName", "Ingress", "", "loadbalancer"] {
            let mut set = single_set();
            entry_mut(&mut set).service_template.spec.type_ = Some(service_type.to_owned());
            assert_error(&set, ".spec.type");
        }
        for service_type in [
            None,
            Some("ClusterIP"),
            Some("NodePort"),
            Some("LoadBalancer"),
        ] {
            let mut set = single_set();
            let spec = &mut entry_mut(&mut set).service_template.spec;
            spec.type_ = service_type.map(str::to_owned);
            spec.external_name = Some("foreign.example.test".to_owned());
            assert_error(&set, ".spec.externalName");
        }
    }

    #[test]
    fn nonempty_explicit_ports_are_required() {
        for ports in [None, Some(Vec::new())] {
            let mut set = single_set();
            entry_mut(&mut set).service_template.spec.ports = ports;
            assert_error(&set, "ports must contain explicit ports");
        }
    }

    #[test]
    fn service_port_ranges_and_names_are_validated() {
        for number in [-1, 0, 65536, i32::MAX] {
            let mut set = single_set();
            entry_mut(&mut set)
                .service_template
                .spec
                .ports
                .as_mut()
                .unwrap()[0]
                .port = number;
            assert_error(&set, ".port must be between 1 and 65535");
        }
        for name in [
            "HTTP",
            "-app",
            "app-",
            "app.port",
            "app_port",
            "ápp",
            &"a".repeat(64),
        ] {
            let mut set = single_set();
            entry_mut(&mut set)
                .service_template
                .spec
                .ports
                .as_mut()
                .unwrap()[0]
                .name = Some(name.to_owned());
            assert_error(&set, ".name");
        }
        for (name, number) in [(None, 1), (Some(""), 65535), (Some("123"), 8080)] {
            let mut set = single_set();
            let port = &mut entry_mut(&mut set)
                .service_template
                .spec
                .ports
                .as_mut()
                .unwrap()[0];
            port.name = name.map(str::to_owned);
            port.port = number;
            assert_eq!(
                render_one(&set).spec.unwrap().ports.unwrap()[0].port,
                number
            );
        }
    }

    fn two_ports() -> Vec<ServicePort> {
        vec![
            ServicePort {
                name: Some("app".to_owned()),
                port: 80,
                ..Default::default()
            },
            ServicePort {
                name: Some("metrics".to_owned()),
                port: 81,
                ..Default::default()
            },
        ]
    }

    #[test]
    fn multiple_service_ports_require_unique_nonempty_names() {
        for name in [None, Some("")] {
            let mut set = single_set();
            let mut ports = two_ports();
            ports[1].name = name.map(str::to_owned);
            entry_mut(&mut set).service_template.spec.ports = Some(ports);
            assert_error(&set, "name is required");
        }
        let mut set = single_set();
        let mut ports = two_ports();
        ports[1].name = ports[0].name.clone();
        entry_mut(&mut set).service_template.spec.ports = Some(ports);
        assert_error(&set, "duplicates another port name");
    }

    #[test]
    fn duplicate_ports_use_the_effective_protocol() {
        for protocol in [None, Some(""), Some("TCP")] {
            let mut set = single_set();
            let mut ports = two_ports();
            ports[1].port = ports[0].port;
            ports[1].protocol = protocol.map(str::to_owned);
            entry_mut(&mut set).service_template.spec.ports = Some(ports);
            assert_error(&set, "duplicates Service port 80/TCP");
        }
        let mut set = single_set();
        let mut ports = two_ports();
        ports[1].port = ports[0].port;
        ports[1].protocol = Some("UDP".to_owned());
        entry_mut(&mut set).service_template.spec.ports = Some(ports.clone());
        assert_eq!(render_one(&set).spec.unwrap().ports, Some(ports));
    }

    #[test]
    fn node_ports_allow_allocation_but_validate_ranges_and_duplicates() {
        for node_port in [Some(-1), Some(65536)] {
            let mut set = single_set();
            let spec = &mut entry_mut(&mut set).service_template.spec;
            spec.type_ = Some("NodePort".to_owned());
            spec.ports.as_mut().unwrap()[0].node_port = node_port;
            assert_error(&set, ".nodePort must be between 1 and 65535");
        }
        for node_port in [None, Some(0), Some(1), Some(30090), Some(65535)] {
            let mut set = single_set();
            let spec = &mut entry_mut(&mut set).service_template.spec;
            spec.type_ = Some("NodePort".to_owned());
            spec.ports.as_mut().unwrap()[0].node_port = node_port;
            assert_eq!(
                render_one(&set).spec.unwrap().ports.unwrap()[0].node_port,
                node_port
            );
        }
        for (node_port, protocol, valid) in [
            (30090, None, false),
            (0, None, true),
            (30090, Some("UDP"), true),
        ] {
            let mut set = single_set();
            let mut ports = two_ports();
            ports[0].node_port = Some(node_port);
            ports[1].node_port = Some(node_port);
            ports[1].protocol = protocol.map(str::to_owned);
            let spec = &mut entry_mut(&mut set).service_template.spec;
            spec.type_ = Some("NodePort".to_owned());
            spec.ports = Some(ports);
            if valid {
                render_one(&set);
            } else {
                assert_error(&set, "duplicates nodePort 30090/TCP");
            }
        }
    }

    #[test]
    fn target_port_numbers_and_iana_names_are_validated() {
        for target in [
            json!(-1),
            json!(0),
            json!(65536),
            json!(""),
            json!("123"),
            json!("HTTP"),
            json!("-app"),
            json!("app-"),
            json!("app--http"),
            json!("app_port"),
            json!("app.http"),
            json!("ápp"),
            json!("sixteen-lettersx"),
        ] {
            let mut set = single_set();
            entry_mut(&mut set)
                .service_template
                .spec
                .ports
                .as_mut()
                .unwrap()[0]
                .target_port = Some(serde_json::from_value(target).unwrap());
            assert_error(&set, ".targetPort");
        }
        for target in [
            Value::Null,
            json!(1),
            json!(65535),
            json!("app"),
            json!("2http"),
            json!("http-2"),
            json!("abcdefghijklmno"),
        ] {
            let mut set = single_set();
            let target: Option<IntOrString> = serde_json::from_value(target).unwrap();
            entry_mut(&mut set)
                .service_template
                .spec
                .ports
                .as_mut()
                .unwrap()[0]
                .target_port = target.clone();
            assert_eq!(
                render_one(&set).spec.unwrap().ports.unwrap()[0].target_port,
                target
            );
        }
    }

    #[test]
    fn managed_services_require_normal_ready_endpoint_behavior() {
        let mut set = single_set();
        entry_mut(&mut set)
            .service_template
            .spec
            .publish_not_ready_addresses = Some(true);
        assert_error(&set, "publishNotReadyAddresses must not be true");
        for value in [None, Some(false)] {
            entry_mut(&mut set)
                .service_template
                .spec
                .publish_not_ready_addresses = value;
            assert_eq!(
                render_one(&set).spec.unwrap().publish_not_ready_addresses,
                value
            );
        }
    }

    #[test]
    fn validation_rejects_the_entire_list_without_mutating_input() {
        let mut invalid = additional("client-read", ServiceSelectorType::Ro);
        invalid.service_template.spec.ports = None;
        let set = configured_set(vec![
            additional("client-write", ServiceSelectorType::Rw),
            invalid,
        ]);
        let before = set.clone();
        assert_error(
            &set,
            "managed.services.additional[1].serviceTemplate.spec.ports",
        );
        assert_eq!(set, before);
    }
}
