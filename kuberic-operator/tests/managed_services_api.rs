use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use k8s_openapi::api::core::v1::{Namespace, Service};
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{DeleteParams, Patch, PatchParams, PostParams, Preconditions};
use kube::{Api, Client, Config, CustomResourceExt, ResourceExt};
use kuberic_operator::cluster_api::{ClusterApi, KubeClusterApi};
use kuberic_operator::crd::{KubericSet, Phase};
use kuberic_operator::services::{ManagedServiceApi, reconcile_managed_services};
use serde_json::json;

#[tokio::test]
#[ignore = "requires a fresh disposable envtest API server at KUBERIC_API_TEST_URL"]
async fn managed_services_reconcile_against_kubernetes_api() {
    let url = std::env::var("KUBERIC_API_TEST_URL").expect("explicit disposable API server URL");
    let mut config = Config::new(url.parse().expect("API server URI"));
    assert_eq!(
        config.cluster_url.host(),
        Some("127.0.0.1"),
        "only a disposable loopback API server is permitted"
    );
    assert_eq!(config.cluster_url.scheme_str(), Some("https"));
    assert!(
        config
            .cluster_url
            .port_u16()
            .is_some_and(|port| port != 443)
    );
    // Only the disposable server's credential is read, never a user's kubeconfig.
    config.accept_invalid_certs = true;
    let token_path =
        std::env::var("KUBERIC_API_TEST_TOKEN_FILE").expect("disposable API server token file");
    config.auth_info.token = Some(std::fs::read_to_string(token_path).unwrap().into());
    let client = Client::try_from(config).unwrap();
    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());
    let installed = crds
        .create(&PostParams::default(), &KubericSet::crd())
        .await
        .expect("install CRD on a fresh disposable API server");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let crd = crds.get("kubericsets.kuberic.io").await.unwrap();
        if crd
            .status
            .as_ref()
            .and_then(|status| status.conditions.as_ref())
            .is_some_and(|conditions| {
                conditions
                    .iter()
                    .any(|condition| condition.type_ == "Established" && condition.status == "True")
            })
        {
            break;
        }
        assert!(Instant::now() < deadline, "CRD did not become established");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let namespace = format!(
        "managed-api-{:x}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let namespaces: Api<Namespace> = Api::all(client.clone());
    let namespace_object = namespaces
        .create(
            &PostParams::default(),
            &Namespace {
                metadata: kube::api::ObjectMeta {
                    name: Some(namespace.clone()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let sets: Api<KubericSet> = Api::namespaced(client.clone(), &namespace);
    let services: Api<Service> = Api::namespaced(client.clone(), &namespace);
    let api = KubeClusterApi { client };
    let set: KubericSet = serde_json::from_value(json!({
        "metadata": {"name": "app", "namespace": namespace},
        "spec": {"image": "example:latest", "managed": {"services": {"additional": [{
            "selectorType": "rw",
            "serviceTemplate": {
                "metadata": {
                    "name": "external",
                    "annotations": {"example.com/old": "remove"},
                    "labels": {"example.com/old": "remove"}
                },
                "spec": {
                    "type": "LoadBalancer",
                    "loadBalancerClass": "test.kuberic.io/no-controller",
                    "externalTrafficPolicy": "Local",
                    "healthCheckNodePort": 0,
                    "loadBalancerSourceRanges": ["192.0.2.0/24"],
                    "ports": [
                        {"name": "app", "port": 8080, "targetPort": 8080},
                        {"name": "metrics", "port": 9080, "targetPort": 9080}
                    ]
                }
            }
        }]}}}
    }))
    .unwrap();
    let set = sets.create(&PostParams::default(), &set).await.unwrap();
    let internal: Service = serde_json::from_value(json!({
        "metadata": {"name": "app-rw", "namespace": namespace, "labels": {"kuberic.io/set": "app"}},
        "spec": {"type": "NodePort", "ports": [{"port": 8080}]}
    }))
    .unwrap();
    let internal = services
        .create(&PostParams::default(), &internal)
        .await
        .unwrap();
    reconcile_managed_services(&set, &api).await.unwrap();
    let before = services.get("external").await.unwrap();
    let allocated = before.spec.as_ref().unwrap();
    assert!(allocated.cluster_ip.is_some());
    assert!(
        allocated
            .health_check_node_port
            .is_some_and(|port| port > 0)
    );
    assert!(
        allocated
            .ports
            .as_ref()
            .unwrap()
            .iter()
            .all(|port| port.node_port.is_some_and(|port| port > 0))
    );
    for _ in 0..3 {
        reconcile_managed_services(&sets.get("app").await.unwrap(), &api)
            .await
            .unwrap();
    }
    assert_eq!(
        before.metadata.resource_version,
        services
            .get("external")
            .await
            .unwrap()
            .metadata
            .resource_version,
        "defaulting must not cause update loops"
    );

    services
        .patch(
            "external",
            &PatchParams::default(),
            &Patch::Merge(json!({
                "metadata": {"annotations": {"provider.example/owned": "keep"}}
            })),
        )
        .await
        .unwrap();
    let mut set = sets.get("app").await.unwrap();
    let template = &mut set.spec.managed.as_mut().unwrap().services.additional[0].service_template;
    template.metadata.annotations.clear();
    template.metadata.labels.clear();
    template.spec.load_balancer_source_ranges = None;
    let ports = template.spec.ports.as_mut().unwrap();
    ports.reverse();
    ports
        .iter_mut()
        .find(|port| port.name.as_deref() == Some("app"))
        .unwrap()
        .port = 8082;
    let set = sets
        .replace("app", &PostParams::default(), &set)
        .await
        .unwrap();
    reconcile_managed_services(&set, &api).await.unwrap();
    let updated = services.get("external").await.unwrap();
    let new = updated.spec.as_ref().unwrap();
    assert_eq!(before.metadata.uid, updated.metadata.uid);
    assert_eq!(allocated.cluster_ip, new.cluster_ip);
    assert_eq!(allocated.cluster_ips, new.cluster_ips);
    assert_eq!(allocated.ip_families, new.ip_families);
    assert_eq!(allocated.ip_family_policy, new.ip_family_policy);
    assert_eq!(allocated.health_check_node_port, new.health_check_node_port);
    assert_eq!(
        allocated.ports.as_ref().unwrap()[0].node_port,
        new.ports.as_ref().unwrap()[1].node_port
    );
    assert_eq!(
        allocated.ports.as_ref().unwrap()[1].node_port,
        new.ports.as_ref().unwrap()[0].node_port
    );
    assert!(
        !updated
            .metadata
            .annotations
            .as_ref()
            .unwrap()
            .contains_key("example.com/old")
    );
    assert_eq!(
        updated.metadata.annotations.as_ref().unwrap()["provider.example/owned"],
        "keep"
    );
    assert!(
        new.load_balancer_source_ranges
            .as_ref()
            .is_none_or(Vec::is_empty)
    );
    assert!(
        api.replace_additional_service(&namespace, &before)
            .await
            .is_err()
    );
    assert!(
        api.delete_additional_service(&namespace, &before)
            .await
            .is_err()
    );

    services
        .patch_status(
            "external",
            &PatchParams::default(),
            &Patch::Merge(json!({
                "status": {"loadBalancer": {"ingress": [{"hostname": "lb.example.internal"}]}}
            })),
        )
        .await
        .unwrap();
    reconcile_managed_services(&sets.get("app").await.unwrap(), &api)
        .await
        .unwrap();
    let set = sets.get("app").await.unwrap();
    let managed = set
        .status
        .as_ref()
        .unwrap()
        .managed_services
        .clone()
        .unwrap();
    assert!(managed.services[0].ready);
    assert_eq!(
        managed.services[0].ingress[0].hostname.as_deref(),
        Some("lb.example.internal")
    );
    let mut topology = set.status.clone().unwrap();
    topology.phase = Phase::Healthy;
    topology.managed_services = None;
    api.patch_set_status(
        &namespace,
        "app",
        &topology,
        set.metadata.resource_version.as_deref(),
    )
    .await
    .unwrap();
    let set = sets.get("app").await.unwrap();
    assert_eq!(
        set.status.as_ref().unwrap().managed_services.as_ref(),
        Some(&managed)
    );

    let mut invalid = set.clone();
    invalid.spec.managed.as_mut().unwrap().services.additional[0]
        .service_template
        .spec
        .cluster_ip = Some("10.42.0.200".to_string());
    let invalid = sets
        .replace("app", &PostParams::default(), &invalid)
        .await
        .unwrap();
    assert!(
        reconcile_managed_services(&invalid, &api)
            .await
            .unwrap_err()
            .contains("immutable")
    );
    assert_eq!(
        services.get("external").await.unwrap().metadata.uid,
        before.metadata.uid
    );

    let foreign: Service = serde_json::from_value(json!({
        "metadata": {"name": "foreign"},
        "spec": {"ports": [{"port": 1234}]}
    }))
    .unwrap();
    let foreign = services
        .create(&PostParams::default(), &foreign)
        .await
        .unwrap();
    let mut collision = sets.get("app").await.unwrap();
    let template =
        &mut collision.spec.managed.as_mut().unwrap().services.additional[0].service_template;
    template.metadata.name = "foreign".to_string();
    template.spec.cluster_ip = None;
    let collision = sets
        .replace("app", &PostParams::default(), &collision)
        .await
        .unwrap();
    assert!(
        reconcile_managed_services(&collision, &api)
            .await
            .unwrap_err()
            .contains("not an additional Service owned")
    );
    assert_eq!(
        services.get("foreign").await.unwrap().metadata.uid,
        foreign.metadata.uid
    );
    assert!(services.get_opt("external").await.unwrap().is_some());

    let mut removed = sets.get("app").await.unwrap();
    removed.spec.managed = None;
    let removed = sets
        .replace("app", &PostParams::default(), &removed)
        .await
        .unwrap();
    reconcile_managed_services(&removed, &api).await.unwrap();
    assert!(services.get_opt("external").await.unwrap().is_none());
    let final_set = sets.get("app").await.unwrap();
    assert!(
        final_set
            .status
            .as_ref()
            .unwrap()
            .managed_services
            .is_none()
    );
    assert_eq!(final_set.status.as_ref().unwrap().phase, Phase::Healthy);
    assert_eq!(services.get("app-rw").await.unwrap().spec, internal.spec);

    for service in [internal, foreign] {
        services
            .delete(
                &service.name_any(),
                &DeleteParams {
                    preconditions: Some(Preconditions {
                        uid: service.metadata.uid,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }
    sets.delete(
        "app",
        &DeleteParams {
            preconditions: Some(Preconditions {
                uid: removed.metadata.uid,
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    namespaces
        .delete(
            &namespace,
            &DeleteParams {
                preconditions: Some(Preconditions {
                    uid: namespace_object.metadata.uid,
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    crds.delete(
        "kubericsets.kuberic.io",
        &DeleteParams {
            preconditions: Some(Preconditions {
                uid: installed.metadata.uid,
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
}
