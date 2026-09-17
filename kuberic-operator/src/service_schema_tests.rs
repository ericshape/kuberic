use kube::CustomResourceExt;
use serde_json::Value;

use crate::crd::KubericSet;

#[test]
fn deployed_managed_service_schemas_match_derived_crd_exactly() {
    let crd = serde_json::to_value(KubericSet::crd()).unwrap();
    let manifest = include_str!("../deploy/deployment.yaml");
    for (section, field, marker) in [
        ("spec", "managed", "managed-services-spec"),
        ("status", "managedServices", "managed-services-status"),
    ] {
        let begin = format!("# BEGIN GENERATED {marker}");
        let end = format!("# END GENERATED {marker}");
        let block = manifest
            .split_once(&begin)
            .unwrap()
            .1
            .split_once(&end)
            .unwrap()
            .0;
        let schema = block
            .trim()
            .strip_prefix(&format!("{field}:"))
            .unwrap()
            .trim();
        let deployed: Value = serde_json::from_str(schema).unwrap();
        let expected = &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]
            [section]["properties"][field];
        assert_eq!(
            &deployed, expected,
            "regenerate managed-Service schemas using docs/Dev.md"
        );
    }
}
