//! Execution intent retained on T, never reconstructed from Kubernetes state.
use k8s_openapi::api::core::v1::Pod;
use serde::{Deserialize, Serialize};

// Commands can contain sensitive arguments; do not derive Debug.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct LaunchIntent {
    pub sandbox_id: String,
    pub namespace: String,
    pub sandbox_cr_uid: String,
    pub sandbox_name: String,
    pub main_process_spec: String,
    pub log_level: String,
    pub agent_uid: u32,
    pub agent_gid: u32,
    pub workload: Pod,
    pub volume_claim_templates: serde_json::Value,
}

impl LaunchIntent {
    pub fn workload_for_generation(&self, secret: &str, image_pull_secrets: &[String]) -> Pod {
        let mut pod = self.workload.clone();
        let spec = pod
            .spec
            .as_mut()
            .expect("stored launch has a workload spec");
        for volume in spec.volumes.iter_mut().flatten() {
            if volume.name == "openshell-sandbox-bootstrap" {
                volume
                    .secret
                    .as_mut()
                    .expect("bootstrap secret source")
                    .secret_name = Some(secret.to_owned());
            }
        }
        spec.image_pull_secrets = (!image_pull_secrets.is_empty()).then(|| {
            image_pull_secrets
                .iter()
                .map(|name| k8s_openapi::api::core::v1::LocalObjectReference { name: name.clone() })
                .collect()
        });
        pod
    }
}
