//! Execution intent retained on T, never reconstructed from Kubernetes state.
use crate::config::KubernetesComputeConfig;
use crate::driver::{
    KubernetesDriverError, replace_sandbox_bootstrap_init_container,
    sandbox_bootstrap_init_container,
};
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_update: Option<LaunchRevision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_environment: Option<std::collections::HashMap<String, String>>,
    pub log_level: String,
    pub agent_uid: u32,
    pub agent_gid: u32,
    pub workload: Pod,
    pub volume_claim_templates: serde_json::Value,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct LaunchRevision {
    pub revision: u64,
    pub operation_id: String,
}

impl LaunchIntent {
    pub fn workload_for_generation(
        &self,
        secret: &str,
        image_pull_secrets: &[String],
        config: &KubernetesComputeConfig,
    ) -> Result<Pod, KubernetesDriverError> {
        let mut pod = self.workload.clone();
        let spec = pod
            .spec
            .as_mut()
            .expect("stored launch has a workload spec");
        // Reuse the native bootstrap replacement, sourced from current trusted
        // runtime configuration. All business containers remain the saved intent.
        let mut init_containers: Vec<serde_json::Value> = spec
            .init_containers
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|container| serde_json::to_value(container).expect("serialize init container"))
            .collect();
        replace_sandbox_bootstrap_init_container(
            &mut init_containers,
            sandbox_bootstrap_init_container(
                &config.sandbox_runtime_image,
                config.sandbox_runtime_image_pull_policy,
                self.agent_uid,
                self.agent_gid,
            ),
        )?;
        spec.init_containers = Some(
            serde_json::from_value(serde_json::Value::Array(init_containers))
                .map_err(|error| KubernetesDriverError::Message(error.to_string()))?,
        );
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
        Ok(pod)
    }
}
