// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Reuse native runtime resources and keep confidential supervisor state in guest memory.

// Shared-supervisor renderers remain in the unmodified upstream module.
#[allow(dead_code)]
#[path = "../../../repos/openshell/crates/openshell-driver-kubernetes/src/sandbox_runtime.rs"]
mod upstream;
pub use upstream::*;

use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;

#[allow(clippy::too_many_arguments, clippy::similar_names)]
pub fn supervisor_pod(
    namespace: &str,
    names: &SandboxRuntimeNames,
    sandbox_id: &str,
    sandbox_name: &str,
    gateway_id: &str,
    supervisor_image: &str,
    supervisor_pull_policy: Option<crate::KubernetesImagePullPolicy>,
    service_account_name: &str,
    control_uid: u32,
    control_gid: u32,
    image_pull_secrets: &[String],
    grpc_endpoint: &str,
    client_tls: SupervisorClientTls<'_>,
    main_process_spec: &str,
    log_level: &str,
    sa_token_ttl_secs: i64,
    https_proxy: Option<&str>,
    no_proxy: Option<&str>,
    proxy_auth_secret: Option<(&str, &str)>,
    proxy_auth_allow_insecure: bool,
    proxy_connect_by_hostname: bool,
    upstream_proxy_ca_bundle_staged: bool,
    provider_spiffe_socket_path: Option<&str>,
    owner: OwnerReference,
    tracing_environment: &[(&str, String)],
) -> Result<Pod, String> {
    let mut pod = upstream::supervisor_pod(
        namespace,
        names,
        sandbox_id,
        sandbox_name,
        gateway_id,
        supervisor_image,
        supervisor_pull_policy,
        service_account_name,
        control_uid,
        control_gid,
        image_pull_secrets,
        grpc_endpoint,
        client_tls,
        main_process_spec,
        log_level,
        sa_token_ttl_secs,
        https_proxy,
        no_proxy,
        proxy_auth_secret,
        proxy_auth_allow_insecure,
        proxy_connect_by_hostname,
        upstream_proxy_ca_bundle_staged,
        provider_spiffe_socket_path,
        owner,
        tracing_environment,
    )?;
    let spec = pod.spec.as_mut().expect("native supervisor Pod has a spec");
    spec.enable_service_links = Some(false);
    let security = spec
        .security_context
        .as_mut()
        .expect("native Pod security context");
    security.supplemental_groups = Some(Vec::new());
    security.supplemental_groups_policy = Some("Strict".to_string());
    // Kata Memory EmptyDir uses guest tmpfs, keeping sockets, TLS state and logs
    // off host-backed volumes. Kata 4.2 does not forward its sizeLimit.
    for volume in spec.volumes.as_mut().expect("native supervisor volumes") {
        if matches!(volume.name.as_str(), "run" | "logs") {
            volume
                .empty_dir
                .as_mut()
                .expect("native supervisor EmptyDir")
                .medium = Some("Memory".to_string());
        }
    }
    Ok(pod)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supervisor_pod_keeps_confidential_groups_environment_and_state_private() {
        let pod = supervisor_pod(
            "sandbox",
            &SandboxRuntimeNames::new("pair"),
            "pair",
            "demo",
            "gateway",
            "supervisor:latest",
            Some(crate::KubernetesImagePullPolicy::IfNotPresent),
            "sandbox-sa",
            1000,
            1000,
            &["registry-credentials".to_string()],
            "https://gateway:8080",
            SupervisorClientTls::Bootstrap,
            "{}",
            "info",
            600,
            None,
            None,
            None,
            false,
            false,
            false,
            None,
            sandbox_owner_reference("demo", "uid-1", "agents.x-k8s.io/v1beta1", false),
            &[],
        )
        .expect("render supervisor Pod");
        let spec = pod.spec.as_ref().expect("supervisor spec");
        assert_eq!(spec.enable_service_links, Some(false));
        for name in ["run", "logs"] {
            let empty_dir = spec
                .volumes
                .as_ref()
                .unwrap()
                .iter()
                .find(|volume| volume.name == name)
                .and_then(|volume| volume.empty_dir.as_ref())
                .unwrap();
            assert_eq!(empty_dir.medium.as_deref(), Some("Memory"));
            assert!(empty_dir.size_limit.is_none());
        }
        let security = spec.security_context.as_ref().unwrap();
        assert_eq!(security.supplemental_groups.as_deref(), Some([].as_slice()));
        assert_eq!(
            security.supplemental_groups_policy.as_deref(),
            Some("Strict")
        );
        let encoded = serde_json::to_value(&pod).unwrap();
        assert_eq!(
            encoded.pointer("/spec/securityContext/supplementalGroupsPolicy"),
            Some(&serde_json::json!("Strict"))
        );
    }
}
