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
        crate::config::MIN_SA_TOKEN_TTL_SECS,
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
    spec.volumes
        .as_mut()
        .expect("native supervisor volumes")
        .retain(|v| v.name != "sa-token");
    for container in &mut spec.containers {
        if let Some(mounts) = &mut container.volume_mounts {
            mounts.retain(|mount| mount.name != "sa-token");
        }
        if let Some(env) = &mut container.env {
            env.retain(|entry| entry.name != "OPENSHELL_K8S_SA_TOKEN_FILE");
        }
    }

    let security = spec
        .security_context
        .as_mut()
        .expect("native Pod security context");
    // Explicit image groups keep containerd and genpolicy aligned for guest pull.
    security.supplemental_groups = Some(vec![0]);
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
    fn supervisor_pod_sets_guest_pull_groups_and_keeps_state_private() {
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
        assert!(
            spec.volumes
                .as_ref()
                .unwrap()
                .iter()
                .all(|v| v.projected.is_none())
        );
        assert!(
            spec.containers[0]
                .env
                .as_ref()
                .unwrap()
                .iter()
                .all(|entry| entry.name != "OPENSHELL_K8S_SA_TOKEN_FILE")
        );
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
        assert_eq!(
            security.supplemental_groups.as_deref(),
            Some([0].as_slice())
        );
        assert_eq!(security.supplemental_groups_policy, None);
        assert_eq!(security.fs_group, Some(1000));
        let identity = spec.containers[0].security_context.as_ref().unwrap();
        assert_eq!(identity.run_as_user, Some(1000));
        assert_eq!(identity.run_as_group, Some(1000));
    }
}
