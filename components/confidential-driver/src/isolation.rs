// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Reuse native boundary provisioning and isolate unsolicited supervisor ingress.

#[path = "../../../repos/openshell/crates/openshell-driver-kubernetes/src/isolation.rs"]
mod upstream;
pub use upstream::*;

pub struct KubernetesSandboxRuntimeNetworkFenceSpec {
    pub namespace: String,
    pub policy_name: String,
    pub supervisor_policy_name: String,
    pub boundary_port: u16,
}

impl KubernetesSandboxRuntimeNetworkFenceSpec {
    #[must_use]
    pub fn provision(self) -> KubernetesSandboxRuntimeNetworkFence {
        let mut fence = upstream::KubernetesSandboxRuntimeNetworkFenceSpec {
            namespace: self.namespace,
            policy_name: self.policy_name,
            supervisor_policy_name: self.supervisor_policy_name,
            boundary_port: self.boundary_port,
        }
        .provision();
        // Supervisor control uses outbound connections and replies; isolate new
        // inbound connections even without a namespace-wide default deny policy.
        let spec = fence
            .supervisor_policy
            .spec
            .as_mut()
            .expect("native supervisor fence spec");
        spec.policy_types = Some(vec!["Ingress".to_string(), "Egress".to_string()]);
        spec.ingress = Some(Vec::new());
        fence
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::networking::v1::NetworkPolicyEgressRule;

    #[test]
    fn network_fence_isolates_supervisor_ingress_without_namespace_default_deny() {
        let fence = KubernetesSandboxRuntimeNetworkFenceSpec {
            namespace: "sandbox-ns".to_string(),
            policy_name: "openshell-sandbox-workloads".to_string(),
            supervisor_policy_name: "openshell-sandbox-supervisors".to_string(),
            boundary_port: 5500,
        }
        .provision();
        let spec = fence
            .supervisor_policy
            .spec
            .expect("supervisor policy has a spec");
        assert_eq!(
            spec.policy_types,
            Some(vec!["Ingress".to_string(), "Egress".to_string()])
        );
        assert_eq!(spec.ingress, Some(Vec::new()));
        assert_eq!(spec.pod_selector.match_labels, Some(fence.control_labels));
        assert_eq!(spec.egress, Some(vec![NetworkPolicyEgressRule::default()]));
    }
}
