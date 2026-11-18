// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

mod attestation;
mod bootstrap;
mod confidential;
mod launch;
// Compile unchanged modules from the pinned upstream checkout. They resolve
// crate:: references against this driver and retain their upstream tests.
#[path = "../../../repos/openshell/crates/openshell-driver-kubernetes/src/config.rs"]
pub mod config;
pub mod driver;
#[path = "../../../repos/openshell/crates/openshell-driver-kubernetes/src/grpc.rs"]
pub mod grpc;
pub mod isolation;
#[path = "../../../repos/openshell/crates/openshell-driver-kubernetes/src/lifecycle.rs"]
mod lifecycle;
#[path = "../../../repos/openshell/crates/openshell-driver-kubernetes/src/otel_tracing.rs"]
pub mod otel_tracing;
#[path = "../../../repos/openshell/crates/openshell-driver-kubernetes/src/resource_admission.rs"]
mod resource_admission;
mod sandbox_runtime;
// Reuse native placement/readiness types; this external driver does not start
// the upstream shared-supervisor credential writer.
#[allow(dead_code)]
#[path = "../../../repos/openshell/crates/openshell-driver-kubernetes/src/shared_supervisor.rs"]
mod shared_supervisor;

pub use config::{
    DEFAULT_GATEWAY_ID, DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME, DEFAULT_WORKSPACE_STORAGE_SIZE,
    KubernetesComputeConfig, KubernetesControlConnection, KubernetesImagePullPolicy,
    KubernetesSandboxRuntimeConfig, ManagedSshIngressConfig, SharedSupervisorConfig,
    SupervisorTopology, WorkspaceMode, managed_namespace_prefix,
};
pub use driver::{ConfidentialDriverSettings, KubernetesComputeDriver, KubernetesDriverError};
pub use grpc::ComputeDriverService;
pub use openshell_core::DynamicStringAllowlist as OperatorNamespaceAllowlist;

#[path = "../../../repos/openshell/crates/openshell-driver-kubernetes/src/app_listener.rs"]
pub mod app_listener;
