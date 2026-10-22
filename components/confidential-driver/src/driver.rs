// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Kubernetes compute driver.

use crate::bootstrap::{BootstrapRole, BootstrapStore, PendingDelete};
use crate::confidential::{GuestInitdata, INITDATA_ANNOTATION, SUPERVISOR_KEYS, WORKLOAD_KEYS};
use crate::config::{
    DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME, DEFAULT_SANDBOX_UID, DEFAULT_WORKSPACE_STORAGE_SIZE,
    KubernetesComputeConfig, OperatorNamespaceAllowlist, WorkspaceMode, is_dns_1123_label,
    managed_namespace, validate_managed_namespace_name,
};
use crate::isolation::{
    BOUNDARY_PAIR_LABEL, BOUNDARY_ROLE_LABEL, KubernetesSandboxRuntimeBoundarySpec,
};
use crate::lifecycle::LifecycleGates;
use crate::sandbox_runtime::{
    BOUNDARY_CERTIFICATE_PATH, BOUNDARY_CONFIG_PATH, BOUNDARY_PRIVATE_KEY_PATH, ClientTlsMaterial,
    SUPERVISOR_TERMINATION_GRACE_PERIOD_SECONDS, SandboxRuntimeNames, SupervisorClientTls,
    boundary_service, generate_proxy_ca_material, image_pull_secret_copy, sandbox_bootstrap_secret,
    sandbox_owner_reference as sandbox_runtime_sandbox_owner_reference,
    supervisor_bootstrap_secret, supervisor_pod, workload_fence,
};
use futures::{Stream, StreamExt, TryStreamExt};
use k8s_openapi::api::core::v1::{
    Event as KubeEventObj, Namespace, Node, PersistentVolume, PersistentVolumeClaim,
    PersistentVolumeClaimVolumeSource, Pod, Secret, Service, ServiceAccount, Volume, VolumeMount,
};
use k8s_openapi::api::networking::v1::{
    NetworkPolicy, NetworkPolicyIngressRule, NetworkPolicyPeer, NetworkPolicyPort,
    NetworkPolicySpec,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, OwnerReference};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::{
    Api, ApiResource, DeleteParams, ListParams, Patch, PatchParams, PostParams, Preconditions,
};
use kube::core::gvk::GroupVersionKind;
use kube::core::{DynamicObject, ObjectMeta};
use kube::runtime::WatchStreamExt;
use kube::runtime::wait::await_condition;
use kube::runtime::watcher::{self, Event};
use kube::{Client, Error as KubeError};
use openshell_core::driver_mounts;
use openshell_core::driver_utils::{
    LABEL_GATEWAY_ID, LABEL_MANAGED_BY, LABEL_MANAGED_BY_VALUE, LABEL_SANDBOX_ID,
    LABEL_SANDBOX_NAME, LABEL_SANDBOX_WORKSPACE, openshell_sandbox_label_selector,
};
use openshell_core::gpu::{driver_gpu_requirements, effective_driver_gpu_count};
use openshell_core::progress::{
    PROGRESS_STEP_PULLING_IMAGE, PROGRESS_STEP_REQUESTING_SANDBOX, PROGRESS_STEP_STARTING_SANDBOX,
    format_bytes, mark_progress_active, mark_progress_complete, mark_progress_detail,
};
use openshell_core::proto::compute::v1::{
    CpuResourceCapabilities, DriverCondition as SandboxCondition,
    DriverPlatformEvent as PlatformEvent, DriverSandbox as Sandbox,
    DriverSandboxSpec as SandboxSpec, DriverSandboxStatus as SandboxStatus,
    DriverSandboxTemplate as SandboxTemplate, GetCapabilitiesResponse, GpuResourceCapabilities,
    GpuResourceRequirements, MemoryResourceCapabilities, ResourceCapabilities,
    WatchSandboxesDeletedEvent, WatchSandboxesEvent, WatchSandboxesPlatformEvent,
    WatchSandboxesSandboxEvent, watch_sandboxes_event,
};
use openshell_core::proto_struct::{struct_to_json_object, value_to_json};
use openshell_isolation_interface::contract::ResolvedWorkloadIdentity;
use openshell_sandbox_backend::boundary_protocol::{
    GatewayVerificationKey, SandboxTlsClientConfig, SandboxTlsServerConfig,
    generate_sandbox_tls_material,
};
use rand::RngCore as _;
use serde::Deserialize;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{OnceCell, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, info, warn};

pub type WatchStream =
    Pin<Box<dyn Stream<Item = Result<WatchSandboxesEvent, KubernetesDriverError>> + Send>>;

const MANAGED_SSH_NETWORK_POLICY_NAME: &str = "openshell-sandbox-ssh";
const AGENT_SANDBOX_TRACE_CONTEXT_ANNOTATION: &str = "opentelemetry.io/trace-context";
const ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAPPING: &str = "openshell.ai/sandbox-runtime-bootstrapping";
const ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_STARTED_AT: &str =
    "openshell.ai/sandbox-runtime-bootstrap-started-at-ms";
const ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_OPERATION: &str =
    "openshell.ai/sandbox-runtime-bootstrap-operation";
const ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_PHASE: &str =
    "openshell.ai/sandbox-runtime-bootstrap-phase";
const ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_SESSION: &str =
    "openshell.ai/sandbox-runtime-bootstrap-session";
const ANNOTATION_SANDBOX_RUNTIME_GENERATION: &str = "openshell.ai/sandbox-runtime-generation";
const ANNOTATION_CONFIDENTIAL_BOOTSTRAP_ATTEMPT: &str =
    "openshell.ai/confidential-bootstrap-attempt";

fn immutable_image_reference(image: &str) -> bool {
    let Some((repository, digest)) = image.rsplit_once("@sha256:") else {
        return false;
    };
    !repository.is_empty()
        && digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// The API server omits an empty supplementalGroups list on Pod readback. With
// supplementalGroupsPolicy=Strict, absent and empty both mean no additional
// groups; any non-empty list remains a security violation.
fn strict_without_supplemental_groups(
    security: &k8s_openapi::api::core::v1::PodSecurityContext,
) -> bool {
    security.supplemental_groups_policy.as_deref() == Some("Strict")
        && security
            .supplemental_groups
            .as_deref()
            .is_none_or(<[i64]>::is_empty)
}
const ANNOTATION_SANDBOX_RUNTIME_READINESS: &str = "openshell.ai/sandbox-runtime-readiness";
const ANNOTATION_SANDBOX_RUNTIME_WORKLOAD_UID: &str = "openshell.ai/sandbox-runtime-workload-uid";
const ANNOTATION_SANDBOX_RUNTIME_SUPERVISOR_UID: &str =
    "openshell.ai/sandbox-runtime-supervisor-uid";
const ANNOTATION_SANDBOX_RUNTIME_NETWORK_POLICY_UID: &str =
    "openshell.ai/sandbox-runtime-network-policy-uid";
const ANNOTATION_SANDBOX_RUNTIME_NETWORK_POLICY_GENERATION: &str =
    "openshell.ai/sandbox-runtime-network-policy-generation";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SandboxRuntimeBootstrapPhase {
    Preparing,
    Released,
    Releasing,
    Suspending,
}

impl SandboxRuntimeBootstrapPhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Preparing => "preparing",
            Self::Released => "released",
            Self::Releasing => "releasing",
            Self::Suspending => "suspending",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "preparing" => Some(Self::Preparing),
            "released" => Some(Self::Released),
            "releasing" => Some(Self::Releasing),
            "suspending" => Some(Self::Suspending),
            _ => None,
        }
    }
}

fn boundary_service_authority(
    namespace: &str,
    names: &SandboxRuntimeNames,
    boundary_port: u16,
) -> String {
    format!(
        "{}.{}.svc:{boundary_port}",
        names.boundary_service, namespace
    )
}

#[derive(Debug, thiserror::Error)]
pub enum KubernetesDriverError {
    #[error("sandbox already exists")]
    AlreadyExists,
    #[error("sandbox not found")]
    NotFound,
    #[error("{0}")]
    InvalidArgument(String),
    #[error("{0}")]
    Precondition(String),
    #[error("{0}")]
    Message(String),
}

impl KubernetesDriverError {
    fn from_kube(err: KubeError) -> Self {
        match err {
            KubeError::Api(api) if api.code == 409 && api.reason == "AlreadyExists" => {
                Self::AlreadyExists
            }
            KubeError::Api(api) if api.code == 404 => Self::NotFound,
            other => Self::Message(other.to_string()),
        }
    }
}

/// Read and validate the operator's corporate proxy CA bundle, if configured.
///
/// Returns the PEM bytes to stage into the supervisor bootstrap Secret, or
/// `None` when `proxy_ca_bundle` is unset. Fail-closed: a path that cannot be
/// read, is not a regular file, or holds no usable trust anchor is an error
/// naming the operator setting, never a silent fall-back to the built-in
/// roots.
///
/// The read is bounded twice. The shared reader applies
/// `MAX_UPSTREAM_PROXY_CA_BUNDLE_BYTES`, which is exactly the apiserver's own
/// Secret limit; this driver then applies the tighter
/// [`MAX_STAGED_PROXY_CA_BUNDLE_BYTES`] so a bundle between the two cannot
/// turn into an opaque `data: Too long` apiserver error on every create.
async fn read_staged_upstream_proxy_ca_bundle(
    path: Option<&str>,
) -> Result<Option<Vec<u8>>, KubernetesDriverError> {
    let Some(path) = path.map(str::to_string) else {
        return Ok(None);
    };
    let pem = tokio::task::spawn_blocking(move || {
        openshell_core::driver_utils::read_upstream_proxy_ca_bundle_file(&path, "proxy_ca_bundle")
    })
    .await
    .map_err(|error| {
        KubernetesDriverError::Message(format!("proxy_ca_bundle read task failed: {error}"))
    })?
    .map_err(KubernetesDriverError::InvalidArgument)?;

    if pem.len() > crate::config::MAX_STAGED_PROXY_CA_BUNDLE_BYTES {
        return Err(KubernetesDriverError::InvalidArgument(format!(
            "proxy_ca_bundle is {} bytes, exceeding the {}-byte limit for a bundle staged into a \
             Kubernetes Secret",
            pem.len(),
            crate::config::MAX_STAGED_PROXY_CA_BUNDLE_BYTES
        )));
    }
    Ok(Some(pem.into_bytes()))
}

fn is_kube_resource_version_conflict(error: &KubeError) -> bool {
    matches!(error, KubeError::Api(api) if api.code == 409 && api.reason == "Conflict")
}

async fn patch_dynamic_object_with_uid_retry(
    api: &Api<DynamicObject>,
    name: &str,
    expected_uid: &str,
    mut patch_for_resource_version: impl FnMut(&str) -> serde_json::Value,
) -> Result<DynamicObject, KubernetesDriverError> {
    let operation = async {
        loop {
            let current = api
                .get(name)
                .await
                .map_err(KubernetesDriverError::from_kube)?;
            if current.metadata.uid.as_deref() != Some(expected_uid) {
                return Err(KubernetesDriverError::Precondition(
                    "Sandbox CR UID changed during lifecycle operation".to_string(),
                ));
            }
            let version = current
                .metadata
                .resource_version
                .as_deref()
                .ok_or_else(|| {
                    KubernetesDriverError::Precondition(
                        "Sandbox CR lacks resourceVersion".to_string(),
                    )
                })?;
            let patch = patch_for_resource_version(version);
            match api
                .patch(name, &PatchParams::default(), &Patch::Merge(&patch))
                .await
            {
                Ok(updated) if updated.metadata.uid.as_deref() == Some(expected_uid) => {
                    return Ok(updated);
                }
                Ok(_) => {
                    return Err(KubernetesDriverError::Precondition(
                        "Sandbox CR UID changed during lifecycle patch".to_string(),
                    ));
                }
                Err(error) if is_kube_resource_version_conflict(&error) => {
                    tokio::task::yield_now().await;
                }
                Err(error) => return Err(KubernetesDriverError::from_kube(error)),
            }
        }
    };
    tokio::time::timeout(KUBE_API_TIMEOUT, operation)
        .await
        .map_err(|_| {
            KubernetesDriverError::Message(format!(
                "timed out after {}s updating Kubernetes resource {name}",
                KUBE_API_TIMEOUT.as_secs()
            ))
        })?
}

impl From<KubernetesDriverError> for openshell_core::ComputeDriverError {
    fn from(err: KubernetesDriverError) -> Self {
        match err {
            KubernetesDriverError::AlreadyExists => Self::AlreadyExists,
            KubernetesDriverError::NotFound => Self::NotFound,
            KubernetesDriverError::InvalidArgument(m) => Self::InvalidArgument(m),
            KubernetesDriverError::Precondition(m) => Self::Precondition(m),
            KubernetesDriverError::Message(m) => Self::Message(m),
        }
    }
}

/// Timeout for individual Kubernetes API calls (create, delete, get).
/// This prevents gRPC handlers from blocking indefinitely when the k8s
/// API server is unreachable or slow.
const KUBE_API_TIMEOUT: Duration = Duration::from_secs(30);
const OPENSHIFT_SCC_ALLOCATOR_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// A controller may update Sandbox status between our GET and UID-guarded DELETE.
/// Bound retries so a constantly changing or independently modified CR stays fenced.
const SANDBOX_DELETE_CONFLICT_RETRIES: usize = 3;
fn admission_error(error: tonic::Status) -> KubernetesDriverError {
    match error.code() {
        tonic::Code::InvalidArgument => {
            KubernetesDriverError::InvalidArgument(error.message().into())
        }
        tonic::Code::FailedPrecondition => {
            KubernetesDriverError::Precondition(error.message().into())
        }
        _ => KubernetesDriverError::Message(error.message().into()),
    }
}
const SANDBOX_RUNTIME_RECONCILE_INTERVAL: Duration = Duration::from_secs(30);
const ATTESTATION_REPORT_PUBLISH_INTERVAL: Duration = Duration::from_secs(5);
/// Bound how long a crash-interrupted, fail-closed bootstrap may remain stranded.
const SANDBOX_RUNTIME_BOOTSTRAP_GRACE: Duration = Duration::from_mins(5);

fn random_sandbox_runtime_token() -> String {
    use std::fmt::Write as _;

    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let mut token = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(token, "{byte:02x}").expect("writing to String cannot fail");
    }
    token
}

fn decode_launch_authentication(
    encoded: &[u8],
) -> Result<openshell_core::jwt::SandboxLaunchAuthentication, KubernetesDriverError> {
    let authentication =
        serde_json::from_slice::<openshell_core::jwt::SandboxLaunchAuthentication>(encoded)
            .map_err(|error| {
                KubernetesDriverError::Precondition(format!(
                    "decode Kubernetes sandbox launch authentication: {error}"
                ))
            })?;
    authentication.validate().map_err(|error| {
        KubernetesDriverError::Precondition(format!(
            "validate Kubernetes sandbox launch authentication: {error}"
        ))
    })?;
    Ok(authentication)
}

fn gateway_verification_keys(
    keys: &[openshell_core::jwt::SessionVerificationKey],
) -> Result<Vec<GatewayVerificationKey>, KubernetesDriverError> {
    keys.iter()
        .map(|key| {
            String::from_utf8(key.public_key_pem.clone())
                .map(|public_key_pem| GatewayVerificationKey {
                    key_id: key.key_id.clone(),
                    public_key_pem,
                })
                .map_err(|error| {
                    KubernetesDriverError::Precondition(format!(
                        "Kubernetes sandbox verification key is not UTF-8 PEM: {error}"
                    ))
                })
        })
        .collect()
}

/// Kubernetes defaults pod termination to 30 seconds when the pod template
/// omits `terminationGracePeriodSeconds`.
const DEFAULT_POD_TERMINATION_GRACE_PERIOD: Duration = Duration::from_secs(30);
const STOP_INITIAL_POLL_INTERVAL: Duration = Duration::from_millis(250);
const STOP_MAX_POLL_INTERVAL: Duration = Duration::from_secs(2);

const SANDBOX_GROUP: &str = "agents.x-k8s.io";
const SANDBOX_VERSION_V1BETA1: &str = "v1beta1";
const SANDBOX_VERSION_V1ALPHA1: &str = "v1alpha1";
const SANDBOX_VERSIONS: &[&str] = &[SANDBOX_VERSION_V1BETA1, SANDBOX_VERSION_V1ALPHA1];
pub const SANDBOX_KIND: &str = "Sandbox";
const SANDBOX_POD_NAME_ANNOTATION: &str = "agents.x-k8s.io/pod-name";
const SANDBOX_SUSPENDED_CONDITION: &str = "Suspended";
const SANDBOX_SUSPENDED_POD_NOT_OWNED_REASON: &str = "PodNotOwned";

const GPU_RESOURCE_NAME: &str = "nvidia.com/gpu";
const SPIFFE_WORKLOAD_API_VOLUME_NAME: &str = "spiffe-workload-api";

struct AgentSandboxApi {
    api: Api<DynamicObject>,
    resource: ApiResource,
}

// This POC treats the selected Struct as a driver-local typed schema. Once the
// Kubernetes shape stabilizes, these serde structs may move to driver-local
// protobuf definitions, but the typed decode should stay inside this driver.
// Do not promote Kubernetes config messages into the public API or gateway
// translation layer; the RFC boundary is Struct at the gateway, typed config in
// the selected driver.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct KubernetesSandboxDriverConfig {
    pod: KubernetesPodDriverConfig,
    containers: KubernetesDriverContainersConfig,
    volumes: Vec<KubernetesDriverVolumeConfig>,
}

impl KubernetesSandboxDriverConfig {
    fn from_template(template: &SandboxTemplate) -> Result<Self, String> {
        let Some(config) = template.driver_config.as_ref() else {
            return Ok(Self::default());
        };

        let json = serde_json::Value::Object(struct_to_json_object(config));
        let config: Self = serde_json::from_value(json)
            .map_err(|err| format!("invalid kubernetes driver_config: {err}"))?;
        config
            .validate()
            .map_err(|err| format!("invalid kubernetes driver_config: {err}"))?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        validate_kubernetes_driver_volumes(&self.volumes)?;
        validate_kubernetes_driver_volume_mounts(
            &self.volumes,
            &self.containers.agent.volume_mounts,
        )
    }

    fn has_explicit_sandbox_data_mount(&self) -> bool {
        self.containers.agent.volume_mounts.iter().any(|mount| {
            driver_mounts::path_is_or_under(
                Path::new(&mount.mount_path),
                Path::new(WORKSPACE_MOUNT_PATH),
            )
        })
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct KubernetesPodDriverConfig {
    node_selector: BTreeMap<String, String>,
    runtime_class_name: String,
    tolerations: Vec<serde_json::Value>,
    priority_class_name: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct KubernetesDriverContainersConfig {
    agent: KubernetesContainerDriverConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct KubernetesContainerDriverConfig {
    resources: KubernetesContainerResourceConfig,
    volume_mounts: Vec<KubernetesDriverVolumeMountConfig>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct KubernetesContainerResourceConfig {
    requests: BTreeMap<String, String>,
    limits: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct KubernetesDriverVolumeConfig {
    name: String,
    persistent_volume_claim: KubernetesPersistentVolumeClaimConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct KubernetesPersistentVolumeClaimConfig {
    claim_name: String,
    read_only: bool,
}

impl Default for KubernetesPersistentVolumeClaimConfig {
    fn default() -> Self {
        Self {
            claim_name: String::new(),
            read_only: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct KubernetesDriverVolumeMountConfig {
    name: String,
    mount_path: String,
    sub_path: Option<String>,
    read_only: bool,
}

impl Default for KubernetesDriverVolumeMountConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            mount_path: String::new(),
            sub_path: None,
            read_only: true,
        }
    }
}

impl From<&KubernetesDriverVolumeConfig> for Volume {
    fn from(volume: &KubernetesDriverVolumeConfig) -> Self {
        Self {
            name: volume.name.clone(),
            persistent_volume_claim: Some(PersistentVolumeClaimVolumeSource {
                claim_name: volume.persistent_volume_claim.claim_name.clone(),
                read_only: Some(volume.persistent_volume_claim.read_only),
            }),
            ..Default::default()
        }
    }
}

impl From<&KubernetesDriverVolumeMountConfig> for VolumeMount {
    fn from(mount: &KubernetesDriverVolumeMountConfig) -> Self {
        Self {
            name: mount.name.clone(),
            mount_path: mount.mount_path.clone(),
            read_only: Some(mount.read_only),
            sub_path: mount.sub_path.clone(),
            ..Default::default()
        }
    }
}

const CLIENT_TLS_VOLUME_NAME: &str = "openshell-client-tls";
const UPSTREAM_PROXY_AUTH_VOLUME_NAME: &str = "openshell-upstream-proxy-auth";
const SERVICE_ACCOUNT_TOKEN_VOLUME_NAME: &str = "openshell-sa-token";
const SERVICE_ACCOUNT_TOKEN_MOUNT_PATH: &str = "/var/run/secrets/openshell";

const KUBERNETES_DRIVER_RESERVED_VOLUME_NAMES: &[&str] = &[
    CLIENT_TLS_VOLUME_NAME,
    UPSTREAM_PROXY_AUTH_VOLUME_NAME,
    SERVICE_ACCOUNT_TOKEN_VOLUME_NAME,
    SPIFFE_WORKLOAD_API_VOLUME_NAME,
    SANDBOX_RUNTIME_VOLUME_NAME,
    SANDBOX_STATE_VOLUME_NAME,
    SANDBOX_BOOTSTRAP_VOLUME_NAME,
    SANDBOX_POD_IDENTITY_VOLUME_NAME,
    SANDBOX_PROXY_CA_VOLUME_NAME,
    WORKSPACE_VOLUME_NAME,
];

const KUBERNETES_DRIVER_PROTECTED_MOUNT_PATHS: &[&str] = &[SERVICE_ACCOUNT_TOKEN_MOUNT_PATH];

fn validate_kubernetes_driver_volumes(
    volumes: &[KubernetesDriverVolumeConfig],
) -> Result<(), String> {
    let mut names = HashSet::new();
    for volume in volumes {
        validate_kubernetes_dns1123_label(&volume.name, "volumes[].name")?;
        let name = volume.name.as_str();
        if KUBERNETES_DRIVER_RESERVED_VOLUME_NAMES.contains(&name) {
            return Err(format!(
                "volume name '{name}' is reserved for OpenShell-managed volumes"
            ));
        }
        if !names.insert(name) {
            return Err(format!(
                "duplicate kubernetes driver_config volume '{name}'"
            ));
        }
        validate_kubernetes_dns1123_subdomain(
            &volume.persistent_volume_claim.claim_name,
            "volumes[].persistent_volume_claim.claim_name",
        )?;
    }
    Ok(())
}

fn validate_kubernetes_driver_volume_mounts(
    volumes: &[KubernetesDriverVolumeConfig],
    volume_mounts: &[KubernetesDriverVolumeMountConfig],
) -> Result<(), String> {
    let mut volume_read_only = BTreeMap::new();
    for volume in volumes {
        volume_read_only.insert(
            volume.name.as_str(),
            volume.persistent_volume_claim.read_only,
        );
    }

    let mut mount_paths = HashSet::new();
    for mount in volume_mounts {
        validate_kubernetes_dns1123_label(&mount.name, "containers.agent.volume_mounts[].name")?;
        let volume_name = mount.name.as_str();
        let Some(volume_is_read_only) = volume_read_only.get(volume_name) else {
            return Err(format!(
                "volume mount references unknown kubernetes driver_config volume '{volume_name}'"
            ));
        };
        if *volume_is_read_only && !mount.read_only {
            return Err(format!(
                "volume mount '{volume_name}' cannot set read_only=false because the PVC volume is read_only=true"
            ));
        }

        driver_mounts::validate_container_mount_target(&mount.mount_path)?;
        driver_mounts::validate_workspace_mount_target(
            &mount.mount_path,
            driver_mounts::DEFAULT_WORKSPACE_ROOT,
        )?;
        let normalized_mount_path = driver_mounts::normalize_mount_target(&mount.mount_path);
        if !mount_paths.insert(normalized_mount_path.clone()) {
            return Err(format!(
                "duplicate kubernetes driver_config mount target '{normalized_mount_path}'"
            ));
        }

        if let Some(sub_path) = mount.sub_path.as_ref() {
            driver_mounts::validate_mount_subpath(sub_path)?;
        }
    }
    Ok(())
}

// TODO: replace with an openshell_core Kubernetes-name helper once available.
fn is_dns_subdomain(value: &str) -> bool {
    value.len() <= 253 && value.split('.').all(is_dns_1123_label)
}

fn validate_kubernetes_dns1123_label(value: &str, field: &str) -> Result<(), String> {
    if !is_dns_1123_label(value) {
        return Err(format!(
            "{field} must be a DNS-1123 label: use lowercase alphanumeric characters or '-', start and end with an alphanumeric character, and use at most 63 characters"
        ));
    }
    Ok(())
}

fn validate_kubernetes_dns1123_subdomain(value: &str, field: &str) -> Result<(), String> {
    if !is_dns_subdomain(value) {
        return Err(format!(
            "{field} must be a DNS-1123 subdomain: use lowercase alphanumeric characters, '-' or '.', start and end with an alphanumeric character, and use at most 253 characters"
        ));
    }
    Ok(())
}

fn mount_path_conflicts_with_protected_path(mount_path: &str, protected_path: &str) -> bool {
    driver_mounts::path_is_or_under(Path::new(mount_path), Path::new(protected_path))
        || driver_mounts::path_is_or_under(Path::new(protected_path), Path::new(mount_path))
}

fn validate_kubernetes_protected_path_conflicts(
    volume_mounts: &[KubernetesDriverVolumeMountConfig],
    protected_paths: &[&str],
) -> Result<(), String> {
    for mount in volume_mounts {
        let mount_path = mount.mount_path.as_str();
        for protected_path in protected_paths {
            if mount_path_conflicts_with_protected_path(mount_path, protected_path) {
                return Err(format!(
                    "mount path '{mount_path}' conflicts with reserved OpenShell path '{protected_path}'"
                ));
            }
        }
    }
    Ok(())
}

fn kubernetes_driver_volume_to_k8s(volume: &KubernetesDriverVolumeConfig) -> serde_json::Value {
    serde_json::to_value(Volume::from(volume)).expect("Volume serializes to JSON")
}

fn kubernetes_driver_volume_mount_to_k8s(
    mount: &KubernetesDriverVolumeMountConfig,
) -> serde_json::Value {
    serde_json::to_value(VolumeMount::from(mount)).expect("VolumeMount serializes to JSON")
}

// ---------------------------------------------------------------------------
// Default workspace persistence (temporary — will be replaced by snapshotting)
// ---------------------------------------------------------------------------
// Every sandbox pod gets a PVC-backed `/sandbox` directory so that user data
// (installed packages, files, dotfiles) survives pod rescheduling across
// gateway stop/start cycles.  An init container seeds the PVC with the
// image's original `/sandbox` contents on first use so that the Python venv,
// skills, and shell config are not lost when the empty PVC is mounted.
//
// NOTE: This PVC + init-container approach is a stopgap.  It has known
// limitations: image upgrades don't propagate into existing PVCs, the init
// copy adds first-start latency, and the full /sandbox directory is
// duplicated on disk.  The plan is to replace this with proper container
// snapshotting so that only the diff from the base image is persisted.

/// Volume name used for the workspace PVC in the pod spec.
const WORKSPACE_VOLUME_NAME: &str = "workspace";

/// Mount path for the workspace PVC in the **agent** container.  This shadows
/// the image's `/sandbox` directory — the init container copies the image
/// contents into the PVC before the agent starts.
const WORKSPACE_MOUNT_PATH: &str = "/sandbox";

/// Mount path for the workspace PVC in the **init** container.  A temporary
/// path so the init container can see the image's original `/sandbox` and
/// copy it into the PVC.
const WORKSPACE_INIT_MOUNT_PATH: &str = "/mnt/openshell-workspace";

/// Name of the init container that seeds the workspace PVC.
const WORKSPACE_INIT_CONTAINER_NAME: &str = "workspace-init";

/// Sentinel file written by the init container after copying the image's
/// `/sandbox` contents.  Subsequent pod starts skip the copy.
const WORKSPACE_SENTINEL: &str = ".workspace-initialized";

#[derive(Clone)]
pub struct KubernetesComputeDriver {
    client: Client,
    watch_client: Client,
    sandbox_api_version: Arc<OnceCell<&'static str>>,
    config: KubernetesComputeConfig,
    operator_allowlist: Option<OperatorNamespaceAllowlist>,
    confidential: Option<Arc<ConfidentialProfile>>,
    lifecycle_gates: Arc<LifecycleGates>,
}

pub struct ConfidentialDriverSettings {
    pub bootstrap_timeout: Duration,
    pub initdata_base: PathBuf,
    pub client_tls_ca: PathBuf,
    pub policy_generator: PathBuf,
    pub policy_tools_dir: PathBuf,
    pub policy_registry: String,
    pub policy_registry_ca: PathBuf,
    pub policy_pause_image: String,
    pub bootstrap_store_dir: PathBuf,
    pub bootstrap_signing_key: PathBuf,
    pub kbs_policy_renderer: PathBuf,
    pub kbs_policy_output: PathBuf,
    pub as_policy_output: PathBuf,
    pub trustee_config: PathBuf,
    pub attestation_reports: bool,
}

/// Use the gateway's native TLS endpoint; its CA and scoped launch JWT are sealed.
fn validate_confidential_gateway_endpoint(endpoint: &str) -> Result<(), KubernetesDriverError> {
    let uri = endpoint.parse::<tonic::transport::Uri>().map_err(|_| {
        KubernetesDriverError::Precondition(
            "confidential gateway endpoint must be an HTTPS URI".to_string(),
        )
    })?;
    if uri.scheme_str() != Some("https")
        || uri.host().is_none()
        || uri.path() != "/"
        || uri.query().is_some()
        || uri.authority().is_some_and(|a| a.as_str().contains('@'))
        || uri.host().is_some_and(|host| {
            host == "localhost"
                || host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified())
        })
    {
        return Err(KubernetesDriverError::Precondition(
            "confidential gateway endpoint requires a direct HTTPS gateway host".to_string(),
        ));
    }
    Ok(())
}

struct ConfidentialProfile {
    reports: Option<Arc<crate::attestation::Reports>>,
    bootstrap_timeout: Duration,
    store: BootstrapStore,
    initdata: GuestInitdata,
    client_tls: TrustedClientTlsPaths,
    policy_generator: PathBuf,
    policy_tools_dir: PathBuf,
    policy_registry: String,
    policy_registry_ca: PathBuf,
    policy_pause_image: String,
}

struct TrustedClientTlsPaths {
    ca: PathBuf,
}

impl TrustedClientTlsPaths {
    fn read(&self) -> Result<ClientTlsMaterial, KubernetesDriverError> {
        fn read_ca(path: &Path) -> Result<Vec<u8>, KubernetesDriverError> {
            use std::io::Read as _;
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
            const O_NOFOLLOW: i32 = 0o400_000;
            if !path.is_absolute() {
                return Err(KubernetesDriverError::Precondition(format!(
                    "trusted gateway CA path must be absolute: {}",
                    path.display()
                )));
            }
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(O_NOFOLLOW)
                .open(path)
                .map_err(|error| {
                    KubernetesDriverError::Precondition(format!(
                        "open trusted gateway CA file {} without following symlinks: {error}",
                        path.display()
                    ))
                })?;
            let metadata = file.metadata().map_err(|error| {
                KubernetesDriverError::Precondition(format!(
                    "inspect trusted gateway CA file {}: {error}",
                    path.display()
                ))
            })?;
            if !metadata.file_type().is_file()
                || metadata.nlink() != 1
                || metadata.permissions().mode() & 0o022 != 0
            {
                return Err(KubernetesDriverError::Precondition(format!(
                    "trusted gateway CA file {} must be a single-link regular file without group or other write permission",
                    path.display()
                )));
            }
            let mut bytes = Vec::new();
            file.take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| {
                    KubernetesDriverError::Precondition(format!(
                        "read trusted gateway CA file {}: {error}",
                        path.display()
                    ))
                })?;
            if bytes.is_empty() || bytes.len() > 1024 * 1024 || !bytes.starts_with(b"-----BEGIN ") {
                return Err(KubernetesDriverError::Precondition(format!(
                    "trusted gateway CA file {} must contain a bounded PEM document",
                    path.display()
                )));
            }
            Ok(bytes)
        }
        Ok(ClientTlsMaterial {
            ca_certificate: read_ca(&self.ca)?,
        })
    }
}

impl std::fmt::Debug for KubernetesComputeDriver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubernetesComputeDriver")
            .field("namespace", &self.config.namespace)
            .field("default_image", &self.config.default_image)
            .field("grpc_endpoint", &self.config.grpc_endpoint)
            .finish()
    }
}

impl KubernetesComputeDriver {
    fn supervisor_tracing_environment(&self) -> Vec<(&'static str, String)> {
        let Some(endpoint) = self.config.supervisor_otlp_endpoint.as_deref() else {
            return Vec::new();
        };
        let mut environment = vec![(
            openshell_core::sandbox_env::OTLP_ENDPOINT,
            endpoint.to_string(),
        )];
        environment.extend(openshell_otel::current_trace_context_environment());
        environment
    }

    async fn wait_for_openshift_scc_annotations(
        &self,
        ns_api: &Api<Namespace>,
        namespace: &str,
        mut current: Namespace,
    ) -> Result<(), KubernetesDriverError> {
        let operation = async {
            loop {
                let annotations = current.metadata.annotations.unwrap_or_default();
                if [
                    crate::config::ANNOTATION_SCC_MCS,
                    crate::config::ANNOTATION_SCC_UID_RANGE,
                    crate::config::ANNOTATION_SCC_SUPPLEMENTAL_GROUPS,
                ]
                .into_iter()
                .all(|key| {
                    annotations
                        .get(key)
                        .is_some_and(|value| !value.trim().is_empty())
                }) {
                    return Ok(());
                }

                let has_uid_range = annotations
                    .get(crate::config::ANNOTATION_SCC_UID_RANGE)
                    .is_some_and(|value| !value.trim().is_empty());
                let has_mcs = annotations
                    .get(crate::config::ANNOTATION_SCC_MCS)
                    .is_some_and(|value| !value.trim().is_empty());
                if has_uid_range && !has_mcs {
                    return Err(KubernetesDriverError::Precondition(format!(
                        "managed namespace {namespace} has an OpenShift UID range but no MCS annotation; the SCC allocator skips namespaces with an existing UID range, so delete and recreate this workspace namespace"
                    )));
                }

                tokio::time::sleep(OPENSHIFT_SCC_ALLOCATOR_POLL_INTERVAL).await;
                current = match ns_api.get(namespace).await {
                    Ok(namespace) => namespace,
                    Err(KubeError::Api(api)) if api.code == 404 => {
                        return Err(KubernetesDriverError::Message(format!(
                            "managed namespace {namespace} disappeared while waiting for OpenShift SCC allocator annotations"
                        )));
                    }
                    Err(error) => return Err(KubernetesDriverError::from_kube(error)),
                };
            }
        };
        tokio::time::timeout(KUBE_API_TIMEOUT, operation)
            .await
            .map_err(|_| {
                KubernetesDriverError::Message(format!(
                    "timed out waiting for OpenShift SCC allocator annotations on managed namespace {namespace}"
                ))
            })?
    }

    fn lifecycle_lock(&self, sandbox_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.lifecycle_gates.gate_for(sandbox_id)
    }
    fn supervisor_client_tls(&self) -> SupervisorClientTls<'_> {
        if self.confidential.is_some() {
            SupervisorClientTls::Bootstrap
        } else {
            self.config.supervisor_client_tls()
        }
    }

    fn confidential_profile(&self) -> Result<&ConfidentialProfile, KubernetesDriverError> {
        self.confidential.as_deref().ok_or_else(|| {
            KubernetesDriverError::Precondition(
                "confidential bootstrap profile is unavailable".to_string(),
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn render_confidential_initdata(
        &self,
        role: BootstrapRole,
        generation: &str,
        sandbox_id: &str,
        sandbox_resource_uid: &str,
        attempt: &str,
        namespace: &str,
        keys: &[&str],
        workspace_key_uri: Option<&str>,
        generated_policy: Option<&str>,
    ) -> Result<crate::confidential::RenderedInitdata, KubernetesDriverError> {
        let profile = self.confidential_profile()?;
        profile
            .initdata
            .render(
                &profile.store,
                role,
                generation,
                sandbox_id,
                sandbox_resource_uid,
                attempt,
                namespace,
                keys,
                workspace_key_uri,
                generated_policy,
            )
            .map_err(KubernetesDriverError::Precondition)
    }

    #[allow(clippy::too_many_arguments)]
    async fn generate_and_patch_initdata(
        &self,
        pods: &Api<Pod>,
        pod: &Pod,
        expected_pod: &Pod,
        role: BootstrapRole,
        generation: &str,
        sandbox_id: &str,
        cr_uid: &str,
        attempt: &str,
        namespace: &str,
        keys: &[&str],
        workspace_key_uri: Option<&str>,
    ) -> Result<crate::confidential::RenderedInitdata, KubernetesDriverError> {
        use tokio::io::AsyncWriteExt as _;
        Self::validate_actual_pod_image_refs(pod)?;
        if role == BootstrapRole::Supervisor {
            self.validate_confidential_supervisor_pod(pod, cr_uid, sandbox_id)?;
        } else if !workload_environment_is_private(pod) {
            return Err(KubernetesDriverError::Precondition(
                "workload Pod must receive user environment only through sealed bootstrap"
                    .to_string(),
            ));
        }
        let name = pod.metadata.name.as_deref().ok_or_else(|| {
            KubernetesDriverError::Precondition("gated Pod lacks name".to_string())
        })?;
        let uid = pod.metadata.uid.as_deref().ok_or_else(|| {
            KubernetesDriverError::Precondition("gated Pod lacks UID".to_string())
        })?;
        let version = pod.metadata.resource_version.as_deref().ok_or_else(|| {
            KubernetesDriverError::Precondition("gated Pod lacks resourceVersion".to_string())
        })?;
        if pod
            .spec
            .as_ref()
            .is_none_or(|spec| spec.scheduling_gates.as_deref().is_none_or(<[_]>::is_empty))
        {
            return Err(KubernetesDriverError::Precondition(
                "Kata policy generation requires a gated Pod".to_string(),
            ));
        }
        let profile = self.confidential_profile()?;
        let mut policy_pod = expected_pod.clone();
        policy_pod
            .metadata
            .annotations
            .get_or_insert_with(BTreeMap::new)
            .insert(INITDATA_ANNOTATION.to_string(), String::new());
        policy_pod.status = None;
        let input = serde_json::to_vec(&serde_json::json!({
            "expected": policy_pod, "admitted": pod,
        }))
        .map_err(|error| {
            KubernetesDriverError::Message(format!(
                "serialize trusted and admitted Pods for Kata policy: {error}"
            ))
        })?;
        let mut child = tokio::process::Command::new("python3")
            .arg(&profile.policy_generator)
            .arg("--role")
            .arg(role.as_str())
            .arg("--tools-dir")
            .arg(&profile.policy_tools_dir)
            .arg("--registry")
            .arg(&profile.policy_registry)
            .arg("--registry-ca")
            .arg(&profile.policy_registry_ca)
            .arg("--pause-image")
            .arg(&profile.policy_pause_image)
            .arg("--runtime-class")
            .arg(&self.config.default_runtime_class_name)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| {
                KubernetesDriverError::Precondition(format!(
                    "start trusted Kata policy generator: {error}"
                ))
            })?;
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(&input)
            .await
            .map_err(|error| {
                KubernetesDriverError::Message(format!(
                    "write gated Pod to Kata policy generator: {error}"
                ))
            })?;
        let output = tokio::time::timeout(Duration::from_secs(330), child.wait_with_output())
            .await
            .map_err(|_| {
                KubernetesDriverError::Precondition("Kata policy generation timed out".to_string())
            })?
            .map_err(|error| {
                KubernetesDriverError::Message(format!("read Kata policy generator: {error}"))
            })?;
        if !output.status.success() {
            return Err(KubernetesDriverError::Precondition(format!(
                "Kata policy generation failed: {}",
                String::from_utf8_lossy(&output.stderr)
                    .chars()
                    .take(4096)
                    .collect::<String>()
            )));
        }
        let policy = String::from_utf8(output.stdout).map_err(|error| {
            KubernetesDriverError::Precondition(format!("Kata policy is not UTF-8: {error}"))
        })?;
        let rendered = self.render_confidential_initdata(
            role,
            generation,
            sandbox_id,
            cr_uid,
            attempt,
            namespace,
            keys,
            workspace_key_uri,
            Some(&policy),
        )?;
        let updated = pods
            .patch(
                name,
                &PatchParams::default(),
                &Patch::Merge(
                    &serde_json::json!({"metadata": {"resourceVersion": version, "uid": uid,
                "annotations": {INITDATA_ANNOTATION: rendered.annotation}}}),
                ),
            )
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        if updated.metadata.uid.as_deref() != Some(uid)
            || updated
                .metadata
                .annotations
                .as_ref()
                .and_then(|a| a.get(INITDATA_ANNOTATION))
                != Some(&rendered.annotation)
        {
            return Err(KubernetesDriverError::Precondition(
                "gated Pod identity or measured initdata changed while installing policy"
                    .to_string(),
            ));
        }
        Ok(rendered)
    }

    fn validate_confidential_supervisor_pod(
        &self,
        pod: &Pod,
        cr_uid: &str,
        sandbox_id: &str,
    ) -> Result<(), KubernetesDriverError> {
        let invalid = || {
            KubernetesDriverError::Precondition(
                "admitted supervisor Pod changed confidential image, identity or isolation"
                    .to_string(),
            )
        };
        let spec = pod.spec.as_ref().ok_or_else(invalid)?;
        let labels = pod.metadata.labels.as_ref().ok_or_else(invalid)?;
        if spec.runtime_class_name.as_deref()
            != Some(self.config.default_runtime_class_name.as_str())
            || spec.enable_service_links != Some(false)
            || spec.host_network == Some(true)
            || spec.host_pid == Some(true)
            || spec.host_ipc == Some(true)
            || spec.share_process_namespace == Some(true)
            || spec.containers.len() != 1
            || spec
                .init_containers
                .as_deref()
                .is_some_and(|containers| !containers.is_empty())
            || spec
                .volumes
                .as_deref()
                .unwrap_or_default()
                .iter()
                .any(|v| v.host_path.is_some())
            || labels.get(BOUNDARY_ROLE_LABEL).map(String::as_str) != Some("supervisor")
            || labels.get(BOUNDARY_PAIR_LABEL).map(String::as_str)
                != Some(crate::sandbox_runtime::pair_label_value(sandbox_id).as_str())
            || !pod
                .metadata
                .owner_references
                .as_deref()
                .unwrap_or_default()
                .iter()
                .any(|owner| owner.uid == cr_uid)
        {
            return Err(invalid());
        }
        let pod_security = spec.security_context.as_ref().ok_or_else(invalid)?;
        if !strict_without_supplemental_groups(pod_security) {
            return Err(invalid());
        }
        let container = &spec.containers[0];
        let context = container.security_context.as_ref().ok_or_else(invalid)?;
        if container.name != "supervisor"
            || container.image.as_deref() != Some(self.config.supervisor_image.as_str())
            || container
                .command
                .as_deref()
                .is_none_or(|cmd| cmd.first().map(String::as_str) != Some("/openshell-supervisor"))
            || context.privileged == Some(true)
            || context.allow_privilege_escalation != Some(false)
            || context.read_only_root_filesystem != Some(true)
            || context.run_as_non_root != Some(true)
            || context
                .capabilities
                .as_ref()
                .and_then(|caps| caps.drop.as_deref())
                .is_none_or(|caps| !caps.iter().any(|cap| cap == "ALL"))
            || container
                .volume_mounts
                .as_deref()
                .unwrap_or_default()
                .iter()
                .filter(|mount| mount.mount_path == "/.openshell/supervisor")
                .count()
                != 1
            || !container
                .volume_mounts
                .as_deref()
                .unwrap_or_default()
                .iter()
                .any(|mount| {
                    mount.name == "bootstrap"
                        && mount.mount_path == "/.openshell/supervisor"
                        && mount.read_only == Some(true)
                })
        {
            return Err(invalid());
        }
        Ok(())
    }

    async fn verify_measured_pod_before_release(
        pods: &Api<Pod>,
        name: &str,
        expected_uid: &str,
        expected_initdata: &str,
        expected_pod: &Pod,
    ) -> Result<String, KubernetesDriverError> {
        let current = pods
            .get(name)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        if current.metadata.uid.as_deref() != Some(expected_uid)
            || current.spec != expected_pod.spec
            || current.metadata.labels != expected_pod.metadata.labels
            || current.metadata.owner_references != expected_pod.metadata.owner_references
            || current
                .metadata
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.get(INITDATA_ANNOTATION))
                .is_none_or(|value| value != expected_initdata)
            || current
                .spec
                .as_ref()
                .is_none_or(|spec| spec.scheduling_gates.as_deref().is_none_or(<[_]>::is_empty))
        {
            return Err(KubernetesDriverError::Precondition(format!(
                "measured initdata, Pod UID, or scheduling gate changed before releasing {name}"
            )));
        }
        current.metadata.resource_version.ok_or_else(|| {
            KubernetesDriverError::Precondition(format!(
                "measured Pod {name} has no resourceVersion before gate release"
            ))
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn seal_bootstrap_secret(
        &self,
        secret: &mut Secret,
        role: BootstrapRole,
        generation: &str,
        sandbox_id: &str,
        sandbox_cr_uid: &str,
        attempt: &str,
        initdata_digest: &str,
        expected_keys: &[&str],
    ) -> Result<(), KubernetesDriverError> {
        let data = secret.data.as_mut().ok_or_else(|| {
            KubernetesDriverError::Precondition("bootstrap Secret has no data".to_string())
        })?;
        if data
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>()
            != expected_keys
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
        {
            return Err(KubernetesDriverError::Precondition(
                "bootstrap Secret keys differ from measured descriptor manifest".to_string(),
            ));
        }
        let profile = self.confidential_profile()?;
        for (key, bytes) in data.iter_mut() {
            let published = profile
                .store
                .publish_file(
                    role,
                    generation,
                    sandbox_id,
                    sandbox_cr_uid,
                    attempt,
                    key,
                    &bytes.0,
                    initdata_digest,
                )
                .map_err(|error| {
                    KubernetesDriverError::Message(format!(
                        "publish confidential bootstrap {key}: {error}"
                    ))
                })?;
            bytes.0 = published.sealed_descriptor.into_bytes();
        }
        Ok(())
    }

    async fn record_workspace_volumes(
        &self,
        sandbox_id: &str,
        namespace: &str,
        cr_uid: &str,
        pod: &Pod,
        require_pvc: bool,
    ) -> Result<(), KubernetesDriverError> {
        let volumes = pod
            .spec
            .as_ref()
            .and_then(|spec| spec.volumes.as_ref())
            .ok_or_else(|| {
                KubernetesDriverError::Precondition(
                    "confidential workload Pod has no volumes".to_string(),
                )
            })?;
        let claims: Vec<&str> = volumes
            .iter()
            .filter_map(|volume| volume.persistent_volume_claim.as_ref())
            .map(|claim| claim.claim_name.as_str())
            .collect();
        if claims.is_empty() && require_pvc {
            return Err(KubernetesDriverError::Precondition(
                "confidential workspace requires a PVC-backed volume".to_string(),
            ));
        }
        if !claims.is_empty() && !require_pvc {
            return Err(KubernetesDriverError::Precondition(
                "ephemeral confidential workspace unexpectedly has a PVC".to_string(),
            ));
        }
        let claims_api: Api<PersistentVolumeClaim> =
            Api::namespaced(self.client.clone(), namespace);
        let volumes_api: Api<PersistentVolume> = Api::all(self.client.clone());
        let profile = self.confidential_profile()?;
        profile
            .store
            .record_workspace_owner(sandbox_id, namespace, cr_uid)
            .map_err(|error| {
                KubernetesDriverError::Precondition(format!(
                    "record confidential sandbox owner: {error}"
                ))
            })?;
        for claim_name in claims {
            // Record ownership before waiting for controller provisioning. The
            // final measured document must name each actual retained cloud disk.
            profile
                .store
                .record_workspace_volume(namespace, cr_uid, claim_name, None, None)
                .map_err(|error| {
                    KubernetesDriverError::Precondition(format!(
                        "record workspace PVC {claim_name}: {error}"
                    ))
                })?;
            let bound = tokio::time::timeout(Duration::from_secs(300), async {
                loop {
                    let pvc = claims_api
                        .get(claim_name)
                        .await
                        .map_err(KubernetesDriverError::from_kube)?;
                    let pvc_uid = pvc.metadata.uid.as_deref().filter(|uid| !uid.is_empty())
                        .ok_or_else(|| KubernetesDriverError::Precondition(format!(
                            "workspace PVC {claim_name} is missing its immutable UID"
                        )))?;
                    if let Some(pv_name) = pvc
                        .spec
                        .as_ref()
                        .and_then(|spec| spec.volume_name.as_deref())
                    {
                        let pv = volumes_api
                            .get(pv_name)
                            .await
                            .map_err(KubernetesDriverError::from_kube)?;
                        let pv_spec = pv.spec.as_ref();
                        let claim_ref = pv_spec.and_then(|spec| spec.claim_ref.as_ref());
                        if !claim_ref.is_some_and(|claim| {
                            claim.uid.as_deref() == Some(pvc_uid)
                                && claim.namespace.as_deref() == Some(namespace)
                                && claim.name.as_deref() == Some(claim_name)
                        }) {
                            return Err(KubernetesDriverError::Precondition(format!(
                                "workspace PV {pv_name} does not bind the exact PVC {namespace}/{claim_name} UID"
                            )));
                        }
                        if let (Some(pv_uid), Some(disk_id)) = (
                            pv.metadata.uid.filter(|uid| !uid.is_empty()),
                            pv_spec
                                .and_then(|spec| spec.csi.as_ref())
                                .and_then(|csi| csi.volume_attributes.as_ref())
                                .and_then(|attributes| attributes.get("cloud-volume-path"))
                                .filter(|disk_id| !disk_id.is_empty())
                                .cloned(),
                        ) {
                            return Ok::<_, KubernetesDriverError>((pv_uid, disk_id));
                        }
                    }
                    tokio::time::sleep(STOP_INITIAL_POLL_INTERVAL).await;
                }
            })
            .await
            .map_err(|_| {
                KubernetesDriverError::Precondition(format!(
                    "workspace PVC {claim_name} did not bind a cloud disk before bootstrap"
                ))
            })??;
            let (pv_uid, disk_id) = bound;
            profile
                .store
                .record_workspace_volume(
                    namespace,
                    cr_uid,
                    claim_name,
                    Some(&pv_uid),
                    Some(&disk_id),
                )
                .map_err(|error| {
                    KubernetesDriverError::Precondition(format!(
                        "record confidential workspace volume {claim_name}: {error}"
                    ))
                })?;
        }
        Ok(())
    }

    fn validate_confidential_runtime_class_request(
        &self,
        spec: Option<&SandboxSpec>,
    ) -> Result<(), String> {
        let Some(template) = spec.and_then(|spec| spec.template.as_ref()) else {
            return Ok(());
        };
        let requested = platform_config_string(template, "runtime_class_name");
        let driver_config = KubernetesSandboxDriverConfig::from_template(template)?;
        for candidate in [
            requested.as_deref(),
            Some(driver_config.pod.runtime_class_name.as_str()),
        ]
        .into_iter()
        .flatten()
        .filter(|value| !value.is_empty())
        {
            if candidate != self.config.default_runtime_class_name {
                return Err(format!(
                    "runtime_class_name {candidate:?} differs from required confidential RuntimeClass {:?}",
                    self.config.default_runtime_class_name
                ));
            }
        }
        Ok(())
    }

    fn validate_confidential_pod_spec(&self, spec: &serde_json::Value) -> Result<(), String> {
        if spec["runtimeClassName"].as_str()
            != Some(self.config.default_runtime_class_name.as_str())
        {
            return Err("workload Pod lacks the required confidential RuntimeClass".to_string());
        }
        let main = spec["containers"]
            .as_array()
            .filter(|containers| !containers.is_empty())
            .ok_or_else(|| "confidential workload Pod has no containers".to_string())?;
        for (group, containers) in [
            ("containers", main.as_slice()),
            (
                "initContainers",
                spec["initContainers"]
                    .as_array()
                    .map(Vec::as_slice)
                    .unwrap_or_default(),
            ),
        ] {
            for container in containers {
                let image = container["image"].as_str().unwrap_or_default();
                if !immutable_image_reference(image) {
                    return Err(format!(
                        "confidential {group} image must use an immutable sha256 digest reference"
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_actual_pod_image_refs(pod: &Pod) -> Result<(), KubernetesDriverError> {
        let spec = pod.spec.as_ref().ok_or_else(|| {
            KubernetesDriverError::Precondition("confidential Pod has no spec".to_string())
        })?;
        for container in spec
            .containers
            .iter()
            .chain(spec.init_containers.as_deref().unwrap_or_default().iter())
        {
            if !container
                .image
                .as_deref()
                .is_some_and(immutable_image_reference)
            {
                return Err(KubernetesDriverError::Precondition(format!(
                    "admitted confidential Pod container {} lacks immutable sha256 image digest",
                    container.name
                )));
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(config: KubernetesComputeConfig) -> Self {
        let service = tower::service_fn(|_request: http::Request<kube::client::Body>| async {
            Ok::<_, std::convert::Infallible>(http::Response::new(http_body_util::Empty::<
                bytes::Bytes,
            >::new()))
        });
        let client = Client::new(service, "default");
        Self {
            client: client.clone(),
            watch_client: client,
            sandbox_api_version: Arc::new(OnceCell::new()),
            config,
            operator_allowlist: None,
            confidential: None,
            lifecycle_gates: Arc::default(),
        }
    }

    pub async fn new(
        config: KubernetesComputeConfig,
        shutdown_rx: tokio::sync::watch::Receiver<bool>,
        confidential_settings: ConfidentialDriverSettings,
    ) -> Result<Self, KubernetesDriverError> {
        config
            .resource_admission
            .validate()
            .map_err(KubernetesDriverError::Precondition)?;
        config
            .validate_workspace_mode()
            .map_err(KubernetesDriverError::Precondition)?;
        config
            .validate_provider_spiffe_workload_api_socket_path()
            .map_err(KubernetesDriverError::Precondition)?;
        config
            .validate_sandbox_identity_config()
            .map_err(KubernetesDriverError::Precondition)?;
        config
            .validate_proxy_uid()
            .map_err(KubernetesDriverError::Precondition)?;
        config
            .validate_upstream_proxy_config()
            .map_err(KubernetesDriverError::Precondition)?;
        if config.default_runtime_class_name.is_empty() {
            return Err(KubernetesDriverError::Precondition(
                "confidential RuntimeClass is required".to_string(),
            ));
        }
        for (name, image) in [
            ("default sandbox", config.default_image.as_str()),
            ("sandbox runtime", config.sandbox_runtime_image.as_str()),
            ("supervisor", config.supervisor_image.as_str()),
        ] {
            if !immutable_image_reference(image) {
                return Err(KubernetesDriverError::Precondition(format!(
                    "confidential {name} image must use an immutable sha256 digest reference"
                )));
            }
        }
        validate_confidential_gateway_endpoint(&config.grpc_endpoint)?;
        if !config.client_tls_secret_name.is_empty()
            || config.proxy_auth_secret_name.is_some()
            || config.proxy_auth_secret_key.is_some()
            || config.proxy_auth_allow_insecure == Some(true)
        {
            return Err(KubernetesDriverError::Precondition(
                "Kubernetes client TLS and proxy authentication Secrets are not accepted by the confidential driver".to_string(),
            ));
        }
        // Read the bundle once at startup so an unreadable path or a
        // certificate-free file fails the gateway here, rather than as a
        // repeated sandbox-create failure. The authoritative read still
        // happens per sandbox, so rotating the file needs no restart.
        read_staged_upstream_proxy_ca_bundle(config.proxy_ca_bundle.as_deref())
            .await
            .map_err(|error| KubernetesDriverError::Precondition(error.to_string()))?;
        if confidential_settings.bootstrap_timeout.is_zero()
            || confidential_settings.bootstrap_timeout > Duration::from_hours(1)
        {
            return Err(KubernetesDriverError::Precondition(
                "bootstrap timeout must be between 1 and 3600 seconds".to_string(),
            ));
        }
        let client_tls = TrustedClientTlsPaths {
            ca: confidential_settings.client_tls_ca,
        };
        client_tls.read()?;
        for path in [
            &confidential_settings.policy_generator,
            &confidential_settings.policy_tools_dir,
            &confidential_settings.policy_registry_ca,
        ] {
            if !path.is_absolute()
                || std::fs::symlink_metadata(path)
                    .map_err(|error| {
                        KubernetesDriverError::Precondition(format!(
                            "inspect trusted Kata policy path {}: {error}",
                            path.display()
                        ))
                    })?
                    .file_type()
                    .is_symlink()
            {
                return Err(KubernetesDriverError::Precondition(format!(
                    "trusted Kata policy path must be absolute and not a symlink: {}",
                    path.display()
                )));
            }
        }
        if confidential_settings.policy_registry.is_empty() {
            return Err(KubernetesDriverError::Precondition(
                "Kata policy registry must be configured".to_string(),
            ));
        }
        if !immutable_image_reference(&confidential_settings.policy_pause_image) {
            return Err(KubernetesDriverError::Precondition(
                "Kata pause image must be pinned by sha256 digest".to_string(),
            ));
        }
        let confidential = Arc::new(ConfidentialProfile {
            reports: confidential_settings.attestation_reports.then(|| {
                crate::attestation::Reports::new(confidential_settings.trustee_config.clone())
            }),
            bootstrap_timeout: confidential_settings.bootstrap_timeout,
            initdata: GuestInitdata::load(&confidential_settings.initdata_base)
                .and_then(|base| base.with_registry_ca(&confidential_settings.policy_registry_ca))
                .map_err(KubernetesDriverError::Precondition)?,
            client_tls,
            policy_generator: confidential_settings.policy_generator,
            policy_tools_dir: confidential_settings.policy_tools_dir,
            policy_registry: confidential_settings.policy_registry,
            policy_registry_ca: confidential_settings.policy_registry_ca,
            policy_pause_image: confidential_settings.policy_pause_image,
            store: BootstrapStore::open_with_trustee(
                &confidential_settings.bootstrap_store_dir,
                &confidential_settings.bootstrap_signing_key,
                &confidential_settings.kbs_policy_renderer,
                &confidential_settings.kbs_policy_output,
                &confidential_settings.as_policy_output,
                &confidential_settings.trustee_config,
            )
            .map_err(|error| KubernetesDriverError::Precondition(error.to_string()))?,
        });
        let base_config = match kube::Config::incluster() {
            Ok(c) => c,
            Err(_) => kube::Config::infer()
                .await
                .map_err(kube::Error::InferConfig)
                .map_err(KubernetesDriverError::from_kube)?,
        };

        let mut kube_config = base_config.clone();
        kube_config.connect_timeout = Some(Duration::from_secs(10));
        kube_config.read_timeout = Some(Duration::from_secs(30));
        kube_config.write_timeout = Some(Duration::from_secs(30));
        let client = Client::try_from(kube_config).map_err(KubernetesDriverError::from_kube)?;

        let mut watch_kube_config = base_config;
        watch_kube_config.connect_timeout = Some(Duration::from_secs(10));
        watch_kube_config.read_timeout = None;
        watch_kube_config.write_timeout = Some(Duration::from_secs(30));
        let watch_client =
            Client::try_from(watch_kube_config).map_err(KubernetesDriverError::from_kube)?;

        let operator_allowlist = if matches!(config.workspace_mode, WorkspaceMode::Operator) {
            let allowlist = OperatorNamespaceAllowlist::new();

            if let Some(ref label) = config.operator_namespace_label {
                spawn_namespace_label_watcher(
                    watch_client.clone(),
                    label.clone(),
                    allowlist.clone(),
                    shutdown_rx.clone(),
                );
            }

            if let Some(ref path) = config.operator_namespace_file {
                spawn_namespace_file_watcher(path.into(), allowlist.clone(), shutdown_rx.clone());
            }

            Some(allowlist)
        } else {
            None
        };

        Ok(Self {
            client,
            watch_client,
            sandbox_api_version: Arc::new(OnceCell::new()),
            config,
            operator_allowlist,
            confidential: Some(confidential),
            lifecycle_gates: Arc::default(),
        })
    }

    fn bootstrap_timeout(&self) -> Duration {
        self.confidential
            .as_ref()
            .map_or(SANDBOX_RUNTIME_BOOTSTRAP_GRACE, |profile| {
                profile.bootstrap_timeout
            })
    }

    pub fn capabilities(&self) -> Result<GetCapabilitiesResponse, String> {
        Ok(GetCapabilitiesResponse {
            resource_admission_policy: openshell_core::resource_admission::DriverAdmissionConfig {
                allow_driver_config: self.config.allow_driver_config,
                resource_admission: self.config.resource_admission.clone(),
            }
            .acknowledgement(),
            driver_name: "kubernetes".to_string(),
            driver_version: openshell_core::VERSION.to_string(),
            default_image: self.config.default_image.clone(),
            gateway_manages_lifecycle: false,
            // Native Gateway also uses this capability to persist the Kubernetes
            // runtime identity needed by Stop/Start. Confidential token exchange
            // is rejected in authenticate_sandbox before Kubernetes is consulted.
            supports_sandbox_authentication: true,
            driver_reports_runtime_readiness: false,
            resource_capabilities: Some(ResourceCapabilities {
                cpu: Some(CpuResourceCapabilities {
                    limit_supported: true,
                }),
                memory: Some(MemoryResourceCapabilities {
                    limit_supported: true,
                }),
                gpu: Some(GpuResourceCapabilities {
                    default_selection_supported: true,
                    count_selection_supported: true,
                }),
            }),
            rootfs_tar_staging_dir: String::new(),
            rootfs_tar_max_bytes: 0,
            extension: Some(openshell_core::extension_protocol::extension_metadata(
                openshell_core::extension_protocol::ExtensionFamily::Compute,
                "openshell/kubernetes",
                openshell_core::VERSION,
                [],
            )),
        })
    }

    /// Require sealed gateway launch authentication instead of host-controlled tokens.
    pub async fn authenticate_sandbox(
        &self,
        _credential: &str,
    ) -> Result<(String, String), tonic::Status> {
        Err(tonic::Status::permission_denied(
            "confidential supervisors require sealed gateway launch authentication",
        ))
    }

    pub fn operator_allowlist(&self) -> Option<&OperatorNamespaceAllowlist> {
        self.operator_allowlist.as_ref()
    }

    pub fn default_image(&self) -> &str {
        &self.config.default_image
    }

    pub fn namespace(&self) -> &str {
        &self.config.namespace
    }

    pub fn ssh_socket_path(&self) -> &str {
        &self.config.ssh_socket_path
    }

    pub fn workspace_mode(&self) -> WorkspaceMode {
        self.config.workspace_mode
    }

    pub(crate) fn validate_workspace_namespace(
        &self,
        workspace: &str,
    ) -> Result<(), KubernetesDriverError> {
        if self.config.workspace_mode == WorkspaceMode::Managed {
            validate_managed_namespace_name(&self.config.gateway_id, workspace)
                .map_err(KubernetesDriverError::InvalidArgument)?;
        }
        Ok(())
    }

    /// Ensure the K8s namespace for a workspace exists (managed mode only).
    ///
    /// Idempotent: returns the namespace name whether it was just created or
    /// already existed. Also creates the sandbox `ServiceAccount` in the
    /// namespace.
    ///
    pub async fn ensure_namespace(&self, workspace: &str) -> Result<String, KubernetesDriverError> {
        let ns_name = managed_namespace(&self.config.gateway_id, workspace);
        let ns_api: Api<Namespace> = Api::all(self.client.clone());

        let gateway_ns_annotations = match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            ns_api.get(&self.config.namespace),
        )
        .await
        {
            Ok(Ok(ns)) => ns.metadata.annotations.unwrap_or_default(),
            Ok(Err(error)) => return Err(KubernetesDriverError::from_kube(error)),
            Err(_) => {
                return Err(KubernetesDriverError::Message(format!(
                    "timeout getting gateway namespace {} for SCC annotations",
                    self.config.namespace
                )));
            }
        };
        let openshift_scc_allocator_enabled = [
            crate::config::ANNOTATION_SCC_MCS,
            crate::config::ANNOTATION_SCC_UID_RANGE,
            crate::config::ANNOTATION_SCC_SUPPLEMENTAL_GROUPS,
        ]
        .iter()
        .any(|key| gateway_ns_annotations.contains_key(*key));

        let mut labels = BTreeMap::new();
        labels.insert(
            LABEL_MANAGED_BY.to_string(),
            LABEL_MANAGED_BY_VALUE.to_string(),
        );
        labels.insert(LABEL_GATEWAY_ID.to_string(), self.config.gateway_id.clone());
        labels.insert(LABEL_SANDBOX_WORKSPACE.to_string(), workspace.to_string());

        let ns = Namespace {
            metadata: ObjectMeta {
                name: Some(ns_name.clone()),
                labels: Some(labels),
                ..Default::default()
            },
            ..Default::default()
        };

        let initial_namespace = match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            ns_api.create(&PostParams::default(), &ns),
        )
        .await
        {
            Ok(Ok(created)) => {
                info!(namespace = %ns_name, workspace = %workspace, "created managed namespace");
                created
            }
            Ok(Err(KubeError::Api(api))) if api.code == 409 => {
                let existing =
                    match tokio::time::timeout(KUBE_API_TIMEOUT, ns_api.get(&ns_name)).await {
                        Ok(Ok(ns)) => ns,
                        Ok(Err(e)) => return Err(KubernetesDriverError::from_kube(e)),
                        Err(_) => {
                            return Err(KubernetesDriverError::Message(format!(
                                "timeout reading namespace {ns_name}"
                            )));
                        }
                    };
                if !is_namespace_owned_by_gateway(
                    existing.metadata.labels.as_ref(),
                    &self.config.gateway_id,
                ) {
                    return Err(KubernetesDriverError::Precondition(format!(
                        "namespace {ns_name} exists but is not owned by this gateway"
                    )));
                }
                debug!(namespace = %ns_name, "managed namespace already exists");
                existing
            }
            Ok(Err(e)) => return Err(KubernetesDriverError::from_kube(e)),
            Err(_) => {
                return Err(KubernetesDriverError::Message(format!(
                    "timeout creating namespace {ns_name}"
                )));
            }
        };

        if openshift_scc_allocator_enabled {
            self.wait_for_openshift_scc_annotations(&ns_api, &ns_name, initial_namespace)
                .await?;
        }

        self.ensure_service_account(&ns_name).await?;
        self.ensure_managed_ssh_network_policy(&ns_name).await?;

        Ok(ns_name)
    }

    async fn ensure_managed_ssh_network_policy(
        &self,
        namespace: &str,
    ) -> Result<(), KubernetesDriverError> {
        if !self.config.managed_ssh_ingress.enabled {
            return Ok(());
        }

        let policy = managed_ssh_network_policy(namespace, &self.config);
        let policy_api: Api<NetworkPolicy> = Api::namespaced(self.client.clone(), namespace);
        match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            policy_api.patch(
                MANAGED_SSH_NETWORK_POLICY_NAME,
                &PatchParams::apply("openshell"),
                &Patch::Apply(&policy),
            ),
        )
        .await
        {
            Ok(Ok(_)) => {
                info!(namespace, "applied managed sandbox SSH NetworkPolicy");
                Ok(())
            }
            Ok(Err(error)) => Err(KubernetesDriverError::from_kube(error)),
            Err(_) => Err(KubernetesDriverError::Message(format!(
                "timeout applying SSH NetworkPolicy in {namespace}"
            ))),
        }
    }

    async fn ensure_service_account(&self, namespace: &str) -> Result<(), KubernetesDriverError> {
        let sa_api: Api<ServiceAccount> = Api::namespaced(self.client.clone(), namespace);
        let sa = ServiceAccount {
            metadata: ObjectMeta {
                name: Some(self.config.service_account_name.clone()),
                labels: Some(BTreeMap::from([(
                    LABEL_MANAGED_BY.to_string(),
                    LABEL_MANAGED_BY_VALUE.to_string(),
                )])),
                ..Default::default()
            },
            ..Default::default()
        };

        match tokio::time::timeout(KUBE_API_TIMEOUT, sa_api.create(&PostParams::default(), &sa))
            .await
        {
            Ok(Ok(_)) => {
                info!(namespace = %namespace, sa = %self.config.service_account_name, "created service account");
            }
            Ok(Err(KubeError::Api(api))) if api.code == 409 => {}
            Ok(Err(e)) => return Err(KubernetesDriverError::from_kube(e)),
            Err(_) => {
                return Err(KubernetesDriverError::Message(format!(
                    "timeout creating service account in {namespace}"
                )));
            }
        }

        Ok(())
    }

    /// Names the workload and supervisor Pods of a runtime generation use in
    /// `imagePullSecrets`.
    fn generation_image_pull_secret_names(&self, names: &SandboxRuntimeNames) -> Vec<String> {
        if self.config.workspace_mode == WorkspaceMode::Managed {
            names.image_pull_secrets(self.config.image_pull_secrets.len())
        } else {
            self.config.image_pull_secrets.clone()
        }
    }

    async fn read_source_secret(&self, name: &str) -> Result<Secret, KubernetesDriverError> {
        let source_api: Api<Secret> = Api::namespaced(self.client.clone(), &self.config.namespace);
        match tokio::time::timeout(KUBE_API_TIMEOUT, source_api.get(name)).await {
            Ok(Ok(secret)) => Ok(secret),
            Ok(Err(KubeError::Api(error))) if error.code == 404 => {
                Err(KubernetesDriverError::Precondition(format!(
                    "Secret {name} does not exist in source namespace {}",
                    self.config.namespace
                )))
            }
            Ok(Err(error)) => Err(KubernetesDriverError::from_kube(error)),
            Err(_) => Err(KubernetesDriverError::Message(format!(
                "timeout reading Secret {name} from {}",
                self.config.namespace
            ))),
        }
    }

    /// Create immutable copies of the configured image-pull Secrets for one
    /// managed-mode runtime generation. An existing Secret with a generation
    /// name fails the create rather than being adopted.
    async fn create_generation_image_pull_secrets(
        &self,
        namespace: &str,
        names: &SandboxRuntimeNames,
        sandbox_id: &str,
        owners: Vec<OwnerReference>,
    ) -> Result<(), KubernetesDriverError> {
        if self.config.workspace_mode != WorkspaceMode::Managed {
            return Ok(());
        }
        let secrets = Api::<Secret>::namespaced(self.client.clone(), namespace);
        let targets = names.image_pull_secrets(self.config.image_pull_secrets.len());
        for (source_name, target_name) in self.config.image_pull_secrets.iter().zip(&targets) {
            let source = self.read_source_secret(source_name).await?;
            let copy =
                image_pull_secret_copy(namespace, target_name, sandbox_id, &source, owners.clone());
            secrets
                .create(&PostParams::default(), &copy)
                .await
                .map_err(KubernetesDriverError::from_kube)?;
        }
        Ok(())
    }

    /// Read the gateway client TLS material staged into supervisor bootstrap
    /// Secrets outside the sandbox namespace.
    async fn read_client_tls_material(
        &self,
    ) -> Result<Option<ClientTlsMaterial>, KubernetesDriverError> {
        if let Some(profile) = &self.confidential {
            return profile.client_tls.read().map(Some);
        }
        if self.config.supervisor_client_tls() != SupervisorClientTls::Bootstrap {
            return Ok(None);
        }
        let name = &self.config.client_tls_secret_name;
        let source = self.read_source_secret(name).await?;
        let mut data = source.data.unwrap_or_default();
        let mut take = |key: &str| {
            data.remove(key).map(|value| value.0).ok_or_else(|| {
                KubernetesDriverError::Precondition(format!(
                    "Secret {name} in {} has no {key}",
                    self.config.namespace
                ))
            })
        };
        Ok(Some(ClientTlsMaterial {
            ca_certificate: take("ca.crt")?,
        }))
    }

    /// Delete the managed namespace and all its contents (managed mode only).
    /// Called via the `DeleteWorkspace` RPC after workspace deletion.
    /// Kubernetes cascades namespace deletion to all resources within it.
    pub async fn delete_namespace(&self, workspace: &str) -> Result<(), KubernetesDriverError> {
        let ns_name = managed_namespace(&self.config.gateway_id, workspace);
        let ns_api: Api<Namespace> = Api::all(self.client.clone());

        let ns = match tokio::time::timeout(KUBE_API_TIMEOUT, ns_api.get(&ns_name)).await {
            Ok(Ok(ns)) => ns,
            Ok(Err(KubeError::Api(api))) if api.code == 404 => {
                debug!(namespace = %ns_name, "managed namespace already deleted");
                return Ok(());
            }
            Ok(Err(e)) => return Err(KubernetesDriverError::from_kube(e)),
            Err(_) => {
                return Err(KubernetesDriverError::Message(format!(
                    "timeout getting namespace {ns_name}"
                )));
            }
        };

        if !is_namespace_owned_by_gateway(ns.metadata.labels.as_ref(), &self.config.gateway_id) {
            debug!(
                namespace = %ns_name,
                "namespace not owned by this gateway, skipping delete"
            );
            return Ok(());
        }

        let namespace_uid = ns.metadata.uid.ok_or_else(|| {
            KubernetesDriverError::Message(format!(
                "namespace {ns_name} has no UID; refusing an unguarded delete"
            ))
        })?;
        let delete_params = namespace_delete_params(namespace_uid);

        match tokio::time::timeout(KUBE_API_TIMEOUT, ns_api.delete(&ns_name, &delete_params)).await
        {
            Ok(Ok(_)) => {
                info!(namespace = %ns_name, workspace = %workspace, "deleted managed namespace");
            }
            Ok(Err(KubeError::Api(api))) if api.code == 404 => {
                debug!(namespace = %ns_name, "managed namespace already deleted");
            }
            Ok(Err(e)) => return Err(KubernetesDriverError::from_kube(e)),
            Err(_) => {
                return Err(KubernetesDriverError::Message(format!(
                    "timeout deleting namespace {ns_name}"
                )));
            }
        }

        Ok(())
    }

    fn validate_driver_config_for_sandbox(
        sandbox: &Sandbox,
    ) -> Result<KubernetesSandboxDriverConfig, String> {
        kubernetes_driver_config_for_spec(sandbox.spec.as_ref())
    }

    fn agent_sandbox_api(
        client: Client,
        sandbox_api_version: &str,
        namespace: &str,
    ) -> AgentSandboxApi {
        let gvk = GroupVersionKind::gvk(SANDBOX_GROUP, sandbox_api_version, SANDBOX_KIND);
        let resource = ApiResource::from_gvk(&gvk);
        let api = Api::namespaced_with(client, namespace, &resource);
        AgentSandboxApi { api, resource }
    }

    fn cluster_wide_sandbox_api(client: Client, sandbox_api_version: &str) -> AgentSandboxApi {
        let gvk = GroupVersionKind::gvk(SANDBOX_GROUP, sandbox_api_version, SANDBOX_KIND);
        let resource = ApiResource::from_gvk(&gvk);
        let api = Api::all_with(client, &resource);
        AgentSandboxApi { api, resource }
    }

    async fn supported_agent_sandbox_api(
        &self,
        client: Client,
        namespace: &str,
    ) -> Result<AgentSandboxApi, String> {
        let sandbox_api_version = self.supported_sandbox_api_version(client.clone()).await?;
        Ok(Self::agent_sandbox_api(
            client,
            sandbox_api_version,
            namespace,
        ))
    }

    async fn supported_sandbox_api_for_lookup(
        &self,
        client: Client,
    ) -> Result<AgentSandboxApi, String> {
        let sandbox_api_version = self.supported_sandbox_api_version(client.clone()).await?;
        if self.config.is_multi_namespace() {
            Ok(Self::cluster_wide_sandbox_api(client, sandbox_api_version))
        } else {
            Ok(Self::agent_sandbox_api(
                client,
                sandbox_api_version,
                &self.config.namespace,
            ))
        }
    }

    fn sandbox_lookup_selector(&self, sandbox_id: &str) -> String {
        sandbox_lookup_selector_for(sandbox_id, &self.config.gateway_id)
    }

    fn openshell_sandbox_selector(&self) -> String {
        openshell_sandbox_selector_for(&self.config.gateway_id)
    }

    async fn supported_sandbox_api_version(&self, client: Client) -> Result<&'static str, String> {
        self.sandbox_api_version
            .get_or_try_init(
                || async move { self.detect_supported_sandbox_api_version(client).await },
            )
            .await
            .copied()
    }

    async fn detect_supported_sandbox_api_version(
        &self,
        client: Client,
    ) -> Result<&'static str, String> {
        for sandbox_api_version in SANDBOX_VERSIONS {
            let agent_sandbox_api = Self::agent_sandbox_api(
                client.clone(),
                sandbox_api_version,
                &self.config.namespace,
            );
            match tokio::time::timeout(
                KUBE_API_TIMEOUT,
                agent_sandbox_api.api.list(&ListParams::default().limit(1)),
            )
            .await
            {
                Ok(Ok(_)) => {
                    debug!(
                        namespace = %self.config.namespace,
                        sandbox_api_version = %sandbox_api_version,
                        "Selected Agent Sandbox API version"
                    );
                    return Ok(sandbox_api_version);
                }
                Ok(Err(err)) if should_try_next_sandbox_api_version(&err) => {
                    debug!(
                        namespace = %self.config.namespace,
                        sandbox_api_version = %sandbox_api_version,
                        error = %err,
                        "Sandbox API version is not available; trying next supported version"
                    );
                }
                Ok(Err(err)) => return Err(err.to_string()),
                Err(_elapsed) => {
                    return Err(format!(
                        "timed out after {}s waiting for Kubernetes API",
                        KUBE_API_TIMEOUT.as_secs()
                    ));
                }
            }
        }
        Err(format!(
            "no supported Agent Sandbox API version is available; tried {}",
            SANDBOX_VERSIONS.join(", ")
        ))
    }

    async fn resolve_sandbox_identity_in_namespace(
        &self,
        namespace: &str,
    ) -> (u32, u32, BTreeMap<String, String>) {
        if self.config.sandbox_uid.is_some() {
            let uid = self.config.resolve_sandbox_uid(None);
            let gid = self.config.resolve_sandbox_gid(uid, None);
            return (uid, gid, BTreeMap::new());
        }

        let ns_api: Api<Namespace> = Api::all(self.client.clone());
        match tokio::time::timeout(KUBE_API_TIMEOUT, ns_api.get(namespace)).await {
            Ok(Ok(ns)) => {
                let anns = ns.metadata.annotations.unwrap_or_default();
                tracing::info!(
                    namespace = %namespace,
                    uid_range = ?anns.get(crate::config::ANNOTATION_SCC_UID_RANGE),
                    sup_groups = ?anns.get(crate::config::ANNOTATION_SCC_SUPPLEMENTAL_GROUPS),
                    "Resolved namespace annotations for sandbox identity"
                );
                let uid = self.config.resolve_sandbox_uid(Some(&anns));
                let baseline_gid = self.config.resolve_sandbox_gid(uid, None);
                let gid = self.config.sandbox_gid.map_or_else(
                    || {
                        anns.get(crate::config::ANNOTATION_SCC_SUPPLEMENTAL_GROUPS)
                            .and_then(|sup_range| {
                                KubernetesComputeConfig::from_open_shift_supplemental_groups(
                                    sup_range,
                                )
                            })
                            .unwrap_or(baseline_gid)
                    },
                    |_| baseline_gid,
                );
                tracing::info!(uid, gid, "Resolved sandbox identity");
                (uid, gid, anns)
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    namespace = %namespace,
                    error = %e,
                    "Failed to fetch namespace for SCC annotations, falling back to defaults"
                );
                let uid = DEFAULT_SANDBOX_UID;
                let gid = self.config.resolve_sandbox_gid(uid, None);
                (uid, gid, BTreeMap::new())
            }
            Err(_) => {
                tracing::warn!(
                    namespace = %namespace,
                    "Namespace fetch timed out, falling back to defaults"
                );
                let uid = DEFAULT_SANDBOX_UID;
                let gid = self.config.resolve_sandbox_gid(uid, None);
                (uid, gid, BTreeMap::new())
            }
        }
    }

    async fn has_gpu_capacity(&self) -> Result<bool, KubeError> {
        let nodes: Api<Node> = Api::all(self.client.clone());
        let node_list = nodes.list(&ListParams::default()).await?;
        Ok(node_list.items.into_iter().any(|node| {
            node.status
                .and_then(|status| status.allocatable)
                .and_then(|allocatable| allocatable.get(GPU_RESOURCE_NAME).cloned())
                .is_some_and(|quantity| quantity.0 != "0")
        }))
    }

    pub async fn validate_sandbox_create(&self, sandbox: &Sandbox) -> Result<(), tonic::Status> {
        openshell_core::resource_admission::check_sandbox_driver_config(
            self.config.allow_driver_config,
            sandbox,
        )?;
        self.config
            .resource_admission
            .validate()
            .map_err(tonic::Status::failed_precondition)?;
        let _ = Self::validate_driver_config_for_sandbox(sandbox)
            .map_err(tonic::Status::invalid_argument)?;
        match self.config.workspace_mode {
            WorkspaceMode::Shared => {
                validate_kube_resource_name_length(&sandbox.workspace, &sandbox.name)?;
            }
            WorkspaceMode::Managed | WorkspaceMode::Operator => {
                validate_kubernetes_dns1123_label(&sandbox.name, "sandbox name")
                    .map_err(tonic::Status::invalid_argument)?;
            }
        }
        let gpu_requirements = sandbox
            .spec
            .as_ref()
            .and_then(|spec| driver_gpu_requirements(spec.resource_requirements.as_ref()));
        validate_gpu_request(gpu_requirements)?;
        if gpu_requirements.is_some()
            && !self.has_gpu_capacity().await.map_err(|err| {
                tonic::Status::internal(format!("check GPU node capacity failed: {err}"))
            })?
        {
            return Err(tonic::Status::failed_precondition(
                "GPU sandbox requested, but the active gateway has no allocatable GPUs. Please refer to documentation and use `openshell doctor` commands to inspect GPU support and gateway configuration.",
            ));
        }
        Ok(())
    }

    async fn admit_requested_resources(
        &self,
        sandbox: &Sandbox,
    ) -> Result<crate::resource_admission::Identities, tonic::Status> {
        self.validate_confidential_runtime_class_request(sandbox.spec.as_ref())
            .map_err(tonic::Status::failed_precondition)?;
        openshell_core::resource_admission::check_sandbox_driver_config(
            self.config.allow_driver_config,
            sandbox,
        )?;
        self.validate_workspace_namespace(&sandbox.workspace)
            .map_err(|error| tonic::Status::failed_precondition(error.to_string()))?;
        let namespace = self
            .config
            .namespace_for_workspace(&sandbox.workspace, self.operator_allowlist.as_ref())
            .map_err(tonic::Status::failed_precondition)?;
        let params = SandboxPodParams {
            default_image: &self.config.default_image,
            image_pull_secrets: &self.config.image_pull_secrets,
            default_runtime_class_name: &self.config.default_runtime_class_name,
            service_account_name: &self.config.service_account_name,
            ..Default::default()
        };
        let rendered = sandbox_to_k8s_spec(sandbox.spec.as_ref(), &params)
            .map_err(tonic::Status::invalid_argument)?;
        crate::resource_admission::admit(
            &self.client,
            &self.config.resource_admission,
            &sandbox.workspace,
            &namespace,
            &rendered["spec"]["podTemplate"]["spec"],
            params.sandbox_secret_name,
        )
        .await
    }

    async fn admit_stored_resources(&self, object: &DynamicObject) -> Result<(), tonic::Status> {
        if self.confidential.is_some() {
            self.validate_confidential_pod_spec(&object.data["spec"]["podTemplate"]["spec"])
                .map_err(tonic::Status::failed_precondition)?;
        }
        if self.config.allow_driver_config && !self.config.resource_admission.enabled {
            return Ok(());
        }
        let expected = crate::resource_admission::check_record(
            object.metadata.annotations.as_ref(),
            self.config.allow_driver_config,
        )?;
        if !self.config.resource_admission.enabled {
            return Ok(());
        }
        let workspace = object
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(LABEL_SANDBOX_WORKSPACE))
            .ok_or_else(|| {
                tonic::Status::failed_precondition("sandbox lacks workspace identity")
            })?;
        let namespace = object
            .metadata
            .namespace
            .as_deref()
            .ok_or_else(|| tonic::Status::failed_precondition("sandbox lacks namespace"))?;
        sandbox_id_from_object(object).map_err(tonic::Status::failed_precondition)?;
        let spec = &object.data["spec"]["podTemplate"]["spec"];
        let private_secret = sandbox_bootstrap_secret_name(spec).ok_or_else(|| {
            tonic::Status::failed_precondition(
                "sandbox pod template is missing its bootstrap Secret volume",
            )
        })?;
        let actual = crate::resource_admission::admit(
            &self.client,
            &self.config.resource_admission,
            workspace,
            namespace,
            spec,
            private_secret,
        )
        .await?;
        if actual != expected {
            return Err(tonic::Status::failed_precondition(
                "sandbox external resource identity or attachment inventory changed",
            ));
        }
        Ok(())
    }

    async fn sandbox_with_attestation(
        &self,
        client: &Client,
        namespace: &str,
        obj: DynamicObject,
    ) -> Result<(String, Sandbox), String> {
        let uid = obj.metadata.uid.clone().unwrap_or_default();
        let (name, mut sandbox) =
            sandbox_from_object_with_sandbox_runtime_readiness(client, namespace, obj).await?;
        if let Some(status) = sandbox.status.as_mut() {
            // These names are owned by T, even when the optional feature is off.
            status
                .conditions
                .retain(|c| !crate::attestation::TYPES.contains(&c.r#type.as_str()));
            if let Some(profile) = &self.confidential
                && let Some(reports) = &profile.reports
            {
                let profile = profile.clone();
                let id = sandbox.id.clone();
                let namespace = namespace.to_owned();
                let bindings = tokio::task::spawn_blocking(move || {
                    profile.store.attestation_bindings(&id, &namespace, &uid)
                })
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or_default();
                status
                    .conditions
                    .extend(reports.conditions(&bindings).await);
            }
        }
        Ok((name, sandbox))
    }

    pub async fn get_sandbox(&self, sandbox_id: &str) -> Result<Option<Sandbox>, String> {
        info!(
            sandbox_id = %sandbox_id,
            workspace_mode = %self.config.workspace_mode,
            "Fetching sandbox from Kubernetes"
        );

        let agent_sandbox_api = self
            .supported_sandbox_api_for_lookup(self.client.clone())
            .await?;
        let selector = self.sandbox_lookup_selector(sandbox_id);
        let lp = ListParams::default().labels(&selector);
        match tokio::time::timeout(KUBE_API_TIMEOUT, agent_sandbox_api.api.list(&lp)).await {
            Ok(Ok(list)) => {
                let Some(obj) = list.items.into_iter().next() else {
                    debug!(sandbox_id = %sandbox_id, "Sandbox not found in Kubernetes");
                    return Ok(None);
                };
                let ns = obj
                    .metadata
                    .namespace
                    .clone()
                    .unwrap_or_else(|| self.config.namespace.clone());
                self.sandbox_with_attestation(&self.client, &ns, obj)
                    .await
                    .map(|(_, sandbox)| Some(sandbox))
            }
            Ok(Err(err)) => {
                warn!(
                    sandbox_id = %sandbox_id,
                    error = %err,
                    "Failed to fetch sandbox from Kubernetes"
                );
                Err(err.to_string())
            }
            Err(_elapsed) => {
                warn!(
                    sandbox_id = %sandbox_id,
                    timeout_secs = KUBE_API_TIMEOUT.as_secs(),
                    "Timed out fetching sandbox from Kubernetes"
                );
                Err(format!(
                    "timed out after {}s waiting for Kubernetes API",
                    KUBE_API_TIMEOUT.as_secs()
                ))
            }
        }
    }

    pub async fn list_sandboxes(&self) -> Result<Vec<Sandbox>, String> {
        info!(
            workspace_mode = %self.config.workspace_mode,
            "Listing sandboxes from Kubernetes"
        );

        let agent_sandbox_api = self
            .supported_sandbox_api_for_lookup(self.client.clone())
            .await?;
        let selector = self.openshell_sandbox_selector();
        match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            agent_sandbox_api
                .api
                .list(&ListParams::default().labels(&selector)),
        )
        .await
        {
            Ok(Ok(list)) => {
                let mut sandboxes = Vec::new();
                for obj in list.items {
                    let name = obj.metadata.name.clone().unwrap_or_default();
                    let ns = obj
                        .metadata
                        .namespace
                        .clone()
                        .unwrap_or_else(|| self.config.namespace.clone());
                    match self.sandbox_with_attestation(&self.client, &ns, obj).await {
                        Ok((_, sandbox)) => sandboxes.push(sandbox),
                        Err(err) => {
                            warn!(object_name = %name, error = %err, "skipping unrecognized Sandbox in list");
                        }
                    }
                }
                sandboxes.sort_by(|left, right| {
                    left.name
                        .cmp(&right.name)
                        .then_with(|| left.id.cmp(&right.id))
                });
                Ok(sandboxes)
            }
            Ok(Err(err)) => {
                warn!(
                    error = %err,
                    "Failed to list sandboxes from Kubernetes"
                );
                Err(err.to_string())
            }
            Err(_elapsed) => {
                warn!(
                    timeout_secs = KUBE_API_TIMEOUT.as_secs(),
                    "Timed out listing sandboxes from Kubernetes"
                );
                Err(format!(
                    "timed out after {}s waiting for Kubernetes API",
                    KUBE_API_TIMEOUT.as_secs()
                ))
            }
        }
    }

    #[allow(clippy::similar_names)]
    #[tracing::instrument(
        name = "kubernetes.provision",
        skip(self, sandbox),
        fields(
            otel.name = "kubernetes.provision",
            otel.status_code = tracing::field::Empty,
            sandbox.id = %sandbox.id,
            sandbox.name = %sandbox.name,
        )
    )]
    pub async fn create_sandbox(&self, sandbox: &Sandbox) -> Result<String, KubernetesDriverError> {
        let _lifecycle_guard = self.lifecycle_lock(&sandbox.id).lock_owned().await;
        let span_status = openshell_otel::ErrorStatusGuard::current();
        let result = Box::pin(self.create_sandbox_inner(sandbox)).await;
        span_status.finish(result)
    }

    #[allow(clippy::similar_names)]
    async fn create_sandbox_inner(
        &self,
        sandbox: &Sandbox,
    ) -> Result<String, KubernetesDriverError> {
        openshell_core::resource_admission::check_sandbox_driver_config(
            self.config.allow_driver_config,
            sandbox,
        )
        .map_err(admission_error)?;
        let gpu_requirements = sandbox
            .spec
            .as_ref()
            .and_then(|spec| driver_gpu_requirements(spec.resource_requirements.as_ref()));
        validate_gpu_request(gpu_requirements).map_err(|status| {
            KubernetesDriverError::InvalidArgument(status.message().to_string())
        })?;

        // Validate sandbox name against Kubernetes naming requirements
        validate_kubernetes_dns1123_label(&sandbox.name, "sandbox name")
            .map_err(KubernetesDriverError::InvalidArgument)?;

        let name = sandbox.name.as_str();
        let workspace = sandbox.workspace.as_str();
        self.validate_workspace_namespace(workspace)?;

        let target_namespace = match self.config.workspace_mode {
            WorkspaceMode::Shared => self.config.namespace.clone(),
            WorkspaceMode::Managed => self.ensure_namespace(workspace).await?,
            WorkspaceMode::Operator => {
                if let Some(ref allowlist) = self.operator_allowlist
                    && !allowlist.contains(workspace)
                {
                    return Err(KubernetesDriverError::Precondition(format!(
                        "workspace '{workspace}' is not in the operator namespace allowlist"
                    )));
                }
                workspace.to_string()
            }
        };

        let resource_identities = self
            .admit_requested_resources(sandbox)
            .await
            .map_err(admission_error)?;

        info!(
            sandbox_id = %sandbox.id,
            sandbox_name = %name,
            namespace = %target_namespace,
            workspace = %workspace,
            workspace_mode = %self.config.workspace_mode,
            "Creating sandbox in Kubernetes"
        );

        let agent_sandbox_api = self
            .supported_agent_sandbox_api(self.client.clone(), &target_namespace)
            .await
            .map_err(KubernetesDriverError::Message)?;

        // Resolve sandbox UID/GID from config or OpenShift SCC namespace annotations.
        let (resolved_user_id, resolved_group_id, ns_annotations) = self
            .resolve_sandbox_identity_in_namespace(&target_namespace)
            .await;

        let generation = random_sandbox_runtime_token();
        let bootstrap_attempt = random_sandbox_runtime_token();
        let proxy_names = SandboxRuntimeNames::for_generation(&sandbox.id, &generation);
        let image_pull_secrets = self.generation_image_pull_secret_names(&proxy_names);
        let main_process_spec = openshell_core::sandbox_env::MainProcessConfig::encode_driver_spec(
            sandbox.spec.as_ref(),
        )
        .map_err(|error| {
            KubernetesDriverError::InvalidArgument(format!("encode main process spec: {error}"))
        })?;
        let log_level = openshell_core::driver_utils::sandbox_log_level(sandbox, "info");
        let params = SandboxPodParams {
            default_image: &self.config.default_image,
            image_pull_policy: self.config.image_pull_policy,
            image_pull_secrets: &image_pull_secrets,
            sandbox_runtime_image: &self.config.sandbox_runtime_image,
            sandbox_runtime_image_pull_policy: self.config.sandbox_runtime_image_pull_policy,
            service_account_name: &self.config.service_account_name,
            sandbox_id: &sandbox.id,
            enable_user_namespaces: self.config.enable_user_namespaces,
            workspace_default_storage_size: &self.config.workspace_default_storage_size,
            workspace_storage_class: &self.config.workspace_storage_class,
            default_runtime_class_name: &self.config.default_runtime_class_name,
            sandbox_uid: resolved_user_id,
            sandbox_gid: resolved_group_id,
            boundary_port: self.config.sandbox_runtime.boundary_port,
            sandbox_secret_name: &proxy_names.sandbox_secret,
        };
        let kube_name = self.config.kube_resource_name(workspace, name);
        let mut data = sandbox_to_k8s_spec(sandbox.spec.as_ref(), &params)
            .map_err(KubernetesDriverError::InvalidArgument)?;
        self.validate_confidential_pod_spec(&data["spec"]["podTemplate"]["spec"])
            .map_err(KubernetesDriverError::Precondition)?;
        self.create_sandbox_runtime_fence(&target_namespace, &proxy_names)
            .await?;
        // A missing bootstrap Secret keeps both pods inert as defense in
        // depth, but the CR is also created suspended so the controller
        // never races an unfenced workload into execution.
        if agent_sandbox_api.resource.version == SANDBOX_VERSION_V1ALPHA1 {
            data["spec"]["replicas"] = serde_json::json!(0);
        } else {
            data["spec"]["operatingMode"] = serde_json::json!("Suspended");
        }
        let mut obj = DynamicObject::new(&kube_name, &agent_sandbox_api.resource);
        let mut annotations = sandbox_annotations(sandbox);
        annotations.insert(
            ANNOTATION_CONFIDENTIAL_BOOTSTRAP_ATTEMPT.to_string(),
            bootstrap_attempt.clone(),
        );
        annotations.insert(
            crate::resource_admission::IDENTITIES.into(),
            serde_json::to_string(&resource_identities)
                .map_err(|error| KubernetesDriverError::Message(error.to_string()))?,
        );
        annotations.insert(
            crate::resource_admission::CONFIG_USED.into(),
            sandbox
                .spec
                .as_ref()
                .and_then(|spec| spec.template.as_ref())
                .and_then(|template| template.driver_config.as_ref())
                .is_some_and(|config| !config.fields.is_empty())
                .to_string(),
        );
        add_trace_context_annotation(&mut annotations);
        annotations.insert(
            ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAPPING.to_string(),
            "true".to_string(),
        );
        annotations.insert(
            ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_STARTED_AT.to_string(),
            openshell_core::time::now_ms().to_string(),
        );
        annotations.insert(
            ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_OPERATION.to_string(),
            "create".to_string(),
        );
        annotations.insert(
            ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_PHASE.to_string(),
            SandboxRuntimeBootstrapPhase::Preparing.as_str().to_string(),
        );
        annotations.insert(
            ANNOTATION_SANDBOX_RUNTIME_GENERATION.to_string(),
            generation.clone(),
        );
        for key in [
            crate::config::ANNOTATION_SCC_UID_RANGE,
            crate::config::ANNOTATION_SCC_SUPPLEMENTAL_GROUPS,
        ] {
            if let Some(v) = ns_annotations.get(key) {
                annotations.insert(key.to_string(), v.clone());
            }
        }
        obj.metadata = ObjectMeta {
            name: Some(kube_name.clone()),
            namespace: Some(target_namespace.clone()),
            labels: Some(sandbox_labels(sandbox, Some(&self.config.gateway_id))),
            annotations: Some(annotations),
            ..Default::default()
        };

        obj.data = data;
        let created = match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            agent_sandbox_api.api.create(&PostParams::default(), &obj),
        )
        .await
        {
            Ok(Ok(result)) => {
                info!(
                    sandbox_id = %sandbox.id,
                    sandbox_name = %name,
                    "Sandbox created in Kubernetes successfully"
                );
                result
            }
            Ok(Err(err)) => {
                warn!(
                    sandbox_id = %sandbox.id,
                    sandbox_name = %name,
                    error = %err,
                    "Failed to create sandbox in Kubernetes"
                );
                return Err(KubernetesDriverError::from_kube(err));
            }
            Err(_elapsed) => {
                warn!(
                    sandbox_id = %sandbox.id,
                    sandbox_name = %name,
                    timeout_secs = KUBE_API_TIMEOUT.as_secs(),
                    "Timed out creating sandbox in Kubernetes"
                );
                return Err(KubernetesDriverError::Message(format!(
                    "timed out after {}s waiting for Kubernetes API",
                    KUBE_API_TIMEOUT.as_secs()
                )));
            }
        };
        let runtime_identity = match Box::pin(self.create_sandbox_runtime_companions(
            sandbox,
            &target_namespace,
            &kube_name,
            &agent_sandbox_api,
            &created,
            &obj,
            &proxy_names,
            &generation,
            &bootstrap_attempt,
            resolved_user_id,
            resolved_group_id,
            &main_process_spec,
            &log_level,
        ))
        .await
        {
            Ok(runtime_identity) => runtime_identity,
            Err(error) => {
                warn!(sandbox_id = %sandbox.id, %error, "sandbox-runtime provisioning failed; rolling back Sandbox CR");
                let cr_uid = created.metadata.uid.as_deref().ok_or_else(|| {
                    KubernetesDriverError::Precondition(
                        "created Sandbox CR lacks UID during rollback".to_string(),
                    )
                })?;
                if let Some(profile) = &self.confidential {
                    let marker = profile
                        .store
                        .record_workspace_owner(&sandbox.id, &target_namespace, cr_uid)
                        .and_then(|()| profile.store.begin_delete(
                            &sandbox.id, &target_namespace, cr_uid,
                            Some((&generation, &bootstrap_attempt)),
                        ))
                        .map_err(|revoke_error| KubernetesDriverError::Message(format!(
                            "provisioning failed: {error}; rollback fence pending: {revoke_error}"
                        )))?;
                    self.withdraw_sandbox_authorization_for_delete(&marker)
                        .map_err(|revoke_error| KubernetesDriverError::Message(format!(
                            "provisioning failed: {error}; rollback revocation pending: {revoke_error}"
                        )))?;
                }
                let delete_result = agent_sandbox_api
                    .api
                    .delete(
                        &kube_name,
                        &DeleteParams::default().preconditions(Preconditions {
                            uid: Some(cr_uid.to_owned()),
                            resource_version: None,
                        }),
                    )
                    .await;
                if let Err(delete_error) = delete_result
                    && !matches!(&delete_error, KubeError::Api(api) if api.code == 404)
                {
                    return Err(KubernetesDriverError::Message(format!(
                        "provisioning failed: {error}; rollback deletion pending: {delete_error}"
                    )));
                }
                return Err(error);
            }
        };
        Ok(runtime_identity)
    }

    async fn create_sandbox_runtime_fence(
        &self,
        namespace: &str,
        names: &SandboxRuntimeNames,
    ) -> Result<(), KubernetesDriverError> {
        let fence = workload_fence(namespace, names, self.config.sandbox_runtime.boundary_port);
        let policies: Api<NetworkPolicy> = Api::namespaced(self.client.clone(), namespace);
        for (mut policy, component) in [
            (fence.workload_policy, "sandbox-workload-fence"),
            (fence.supervisor_policy, "sandbox-supervisor-egress"),
        ] {
            let labels = policy.metadata.labels.get_or_insert_default();
            labels.insert(
                LABEL_MANAGED_BY.to_string(),
                LABEL_MANAGED_BY_VALUE.to_string(),
            );
            labels.insert("openshell.ai/component".to_string(), component.to_string());
            create_or_validate_sandbox_runtime_fence(&policies, &policy).await?;
        }
        Ok(())
    }

    async fn wait_for_bootstrap_workload_pod(
        &self,
        pods: &Api<Pod>,
        pod_name: &str,
        sandbox_uid: &str,
    ) -> Result<Pod, KubernetesDriverError> {
        let deadline = tokio::time::Instant::now() + KUBE_API_TIMEOUT;
        loop {
            match pods.get_opt(pod_name).await {
                Ok(Some(pod)) => {
                    let owned = pod
                        .metadata
                        .owner_references
                        .as_deref()
                        .unwrap_or_default()
                        .iter()
                        .any(|owner| {
                            owner.controller == Some(true)
                                && owner.kind == SANDBOX_KIND
                                && owner.uid == sandbox_uid
                        });
                    if !owned {
                        return Err(KubernetesDriverError::Precondition(format!(
                            "workload Pod {pod_name} is not controlled by the created Sandbox UID"
                        )));
                    }
                    return Ok(pod);
                }
                Ok(None) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Ok(None) => {
                    return Err(KubernetesDriverError::Message(format!(
                        "timed out waiting for gated workload Pod {pod_name}"
                    )));
                }
                Err(error) => return Err(KubernetesDriverError::from_kube(error)),
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_capability_free_workload_pod(
        pod: &Pod,
        sandbox_resource_uid: &str,
        sandbox_id: &str,
        uid: u32,
        gid: u32,
        sandbox_secret_name: &str,
    ) -> Result<(), KubernetesDriverError> {
        let fail = |message: &str| {
            KubernetesDriverError::Precondition(format!(
                "admitted workload Pod does not preserve capability-free isolation: {message}"
            ))
        };
        if pod.metadata.uid.as_deref().is_none() {
            return Err(fail("missing Pod UID"));
        }
        let owner_matches = pod
            .metadata
            .owner_references
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|owner| {
                owner.controller == Some(true)
                    && owner.kind == SANDBOX_KIND
                    && owner.uid == sandbox_resource_uid
            });
        if !owner_matches {
            return Err(fail("Sandbox owner UID changed"));
        }
        let labels = pod
            .metadata
            .labels
            .as_ref()
            .ok_or_else(|| fail("missing labels"))?;
        let expected_pair = crate::sandbox_runtime::pair_label_value(sandbox_id);
        if labels.get(BOUNDARY_ROLE_LABEL).map(String::as_str) != Some("workload")
            || labels.get(BOUNDARY_PAIR_LABEL).map(String::as_str) != Some(expected_pair.as_str())
        {
            return Err(fail("pair labels changed"));
        }
        let spec = pod.spec.as_ref().ok_or_else(|| fail("missing Pod spec"))?;
        if spec.host_network == Some(true)
            || spec.host_pid == Some(true)
            || spec.host_ipc == Some(true)
            || spec.share_process_namespace == Some(true)
            || spec.automount_service_account_token != Some(false)
            || spec.enable_service_links != Some(false)
        {
            return Err(fail("host namespaces or ServiceAccount token enabled"));
        }
        let projected_service_account_token = spec
            .volumes
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter_map(|volume| volume.projected.as_ref())
            .flat_map(|projected| projected.sources.as_deref().unwrap_or_default())
            .any(|source| source.service_account_token.is_some());
        if projected_service_account_token {
            return Err(fail(
                "workload Pod must not receive a projected ServiceAccount token",
            ));
        }
        if spec.restart_policy.as_deref() != Some("Never")
            || spec.dns_policy.as_deref() != Some("None")
            || spec
                .dns_config
                .as_ref()
                .is_none_or(|dns| dns.nameservers.as_deref() != Some(&["127.0.0.53".to_string()]))
        {
            return Err(fail("restart or DNS posture changed"));
        }
        if !spec
            .scheduling_gates
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|gate| gate.name == SANDBOX_BOOTSTRAP_SCHEDULING_GATE)
        {
            return Err(fail("bootstrap scheduling gate missing"));
        }
        let security = spec
            .security_context
            .as_ref()
            .ok_or_else(|| fail("missing Pod security context"))?;
        if security.run_as_user != Some(i64::from(uid))
            || security.run_as_group != Some(i64::from(gid))
            || security.run_as_non_root != Some(true)
            || security.fs_group != Some(i64::from(gid))
        {
            return Err(fail("numeric identity changed"));
        }
        if security.supplemental_groups_policy.as_deref() != Some("Strict") {
            return Err(fail("supplementalGroupsPolicy must be Strict"));
        }
        if !strict_without_supplemental_groups(security) {
            return Err(fail("supplementalGroups must be empty"));
        }
        if security
            .seccomp_profile
            .as_ref()
            .is_none_or(|profile| profile.type_ != "RuntimeDefault")
        {
            return Err(fail("seccomp profile changed"));
        }
        let pod_json = serde_json::to_value(pod)
            .map_err(|error| KubernetesDriverError::Message(error.to_string()))?;
        let unprivileged_port_sysctl = pod_json
            .pointer("/spec/securityContext/sysctls")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|sysctls| {
                sysctls.iter().any(|sysctl| {
                    sysctl.get("name").and_then(serde_json::Value::as_str)
                        == Some("net.ipv4.ip_unprivileged_port_start")
                        && sysctl.get("value").and_then(serde_json::Value::as_str) == Some("0")
                })
            });
        if !unprivileged_port_sysctl {
            return Err(fail("safe unprivileged-port sysctl changed"));
        }
        let check_container = |container: &k8s_openapi::api::core::v1::Container,
                               name: &str|
         -> Result<(), KubernetesDriverError> {
            let context = container
                .security_context
                .as_ref()
                .ok_or_else(|| fail(&format!("{name} has no security context")))?;
            let drops_all = context
                .capabilities
                .as_ref()
                .and_then(|capabilities| capabilities.drop.as_deref())
                .is_some_and(|drops| drops.iter().any(|capability| capability == "ALL"));
            let adds_none = context
                .capabilities
                .as_ref()
                .and_then(|capabilities| capabilities.add.as_deref())
                .is_none_or(<[String]>::is_empty);
            if context.run_as_user != Some(i64::from(uid))
                || context.run_as_group != Some(i64::from(gid))
                || context.run_as_non_root != Some(true)
                || context.allow_privilege_escalation != Some(false)
                || !drops_all
                || !adds_none
            {
                return Err(fail(&format!("{name} security context changed")));
            }
            Ok(())
        };
        let agent = spec
            .containers
            .iter()
            .find(|container| container.name == "agent")
            .ok_or_else(|| fail("agent container missing"))?;
        check_container(agent, "agent")?;
        let bootstrap = spec
            .init_containers
            .as_deref()
            .unwrap_or_default()
            .iter()
            .find(|container| container.name == "openshell-sandbox-bootstrap")
            .ok_or_else(|| fail("trusted bootstrap init container missing"))?;
        check_container(bootstrap, "bootstrap init container")?;
        let mounts_volume = |container: &k8s_openapi::api::core::v1::Container,
                             volume_name: &str| {
            container
                .volume_mounts
                .as_deref()
                .unwrap_or_default()
                .iter()
                .any(|mount| mount.name == volume_name)
        };
        if mounts_volume(agent, SANDBOX_BOOTSTRAP_VOLUME_NAME)
            || !mounts_volume(bootstrap, SANDBOX_BOOTSTRAP_VOLUME_NAME)
            || bootstrap
                .volume_mounts
                .as_deref()
                .unwrap_or_default()
                .iter()
                .filter(|mount| {
                    mount.name == SANDBOX_BOOTSTRAP_VOLUME_NAME
                        && mount.mount_path == crate::sandbox_runtime::SANDBOX_BOOTSTRAP_INPUT_PATH
                        && mount.read_only == Some(true)
                })
                .count()
                != 1
        {
            return Err(fail(
                "bootstrap Secret must be mounted only by the trusted init container",
            ));
        }
        let secret_matches = spec
            .volumes
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|volume| {
                volume.name == SANDBOX_BOOTSTRAP_VOLUME_NAME
                    && volume
                        .secret
                        .as_ref()
                        .and_then(|secret| secret.secret_name.as_deref())
                        == Some(sandbox_secret_name)
            });
        if !secret_matches {
            return Err(fail("generation-specific sandbox Secret changed"));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments, clippy::similar_names)]
    async fn create_sandbox_runtime_companions(
        &self,
        sandbox: &Sandbox,
        namespace: &str,
        cr_name: &str,
        sandbox_api: &AgentSandboxApi,
        sandbox_cr: &DynamicObject,
        trusted_cr: &DynamicObject,
        names: &SandboxRuntimeNames,
        generation: &str,
        bootstrap_attempt: &str,
        agent_uid: u32,
        agent_gid: u32,
        main_process_spec: &str,
        log_level: &str,
    ) -> Result<String, KubernetesDriverError> {
        // Read once per call so the whole generation stages, mounts, and
        // references the same bytes, and so a bundle that became unreadable
        // fails before any Service, Pod, or Secret is created.
        let upstream_proxy_ca_bundle =
            read_staged_upstream_proxy_ca_bundle(self.config.proxy_ca_bundle.as_deref()).await?;
        let cr_uid = sandbox_cr.metadata.uid.as_deref().ok_or_else(|| {
            KubernetesDriverError::Message("created Sandbox CR has no UID".to_string())
        })?;
        let mut expected_workload: Pod = serde_json::from_value(serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": trusted_cr.data["spec"]["podTemplate"]["metadata"],
            "spec": trusted_cr.data["spec"]["podTemplate"]["spec"],
        }))
        .map_err(|error| KubernetesDriverError::Message(error.to_string()))?;
        expected_workload.metadata.name = Some(cr_name.to_owned());
        expected_workload.metadata.namespace = Some(namespace.to_owned());
        // The pinned Sandbox controller names claims <template>-<Sandbox name>.
        for claim in trusted_cr.data["spec"]["volumeClaimTemplates"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let name = claim["metadata"]["name"].as_str().ok_or_else(|| {
                KubernetesDriverError::Precondition("trusted claim template lacks name".into())
            })?;
            expected_workload
                .spec
                .as_mut()
                .expect("trusted workload spec")
                .volumes
                .get_or_insert_default()
                .push(
                    serde_json::from_value(
                        serde_json::json!({"name": name, "persistentVolumeClaim": {
                            "claimName": format!("{name}-{cr_name}")
                        }}),
                    )
                    .map_err(|error| KubernetesDriverError::Message(error.to_string()))?,
                );
        }
        self.confidential_profile()?
            .store
            .record_launch(&crate::launch::LaunchIntent {
                sandbox_id: sandbox.id.clone(),
                namespace: namespace.to_owned(),
                sandbox_cr_uid: cr_uid.to_owned(),
                sandbox_name: sandbox.name.clone(),
                main_process_spec: main_process_spec.to_owned(),
                log_level: log_level.to_owned(),
                agent_uid,
                agent_gid,
                workload: expected_workload.clone(),
                volume_claim_templates: trusted_cr.data["spec"]["volumeClaimTemplates"].clone(),
            })
            .map_err(|error| {
                KubernetesDriverError::Precondition(format!(
                    "persist trusted launch intent: {error}"
                ))
            })?;
        self.confidential_profile()?
            .store
            .record_attempt(
                &sandbox.id,
                namespace,
                cr_uid,
                generation,
                bootstrap_attempt,
            )
            .map_err(|error| {
                KubernetesDriverError::Precondition(format!(
                    "record trusted bootstrap attempt: {error}"
                ))
            })?;
        let child_env = workload_environment_from_spec(sandbox.spec.as_ref());
        self.confidential_profile()?
            .store
            .record_workload_environment(&sandbox.id, namespace, cr_uid, &child_env)
            .map_err(|_| {
                KubernetesDriverError::Precondition(
                    "cannot persist the trusted workload environment".to_string(),
                )
            })?;
        let workspace_key_uri = if sandbox_uses_persistent_volume(trusted_cr) {
            Some(
                self.confidential_profile()?
                    .store
                    .plan_workspace_key(namespace, cr_uid)
                    .map_err(|error| KubernetesDriverError::Precondition(error.to_string()))?
                    .resource_uri,
            )
        } else {
            None
        };
        let mut supervisor_keys = SUPERVISOR_KEYS.to_vec();
        supervisor_keys.push("client-ca.crt");
        if upstream_proxy_ca_bundle.is_some() {
            supervisor_keys.push("upstream-proxy-ca.pem");
        }
        let supervisor_initdata = self.render_confidential_initdata(
            BootstrapRole::Supervisor,
            generation,
            &sandbox.id,
            cr_uid,
            bootstrap_attempt,
            namespace,
            &supervisor_keys,
            None,
            None,
        )?;
        let workload_initdata = self.render_confidential_initdata(
            BootstrapRole::Workload,
            generation,
            &sandbox.id,
            cr_uid,
            bootstrap_attempt,
            namespace,
            WORKLOAD_KEYS,
            workspace_key_uri.as_deref(),
            None,
        )?;
        patch_dynamic_object_with_uid_retry(&sandbox_api.api, cr_name, cr_uid, |version| {
            serde_json::json!({
                "metadata": {"resourceVersion": version},
                "spec": {"podTemplate": {"metadata": {"annotations": {
                    INITDATA_ANNOTATION: workload_initdata.annotation,
                }}}}
            })
        })
        .await?;
        let client_tls = self.read_client_tls_material().await?;
        let namespace_uid = Api::<Namespace>::all(self.client.clone())
            .get(namespace)
            .await
            .map_err(KubernetesDriverError::from_kube)?
            .metadata
            .uid
            .ok_or_else(|| {
                KubernetesDriverError::Message("sandbox namespace has no UID".to_string())
            })?;
        let dependent_owner = sandbox_runtime_sandbox_owner_reference(
            cr_name,
            cr_uid,
            &sandbox_api.resource.api_version,
            false,
        );
        let services: Api<Service> = Api::namespaced(self.client.clone(), namespace);
        let service = services
            .create(
                &PostParams::default(),
                &boundary_service(
                    namespace,
                    names,
                    &sandbox.id,
                    self.config.sandbox_runtime.boundary_port,
                    dependent_owner.clone(),
                ),
            )
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        let service_ip: std::net::IpAddr = service
            .spec
            .and_then(|spec| spec.cluster_ip)
            .filter(|ip| ip != "None")
            .ok_or_else(|| {
                KubernetesDriverError::Message("boundary Service has no ClusterIP".to_string())
            })?
            .parse()
            .map_err(|error| {
                KubernetesDriverError::Message(format!(
                    "invalid boundary Service ClusterIP: {error}"
                ))
            })?;

        let pods: Api<Pod> = Api::namespaced(self.client.clone(), namespace);
        let expected_supervisor = supervisor_pod(
            namespace,
            names,
            &sandbox.id,
            &sandbox.name,
            &self.config.gateway_id,
            &self.config.supervisor_image,
            self.config.supervisor_image_pull_policy,
            &self.config.service_account_name,
            agent_uid,
            agent_gid,
            &self.generation_image_pull_secret_names(names),
            &self.config.grpc_endpoint,
            self.supervisor_client_tls(),
            main_process_spec,
            log_level,
            self.config.effective_sa_token_ttl_secs(),
            self.config.https_proxy.as_deref(),
            self.config.no_proxy.as_deref(),
            self.config
                .proxy_auth_secret_name
                .as_deref()
                .zip(self.config.proxy_auth_secret_key.as_deref()),
            self.config.proxy_auth_allow_insecure == Some(true),
            self.config.proxy_connect_by_hostname == Some(true),
            upstream_proxy_ca_bundle.is_some(),
            self.config.provider_spiffe_enabled().then_some(
                self.config
                    .provider_spiffe_workload_api_socket_path
                    .as_str(),
            ),
            dependent_owner.clone(),
            &self.supervisor_tracing_environment(),
        )
        .map(|mut pod| {
            pod.spec
                .as_mut()
                .expect("supervisor Pod has a spec")
                .runtime_class_name = Some(self.config.default_runtime_class_name.clone());
            pod.metadata
                .annotations
                .get_or_insert_with(BTreeMap::new)
                .insert(
                    INITDATA_ANNOTATION.to_string(),
                    supervisor_initdata.annotation.clone(),
                );
            pod
        })
        .map_err(KubernetesDriverError::Message)?;
        let supervisor = pods
            .create(&PostParams::default(), &expected_supervisor)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        let supervisor_uid = supervisor.metadata.uid.ok_or_else(|| {
            KubernetesDriverError::Message("supervisor Pod has no UID".to_string())
        })?;

        let policies: Api<NetworkPolicy> = Api::namespaced(self.client.clone(), namespace);
        let fence = policies
            .get(&names.workload_policy)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        let fence_uid = fence.metadata.uid.ok_or_else(|| {
            KubernetesDriverError::Message("workload NetworkPolicy has no UID".to_string())
        })?;
        let fence_generation = fence.metadata.generation.ok_or_else(|| {
            KubernetesDriverError::Message("workload NetworkPolicy has no generation".to_string())
        })?;
        let fence_resource_version = fence.metadata.resource_version.ok_or_else(|| {
            KubernetesDriverError::Message(
                "workload NetworkPolicy has no resourceVersion".to_string(),
            )
        })?;

        // Release the Sandbox CR only far enough for the controller to create
        // the workload Pod. The Pod remains unschedulable because its template
        // carries the OpenShell scheduling gate and references a Secret that
        // does not exist yet.
        patch_dynamic_object_with_uid_retry(&sandbox_api.api, cr_name, cr_uid, |version| {
            sandbox_operating_state_patch(&sandbox_api.resource.version, version, true)
        })
        .await?;

        let workload_pod = self
            .wait_for_bootstrap_workload_pod(&pods, cr_name, cr_uid)
            .await?;
        self.record_workspace_volumes(
            &sandbox.id,
            namespace,
            cr_uid,
            &workload_pod,
            workspace_key_uri.is_some(),
        )
        .await?;
        let admission_object = sandbox_api
            .api
            .get(cr_name)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        self.admit_stored_resources(&admission_object)
            .await
            .map_err(admission_error)?;
        Self::validate_capability_free_workload_pod(
            &workload_pod,
            cr_uid,
            &sandbox.id,
            agent_uid,
            agent_gid,
            &names.sandbox_secret,
        )?;
        let workload_pod_uid =
            workload_pod.metadata.uid.clone().ok_or_else(|| {
                KubernetesDriverError::Message("workload Pod has no UID".to_string())
            })?;
        let workload_pod_name = workload_pod.metadata.name.clone().ok_or_else(|| {
            KubernetesDriverError::Message("workload Pod has no name".to_string())
        })?;
        let supervisor_pod = pods
            .get(&names.supervisor_pod)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        if supervisor_pod.metadata.uid.as_deref() != Some(&supervisor_uid) {
            return Err(KubernetesDriverError::Precondition(
                "supervisor Pod UID changed during confidential bootstrap".to_string(),
            ));
        }
        let supervisor_initdata = self
            .generate_and_patch_initdata(
                &pods,
                &supervisor_pod,
                &expected_supervisor,
                BootstrapRole::Supervisor,
                generation,
                &sandbox.id,
                cr_uid,
                bootstrap_attempt,
                namespace,
                &supervisor_keys,
                None,
            )
            .await?;
        let workload_initdata = self
            .generate_and_patch_initdata(
                &pods,
                &workload_pod,
                &expected_workload,
                BootstrapRole::Workload,
                generation,
                &sandbox.id,
                cr_uid,
                bootstrap_attempt,
                namespace,
                WORKLOAD_KEYS,
                workspace_key_uri.as_deref(),
            )
            .await?;
        patch_dynamic_object_with_uid_retry(&sandbox_api.api, cr_name, cr_uid, |version| {
            serde_json::json!({"metadata": {"resourceVersion": version},
            "spec": {"podTemplate": {"metadata": {"annotations": {
                INITDATA_ANNOTATION: workload_initdata.annotation,
            }}}}})
        })
        .await?;
        patch_dynamic_object_with_uid_retry(&sandbox_api.api, cr_name, cr_uid, |version| {
            serde_json::json!({
                "metadata": {
                    "resourceVersion": version,
                    "annotations": {
                        ANNOTATION_SANDBOX_RUNTIME_WORKLOAD_UID: workload_pod_uid.clone(),
                        ANNOTATION_SANDBOX_RUNTIME_SUPERVISOR_UID: supervisor_uid.clone(),
                        ANNOTATION_SANDBOX_RUNTIME_NETWORK_POLICY_UID: fence_uid.clone(),
                        ANNOTATION_SANDBOX_RUNTIME_NETWORK_POLICY_GENERATION: fence_generation.to_string(),
                    }
                }
            })
        })
        .await?;

        let launch_authentication = sandbox
            .spec
            .as_ref()
            .filter(|spec| !spec.launch_authentication.is_empty())
            .ok_or_else(|| {
                KubernetesDriverError::Precondition(
                    "Kubernetes sandbox launch authentication is required".to_string(),
                )
            })
            .and_then(|spec| decode_launch_authentication(&spec.launch_authentication))?;
        let host_gateway_ip = self.config.host_gateway_ip.parse().ok();
        let session_id = launch_authentication.supervisor.session_id;
        let tls = generate_sandbox_tls_material(session_id)
            .map_err(|error| KubernetesDriverError::Message(error.to_string()))?;
        let verification_keys =
            gateway_verification_keys(&launch_authentication.verification_keys)?;
        let proxy_ca = generate_proxy_ca_material().map_err(KubernetesDriverError::Message)?;
        let workload_identity = ResolvedWorkloadIdentity::new(
            agent_uid,
            agent_gid,
            Vec::new(),
            "kubernetes-config".to_string(),
            format!("sandbox:{cr_uid}"),
        )
        .map_err(|error| KubernetesDriverError::Message(error.to_string()))?;
        let provisioned = KubernetesSandboxRuntimeBoundarySpec {
            boundary_id: sandbox.id.clone(),
            generation: launch_authentication
                .supervisor
                .runtime_generation
                .to_string(),
            session_id,
            session_rotation: launch_authentication.supervisor.session_rotation,
            auth_epoch: launch_authentication.supervisor.auth_epoch,
            gateway_id: launch_authentication.gateway_id,
            verification_keys,
            namespace_uid,
            sandbox_resource_uid: cr_uid.to_string(),
            workload_pod_uid: workload_pod_uid.clone(),
            workload_pod_uid_path: PathBuf::from(SANDBOX_POD_UID_PATH),
            supervisor_pod_uid: supervisor_uid.clone(),
            egress_policy_uid: fence_uid.clone(),
            egress_policy_resource_version: fence_resource_version.clone(),
            boundary_listener: std::net::SocketAddr::new(
                if service_ip.is_ipv6() {
                    std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
                } else {
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
                },
                self.config.sandbox_runtime.boundary_port,
            ),
            control_authority: boundary_service_authority(
                namespace,
                names,
                self.config.sandbox_runtime.boundary_port,
            ),
            control_address: std::net::SocketAddr::new(
                service_ip,
                self.config.sandbox_runtime.boundary_port,
            ),
            sandbox_tls: SandboxTlsServerConfig {
                certificate_chain_path: PathBuf::from(BOUNDARY_CERTIFICATE_PATH),
                private_key_path: PathBuf::from(BOUNDARY_PRIVATE_KEY_PATH),
            },
            supervisor_tls: SandboxTlsClientConfig {
                server_name: tls.server_name.clone(),
                trust_anchor_pem: tls.trust_anchor_pem.clone(),
            },
            host_gateway_ip,
            workload_identity,
            child_env,
        }
        .provision()
        .map_err(|error| KubernetesDriverError::Message(error.to_string()))?;
        let descriptor = provisioned
            .runtime_descriptor
            .backend_descriptor()
            .map_err(|error| KubernetesDriverError::Message(error.to_string()))?;
        let workload_owner = runtime_pod_owner(&workload_pod_name, &workload_pod_uid);
        let supervisor_owner = runtime_pod_owner(&names.supervisor_pod, &supervisor_uid);
        let mut sandbox_secret = sandbox_bootstrap_secret(
            namespace,
            names,
            &sandbox.id,
            provisioned
                .boundary_config
                .encode()
                .map_err(|error| KubernetesDriverError::Message(error.to_string()))?,
            tls.certificate_chain_pem.into_bytes(),
            tls.private_key_pem.into_bytes(),
            workload_owner.clone(),
        );
        let mut supervisor_secret = supervisor_bootstrap_secret(
            namespace,
            names,
            &sandbox.id,
            descriptor.payload,
            serde_json::to_vec(&launch_authentication.supervisor).map_err(|error| {
                KubernetesDriverError::Message(format!("encode supervisor auth bundle: {error}"))
            })?,
            proxy_ca.certificate_pem.into_bytes(),
            proxy_ca.private_key_pem.into_bytes(),
            upstream_proxy_ca_bundle.clone(),
            client_tls,
            supervisor_owner.clone(),
        );
        self.seal_bootstrap_secret(
            &mut sandbox_secret,
            BootstrapRole::Workload,
            generation,
            &sandbox.id,
            cr_uid,
            bootstrap_attempt,
            &workload_initdata.digest,
            WORKLOAD_KEYS,
        )?;
        self.seal_bootstrap_secret(
            &mut supervisor_secret,
            BootstrapRole::Supervisor,
            generation,
            &sandbox.id,
            cr_uid,
            bootstrap_attempt,
            &supervisor_initdata.digest,
            &supervisor_keys,
        )?;
        if workspace_key_uri.is_some() {
            self.confidential_profile()?
                .store
                .ensure_workspace_key_for_attempt(
                    namespace,
                    cr_uid,
                    &workload_initdata.digest,
                    bootstrap_attempt,
                )
                .map_err(|error| {
                    KubernetesDriverError::Message(format!(
                        "authorize confidential workspace key: {error}"
                    ))
                })?;
        }
        let secrets = Api::<Secret>::namespaced(self.client.clone(), namespace);
        secrets
            .create(&PostParams::default(), &sandbox_secret)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        secrets
            .create(&PostParams::default(), &supervisor_secret)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        self.create_generation_image_pull_secrets(
            namespace,
            names,
            &sandbox.id,
            vec![workload_owner, supervisor_owner],
        )
        .await?;

        let supervisor_release_version = Self::verify_measured_pod_before_release(
            &pods,
            &names.supervisor_pod,
            &supervisor_uid,
            &supervisor_initdata.annotation,
            &supervisor_pod,
        )
        .await?;
        let workload_release_version = Self::verify_measured_pod_before_release(
            &pods,
            &workload_pod_name,
            &workload_pod_uid,
            &workload_initdata.annotation,
            &workload_pod,
        )
        .await?;
        pods.patch(
            &names.supervisor_pod,
            &PatchParams::default(),
            &Patch::Merge(&serde_json::json!({"metadata": {"resourceVersion": supervisor_release_version}, "spec": {"schedulingGates": []}})),
        )
        .await
        .map_err(KubernetesDriverError::from_kube)?;
        pods.patch(
            &workload_pod_name,
            &PatchParams::default(),
            &Patch::Merge(&serde_json::json!({"metadata": {"resourceVersion": workload_release_version}, "spec": {"schedulingGates": []}})),
        )
        .await
        .map_err(KubernetesDriverError::from_kube)?;
        patch_dynamic_object_with_uid_retry(&sandbox_api.api, cr_name, cr_uid, |version| {
            sandbox_runtime_bootstrap_phase_patch(version, SandboxRuntimeBootstrapPhase::Released)
        })
        .await?;
        spawn_sandbox_runtime_bootstrap_completion(
            pods.clone(),
            sandbox_api.api.clone(),
            names.supervisor_pod.clone(),
            cr_name.to_string(),
            Some(cr_uid.to_string()),
            self.bootstrap_timeout(),
        );
        // Return while the CR remains explicitly bootstrapping. The gateway
        // can now commit the sandbox configuration required by a policy-less
        // control process without deadlocking behind this driver call. Only
        // boundary PID 1 is running at this point; the agent process cannot
        // start until control attaches and confirms enforcement. Reconcile
        // removes the marker after the supervisor Pod becomes Ready.
        Ok(kubernetes_runtime_identity(
            namespace,
            cr_uid,
            &supervisor_uid,
        ))
    }

    #[allow(clippy::too_many_arguments, clippy::similar_names)]
    async fn install_sandbox_runtime_generation(
        &self,
        namespace: &str,
        cr_name: &str,
        sandbox_api: &AgentSandboxApi,
        sandbox_id: &str,
        cr_uid: &str,
        names: &SandboxRuntimeNames,
        generation: &str,
        bootstrap_attempt: &str,
        persistent_workspace: bool,
        supervisor_uid: &str,
        expected_supervisor: &Pod,
        agent_uid: u32,
        agent_gid: u32,
        child_env: std::collections::HashMap<String, String>,
        launch_authentication: &openshell_core::jwt::SandboxLaunchAuthentication,
    ) -> Result<(), KubernetesDriverError> {
        // Read once per call so the whole generation stages, mounts, and
        // references the same bytes, and so a bundle that became unreadable
        // fails before any Service, Pod, or Secret is created.
        let upstream_proxy_ca_bundle =
            read_staged_upstream_proxy_ca_bundle(self.config.proxy_ca_bundle.as_deref()).await?;
        let expected_workload = self
            .confidential_profile()?
            .store
            .load_launch(sandbox_id, namespace, cr_uid)
            .map_err(|error| {
                KubernetesDriverError::Precondition(format!("load trusted launch intent: {error}"))
            })?
            .workload_for_generation(
                &names.sandbox_secret,
                &self.generation_image_pull_secret_names(names),
            );
        let workspace_key_uri = if persistent_workspace {
            Some(
                self.confidential_profile()?
                    .store
                    .plan_workspace_key(namespace, cr_uid)
                    .map_err(|error| KubernetesDriverError::Precondition(error.to_string()))?
                    .resource_uri,
            )
        } else {
            None
        };
        let mut supervisor_keys = SUPERVISOR_KEYS.to_vec();
        supervisor_keys.push("client-ca.crt");
        if upstream_proxy_ca_bundle.is_some() {
            supervisor_keys.push("upstream-proxy-ca.pem");
        }
        let client_tls = self.read_client_tls_material().await?;
        let namespace_uid = Api::<Namespace>::all(self.client.clone())
            .get(namespace)
            .await
            .map_err(KubernetesDriverError::from_kube)?
            .metadata
            .uid
            .ok_or_else(|| {
                KubernetesDriverError::Message("sandbox namespace has no UID".to_string())
            })?;
        let services = Api::<Service>::namespaced(self.client.clone(), namespace);
        let service_ip: std::net::IpAddr = services
            .get(&names.boundary_service)
            .await
            .map_err(KubernetesDriverError::from_kube)?
            .spec
            .and_then(|spec| spec.cluster_ip)
            .filter(|ip| ip != "None")
            .ok_or_else(|| {
                KubernetesDriverError::Message("boundary Service has no ClusterIP".to_string())
            })?
            .parse()
            .map_err(|error| {
                KubernetesDriverError::Message(format!(
                    "invalid boundary Service ClusterIP: {error}"
                ))
            })?;
        let policies = Api::<NetworkPolicy>::namespaced(self.client.clone(), namespace);
        let fence = policies
            .get(&names.workload_policy)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        let fence_uid = fence.metadata.uid.ok_or_else(|| {
            KubernetesDriverError::Message("workload NetworkPolicy has no UID".to_string())
        })?;
        let fence_generation = fence.metadata.generation.ok_or_else(|| {
            KubernetesDriverError::Message("workload NetworkPolicy has no generation".to_string())
        })?;
        let fence_resource_version = fence.metadata.resource_version.ok_or_else(|| {
            KubernetesDriverError::Message(
                "workload NetworkPolicy has no resourceVersion".to_string(),
            )
        })?;

        let pods = Api::<Pod>::namespaced(self.client.clone(), namespace);
        let workload_pod = self
            .wait_for_bootstrap_workload_pod(&pods, cr_name, cr_uid)
            .await?;
        self.record_workspace_volumes(
            sandbox_id,
            namespace,
            cr_uid,
            &workload_pod,
            persistent_workspace,
        )
        .await?;
        let admission_object = sandbox_api
            .api
            .get(cr_name)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        self.admit_stored_resources(&admission_object)
            .await
            .map_err(admission_error)?;
        Self::validate_capability_free_workload_pod(
            &workload_pod,
            cr_uid,
            sandbox_id,
            agent_uid,
            agent_gid,
            &names.sandbox_secret,
        )?;
        let workload_pod_uid =
            workload_pod.metadata.uid.clone().ok_or_else(|| {
                KubernetesDriverError::Message("workload Pod has no UID".to_string())
            })?;
        let workload_pod_name = workload_pod.metadata.name.clone().ok_or_else(|| {
            KubernetesDriverError::Message("workload Pod has no name".to_string())
        })?;
        let supervisor_pod = pods
            .get(&names.supervisor_pod)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        if supervisor_pod.metadata.uid.as_deref() != Some(supervisor_uid) {
            return Err(KubernetesDriverError::Precondition(
                "supervisor Pod UID changed during confidential restart".to_string(),
            ));
        }
        let supervisor_initdata = self
            .generate_and_patch_initdata(
                &pods,
                &supervisor_pod,
                &expected_supervisor,
                BootstrapRole::Supervisor,
                generation,
                sandbox_id,
                cr_uid,
                bootstrap_attempt,
                namespace,
                &supervisor_keys,
                None,
            )
            .await?;
        let workload_initdata = self
            .generate_and_patch_initdata(
                &pods,
                &workload_pod,
                &expected_workload,
                BootstrapRole::Workload,
                generation,
                sandbox_id,
                cr_uid,
                bootstrap_attempt,
                namespace,
                WORKLOAD_KEYS,
                workspace_key_uri.as_deref(),
            )
            .await?;
        patch_dynamic_object_with_uid_retry(&sandbox_api.api, cr_name, cr_uid, |version| {
            serde_json::json!({"metadata": {"resourceVersion": version},
            "spec": {"podTemplate": {"metadata": {"annotations": {
                INITDATA_ANNOTATION: workload_initdata.annotation,
            }}}}})
        })
        .await?;
        patch_dynamic_object_with_uid_retry(&sandbox_api.api, cr_name, cr_uid, |version| {
            serde_json::json!({
                "metadata": {
                    "resourceVersion": version,
                    "annotations": {
                        ANNOTATION_SANDBOX_RUNTIME_WORKLOAD_UID: workload_pod_uid.clone(),
                        ANNOTATION_SANDBOX_RUNTIME_SUPERVISOR_UID: supervisor_uid,
                        ANNOTATION_SANDBOX_RUNTIME_NETWORK_POLICY_UID: fence_uid.clone(),
                        ANNOTATION_SANDBOX_RUNTIME_NETWORK_POLICY_GENERATION: fence_generation.to_string(),
                    }
                }
            })
        })
        .await?;

        let session_id = launch_authentication.supervisor.session_id;
        let tls = generate_sandbox_tls_material(session_id)
            .map_err(|error| KubernetesDriverError::Message(error.to_string()))?;
        let verification_keys =
            gateway_verification_keys(&launch_authentication.verification_keys)?;
        let proxy_ca = generate_proxy_ca_material().map_err(KubernetesDriverError::Message)?;
        let workload_identity = ResolvedWorkloadIdentity::new(
            agent_uid,
            agent_gid,
            Vec::new(),
            "kubernetes-config".to_string(),
            format!("sandbox:{cr_uid}"),
        )
        .map_err(|error| KubernetesDriverError::Message(error.to_string()))?;
        let provisioned = KubernetesSandboxRuntimeBoundarySpec {
            boundary_id: sandbox_id.to_string(),
            generation: launch_authentication
                .supervisor
                .runtime_generation
                .to_string(),
            session_id,
            session_rotation: launch_authentication.supervisor.session_rotation,
            auth_epoch: launch_authentication.supervisor.auth_epoch,
            gateway_id: launch_authentication.gateway_id.clone(),
            verification_keys,
            namespace_uid,
            sandbox_resource_uid: cr_uid.to_string(),
            workload_pod_uid: workload_pod_uid.clone(),
            workload_pod_uid_path: PathBuf::from(SANDBOX_POD_UID_PATH),
            supervisor_pod_uid: supervisor_uid.to_string(),
            egress_policy_uid: fence_uid.clone(),
            egress_policy_resource_version: fence_resource_version.clone(),
            boundary_listener: std::net::SocketAddr::new(
                if service_ip.is_ipv6() {
                    std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
                } else {
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
                },
                self.config.sandbox_runtime.boundary_port,
            ),
            control_authority: boundary_service_authority(
                namespace,
                names,
                self.config.sandbox_runtime.boundary_port,
            ),
            control_address: std::net::SocketAddr::new(
                service_ip,
                self.config.sandbox_runtime.boundary_port,
            ),
            sandbox_tls: SandboxTlsServerConfig {
                certificate_chain_path: PathBuf::from(BOUNDARY_CERTIFICATE_PATH),
                private_key_path: PathBuf::from(BOUNDARY_PRIVATE_KEY_PATH),
            },
            supervisor_tls: SandboxTlsClientConfig {
                server_name: tls.server_name.clone(),
                trust_anchor_pem: tls.trust_anchor_pem.clone(),
            },
            host_gateway_ip: self.config.host_gateway_ip.parse().ok(),
            workload_identity,
            child_env,
        }
        .provision()
        .map_err(|error| KubernetesDriverError::Message(error.to_string()))?;
        let descriptor = provisioned
            .runtime_descriptor
            .backend_descriptor()
            .map_err(|error| KubernetesDriverError::Message(error.to_string()))?;
        let workload_owner = runtime_pod_owner(&workload_pod_name, &workload_pod_uid);
        let supervisor_owner = runtime_pod_owner(&names.supervisor_pod, supervisor_uid);
        let mut sandbox_secret = sandbox_bootstrap_secret(
            namespace,
            names,
            sandbox_id,
            provisioned
                .boundary_config
                .encode()
                .map_err(|error| KubernetesDriverError::Message(error.to_string()))?,
            tls.certificate_chain_pem.into_bytes(),
            tls.private_key_pem.into_bytes(),
            workload_owner.clone(),
        );
        let mut supervisor_secret = supervisor_bootstrap_secret(
            namespace,
            names,
            sandbox_id,
            descriptor.payload,
            serde_json::to_vec(&launch_authentication.supervisor).map_err(|error| {
                KubernetesDriverError::Message(format!("encode supervisor auth bundle: {error}"))
            })?,
            proxy_ca.certificate_pem.into_bytes(),
            proxy_ca.private_key_pem.into_bytes(),
            upstream_proxy_ca_bundle.clone(),
            client_tls,
            supervisor_owner.clone(),
        );
        self.seal_bootstrap_secret(
            &mut sandbox_secret,
            BootstrapRole::Workload,
            generation,
            sandbox_id,
            cr_uid,
            bootstrap_attempt,
            &workload_initdata.digest,
            WORKLOAD_KEYS,
        )?;
        self.seal_bootstrap_secret(
            &mut supervisor_secret,
            BootstrapRole::Supervisor,
            generation,
            sandbox_id,
            cr_uid,
            bootstrap_attempt,
            &supervisor_initdata.digest,
            &supervisor_keys,
        )?;
        if persistent_workspace {
            self.confidential_profile()?
                .store
                .ensure_workspace_key_for_attempt(
                    namespace,
                    cr_uid,
                    &workload_initdata.digest,
                    bootstrap_attempt,
                )
                .map_err(|error| {
                    KubernetesDriverError::Message(format!(
                        "authorize confidential workspace key: {error}"
                    ))
                })?;
        }
        let secrets = Api::<Secret>::namespaced(self.client.clone(), namespace);
        secrets
            .create(&PostParams::default(), &sandbox_secret)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        secrets
            .create(&PostParams::default(), &supervisor_secret)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        self.create_generation_image_pull_secrets(
            namespace,
            names,
            sandbox_id,
            vec![workload_owner, supervisor_owner],
        )
        .await?;

        let supervisor_release_version = Self::verify_measured_pod_before_release(
            &pods,
            &names.supervisor_pod,
            supervisor_uid,
            &supervisor_initdata.annotation,
            &supervisor_pod,
        )
        .await?;
        let workload_release_version = Self::verify_measured_pod_before_release(
            &pods,
            &workload_pod_name,
            &workload_pod_uid,
            &workload_initdata.annotation,
            &workload_pod,
        )
        .await?;
        pods.patch(
            &names.supervisor_pod,
            &PatchParams::default(),
            &Patch::Merge(&serde_json::json!({"metadata": {"resourceVersion": supervisor_release_version}, "spec": {"schedulingGates": []}})),
        )
        .await
        .map_err(KubernetesDriverError::from_kube)?;
        pods.patch(
            &workload_pod_name,
            &PatchParams::default(),
            &Patch::Merge(&serde_json::json!({"metadata": {"resourceVersion": workload_release_version}, "spec": {"schedulingGates": []}})),
        )
        .await
        .map_err(KubernetesDriverError::from_kube)?;
        patch_dynamic_object_with_uid_retry(&sandbox_api.api, cr_name, cr_uid, |version| {
            sandbox_runtime_bootstrap_phase_patch(version, SandboxRuntimeBootstrapPhase::Released)
        })
        .await?;
        spawn_sandbox_runtime_bootstrap_completion(
            pods,
            sandbox_api.api.clone(),
            names.supervisor_pod.clone(),
            cr_name.to_string(),
            Some(cr_uid.to_string()),
            self.bootstrap_timeout(),
        );
        Ok(())
    }

    #[tracing::instrument(
        name = "kubernetes.stop_sandbox",
        skip(self),
        fields(
            otel.name = "kubernetes.stop_sandbox",
            otel.status_code = tracing::field::Empty,
            sandbox.id = %sandbox_id,
        )
    )]
    pub async fn stop_sandbox(&self, sandbox_id: &str) -> Result<(), KubernetesDriverError> {
        let _lifecycle_guard = self.lifecycle_lock(sandbox_id).lock_owned().await;
        let span_status = openshell_otel::ErrorStatusGuard::current();
        let result = Box::pin(self.stop_sandbox_inner(sandbox_id)).await;
        span_status.finish(result)
    }

    async fn stop_sandbox_inner(&self, sandbox_id: &str) -> Result<(), KubernetesDriverError> {
        let mut cleanup_errors = Vec::new();
        if let Some(profile) = &self.confidential {
            if let Err(error) = profile.store.revoke_owned_sandbox(sandbox_id, None) {
                cleanup_errors.push(format!(
                    "trusted authorization revocation remains pending: {error}"
                ));
            }
        }
        let (agent_sandbox_api, kube_name, pod_name, namespace, cr_uid, stop_timeout, phase) = self
            .prepare_sandbox_stop(sandbox_id)
            .await
            .map_err(|error| {
                if cleanup_errors.is_empty() {
                    error
                } else {
                    KubernetesDriverError::Message(format!(
                        "{error}; {}",
                        cleanup_errors.join("; ")
                    ))
                }
            })?;
        if let Some(profile) = &self.confidential {
            // Fence any concurrent bootstrap before removing Pods. The CAS
            // makes a racing start either lose or become the attempt this
            // stop tombstones. Publishing after this tombstone is rejected
            // by the private store even if a stale task keeps running.
            loop {
                let current = agent_sandbox_api
                    .api
                    .get(&kube_name)
                    .await
                    .map_err(KubernetesDriverError::from_kube)?;
                if current.metadata.uid.as_deref() != Some(cr_uid.as_str()) {
                    return Err(KubernetesDriverError::Precondition(
                        "Sandbox CR UID changed during stop".to_string(),
                    ));
                }
                let attempt = current
                    .metadata
                    .annotations
                    .as_ref()
                    .and_then(|a| a.get(ANNOTATION_CONFIDENTIAL_BOOTSTRAP_ATTEMPT))
                    .cloned();
                let generation = sandbox_runtime_generation(&current).map(str::to_string);
                let Some(attempt) = attempt else {
                    break;
                };
                let version = current
                    .metadata
                    .resource_version
                    .as_deref()
                    .ok_or_else(|| {
                        KubernetesDriverError::Precondition(
                            "Sandbox CR lacks resourceVersion".to_string(),
                        )
                    })?;
                match agent_sandbox_api
                    .api
                    .patch(
                        &kube_name,
                        &PatchParams::default(),
                        &Patch::Merge(&serde_json::json!({"metadata": {
                            "resourceVersion": version,
                            "annotations": {ANNOTATION_CONFIDENTIAL_BOOTSTRAP_ATTEMPT: null}
                        }})),
                    )
                    .await
                {
                    Ok(updated) if updated.metadata.uid.as_deref() == Some(cr_uid.as_str()) => {
                        if let Some(generation) = generation {
                            for role in [BootstrapRole::Workload, BootstrapRole::Supervisor] {
                                if let Err(error) = profile.store.revoke_attempt(
                                    role,
                                    &generation,
                                    sandbox_id,
                                    &attempt,
                                ) {
                                    cleanup_errors.push(format!(
                                        "fence confidential bootstrap during stop: {error}"
                                    ));
                                }
                            }
                        }
                        break;
                    }
                    Ok(_) => {
                        return Err(KubernetesDriverError::Precondition(
                            "Sandbox CR UID changed during stop attempt fence".to_string(),
                        ));
                    }
                    Err(error) if is_kube_resource_version_conflict(&error) => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => return Err(KubernetesDriverError::from_kube(error)),
                }
            }
        }
        if phase != Some(SandboxRuntimeBootstrapPhase::Suspending) {
            let current = agent_sandbox_api
                .api
                .get(&kube_name)
                .await
                .map_err(KubernetesDriverError::from_kube)?;
            if current.metadata.uid.as_deref() != Some(cr_uid.as_str()) {
                return Err(KubernetesDriverError::Precondition(
                    "Sandbox CR UID changed before supervisor deletion".to_string(),
                ));
            }
            self.delete_sandbox_runtime_supervisor_pod_for_uid(sandbox_id, &namespace, &cr_uid)
                .await?;
            patch_dynamic_object_with_uid_retry(
                &agent_sandbox_api.api,
                &kube_name,
                &cr_uid,
                |version| {
                    sandbox_runtime_suspension_patch(&agent_sandbox_api.resource.version, version)
                },
            )
            .await?;
        }
        let pod_api = Api::<Pod>::namespaced(self.client.clone(), &namespace);

        let deadline = tokio::time::Instant::now() + stop_timeout;
        let mut poll_interval = STOP_INITIAL_POLL_INTERVAL;
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(KubernetesDriverError::Message(format!(
                    "timed out after {}s waiting for Kubernetes sandbox to stop",
                    stop_timeout.as_secs()
                )));
            }
            let request_timeout = KUBE_API_TIMEOUT.min(deadline.saturating_duration_since(now));
            let object = tokio::time::timeout(
                request_timeout,
                agent_sandbox_api.api.get(&kube_name),
            )
            .await
            .map_err(|_| {
                KubernetesDriverError::Message(format!(
                    "timed out after {}s waiting for Kubernetes API while checking sandbox stop",
                    request_timeout.as_secs()
                ))
            })?
            .map_err(KubernetesDriverError::from_kube)?;
            if object.metadata.uid.as_deref() != Some(cr_uid.as_str()) {
                return Err(KubernetesDriverError::Precondition(
                    "Sandbox CR UID changed while waiting for stop".to_string(),
                ));
            }
            if let Some(error) = kubernetes_sandbox_stop_failure(&object) {
                return Err(KubernetesDriverError::Message(error));
            }
            let pod_is_gone = kubernetes_sandbox_pod_is_gone(&pod_api, &pod_name, deadline)
                .await
                .map_err(KubernetesDriverError::Message)?;
            let stop_is_complete = kubernetes_sandbox_stop_is_complete(
                &agent_sandbox_api.resource.version,
                &object,
                pod_is_gone,
            );
            if stop_is_complete {
                self.delete_sandbox_runtime_supervisor_pod_for_uid(sandbox_id, &namespace, &cr_uid)
                    .await?;
                if let Some(profile) = &self.confidential {
                    if let Err(error) = profile.store.deauthorize_workspace_key(&namespace, &cr_uid)
                    {
                        cleanup_errors
                            .push(format!("deauthorize confidential workspace key: {error}"));
                    }
                    if let Err(error) = profile.store.revoke_sandbox_uid(sandbox_id, &cr_uid) {
                        cleanup_errors
                            .push(format!("revoke confidential sandbox {sandbox_id}: {error}"));
                    }
                }
                let annotations = object.metadata.annotations.as_ref();
                if let Err(error) = self
                    .delete_sandbox_runtime_generation_secrets_for_pods(
                        sandbox_id,
                        &namespace,
                        sandbox_runtime_generation(&object).as_slice(),
                        annotations
                            .and_then(|a| a.get(ANNOTATION_SANDBOX_RUNTIME_WORKLOAD_UID))
                            .map(String::as_str),
                        annotations
                            .and_then(|a| a.get(ANNOTATION_SANDBOX_RUNTIME_SUPERVISOR_UID))
                            .map(String::as_str),
                    )
                    .await
                {
                    cleanup_errors.push(format!("retire old role-owned Secrets: {error}"));
                }
                if !cleanup_errors.is_empty() {
                    return Err(KubernetesDriverError::Message(cleanup_errors.join("; ")));
                }
                patch_dynamic_object_with_uid_retry(
                    &agent_sandbox_api.api,
                    &kube_name,
                    &cr_uid,
                    sandbox_runtime_suspension_completion_patch,
                )
                .await?;
                return Ok(());
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(KubernetesDriverError::Message(format!(
                    "timed out after {}s waiting for Kubernetes sandbox to stop",
                    stop_timeout.as_secs()
                )));
            }
            tokio::time::sleep(poll_interval.min(deadline.saturating_duration_since(now))).await;
            poll_interval = next_stop_poll_interval(poll_interval);
        }
    }

    #[tracing::instrument(
        name = "kubernetes.start_sandbox",
        skip_all,
        fields(
            otel.name = "kubernetes.start_sandbox",
            otel.status_code = tracing::field::Empty,
            sandbox.id = %sandbox_id,
        )
    )]
    pub async fn start_sandbox(
        &self,
        sandbox_id: &str,
        generation_id: &str,
        launch_authentication: &[u8],
        expected_runtime_identity: &str,
    ) -> Result<String, KubernetesDriverError> {
        let _lifecycle_guard = self.lifecycle_lock(sandbox_id).lock_owned().await;
        let span_status = openshell_otel::ErrorStatusGuard::current();
        let result = Box::pin(self.start_sandbox_runtime_generation(
            sandbox_id,
            generation_id,
            launch_authentication,
            expected_runtime_identity,
        ))
        .await;
        span_status.finish(result)
    }

    #[allow(clippy::similar_names)]
    async fn start_sandbox_runtime_generation(
        &self,
        sandbox_id: &str,
        encoded_generation: &str,
        encoded_authentication: &[u8],
        encoded_expected_runtime_identity: &str,
    ) -> Result<String, KubernetesDriverError> {
        // Read once per call so the whole generation stages, mounts, and
        // references the same bytes, and so a bundle that became unreadable
        // fails before any Service, Pod, or Secret is created.
        let upstream_proxy_ca_bundle =
            read_staged_upstream_proxy_ca_bundle(self.config.proxy_ca_bundle.as_deref()).await?;
        let generation = openshell_core::sandbox_generation::SandboxGenerationId::parse(
            encoded_generation.to_string(),
        )
        .map_err(|error| KubernetesDriverError::InvalidArgument(error.to_string()))?;
        let launch_authentication = decode_launch_authentication(encoded_authentication)?;
        let expected_runtime_identity =
            parse_kubernetes_runtime_identity(encoded_expected_runtime_identity)?;
        let lookup_api = self
            .supported_sandbox_api_for_lookup(self.client.clone())
            .await
            .map_err(KubernetesDriverError::Message)?;
        let selector = self.sandbox_lookup_selector(sandbox_id);
        let objects = lookup_api
            .api
            .list(&ListParams::default().labels(&selector))
            .await
            .map_err(KubernetesDriverError::from_kube)?
            .items;
        let mut object = select_expected_sandbox_runtime(objects, &expected_runtime_identity)?;
        self.admit_stored_resources(&object)
            .await
            .map_err(admission_error)?;
        if sandbox_runtime_bootstrap_in_progress(&object) {
            let phase = sandbox_runtime_bootstrap_phase(&object);
            if phase != Some(SandboxRuntimeBootstrapPhase::Suspending)
                && sandbox_runtime_bootstrap_operation(&object) != Some("restart")
            {
                return Err(KubernetesDriverError::Precondition(
                    "initial sandbox bootstrap has not completed; wait for reconciliation"
                        .to_string(),
                ));
            }
            if sandbox_runtime_generation(&object) == Some(generation.as_str())
                && sandbox_runtime_bootstrap_phase(&object)
                    == Some(SandboxRuntimeBootstrapPhase::Released)
            {
                let namespace = object
                    .metadata
                    .namespace
                    .as_deref()
                    .unwrap_or(&self.config.namespace);
                if sandbox_runtime_control_availability(&self.client, namespace, sandbox_id).await
                    == SandboxRuntimeControlAvailability::Available
                    && sandbox_runtime_bootstrap_is_ready_to_complete(&object)
                {
                    self.complete_sandbox_runtime_bootstrap(&lookup_api, &object)
                        .await;
                    let cr_uid = object.metadata.uid.as_deref().ok_or_else(|| {
                        KubernetesDriverError::Message("sandbox resource has no UID".to_string())
                    })?;
                    let supervisor_uid = required_sandbox_annotation(
                        &object,
                        ANNOTATION_SANDBOX_RUNTIME_SUPERVISOR_UID,
                    )?;
                    return Ok(kubernetes_runtime_identity(
                        namespace,
                        cr_uid,
                        &supervisor_uid,
                    ));
                }
            }

            // A retry adopts the durable generation identity, but reconstructs
            // its resources from a clean suspended state. This is safe even
            // after gateway replacement because launch credentials stay in
            // memory and are supplied again by the caller.
            self.stop_sandbox_inner(sandbox_id).await?;
            let refreshed = lookup_api
                .api
                .list(&ListParams::default().labels(&selector))
                .await
                .map_err(KubernetesDriverError::from_kube)?
                .items;
            object = select_expected_sandbox_runtime(refreshed, &expected_runtime_identity)?;
            self.admit_stored_resources(&object)
                .await
                .map_err(admission_error)?;
        }
        let namespace = object
            .metadata
            .namespace
            .clone()
            .unwrap_or_else(|| self.config.namespace.clone());
        let cr_name = object.metadata.name.as_deref().ok_or_else(|| {
            KubernetesDriverError::Message("sandbox resource has no name".to_string())
        })?;
        let cr_uid = object.metadata.uid.as_deref().ok_or_else(|| {
            KubernetesDriverError::Message("sandbox resource has no UID".to_string())
        })?;
        let sandbox_api = Self::agent_sandbox_api(
            self.client.clone(),
            &lookup_api.resource.version,
            &namespace,
        );
        let pods = Api::<Pod>::namespaced(self.client.clone(), &namespace);
        if pods
            .get_opt(cr_name)
            .await
            .map_err(KubernetesDriverError::from_kube)?
            .is_some()
        {
            if !encoded_authentication.is_empty() {
                // Gateway restart creates a fresh in-memory launch session.
                // Recreate both Pods so neither side retains credentials for
                // the gateway instance that was replaced.
                self.stop_sandbox_inner(sandbox_id).await?;
                return Box::pin(self.start_sandbox_runtime_generation(
                    sandbox_id,
                    encoded_generation,
                    encoded_authentication,
                    encoded_expected_runtime_identity,
                ))
                .await;
            }
            return Err(KubernetesDriverError::Precondition(
                "cannot rotate a running workload Pod; stop the sandbox first".to_string(),
            ));
        }

        let names = SandboxRuntimeNames::for_generation(sandbox_id, generation.as_str());
        let bootstrap_attempt = random_sandbox_runtime_token();
        let trusted_launch = self
            .confidential_profile()?
            .store
            .load_launch(sandbox_id, &namespace, cr_uid)
            .map_err(|error| {
                KubernetesDriverError::Precondition(format!("load trusted launch intent: {error}"))
            })?;
        let expected_workload = trusted_launch.workload_for_generation(
            &names.sandbox_secret,
            &self.generation_image_pull_secret_names(&names),
        );
        let persistent_workspace = expected_workload.spec.as_ref().is_some_and(|spec| {
            spec.volumes
                .iter()
                .flatten()
                .any(|v| v.persistent_volume_claim.is_some())
        });
        let child_env = self
            .confidential_profile()?
            .store
            .load_workload_environment(sandbox_id, &namespace, cr_uid)
            .map_err(|_| {
                KubernetesDriverError::Precondition(
                    "trusted workload environment is missing or invalid".to_string(),
                )
            })?;
        let workspace_key_uri = if persistent_workspace {
            Some(
                self.confidential_profile()?
                    .store
                    .plan_workspace_key(&namespace, cr_uid)
                    .map_err(|error| KubernetesDriverError::Precondition(error.to_string()))?
                    .resource_uri,
            )
        } else {
            None
        };
        let mut supervisor_keys = SUPERVISOR_KEYS.to_vec();
        supervisor_keys.push("client-ca.crt");
        if upstream_proxy_ca_bundle.is_some() {
            supervisor_keys.push("upstream-proxy-ca.pem");
        }
        let supervisor_initdata = self.render_confidential_initdata(
            BootstrapRole::Supervisor,
            generation.as_str(),
            sandbox_id,
            cr_uid,
            &bootstrap_attempt,
            &namespace,
            &supervisor_keys,
            None,
            None,
        )?;
        let workload_initdata = self.render_confidential_initdata(
            BootstrapRole::Workload,
            generation.as_str(),
            sandbox_id,
            cr_uid,
            &bootstrap_attempt,
            &namespace,
            WORKLOAD_KEYS,
            workspace_key_uri.as_deref(),
            None,
        )?;
        // A resourceVersion precondition elects one concurrent restart as the
        // owner of this attempt before it may create Pods or publish KBS data.
        let current = sandbox_api
            .api
            .get(cr_name)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        if current.metadata.uid.as_deref() != Some(cr_uid) {
            return Err(KubernetesDriverError::Precondition(
                "Sandbox CR UID changed before bootstrap attempt CAS".to_string(),
            ));
        }
        let expected_old_attempt = object
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(ANNOTATION_CONFIDENTIAL_BOOTSTRAP_ATTEMPT));
        let actual_old_attempt = current
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(ANNOTATION_CONFIDENTIAL_BOOTSTRAP_ATTEMPT));
        if actual_old_attempt != expected_old_attempt {
            return Err(KubernetesDriverError::Precondition(
                "confidential bootstrap attempt changed concurrently".to_string(),
            ));
        }
        let resource_version = current.metadata.resource_version.ok_or_else(|| {
            KubernetesDriverError::Precondition("Sandbox CR lacks resourceVersion".to_string())
        })?;
        let elected = sandbox_api
            .api
            .patch(
                cr_name,
                &PatchParams::default(),
                &Patch::Merge(&serde_json::json!({
                    "metadata": {
                        "resourceVersion": resource_version,
                        "annotations": {
                            ANNOTATION_CONFIDENTIAL_BOOTSTRAP_ATTEMPT: bootstrap_attempt,
                        }
                    }
                })),
            )
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        if elected.metadata.uid.as_deref() != Some(cr_uid) {
            return Err(KubernetesDriverError::Precondition(
                "Sandbox CR UID changed during bootstrap attempt CAS".to_string(),
            ));
        }
        self.confidential_profile()?
            .store
            .revoke_owned_sandbox(sandbox_id, Some(cr_uid))
            .map_err(|error| {
                KubernetesDriverError::Message(format!("revoke prior trusted attempts: {error}"))
            })?;
        self.confidential_profile()?
            .store
            .record_attempt(
                sandbox_id,
                &namespace,
                cr_uid,
                generation.as_str(),
                &bootstrap_attempt,
            )
            .map_err(|error| {
                KubernetesDriverError::Precondition(format!(
                    "record trusted restart attempt: {error}"
                ))
            })?;
        // Only the resourceVersion CAS winner may remove old resources or
        // revoke old bindings. A losing restart must not delete its winner.
        self.create_sandbox_runtime_fence(&namespace, &names)
            .await?;
        self.delete_sandbox_runtime_supervisor_pod_for_uid(sandbox_id, &namespace, cr_uid)
            .await?;
        let prior_annotations = object.metadata.annotations.as_ref();
        let mut cleanup_generations = sandbox_runtime_generation(&object).as_slice().to_vec();
        cleanup_generations.push(generation.as_str());
        self.delete_sandbox_runtime_generation_secrets_for_pods(
            sandbox_id,
            &namespace,
            &cleanup_generations,
            prior_annotations
                .and_then(|a| a.get(ANNOTATION_SANDBOX_RUNTIME_WORKLOAD_UID))
                .map(String::as_str),
            prior_annotations
                .and_then(|a| a.get(ANNOTATION_SANDBOX_RUNTIME_SUPERVISOR_UID))
                .map(String::as_str),
        )
        .await?;
        let main_process_spec = trusted_launch.main_process_spec.clone();
        let log_level = trusted_launch.log_level.clone();
        let sandbox_name = trusted_launch.sandbox_name.clone();
        let (agent_uid, agent_gid) = (trusted_launch.agent_uid, trusted_launch.agent_gid);
        let expected_supervisor = supervisor_pod(
            &namespace,
            &names,
            sandbox_id,
            &sandbox_name,
            &self.config.gateway_id,
            &self.config.supervisor_image,
            self.config.supervisor_image_pull_policy,
            &self.config.service_account_name,
            agent_uid,
            agent_gid,
            &self.generation_image_pull_secret_names(&names),
            &self.config.grpc_endpoint,
            self.supervisor_client_tls(),
            &main_process_spec,
            &log_level,
            self.config.effective_sa_token_ttl_secs(),
            self.config.https_proxy.as_deref(),
            self.config.no_proxy.as_deref(),
            self.config
                .proxy_auth_secret_name
                .as_deref()
                .zip(self.config.proxy_auth_secret_key.as_deref()),
            self.config.proxy_auth_allow_insecure == Some(true),
            self.config.proxy_connect_by_hostname == Some(true),
            upstream_proxy_ca_bundle.is_some(),
            self.config.provider_spiffe_enabled().then_some(
                self.config
                    .provider_spiffe_workload_api_socket_path
                    .as_str(),
            ),
            sandbox_runtime_sandbox_owner_reference(
                cr_name,
                cr_uid,
                &sandbox_api.resource.api_version,
                false,
            ),
            &self.supervisor_tracing_environment(),
        )
        .map(|mut pod| {
            pod.spec
                .as_mut()
                .expect("supervisor Pod has a spec")
                .runtime_class_name = Some(self.config.default_runtime_class_name.clone());
            pod.metadata
                .annotations
                .get_or_insert_with(BTreeMap::new)
                .insert(
                    INITDATA_ANNOTATION.to_string(),
                    supervisor_initdata.annotation.clone(),
                );
            pod
        })
        .map_err(KubernetesDriverError::Message)?;
        let supervisor = pods
            .create(&PostParams::default(), &expected_supervisor)
            .await
            .map_err(KubernetesDriverError::from_kube)?;
        let supervisor_uid = supervisor.metadata.uid.ok_or_else(|| {
            KubernetesDriverError::Message("replacement supervisor Pod has no UID".to_string())
        })?;

        let trusted_template = serde_json::to_value(&expected_workload)
            .map_err(|error| KubernetesDriverError::Message(error.to_string()))?;
        let restart = async {
            patch_dynamic_object_with_uid_retry(
                &sandbox_api.api,
                cr_name,
                cr_uid,
                |version| {
                    let mut running_patch =
                        sandbox_operating_state_patch(&sandbox_api.resource.version, version, true);
                    running_patch["metadata"]["annotations"] = serde_json::json!({
                        ANNOTATION_CONFIDENTIAL_BOOTSTRAP_ATTEMPT: bootstrap_attempt,
                        ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAPPING: "true",
                        ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_STARTED_AT: openshell_core::time::now_ms().to_string(),
                        ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_OPERATION: "restart",
                        ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_PHASE: SandboxRuntimeBootstrapPhase::Preparing.as_str(),
                        ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_SESSION: launch_authentication.supervisor.session_id.to_string(),
                        ANNOTATION_SANDBOX_RUNTIME_GENERATION: generation.as_str(),
                        ANNOTATION_SANDBOX_RUNTIME_SUPERVISOR_UID: supervisor_uid.clone(),
                    });
                    running_patch["spec"]["podTemplate"] = trusted_template.clone();
                    running_patch["spec"]["podTemplate"].as_object_mut().unwrap().remove("apiVersion");
                    running_patch["spec"]["podTemplate"].as_object_mut().unwrap().remove("kind");
                    running_patch["spec"]["volumeClaimTemplates"] = trusted_launch.volume_claim_templates.clone();
                    // Claim volumes are added by the Sandbox controller, not its template.
                    if let Some(claims) = trusted_launch.volume_claim_templates.as_array() {
                        let claim_names: Vec<_> = claims.iter().filter_map(|c| c["metadata"]["name"].as_str()).collect();
                        if let Some(volumes) = running_patch["spec"]["podTemplate"]["spec"]["volumes"].as_array_mut() {
                            volumes.retain(|v| !claim_names.contains(&v["name"].as_str().unwrap_or_default()));
                        }
                    }
                    running_patch["spec"]["podTemplate"]["metadata"]["annotations"]
                        [INITDATA_ANNOTATION] = serde_json::json!(workload_initdata.annotation);
                    running_patch
                },
            )
            .await?;

            self.install_sandbox_runtime_generation(
                &namespace,
                cr_name,
                &sandbox_api,
                sandbox_id,
                cr_uid,
                &names,
                generation.as_str(),
                &bootstrap_attempt,
                persistent_workspace,
                &supervisor_uid,
                &expected_supervisor,
                agent_uid,
                agent_gid,
                child_env,
                &launch_authentication,
            )
            .await
        }
        .await;

        if let Err(error) = restart {
            if let Err(rollback_error) = self.stop_sandbox_inner(sandbox_id).await {
                return Err(KubernetesDriverError::Message(format!(
                    "restart failed: {error}; rollback remains pending: {rollback_error}"
                )));
            }
            return Err(error);
        }
        Ok(kubernetes_runtime_identity(
            &namespace,
            cr_uid,
            &supervisor_uid,
        ))
    }

    async fn prepare_sandbox_stop(
        &self,
        sandbox_id: &str,
    ) -> Result<
        (
            AgentSandboxApi,
            String,
            String,
            String,
            String,
            Duration,
            Option<SandboxRuntimeBootstrapPhase>,
        ),
        KubernetesDriverError,
    > {
        let lookup_api = self
            .supported_sandbox_api_for_lookup(self.client.clone())
            .await
            .map_err(KubernetesDriverError::Message)?;
        let selector = self.sandbox_lookup_selector(sandbox_id);
        let list = tokio::time::timeout(
            KUBE_API_TIMEOUT,
            lookup_api
                .api
                .list(&ListParams::default().labels(&selector)),
        )
        .await
        .map_err(|_| {
            KubernetesDriverError::Message(format!(
                "timed out after {}s waiting for Kubernetes API",
                KUBE_API_TIMEOUT.as_secs()
            ))
        })?
        .map_err(KubernetesDriverError::from_kube)?;
        let object = list
            .items
            .into_iter()
            .next()
            .ok_or(KubernetesDriverError::NotFound)?;
        let cr_uid = object.metadata.uid.clone().ok_or_else(|| {
            KubernetesDriverError::Precondition("Sandbox CR lacks UID during stop".to_string())
        })?;
        let phase = sandbox_runtime_bootstrap_phase(&object);
        let namespace = object
            .metadata
            .namespace
            .clone()
            .unwrap_or_else(|| self.config.namespace.clone());
        let agent_sandbox_api = Self::agent_sandbox_api(
            self.client.clone(),
            &lookup_api.resource.version,
            &namespace,
        );
        let stop_timeout = kubernetes_sandbox_stop_timeout(&object);
        let kube_name = object.metadata.name.clone().ok_or_else(|| {
            KubernetesDriverError::Message("sandbox resource has no name".to_string())
        })?;
        let pod_name = object
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(SANDBOX_POD_NAME_ANNOTATION))
            .cloned()
            .unwrap_or_else(|| kube_name.clone());
        if !matches!(
            phase,
            Some(
                SandboxRuntimeBootstrapPhase::Releasing | SandboxRuntimeBootstrapPhase::Suspending
            )
        ) {
            patch_dynamic_object_with_uid_retry(
                &agent_sandbox_api.api,
                &kube_name,
                &cr_uid,
                sandbox_runtime_stop_begin_patch,
            )
            .await?;
        }

        info!(
            sandbox_id,
            sandbox_api_version = %agent_sandbox_api.resource.version,
            "Prepared Kubernetes sandbox stop"
        );
        Ok((
            agent_sandbox_api,
            kube_name,
            pod_name,
            namespace,
            cr_uid,
            stop_timeout,
            phase,
        ))
    }

    async fn delete_sandbox_runtime_supervisor_pod_for_uid(
        &self,
        sandbox_id: &str,
        namespace: &str,
        cr_uid: &str,
    ) -> Result<(), KubernetesDriverError> {
        let names = SandboxRuntimeNames::new(sandbox_id);
        let pods = Api::<Pod>::namespaced(self.client.clone(), namespace);
        if let Some(pod) = pods
            .get_opt(&names.supervisor_pod)
            .await
            .map_err(KubernetesDriverError::from_kube)?
        {
            if !pod
                .metadata
                .owner_references
                .as_deref()
                .unwrap_or_default()
                .iter()
                .any(|owner| owner.uid == cr_uid && owner.kind == "Sandbox")
            {
                return Err(KubernetesDriverError::Precondition(
                    "supervisor Pod belongs to a different Sandbox CR UID".to_string(),
                ));
            }
            let deletion_timeout = kubernetes_pod_termination_timeout(&pod);
            match pods
                .delete(
                    &names.supervisor_pod,
                    &DeleteParams::foreground().preconditions(Preconditions {
                        uid: pod.metadata.uid,
                        resource_version: None,
                    }),
                )
                .await
            {
                Ok(_) => {}
                Err(KubeError::Api(error)) if error.code == 404 => return Ok(()),
                Err(error) => return Err(KubernetesDriverError::from_kube(error)),
            }
            let deadline = tokio::time::Instant::now() + deletion_timeout;
            loop {
                if pods
                    .get_opt(&names.supervisor_pod)
                    .await
                    .map_err(KubernetesDriverError::from_kube)?
                    .is_none()
                {
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(KubernetesDriverError::Message(format!(
                        "timed out after {}s waiting for supervisor Pod deletion",
                        deletion_timeout.as_secs()
                    )));
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        Ok(())
    }

    /// Remove only Secrets owned by the original role Pod UIDs. A replacement
    /// generation can reuse the same first-12-character name, so the Secret's
    /// own UID also fences the DELETE and we wait until the name is absent.
    async fn delete_sandbox_runtime_generation_secrets_for_pods(
        &self,
        sandbox_id: &str,
        namespace: &str,
        generations: &[&str],
        workload_pod_uid: Option<&str>,
        supervisor_pod_uid: Option<&str>,
    ) -> Result<(), KubernetesDriverError> {
        let secrets = Api::<Secret>::namespaced(self.client.clone(), namespace);
        let mut targets = BTreeMap::<String, Vec<&str>>::new();
        for generation in generations {
            let names = SandboxRuntimeNames::for_generation(sandbox_id, generation);
            targets.insert(
                names.sandbox_secret.clone(),
                workload_pod_uid.into_iter().collect(),
            );
            targets.insert(
                names.supervisor_secret.clone(),
                supervisor_pod_uid.into_iter().collect(),
            );
            if self.config.workspace_mode == WorkspaceMode::Managed {
                for name in names.image_pull_secrets(self.config.image_pull_secrets.len()) {
                    targets.insert(
                        name,
                        workload_pod_uid
                            .into_iter()
                            .chain(supervisor_pod_uid)
                            .collect(),
                    );
                }
            }
        }
        for (name, expected_owners) in targets {
            let Some(secret) = secrets
                .get_opt(&name)
                .await
                .map_err(KubernetesDriverError::from_kube)?
            else {
                continue;
            };
            let owners = secret
                .metadata
                .owner_references
                .as_deref()
                .unwrap_or_default();
            let expected_set: std::collections::BTreeSet<&str> =
                expected_owners.iter().copied().collect();
            let actual_set: std::collections::BTreeSet<&str> =
                owners.iter().map(|owner| owner.uid.as_str()).collect();
            if expected_owners.is_empty()
                || owners.len() != expected_owners.len()
                || actual_set != expected_set
                || owners.iter().any(|owner| owner.kind != "Pod")
            {
                return Err(KubernetesDriverError::Precondition(format!(
                    "generation Secret {name} is not owned by the old role Pod UIDs"
                )));
            }
            let secret_uid = secret.metadata.uid.ok_or_else(|| {
                KubernetesDriverError::Precondition(format!("generation Secret {name} lacks UID"))
            })?;
            match secrets
                .delete(
                    &name,
                    &DeleteParams::default().preconditions(Preconditions {
                        uid: Some(secret_uid.clone()),
                        resource_version: None,
                    }),
                )
                .await
            {
                Ok(_) | Err(KubeError::Api(kube::core::ErrorResponse { code: 404, .. })) => {}
                Err(error) => return Err(KubernetesDriverError::from_kube(error)),
            }
            let deadline = tokio::time::Instant::now() + KUBE_API_TIMEOUT;
            loop {
                match secrets
                    .get_opt(&name)
                    .await
                    .map_err(KubernetesDriverError::from_kube)?
                {
                    None => break,
                    Some(current) if current.metadata.uid.as_deref() != Some(&secret_uid) => {
                        return Err(KubernetesDriverError::Precondition(format!(
                            "generation Secret {name} was replaced during cleanup"
                        )));
                    }
                    Some(_) if tokio::time::Instant::now() >= deadline => {
                        return Err(KubernetesDriverError::Message(format!(
                            "timed out waiting for generation Secret {name} deletion"
                        )));
                    }
                    Some(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                }
            }
        }
        Ok(())
    }

    #[tracing::instrument(
        name = "kubernetes.delete_sandbox",
        skip(self),
        fields(
            otel.name = "kubernetes.delete_sandbox",
            otel.status_code = tracing::field::Empty,
            sandbox.id = %sandbox_id,
        )
    )]
    pub async fn delete_sandbox(&self, sandbox_id: &str) -> Result<bool, String> {
        let _lifecycle_guard = self.lifecycle_lock(sandbox_id).lock_owned().await;
        let span_status = openshell_otel::ErrorStatusGuard::current();
        let result = self.delete_sandbox_inner(sandbox_id, None).await;
        span_status.finish(result)
    }

    async fn sandbox_runtime_role_pods_absent(&self, sandbox_id: &str) -> Result<bool, String> {
        let pods = if self.config.is_multi_namespace() {
            Api::<Pod>::all(self.client.clone())
        } else {
            Api::<Pod>::namespaced(self.client.clone(), &self.config.namespace)
        };
        let selector = format!(
            "{BOUNDARY_PAIR_LABEL}={}",
            crate::sandbox_runtime::pair_label_value(sandbox_id)
        );
        let list = tokio::time::timeout(
            KUBE_API_TIMEOUT,
            pods.list(&ListParams::default().labels(&selector)),
        )
        .await
        .map_err(|_| "timed out verifying Sandbox role Pod deletion".to_string())?
        .map_err(|error| format!("verify Sandbox role Pod deletion: {error}"))?;
        Ok(list.items.is_empty())
    }

    async fn deleted_cr_role_pods_absent(&self, marker: &PendingDelete) -> Result<bool, String> {
        let pods = Api::<Pod>::namespaced(self.client.clone(), &marker.namespace);
        let selector = format!(
            "{BOUNDARY_PAIR_LABEL}={}",
            crate::sandbox_runtime::pair_label_value(&marker.sandbox_id)
        );
        let list = tokio::time::timeout(
            KUBE_API_TIMEOUT,
            pods.list(&ListParams::default().labels(&selector)),
        )
        .await
        .map_err(|_| "timed out verifying old Sandbox role Pod deletion".to_string())?
        .map_err(|error| format!("verify old Sandbox role Pod deletion: {error}"))?;
        Ok(list.items.iter().all(|pod| {
            pod.metadata
                .owner_references
                .as_ref()
                .is_some_and(|owners| {
                    owners
                        .iter()
                        .all(|owner| owner.uid != marker.sandbox_cr_uid)
                })
        }))
    }

    fn withdraw_sandbox_authorization_for_delete(
        &self,
        marker: &PendingDelete,
    ) -> Result<(), String> {
        let mut errors = Vec::new();
        if let Some(profile) = &self.confidential
            && let Err(error) = profile.store.revoke_pending_delete(marker)
        {
            errors.push(format!(
                "revoke confidential sandbox {}: {error}",
                marker.sandbox_id
            ));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    async fn delete_sandbox_inner(
        &self,
        sandbox_id: &str,
        expected_cr_uid: Option<&str>,
    ) -> Result<bool, String> {
        info!(
            sandbox_id = %sandbox_id,
            workspace_mode = %self.config.workspace_mode,
            "Deleting sandbox from Kubernetes"
        );

        let lookup_api = self
            .supported_sandbox_api_for_lookup(self.client.clone())
            .await?;
        let selector = self.sandbox_lookup_selector(sandbox_id);
        let lp = ListParams::default().labels(&selector);
        let (kube_name, obj_namespace, mut preconditions, pod_name, current_attempt) =
            match tokio::time::timeout(KUBE_API_TIMEOUT, lookup_api.api.list(&lp)).await {
                Ok(Ok(list)) => {
                    if let Some(obj) = list.items.into_iter().next() {
                        match obj.metadata.name.clone() {
                            Some(name) => {
                                let ns = obj
                                    .metadata
                                    .namespace
                                    .clone()
                                    .unwrap_or_else(|| self.config.namespace.clone());
                                if expected_cr_uid.is_some_and(|expected| {
                                    obj.metadata.uid.as_deref() != Some(expected)
                                }) {
                                    return Err("Sandbox CR was replaced during deletion; retry ownership review".to_string());
                                }
                                let pc = Preconditions {
                                    uid: obj.metadata.uid.clone(),
                                    resource_version: obj.metadata.resource_version.clone(),
                                };
                                let current_attempt = obj
                                    .metadata
                                    .annotations
                                    .as_ref()
                                    .and_then(|annotations| {
                                        annotations.get(ANNOTATION_CONFIDENTIAL_BOOTSTRAP_ATTEMPT)
                                    })
                                    .and_then(|attempt| {
                                        sandbox_runtime_generation(&obj).map(|generation| {
                                            (generation.to_owned(), attempt.to_owned())
                                        })
                                    });
                                let pod_name = obj
                                    .metadata
                                    .annotations
                                    .as_ref()
                                    .and_then(|annotations| {
                                        annotations.get(SANDBOX_POD_NAME_ANNOTATION)
                                    })
                                    .cloned()
                                    .unwrap_or_else(|| name.clone());
                                (name, ns, pc, pod_name, current_attempt)
                            }
                            None => return Ok(false),
                        }
                    } else {
                        debug!(sandbox_id = %sandbox_id, "Sandbox not found in Kubernetes (already deleted)");
                        let mut cleanup_errors = Vec::new();
                        let mut markers = Vec::new();
                        if let Some(profile) = &self.confidential {
                            markers = profile
                                .store
                                .pending_deletes()
                                .map_err(|error| error.to_string())?
                                .into_iter()
                                .filter(|marker| marker.sandbox_id == sandbox_id)
                                .collect();
                            for owner in profile
                                .store
                                .workspace_owners()
                                .map_err(|error| error.to_string())?
                                .into_iter()
                                .filter(|owner| owner.sandbox_id == sandbox_id)
                            {
                                if !markers.iter().any(|marker: &PendingDelete| {
                                    marker.namespace == owner.namespace
                                        && marker.sandbox_cr_uid == owner.sandbox_cr_uid
                                }) {
                                    markers.push(
                                        profile
                                            .store
                                            .begin_delete(
                                                sandbox_id,
                                                &owner.namespace,
                                                &owner.sandbox_cr_uid,
                                                None,
                                            )
                                            .map_err(|error| error.to_string())?,
                                    );
                                }
                            }
                            for marker in &markers {
                                if let Err(error) =
                                    self.withdraw_sandbox_authorization_for_delete(marker)
                                {
                                    cleanup_errors.push(error);
                                }
                            }
                        }
                        match self.sandbox_runtime_role_pods_absent(sandbox_id).await {
                            Ok(true) => {}
                            Ok(false) => cleanup_errors
                                .push("Sandbox role Pod deletion was not confirmed".to_string()),
                            Err(error) => cleanup_errors.push(error),
                        }
                        return if cleanup_errors.is_empty() {
                            if let Some(profile) = &self.confidential {
                                for marker in &markers {
                                    profile
                                        .store
                                        .finish_delete(marker)
                                        .map_err(|error| error.to_string())?;
                                }
                            }
                            Ok(false)
                        } else {
                            Err(cleanup_errors.join("; "))
                        };
                    }
                }
                Ok(Err(err)) => {
                    warn!(
                        sandbox_id = %sandbox_id,
                        error = %err,
                        "Failed to list sandbox for deletion from Kubernetes"
                    );
                    return Err(err.to_string());
                }
                Err(_elapsed) => {
                    warn!(
                        sandbox_id = %sandbox_id,
                        timeout_secs = KUBE_API_TIMEOUT.as_secs(),
                        "Timed out listing sandbox for deletion from Kubernetes"
                    );
                    return Err(format!(
                        "timed out after {}s waiting for Kubernetes API",
                        KUBE_API_TIMEOUT.as_secs()
                    ));
                }
            };

        if preconditions.uid.is_none() {
            return Err("Sandbox CR lacks UID; cannot confirm deletion ownership".to_string());
        }
        let cr_uid = preconditions.uid.clone();
        let delete_api = self
            .supported_agent_sandbox_api(self.client.clone(), &obj_namespace)
            .await?;
        let observed = tokio::time::timeout(KUBE_API_TIMEOUT, delete_api.api.get(&kube_name))
            .await
            .map_err(|_| "timed out verifying Sandbox CR before deletion".to_string())?
            .map_err(|error| format!("verify Sandbox CR before deletion: {error}"))?;
        if observed.metadata.uid != cr_uid {
            return Err(
                "Sandbox CR was replaced during deletion; retry ownership review".to_string(),
            );
        }
        if let Some(resource_version) = observed.metadata.resource_version {
            preconditions.resource_version = Some(resource_version);
        }
        let marker = if let Some(profile) = &self.confidential {
            let cr_uid = cr_uid.as_deref().expect("checked Sandbox CR UID");
            profile
                .store
                .record_workspace_owner(sandbox_id, &obj_namespace, cr_uid)
                .map_err(|error| {
                    format!("record confidential sandbox owner before delete: {error}")
                })?;
            let marker = profile
                .store
                .begin_delete(
                    sandbox_id,
                    &obj_namespace,
                    cr_uid,
                    current_attempt
                        .as_ref()
                        .map(|(generation, attempt)| (generation.as_str(), attempt.as_str())),
                )
                .map_err(|error| format!("fence confidential sandbox deletion: {error}"))?;
            self.withdraw_sandbox_authorization_for_delete(&marker)?;
            Some(marker)
        } else {
            None
        };
        let mut conflict_retries = 0;
        loop {
            let dp = DeleteParams::default().preconditions(preconditions.clone());
            return match tokio::time::timeout(
                KUBE_API_TIMEOUT,
                delete_api.api.delete(&kube_name, &dp),
            )
            .await
            {
                Ok(Ok(_response)) => {
                    info!(sandbox_id = %sandbox_id, namespace = %obj_namespace, "Sandbox deleted from Kubernetes");
                    {
                        let pod_api = Api::<Pod>::namespaced(self.client.clone(), &obj_namespace);
                        let supervisor_pod_name =
                            SandboxRuntimeNames::new(sandbox_id).supervisor_pod;
                        let deadline = tokio::time::Instant::now()
                            + DEFAULT_POD_TERMINATION_GRACE_PERIOD
                            + KUBE_API_TIMEOUT;
                        wait_for_sandbox_role_pods_deleted(
                            &pod_api,
                            &pod_name,
                            &supervisor_pod_name,
                            deadline,
                        )
                        .await?;
                        // API acceptance of DELETE does not mean the CR is gone.
                        // Keep the unowned fence while finalizers can still leave
                        // the controller able to reconcile a workload Pod.
                        if !matches!(
                            tokio::time::timeout(KUBE_API_TIMEOUT, delete_api.api.get(&kube_name))
                                .await,
                            Ok(Err(KubeError::Api(kube::core::ErrorResponse {
                                code: 404,
                                ..
                            })))
                        ) {
                            warn!(sandbox_id, "Sandbox CR deletion was not confirmed");
                            return Err("Sandbox CR deletion was not confirmed".to_string());
                        }
                    }
                    if !self.sandbox_runtime_role_pods_absent(sandbox_id).await? {
                        return Err("Sandbox role Pod deletion was not confirmed".to_string());
                    }
                    if let (Some(profile), Some(marker)) = (&self.confidential, marker.as_ref()) {
                        profile
                            .store
                            .finish_delete(marker)
                            .map_err(|error| error.to_string())?;
                    }
                    Ok(true)
                }
                Ok(Err(KubeError::Api(err))) if err.code == 404 => {
                    debug!(sandbox_id = %sandbox_id, "Sandbox not found in Kubernetes (already deleted)");
                    if !self.sandbox_runtime_role_pods_absent(sandbox_id).await? {
                        return Err("Sandbox role Pod deletion was not confirmed".to_string());
                    }
                    if let (Some(profile), Some(marker)) = (&self.confidential, marker.as_ref()) {
                        profile
                            .store
                            .finish_delete(marker)
                            .map_err(|error| error.to_string())?;
                    }
                    Ok(false)
                }
                Ok(Err(KubeError::Api(err))) if err.code == 409 && err.reason == "Conflict" => {
                    match tokio::time::timeout(KUBE_API_TIMEOUT, delete_api.api.get(&kube_name))
                        .await
                    {
                        Ok(Ok(current)) if current.metadata.uid != cr_uid => Err(
                            "Sandbox CR was replaced during deletion; retry ownership review"
                                .to_string(),
                        ),
                        Ok(Err(KubeError::Api(get_err))) if get_err.code == 404 => {
                            if !self.sandbox_runtime_role_pods_absent(sandbox_id).await? {
                                return Err(
                                    "Sandbox role Pod deletion was not confirmed".to_string()
                                );
                            }
                            if let (Some(profile), Some(marker)) =
                                (&self.confidential, marker.as_ref())
                            {
                                profile
                                    .store
                                    .finish_delete(marker)
                                    .map_err(|error| error.to_string())?;
                            }
                            Ok(false)
                        }
                        Ok(Ok(current)) => {
                            let Some(next_version) = current.metadata.resource_version else {
                                break Err(
                                    "Sandbox CR lacks resourceVersion after delete conflict"
                                        .to_string(),
                                );
                            };
                            if preconditions.resource_version.as_deref() == Some(&next_version) {
                                break Err(
                                    "Sandbox CR delete conflict without a newer resourceVersion"
                                        .to_string(),
                                );
                            }
                            if conflict_retries == SANDBOX_DELETE_CONFLICT_RETRIES {
                                break Err(format!(
                                    "Sandbox CR kept changing during deletion after {SANDBOX_DELETE_CONFLICT_RETRIES} retries; pending delete remains fenced"
                                ));
                            }
                            preconditions.resource_version = Some(next_version);
                            conflict_retries += 1;
                            continue;
                        }
                        Ok(Err(get_err)) => Err(format!(
                            "verify Sandbox CR after delete conflict: {get_err}"
                        )),
                        Err(_) => {
                            Err("timed out verifying Sandbox CR after delete conflict".to_string())
                        }
                    }
                }
                Ok(Err(err)) => {
                    warn!(
                        sandbox_id = %sandbox_id,
                        error = %err,
                        "Failed to delete sandbox from Kubernetes"
                    );
                    Err(err.to_string())
                }
                Err(_elapsed) => {
                    warn!(
                        sandbox_id = %sandbox_id,
                        timeout_secs = KUBE_API_TIMEOUT.as_secs(),
                        "Timed out deleting sandbox from Kubernetes"
                    );
                    Err(format!(
                        "timed out after {}s waiting for Kubernetes API",
                        KUBE_API_TIMEOUT.as_secs()
                    ))
                }
            };
        }
    }

    pub async fn sandbox_exists(&self, sandbox_id: &str) -> Result<bool, String> {
        let agent_sandbox_api = self
            .supported_sandbox_api_for_lookup(self.client.clone())
            .await?;
        let selector = self.sandbox_lookup_selector(sandbox_id);
        let lp = ListParams::default().labels(&selector);
        match tokio::time::timeout(KUBE_API_TIMEOUT, agent_sandbox_api.api.list(&lp)).await {
            Ok(Ok(list)) => Ok(!list.items.is_empty()),
            Ok(Err(err)) => Err(err.to_string()),
            Err(_elapsed) => Err(format!(
                "timed out after {}s waiting for Kubernetes API",
                KUBE_API_TIMEOUT.as_secs()
            )),
        }
    }

    /// Repair lifecycle drift and reap unowned workload fences while the
    /// gateway's sandbox watch is alive. Bootstrap material is immutable and
    /// intentionally not read by the gateway, so this pass only repairs state
    /// that can be proven from the Sandbox CR and named companion objects.
    async fn reconcile_pending_sandbox_deletions(&self) {
        let Some(profile) = &self.confidential else {
            return;
        };
        match profile.store.pending_revocations() {
            Ok(owners) => {
                for owner in owners {
                    let Ok(_guard) = self.lifecycle_lock(&owner.sandbox_id).try_lock_owned() else {
                        continue;
                    };
                    if let Err(error) = profile
                        .store
                        .revoke_owned_sandbox(&owner.sandbox_id, Some(&owner.sandbox_cr_uid))
                    {
                        warn!(sandbox_id = %owner.sandbox_id, %error, "authorization revocation remains pending");
                    }
                }
            }
            Err(error) => warn!(%error, "cannot inspect pending authorization revocations"),
        }
        let pending = match profile.store.pending_deletes() {
            Ok(pending) => pending,
            Err(error) => {
                warn!(%error, "cannot inspect pending confidential deletions");
                return;
            }
        };
        let mut targets = std::collections::BTreeSet::new();
        let mut pending_ids = std::collections::BTreeSet::new();
        for marker in pending {
            // Withdrawing private resources must not depend on Kubernetes API
            // availability. A previous renderer or filesystem failure may
            // have left a marker while its raw resources were still served.
            if let Err(error) = self.withdraw_sandbox_authorization_for_delete(&marker) {
                warn!(sandbox_id = %marker.sandbox_id, %error, "confidential deletion authorization remains pending");
            }
            pending_ids.insert(marker.sandbox_id.clone());
            targets.insert((marker.sandbox_id, Some(marker.sandbox_cr_uid)));
        }
        // Older crashes or out-of-band CR deletion may leave an owner record
        // without a pending marker. Only select it when no CR with this
        // Sandbox ID exists; an active replacement UID must not be deleted.
        let lookup_api = match self
            .supported_sandbox_api_for_lookup(self.client.clone())
            .await
        {
            Ok(api) => api,
            Err(error) => {
                warn!(%error, "cannot inspect orphaned confidential sandbox owners");
                return;
            }
        };
        let live = match lookup_api
            .api
            .list(&ListParams::default().labels(&self.openshell_sandbox_selector()))
            .await
        {
            Ok(list) => list,
            Err(error) => {
                warn!(%error, "cannot list Sandbox CRs for confidential delete recovery");
                return;
            }
        };
        let live_ids: std::collections::BTreeSet<String> = live
            .items
            .iter()
            .filter_map(|object| sandbox_id_from_object(object).ok())
            .collect();
        match profile.store.workspace_owners() {
            Ok(owners) => {
                for owner in owners {
                    if !live_ids.contains(&owner.sandbox_id)
                        && !pending_ids.contains(&owner.sandbox_id)
                    {
                        targets.insert((owner.sandbox_id, None));
                    }
                }
            }
            Err(error) => warn!(%error, "cannot inspect confidential sandbox owner index"),
        }
        for (sandbox_id, expected_uid) in targets {
            let Ok(_guard) = self.lifecycle_lock(&sandbox_id).try_lock_owned() else {
                continue;
            };
            if let Err(error) = self
                .delete_sandbox_inner(&sandbox_id, expected_uid.as_deref())
                .await
            {
                if error.contains("replaced during deletion") {
                    // The old UID may no longer own the CR name. Retire only
                    // its frozen bindings; never delete the replacement.
                    for marker in profile
                        .store
                        .pending_deletes()
                        .unwrap_or_default()
                        .into_iter()
                        .filter(|marker| {
                            marker.sandbox_id == sandbox_id
                                && expected_uid.as_deref() == Some(marker.sandbox_cr_uid.as_str())
                        })
                    {
                        match self.withdraw_sandbox_authorization_for_delete(&marker) {
                            Ok(()) => match self.deleted_cr_role_pods_absent(&marker).await {
                                Ok(true) => {
                                    if let Err(finish_error) = profile.store.finish_delete(&marker)
                                    {
                                        warn!(sandbox_id, %finish_error, "could not finish old UID deletion fence");
                                    }
                                }
                                Ok(false) => warn!(
                                    sandbox_id,
                                    "old UID role Pod still exists; retaining deletion fence"
                                ),
                                Err(verify_error) => {
                                    warn!(sandbox_id, %verify_error, "could not verify old UID Pod deletion");
                                }
                            },
                            Err(withdraw_error) => {
                                warn!(sandbox_id, %withdraw_error, "could not retire old UID deletion fence");
                            }
                        }
                    }
                } else {
                    warn!(sandbox_id, %error, "confidential deletion remains pending");
                }
            }
        }
    }

    async fn reconcile_sandbox_runtime_resources(&self) {
        let lookup_api = match self
            .supported_sandbox_api_for_lookup(self.client.clone())
            .await
        {
            Ok(api) => api,
            Err(error) => {
                warn!(%error, "skipping sandbox-runtime reconciliation: Sandbox API unavailable");
                return;
            }
        };
        let list = match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            lookup_api
                .api
                .list(&ListParams::default().labels(&self.openshell_sandbox_selector())),
        )
        .await
        {
            Ok(Ok(list)) => list,
            Ok(Err(error)) => {
                warn!(%error, "skipping sandbox-runtime reconciliation: Sandbox list failed");
                return;
            }
            Err(_) => {
                warn!("skipping sandbox-runtime reconciliation: Sandbox list timed out");
                return;
            }
        };

        for object in list.items {
            let Ok(sandbox_id) = sandbox_id_from_object(&object) else {
                continue;
            };
            // A long-running create must not stall cleanup of other sandboxes.
            // Refresh under the acquired gate below to reject stale LIST identities.
            let Ok(_lifecycle_guard) = self.lifecycle_lock(&sandbox_id).try_lock_owned() else {
                continue;
            };
            let live_namespace = object
                .metadata
                .namespace
                .as_deref()
                .unwrap_or(&self.config.namespace);
            let Some(live_name) = object.metadata.name.as_deref() else {
                continue;
            };
            let live_api = Self::agent_sandbox_api(
                self.client.clone(),
                &lookup_api.resource.version,
                live_namespace,
            );
            let object = match live_api.api.get_opt(live_name).await {
                Ok(Some(current)) if current.metadata.uid == object.metadata.uid => current,
                Ok(_) => continue,
                Err(error) => {
                    warn!(%sandbox_id, %error, "cannot refresh Sandbox CR under lifecycle lock");
                    continue;
                }
            };
            if let Err(error) = self.admit_stored_resources(&object).await {
                warn!(%sandbox_id, reason = %error.message(), "Sandbox resource admission revalidation failed");
                if error.code() == tonic::Code::FailedPrecondition {
                    self.suspend_sandbox_runtime_after_dependency_failure(&lookup_api, &object)
                        .await;
                }
                continue;
            }
            let namespace = object
                .metadata
                .namespace
                .as_deref()
                .unwrap_or(&self.config.namespace);
            let cr_name = object.metadata.name.as_deref().unwrap_or_default();
            if sandbox_runtime_bootstrap_phase(&object)
                == Some(SandboxRuntimeBootstrapPhase::Releasing)
            {
                self.reconcile_sandbox_runtime_control_release(
                    &lookup_api,
                    &object,
                    &sandbox_id,
                    namespace,
                    cr_name,
                )
                .await;
                continue;
            }
            if sandbox_runtime_bootstrap_phase(&object)
                == Some(SandboxRuntimeBootstrapPhase::Suspending)
            {
                self.reconcile_sandbox_runtime_suspending(
                    &lookup_api,
                    &object,
                    &sandbox_id,
                    namespace,
                    cr_name,
                )
                .await;
                continue;
            }
            let names = SandboxRuntimeNames::new(&sandbox_id);
            let policies = Api::<NetworkPolicy>::namespaced(self.client.clone(), namespace);
            match self.create_sandbox_runtime_fence(namespace, &names).await {
                Ok(()) => {}
                Err(KubernetesDriverError::Precondition(error)) => {
                    warn!(sandbox_id, %error, "sandbox-runtime workload fence is altered; suspending workload");
                    self.suspend_sandbox_runtime_after_dependency_failure(&lookup_api, &object)
                        .await;
                    continue;
                }
                Err(error) => {
                    warn!(sandbox_id, %error, "could not verify sandbox-runtime workload fence; reconciliation will retry");
                    continue;
                }
            }
            let Ok(Ok(fence)) =
                tokio::time::timeout(KUBE_API_TIMEOUT, policies.get(&names.workload_policy)).await
            else {
                continue;
            };
            let workload_may_run = sandbox_runtime_should_run(&object)
                || sandbox_runtime_bootstrap_in_progress(&object);
            if workload_may_run
                && !sandbox_runtime_namespace_fence_generation_matches(&fence, &object)
            {
                warn!(
                    sandbox_id,
                    "namespace workload fence generation changed; suspending stale boundary"
                );
                self.suspend_sandbox_runtime_after_dependency_failure(&lookup_api, &object)
                    .await;
                continue;
            }
            if sandbox_runtime_bootstrap_in_progress(&object) {
                if sandbox_runtime_control_availability(&self.client, namespace, &sandbox_id).await
                    == SandboxRuntimeControlAvailability::Available
                    && sandbox_runtime_bootstrap_is_ready_to_complete(&object)
                {
                    self.complete_sandbox_runtime_bootstrap(&lookup_api, &object)
                        .await;
                } else {
                    self.reap_stale_sandbox_runtime_bootstrap(&lookup_api, &object)
                        .await;
                }
                continue;
            }
            let desired_running = sandbox_runtime_should_run(&object);
            if desired_running {
                match sandbox_runtime_workload_generation_matches(
                    &self.client,
                    namespace,
                    cr_name,
                    &object,
                )
                .await
                {
                    SandboxRuntimeControlAvailability::Available
                    | SandboxRuntimeControlAvailability::Degraded => {}
                    SandboxRuntimeControlAvailability::Unavailable => {
                        warn!(
                            sandbox_id,
                            "sandbox-runtime workload generation changed; suspending stale boundary"
                        );
                        self.suspend_sandbox_runtime_after_dependency_failure(&lookup_api, &object)
                            .await;
                        continue;
                    }
                    SandboxRuntimeControlAvailability::Unknown => {
                        warn!(
                            sandbox_id,
                            "could not verify sandbox-runtime workload generation; reconciliation will retry"
                        );
                        continue;
                    }
                }
                match sandbox_runtime_supervisor_generation_matches(
                    &self.client,
                    namespace,
                    &sandbox_id,
                    &object,
                )
                .await
                {
                    SandboxRuntimeControlAvailability::Available
                    | SandboxRuntimeControlAvailability::Degraded => {}
                    SandboxRuntimeControlAvailability::Unavailable => {
                        warn!(
                            sandbox_id,
                            "sandbox-runtime supervisor generation changed; suspending stale boundary"
                        );
                        self.suspend_sandbox_runtime_after_dependency_failure(&lookup_api, &object)
                            .await;
                        continue;
                    }
                    SandboxRuntimeControlAvailability::Unknown => continue,
                }
            }
            match self
                .reconcile_sandbox_runtime_supervisor(
                    &sandbox_id,
                    namespace,
                    desired_running,
                    object.metadata.uid.as_deref(),
                )
                .await
            {
                Ok(()) => {
                    if !desired_running
                        && let (Some(profile), Some(cr_uid)) =
                            (&self.confidential, object.metadata.uid.as_deref())
                    {
                        if let Err(error) =
                            profile.store.deauthorize_workspace_key(namespace, cr_uid)
                        {
                            warn!(sandbox_id, %error, "failed to deauthorize stopped workspace");
                        }
                        if let Err(error) = profile.store.revoke_sandbox_uid(&sandbox_id, cr_uid) {
                            warn!(sandbox_id, %error, "failed to revoke stopped confidential sandbox");
                        }
                        let annotations = object.metadata.annotations.as_ref();
                        if let Err(error) = self
                            .delete_sandbox_runtime_generation_secrets_for_pods(
                                &sandbox_id,
                                namespace,
                                sandbox_runtime_generation(&object).as_slice(),
                                annotations
                                    .and_then(|a| a.get(ANNOTATION_SANDBOX_RUNTIME_WORKLOAD_UID))
                                    .map(String::as_str),
                                annotations
                                    .and_then(|a| a.get(ANNOTATION_SANDBOX_RUNTIME_SUPERVISOR_UID))
                                    .map(String::as_str),
                            )
                            .await
                        {
                            warn!(sandbox_id, %error, "failed to retire stopped role-owned Secrets");
                        }
                    }
                }
                Err(KubernetesDriverError::Precondition(error)) => {
                    warn!(sandbox_id, %error, "sandbox-runtime companion is missing; suspending workload");
                    self.suspend_sandbox_runtime_after_dependency_failure(&lookup_api, &object)
                        .await;
                }
                Err(error) => {
                    warn!(sandbox_id, %error, "failed to reconcile sandbox-runtime supervisor Pod");
                }
            }
            let availability =
                sandbox_runtime_control_availability(&self.client, namespace, &sandbox_id).await;
            if desired_running && availability == SandboxRuntimeControlAvailability::Unavailable {
                warn!(
                    sandbox_id,
                    "sandbox-runtime supervisor is unavailable; suspending workload"
                );
                self.suspend_sandbox_runtime_after_dependency_failure(&lookup_api, &object)
                    .await;
                continue;
            }
            self.publish_sandbox_runtime_readiness_transition(&lookup_api, &object, availability)
                .await;
        }
    }

    async fn reconcile_sandbox_runtime_suspending(
        &self,
        lookup_api: &AgentSandboxApi,
        object: &DynamicObject,
        sandbox_id: &str,
        namespace: &str,
        cr_name: &str,
    ) {
        let Some(cr_uid) = object.metadata.uid.as_deref() else {
            warn!(sandbox_id, "cannot suspend Sandbox without CR UID");
            return;
        };
        let pod_name = object
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(SANDBOX_POD_NAME_ANNOTATION))
            .map_or(cr_name, String::as_str);
        let pod_api = Api::<Pod>::namespaced(self.client.clone(), namespace);
        let deadline = tokio::time::Instant::now() + KUBE_API_TIMEOUT;
        match kubernetes_sandbox_pod_is_gone(&pod_api, pod_name, deadline).await {
            Ok(true) => {}
            Ok(false) => return,
            Err(error) => {
                debug!(sandbox_id, %error, "could not verify sandbox-runtime suspension; reconciliation will retry");
                return;
            }
        }
        if let Err(error) = self
            .delete_sandbox_runtime_supervisor_pod_for_uid(sandbox_id, namespace, cr_uid)
            .await
        {
            warn!(sandbox_id, %error, "could not finish sandbox-runtime suspension cleanup");
            return;
        }
        let mut revoke_failed = false;
        if let Some(profile) = &self.confidential {
            if let Err(error) = profile.store.deauthorize_workspace_key(namespace, cr_uid) {
                warn!(sandbox_id, %error, "could not deauthorize confidential workspace");
                revoke_failed = true;
            }
            if let Err(error) = profile.store.revoke_sandbox_uid(sandbox_id, cr_uid) {
                warn!(sandbox_id, %error, "could not revoke confidential sandbox bootstrap");
                revoke_failed = true;
            }
        }
        let annotations = object.metadata.annotations.as_ref();
        if let Err(error) = self
            .delete_sandbox_runtime_generation_secrets_for_pods(
                sandbox_id,
                namespace,
                sandbox_runtime_generation(object).as_slice(),
                annotations
                    .and_then(|a| a.get(ANNOTATION_SANDBOX_RUNTIME_WORKLOAD_UID))
                    .map(String::as_str),
                annotations
                    .and_then(|a| a.get(ANNOTATION_SANDBOX_RUNTIME_SUPERVISOR_UID))
                    .map(String::as_str),
            )
            .await
        {
            warn!(sandbox_id, %error, "could not retire old role-owned Secrets");
            revoke_failed = true;
        }
        if revoke_failed {
            return;
        }
        let Some(resource_version) = object.metadata.resource_version.as_deref() else {
            return;
        };
        let api =
            Self::agent_sandbox_api(self.client.clone(), &lookup_api.resource.version, namespace);
        let patch = sandbox_runtime_suspension_completion_patch(resource_version);
        match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            api.api
                .patch(cr_name, &PatchParams::default(), &Patch::Merge(&patch)),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                debug!(sandbox_id, %error, "sandbox-runtime suspension completion raced; reconciliation will retry");
            }
            Err(_) => {
                warn!(
                    sandbox_id,
                    "timed out completing sandbox-runtime suspension"
                );
            }
        }
    }

    async fn reconcile_sandbox_runtime_control_release(
        &self,
        lookup_api: &AgentSandboxApi,
        object: &DynamicObject,
        sandbox_id: &str,
        namespace: &str,
        cr_name: &str,
    ) {
        let Some(cr_uid) = object.metadata.uid.as_deref() else {
            warn!(sandbox_id, "cannot release Sandbox control without CR UID");
            return;
        };
        if let Err(error) = self
            .delete_sandbox_runtime_supervisor_pod_for_uid(sandbox_id, namespace, cr_uid)
            .await
        {
            warn!(sandbox_id, %error, "could not release sandbox-runtime control; reconciliation will retry");
            return;
        }
        let Some(resource_version) = object.metadata.resource_version.as_deref() else {
            return;
        };
        let api =
            Self::agent_sandbox_api(self.client.clone(), &lookup_api.resource.version, namespace);
        let patch =
            sandbox_runtime_suspension_patch(&lookup_api.resource.version, resource_version);
        match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            api.api
                .patch(cr_name, &PatchParams::default(), &Patch::Merge(&patch)),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                debug!(sandbox_id, %error, "sandbox-runtime control release raced; reconciliation will retry");
            }
            Err(_) => {
                warn!(
                    sandbox_id,
                    "timed out completing sandbox-runtime control release"
                );
            }
        }
    }

    async fn publish_sandbox_runtime_readiness_transition(
        &self,
        lookup_api: &AgentSandboxApi,
        object: &DynamicObject,
        availability: SandboxRuntimeControlAvailability,
    ) {
        let Some(state) = sandbox_runtime_readiness_state(availability) else {
            return;
        };
        if object
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(ANNOTATION_SANDBOX_RUNTIME_READINESS))
            .is_some_and(|current| current == state)
        {
            return;
        }
        let (Some(name), Some(resource_version)) = (
            object.metadata.name.as_deref(),
            object.metadata.resource_version.as_deref(),
        ) else {
            return;
        };
        let namespace = object
            .metadata
            .namespace
            .as_deref()
            .unwrap_or(&self.config.namespace);
        let api =
            Self::agent_sandbox_api(self.client.clone(), &lookup_api.resource.version, namespace);
        let patch = sandbox_runtime_readiness_transition_patch(resource_version, state);
        match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            api.api
                .patch(name, &PatchParams::default(), &Patch::Merge(&patch)),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                debug!(sandbox = name, %error, "sandbox-runtime readiness transition publication raced; reconciliation will retry");
            }
            Err(_) => {
                warn!(
                    sandbox = name,
                    "timed out publishing sandbox-runtime readiness transition"
                );
            }
        }
    }

    async fn suspend_sandbox_runtime_after_dependency_failure(
        &self,
        lookup_api: &AgentSandboxApi,
        object: &DynamicObject,
    ) {
        let Some(name) = object.metadata.name.as_deref() else {
            return;
        };
        let namespace = object
            .metadata
            .namespace
            .as_deref()
            .unwrap_or(&self.config.namespace);
        let api =
            Self::agent_sandbox_api(self.client.clone(), &lookup_api.resource.version, namespace);
        let patch = sandbox_runtime_suspension_patch(
            &lookup_api.resource.version,
            object
                .metadata
                .resource_version
                .as_deref()
                .unwrap_or_default(),
        );
        match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            api.api
                .patch(name, &PatchParams::default(), &Patch::Merge(&patch)),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                warn!(sandbox = name, %error, "failed to suspend sandbox-runtime after fence failure");
            }
            Err(error) => {
                warn!(sandbox = name, %error, "timed out suspending sandbox-runtime after fence failure");
            }
        }
    }

    async fn reap_stale_sandbox_runtime_bootstrap(
        &self,
        lookup_api: &AgentSandboxApi,
        object: &DynamicObject,
    ) {
        if !sandbox_runtime_bootstrap_is_stale(object, SystemTime::now(), self.bootstrap_timeout())
        {
            return;
        }
        if sandbox_runtime_bootstrap_operation(object) != Some("create") {
            warn!(
                sandbox = object.metadata.name.as_deref().unwrap_or("<unknown>"),
                "suspending stale sandbox-runtime restart bootstrap"
            );
            self.suspend_sandbox_runtime_after_dependency_failure(lookup_api, object)
                .await;
            return;
        }
        let (Some(name), Some(uid), Some(resource_version)) = (
            object.metadata.name.as_deref(),
            object.metadata.uid.clone(),
            object.metadata.resource_version.clone(),
        ) else {
            return;
        };
        let namespace = object
            .metadata
            .namespace
            .as_deref()
            .unwrap_or(&self.config.namespace);
        let api =
            Self::agent_sandbox_api(self.client.clone(), &lookup_api.resource.version, namespace);
        let Ok(sandbox_id) = sandbox_id_from_object(object) else {
            warn!(sandbox = name, "stale bootstrap lacks sandbox identity");
            return;
        };
        if let Some(profile) = &self.confidential {
            let marker = match profile
                .store
                .record_workspace_owner(&sandbox_id, namespace, &uid)
                .and_then(|()| {
                    profile
                        .store
                        .begin_delete(&sandbox_id, namespace, &uid, None)
                }) {
                Ok(marker) => marker,
                Err(error) => {
                    warn!(sandbox = name, %error, "could not fence stale bootstrap deletion");
                    return;
                }
            };
            if let Err(error) = self.withdraw_sandbox_authorization_for_delete(&marker) {
                warn!(sandbox = name, %error, "could not withdraw stale bootstrap authorization");
                return;
            }
        }
        let params = DeleteParams::default().preconditions(Preconditions {
            uid: Some(uid.clone()),
            resource_version: Some(resource_version),
        });
        match tokio::time::timeout(KUBE_API_TIMEOUT, api.api.delete(name, &params)).await {
            Ok(Ok(_)) => {
                warn!(
                    sandbox = name,
                    "rolled back stale fail-closed sandbox-runtime bootstrap"
                );
            }
            Ok(Err(KubeError::Api(error))) if error.code == 404 || error.code == 409 => {}
            Ok(Err(error)) => {
                warn!(sandbox = name, %error, "failed to roll back stale sandbox-runtime bootstrap");
            }
            Err(_) => {
                warn!(
                    sandbox = name,
                    "timed out rolling back stale sandbox-runtime bootstrap"
                );
            }
        }
    }

    async fn complete_sandbox_runtime_bootstrap(
        &self,
        lookup_api: &AgentSandboxApi,
        object: &DynamicObject,
    ) {
        if !sandbox_runtime_bootstrap_is_ready_to_complete(object) {
            return;
        }
        let (Some(name), Some(resource_version)) = (
            object.metadata.name.as_deref(),
            object.metadata.resource_version.as_deref(),
        ) else {
            return;
        };
        let namespace = object
            .metadata
            .namespace
            .as_deref()
            .unwrap_or(&self.config.namespace);
        let api =
            Self::agent_sandbox_api(self.client.clone(), &lookup_api.resource.version, namespace);
        let patch = sandbox_runtime_bootstrap_completion_patch(resource_version);
        match tokio::time::timeout(
            KUBE_API_TIMEOUT,
            api.api
                .patch(name, &PatchParams::default(), &Patch::Merge(&patch)),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                debug!(sandbox = name, %error, "sandbox-runtime bootstrap completion raced; reconciliation will retry");
            }
            Err(_) => warn!(
                sandbox = name,
                "timed out completing sandbox-runtime bootstrap"
            ),
        }
    }

    async fn reconcile_sandbox_runtime_supervisor(
        &self,
        sandbox_id: &str,
        namespace: &str,
        desired_running: bool,
        cr_uid: Option<&str>,
    ) -> Result<(), KubernetesDriverError> {
        if !desired_running {
            let cr_uid = cr_uid.ok_or_else(|| {
                KubernetesDriverError::Precondition(
                    "Sandbox CR lacks UID during supervisor cleanup".to_string(),
                )
            })?;
            return self
                .delete_sandbox_runtime_supervisor_pod_for_uid(sandbox_id, namespace, cr_uid)
                .await;
        }
        let names = SandboxRuntimeNames::new(sandbox_id);
        let services = Api::<Service>::namespaced(self.client.clone(), namespace);
        let service_exists =
            tokio::time::timeout(KUBE_API_TIMEOUT, services.get_opt(&names.boundary_service))
                .await
                .map_err(|_| {
                    KubernetesDriverError::Message(
                        "timed out reading sandbox-runtime boundary Service".to_string(),
                    )
                })?
                .map_err(KubernetesDriverError::from_kube)?
                .is_some();
        if !service_exists {
            return Err(KubernetesDriverError::Precondition(format!(
                "sandbox-runtime boundary Service {} is missing and its allocated address cannot be safely reconstructed",
                names.boundary_service
            )));
        }
        let pods = Api::<Pod>::namespaced(self.client.clone(), namespace);
        tokio::time::timeout(
            KUBE_API_TIMEOUT,
            pods.get_opt(&names.supervisor_pod),
        )
        .await
        .map_err(|_| {
            KubernetesDriverError::Message(
                "timed out reading sandbox-runtime supervisor Pod".to_string(),
            )
        })?
        .map_err(KubernetesDriverError::from_kube)?
        .ok_or_else(|| {
            KubernetesDriverError::Precondition(format!(
                "sandbox-runtime supervisor Pod {} is missing; start a fresh sandbox generation",
                names.supervisor_pod
            ))
        })?;
        Ok(())
    }

    fn spawn_sandbox_runtime_periodic_reconcile(
        &self,
        tx: mpsc::Sender<Result<WatchSandboxesEvent, KubernetesDriverError>>,
    ) {
        self.spawn_attestation_report_updates(tx.clone());
        let driver = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(SANDBOX_RUNTIME_RECONCILE_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        driver.reconcile_pending_sandbox_deletions().await;
                        driver.reconcile_sandbox_runtime_resources().await;
                        if let Ok(sandboxes) = driver.list_sandboxes().await {
                            for sandbox in sandboxes {
                                if tx.send(Ok(WatchSandboxesEvent {
                                    payload: Some(watch_sandboxes_event::Payload::Sandbox(
                                        WatchSandboxesSandboxEvent { sandbox: Some(sandbox) },
                                    )),
                                })).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                    () = tx.closed() => return,
                }
            }
        });
    }

    fn spawn_attestation_report_updates(
        &self,
        tx: mpsc::Sender<Result<WatchSandboxesEvent, KubernetesDriverError>>,
    ) {
        if !self
            .confidential
            .as_ref()
            .is_some_and(|profile| profile.reports.is_some())
        {
            return;
        }
        // The stock Gateway serves its watch-driven sandbox store. Refresh display
        // snapshots before collection status expires, independently of lifecycle
        // reconciliation. This task only reads sandboxes and passive reports.
        let driver = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(ATTESTATION_REPORT_PUBLISH_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Ok(sandboxes) = driver.list_sandboxes().await {
                            for sandbox in sandboxes {
                                if tx.send(Ok(WatchSandboxesEvent {
                                    payload: Some(watch_sandboxes_event::Payload::Sandbox(
                                        WatchSandboxesSandboxEvent { sandbox: Some(sandbox) },
                                    )),
                                })).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                    () = tx.closed() => return,
                }
            }
        });
    }

    // Kept `async` to match the gRPC handler signature in `grpc.rs`, which awaits this method.
    #[allow(clippy::unused_async)]
    pub async fn watch_sandboxes(&self) -> Result<WatchStream, String> {
        self.reconcile_pending_sandbox_deletions().await;
        self.reconcile_sandbox_runtime_resources().await;
        if self.config.is_multi_namespace() {
            self.watch_sandboxes_cluster_wide().await
        } else {
            self.watch_sandboxes_single_namespace().await
        }
    }

    async fn watch_sandboxes_single_namespace(&self) -> Result<WatchStream, String> {
        let namespace = self.config.namespace.clone();
        let agent_sandbox_api = self
            .supported_agent_sandbox_api(self.watch_client.clone(), &self.config.namespace)
            .await?;
        let event_api: Api<KubeEventObj> = Api::namespaced(self.watch_client.clone(), &namespace);
        let watcher_config = watcher::Config::default().labels(&openshell_sandbox_label_selector());
        let mut sandbox_stream = recovering_watcher_stream(
            watcher::watcher(agent_sandbox_api.api, watcher_config),
            "sandbox-resource",
        )
        .boxed();
        let mut event_stream = recovering_watcher_stream(
            watcher::watcher(event_api, watcher::Config::default()),
            "kubernetes-event",
        )
        .boxed();
        let (tx, rx) = mpsc::channel(256);
        self.spawn_sandbox_runtime_periodic_reconcile(tx.clone());
        let readiness_client = self.watch_client.clone();
        let driver = self.clone();

        tokio::spawn(async move {
            let mut sandbox_name_to_id = std::collections::HashMap::<String, String>::new();
            let mut agent_pod_to_id = std::collections::HashMap::<String, String>::new();

            loop {
                tokio::select! {
                    event = sandbox_stream.next() => match event {
                        Some(Event::Apply(obj) | Event::InitApply(obj)) => {
                            if let Ok((kube_name, sandbox)) = driver.sandbox_with_attestation(&readiness_client, &namespace, obj).await {
                                update_indexes(&mut sandbox_name_to_id, &mut agent_pod_to_id, &kube_name, &sandbox);
                                let event = WatchSandboxesEvent {
                                    payload: Some(watch_sandboxes_event::Payload::Sandbox(
                                        WatchSandboxesSandboxEvent { sandbox: Some(sandbox) }
                                    )),
                                };
                                if tx.send(Ok(event)).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Some(Event::Delete(obj)) => {
                            if is_openshell_managed(&obj)
                                && let Ok(sandbox_id) = sandbox_id_from_object(&obj)
                            {
                                remove_indexes(&mut sandbox_name_to_id, &mut agent_pod_to_id, &sandbox_id);
                                let event = WatchSandboxesEvent {
                                    payload: Some(watch_sandboxes_event::Payload::Deleted(
                                        WatchSandboxesDeletedEvent { sandbox_id }
                                    )),
                                };
                                if tx.send(Ok(event)).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Some(Event::Init | Event::InitDone) => {}
                        None => {
                            let _ = tx.send(Err(KubernetesDriverError::Message(
                                "sandbox watcher stream ended unexpectedly".to_string()
                            ))).await;
                            break;
                        }
                    },
                    event = event_stream.next() => match event {
                        Some(Event::Apply(obj) | Event::InitApply(obj)) => {
                            if let Some((sandbox_id, event)) = map_kube_event_to_platform(
                                &sandbox_name_to_id,
                                &agent_pod_to_id,
                                &obj,
                            ) {
                                let event = WatchSandboxesEvent {
                                    payload: Some(watch_sandboxes_event::Payload::PlatformEvent(
                                        WatchSandboxesPlatformEvent { sandbox_id, event: Some(event) }
                                    )),
                                };
                                if tx.send(Ok(event)).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Some(Event::Delete(_)) => {}
                        Some(Event::Init | Event::InitDone) => {
                            debug!(namespace = %namespace, "Kubernetes event watcher restarted");
                        }
                        None => {
                            let _ = tx.send(Err(KubernetesDriverError::Message(
                                "kubernetes event watcher stream ended".to_string()
                            ))).await;
                            break;
                        }
                    },
                    () = tx.closed() => break,
                }
            }
        });

        Ok(Box::pin(ReceiverStream::new(rx)))
    }

    async fn watch_sandboxes_cluster_wide(&self) -> Result<WatchStream, String> {
        let sandbox_api_version = self
            .supported_sandbox_api_version(self.watch_client.clone())
            .await?;
        let cluster_api =
            Self::cluster_wide_sandbox_api(self.watch_client.clone(), sandbox_api_version);
        let selector = self.openshell_sandbox_selector();
        let watcher_config = watcher::Config::default().labels(&selector);
        let sandbox_stream = recovering_watcher_stream(
            watcher::watcher(cluster_api.api, watcher_config),
            "sandbox-resource",
        )
        .boxed();

        Ok(cluster_wide_watch_stream(
            sandbox_stream,
            self.config.namespace.clone(),
            self.watch_client.clone(),
            self.clone(),
        ))
    }
}

fn sandbox_runtime_bootstrap_completion_patch(resource_version: &str) -> serde_json::Value {
    serde_json::json!({
        "metadata": {
            "resourceVersion": resource_version,
            "annotations": {
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAPPING: serde_json::Value::Null,
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_STARTED_AT: serde_json::Value::Null,
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_OPERATION: serde_json::Value::Null,
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_PHASE: serde_json::Value::Null,
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_SESSION: serde_json::Value::Null,
                ANNOTATION_SANDBOX_RUNTIME_READINESS: "ready",
            }
        }
    })
}

fn spawn_sandbox_runtime_bootstrap_completion(
    pods: Api<Pod>,
    sandboxes: Api<DynamicObject>,
    supervisor_pod_name: String,
    sandbox_name: String,
    expected_sandbox_uid: Option<String>,
    bootstrap_timeout: Duration,
) {
    tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + bootstrap_timeout;
        let available = |pod: Option<&Pod>| {
            pod.is_some_and(|pod| {
                sandbox_runtime_control_availability_from_pod(pod)
                    == SandboxRuntimeControlAvailability::Available
            })
        };
        match tokio::time::timeout_at(
            deadline,
            await_condition(pods, &supervisor_pod_name, available),
        )
        .await
        {
            Ok(Ok(Some(_))) => {}
            Ok(Ok(None)) | Err(_) => return,
            Ok(Err(error)) => {
                debug!(%error, sandbox = sandbox_name, "sandbox-runtime bootstrap availability watch failed; reconciliation will retry");
                return;
            }
        }

        // A replacement control can become Available before the Agent
        // Sandbox controller has replaced the prior Suspended condition.
        // Clearing the bootstrap marker in that window publishes a terminal
        // Stopped event to the gateway. Wait for the controller's real Ready
        // condition so the marker removal and readiness annotation expose one
        // causally complete transition for both API versions.
        let runtime_ready = |object: Option<&DynamicObject>| {
            object.is_some_and(|object| {
                object.metadata.uid == expected_sandbox_uid
                    && sandbox_runtime_bootstrap_is_ready_to_complete(object)
            })
        };
        let object = match tokio::time::timeout_at(
            deadline,
            await_condition(sandboxes.clone(), &sandbox_name, runtime_ready),
        )
        .await
        {
            Ok(Ok(Some(object))) => object,
            Ok(Ok(None)) | Err(_) => return,
            Ok(Err(error)) => {
                debug!(%error, sandbox = sandbox_name, "sandbox-runtime runtime readiness watch failed; reconciliation will retry");
                return;
            }
        };
        let Some(resource_version) = object.metadata.resource_version.as_deref() else {
            return;
        };
        let patch = sandbox_runtime_bootstrap_completion_patch(resource_version);
        if let Err(error) = sandboxes
            .patch(
                &sandbox_name,
                &PatchParams::default(),
                &Patch::Merge(&patch),
            )
            .await
        {
            debug!(%error, sandbox = sandbox_name, "sandbox-runtime bootstrap completion raced; reconciliation will retry");
        }
    });
}

fn sandbox_runtime_runtime_is_ready(object: &DynamicObject) -> bool {
    let Some(generation) = object.metadata.generation else {
        return false;
    };
    let Some(conditions) = object
        .data
        .pointer("/status/conditions")
        .and_then(serde_json::Value::as_array)
    else {
        return false;
    };
    let observes_current_generation = |condition: &serde_json::Value| {
        condition
            .get("observedGeneration")
            .and_then(serde_json::Value::as_i64)
            == Some(generation)
    };
    let ready = conditions.iter().any(|condition| {
        condition.get("type").and_then(serde_json::Value::as_str) == Some("Ready")
            && condition.get("status").and_then(serde_json::Value::as_str) == Some("True")
            && observes_current_generation(condition)
    });
    let suspended = conditions.iter().any(|condition| {
        condition.get("type").and_then(serde_json::Value::as_str)
            == Some(SANDBOX_SUSPENDED_CONDITION)
            && condition.get("status").and_then(serde_json::Value::as_str) == Some("True")
            && observes_current_generation(condition)
    });
    ready && !suspended
}

fn sandbox_runtime_bootstrap_in_progress(object: &DynamicObject) -> bool {
    object
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAPPING))
        .is_some_and(|value| value == "true")
}

fn sandbox_runtime_bootstrap_operation(object: &DynamicObject) -> Option<&str> {
    object
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_OPERATION))
        .map(String::as_str)
}

fn sandbox_runtime_bootstrap_is_ready_to_complete(object: &DynamicObject) -> bool {
    sandbox_runtime_bootstrap_in_progress(object)
        && sandbox_runtime_bootstrap_phase(object) == Some(SandboxRuntimeBootstrapPhase::Released)
        && matches!(
            sandbox_runtime_bootstrap_operation(object),
            Some("create" | "restart")
        )
        && sandbox_runtime_runtime_is_ready(object)
}

fn sandbox_runtime_bootstrap_phase(object: &DynamicObject) -> Option<SandboxRuntimeBootstrapPhase> {
    object
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_PHASE))
        .and_then(|value| SandboxRuntimeBootstrapPhase::parse(value))
}

fn sandbox_runtime_generation(object: &DynamicObject) -> Option<&str> {
    object
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(ANNOTATION_SANDBOX_RUNTIME_GENERATION))
        .map(String::as_str)
}

fn sandbox_runtime_bootstrap_phase_patch(
    resource_version: &str,
    phase: SandboxRuntimeBootstrapPhase,
) -> serde_json::Value {
    serde_json::json!({
        "metadata": {
            "resourceVersion": resource_version,
            "annotations": {
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_PHASE: phase.as_str(),
            }
        }
    })
}

fn sandbox_runtime_bootstrap_is_stale(
    object: &DynamicObject,
    now: SystemTime,
    minimum_age: Duration,
) -> bool {
    let Some(started_at_ms) = object
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_STARTED_AT))
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return true;
    };
    now.duration_since(SystemTime::UNIX_EPOCH + Duration::from_millis(started_at_ms))
        .is_ok_and(|age| age >= minimum_age)
}

fn sandbox_runtime_readiness_transition_patch(
    resource_version: &str,
    state: &str,
) -> serde_json::Value {
    serde_json::json!({
        "metadata": {
            "resourceVersion": resource_version,
            "annotations": { ANNOTATION_SANDBOX_RUNTIME_READINESS: state },
        }
    })
}

fn cluster_wide_watch_stream<S>(
    mut sandbox_stream: S,
    default_namespace: String,
    readiness_client: Client,
    driver: KubernetesComputeDriver,
) -> WatchStream
where
    S: Stream<Item = Event<DynamicObject>> + Send + Unpin + 'static,
{
    let (tx, rx) = mpsc::channel(256);
    driver.spawn_sandbox_runtime_periodic_reconcile(tx.clone());

    tokio::spawn(async move {
        loop {
            tokio::select! {
                event = sandbox_stream.next() => match event {
                    Some(Event::Apply(obj) | Event::InitApply(obj)) => {
                        let ns = obj.metadata.namespace.clone()
                            .unwrap_or_else(|| default_namespace.clone());
                        if let Ok((_kube_name, sandbox)) = driver.sandbox_with_attestation(&readiness_client, &ns, obj).await {
                            let event = WatchSandboxesEvent {
                                payload: Some(watch_sandboxes_event::Payload::Sandbox(
                                    WatchSandboxesSandboxEvent { sandbox: Some(sandbox) }
                                )),
                            };
                            if tx.send(Ok(event)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(Event::Delete(obj)) => {
                        if is_openshell_managed(&obj)
                            && let Ok(sandbox_id) = sandbox_id_from_object(&obj)
                        {
                            let event = WatchSandboxesEvent {
                                payload: Some(watch_sandboxes_event::Payload::Deleted(
                                    WatchSandboxesDeletedEvent { sandbox_id }
                                )),
                            };
                            if tx.send(Ok(event)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(Event::Init | Event::InitDone) => {}
                    None => {
                        let _ = tx.send(Err(KubernetesDriverError::Message(
                            "sandbox watcher stream ended unexpectedly".to_string()
                        ))).await;
                        break;
                    }
                },
                () = tx.closed() => break,
            }
        }
    });

    Box::pin(ReceiverStream::new(rx))
}

fn recovering_watcher_stream<S, T, E>(
    stream: S,
    watcher: &'static str,
) -> impl Stream<Item = Event<T>>
where
    S: Stream<Item = Result<Event<T>, E>>,
    E: std::fmt::Display,
{
    continue_on_watcher_errors(stream.default_backoff(), watcher)
}

/// Drop kube-runtime watcher errors after logging them so continued polling can
/// drive its built-in relist and recovery state machine. The production adapter
/// above applies backoff first to avoid hot-looping on persistent API failures.
fn continue_on_watcher_errors<S, T, E>(
    stream: S,
    watcher: &'static str,
) -> impl Stream<Item = Event<T>>
where
    S: Stream<Item = Result<Event<T>, E>>,
    E: std::fmt::Display,
{
    stream.filter_map(move |result| {
        futures::future::ready(match result {
            Ok(event) => Some(event),
            Err(err) => {
                warn!(
                    watcher,
                    error = %err,
                    "Kubernetes watcher stream error; waiting for kube-runtime recovery"
                );
                None
            }
        })
    })
}

fn add_trace_context_annotation(annotations: &mut BTreeMap<String, String>) {
    let Some(carrier) = openshell_otel::current_trace_context_carrier() else {
        return;
    };
    if let Ok(value) = serde_json::to_string(&carrier) {
        annotations.insert(AGENT_SANDBOX_TRACE_CONTEXT_ANNOTATION.to_string(), value);
    }
}

fn should_try_next_sandbox_api_version(err: &KubeError) -> bool {
    // Kubernetes returns a structured 404 for some missing API resources and a
    // raw "404 page not found" body for others. Both mean the probed
    // group/version is unavailable and the next supported Sandbox API version
    // should be tried.
    matches!(err, KubeError::Api(api) if api.code == 404)
}

fn validate_gpu_request(
    gpu_requirements: Option<&GpuResourceRequirements>,
) -> Result<(), tonic::Status> {
    let _ =
        effective_driver_gpu_count(gpu_requirements).map_err(tonic::Status::invalid_argument)?;
    Ok(())
}

const MAX_KUBE_NAME_LEN: usize = 63;

fn validate_kube_resource_name_length(workspace: &str, name: &str) -> Result<(), tonic::Status> {
    let combined = workspace.len() + 2 + name.len(); // "--" separator
    if combined > MAX_KUBE_NAME_LEN {
        return Err(tonic::Status::invalid_argument(format!(
            "combined Kubernetes resource name '{workspace}--{name}' is {combined} characters, \
             exceeding the DNS-1123 limit of {MAX_KUBE_NAME_LEN}"
        )));
    }
    Ok(())
}

fn is_namespace_owned_by_gateway(
    labels: Option<&BTreeMap<String, String>>,
    gateway_id: &str,
) -> bool {
    labels
        .and_then(|l| l.get(LABEL_MANAGED_BY))
        .is_some_and(|v| v == LABEL_MANAGED_BY_VALUE)
        && labels
            .and_then(|l| l.get(LABEL_GATEWAY_ID))
            .is_some_and(|v| v == gateway_id)
}

fn namespace_delete_params(uid: String) -> DeleteParams {
    DeleteParams::default().preconditions(Preconditions {
        uid: Some(uid),
        resource_version: None,
    })
}

fn sandbox_lookup_selector_for(sandbox_id: &str, gateway_id: &str) -> String {
    format!(
        "{LABEL_MANAGED_BY}={LABEL_MANAGED_BY_VALUE},{LABEL_SANDBOX_ID}={sandbox_id},{LABEL_GATEWAY_ID}={gateway_id}"
    )
}

fn openshell_sandbox_selector_for(gateway_id: &str) -> String {
    use std::fmt::Write;
    let mut selector = openshell_sandbox_label_selector();
    write!(selector, ",{LABEL_GATEWAY_ID}={gateway_id}").unwrap();
    selector
}

fn sandbox_labels(sandbox: &Sandbox, gateway_id: Option<&str>) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert(LABEL_SANDBOX_ID.to_string(), sandbox.id.clone());
    labels.insert(LABEL_SANDBOX_NAME.to_string(), sandbox.name.clone());
    labels.insert(
        LABEL_SANDBOX_WORKSPACE.to_string(),
        sandbox.workspace.clone(),
    );
    labels.insert(
        LABEL_MANAGED_BY.to_string(),
        LABEL_MANAGED_BY_VALUE.to_string(),
    );
    if let Some(gw_id) = gateway_id {
        labels.insert(LABEL_GATEWAY_ID.to_string(), gw_id.to_string());
    }
    labels
}

fn managed_ssh_network_policy(namespace: &str, config: &KubernetesComputeConfig) -> NetworkPolicy {
    NetworkPolicy {
        metadata: ObjectMeta {
            name: Some(MANAGED_SSH_NETWORK_POLICY_NAME.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(BTreeMap::from([(
                LABEL_MANAGED_BY.to_string(),
                LABEL_MANAGED_BY_VALUE.to_string(),
            )])),
            ..Default::default()
        },
        spec: Some(NetworkPolicySpec {
            pod_selector: LabelSelector {
                match_labels: Some(BTreeMap::from([(
                    LABEL_MANAGED_BY.to_string(),
                    LABEL_MANAGED_BY_VALUE.to_string(),
                )])),
                ..Default::default()
            },
            policy_types: Some(vec!["Ingress".to_string()]),
            ingress: Some(vec![NetworkPolicyIngressRule {
                from: Some(vec![NetworkPolicyPeer {
                    namespace_selector: Some(LabelSelector {
                        match_labels: Some(BTreeMap::from([(
                            "kubernetes.io/metadata.name".to_string(),
                            config.managed_ssh_ingress.gateway_namespace.clone(),
                        )])),
                        ..Default::default()
                    }),
                    pod_selector: Some(LabelSelector {
                        match_labels: Some(config.managed_ssh_ingress.gateway_pod_selector.clone()),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                ports: Some(vec![NetworkPolicyPort {
                    port: Some(IntOrString::Int(2222)),
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                }]),
            }]),
            ..Default::default()
        }),
    }
}

fn runtime_pod_owner(name: &str, uid: &str) -> OwnerReference {
    OwnerReference {
        api_version: "v1".to_string(),
        kind: "Pod".to_string(),
        name: name.to_string(),
        uid: uid.to_string(),
        controller: Some(false),
        block_owner_deletion: Some(false),
    }
}

fn sandbox_annotations(sandbox: &Sandbox) -> BTreeMap<String, String> {
    let mut annotations = BTreeMap::new();
    annotations.insert(LABEL_SANDBOX_ID.to_string(), sandbox.id.clone());
    annotations.insert(LABEL_SANDBOX_NAME.to_string(), sandbox.name.clone());
    annotations.insert(
        LABEL_SANDBOX_WORKSPACE.to_string(),
        sandbox.workspace.clone(),
    );
    annotations
}

fn kubernetes_runtime_identity(namespace: &str, resource_uid: &str, pod_uid: &str) -> String {
    format!("kubernetes://{namespace}/{resource_uid}/{pod_uid}")
}

#[derive(Debug, PartialEq, Eq)]
struct KubernetesRuntimeIdentity {
    namespace: String,
    resource_uid: String,
}

fn parse_kubernetes_runtime_identity(
    encoded: &str,
) -> Result<KubernetesRuntimeIdentity, KubernetesDriverError> {
    let value = encoded.strip_prefix("kubernetes://").ok_or_else(|| {
        KubernetesDriverError::Precondition(
            "persisted runtime identity is missing or is not a Kubernetes identity".to_string(),
        )
    })?;
    let mut components = value.split('/');
    let namespace = components.next().unwrap_or_default();
    let resource_uid = components.next().unwrap_or_default();
    let pod_uid = components.next().unwrap_or_default();
    if namespace.is_empty()
        || resource_uid.is_empty()
        || pod_uid.is_empty()
        || components.next().is_some()
    {
        return Err(KubernetesDriverError::Precondition(
            "persisted Kubernetes runtime identity is invalid".to_string(),
        ));
    }
    Ok(KubernetesRuntimeIdentity {
        namespace: namespace.to_string(),
        resource_uid: resource_uid.to_string(),
    })
}

fn select_expected_sandbox_runtime(
    objects: Vec<DynamicObject>,
    expected: &KubernetesRuntimeIdentity,
) -> Result<DynamicObject, KubernetesDriverError> {
    let [object]: [DynamicObject; 1] = objects.try_into().map_err(|objects: Vec<_>| {
        if objects.is_empty() {
            KubernetesDriverError::NotFound
        } else {
            KubernetesDriverError::Precondition(
                "multiple Kubernetes Sandbox resources match the persisted sandbox identity"
                    .to_string(),
            )
        }
    })?;
    let namespace = object.metadata.namespace.as_deref().ok_or_else(|| {
        KubernetesDriverError::Precondition(
            "matched Kubernetes Sandbox resource has no namespace".to_string(),
        )
    })?;
    let resource_uid = object.metadata.uid.as_deref().ok_or_else(|| {
        KubernetesDriverError::Precondition(
            "matched Kubernetes Sandbox resource has no UID".to_string(),
        )
    })?;
    if namespace != expected.namespace || resource_uid != expected.resource_uid {
        return Err(KubernetesDriverError::Precondition(
            "matched Kubernetes Sandbox resource does not match the persisted runtime identity"
                .to_string(),
        ));
    }
    Ok(object)
}

fn sandbox_id_from_object(obj: &DynamicObject) -> Result<String, String> {
    if let Some(annotations) = obj.metadata.annotations.as_ref()
        && let Some(id) = annotations.get(LABEL_SANDBOX_ID)
    {
        return Ok(id.clone());
    }
    if let Some(labels) = obj.metadata.labels.as_ref()
        && let Some(id) = labels.get(LABEL_SANDBOX_ID)
    {
        return Ok(id.clone());
    }
    Err("sandbox id not found on object".to_string())
}

fn annotation_or_label(obj: &DynamicObject, key: &str) -> Option<String> {
    obj.metadata
        .annotations
        .as_ref()
        .and_then(|a| a.get(key))
        .or_else(|| obj.metadata.labels.as_ref().and_then(|l| l.get(key)))
        .cloned()
}

fn is_openshell_managed(obj: &DynamicObject) -> bool {
    annotation_or_label(obj, LABEL_MANAGED_BY).as_deref() == Some(LABEL_MANAGED_BY_VALUE)
}

/// Returns `(kube_resource_name, DriverSandbox)`.
///
/// Returns `Err` in two cases (callers should skip, not fail):
/// - The object is not managed by `OpenShell` (missing/wrong `managed-by` label).
/// - The object is managed by `OpenShell` but missing required fields (orphan).
fn sandbox_from_object(namespace: &str, obj: DynamicObject) -> Result<(String, Sandbox), String> {
    let kube_name = obj.metadata.name.clone().unwrap_or_default();

    if !is_openshell_managed(&obj) {
        debug!(object = %kube_name, "skipping sandbox CR not managed by openshell");
        return Err(format!("object {kube_name} not managed by openshell"));
    }

    let Ok(id) = sandbox_id_from_object(&obj) else {
        warn!(object = %kube_name, "openshell-managed sandbox CR missing id");
        return Err(format!("object {kube_name} missing sandbox id"));
    };
    let Some(name) = annotation_or_label(&obj, LABEL_SANDBOX_NAME) else {
        warn!(object = %kube_name, "openshell-managed sandbox CR missing name");
        return Err(format!("object {kube_name} missing sandbox name"));
    };
    let Some(workspace) = annotation_or_label(&obj, LABEL_SANDBOX_WORKSPACE) else {
        warn!(object = %kube_name, "openshell-managed sandbox CR missing workspace");
        return Err(format!("object {kube_name} missing sandbox workspace"));
    };

    let namespace = obj
        .metadata
        .namespace
        .clone()
        .unwrap_or_else(|| namespace.to_string());
    let status = status_from_object(&obj);

    Ok((
        kube_name,
        Sandbox {
            id,
            name,
            namespace,
            spec: None,
            status,
            workspace,
        },
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SandboxRuntimeControlAvailability {
    Available,
    Degraded,
    Unavailable,
    Unknown,
}

fn sandbox_runtime_control_availability_from_pod(pod: &Pod) -> SandboxRuntimeControlAvailability {
    if pod.metadata.deletion_timestamp.is_some() {
        return SandboxRuntimeControlAvailability::Unavailable;
    }
    let status = pod.status.as_ref();
    let ready = status
        .and_then(|status| status.conditions.as_ref())
        .is_some_and(|conditions| {
            conditions
                .iter()
                .any(|condition| condition.type_ == "Ready" && condition.status == "True")
        });
    if ready {
        SandboxRuntimeControlAvailability::Available
    } else if status.and_then(|status| status.phase.as_deref()) == Some("Running") {
        SandboxRuntimeControlAvailability::Degraded
    } else {
        SandboxRuntimeControlAvailability::Unavailable
    }
}

async fn sandbox_runtime_control_availability(
    client: &Client,
    namespace: &str,
    sandbox_id: &str,
) -> SandboxRuntimeControlAvailability {
    let names = SandboxRuntimeNames::new(sandbox_id);
    let pods = Api::<Pod>::namespaced(client.clone(), namespace);
    let services = Api::<Service>::namespaced(client.clone(), namespace);
    let policies = Api::<NetworkPolicy>::namespaced(client.clone(), namespace);
    let supervisor = Box::pin(tokio::time::timeout(
        KUBE_API_TIMEOUT,
        pods.get_opt(&names.supervisor_pod),
    ));
    let service = Box::pin(tokio::time::timeout(
        KUBE_API_TIMEOUT,
        services.get_opt(&names.boundary_service),
    ));
    let fence = Box::pin(tokio::time::timeout(
        KUBE_API_TIMEOUT,
        policies.get_opt(&names.workload_policy),
    ));
    let supervisor_fence = Box::pin(tokio::time::timeout(
        KUBE_API_TIMEOUT,
        policies.get_opt(&names.supervisor_policy),
    ));
    let (supervisor, service, fence, supervisor_fence) =
        tokio::join!(supervisor, service, fence, supervisor_fence);
    let control = match supervisor {
        Ok(Ok(Some(pod))) => sandbox_runtime_control_availability_from_pod(&pod),
        Ok(Ok(None)) => SandboxRuntimeControlAvailability::Unavailable,
        Ok(Err(error)) => {
            warn!(sandbox_id, %error, "could not determine sandbox-runtime control availability");
            SandboxRuntimeControlAvailability::Unknown
        }
        Err(_) => {
            warn!(
                sandbox_id,
                "timed out checking sandbox-runtime control availability"
            );
            SandboxRuntimeControlAvailability::Unknown
        }
    };
    let service = match service {
        Ok(Ok(Some(_))) => SandboxRuntimeControlAvailability::Available,
        Ok(Ok(None)) => SandboxRuntimeControlAvailability::Unavailable,
        Ok(Err(error)) => {
            warn!(sandbox_id, %error, "could not determine sandbox-runtime boundary Service availability");
            SandboxRuntimeControlAvailability::Unknown
        }
        Err(_) => {
            warn!(
                sandbox_id,
                "timed out checking sandbox-runtime boundary Service availability"
            );
            SandboxRuntimeControlAvailability::Unknown
        }
    };

    // Supervisor readiness alone is not sufficient: deletion of the shared
    // fence would otherwise leave a live boundary with direct pod
    // egress while the driver continued to publish Ready.
    let fence = match fence {
        Ok(Ok(Some(_))) => SandboxRuntimeControlAvailability::Available,
        Ok(Ok(None)) => SandboxRuntimeControlAvailability::Unavailable,
        Ok(Err(error)) => {
            warn!(sandbox_id, %error, "could not determine sandbox-runtime workload fence availability");
            SandboxRuntimeControlAvailability::Unknown
        }
        Err(_) => {
            warn!(
                sandbox_id,
                "timed out checking sandbox-runtime workload fence availability"
            );
            SandboxRuntimeControlAvailability::Unknown
        }
    };
    let supervisor_fence = match supervisor_fence {
        Ok(Ok(Some(_))) => SandboxRuntimeControlAvailability::Available,
        Ok(Ok(None)) => SandboxRuntimeControlAvailability::Unavailable,
        Ok(Err(error)) => {
            warn!(sandbox_id, %error, "could not determine sandbox-runtime supervisor fence availability");
            SandboxRuntimeControlAvailability::Unknown
        }
        Err(_) => {
            warn!(
                sandbox_id,
                "timed out checking sandbox-runtime supervisor fence availability"
            );
            SandboxRuntimeControlAvailability::Unknown
        }
    };
    combine_sandbox_runtime_control_availability([control, service, fence, supervisor_fence])
}

fn combine_sandbox_runtime_control_availability(
    dependencies: [SandboxRuntimeControlAvailability; 4],
) -> SandboxRuntimeControlAvailability {
    if dependencies.contains(&SandboxRuntimeControlAvailability::Unavailable) {
        SandboxRuntimeControlAvailability::Unavailable
    } else if dependencies.contains(&SandboxRuntimeControlAvailability::Degraded) {
        SandboxRuntimeControlAvailability::Degraded
    } else if dependencies.contains(&SandboxRuntimeControlAvailability::Unknown) {
        SandboxRuntimeControlAvailability::Unknown
    } else {
        SandboxRuntimeControlAvailability::Available
    }
}

fn sandbox_runtime_readiness_state(
    availability: SandboxRuntimeControlAvailability,
) -> Option<&'static str> {
    match availability {
        SandboxRuntimeControlAvailability::Available => Some("ready"),
        SandboxRuntimeControlAvailability::Degraded
        | SandboxRuntimeControlAvailability::Unavailable => Some("unavailable"),
        SandboxRuntimeControlAvailability::Unknown => None,
    }
}

async fn sandbox_runtime_workload_generation_matches(
    client: &Client,
    namespace: &str,
    pod_name: &str,
    sandbox: &DynamicObject,
) -> SandboxRuntimeControlAvailability {
    let Some(expected_uid) = sandbox
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(ANNOTATION_SANDBOX_RUNTIME_WORKLOAD_UID))
    else {
        return SandboxRuntimeControlAvailability::Unavailable;
    };
    let pods = Api::<Pod>::namespaced(client.clone(), namespace);
    match tokio::time::timeout(KUBE_API_TIMEOUT, pods.get_opt(pod_name)).await {
        Ok(Ok(Some(pod))) if pod.metadata.uid.as_deref() == Some(expected_uid.as_str()) => {
            SandboxRuntimeControlAvailability::Available
        }
        Ok(Ok(_)) => SandboxRuntimeControlAvailability::Unavailable,
        Ok(Err(error)) => {
            warn!(pod = pod_name, %error, "could not verify sandbox-runtime workload generation");
            SandboxRuntimeControlAvailability::Unknown
        }
        Err(_) => {
            warn!(
                pod = pod_name,
                "timed out checking sandbox-runtime workload generation"
            );
            SandboxRuntimeControlAvailability::Unknown
        }
    }
}

async fn sandbox_runtime_supervisor_generation_matches(
    client: &Client,
    namespace: &str,
    sandbox_id: &str,
    sandbox: &DynamicObject,
) -> SandboxRuntimeControlAvailability {
    let Some(expected_uid) = sandbox
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(ANNOTATION_SANDBOX_RUNTIME_SUPERVISOR_UID))
    else {
        return SandboxRuntimeControlAvailability::Unavailable;
    };
    let names = SandboxRuntimeNames::new(sandbox_id);
    let pods = Api::<Pod>::namespaced(client.clone(), namespace);
    match tokio::time::timeout(KUBE_API_TIMEOUT, pods.get_opt(&names.supervisor_pod)).await {
        Ok(Ok(Some(pod))) if pod.metadata.uid.as_deref() == Some(expected_uid.as_str()) => {
            SandboxRuntimeControlAvailability::Available
        }
        Ok(Ok(_)) => SandboxRuntimeControlAvailability::Unavailable,
        Ok(Err(error)) => {
            warn!(pod = names.supervisor_pod, %error, "could not verify sandbox-runtime supervisor generation");
            SandboxRuntimeControlAvailability::Unknown
        }
        Err(_) => {
            warn!(
                pod = names.supervisor_pod,
                "timed out checking sandbox-runtime supervisor generation"
            );
            SandboxRuntimeControlAvailability::Unknown
        }
    }
}

async fn sandbox_from_object_with_sandbox_runtime_readiness(
    client: &Client,
    namespace: &str,
    obj: DynamicObject,
) -> Result<(String, Sandbox), String> {
    let bootstrapping = sandbox_runtime_bootstrap_in_progress(&obj);
    let sandbox_id = sandbox_id_from_object(&obj).unwrap_or_default();
    let object_namespace = obj
        .metadata
        .namespace
        .clone()
        .unwrap_or_else(|| namespace.to_string());
    let (name, mut sandbox) = sandbox_from_object(namespace, obj.clone())?;
    if bootstrapping {
        mark_sandbox_runtime_bootstrapping(&mut sandbox);
    }
    if !sandbox_id.is_empty() {
        let dependencies = Box::pin(sandbox_runtime_control_availability(
            client,
            &object_namespace,
            &sandbox_id,
        ));
        let workload_generation = Box::pin(sandbox_runtime_workload_generation_matches(
            client,
            &object_namespace,
            &name,
            &obj,
        ));
        let supervisor_generation = Box::pin(sandbox_runtime_supervisor_generation_matches(
            client,
            &object_namespace,
            &sandbox_id,
            &obj,
        ));
        let (dependencies, workload_generation, supervisor_generation) =
            tokio::join!(dependencies, workload_generation, supervisor_generation);
        // A transient API read failure is not evidence that the running
        // boundary disappeared. Preserve the CR's published readiness for
        // Unknown and let periodic reconciliation retry.
        if matches!(
            dependencies,
            SandboxRuntimeControlAvailability::Unavailable
                | SandboxRuntimeControlAvailability::Degraded
        ) || workload_generation == SandboxRuntimeControlAvailability::Unavailable
            || supervisor_generation == SandboxRuntimeControlAvailability::Unavailable
        {
            mark_sandbox_runtime_control_unavailable(&mut sandbox);
        }
    }
    Ok((name, sandbox))
}

fn mark_sandbox_runtime_bootstrapping(sandbox: &mut Sandbox) {
    if let Some(status) = sandbox.status.as_mut() {
        status.conditions.retain(|condition| {
            condition.r#type != SANDBOX_SUSPENDED_CONDITION && condition.r#type != "Bootstrapping"
        });
        status.conditions.push(SandboxCondition {
            r#type: "Bootstrapping".to_string(),
            status: "True".to_string(),
            reason: "SandboxRuntimeGenerationStarting".to_string(),
            message: "replacement sandbox-runtime generation is starting".to_string(),
            transition_time: None,
        });
    }
    mark_sandbox_runtime_control_unavailable(sandbox);
}

fn mark_sandbox_runtime_control_unavailable(sandbox: &mut Sandbox) {
    const REASON: &str = "DependenciesNotReady";
    const MESSAGE: &str = "sandbox-runtime enforcement dependencies are not ready";
    let Some(status) = sandbox.status.as_mut() else {
        return;
    };
    if let Some(ready) = status
        .conditions
        .iter_mut()
        .find(|condition| condition.r#type == "Ready")
    {
        ready.status = "False".to_string();
        ready.reason = REASON.to_string();
        ready.message = MESSAGE.to_string();
    } else {
        status.conditions.push(SandboxCondition {
            r#type: "Ready".to_string(),
            status: "False".to_string(),
            reason: REASON.to_string(),
            message: MESSAGE.to_string(),
            transition_time: None,
        });
    }
}

fn sandbox_runtime_should_run(obj: &DynamicObject) -> bool {
    if let Some(mode) = obj
        .data
        .get("spec")
        .and_then(|spec| spec.get("operatingMode"))
        .and_then(serde_json::Value::as_str)
    {
        return !mode.eq_ignore_ascii_case("Suspended");
    }
    obj.data
        .get("spec")
        .and_then(|spec| spec.get("replicas"))
        .and_then(serde_json::Value::as_i64)
        .is_none_or(|replicas| replicas > 0)
}

fn update_indexes(
    sandbox_name_to_id: &mut std::collections::HashMap<String, String>,
    agent_pod_to_id: &mut std::collections::HashMap<String, String>,
    kube_name: &str,
    sandbox: &Sandbox,
) {
    if !kube_name.is_empty() {
        sandbox_name_to_id.insert(kube_name.to_string(), sandbox.id.clone());
    }
    if let Some(status) = sandbox.status.as_ref()
        && !status.instance_id.is_empty()
    {
        agent_pod_to_id.insert(status.instance_id.clone(), sandbox.id.clone());
    }
}

fn remove_indexes(
    sandbox_name_to_id: &mut std::collections::HashMap<String, String>,
    agent_pod_to_id: &mut std::collections::HashMap<String, String>,
    sandbox_id: &str,
) {
    sandbox_name_to_id.retain(|_, value| value != sandbox_id);
    agent_pod_to_id.retain(|_, value| value != sandbox_id);
}

fn map_kube_event_to_platform(
    sandbox_name_to_id: &std::collections::HashMap<String, String>,
    agent_pod_to_id: &std::collections::HashMap<String, String>,
    obj: &KubeEventObj,
) -> Option<(String, PlatformEvent)> {
    let involved = obj.involved_object.clone();
    let involved_kind = involved.kind.unwrap_or_default();
    let involved_name = involved.name.unwrap_or_default();

    let sandbox_id = match involved_kind.as_str() {
        "Sandbox" => sandbox_name_to_id.get(&involved_name).cloned()?,
        "Pod" => sandbox_name_to_id
            .get(&involved_name)
            .cloned()
            .or_else(|| agent_pod_to_id.get(&involved_name).cloned())?,
        _ => return None,
    };

    let ts = obj
        .last_timestamp
        .as_ref()
        .or(obj.first_timestamp.as_ref())
        .map_or(0, |t| t.0.timestamp_millis());

    let mut metadata = std::collections::HashMap::new();
    metadata.insert("involved_kind".to_string(), involved_kind);
    metadata.insert("involved_name".to_string(), involved_name);
    if let Some(ns) = &obj.involved_object.namespace {
        metadata.insert("namespace".to_string(), ns.clone());
    }
    if let Some(count) = obj.count {
        metadata.insert("count".to_string(), count.to_string());
    }
    attach_kube_progress_metadata(
        &mut metadata,
        obj.reason.as_deref().unwrap_or_default(),
        obj.message.as_deref().unwrap_or_default(),
    );

    Some((
        sandbox_id,
        PlatformEvent {
            event_time: openshell_core::time::timestamp_from_millis(ts).ok(),
            source: "kubernetes".to_string(),
            r#type: obj.type_.clone().unwrap_or_default(),
            reason: obj.reason.clone().unwrap_or_default(),
            message: obj.message.clone().unwrap_or_default(),
            metadata,
        },
    ))
}

fn attach_kube_progress_metadata(
    metadata: &mut std::collections::HashMap<String, String>,
    reason: &str,
    message: &str,
) {
    match reason {
        "Scheduled" => {
            mark_progress_complete(
                metadata,
                PROGRESS_STEP_REQUESTING_SANDBOX,
                "Sandbox allocated",
            );
            mark_progress_active(metadata, PROGRESS_STEP_PULLING_IMAGE);
        }
        "Pulling" => {
            mark_progress_active(metadata, PROGRESS_STEP_PULLING_IMAGE);
            if let Some(image) = pulling_image_from_kube_message(message) {
                mark_progress_detail(metadata, image);
            }
        }
        "Pulled" => {
            let label = pulled_image_label(message);
            mark_progress_complete(metadata, PROGRESS_STEP_PULLING_IMAGE, label);
            mark_progress_active(metadata, PROGRESS_STEP_STARTING_SANDBOX);
        }
        _ => {}
    }
}

fn pulling_image_from_kube_message(message: &str) -> Option<String> {
    let image = message
        .strip_prefix("Pulling image ")
        .map(str::trim)
        .map(|value| value.trim_matches('"'))?;
    (!image.is_empty()).then(|| image.to_string())
}

fn pulled_image_label(message: &str) -> String {
    extract_image_size(message).map_or_else(
        || "Image pulled".to_string(),
        |bytes| format!("Image pulled ({})", format_bytes(bytes)),
    )
}

fn extract_image_size(message: &str) -> Option<u64> {
    let size_prefix = "Image size: ";
    let start = message.find(size_prefix)? + size_prefix.len();
    let rest = &message[start..];
    let end = rest.find(' ')?;
    rest[..end].parse().ok()
}

const SANDBOX_RUNTIME_VOLUME_NAME: &str = "openshell-runtime";
const SANDBOX_STATE_VOLUME_NAME: &str = "openshell-runtime-state";
const SANDBOX_BOOTSTRAP_VOLUME_NAME: &str = "openshell-sandbox-bootstrap";
const SANDBOX_POD_IDENTITY_VOLUME_NAME: &str = "openshell-pod-identity";
const SANDBOX_RUNTIME_MOUNT_PATH: &str = "/.openshell/runtime";
const SANDBOX_STATE_MOUNT_PATH: &str = "/.openshell/state";
const SANDBOX_POD_IDENTITY_MOUNT_PATH: &str = "/.openshell/pod-identity";
const SANDBOX_POD_UID_PATH: &str = "/.openshell/pod-identity/uid";
const SANDBOX_PROXY_CA_VOLUME_NAME: &str = "openshell-run";
const SANDBOX_PROXY_CA_MOUNT_PATH: &str = "/run";
const SANDBOX_BOOTSTRAP_SCHEDULING_GATE: &str = "openshell.ai/bootstrap";

fn sandbox_uses_persistent_volume(object: &DynamicObject) -> bool {
    object.data["spec"]["volumeClaimTemplates"]
        .as_array()
        .is_some_and(|claims| !claims.is_empty())
        || object.data["spec"]["podTemplate"]["spec"]["volumes"]
            .as_array()
            .is_some_and(|volumes| {
                volumes
                    .iter()
                    .any(|volume| volume.get("persistentVolumeClaim").is_some())
            })
}

fn sandbox_bootstrap_secret_name(spec: &serde_json::Value) -> Option<&str> {
    spec["volumes"]
        .as_array()?
        .iter()
        .find(|volume| volume["name"] == SANDBOX_BOOTSTRAP_VOLUME_NAME)?["secret"]["secretName"]
        .as_str()
        .filter(|name| !name.is_empty())
}

/// Render the workload Pod that runs the `OpenShell` sandbox runtime.
///
/// The pod receives no gateway credential or endpoint. Its non-root sandbox
/// owns the workload process and seccomp listener. The namespace workload
/// policy permits supervisor Pods to reach its TLS listener; authenticated
/// protocol identity binds the request to the exact supervisor generation.
fn apply_supervisor_sandbox_runtime_boundary(
    pod_template: &mut serde_json::Value,
    params: &SandboxPodParams<'_>,
) {
    let metadata = pod_template
        .as_object_mut()
        .expect("pod template must be an object")
        .entry("metadata")
        .or_insert_with(|| serde_json::json!({}));
    let labels = metadata
        .as_object_mut()
        .expect("pod metadata must be an object")
        .entry("labels")
        .or_insert_with(|| serde_json::json!({}));
    let labels = labels
        .as_object_mut()
        .expect("pod labels must be an object");
    labels.insert(
        BOUNDARY_PAIR_LABEL.to_string(),
        serde_json::json!(crate::sandbox_runtime::pair_label_value(params.sandbox_id)),
    );
    labels.insert(
        BOUNDARY_ROLE_LABEL.to_string(),
        serde_json::json!("workload"),
    );

    let Some(spec) = pod_template
        .get_mut("spec")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    spec.insert("hostNetwork".to_string(), serde_json::json!(false));
    spec.insert("hostPID".to_string(), serde_json::json!(false));
    spec.insert("hostIPC".to_string(), serde_json::json!(false));
    spec.insert(
        "shareProcessNamespace".to_string(),
        serde_json::json!(false),
    );
    spec.insert("dnsPolicy".to_string(), serde_json::json!("None"));
    spec.insert("enableServiceLinks".to_string(), serde_json::json!(false));
    spec.insert(
        "schedulingGates".to_string(),
        serde_json::json!([{"name": SANDBOX_BOOTSTRAP_SCHEDULING_GATE}]),
    );
    spec.insert(
        "dnsConfig".to_string(),
        serde_json::json!({
            "nameservers": ["127.0.0.53"],
            "options": [
                {"name": "ndots", "value": "5"},
                {"name": "timeout", "value": "2"},
                {"name": "attempts", "value": "2"}
            ]
        }),
    );
    spec.insert(
        "securityContext".to_string(),
        serde_json::json!({
            "runAsUser": params.sandbox_uid,
            "runAsGroup": params.sandbox_gid,
            "runAsNonRoot": true,
            "fsGroup": params.sandbox_gid,
            "fsGroupChangePolicy": "OnRootMismatch",
            "supplementalGroups": [],
            "supplementalGroupsPolicy": "Strict",
            "seccompProfile": {"type": "RuntimeDefault"},
            "sysctls": [{"name": "net.ipv4.ip_unprivileged_port_start", "value": "0"}]
        }),
    );
    let volumes = spec
        .entry("volumes")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .expect("pod volumes must be an array");
    volumes.retain(|volume| {
        !matches!(
            volume.get("name").and_then(serde_json::Value::as_str),
            Some(
                "openshell-sa-token"
                    | "openshell-client-tls"
                    | "spiffe-workload-api"
                    | SANDBOX_RUNTIME_VOLUME_NAME
                    | SANDBOX_STATE_VOLUME_NAME
                    | SANDBOX_BOOTSTRAP_VOLUME_NAME
                    | SANDBOX_POD_IDENTITY_VOLUME_NAME
                    | SANDBOX_PROXY_CA_VOLUME_NAME
            )
        )
    });
    volumes.extend([
        serde_json::json!({"name": SANDBOX_RUNTIME_VOLUME_NAME, "emptyDir": {"medium": "Memory"}}),
        serde_json::json!({"name": SANDBOX_STATE_VOLUME_NAME, "emptyDir": {"medium": "Memory"}}),
        serde_json::json!({
            "name": SANDBOX_BOOTSTRAP_VOLUME_NAME,
            "secret": {"secretName": params.sandbox_secret_name, "defaultMode": 0o440}
        }),
        serde_json::json!({
            "name": SANDBOX_POD_IDENTITY_VOLUME_NAME,
            "downwardAPI": {
                "items": [{"path": "uid", "fieldRef": {"fieldPath": "metadata.uid"}}]
            }
        }),
        serde_json::json!({
            "name": SANDBOX_PROXY_CA_VOLUME_NAME,
            "emptyDir": {"medium": "Memory"}
        }),
    ]);

    let init_containers = spec
        .entry("initContainers")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .expect("pod init containers must be an array");
    let mut bootstrap = serde_json::json!({
        "name": "openshell-sandbox-bootstrap",
        "image": params.sandbox_runtime_image,
        "command": ["/openshell-sandbox", "bootstrap"],
        "securityContext": {
            "runAsUser": params.sandbox_uid,
            "runAsGroup": params.sandbox_gid,
            "runAsNonRoot": true,
            "readOnlyRootFilesystem": true,
            "allowPrivilegeEscalation": false,
            "capabilities": {"drop": ["ALL"]}
        },
        "volumeMounts": [
            {"name": SANDBOX_BOOTSTRAP_VOLUME_NAME, "mountPath": crate::sandbox_runtime::SANDBOX_BOOTSTRAP_INPUT_PATH, "readOnly": true},
            {"name": SANDBOX_RUNTIME_VOLUME_NAME, "mountPath": SANDBOX_RUNTIME_MOUNT_PATH},
            {"name": SANDBOX_STATE_VOLUME_NAME, "mountPath": SANDBOX_STATE_MOUNT_PATH}
        ]
    });
    if let Some(policy) = params.sandbox_runtime_image_pull_policy {
        bootstrap["imagePullPolicy"] = serde_json::json!(policy.as_kubernetes_str());
    }
    init_containers.push(bootstrap);

    let containers = spec
        .get_mut("containers")
        .and_then(serde_json::Value::as_array_mut)
        .expect("pod containers must be an array");
    let index = containers
        .iter()
        .position(|container| {
            container.get("name").and_then(serde_json::Value::as_str) == Some("agent")
        })
        .unwrap_or(0);
    let container = containers[index]
        .as_object_mut()
        .expect("agent container must be an object");
    container.insert(
        "command".to_string(),
        serde_json::json!([
            format!("{SANDBOX_RUNTIME_MOUNT_PATH}/openshell-sandbox"),
            "--bootstrap",
            BOUNDARY_CONFIG_PATH,
        ]),
    );
    container.insert(
        "securityContext".to_string(),
        serde_json::json!({
            "runAsUser": params.sandbox_uid,
            "runAsGroup": params.sandbox_gid,
            "runAsNonRoot": true,
            "allowPrivilegeEscalation": false,
            "capabilities": {"drop": ["ALL"]}
        }),
    );
    container.insert(
        "ports".to_string(),
        serde_json::json!([{
            "name": "sandbox-control",
            "containerPort": params.boundary_port,
            "protocol": "TCP"
        }]),
    );
    let mounts = container
        .entry("volumeMounts")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .expect("agent volume mounts must be an array");
    mounts.retain(|mount| {
        !matches!(
            mount.get("name").and_then(serde_json::Value::as_str),
            Some(
                "openshell-sa-token"
                    | "openshell-client-tls"
                    | "spiffe-workload-api"
                    | SANDBOX_BOOTSTRAP_VOLUME_NAME
            )
        )
    });
    mounts.extend([
        serde_json::json!({"name": SANDBOX_RUNTIME_VOLUME_NAME, "mountPath": SANDBOX_RUNTIME_MOUNT_PATH, "readOnly": true}),
        serde_json::json!({"name": SANDBOX_STATE_VOLUME_NAME, "mountPath": SANDBOX_STATE_MOUNT_PATH}),
        serde_json::json!({"name": SANDBOX_POD_IDENTITY_VOLUME_NAME, "mountPath": SANDBOX_POD_IDENTITY_MOUNT_PATH, "readOnly": true}),
        serde_json::json!({"name": SANDBOX_PROXY_CA_VOLUME_NAME, "mountPath": SANDBOX_PROXY_CA_MOUNT_PATH}),
    ]);
    let env = container
        .entry("env")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .expect("agent environment must be an array");
    for key in [
        openshell_core::sandbox_env::ENDPOINT,
        openshell_core::sandbox_env::GATEWAY_TLS_SERVER_NAME,
        openshell_core::sandbox_env::TLS_CA,
        openshell_core::sandbox_env::TLS_CERT,
        openshell_core::sandbox_env::TLS_KEY,
        openshell_core::sandbox_env::SANDBOX_TOKEN,
        openshell_core::sandbox_env::SANDBOX_TOKEN_FILE,
        openshell_core::sandbox_env::K8S_SA_TOKEN_FILE,
        openshell_core::sandbox_env::PROVIDER_SPIFFE_WORKLOAD_API_SOCKET,
        openshell_core::sandbox_env::MAIN_PROCESS_SPEC,
    ] {
        remove_env(env, key);
    }
    apply_resolved_identity_env(env, params.sandbox_uid, params.sandbox_gid);
}

/// Apply workspace persistence transforms to an already-built pod template.
///
/// This injects:
///   1. A volume mount on the agent container at `/sandbox`.
///   2. An init container (same image) that seeds the PVC with the image's
///      original `/sandbox` contents on first use.
///
/// The PVC volume itself is **not** added here — the Sandbox CRD controller
/// automatically creates a volume for each entry in `volumeClaimTemplates`
/// (following the `StatefulSet` convention).  Adding one here would create a
/// duplicate volume name and fail pod validation.
///
/// The init container mounts the PVC at a temporary path so it can still see
/// the image's `/sandbox` directory.  It checks for a sentinel file and skips
/// the copy if the PVC was already initialised.
#[allow(clippy::similar_names)]
fn apply_workspace_persistence(
    pod_template: &mut serde_json::Value,
    image: &str,
    image_pull_policy: Option<crate::KubernetesImagePullPolicy>,
    sandbox_gid: Option<u32>,
    workspace_owner: Option<(u32, u32)>,
) {
    let Some(spec) = pod_template.get_mut("spec").and_then(|v| v.as_object_mut()) else {
        return;
    };

    // fsGroup is a pod-level field — it instructs kubelet to chown mounted
    // volumes to this GID. It is invalid at the container securityContext level.
    if let Some(sandbox_gid) = sandbox_gid {
        let pod_sc = spec
            .entry("securityContext")
            .or_insert_with(|| serde_json::json!({}));
        if let Some(pod_sc_obj) = pod_sc.as_object_mut() {
            pod_sc_obj.insert("fsGroup".to_string(), serde_json::json!(sandbox_gid));
        }
    }

    // 1. Add workspace volume mount to the agent container
    let containers = spec.get_mut("containers").and_then(|v| v.as_array_mut());
    if let Some(containers) = containers {
        let mut target_index = None;
        for (i, c) in containers.iter().enumerate() {
            if c.get("name").and_then(|v| v.as_str()) == Some("agent") {
                target_index = Some(i);
                break;
            }
        }
        let index = target_index.unwrap_or(0);

        if let Some(container) = containers.get_mut(index).and_then(|v| v.as_object_mut()) {
            let volume_mounts = container
                .entry("volumeMounts")
                .or_insert_with(|| serde_json::json!([]))
                .as_array_mut();
            if let Some(volume_mounts) = volume_mounts {
                volume_mounts.push(serde_json::json!({
                    "name": WORKSPACE_VOLUME_NAME,
                    "mountPath": WORKSPACE_MOUNT_PATH
                }));
            }
        }
    }

    // 3. Add the init container that seeds the PVC from the image
    let init_containers = spec
        .entry("initContainers")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut();
    if let Some(init_containers) = init_containers {
        // The init container mounts the PVC at a temp path so it can still
        // read the image's original /sandbox contents.  It copies them into
        // the PVC only when the sentinel file is absent.
        //
        // Prefer a tar stream over `cp -a`: some sandbox images contain
        // self-referential symlinks under `/sandbox/.uv`, and GNU cp can
        // fail while seeding the PVC even though preserving the symlink as-is
        // is valid. `tar` copies the tree without dereferencing those links.
        // Archive only the contents, not the `/sandbox` directory entry
        // itself, so extraction never tries to chmod the PVC mount root.
        // Extract without restoring owner, mode, or timestamps so the
        // non-root init container can seed kubelet-owned PVCs.
        //
        // The inner `[ -d ... ]` guard handles custom images that don't have
        // a /sandbox directory — the copy is skipped but the sentinel is
        // still written so subsequent starts are instant.
        let copy_cmd = format!(
            "if [ ! -f {WORKSPACE_INIT_MOUNT_PATH}/{WORKSPACE_SENTINEL} ]; then \
               if [ -d {WORKSPACE_MOUNT_PATH} ]; then \
                 tmp=$(mktemp) && rm -f \"$tmp\" && \
                   (cd {WORKSPACE_MOUNT_PATH} && find . -mindepth 1 -maxdepth 1 -exec tar -cf \"$tmp\" {{}} +) && \
                   if [ -f \"$tmp\" ]; then \
                     tar -C {WORKSPACE_INIT_MOUNT_PATH} --no-same-owner --no-same-permissions --touch -xf \"$tmp\" && \
                     rm -f \"$tmp\"; \
                   fi; \
               fi && \
               touch {WORKSPACE_INIT_MOUNT_PATH}/{WORKSPACE_SENTINEL}; \
             fi"
        );

        let mut init_spec = if let Some((uid, gid)) = workspace_owner {
            serde_json::json!({
                "name": WORKSPACE_INIT_CONTAINER_NAME,
                "image": image,
                "command": [format!("{SANDBOX_RUNTIME_MOUNT_PATH}/openshell-sandbox"), "seed-workspace"],
                "securityContext": {
                    "runAsUser": uid,
                    "runAsGroup": gid,
                    "runAsNonRoot": true,
                    "readOnlyRootFilesystem": true,
                    "allowPrivilegeEscalation": false,
                    "capabilities": {"drop": ["ALL"]}
                },
                "volumeMounts": [
                    {"name": WORKSPACE_VOLUME_NAME, "mountPath": WORKSPACE_INIT_MOUNT_PATH},
                    {"name": SANDBOX_RUNTIME_VOLUME_NAME, "mountPath": SANDBOX_RUNTIME_MOUNT_PATH, "readOnly": true}
                ]
            })
        } else {
            serde_json::json!({
                "name": WORKSPACE_INIT_CONTAINER_NAME,
                "image": image,
                "command": ["sh", "-c", copy_cmd],
                "securityContext": {"runAsUser": 0},
                "volumeMounts": [{
                    "name": WORKSPACE_VOLUME_NAME,
                    "mountPath": WORKSPACE_INIT_MOUNT_PATH
                }]
            })
        };
        if let Some(policy) = image_pull_policy {
            init_spec["imagePullPolicy"] = serde_json::json!(policy.as_kubernetes_str());
        }
        init_containers.push(init_spec);
    }
}

/// Build the default `volumeClaimTemplates` array for sandbox pods.
///
/// Provides a single PVC named "workspace" that backs the `/sandbox`
/// directory.  The init container seeds it from the image on first use.
///
/// When `storage_class` is non-empty, it is written to the PVC's
/// `storageClassName`. An empty value omits the field so the cluster's
/// default `StorageClass` applies. Clusters with no default `StorageClass`
/// must set this to prevent the PVC from staying `Pending`.
fn default_workspace_volume_claim_templates(
    storage_size: &str,
    storage_class: &str,
) -> serde_json::Value {
    let size = if storage_size.is_empty() {
        DEFAULT_WORKSPACE_STORAGE_SIZE
    } else {
        storage_size
    };
    let mut spec = serde_json::json!({
        "accessModes": ["ReadWriteOnce"],
        "resources": {
            "requests": {
                "storage": size
            }
        }
    });
    if !storage_class.is_empty() {
        spec["storageClassName"] = serde_json::json!(storage_class);
    }
    serde_json::json!([{
        "metadata": {
            "name": WORKSPACE_VOLUME_NAME
        },
        "spec": spec
    }])
}

/// Parameters shared by `sandbox_to_k8s_spec` and `sandbox_template_to_k8s`.
#[allow(clippy::struct_excessive_bools)]
struct SandboxPodParams<'a> {
    default_image: &'a str,
    image_pull_policy: Option<crate::KubernetesImagePullPolicy>,
    image_pull_secrets: &'a [String],
    sandbox_runtime_image: &'a str,
    sandbox_runtime_image_pull_policy: Option<crate::KubernetesImagePullPolicy>,
    service_account_name: &'a str,
    sandbox_id: &'a str,
    enable_user_namespaces: bool,
    workspace_default_storage_size: &'a str,
    workspace_storage_class: &'a str,
    default_runtime_class_name: &'a str,
    /// Resolved sandbox UID for supervisor `runAsUser` and env var.
    sandbox_uid: u32,
    /// Resolved sandbox GID for PVC init container operations.
    sandbox_gid: u32,
    /// TLS listener port exposed only to the paired supervisor Pod.
    boundary_port: u16,
    /// Immutable Secret name for this workload Pod generation.
    sandbox_secret_name: &'a str,
}

impl Default for SandboxPodParams<'_> {
    fn default() -> Self {
        Self {
            default_image: "",
            image_pull_policy: None,
            image_pull_secrets: &[],
            sandbox_runtime_image: "",
            sandbox_runtime_image_pull_policy: None,
            service_account_name: DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME,
            sandbox_id: "",
            enable_user_namespaces: false,
            workspace_default_storage_size: DEFAULT_WORKSPACE_STORAGE_SIZE,
            workspace_storage_class: "",
            default_runtime_class_name: "",
            sandbox_uid: DEFAULT_SANDBOX_UID,
            sandbox_gid: DEFAULT_SANDBOX_UID,
            boundary_port: 5500,
            sandbox_secret_name: "os-sandbox-test-generation",
        }
    }
}

fn spec_pod_env(spec: Option<&SandboxSpec>) -> std::collections::HashMap<String, String> {
    let mut env = spec.map_or_else(Default::default, |s| s.environment.clone());
    if let Some(s) = spec.filter(|s| !s.log_level.is_empty()) {
        env.insert(
            openshell_core::sandbox_env::LOG_LEVEL.to_string(),
            s.log_level.clone(),
        );
    }
    env
}

fn kubernetes_driver_config_for_spec(
    spec: Option<&SandboxSpec>,
) -> Result<KubernetesSandboxDriverConfig, String> {
    let config = spec
        .and_then(|spec| spec.template.as_ref())
        .map(KubernetesSandboxDriverConfig::from_template)
        .transpose()?
        .unwrap_or_default();
    validate_kubernetes_protected_path_conflicts(
        &config.containers.agent.volume_mounts,
        KUBERNETES_DRIVER_PROTECTED_MOUNT_PATHS,
    )?;
    Ok(config)
}

fn sandbox_to_k8s_spec(
    spec: Option<&SandboxSpec>,
    params: &SandboxPodParams<'_>,
) -> Result<serde_json::Value, String> {
    let driver_config = kubernetes_driver_config_for_spec(spec)?;
    let mut root = serde_json::Map::new();

    // Determine early whether OpenShell should inject its default workspace
    // PVC. Explicit Kubernetes driver-config mounts under /sandbox/ take
    // ownership of workspace persistence.
    // We need this flag before building the podTemplate because the workspace
    // persistence transforms are applied inside sandbox_template_to_k8s.
    let user_has_explicit_workspace_mount = driver_config.has_explicit_sandbox_data_mount();
    let inject_workspace = !user_has_explicit_workspace_mount;

    if let Some(spec) = spec {
        let pod_env = spec_pod_env(Some(spec));
        if let Some(template) = spec.template.as_ref() {
            root.insert(
                "podTemplate".to_string(),
                sandbox_template_to_k8s_with_validated_config(
                    template,
                    driver_gpu_requirements(spec.resource_requirements.as_ref()),
                    &pod_env,
                    &driver_config,
                    inject_workspace,
                    params,
                ),
            );
            if !template.agent_socket_path.is_empty() {
                root.insert(
                    "agentSocket".to_string(),
                    serde_json::json!(template.agent_socket_path),
                );
            }
        }
    }

    if inject_workspace {
        root.insert(
            "volumeClaimTemplates".to_string(),
            default_workspace_volume_claim_templates(
                params.workspace_default_storage_size,
                params.workspace_storage_class,
            ),
        );
    }

    // podTemplate is required by the Kubernetes CRD - ensure it's always present
    if !root.contains_key("podTemplate") {
        let pod_env = spec_pod_env(spec);
        root.insert(
            "podTemplate".to_string(),
            sandbox_template_to_k8s_with_validated_config(
                &SandboxTemplate::default(),
                driver_gpu_requirements(spec.and_then(|s| s.resource_requirements.as_ref())),
                &pod_env,
                &driver_config,
                inject_workspace,
                params,
            ),
        );
    }

    Ok(serde_json::Value::Object(
        std::iter::once(("spec".to_string(), serde_json::Value::Object(root))).collect(),
    ))
}

#[cfg(test)]
fn sandbox_template_to_k8s(
    template: &SandboxTemplate,
    gpu: bool,
    spec_environment: &std::collections::HashMap<String, String>,
    inject_workspace: bool,
    params: &SandboxPodParams<'_>,
) -> serde_json::Value {
    let gpu_requirements = gpu.then_some(GpuResourceRequirements { count: None });
    let driver_config = KubernetesSandboxDriverConfig::from_template(template)
        .expect("test Kubernetes driver_config should be valid");
    sandbox_template_to_k8s_with_validated_config(
        template,
        gpu_requirements.as_ref(),
        spec_environment,
        &driver_config,
        inject_workspace,
        params,
    )
}

#[cfg(test)]
fn sandbox_template_to_k8s_with_gpu_requirements(
    template: &SandboxTemplate,
    gpu_requirements: Option<&GpuResourceRequirements>,
    spec_environment: &std::collections::HashMap<String, String>,
    inject_workspace: bool,
    params: &SandboxPodParams<'_>,
) -> serde_json::Value {
    let driver_config = KubernetesSandboxDriverConfig::from_template(template)
        .expect("test Kubernetes driver_config should be valid");
    sandbox_template_to_k8s_with_validated_config(
        template,
        gpu_requirements,
        spec_environment,
        &driver_config,
        inject_workspace,
        params,
    )
}

fn sandbox_template_to_k8s_with_validated_config(
    template: &SandboxTemplate,
    gpu_requirements: Option<&GpuResourceRequirements>,
    spec_environment: &std::collections::HashMap<String, String>,
    driver_config: &KubernetesSandboxDriverConfig,
    inject_workspace: bool,
    params: &SandboxPodParams<'_>,
) -> serde_json::Value {
    let mut metadata = serde_json::Map::new();
    let pod_labels = template
        .labels
        .iter()
        .map(|(key, value)| (key.clone(), serde_json::Value::String(value.clone())))
        .collect::<serde_json::Map<String, serde_json::Value>>();
    if !pod_labels.is_empty() {
        metadata.insert("labels".to_string(), serde_json::Value::Object(pod_labels));
    }
    // Carry the sandbox UUID as Pod metadata for runtime identity and bootstrap binding.
    let mut pod_annotations = platform_config_struct(template, "annotations")
        .and_then(|v| match v {
            serde_json::Value::Object(map) => Some(map),
            _ => None,
        })
        .unwrap_or_default();
    if !params.sandbox_id.is_empty() {
        pod_annotations.insert(
            LABEL_SANDBOX_ID.to_string(),
            serde_json::Value::String(params.sandbox_id.to_string()),
        );
    }
    if !pod_annotations.is_empty() {
        metadata.insert(
            "annotations".to_string(),
            serde_json::Value::Object(pod_annotations),
        );
    }

    let mut spec = serde_json::Map::new();
    let runtime_class_name = platform_config_string(template, "runtime_class_name")
        .or_else(|| {
            (!driver_config.pod.runtime_class_name.is_empty())
                .then(|| driver_config.pod.runtime_class_name.clone())
        })
        .or_else(|| {
            (!params.default_runtime_class_name.is_empty())
                .then(|| params.default_runtime_class_name.to_string())
        });
    if let Some(runtime_class) = runtime_class_name {
        spec.insert(
            "runtimeClassName".to_string(),
            serde_json::json!(runtime_class),
        );
    }
    if let Some(node_selector) = platform_config_struct(template, "node_selector") {
        spec.insert("nodeSelector".to_string(), node_selector);
    }
    if let Some(tolerations) = platform_config_struct(template, "tolerations") {
        spec.insert("tolerations".to_string(), tolerations);
    }
    apply_pod_driver_config(&mut spec, &driver_config.pod);

    // Per-sandbox portable intent overrides the cluster-wide default. This
    // driver owns the Kubernetes-specific `hostUsers` translation.
    let use_user_namespaces = template
        .user_namespaces
        .unwrap_or(params.enable_user_namespaces);

    if use_user_namespaces {
        spec.insert("hostUsers".to_string(), serde_json::json!(false));
        if gpu_requirements.is_some() {
            warn!(
                "GPU sandbox with user namespaces enabled — \
                 NVIDIA device plugin compatibility is unverified"
            );
        }
    }

    if !params.service_account_name.is_empty() {
        spec.insert(
            "serviceAccountName".to_string(),
            serde_json::json!(params.service_account_name),
        );
    }

    let image_pull_secrets = image_pull_secret_refs(params.image_pull_secrets);
    if !image_pull_secrets.is_empty() {
        spec.insert(
            "imagePullSecrets".to_string(),
            serde_json::Value::Array(image_pull_secrets),
        );
    }

    // Disable service account token auto-mounting for security hardening.
    // Sandbox pods should not have access to the Kubernetes API by default.
    spec.insert(
        "automountServiceAccountToken".to_string(),
        serde_json::json!(false),
    );
    // Do not let kubelet replace the canonical main-process generation after
    // the supervisor exits. The gateway records that exit as terminal Error.
    spec.insert("restartPolicy".to_string(), serde_json::json!("Never"));

    let mut container = serde_json::Map::new();
    container.insert("name".to_string(), serde_json::json!("agent"));
    // Use template image if provided, otherwise fall back to default
    let image = if template.image.is_empty() {
        params.default_image
    } else {
        &template.image
    };
    if !image.is_empty() {
        container.insert("image".to_string(), serde_json::json!(image));
        if let Some(policy) = params.image_pull_policy {
            container.insert(
                "imagePullPolicy".to_string(),
                serde_json::json!(policy.as_kubernetes_str()),
            );
        }
    }

    let env = build_sandbox_env(&template.environment, spec_environment);

    container.insert("env".to_string(), serde_json::Value::Array(env));

    let volume_mounts = driver_config
        .containers
        .agent
        .volume_mounts
        .iter()
        .map(kubernetes_driver_volume_mount_to_k8s)
        .collect::<Vec<_>>();
    container.insert(
        "volumeMounts".to_string(),
        serde_json::Value::Array(volume_mounts),
    );

    if let Some(resources) = container_resources(template, gpu_requirements) {
        container.insert("resources".to_string(), resources);
    }
    apply_agent_driver_resources(&mut container, &driver_config.containers.agent.resources);
    spec.insert(
        "containers".to_string(),
        serde_json::Value::Array(vec![serde_json::Value::Object(container)]),
    );

    let volumes = driver_config
        .volumes
        .iter()
        .map(kubernetes_driver_volume_to_k8s)
        .collect::<Vec<_>>();
    spec.insert("volumes".to_string(), serde_json::Value::Array(volumes));

    let mut template_value = serde_json::Map::new();
    if !metadata.is_empty() {
        template_value.insert("metadata".to_string(), serde_json::Value::Object(metadata));
    }
    template_value.insert("spec".to_string(), serde_json::Value::Object(spec));

    let mut result = serde_json::Value::Object(template_value);

    apply_supervisor_sandbox_runtime_boundary(&mut result, params);

    // Inject workspace persistence (init container + PVC volume mount) so
    // that /sandbox data survives pod rescheduling. Skipped when the user
    // provides custom storage through driver_config.
    if inject_workspace {
        apply_workspace_persistence(
            &mut result,
            image,
            params.image_pull_policy,
            None,
            Some((params.sandbox_uid, params.sandbox_gid)),
        );
    }

    result
}

fn apply_pod_driver_config(
    spec: &mut serde_json::Map<String, serde_json::Value>,
    config: &KubernetesPodDriverConfig,
) {
    if !config.node_selector.is_empty() {
        let node_selector = spec
            .entry("nodeSelector".to_string())
            .or_insert_with(|| serde_json::json!({}));
        merge_string_map(node_selector, &config.node_selector);
    }

    if !config.priority_class_name.is_empty() {
        spec.entry("priorityClassName".to_string())
            .or_insert_with(|| serde_json::json!(config.priority_class_name));
    }

    if !config.tolerations.is_empty() {
        let tolerations = spec
            .entry("tolerations".to_string())
            .or_insert_with(|| serde_json::json!([]));
        if let Some(existing) = tolerations.as_array_mut() {
            existing.extend(config.tolerations.iter().cloned());
        } else {
            *tolerations = serde_json::Value::Array(config.tolerations.clone());
        }
    }
}

fn apply_agent_driver_resources(
    container: &mut serde_json::Map<String, serde_json::Value>,
    resources: &KubernetesContainerResourceConfig,
) {
    if resources.requests.is_empty() && resources.limits.is_empty() {
        return;
    }

    let target = container
        .entry("resources".to_string())
        .or_insert_with(|| serde_json::json!({}));
    apply_resource_quantity_map(target, "requests", &resources.requests);
    apply_resource_quantity_map(target, "limits", &resources.limits);
}

fn merge_string_map(target: &mut serde_json::Value, values: &BTreeMap<String, String>) {
    if !target.is_object() {
        *target = serde_json::json!({});
    }
    let target = target
        .as_object_mut()
        .expect("target was converted to object");
    for (key, value) in values {
        target
            .entry(key.clone())
            .or_insert_with(|| serde_json::json!(value));
    }
}

fn apply_resource_quantity_map(
    target: &mut serde_json::Value,
    section: &str,
    values: &BTreeMap<String, String>,
) {
    if values.is_empty() {
        return;
    }
    if !target.is_object() {
        *target = serde_json::json!({});
    }
    let target = target
        .as_object_mut()
        .expect("target was converted to object");
    let section_value = target
        .entry(section.to_string())
        .or_insert_with(|| serde_json::json!({}));
    merge_string_map(section_value, values);
}

fn image_pull_secret_refs(secrets: &[String]) -> Vec<serde_json::Value> {
    secrets
        .iter()
        .map(|secret| secret.trim())
        .filter(|secret| !secret.is_empty())
        .map(|secret| serde_json::json!({ "name": secret }))
        .collect()
}

fn container_resources(
    template: &SandboxTemplate,
    gpu_requirements: Option<&GpuResourceRequirements>,
) -> Option<serde_json::Value> {
    // Start from the raw resources passthrough in platform_config (preserves
    // custom resource types like GPU limits that users set via the public API
    // Struct), then overlay the typed DriverResourceRequirements on top.
    let mut resources =
        platform_config_struct(template, "resources_raw").unwrap_or_else(|| serde_json::json!({}));

    // Overlay typed CPU/memory from DriverResourceRequirements.
    if let Some(ref req) = template.resources {
        let obj = resources.as_object_mut().unwrap();
        let mut apply = |section: &str, key: &str, value: &str| {
            if !value.is_empty() {
                let sec = obj.entry(section).or_insert_with(|| serde_json::json!({}));
                sec[key] = serde_json::json!(value);
            }
        };
        apply("limits", "cpu", &req.cpu_limit);
        apply("limits", "memory", &req.memory_limit);

        let cpu_request = if req.cpu_request.is_empty() {
            &req.cpu_limit
        } else {
            &req.cpu_request
        };
        let memory_request = if req.memory_request.is_empty() {
            &req.memory_limit
        } else {
            &req.memory_request
        };
        apply("requests", "cpu", cpu_request);
        apply("requests", "memory", memory_request);
    }

    if let Some(gpu) = gpu_requirements {
        let quantity = gpu.count.unwrap_or(1).to_string();
        apply_gpu_limit(&mut resources, &quantity);
    }
    if resources.as_object().is_some_and(serde_json::Map::is_empty) {
        None
    } else {
        Some(resources)
    }
}

fn apply_gpu_limit(resources: &mut serde_json::Value, quantity: &str) {
    let Some(resources_obj) = resources.as_object_mut() else {
        *resources = serde_json::json!({});
        return apply_gpu_limit(resources, quantity);
    };

    let limits = resources_obj
        .entry("limits")
        .or_insert_with(|| serde_json::json!({}));
    let Some(limits_obj) = limits.as_object_mut() else {
        *limits = serde_json::json!({});
        return apply_gpu_limit(resources, quantity);
    };

    limits_obj.insert(GPU_RESOURCE_NAME.to_string(), serde_json::json!(quantity));
}

fn build_sandbox_env(
    template_environment: &std::collections::HashMap<String, String>,
    spec_environment: &std::collections::HashMap<String, String>,
) -> Vec<serde_json::Value> {
    let mut env = Vec::new();
    for (name, value) in template_environment.iter().chain(spec_environment) {
        // User values travel only in the sealed boundary.json child_env.
        // Even non-secret-looking variables can contain arbitrary credentials.
        if name == openshell_core::sandbox_env::LOG_LEVEL {
            upsert_env(&mut env, name, value);
        }
    }
    upsert_env(
        &mut env,
        openshell_core::sandbox_env::TELEMETRY_ENABLED,
        openshell_core::telemetry::enabled_env_value(),
    );
    env
}

fn upsert_env(env: &mut Vec<serde_json::Value>, name: &str, value: &str) {
    if let Some(existing) = env
        .iter_mut()
        .find(|item| item.get("name").and_then(|value| value.as_str()) == Some(name))
    {
        *existing = serde_json::json!({"name": name, "value": value});
        return;
    }

    env.push(serde_json::json!({"name": name, "value": value}));
}

fn apply_resolved_identity_env(env: &mut Vec<serde_json::Value>, uid: u32, gid: u32) {
    remove_env(env, openshell_core::sandbox_env::OCI_IMAGE_USER);
    remove_env(env, openshell_core::sandbox_env::SANDBOX_UID);
    remove_env(env, openshell_core::sandbox_env::SANDBOX_GID);
    upsert_env(env, openshell_core::sandbox_env::OCI_IMAGE_USER, "");
    upsert_env(
        env,
        openshell_core::sandbox_env::SANDBOX_UID,
        &uid.to_string(),
    );
    upsert_env(
        env,
        openshell_core::sandbox_env::SANDBOX_GID,
        &gid.to_string(),
    );
}

fn remove_env(env: &mut Vec<serde_json::Value>, name: &str) {
    env.retain(|item| item.get("name").and_then(|value| value.as_str()) != Some(name));
}

/// Extract a string value from the template's `platform_config` Struct.
fn platform_config_string(template: &SandboxTemplate, key: &str) -> Option<String> {
    let config = template.platform_config.as_ref()?;
    let value = config.fields.get(key)?;
    match value.kind.as_ref() {
        Some(prost_types::value::Kind::StringValue(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// Extract a nested Struct value from the template's `platform_config`,
/// converting it to `serde_json::Value`.
fn platform_config_struct(template: &SandboxTemplate, key: &str) -> Option<serde_json::Value> {
    let config = template.platform_config.as_ref()?;
    let value = config.fields.get(key)?;
    let json = value_to_json(value);
    // Return None for null/empty objects so callers can distinguish
    // "field absent" from "field present but empty".
    match &json {
        serde_json::Value::Null => None,
        serde_json::Value::Object(m) if m.is_empty() => None,
        _ => Some(json),
    }
}

fn workload_environment_from_spec(
    spec: Option<&SandboxSpec>,
) -> std::collections::HashMap<String, String> {
    let mut environment = spec
        .and_then(|spec| spec.template.as_ref())
        .map_or_else(std::collections::HashMap::new, |template| {
            template.environment.clone()
        });
    if let Some(spec) = spec {
        environment.extend(spec.environment.clone());
    }
    environment.retain(|name, _| !name.starts_with("OPENSHELL_"));
    environment
}

// A mutated CR/Pod must not reintroduce host-visible user env before policy
// generation. Image defaults are public inputs pinned by the image digest.
fn workload_environment_is_private(pod: &Pod) -> bool {
    pod.spec.as_ref().is_some_and(|spec| {
        spec.containers
            .iter()
            .chain(spec.init_containers.iter().flatten())
            .all(|container| {
                container.env_from.as_deref().is_none_or(<[_]>::is_empty)
                    && container.env.iter().flatten().all(|entry| {
                        entry.value_from.is_none()
                            && matches!(
                                entry.name.as_str(),
                                openshell_core::sandbox_env::LOG_LEVEL
                                    | openshell_core::sandbox_env::TELEMETRY_ENABLED
                                    | openshell_core::sandbox_env::OCI_IMAGE_USER
                                    | openshell_core::sandbox_env::SANDBOX_UID
                                    | openshell_core::sandbox_env::SANDBOX_GID
                            )
                    })
            })
    })
}

fn required_sandbox_annotation(
    object: &DynamicObject,
    name: &str,
) -> Result<String, KubernetesDriverError> {
    object
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(name))
        .cloned()
        .ok_or_else(|| {
            KubernetesDriverError::Precondition(format!(
                "Sandbox resource is missing required annotation {name}"
            ))
        })
}

fn condition_observes_current_generation(
    object: &DynamicObject,
    condition: &serde_json::Value,
) -> bool {
    match (
        object.metadata.generation,
        condition
            .get("observedGeneration")
            .and_then(serde_json::Value::as_i64),
    ) {
        (Some(generation), Some(observed_generation)) => generation == observed_generation,
        // Older Agent Sandbox API versions can omit observedGeneration.
        _ => true,
    }
}

fn status_from_object(obj: &DynamicObject) -> Option<SandboxStatus> {
    let status = obj.data.get("status")?;
    let status_obj = status.as_object()?;

    let conditions = status_obj
        .get("conditions")
        .and_then(|val| val.as_array())
        .map(|items| {
            items
                .iter()
                .filter(|condition| condition_observes_current_generation(obj, condition))
                .filter_map(condition_from_value)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Some(SandboxStatus {
        name: status_obj
            .get("sandboxName")
            .and_then(|val| val.as_str())
            .unwrap_or_default()
            .to_string(),
        instance_id: status_obj
            .get("agentPod")
            .and_then(|val| val.as_str())
            .unwrap_or_default()
            .to_string(),
        agent_fd: status_obj
            .get("agentFd")
            .and_then(|val| val.as_str())
            .unwrap_or_default()
            .to_string(),
        sandbox_fd: status_obj
            .get("sandboxFd")
            .and_then(|val| val.as_str())
            .unwrap_or_default()
            .to_string(),
        conditions,
        deleting: obj.metadata.deletion_timestamp.is_some(),
        ..Default::default()
    })
}

async fn create_or_validate_sandbox_runtime_fence(
    policies: &Api<NetworkPolicy>,
    expected: &NetworkPolicy,
) -> Result<(), KubernetesDriverError> {
    let name = expected.metadata.name.as_deref().unwrap_or_default();
    match tokio::time::timeout(KUBE_API_TIMEOUT, policies.get_opt(name)).await {
        Ok(Ok(Some(existing))) => {
            return validate_sandbox_runtime_fence(&existing, expected);
        }
        Ok(Ok(None)) => {}
        Ok(Err(error)) => return Err(KubernetesDriverError::from_kube(error)),
        Err(_) => {
            return Err(KubernetesDriverError::Message(
                "timed out reading sandbox-runtime workload fence".to_string(),
            ));
        }
    }

    match tokio::time::timeout(
        KUBE_API_TIMEOUT,
        policies.create(&PostParams::default(), expected),
    )
    .await
    {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(KubeError::Api(error))) if error.code == 409 => {
            let existing = tokio::time::timeout(KUBE_API_TIMEOUT, policies.get(name))
                .await
                .map_err(|_| {
                    KubernetesDriverError::Message(
                        "timed out validating existing sandbox-runtime workload fence".to_string(),
                    )
                })?
                .map_err(KubernetesDriverError::from_kube)?;
            validate_sandbox_runtime_fence(&existing, expected)
        }
        Ok(Err(error)) => Err(KubernetesDriverError::from_kube(error)),
        Err(_) => Err(KubernetesDriverError::Message(
            "timed out creating sandbox-runtime workload fence".to_string(),
        )),
    }
}

fn validate_sandbox_runtime_fence(
    existing: &NetworkPolicy,
    expected: &NetworkPolicy,
) -> Result<(), KubernetesDriverError> {
    if sandbox_runtime_fence_matches(existing, expected) {
        Ok(())
    } else {
        let name = expected.metadata.name.as_deref().unwrap_or_default();
        Err(KubernetesDriverError::Precondition(format!(
            "sandbox-runtime workload fence {name} exists but does not match the intended enforcement"
        )))
    }
}

fn sandbox_runtime_fence_matches(existing: &NetworkPolicy, expected: &NetworkPolicy) -> bool {
    fn normalized_spec(mut spec: Option<NetworkPolicySpec>) -> Option<NetworkPolicySpec> {
        if let Some(spec) = spec.as_mut() {
            // The Kubernetes API server omits explicitly empty rule arrays when it
            // persists a NetworkPolicy. For a policy type named in `policyTypes`,
            // an omitted rule array and an empty rule array both deny all traffic.
            if spec.egress.as_ref().is_some_and(Vec::is_empty) {
                spec.egress = None;
            }
            if spec.ingress.as_ref().is_some_and(Vec::is_empty) {
                spec.ingress = None;
            }
        }
        spec
    }

    fn contains_required_metadata(
        actual: &Option<BTreeMap<String, String>>,
        required: &Option<BTreeMap<String, String>>,
    ) -> bool {
        required.as_ref().is_none_or(|required| {
            actual.as_ref().is_some_and(|actual| {
                required
                    .iter()
                    .all(|(key, value)| actual.get(key) == Some(value))
            })
        })
    }

    normalized_spec(existing.spec.clone()) == normalized_spec(expected.spec.clone())
        && contains_required_metadata(&existing.metadata.labels, &expected.metadata.labels)
        && contains_required_metadata(
            &existing.metadata.annotations,
            &expected.metadata.annotations,
        )
}

fn sandbox_runtime_namespace_fence_generation_matches(
    policy: &NetworkPolicy,
    sandbox: &DynamicObject,
) -> bool {
    let Some(annotations) = sandbox.metadata.annotations.as_ref() else {
        return false;
    };
    policy.metadata.uid.as_deref()
        == annotations
            .get(ANNOTATION_SANDBOX_RUNTIME_NETWORK_POLICY_UID)
            .map(String::as_str)
        && annotations
            .get(ANNOTATION_SANDBOX_RUNTIME_NETWORK_POLICY_GENERATION)
            .and_then(|generation| generation.parse::<i64>().ok())
            == policy.metadata.generation
}

fn kubernetes_sandbox_has_stopped_condition(obj: &DynamicObject) -> bool {
    obj.data
        .get("status")
        .and_then(|status| status.get("conditions"))
        .and_then(serde_json::Value::as_array)
        .is_some_and(|conditions| {
            conditions.iter().any(|condition| {
                condition_observes_current_generation(obj, condition)
                    && condition.get("type").and_then(serde_json::Value::as_str)
                        == Some(SANDBOX_SUSPENDED_CONDITION)
                    && condition
                        .get("status")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|status| status.eq_ignore_ascii_case("true"))
            })
        })
}

fn kubernetes_sandbox_stop_is_complete(
    api_version: &str,
    obj: &DynamicObject,
    pod_is_gone: bool,
) -> bool {
    if api_version == SANDBOX_VERSION_V1ALPHA1 {
        // v1alpha1 omits a usable stopped condition.
        pod_is_gone
    } else {
        kubernetes_sandbox_has_stopped_condition(obj) && pod_is_gone
    }
}

fn kubernetes_sandbox_stop_failure(obj: &DynamicObject) -> Option<String> {
    obj.data
        .get("status")?
        .get("conditions")?
        .as_array()?
        .iter()
        .find_map(|condition| {
            let is_terminal = condition_observes_current_generation(obj, condition)
                && condition.get("type").and_then(serde_json::Value::as_str)
                    == Some(SANDBOX_SUSPENDED_CONDITION)
                && condition
                    .get("status")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|status| status.eq_ignore_ascii_case("false"))
                && condition.get("reason").and_then(serde_json::Value::as_str)
                    == Some(SANDBOX_SUSPENDED_POD_NOT_OWNED_REASON);
            if !is_terminal {
                return None;
            }

            let message = condition
                .get("message")
                .and_then(serde_json::Value::as_str)
                .filter(|message| !message.is_empty())
                .unwrap_or("backing pod is not owned by this sandbox");
            Some(format!("Kubernetes sandbox stop rejected: {message}"))
        })
}

async fn kubernetes_sandbox_pod_is_gone(
    pod_api: &Api<Pod>,
    pod_name: &str,
    deadline: tokio::time::Instant,
) -> Result<bool, String> {
    let request_timeout =
        KUBE_API_TIMEOUT.min(deadline.saturating_duration_since(tokio::time::Instant::now()));
    if request_timeout.is_zero() {
        return Ok(false);
    }

    match tokio::time::timeout(request_timeout, pod_api.get(pod_name)).await {
        Ok(Ok(_)) => Ok(false),
        Ok(Err(KubeError::Api(err))) if err.code == 404 => Ok(true),
        Ok(Err(err)) => Err(err.to_string()),
        Err(_) => Err(format!(
            "timed out after {}s waiting for Kubernetes API while checking sandbox pod termination",
            request_timeout.as_secs()
        )),
    }
}

async fn wait_for_sandbox_role_pods_deleted(
    pod_api: &Api<Pod>,
    workload_pod_name: &str,
    supervisor_pod_name: &str,
    deadline: tokio::time::Instant,
) -> Result<(), String> {
    loop {
        let workload_gone =
            kubernetes_sandbox_pod_is_gone(pod_api, workload_pod_name, deadline).await?;
        let supervisor_gone =
            kubernetes_sandbox_pod_is_gone(pod_api, supervisor_pod_name, deadline).await?;
        if workload_gone && supervisor_gone {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("Sandbox role Pod deletion was not confirmed".to_string());
        }
        tokio::time::sleep(STOP_INITIAL_POLL_INTERVAL).await;
    }
}

fn kubernetes_sandbox_stop_timeout(obj: &DynamicObject) -> Duration {
    let termination_grace_period = obj
        .data
        .get("spec")
        .and_then(|spec| spec.get("podTemplate"))
        .and_then(|template| template.get("spec"))
        .and_then(|spec| spec.get("terminationGracePeriodSeconds"))
        .and_then(serde_json::Value::as_u64)
        .map_or(DEFAULT_POD_TERMINATION_GRACE_PERIOD, Duration::from_secs);

    // The controller must observe the desired state, wait for the pod grace
    // period and kubelet teardown, then reconcile the deleted pod into the
    // Sandbox status. Keep one API timeout of headroom around that grace.
    termination_grace_period.saturating_add(KUBE_API_TIMEOUT)
}

fn kubernetes_pod_termination_timeout(pod: &Pod) -> Duration {
    let default_grace = u64::try_from(SUPERVISOR_TERMINATION_GRACE_PERIOD_SECONDS)
        .map_or(DEFAULT_POD_TERMINATION_GRACE_PERIOD, Duration::from_secs);
    let termination_grace = pod
        .spec
        .as_ref()
        .and_then(|spec| spec.termination_grace_period_seconds)
        .and_then(|seconds| u64::try_from(seconds).ok())
        .map_or(default_grace, Duration::from_secs);
    termination_grace.saturating_add(KUBE_API_TIMEOUT)
}

fn next_stop_poll_interval(current: Duration) -> Duration {
    current.saturating_mul(2).min(STOP_MAX_POLL_INTERVAL)
}

fn sandbox_operating_state_patch(
    api_version: &str,
    resource_version: &str,
    running: bool,
) -> serde_json::Value {
    if api_version == SANDBOX_VERSION_V1BETA1 {
        if running {
            serde_json::json!({
                "metadata": {"resourceVersion": resource_version},
                "spec": {"operatingMode": "Running"}
            })
        } else {
            sandbox_runtime_suspension_patch(api_version, resource_version)
        }
    } else {
        if running {
            serde_json::json!({
                "metadata": {"resourceVersion": resource_version},
                "spec": {"replicas": 1}
            })
        } else {
            sandbox_runtime_suspension_patch(api_version, resource_version)
        }
    }
}

fn sandbox_runtime_stop_begin_patch(resource_version: &str) -> serde_json::Value {
    serde_json::json!({
        "metadata": {
            "resourceVersion": resource_version,
            "annotations": {
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAPPING: "true",
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_STARTED_AT: openshell_core::time::now_ms().to_string(),
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_OPERATION: "stop",
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_PHASE: SandboxRuntimeBootstrapPhase::Releasing.as_str(),
                ANNOTATION_SANDBOX_RUNTIME_READINESS: "unavailable",
            },
        },
    })
}

fn sandbox_runtime_suspension_patch(
    api_version: &str,
    resource_version: &str,
) -> serde_json::Value {
    let desired_state = if api_version == SANDBOX_VERSION_V1BETA1 {
        serde_json::json!({"operatingMode": "Suspended"})
    } else {
        serde_json::json!({"replicas": 0})
    };
    serde_json::json!({
        "metadata": {
            "resourceVersion": resource_version,
            "annotations": {
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAPPING: "true",
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_STARTED_AT: openshell_core::time::now_ms().to_string(),
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_OPERATION: "stop",
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_PHASE: SandboxRuntimeBootstrapPhase::Suspending.as_str(),
                ANNOTATION_SANDBOX_RUNTIME_READINESS: "unavailable",
            },
        },
        "spec": desired_state,
    })
}

fn sandbox_runtime_suspension_completion_patch(resource_version: &str) -> serde_json::Value {
    serde_json::json!({
        "metadata": {
            "resourceVersion": resource_version,
            "annotations": {
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAPPING: serde_json::Value::Null,
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_STARTED_AT: serde_json::Value::Null,
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_OPERATION: serde_json::Value::Null,
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_PHASE: serde_json::Value::Null,
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_SESSION: serde_json::Value::Null,
                ANNOTATION_SANDBOX_RUNTIME_GENERATION: serde_json::Value::Null,
                ANNOTATION_SANDBOX_RUNTIME_WORKLOAD_UID: serde_json::Value::Null,
                ANNOTATION_SANDBOX_RUNTIME_SUPERVISOR_UID: serde_json::Value::Null,
                ANNOTATION_SANDBOX_RUNTIME_NETWORK_POLICY_UID: serde_json::Value::Null,
                ANNOTATION_SANDBOX_RUNTIME_NETWORK_POLICY_GENERATION: serde_json::Value::Null,
                ANNOTATION_SANDBOX_RUNTIME_READINESS: "unavailable",
            },
        }
    })
}

fn condition_from_value(value: &serde_json::Value) -> Option<SandboxCondition> {
    let obj = value.as_object()?;
    Some(SandboxCondition {
        r#type: obj.get("type")?.as_str()?.to_string(),
        status: obj.get("status")?.as_str()?.to_string(),
        reason: obj
            .get("reason")
            .and_then(|val| val.as_str())
            .unwrap_or_default()
            .to_string(),
        message: obj
            .get("message")
            .and_then(|val| val.as_str())
            .unwrap_or_default()
            .to_string(),
        transition_time: obj
            .get("lastTransitionTime")
            .and_then(|val| val.as_str())
            .and_then(|value| value.parse().ok()),
    })
}

fn spawn_namespace_label_watcher(
    client: Client,
    label_selector: String,
    allowlist: OperatorNamespaceAllowlist,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let ns_api: Api<Namespace> = Api::all(client);
    let watcher_config = watcher::Config::default().labels(&label_selector);
    let jitter_seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_secs() ^ u64::from(duration.subsec_nanos())
        });

    tokio::spawn(async move {
        let mut retry_attempt = 0;
        let mut relisted_names = std::collections::BTreeSet::new();
        loop {
            let mut stream = watcher::watcher(ns_api.clone(), watcher_config.clone()).boxed();

            loop {
                let event = tokio::select! {
                    result = stream.try_next() => result,
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            return;
                        }
                        continue;
                    }
                };
                match event {
                    Ok(Some(Event::Apply(ns))) => {
                        retry_attempt = 0;
                        if let Some(name) = ns.metadata.name.as_deref()
                            && allowlist.insert(name.to_string())
                        {
                            info!(namespace = name, "operator namespace added to allowlist");
                        }
                    }
                    Ok(Some(Event::Delete(ns))) => {
                        retry_attempt = 0;
                        if let Some(name) = ns.metadata.name.as_deref()
                            && allowlist.remove(name)
                        {
                            info!(
                                namespace = name,
                                "operator namespace removed from allowlist"
                            );
                        }
                    }
                    Ok(Some(Event::Init)) => {
                        retry_attempt = 0;
                        relisted_names.clear();
                    }
                    Ok(Some(Event::InitApply(ns))) => {
                        retry_attempt = 0;
                        if let Some(name) = ns.metadata.name {
                            relisted_names.insert(name);
                        }
                    }
                    Ok(Some(Event::InitDone)) => {
                        retry_attempt = 0;
                        let count = relisted_names.len();
                        allowlist.replace(std::mem::take(&mut relisted_names));
                        info!(
                            total = count,
                            "operator namespace allowlist replaced from full relist"
                        );
                    }
                    Ok(None) => {
                        warn!("operator namespace watcher stream ended unexpectedly");
                        break;
                    }
                    Err(err) => {
                        warn!(error = %err, "operator namespace watcher stream error");
                        break;
                    }
                }
            }

            let retry_delay = namespace_watcher_retry_delay(retry_attempt, jitter_seed);
            warn!(?retry_delay, "operator namespace watcher reconnecting");
            tokio::select! {
                () = tokio::time::sleep(retry_delay) => {}
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        return;
                    }
                }
            }
            retry_attempt = retry_attempt.saturating_add(1);
        }
    });

    info!(
        label_selector = %label_selector,
        "operator namespace label watcher spawned"
    );
}

fn namespace_watcher_retry_delay(attempt: u32, jitter_seed: u64) -> Duration {
    let base_secs = 2_u64.saturating_mul(1_u64 << attempt.min(4)).min(24);
    let max_jitter_secs = base_secs / 4;
    let mixed_seed =
        jitter_seed.wrapping_add(u64::from(attempt).wrapping_mul(0x9e37_79b9_7f4a_7c15));
    let jitter_secs = mixed_seed % (max_jitter_secs + 1);
    Duration::from_secs(base_secs + jitter_secs)
}

fn load_namespace_file(path: &Path) -> Result<std::collections::BTreeSet<String>, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    let names: Vec<String> = serde_json::from_str(&contents)
        .map_err(|e| format!("failed to parse {}: {e}", path.display()))?;
    Ok(names.into_iter().collect())
}

fn spawn_namespace_file_watcher(
    path: PathBuf,
    allowlist: OperatorNamespaceAllowlist,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    match load_namespace_file(&path) {
        Ok(names) => {
            let count = names.len();
            allowlist.replace(names);
            info!(
                path = %path.display(),
                total = count,
                "operator namespace allowlist loaded from file"
            );
        }
        Err(err) => {
            warn!(
                error = %err,
                "failed to load initial operator namespace file, allowlist empty"
            );
        }
    }

    let watch_dir = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let debounce = Duration::from_secs(1);

    tokio::spawn(async move {
        let (tx, mut rx) = mpsc::unbounded_channel();

        let mut watcher =
            match notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
                if let Ok(event) = res
                    && matches!(
                        event.kind,
                        notify::EventKind::Modify(_) | notify::EventKind::Create(_)
                    )
                {
                    let _ = tx.send(());
                }
            }) {
                Ok(w) => w,
                Err(e) => {
                    warn!(
                        error = %e,
                        "failed to start operator namespace file watcher, hot-reload disabled"
                    );
                    return;
                }
            };

        if let Err(e) = notify::Watcher::watch(
            &mut watcher,
            &watch_dir,
            notify::RecursiveMode::NonRecursive,
        ) {
            warn!(
                error = %e,
                dir = %watch_dir.display(),
                "failed to watch operator namespace file directory, hot-reload disabled"
            );
            return;
        }

        info!(
            path = %path.display(),
            "operator namespace file watcher started"
        );

        loop {
            let got_event = tokio::select! {
                event = rx.recv() => event.is_some(),
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        return;
                    }
                    continue;
                }
            };
            if !got_event {
                warn!("operator namespace file watcher disconnected");
                break;
            }

            loop {
                tokio::select! {
                    () = tokio::time::sleep(debounce) => {
                        match load_namespace_file(&path) {
                            Ok(names) => {
                                let count = names.len();
                                allowlist.replace(names);
                                info!(
                                    total = count,
                                    "operator namespace allowlist reloaded from file"
                                );
                            }
                            Err(err) => {
                                warn!(
                                    error = %err,
                                    "failed to reload operator namespace file, keeping existing allowlist"
                                );
                            }
                        }
                        break;
                    }
                    r = rx.recv() => {
                        if r.is_some() {
                            continue;
                        }
                        warn!("operator namespace file watcher disconnected");
                        return;
                    }
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            return;
                        }
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admitted_pod_strict_groups_accept_api_omission_but_reject_added_groups() {
        let readback = |security: serde_json::Value| {
            serde_json::from_value::<k8s_openapi::api::core::v1::PodSecurityContext>(security)
                .expect("Pod security context")
        };
        assert!(strict_without_supplemental_groups(&readback(
            serde_json::json!({"supplementalGroupsPolicy":"Strict"})
        )));
        assert!(strict_without_supplemental_groups(&readback(
            serde_json::json!({"supplementalGroupsPolicy":"Strict","supplementalGroups":[]})
        )));
        assert!(!strict_without_supplemental_groups(&readback(
            serde_json::json!({"supplementalGroupsPolicy":"Strict","supplementalGroups":[0]})
        )));
        assert!(!strict_without_supplemental_groups(&readback(
            serde_json::json!({"supplementalGroups":[]})
        )));
    }

    #[tokio::test]
    async fn admission_defaults_reject_driver_config_before_kubernetes_io_in_every_mode() {
        for workspace_mode in [
            WorkspaceMode::Shared,
            WorkspaceMode::Managed,
            WorkspaceMode::Operator,
        ] {
            let driver = KubernetesComputeDriver::new_for_test(KubernetesComputeConfig {
                workspace_mode,
                ..Default::default()
            });
            let sandbox = Sandbox {
                workspace: "team-a".into(),
                name: "attacker".into(),
                spec: Some(SandboxSpec {
                    template: Some(SandboxTemplate {
                        driver_config: Some(json_struct(
                            serde_json::json!({"volumes":[{"name":"data","persistent_volume_claim":{"claim_name":"openshell-data-openshell-0"}}]}),
                        )),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let error = driver.validate_sandbox_create(&sandbox).await.unwrap_err();
            assert_eq!(error.code(), tonic::Code::FailedPrecondition);
            assert!(error.message().contains("allow_driver_config"));
            assert!(
                matches!(Box::pin(driver.create_sandbox_inner(&sandbox)).await, Err(KubernetesDriverError::Precondition(message)) if message.contains("allow_driver_config"))
            );
        }
    }

    #[tokio::test]
    async fn admission_allows_private_default_workload_without_external_lookups() {
        let driver = KubernetesComputeDriver::new_for_test(KubernetesComputeConfig::default());
        let sandbox = Sandbox {
            workspace: "team-a".into(),
            name: "private".into(),
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate {
                    image: "test".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(
            driver
                .admit_requested_resources(&sandbox)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn admission_revalidates_stopped_sandbox_without_runtime_generation() {
        let driver = KubernetesComputeDriver::new_for_test(KubernetesComputeConfig::default());
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            SANDBOX_GROUP,
            SANDBOX_VERSION_V1BETA1,
            SANDBOX_KIND,
        ));
        let mut sandbox = DynamicObject::new("stopped-sandbox", &resource);
        sandbox.metadata.namespace = Some("openshell".to_string());
        sandbox.metadata.labels = Some(BTreeMap::from([
            (LABEL_SANDBOX_ID.to_string(), "sandbox-id".to_string()),
            (LABEL_SANDBOX_WORKSPACE.to_string(), "team-a".to_string()),
        ]));
        sandbox.metadata.annotations = Some(BTreeMap::from([
            (
                crate::resource_admission::CONFIG_USED.to_string(),
                "false".to_string(),
            ),
            (
                crate::resource_admission::IDENTITIES.to_string(),
                "{}".to_string(),
            ),
        ]));
        sandbox.data = serde_json::json!({
            "spec": {
                "podTemplate": {
                    "spec": {
                        "automountServiceAccountToken": false,
                        "volumes": [{
                            "name": SANDBOX_BOOTSTRAP_VOLUME_NAME,
                            "secret": {"secretName": "os-sandbox-sandbox-id-oldgeneration"}
                        }]
                    }
                }
            }
        });

        driver
            .admit_stored_resources(&sandbox)
            .await
            .expect("stopped sandbox should use its stored private Secret reference");
    }

    #[tokio::test]
    async fn admission_reconcile_does_not_suspend_on_forbidden_metadata_lookup() {
        let sandbox = serde_json::json!({
            "apiVersion": "agents.x-k8s.io/v1beta1",
            "kind": "Sandbox",
            "metadata": {
                "name": "sandbox-cr",
                "namespace": "openshell",
                "resourceVersion": "42",
                "labels": {
                    LABEL_SANDBOX_ID: "sandbox-id",
                    LABEL_SANDBOX_WORKSPACE: "team-a"
                },
                "annotations": {
                    crate::resource_admission::CONFIG_USED: "false",
                    crate::resource_admission::IDENTITIES:
                        "{\"PersistentVolumeClaim/openshell/team-data\":\"pvc-uid\"}"
                }
            },
            "spec": {
                "podTemplate": {
                    "spec": {
                        "automountServiceAccountToken": false,
                        "volumes": [
                            {
                                "name": "data",
                                "persistentVolumeClaim": {"claimName": "team-data"}
                            },
                            {
                                "name": SANDBOX_BOOTSTRAP_VOLUME_NAME,
                                "secret": {"secretName": "os-sandbox-sandbox-id-generation"}
                            }
                        ]
                    }
                }
            }
        });
        let steps = Arc::new(std::sync::Mutex::new(VecDeque::from([
            (
                http::Method::GET,
                "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes",
                kube_test_response(
                    http::StatusCode::OK,
                    serde_json::json!({
                        "apiVersion": "agents.x-k8s.io/v1beta1",
                        "kind": "SandboxList",
                        "items": [sandbox.clone()]
                    }),
                ),
            ),
            (
                http::Method::GET,
                "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes/sandbox-cr",
                kube_test_response(http::StatusCode::OK, sandbox),
            ),
            (
                http::Method::GET,
                "/api/v1/namespaces/openshell/persistentvolumeclaims/team-data",
                kube_test_response(
                    http::StatusCode::FORBIDDEN,
                    serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Status",
                        "status": "Failure",
                        "message": "fixture forbidden",
                        "reason": "Forbidden",
                        "code": 403
                    }),
                ),
            ),
        ])));
        let service_steps = steps.clone();
        let service = tower::service_fn(move |request: http::Request<kube::client::Body>| {
            let steps = service_steps.clone();
            async move {
                let (method, path, response) = steps
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("403 admission retry must not issue a suspension patch");
                assert_eq!(request.method(), method);
                assert_eq!(request.uri().path(), path);
                Ok::<_, std::convert::Infallible>(response)
            }
        });
        let client = Client::new(service, "openshell");
        let driver = KubernetesComputeDriver {
            client: client.clone(),
            watch_client: client,
            sandbox_api_version: Arc::new(OnceCell::new()),
            config: KubernetesComputeConfig::default(),
            operator_allowlist: None,
            confidential: None,
            lifecycle_gates: Arc::default(),
        };
        driver
            .sandbox_api_version
            .set(SANDBOX_VERSION_V1BETA1)
            .expect("set test Sandbox API version");

        driver.reconcile_sandbox_runtime_resources().await;

        assert!(steps.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn substituted_workload_is_rejected_before_initdata_patch_or_publication() {
        let (mut driver, requests) = delete_test_driver(vec![]);
        let (temp, _, bindings) = attach_delete_test_workspace(&mut driver);
        let profile = Arc::get_mut(driver.confidential.as_mut().unwrap()).unwrap();
        profile.policy_generator = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../deployment/runtime/agent_policy.py");
        let image = format!("registry.example/agent@sha256:{}", "a".repeat(64));
        let params = SandboxPodParams {
            default_image: &image,
            sandbox_runtime_image: &image,
            sandbox_id: "sandbox-id",
            default_runtime_class_name: "kata-remote",
            sandbox_secret_name: "trusted-bootstrap",
            ..SandboxPodParams::default()
        };
        let rendered = sandbox_to_k8s_spec(None, &params).unwrap();
        let expected: Pod = serde_json::from_value(serde_json::json!({
            "apiVersion":"v1", "kind":"Pod",
            "metadata":{"name":"workload", "namespace":"openshell", "labels": {BOUNDARY_ROLE_LABEL:"workload"}},
            "spec":rendered["spec"]["podTemplate"]["spec"],
        })).unwrap();
        let mut observed = serde_json::to_value(&expected).unwrap();
        observed["metadata"]["uid"] = serde_json::json!("pod-uid");
        observed["metadata"]["resourceVersion"] = serde_json::json!("42");
        observed["spec"]["overhead"] = serde_json::json!({"cpu":"250m", "memory":"120Mi"});
        for field in ["containers", "initContainers"] {
            for container in observed["spec"][field].as_array_mut().into_iter().flatten() {
                container["resources"] = serde_json::json!({});
            }
        }
        observed["spec"]["containers"][0]["resources"] = serde_json::json!({
            "limits":{"kata.peerpods.io/vm":"1"}, "requests":{"kata.peerpods.io/vm":"1"}});
        observed["spec"]["containers"][0]["command"] = serde_json::json!(["/bin/sh"]);
        let admitted: Pod = serde_json::from_value(observed).unwrap();
        let pods = Api::<Pod>::namespaced(driver.client.clone(), "openshell");
        let before = std::fs::read_dir(bindings).unwrap().count();
        let result = driver
            .generate_and_patch_initdata(
                &pods,
                &admitted,
                &expected,
                BootstrapRole::Workload,
                "g000000000000002a",
                "sandbox-id",
                "old-uid",
                &"a".repeat(64),
                "openshell",
                WORKLOAD_KEYS,
                None,
            )
            .await;
        let error = result
            .err()
            .expect("substituted workload must fail")
            .to_string();
        assert!(
            error.contains("execution differs from trusted launch intent"),
            "{error}"
        );
        assert!(requests.lock().unwrap().is_empty());
        assert_eq!(
            std::fs::read_dir(
                driver
                    .confidential
                    .as_ref()
                    .unwrap()
                    .store
                    .workspace_binding_directory()
            )
            .unwrap()
            .count(),
            before
        );
        assert_eq!(
            std::fs::read_dir(
                driver
                    .confidential
                    .as_ref()
                    .unwrap()
                    .store
                    .binding_directory()
            )
            .unwrap()
            .count(),
            0
        );
        std::fs::remove_dir_all(temp).unwrap();
    }

    #[tokio::test]
    async fn reconcile_skips_busy_sandbox_and_revisits_it_next_pass() {
        let object = |id: &str| {
            serde_json::json!({
                "apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
                "metadata": {"name": id, "namespace": "openshell", "uid": id,
                    "labels": {LABEL_SANDBOX_ID: id}},
                "spec": {"operatingMode": "Suspended"}
            })
        };
        let list = || {
            kube_test_response(
                http::StatusCode::OK,
                serde_json::json!({
                    "apiVersion": "agents.x-k8s.io/v1beta1", "kind": "SandboxList",
                    "items": [object("busy"), object("ready")]
                }),
            )
        };
        let (driver, steps, _) = scripted_driver(
            KubernetesComputeConfig::default(),
            vec![
                (
                    http::Method::GET,
                    "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes",
                    list(),
                ),
                (
                    http::Method::GET,
                    "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes/ready",
                    kube_test_not_found("sandboxes", "ready"),
                ),
                (
                    http::Method::GET,
                    "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes",
                    list(),
                ),
                (
                    http::Method::GET,
                    "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes/busy",
                    kube_test_not_found("sandboxes", "busy"),
                ),
                (
                    http::Method::GET,
                    "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes/ready",
                    kube_test_not_found("sandboxes", "ready"),
                ),
            ],
        );
        driver.sandbox_api_version.set(SANDBOX_VERSION_V1BETA1).ok();
        let busy = driver.lifecycle_lock("busy").lock_owned().await;
        tokio::time::timeout(
            Duration::from_secs(1),
            driver.reconcile_sandbox_runtime_resources(),
        )
        .await
        .expect("busy sandbox must not block the rest of the pass");
        assert_eq!(steps.lock().unwrap().len(), 3);
        drop(busy);
        driver.reconcile_sandbox_runtime_resources().await;
        assert!(steps.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn reconcile_skips_stale_list_identity_before_cleanup() {
        let stale = serde_json::json!({
            "apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
            "metadata": {"name": "sandbox-cr", "namespace": "openshell", "uid": "old-uid",
                "labels": {LABEL_SANDBOX_ID: "sandbox-id"}},
            "spec": {"operatingMode": "Suspended"}
        });
        let current = serde_json::json!({
            "apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
            "metadata": {"name": "sandbox-cr", "namespace": "openshell", "uid": "new-uid",
                "labels": {LABEL_SANDBOX_ID: "sandbox-id"}},
            "spec": {"operatingMode": "Running"}
        });
        let (driver, steps, _) = scripted_driver(
            KubernetesComputeConfig::default(),
            vec![
                (
                    http::Method::GET,
                    "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes",
                    kube_test_response(
                        http::StatusCode::OK,
                        serde_json::json!({
                            "apiVersion": "agents.x-k8s.io/v1beta1", "kind": "SandboxList",
                            "items": [stale]
                        }),
                    ),
                ),
                (
                    http::Method::GET,
                    "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes/sandbox-cr",
                    kube_test_response(http::StatusCode::OK, current),
                ),
            ],
        );
        driver.sandbox_api_version.set(SANDBOX_VERSION_V1BETA1).ok();
        driver.reconcile_sandbox_runtime_resources().await;
        assert!(
            steps.lock().unwrap().is_empty(),
            "stale identity must not be cleaned up"
        );
    }

    #[tokio::test]
    async fn stop_deletes_supervisor_even_when_policy_revocation_fails() {
        use std::os::unix::fs::PermissionsExt;
        let temp = std::env::temp_dir().join(format!(
            "confidential-stop-revoke-failure-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&temp).unwrap();
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o700)).unwrap();
        let script = temp.join("renderer.py");
        let fail = temp.join("fail");
        std::fs::write(
            &script,
            format!(
                "import pathlib, sys\nif pathlib.Path({:?}).exists(): sys.exit(1)\n",
                fail.to_str().unwrap()
            ),
        )
        .unwrap();
        let store = BootstrapStore::open_with_policies(
            temp.join("repo"),
            temp.join("signer.pem"),
            &script,
            temp.join("kbs.rego"),
            temp.join("as.rego"),
        )
        .unwrap();
        let base = temp.join("base.toml");
        std::fs::write(
            &base,
            concat!(
                "version = '0.1.0'\nalgorithm = 'sha384'\n[data]\n",
                "'aa.toml' = 'aa'\n'cdh.toml' = 'cdh'\n",
                "'policy.rego' = 'package agent_policy'\n",
            ),
        )
        .unwrap();
        let object = serde_json::json!({
            "apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
            "metadata": {"name": "sandbox-cr", "namespace": "openshell",
                "uid": "cr-uid", "resourceVersion": "42",
                "labels": {LABEL_SANDBOX_ID: "sandbox-id"},
                "annotations": {
                    ANNOTATION_SANDBOX_RUNTIME_GENERATION: "g000000000000002a",
                    ANNOTATION_CONFIDENTIAL_BOOTSTRAP_ATTEMPT:
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                }},
            "spec": {"operatingMode": "Running"}
        });
        let deleted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let deleted_for_service = deleted.clone();
        let service = tower::service_fn(move |request: http::Request<kube::client::Body>| {
            let object = object.clone();
            let deleted = deleted_for_service.clone();
            async move {
                use std::sync::atomic::Ordering;
                let path = request.uri().path();
                let response = if path.ends_with("/sandboxes") {
                    kube_test_response(
                        http::StatusCode::OK,
                        serde_json::json!({
                            "apiVersion": "agents.x-k8s.io/v1beta1", "kind": "SandboxList",
                            "items": [object]
                        }),
                    )
                } else if path.ends_with("/sandboxes/sandbox-cr") {
                    if deleted.load(Ordering::SeqCst) {
                        kube_test_not_found("sandboxes", "sandbox-cr")
                    } else {
                        kube_test_response(http::StatusCode::OK, object)
                    }
                } else if path.contains("/pods/") && request.method() == http::Method::DELETE {
                    deleted.store(true, Ordering::SeqCst);
                    kube_test_response(
                        http::StatusCode::OK,
                        serde_json::json!({
                            "apiVersion": "v1", "kind": "Status", "status": "Success"
                        }),
                    )
                } else if path.contains("/pods/") {
                    if deleted.load(Ordering::SeqCst) {
                        kube_test_not_found("pods", "supervisor")
                    } else {
                        kube_test_response(
                            http::StatusCode::OK,
                            serde_json::json!({
                                "apiVersion": "v1", "kind": "Pod",
                                "metadata": {"name": path.rsplit('/').next().unwrap(),
                                    "namespace": "openshell", "uid": "supervisor-uid",
                                    "ownerReferences": [{"apiVersion":"agents.x-k8s.io/v1beta1",
                                        "kind":"Sandbox", "name":"sandbox-cr", "uid":"cr-uid"}]}
                            }),
                        )
                    }
                } else {
                    kube_test_not_found("resources", "unknown")
                };
                Ok::<_, std::convert::Infallible>(response)
            }
        });
        let client = Client::new(service, "openshell");
        let driver = KubernetesComputeDriver {
            client: client.clone(),
            watch_client: client,
            sandbox_api_version: Arc::new(OnceCell::new()),
            config: KubernetesComputeConfig::default(),
            operator_allowlist: None,
            confidential: Some(Arc::new(ConfidentialProfile {
                reports: None,
                bootstrap_timeout: SANDBOX_RUNTIME_BOOTSTRAP_GRACE,
                store,
                initdata: GuestInitdata::load(&base).unwrap(),
                client_tls: TrustedClientTlsPaths { ca: base.clone() },
                policy_generator: script,
                policy_tools_dir: temp.clone(),
                policy_registry: "unused".to_string(),
                policy_registry_ca: temp.join("ca.pem"),
                policy_pause_image: format!("registry.local/pause@sha256:{}", "a".repeat(64)),
            })),
            lifecycle_gates: Arc::default(),
        };
        driver.sandbox_api_version.set(SANDBOX_VERSION_V1BETA1).ok();
        std::fs::write(&fail, b"fail").unwrap();
        let _ =
            tokio::time::timeout(Duration::from_secs(2), driver.stop_sandbox("sandbox-id")).await;
        assert!(
            deleted.load(std::sync::atomic::Ordering::SeqCst),
            "supervisor Pod must be deleted despite AS/KBS policy renderer failure"
        );
        drop(driver);
        std::fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn trusted_gateway_ca_accepts_native_public_ca_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let ca = temp.path().join("ca.crt");
        let pem = rcgen::generate_simple_self_signed(vec!["gateway.internal".to_string()])
            .unwrap()
            .cert
            .pem();
        std::fs::write(&ca, &pem).unwrap();
        let paths = TrustedClientTlsPaths { ca: ca.clone() };
        // Official OpenShell certgen writes its public CA with mode 0644.
        for mode in [0o644, 0o640, 0o600, 0o444] {
            std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                paths.read().unwrap().ca_certificate,
                pem.as_bytes(),
                "mode {mode:o}"
            );
        }
        for mode in [0o660, 0o606, 0o666, 0o777] {
            std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                paths.read().is_err(),
                "mode {mode:o} allows modification outside the owner"
            );
        }
    }

    #[test]
    fn trusted_gateway_ca_rejects_symlink_hardlink_and_nonregular_files() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temp = tempfile::tempdir().unwrap();
        let ca = temp.path().join("ca.crt");
        let pem = rcgen::generate_simple_self_signed(vec!["gateway.internal".to_string()])
            .unwrap()
            .cert
            .pem();
        std::fs::write(&ca, &pem).unwrap();
        std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(0o644)).unwrap();
        let paths = TrustedClientTlsPaths { ca: ca.clone() };
        let hardlink = temp.path().join("hardlink.crt");
        std::fs::hard_link(&ca, &hardlink).unwrap();
        assert!(paths.read().is_err());
        std::fs::remove_file(hardlink).unwrap();
        let symlink_path = temp.path().join("symlink.crt");
        symlink(&ca, &symlink_path).unwrap();
        assert!(TrustedClientTlsPaths { ca: symlink_path }.read().is_err());
        assert!(
            TrustedClientTlsPaths {
                ca: temp.path().to_path_buf()
            }
            .read()
            .is_err()
        );
        assert!(
            TrustedClientTlsPaths {
                ca: PathBuf::from("ca.crt")
            }
            .read()
            .is_err()
        );
        std::fs::write(&ca, b"").unwrap();
        assert!(paths.read().is_err());
        std::fs::write(&ca, b"not PEM").unwrap();
        assert!(paths.read().is_err());
        std::fs::write(
            &ca,
            format!("-----BEGIN CERTIFICATE-----\n{}", "A".repeat(1024 * 1024)),
        )
        .unwrap();
        assert!(paths.read().is_err());
    }

    #[test]
    fn confidential_gateway_endpoint_requires_direct_https() {
        for accepted in [
            "https://gateway.internal:8080",
            "https://192.168.16.106:8445",
        ] {
            validate_confidential_gateway_endpoint(accepted).unwrap();
        }
        for denied in [
            "http://gateway:8080",
            "https://127.0.0.1:17670",
            "https://localhost:8080",
            "https://[::1]:8080",
            "https://[::]:8080",
            "https://gateway/prefix",
            "https://user@gateway",
            "https://gateway?foo=bar",
        ] {
            assert!(
                validate_confidential_gateway_endpoint(denied).is_err(),
                "{denied}"
            );
        }
    }

    #[tokio::test]
    async fn confidential_runtime_binding_preserves_restart_without_host_token_exchange() {
        let (mut driver, steps, _) =
            scripted_driver(KubernetesComputeConfig::default(), Vec::new());
        let (temp, _, _) = attach_delete_test_workspace(&mut driver);
        assert!(
            driver
                .capabilities()
                .unwrap()
                .supports_sandbox_authentication,
            "native Gateway must persist the driver runtime identity for Stop/Start"
        );
        let created_identity =
            kubernetes_runtime_identity("sandbox-namespace", "resource-uid", "old-supervisor-uid");
        let persisted = parse_kubernetes_runtime_identity(&created_identity).unwrap();
        let resumed = select_expected_sandbox_runtime(
            vec![sandbox_object_for_test("resource-uid", "sandbox-id-a")],
            &persisted,
        )
        .unwrap();
        assert_eq!(resumed.metadata.uid.as_deref(), Some("resource-uid"));
        assert!(
            select_expected_sandbox_runtime(
                vec![sandbox_object_for_test("replacement-uid", "sandbox-id-a")],
                &persisted,
            )
            .is_err(),
            "restart must not adopt a host-replaced Sandbox CR"
        );
        let error = driver
            .authenticate_sandbox("host-controlled-kubernetes-token")
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
        assert!(
            steps.lock().unwrap().is_empty(),
            "must reject before contacting Kubernetes"
        );
        drop(driver);
        std::fs::remove_dir_all(temp).unwrap();
    }

    use openshell_core::progress::{
        PROGRESS_ACTIVE_DETAIL_KEY, PROGRESS_ACTIVE_STEP_KEY, PROGRESS_COMPLETE_LABEL_KEY,
        PROGRESS_COMPLETE_STEP_KEY,
    };
    use openshell_core::proto::compute::v1::{GpuResourceRequirements, ResourceRequirements};
    use prost_types::{Struct, Value, value::Kind};
    use std::collections::VecDeque;

    /// Write `contents` to a uniquely named temp file and return its path.
    /// The caller removes it.
    fn write_temp_pem(tag: &str, contents: &str) -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "openshell-proxy-ca-{tag}-{}-{unique}.pem",
            std::process::id()
        ));
        std::fs::write(&path, contents).expect("write temp PEM");
        path
    }

    #[tokio::test]
    async fn staged_proxy_ca_bundle_is_absent_when_unconfigured() {
        assert!(
            read_staged_upstream_proxy_ca_bundle(None)
                .await
                .expect("an unset bundle is not an error")
                .is_none()
        );
    }

    #[tokio::test]
    async fn staged_proxy_ca_bundle_reads_a_valid_bundle() {
        let material = generate_proxy_ca_material().expect("generate a CA certificate");
        let path = write_temp_pem("valid", &material.certificate_pem);
        let staged = read_staged_upstream_proxy_ca_bundle(path.to_str())
            .await
            .expect("a CA certificate is a usable trust anchor")
            .expect("bundle staged");
        std::fs::remove_file(&path).ok();
        assert_eq!(staged, material.certificate_pem.into_bytes());
    }

    #[tokio::test]
    async fn staged_proxy_ca_bundle_fails_closed_and_names_the_setting() {
        // Fail-closed: a bundle the operator pointed at must never silently
        // degrade to the built-in roots. Every error names `proxy_ca_bundle`
        // so the operator can find the setting.
        let missing = std::env::temp_dir().join("openshell-proxy-ca-does-not-exist.pem");
        let err = read_staged_upstream_proxy_ca_bundle(missing.to_str())
            .await
            .expect_err("an unreadable path is fatal");
        assert!(err.to_string().contains("proxy_ca_bundle"), "{err}");

        let empty = write_temp_pem("certificate-free", "not a certificate\n");
        let err = read_staged_upstream_proxy_ca_bundle(empty.to_str())
            .await
            .expect_err("a certificate-free bundle is fatal");
        std::fs::remove_file(&empty).ok();
        assert!(err.to_string().contains("proxy_ca_bundle"), "{err}");

        let directory = std::env::temp_dir();
        let err = read_staged_upstream_proxy_ca_bundle(directory.to_str())
            .await
            .expect_err("a non-regular file is fatal");
        assert!(err.to_string().contains("proxy_ca_bundle"), "{err}");
    }

    #[tokio::test]
    async fn staged_proxy_ca_bundle_rejects_a_bundle_too_large_for_a_secret() {
        // Between this bound and the shared 1 MiB reader lies the apiserver's
        // own Secret limit, where the failure would otherwise be an opaque
        // `data: Too long` on every sandbox create.
        let material = generate_proxy_ca_material().expect("generate a CA certificate");
        let repeats =
            crate::config::MAX_STAGED_PROXY_CA_BUNDLE_BYTES / material.certificate_pem.len() + 2;
        let path = write_temp_pem("oversized", &material.certificate_pem.repeat(repeats));
        let err = read_staged_upstream_proxy_ca_bundle(path.to_str())
            .await
            .expect_err("an oversized bundle would fail at the apiserver");
        std::fs::remove_file(&path).ok();
        let err = err.to_string();
        assert!(err.contains("proxy_ca_bundle"), "{err}");
        assert!(err.contains("Secret"), "{err}");
    }

    static ENV_LOCK: std::sync::LazyLock<std::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(()));

    fn kube_test_response(
        status: http::StatusCode,
        body: serde_json::Value,
    ) -> http::Response<kube::client::Body> {
        http::Response::builder()
            .status(status)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(kube::client::Body::from(body.to_string().into_bytes()))
            .expect("valid Kubernetes test response")
    }

    fn kube_test_not_found(kind: &str, name: &str) -> http::Response<kube::client::Body> {
        kube_test_response(
            http::StatusCode::NOT_FOUND,
            serde_json::json!({
                "apiVersion": "v1",
                "kind": "Status",
                "status": "Failure",
                "message": format!("{kind} {name} not found"),
                "reason": "NotFound",
                "details": {"kind": kind, "name": name},
                "code": 404
            }),
        )
    }

    fn delete_test_sandbox(uid: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "agents.x-k8s.io/v1beta1",
            "kind": "Sandbox",
            "metadata": {
                "name": "sandbox-cr",
                "namespace": "openshell",
                "uid": uid,
                "resourceVersion": "42",
                "labels": {LABEL_SANDBOX_ID: "sandbox-id"}
            }
        })
    }

    type DeleteTestSteps = Arc<
        std::sync::Mutex<
            VecDeque<(
                http::Method,
                &'static str,
                http::Response<kube::client::Body>,
            )>,
        >,
    >;

    fn delete_test_driver(
        steps: Vec<(
            http::Method,
            &'static str,
            http::Response<kube::client::Body>,
        )>,
    ) -> (KubernetesComputeDriver, DeleteTestSteps) {
        let (driver, steps, _) = delete_test_driver_with_versions(steps, vec![]);
        (driver, steps)
    }

    fn delete_test_driver_with_versions(
        mut steps: Vec<(
            http::Method,
            &'static str,
            http::Response<kube::client::Body>,
        )>,
        expected_delete_versions: Vec<&'static str>,
    ) -> (
        KubernetesComputeDriver,
        DeleteTestSteps,
        Arc<std::sync::Mutex<VecDeque<&'static str>>>,
    ) {
        if let Some(index) = steps
            .iter()
            .position(|(method, _, _)| *method == http::Method::DELETE)
            && !steps[..index].iter().any(|(method, path, _)| {
                *method == http::Method::GET
                    && *path
                        == "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes/sandbox-cr"
            })
        {
            steps.insert(
                index,
                (
                    http::Method::GET,
                    "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes/sandbox-cr",
                    kube_test_response(http::StatusCode::OK, delete_test_sandbox("old-uid")),
                ),
            );
        }
        let steps = Arc::new(std::sync::Mutex::new(VecDeque::from(steps)));
        let service_steps = steps.clone();
        let expected_delete_versions = Arc::new(std::sync::Mutex::new(VecDeque::from(
            expected_delete_versions,
        )));
        let service_versions = expected_delete_versions.clone();
        let service = tower::service_fn(move |request: http::Request<kube::client::Body>| {
            let steps = service_steps.clone();
            let expected_delete_versions = service_versions.clone();
            async move {
                let (method, path, response) = steps
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("unexpected Kubernetes delete API request");
                assert_eq!(request.method(), method);
                assert_eq!(request.uri().path(), path);
                if method == http::Method::DELETE {
                    let expected_version = expected_delete_versions.lock().unwrap().pop_front();
                    if let Some(expected_version) = expected_version {
                        use http_body_util::BodyExt as _;
                        let body = request.into_body().collect().await.unwrap().to_bytes();
                        let params: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        assert_eq!(
                            params
                                .pointer("/preconditions/uid")
                                .and_then(|value| value.as_str()),
                            Some("old-uid")
                        );
                        assert_eq!(
                            params
                                .pointer("/preconditions/resourceVersion")
                                .and_then(|value| value.as_str()),
                            Some(expected_version)
                        );
                    }
                }
                Ok::<_, std::convert::Infallible>(response)
            }
        });
        let client = Client::new(service, "openshell");
        let driver = KubernetesComputeDriver {
            client: client.clone(),
            watch_client: client,
            sandbox_api_version: Arc::new(OnceCell::new()),
            config: KubernetesComputeConfig::default(),
            operator_allowlist: None,
            confidential: None,
            lifecycle_gates: Arc::default(),
        };
        driver
            .sandbox_api_version
            .set(SANDBOX_VERSION_V1BETA1)
            .expect("set test Sandbox API version");
        (driver, steps, expected_delete_versions)
    }

    fn attach_delete_test_workspace(
        driver: &mut KubernetesComputeDriver,
    ) -> (PathBuf, PathBuf, PathBuf) {
        use std::os::unix::fs::PermissionsExt;

        let temp = std::env::temp_dir().join(format!(
            "confidential-delete-workspace-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&temp).unwrap();
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o700)).unwrap();
        let script = temp.join("renderer.py");
        std::fs::write(&script, b"# test renderer\n").unwrap();
        let repo = temp.join("repo");
        let store = BootstrapStore::open_with_policies(
            &repo,
            temp.join("signer.pem"),
            &script,
            temp.join("kbs.rego"),
            temp.join("as.rego"),
        )
        .unwrap();
        store
            .record_workspace_owner("sandbox-id", "openshell", "old-uid")
            .unwrap();
        store
            .record_workspace_volume("openshell", "old-uid", "workspace-pvc", None, None)
            .unwrap();
        let planned = store
            .ensure_workspace_key("openshell", "old-uid", &"a".repeat(96))
            .unwrap();
        let serving = repo.join(crate::bootstrap::staged_resource_key(
            planned.resource_path.strip_prefix("resource/").unwrap(),
        ));
        let bindings = store.workspace_binding_directory();
        assert!(serving.exists());
        assert_eq!(std::fs::read_dir(&bindings).unwrap().count(), 1);

        let base = temp.join("base.toml");
        std::fs::write(
            &base,
            concat!(
                "version = '0.1.0'\nalgorithm = 'sha384'\n[data]\n",
                "'aa.toml' = 'aa'\n'cdh.toml' = 'cdh'\n",
                "'policy.rego' = 'package agent_policy'\n",
            ),
        )
        .unwrap();
        driver.confidential = Some(Arc::new(ConfidentialProfile {
            reports: None,
            bootstrap_timeout: SANDBOX_RUNTIME_BOOTSTRAP_GRACE,
            store,
            initdata: GuestInitdata::load(&base).unwrap(),
            client_tls: TrustedClientTlsPaths { ca: base.clone() },
            policy_generator: script,
            policy_tools_dir: temp.clone(),
            policy_registry: "unused".to_string(),
            policy_registry_ca: temp.join("ca.pem"),
            policy_pause_image: format!("registry.local/pause@sha256:{}", "a".repeat(64)),
        }));
        (temp, serving, bindings)
    }

    #[tokio::test(start_paused = true)]
    async fn measured_workspace_waits_for_pvc_and_cloud_disk_binding() {
        const PVC_PATH: &str = "/api/v1/namespaces/openshell/persistentvolumeclaims/workspace-pvc";
        const PV_PATH: &str = "/api/v1/persistentvolumes/workspace-pv";
        let pending = serde_json::json!({
            "apiVersion": "v1", "kind": "PersistentVolumeClaim",
            "metadata": {"name": "workspace-pvc", "namespace": "openshell", "uid": "pvc-uid"},
            "spec": {}
        });
        let bound = serde_json::json!({
            "apiVersion": "v1", "kind": "PersistentVolumeClaim",
            "metadata": {"name": "workspace-pvc", "namespace": "openshell", "uid": "pvc-uid"},
            "spec": {"volumeName": "workspace-pv"}
        });
        let (mut driver, steps) = delete_test_driver(vec![
            (
                http::Method::GET,
                PVC_PATH,
                kube_test_response(http::StatusCode::OK, pending),
            ),
            (
                http::Method::GET,
                PVC_PATH,
                kube_test_response(http::StatusCode::OK, bound.clone()),
            ),
            (
                http::Method::GET,
                PV_PATH,
                kube_test_response(
                    http::StatusCode::OK,
                    serde_json::json!({
                        "apiVersion": "v1", "kind": "PersistentVolume",
                        "metadata": {"name": "workspace-pv", "uid": "pv-uid"},
                        "spec": {"claimRef": {"name": "workspace-pvc", "namespace": "openshell", "uid": "pvc-uid"}}
                    }),
                ),
            ),
            (
                http::Method::GET,
                PVC_PATH,
                kube_test_response(http::StatusCode::OK, bound),
            ),
            (
                http::Method::GET,
                PV_PATH,
                kube_test_response(
                    http::StatusCode::OK,
                    serde_json::json!({
                        "apiVersion": "v1", "kind": "PersistentVolume",
                        "metadata": {"name": "workspace-pv", "uid": "pv-uid"},
                        "spec": {
                            "claimRef": {"name": "workspace-pvc", "namespace": "openshell", "uid": "pvc-uid"},
                            "csi": {"driver": "diskplugin.csi.alibabacloud.com", "volumeHandle": "pvc-logical-handle",
                                "volumeAttributes": {"cloud-volume-path": "d-workspace"}}
                        }
                    }),
                ),
            ),
        ]);
        let (temp, _, _) = attach_delete_test_workspace(&mut driver);
        let pod: Pod = serde_json::from_value(serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "spec": {"containers": [], "volumes": [{
                "name": "workspace", "persistentVolumeClaim": {"claimName": "workspace-pvc"}
            }]}
        }))
        .unwrap();
        let before = tokio::time::Instant::now();
        driver
            .record_workspace_volumes("sandbox-id", "openshell", "old-uid", &pod, true)
            .await
            .unwrap();
        assert!(tokio::time::Instant::now() - before >= STOP_INITIAL_POLL_INTERVAL * 2);
        assert!(steps.lock().unwrap().is_empty());
        assert_eq!(
            driver
                .confidential_profile()
                .unwrap()
                .store
                .workspace_disk_ids("openshell", "old-uid")
                .unwrap(),
            vec!["d-workspace"]
        );
        std::fs::remove_dir_all(temp).unwrap();
    }

    #[tokio::test]
    async fn measured_workspace_rejects_pv_claim_reference_substitution() {
        let pod: Pod = serde_json::from_value(serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "spec": {"containers": [], "volumes": [{
                "name": "workspace", "persistentVolumeClaim": {"claimName": "workspace-pvc"}
            }]}
        }))
        .unwrap();
        for claim_ref in [
            serde_json::Value::Null,
            serde_json::json!({"name": "workspace-pvc", "namespace": "openshell", "uid": "replacement-uid"}),
            serde_json::json!({"name": "workspace-pvc", "namespace": "other-namespace", "uid": "pvc-uid"}),
            serde_json::json!({"name": "other-pvc", "namespace": "openshell", "uid": "pvc-uid"}),
        ] {
            let (mut driver, steps) = delete_test_driver(vec![
                (
                    http::Method::GET,
                    "/api/v1/namespaces/openshell/persistentvolumeclaims/workspace-pvc",
                    kube_test_response(
                        http::StatusCode::OK,
                        serde_json::json!({
                            "apiVersion": "v1", "kind": "PersistentVolumeClaim",
                            "metadata": {"name": "workspace-pvc", "namespace": "openshell", "uid": "pvc-uid"},
                            "spec": {"volumeName": "workspace-pv"}
                        }),
                    ),
                ),
                (
                    http::Method::GET,
                    "/api/v1/persistentvolumes/workspace-pv",
                    kube_test_response(
                        http::StatusCode::OK,
                        serde_json::json!({
                            "apiVersion": "v1", "kind": "PersistentVolume",
                            "metadata": {"name": "workspace-pv", "uid": "pv-uid"},
                            "spec": {"claimRef": claim_ref,
                                "csi": {"driver": "diskplugin.csi.alibabacloud.com", "volumeHandle": "pvc-logical-handle",
                                    "volumeAttributes": {"cloud-volume-path": "d-workspace"}}}
                        }),
                    ),
                ),
            ]);
            let (temp, _, _) = attach_delete_test_workspace(&mut driver);
            let error = driver
                .record_workspace_volumes("sandbox-id", "openshell", "old-uid", &pod, true)
                .await
                .unwrap_err();
            assert!(
                error.to_string().contains("does not bind the exact PVC"),
                "{error}"
            );
            assert!(steps.lock().unwrap().is_empty());
            assert!(
                driver
                    .confidential_profile()
                    .unwrap()
                    .store
                    .workspace_disk_ids("openshell", "old-uid")
                    .unwrap()
                    .is_empty()
            );
            std::fs::remove_dir_all(temp).unwrap();
        }
    }

    #[tokio::test]
    async fn delete_ack_waits_for_role_pods_and_sandbox_cr() {
        const CR_PATH: &str =
            "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes/sandbox-cr";
        const LIST_PATH: &str = "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes";
        const WORKLOAD_PATH: &str = "/api/v1/namespaces/openshell/pods/sandbox-cr";
        const SUPERVISOR_PATH: &str = "/api/v1/namespaces/openshell/pods/os-supervisor-sandbox-id";
        let sandbox = delete_test_sandbox("old-uid");
        let list = serde_json::json!({
            "apiVersion": "agents.x-k8s.io/v1beta1", "kind": "SandboxList",
            "items": [sandbox.clone()]
        });
        let (driver, steps) = delete_test_driver(vec![
            (
                http::Method::GET,
                LIST_PATH,
                kube_test_response(http::StatusCode::OK, list),
            ),
            (
                http::Method::DELETE,
                CR_PATH,
                kube_test_response(http::StatusCode::OK, sandbox.clone()),
            ),
            (
                http::Method::GET,
                WORKLOAD_PATH,
                kube_test_not_found("pods", "sandbox-cr"),
            ),
            (
                http::Method::GET,
                SUPERVISOR_PATH,
                kube_test_not_found("pods", "os-supervisor-sandbox-id"),
            ),
            (
                http::Method::GET,
                CR_PATH,
                kube_test_response(http::StatusCode::OK, sandbox),
            ),
        ]);
        let error = driver.delete_sandbox("sandbox-id").await.unwrap_err();
        assert!(error.contains("CR deletion was not confirmed"), "{error}");
        assert!(steps.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_ack_succeeds_after_cr_and_both_role_pods_disappear() {
        const CR_PATH: &str =
            "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes/sandbox-cr";
        const LIST_PATH: &str = "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes";
        const WORKLOAD_PATH: &str = "/api/v1/namespaces/openshell/pods/sandbox-cr";
        const SUPERVISOR_PATH: &str = "/api/v1/namespaces/openshell/pods/os-supervisor-sandbox-id";
        const PODS_PATH: &str = "/api/v1/namespaces/openshell/pods";
        let sandbox = delete_test_sandbox("old-uid");
        let (mut driver, steps) = delete_test_driver(vec![
            (
                http::Method::GET,
                LIST_PATH,
                kube_test_response(
                    http::StatusCode::OK,
                    serde_json::json!({
                        "apiVersion":"agents.x-k8s.io/v1beta1", "kind":"SandboxList",
                        "items":[sandbox.clone()]
                    }),
                ),
            ),
            (
                http::Method::DELETE,
                CR_PATH,
                kube_test_response(http::StatusCode::OK, sandbox),
            ),
            (
                http::Method::GET,
                WORKLOAD_PATH,
                kube_test_not_found("pods", "sandbox-cr"),
            ),
            (
                http::Method::GET,
                SUPERVISOR_PATH,
                kube_test_not_found("pods", "os-supervisor-sandbox-id"),
            ),
            (
                http::Method::GET,
                CR_PATH,
                kube_test_not_found("sandboxes", "sandbox-cr"),
            ),
            (
                http::Method::GET,
                PODS_PATH,
                kube_test_response(
                    http::StatusCode::OK,
                    serde_json::json!({"apiVersion":"v1", "kind":"PodList", "items":[]}),
                ),
            ),
        ]);
        let (temp, serving, bindings) = attach_delete_test_workspace(&mut driver);
        assert!(driver.delete_sandbox("sandbox-id").await.unwrap());
        assert!(!serving.exists());
        assert_eq!(std::fs::read_dir(bindings).unwrap().count(), 0);
        assert!(steps.lock().unwrap().is_empty());
        std::fs::remove_dir_all(temp).unwrap();
    }

    #[tokio::test]
    async fn delete_ack_retries_while_workload_pod_exists() {
        const WORKLOAD_PATH: &str = "/api/v1/namespaces/openshell/pods/sandbox-cr";
        const SUPERVISOR_PATH: &str = "/api/v1/namespaces/openshell/pods/os-supervisor-sandbox-id";
        tokio::time::pause();
        let (driver, steps) = delete_test_driver(vec![
            (
                http::Method::GET,
                WORKLOAD_PATH,
                kube_test_response(
                    http::StatusCode::OK,
                    serde_json::json!({
                        "apiVersion":"v1", "kind":"Pod", "metadata":{"name":"sandbox-cr"}
                    }),
                ),
            ),
            (
                http::Method::GET,
                SUPERVISOR_PATH,
                kube_test_not_found("pods", "os-supervisor-sandbox-id"),
            ),
        ]);
        let pods = Api::<Pod>::namespaced(driver.client.clone(), "openshell");
        let check = tokio::spawn(async move {
            wait_for_sandbox_role_pods_deleted(
                &pods,
                "sandbox-cr",
                "os-supervisor-sandbox-id",
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await
        });
        for _ in 0..100 {
            if steps.lock().unwrap().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            steps.lock().unwrap().is_empty(),
            "both role Pods must be queried"
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        let error = check.await.unwrap().unwrap_err();
        assert!(
            error.contains("role Pod deletion was not confirmed"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn delete_conflict_checks_uid_and_pods_before_ack() {
        const CR_PATH: &str =
            "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes/sandbox-cr";
        const LIST_PATH: &str = "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes";
        let old = delete_test_sandbox("old-uid");
        let list = serde_json::json!({
            "apiVersion": "agents.x-k8s.io/v1beta1", "kind": "SandboxList",
            "items": [old.clone()]
        });
        let conflict = || {
            kube_test_response(
                http::StatusCode::CONFLICT,
                serde_json::json!({
                    "apiVersion": "v1", "kind": "Status", "status": "Failure",
                    "reason": "Conflict", "message": "resourceVersion changed", "code": 409
                }),
            )
        };
        let (mut driver, steps) = delete_test_driver(vec![
            (
                http::Method::GET,
                LIST_PATH,
                kube_test_response(http::StatusCode::OK, list.clone()),
            ),
            (http::Method::DELETE, CR_PATH, conflict()),
            (
                http::Method::GET,
                CR_PATH,
                kube_test_response(http::StatusCode::OK, old),
            ),
        ]);
        let (temp, serving, _) = attach_delete_test_workspace(&mut driver);
        let error = driver.delete_sandbox("sandbox-id").await.unwrap_err();
        assert!(error.contains("without a newer resourceVersion"), "{error}");
        assert!(!serving.exists());
        assert_eq!(
            driver
                .confidential
                .as_ref()
                .unwrap()
                .store
                .pending_deletes()
                .unwrap()
                .len(),
            1
        );
        assert!(steps.lock().unwrap().is_empty());
        std::fs::remove_dir_all(temp).unwrap();

        let (mut driver, steps) = delete_test_driver(vec![
            (
                http::Method::GET,
                LIST_PATH,
                kube_test_response(http::StatusCode::OK, list),
            ),
            (
                http::Method::GET,
                CR_PATH,
                kube_test_response(http::StatusCode::OK, delete_test_sandbox("new-uid")),
            ),
            (http::Method::DELETE, CR_PATH, conflict()),
            (
                http::Method::GET,
                CR_PATH,
                kube_test_response(http::StatusCode::OK, delete_test_sandbox("new-uid")),
            ),
        ]);
        let (temp, serving, bindings) = attach_delete_test_workspace(&mut driver);
        let error = driver.delete_sandbox("sandbox-id").await.unwrap_err();
        assert!(error.contains("replaced during deletion"), "{error}");
        assert!(
            serving.exists(),
            "replacement must not revoke old UID without ownership review"
        );
        assert_eq!(std::fs::read_dir(bindings).unwrap().count(), 1);
        assert_eq!(
            steps.lock().unwrap().len(),
            2,
            "replacement must not be deleted"
        );
        std::fs::remove_dir_all(temp).unwrap();
    }

    #[tokio::test]
    async fn delete_retries_same_uid_resource_version_churn_behind_fence() {
        const CR_PATH: &str =
            "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes/sandbox-cr";
        const LIST_PATH: &str = "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes";
        const WORKLOAD_PATH: &str = "/api/v1/namespaces/openshell/pods/sandbox-cr";
        const SUPERVISOR_PATH: &str = "/api/v1/namespaces/openshell/pods/os-supervisor-sandbox-id";
        const PODS_PATH: &str = "/api/v1/namespaces/openshell/pods";
        let old = delete_test_sandbox("old-uid");
        let mut observed = old.clone();
        observed["metadata"]["resourceVersion"] = serde_json::json!("43");
        let mut newer = old.clone();
        newer["metadata"]["resourceVersion"] = serde_json::json!("44");
        let (mut driver, steps, versions) = delete_test_driver_with_versions(
            vec![
                (
                    http::Method::GET,
                    LIST_PATH,
                    kube_test_response(
                        http::StatusCode::OK,
                        serde_json::json!({
                            "apiVersion":"agents.x-k8s.io/v1beta1", "kind":"SandboxList",
                            "items":[old.clone()]
                        }),
                    ),
                ),
                (
                    http::Method::GET,
                    CR_PATH,
                    kube_test_response(http::StatusCode::OK, observed),
                ),
                (
                    http::Method::DELETE,
                    CR_PATH,
                    kube_test_response(
                        http::StatusCode::CONFLICT,
                        serde_json::json!({
                            "apiVersion":"v1", "kind":"Status", "status":"Failure",
                            "reason":"Conflict", "message":"resourceVersion changed", "code":409
                        }),
                    ),
                ),
                (
                    http::Method::GET,
                    CR_PATH,
                    kube_test_response(http::StatusCode::OK, newer),
                ),
                (
                    http::Method::DELETE,
                    CR_PATH,
                    kube_test_response(http::StatusCode::OK, old),
                ),
                (
                    http::Method::GET,
                    WORKLOAD_PATH,
                    kube_test_not_found("pods", "sandbox-cr"),
                ),
                (
                    http::Method::GET,
                    SUPERVISOR_PATH,
                    kube_test_not_found("pods", "os-supervisor-sandbox-id"),
                ),
                (
                    http::Method::GET,
                    CR_PATH,
                    kube_test_not_found("sandboxes", "sandbox-cr"),
                ),
                (
                    http::Method::GET,
                    PODS_PATH,
                    kube_test_response(
                        http::StatusCode::OK,
                        serde_json::json!({"apiVersion":"v1", "kind":"PodList", "items":[]}),
                    ),
                ),
            ],
            vec!["43", "44"],
        );
        let (temp, serving, bindings) = attach_delete_test_workspace(&mut driver);
        assert!(driver.delete_sandbox("sandbox-id").await.unwrap());
        assert!(!serving.exists());
        assert_eq!(std::fs::read_dir(bindings).unwrap().count(), 0);
        assert!(
            driver
                .confidential
                .as_ref()
                .unwrap()
                .store
                .pending_deletes()
                .unwrap()
                .is_empty()
        );
        assert!(steps.lock().unwrap().is_empty());
        assert!(versions.lock().unwrap().is_empty());
        std::fs::remove_dir_all(temp).unwrap();
    }

    #[tokio::test]
    async fn delete_conflict_replacement_keeps_old_uid_fenced_without_retrying_delete() {
        const CR_PATH: &str =
            "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes/sandbox-cr";
        const LIST_PATH: &str = "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes";
        let old = delete_test_sandbox("old-uid");
        let (mut driver, steps, versions) = delete_test_driver_with_versions(
            vec![
                (
                    http::Method::GET,
                    LIST_PATH,
                    kube_test_response(
                        http::StatusCode::OK,
                        serde_json::json!({
                            "apiVersion":"agents.x-k8s.io/v1beta1", "kind":"SandboxList",
                            "items":[old]
                        }),
                    ),
                ),
                (
                    http::Method::DELETE,
                    CR_PATH,
                    kube_test_response(
                        http::StatusCode::CONFLICT,
                        serde_json::json!({
                            "apiVersion":"v1", "kind":"Status", "status":"Failure",
                            "reason":"Conflict", "message":"UID changed", "code":409
                        }),
                    ),
                ),
                (
                    http::Method::GET,
                    CR_PATH,
                    kube_test_response(
                        http::StatusCode::OK,
                        delete_test_sandbox("replacement-uid"),
                    ),
                ),
            ],
            vec!["42"],
        );
        let (temp, serving, _) = attach_delete_test_workspace(&mut driver);
        let error = driver.delete_sandbox("sandbox-id").await.unwrap_err();
        assert!(error.contains("replaced during deletion"), "{error}");
        assert!(!serving.exists(), "old UID authorization must be withdrawn");
        let pending = driver
            .confidential
            .as_ref()
            .unwrap()
            .store
            .pending_deletes()
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].sandbox_cr_uid, "old-uid");
        assert!(
            steps.lock().unwrap().is_empty(),
            "replacement must not be deleted"
        );
        assert!(versions.lock().unwrap().is_empty());
        std::fs::remove_dir_all(temp).unwrap();
    }

    #[tokio::test]
    async fn delete_conflict_retry_budget_exhaustion_keeps_pending_fence() {
        const CR_PATH: &str =
            "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes/sandbox-cr";
        const LIST_PATH: &str = "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes";
        let old = delete_test_sandbox("old-uid");
        let mut script = vec![(
            http::Method::GET,
            LIST_PATH,
            kube_test_response(
                http::StatusCode::OK,
                serde_json::json!({
                    "apiVersion":"agents.x-k8s.io/v1beta1", "kind":"SandboxList",
                    "items":[old]
                }),
            ),
        )];
        for version in ["43", "44", "45", "46"] {
            script.push((
                http::Method::DELETE,
                CR_PATH,
                kube_test_response(
                    http::StatusCode::CONFLICT,
                    serde_json::json!({
                        "apiVersion":"v1", "kind":"Status", "status":"Failure",
                        "reason":"Conflict", "message":"resourceVersion changed", "code":409
                    }),
                ),
            ));
            let mut updated = delete_test_sandbox("old-uid");
            updated["metadata"]["resourceVersion"] = serde_json::json!(version);
            script.push((
                http::Method::GET,
                CR_PATH,
                kube_test_response(http::StatusCode::OK, updated),
            ));
        }
        let (mut driver, steps, versions) =
            delete_test_driver_with_versions(script, vec!["42", "43", "44", "45"]);
        let (temp, serving, _) = attach_delete_test_workspace(&mut driver);
        let error = driver.delete_sandbox("sandbox-id").await.unwrap_err();
        assert!(error.contains("after 3 retries"), "{error}");
        assert!(!serving.exists());
        assert_eq!(
            driver
                .confidential
                .as_ref()
                .unwrap()
                .store
                .pending_deletes()
                .unwrap()
                .len(),
            1
        );
        assert!(steps.lock().unwrap().is_empty());
        assert!(versions.lock().unwrap().is_empty());
        std::fs::remove_dir_all(temp).unwrap();
    }

    #[tokio::test]
    async fn delete_conflict_without_resource_version_keeps_pending_fence() {
        const CR_PATH: &str =
            "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes/sandbox-cr";
        const LIST_PATH: &str = "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes";
        let old = delete_test_sandbox("old-uid");
        let mut current = old.clone();
        current["metadata"]
            .as_object_mut()
            .unwrap()
            .remove("resourceVersion");
        let (mut driver, steps, versions) = delete_test_driver_with_versions(
            vec![
                (
                    http::Method::GET,
                    LIST_PATH,
                    kube_test_response(
                        http::StatusCode::OK,
                        serde_json::json!({
                            "apiVersion":"agents.x-k8s.io/v1beta1", "kind":"SandboxList",
                            "items":[old]
                        }),
                    ),
                ),
                (
                    http::Method::DELETE,
                    CR_PATH,
                    kube_test_response(
                        http::StatusCode::CONFLICT,
                        serde_json::json!({
                            "apiVersion":"v1", "kind":"Status", "status":"Failure",
                            "reason":"Conflict", "message":"resourceVersion changed", "code":409
                        }),
                    ),
                ),
                (
                    http::Method::GET,
                    CR_PATH,
                    kube_test_response(http::StatusCode::OK, current),
                ),
            ],
            vec!["42"],
        );
        let (temp, serving, _) = attach_delete_test_workspace(&mut driver);
        let error = driver.delete_sandbox("sandbox-id").await.unwrap_err();
        assert!(error.contains("lacks resourceVersion"), "{error}");
        assert!(!serving.exists());
        assert_eq!(
            driver
                .confidential
                .as_ref()
                .unwrap()
                .store
                .pending_deletes()
                .unwrap()
                .len(),
            1
        );
        assert!(steps.lock().unwrap().is_empty());
        assert!(versions.lock().unwrap().is_empty());
        std::fs::remove_dir_all(temp).unwrap();
    }

    #[tokio::test]
    async fn delete_not_found_requires_absent_role_pods() {
        const CR_PATH: &str =
            "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes/sandbox-cr";
        const LIST_PATH: &str = "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes";
        const PODS_PATH: &str = "/api/v1/namespaces/openshell/pods";
        let list = serde_json::json!({
            "apiVersion": "agents.x-k8s.io/v1beta1", "kind": "SandboxList",
            "items": [delete_test_sandbox("old-uid")]
        });
        let (mut driver, steps) = delete_test_driver(vec![
            (
                http::Method::GET,
                LIST_PATH,
                kube_test_response(http::StatusCode::OK, list),
            ),
            (
                http::Method::DELETE,
                CR_PATH,
                kube_test_not_found("sandboxes", "sandbox-cr"),
            ),
            (
                http::Method::GET,
                PODS_PATH,
                kube_test_response(
                    http::StatusCode::OK,
                    serde_json::json!({
                        "apiVersion":"v1", "kind":"PodList", "items":[{
                            "metadata":{"name":"os-supervisor-sandbox-id","labels":{
                                BOUNDARY_PAIR_LABEL: crate::sandbox_runtime::pair_label_value("sandbox-id"),
                                BOUNDARY_ROLE_LABEL: "supervisor"
                            }}
                        }]
                    }),
                ),
            ),
        ]);
        let (temp, serving, bindings) = attach_delete_test_workspace(&mut driver);
        let error = driver.delete_sandbox("sandbox-id").await.unwrap_err();
        assert!(
            error.contains("role Pod deletion was not confirmed"),
            "{error}"
        );
        assert!(
            !serving.exists(),
            "known deleted UID must lose KBS resource"
        );
        assert_eq!(std::fs::read_dir(bindings).unwrap().count(), 0);
        assert!(steps.lock().unwrap().is_empty());
        std::fs::remove_dir_all(temp).unwrap();
    }

    #[tokio::test]
    async fn delete_conflict_then_not_found_withdraws_known_workspace() {
        const CR_PATH: &str =
            "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes/sandbox-cr";
        const LIST_PATH: &str = "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes";
        const PODS_PATH: &str = "/api/v1/namespaces/openshell/pods";
        let (mut driver, steps) = delete_test_driver(vec![
            (
                http::Method::GET,
                LIST_PATH,
                kube_test_response(
                    http::StatusCode::OK,
                    serde_json::json!({
                        "apiVersion":"agents.x-k8s.io/v1beta1", "kind":"SandboxList",
                        "items":[delete_test_sandbox("old-uid")]
                    }),
                ),
            ),
            (
                http::Method::DELETE,
                CR_PATH,
                kube_test_response(
                    http::StatusCode::CONFLICT,
                    serde_json::json!({
                        "apiVersion":"v1", "kind":"Status", "status":"Failure",
                        "reason":"Conflict", "message":"resourceVersion changed", "code":409
                    }),
                ),
            ),
            (
                http::Method::GET,
                CR_PATH,
                kube_test_not_found("sandboxes", "sandbox-cr"),
            ),
            (
                http::Method::GET,
                PODS_PATH,
                kube_test_response(
                    http::StatusCode::OK,
                    serde_json::json!({"apiVersion":"v1", "kind":"PodList", "items":[]}),
                ),
            ),
        ]);
        let (temp, serving, bindings) = attach_delete_test_workspace(&mut driver);
        assert!(!driver.delete_sandbox("sandbox-id").await.unwrap());
        assert!(!serving.exists());
        assert_eq!(std::fs::read_dir(bindings).unwrap().count(), 0);
        assert!(steps.lock().unwrap().is_empty());
        std::fs::remove_dir_all(temp).unwrap();
    }

    #[tokio::test]
    async fn delete_not_found_reports_workspace_revocation_failure() {
        const CR_PATH: &str =
            "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes/sandbox-cr";
        const LIST_PATH: &str = "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes";
        const PODS_PATH: &str = "/api/v1/namespaces/openshell/pods";
        let (mut driver, steps) = delete_test_driver(vec![
            (
                http::Method::GET,
                LIST_PATH,
                kube_test_response(
                    http::StatusCode::OK,
                    serde_json::json!({
                        "apiVersion":"agents.x-k8s.io/v1beta1", "kind":"SandboxList",
                        "items":[delete_test_sandbox("old-uid")]
                    }),
                ),
            ),
            (
                http::Method::DELETE,
                CR_PATH,
                kube_test_not_found("sandboxes", "sandbox-cr"),
            ),
            (
                http::Method::GET,
                PODS_PATH,
                kube_test_response(
                    http::StatusCode::OK,
                    serde_json::json!({"apiVersion":"v1", "kind":"PodList", "items":[]}),
                ),
            ),
        ]);
        let (temp, serving, _) = attach_delete_test_workspace(&mut driver);
        std::fs::write(temp.join("renderer.py"), b"import sys\nsys.exit(1)\n").unwrap();
        let error = driver.delete_sandbox("sandbox-id").await.unwrap_err();
        assert!(error.contains("revoke confidential sandbox"), "{error}");
        assert!(
            !serving.exists(),
            "KBS resource is withdrawn before policy refresh"
        );
        assert_eq!(
            steps.lock().unwrap().len(),
            2,
            "failed revocation must precede DELETE"
        );
        std::fs::remove_dir_all(temp).unwrap();
    }

    #[tokio::test]
    async fn delete_retry_after_cr_disappeared_keeps_gateway_record_for_lingering_pod() {
        const LIST_PATH: &str = "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes";
        const PODS_PATH: &str = "/api/v1/namespaces/openshell/pods";
        let (driver, steps) = delete_test_driver(vec![
            (
                http::Method::GET,
                LIST_PATH,
                kube_test_response(
                    http::StatusCode::OK,
                    serde_json::json!({
                        "apiVersion":"agents.x-k8s.io/v1beta1", "kind":"SandboxList", "items":[]
                    }),
                ),
            ),
            (
                http::Method::GET,
                PODS_PATH,
                kube_test_response(
                    http::StatusCode::OK,
                    serde_json::json!({
                        "apiVersion":"v1", "kind":"PodList", "items":[{
                            "metadata":{"name":"workload-pod", "labels":{
                                BOUNDARY_PAIR_LABEL: crate::sandbox_runtime::pair_label_value("sandbox-id")
                            }}
                        }]
                    }),
                ),
            ),
        ]);
        let error = driver.delete_sandbox("sandbox-id").await.unwrap_err();
        assert!(
            error.contains("role Pod deletion was not confirmed"),
            "{error}"
        );
        assert!(steps.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn periodic_delete_retires_orphaned_owner_after_cr_disappears() {
        const LIST_PATH: &str = "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes";
        const PODS_PATH: &str = "/api/v1/namespaces/openshell/pods";
        let absent = serde_json::json!({
            "apiVersion":"agents.x-k8s.io/v1beta1", "kind":"SandboxList", "items":[]
        });
        let (mut driver, steps) = delete_test_driver(vec![
            (
                http::Method::GET,
                LIST_PATH,
                kube_test_response(http::StatusCode::OK, absent.clone()),
            ),
            (
                http::Method::GET,
                LIST_PATH,
                kube_test_response(http::StatusCode::OK, absent),
            ),
            (
                http::Method::GET,
                PODS_PATH,
                kube_test_response(
                    http::StatusCode::OK,
                    serde_json::json!({"apiVersion":"v1", "kind":"PodList", "items":[]}),
                ),
            ),
        ]);
        let (temp, serving, bindings) = attach_delete_test_workspace(&mut driver);
        let store = &driver.confidential.as_ref().unwrap().store;
        // Simulate a crash immediately after saving env: no CR, Pod, volume
        // journal, or separately recorded owner is needed to recover cleanup.
        store
            .record_workload_environment(
                "sandbox-id",
                "openshell",
                "replacement-uid",
                &std::collections::HashMap::from([("TOKEN".into(), "secret".into())]),
            )
            .unwrap();
        store
            .begin_delete("sandbox-id", "openshell", "old-uid", None)
            .unwrap();
        store
            .record_workspace_volume(
                "openshell",
                "replacement-uid",
                "replacement-pvc",
                None,
                None,
            )
            .unwrap();
        let replacement = store
            .ensure_workspace_key("openshell", "replacement-uid", &"b".repeat(96))
            .unwrap();
        let replacement_serving = temp
            .join("repo")
            .join(crate::bootstrap::staged_resource_key(
                replacement.resource_path.strip_prefix("resource/").unwrap(),
            ));
        driver.reconcile_pending_sandbox_deletions().await;
        assert!(!serving.exists());
        assert!(
            !replacement_serving.exists(),
            "all absent CR UIDs must be deauthorized"
        );
        assert_eq!(std::fs::read_dir(bindings).unwrap().count(), 0);
        let store = &driver.confidential.as_ref().unwrap().store;
        assert!(store.pending_deletes().unwrap().is_empty());
        assert!(store.workspace_owners().unwrap().is_empty());
        assert_eq!(
            std::fs::read_dir(temp.join("workload-environments"))
                .unwrap()
                .count(),
            0,
        );
        assert!(steps.lock().unwrap().is_empty());
        std::fs::remove_dir_all(temp).unwrap();
    }

    #[tokio::test]
    async fn busy_sandbox_does_not_block_other_pending_revocation_without_kubernetes() {
        let unavailable = || {
            kube_test_response(
                http::StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({"apiVersion":"v1", "kind":"Status", "status":"Failure", "reason":"ServiceUnavailable", "code":503}),
            )
        };
        let (mut driver, steps) = delete_test_driver(vec![
            (
                http::Method::GET,
                "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes",
                unavailable(),
            ),
            (
                http::Method::GET,
                "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes",
                unavailable(),
            ),
        ]);
        let (temp, _, _) = attach_delete_test_workspace(&mut driver);
        let store = &driver.confidential.as_ref().unwrap().store;
        store
            .record_workspace_owner("busy", "openshell", "busy-uid")
            .unwrap();
        std::fs::write(temp.join("renderer.py"), b"raise SystemExit(1)\n").unwrap();
        assert!(store.revoke_owned_sandbox("sandbox-id", None).is_err());
        assert!(store.revoke_owned_sandbox("busy", None).is_err());
        assert_eq!(store.pending_revocations().unwrap().len(), 2);
        std::fs::write(temp.join("renderer.py"), b"# recovered\n").unwrap();
        let guard = driver.lifecycle_lock("busy").lock_owned().await;
        tokio::time::timeout(
            Duration::from_secs(1),
            driver.reconcile_pending_sandbox_deletions(),
        )
        .await
        .expect("busy sandbox must not stall pending revocations");
        let pending = store.pending_revocations().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].sandbox_id, "busy");
        drop(guard);
        driver.reconcile_pending_sandbox_deletions().await;
        assert!(store.pending_revocations().unwrap().is_empty());
        assert!(steps.lock().unwrap().is_empty());
        std::fs::remove_dir_all(temp).unwrap();
    }

    #[tokio::test]
    async fn periodic_delete_withdraws_pending_authorization_when_kubernetes_is_unavailable() {
        const LIST_PATH: &str = "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes";
        let (mut driver, steps) = delete_test_driver(vec![(
            http::Method::GET,
            LIST_PATH,
            kube_test_response(
                http::StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({
                    "apiVersion":"v1", "kind":"Status", "status":"Failure",
                    "reason":"ServiceUnavailable", "code":503
                }),
            ),
        )]);
        let (temp, serving, _) = attach_delete_test_workspace(&mut driver);
        let store = &driver.confidential.as_ref().unwrap().store;
        store
            .begin_delete("sandbox-id", "openshell", "old-uid", None)
            .unwrap();
        assert!(serving.exists());
        driver.reconcile_pending_sandbox_deletions().await;
        assert!(
            !serving.exists(),
            "pending raw resource must be withdrawn before Kubernetes lookup"
        );
        assert_eq!(store.pending_deletes().unwrap().len(), 1);
        assert!(steps.lock().unwrap().is_empty());
        std::fs::remove_dir_all(temp).unwrap();
    }

    #[tokio::test]
    async fn periodic_delete_preserves_replacement_uid_resources() {
        const LIST_PATH: &str = "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes";
        const PODS_PATH: &str = "/api/v1/namespaces/openshell/pods";
        let replacement_cr = serde_json::json!({
            "apiVersion":"agents.x-k8s.io/v1beta1", "kind":"Sandbox",
            "metadata":{
                "name":"sandbox-cr", "namespace":"openshell", "uid":"replacement-uid",
                "resourceVersion":"43", "labels":{LABEL_SANDBOX_ID:"sandbox-id"}
            }
        });
        let live = serde_json::json!({
            "apiVersion":"agents.x-k8s.io/v1beta1", "kind":"SandboxList",
            "items":[replacement_cr]
        });
        let (mut driver, steps) = delete_test_driver(vec![
            (
                http::Method::GET,
                LIST_PATH,
                kube_test_response(http::StatusCode::OK, live.clone()),
            ),
            (
                http::Method::GET,
                LIST_PATH,
                kube_test_response(http::StatusCode::OK, live),
            ),
            (
                http::Method::GET,
                PODS_PATH,
                kube_test_response(
                    http::StatusCode::OK,
                    serde_json::json!({"apiVersion":"v1", "kind":"PodList", "items":[]}),
                ),
            ),
        ]);
        let (temp, old_serving, _) = attach_delete_test_workspace(&mut driver);
        let store = &driver.confidential.as_ref().unwrap().store;
        store
            .begin_delete("sandbox-id", "openshell", "old-uid", None)
            .unwrap();
        store
            .record_workspace_owner("sandbox-id", "openshell", "replacement-uid")
            .unwrap();
        store
            .record_workspace_volume(
                "openshell",
                "replacement-uid",
                "replacement-pvc",
                None,
                None,
            )
            .unwrap();
        let replacement = store
            .ensure_workspace_key("openshell", "replacement-uid", &"b".repeat(96))
            .unwrap();
        let replacement_serving = temp
            .join("repo")
            .join(crate::bootstrap::staged_resource_key(
                replacement.resource_path.strip_prefix("resource/").unwrap(),
            ));
        driver.reconcile_pending_sandbox_deletions().await;
        assert!(!old_serving.exists());
        assert!(replacement_serving.exists());
        assert!(store.pending_deletes().unwrap().is_empty());
        assert_eq!(store.workspace_owners().unwrap().len(), 1);
        assert!(steps.lock().unwrap().is_empty());
        std::fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn boundary_authority_uses_stable_service_dns_name() {
        let names = SandboxRuntimeNames::new("sandbox-1");

        assert_eq!(
            boundary_service_authority("workspace-a", &names, 5500),
            "os-boundary-sandbox-1.workspace-a.svc:5500"
        );
    }

    #[tokio::test]
    async fn tracing_create_sandbox_failure_exports_a_kubernetes_operation_span() {
        use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
        use tracing::instrument::WithSubscriber as _;
        use tracing_subscriber::layer::SubscriberExt as _;

        let _tracing_lock = openshell_otel_test_support::tracing_test_lock().await;
        let exporter = InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber =
            tracing_subscriber::registry().with(crate::otel_tracing::TRACING.layer(&provider));
        let driver = KubernetesComputeDriver::new_for_test(KubernetesComputeConfig::default());

        driver
            .create_sandbox(&Sandbox::default())
            .with_subscriber(subscriber)
            .await
            .expect_err("missing sandbox name should fail");
        provider.force_flush().unwrap();

        let spans = exporter.get_finished_spans().unwrap();
        let span = spans
            .iter()
            .find(|span| span.name == "kubernetes.provision")
            .expect("create operation span");
        assert!(matches!(
            span.status,
            opentelemetry::trace::Status::Error { .. }
        ));
        provider.shutdown().unwrap();
    }

    #[tokio::test]
    async fn start_sandbox_span_does_not_capture_launch_authentication() {
        use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
        use tracing::instrument::WithSubscriber as _;
        use tracing_subscriber::layer::SubscriberExt as _;

        let _tracing_lock = openshell_otel_test_support::tracing_test_lock().await;
        let exporter = InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber =
            tracing_subscriber::registry().with(crate::otel_tracing::TRACING.layer(&provider));
        let driver = KubernetesComputeDriver::new_for_test(KubernetesComputeConfig::default());

        driver
            .start_sandbox(
                "sandbox-1",
                "invalid-generation",
                b"secret-launch-authentication",
                "kubernetes://namespace/resource/pod",
            )
            .with_subscriber(subscriber)
            .await
            .expect_err("invalid generation must fail before contacting Kubernetes");
        provider.force_flush().unwrap();

        let spans = exporter.get_finished_spans().unwrap();
        let span = spans
            .iter()
            .find(|span| span.name == "kubernetes.start_sandbox")
            .expect("start operation span");
        assert!(span.attributes.iter().all(|attribute| {
            !matches!(
                attribute.key.as_str(),
                "launch_authentication" | "encoded_authentication"
            )
        }));
        provider.shutdown().unwrap();
    }

    #[tokio::test]
    async fn sandbox_annotation_propagates_the_active_w3c_trace_context() {
        use opentelemetry_sdk::trace::{InMemorySpanExporterBuilder, SdkTracerProvider};
        use tracing_subscriber::layer::SubscriberExt as _;

        let _tracing_lock = openshell_otel_test_support::tracing_test_lock().await;
        let exporter = InMemorySpanExporterBuilder::new().build();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter)
            .build();
        let subscriber =
            tracing_subscriber::registry().with(crate::otel_tracing::TRACING.layer(&provider));

        let annotations = tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("kubernetes.provision");
            let _entered = span.enter();
            let mut annotations = BTreeMap::new();
            add_trace_context_annotation(&mut annotations);
            annotations
        });

        let carrier: serde_json::Value = serde_json::from_str(
            annotations
                .get("opentelemetry.io/trace-context")
                .expect("agent-sandbox trace-context annotation"),
        )
        .expect("annotation should contain a JSON propagation carrier");
        let traceparent = carrier["traceparent"]
            .as_str()
            .expect("carrier should contain traceparent");
        assert!(traceparent.starts_with("00-"));
        assert_eq!(traceparent.len(), 55);

        provider.shutdown().unwrap();
    }

    fn json_struct(value: serde_json::Value) -> Struct {
        let serde_json::Value::Object(object) = value else {
            panic!("expected JSON object");
        };
        openshell_core::proto_struct::json_object_to_struct(object)
            .expect("test JSON must convert to a protobuf Struct")
    }

    fn sandbox_to_k8s_spec_for_test(
        spec: Option<&SandboxSpec>,
        params: &SandboxPodParams<'_>,
    ) -> serde_json::Value {
        sandbox_to_k8s_spec(spec, params).expect("test Kubernetes driver_config should be valid")
    }

    #[test]
    fn export_exact_gated_pod_policy_fixtures() {
        let Ok(output_dir) = std::env::var("OPENSHELL_POLICY_POD_FIXTURE_DIR") else {
            return;
        };
        let output_dir = Path::new(&output_dir);
        std::fs::create_dir_all(output_dir).expect("create policy fixture directory");
        let names = SandboxRuntimeNames::for_generation("sandbox-1", "g000000000000002a");
        let owner = sandbox_runtime_sandbox_owner_reference(
            "sandbox-1",
            "cr-uid-1",
            "agents.x-k8s.io/v1beta1",
            false,
        );
        let mut supervisor = supervisor_pod(
            "sandbox",
            &names,
            "sandbox-1",
            "demo",
            "gateway",
            "registry.internal:5000/openshell-supervisor:0.1.3",
            None,
            "sandbox-sa",
            1000,
            1000,
            &[],
            "https://gateway.internal:8080",
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
            owner,
            &[],
        )
        .expect("render real supervisor constructor");
        supervisor.spec.as_mut().unwrap().runtime_class_name = Some("kata-remote".into());
        supervisor.metadata.name = Some(names.supervisor_pod.clone());
        supervisor.metadata.namespace = Some("sandbox".into());
        supervisor
            .metadata
            .annotations
            .get_or_insert_with(BTreeMap::new)
            .insert(INITDATA_ANNOTATION.into(), String::new());
        std::fs::write(
            output_dir.join("supervisor-pod.json"),
            serde_json::to_vec_pretty(&supervisor).unwrap(),
        )
        .unwrap();

        let params = SandboxPodParams {
            default_image: "registry.internal:5000/openshell-sandbox:0.1.3",
            sandbox_runtime_image: "registry.internal:5000/openshell-sandbox:0.1.3",
            sandbox_id: "sandbox-1",
            default_runtime_class_name: "kata-remote",
            sandbox_secret_name: &names.sandbox_secret,
            ..SandboxPodParams::default()
        };
        let rendered = sandbox_to_k8s_spec(None, &params).unwrap();
        let mut workload = serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": rendered["spec"]["podTemplate"]["metadata"],
            "spec": rendered["spec"]["podTemplate"]["spec"],
        });
        workload["metadata"]["name"] = serde_json::json!("sandbox-1");
        workload["metadata"]["namespace"] = serde_json::json!("sandbox");
        workload["metadata"]["annotations"][INITDATA_ANNOTATION] = serde_json::json!("");
        std::fs::write(
            output_dir.join("workload-pod.json"),
            serde_json::to_vec_pretty(&workload).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn confidential_images_require_immutable_sha256_references() {
        let digest = "a".repeat(64);
        assert!(immutable_image_reference(&format!(
            "registry.example/app@sha256:{digest}"
        )));
        assert!(immutable_image_reference(&format!(
            "registry.example/app:v1@sha256:{digest}"
        )));
        assert!(!immutable_image_reference("registry.example/app:v1"));
        assert!(!immutable_image_reference(&format!(
            "registry.example/app@sha256:{}",
            "A".repeat(64)
        )));
        assert!(!immutable_image_reference(
            "registry.example/app@sha256:abc"
        ));
        assert!(!immutable_image_reference(&format!("@sha256:{digest}")));
    }

    fn kube_api_error(code: u16, message: &str) -> KubeError {
        KubeError::Api(kube::core::ErrorResponse {
            status: if code == 404 {
                "404 Not Found".to_string()
            } else {
                "Failure".to_string()
            },
            message: message.to_string(),
            reason: "Failed to parse error data".to_string(),
            code,
        })
    }

    #[test]
    fn resource_version_conflicts_are_not_reported_as_duplicate_sandboxes() {
        let conflict = KubeError::Api(kube::core::ErrorResponse {
            status: "Failure".to_string(),
            message: "the object has been modified".to_string(),
            reason: "Conflict".to_string(),
            code: 409,
        });
        assert!(is_kube_resource_version_conflict(&conflict));
        assert!(matches!(
            KubernetesDriverError::from_kube(conflict),
            KubernetesDriverError::Message(_)
        ));

        let duplicate = KubeError::Api(kube::core::ErrorResponse {
            status: "Failure".to_string(),
            message: "already exists".to_string(),
            reason: "AlreadyExists".to_string(),
            code: 409,
        });
        assert!(matches!(
            KubernetesDriverError::from_kube(duplicate),
            KubernetesDriverError::AlreadyExists
        ));
    }

    fn expired_watch_error() -> watcher::Error {
        watcher::Error::WatchError(kube::core::ErrorResponse {
            status: "Failure".to_string(),
            message: "too old resource version".to_string(),
            reason: "Expired".to_string(),
            code: 410,
        })
    }

    #[tokio::test]
    async fn sandbox_watcher_error_does_not_hide_restarted_recovery_event() {
        let recovered = DynamicObject {
            types: None,
            metadata: ObjectMeta {
                name: Some("recovered-sandbox".to_string()),
                ..Default::default()
            },
            data: serde_json::json!({}),
        };
        let source =
            futures::stream::iter([Err(expired_watch_error()), Ok(Event::InitApply(recovered))]);
        let mut stream = continue_on_watcher_errors(source, "sandbox-resource");

        let event = stream
            .next()
            .await
            .expect("410 Expired must not terminate the watcher stream");
        let Event::InitApply(object) = event else {
            panic!("expected kube-runtime recovery to emit InitApply");
        };
        assert_eq!(object.metadata.name.as_deref(), Some("recovered-sandbox"));
        assert!(
            stream.next().await.is_none(),
            "source closure must be preserved"
        );
    }

    #[tokio::test]
    async fn outward_snapshots_strip_cloud_supplied_attestation_conditions() {
        let mut object = sandbox_object_for_test("uid", "sandbox-id");
        object
            .metadata
            .labels
            .as_mut()
            .unwrap()
            .insert(LABEL_MANAGED_BY.into(), LABEL_MANAGED_BY_VALUE.into());
        object
            .metadata
            .labels
            .as_mut()
            .unwrap()
            .insert(LABEL_SANDBOX_NAME.into(), "sandbox-name".into());
        object
            .metadata
            .labels
            .as_mut()
            .unwrap()
            .insert(LABEL_SANDBOX_WORKSPACE.into(), "workspace".into());
        object.data = serde_json::json!({"status": {"conditions": [
            {"type": "WorkloadAttestation", "status": "True", "reason": "Forged", "message": "untrusted"},
            {"type": "SupervisorAttestation", "status": "True", "reason": "Forged", "message": "untrusted"},
            {"type": "Other", "status": "Unknown", "reason": "Unrelated", "message": "keep"}
        ]}});
        let driver = KubernetesComputeDriver::new_for_test(KubernetesComputeConfig::default());
        let assert_conditions = |sandbox: &Sandbox| {
            let conditions = &sandbox.status.as_ref().unwrap().conditions;
            assert!(
                conditions
                    .iter()
                    .all(|c| !crate::attestation::TYPES.contains(&c.r#type.as_str()))
            );
            assert!(conditions.iter().any(|c| c.r#type == "Other"));
        };
        // The same snapshot path is used by get/list and both watch modes.
        let (_, snapshot) = driver
            .sandbox_with_attestation(&driver.client, "sandbox-namespace", object.clone())
            .await
            .unwrap();
        assert_conditions(&snapshot);
        let stream = futures::stream::iter([Event::Apply(object)])
            .chain(futures::stream::pending())
            .boxed();
        let mut outward = cluster_wide_watch_stream(
            stream,
            "default".into(),
            driver.watch_client.clone(),
            driver,
        );
        let event = outward.next().await.unwrap().unwrap();
        let Some(watch_sandboxes_event::Payload::Sandbox(event)) = event.payload else {
            panic!("expected sandbox");
        };
        assert_conditions(&event.sandbox.unwrap());
    }

    #[tokio::test(start_paused = true)]
    async fn outward_watch_stream_survives_expired_error_and_backoff_recovery() {
        let recovered = DynamicObject {
            types: None,
            metadata: ObjectMeta {
                name: Some("recovered-sandbox".to_string()),
                namespace: Some("recovered-namespace".to_string()),
                labels: Some(BTreeMap::from([
                    (LABEL_SANDBOX_ID.to_string(), "sandbox-id".to_string()),
                    (LABEL_SANDBOX_NAME.to_string(), "sandbox-name".to_string()),
                    (LABEL_SANDBOX_WORKSPACE.to_string(), "workspace".to_string()),
                    (
                        LABEL_MANAGED_BY.to_string(),
                        LABEL_MANAGED_BY_VALUE.to_string(),
                    ),
                ])),
                ..Default::default()
            },
            data: serde_json::json!({}),
        };
        let source =
            futures::stream::iter([Err(expired_watch_error()), Ok(Event::InitApply(recovered))])
                .chain(futures::stream::pending());
        let sandbox_stream = recovering_watcher_stream(source, "sandbox-resource").boxed();
        let driver = KubernetesComputeDriver::new_for_test(KubernetesComputeConfig::default());
        let mut outward = cluster_wide_watch_stream(
            sandbox_stream,
            "default".to_string(),
            driver.watch_client.clone(),
            driver,
        );

        let event = outward
            .next()
            .await
            .expect("outward stream must stay open through recovery")
            .expect("recoverable watcher error must not reach the outward stream");
        let Some(watch_sandboxes_event::Payload::Sandbox(event)) = event.payload else {
            panic!("expected recovered sandbox event");
        };
        let sandbox = event.sandbox.expect("sandbox payload must be populated");
        assert_eq!(sandbox.id, "sandbox-id");
        assert_eq!(sandbox.namespace, "recovered-namespace");

        let next = outward.next();
        futures::pin_mut!(next);
        assert!(
            futures::poll!(next).is_pending(),
            "outward stream must remain open after the recovered event"
        );
    }

    #[tokio::test]
    async fn kubernetes_event_watcher_error_does_not_hide_restarted_recovery_event() {
        let source = futures::stream::iter([
            Err(expired_watch_error()),
            Ok(Event::InitApply(KubeEventObj::default())),
        ]);
        let mut stream = continue_on_watcher_errors(source, "kubernetes-event");

        let event = stream
            .next()
            .await
            .expect("410 Expired must not terminate the watcher stream");
        let Event::InitApply(_event) = event else {
            panic!("expected kube-runtime recovery to emit InitApply");
        };
        assert!(
            stream.next().await.is_none(),
            "source closure must be preserved"
        );
    }

    fn sandbox_object_for_test(uid: &str, sandbox_id: &str) -> DynamicObject {
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            SANDBOX_GROUP,
            SANDBOX_VERSION_V1BETA1,
            SANDBOX_KIND,
        ));
        let mut sandbox = DynamicObject::new("sandbox-a", &resource);
        sandbox.metadata.uid = Some(uid.to_string());
        sandbox.metadata.namespace = Some("sandbox-namespace".to_string());
        sandbox.metadata.labels = Some(BTreeMap::from([(
            LABEL_SANDBOX_ID.to_string(),
            sandbox_id.to_string(),
        )]));
        sandbox
    }

    #[test]
    fn restart_runtime_selection_preserves_namespace_and_resource_uid() {
        let expected = parse_kubernetes_runtime_identity(
            "kubernetes://sandbox-namespace/resource-uid/old-supervisor-uid",
        )
        .expect("persisted identity");
        let sandbox = sandbox_object_for_test("resource-uid", "sandbox-id-a");
        let selected = select_expected_sandbox_runtime(vec![sandbox], &expected)
            .expect("matching runtime must be selected");
        assert_eq!(selected.metadata.uid.as_deref(), Some("resource-uid"));

        let wrong_namespace = KubernetesRuntimeIdentity {
            namespace: "other-namespace".to_string(),
            resource_uid: "resource-uid".to_string(),
        };
        assert!(matches!(
            select_expected_sandbox_runtime(
                vec![sandbox_object_for_test("resource-uid", "sandbox-id-a")],
                &wrong_namespace,
            ),
            Err(KubernetesDriverError::Precondition(_))
        ));

        let wrong_uid = KubernetesRuntimeIdentity {
            namespace: "sandbox-namespace".to_string(),
            resource_uid: "replacement-resource-uid".to_string(),
        };
        assert!(matches!(
            select_expected_sandbox_runtime(
                vec![sandbox_object_for_test("resource-uid", "sandbox-id-a")],
                &wrong_uid,
            ),
            Err(KubernetesDriverError::Precondition(_))
        ));
    }

    #[test]
    fn restart_runtime_selection_rejects_ambiguous_and_invalid_bindings() {
        let expected = parse_kubernetes_runtime_identity(
            "kubernetes://sandbox-namespace/resource-uid/old-supervisor-uid",
        )
        .expect("persisted identity");
        assert!(matches!(
            select_expected_sandbox_runtime(
                vec![
                    sandbox_object_for_test("resource-uid", "sandbox-id-a"),
                    sandbox_object_for_test("resource-uid", "sandbox-id-a"),
                ],
                &expected,
            ),
            Err(KubernetesDriverError::Precondition(_))
        ));
        assert!(matches!(
            parse_kubernetes_runtime_identity(""),
            Err(KubernetesDriverError::Precondition(_))
        ));
        assert!(matches!(
            parse_kubernetes_runtime_identity("kubernetes://namespace/resource-only"),
            Err(KubernetesDriverError::Precondition(_))
        ));
    }

    #[test]
    fn sandbox_runtime_fence_validation_accepts_api_normalization_and_injected_metadata() {
        let names = SandboxRuntimeNames::new("sandbox-id-a");
        let mut expected = workload_fence("namespace-a", &names, 5000).workload_policy;
        expected.metadata.labels = Some(BTreeMap::from([(
            LABEL_MANAGED_BY.to_string(),
            LABEL_MANAGED_BY_VALUE.to_string(),
        )]));

        let mut persisted = expected.clone();
        persisted.spec.as_mut().unwrap().egress = None;
        persisted
            .metadata
            .labels
            .as_mut()
            .unwrap()
            .insert("admission.example/injected".to_string(), "true".to_string());
        assert!(sandbox_runtime_fence_matches(&persisted, &expected));
        assert!(validate_sandbox_runtime_fence(&persisted, &expected).is_ok());

        persisted.spec.as_mut().unwrap().policy_types = Some(vec!["Ingress".to_string()]);
        assert!(!sandbox_runtime_fence_matches(&persisted, &expected));
        assert!(matches!(
            validate_sandbox_runtime_fence(&persisted, &expected),
            Err(KubernetesDriverError::Precondition(_))
        ));
    }

    #[test]
    fn supervisor_fence_persistence_requires_ingress_isolation() {
        let names = SandboxRuntimeNames::new("sandbox-id-a");
        let expected =
            workload_fence("without-namespace-default-deny", &names, 5000).supervisor_policy;
        let mut persisted = expected.clone();
        // Kubernetes may omit an empty ingress list, but must retain its type.
        persisted.spec.as_mut().unwrap().ingress = None;
        assert!(validate_sandbox_runtime_fence(&persisted, &expected).is_ok());
        persisted.spec.as_mut().unwrap().policy_types = Some(vec!["Egress".to_string()]);
        assert!(matches!(
            validate_sandbox_runtime_fence(&persisted, &expected),
            Err(KubernetesDriverError::Precondition(_))
        ));
    }

    #[test]
    fn both_persisted_fences_reject_retired_inbound_access() {
        use k8s_openapi::api::networking::v1::{NetworkPolicyIngressRule, NetworkPolicyPort};
        let names = SandboxRuntimeNames::new("sandbox-id-a");
        let fence = workload_fence("without-namespace-default-deny", &names, 5000);
        for expected in [fence.workload_policy, fence.supervisor_policy] {
            let mut persisted = expected.clone();
            persisted
                .spec
                .as_mut()
                .unwrap()
                .ingress
                .get_or_insert_default()
                .push(NetworkPolicyIngressRule {
                    ports: Some(vec![NetworkPolicyPort {
                        port: Some(IntOrString::Int(18_006)),
                        protocol: Some("TCP".to_string()),
                        ..Default::default()
                    }]),
                    ..Default::default()
                });
            assert!(matches!(
                validate_sandbox_runtime_fence(&persisted, &expected),
                Err(KubernetesDriverError::Precondition(_))
            ));
        }
    }

    fn sandbox_runtime_fence_pair_for_test() -> (NetworkPolicy, DynamicObject) {
        let policy = NetworkPolicy {
            metadata: ObjectMeta {
                uid: Some("policy-uid".to_string()),
                generation: Some(7),
                resource_version: Some("200".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            SANDBOX_GROUP,
            SANDBOX_VERSION_V1BETA1,
            SANDBOX_KIND,
        ));
        let mut sandbox = DynamicObject::new("sandbox", &resource);
        sandbox.metadata.annotations = Some(BTreeMap::from([
            (
                ANNOTATION_SANDBOX_RUNTIME_NETWORK_POLICY_UID.to_string(),
                "policy-uid".to_string(),
            ),
            (
                ANNOTATION_SANDBOX_RUNTIME_NETWORK_POLICY_GENERATION.to_string(),
                "7".to_string(),
            ),
        ]));
        (policy, sandbox)
    }

    #[test]
    fn sandbox_runtime_fence_reconciliation_uses_generation_not_resource_version() {
        let (mut policy, sandbox) = sandbox_runtime_fence_pair_for_test();

        assert!(
            sandbox_runtime_namespace_fence_generation_matches(&policy, &sandbox),
            "metadata-only writes must not invalidate an unchanged fence"
        );

        policy.metadata.generation = Some(8);
        assert!(
            !sandbox_runtime_namespace_fence_generation_matches(&policy, &sandbox),
            "a policy spec change must invalidate the recorded fence generation"
        );

        policy.metadata.generation = Some(7);
        policy.metadata.uid = Some("replacement-policy-uid".to_string());
        assert!(
            !sandbox_runtime_namespace_fence_generation_matches(&policy, &sandbox),
            "a replacement policy must invalidate the recorded fence identity"
        );
    }

    #[tokio::test]
    async fn configured_bootstrap_budget_keeps_slow_start_bounded() {
        let (mut driver, _) = delete_test_driver(vec![]);
        assert_eq!(driver.bootstrap_timeout(), Duration::from_mins(5));
        let (temp, _, _) = attach_delete_test_workspace(&mut driver);
        Arc::get_mut(driver.confidential.as_mut().unwrap())
            .unwrap()
            .bootstrap_timeout = Duration::from_mins(15);
        let started = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let object: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "agents.x-k8s.io/v1beta1", "kind": "Sandbox",
            "metadata": {"annotations": {
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_STARTED_AT: "1000000",
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAPPING: "true"
            }}
        }))
        .unwrap();
        assert!(!sandbox_runtime_bootstrap_is_stale(
            &object,
            started + Duration::from_mins(6),
            driver.bootstrap_timeout()
        ));
        assert!(sandbox_runtime_bootstrap_is_stale(
            &object,
            started + Duration::from_mins(15),
            driver.bootstrap_timeout()
        ));
        drop(driver);
        std::fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn sandbox_runtime_bootstrap_marker_and_age_gate_rollback() {
        let started = Duration::from_hours(490_896);
        let mut object: DynamicObject = serde_json::from_value(serde_json::json!({
            "apiVersion": "agents.x-k8s.io/v1beta1",
            "kind": "Sandbox",
            "metadata": {
                "name": "sandbox-a",
                "creationTimestamp": "2020-01-01T00:00:00Z",
                "annotations": {
                    ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAPPING: "true",
                    ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_STARTED_AT: started.as_millis().to_string(),
                    ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_OPERATION: "restart",
                }
            }
        }))
        .unwrap();
        assert!(sandbox_runtime_bootstrap_in_progress(&object));
        assert_eq!(
            sandbox_runtime_bootstrap_operation(&object),
            Some("restart")
        );
        let started_at = SystemTime::UNIX_EPOCH + started;
        assert!(!sandbox_runtime_bootstrap_is_stale(
            &object,
            started_at + SANDBOX_RUNTIME_BOOTSTRAP_GRACE - Duration::from_secs(1),
            SANDBOX_RUNTIME_BOOTSTRAP_GRACE
        ));
        assert!(sandbox_runtime_bootstrap_is_stale(
            &object,
            started_at + SANDBOX_RUNTIME_BOOTSTRAP_GRACE,
            SANDBOX_RUNTIME_BOOTSTRAP_GRACE
        ));
        object
            .metadata
            .annotations
            .as_mut()
            .unwrap()
            .remove(ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_STARTED_AT);
        assert!(sandbox_runtime_bootstrap_is_stale(
            &object,
            started_at,
            SANDBOX_RUNTIME_BOOTSTRAP_GRACE
        ));
        object
            .metadata
            .annotations
            .as_mut()
            .unwrap()
            .remove(ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAPPING);
        assert!(!sandbox_runtime_bootstrap_in_progress(&object));
    }

    #[test]
    fn sandbox_api_version_probe_retries_on_structured_and_raw_404() {
        let structured = kube_api_error(404, "could not find the requested resource");
        assert!(should_try_next_sandbox_api_version(&structured));

        let raw = kube_api_error(404, "404 page not found\n");
        assert!(should_try_next_sandbox_api_version(&raw));
    }

    #[test]
    fn lifecycle_patch_stops_supervisor_before_suspending_workload() {
        let stop_begin = sandbox_runtime_stop_begin_patch("42");
        assert_eq!(stop_begin["metadata"]["resourceVersion"], "42");
        assert_eq!(
            stop_begin["metadata"]["annotations"][ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAPPING],
            "true"
        );
        assert_eq!(
            stop_begin["metadata"]["annotations"][ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_PHASE],
            SandboxRuntimeBootstrapPhase::Releasing.as_str()
        );
        assert!(stop_begin.get("spec").is_none());

        let beta_stop = sandbox_runtime_suspension_patch(SANDBOX_VERSION_V1BETA1, "43");
        assert_eq!(beta_stop["spec"]["operatingMode"], "Suspended");
        assert!(beta_stop["spec"].get("replicas").is_none());

        let alpha_stop = sandbox_runtime_suspension_patch(SANDBOX_VERSION_V1ALPHA1, "44");
        assert_eq!(alpha_stop["spec"]["replicas"], 0);
        assert!(alpha_stop["spec"].get("operatingMode").is_none());

        let alpha_start = sandbox_operating_state_patch(SANDBOX_VERSION_V1ALPHA1, "45", true);
        assert_eq!(alpha_start["metadata"]["resourceVersion"], "45");
        assert!(alpha_start["metadata"].get("annotations").is_none());
        assert_eq!(alpha_start["spec"]["replicas"], 1);
        assert!(alpha_start["spec"].get("operatingMode").is_none());
    }

    #[tokio::test]
    async fn stop_resumed_from_suspending_removes_the_complete_runtime() {
        let sandbox = serde_json::json!({
            "apiVersion": "agents.x-k8s.io/v1beta1",
            "kind": "Sandbox",
            "metadata": {
                "name": "sandbox-cr",
                "namespace": "openshell",
                "uid": "old-uid",
                "resourceVersion": "42",
                "annotations": {
                    SANDBOX_POD_NAME_ANNOTATION: "workload-pod",
                    ANNOTATION_SANDBOX_RUNTIME_GENERATION: "gen-7",
                    ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_PHASE:
                        SandboxRuntimeBootstrapPhase::Suspending.as_str()
                }
            },
            "status": {"conditions": [{"type": "Suspended", "status": "True"}]}
        });
        let sandbox_path =
            "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes/sandbox-cr";
        let supervisor_path = "/api/v1/namespaces/openshell/pods/os-supervisor-sandbox-1";
        let success = || {
            kube_test_response(
                http::StatusCode::OK,
                serde_json::json!({"kind": "Status", "status": "Success", "code": 200}),
            )
        };
        let steps = Arc::new(std::sync::Mutex::new(VecDeque::from([
            (
                http::Method::GET,
                "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes",
                kube_test_response(
                    http::StatusCode::OK,
                    serde_json::json!({
                        "apiVersion": "agents.x-k8s.io/v1beta1",
                        "kind": "SandboxList",
                        "items": [sandbox.clone()]
                    }),
                ),
            ),
            (
                http::Method::GET,
                sandbox_path,
                kube_test_response(http::StatusCode::OK, sandbox.clone()),
            ),
            (
                http::Method::GET,
                "/api/v1/namespaces/openshell/pods/workload-pod",
                kube_test_not_found("pods", "workload-pod"),
            ),
            (
                http::Method::GET,
                supervisor_path,
                kube_test_response(
                    http::StatusCode::OK,
                    serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Pod",
                        "metadata": {
                            "name": "os-supervisor-sandbox-1", "uid": "supervisor-uid",
                            "ownerReferences": [{"apiVersion":"agents.x-k8s.io/v1beta1",
                                "kind":"Sandbox", "name":"sandbox-cr", "uid":"old-uid"}]
                        },
                        "spec": {"containers": []}
                    }),
                ),
            ),
            (http::Method::DELETE, supervisor_path, success()),
            (
                http::Method::GET,
                supervisor_path,
                kube_test_not_found("pods", "os-supervisor-sandbox-1"),
            ),
            (
                http::Method::GET,
                "/api/v1/namespaces/openshell/secrets/os-sandbox-sandbox-1-gen7",
                kube_test_not_found("secrets", "os-sandbox-sandbox-1-gen7"),
            ),
            (
                http::Method::GET,
                "/api/v1/namespaces/openshell/secrets/os-supervisor-sandbox-1-gen7",
                kube_test_not_found("secrets", "os-supervisor-sandbox-1-gen7"),
            ),
            (
                http::Method::GET,
                sandbox_path,
                kube_test_response(http::StatusCode::OK, sandbox.clone()),
            ),
            (
                http::Method::PATCH,
                sandbox_path,
                kube_test_response(http::StatusCode::OK, sandbox),
            ),
        ])));
        let service_steps = steps.clone();
        let service = tower::service_fn(move |request: http::Request<kube::client::Body>| {
            let steps = service_steps.clone();
            async move {
                let (method, path, response) = steps
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("unexpected Kubernetes API request");
                assert_eq!(request.method(), method);
                assert_eq!(request.uri().path(), path);
                Ok::<_, std::convert::Infallible>(response)
            }
        });
        let client = Client::new(service, "openshell");
        let driver = KubernetesComputeDriver {
            client: client.clone(),
            watch_client: client,
            sandbox_api_version: Arc::new(OnceCell::new()),
            config: KubernetesComputeConfig::default(),
            operator_allowlist: None,
            confidential: None,
            lifecycle_gates: Arc::default(),
        };
        driver
            .sandbox_api_version
            .set(SANDBOX_VERSION_V1BETA1)
            .expect("set test Sandbox API version");

        tokio::time::timeout(Duration::from_secs(1), driver.stop_sandbox("sandbox-1"))
            .await
            .expect("stop timed out")
            .expect("resume stop from Suspending");
        assert!(steps.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn stop_does_not_patch_replacement_cr_after_lookup() {
        const LIST_PATH: &str = "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes";
        const CR_PATH: &str =
            "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes/sandbox-cr";
        let old = delete_test_sandbox("old-uid");
        let replacement = delete_test_sandbox("replacement-uid");
        let (driver, steps) = delete_test_driver(vec![
            (
                http::Method::GET,
                LIST_PATH,
                kube_test_response(
                    http::StatusCode::OK,
                    serde_json::json!({
                        "apiVersion":"agents.x-k8s.io/v1beta1", "kind":"SandboxList", "items":[old]
                    }),
                ),
            ),
            (
                http::Method::GET,
                CR_PATH,
                kube_test_response(http::StatusCode::OK, replacement),
            ),
        ]);
        let error = driver.stop_sandbox("sandbox-id").await.unwrap_err();
        assert!(error.to_string().contains("UID changed"), "{error}");
        assert!(steps.lock().unwrap().is_empty());
    }

    #[test]
    fn bootstrap_phase_round_trips_releasing() {
        let phase = SandboxRuntimeBootstrapPhase::Releasing;
        assert_eq!(
            SandboxRuntimeBootstrapPhase::parse(phase.as_str()),
            Some(phase)
        );
    }

    #[tokio::test]
    async fn control_release_reconcile_does_not_retry_a_stale_transition() {
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            SANDBOX_GROUP,
            SANDBOX_VERSION_V1BETA1,
            SANDBOX_KIND,
        ));
        let mut sandbox = DynamicObject::new("sandbox-cr", &resource);
        sandbox.metadata.namespace = Some("openshell".to_string());
        sandbox.metadata.uid = Some("old-uid".to_string());
        sandbox.metadata.resource_version = Some("42".to_string());
        sandbox.metadata.annotations = Some(BTreeMap::from([
            (
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_OPERATION.to_string(),
                "stop".to_string(),
            ),
            (
                ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_PHASE.to_string(),
                SandboxRuntimeBootstrapPhase::Releasing.as_str().to_string(),
            ),
        ]));

        let steps = Arc::new(std::sync::Mutex::new(VecDeque::from([
            (
                http::Method::GET,
                "/api/v1/namespaces/openshell/pods/os-supervisor-sandbox-1",
                kube_test_not_found("pods", "os-supervisor-sandbox-1"),
            ),
            (
                http::Method::PATCH,
                "/apis/agents.x-k8s.io/v1beta1/namespaces/openshell/sandboxes/sandbox-cr",
                kube_test_response(
                    http::StatusCode::CONFLICT,
                    serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Status",
                        "status": "Failure",
                        "message": "the object has been modified",
                        "reason": "Conflict",
                        "code": 409
                    }),
                ),
            ),
        ])));
        let service_steps = steps.clone();
        let service = tower::service_fn(move |request: http::Request<kube::client::Body>| {
            let steps = service_steps.clone();
            async move {
                let (method, path, response) =
                    steps.lock().unwrap().pop_front().expect(
                        "stale reconciliation must not retry with a newer resource version",
                    );
                assert_eq!(request.method(), method);
                assert_eq!(request.uri().path(), path);
                Ok::<_, std::convert::Infallible>(response)
            }
        });
        let client = Client::new(service, "openshell");
        let lookup_api = KubernetesComputeDriver::agent_sandbox_api(
            client.clone(),
            SANDBOX_VERSION_V1BETA1,
            "openshell",
        );
        let driver = KubernetesComputeDriver {
            client: client.clone(),
            watch_client: client,
            sandbox_api_version: Arc::new(OnceCell::new()),
            config: KubernetesComputeConfig::default(),
            operator_allowlist: None,
            confidential: None,
            lifecycle_gates: Arc::default(),
        };

        driver
            .reconcile_sandbox_runtime_control_release(
                &lookup_api,
                &sandbox,
                "sandbox-1",
                "openshell",
                "sandbox-cr",
            )
            .await;

        assert!(steps.lock().unwrap().is_empty());
    }

    #[test]
    fn stop_timeout_includes_pod_grace_period_and_reconcile_headroom() {
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            SANDBOX_GROUP,
            SANDBOX_VERSION_V1BETA1,
            SANDBOX_KIND,
        ));
        let mut sandbox = DynamicObject::new("sandbox", &resource);

        assert_eq!(
            kubernetes_sandbox_stop_timeout(&sandbox),
            Duration::from_mins(1),
            "an omitted grace period uses the Kubernetes 30-second default"
        );

        sandbox.data = serde_json::json!({
            "spec": {
                "podTemplate": {
                    "spec": {"terminationGracePeriodSeconds": 45}
                }
            }
        });
        assert_eq!(
            kubernetes_sandbox_stop_timeout(&sandbox),
            Duration::from_secs(75)
        );
    }

    #[test]
    fn supervisor_deletion_timeout_includes_grace_and_api_headroom() {
        let mut pod = Pod::default();
        assert_eq!(
            kubernetes_pod_termination_timeout(&pod),
            Duration::from_mins(1),
            "an older Pod without an explicit grace uses the Kubernetes default"
        );

        pod.spec = Some(k8s_openapi::api::core::v1::PodSpec {
            containers: Vec::new(),
            termination_grace_period_seconds: Some(45),
            ..Default::default()
        });
        assert_eq!(
            kubernetes_pod_termination_timeout(&pod),
            Duration::from_secs(75)
        );

        pod.spec.as_mut().unwrap().termination_grace_period_seconds = Some(0);
        assert_eq!(kubernetes_pod_termination_timeout(&pod), KUBE_API_TIMEOUT);
    }

    #[test]
    fn stop_poll_interval_backs_off_to_cap() {
        let mut interval = STOP_INITIAL_POLL_INTERVAL;
        let expected = [
            Duration::from_millis(500),
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(2),
        ];

        for expected_interval in expected {
            interval = next_stop_poll_interval(interval);
            assert_eq!(interval, expected_interval);
        }
    }

    #[test]
    fn stopped_status_requires_published_condition() {
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            SANDBOX_GROUP,
            SANDBOX_VERSION_V1ALPHA1,
            SANDBOX_KIND,
        ));
        let mut sandbox = DynamicObject::new("sandbox", &resource);
        sandbox.data = serde_json::json!({"status": {"replicas": 0}});

        assert!(
            !kubernetes_sandbox_has_stopped_condition(&sandbox),
            "v1alpha1 omits a zero status replica count on the wire; it is not a usable completion signal"
        );

        sandbox.data = serde_json::json!({
            "status": {
                "conditions": [{"type": "Suspended", "status": "True"}]
            }
        });
        assert!(kubernetes_sandbox_has_stopped_condition(&sandbox));
    }

    #[test]
    fn stale_generation_conditions_do_not_change_current_status() {
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            SANDBOX_GROUP,
            SANDBOX_VERSION_V1BETA1,
            SANDBOX_KIND,
        ));
        let mut sandbox = DynamicObject::new("sandbox", &resource);
        sandbox.metadata.generation = Some(2);
        sandbox.data = serde_json::json!({
            "status": {
                "conditions": [
                    {
                        "type": "Suspended",
                        "status": "True",
                        "reason": "PodTerminated",
                        "observedGeneration": 1
                    },
                    {
                        "type": "Ready",
                        "status": "True",
                        "reason": "DependenciesReady",
                        "observedGeneration": 2
                    }
                ]
            }
        });

        assert!(!kubernetes_sandbox_has_stopped_condition(&sandbox));
        let status = status_from_object(&sandbox).expect("sandbox status");
        assert_eq!(status.conditions.len(), 1);
        assert_eq!(status.conditions[0].r#type, "Ready");
    }

    #[test]
    fn beta_stop_requires_suspended_condition_and_deleted_pod() {
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            SANDBOX_GROUP,
            SANDBOX_VERSION_V1BETA1,
            SANDBOX_KIND,
        ));
        let mut sandbox = DynamicObject::new("sandbox", &resource);

        assert!(!kubernetes_sandbox_stop_is_complete(
            SANDBOX_VERSION_V1BETA1,
            &sandbox,
            true,
        ));

        sandbox.data = serde_json::json!({
            "status": {
                "conditions": [{"type": "Suspended", "status": "True"}]
            }
        });
        assert!(!kubernetes_sandbox_stop_is_complete(
            SANDBOX_VERSION_V1BETA1,
            &sandbox,
            false,
        ));
        assert!(kubernetes_sandbox_stop_is_complete(
            SANDBOX_VERSION_V1BETA1,
            &sandbox,
            true,
        ));
        assert!(kubernetes_sandbox_stop_is_complete(
            SANDBOX_VERSION_V1ALPHA1,
            &DynamicObject::new("sandbox", &resource),
            true,
        ));
    }

    #[test]
    fn stop_failure_only_rejects_terminal_suspension_condition() {
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            SANDBOX_GROUP,
            SANDBOX_VERSION_V1BETA1,
            SANDBOX_KIND,
        ));
        let mut sandbox = DynamicObject::new("sandbox", &resource);
        sandbox.data = serde_json::json!({
            "status": {
                "conditions": [{
                    "type": "Suspended",
                    "status": "False",
                    "reason": "PodNotOwned",
                    "message": "Refused to delete pod because it is not owned by this sandbox"
                }]
            }
        });

        assert_eq!(
            kubernetes_sandbox_stop_failure(&sandbox).as_deref(),
            Some(
                "Kubernetes sandbox stop rejected: Refused to delete pod because it is not owned by this sandbox"
            )
        );

        sandbox.data["status"]["conditions"][0]["status"] = serde_json::json!("Unknown");
        sandbox.data["status"]["conditions"][0]["reason"] = serde_json::json!("PodStateUnknown");
        assert!(
            kubernetes_sandbox_stop_failure(&sandbox).is_none(),
            "an unknown pod state can recover on a later controller reconciliation"
        );
    }

    #[test]
    fn sandbox_api_version_probe_keeps_non_404_errors() {
        let err = kube_api_error(403, "sandboxes.agents.x-k8s.io is forbidden");
        assert!(!should_try_next_sandbox_api_version(&err));
    }

    fn rendered_env<'a>(container: &'a serde_json::Value, name: &str) -> Option<&'a str> {
        container["env"]
            .as_array()?
            .iter()
            .find(|item| item.get("name").and_then(|value| value.as_str()) == Some(name))?
            .get("value")?
            .as_str()
    }

    #[test]
    fn driver_config_rejects_invalid_shape() {
        let template = SandboxTemplate {
            driver_config: Some(json_struct(serde_json::json!({
                "pod": "not-an-object"
            }))),
            ..SandboxTemplate::default()
        };

        let err = KubernetesSandboxDriverConfig::from_template(&template).unwrap_err();

        assert!(err.contains("invalid kubernetes driver_config"));
    }

    #[test]
    fn driver_config_rejects_unknown_fields() {
        let template = SandboxTemplate {
            driver_config: Some(json_struct(serde_json::json!({
                "cdi_devices": ["nvidia.com/gpu=0"]
            }))),
            ..SandboxTemplate::default()
        };

        let err = KubernetesSandboxDriverConfig::from_template(&template).unwrap_err();

        assert!(err.contains("unknown field"));
    }

    #[test]
    fn driver_config_for_spec_rejects_unknown_fields() {
        let sandbox = Sandbox {
            id: "sandbox-123".to_string(),
            spec: Some(SandboxSpec {
                template: Some(SandboxTemplate {
                    driver_config: Some(json_struct(serde_json::json!({
                        "gpu_device_ids": ["0000:2d:00.0"]
                    }))),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = kubernetes_driver_config_for_spec(sandbox.spec.as_ref()).unwrap_err();
        assert!(err.contains("unknown field"));
        assert!(err.contains("gpu_device_ids"));
    }

    #[test]
    fn driver_config_pvc_subpath_mounts_render_in_pod_template() {
        let template = SandboxTemplate {
            driver_config: Some(json_struct(serde_json::json!({
                "volumes": [{
                    "name": "user-data",
                    "persistent_volume_claim": {
                        "claim_name": "pvc-user-data-123",
                        "read_only": false
                    }
                }],
                "containers": {
                    "agent": {
                        "volume_mounts": [
                            {
                                "name": "user-data",
                                "mount_path": "/sandbox/.openshell/workspace",
                                "sub_path": "workspace",
                                "read_only": false
                            },
                            {
                                "name": "user-data",
                                "mount_path": "/sandbox/.openshell/memory",
                                "sub_path": "memory"
                            }
                        ]
                    }
                }
            }))),
            ..SandboxTemplate::default()
        };
        let spec = SandboxSpec {
            template: Some(template),
            ..SandboxSpec::default()
        };

        let cr = sandbox_to_k8s_spec_for_test(Some(&spec), &SandboxPodParams::default());
        let pod_template = &cr["spec"]["podTemplate"];

        let volumes = pod_template["spec"]["volumes"]
            .as_array()
            .expect("volumes should exist");
        let user_volume = volumes
            .iter()
            .find(|volume| volume["name"] == "user-data")
            .expect("user PVC volume should be rendered");
        assert_eq!(
            user_volume["persistentVolumeClaim"]["claimName"],
            "pvc-user-data-123"
        );
        assert_eq!(user_volume["persistentVolumeClaim"]["readOnly"], false);

        let mounts = pod_template["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .expect("volumeMounts should exist");
        let workspace_mount = mounts
            .iter()
            .find(|mount| mount["mountPath"] == "/sandbox/.openshell/workspace")
            .expect("workspace subPath mount should be rendered");
        assert_eq!(workspace_mount["name"], "user-data");
        assert_eq!(workspace_mount["subPath"], "workspace");
        assert_eq!(workspace_mount["readOnly"], false);

        let memory_mount = mounts
            .iter()
            .find(|mount| mount["mountPath"] == "/sandbox/.openshell/memory")
            .expect("memory subPath mount should be rendered");
        assert_eq!(memory_mount["name"], "user-data");
        assert_eq!(memory_mount["subPath"], "memory");
        assert_eq!(memory_mount["readOnly"], true);

        let spec_obj = cr["spec"].as_object().expect("spec should be an object");
        assert!(
            !spec_obj.contains_key("volumeClaimTemplates"),
            "explicit /sandbox driver_config mounts should skip the default workspace VCT"
        );
        let has_workspace_init = pod_template["spec"]["initContainers"]
            .as_array()
            .is_some_and(|containers| {
                containers
                    .iter()
                    .any(|container| container["name"] == WORKSPACE_INIT_CONTAINER_NAME)
            });
        assert!(
            !has_workspace_init,
            "explicit /sandbox driver_config mounts should skip the default workspace init container"
        );
    }

    #[test]
    fn driver_config_accepts_read_write_pvc_with_multiple_subpath_mounts() {
        let template = SandboxTemplate {
            driver_config: Some(json_struct(serde_json::json!({
                "volumes": [{
                    "name": "user-data",
                    "persistent_volume_claim": {
                        "claim_name": "pvc-user-data",
                        "read_only": false
                    }
                }],
                "containers": {
                    "agent": {
                        "volume_mounts": [
                            {
                                "name": "user-data",
                                "mount_path": "/sandbox/.openshell/workspace",
                                "sub_path": "workspace",
                                "read_only": false
                            },
                            {
                                "name": "user-data",
                                "mount_path": "/sandbox/.openshell/memory",
                                "sub_path": "memory",
                                "read_only": false
                            },
                            {
                                "name": "user-data",
                                "mount_path": "/sandbox/.openshell/sessions",
                                "sub_path": "sessions",
                                "read_only": false
                            }
                        ]
                    }
                }
            }))),
            ..SandboxTemplate::default()
        };

        let config = KubernetesSandboxDriverConfig::from_template(&template)
            .expect("read-write PVC with multiple subPath mounts should validate");

        assert_eq!(config.volumes.len(), 1);
        assert_eq!(config.volumes[0].name, "user-data");
        assert_eq!(
            config.volumes[0].persistent_volume_claim.claim_name,
            "pvc-user-data"
        );
        assert!(!config.volumes[0].persistent_volume_claim.read_only);
        assert_eq!(config.containers.agent.volume_mounts.len(), 3);
        assert!(
            config
                .containers
                .agent
                .volume_mounts
                .iter()
                .all(|mount| !mount.read_only)
        );
        assert!(config.has_explicit_sandbox_data_mount());
    }

    #[test]
    fn driver_config_rejects_duplicate_pvc_volume_names() {
        let template = SandboxTemplate {
            driver_config: Some(json_struct(serde_json::json!({
                "volumes": [
                    {
                        "name": "user-data",
                        "persistent_volume_claim": {"claim_name": "pvc-a"}
                    },
                    {
                        "name": "user-data",
                        "persistent_volume_claim": {"claim_name": "pvc-b"}
                    }
                ]
            }))),
            ..SandboxTemplate::default()
        };

        let err = KubernetesSandboxDriverConfig::from_template(&template).unwrap_err();

        assert!(err.contains("duplicate kubernetes driver_config volume"));
    }

    #[test]
    fn driver_config_rejects_duplicate_pvc_volume_mount_targets() {
        let template = SandboxTemplate {
            driver_config: Some(json_struct(serde_json::json!({
                "volumes": [{
                    "name": "user-data",
                    "persistent_volume_claim": {"claim_name": "pvc-user-data"}
                }],
                "containers": {
                    "agent": {
                        "volume_mounts": [
                            {
                                "name": "user-data",
                                "mount_path": "/sandbox/.openshell/workspace"
                            },
                            {
                                "name": "user-data",
                                "mount_path": "/sandbox/.openshell/workspace"
                            }
                        ]
                    }
                }
            }))),
            ..SandboxTemplate::default()
        };

        let err = KubernetesSandboxDriverConfig::from_template(&template).unwrap_err();

        assert!(err.contains("duplicate kubernetes driver_config mount target"));
    }

    #[test]
    fn driver_config_accepts_dns1123_subdomain_pvc_claim_name() {
        let template = SandboxTemplate {
            driver_config: Some(json_struct(serde_json::json!({
                "volumes": [{
                    "name": "user-data",
                    "persistent_volume_claim": {"claim_name": "pvc.user-data.123"}
                }]
            }))),
            ..SandboxTemplate::default()
        };

        let config = KubernetesSandboxDriverConfig::from_template(&template)
            .expect("DNS-1123 subdomain PVC names should validate");

        assert_eq!(
            config.volumes[0].persistent_volume_claim.claim_name,
            "pvc.user-data.123"
        );
    }

    #[test]
    fn driver_config_rejects_invalid_volume_label_and_claim_name() {
        for (field, config) in [
            (
                "volumes[].name",
                serde_json::json!({
                    "volumes": [{
                        "name": "User_Data",
                        "persistent_volume_claim": {"claim_name": "pvc-user-data"}
                    }]
                }),
            ),
            (
                "volumes[].persistent_volume_claim.claim_name",
                serde_json::json!({
                    "volumes": [{
                        "name": "user-data",
                        "persistent_volume_claim": {"claim_name": "Pvc_User_Data"}
                    }]
                }),
            ),
        ] {
            let template = SandboxTemplate {
                driver_config: Some(json_struct(config)),
                ..SandboxTemplate::default()
            };

            let err = KubernetesSandboxDriverConfig::from_template(&template).unwrap_err();
            assert!(
                err.contains(field) && err.contains("DNS-1123"),
                "expected invalid {field} to fail DNS-1123 validation, got {err}"
            );
        }
    }

    #[test]
    fn driver_config_rejects_mounts_referencing_unknown_volumes() {
        let template = SandboxTemplate {
            driver_config: Some(json_struct(serde_json::json!({
                "volumes": [{
                    "name": "known-data",
                    "persistent_volume_claim": {"claim_name": "pvc-known"}
                }],
                "containers": {
                    "agent": {
                        "volume_mounts": [{
                            "name": "missing-data",
                            "mount_path": "/sandbox/.openshell/workspace",
                            "sub_path": "workspace"
                        }]
                    }
                }
            }))),
            ..SandboxTemplate::default()
        };

        let err = KubernetesSandboxDriverConfig::from_template(&template).unwrap_err();

        assert!(err.contains("unknown kubernetes driver_config volume 'missing-data'"));
    }

    #[test]
    fn driver_config_rejects_shared_reserved_mount_targets() {
        for mount_path in [
            "/",
            "/sandbox",
            "/etc/openshell",
            "/etc/openshell-tls/client",
            "/opt/openshell/bin",
        ] {
            let template = SandboxTemplate {
                driver_config: Some(json_struct(serde_json::json!({
                    "volumes": [{
                        "name": "user-data",
                        "persistent_volume_claim": {"claim_name": "pvc-user-data"}
                    }],
                    "containers": {
                        "agent": {
                            "volume_mounts": [{
                                "name": "user-data",
                                "mount_path": mount_path
                            }]
                        }
                    }
                }))),
                ..SandboxTemplate::default()
            };

            let err = KubernetesSandboxDriverConfig::from_template(&template).unwrap_err();
            assert!(
                err.contains("mount path") || err.contains("mount target"),
                "expected protected mount target {mount_path:?} to be rejected, got {err}"
            );
        }
    }

    #[test]
    fn driver_config_rejects_kubernetes_static_protected_mount_targets() {
        let spec = SandboxSpec {
            template: Some(SandboxTemplate {
                driver_config: Some(json_struct(serde_json::json!({
                    "volumes": [{
                        "name": "user-data",
                        "persistent_volume_claim": {"claim_name": "pvc-user-data"}
                    }],
                    "containers": {
                        "agent": {
                            "volume_mounts": [{
                                "name": "user-data",
                                "mount_path": "/var/run/secrets/openshell"
                            }]
                        }
                    }
                }))),
                ..SandboxTemplate::default()
            }),
            ..SandboxSpec::default()
        };

        let err = kubernetes_driver_config_for_spec(Some(&spec)).unwrap_err();

        assert!(err.contains("/var/run/secrets/openshell"));
    }

    #[test]
    fn driver_config_allows_spiffe_workload_path_without_provider_spiffe() {
        let spec = SandboxSpec {
            template: Some(SandboxTemplate {
                driver_config: Some(json_struct(serde_json::json!({
                    "volumes": [{
                        "name": "user-data",
                        "persistent_volume_claim": {"claim_name": "pvc-user-data"}
                    }],
                    "containers": {
                        "agent": {
                            "volume_mounts": [{
                                "name": "user-data",
                                "mount_path": "/spiffe-workload-api"
                            }]
                        }
                    }
                }))),
                ..SandboxTemplate::default()
            }),
            ..SandboxSpec::default()
        };

        kubernetes_driver_config_for_spec(Some(&spec))
            .expect("SPIFFE workload path should only be protected when SPIFFE is enabled");
    }

    #[test]
    fn driver_config_rejects_invalid_kubernetes_sub_paths() {
        for sub_path in ["/workspace", "../workspace"] {
            let template = SandboxTemplate {
                driver_config: Some(json_struct(serde_json::json!({
                    "volumes": [{
                        "name": "user-data",
                        "persistent_volume_claim": {"claim_name": "pvc-user-data"}
                    }],
                    "containers": {
                        "agent": {
                            "volume_mounts": [{
                                "name": "user-data",
                                "mount_path": "/sandbox/.openshell/workspace",
                                "sub_path": sub_path
                            }]
                        }
                    }
                }))),
                ..SandboxTemplate::default()
            };

            let err = KubernetesSandboxDriverConfig::from_template(&template).unwrap_err();
            assert!(
                err.contains("mount subpath must be relative"),
                "expected invalid sub_path {sub_path:?} to be rejected, got {err}"
            );
        }
    }

    #[test]
    fn driver_config_defaults_pvc_mounts_to_read_only() {
        let template = SandboxTemplate {
            driver_config: Some(json_struct(serde_json::json!({
                "volumes": [{
                    "name": "user-data",
                    "persistent_volume_claim": {"claim_name": "pvc-user-data"}
                }],
                "containers": {
                    "agent": {
                        "volume_mounts": [{
                            "name": "user-data",
                            "mount_path": "/sandbox/.openshell/workspace",
                            "sub_path": "workspace"
                        }]
                    }
                }
            }))),
            ..SandboxTemplate::default()
        };

        let pod_template = sandbox_template_to_k8s(
            &template,
            false,
            &std::collections::HashMap::new(),
            false,
            &SandboxPodParams::default(),
        );

        let volume = pod_template["spec"]["volumes"]
            .as_array()
            .expect("volumes should exist")
            .iter()
            .find(|volume| volume["name"] == "user-data")
            .expect("user volume should exist");
        assert_eq!(volume["persistentVolumeClaim"]["readOnly"], true);

        let mount = pod_template["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .expect("volumeMounts should exist")
            .iter()
            .find(|mount| mount["mountPath"] == "/sandbox/.openshell/workspace")
            .expect("user mount should exist");
        assert_eq!(mount["readOnly"], true);
    }

    #[test]
    fn driver_config_rejects_read_write_mount_for_read_only_pvc_volume() {
        let template = SandboxTemplate {
            driver_config: Some(json_struct(serde_json::json!({
                "volumes": [{
                    "name": "user-data",
                    "persistent_volume_claim": {
                        "claim_name": "pvc-user-data",
                        "read_only": true
                    }
                }],
                "containers": {
                    "agent": {
                        "volume_mounts": [{
                            "name": "user-data",
                            "mount_path": "/sandbox/.openshell/workspace",
                            "read_only": false
                        }]
                    }
                }
            }))),
            ..SandboxTemplate::default()
        };

        let err = KubernetesSandboxDriverConfig::from_template(&template).unwrap_err();

        assert!(err.contains("cannot set read_only=false"));
    }

    #[test]
    fn driver_config_rejects_reserved_kubernetes_volume_names() {
        for volume_name in [
            CLIENT_TLS_VOLUME_NAME,
            SERVICE_ACCOUNT_TOKEN_VOLUME_NAME,
            SPIFFE_WORKLOAD_API_VOLUME_NAME,
            SANDBOX_RUNTIME_VOLUME_NAME,
            SANDBOX_STATE_VOLUME_NAME,
            SANDBOX_BOOTSTRAP_VOLUME_NAME,
            SANDBOX_POD_IDENTITY_VOLUME_NAME,
            SANDBOX_PROXY_CA_VOLUME_NAME,
            WORKSPACE_VOLUME_NAME,
        ] {
            let template = SandboxTemplate {
                driver_config: Some(json_struct(serde_json::json!({
                    "volumes": [{
                        "name": volume_name,
                        "persistent_volume_claim": {"claim_name": "pvc-user-data"}
                    }]
                }))),
                ..SandboxTemplate::default()
            };

            let err = KubernetesSandboxDriverConfig::from_template(&template).unwrap_err();
            assert!(
                err.contains("reserved for OpenShell-managed volumes"),
                "expected reserved volume name {volume_name:?} to be rejected, got {err}"
            );
        }
    }

    #[test]
    fn reserved_kubernetes_volume_names_cover_managed_pod_volumes() {
        let params = SandboxPodParams::default();
        let pod_template = sandbox_template_to_k8s(
            &SandboxTemplate::default(),
            false,
            &std::collections::HashMap::new(),
            true,
            &params,
        );
        let volume_names = pod_template["spec"]["volumes"]
            .as_array()
            .expect("volumes should exist")
            .iter()
            .filter_map(|volume| volume["name"].as_str())
            .collect::<Vec<_>>();

        for volume_name in volume_names {
            assert!(
                KUBERNETES_DRIVER_RESERVED_VOLUME_NAMES.contains(&volume_name),
                "managed volume {volume_name:?} should be reserved"
            );
        }
    }

    #[test]
    fn validate_rejects_zero_gpu_count() {
        let sandbox = Sandbox {
            spec: Some(SandboxSpec {
                resource_requirements: Some(ResourceRequirements {
                    gpu: Some(GpuResourceRequirements { count: Some(0) }),
                }),
                ..SandboxSpec::default()
            }),
            ..Sandbox::default()
        };

        let gpu_requirements = sandbox
            .spec
            .as_ref()
            .and_then(|spec| driver_gpu_requirements(spec.resource_requirements.as_ref()));
        let err = validate_gpu_request(gpu_requirements).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("gpu count must be greater than 0"));
    }

    #[test]
    fn kube_pulling_event_adds_image_progress_metadata() {
        let mut metadata = std::collections::HashMap::new();

        attach_kube_progress_metadata(
            &mut metadata,
            "Pulling",
            "Pulling image \"ghcr.io/acme/sandbox:latest\"",
        );

        assert_eq!(
            metadata.get(PROGRESS_ACTIVE_STEP_KEY).map(String::as_str),
            Some(PROGRESS_STEP_PULLING_IMAGE)
        );
        assert_eq!(
            metadata.get(PROGRESS_ACTIVE_DETAIL_KEY).map(String::as_str),
            Some("ghcr.io/acme/sandbox:latest")
        );
    }

    #[test]
    fn kube_pulled_event_adds_completed_image_progress_metadata() {
        let mut metadata = std::collections::HashMap::new();

        attach_kube_progress_metadata(
            &mut metadata,
            "Pulled",
            "Successfully pulled image \"ghcr.io/acme/sandbox:latest\". Image size: 44040192 bytes.",
        );

        assert_eq!(
            metadata.get(PROGRESS_COMPLETE_STEP_KEY).map(String::as_str),
            Some(PROGRESS_STEP_PULLING_IMAGE)
        );
        assert_eq!(
            metadata
                .get(PROGRESS_COMPLETE_LABEL_KEY)
                .map(String::as_str),
            Some("Image pulled (42 MB)")
        );
        assert_eq!(
            metadata.get(PROGRESS_ACTIVE_STEP_KEY).map(String::as_str),
            Some(PROGRESS_STEP_STARTING_SANDBOX)
        );
    }

    #[test]
    fn sandbox_runtime_renders_credential_free_boundary_workload() {
        let params = SandboxPodParams {
            default_image: "agent:latest",
            image_pull_policy: Some(crate::KubernetesImagePullPolicy::Always),
            sandbox_runtime_image: "sandbox-runtime-image:latest",
            sandbox_runtime_image_pull_policy: Some(crate::KubernetesImagePullPolicy::Never),
            sandbox_id: "sandbox-123",
            sandbox_uid: 1500,
            sandbox_gid: 1500,
            ..SandboxPodParams::default()
        };
        let pod_template = sandbox_template_to_k8s(
            &SandboxTemplate::default(),
            false,
            &std::collections::HashMap::new(),
            true,
            &params,
        );
        let agent = &pod_template["spec"]["containers"][0];
        assert_eq!(agent["imagePullPolicy"], "Always");

        assert_eq!(
            agent["command"],
            serde_json::json!([
                format!("{SANDBOX_RUNTIME_MOUNT_PATH}/openshell-sandbox"),
                "--bootstrap",
                BOUNDARY_CONFIG_PATH
            ])
        );
        assert_eq!(agent["securityContext"]["runAsUser"], 1500);
        assert_eq!(agent["securityContext"]["runAsGroup"], 1500);
        assert_eq!(agent["securityContext"]["runAsNonRoot"], true);
        assert_eq!(
            agent["securityContext"]["capabilities"],
            serde_json::json!({"drop": ["ALL"]})
        );
        assert!(agent["securityContext"]["capabilities"]["add"].is_null());
        assert_eq!(pod_template["spec"]["securityContext"]["fsGroup"], 1500);
        assert_eq!(
            pod_template["spec"]["securityContext"]["seccompProfile"]["type"],
            "RuntimeDefault"
        );
        assert_eq!(pod_template["spec"]["dnsPolicy"], "None");
        assert_eq!(
            pod_template["spec"]["dnsConfig"]["nameservers"],
            serde_json::json!(["127.0.0.53"])
        );
        assert_eq!(
            pod_template["spec"]["schedulingGates"],
            serde_json::json!([{"name": SANDBOX_BOOTSTRAP_SCHEDULING_GATE}])
        );
        let sandbox_bootstrap = pod_template["spec"]["initContainers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|container| container["name"] == "openshell-sandbox-bootstrap")
            .unwrap();
        assert_eq!(sandbox_bootstrap["image"], "sandbox-runtime-image:latest");
        assert_eq!(sandbox_bootstrap["imagePullPolicy"], "Never");
        let workspace_init = pod_template["spec"]["initContainers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|container| container["name"] == WORKSPACE_INIT_CONTAINER_NAME)
            .unwrap();
        assert_eq!(
            workspace_init["command"],
            serde_json::json!([
                format!("{SANDBOX_RUNTIME_MOUNT_PATH}/openshell-sandbox"),
                "seed-workspace"
            ])
        );
        assert_eq!(workspace_init["securityContext"]["runAsUser"], 1500);
        assert_eq!(workspace_init["imagePullPolicy"], "Always");
        assert_eq!(
            workspace_init["securityContext"]["capabilities"],
            serde_json::json!({"drop": ["ALL"]})
        );
        assert_eq!(
            rendered_env(agent, openshell_core::sandbox_env::ENDPOINT),
            None
        );
        assert_eq!(
            rendered_env(agent, openshell_core::sandbox_env::K8S_SA_TOKEN_FILE),
            None
        );
        assert_eq!(
            pod_template["metadata"]["labels"][BOUNDARY_ROLE_LABEL],
            "workload"
        );

        let mounts = agent["volumeMounts"].as_array().unwrap();
        assert!(mounts.iter().any(|mount| {
            mount["name"] == SANDBOX_RUNTIME_VOLUME_NAME && mount["readOnly"] == true
        }));
        assert!(mounts.iter().any(|mount| {
            mount["name"] == SANDBOX_STATE_VOLUME_NAME && mount["readOnly"].is_null()
        }));
        assert!(mounts.iter().any(|mount| {
            mount["name"] == SANDBOX_POD_IDENTITY_VOLUME_NAME
                && mount["mountPath"] == SANDBOX_POD_IDENTITY_MOUNT_PATH
                && mount["readOnly"] == true
        }));
        assert!(mounts.iter().any(|mount| {
            mount["name"] == SANDBOX_PROXY_CA_VOLUME_NAME
                && mount["mountPath"] == SANDBOX_PROXY_CA_MOUNT_PATH
                && mount["readOnly"].is_null()
        }));
        assert!(
            !mounts
                .iter()
                .any(|mount| mount["name"] == SANDBOX_BOOTSTRAP_VOLUME_NAME)
        );
        assert!(
            !mounts
                .iter()
                .any(|mount| mount["name"] == CLIENT_TLS_VOLUME_NAME)
        );
        assert!(
            !mounts
                .iter()
                .any(|mount| mount["name"] == SERVICE_ACCOUNT_TOKEN_VOLUME_NAME)
        );

        let volumes = pod_template["spec"]["volumes"].as_array().unwrap();
        let pod_identity = volumes
            .iter()
            .find(|volume| volume["name"] == SANDBOX_POD_IDENTITY_VOLUME_NAME)
            .unwrap();
        assert_eq!(
            pod_identity["downwardAPI"]["items"],
            serde_json::json!([{"path": "uid", "fieldRef": {"fieldPath": "metadata.uid"}}])
        );
    }

    /// Regression test: TLS mount path must match env var paths.
    /// The volume is mounted at a specific path and the env vars must point to
    /// files within that same path, otherwise the sandbox will fail to start
    /// with "No such file or directory" errors.

    #[test]
    fn gpu_sandbox_adds_runtime_class_and_gpu_limit() {
        let pod_template = {
            let params = SandboxPodParams::default();
            sandbox_template_to_k8s(
                &SandboxTemplate::default(),
                true,
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        assert_eq!(
            pod_template["spec"]["runtimeClassName"],
            serde_json::Value::Null
        );
        assert_eq!(
            pod_template["spec"]["containers"][0]["resources"]["limits"][GPU_RESOURCE_NAME],
            serde_json::json!("1")
        );
    }

    #[test]
    fn gpu_count_sandbox_adds_requested_gpu_limit() {
        let pod_template = {
            let params = SandboxPodParams::default();
            let gpu_requirements = GpuResourceRequirements { count: Some(2) };
            sandbox_template_to_k8s_with_gpu_requirements(
                &SandboxTemplate::default(),
                Some(&gpu_requirements),
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        assert_eq!(
            pod_template["spec"]["containers"][0]["resources"]["limits"][GPU_RESOURCE_NAME],
            serde_json::json!("2")
        );
    }

    #[test]
    fn gpu_sandbox_uses_template_runtime_class_name_when_set() {
        let template = SandboxTemplate {
            platform_config: Some(Struct {
                fields: std::iter::once((
                    "runtime_class_name".to_string(),
                    Value {
                        kind: Some(Kind::StringValue("kata-containers".to_string())),
                    },
                ))
                .collect(),
            }),
            ..SandboxTemplate::default()
        };

        let pod_template = {
            let params = SandboxPodParams::default();
            sandbox_template_to_k8s(
                &template,
                true,
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        assert_eq!(
            pod_template["spec"]["runtimeClassName"],
            serde_json::json!("kata-containers")
        );
    }

    #[test]
    fn non_gpu_sandbox_uses_template_runtime_class_name_when_set() {
        let template = SandboxTemplate {
            platform_config: Some(Struct {
                fields: std::iter::once((
                    "runtime_class_name".to_string(),
                    Value {
                        kind: Some(Kind::StringValue("kata-containers".to_string())),
                    },
                ))
                .collect(),
            }),
            ..SandboxTemplate::default()
        };

        let pod_template = {
            let params = SandboxPodParams::default();
            sandbox_template_to_k8s(
                &template,
                false,
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        assert_eq!(
            pod_template["spec"]["runtimeClassName"],
            serde_json::json!("kata-containers")
        );
    }

    #[test]
    fn default_runtime_class_name_applied_when_template_omits_it() {
        let template = SandboxTemplate::default();
        let pod_template = {
            let params = SandboxPodParams {
                default_runtime_class_name: "kata-containers",
                ..SandboxPodParams::default()
            };
            sandbox_template_to_k8s(
                &template,
                false,
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        assert_eq!(
            pod_template["spec"]["runtimeClassName"],
            serde_json::json!("kata-containers")
        );
    }

    #[test]
    fn template_runtime_class_name_overrides_config_default() {
        let template = SandboxTemplate {
            platform_config: Some(Struct {
                fields: std::iter::once((
                    "runtime_class_name".to_string(),
                    Value {
                        kind: Some(Kind::StringValue("gvisor".to_string())),
                    },
                ))
                .collect(),
            }),
            ..SandboxTemplate::default()
        };

        let pod_template = {
            let params = SandboxPodParams {
                default_runtime_class_name: "kata-containers",
                ..SandboxPodParams::default()
            };
            sandbox_template_to_k8s(
                &template,
                false,
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        assert_eq!(
            pod_template["spec"]["runtimeClassName"],
            serde_json::json!("gvisor")
        );
    }

    #[test]
    fn driver_config_runtime_class_name_applies_to_pod_spec() {
        let template = SandboxTemplate {
            driver_config: Some(json_struct(serde_json::json!({
                "pod": {
                    "runtime_class_name": "kata-containers"
                }
            }))),
            ..SandboxTemplate::default()
        };

        let pod_template = {
            let params = SandboxPodParams::default();
            sandbox_template_to_k8s(
                &template,
                false,
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        assert_eq!(
            pod_template["spec"]["runtimeClassName"],
            serde_json::json!("kata-containers")
        );
    }

    #[test]
    fn driver_config_runtime_class_name_overrides_config_default() {
        let template = SandboxTemplate {
            driver_config: Some(json_struct(serde_json::json!({
                "pod": {
                    "runtime_class_name": "kata-containers"
                }
            }))),
            ..SandboxTemplate::default()
        };

        let pod_template = {
            let params = SandboxPodParams {
                default_runtime_class_name: "gvisor",
                ..SandboxPodParams::default()
            };
            sandbox_template_to_k8s(
                &template,
                false,
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        assert_eq!(
            pod_template["spec"]["runtimeClassName"],
            serde_json::json!("kata-containers")
        );
    }

    #[test]
    fn template_runtime_class_name_overrides_driver_config() {
        let template = SandboxTemplate {
            platform_config: Some(Struct {
                fields: std::iter::once((
                    "runtime_class_name".to_string(),
                    Value {
                        kind: Some(Kind::StringValue("gvisor".to_string())),
                    },
                ))
                .collect(),
            }),
            driver_config: Some(json_struct(serde_json::json!({
                "pod": {
                    "runtime_class_name": "kata-containers"
                }
            }))),
            ..SandboxTemplate::default()
        };

        let pod_template = {
            let params = SandboxPodParams::default();
            sandbox_template_to_k8s(
                &template,
                false,
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        assert_eq!(
            pod_template["spec"]["runtimeClassName"],
            serde_json::json!("gvisor")
        );
    }

    #[test]
    fn runtime_class_name_omitted_when_both_template_and_default_empty() {
        let template = SandboxTemplate::default();
        let pod_template = {
            let params = SandboxPodParams::default();
            sandbox_template_to_k8s(
                &template,
                false,
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        assert_eq!(
            pod_template["spec"]["runtimeClassName"],
            serde_json::json!(null)
        );
    }

    #[test]
    fn gpu_sandbox_preserves_existing_resource_limits() {
        use openshell_core::proto::compute::v1::DriverResourceRequirements;
        let template = SandboxTemplate {
            resources: Some(DriverResourceRequirements {
                cpu_limit: "2".to_string(),
                ..Default::default()
            }),
            ..SandboxTemplate::default()
        };

        let pod_template = {
            let params = SandboxPodParams::default();
            sandbox_template_to_k8s(
                &template,
                true,
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        let limits = &pod_template["spec"]["containers"][0]["resources"]["limits"];
        assert_eq!(limits["cpu"], serde_json::json!("2"));
        assert_eq!(limits[GPU_RESOURCE_NAME], serde_json::json!("1"));
    }

    #[test]
    fn cpu_and_memory_limits_are_mirrored_to_requests() {
        use openshell_core::proto::compute::v1::DriverResourceRequirements;
        let template = SandboxTemplate {
            resources: Some(DriverResourceRequirements {
                cpu_limit: "500m".to_string(),
                memory_limit: "2Gi".to_string(),
                ..Default::default()
            }),
            ..SandboxTemplate::default()
        };

        let pod_template = {
            let params = SandboxPodParams::default();
            sandbox_template_to_k8s(
                &template,
                false,
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        let resources = &pod_template["spec"]["containers"][0]["resources"];
        assert_eq!(resources["limits"]["cpu"], serde_json::json!("500m"));
        assert_eq!(resources["limits"]["memory"], serde_json::json!("2Gi"));
        assert_eq!(resources["requests"]["cpu"], serde_json::json!("500m"));
        assert_eq!(resources["requests"]["memory"], serde_json::json!("2Gi"));
    }

    // -----------------------------------------------------------------------
    // Workspace persistence tests
    // -----------------------------------------------------------------------

    #[test]
    fn workspace_persistence_injects_init_container_volume_and_mount() {
        let mut pod_template = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "agent",
                    "image": "openshell/sandbox:latest"
                }]
            }
        });

        apply_workspace_persistence(
            &mut pod_template,
            "openshell/sandbox:latest",
            Some(crate::KubernetesImagePullPolicy::IfNotPresent),
            Some(1000), // sandbox_gid
            None,
        );

        // Init container
        let init_containers = pod_template["spec"]["initContainers"]
            .as_array()
            .expect("initContainers should exist");
        assert_eq!(init_containers.len(), 1);
        assert_eq!(init_containers[0]["name"], WORKSPACE_INIT_CONTAINER_NAME);
        assert_eq!(init_containers[0]["image"], "openshell/sandbox:latest");
        assert_eq!(init_containers[0]["imagePullPolicy"], "IfNotPresent");
        // init container always runs as root to handle PVC root directory permissions
        assert_eq!(init_containers[0]["securityContext"]["runAsUser"], 0);

        // Init container mounts PVC at temp path, not /sandbox
        let init_mounts = init_containers[0]["volumeMounts"]
            .as_array()
            .expect("init volumeMounts should exist");
        assert_eq!(init_mounts.len(), 1);
        assert_eq!(init_mounts[0]["name"], WORKSPACE_VOLUME_NAME);
        assert_eq!(init_mounts[0]["mountPath"], WORKSPACE_INIT_MOUNT_PATH);

        // Agent container mounts PVC at /sandbox
        let agent_mounts = pod_template["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .expect("agent volumeMounts should exist");
        let workspace_mount = agent_mounts
            .iter()
            .find(|m| m["name"] == WORKSPACE_VOLUME_NAME)
            .expect("workspace mount should exist on agent container");
        assert_eq!(workspace_mount["mountPath"], WORKSPACE_MOUNT_PATH);

        // The PVC volume is NOT created by apply_workspace_persistence — the
        // Sandbox CRD controller adds it from the volumeClaimTemplates.
        // Verify we did not inject one (which would cause a duplicate).
        let has_pvc_vol = pod_template["spec"]["volumes"]
            .as_array()
            .is_some_and(|vols| vols.iter().any(|v| v["name"] == WORKSPACE_VOLUME_NAME));
        assert!(
            !has_pvc_vol,
            "apply_workspace_persistence must NOT add a PVC volume (the CRD controller does that)"
        );
    }

    #[test]
    fn workspace_persistence_uses_same_image_as_agent() {
        let mut pod_template = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "agent",
                    "image": "my-custom-image:v2"
                }]
            }
        });

        apply_workspace_persistence(
            &mut pod_template,
            "my-custom-image:v2",
            Some(crate::KubernetesImagePullPolicy::IfNotPresent),
            Some(1000),
            None,
        );

        let init_image = pod_template["spec"]["initContainers"][0]["image"]
            .as_str()
            .expect("init container should have image");
        assert_eq!(
            init_image, "my-custom-image:v2",
            "init container must use the same image as the agent container"
        );
    }

    #[test]
    fn workspace_init_command_checks_sentinel() {
        let mut pod_template = serde_json::json!({
            "spec": {
                "containers": [{
                    "name": "agent",
                    "image": "img:latest"
                }]
            }
        });

        apply_workspace_persistence(
            &mut pod_template,
            "img:latest",
            Some(crate::KubernetesImagePullPolicy::Always),
            Some(1000),
            None,
        );

        let cmd = pod_template["spec"]["initContainers"][0]["command"]
            .as_array()
            .expect("command should be an array");
        let script = cmd[2].as_str().expect("third element should be the script");
        assert!(
            script.contains(WORKSPACE_SENTINEL),
            "init script must check for sentinel file"
        );
        assert!(
            script.contains("tar -C"),
            "init script must seed image contents with a tar stream"
        );
        assert!(
            script.contains("find . -mindepth 1 -maxdepth 1"),
            "init script must archive sandbox contents without the mount root entry"
        );
        assert!(
            script.contains("--no-same-owner")
                && script.contains("--no-same-permissions")
                && script.contains("--touch"),
            "init script must avoid restoring metadata onto the PVC root"
        );
    }

    #[test]
    fn workspace_persistence_skipped_when_inject_workspace_false() {
        let params = SandboxPodParams::default();
        let pod_template = sandbox_template_to_k8s(
            &SandboxTemplate::default(),
            false,
            &std::collections::HashMap::new(),
            false, // user provided custom VCTs
            &params,
        );

        // Only the supervisor init container should be present — no workspace init container
        let init_containers = pod_template["spec"]["initContainers"]
            .as_array()
            .expect("supervisor init container should always be present");
        assert!(
            !init_containers
                .iter()
                .any(|c| c["name"] == WORKSPACE_INIT_CONTAINER_NAME),
            "workspace init container must NOT be present when inject_workspace is false"
        );

        // No workspace volume mount on agent
        let has_workspace_mount = pod_template["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .is_some_and(|mounts| mounts.iter().any(|m| m["name"] == WORKSPACE_VOLUME_NAME));
        assert!(
            !has_workspace_mount,
            "workspace mount must NOT be present when inject_workspace is false"
        );
    }

    // -----------------------------------------------------------------------
    // User namespace tests
    // -----------------------------------------------------------------------

    fn default_template_to_k8s(enable_user_namespaces: bool) -> serde_json::Value {
        let params = SandboxPodParams {
            enable_user_namespaces,
            ..Default::default()
        };
        sandbox_template_to_k8s(
            &SandboxTemplate::default(),
            false,
            &std::collections::HashMap::new(),
            true,
            &params,
        )
    }

    #[test]
    fn user_namespaces_disabled_by_default() {
        let pod_template = default_template_to_k8s(false);
        assert!(
            pod_template["spec"]["hostUsers"].is_null(),
            "hostUsers must not be set when user namespaces are disabled"
        );
        let capabilities =
            &pod_template["spec"]["containers"][0]["securityContext"]["capabilities"];
        assert!(capabilities["add"].is_null());
        assert_eq!(capabilities["drop"], serde_json::json!(["ALL"]));
    }

    #[test]
    fn user_namespaces_enabled_by_cluster_default() {
        let pod_template = default_template_to_k8s(true);
        assert_eq!(
            pod_template["spec"]["hostUsers"],
            serde_json::json!(false),
            "hostUsers must be false when user namespaces are enabled"
        );
    }

    #[test]
    fn user_namespaces_preserve_capability_free_posture() {
        let pod_template = default_template_to_k8s(true);
        let capabilities =
            &pod_template["spec"]["containers"][0]["securityContext"]["capabilities"];
        assert!(capabilities["add"].is_null());
        assert_eq!(capabilities["drop"], serde_json::json!(["ALL"]));
    }

    #[test]
    fn user_namespaces_per_sandbox_override_enables() {
        let template = SandboxTemplate {
            user_namespaces: Some(true),
            ..SandboxTemplate::default()
        };

        let params = SandboxPodParams::default(); // cluster default is off
        let pod_template = sandbox_template_to_k8s(
            &template,
            false,
            &std::collections::HashMap::new(),
            true,
            &params,
        );

        assert_eq!(
            pod_template["spec"]["hostUsers"],
            serde_json::json!(false),
            "per-sandbox user namespace intent must set hostUsers: false"
        );
        let capabilities =
            &pod_template["spec"]["containers"][0]["securityContext"]["capabilities"];
        assert!(capabilities["add"].is_null());
        assert_eq!(capabilities["drop"], serde_json::json!(["ALL"]));
    }

    #[test]
    fn user_namespaces_per_sandbox_override_disables() {
        let template = SandboxTemplate {
            user_namespaces: Some(false),
            ..SandboxTemplate::default()
        };

        let params = SandboxPodParams {
            enable_user_namespaces: true, // cluster default is on
            ..Default::default()
        };
        let pod_template = sandbox_template_to_k8s(
            &template,
            false,
            &std::collections::HashMap::new(),
            true,
            &params,
        );

        assert!(
            pod_template["spec"]["hostUsers"].is_null(),
            "per-sandbox user namespace intent must override the cluster default"
        );
        let capabilities =
            &pod_template["spec"]["containers"][0]["securityContext"]["capabilities"];
        assert!(capabilities["add"].is_null());
        assert_eq!(capabilities["drop"], serde_json::json!(["ALL"]));
    }

    #[test]
    fn automount_service_account_token_is_disabled() {
        let pod_template = {
            let params = SandboxPodParams::default();
            sandbox_template_to_k8s(
                &SandboxTemplate::default(),
                false,
                &std::collections::HashMap::new(),
                true,
                &params,
            )
        };

        assert_eq!(
            pod_template["spec"]["automountServiceAccountToken"],
            serde_json::json!(false),
            "service account token auto-mounting must be disabled for security hardening"
        );
    }

    #[test]
    fn sandbox_template_sets_configured_service_account_name() {
        let params = SandboxPodParams {
            service_account_name: "openshell-sandbox",
            ..Default::default()
        };
        let pod_template = sandbox_template_to_k8s(
            &SandboxTemplate::default(),
            false,
            &std::collections::HashMap::new(),
            true,
            &params,
        );

        assert_eq!(
            pod_template["spec"]["serviceAccountName"],
            serde_json::json!("openshell-sandbox"),
            "sandbox pods must run under the configured service account"
        );
        assert_eq!(
            pod_template["spec"]["automountServiceAccountToken"],
            serde_json::json!(false),
            "explicit service account selection must not re-enable default token automounting"
        );
    }

    #[test]
    fn sandbox_template_omits_empty_image_pull_secrets() {
        let pod_template = sandbox_template_to_k8s(
            &SandboxTemplate::default(),
            false,
            &std::collections::HashMap::new(),
            true,
            &SandboxPodParams::default(),
        );

        assert!(
            pod_template["spec"]["imagePullSecrets"].is_null(),
            "imagePullSecrets must be omitted when no secrets are configured"
        );
    }

    #[test]
    fn sandbox_template_renders_configured_image_pull_secrets() {
        let secrets = vec![
            "regcred".to_string(),
            " backup-regcred ".to_string(),
            String::new(),
        ];
        let params = SandboxPodParams {
            image_pull_secrets: &secrets,
            ..Default::default()
        };
        let pod_template = sandbox_template_to_k8s(
            &SandboxTemplate::default(),
            false,
            &std::collections::HashMap::new(),
            true,
            &params,
        );

        assert_eq!(
            pod_template["spec"]["imagePullSecrets"],
            serde_json::json!([
                { "name": "regcred" },
                { "name": "backup-regcred" }
            ])
        );
    }

    #[test]
    fn sandbox_template_renders_image_pull_secrets_for_template_image() {
        let secrets = vec!["regcred".to_string()];
        let params = SandboxPodParams {
            default_image: "default-image:latest",
            image_pull_secrets: &secrets,
            ..Default::default()
        };
        let template = SandboxTemplate {
            image: "private.example.com/team/sandbox:v1".to_string(),
            ..Default::default()
        };
        let pod_template = sandbox_template_to_k8s(
            &template,
            false,
            &std::collections::HashMap::new(),
            true,
            &params,
        );

        assert_eq!(
            pod_template["spec"]["containers"][0]["image"],
            serde_json::json!("private.example.com/team/sandbox:v1")
        );
        assert_eq!(
            pod_template["spec"]["imagePullSecrets"],
            serde_json::json!([{ "name": "regcred" }])
        );
    }

    #[test]
    fn user_environment_is_preserved_for_sealing_and_absent_from_kubernetes() {
        let spec = SandboxSpec {
            template: Some(SandboxTemplate {
                environment: std::collections::HashMap::from([
                    ("TEMPLATE_TOKEN".into(), "template-secret-marker".into()),
                    ("OVERRIDE".into(), "template-value".into()),
                    ("OPENSHELL_LOG_LEVEL".into(), "info".into()),
                ]),
                ..Default::default()
            }),
            environment: std::collections::HashMap::from([
                (
                    "OVERRIDE".into(),
                    "spec-secret-marker=含空格\nsecond line".into(),
                ),
                ("EMPTY".into(), String::new()),
                ("OPENSHELL_SANDBOX_UID".into(), "0".into()),
            ]),
            ..Default::default()
        };
        let environment = workload_environment_from_spec(Some(&spec));
        assert_eq!(environment.len(), 3);
        assert_eq!(environment["TEMPLATE_TOKEN"], "template-secret-marker");
        assert_eq!(
            environment["OVERRIDE"],
            "spec-secret-marker=含空格\nsecond line"
        );
        assert_eq!(environment["EMPTY"], "");
        let cr = sandbox_to_k8s_spec_for_test(Some(&spec), &SandboxPodParams::default());
        let serialized = serde_json::to_string(&cr).unwrap();
        for forbidden in [
            "TEMPLATE_TOKEN",
            "OVERRIDE",
            "EMPTY",
            "template-secret-marker",
            "spec-secret-marker",
            "template-value",
        ] {
            assert!(
                !serialized.contains(forbidden),
                "user environment leaked to Kubernetes"
            );
        }
        let pod: Pod = serde_json::from_value(serde_json::json!({
            "metadata": cr["spec"]["podTemplate"]["metadata"],
            "spec": cr["spec"]["podTemplate"]["spec"],
        }))
        .unwrap();
        assert!(workload_environment_is_private(&pod));
    }

    #[test]
    fn policy_admission_rejects_reintroduced_user_env_and_env_sources() {
        let cr = sandbox_to_k8s_spec_for_test(None, &SandboxPodParams::default());
        let clean: Pod = serde_json::from_value(serde_json::json!({
            "metadata": cr["spec"]["podTemplate"]["metadata"],
            "spec": cr["spec"]["podTemplate"]["spec"],
        }))
        .unwrap();
        assert!(workload_environment_is_private(&clean));
        for entry in [
            serde_json::json!({"name": "TOKEN", "value": "host-injected"}),
            serde_json::json!({"name": "OPENSHELL_LOG_LEVEL", "valueFrom": {"secretKeyRef": {"name": "host-secret", "key": "value"}}}),
        ] {
            let mut pod = clean.clone();
            pod.spec.as_mut().unwrap().containers[0]
                .env
                .get_or_insert_default()
                .push(serde_json::from_value(entry).unwrap());
            assert!(!workload_environment_is_private(&pod));
        }
        let mut pod = clean.clone();
        pod.spec.as_mut().unwrap().containers[0].env_from = Some(vec![
            serde_json::from_value(serde_json::json!({"configMapRef": {"name": "host-env"}}))
                .unwrap(),
        ]);
        assert!(!workload_environment_is_private(&pod));
        let mut pod = clean;
        pod.spec.as_mut().unwrap().init_containers = Some(vec![
            serde_json::from_value(serde_json::json!({"name": "injected", "image": "test", "env": [{"name": "TOKEN", "value": "host-injected"}]})).unwrap(),
        ]);
        assert!(!workload_environment_is_private(&pod));
    }

    #[test]
    fn log_level_propagates_as_env_var_to_sandbox_pod() {
        let spec = SandboxSpec {
            log_level: "debug".to_string(),
            ..SandboxSpec::default()
        };
        let cr = sandbox_to_k8s_spec_for_test(Some(&spec), &SandboxPodParams::default());
        let env = cr["spec"]["podTemplate"]["spec"]["containers"][0]["env"]
            .as_array()
            .unwrap();
        assert!(
            env.iter()
                .any(|e| e["name"] == "OPENSHELL_LOG_LEVEL" && e["value"] == "debug")
        );
        assert!(cr["spec"].get("logLevel").is_none());
    }

    #[test]
    fn telemetry_toggle_propagates_from_driver_env_to_sandbox_pod() {
        let _guard = ENV_LOCK.lock().unwrap();
        temp_env::with_vars(
            [(
                openshell_core::sandbox_env::TELEMETRY_ENABLED,
                Some("false"),
            )],
            || {
                let spec = SandboxSpec {
                    environment: std::collections::HashMap::from([(
                        openshell_core::sandbox_env::TELEMETRY_ENABLED.to_string(),
                        "true".to_string(),
                    )]),
                    ..SandboxSpec::default()
                };
                let cr = sandbox_to_k8s_spec_for_test(Some(&spec), &SandboxPodParams::default());
                let env = cr["spec"]["podTemplate"]["spec"]["containers"][0]["env"]
                    .as_array()
                    .unwrap();
                let telemetry_entries = env
                    .iter()
                    .filter(|entry| entry["name"] == openshell_core::sandbox_env::TELEMETRY_ENABLED)
                    .collect::<Vec<_>>();

                assert_eq!(telemetry_entries.len(), 1);
                assert_eq!(telemetry_entries[0]["value"], serde_json::json!("false"));
            },
        );
    }

    #[test]
    fn node_selector_from_platform_config() {
        let template = SandboxTemplate {
            platform_config: Some(Struct {
                fields: std::iter::once((
                    "node_selector".to_string(),
                    Value {
                        kind: Some(Kind::StructValue(Struct {
                            fields: std::iter::once((
                                "gpu-pool".to_string(),
                                Value {
                                    kind: Some(Kind::StringValue("true".to_string())),
                                },
                            ))
                            .collect(),
                        })),
                    },
                ))
                .collect(),
            }),
            ..SandboxTemplate::default()
        };

        let pod_template = {
            let params = SandboxPodParams::default();
            sandbox_template_to_k8s(
                &template,
                false,
                &std::collections::HashMap::new(),
                false,
                &params,
            )
        };

        assert_eq!(
            pod_template["spec"]["nodeSelector"]["gpu-pool"],
            serde_json::json!("true")
        );
    }

    #[test]
    fn tolerations_from_platform_config() {
        let toleration = Struct {
            fields: [
                (
                    "key".to_string(),
                    Value {
                        kind: Some(Kind::StringValue("nvidia.com/gpu".to_string())),
                    },
                ),
                (
                    "operator".to_string(),
                    Value {
                        kind: Some(Kind::StringValue("Exists".to_string())),
                    },
                ),
                (
                    "effect".to_string(),
                    Value {
                        kind: Some(Kind::StringValue("NoSchedule".to_string())),
                    },
                ),
            ]
            .into_iter()
            .collect(),
        };

        let template = SandboxTemplate {
            platform_config: Some(Struct {
                fields: std::iter::once((
                    "tolerations".to_string(),
                    Value {
                        kind: Some(Kind::ListValue(prost_types::ListValue {
                            values: vec![Value {
                                kind: Some(Kind::StructValue(toleration)),
                            }],
                        })),
                    },
                ))
                .collect(),
            }),
            ..SandboxTemplate::default()
        };

        let pod_template = {
            let params = SandboxPodParams::default();
            sandbox_template_to_k8s(
                &template,
                false,
                &std::collections::HashMap::new(),
                false,
                &params,
            )
        };

        let tolerations = pod_template["spec"]["tolerations"]
            .as_array()
            .expect("tolerations should be an array");
        assert_eq!(tolerations.len(), 1);
        assert_eq!(tolerations[0]["key"], "nvidia.com/gpu");
        assert_eq!(tolerations[0]["operator"], "Exists");
        assert_eq!(tolerations[0]["effect"], "NoSchedule");
    }

    #[test]
    fn driver_config_applies_pod_scheduling_and_agent_resources() {
        let template = SandboxTemplate {
            driver_config: Some(json_struct(serde_json::json!({
                "pod": {
                    "node_selector": {
                        "accelerator": "nvidia"
                    },
                    "runtime_class_name": "kata-containers",
                    "priority_class_name": "gpu-workload",
                    "tolerations": [{
                        "key": "nvidia.com/gpu",
                        "operator": "Exists",
                        "effect": "NoSchedule"
                    }]
                },
                "containers": {
                    "agent": {
                        "resources": {
                            "requests": {
                                "vendor.example/gpu-memory": "8Gi"
                            },
                            "limits": {
                                "vendor.example/gpu-slices": "1"
                            }
                        }
                    }
                }
            }))),
            ..SandboxTemplate::default()
        };

        let pod_template = sandbox_template_to_k8s(
            &template,
            false,
            &std::collections::HashMap::new(),
            false,
            &SandboxPodParams::default(),
        );

        assert_eq!(
            pod_template["spec"]["nodeSelector"]["accelerator"],
            serde_json::json!("nvidia")
        );
        assert_eq!(
            pod_template["spec"]["priorityClassName"],
            serde_json::json!("gpu-workload")
        );
        assert_eq!(
            pod_template["spec"]["runtimeClassName"],
            serde_json::json!("kata-containers")
        );
        assert_eq!(
            pod_template["spec"]["tolerations"][0]["key"],
            serde_json::json!("nvidia.com/gpu")
        );
        assert_eq!(
            pod_template["spec"]["containers"][0]["resources"]["requests"]["vendor.example/gpu-memory"],
            serde_json::json!("8Gi")
        );
        assert_eq!(
            pod_template["spec"]["containers"][0]["resources"]["limits"]["vendor.example/gpu-slices"],
            serde_json::json!("1")
        );
    }

    #[test]
    fn default_workspace_vct_uses_provided_storage_size() {
        let vct = default_workspace_volume_claim_templates("5Gi", "");
        let storage = &vct[0]["spec"]["resources"]["requests"]["storage"];
        assert_eq!(storage, "5Gi");
    }

    #[test]
    fn default_workspace_vct_falls_back_to_const_when_empty() {
        let vct = default_workspace_volume_claim_templates("", "");
        let storage = &vct[0]["spec"]["resources"]["requests"]["storage"];
        assert_eq!(storage, DEFAULT_WORKSPACE_STORAGE_SIZE);
    }

    #[test]
    fn sandbox_name_validation_accepts_valid_dns_labels() {
        assert!(validate_kubernetes_dns1123_label("my-sandbox", "sandbox name").is_ok());
        assert!(validate_kubernetes_dns1123_label("test123", "sandbox name").is_ok());
        assert!(validate_kubernetes_dns1123_label("123abc", "sandbox name").is_ok());
    }

    #[test]
    fn sandbox_name_validation_rejects_invalid_dns_labels() {
        assert!(validate_kubernetes_dns1123_label("my_sandbox", "sandbox name").is_err());
        assert!(validate_kubernetes_dns1123_label("MySandbox", "sandbox name").is_err());
        assert!(validate_kubernetes_dns1123_label("dotted.name", "sandbox name").is_err());
    }

    #[test]
    fn kube_resource_name_length_validation_accepts_short_names() {
        validate_kube_resource_name_length("default", "my-sandbox").unwrap();
    }

    #[test]
    fn kube_resource_name_length_validation_rejects_oversized_names() {
        let long_ws = "a".repeat(40);
        let long_name = "b".repeat(25);
        let err = validate_kube_resource_name_length(&long_ws, &long_name).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("67"));
    }

    #[test]
    fn sandbox_from_object_reads_annotations() {
        let obj = DynamicObject {
            types: None,
            metadata: ObjectMeta {
                name: Some("alpha--work".to_string()),
                namespace: Some("default".to_string()),
                annotations: Some(BTreeMap::from([
                    (LABEL_SANDBOX_ID.to_string(), "uuid-123".to_string()),
                    (LABEL_SANDBOX_NAME.to_string(), "work".to_string()),
                    (LABEL_SANDBOX_WORKSPACE.to_string(), "alpha".to_string()),
                ])),
                labels: Some(BTreeMap::from([
                    (LABEL_SANDBOX_ID.to_string(), "uuid-123".to_string()),
                    (LABEL_SANDBOX_NAME.to_string(), "work".to_string()),
                    (LABEL_SANDBOX_WORKSPACE.to_string(), "alpha".to_string()),
                    (
                        LABEL_MANAGED_BY.to_string(),
                        LABEL_MANAGED_BY_VALUE.to_string(),
                    ),
                ])),
                ..Default::default()
            },
            data: serde_json::json!({}),
        };

        let (kube_name, sandbox) = sandbox_from_object("default", obj).unwrap();
        assert_eq!(kube_name, "alpha--work");
        assert_eq!(sandbox.name, "work");
        assert_eq!(sandbox.workspace, "alpha");
        assert_eq!(sandbox.id, "uuid-123");
    }

    #[test]
    fn sandbox_from_object_falls_back_to_labels() {
        let obj = DynamicObject {
            types: None,
            metadata: ObjectMeta {
                name: Some("alpha--work".to_string()),
                namespace: Some("default".to_string()),
                annotations: None,
                labels: Some(BTreeMap::from([
                    (LABEL_SANDBOX_ID.to_string(), "uuid-456".to_string()),
                    (LABEL_SANDBOX_NAME.to_string(), "work".to_string()),
                    (LABEL_SANDBOX_WORKSPACE.to_string(), "alpha".to_string()),
                    (
                        LABEL_MANAGED_BY.to_string(),
                        LABEL_MANAGED_BY_VALUE.to_string(),
                    ),
                ])),
                ..Default::default()
            },
            data: serde_json::json!({}),
        };

        let (_, sandbox) = sandbox_from_object("default", obj).unwrap();
        assert_eq!(sandbox.name, "work");
        assert_eq!(sandbox.workspace, "alpha");
        assert_eq!(sandbox.id, "uuid-456");
    }

    #[test]
    fn sandbox_from_object_skips_unmanaged_cr() {
        let obj = DynamicObject {
            types: None,
            metadata: ObjectMeta {
                name: Some("foreign-sandbox".to_string()),
                namespace: Some("default".to_string()),
                labels: Some(BTreeMap::from([(
                    "some-other-label".to_string(),
                    "value".to_string(),
                )])),
                ..Default::default()
            },
            data: serde_json::json!({}),
        };

        let result = sandbox_from_object("default", obj);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not managed by openshell"));
    }

    #[test]
    fn sandbox_from_object_uses_object_namespace_over_fallback() {
        let obj = DynamicObject {
            types: None,
            metadata: ObjectMeta {
                name: Some("work".to_string()),
                namespace: Some("openshell-gw1-team-a".to_string()),
                annotations: Some(BTreeMap::from([
                    (LABEL_SANDBOX_ID.to_string(), "uuid-cross".to_string()),
                    (LABEL_SANDBOX_NAME.to_string(), "work".to_string()),
                    (LABEL_SANDBOX_WORKSPACE.to_string(), "team-a".to_string()),
                ])),
                labels: Some(BTreeMap::from([
                    (LABEL_SANDBOX_ID.to_string(), "uuid-cross".to_string()),
                    (LABEL_SANDBOX_NAME.to_string(), "work".to_string()),
                    (LABEL_SANDBOX_WORKSPACE.to_string(), "team-a".to_string()),
                    (
                        LABEL_MANAGED_BY.to_string(),
                        LABEL_MANAGED_BY_VALUE.to_string(),
                    ),
                ])),
                ..Default::default()
            },
            data: serde_json::json!({}),
        };

        let (_, sandbox) = sandbox_from_object("openshell", obj).unwrap();
        assert_eq!(sandbox.namespace, "openshell-gw1-team-a");
        assert_eq!(sandbox.workspace, "team-a");
    }

    #[test]
    fn sandbox_from_object_warns_on_managed_cr_missing_workspace() {
        let obj = DynamicObject {
            types: None,
            metadata: ObjectMeta {
                name: Some("work".to_string()),
                namespace: Some("default".to_string()),
                labels: Some(BTreeMap::from([
                    (LABEL_SANDBOX_ID.to_string(), "uuid-789".to_string()),
                    (LABEL_SANDBOX_NAME.to_string(), "work".to_string()),
                    (
                        LABEL_MANAGED_BY.to_string(),
                        LABEL_MANAGED_BY_VALUE.to_string(),
                    ),
                ])),
                ..Default::default()
            },
            data: serde_json::json!({}),
        };

        let result = sandbox_from_object("default", obj);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing sandbox workspace"));
    }

    #[test]
    fn sandbox_labels_includes_workspace_and_name() {
        let sandbox = Sandbox {
            id: "uuid-1".to_string(),
            name: "work".to_string(),
            workspace: "alpha".to_string(),
            ..Default::default()
        };
        let labels = sandbox_labels(&sandbox, None);
        assert_eq!(labels.get(LABEL_SANDBOX_ID).unwrap(), "uuid-1");
        assert_eq!(labels.get(LABEL_SANDBOX_NAME).unwrap(), "work");
        assert_eq!(labels.get(LABEL_SANDBOX_WORKSPACE).unwrap(), "alpha");
        assert_eq!(
            labels.get(LABEL_MANAGED_BY).unwrap(),
            LABEL_MANAGED_BY_VALUE
        );
        assert!(!labels.contains_key(LABEL_GATEWAY_ID));
    }

    #[test]
    fn sandbox_labels_includes_gateway_id_when_provided() {
        let sandbox = Sandbox {
            id: "uuid-1".to_string(),
            name: "work".to_string(),
            workspace: "alpha".to_string(),
            ..Default::default()
        };
        let labels = sandbox_labels(&sandbox, Some("gw-42"));
        assert_eq!(labels.get(LABEL_GATEWAY_ID).unwrap(), "gw-42");
    }

    #[test]
    fn sandbox_annotations_stores_authoritative_values() {
        let sandbox = Sandbox {
            id: "uuid-2".to_string(),
            name: "dev".to_string(),
            workspace: "beta".to_string(),
            ..Default::default()
        };
        let annotations = sandbox_annotations(&sandbox);
        assert_eq!(annotations.get(LABEL_SANDBOX_ID).unwrap(), "uuid-2");
        assert_eq!(annotations.get(LABEL_SANDBOX_NAME).unwrap(), "dev");
        assert_eq!(annotations.get(LABEL_SANDBOX_WORKSPACE).unwrap(), "beta");
    }

    #[test]
    fn sandbox_id_from_object_errors_without_label() {
        let obj = DynamicObject {
            types: None,
            metadata: ObjectMeta {
                name: Some("some-name".to_string()),
                ..Default::default()
            },
            data: serde_json::json!({}),
        };
        assert!(sandbox_id_from_object(&obj).is_err());
    }

    #[test]
    fn default_workspace_vct_sets_storage_class_when_provided() {
        let vct = default_workspace_volume_claim_templates("5Gi", "fast-ssd");
        assert_eq!(vct[0]["spec"]["storageClassName"], "fast-ssd");
    }

    #[test]
    fn default_workspace_vct_omits_storage_class_when_empty() {
        let vct = default_workspace_volume_claim_templates("5Gi", "");
        assert!(vct[0]["spec"].get("storageClassName").is_none());
    }

    #[test]
    fn workspace_storage_class_propagates_to_generated_cr_spec() {
        let params = SandboxPodParams {
            workspace_storage_class: "fast-ssd",
            ..SandboxPodParams::default()
        };
        let cr = sandbox_to_k8s_spec_for_test(Some(&SandboxSpec::default()), &params);
        assert_eq!(
            cr["spec"]["volumeClaimTemplates"][0]["spec"]["storageClassName"],
            "fast-ssd"
        );
    }

    #[test]
    fn confidential_workload_template_disables_service_environment_injection() {
        let cr = sandbox_to_k8s_spec_for_test(
            Some(&SandboxSpec::default()),
            &SandboxPodParams::default(),
        );
        assert_eq!(
            cr.pointer("/spec/podTemplate/spec/enableServiceLinks"),
            Some(&serde_json::json!(false))
        );
    }

    #[test]
    fn workspace_storage_class_omitted_from_cr_spec_when_empty() {
        let cr = sandbox_to_k8s_spec_for_test(
            Some(&SandboxSpec::default()),
            &SandboxPodParams::default(),
        );
        assert!(
            cr["spec"]["volumeClaimTemplates"][0]["spec"]
                .get("storageClassName")
                .is_none()
        );
    }

    #[test]
    fn sandbox_lookup_selector_always_includes_gateway_id() {
        let sel = sandbox_lookup_selector_for("sb-123", "gw-42");
        assert!(
            sel.contains(&format!("{LABEL_GATEWAY_ID}=gw-42")),
            "selector must include gateway ID: {sel}"
        );
        assert!(
            sel.contains(&format!("{LABEL_SANDBOX_ID}=sb-123")),
            "selector must include sandbox ID: {sel}"
        );
        assert!(
            sel.contains(&format!("{LABEL_MANAGED_BY}={LABEL_MANAGED_BY_VALUE}")),
            "selector must include managed-by: {sel}"
        );
    }

    #[test]
    fn openshell_sandbox_selector_always_includes_gateway_id() {
        let sel = openshell_sandbox_selector_for("gw-99");
        assert!(
            sel.contains(&format!("{LABEL_GATEWAY_ID}=gw-99")),
            "selector must include gateway ID: {sel}"
        );
        assert!(
            sel.contains(&format!("{LABEL_MANAGED_BY}={LABEL_MANAGED_BY_VALUE}")),
            "selector must include managed-by: {sel}"
        );
    }

    #[test]
    fn managed_ssh_policy_allows_only_gateway_peer_on_port_2222() {
        let config = KubernetesComputeConfig {
            managed_ssh_ingress: crate::config::ManagedSshIngressConfig {
                enabled: true,
                gateway_namespace: "gateway-ns".to_string(),
                gateway_pod_selector: BTreeMap::from([(
                    "app.kubernetes.io/name".to_string(),
                    "openshell".to_string(),
                )]),
            },
            ..KubernetesComputeConfig::default()
        };
        let policy = managed_ssh_network_policy("workspace-ns", &config);
        let spec = policy.spec.unwrap();
        assert_eq!(
            spec.policy_types.as_deref(),
            Some(["Ingress".to_string()].as_slice())
        );
        let ingress = &spec.ingress.unwrap()[0];
        assert_eq!(
            ingress.ports.as_ref().unwrap()[0].port,
            Some(IntOrString::Int(2222))
        );
        let peer = &ingress.from.as_ref().unwrap()[0];
        assert_eq!(
            peer.namespace_selector
                .as_ref()
                .unwrap()
                .match_labels
                .as_ref()
                .unwrap()
                .get("kubernetes.io/metadata.name")
                .map(String::as_str),
            Some("gateway-ns")
        );
        assert_eq!(
            peer.pod_selector
                .as_ref()
                .unwrap()
                .match_labels
                .as_ref()
                .unwrap()
                .get("app.kubernetes.io/name")
                .map(String::as_str),
            Some("openshell")
        );
    }

    type KubeTestStep = (
        http::Method,
        &'static str,
        http::Response<kube::client::Body>,
    );

    type ScriptedDriver = (
        KubernetesComputeDriver,
        Arc<std::sync::Mutex<VecDeque<KubeTestStep>>>,
        Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    );

    /// Build a driver whose client answers `steps` in order and records each
    /// request body.
    fn scripted_driver(
        config: KubernetesComputeConfig,
        steps: Vec<KubeTestStep>,
    ) -> ScriptedDriver {
        use http_body_util::BodyExt as _;
        let steps = Arc::new(std::sync::Mutex::new(VecDeque::from(steps)));
        let bodies = Arc::new(std::sync::Mutex::new(Vec::new()));
        let service_steps = steps.clone();
        let service_bodies = bodies.clone();
        let service = tower::service_fn(move |request: http::Request<kube::client::Body>| {
            let steps = service_steps.clone();
            let bodies = service_bodies.clone();
            async move {
                let (method, path, response) = steps
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("unexpected Kubernetes API request");
                assert_eq!(request.method(), method);
                assert_eq!(request.uri().path(), path);
                let body = request.into_body().collect().await.unwrap().to_bytes();
                if !body.is_empty() {
                    bodies
                        .lock()
                        .unwrap()
                        .push(serde_json::from_slice(&body).unwrap());
                }
                Ok::<_, std::convert::Infallible>(response)
            }
        });
        let client = Client::new(service, "openshell");
        let driver = KubernetesComputeDriver {
            client: client.clone(),
            watch_client: client,
            sandbox_api_version: Arc::new(OnceCell::new()),
            config,
            operator_allowlist: None,
            confidential: None,
            lifecycle_gates: Arc::default(),
        };
        (driver, steps, bodies)
    }

    fn pod_owner(name: &str, uid: &str) -> OwnerReference {
        OwnerReference {
            api_version: "v1".to_string(),
            kind: "Pod".to_string(),
            name: name.to_string(),
            uid: uid.to_string(),
            controller: Some(false),
            block_owner_deletion: Some(false),
        }
    }

    fn managed_config(image_pull_secrets: &[&str]) -> KubernetesComputeConfig {
        KubernetesComputeConfig {
            namespace: "openshell".into(),
            gateway_id: "gateway-a".into(),
            workspace_mode: WorkspaceMode::Managed,
            image_pull_secrets: image_pull_secrets.iter().map(ToString::to_string).collect(),
            client_tls_secret_name: "openshell-client-tls".into(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn managed_pods_reference_generation_image_pull_secrets() {
        let names = SandboxRuntimeNames::for_generation("sandbox-1", "gen7");
        let driver = KubernetesComputeDriver::new_for_test(managed_config(&["regcred", "backup"]));
        assert_eq!(
            driver.generation_image_pull_secret_names(&names),
            [
                "os-pull-sandbox-1-gen7-0".to_string(),
                "os-pull-sandbox-1-gen7-1".to_string()
            ]
        );
        for workspace_mode in [WorkspaceMode::Shared, WorkspaceMode::Operator] {
            let driver = KubernetesComputeDriver::new_for_test(KubernetesComputeConfig {
                workspace_mode,
                ..managed_config(&["regcred"])
            });
            assert_eq!(
                driver.generation_image_pull_secret_names(&names),
                ["regcred".to_string()]
            );
        }
    }

    #[test]
    fn supervisor_client_tls_is_staged_outside_the_sandbox_namespace() {
        let assert_tls = |workspace_mode, name: &str, expected: SupervisorClientTls<'_>| {
            let config = KubernetesComputeConfig {
                workspace_mode,
                client_tls_secret_name: name.into(),
                ..Default::default()
            };
            assert_eq!(config.supervisor_client_tls(), expected);
        };
        assert_tls(
            WorkspaceMode::Shared,
            "client-tls",
            SupervisorClientTls::Secret("client-tls"),
        );
        assert_tls(
            WorkspaceMode::Managed,
            "client-tls",
            SupervisorClientTls::Bootstrap,
        );
        assert_tls(
            WorkspaceMode::Operator,
            "client-tls",
            SupervisorClientTls::Bootstrap,
        );
        assert_tls(WorkspaceMode::Managed, "", SupervisorClientTls::Disabled);
    }

    #[tokio::test]
    async fn managed_generation_image_pull_secrets_are_created_without_reading_targets() {
        let source = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "regcred", "namespace": "openshell"},
            "type": "kubernetes.io/dockerconfigjson",
            "data": {".dockerconfigjson": "e30="}
        });
        let (driver, steps, bodies) = scripted_driver(
            managed_config(&["regcred"]),
            vec![
                (
                    http::Method::GET,
                    "/api/v1/namespaces/openshell/secrets/regcred",
                    kube_test_response(http::StatusCode::OK, source),
                ),
                (
                    http::Method::POST,
                    "/api/v1/namespaces/managed-team-a/secrets",
                    kube_test_response(
                        http::StatusCode::CREATED,
                        serde_json::json!({
                            "apiVersion": "v1",
                            "kind": "Secret",
                            "metadata": {"name": "os-pull-sandbox-1-gen7-0", "namespace": "managed-team-a"}
                        }),
                    ),
                ),
            ],
        );
        let names = SandboxRuntimeNames::for_generation("sandbox-1", "gen7");
        driver
            .create_generation_image_pull_secrets(
                "managed-team-a",
                &names,
                "sandbox-1",
                vec![
                    pod_owner("workload", "w-uid"),
                    pod_owner("supervisor", "s-uid"),
                ],
            )
            .await
            .expect("generation image-pull Secret should be created");
        assert!(steps.lock().unwrap().is_empty());
        let created = &bodies.lock().unwrap()[0];
        assert_eq!(created["metadata"]["name"], "os-pull-sandbox-1-gen7-0");
        assert_eq!(created["immutable"], true);
        assert_eq!(created["type"], "kubernetes.io/dockerconfigjson");
        assert_eq!(created["data"][".dockerconfigjson"], "e30=");
        assert_eq!(
            created["metadata"]["ownerReferences"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn generation_image_pull_secret_name_collision_fails_closed() {
        let (driver, steps, _) = scripted_driver(
            managed_config(&["regcred"]),
            vec![
                (
                    http::Method::GET,
                    "/api/v1/namespaces/openshell/secrets/regcred",
                    kube_test_response(
                        http::StatusCode::OK,
                        serde_json::json!({
                            "apiVersion": "v1",
                            "kind": "Secret",
                            "metadata": {"name": "regcred", "namespace": "openshell"},
                            "type": "kubernetes.io/dockerconfigjson",
                            "data": {".dockerconfigjson": "e30="}
                        }),
                    ),
                ),
                (
                    http::Method::POST,
                    "/api/v1/namespaces/managed-team-a/secrets",
                    kube_test_response(
                        http::StatusCode::CONFLICT,
                        serde_json::json!({
                            "apiVersion": "v1",
                            "kind": "Status",
                            "status": "Failure",
                            "reason": "AlreadyExists",
                            "message": "secrets \"os-pull-sandbox-1-gen7-0\" already exists",
                            "code": 409
                        }),
                    ),
                ),
            ],
        );
        let names = SandboxRuntimeNames::for_generation("sandbox-1", "gen7");
        driver
            .create_generation_image_pull_secrets("managed-team-a", &names, "sandbox-1", Vec::new())
            .await
            .expect_err("an existing Secret must not be adopted");
        assert!(steps.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unmanaged_modes_create_no_generation_image_pull_secrets() {
        for workspace_mode in [WorkspaceMode::Shared, WorkspaceMode::Operator] {
            let (driver, _, _) = scripted_driver(
                KubernetesComputeConfig {
                    workspace_mode,
                    ..managed_config(&["regcred"])
                },
                Vec::new(),
            );
            driver
                .create_generation_image_pull_secrets(
                    "workspace",
                    &SandboxRuntimeNames::for_generation("sandbox-1", "gen7"),
                    "sandbox-1",
                    Vec::new(),
                )
                .await
                .expect("no Secret is staged outside managed mode");
        }
    }

    #[tokio::test]
    async fn client_tls_material_is_read_from_the_source_namespace() {
        let (driver, steps, _) = scripted_driver(
            managed_config(&[]),
            vec![(
                http::Method::GET,
                "/api/v1/namespaces/openshell/secrets/openshell-client-tls",
                kube_test_response(
                    http::StatusCode::OK,
                    serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "Secret",
                        "metadata": {"name": "openshell-client-tls", "namespace": "openshell"},
                        "type": "kubernetes.io/tls",
                        "data": {"ca.crt": "Y2E=", "tls.crt": "Y2VydA==", "tls.key": "a2V5"}
                    }),
                ),
            )],
        );
        let material = driver
            .read_client_tls_material()
            .await
            .expect("read client TLS")
            .expect("client TLS is staged in managed mode");
        assert_eq!(material.ca_certificate, b"ca");
        assert!(steps.lock().unwrap().is_empty());

        let (shared, _, _) = scripted_driver(
            KubernetesComputeConfig {
                workspace_mode: WorkspaceMode::Shared,
                ..managed_config(&[])
            },
            Vec::new(),
        );
        assert!(shared.read_client_tls_material().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn supervisor_cleanup_rejects_replacement_pod_owner() {
        let (driver, steps, _) = scripted_driver(
            managed_config(&[]),
            vec![(
                http::Method::GET,
                "/api/v1/namespaces/managed-team-a/pods/os-supervisor-sandbox-1",
                kube_test_response(
                    http::StatusCode::OK,
                    serde_json::json!({
                        "apiVersion":"v1", "kind":"Pod",
                        "metadata": {
                            "name":"os-supervisor-sandbox-1", "uid":"new-pod-uid",
                            "ownerReferences":[{"apiVersion":"agents.x-k8s.io/v1beta1",
                                "kind":"Sandbox", "name":"new-cr", "uid":"new-cr-uid"}]
                        },
                        "spec":{"containers":[]}
                    }),
                ),
            )],
        );
        let error = driver
            .delete_sandbox_runtime_supervisor_pod_for_uid(
                "sandbox-1",
                "managed-team-a",
                "old-cr-uid",
            )
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("different Sandbox CR UID"),
            "{error}"
        );
        assert!(steps.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn generation_secret_cleanup_rejects_replacement_owner() {
        let (driver, steps, _) = scripted_driver(
            managed_config(&[]),
            vec![(
                http::Method::GET,
                "/api/v1/namespaces/managed-team-a/secrets/os-sandbox-sandbox-1-gen7",
                kube_test_response(
                    http::StatusCode::OK,
                    serde_json::json!({
                        "apiVersion":"v1", "kind":"Secret",
                        "metadata": {"name":"os-sandbox-sandbox-1-gen7", "uid":"new-secret-uid",
                            "ownerReferences":[{"apiVersion":"v1", "kind":"Pod",
                                "name":"new-workload", "uid":"new-pod-uid"}]}
                    }),
                ),
            )],
        );
        let error = driver
            .delete_sandbox_runtime_generation_secrets_for_pods(
                "sandbox-1",
                "managed-team-a",
                &["gen7"],
                Some("old-pod-uid"),
                Some("old-supervisor-uid"),
            )
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("not owned by the old role Pod UIDs"),
            "{error}"
        );
        assert!(steps.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn generation_secret_cleanup_waits_until_owned_name_is_absent() {
        let (driver, steps, _) = scripted_driver(
            managed_config(&[]),
            vec![
                (
                    http::Method::GET,
                    "/api/v1/namespaces/managed-team-a/secrets/os-sandbox-sandbox-1-gen7",
                    kube_test_response(
                        http::StatusCode::OK,
                        serde_json::json!({
                            "apiVersion":"v1", "kind":"Secret",
                            "metadata":{"name":"os-sandbox-sandbox-1-gen7", "uid":"old-secret-uid",
                                "ownerReferences":[{"apiVersion":"v1", "kind":"Pod",
                                    "name":"old-workload", "uid":"old-pod-uid"}]}
                        }),
                    ),
                ),
                (
                    http::Method::DELETE,
                    "/api/v1/namespaces/managed-team-a/secrets/os-sandbox-sandbox-1-gen7",
                    kube_test_response(
                        http::StatusCode::OK,
                        serde_json::json!({
                            "apiVersion":"v1", "kind":"Status", "status":"Success"
                        }),
                    ),
                ),
                (
                    http::Method::GET,
                    "/api/v1/namespaces/managed-team-a/secrets/os-sandbox-sandbox-1-gen7",
                    kube_test_not_found("secrets", "os-sandbox-sandbox-1-gen7"),
                ),
                (
                    http::Method::GET,
                    "/api/v1/namespaces/managed-team-a/secrets/os-supervisor-sandbox-1-gen7",
                    kube_test_not_found("secrets", "os-supervisor-sandbox-1-gen7"),
                ),
            ],
        );
        driver
            .delete_sandbox_runtime_generation_secrets_for_pods(
                "sandbox-1",
                "managed-team-a",
                &["gen7"],
                Some("old-pod-uid"),
                Some("old-supervisor-uid"),
            )
            .await
            .unwrap();
        assert!(steps.lock().unwrap().is_empty());
    }

    #[test]
    fn namespace_owned_with_correct_labels() {
        let labels = BTreeMap::from([
            (
                LABEL_MANAGED_BY.to_string(),
                LABEL_MANAGED_BY_VALUE.to_string(),
            ),
            (LABEL_GATEWAY_ID.to_string(), "gw-1".to_string()),
        ]);
        assert!(is_namespace_owned_by_gateway(Some(&labels), "gw-1"));
    }

    #[test]
    fn namespace_not_owned_missing_managed_by() {
        let labels = BTreeMap::from([(LABEL_GATEWAY_ID.to_string(), "gw-1".to_string())]);
        assert!(!is_namespace_owned_by_gateway(Some(&labels), "gw-1"));
    }

    #[test]
    fn namespace_not_owned_wrong_gateway_id() {
        let labels = BTreeMap::from([
            (
                LABEL_MANAGED_BY.to_string(),
                LABEL_MANAGED_BY_VALUE.to_string(),
            ),
            (LABEL_GATEWAY_ID.to_string(), "gw-other".to_string()),
        ]);
        assert!(!is_namespace_owned_by_gateway(Some(&labels), "gw-1"));
    }

    #[test]
    fn namespace_not_owned_no_labels() {
        assert!(!is_namespace_owned_by_gateway(None, "gw-1"));
    }

    #[test]
    fn namespace_delete_is_guarded_by_fetched_uid() {
        let params = namespace_delete_params("namespace-uid".to_string());
        assert_eq!(
            params
                .preconditions
                .and_then(|preconditions| preconditions.uid),
            Some("namespace-uid".to_string())
        );
    }

    #[test]
    fn namespace_watcher_retry_delay_is_bounded_exponential_with_jitter() {
        let seed = 42;
        let expected_ranges = [(2, 2), (4, 5), (8, 10), (16, 20), (24, 30), (24, 30)];

        for (attempt, (minimum, maximum)) in expected_ranges.into_iter().enumerate() {
            let attempt = u32::try_from(attempt).unwrap();
            let delay = namespace_watcher_retry_delay(attempt, seed).as_secs();
            assert!(
                (minimum..=maximum).contains(&delay),
                "attempt {attempt} produced {delay}s"
            );
        }
    }

    #[test]
    fn namespace_watcher_retry_delay_uses_seeded_jitter() {
        assert_ne!(
            namespace_watcher_retry_delay(3, 1),
            namespace_watcher_retry_delay(3, 2)
        );
    }

    #[tokio::test]
    async fn capabilities_report_static_resource_support() {
        let driver = KubernetesComputeDriver::new_for_test(KubernetesComputeConfig::default());
        let resources = driver
            .capabilities()
            .unwrap()
            .resource_capabilities
            .unwrap();
        assert!(resources.cpu.unwrap().limit_supported);
        assert!(resources.memory.unwrap().limit_supported);
        let gpu = resources.gpu.unwrap();
        assert!(gpu.default_selection_supported);
        assert!(gpu.count_selection_supported);
    }

    #[test]
    fn sandbox_runtime_control_availability_requires_a_ready_pod() {
        let mut pod = Pod::default();
        assert_eq!(
            sandbox_runtime_control_availability_from_pod(&pod),
            SandboxRuntimeControlAvailability::Unavailable
        );
        pod.status = Some(
            serde_json::from_value(serde_json::json!({
                "conditions": [{"type": "Ready", "status": "True"}]
            }))
            .expect("valid Pod status"),
        );
        assert_eq!(
            sandbox_runtime_control_availability_from_pod(&pod),
            SandboxRuntimeControlAvailability::Available
        );
    }

    #[test]
    fn sandbox_runtime_degraded_supervisor_is_not_masked_by_unknown_dependency() {
        use SandboxRuntimeControlAvailability::{Available, Degraded, Unavailable, Unknown};

        let combined =
            combine_sandbox_runtime_control_availability([Degraded, Unknown, Available, Available]);
        assert_eq!(combined, Degraded);
        assert_eq!(
            sandbox_runtime_readiness_state(combined),
            Some("unavailable")
        );

        assert_eq!(
            combine_sandbox_runtime_control_availability([
                Degraded,
                Unknown,
                Unavailable,
                Available
            ]),
            Unavailable
        );
        let unknown = combine_sandbox_runtime_control_availability([
            Available, Unknown, Available, Available,
        ]);
        assert_eq!(unknown, Unknown);
        assert_eq!(sandbox_runtime_readiness_state(unknown), None);
        assert_eq!(
            combine_sandbox_runtime_control_availability([Available; 4]),
            Available
        );
    }

    #[test]
    fn sandbox_runtime_unready_running_supervisor_is_degraded_not_unavailable() {
        let pod_with = |status: serde_json::Value| Pod {
            status: Some(serde_json::from_value(status).expect("valid Pod status")),
            ..Default::default()
        };

        let reconnecting = pod_with(serde_json::json!({
            "phase": "Running",
            "conditions": [{"type": "Ready", "status": "False"}]
        }));
        assert_eq!(
            sandbox_runtime_control_availability_from_pod(&reconnecting),
            SandboxRuntimeControlAvailability::Degraded
        );

        for phase in ["Failed", "Succeeded", "Pending"] {
            let pod = pod_with(serde_json::json!({
                "phase": phase,
                "conditions": [{"type": "Ready", "status": "False"}]
            }));
            assert_eq!(
                sandbox_runtime_control_availability_from_pod(&pod),
                SandboxRuntimeControlAvailability::Unavailable,
                "phase {phase}"
            );
        }

        let mut deleting = reconnecting;
        deleting.metadata.deletion_timestamp = Some(
            k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(k8s_openapi::chrono::Utc::now()),
        );
        assert_eq!(
            sandbox_runtime_control_availability_from_pod(&deleting),
            SandboxRuntimeControlAvailability::Unavailable
        );
    }

    #[test]
    fn sandbox_runtime_readiness_transitions_bump_the_watched_cr() {
        let unavailable = sandbox_runtime_readiness_transition_patch("42", "unavailable");
        let ready = sandbox_runtime_readiness_transition_patch("42", "ready");

        assert_eq!(unavailable["metadata"]["resourceVersion"], "42");
        assert_eq!(ready["metadata"]["resourceVersion"], "42");
        assert_eq!(
            unavailable["metadata"]["annotations"][ANNOTATION_SANDBOX_RUNTIME_READINESS],
            "unavailable"
        );
        assert_eq!(
            ready["metadata"]["annotations"][ANNOTATION_SANDBOX_RUNTIME_READINESS],
            "ready"
        );
        assert_ne!(unavailable, ready);
    }

    #[test]
    fn sandbox_runtime_bootstrap_completion_is_resource_version_guarded_and_publishes_ready() {
        let patch = sandbox_runtime_bootstrap_completion_patch("42");

        assert_eq!(patch["metadata"]["resourceVersion"], "42");
        assert_eq!(
            patch["metadata"]["annotations"][ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAPPING],
            serde_json::Value::Null
        );
        assert_eq!(
            patch["metadata"]["annotations"][ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_STARTED_AT],
            serde_json::Value::Null
        );
        assert_eq!(
            patch["metadata"]["annotations"][ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_OPERATION],
            serde_json::Value::Null
        );
        assert_eq!(
            patch["metadata"]["annotations"][ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_PHASE],
            serde_json::Value::Null
        );
        assert_eq!(
            patch["metadata"]["annotations"][ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_SESSION],
            serde_json::Value::Null
        );
        assert_eq!(
            patch["metadata"]["annotations"][ANNOTATION_SANDBOX_RUNTIME_READINESS],
            "ready"
        );
    }

    #[test]
    fn sandbox_runtime_suspension_is_durable_until_cleanup_completes() {
        let suspension = sandbox_runtime_suspension_patch(SANDBOX_VERSION_V1BETA1, "42");
        assert_eq!(suspension["metadata"]["resourceVersion"], "42");
        assert_eq!(
            suspension["metadata"]["annotations"][ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAPPING],
            "true"
        );
        assert_eq!(
            suspension["metadata"]["annotations"][ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_OPERATION],
            "stop"
        );
        assert_eq!(
            suspension["metadata"]["annotations"][ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_PHASE],
            SandboxRuntimeBootstrapPhase::Suspending.as_str()
        );
        assert_eq!(suspension["spec"]["operatingMode"], "Suspended");

        let complete = sandbox_runtime_suspension_completion_patch("43");
        assert_eq!(complete["metadata"]["resourceVersion"], "43");
        for annotation in [
            ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAPPING,
            ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_STARTED_AT,
            ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_OPERATION,
            ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_PHASE,
            ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_SESSION,
            ANNOTATION_SANDBOX_RUNTIME_GENERATION,
            ANNOTATION_SANDBOX_RUNTIME_WORKLOAD_UID,
            ANNOTATION_SANDBOX_RUNTIME_SUPERVISOR_UID,
            ANNOTATION_SANDBOX_RUNTIME_NETWORK_POLICY_UID,
            ANNOTATION_SANDBOX_RUNTIME_NETWORK_POLICY_GENERATION,
        ] {
            assert_eq!(
                complete["metadata"]["annotations"][annotation],
                serde_json::Value::Null
            );
        }
    }

    #[test]
    fn sandbox_runtime_bootstrap_completion_waits_for_runtime_ready() {
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            SANDBOX_GROUP,
            SANDBOX_VERSION_V1BETA1,
            SANDBOX_KIND,
        ));
        let mut sandbox = DynamicObject::new("sandbox", &resource);
        sandbox.metadata.generation = Some(7);
        sandbox.data = serde_json::json!({
            "status": {
                "conditions": [{"type": "Suspended", "status": "True", "observedGeneration": 7}]
            }
        });
        assert!(!sandbox_runtime_runtime_is_ready(&sandbox));

        sandbox.data["status"]["conditions"] = serde_json::json!([
            {"type": "Suspended", "status": "False", "observedGeneration": 6},
            {"type": "Ready", "status": "True", "observedGeneration": 6}
        ]);
        assert!(!sandbox_runtime_runtime_is_ready(&sandbox));

        sandbox.data["status"]["conditions"] = serde_json::json!([
            {"type": "Suspended", "status": "False", "observedGeneration": 7},
            {"type": "Ready", "status": "True", "observedGeneration": 7}
        ]);
        assert!(sandbox_runtime_runtime_is_ready(&sandbox));

        sandbox.data["status"]["conditions"] = serde_json::json!([
            {"type": "Suspended", "status": "True", "observedGeneration": 7},
            {"type": "Ready", "status": "True", "observedGeneration": 7}
        ]);
        assert!(!sandbox_runtime_runtime_is_ready(&sandbox));
    }

    #[test]
    fn sandbox_runtime_bootstrap_completion_requires_released_create_or_restart() {
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            SANDBOX_GROUP,
            SANDBOX_VERSION_V1BETA1,
            SANDBOX_KIND,
        ));
        let mut sandbox = DynamicObject::new("sandbox", &resource);
        sandbox.metadata.generation = Some(7);
        sandbox.data = serde_json::json!({
            "status": {
                "conditions": [{
                    "type": "Ready",
                    "status": "True",
                    "observedGeneration": 7
                }]
            }
        });
        let annotations = sandbox.metadata.annotations.get_or_insert_default();
        annotations.insert(
            ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAPPING.to_string(),
            "true".to_string(),
        );
        annotations.insert(
            ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_PHASE.to_string(),
            SandboxRuntimeBootstrapPhase::Released.as_str().to_string(),
        );
        annotations.insert(
            ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_OPERATION.to_string(),
            "create".to_string(),
        );
        assert!(sandbox_runtime_bootstrap_is_ready_to_complete(&sandbox));

        sandbox.metadata.annotations.as_mut().unwrap().insert(
            ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_OPERATION.to_string(),
            "restart".to_string(),
        );
        assert!(sandbox_runtime_bootstrap_is_ready_to_complete(&sandbox));

        sandbox.metadata.annotations.as_mut().unwrap().insert(
            ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_PHASE.to_string(),
            SandboxRuntimeBootstrapPhase::Releasing.as_str().to_string(),
        );
        assert!(!sandbox_runtime_bootstrap_is_ready_to_complete(&sandbox));

        sandbox.metadata.annotations.as_mut().unwrap().insert(
            ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_PHASE.to_string(),
            SandboxRuntimeBootstrapPhase::Suspending
                .as_str()
                .to_string(),
        );
        assert!(!sandbox_runtime_bootstrap_is_ready_to_complete(&sandbox));

        sandbox.metadata.annotations.as_mut().unwrap().insert(
            ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_PHASE.to_string(),
            SandboxRuntimeBootstrapPhase::Released.as_str().to_string(),
        );
        sandbox.metadata.annotations.as_mut().unwrap().insert(
            ANNOTATION_SANDBOX_RUNTIME_BOOTSTRAP_OPERATION.to_string(),
            "stop".to_string(),
        );
        assert!(!sandbox_runtime_bootstrap_is_ready_to_complete(&sandbox));
    }

    #[test]
    fn sandbox_runtime_readiness_is_downgraded_with_a_transient_reason() {
        let mut sandbox = Sandbox {
            status: Some(SandboxStatus {
                conditions: vec![SandboxCondition {
                    r#type: "Ready".to_string(),
                    status: "True".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        mark_sandbox_runtime_control_unavailable(&mut sandbox);
        let ready = &sandbox.status.unwrap().conditions[0];
        assert_eq!(ready.status, "False");
        assert_eq!(ready.reason, "DependenciesNotReady");
    }

    #[test]
    fn sandbox_runtime_bootstrap_does_not_publish_a_terminal_suspension() {
        let mut sandbox = Sandbox {
            status: Some(SandboxStatus {
                conditions: vec![SandboxCondition {
                    r#type: SANDBOX_SUSPENDED_CONDITION.to_string(),
                    status: "True".to_string(),
                    reason: "PodTerminated".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };

        mark_sandbox_runtime_bootstrapping(&mut sandbox);

        let conditions = &sandbox.status.unwrap().conditions;
        assert!(
            !conditions
                .iter()
                .any(|condition| condition.r#type == SANDBOX_SUSPENDED_CONDITION)
        );
        assert!(conditions.iter().any(|condition| {
            condition.r#type == "Ready"
                && condition.status == "False"
                && condition.reason == "DependenciesNotReady"
        }));
        assert!(conditions.iter().any(|condition| {
            condition.r#type == "Bootstrapping"
                && condition.status == "True"
                && condition.reason == "SandboxRuntimeGenerationStarting"
        }));
    }

    #[test]
    fn completed_sandbox_runtime_bootstrap_preserves_real_suspension() {
        let sandbox = Sandbox {
            status: Some(SandboxStatus {
                conditions: vec![SandboxCondition {
                    r#type: SANDBOX_SUSPENDED_CONDITION.to_string(),
                    status: "True".to_string(),
                    reason: "PodTerminated".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };

        assert!(sandbox.status.unwrap().conditions.iter().any(|condition| {
            condition.r#type == SANDBOX_SUSPENDED_CONDITION && condition.status == "True"
        }));
    }

    #[test]
    fn sandbox_runtime_should_run_tracks_both_sandbox_apis() {
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(
            SANDBOX_GROUP,
            SANDBOX_VERSION_V1BETA1,
            SANDBOX_KIND,
        ));
        let mut beta = DynamicObject::new("beta", &resource);
        beta.data = serde_json::json!({"spec": {"operatingMode": "Suspended"}});
        assert!(!sandbox_runtime_should_run(&beta));
        beta.data = serde_json::json!({"spec": {"operatingMode": "Running"}});
        assert!(sandbox_runtime_should_run(&beta));

        let mut alpha = DynamicObject::new("alpha", &resource);
        alpha.data = serde_json::json!({"spec": {"replicas": 0}});
        assert!(!sandbox_runtime_should_run(&alpha));
        alpha.data = serde_json::json!({"spec": {"replicas": 1}});
        assert!(sandbox_runtime_should_run(&alpha));
    }
}
